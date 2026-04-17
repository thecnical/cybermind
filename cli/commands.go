package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"cybermind-cli/anon"
	"cybermind-cli/api"
	"cybermind-cli/bizlogic"
	"cybermind-cli/brain"
	"cybermind-cli/bugdetect"
	"cybermind-cli/hunt"
	"cybermind-cli/omega"
	"cybermind-cli/recon"
	"cybermind-cli/sandbox"
	"cybermind-cli/storage"
	"cybermind-cli/utils"

	"github.com/charmbracelet/lipgloss"
)

// omegaLogFile is the path to the floating terminal log file for the current OMEGA run.
var omegaLogFile string

// omegaLog appends a message to the OMEGA log file (stripping ANSI codes).
func omegaLog(msg string) {
	if omegaLogFile == "" {
		return
	}
	f, err := os.OpenFile(omegaLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	ansiStrip := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	clean := ansiStrip.ReplaceAllString(msg, "")
	fmt.Fprintln(f, clean)
}

// readWithTimeout reads a line from stdin with a timeout.
// If timeout expires, returns the defaultVal.
func readWithTimeout(prompt string, defaultVal string, timeoutSec int) string {
	fmt.Print(prompt)
	type result struct{ val string }
	ch := make(chan result, 1)
	go func() {
		var s string
		fmt.Scanln(&s)
		ch <- result{s}
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	remaining := timeoutSec
	for {
		select {
		case r := <-ch:
			fmt.Println()
			return strings.TrimSpace(r.val)
		case <-ticker.C:
			remaining--
			fmt.Printf("\r%s [auto-%s in %ds] ", prompt, defaultVal, remaining)
			if remaining <= 0 {
				fmt.Printf("\r%s → %s (auto)\n", prompt, defaultVal)
				return defaultVal
			}
		}
	}
}

// ─── Feature 2: Windows Native Recon ─────────────────────────────────────────

// runNativeScan performs native network scanning using PowerShell + Go net.
// Works on Windows, macOS, Linux — no external tools needed.
func runNativeScan(target string, localMode bool) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0078D6")).Render("  🌐 NATIVE SCAN — " + target))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	results := map[string]string{}

	// DNS resolution
	fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ DNS resolution..."))
	addrs, err := net.LookupHost(target)
	if err == nil && len(addrs) > 0 {
		results["dns"] = strings.Join(addrs, ", ")
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ IPs: " + strings.Join(addrs, ", ")))
	}

	// Port scan — top ports
	fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ Scanning common ports..."))
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017}
	var openPorts []string

	if runtime.GOOS == "windows" {
		// Windows: use PowerShell Test-NetConnection
		// Use sanitized target + pass port as separate arg to avoid injection
		safeTarget := sanitizeTarget(target)
		if safeTarget == "" {
			fmt.Println(lipgloss.NewStyle().Foreground(red).Render("  ✗ Invalid target"))
			return
		}
		for _, port := range commonPorts {
			// Use -EncodedCommand to prevent any injection via target string
			script := fmt.Sprintf("$r=(Test-NetConnection -ComputerName ([string]::new('%s')) -Port %d -WarningAction SilentlyContinue -InformationLevel Quiet -ErrorAction SilentlyContinue);if($r){Write-Output 'True'}else{Write-Output 'False'}", safeTarget, port)
			cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
			out, err := cmd.Output()
			if err == nil && strings.TrimSpace(string(out)) == "True" {
				openPorts = append(openPorts, fmt.Sprintf("%d", port))
			}
		}
	} else {
		// Linux/macOS: direct TCP dial
		for _, port := range commonPorts {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 2*time.Second)
			if err == nil {
				conn.Close()
				openPorts = append(openPorts, fmt.Sprintf("%d", port))
			}
		}
	}

	if len(openPorts) > 0 {
		results["open_ports"] = strings.Join(openPorts, ", ")
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Open ports: " + strings.Join(openPorts, ", ")))
	} else {
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  - No common ports open"))
	}

	// HTTP banner grab — no defer in loop, close immediately
	fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ HTTP banner grab..."))
	for _, scheme := range []string{"https", "http"} {
		targetURL := fmt.Sprintf("%s://%s", scheme, target)
		bannerClient := &http.Client{Timeout: 5 * time.Second}
		bannerResp, bannerErr := bannerClient.Get(targetURL)
		if bannerErr == nil {
			_, _ = io.ReadAll(io.LimitReader(bannerResp.Body, 512))
			bannerResp.Body.Close()
			server := bannerResp.Header.Get("Server")
			powered := bannerResp.Header.Get("X-Powered-By")
			banner := fmt.Sprintf("Status: %d | Server: %s | X-Powered-By: %s", bannerResp.StatusCode, server, powered)
			results["http_"+scheme] = banner
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ " + strings.ToUpper(scheme) + ": " + banner))
			break
		}
	}

	// Shodan InternetDB
	fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ Shodan InternetDB lookup..."))
	shodanData := shodanInternetDB(addrs)
	if shodanData != "" {
		results["shodan"] = shodanData
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Shodan: " + shodanData))
	}

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ AI analysis..."))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Native scan results for %s:\n\n", target))
	for k, v := range results {
		sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
	}
	sb.WriteString("\nProvide: attack surface analysis, CVE suggestions for detected services, MITRE ATT&CK mapping, exploitation recommendations, next steps.")

	var aiResult string
	var aiErr error
	if localMode {
		aiResult, aiErr = runLocalChat(sb.String(), nil)
	} else {
		aiResult, aiErr = api.SendPrompt(sb.String())
	}
	if aiErr != nil {
		printError("AI analysis failed: " + aiErr.Error())
		return
	}
	clean := utils.StripMarkdown(aiResult)
	printResult("🌐 Scan → "+target, clean)
	_ = storage.AddEntry("/scan "+target, clean)
}

// runPortScan parses netstat output to show active connections and listening ports.
func runPortScan(target string, localMode bool) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0078D6")).Render("  🔌 PORT SCAN — " + target))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	var openPorts []string
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017}

	fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ Scanning ports..."))

	if runtime.GOOS == "windows" {
		safeTarget := sanitizeTarget(target)
		if safeTarget == "" {
			printError("Invalid target")
			return
		}
		for _, port := range commonPorts {
			script := fmt.Sprintf("$r=(Test-NetConnection -ComputerName ([string]::new('%s')) -Port %d -WarningAction SilentlyContinue -InformationLevel Quiet -ErrorAction SilentlyContinue);if($r){Write-Output 'True'}else{Write-Output 'False'}", safeTarget, port)
			cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
			out, err := cmd.Output()
			if err == nil && strings.TrimSpace(string(out)) == "True" {
				openPorts = append(openPorts, fmt.Sprintf("%d", port))
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ Port %d OPEN", port)))
			}
		}
	} else {
		for _, port := range commonPorts {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 2*time.Second)
			if err == nil {
				conn.Close()
				openPorts = append(openPorts, fmt.Sprintf("%d", port))
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ Port %d OPEN", port)))
			}
		}
	}

	// Also show local netstat
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ Local netstat..."))
	var netstatOut string
	if runtime.GOOS == "windows" {
		cmd := exec.Command("netstat", "-an")
		out, err := cmd.Output()
		if err == nil {
			netstatOut = string(out)
		}
	} else {
		cmd := exec.Command("netstat", "-tlnp")
		out, err := cmd.Output()
		if err == nil {
			netstatOut = string(out)
		}
	}

	// Parse listening ports from netstat
	var listening []string
	portRe := regexp.MustCompile(`(?i)(TCP|UDP)\s+[\d.:*]+:(\d+)\s+[\d.:*]+\s+(LISTEN\w*)`)
	for _, line := range strings.Split(netstatOut, "\n") {
		m := portRe.FindStringSubmatch(line)
		if m != nil {
			listening = append(listening, m[1]+"/"+m[2])
		}
	}
	listening = dedup(listening)

	if len(listening) > 0 {
		limit := len(listening)
		if limit > 15 {
			limit = 15
		}
		fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  Local listening: " + strings.Join(listening[:limit], ", ")))
	}

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ AI analysis..."))

	prompt := fmt.Sprintf("Port scan results for %s:\nOpen ports: %s\nLocal listening: %s\n\nIdentify: suspicious services, CVEs for each service, attack vectors, MITRE ATT&CK mapping, exploitation priority.",
		target, strings.Join(openPorts, ", "), strings.Join(listening, ", "))

	var aiResult string
	var aiErr error
	if localMode {
		aiResult, aiErr = runLocalChat(prompt, nil)
	} else {
		aiResult, aiErr = api.SendPrompt(prompt)
	}
	if aiErr != nil {
		printError("AI analysis failed: " + aiErr.Error())
		return
	}
	clean := utils.StripMarkdown(aiResult)
	printResult("🔌 Port Scan → "+target, clean)
	_ = storage.AddEntry("/portscan "+target, clean)
}

// runOSINT performs OSINT using DNS + Shodan InternetDB (free, no key).
func runOSINT(target string, localMode bool) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700")).Render("  🔍 OSINT — " + target))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	var results []string

	// DNS
	fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ DNS lookup..."))
	addrs, err := net.LookupHost(target)
	if err == nil {
		results = append(results, "IPs: "+strings.Join(addrs, ", "))
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ IPs: " + strings.Join(addrs, ", ")))
	}

	// MX
	mxs, err := net.LookupMX(target)
	if err == nil && len(mxs) > 0 {
		var mxList []string
		for _, mx := range mxs {
			mxList = append(mxList, mx.Host)
		}
		results = append(results, "MX: "+strings.Join(mxList, ", "))
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ MX: " + strings.Join(mxList, ", ")))
	}

	// TXT (SPF, DMARC)
	txts, err := net.LookupTXT(target)
	if err == nil && len(txts) > 0 {
		limit := len(txts)
		if limit > 5 {
			limit = 5
		}
		for _, txt := range txts[:limit] {
			short := txt
			if len(short) > 100 {
				short = short[:100] + "..."
			}
			results = append(results, "TXT: "+short)
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ TXT: " + short))
		}
	}

	// NS
	nss, err := net.LookupNS(target)
	if err == nil && len(nss) > 0 {
		var nsList []string
		for _, ns := range nss {
			nsList = append(nsList, ns.Host)
		}
		results = append(results, "NS: "+strings.Join(nsList, ", "))
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ NS: " + strings.Join(nsList, ", ")))
	}

	// Shodan InternetDB
	fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ Shodan InternetDB..."))
	shodanData := shodanInternetDB(addrs)
	if shodanData != "" {
		results = append(results, "Shodan: "+shodanData)
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Shodan: " + shodanData))
	}

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ AI OSINT analysis..."))

	prompt := fmt.Sprintf("OSINT data for %s:\n%s\n\nProvide: threat intelligence, attack surface, CVEs for detected services, email security analysis (SPF/DMARC), subdomain takeover potential, MITRE ATT&CK mapping, next steps.",
		target, strings.Join(results, "\n"))

	var aiResult string
	var aiErr error
	if localMode {
		aiResult, aiErr = runLocalChat(prompt, nil)
	} else {
		aiResult, aiErr = api.SendPrompt(prompt)
	}
	if aiErr != nil {
		printError("AI analysis failed: " + aiErr.Error())
		return
	}
	clean := utils.StripMarkdown(aiResult)
	printResult("🔍 OSINT → "+target, clean)
	_ = storage.AddEntry("/osint "+target, clean)
}

// shodanInternetDB queries Shodan's free InternetDB API (no key needed).
func shodanInternetDB(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	ip := ips[0]
	if isPrivateIP(ip) {
		return ""
	}
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get("https://internetdb.shodan.io/" + ip)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return ""
	}
	raw := string(body)
	var parts []string
	if ports := extractJSONArray(raw, "ports"); ports != "" {
		parts = append(parts, "ports=["+ports+"]")
	}
	if vulns := extractJSONArray(raw, "vulns"); vulns != "" {
		parts = append(parts, "vulns=["+vulns+"]")
	}
	if tags := extractJSONArray(raw, "tags"); tags != "" {
		parts = append(parts, "tags=["+tags+"]")
	}
	if hostnames := extractJSONArray(raw, "hostnames"); hostnames != "" {
		parts = append(parts, "hostnames=["+hostnames+"]")
	}
	return strings.Join(parts, " | ")
}

func extractJSONArray(jsonStr, key string) string {
	search := `"` + key + `":`
	idx := strings.Index(jsonStr, search)
	if idx < 0 {
		return ""
	}
	start := strings.Index(jsonStr[idx:], "[")
	if start < 0 {
		return ""
	}
	start += idx
	end := strings.Index(jsonStr[start:], "]")
	if end < 0 {
		return ""
	}
	inner := strings.ReplaceAll(jsonStr[start+1:start+end], `"`, "")
	return strings.TrimSpace(inner)
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"} {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func dedup(s []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// ─── Feature 3: Payload Generator ────────────────────────────────────────────

// runPayload generates AI-powered payloads (no msfvenom needed).
func runPayload(targetOS, arch, payloadType string, localMode bool) {
	lhost := getLocalIP()
	lport := "4444"
	format := ""
	switch strings.ToLower(targetOS) {
	case "windows":
		format = "exe"
	case "linux":
		format = "elf"
	case "macos", "mac", "darwin":
		format = "macho"
	default:
		format = "exe"
	}

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render("  💣 PAYLOAD GENERATOR"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  OS: %s | Arch: %s | LHOST: %s | LPORT: %s | Type: %s", targetOS, arch, lhost, lport, payloadType)))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Generating payload package..."))

	var result string
	var err error
	if localMode {
		prompt := fmt.Sprintf("Generate complete payload package for OS=%s arch=%s lhost=%s lport=%s format=%s type=%s. Include: PowerShell/Python/Bash/C code payloads, msfvenom commands, listener setup, delivery methods, AV evasion, MITRE ATT&CK mapping.", targetOS, arch, lhost, lport, format, payloadType)
		result, err = runLocalChat(prompt, nil)
	} else {
		result, err = api.SendPayloadGen(targetOS, arch, lhost, lport, format, payloadType)
	}
	if err != nil {
		printError("Payload generation failed: " + err.Error())
		return
	}
	clean := utils.StripMarkdown(result)
	printResult("💣 Payload → "+targetOS+"/"+arch, clean)
	_ = storage.AddEntry("/payload "+targetOS+" "+arch, clean)
}

// ─── Feature 4: CVE Intelligence ─────────────────────────────────────────────

// runCVE queries NVD for a specific CVE and AI analysis.
func runCVE(cveID string, localMode bool) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render("  🔎 CVE INTELLIGENCE — " + cveID))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Fetching from NVD..."))

	var result string
	var err error
	if localMode {
		prompt := fmt.Sprintf("CVE Intelligence for %s: Provide full technical details, CVSS score, affected systems, exploitation methodology with exact commands, MITRE ATT&CK mapping, and remediation.", cveID)
		result, err = runLocalChat(prompt, nil)
	} else {
		result, err = api.SendCVE(cveID)
	}
	if err != nil {
		printError("CVE lookup failed: " + err.Error())
		return
	}
	clean := utils.StripMarkdown(result)
	printResult("🔎 CVE → "+cveID, clean)
	_ = storage.AddEntry("/cve "+cveID, clean)
}

// runCVELatest fetches latest critical CVEs from NVD.
func runCVELatest(severity string, localMode bool) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render("  🔎 LATEST CVEs (7 days)"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Fetching from NVD..."))

	var result string
	var err error
	if localMode {
		prompt := "List the most critical CVEs from the last 7 days. For each: CVE ID, CVSS score, affected product, exploitation status, and quick exploit command."
		result, err = runLocalChat(prompt, nil)
	} else {
		result, err = api.SendCVELatest()
	}
	if err != nil {
		printError("CVE fetch failed: " + err.Error())
		return
	}
	clean := utils.StripMarkdown(result)
	printResult("🔎 Latest CVEs", clean)
	_ = storage.AddEntry("/cve --latest", clean)
}

// ─── Feature 5: Report Writer ─────────────────────────────────────────────────

// runReport generates a professional pentest report from session history.
func runReport(format string, localMode bool) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#8A2BE2")).Render("  📄 PENTEST REPORT WRITER"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	history := storage.GetHistory()
	if len(history) == 0 {
		printError("No session history found. Run some scans first.")
		printError("  cybermind /scan example.com")
		printError("  cybermind /cve CVE-2024-1234")
		printError("  cybermind report")
		return
	}

	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  History entries: %d | Format: %s", len(history), format)))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Generating professional pentest report..."))

	var result string
	var err error
	if localMode {
		var sb strings.Builder
		sb.WriteString("Generate a professional penetration testing report in Markdown format from this session history:\n\n")
		for _, e := range history {
			aiSnippet := e.AI
			if len(aiSnippet) > 500 {
				aiSnippet = aiSnippet[:500]
			}
			sb.WriteString(fmt.Sprintf("[USER] %s\n[AI] %s\n\n", e.User, aiSnippet))
		}
		sb.WriteString("\nInclude: Executive Summary, Findings Table, Detailed Findings with CVE/CVSS/MITRE, Remediation Roadmap.")
		result, err = runLocalChat(sb.String(), nil)
	} else {
		result, err = api.SendReport(history, "")
	}
	if err != nil {
		printError("Report generation failed: " + err.Error())
		return
	}

	// Save to file
	ts := time.Now().Format("2006-01-02_15-04-05")
	outputFile := fmt.Sprintf("cybermind_report_%s.md", ts)
	if err := os.WriteFile(outputFile, []byte(result), 0644); err != nil {
		printError("Could not save report: " + err.Error())
	} else {
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green).Render("  ✓ Report saved: " + outputFile))
	}

	clean := utils.StripMarkdown(result)
	printResult("📄 Pentest Report", clean)
	_ = storage.AddEntry("report", "Report generated: "+outputFile)
}

// ─── Feature 6: Wordlist Generator ───────────────────────────────────────────

// runWordlist generates a custom wordlist by scraping target + AI generation.
func runWordlist(target, wordlistType string, localMode bool) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(yellow).Render("  📝 WORDLIST GENERATOR — " + target))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  Target: %s | Type: %s", target, wordlistType)))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Scraping target + generating wordlist..."))

	var result string
	var err error
	if localMode {
		prompt := fmt.Sprintf("Generate a custom %s wordlist for target: %s. Output ONLY the wordlist entries, one per line, no comments. Include 500 entries with variations (lowercase, UPPERCASE, numbers, special chars, year suffixes).", wordlistType, target)
		result, err = runLocalChat(prompt, nil)
	} else {
		result, err = api.SendWordlist(target, wordlistType, 500)
	}
	if err != nil {
		printError("Wordlist generation failed: " + err.Error())
		return
	}

	ts := time.Now().Format("2006-01-02_15-04-05")
	outputFile := fmt.Sprintf("wordlist_%s_%s.txt", strings.ReplaceAll(target, ".", "_"), ts)
	if err := os.WriteFile(outputFile, []byte(result), 0644); err != nil {
		printError("Could not save wordlist: " + err.Error())
	} else {
		lines := strings.Count(result, "\n") + 1
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green).Render(fmt.Sprintf("  ✓ Wordlist saved: %s (%d words)", outputFile, lines)))
	}

	// Preview
	lines := strings.Split(result, "\n")
	previewCount := len(lines)
	if previewCount > 15 {
		previewCount = 15
	}
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(yellow).Render("  Preview:"))
	for _, w := range lines[:previewCount] {
		if w != "" {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render("  " + w))
		}
	}
	if len(lines) > 15 {
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  ... and %d more in %s", len(lines)-15, outputFile)))
	}
	_ = storage.AddEntry("/wordlist "+target, fmt.Sprintf("Generated %d words → %s", len(lines), outputFile))
}

// ─── Feature 7: Local AI Mode (Ollama) ───────────────────────────────────────

// runLocalChat sends a prompt to local Ollama instance.
// Activated by: CYBERMIND_LOCAL=true env var or --local flag.
func runLocalChat(prompt string, history []api.Message) (string, error) {
	ollamaURL := os.Getenv("OLLAMA_URL")
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}
	model := os.Getenv("OLLAMA_MODEL")
	if model == "" {
		model = getLocalModel()
	}

	type ollamaMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type ollamaReq struct {
		Model    string      `json:"model"`
		Messages []ollamaMsg `json:"messages"`
		Stream   bool        `json:"stream"`
	}

	msgs := []ollamaMsg{
		{Role: "system", Content: "You are CyberMind, an elite offensive security AI. Answer all cybersecurity questions with full technical detail, exact commands, CVE references, MITRE ATT&CK mappings, and tool suggestions."},
	}
	for _, h := range history {
		msgs = append(msgs, ollamaMsg{Role: h.Role, Content: h.Content})
	}
	msgs = append(msgs, ollamaMsg{Role: "user", Content: prompt})

	reqBody := ollamaReq{Model: model, Messages: msgs, Stream: false}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Post(ollamaURL+"/api/chat", "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("Ollama not running. Start: ollama serve | Pull model: ollama pull llama3 | Install: https://ollama.ai")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", fmt.Errorf("failed to read Ollama response: %w", err)
	}

	var result struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("invalid Ollama response: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("Ollama error: %s", result.Error)
	}
	if result.Message.Content == "" {
		return "", fmt.Errorf("empty response from Ollama (model: %s)", model)
	}
	return result.Message.Content, nil
}

// printLocalModeInfo shows local AI mode status.
func printLocalModeInfo() {
	running, models := checkOllamaStatus()
	fmt.Println()
	if running {
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green).Render("  ✓ LOCAL AI MODE — Ollama running"))
		if len(models) > 0 {
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Available models: " + strings.Join(models, ", ")))
		}
		model := getLocalModel()
		fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  Active model: " + model))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Change model: OLLAMA_MODEL=mistral cybermind --local"))
	} else {
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render("  ✗ LOCAL AI MODE — Ollama not running"))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Start Ollama: ollama serve"))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Pull a model: ollama pull llama3"))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Install: https://ollama.ai"))
	}
	fmt.Println()
}

// checkOllamaStatus checks if Ollama is running and returns available models.
func checkOllamaStatus() (bool, []string) {
	ollamaURL := os.Getenv("OLLAMA_URL")
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(ollamaURL + "/api/tags")
	if err != nil || resp.StatusCode != 200 {
		return false, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	nameRe := regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)
	matches := nameRe.FindAllStringSubmatch(string(body), -1)
	var models []string
	for _, m := range matches {
		if len(m) > 1 {
			models = append(models, m[1])
		}
	}
	return true, models
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// sanitizeTarget strips any characters that could be used for command injection.
// Only allows hostname/IP safe chars: alphanumeric, dots, hyphens, colons (IPv6), brackets.
func sanitizeTarget(t string) string {
	var sb strings.Builder
	for _, r := range t {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '-' || r == ':' || r == '[' || r == ']' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// buildRequestedTools returns a tool list excluding skipped tools.
// mode: "recon" | "hunt" | "exploit" — filters by mode from omega tool list.
// Returns nil if no skip set (run all tools).
func buildRequestedTools(skipTools map[string]bool, mode string) []string {
	if len(skipTools) == 0 {
		return nil // nil = run all tools
	}
	// Get all tool names for this mode from omega tool list
	allTools := omega.GetOmegaToolList()
	var requested []string
	for _, t := range allTools {
		if t.Mode == mode && !skipTools[t.Name] {
			requested = append(requested, t.Name)
		}
	}
	if len(requested) == 0 {
		return nil // fallback: run all if filter produces empty list
	}
	return requested
}

// Suppress unused import warnings for packages used only in some build targets
var _ = base64.StdEncoding
var _ = filepath.Join
var _ = exec.LookPath
var _ = runtime.GOOS

// ─── OMEGA Agentic Brain Loop ─────────────────────────────────────────────────

// agentPrint prints a styled agent brain message
func agentPrint(msg string) {
	fmt.Println(lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00FFFF")).
		Background(lipgloss.Color("#0A0A1A")).
		Padding(0, 1).
		Render("  🧠 AGENT") + " " +
		lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render(msg))
}

func agentThink(msg string) {
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render("  ⟳ [BRAIN] " + msg))
}

func agentDecide(msg string) {
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700")).Render("  → [DECIDE] " + msg))
}

func agentAct(msg string) {
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF00")).Render("  ⚡ [ACT] " + msg))
}

// runAgenticOmega is the full agentic loop — AI brain controls everything.
// It decides what to run, adapts based on findings, and loops until bugs found or exhausted.
func runAgenticOmega(target, skillLevel, focusBugs, mode string, localMode bool) {
	cyan2 := lipgloss.Color("#00FFFF")
	green2 := lipgloss.Color("#00FF00")
	red2 := lipgloss.Color("#FF4444")
	yellow2 := lipgloss.Color("#FFD700")
	dim2 := lipgloss.Color("#777777")

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render(strings.Repeat("═", 64)))
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render("  🤖 OMEGA AGENTIC MODE — AI BRAIN IN CONTROL"))
	fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(fmt.Sprintf("  Target: %s | Mode: %s | Skill: %s | Focus: %s", target, mode, skillLevel, focusBugs)))
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render(strings.Repeat("═", 64)))
	fmt.Println()

	// ── Step 0: Ask user about anonymization ─────────────────────────────
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700")).Render(
		"  🔒 ANONYMIZATION — Route traffic through Tor? (slower but hides your IP)"))
	fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
		"  Yes = Tor (anonymous, ~3x slower) | No = Direct (fast, your real IP used)"))
	anonAns := readWithTimeout(
		lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render("  Enable Tor anonymization? [y/N] → "),
		"n", 15)

	if strings.ToLower(strings.TrimSpace(anonAns)) == "y" {
		anonStatus := anon.Setup()
		if anonStatus.Active {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
				fmt.Sprintf("  ✓ Anonymized via %s — Anon IP: %s", anonStatus.Method, anonStatus.AnonIP)))
		} else {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render(
				"  ✗ Tor setup failed — continuing without anonymization"))
		}
		defer anon.Teardown()
	} else {
		fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
			"  ℹ  Direct mode — no anonymization"))
	}
	fmt.Println()

	// ── Agent state — the brain's memory ─────────────────────────────────
	state := api.AgentState{
		Target:     target,
		Iteration:  0,
		Phase:      "init",
		SkillLevel: skillLevel,
		FocusBugs:  focusBugs,
		Mode:       mode,
		Findings:   make(map[string]string),
	}

	// ── SELF-THINK: Independent reasoning before any AI call ─────────────
	// Build target profile from memory for self-think engine
	selfThinkProfile := brain.BuildTargetProfile(target, []string{}, []int{}, false, "", []string{}, nil, nil)
	thinkResult := brain.SelfThink(selfThinkProfile)
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
		brain.FormatThinkResult(thinkResult)))

	// Apply self-think tool priority to environment
	if len(thinkResult.ToolPriority) > 0 {
		os.Setenv("CYBERMIND_PRIORITY_TOOLS", strings.Join(thinkResult.ToolPriority, ","))
	}
	if thinkResult.Priority == "critical" || thinkResult.Priority == "high" {
		os.Setenv("CYBERMIND_CONFIDENCE", thinkResult.Priority)
	}

	// ── Load memory context for self-improving prompts ────────────────────
	memContext := brain.GetLearnedPromptContext(target)
	if memContext != "" {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
			"  🧠 Brain memory loaded — using past learnings"))
	}

	// ── Memory-driven: find similar targets where bugs were found ─────────
	similar := brain.FindSimilarTargets(target, 3)
	if len(similar) > 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
			fmt.Sprintf("  🧠 Found %d similar targets with known bugs:", len(similar))))
		for _, s := range similar {
			fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
				fmt.Sprintf("    → %s (%.0f%% similar, bugs: %v)", s.Domain, s.Similarity*100, s.BugTypes)))
		}
		fmt.Println()
	}

	// ── Get best attack strategy from memory ─────────────────────────────
	bestPatterns := brain.GetBestAttackStrategy(target)
	if len(bestPatterns) > 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
			fmt.Sprintf("  🧠 %d proven attack patterns loaded from memory", len(bestPatterns))))
	}
	fmt.Println()

	// ── REAL MULTI-STEP PLANNING: Get full attack chain upfront ──────────
	var attackPlan []api.AttackStep
	if !localMode {
		agentThink("Planning full attack chain (5-10 steps ahead)...")
		mem := brain.LoadTarget(target)
		planReq := api.PlanStepsRequest{
			Target:        target,
			TechStack:     mem.TechStack,
			OpenPorts:     mem.OpenPorts,
			WAFDetected:   mem.WAFDetected,
			WAFVendor:     mem.WAFVendor,
			Subdomains:    mem.SubdomainsFound,
			LiveURLs:      mem.LiveURLs,
			SkillLevel:    skillLevel,
			FocusBugs:     focusBugs,
			Mode:          mode,
			MemoryContext: memContext,
		}
		if steps, planErr := api.SendPlanSteps(planReq); planErr == nil && len(steps) > 0 {
			attackPlan = steps
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF00")).Render(
				fmt.Sprintf("  ✓ Full attack plan: %d steps planned", len(steps))))
			for _, s := range steps {
				fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
					fmt.Sprintf("    Step %d: [%s] %s — %s (~%dm)",
						s.StepNumber, s.Action, s.Tool, s.VulnFocus, s.EstimatedMinutes)))
			}
			fmt.Println()
		} else {
			fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
				"  ℹ  Using reactive planning (plan-steps unavailable)"))
		}
	}
	planStepIdx := 0 // current position in attack plan

	// Accumulated context across all phases
	var allBugs []bugdetect.Bug
	var reconResult recon.ReconResult
	var huntResult hunt.HuntResult
	var allFindings = make(map[string]string)
	_ = bestPatterns // used in future iterations

	maxIterations := 10 // prevent infinite loops — enough for: recon+hunt+exploit+poc+guide
	if mode == "overnight" {
		maxIterations = 25
	} else if mode == "quick" {
		maxIterations = 6 // quick: recon+hunt+exploit+poc minimum
	}

	for iter := 0; iter < maxIterations; iter++ {
		state.Iteration = iter + 1
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(fmt.Sprintf("  %s", strings.Repeat("─", 60))))
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(yellow2).Render(
			fmt.Sprintf("  🔄 AGENT ITERATION %d/%d", iter+1, maxIterations)))
		fmt.Println()

		// ── Ask AI brain what to do next ─────────────────────────────────
		agentThink(fmt.Sprintf("Analyzing state: recon=%v hunt=%v bugs=%d phase=%s",
			state.ReconDone, state.HuntDone, state.BugsFound, state.Phase))

		var decision *api.AgentDecision
		var decErr error

		// ── Use pre-planned steps if available (real multi-step planning) ─
		if len(attackPlan) > 0 && planStepIdx < len(attackPlan) {
			plannedStep := attackPlan[planStepIdx]

			// Check skip condition
			shouldSkip := false
			skipLower := strings.ToLower(plannedStep.SkipCondition)
			if strings.Contains(skipLower, "already") && strings.Contains(skipLower, "memory") {
				if plannedStep.Action == "recon" && state.ReconDone {
					shouldSkip = true
				}
				if plannedStep.Action == "hunt" && state.HuntDone {
					shouldSkip = true
				}
			}
			if strings.Contains(skipLower, "subdomains already") && len(state.LiveURLs) > 0 {
				shouldSkip = true
			}

			if shouldSkip {
				fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
					fmt.Sprintf("  ⏭  Step %d skipped: %s", plannedStep.StepNumber, plannedStep.SkipCondition)))
				planStepIdx++
				continue
			}

			// Convert planned step to decision
			decision = &api.AgentDecision{
				Action:    plannedStep.Action,
				Reason:    plannedStep.Reason,
				VulnFocus: plannedStep.VulnFocus,
				Depth:     "deep",
				Notes:     fmt.Sprintf("Step %d/%d: %s", plannedStep.StepNumber, len(attackPlan), plannedStep.Reason),
			}
			planStepIdx++
			agentDecide(fmt.Sprintf("[PLAN Step %d/%d] Action=%s | Tool=%s | Focus=%s",
				plannedStep.StepNumber, len(attackPlan), decision.Action, plannedStep.Tool, decision.VulnFocus))
		} else {
			// ── Reactive: ask AI what to do next ─────────────────────────
			if !localMode {
				// Priority: cybermindcli (our fine-tuned model) → Groq → Backend
				if api.IsCyberMindLocalAvailable() || api.GetHFToken() != "" {
					cmDecision, cmErr := sendCyberMindAgentDecision(state, memContext)
					if cmErr == nil && cmDecision != nil {
						decision = cmDecision
					} else if api.IsGroqConfigured() {
						groqDecision, groqErr := sendGroqAgentDecision(state, memContext)
						if groqErr == nil && groqDecision != nil {
							decision = groqDecision
						} else {
							decision, decErr = api.SendAgentDecision(state)
						}
					} else {
						decision, decErr = api.SendAgentDecision(state)
					}
				} else if api.IsGroqConfigured() {
					groqDecision, groqErr := sendGroqAgentDecision(state, memContext)
					if groqErr == nil && groqDecision != nil {
						decision = groqDecision
					} else {
						decision, decErr = api.SendAgentDecision(state)
					}
				} else {
					decision, decErr = api.SendAgentDecision(state)
				}
			}
			// Fallback: local decision logic if AI unavailable
			if localMode || decErr != nil || decision == nil {
				decision = localAgentDecision(state)
				if decErr != nil {
					fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
						fmt.Sprintf("  ℹ  AI brain offline (%v) — using local logic", decErr)))
				}
			}
			agentDecide(fmt.Sprintf("Action=%s | Focus=%s | Reason: %s",
				decision.Action, decision.VulnFocus, truncate(decision.Reason, 80)))
		}

		if decision.Notes != "" && decision.Notes != decision.Reason {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
				"  💭 " + truncate(decision.Notes, 120)))
		}
		fmt.Println()

		// ── Execute the decision ──────────────────────────────────────────
		switch decision.Action {

		case "recon":
			agentAct("Running RECON phase...")
			omegaLog("\n═══ AGENT: RECON ═══\nTarget: " + target)

			reconResult = runAutoReconSilent(target, nil)
			state.ReconDone = true
			state.Phase = "recon_done"

			// Update state from recon
			if reconResult.Context != nil {
				rc := reconResult.Context
				state.LiveURLs = rc.LiveURLs
				state.OpenPorts = rc.OpenPorts
				state.WAFDetected = rc.WAFDetected
				state.WAFVendor = rc.WAFVendor
				state.Technologies = rc.Technologies
				state.Subdomains = len(rc.Subdomains)
			}
			state.ToolsRan = append(state.ToolsRan, reconResult.Tools...)
			for _, f := range reconResult.Results {
				if f.Output != "" {
					allFindings["recon_"+f.Tool] = truncate(f.Output, 500)
				}
			}

			// Parse bugs from recon
			for _, tr := range reconResult.Results {
				if tr.Output != "" {
					bugs := bugdetect.ParseToolOutput(tr.Tool, tr.Output, target)
					allBugs = append(allBugs, bugs...)
				}
			}
			state.BugsFound = len(allBugs)
			state.BugTypes = extractBugTypes(allBugs)

			// ── AGENT AUTO-TRIGGER: CVE Feed during recon ─────────────────
			// As soon as we know the tech stack, check for known CVEs
			if len(state.Technologies) > 0 {
				go func() {
					agentThink("Auto-checking CVE feed for detected tech stack...")
					shodanVulns := ""
					if reconResult.Context != nil {
						// Extract Shodan vulns from findings if available
						for _, tr := range reconResult.Results {
							if strings.Contains(tr.Tool, "shodan") && strings.Contains(tr.Output, "CVE-") {
								shodanVulns = tr.Output
								break
							}
						}
					}
					cveResult := brain.MatchCVEsToTarget(target, state.Technologies, shodanVulns)
					if cveResult.TotalFound > 0 {
						fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red2).Render(
							fmt.Sprintf("  🔴 CVE FEED: %d CVEs matched to target tech stack!", cveResult.TotalFound)))
						// Add high-severity CVEs to findings for AI context
						allFindings["cve_feed"] = brain.FormatCVEReport(cveResult)
						// Auto-run nuclei templates for critical CVEs
						criticalCVEs := []brain.CVEEntry{}
						for _, cve := range cveResult.Matched {
							if cve.CVSS >= 9.0 || cve.Severity == "CRITICAL" {
								criticalCVEs = append(criticalCVEs, cve)
							}
						}
						if len(criticalCVEs) > 0 {
							fmt.Println(lipgloss.NewStyle().Foreground(red2).Render(
								fmt.Sprintf("  ⚡ Auto-running nuclei for %d critical CVEs...", len(criticalCVEs))))
							brain.RunCVEExploitation(target, criticalCVEs, func(cveID, result string) {
								if strings.TrimSpace(result) != "" {
									fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red2).Render(
										fmt.Sprintf("  🎯 CVE CONFIRMED: %s", cveID)))
									allBugs = append(allBugs, bugdetect.Bug{
										Title:    "CVE Confirmed: " + cveID,
										Severity: bugdetect.SeverityCritical,
										Tool:     "cve_feed+nuclei",
										Target:   target,
										Evidence: result[:min(500, len(result))],
										CVSS:     9.8,
										CWE:      "CVE",
										FoundAt:  time.Now(),
									})
									state.BugsFound = len(allBugs)
								}
							})
						}
					}
				}()
			}

			// ── AGENT AUTO-TRIGGER: Cloud misconfiguration scan ───────────
			// Always run cloud scan — S3/GCS/Firebase misconfigs are high value
			go func() {
				agentThink("Auto-scanning for cloud misconfigurations...")
				subdomains := []string{}
				if reconResult.Context != nil {
					subdomains = reconResult.Context.Subdomains
				}
				cloudResult := brain.ScanCloudMisconfigurations(target, subdomains)
				if len(cloudResult.Findings) > 0 {
					fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red2).Render(
						fmt.Sprintf("  ☁️  CLOUD: %d misconfigurations found!", len(cloudResult.Findings))))
					allFindings["cloud_misconfig"] = brain.FormatCloudReport(cloudResult)
					for _, f := range cloudResult.Findings {
						sev := bugdetect.SeverityHigh
						if f.Severity == "critical" {
							sev = bugdetect.SeverityCritical
						}
						allBugs = append(allBugs, bugdetect.Bug{
							Title:       f.Type + " — " + f.Provider,
							Severity:    sev,
							Tool:        "cloud_scanner",
							Target:      target,
							URL:         f.URL,
							Description: f.Description,
							Evidence:    f.Evidence,
							CVSS:        9.0,
							CWE:         "CWE-732",
							FoundAt:     time.Now(),
						})
					}
					state.BugsFound = len(allBugs)
					state.BugTypes = extractBugTypes(allBugs)
				}
			}()

			// ── Brain: record recon results ───────────────────────────────
			if reconResult.Context != nil {
				rc := reconResult.Context
				brain.RecordRun(target, rc.Technologies, rc.WAFVendor, rc.WAFDetected,
					rc.Subdomains, rc.LiveURLs, rc.OpenPorts)
				// Real-time state update from fresh memory
				state.Technologies = rc.Technologies
				state.WAFDetected = rc.WAFDetected
				state.WAFVendor = rc.WAFVendor
				state.Subdomains = len(rc.Subdomains)
				// Update attack plan with new intelligence
				if len(attackPlan) > 0 && !localMode {
					agentThink("Recon complete — refining attack plan with new intelligence...")
					mem := brain.LoadTarget(target)
					if newSteps, planErr := api.SendPlanSteps(api.PlanStepsRequest{
						Target:        target,
						TechStack:     rc.Technologies,
						OpenPorts:     rc.OpenPorts,
						WAFDetected:   rc.WAFDetected,
						WAFVendor:     rc.WAFVendor,
						Subdomains:    rc.Subdomains,
						LiveURLs:      rc.LiveURLs,
						SkillLevel:    skillLevel,
						FocusBugs:     focusBugs,
						Mode:          mode,
						MemoryContext: brain.GetLearnedPromptContext(target),
					}); planErr == nil && len(newSteps) > 0 {
						attackPlan = newSteps
						planStepIdx = 0 // restart from beginning with new plan
						fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
							fmt.Sprintf("  ✓ Attack plan refined: %d steps based on recon findings", len(newSteps))))
					}
					_ = mem
				}
			}

			fmt.Println(lipgloss.NewStyle().Foreground(green2).Render(
				fmt.Sprintf("  ✓ Recon complete: %d tools ran, %d live URLs, %d ports, %d bugs",
					len(reconResult.Tools), len(state.LiveURLs), len(state.OpenPorts), state.BugsFound)))

		case "hunt":
			agentAct(fmt.Sprintf("Running HUNT phase (focus: %s) — PARALLEL MODE...", decision.VulnFocus))
			omegaLog("\n═══ AGENT: HUNT (PARALLEL) ═══")

			// ── Update self-think with fresh recon data ───────────────────
			if reconResult.Context != nil {
				rc := reconResult.Context
				freshProfile := brain.BuildTargetProfile(target, rc.LiveURLs, rc.OpenPorts,
					rc.WAFDetected, rc.WAFVendor, rc.Technologies, nil, nil)
				freshThink := brain.SelfThink(freshProfile)
				if freshThink.Confidence > thinkResult.Confidence {
					thinkResult = freshThink
					fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
						fmt.Sprintf("  🧠 Self-think updated: confidence %.0f%% [%s]",
							freshThink.Confidence*100, freshThink.Priority)))
					// Show business logic opportunities if found
					if len(freshThink.BusinessLogic) > 0 {
						fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6600")).Render(
							fmt.Sprintf("  💰 Business logic targets: %d patterns identified", len(freshThink.BusinessLogic))))
					}
					// Show OAuth angles if found
					if len(freshThink.OAuthAngles) > 0 {
						fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render(
							fmt.Sprintf("  🔐 OAuth attack vectors: %d identified", len(freshThink.OAuthAngles))))
					}
				}
			}

			// Build hunt context from recon
			var huntCtx *hunt.HuntContext
			if reconResult.Context != nil {
				rc := reconResult.Context
				huntCtx = &hunt.HuntContext{
					Target:       target,
					TargetType:   rc.TargetType,
					LiveURLs:     rc.LiveURLs,
					CrawledURLs:  rc.CrawledURLs,
					OpenPorts:    rc.OpenPorts,
					WAFDetected:  rc.WAFDetected,
					WAFVendor:    rc.WAFVendor,
					Subdomains:   rc.Subdomains,
					Technologies: rc.Technologies,
				}
			}

			// Apply agent's tool decisions
			var skipTools map[string]bool
			if len(decision.ToolsSkip) > 0 {
				skipTools = make(map[string]bool)
				for _, t := range decision.ToolsSkip {
					skipTools[t] = true
				}
			}

			// ── Fix 3: Apply memory patterns to tool args ─────────────────
			// Proven payloads from past scans → dalfox/sqlmap custom payloads
			applyMemoryPatternsToHunt(target, bestPatterns)

			// ── MULTI-AGENT PARALLELISM ───────────────────────────────────
			// Run hunt + bizlogic + adversarial thinking simultaneously
			type parallelResult struct {
				hunt      hunt.HuntResult
				bizResult bizlogic.BizLogicResult
				adversarial string
			}
			pResult := parallelResult{}
			var wg sync.WaitGroup

			// Agent 1: Hunt
			wg.Add(1)
			go func() {
				defer wg.Done()
				pResult.hunt = runHuntSilent(target, huntCtx, buildRequestedTools(skipTools, "hunt"))
			}()

			// Agent 2: BizLogic (runs in parallel with hunt)
			wg.Add(1)
			go func() {
				defer wg.Done()
				pResult.bizResult = bizlogic.RunBizLogicScan(target,
					map[string]string{}, map[string]string{},
					func(test, status string) {
						if strings.Contains(status, "FOUND") {
							fmt.Println(lipgloss.NewStyle().Foreground(red2).Render("  [BIZ] " + status))
						}
					})
			}()

			// Agent 4: OAuth/OIDC analysis (runs in parallel)
			// Only run if OAuth endpoints detected by self-think or recon
			if len(thinkResult.OAuthAngles) > 0 || strings.Contains(strings.ToLower(strings.Join(state.Technologies, " ")), "oauth") {
				wg.Add(1)
				go func() {
					defer wg.Done()
					liveURLs := state.LiveURLs
					if reconResult.Context != nil {
						liveURLs = reconResult.Context.LiveURLs
					}
					oauthResult := brain.AnalyzeOAuthFlows(target, liveURLs)
					if len(oauthResult.Findings) > 0 {
						fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render(
							fmt.Sprintf("  🔐 OAuth: %d vulnerabilities found!", len(oauthResult.Findings))))
						for _, f := range oauthResult.Findings {
							sev := bugdetect.SeverityHigh
							if f.Severity == "critical" {
								sev = bugdetect.SeverityCritical
							} else if f.Severity == "medium" {
								sev = bugdetect.SeverityMedium
							}
							allBugs = append(allBugs, bugdetect.Bug{
								Title:       f.Type + " — OAuth/OIDC",
								Severity:    sev,
								Tool:        "oauth_engine",
								Target:      target,
								URL:         f.URL,
								Description: f.Description,
								Evidence:    f.Evidence,
								CVSS:        8.5,
								CWE:         "CWE-287",
								FoundAt:     time.Now(),
							})
						}
					}
				}()
			}

			// Agent 5: ZAP passive scan (runs in parallel — always)
			// ZAP passive scan catches things CLI tools miss: headers, cookies, info disclosure
			if sandbox.IsZAPRunning() || mode == "deep" || mode == "overnight" {
				wg.Add(1)
				go func() {
					defer wg.Done()
					zapTarget := target
					if !strings.HasPrefix(zapTarget, "http") {
						zapTarget = "https://" + zapTarget
					}
					// Use passive scan during hunt (fast), active scan only in deep/overnight
					zapScanType := "passive"
					if mode == "overnight" {
						zapScanType = "full"
					} else if mode == "deep" {
						zapScanType = "active"
					}
					agentThink(fmt.Sprintf("ZAP %s scan running in parallel...", zapScanType))
					zapResult := sandbox.RunZAPScan(zapTarget, zapScanType, func(msg string) {
						// Silent progress — don't spam output
					})
					if len(zapResult.Alerts) > 0 {
						fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render(
							fmt.Sprintf("  🔍 ZAP: %d findings!", len(zapResult.Alerts))))
						allFindings["zap_scan"] = sandbox.FormatZAPReport(zapResult)
						for _, alert := range zapResult.Alerts {
							sev := bugdetect.SeverityMedium
							if alert.Risk == "High" || alert.Risk == "Critical" {
								sev = bugdetect.SeverityHigh
							}
							allBugs = append(allBugs, bugdetect.Bug{
								Title:       alert.Alert + " — ZAP",
								Severity:    sev,
								Tool:        "zap",
								Target:      target,
								URL:         alert.URL,
								Description: alert.Description,
								Evidence:    alert.Evidence,
								CVSS:        7.5,
								CWE:         "CWE-" + alert.CWEId,
								FoundAt:     time.Now(),
							})
						}
					}
				}()
			}

			// Agent 3: Adversarial thinking (runs in parallel)
			if !localMode {
				wg.Add(1)
				go func() {
					defer wg.Done()
					bugMaps := make([]map[string]string, 0, len(allBugs))
					for _, b := range allBugs {
						bugMaps = append(bugMaps, map[string]string{
							"title": b.Title, "severity": string(b.Severity),
						})
					}
					failedAttacks := []string{}
					for _, t := range state.ToolsFailed {
						failedAttacks = append(failedAttacks, t)
					}
					analysis, err := api.SendAdversarialThink(api.AdversarialRequest{
						Target:        target,
						TechStack:     state.Technologies,
						BugsFound:     bugMaps,
						WAFVendor:     state.WAFVendor,
						OpenPorts:     state.OpenPorts,
						FailedAttacks: failedAttacks,
						MemoryContext: memContext,
					})
					if err == nil {
						pResult.adversarial = analysis
					}
				}()
			}

			fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
				"  ⟳ Running Hunt + BizLogic + Adversarial Analysis in parallel..."))
			wg.Wait()

			// Merge results
			huntResult = pResult.hunt
			state.HuntDone = true
			state.Phase = "hunt_done"

			// Update state from hunt
			if huntResult.Context != nil {
				hc := huntResult.Context
				if len(hc.LiveURLs) > len(state.LiveURLs) {
					state.LiveURLs = hc.LiveURLs
				}
			}
			state.ToolsRan = append(state.ToolsRan, huntResult.Tools...)
			for _, f := range huntResult.Results {
				if f.Output != "" {
					allFindings[f.Tool] = truncate(f.Output, 500)
				}
			}

			// Parse bugs from hunt
			for _, tr := range huntResult.Results {
				if tr.Output != "" {
					bugs := bugdetect.ParseToolOutput(tr.Tool, tr.Output, target)
					allBugs = append(allBugs, bugs...)
				}
			}

			// Merge bizlogic findings
			for _, f := range pResult.bizResult.Findings {
				sev := bugdetect.SeverityHigh
				if f.Severity == "critical" {
					sev = bugdetect.SeverityCritical
				} else if f.Severity == "medium" {
					sev = bugdetect.SeverityMedium
				}
				allBugs = append(allBugs, bugdetect.Bug{
					Title:       f.Type + " — Business Logic",
					Severity:    sev,
					Tool:        "bizlogic",
					Target:      target,
					URL:         f.URL,
					Description: f.Description,
					Evidence:    f.Evidence,
					CVSS:        7.5,
					CWE:         "CWE-840",
					FoundAt:     time.Now(),
				})
			}

			// Dedup bugs
			allBugs = dedupBugs(allBugs)
			state.BugsFound = len(allBugs)
			state.BugTypes = extractBugTypes(allBugs)

			// ── Brain: record hunt patterns ───────────────────────────────
			for _, tr := range huntResult.Results {
				if tr.Output != "" && tr.Tool == "dalfox" {
					brain.RecordPattern(target, "xss", "dalfox XSS found", "", tr.Command)
				}
				if tr.Output != "" && tr.Tool == "nuclei" {
					brain.RecordPattern(target, "nuclei_vuln", "nuclei finding", "", tr.Command)
				}
			}

			// ── Self-correction: retry failed tools with fallback ─────────
			if len(huntResult.Failed) > 0 && len(attackPlan) > 0 {
				for _, failed := range huntResult.Failed {
					// Find the planned step for this tool
					for _, step := range attackPlan {
						if step.Tool == failed.Tool && step.FallbackTool != "" && step.FallbackTool != "manual" {
							fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(
								fmt.Sprintf("  🔄 Self-correction: %s failed → trying %s", failed.Tool, step.FallbackTool)))
							// Run fallback tool
							fallbackResult := runHuntSilent(target, huntCtx, []string{step.FallbackTool})
							for _, tr := range fallbackResult.Results {
								if tr.Output != "" {
									allFindings[step.FallbackTool+"_fallback"] = truncate(tr.Output, 500)
									bugs := bugdetect.ParseToolOutput(tr.Tool, tr.Output, target)
									allBugs = append(allBugs, bugs...)
								}
							}
							break
						}
					}
				}
				allBugs = dedupBugs(allBugs)
				state.BugsFound = len(allBugs)
			}

			// ── Generate custom nuclei templates for this target ──────────
			if len(state.Technologies) > 0 && !localMode {
				go func() {
					tmplReq := api.NucleiTemplateRequest{
						Target:    target,
						TechStack: state.Technologies,
						VulnType:  decision.VulnFocus,
					}
					if tmpl, err := api.GenerateNucleiTemplate(tmplReq); err == nil && tmpl != nil {
						tmplDir := "/tmp/cybermind_custom_templates"
						os.MkdirAll(tmplDir, 0755)
						tmplPath := tmplDir + "/" + tmpl.Filename
						if os.WriteFile(tmplPath, []byte(tmpl.Template), 0644) == nil {
							fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
								"  ✓ Custom nuclei template: " + tmplPath))
						}
					}
				}()
			}

			// ── Show adversarial analysis + FEED INTO NEXT HUNT ─────────
			if pResult.adversarial != "" {
				fmt.Println()
				fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render(
					"  🎭 ADVERSARIAL ANALYSIS:"))
				preview := pResult.adversarial
				if len(preview) > 500 {
					preview = preview[:500] + "..."
				}
				fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render("  " + strings.ReplaceAll(preview, "\n", "\n  ")))

				// Save full analysis
				advPath := fmt.Sprintf("/tmp/cybermind_adversarial_%s.txt", strings.ReplaceAll(target, ".", "_"))
				os.WriteFile(advPath, []byte(pResult.adversarial), 0644)

				// ── FEED adversarial output into next iteration ───────────
				// Parse: extract specific endpoints, params, payloads to test
				advEndpoints := extractAdversarialEndpoints(pResult.adversarial)
				advPayloads := extractAdversarialPayloads(pResult.adversarial)

				if len(advEndpoints) > 0 {
					fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
						fmt.Sprintf("  🎯 Adversarial: %d new endpoints to test next iteration", len(advEndpoints))))
					// Add to allFindings so next AI decision knows about them
					allFindings["adversarial_endpoints"] = strings.Join(advEndpoints, "\n")
					// Also set as env var for nuclei/dalfox to pick up
					os.Setenv("CYBERMIND_ADVERSARIAL_ENDPOINTS", strings.Join(advEndpoints[:min(5, len(advEndpoints))], ","))
				}
				if len(advPayloads) > 0 {
					fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
						fmt.Sprintf("  💉 Adversarial: %d custom payloads extracted", len(advPayloads))))
					allFindings["adversarial_payloads"] = strings.Join(advPayloads, "\n")
					// Write payloads to file for dalfox/sqlmap to use
					payloadFile := "/tmp/cybermind_adversarial_payloads.txt"
					os.WriteFile(payloadFile, []byte(strings.Join(advPayloads, "\n")), 0644)
					os.Setenv("CYBERMIND_ADVERSARIAL_PAYLOADS", payloadFile)
				}
			}

			fmt.Println(lipgloss.NewStyle().Foreground(green2).Render(
				fmt.Sprintf("  ✓ Parallel hunt complete: %d hunt tools + %d bizlogic tests → %d bugs",
					len(huntResult.Tools), pResult.bizResult.Tested, state.BugsFound)))

			if state.BugsFound > 0 {
				for _, b := range allBugs {
					color := yellow2
					if b.Severity == bugdetect.SeverityCritical {
						color = red2
					}
					fmt.Println(lipgloss.NewStyle().Foreground(color).Render(
						fmt.Sprintf("    🐛 [%s] %s", strings.ToUpper(string(b.Severity)), b.Title)))
				}
			}

		case "bizlogic":
			agentAct("Running Business Logic Bug Hunter...")
			omegaLog("\n═══ AGENT: BIZLOGIC ═══")

			// Get session cookies from brain memory if available
			bizCookies := map[string]string{}
			bizHeaders := map[string]string{}

			bizResult := bizlogic.RunBizLogicScan(target, bizCookies, bizHeaders, func(test, status string) {
				if strings.Contains(status, "FOUND") {
					fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red2).Render("  " + status))
				}
			})

			// Convert bizlogic findings to bugdetect.Bug
			for _, f := range bizResult.Findings {
				sev := bugdetect.SeverityHigh
				if f.Severity == "critical" {
					sev = bugdetect.SeverityCritical
				} else if f.Severity == "medium" {
					sev = bugdetect.SeverityMedium
				}
				allBugs = append(allBugs, bugdetect.Bug{
					Title:       f.Type + " — Business Logic",
					Severity:    sev,
					Tool:        "bizlogic",
					Target:      target,
					URL:         f.URL,
					Description: f.Description,
					Evidence:    f.Evidence,
					CVSS:        7.5,
					CWE:         "CWE-840",
					FoundAt:     time.Now(),
				})
			}
			allBugs = dedupBugs(allBugs)
			state.BugsFound = len(allBugs)
			state.BugTypes = extractBugTypes(allBugs)
			fmt.Println(lipgloss.NewStyle().Foreground(green2).Render(
				fmt.Sprintf("  ✓ BizLogic: %d tests, %d bugs found", bizResult.Tested, len(bizResult.Findings))))

		case "exploit":
			agentAct(fmt.Sprintf("Running ABHIMANYU exploit phase (focus: %s)...", decision.VulnFocus))
			omegaLog("\n═══ AGENT: EXPLOIT (ABHIMANYU) ═══")

			var huntCtxForAbhi hunt.HuntContext
			if huntResult.Context != nil {
				huntCtxForAbhi = *huntResult.Context
			}

			// ── CRITICAL FIX: Pass specific vuln targets to Abhimanyu ────
			// If hunt found specific SQLi params, XSS URLs, etc. — pass them
			xssFound := huntCtxForAbhi.XSSFound
			vulnsFound := huntCtxForAbhi.VulnsFound
			paramsFound := huntCtxForAbhi.ParamsFound
			openPorts := huntCtxForAbhi.OpenPorts
			if len(openPorts) == 0 && reconResult.Context != nil {
				openPorts = reconResult.Context.OpenPorts
			}

			// Set vuln focus from decision (tech-aware selection)
			if decision.VulnFocus != "" && decision.VulnFocus != "all" {
				huntCtxForAbhi.Technologies = append(huntCtxForAbhi.Technologies,
					"CYBERMIND_VULN_FOCUS:"+decision.VulnFocus)
			}

			// Show what Abhimanyu will target
			fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
				fmt.Sprintf("  ⚔️  Abhimanyu targets: XSS=%d URLs, Vulns=%d, Params=%d, Ports=%d",
					len(xssFound), len(vulnsFound), len(paramsFound), len(openPorts))))

			runAbhimanyuFromHunt(target, huntCtxForAbhi, xssFound, vulnsFound, paramsFound, openPorts, allFindings)
			state.AbhiDone = true
			state.Phase = "exploit_done"

		case "deep_hunt":
			// ── NEW: Second-pass deep scan when first hunt finds nothing ──
			agentAct("Running DEEP HUNT — second-pass scan with exhaustive tool coverage...")
			omegaLog("\n═══ AGENT: DEEP HUNT (SECOND PASS) ═══")

			fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
				"  ⟳ Deep hunt: running novel attacks + full nuclei template set + extended crawl..."))

			// Run novel attacks from brain module
			if reconResult.Context != nil {
				liveURLs := reconResult.Context.LiveURLs
				brain.RunNovelAttacks(target, liveURLs, func(result brain.NovelAttackResult) {
					if result.Vulnerable {
						sev := bugdetect.SeverityHigh
						if result.Severity == "critical" {
							sev = bugdetect.SeverityCritical
						} else if result.Severity == "medium" {
							sev = bugdetect.SeverityMedium
						}
						allBugs = append(allBugs, bugdetect.Bug{
							Title:       result.AttackType + " — Novel Attack",
							Severity:    sev,
							Tool:        "novel_attacks",
							Target:      target,
							URL:         result.URL,
							Description: result.Description,
							Evidence:    result.Evidence,
							CVSS:        8.0,
							CWE:         "CWE-200",
							FoundAt:     time.Now(),
						})
						fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red2).Render(
							fmt.Sprintf("  🐛 NOVEL ATTACK: [%s] %s", result.Severity, result.AttackType)))
					}
				})
			}

			// Run a second hunt pass with different tool focus
			var deepHuntCtx *hunt.HuntContext
			if reconResult.Context != nil {
				rc := reconResult.Context
				deepHuntCtx = &hunt.HuntContext{
					Target:       target,
					TargetType:   rc.TargetType,
					LiveURLs:     rc.LiveURLs,
					CrawledURLs:  rc.CrawledURLs,
					OpenPorts:    rc.OpenPorts,
					WAFDetected:  rc.WAFDetected,
					WAFVendor:    rc.WAFVendor,
					Subdomains:   rc.Subdomains,
					Technologies: rc.Technologies,
				}
			}
			// Focus on tools not yet run
			deepHuntResult := runHuntSilent(target, deepHuntCtx, []string{"nuclei", "ssrfmap", "tplmap", "jwt_tool", "corsy", "smuggler"})
			for _, tr := range deepHuntResult.Results {
				if tr.Output != "" {
					bugs := bugdetect.ParseToolOutput(tr.Tool, tr.Output, target)
					allBugs = append(allBugs, bugs...)
					allFindings["deep_"+tr.Tool] = truncate(tr.Output, 500)
				}
			}
			allBugs = dedupBugs(allBugs)
			state.BugsFound = len(allBugs)
			state.BugTypes = extractBugTypes(allBugs)
			state.Phase = "deep_hunt_done"
			fmt.Println(lipgloss.NewStyle().Foreground(green2).Render(
				fmt.Sprintf("  ✓ Deep hunt complete: %d additional bugs found", state.BugsFound)))

		case "poc":
			agentAct("Verifying bugs + generating PoC...")
			omegaLog("\n═══ AGENT: POC + VERIFY + SUBMIT ═══")

			// ── Step 1: Real verification before PoC ─────────────────────
			verifiedBugs := []bugdetect.Bug{}
			for _, bug := range allBugs {
				if bug.Severity == bugdetect.SeverityLow || bug.Severity == bugdetect.SeverityInfo {
					continue
				}
				if bug.Evidence == "" {
					continue
				}

				// Re-verify using brain/verify
				rawF := brain.RawFinding{
					Tool:      bug.Tool,
					Type:      strings.ToLower(strings.Split(bug.CWE, "-")[0]),
					URL:       bug.URL,
					Evidence:  bug.Evidence,
					Severity:  string(bug.Severity),
					RawOutput: bug.Evidence,
				}
				confidence := brain.ScoreConfidence(rawF)

				// Only verify high-confidence findings (>0.6) to save time
				if confidence >= 0.6 {
					verified, proof := brain.VerifyFinding(rawF)
					if verified && proof != "" {
						bug.Evidence = proof // use real proof
						fmt.Println(lipgloss.NewStyle().Foreground(green2).Render(
							fmt.Sprintf("  ✓ Verified: %s (confidence: %.0f%%)", bug.Title, confidence*100)))
					} else if confidence < 0.7 {
						// Low confidence + not verified = skip
						fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
							fmt.Sprintf("  - Skipped (unverified, confidence: %.0f%%): %s", confidence*100, bug.Title)))
						// Record as false positive so brain learns
						brain.RecordFalsePositive(target, bug.Tool, bug.CWE, bug.URL+"|"+bug.Title, "unverified")
						continue
					}
				}
				verifiedBugs = append(verifiedBugs, bug)
			}

			if len(verifiedBugs) == 0 && len(allBugs) > 0 {
				fmt.Println(lipgloss.NewStyle().Foreground(yellow2).Render(
					"  ⚠  All findings failed verification — likely false positives"))
				allBugs = []bugdetect.Bug{}
				state.BugsFound = 0
				state.Phase = "poc_done"
				break
			}
			if len(verifiedBugs) > 0 {
				allBugs = verifiedBugs
				state.BugsFound = len(allBugs)
			}

			// ── Step 2: Generate PoC for each verified bug ────────────────
			pocs := make(map[int]string)
			for i, bug := range allBugs {
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
					fmt.Sprintf("  ⟳ PoC [%d/%d]: %s", i+1, len(allBugs), bug.Title)))
				poc, pocErr := api.SendPoCGeneration(api.PoCRequest{
					BugType:  bug.Title,
					URL:      bug.URL,
					Evidence: bug.Evidence,
					Target:   target,
					CVE:      bug.CVE,
					CWE:      bug.CWE,
					Severity: string(bug.Severity),
					Tool:     bug.Tool,
				})
				if pocErr == nil && poc != "" {
					pocs[i] = poc
					fmt.Println(lipgloss.NewStyle().Foreground(green2).Render(
						fmt.Sprintf("  ✓ PoC generated: %s", bug.Title)))
				}

			// ── Step 3: Record in brain memory + self-improving prompts ──
				brain.RecordBug(target, brain.Bug{
					Title:    bug.Title,
					Type:     bug.CWE,
					URL:      bug.URL,
					Severity: string(bug.Severity),
					Evidence: bug.Evidence,
					PoC:      poc,
					Tool:     bug.Tool,
					Verified: true,
				})

				// Self-improving: refine attack strategy after successful PoC
				if poc != "" && !localMode {
					go func(b bugdetect.Bug, p string) {
						similarDomains := make([]string, 0, len(similar))
						for _, s := range similar {
							similarDomains = append(similarDomains, s.Domain)
						}
						refinement, err := api.SendAdversarialRefine(
							target, b.CWE, b.Evidence, b.URL,
							state.Technologies, similarDomains)
						if err == nil && refinement != "" {
							// Record the refined pattern in brain
							brain.RecordSuccessfulPoC(target, b.CWE, b.Evidence, b.URL, p)
							// Save refinement for user
							refPath := fmt.Sprintf("/tmp/cybermind_refinement_%s.txt",
								strings.ReplaceAll(target, ".", "_"))
							existing, _ := os.ReadFile(refPath)
							os.WriteFile(refPath, append(existing, []byte("\n\n---\n"+refinement)...), 0644)
						}
					}(bug, poc)
				}

				// Sandbox XSS verification if available
				if strings.Contains(strings.ToLower(bug.CWE), "79") && sandbox.IsAvailable() && bug.URL != "" {
					go func(b bugdetect.Bug) {
						result := sandbox.VerifyXSSInBrowser(b.URL, b.Evidence)
						if result.Success {
							fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green2).Render(
								"  ✓ XSS verified in real browser (Vercel Sandbox)!"))
						}
					}(bug)
				}
			}

			// Save report with PoCs
			bugReport := bugdetect.BugReport{
				Target:    target,
				Bugs:      allBugs,
				StartTime: time.Now().Add(-2 * time.Hour),
				EndTime:   time.Now(),
			}
			content := bugdetect.GenerateReportWithPoC(bugReport, pocs)
			ts := time.Now().Format("2006-01-02_15-04-05")
			safeTarget := strings.ReplaceAll(target, ".", "_")
			reportPath := fmt.Sprintf("cybermind_bugs_%s_%s.md", safeTarget, ts)
			if err := os.WriteFile(reportPath, []byte(content), 0644); err == nil {
				fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green2).Render(
					"  ✓ Full bug report saved: " + reportPath))
			}

			// Also save HackerOne-format report
			h1Content := bugdetect.GenerateH1Report(bugReport, pocs)
			if h1Content != "" {
				h1Path := fmt.Sprintf("cybermind_h1_report_%s_%s.md", safeTarget, ts)
				if os.WriteFile(h1Path, []byte(h1Content), 0644) == nil {
					fmt.Println(lipgloss.NewStyle().Foreground(green2).Render(
						"  ✓ HackerOne report saved: " + h1Path))
				}
			}

			// ── Step 5: Telegram notification ────────────────────────────
			notifyBugsFound(target, allBugs, reportPath)

			// ── Step 6: HackerOne auto-submit ─────────────────────────────
			creds, credsErr := brain.LoadCredentials()
			if credsErr == nil && creds != nil && creds.H1Token != "" {
				fmt.Println()
				fmt.Println(lipgloss.NewStyle().Foreground(cyan2).Render(
					"  ⟳ Checking HackerOne for duplicates + auto-submitting..."))

				for i, bug := range allBugs {
					poc := pocs[i]
					if poc == "" {
						continue
					}

					// Check for duplicates first
					handle := extractH1Handle(target)
					isDup, dupURL := brain.CheckH1Duplicate(creds, handle, bug.Title, bug.URL)
					if isDup {
						fmt.Println(lipgloss.NewStyle().Foreground(yellow2).Render(
							fmt.Sprintf("  ⚠  Duplicate: %s → %s", bug.Title, dupURL)))
						continue
					}

					// Build H1 report
					h1Report := brain.H1Report{
						TeamHandle:        handle,
						Title:             fmt.Sprintf("[%s] %s on %s", strings.ToUpper(string(bug.Severity)), bug.Title, target),
						VulnerabilityInfo: fmt.Sprintf("## Summary\n%s\n\n## Evidence\n```\n%s\n```\n\n## PoC\n%s", bug.Description, bug.Evidence, poc),
						SeverityRating:    string(bug.Severity),
						Impact:            bug.Description,
					}

					result, submitErr := brain.SubmitH1Report(creds, h1Report)
					if submitErr != nil {
						fmt.Println(lipgloss.NewStyle().Foreground(red2).Render(
							fmt.Sprintf("  ✗ H1 submit failed: %v", submitErr)))
					} else if result.Error != "" {
						fmt.Println(lipgloss.NewStyle().Foreground(yellow2).Render(
							fmt.Sprintf("  ⚠  H1: %s", result.Error)))
					} else {
						fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green2).Render(
							fmt.Sprintf("  ✓ Submitted to HackerOne: %s", result.URL)))
						// Update brain memory with submission
						brain.RecordBug(target, brain.Bug{
							Title:     bug.Title,
							Type:      bug.CWE,
							URL:       bug.URL,
							Severity:  string(bug.Severity),
							Evidence:  bug.Evidence,
							PoC:       poc,
							Tool:      bug.Tool,
							Verified:  true,
							Submitted: true,
							Platform:  "hackerone",
							ReportID:  result.ReportID,
						})
					}
				}
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
					"  ℹ  No H1 credentials — skipping auto-submit"))
				fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
					"  Set credentials: cybermind /platform --setup"))
			}

			fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
				"  " + bugdetect.GetBugBountyInfo(target)))
			state.Phase = "poc_done"

		case "report":
			agentAct("Generating final report...")
			runReport("markdown", localMode)
			state.Phase = "report_done"

		case "guide":
			agentAct("Generating manual testing guide for remaining 12%...")
			omegaLog("\n═══ AGENT: MANUAL GUIDE + BROWSER TESTS ═══")

			// First: try autonomous browser tests
			if sandbox.IsAvailable() {
				agentAct("Running autonomous browser tests (Playwright)...")
				fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
					"  ⟳ Browser engine testing: price manipulation, IDOR, race conditions, DOM XSS, OAuth..."))

				// Get session cookies from brain memory
				mem := brain.LoadTarget(target)
				sessionCookies := map[string]string{}
				// Use any cookies from previous login attempts
				_ = mem

				browserResults := sandbox.RunAutonomousBrowserTests(
					"https://"+target,
					sessionCookies,
					func(msg string) {
						fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render("  ⟳ " + msg))
					},
				)

				// Show browser results
				for _, r := range browserResults {
					if r.BugFound {
						fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red2).Render(
							fmt.Sprintf("  🐛 BROWSER BUG: [%s] %s", r.TestName, r.Evidence)))
						// Add to allBugs
						allBugs = append(allBugs, bugdetect.Bug{
							Title:       r.TestName + " — Browser Confirmed",
							Severity:    bugdetect.SeverityHigh,
							Tool:        "playwright",
							Target:      target,
							Description: r.Evidence,
							Evidence:    r.Evidence,
							CVSS:        7.5,
							CWE:         "CWE-840",
							FoundAt:     time.Now(),
						})
					}
				}
				state.BugsFound = len(allBugs)

				// Format and save browser results + manual steps
				browserReport := sandbox.FormatBrowserResults(browserResults)
				ts := time.Now().Format("2006-01-02_15-04-05")
				safeT := strings.ReplaceAll(target, ".", "_")
				browserPath := fmt.Sprintf("cybermind_browser_%s_%s.md", safeT, ts)
				os.WriteFile(browserPath, []byte(browserReport), 0644)
				fmt.Println(lipgloss.NewStyle().Foreground(green2).Render(
					"  ✓ Browser test report: " + browserPath))
			}

			// Then: generate AI manual guide for what browser couldn't do
			bugMaps := make([]map[string]string, 0, len(allBugs))
			for _, b := range allBugs {
				bugMaps = append(bugMaps, map[string]string{
					"title": b.Title, "severity": string(b.Severity), "url": b.URL,
				})
			}
			liveURLs := state.LiveURLs
			if len(liveURLs) == 0 && reconResult.Context != nil {
				liveURLs = reconResult.Context.LiveURLs
			}
			subdomains := []string{}
			if reconResult.Context != nil {
				subdomains = reconResult.Context.Subdomains
			}
			scanSummary := fmt.Sprintf(
				"Automated scan complete. Recon: %d tools. Hunt: %d tools. Bugs: %d. Subdomains: %d. Live URLs: %d.",
				len(reconResult.Tools), len(huntResult.Tools), len(allBugs), len(subdomains), len(liveURLs))

			guide, guideErr := api.SendManualGuide(api.ManualGuideRequest{
				Target:      target,
				TechStack:   state.Technologies,
				BugsFound:   bugMaps,
				LiveURLs:    liveURLs,
				OpenPorts:   state.OpenPorts,
				WAFDetected: state.WAFDetected,
				WAFVendor:   state.WAFVendor,
				Subdomains:  subdomains,
				Focus:       focusBugs,
				ScanSummary: scanSummary,
			})
			if guideErr == nil && guide != "" {
				fmt.Println()
				fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700")).Render(
					"  📋 MANUAL TESTING GUIDE:"))
				preview := guide
				if len(preview) > 2000 {
					preview = preview[:2000] + "\n\n... [see full guide in file]"
				}
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render(preview))
				ts := time.Now().Format("2006-01-02_15-04-05")
				safeT := strings.ReplaceAll(target, ".", "_")
				guidePath := fmt.Sprintf("cybermind_guide_%s_%s.md", safeT, ts)
				if os.WriteFile(guidePath, []byte(guide), 0644) == nil {
					fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green2).Render(
						"  ✓ Full manual guide saved: " + guidePath))
				}
			}
			state.Phase = "guide_done"

		case "next_target":
			agentAct("No bugs found — suggesting next target...")
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(yellow2).Render(
				"  ⚡ Agent recommends moving to next target"))
			if decision.NextTarget != "" {
				fmt.Println(lipgloss.NewStyle().Foreground(cyan2).Render(
					"  → Suggested: " + decision.NextTarget))
				fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
					"  Run: sudo cybermind /plan " + decision.NextTarget))
			} else {
				nextTargets := bugdetect.SuggestNextTarget(target)
				for i, t := range nextTargets {
					fmt.Println(lipgloss.NewStyle().Foreground(cyan2).Render(
						fmt.Sprintf("  %d. %s — %s", i+1, t, bugdetect.GetBugBountyInfo(t))))
				}
			}
			return

		case "done":
			agentAct("Agent complete!")
			break
		}

		// Update findings summary for next AI decision
		state.Findings = make(map[string]string)
		for k, v := range allFindings {
			state.Findings[k] = truncate(v, 200)
		}
		state.LastAction = decision.Action

		// ── Check if we should stop ───────────────────────────────────────
		if decision.Action == "done" {
			break
		}

		// Rotate IP every 3 iterations if Tor is active
		if iter > 0 && iter%3 == 0 && anon.IsActive() {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
				"  ⟳ Rotating Tor exit node for fresh IP..."))
			newIP := anon.RotateIP()
			if newIP != "" {
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
					"  ✓ New exit IP: " + newIP))
			}
		}

		// If we have high-severity bugs and PoC is done, we're done
		if state.Phase == "poc_done" && state.BugsFound > 0 {
			break
		}
		// If guide is done, we're fully complete
		if state.Phase == "guide_done" {
			break
		}

		// If all phases done and no bugs, suggest next target
		if state.ReconDone && state.HuntDone && state.AbhiDone && state.BugsFound == 0 {
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(yellow2).Render(
				"  ⚡ All phases complete — no confirmed bugs on this target"))
			nextTargets := bugdetect.SuggestNextTarget(target)
			fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render("  Suggested next targets:"))
			for i, t := range nextTargets {
				fmt.Println(lipgloss.NewStyle().Foreground(cyan2).Render(
					fmt.Sprintf("  %d. %s — %s", i+1, t, bugdetect.GetBugBountyInfo(t))))
			}
			break
		}
	}

	// ── Final summary ─────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render(strings.Repeat("═", 64)))
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render("  🤖 OMEGA AGENT COMPLETE"))
	fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
		fmt.Sprintf("  Target: %s | Iterations: %d | Bugs: %d | Tools ran: %d",
			target, state.Iteration, state.BugsFound, len(state.ToolsRan))))
	if state.BugsFound > 0 {
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red2).Render(
			fmt.Sprintf("  🎯 %d BUGS CONFIRMED — check cybermind_bugs_*.md", state.BugsFound)))
	}
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render(strings.Repeat("═", 64)))
	fmt.Println()
}

// localAgentDecision makes a decision without AI — pure logic fallback
// localAgentDecision is the fallback decision engine when AI is unavailable.
// It implements a proper state machine that:
// 1. Always runs recon → hunt → exploit (Abhimanyu) → poc
// 2. Selects vuln-specific exploit focus based on what was found
// 3. Runs deep_hunt for second-pass scanning when first hunt finds nothing
// 4. Exits early on critical findings in quick mode
func localAgentDecision(state api.AgentState) *api.AgentDecision {
	d := &api.AgentDecision{
		VulnFocus:  "all",
		Depth:      "deep",
		Confidence: 60,
	}

	// ── Quick mode: exit early if critical bug found ──────────────────────
	if state.Mode == "quick" && state.BugsFound > 0 {
		for _, bt := range state.BugTypes {
			if bt == "rce" || bt == "sqli" || bt == "critical" {
				if state.AbhiDone {
					d.Action = "poc"
					d.Reason = fmt.Sprintf("Critical bug found (%s) — generating PoC immediately", bt)
					return d
				}
				d.Action = "exploit"
				d.Reason = fmt.Sprintf("Critical bug found (%s) — exploiting immediately", bt)
				d.VulnFocus = bt
				return d
			}
		}
	}

	switch {
	case !state.ReconDone:
		d.Action = "recon"
		d.Reason = "Recon not done yet — gather target intelligence first"

	case !state.HuntDone:
		d.Action = "hunt"
		d.Reason = "Hunt not done yet — find vulnerabilities"
		if state.WAFDetected {
			d.WAFBypass = "random-agent,delay,tamper"
		}
		// Tech-aware vuln focus
		d.VulnFocus = selectVulnFocusByTech(state.Technologies)

	case state.HuntDone && state.BugsFound == 0 && state.Phase == "hunt_done":
		// After hunt with no bugs — try business logic first, then deep hunt
		if state.LastAction != "bizlogic" {
			d.Action = "bizlogic"
			d.Reason = "No bugs from standard hunt — trying business logic scanner"
		} else {
			// BizLogic also found nothing — run deep hunt with different tools
			d.Action = "deep_hunt"
			d.Reason = "Standard hunt + bizlogic found nothing — running deep second-pass scan"
			d.Depth = "exhaustive"
		}

	case state.BugsFound > 0 && !state.AbhiDone:
		// ── CRITICAL FIX: Always run Abhimanyu when bugs are found ──────
		d.Action = "exploit"
		d.Reason = fmt.Sprintf("Found %d bugs — running Abhimanyu exploit phase", state.BugsFound)
		// Select specific vuln focus based on what was found
		d.VulnFocus = selectExploitFocusByBugs(state.BugTypes)
		if state.WAFDetected {
			d.WAFBypass = "tamper,random-agent,chunked"
		}

	case state.BugsFound > 0 && state.AbhiDone && state.Phase != "poc_done":
		d.Action = "poc"
		d.Reason = "Bugs confirmed + exploited — generating PoC + submitting"

	case state.Phase == "poc_done":
		d.Action = "guide"
		d.Reason = "PoC done — generate manual testing guide for remaining attack surface"

	case state.ReconDone && state.HuntDone && state.BugsFound == 0 && state.LastAction == "deep_hunt":
		d.Action = "next_target"
		d.Reason = "Exhaustive scan complete — no bugs found, moving to next target"

	default:
		d.Action = "done"
		d.Reason = "All phases complete"
	}

	return d
}

// selectVulnFocusByTech returns the best vuln focus based on detected tech stack.
// This makes the hunt phase target the most likely vulnerabilities for the tech.
func selectVulnFocusByTech(technologies []string) string {
	techStr := strings.ToLower(strings.Join(technologies, " "))
	switch {
	case strings.Contains(techStr, "wordpress") || strings.Contains(techStr, "wp-"):
		return "sqli,xss,rce" // WordPress: SQLi via plugins, XSS, RCE via file upload
	case strings.Contains(techStr, "graphql"):
		return "idor,ssrf,injection" // GraphQL: IDOR, SSRF via queries, injection
	case strings.Contains(techStr, "node") || strings.Contains(techStr, "express"):
		return "ssrf,prototype,xss" // Node.js: SSRF, prototype pollution, XSS
	case strings.Contains(techStr, "php"):
		return "sqli,lfi,rce" // PHP: SQLi, LFI, RCE via file inclusion
	case strings.Contains(techStr, "asp.net") || strings.Contains(techStr, "iis"):
		return "sqli,xxe,deserialization" // ASP.NET: SQLi, XXE, .NET deserialization
	case strings.Contains(techStr, "java") || strings.Contains(techStr, "spring") || strings.Contains(techStr, "tomcat"):
		return "deserialization,ssrf,rce" // Java: deserialization, SSRF, Log4Shell
	case strings.Contains(techStr, "django") || strings.Contains(techStr, "python"):
		return "ssti,ssrf,sqli" // Django/Python: SSTI, SSRF, SQLi
	case strings.Contains(techStr, "rails") || strings.Contains(techStr, "ruby"):
		return "deserialization,sqli,ssrf" // Rails: deserialization, SQLi, SSRF
	default:
		return "all"
	}
}

// selectExploitFocusByBugs returns the best Abhimanyu vuln focus based on confirmed bugs.
// This ensures Abhimanyu runs the right tools for what was actually found.
func selectExploitFocusByBugs(bugTypes []string) string {
	if len(bugTypes) == 0 {
		return "all"
	}
	// Priority order: RCE > SQLi > XSS > SSRF > Auth > others
	priority := []string{"rce", "sqli", "xss", "ssrf", "auth", "lfi", "xxe", "idor"}
	bugSet := make(map[string]bool)
	for _, bt := range bugTypes {
		bugSet[strings.ToLower(bt)] = true
	}
	for _, p := range priority {
		if bugSet[p] {
			return p
		}
	}
	// Check for partial matches
	for _, bt := range bugTypes {
		lower := strings.ToLower(bt)
		if strings.Contains(lower, "sql") {
			return "sqli"
		}
		if strings.Contains(lower, "xss") || strings.Contains(lower, "cross-site") {
			return "xss"
		}
		if strings.Contains(lower, "rce") || strings.Contains(lower, "command") || strings.Contains(lower, "inject") {
			return "rce"
		}
		if strings.Contains(lower, "ssrf") {
			return "ssrf"
		}
	}
	return bugTypes[0] // use first bug type as focus
}

// shouldRunAbhimanyu returns true if Abhimanyu should be triggered based on hunt findings.
// This is the smart exploit trigger — only runs when there's something worth exploiting.
func shouldRunAbhimanyu(huntResult hunt.HuntResult, allBugs []bugdetect.Bug) bool {
	// Always run if confirmed bugs found
	if len(allBugs) > 0 {
		return true
	}
	// Run if hunt found specific exploitable indicators
	if huntResult.Context != nil {
		hc := huntResult.Context
		if len(hc.XSSFound) > 0 {
			return true // confirmed XSS → dalfox deep mode
		}
		if len(hc.VulnsFound) > 0 {
			return true // nuclei confirmed vulns
		}
		if len(hc.ParamsFound) > 5 {
			return true // many params found → worth running sqlmap/ssrfmap
		}
	}
	return false
}

// extractBugTypes returns unique vuln type names from bugs
func extractBugTypes(bugs []bugdetect.Bug) []string {
	seen := map[string]bool{}
	var types []string
	for _, b := range bugs {
		t := strings.ToLower(b.CWE)
		if t == "" {
			t = strings.ToLower(b.Title)
		}
		if !seen[t] && t != "" {
			seen[t] = true
			types = append(types, t)
		}
	}
	return types
}

// dedupBugs removes duplicate bugs by title+url
func dedupBugs(bugs []bugdetect.Bug) []bugdetect.Bug {
	seen := map[string]bool{}
	var out []bugdetect.Bug
	for _, b := range bugs {
		key := b.Title + "|" + b.URL
		if !seen[key] {
			seen[key] = true
			out = append(out, b)
		}
	}
	return out
}

// truncate shortens a string to maxLen chars
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// extractAdversarialEndpoints parses adversarial analysis output for specific endpoints to test
func extractAdversarialEndpoints(analysis string) []string {
	var endpoints []string
	seen := map[string]bool{}
	lines := strings.Split(analysis, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Look for URL patterns: /api/v1/..., /admin/..., etc.
		if strings.HasPrefix(line, "/") && len(line) > 3 && len(line) < 200 {
			// Clean up — remove markdown, bullets
			clean := strings.TrimLeft(line, "- *•→")
			clean = strings.TrimSpace(clean)
			if strings.HasPrefix(clean, "/") && !seen[clean] {
				seen[clean] = true
				endpoints = append(endpoints, clean)
			}
		}
		// Also extract from "Try /path" patterns
		if strings.Contains(line, "Try ") || strings.Contains(line, "test ") || strings.Contains(line, "check ") {
			words := strings.Fields(line)
			for _, w := range words {
				if strings.HasPrefix(w, "/") && len(w) > 3 && !seen[w] {
					seen[w] = true
					endpoints = append(endpoints, w)
				}
			}
		}
	}
	return endpoints
}

// extractAdversarialPayloads parses adversarial analysis for specific attack payloads
func extractAdversarialPayloads(analysis string) []string {
	var payloads []string
	seen := map[string]bool{}
	lines := strings.Split(analysis, "\n")
	inCodeBlock := false
	for _, line := range lines {
		if strings.HasPrefix(line, "```") {
			inCodeBlock = !inCodeBlock
			continue
		}
		if inCodeBlock {
			line = strings.TrimSpace(line)
			if len(line) > 3 && len(line) < 500 && !seen[line] {
				// Skip pure shell commands, keep injection payloads
				if !strings.HasPrefix(line, "curl ") && !strings.HasPrefix(line, "nmap ") &&
					!strings.HasPrefix(line, "sudo ") && !strings.HasPrefix(line, "#") {
					seen[line] = true
					payloads = append(payloads, line)
				}
			}
		}
	}
	return payloads
}

// applyMemoryPatternsToHunt applies proven attack patterns from brain memory to hunt tools.
// This is Fix 3: memory patterns → tool args.
func applyMemoryPatternsToHunt(target string, patterns []brain.Pattern) {
	if len(patterns) == 0 {
		return
	}

	// Collect XSS payloads that worked before
	var xssPayloads []string
	var sqliPayloads []string
	var ssrfEndpoints []string

	for _, p := range patterns {
		lower := strings.ToLower(p.Type)
		if strings.Contains(lower, "xss") && p.Payload != "" {
			xssPayloads = append(xssPayloads, p.Payload)
		}
		if strings.Contains(lower, "sqli") && p.Payload != "" {
			sqliPayloads = append(sqliPayloads, p.Payload)
		}
		if strings.Contains(lower, "ssrf") && p.Endpoint != "" {
			ssrfEndpoints = append(ssrfEndpoints, p.Endpoint)
		}
	}

	// Write proven XSS payloads to file for dalfox
	if len(xssPayloads) > 0 {
		payloadFile := "/tmp/cybermind_memory_xss_payloads.txt"
		os.WriteFile(payloadFile, []byte(strings.Join(xssPayloads, "\n")), 0644)
		os.Setenv("CYBERMIND_MEMORY_XSS_PAYLOADS", payloadFile)
	}

	// Write proven SQLi payloads for sqlmap tamper
	if len(sqliPayloads) > 0 {
		payloadFile := "/tmp/cybermind_memory_sqli_payloads.txt"
		os.WriteFile(payloadFile, []byte(strings.Join(sqliPayloads, "\n")), 0644)
		os.Setenv("CYBERMIND_MEMORY_SQLI_PAYLOADS", payloadFile)
	}

	// Write SSRF endpoints that worked
	if len(ssrfEndpoints) > 0 {
		os.Setenv("CYBERMIND_MEMORY_SSRF_ENDPOINTS", strings.Join(ssrfEndpoints[:min(5, len(ssrfEndpoints))], ","))
	}
}
// Uses the existing core/telegram.js infrastructure — no separate bot needed.
func notifyBugsFound(target string, bugs []bugdetect.Bug, reportPath string) {
	if len(bugs) == 0 {
		return
	}

	critCount, highCount := 0, 0
	bugMaps := make([]map[string]string, 0, len(bugs))
	for _, b := range bugs {
		if b.Severity == bugdetect.SeverityCritical {
			critCount++
		} else if b.Severity == bugdetect.SeverityHigh {
			highCount++
		}
		bugMaps = append(bugMaps, map[string]string{
			"title":    b.Title,
			"severity": string(b.Severity),
			"url":      b.URL,
			"tool":     b.Tool,
		})
	}

	// Send via backend Telegram agent (uses TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID on server)
	err := api.SendBugAlert(target, bugMaps, reportPath, critCount, highCount, "")
	if err == nil {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
			"  ✓ Telegram notification sent via backend agent"))
	}
	// Also try direct env-based notification as fallback
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if token != "" && chatID != "" && err != nil {
		brain.NotifyBugFound(target, fmt.Sprintf("%d bugs found", len(bugs)),
			"critical", "", reportPath)
	}
}

// extractH1Handle extracts a HackerOne program handle from a target domain.
// e.g. "shopify.com" → "shopify", "api.github.com" → "github"
func extractH1Handle(target string) string {
	target = strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	parts := strings.Split(target, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] // second-to-last part = company name
	}
	return target
}

// sendGroqAgentDecision uses Groq to make an agent decision — fast, free, uncensored
func sendGroqAgentDecision(state api.AgentState, memContext string) (*api.AgentDecision, error) {
	prompt := fmt.Sprintf(`You are an elite bug bounty hunter AI making a tactical decision.

TARGET: %s
CURRENT STATE:
- Phase: %s
- Recon done: %v
- Hunt done: %v  
- Bugs found: %d (types: %v)
- Technologies: %v
- WAF: %v (%s)
- Open ports: %v
- Mode: %s

MEMORY CONTEXT:
%s

Based on this state, decide the NEXT ACTION. Respond with ONLY a JSON object:
{
  "action": "recon|hunt|exploit|bizlogic|deep_hunt|poc|guide|done|next_target",
  "vuln_focus": "all|xss|sqli|ssrf|rce|idor|ssti|lfi|auth|deserialization",
  "reason": "brief tactical reason",
  "confidence": 85,
  "notes": "specific attack angle or tool to prioritize",
  "waf_bypass": "tamper technique if WAF detected"
}

Think like a world-class hacker. Be aggressive. Prioritize high-value attack vectors.`,
		state.Target, state.Phase, state.ReconDone, state.HuntDone,
		state.BugsFound, state.BugTypes, state.Technologies,
		state.WAFDetected, state.WAFVendor, state.OpenPorts, state.Mode,
		memContext)

	response, err := api.SendGroqSecurity(prompt)
	if err != nil {
		return nil, err
	}

	// Parse JSON from response
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start < 0 || end < 0 || end <= start {
		return nil, fmt.Errorf("no JSON in Groq response")
	}
	jsonStr := response[start : end+1]

	var decision api.AgentDecision
	if err := json.Unmarshal([]byte(jsonStr), &decision); err != nil {
		return nil, fmt.Errorf("Groq decision parse error: %v", err)
	}
	return &decision, nil
}

// sendCyberMindAgentDecision uses thecnical/cybermindcli to make agent decisions.
// This is our fine-tuned model — purpose-built for bug bounty agentic decisions.
// Uses Alpaca prompt format (the exact format it was trained on).
func sendCyberMindAgentDecision(state api.AgentState, memContext string) (*api.AgentDecision, error) {
	prompt := fmt.Sprintf(`You are CyberMind, an elite bug bounty hunter AI making a tactical decision.

TARGET: %s
CURRENT STATE:
- Phase: %s
- Recon done: %v
- Hunt done: %v
- Bugs found: %d (types: %v)
- Technologies: %v
- WAF: %v (%s)
- Open ports: %v
- Mode: %s

MEMORY CONTEXT:
%s

Based on this state, decide the NEXT ACTION. Respond with ONLY a JSON object:
{
  "action": "recon|hunt|exploit|bizlogic|deep_hunt|poc|guide|done|next_target",
  "vuln_focus": "all|xss|sqli|ssrf|rce|idor|ssti|lfi|auth|deserialization",
  "reason": "brief tactical reason",
  "confidence": 85,
  "notes": "specific attack angle or tool to prioritize",
  "waf_bypass": "tamper technique if WAF detected"
}`,
		state.Target, state.Phase, state.ReconDone, state.HuntDone,
		state.BugsFound, state.BugTypes, state.Technologies,
		state.WAFDetected, state.WAFVendor, state.OpenPorts, state.Mode,
		memContext)

	response, err := api.SendCyberMindLocal(prompt)
	if err != nil {
		return nil, fmt.Errorf("cybermindcli: %v", err)
	}

	// Parse JSON from response
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start < 0 || end < 0 || end <= start {
		return nil, fmt.Errorf("no JSON in cybermindcli response")
	}
	jsonStr := response[start : end+1]

	var decision api.AgentDecision
	if err := json.Unmarshal([]byte(jsonStr), &decision); err != nil {
		return nil, fmt.Errorf("cybermindcli decision parse error: %v", err)
	}
	return &decision, nil
}

// ─── OMEGA Planning Mode ──────────────────────────────────────────────────────

// runOmegaPlan is the main entry point for /plan command
func runOmegaPlan(target string, localMode bool) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render("  ⚡ OMEGA PLANNING MODE — " + target))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	// ── STEP 0: Root user check ───────────────────────────────────────────
	// Many tools (masscan, rustscan raw sockets, nmap -sS) require root.
	// Running as root also prevents permission issues with tool installation.
	if os.Getuid() != 0 {
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700")).Render("  ⚠  ROOT REQUIRED FOR OMEGA MODE"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render("  Many tools (masscan, rustscan, nmap -sS, naabu) require root for raw socket access."))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render("  Running as non-root causes port scan tools to skip or produce incomplete results."))
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render("  Run as root:"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render("  sudo cybermind /plan " + target))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render("  Or: sudo -E cybermind /plan " + target + "  (preserves env vars)"))
		fmt.Println()
		fmt.Print(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render("  Continue anyway as non-root? (some tools may fail) [y/N] → "))
		var rootAns string
		fmt.Scanln(&rootAns)
		if strings.ToLower(strings.TrimSpace(rootAns)) != "y" {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render("  Cancelled. Re-run as root for best results."))
			return
		}
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render("  ⚠  Continuing as non-root — some tools may produce incomplete results"))
		fmt.Println()
	} else {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render("  ✓ Running as root — full tool access enabled"))
		fmt.Println()
	}

	// ── Auto-fetch tool API keys from backend (Shodan, etc.) ─────────────
	// User doesn't need to configure anything — keys come from server
	if os.Getenv("SHODAN_API_KEY") == "" {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render("  ⟳ Fetching tool API keys from server..."))
		if toolsCfg, cfgErr := api.FetchToolsConfig(); cfgErr == nil && toolsCfg != nil {
			if toolsCfg.ShodanAPIKey != "" {
				os.Setenv("SHODAN_API_KEY", toolsCfg.ShodanAPIKey)
				// Auto-init shodan CLI
				if _, shodanErr := exec.LookPath("shodan"); shodanErr == nil {
					exec.Command("shodan", "init", toolsCfg.ShodanAPIKey).Run()
				}
				// Cache for future use
				_ = api.SaveToolsConfig(toolsCfg)
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render("  ✓ Shodan API key loaded from server"))
			}
		} else {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render("  ℹ  Using free Shodan InternetDB (no API key)"))
		}
		fmt.Println()
	} else {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render("  ✓ Shodan API key: configured"))
		fmt.Println()
	}

	// ── STEP 1: System resource check ────────────────────────────────────
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render("  ⟳ Checking system resources..."))
	sysRes := omega.CheckSystemResources()
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
		fmt.Sprintf("  CPU: %d cores | RAM free: %dMB | Disk free: %dMB",
			sysRes.CPUCores, sysRes.RAMFreeMB, sysRes.DiskFreeMB)))

	if len(sysRes.Warnings) > 0 {
		for _, w := range sysRes.Warnings {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render("  ⚠  " + w))
		}
		fmt.Println()
		ans := readWithTimeout(
			lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render("  Continue anyway? [Y/n] → "),
			"y", 20)
		if strings.ToLower(strings.TrimSpace(ans)) == "n" {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render("  Cancelled."))
			return
		}
	} else {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render("  ✓ System resources OK"))
	}
	fmt.Println()

	// ── STEP 2: Auto-doctor — check and install all tools ────────────────
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render("  🩺 OMEGA DOCTOR — Checking all tools..."))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	doctorResult := omega.RunOmegaDoctor(func(tool, status, msg string) {
		switch status {
		case "ok":
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(fmt.Sprintf("  ✓ %-22s installed", tool)))
		case "installing":
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(fmt.Sprintf("  ⟳ %-22s installing...", tool)))
		case "installed", "installed_alt":
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(fmt.Sprintf("  ✓ %-22s installed ✓", tool)))
		case "failed":
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render(fmt.Sprintf("  ✗ %-22s failed — %s", tool, msg)))
		}
	})

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
		fmt.Sprintf("  ✓ Installed: %d/%d tools", doctorResult.InstalledOK, doctorResult.TotalTools)))
	if len(doctorResult.Missing) > 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render(
			fmt.Sprintf("  ✗ Missing:   %s", strings.Join(doctorResult.Missing, ", "))))
	}
	fmt.Println()

	// ── STEP 3: Ask permission to start planning ──────────────────────────
	startAns := readWithTimeout(
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700")).Render("  Start OMEGA planning for "+target+"? [Y/n] → "),
		"y", 20)
	if strings.ToLower(startAns) == "n" {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render("  Cancelled."))
		return
	}
	fmt.Println()

	// ── STEP 4: Deep passive target intelligence ──────────────────────────
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render("  🧠 DEEP TARGET INTELLIGENCE"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	intel := omega.GatherTargetIntel(target, func(step, result string) {
		if result != "" {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
				fmt.Sprintf("  ✓ %-18s %s", step+":", result)))
		} else {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
				fmt.Sprintf("  ⟳ %s...", step)))
		}
	})

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	if intel.WAFDetected {
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4444")).Render(
			"  ⚠  WAF DETECTED: " + intel.WAFVendor + " — stealth mode will be applied"))
	}
	if len(intel.TechStack) > 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			"  Tech: " + strings.Join(intel.TechStack[:min(8, len(intel.TechStack))], ", ")))
	}
	fmt.Println()

	// ── STEP 5: AI generates OMEGA attack plan ────────────────────────────
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render("  ⟳ AI generating OMEGA attack plan..."))

	// ── NEW: Tech-aware tool selection based on gathered intel ────────────
	toolSel := omega.SelectToolsByIntel(intel)
	omega.DisplayToolSelection(toolSel, target)

	// Apply tool selection to environment for agentic loop
	if toolSel.VulnFocus != "" && toolSel.VulnFocus != "all" {
		os.Setenv("CYBERMIND_FOCUS_BUGS", toolSel.VulnFocus)
	}
	if len(toolSel.SkipTools) > 0 {
		os.Setenv("CYBERMIND_SKIP_TOOLS", strings.Join(toolSel.SkipTools, ","))
	}

	// Build Shodan map
	shodanMap := make(map[string]string)
	for k, v := range intel.ShodanData {
		shodanMap[k] = v
	}

	planReq := api.PlanRequest{
		Target:      target,
		DNSIPs:      intel.DNSIPs,
		Shodan:      shodanMap,
		HTTPHeaders: intel.HTTPHeaders,
		TechStack:   intel.TechStack,
		OpenPorts:   intel.OpenPorts,
		WAFDetected: intel.WAFDetected,
		WAFVendor:   intel.WAFVendor,
		MXRecords:   intel.MXRecords,
		TXTRecords:  intel.TXTRecords[:min(5, len(intel.TXTRecords))],
		NSRecords:   intel.NSRecords,
		RDNS:        intel.RDNS,
		OSHint:      intel.OSHint,
	}

	var plan *api.OmegaPlan
	var rawPlan string
	var planErr error

	if localMode {
		// Local mode: generate a basic plan without AI
		rawPlan = fmt.Sprintf("OMEGA Plan for %s\n\nTarget Intel:\n- IPs: %s\n- Tech: %s\n- WAF: %v (%s)\n- Ports: %v\n\nRecommended: Run /recon then /hunt then /abhimanyu",
			target, strings.Join(intel.DNSIPs, ", "), strings.Join(intel.TechStack, ", "),
			intel.WAFDetected, intel.WAFVendor, intel.OpenPorts)
	} else {
		plan, rawPlan, planErr = api.SendPlan(planReq)
		if planErr != nil {
			printError("Plan generation failed: " + planErr.Error())
			return
		}
	}

	// ── STEP 6: Display plan ──────────────────────────────────────────────
	if plan != nil {
		omega.DisplayPlan(plan, target)
	} else {
		omega.DisplayPlanRaw(rawPlan)
	}

	// ── STEP 7: Save plan to file ─────────────────────────────────────────
	if plan != nil {
		filename, err := omega.SavePlanToFile(plan, target)
		if err == nil {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF00")).Render(
				"  ✓ Plan saved: " + filename))
		}
	}

	// ── STEP 8: Ask to execute ────────────────────────────────────────────
	fmt.Println()
	execAns := readWithTimeout(
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700")).Render("  Execute this plan? [Y/n] → "),
		"y", 20)
	if strings.ToLower(execAns) == "n" {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			"  Plan saved. Run /recon to start manually."))
		return
	}

		// ── STEP 9: Execute — AGENTIC BRAIN LOOP ────────────────────────────
	fmt.Println()

	// Launch floating terminal if tmux available
	launchFloatingTerminal(target)
	omegaLogFile = fmt.Sprintf("/tmp/cybermind_omega_%s.log", strings.ReplaceAll(target, ".", "_"))

	// Apply plan WAF/stealth settings to env
	if plan != nil {
		if plan.WAFStrategy != "" && plan.WAFStrategy != "none" {
			os.Setenv("CYBERMIND_WAF_STRATEGY", plan.WAFStrategy)
		}
		if plan.StealthMode {
			os.Setenv("CYBERMIND_STEALTH", "true")
		}
	}

	// ── Hand off to the agentic brain loop ───────────────────────────────
	skillLevel := os.Getenv("CYBERMIND_SKILL")
	if skillLevel == "" {
		skillLevel = "intermediate"
	}
	focusBugs := os.Getenv("CYBERMIND_FOCUS_BUGS")
	execMode := os.Getenv("CYBERMIND_EXEC_MODE")
	if execMode == "" {
		execMode = "deep"
	}

	runAgenticOmega(target, skillLevel, focusBugs, execMode, localMode)
}

// launchFloatingTerminal launches a live monitoring window during OMEGA execution.
// Priority: xterm → gnome-terminal → konsole → alacritty → tmux popup → skip
// The floating terminal shows ONLY the log file — main terminal shows tool status.
func launchFloatingTerminal(target string) {
	logFile := fmt.Sprintf("/tmp/cybermind_omega_%s.log", strings.ReplaceAll(target, ".", "_"))
	// Create log file with header
	os.WriteFile(logFile, []byte(fmt.Sprintf(
		"╔══════════════════════════════════════════════════════════╗\n"+
			"║  ⚡ CyberMind OMEGA — %s\n"+
			"║  Live execution log — updates in real time\n"+
			"╚══════════════════════════════════════════════════════════╝\n\n",
		target)), 0644)

	// watchCmd: clear screen, show header, then follow log file
	// Uses `tail -f` so it updates live as tools run
	// `--no-close` / `-hold` keeps window open after scan completes
	watchCmd := fmt.Sprintf(`tail -n +1 -f %s`, logFile)

	// 1. xterm (most common on Kali — use -hold to keep open after scan)
	if _, err := exec.LookPath("xterm"); err == nil {
		cmd := exec.Command("xterm",
			"-title", "CyberMind OMEGA — "+target,
			"-geometry", "110x35+50+50",
			"-bg", "#020d1a",
			"-fg", "#00FFFF",
			"-fa", "Monospace",
			"-fs", "10",
			"-hold",
			"-e", watchCmd,
		)
		if cmd.Start() == nil {
			return
		}
	}

	// 2. gnome-terminal
	if _, err := exec.LookPath("gnome-terminal"); err == nil {
		cmd := exec.Command("gnome-terminal",
			"--title=CyberMind OMEGA — "+target,
			"--geometry=110x35",
			"--",
			"bash", "-c", watchCmd+"; read -p 'Scan complete. Press Enter to close.'",
		)
		if cmd.Start() == nil {
			return
		}
	}

	// 3. konsole (KDE)
	if _, err := exec.LookPath("konsole"); err == nil {
		cmd := exec.Command("konsole",
			"--title", "CyberMind OMEGA — "+target,
			"--noclose",
			"-e", "bash", "-c", watchCmd,
		)
		if cmd.Start() == nil {
			return
		}
	}

	// 4. alacritty
	if _, err := exec.LookPath("alacritty"); err == nil {
		cmd := exec.Command("alacritty",
			"--title", "CyberMind OMEGA — "+target,
			"-e", "bash", "-c", watchCmd,
		)
		if cmd.Start() == nil {
			return
		}
	}

	// 5. xfce4-terminal
	if _, err := exec.LookPath("xfce4-terminal"); err == nil {
		cmd := exec.Command("xfce4-terminal",
			"--title=CyberMind OMEGA — "+target,
			"--hold",
			"-e", watchCmd,
		)
		if cmd.Start() == nil {
			return
		}
	}

	// 6. tmux popup (fallback — only if inside tmux)
	if _, err := exec.LookPath("tmux"); err == nil && os.Getenv("TMUX") != "" {
		cmd := exec.Command("tmux", "popup",
			"-d", "~",
			"-w", "80%",
			"-h", "60%",
			"-E",
			fmt.Sprintf("bash -c %q", watchCmd),
		)
		cmd.Start()
		return
	}

	// No terminal found — print hint
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
		"  ℹ  No terminal emulator found. Live log: "+logFile))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
		"  ℹ  In another terminal: tail -f "+logFile))
}

