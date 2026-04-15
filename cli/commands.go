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
	"time"

	"cybermind-cli/api"
	"cybermind-cli/bugdetect"
	"cybermind-cli/hunt"
	"cybermind-cli/omega"
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

		// ── STEP 9: Execute — full plan-aware chained execution ─────────────
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render(
		"  🚀 EXECUTING OMEGA PLAN — " + target))
	fmt.Println()

	// Launch floating terminal if tmux available
	launchFloatingTerminal(target)
	omegaLogFile = fmt.Sprintf("/tmp/cybermind_omega_%s.log", strings.ReplaceAll(target, ".", "_"))

	// Build skip set from plan phases
	skipTools := make(map[string]bool)
	// Also build per-phase focus args from plan — passed via env for tools to use
	planFocusArgs := make(map[string]string)
	if plan != nil {
		for _, phase := range plan.Phases {
			for _, skip := range phase.ToolsSkip {
				skipTools[skip] = true
			}
			for tool, args := range phase.ToolsFocus {
				planFocusArgs[tool] = args
			}
		}
		if plan.WAFStrategy != "" && plan.WAFStrategy != "none" {
			os.Setenv("CYBERMIND_WAF_STRATEGY", plan.WAFStrategy)
		}
		if plan.StealthMode {
			os.Setenv("CYBERMIND_STEALTH", "true")
		}
		// Encode focus args as JSON env var so recon/hunt engines can read them
		if len(planFocusArgs) > 0 {
			if focusJSON, err := json.Marshal(planFocusArgs); err == nil {
				os.Setenv("CYBERMIND_FOCUS_ARGS", string(focusJSON))
			}
		}
	}

	// ── PHASE 1: RECON (plan-aware) ──────────────────────────────────────
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700")).Render(
		"  ═══ PHASE 1: RECON ═══"))
	omegaLog("\n═══ PHASE 1: RECON ═══\nTarget: " + target)
	if plan != nil && len(skipTools) > 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			fmt.Sprintf("  ℹ  Plan-aware: skipping %d tools, focusing on AI-recommended tools", len(skipTools))))
	}
	fmt.Println()

	// Run recon silently (no interactive prompts) and capture result for context chaining
	reconResult := runAutoReconSilent(target, buildRequestedTools(skipTools, "recon"))

	// ── PHASE 2: HUNT (plan-aware, recon context fed in) ─────────────────
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render(
		"  ═══ PHASE 2: HUNT ═══"))
	omegaLog("\n═══ PHASE 2: HUNT ═══")

	// Build hunt context from recon results — this is the key fix
	// Hunt now knows: live URLs, open ports, WAF, subdomains from recon
	var huntCtxFromRecon *hunt.HuntContext
	if reconResult.Context != nil {
		rc := reconResult.Context
		liveURLs := rc.LiveURLs
		if liveURLs == nil {
			liveURLs = []string{}
		}
		openPorts := rc.OpenPorts
		if openPorts == nil {
			openPorts = []int{}
		}
		huntCtxFromRecon = &hunt.HuntContext{
			Target:      target,
			TargetType:  rc.TargetType,
			LiveURLs:    liveURLs,
			CrawledURLs: rc.CrawledURLs,
			OpenPorts:   openPorts,
			WAFDetected: rc.WAFDetected,
			WAFVendor:   rc.WAFVendor,
			Subdomains:  rc.Subdomains,
		}
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			fmt.Sprintf("  ℹ  Recon context: %d live URLs, %d open ports, WAF=%v (%s)",
				len(liveURLs), len(openPorts), rc.WAFDetected, rc.WAFVendor)))
	} else {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			"  ℹ  No recon context — hunt running in standalone mode"))
	}
	fmt.Println()

	// Run hunt silently with recon context and plan-aware tool filter
	huntResult := runHuntSilent(target, huntCtxFromRecon, buildRequestedTools(skipTools, "hunt"))

	// ── BUG DETECTION: Parse hunt + recon output for confirmed vulnerabilities ──
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render(
		"  🔍 BUG DETECTION — Analyzing tool output..."))

	var allBugs []bugdetect.Bug
	bugReport := bugdetect.BugReport{
		Target:    target,
		StartTime: time.Now().Add(-time.Hour), // approximate
		EndTime:   time.Now(),
	}

	// Parse nuclei output from hunt
	for _, tr := range huntResult.Results {
		if tr.Output != "" {
			bugs := bugdetect.ParseToolOutput(tr.Tool, tr.Output, target)
			allBugs = append(allBugs, bugs...)
		}
	}
	// Parse nuclei output from recon
	for _, tr := range reconResult.Results {
		if tr.Output != "" {
			bugs := bugdetect.ParseToolOutput(tr.Tool, tr.Output, target)
			allBugs = append(allBugs, bugs...)
		}
	}

	bugReport.Bugs = allBugs

	if len(allBugs) > 0 {
		// Count by severity
		critCount, highCount, medCount := 0, 0, 0
		for _, b := range allBugs {
			switch b.Severity {
			case bugdetect.SeverityCritical:
				critCount++
			case bugdetect.SeverityHigh:
				highCount++
			case bugdetect.SeverityMedium:
				medCount++
			}
		}
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4444")).Render(
			fmt.Sprintf("  🐛 BUGS FOUND: %d total (Critical:%d High:%d Medium:%d)",
				len(allBugs), critCount, highCount, medCount)))
		omegaLog(fmt.Sprintf("🐛 BUGS FOUND: %d", len(allBugs)))
		fmt.Println()

		// Show each bug
		for _, bug := range allBugs {
			color := lipgloss.Color("#FFD700")
			if bug.Severity == bugdetect.SeverityCritical {
				color = lipgloss.Color("#FF4444")
			} else if bug.Severity == bugdetect.SeverityHigh {
				color = lipgloss.Color("#FF6600")
			}
			fmt.Println(lipgloss.NewStyle().Foreground(color).Render(
				fmt.Sprintf("  [%s] %s", strings.ToUpper(string(bug.Severity)), bug.Title)))
			if bug.URL != "" {
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
					"    URL: " + bug.URL))
			}
		}
		fmt.Println()

		// ── AUTO PoC GENERATION ────────────────────────────────────────────
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render(
			"  ⟳ Generating PoC for each confirmed bug..."))

		pocs := make(map[int]string)
		for i, bug := range allBugs {
			// Only generate PoC for medium+ severity
			if bug.Severity == bugdetect.SeverityLow || bug.Severity == bugdetect.SeverityInfo {
				continue
			}
			// Skip PoC if evidence is empty or clearly negative — prevents hallucinated PoCs
			if bug.Evidence == "" {
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
					fmt.Sprintf("  - PoC skipped [%d/%d]: no evidence for %s", i+1, len(allBugs), bug.Title)))
				continue
			}
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
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
					fmt.Sprintf("  ✓ PoC generated for: %s", bug.Title)))
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
					fmt.Sprintf("  - PoC generation failed: %v", pocErr)))
			}
		}

		// Save report with PoCs included
		bugReport.Bugs = allBugs
		bugReport.EndTime = time.Now()
		content := bugdetect.GenerateReportWithPoC(bugReport, pocs)
		ts := time.Now().Format("2006-01-02_15-04-05")
		safeTarget := strings.ReplaceAll(target, ".", "_")
		reportPath := fmt.Sprintf("cybermind_bugs_%s_%s.md", safeTarget, ts)
		if err := os.WriteFile(reportPath, []byte(content), 0644); err == nil {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF00")).Render(
				"  ✓ Full bug report with PoCs saved: " + reportPath))
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
				"  " + bugdetect.GetBugBountyInfo(target)))
		}
	} else {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			"  No confirmed bugs detected yet — continuing to Abhimanyu exploitation phase..."))
	}
	fmt.Println()

	// ── PHASE 3: ABHIMANYU (plan-aware, hunt context fed in) ─────────────
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4444")).Render(
		"  ═══ PHASE 3: ABHIMANYU ═══"))
	omegaLog("\n═══ PHASE 3: ABHIMANYU ═══")

	// Build abhimanyu context from hunt results — full context chain
	var huntCtx hunt.HuntContext
	if huntResult.Context != nil {
		huntCtx = *huntResult.Context
	}

	xssFound := huntCtx.XSSFound
	if xssFound == nil {
		xssFound = []string{}
	}
	vulnsFound := huntCtx.VulnsFound
	if vulnsFound == nil {
		vulnsFound = []string{}
	}
	paramsFound := huntCtx.ParamsFound
	if paramsFound == nil {
		paramsFound = []string{}
	}
	openPortsForAbhi := huntCtx.OpenPorts
	if openPortsForAbhi == nil && reconResult.Context != nil {
		openPortsForAbhi = reconResult.Context.OpenPorts
	}
	if openPortsForAbhi == nil {
		openPortsForAbhi = []int{}
	}
	// Ensure huntCtx.LiveURLs is populated — fall back to recon live URLs if hunt didn't find any
	if len(huntCtx.LiveURLs) == 0 && reconResult.Context != nil && len(reconResult.Context.LiveURLs) > 0 {
		huntCtx.LiveURLs = reconResult.Context.LiveURLs
	}

	vulnCount := len(xssFound) + len(vulnsFound)
	if vulnCount > 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render(
			fmt.Sprintf("  ℹ  Hunt found %d vulnerabilities — feeding into Abhimanyu", vulnCount)))
	}
	fmt.Println()

	// Build hunt findings map for abhimanyu
	huntFindings := make(map[string]string)
	for _, tr := range huntResult.Results {
		if tr.Output != "" {
			huntFindings[tr.Tool] = tr.Output
		}
	}
	// Also add recon findings
	for _, tr := range reconResult.Results {
		if tr.Output != "" && tr.Tool != "combined" {
			huntFindings["recon_"+tr.Tool] = tr.Output
		}
	}

	// Run abhimanyu with full context from recon+hunt chain
	runAbhimanyuFromHunt(target, huntCtx, xssFound, vulnsFound, paramsFound, openPortsForAbhi, huntFindings)

	// ── PHASE 4: REPORT ──────────────────────────────────────────────────
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#8A2BE2")).Render(
		"  ═══ PHASE 4: REPORT ═══"))
	fmt.Println()
	runReport("markdown", localMode)

	// ── FINAL SUMMARY ─────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF00")).Render(
		"  ✓ OMEGA PLAN EXECUTION COMPLETE — " + target))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
		fmt.Sprintf("  Recon: %d tools ran | Hunt: %d tools ran | Bugs: %d confirmed",
			len(reconResult.Tools), len(huntResult.Tools), len(allBugs))))
	fmt.Println()

	// ── CONTINUOUS LOOP: Suggest next target if no high-severity bugs found ──
	if !bugdetect.HasHighSeverityBugs(allBugs) {
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700")).Render(
			"  ⚡ No medium/high/critical bugs found on this target."))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			"  Suggesting next bug bounty targets with better attack surface:"))
		fmt.Println()

		nextTargets := bugdetect.SuggestNextTarget(target)
		for i, t := range nextTargets {
			info := bugdetect.GetBugBountyInfo(t)
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render(
				fmt.Sprintf("  %d. %s", i+1, t)))
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
				"     " + info))
		}
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
			"  Run: sudo cybermind /plan <next-target>"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			"  Tip: Choose targets with *.domain.com wildcard scope for maximum attack surface"))
	} else {
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4444")).Render(
			fmt.Sprintf("  🎯 %d bugs confirmed! Check the report file for details.", len(allBugs))))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			"  Next steps:"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
			"  1. Review the bug report (cybermind_bugs_*.md)"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
			"  2. Write PoC for each confirmed bug"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
			"  3. Submit to HackerOne/Bugcrowd with full evidence"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			"  "+bugdetect.GetBugBountyInfo(target)))
	}
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

