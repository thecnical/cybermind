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
	"cybermind-cli/recon"
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

	// Accumulated context across all phases
	var allBugs []bugdetect.Bug
	var reconResult recon.ReconResult
	var huntResult hunt.HuntResult
	var allFindings = make(map[string]string)

	maxIterations := 8 // prevent infinite loops
	if mode == "overnight" {
		maxIterations = 20
	} else if mode == "quick" {
		maxIterations = 4
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

		if !localMode {
			decision, decErr = api.SendAgentDecision(state)
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

			fmt.Println(lipgloss.NewStyle().Foreground(green2).Render(
				fmt.Sprintf("  ✓ Recon complete: %d tools ran, %d live URLs, %d ports, %d bugs",
					len(reconResult.Tools), len(state.LiveURLs), len(state.OpenPorts), state.BugsFound)))

		case "hunt":
			agentAct(fmt.Sprintf("Running HUNT phase (focus: %s)...", decision.VulnFocus))
			omegaLog("\n═══ AGENT: HUNT ═══")

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

			huntResult = runHuntSilent(target, huntCtx, buildRequestedTools(skipTools, "hunt"))
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
			// Dedup bugs
			allBugs = dedupBugs(allBugs)
			state.BugsFound = len(allBugs)
			state.BugTypes = extractBugTypes(allBugs)

			fmt.Println(lipgloss.NewStyle().Foreground(green2).Render(
				fmt.Sprintf("  ✓ Hunt complete: %d tools ran, %d bugs found",
					len(huntResult.Tools), state.BugsFound)))

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

		case "exploit":
			agentAct(fmt.Sprintf("Running ABHIMANYU exploit phase (focus: %s)...", decision.VulnFocus))
			omegaLog("\n═══ AGENT: EXPLOIT ═══")

			var huntCtxForAbhi hunt.HuntContext
			if huntResult.Context != nil {
				huntCtxForAbhi = *huntResult.Context
			}

			xssFound := huntCtxForAbhi.XSSFound
			vulnsFound := huntCtxForAbhi.VulnsFound
			paramsFound := huntCtxForAbhi.ParamsFound
			openPorts := huntCtxForAbhi.OpenPorts
			if len(openPorts) == 0 && reconResult.Context != nil {
				openPorts = reconResult.Context.OpenPorts
			}

			runAbhimanyuFromHunt(target, huntCtxForAbhi, xssFound, vulnsFound, paramsFound, openPorts, allFindings)
			state.AbhiDone = true
			state.Phase = "exploit_done"

		case "poc":
			agentAct("Generating PoC for confirmed bugs...")
			omegaLog("\n═══ AGENT: POC GENERATION ═══")

			pocs := make(map[int]string)
			for i, bug := range allBugs {
				if bug.Severity == bugdetect.SeverityLow || bug.Severity == bugdetect.SeverityInfo {
					continue
				}
				if bug.Evidence == "" {
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
					fmt.Println(lipgloss.NewStyle().Foreground(green2).Render(
						fmt.Sprintf("  ✓ PoC: %s", bug.Title)))
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
				fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render(
					"  " + bugdetect.GetBugBountyInfo(target)))
			}
			state.Phase = "poc_done"

		case "report":
			agentAct("Generating final report...")
			runReport("markdown", localMode)
			state.Phase = "report_done"

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

		// If we have high-severity bugs and PoC is done, we're done
		if state.Phase == "poc_done" && state.BugsFound > 0 {
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
func localAgentDecision(state api.AgentState) *api.AgentDecision {
	d := &api.AgentDecision{
		VulnFocus:  "all",
		Depth:      "deep",
		Confidence: 60,
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
	case state.BugsFound > 0 && !state.AbhiDone:
		d.Action = "exploit"
		d.Reason = fmt.Sprintf("Found %d bugs — running exploit phase", state.BugsFound)
		d.VulnFocus = "all"
		if len(state.BugTypes) > 0 {
			d.VulnFocus = state.BugTypes[0]
		}
	case state.BugsFound > 0 && state.AbhiDone:
		d.Action = "poc"
		d.Reason = "Bugs confirmed — generating PoC"
	case state.ReconDone && state.HuntDone && state.BugsFound == 0:
		d.Action = "next_target"
		d.Reason = "No bugs found — move to next target"
	default:
		d.Action = "done"
		d.Reason = "All phases complete"
	}

	return d
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

