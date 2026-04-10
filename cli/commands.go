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
	"cybermind-cli/storage"
	"cybermind-cli/utils"

	"github.com/charmbracelet/lipgloss"
)

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
		// Sanitize target — only allow safe hostname/IP chars to prevent PowerShell injection
		safeTarget := sanitizeTarget(target)
		for _, port := range commonPorts {
			cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
				fmt.Sprintf("(Test-NetConnection -ComputerName '%s' -Port %d -WarningAction SilentlyContinue).TcpTestSucceeded", safeTarget, port))
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
		for _, port := range commonPorts {
			cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
				fmt.Sprintf("(Test-NetConnection -ComputerName '%s' -Port %d -WarningAction SilentlyContinue).TcpTestSucceeded", safeTarget, port))
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

// Suppress unused import warnings for packages used only in some build targets
var _ = base64.StdEncoding
var _ = filepath.Join
var _ = exec.LookPath
var _ = runtime.GOOS
