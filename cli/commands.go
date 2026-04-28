package main

import (
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
	"cybermind-cli/abhimanyu"
	"cybermind-cli/bizlogic"
	"cybermind-cli/brain"
	"cybermind-cli/bugdetect"
	"cybermind-cli/hunt"
	"cybermind-cli/omega"
	locatePkg "cybermind-cli/locate"
	osintPkg "cybermind-cli/osint"
	revengPkg "cybermind-cli/reveng"
	"cybermind-cli/recon"
	"cybermind-cli/sandbox"
	"cybermind-cli/storage"
	"cybermind-cli/utils"
	"cybermind-cli/aegis"

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
		aiResult, aiErr = api.SendPrompt(sb.String())
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
		aiResult, aiErr = api.SendPrompt(prompt)
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
		aiResult, aiErr = api.SendPrompt(prompt)
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
		result, err = api.SendPayloadGen(targetOS, arch, lhost, lport, format, payloadType)
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
		result, err = api.SendCVE(cveID)
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
		result, err = api.SendCVELatest()
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
// If filename is provided, saves to that path. Otherwise auto-generates a name
// based on the last scanned target and saves to ~/.cybermind/reports/.
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
		result, err = api.SendReport(history, "")
	} else {
		result, err = api.SendReport(history, "")
	}
	if err != nil {
		printError("Report generation failed: " + err.Error())
		return
	}

	// Auto-generate filename: cybermind_report_<target>_<date>.md
	// Try to extract target from Brain Memory or last history entry
	target := "unknown"
	globalMem := brain.LoadGlobal()
	if globalMem != nil && len(globalMem.TargetStats) > 0 {
		// Use the target with the most bugs (most recently worked on)
		maxBugs := -1
		for t, count := range globalMem.TargetStats {
			if count > maxBugs {
				maxBugs = count
				target = t
			}
		}
	}
	if target == "unknown" && len(history) > 0 {
		// Extract target from last recon/scan entry
		for i := len(history) - 1; i >= 0; i-- {
			u := history[i].User
			if strings.Contains(u, "/recon ") || strings.Contains(u, "/scan ") || strings.Contains(u, "/hunt ") {
				parts := strings.Fields(u)
				if len(parts) >= 2 {
					target = parts[len(parts)-1]
					break
				}
			}
		}
	}
	// Sanitize target for filename
	target = strings.NewReplacer("/", "_", ":", "_", " ", "_").Replace(target)

	// Save to ~/.cybermind/reports/
	home, _ := os.UserHomeDir()
	reportsDir := filepath.Join(home, ".cybermind", "reports")
	os.MkdirAll(reportsDir, 0700)

	date := time.Now().Format("2006-01-02")
	outputFile := filepath.Join(reportsDir, fmt.Sprintf("cybermind_report_%s_%s.md", target, date))

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
		result, err = api.SendWordlist(target, wordlistType, 500)
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

// ─── New Imports for OSINT/RevEng/Locate ─────────────────────────────────────
// These are used by the new command handlers below.
// Import them in the import block at the top of this file.

// ─── OSINT Deep Command Handler ───────────────────────────────────────────────

func runOSINTDeep(target string, requested []string, localMode bool) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render("  🔍 OSINT DEEP — " + target))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))

	// Auto-detect target type
	targetType := osintPkg.DetectTargetType(target)
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
		fmt.Sprintf("  ℹ  Target type: %s | Tools: %d available", targetType, len(osintPkg.OSINTToolNames()))))
	fmt.Println()

	result := osintPkg.RunOSINTDeep(target, requested, func(status osintPkg.OSINTStatus) {
		switch status.Kind {
		case osintPkg.OSINTRunning:
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
				fmt.Sprintf("  ⟳ %-18s running...", status.Tool)))
		case osintPkg.OSINTDone:
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
				fmt.Sprintf("  ✓ %-18s done (%s)", status.Tool, status.Took.Round(time.Millisecond))))
		case osintPkg.OSINTPartial:
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(
				fmt.Sprintf("  ⚡ %-18s partial output kept", status.Tool)))
		case osintPkg.OSINTFailed:
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render(
				fmt.Sprintf("  ✗ %-18s failed — %s", status.Tool, status.Reason)))
		case osintPkg.OSINTKindSkipped:
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
				fmt.Sprintf("  - %-18s skipped — %s", status.Tool, status.Reason)))
		case osintPkg.OSINTRetry:
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(
				fmt.Sprintf("  ↻ %-18s %s", status.Tool, status.Reason)))
		}
	})

	// Print summary
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render("  📋 OSINT Summary"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	if result.Context != nil {
		ctx := result.Context
		if len(ctx.EmailsFound) > 0 {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
				fmt.Sprintf("  📧 Emails found:      %d", len(ctx.EmailsFound))))
			for _, e := range ctx.EmailsFound[:min(5, len(ctx.EmailsFound))] {
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render("     → " + e))
			}
		}
		if len(ctx.SubdomainsFound) > 0 {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
				fmt.Sprintf("  🌐 Subdomains found:  %d", len(ctx.SubdomainsFound))))
		}
		if len(ctx.SocialProfiles) > 0 {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
				fmt.Sprintf("  👤 Social profiles:   %d", len(ctx.SocialProfiles))))
			for _, p := range ctx.SocialProfiles[:min(5, len(ctx.SocialProfiles))] {
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render("     → " + p))
			}
		}
		if len(ctx.EmployeesFound) > 0 {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(
				fmt.Sprintf("  👥 Employees found:   %d", len(ctx.EmployeesFound))))
		}
		if len(ctx.GitHubLeaks) > 0 {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4444")).Render(
				fmt.Sprintf("  🔑 GitHub leaks:      %d", len(ctx.GitHubLeaks))))
		}
	}

	if len(result.Tools) == 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render("  ✗ No OSINT tools produced output."))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render("  Run: cybermind /doctor to install OSINT tools"))
		return
	}

	// Build structured payload for dedicated API endpoint
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render("  ⟳ Sending to AI for OSINT analysis..."))

	findings := make(map[string]string)
	for _, tr := range result.Results {
		if tr.Output != "" {
			out := tr.Output
			if len(out) > 5000 {
				out = out[:5000] + "\n...[truncated]"
			}
			findings[tr.Tool] = out
		}
	}

	combined := osintPkg.GetOSINTCombinedOutput(result)
	if len(combined) > 50000 {
		combined = combined[:50000] + "\n...[truncated]"
	}

	osintPayload := api.OSINTPayload{
		Target:      target,
		TargetType:  result.TargetType,
		ToolsRun:    result.Tools,
		Findings:    findings,
		RawCombined: combined,
	}
	if result.Context != nil {
		ctx := result.Context
		osintPayload.EmailsFound = ctx.EmailsFound
		osintPayload.SubdomainsFound = ctx.SubdomainsFound
		osintPayload.EmployeesFound = ctx.EmployeesFound
		osintPayload.SocialProfiles = ctx.SocialProfiles
		osintPayload.GitHubLeaks = ctx.GitHubLeaks

		// Social Media Scanner for username targets (Phase 3)
		if targetType == "username" || targetType == "person" || targetType == "email" {
			username := target
			if strings.Contains(target, "@") {
				username = strings.Split(target, "@")[0]
			}
			_ = username // social media scanner removed
		}
	}

	var aiResult string
	var aiErr error
	if localMode {
		aiResult, aiErr = api.SendOSINTDeep(osintPayload)
	} else {
		aiResult, aiErr = api.SendOSINTDeep(osintPayload)
	}
	if aiErr != nil {
		printError("AI analysis failed: " + aiErr.Error())
		return
	}
	clean := utils.StripMarkdown(aiResult)
	printResult("🔍 OSINT Deep → "+target, clean)
	_ = storage.AddEntry("/osint-deep "+target, clean)
}

// ─── Reverse Engineering Command Handler ──────────────────────────────────────

func runRevEng(target, mode string, requested []string, localMode bool) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render("  ⚙️  REVERSE ENGINEERING — " + target))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
		fmt.Sprintf("  ℹ  Mode: %s | Tools: %d available", mode, len(revengPkg.RevEngToolNames()))))
	fmt.Println()

	result := revengPkg.RunRevEng(target, mode, requested, func(status revengPkg.RevEngStatus) {
		switch status.Kind {
		case revengPkg.RevEngRunning:
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
				fmt.Sprintf("  ⟳ %-18s running...", status.Tool)))
		case revengPkg.RevEngDone:
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
				fmt.Sprintf("  ✓ %-18s done (%s)", status.Tool, status.Took.Round(time.Millisecond))))
		case revengPkg.RevEngPartial:
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(
				fmt.Sprintf("  ⚡ %-18s partial", status.Tool)))
		case revengPkg.RevEngFailed:
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render(
				fmt.Sprintf("  ✗ %-18s failed — %s", status.Tool, status.Reason)))
		case revengPkg.RevEngKindSkipped:
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
				fmt.Sprintf("  - %-18s skipped — %s", status.Tool, status.Reason)))
		case revengPkg.RevEngRetry:
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(
				fmt.Sprintf("  ↻ %-18s %s", status.Tool, status.Reason)))
		}
	})

	// Print summary
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render("  ⚙️  RE Summary"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	if result.Context != nil {
		ctx := result.Context
		if ctx.FileType != "" {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render(
				fmt.Sprintf("  File type:     %s (%s %s)", ctx.FileType, ctx.Architecture, ctx.Bitness)))
		}
		secProps := []string{}
		if ctx.PIE {
			secProps = append(secProps, "PIE")
		}
		if ctx.NX {
			secProps = append(secProps, "NX")
		}
		if ctx.Canary {
			secProps = append(secProps, "Canary")
		}
		if ctx.RELRO != "" {
			secProps = append(secProps, "RELRO="+ctx.RELRO)
		}
		if ctx.Stripped {
			secProps = append(secProps, "Stripped")
		}
		if len(secProps) > 0 {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render(
				"  Security:      "+strings.Join(secProps, " | ")))
		}
		if len(ctx.VulnFunctions) > 0 {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4444")).Render(
				fmt.Sprintf("  ⚠ Vuln funcs:  %s", strings.Join(ctx.VulnFunctions, ", "))))
		}
		if len(ctx.SuspiciousStrings) > 0 {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(
				fmt.Sprintf("  Suspicious:    %d strings found", len(ctx.SuspiciousStrings))))
		}
		if len(ctx.YARAMatches) > 0 {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4444")).Render(
				fmt.Sprintf("  🦠 YARA hits:  %d matches", len(ctx.YARAMatches))))
		}
		if len(ctx.ROPGadgets) > 0 {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(
				fmt.Sprintf("  ROP gadgets:   %d found", len(ctx.ROPGadgets))))
		}
		if ctx.SessionDir != "" {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
				"  Session:       "+ctx.SessionDir))
		}
	}

	if len(result.Tools) == 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render("  ✗ No RE tools produced output."))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render("  Run: cybermind /doctor to install RE tools"))
		return
	}

	// Build structured payload for dedicated API endpoint
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render("  ⟳ Sending to AI for reverse engineering analysis..."))

	findings := make(map[string]string)
	for _, tr := range result.Results {
		if tr.Output != "" {
			out := tr.Output
			if len(out) > 8000 {
				out = out[:8000] + "\n...[truncated]"
			}
			findings[tr.Tool] = out
		}
	}

	// VirusTotal hash check skipped (breach package removed)
	if result.Context != nil && result.Context.SHA256Hash != "" {
		sha256hash := result.Context.SHA256Hash
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			fmt.Sprintf("  ℹ  Hash: %s... — check manually at virustotal.com", sha256hash[:16])))
	}

	combined := revengPkg.GetRevEngCombinedOutput(result)
	if len(combined) > 80000 {
		combined = combined[:80000] + "\n...[truncated]"
	}

	revPayload := api.RevEngPayload{
		Target:      target,
		AnalysisMode: mode,
		ToolsRun:    result.Tools,
		Findings:    findings,
		RawCombined: combined,
	}
	if result.Context != nil {
		ctx := result.Context
		revPayload.FileType = ctx.FileType
		revPayload.Architecture = ctx.Architecture
		revPayload.Bitness = ctx.Bitness
		revPayload.PIE = ctx.PIE
		revPayload.NX = ctx.NX
		revPayload.Canary = ctx.Canary
		revPayload.RELRO = ctx.RELRO
		revPayload.Stripped = ctx.Stripped
		revPayload.VulnFunctions = ctx.VulnFunctions
		revPayload.YARAMatches = ctx.YARAMatches
		revPayload.ROPGadgets = ctx.ROPGadgets
		revPayload.SuspiciousStrings = ctx.SuspiciousStrings
	}

	var aiResult string
	var aiErr error
	if localMode {
		aiResult, aiErr = api.SendRevEng(revPayload)
	} else {
		aiResult, aiErr = api.SendRevEng(revPayload)
	}
	if aiErr != nil {
		printError("AI analysis failed: " + aiErr.Error())
		return
	}
	clean := utils.StripMarkdown(aiResult)
	printResult("⚙️  RevEng → "+target, clean)
	_ = storage.AddEntry("/reveng "+target, clean)
}

// ─── Locate Command Handler ───────────────────────────────────────────────────

func runLocate(target string, advanced bool, localMode bool) {
	label := "🌍 LOCATE"
	if advanced {
		label = "🛰️  LOCATE ADVANCED (SDR)"
	}
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF88")).Render("  "+label+" — "+target))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	result := locatePkg.RunLocate(target, advanced, nil, func(status locatePkg.LocateStatus) {
		switch status.Kind {
		case locatePkg.LocateRunning:
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
				fmt.Sprintf("  ⟳ %-18s running...", status.Tool)))
		case locatePkg.LocateDone:
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
				fmt.Sprintf("  ✓ %-18s done (%s)", status.Tool, status.Took.Round(time.Millisecond))))
		case locatePkg.LocateFailed:
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render(
				fmt.Sprintf("  ✗ %-18s failed", status.Tool)))
		case locatePkg.LocateKindSkipped:
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
				fmt.Sprintf("  - %-18s skipped — %s", status.Tool, status.Reason)))
		}
	})

	// Print findings
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF88")).Render("  🌍 Location Findings"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	if result.Context != nil {
		ctx := result.Context
		if ctx.City != "" || ctx.Country != "" {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF88")).Render(
				fmt.Sprintf("  📍 Location:   %s, %s", ctx.City, ctx.Country)))
		}
		if ctx.ISP != "" {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render(
				"  🏢 ISP/Org:    "+ctx.ISP))
		}
		if len(ctx.Coordinates) > 0 {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700")).Render(
				"  🗺️  GPS:        "+strings.Join(ctx.Coordinates, " | ")))
		}
		if ctx.ExifGPS != "" {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4444")).Render(
				"  📸 EXIF GPS:   "+strings.TrimSpace(ctx.ExifGPS)))
		}
		if len(ctx.WiFiSSIDs) > 0 {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(
				fmt.Sprintf("  📶 WiFi SSIDs: %d captured", len(ctx.WiFiSSIDs))))
		}
		if len(ctx.CellTowers) > 0 {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4444")).Render(
				fmt.Sprintf("  📡 Cell towers: %d captured", len(ctx.CellTowers))))
		}
	}

	if len(result.Tools) == 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render("  ✗ No location data found."))
		return
	}

	// AI analysis
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render("  ⟳ AI geolocation analysis..."))

	findings := make(map[string]string)
	for _, tr := range result.Results {
		if tr.Output != "" {
			out := tr.Output
			if len(out) > 3000 {
				out = out[:3000] + "\n...[truncated]"
			}
			findings[tr.Tool] = out
		}
	}

	// AbuseIPDB + OTX threat intel removed (breach package removed)
	locTargetType := locatePkg.DetectLocateTargetType(target)

	combined := locatePkg.GetLocateCombinedOutput(result)
	if len(combined) > 20000 {
		combined = combined[:20000] + "\n...[truncated]"
	}

	locPayload := api.LocatePayload{
		Target:      target,
		TargetType:  locTargetType,
		ToolsRun:    result.Tools,
		Findings:    findings,
		RawCombined: combined,
	}
	if result.Context != nil {
		ctx := result.Context
		locPayload.Coordinates = ctx.Coordinates
		locPayload.City = ctx.City
		locPayload.Country = ctx.Country
		locPayload.ISP = ctx.ISP
		locPayload.ExifGPS = ctx.ExifGPS
		locPayload.WiFiSSIDs = ctx.WiFiSSIDs
		locPayload.CellTowers = ctx.CellTowers
	}

	var aiResult string
	var aiErr error
	if localMode {
		aiResult, aiErr = api.SendLocate(locPayload)
	} else {
		aiResult, aiErr = api.SendLocate(locPayload)
	}
	if aiErr != nil {
		printError("AI analysis failed: " + aiErr.Error())
		return
	}
	clean := utils.StripMarkdown(aiResult)
	printResult("🌍 Locate → "+target, clean)
	_ = storage.AddEntry("/locate "+target, clean)
}

// ─── OMEGA Agentic Brain Loop ─────────────────────────────────────────────

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

	// Track attack session in web dashboard (non-blocking)
	api.SendAttackSessionStart(target, "omega")

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

	maxIterations := 20 // increased from 15
	if mode == "overnight" {
		maxIterations = 40 // increased from 30
	} else if mode == "quick" {
		maxIterations = 10 // increased from 8
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

			// Set mode env so reconftw uses correct flags (quick/-s, deep/-r, overnight/-a --deep)
			os.Setenv("CYBERMIND_MODE", mode)

			// ── NEW v5.1.0: Crawling Intelligence Analysis ─────────────────
			// Before running recon, analyze what crawling types are needed
			crawlingIntel := brain.AnalyzeCrawlingNeeds(target, state.Technologies, state.LiveURLs, state.OpenPorts)
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
				brain.FormatCrawlingPlan(crawlingIntel)))

			// Set headless mode if SPA detected
			if crawlingIntel.SPADetected {
				os.Setenv("CYBERMIND_HEADLESS_CRAWL", "true")
				fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700")).Render(
					"  ⚡ SPA detected — enabling headless browser crawling (katana -headless)"))
			}
			// Set API crawling if API detected
			if crawlingIntel.APIDetected {
				os.Setenv("CYBERMIND_API_CRAWL", "true")
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render(
					"  🔌 API detected — enabling Swagger/OpenAPI crawling"))
			}

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

				// ── NEW v5.0.0: Run Recon Brain Intelligence Analysis ──────
				// Build phase results from recon output
				phaseResult := brain.ReconPhaseResult{
					Phase:       1,
					ToolsRun:    reconResult.Tools,
					Subdomains:  rc.Subdomains,
					LiveURLs:    rc.LiveURLs,
					OpenPorts:   rc.OpenPorts,
					Technologies: rc.Technologies,
					WAFDetected: rc.WAFDetected,
					WAFVendor:   rc.WAFVendor,
					Secrets:     rc.ReconFTWSecrets,
					Emails:      rc.ReconFTWEmails,
					Buckets:     rc.ReconFTWBuckets,
					Takeovers:   rc.ReconFTWTakeover,
					CMSType:     "", // populated from hunt phase
				}

				// Analyze intelligence
				reconIntel := brain.AnalyzeReconIntelligence(
					target,
					[]brain.ReconPhaseResult{phaseResult},
					rc.Technologies,
					rc.LiveURLs,
				)

				// Display intelligence report
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
					brain.FormatReconIntelligence(reconIntel)))

				// Apply intelligence to agent state
				if reconIntel.Priority == "critical" || reconIntel.Priority == "high" {
					fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red2).Render(
						fmt.Sprintf("  🎯 HIGH-VALUE TARGET: %s priority (%.0f%% confidence)",
							strings.ToUpper(reconIntel.Priority), reconIntel.Confidence*100)))
				}

				// Override focus bugs with intelligence-driven recommendations
				if len(reconIntel.RecommendedFocus) > 0 && focusBugs == "" {
					focusBugs = strings.Join(reconIntel.RecommendedFocus[:min(5, len(reconIntel.RecommendedFocus))], ",")
					os.Setenv("CYBERMIND_FOCUS_BUGS", focusBugs)
					fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render(
						"  🧠 Brain focus: " + focusBugs))
				}

				// Immediate wins — flag for priority handling
				if len(reconIntel.TakeoverTargets) > 0 {
					allFindings["immediate_takeovers"] = strings.Join(reconIntel.TakeoverTargets, "\n")
					state.BugsFound += len(reconIntel.TakeoverTargets)
				}
				if len(reconIntel.ExposedSecrets) > 0 {
					allFindings["immediate_secrets"] = strings.Join(reconIntel.ExposedSecrets[:min(10, len(reconIntel.ExposedSecrets))], "\n")
				}
				if len(reconIntel.CloudBuckets) > 0 {
					allFindings["immediate_buckets"] = strings.Join(reconIntel.CloudBuckets, "\n")
				}

				// ── Feed JS analysis findings into agent state ────────────
				if rc.ReconFTWDone {
					if len(rc.ReconFTWSecrets) > 0 {
						allFindings["recon_js_secrets"] = strings.Join(rc.ReconFTWSecrets[:min(10, len(rc.ReconFTWSecrets))], "\n")
						fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red2).Render(
							fmt.Sprintf("  🔑 reconFTW found %d secrets/API keys!", len(rc.ReconFTWSecrets))))
					}
					if len(rc.ReconFTWTakeover) > 0 {
						allFindings["recon_takeovers"] = strings.Join(rc.ReconFTWTakeover, "\n")
						fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red2).Render(
							fmt.Sprintf("  ⚠️  %d subdomain takeover candidates!", len(rc.ReconFTWTakeover))))
					}
					if len(rc.ReconFTWBuckets) > 0 {
						allFindings["recon_buckets"] = strings.Join(rc.ReconFTWBuckets, "\n")
						fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(yellow2).Render(
							fmt.Sprintf("  ☁️  %d exposed cloud buckets found!", len(rc.ReconFTWBuckets))))
					}
					if len(rc.ReconFTWVulns) > 0 {
						allFindings["recon_vulns"] = strings.Join(rc.ReconFTWVulns[:min(20, len(rc.ReconFTWVulns))], "\n")
					}
				}
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

			// ── Save snapshot after recon ──────────────────────────────────
			go func() {
				runID := brain.GenerateRunID()
				var snapVulns []brain.SnapshotVuln
				for _, v := range reconResult.Results {
					for _, line := range strings.Split(v.Output, "\n") {
						if strings.Contains(strings.ToLower(line), "[critical]") || strings.Contains(strings.ToLower(line), "[high]") {
							sev := "high"
							if strings.Contains(strings.ToLower(line), "[critical]") {
								sev = "critical"
							}
							snapVulns = append(snapVulns, brain.SnapshotVuln{Type: "nuclei", URL: target, Severity: sev, Tool: v.Tool})
						}
					}
				}
				var rc2 recon.ReconContext
				if reconResult.Context != nil {
					rc2 = *reconResult.Context
				}
				snap := brain.ScanSnapshot{
					Target: target, Timestamp: time.Now(), RunID: runID, Mode: "omega_recon",
					Subdomains: rc2.Subdomains, LiveURLs: rc2.LiveURLs, OpenPorts: rc2.OpenPorts,
					Technologies: rc2.Technologies, Vulns: snapVulns,
					JSSecrets: rc2.ReconFTWSecrets, CloudBuckets: rc2.ReconFTWBuckets,
					TakeoverCandidates: rc2.ReconFTWTakeover,
					SubdomainCount: len(rc2.Subdomains), VulnCount: len(snapVulns),
				}
				brain.SaveSnapshot(snap)
			}()

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

			// ── NEW v5.2.0: Crawling Intelligence Analysis for Hunt ───────
			// Before running hunt, analyze what crawling types are needed
			crawlingIntel := brain.AnalyzeCrawlingNeeds(target, state.Technologies, state.LiveURLs, state.OpenPorts)
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(
				brain.FormatCrawlingPlan(crawlingIntel)))

			// Set headless mode if SPA detected
			if crawlingIntel.SPADetected {
				os.Setenv("CYBERMIND_HEADLESS_CRAWL", "true")
				fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700")).Render(
					"  ⚡ SPA detected — enabling headless browser crawling (katana -headless)"))
			}
			// Set API crawling if API detected
			if crawlingIntel.APIDetected {
				os.Setenv("CYBERMIND_API_CRAWL", "true")
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render(
					"  🔌 API detected — enabling Swagger/OpenAPI crawling"))
			}

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

	// ── Generate HTML report for OMEGA run ────────────────────────────────
	go func() {
		runID := brain.GenerateRunID()
		var rc recon.ReconContext
		if reconResult.Context != nil {
			rc = *reconResult.Context
		}
		var snapVulns []brain.SnapshotVuln
		for _, b := range allBugs {
			snapVulns = append(snapVulns, brain.SnapshotVuln{
				Type: b.Title, URL: b.URL, Severity: string(b.Severity),
				Tool: b.Tool, Evidence: b.Evidence,
			})
		}
		snap := brain.ScanSnapshot{
			Target: target, Timestamp: time.Now(), RunID: runID, Mode: "omega",
			Subdomains: rc.Subdomains, LiveURLs: rc.LiveURLs, OpenPorts: rc.OpenPorts,
			Technologies: rc.Technologies, Vulns: snapVulns,
			JSSecrets: rc.ReconFTWSecrets, CloudBuckets: rc.ReconFTWBuckets,
			TakeoverCandidates: rc.ReconFTWTakeover,
			SubdomainCount: len(rc.Subdomains), VulnCount: len(snapVulns),
		}
		brain.SaveSnapshot(snap)

		// Diff vs previous
		var diff *brain.ScanDiff
		if prevSnap, err := brain.LoadLatestSnapshot(target); err == nil && prevSnap.RunID != runID {
			d := brain.DiffSnapshots(prevSnap, &snap)
			diff = &d
		}

		// Build hotlist
		hotlist := brain.BuildHotlist(&snap, diff, 20)

		// Generate HTML report
		reportData := brain.ReportData{
			Target: target, ScanMode: "omega/" + mode,
			StartTime: time.Now().Add(-time.Duration(state.Iteration*10) * time.Minute),
			EndTime: time.Now(), RunID: runID,
			Subdomains: rc.Subdomains, LiveURLs: rc.LiveURLs,
			OpenPorts: rc.OpenPorts, Technologies: rc.Technologies,
			WAFDetected: rc.WAFDetected, WAFVendor: rc.WAFVendor,
			Vulns: snapVulns, JSSecrets: rc.ReconFTWSecrets,
			CloudBuckets: rc.ReconFTWBuckets, Takeovers: rc.ReconFTWTakeover,
			Diff: diff, Hotlist: hotlist,
			ToolsRun: state.ToolsRan,
		}
		if htmlPath, err := brain.GenerateHTMLReport(reportData); err == nil {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF88")).Render(
				"  ✓ OMEGA HTML report: " + htmlPath))
		}
		if len(hotlist) > 0 {
			hotlistPath := brain.SaveHotlist(target, hotlist)
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(
				fmt.Sprintf("  🎯 Hotlist (%d items): %s", len(hotlist), hotlistPath)))
		}
		// Append to asset store
		var assetRecords []brain.AssetRecord
		for _, s := range rc.Subdomains {
			assetRecords = append(assetRecords, brain.AssetRecord{
				Target: target, Type: "subdomain", Value: s,
				Tool: "omega", Timestamp: time.Now(), RunID: runID,
			})
		}
		for _, b := range allBugs {
			assetRecords = append(assetRecords, brain.AssetRecord{
				Target: target, Type: "vuln", Value: b.URL,
				Severity: string(b.Severity), Tool: b.Tool,
				Timestamp: time.Now(), RunID: runID,
			})
		}
		brain.AppendAssetStore(target, assetRecords)
	}()

	// Track attack session completion in web dashboard (non-blocking)
	findingChance := 30
	if state.BugsFound > 0 {
		findingChance = 85
	} else if state.HuntDone {
		findingChance = 45
	}
	api.SendAttackSessionComplete(target, "omega", state.BugsFound, len(state.ToolsRan), findingChance)
}

// localAgentDecision makes a decision without AI — pure logic fallback
// localAgentDecision is the fallback decision engine when AI is unavailable.
// It implements a proper state machine that:
// 1. Always runs recon → hunt → exploit (Abhimanyu) → poc
// 2. Selects vuln-specific exploit focus based on what was found
// 3. Runs deep_hunt for second-pass scanning when first hunt finds nothing
// 4. Exits early on critical findings in quick mode
func localAgentDecision(state api.AgentState) *api.AgentDecision {
	// Use brain intelligence for local decisions
	action, vulnFocus, reason := brain.SuggestNextAction(
		state.Target,
		state.ReconDone,
		state.HuntDone,
		state.AbhiDone,
		state.BugsFound,
		state.BugTypes,
		state.Technologies,
		state.WAFDetected,
		state.Mode,
	)
	return &api.AgentDecision{
		Action:    action,
		VulnFocus: vulnFocus,
		Reason:    reason,
		Depth:     "deep",
	}
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

	// ── STEP 0.5: Smart target-type detection ────────────────────────────
	// Detect what kind of target this is and show the right pipeline.
	// This is the core of "OMEGA target-type routing".
	detectedType := omega.DetectOmegaTargetType(target)
	pipeline := omega.GetOmegaPipeline(detectedType, target)
	omega.DisplayOmegaPipeline(pipeline, target)

	// For non-web targets: run the specialized pipeline and return
	// Web targets continue with the full OMEGA flow below
	switch detectedType {
	case omega.TargetEmail, omega.TargetPhone, omega.TargetPerson, omega.TargetHash:
		// Pure intelligence targets — no recon/hunt/abhimanyu needed
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700")).Render(
			fmt.Sprintf("  ℹ  %s target detected — running intelligence pipeline", strings.ToUpper(string(detectedType)))))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			"  Run each phase manually with the commands shown above."))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			"  Or press Enter to auto-run all phases now."))
		fmt.Print(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render("  Auto-run pipeline? [Y/n] → "))
		var pipeAns string
		fmt.Scanln(&pipeAns)
		if strings.ToLower(strings.TrimSpace(pipeAns)) != "n" {
			runOmegaSpecializedPipeline(pipeline, localMode)
		}
		return

	case omega.TargetBinary, omega.TargetAPK:
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render(
			fmt.Sprintf("  ℹ  %s target detected — running reverse engineering pipeline", strings.ToUpper(string(detectedType)))))
		fmt.Print(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render("  Auto-run pipeline? [Y/n] → "))
		var pipeAns string
		fmt.Scanln(&pipeAns)
		if strings.ToLower(strings.TrimSpace(pipeAns)) != "n" {
			runOmegaSpecializedPipeline(pipeline, localMode)
		}
		return

	case omega.TargetCompany:
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00CFFF")).Render(
			"  ℹ  Company target detected — running corporate intelligence pipeline"))
		fmt.Print(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render("  Auto-run pipeline? [Y/n] → "))
		var pipeAns string
		fmt.Scanln(&pipeAns)
		if strings.ToLower(strings.TrimSpace(pipeAns)) != "n" {
			runOmegaSpecializedPipeline(pipeline, localMode)
		}
		return

	case omega.TargetIP:
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render(
			"  ℹ  IP target detected — network exploitation pipeline"))
		// IP targets still go through the full OMEGA flow but with network focus
		os.Setenv("CYBERMIND_FOCUS_BUGS", "network,rce,auth")
		// Fall through to full OMEGA flow

	case omega.TargetWeb:
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF88")).Render(
			"  ✓ Web/Domain target — full bug bounty pipeline"))
		// Fall through to full OMEGA flow
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


// -- STEP 3.5: Phase 0 OSINT Deep (passive intel before touching target) --
fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render("  🔍 PHASE 0 — OSINT DEEP"))
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("-", 60)))
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render("  Passive intel: subfinder, amass, theHarvester, sherlock, h8mail, spiderfoot"))
fmt.Println()
osintPhase0Result := osintPkg.RunOSINTDeep(target, nil, func(status osintPkg.OSINTStatus) {
switch status.Kind {
case osintPkg.OSINTRunning:
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(fmt.Sprintf("  o [OSINT] %-16s running...", status.Tool)))
case osintPkg.OSINTDone:
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(fmt.Sprintf("  v [OSINT] %-16s done (%s)", status.Tool, status.Took.Round(time.Millisecond))))
case osintPkg.OSINTFailed:
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render(fmt.Sprintf("  x [OSINT] %-16s failed", status.Tool)))
case osintPkg.OSINTKindSkipped:
}
})
if osintPhase0Result.Context != nil {
ctx0 := osintPhase0Result.Context
fmt.Println()
if len(ctx0.SubdomainsFound) > 0 {
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(fmt.Sprintf("  v Subdomains: %d found", len(ctx0.SubdomainsFound))))
}
if len(ctx0.EmailsFound) > 0 {
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(fmt.Sprintf("  v Emails: %d found", len(ctx0.EmailsFound))))
}
if len(ctx0.BreachesFound) > 0 {
fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4444")).Render(fmt.Sprintf("  ! BREACHES: %d found - credential stuffing possible!", len(ctx0.BreachesFound))))
}
if len(ctx0.SocialProfiles) > 0 {
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(fmt.Sprintf("  v Social profiles: %d found", len(ctx0.SocialProfiles))))
}
if len(ctx0.EmployeesFound) > 0 {
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(fmt.Sprintf("  v Employees: %d found", len(ctx0.EmployeesFound))))
}
fmt.Println()
}
_ = osintPhase0Result
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

	// ── STEP 10: Abhimanyu — GUARANTEED FINAL PHASE ──────────────────────
	// Abhimanyu always runs after OMEGA agentic loop, regardless of bug count.
	// It uses all intelligence gathered: ports, vulns, creds, tech stack.
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4444")).Render(
		"  ⚔️  ABHIMANYU MODE — FINAL EXPLOITATION PHASE"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render(
		"  Entering the Chakravyuh. Fighting every layer. No retreat."))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render(
		"  " + strings.Repeat("─", 60)))
	fmt.Println()

	abhimanyuAns := readWithTimeout(
		lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render("  Run Abhimanyu exploit phase? [Y/n] → "),
		"y", 20)

	if strings.ToLower(strings.TrimSpace(abhimanyuAns)) != "n" {
		// Build AbhimanyuContext from everything OMEGA gathered
		lhost := getLocalIP()

		// Load brain memory for this target — has ports, tech, vulns from recon/hunt
		mem := brain.LoadTarget(target)

		// Determine best vuln focus from what was found
		vulnFocus := os.Getenv("CYBERMIND_FOCUS_BUGS")
		if vulnFocus == "" {
			vulnFocus = "all"
		}

		abhCtx := &abhimanyu.AbhimanyuContext{
			Target:       target,
			TargetType:   "domain",
			VulnType:     vulnFocus,
			LHOST:        lhost,
			LPORT:        "4444",
			OpenPorts:    mem.OpenPorts,
			Technologies: mem.TechStack,
			LiveURLs:     mem.LiveURLs,
			WAFDetected:  mem.WAFDetected,
			WAFVendor:    mem.WAFVendor,
		}

		// Pass vulns/XSS found during hunt phase
		for _, b := range mem.BugsFound {
			lower := strings.ToLower(b.Type)
			if strings.Contains(lower, "xss") {
				abhCtx.XSSFound = appendStrUnique(abhCtx.XSSFound, b.URL)
			} else {
				abhCtx.VulnsFound = appendStrUnique(abhCtx.VulnsFound, b.Title)
			}
		}

		results := abhimanyu.RunAbhimanyuMode(abhCtx, func(status abhimanyu.AbhimanyuStatus) {
			switch status.Kind {
			case abhimanyu.StatusInstalling:
				fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
					fmt.Sprintf("  ⟳ %-22s installing...", status.Tool)))
			case abhimanyu.StatusRunning:
				reason := ""
				if status.Reason != "" {
					reason = " (" + status.Reason + ")"
				}
				fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(
					fmt.Sprintf("  ⟳ %-22s attacking...%s", status.Tool, reason)))
			case abhimanyu.StatusDone:
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render(
					fmt.Sprintf("  ✓ %-22s done (%s)", status.Tool, status.Took.Round(time.Millisecond))))
			case abhimanyu.StatusFailed:
				fmt.Println(lipgloss.NewStyle().Foreground(red).Render(
					fmt.Sprintf("  ✗ %-22s failed — %s", status.Tool, status.Reason)))
			case abhimanyu.StatusSkipped:
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
					fmt.Sprintf("  - %-22s skipped — %s", status.Tool, status.Reason)))
			}
		})

		// Print summary
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4444")).Render(
			"  ⚔️  Abhimanyu Summary"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render(
			"  " + strings.Repeat("─", 60)))

		successCount := 0
		for _, r := range results {
			if r.Success && r.Output != "" {
				successCount++
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render(
					fmt.Sprintf("  ✓ %-22s → %d chars output", r.Tool, len(r.Output))))
			}
		}

		if abhCtx.ShellObtained {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF0000")).Render(
				fmt.Sprintf("  🔴 SHELL OBTAINED: %s | Evidence: %s", abhCtx.ShellType, abhCtx.ShellEvidence)))
		}
		if len(abhCtx.CredsFound) > 0 {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4444")).Render(
				fmt.Sprintf("  🔑 CREDENTIALS FOUND: %d", len(abhCtx.CredsFound))))
			for _, c := range abhCtx.CredsFound[:min(3, len(abhCtx.CredsFound))] {
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render("     → " + c))
			}
		}
		if len(abhCtx.HashesFound) > 0 {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(
				fmt.Sprintf("  🔐 HASHES FOUND: %d (saved to session dir)", len(abhCtx.HashesFound))))
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			fmt.Sprintf("  Session: %s", abhCtx.SessionDir)))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			fmt.Sprintf("  MSF script: msfconsole -r %s/cybermind_msf.rc", abhCtx.SessionDir)))

		// Record in brain memory
		for _, v := range abhCtx.VulnsFound {
			brain.RecordBug(target, brain.Bug{
				Title:    v,
				Type:     "exploit",
				Severity: "high",
				Tool:     "abhimanyu",
			})
		}
	} else {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			"  Skipped. Run manually: cybermind /abhimanyu " + target))
	}

	// ── STEP 11: Aegis Deep Scan — runs after Abhimanyu ──────────────────
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render(
		"  ⚔️  AEGIS DEEP SCAN — Additional attack surface coverage"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
		"  Aegis adds: HTTP smuggling, OOB SSRF/XXE, cloud assets, MSF, CVE correlation, HTML report"))
	fmt.Println()

	aegisAns := readWithTimeout(
		lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render("  Run Aegis deep scan? [Y/n] → "),
		"y", 15)

	if strings.ToLower(strings.TrimSpace(aegisAns)) != "n" {
		runAegisIntegration(target, "default")
	} else {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
			"  Skipped. Run manually: cybermind /aegis " + target))
	}
}

// appendStrUnique appends a string to a slice only if not already present
func appendStrUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

// runOmegaSpecializedPipeline executes a non-web OMEGA pipeline
// (email, phone, person, company, binary, APK, hash targets)
func runOmegaSpecializedPipeline(pipeline omega.OmegaPipeline, localMode bool) {
	s := func(color lipgloss.Color, text string) string {
		return lipgloss.NewStyle().Foreground(color).Render(text)
	}
	b := func(color lipgloss.Color, text string) string {
		return lipgloss.NewStyle().Bold(true).Foreground(color).Render(text)
	}

	fmt.Println()
	fmt.Println(b(cyan, fmt.Sprintf("  ⚡ OMEGA PIPELINE — %s", strings.ToUpper(string(pipeline.TargetType)))))
	fmt.Println(s(lipgloss.Color("#333333"), "  "+strings.Repeat("─", 60)))
	fmt.Println()

	for i, phase := range pipeline.Phases {
		fmt.Println()
		fmt.Println(b(lipgloss.Color("#FFD700"), fmt.Sprintf("  [%d/%d] %s", i+1, len(pipeline.Phases), phase.Name)))
		fmt.Println(s(dim, "  "+phase.Description))
		fmt.Println()

		// Parse the command and run it
		// Commands are like "/osint-deep target" or "/breach target"
		parts := strings.Fields(phase.Command)
		if len(parts) == 0 {
			continue
		}

		cmd := parts[0]
		args := parts[1:]

		switch cmd {
		case "/osint-deep":
			if len(args) > 0 {
				runOSINTDeep(args[0], nil, localMode)
			}
		case "/locate":
			if len(args) > 0 {
				runLocate(args[0], false, localMode)
			}
		case "/threat":
			if len(args) > 0 {
				// Threat intel via AI analysis
				prompt := fmt.Sprintf("Threat intelligence analysis for: %s\nProvide: reputation, known malicious activity, CVEs, MITRE ATT&CK mapping, recommended actions.", args[0])
				if result, err := api.SendPrompt(prompt); err == nil {
					printResult("🔴 Threat Intel → "+args[0], utils.StripMarkdown(result))
				}
			}
		case "/osint":
			if len(args) > 0 {
				runOSINT(args[0], localMode)
			}
		case "/cloud":
			if len(args) > 0 {
				// Cloud scan — inline
				fmt.Println(s(cyan, "  ⟳ Cloud misconfiguration scan..."))
				cloudTarget := args[0]
				mem := brain.LoadTarget(cloudTarget)
				cloudResult := brain.ScanCloudMisconfigurations(cloudTarget, mem.SubdomainsFound)
				fmt.Println(s(lipgloss.Color("#E0E0E0"), brain.FormatCloudReport(cloudResult)))
			}
		case "/reveng":
			if len(args) > 0 {
				mode := "all"
				for j, a := range args {
					if a == "--mode" && j+1 < len(args) {
						mode = args[j+1]
					}
				}
				runRevEng(args[0], mode, nil, localMode)
			}
		case "/mobile":
			if len(args) > 0 {
				fmt.Println(s(cyan, "  ⟳ Mobile APK analysis..."))
				mobileResult := brain.AnalyzeAPK(args[0])
				fmt.Println(s(lipgloss.Color("#E0E0E0"), brain.FormatMobileReport(mobileResult)))
			}
		case "/cve-feed":
			if len(args) > 0 {
				mem := brain.LoadTarget(args[0])
				cveResult := brain.MatchCVEsToTarget(args[0], mem.TechStack, "")
				fmt.Println(s(lipgloss.Color("#E0E0E0"), brain.FormatCVEReport(cveResult)))
			}
		case "/recon":
			if len(args) > 0 {
				runAutoReconSilent(args[0], nil)
			}
		case "/hunt":
			if len(args) > 0 {
				runHuntSilent(args[0], nil, nil)
			}
		case "/abhimanyu":
			if len(args) > 0 {
				vulnType := "all"
				if len(args) > 1 {
					vulnType = args[1]
				}
				runAbhimanyu(args[0], vulnType)
			}
		default:
			fmt.Println(s(dim, fmt.Sprintf("  Skipping %s — run manually: cybermind %s", cmd, phase.Command)))
		}

		// Optional phase — ask before running
		if !phase.Required && i < len(pipeline.Phases)-1 {
			fmt.Println()
			fmt.Print(s(lipgloss.Color("#FFD700"), fmt.Sprintf("  Continue to next phase? [Y/n] → ")))
			var cont string
			fmt.Scanln(&cont)
			if strings.ToLower(strings.TrimSpace(cont)) == "n" {
				fmt.Println(s(dim, "  Pipeline stopped. Run remaining phases manually."))
				return
			}
		}
	}

	fmt.Println()
	fmt.Println(b(green, "  ✓ OMEGA Pipeline complete!"))
	fmt.Println()
}
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


// ─── Aegis Integration ────────────────────────────────────────────────────────

// runAegisIntegration runs Aegis as a deep scan layer after OMEGA completes.
// Aegis adds: HTTP smuggling, OOB SSRF/XXE, cloud asset discovery,
// Metasploit auto-mapping, CVE correlation, SARIF export, D3.js HTML report.
func runAegisIntegration(target string, mode string) {
	cyan2 := lipgloss.Color("#00FFFF")
	green2 := lipgloss.Color("#00FF00")
	red2 := lipgloss.Color("#FF4444")
	yellow2 := lipgloss.Color("#FFD700")
	dim2 := lipgloss.Color("#777777")
	purple2 := lipgloss.Color("#8A2BE2")

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render("  ⚔️  AEGIS DEEP SCAN — " + target))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render("  AI-driven autonomous pentest: HTTP smuggling, OOB SSRF/XXE, cloud assets, MSF, CVE correlation"))
	fmt.Println()

	// Ensure Aegis is installed
	if !aegis.IsInstalled() {
		fmt.Println(lipgloss.NewStyle().Foreground(yellow2).Render("  ⟳ Aegis not installed — setting up isolated Python environment..."))
		fmt.Println()

		err := aegis.EnsureInstalled(func(status aegis.AegisStatus) {
			if status.Error {
				fmt.Println(lipgloss.NewStyle().Foreground(red2).Render("  ✗ " + status.Message))
			} else if status.Done {
				fmt.Println(lipgloss.NewStyle().Foreground(green2).Render("  ✓ " + status.Message))
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(purple2).Render("  ⟳ " + status.Message))
			}
		})

		if err != nil {
			fmt.Println(lipgloss.NewStyle().Foreground(red2).Render("  ✗ Aegis setup failed: " + err.Error()))
			fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render("  Skipping Aegis deep scan. CyberMind results are still complete."))
			return
		}
		fmt.Println()
	} else {
		fmt.Println(lipgloss.NewStyle().Foreground(green2).Render("  ✓ Aegis installed and ready"))
		fmt.Println()
	}

	onLine := func(line string) {
		if line == "" {
			return
		}
		// Color-code Aegis output
		switch {
		case strings.Contains(line, "✓") || strings.Contains(line, "SUCCESS") || strings.Contains(line, "FOUND"):
			fmt.Println(lipgloss.NewStyle().Foreground(green2).Render("  " + line))
		case strings.Contains(line, "✗") || strings.Contains(line, "ERROR") || strings.Contains(line, "FAIL"):
			fmt.Println(lipgloss.NewStyle().Foreground(red2).Render("  " + line))
		case strings.Contains(line, "⟳") || strings.Contains(line, "Running") || strings.Contains(line, "Scanning"):
			fmt.Println(lipgloss.NewStyle().Foreground(purple2).Render("  " + line))
		case strings.Contains(line, "WARNING") || strings.Contains(line, "WARN"):
			fmt.Println(lipgloss.NewStyle().Foreground(yellow2).Render("  " + line))
		default:
			fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render("  " + line))
		}
	}

	switch mode {
	case "auto", "full":
		// Full autonomous pentest
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render("  🤖 Running full autonomous pentest..."))
		fmt.Println()
		if err := aegis.RunAuto(target, onLine); err != nil {
			fmt.Println(lipgloss.NewStyle().Foreground(red2).Render("  ✗ Aegis auto failed: " + err.Error()))
		}

	case "recon":
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render("  🔍 Running Aegis recon..."))
		aegis.RunRecon(target, onLine)

	case "vuln":
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render("  🔎 Running Aegis web vuln scan..."))
		aegis.RunVulnWeb(target, "", onLine)

	case "exploit":
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render("  💥 Running Aegis exploit phase..."))
		// HTTP smuggling
		fmt.Println(lipgloss.NewStyle().Foreground(purple2).Render("  ⟳ HTTP Request Smuggling detection..."))
		aegis.RunSmuggling("https://"+target, onLine)
		// OOB SSRF/XXE
		fmt.Println(lipgloss.NewStyle().Foreground(purple2).Render("  ⟳ OOB SSRF/XXE detection (interactsh)..."))
		aegis.RunExploitOOB("https://"+target, onLine)
		// Cloud assets
		fmt.Println(lipgloss.NewStyle().Foreground(purple2).Render("  ⟳ Cloud asset discovery (S3/Azure/GCP)..."))
		aegis.RunCloudRecon(target, onLine)
		// Metasploit auto-mapping
		fmt.Println(lipgloss.NewStyle().Foreground(purple2).Render("  ⟳ Metasploit module auto-mapping..."))
		aegis.RunExploitMSF(target, onLine)

	default:
		// Default: recon + vuln + key exploits
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render("  🔍 Phase 1: Aegis Recon..."))
		aegis.RunRecon(target, onLine)

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render("  🔎 Phase 2: Aegis Web Vuln Scan..."))
		aegis.RunVulnWeb(target, "", onLine)

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render("  💥 Phase 3: Advanced Exploits..."))
		fmt.Println(lipgloss.NewStyle().Foreground(purple2).Render("  ⟳ HTTP Request Smuggling..."))
		aegis.RunSmuggling("https://"+target, onLine)
		fmt.Println(lipgloss.NewStyle().Foreground(purple2).Render("  ⟳ OOB SSRF/XXE (interactsh)..."))
		aegis.RunExploitOOB("https://"+target, onLine)
		fmt.Println(lipgloss.NewStyle().Foreground(purple2).Render("  ⟳ Cloud asset discovery..."))
		aegis.RunCloudRecon(target, onLine)
	}

	// CVE correlation
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(purple2).Render("  ⟳ CVE correlation (NVD API)..."))
	aegis.RunCVECorrelate(1, onLine)

	// AI triage
	fmt.Println(lipgloss.NewStyle().Foreground(purple2).Render("  ⟳ AI triage of findings..."))
	aegis.RunAITriage(1, onLine)

	// Generate HTML report with D3.js attack path graph
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(purple2).Render("  ⟳ Generating HTML report with attack path graph..."))
	reportPath, err := aegis.RunReport(target, "html", onLine)
	if err == nil && reportPath != "" {
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green2).Render("  ✓ HTML report: " + reportPath))
	}

	// SARIF export for GitHub Code Scanning
	sarifPath := aegis.GetAegisDir() + "/data/reports/" + strings.ReplaceAll(target, ".", "_") + ".sarif"
	aegis.RunSARIFExport(1, sarifPath, onLine)
	if _, err := os.Stat(sarifPath); err == nil {
		fmt.Println(lipgloss.NewStyle().Foreground(green2).Render("  ✓ SARIF export: " + sarifPath))
	}

	// Read and display findings summary
	fmt.Println()
	summary := aegis.GetFindingsSummary(target)
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render("  📊 AEGIS FINDINGS SUMMARY"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).MarginLeft(2).Render(summary))
	fmt.Println()

	// Feed Aegis findings into CyberMind brain memory
	findings, _ := aegis.GetFindings(target)
	if len(findings) > 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(purple2).Render(
			fmt.Sprintf("  🧠 Feeding %d Aegis findings into CyberMind brain memory...", len(findings))))
		for _, f := range findings {
			brain.RecordBug(target, brain.Bug{
				Title:    f.Title,
				Type:     f.Category,
				URL:      f.URL,
				Severity: f.Severity,
				Evidence: f.Evidence,
				Tool:     "aegis/" + f.Tool,
				Verified: true,
			})
		}
		fmt.Println(lipgloss.NewStyle().Foreground(green2).Render("  ✓ Aegis findings saved to brain memory"))
	}

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render("  ✓ AEGIS DEEP SCAN COMPLETE"))
	fmt.Println(lipgloss.NewStyle().Foreground(dim2).Render("  Aegis data: " + aegis.GetAegisDir()))
	fmt.Println()
}

// runAegisSetup installs Aegis and all its dependencies
func runAegisSetup() {
	cyan2 := lipgloss.Color("#00FFFF")
	green2 := lipgloss.Color("#00FF00")
	red2 := lipgloss.Color("#FF4444")
	purple2 := lipgloss.Color("#8A2BE2")

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan2).Render("  🔧 AEGIS SETUP — Installing AI Pentest Platform"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render("  Installing in isolated Python venv: ~/.cybermind/aegis/"))
	fmt.Println()

	err := aegis.EnsureInstalled(func(status aegis.AegisStatus) {
		if status.Error {
			fmt.Println(lipgloss.NewStyle().Foreground(red2).Render("  ✗ " + status.Message))
		} else if status.Done {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green2).Render("  ✓ " + status.Message))
		} else {
			fmt.Println(lipgloss.NewStyle().Foreground(purple2).Render("  ⟳ " + status.Message))
		}
	})

	if err != nil {
		fmt.Println(lipgloss.NewStyle().Foreground(red2).Render("  ✗ Setup failed: " + err.Error()))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render("  Manual install: pip install aegis-cli"))
		return
	}

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green2).Render("  ✓ Aegis fully installed!"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render("  Usage:"))
	fmt.Println(lipgloss.NewStyle().Foreground(cyan2).Render("  cybermind /aegis <target>          → deep scan (recon + vuln + exploits)"))
	fmt.Println(lipgloss.NewStyle().Foreground(cyan2).Render("  cybermind /aegis <target> --auto   → full autonomous pentest"))
	fmt.Println(lipgloss.NewStyle().Foreground(cyan2).Render("  cybermind /aegis --setup           → reinstall/update Aegis"))
	fmt.Println(lipgloss.NewStyle().Foreground(cyan2).Render("  cybermind /plan <target>           → OMEGA + Aegis combined (recommended)"))
	fmt.Println()
}
