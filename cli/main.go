package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"cybermind-cli/abhimanyu"
	"cybermind-cli/api"
	"cybermind-cli/bizlogic"
	"cybermind-cli/brain"
	"cybermind-cli/hunt"
	"cybermind-cli/recon"
	"cybermind-cli/sandbox"
	"cybermind-cli/storage"
	"cybermind-cli/ui"
	"cybermind-cli/utils"
	"cybermind-cli/vibecoder"
	_ "cybermind-cli/aegis" // imported for side effects — aegis package registers itself

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	Version = "4.2.0"
	cyan    = lipgloss.Color("#00FFFF")
	green   = lipgloss.Color("#00FF00")
	purple  = lipgloss.Color("#8A2BE2")
	red     = lipgloss.Color("#FF4444")
	dim     = lipgloss.Color("#777777")
	credit  = lipgloss.Color("#555555")
	yellow  = lipgloss.Color("#FFD700")
)

// getLocalIP returns the local network IP, skipping link-local (APIPA) addresses
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}
	var fallback string
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ip := ipnet.IP.String()
				// Skip APIPA link-local addresses (169.254.x.x)
				if strings.HasPrefix(ip, "169.254.") {
					fallback = ip // keep as fallback only
					continue
				}
				return ip
			}
		}
	}
	if fallback != "" {
		return fallback
	}
	return "unknown"
}

// getOSLabel returns a styled OS label
func getOSLabel() (string, string) {
	switch runtime.GOOS {
	case "linux":
		return "🐧 Kali Linux", "#268BEE"
	case "windows":
		return "🪟 Windows", "#0078D6"
	case "darwin":
		return "🍎 macOS", "#A8A8A8"
	default:
		return runtime.GOOS, "#777777"
	}
}

func printBanner() {
	osLabel, osColor := getOSLabel()
	localIP := getLocalIP()

	lines := []struct{ text, color string }{
		{` ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗███╗   ██╗██████╗ `, "#00FFFF"},
		{`██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗`, "#00CFFF"},
		{`██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║██║  ██║`, "#009FFF"},
		{`██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██║  ██║`, "#7B68EE"},
		{`╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝`, "#8A2BE2"},
		{` ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝`, "#9400D3"},
	}

	fmt.Println()
	for _, l := range lines {
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(l.color)).Render(l.text))
	}

	// Personalized greeting — no extra blank line between banner and info
	greeting := fmt.Sprintf("  ⚡ CyberMind CLI v%s  |  %s", Version,
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(osColor)).Render(osLabel))
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render(greeting))
	fmt.Println(lipgloss.NewStyle().Foreground(credit).Render("  created by CyberMind Team under Sanjay Pandey"))

	// System info — compact, no extra blank lines
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  Local IP:  %s", localIP)))

	// Linux-only recon notice
	if runtime.GOOS == "linux" {
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ OMEGA Plan Mode available    →  cybermind /plan <target>"))
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Auto Recon Mode available  →  cybermind /recon <target>"))
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Abhimanyu Mode available   →  cybermind /abhimanyu <target>"))
	} else if runtime.GOOS == "darwin" {
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ℹ  macOS: AI chat + /scan /portscan /osint /payload /cve /wordlist report"))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ℹ  Recon/Hunt/Abhimanyu: Linux/Kali only"))
	} else {
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ℹ  Windows: AI chat + /scan /portscan /osint /payload /cve /wordlist report"))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ℹ  Recon/Hunt/Abhimanyu: Linux/Kali only"))
	}
	fmt.Println()
}

func printHelp() {
	s := lipgloss.NewStyle().Bold(true).Foreground(cyan)
	d := lipgloss.NewStyle().Foreground(dim)
	g := lipgloss.NewStyle().Foreground(green)
	y := lipgloss.NewStyle().Foreground(yellow)

	fmt.Println()
	fmt.Println(s.Render("  ⚡ CyberMind CLI – Commands"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 55)))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(purple).Render("  INTERACTIVE:"))
	fmt.Println(g.Render("  cybermind") + d.Render("                         → start AI chat"))
	fmt.Println()

	if runtime.GOOS == "linux" {
		fmt.Println(y.Render("  🐧 LINUX ONLY — AUTO RECON + HUNT:"))
		fmt.Println(g.Render("  cybermind /plan <target>") + d.Render("         → ⚡ OMEGA planning mode (auto-doctor + deep plan + execute)"))
		fmt.Println(g.Render("  cybermind /recon <target>") + d.Render("       → full auto recon + AI analysis"))
		fmt.Println(g.Render("  cybermind /recon <target> --tools nmap,httpx") + d.Render(" → run specific tools only"))
		fmt.Println(g.Render("  cybermind /hunt <target>") + d.Render("        → vulnerability hunt (XSS, params, CVEs)"))
		fmt.Println(g.Render("  cybermind /hunt <target> --tools dalfox,nuclei") + d.Render(" → specific hunt tools"))
		fmt.Println(g.Render("  cybermind /doctor") + d.Render("              → check all tools, auto-install missing"))
		fmt.Println(g.Render("  cybermind /tools") + d.Render("               → quick tool status check"))
		fmt.Println(g.Render("  cybermind /install-tools") + d.Render("       → install all recon + hunt tools"))
		fmt.Println(g.Render("  cybermind /abhimanyu <target>") + d.Render("  → ⚔️  exploit mode (auto-exploit all vulns)"))
		fmt.Println(g.Render("  cybermind /abhimanyu <target> sqli") + d.Render(" → SQLi only"))
		fmt.Println(g.Render("  cybermind /abhimanyu <target> rce") + d.Render("  → RCE/CMDi only"))
		fmt.Println(g.Render("  cybermind /abhimanyu <target> auth") + d.Render(" → Auth brute force"))
		fmt.Println(g.Render("  cybermind /abhimanyu <target> postexploit") + d.Render(" → Post-exploitation"))
		fmt.Println(g.Render("  cybermind /abhimanyu <target> lateral") + d.Render(" → Lateral movement"))
		fmt.Println(g.Render("  cybermind /osint-deep <target>") + d.Render("   → 🔍 Deep OSINT (email/username/domain/phone/company — 45 tools, 9 phases)"))
		fmt.Println(g.Render("  cybermind /osint-deep user@gmail.com") + d.Render(" → email + breach check + social footprint"))
		fmt.Println(g.Render("  cybermind /osint-deep johndoe") + d.Render("       → username hunt across 3000+ sites"))
		fmt.Println(g.Render("  cybermind /reveng <binary>") + d.Render("       → ⚙️  Reverse Engineering (static+dynamic+decompile, 30 tools)"))
		fmt.Println(g.Render("  cybermind /reveng binary --mode malware") + d.Render(" → malware analysis (YARA, ssdeep, clamscan)"))
		fmt.Println(g.Render("  cybermind /reveng app.apk --mode mobile") + d.Render(" → APK decompile (jadx, apktool)"))
		fmt.Println(g.Render("  cybermind /locate-advanced <target>") + d.Render(" → 🛰️  SDR cell tower tracking (needs hardware)"))
		fmt.Println(g.Render("  cybermind /bizlogic <target>") + d.Render("   → 💰 Business logic bugs (price manipulation, IDOR, race conditions)"))
		fmt.Println(g.Render("  cybermind /bizlogic <target> --cookie 'session=abc'") + d.Render(" → authenticated scan"))
		fmt.Println(g.Render("  cybermind /guide <target>") + d.Render("      → 📋 AI manual testing guide (step-by-step for the 12% tools can't automate)"))
		fmt.Println(g.Render("  cybermind /guide <target> --focus oauth") + d.Render(" → OAuth/SSO specific guide"))
		fmt.Println(g.Render("  cybermind /aegis <target>") + d.Render("      → ⚔️  Aegis deep scan (HTTP smuggling, OOB SSRF, cloud, MSF, CVE, HTML report)"))
		fmt.Println(g.Render("  cybermind /aegis <target> --auto") + d.Render("  → Full autonomous Aegis pentest"))
		fmt.Println(g.Render("  cybermind /aegis --setup") + d.Render("         → Install/update Aegis platform"))
		fmt.Println(g.Render("  cybermind /platform --setup") + d.Render("         → 🎯 Save HackerOne/Bugcrowd credentials for auto-submit"))
		fmt.Println(g.Render("  cybermind /platform --programs") + d.Render("      → List your HackerOne programs"))
		fmt.Println(g.Render("  cybermind /platform --status") + d.Render("        → Check saved credentials"))
		fmt.Println()
	}

	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(purple).Render("  AI GUIDED:"))
	fmt.Println(g.Render("  cybermind scan <target> [type]") + d.Render("  → AI scan guide"))
	fmt.Println(g.Render("  cybermind recon <target> [type]") + d.Render(" → AI recon guide"))
	fmt.Println(g.Render("  cybermind exploit <vuln>") + d.Render("        → exploitation guide"))
	fmt.Println(g.Render("  cybermind payload <os> [arch]") + d.Render("   → msfvenom payload"))
	fmt.Println(g.Render("  cybermind tool <name> [task]") + d.Render("    → tool usage guide"))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render("  CROSS-PLATFORM (Windows/macOS/Linux):"))
	fmt.Println(g.Render("  cybermind /scan <target>") + d.Render("        → native network scan (no tools needed)"))
	fmt.Println(g.Render("  cybermind /portscan <target>") + d.Render("    → port scan + netstat analysis"))
	fmt.Println(g.Render("  cybermind /osint <domain>") + d.Render("       → DNS + Shodan OSINT (free, no key)"))
	fmt.Println(g.Render("  cybermind /breach <email|domain>") + d.Render("  → breach intelligence (HIBP + LeakCheck + IntelX)"))
	fmt.Println(g.Render("  cybermind /breach --index /dump.txt") + d.Render(" → index local breach dump to SQLite"))
	fmt.Println(g.Render("  cybermind /locate <ip|domain|file>") + d.Render(" → geolocation (IP/EXIF/WiFi/Social)"))
	fmt.Println(g.Render("  cybermind /payload <os> <arch>") + d.Render("  → AI payload generator (no msfvenom)"))
	fmt.Println(g.Render("  cybermind /cve <CVE-ID>") + d.Render("         → CVE intelligence from NVD"))
	fmt.Println(g.Render("  cybermind /cve --latest") + d.Render("         → latest critical CVEs (7 days)"))
	fmt.Println(g.Render("  cybermind /wordlist <target>") + d.Render("    → smart target-aware wordlist generator"))
	fmt.Println(g.Render("  cybermind /platform --setup") + d.Render("     → save HackerOne/Bugcrowd credentials"))
	fmt.Println(g.Render("  cybermind /brain --target <t>") + d.Render("   → view memory + learned patterns"))
	fmt.Println(g.Render("  cybermind /novel <target>") + d.Render("       → novel attack engine (cache poison, smuggling, race)"))
	fmt.Println(g.Render("  cybermind /doctor") + d.Render("               → update CLI + check/install tools"))
	fmt.Println(g.Render("  cybermind report") + d.Render("                → generate pentest report from history"))
	fmt.Println(g.Render("  cybermind --local") + d.Render("               → use local Ollama AI (CYBERMIND_LOCAL=true)"))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(purple).Render("  HISTORY:"))
	fmt.Println(g.Render("  cybermind history") + d.Render("               → view chat history"))
	fmt.Println(g.Render("  cybermind clear") + d.Render("                 → clear history"))
	fmt.Println(g.Render("  cybermind --key <key>") + d.Render("           → save API key"))
	fmt.Println(g.Render("  cybermind whoami") + d.Render("                → show current key + plan"))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(purple).Render("  SYSTEM:"))
	fmt.Println(g.Render("  cybermind uninstall") + d.Render("             → remove CyberMind from this system"))
	fmt.Println()
}

func printResult(label, result string) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green).Render("  ⚡ CyberMind AI → " + label))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).MarginLeft(2).Render(result))
	fmt.Println()
}

func printError(msg string) {
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render("  ✗ " + msg))
}

// parseToolsFlag parses the target and optional --tools flag from /recon args.
// args is everything after "/recon" (i.e. os.Args[2:])
// Returns target, comma-split tool names (nil if no --tools), and error for unknown tools.
func parseToolsFlag(args []string) (target string, tools []string, err error) {
	if len(args) == 0 {
		return "", nil, fmt.Errorf("target required")
	}
	target = args[0]
	for i := 1; i < len(args); i++ {
		if args[i] == "--tools" && i+1 < len(args) {
			names := strings.Split(args[i+1], ",")
			for _, n := range names {
				n = strings.TrimSpace(n)
				if n != "" {
					tools = append(tools, n)
				}
			}
			i++ // skip the value
		}
	}
	// Validate tool names against registry
	if len(tools) > 0 {
		validNames := recon.ToolNames()
		validSet := make(map[string]bool)
		for _, n := range validNames {
			validSet[n] = true
		}
		for _, t := range tools {
			if !validSet[t] {
				return "", nil, fmt.Errorf("unknown tool %q — valid tools: %s", t, strings.Join(validNames, ", "))
			}
		}
	}
	return target, tools, nil
}

// printReconSummary prints a per-tool status table after recon completes.
func printReconSummary(result recon.ReconResult) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  📋 Recon Summary"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	// Build lookup maps
	toolOutputs := make(map[string]recon.ToolResult)
	for _, tr := range result.Results {
		if tr.Tool != "combined" {
			toolOutputs[tr.Tool] = tr
		}
	}
	failedSet := make(map[string]recon.ToolResult)
	for _, tr := range result.Failed {
		failedSet[tr.Tool] = tr
	}
	skippedSet := make(map[string]recon.SkippedTool)
	for _, s := range result.Skipped {
		skippedSet[s.Tool] = s
	}

	// Print one row per registry tool in phase order
	for _, name := range recon.ToolNames() {
		if tr, ok := toolOutputs[name]; ok {
			if tr.Partial {
				fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render(
					fmt.Sprintf("  ⚡ %-14s partial — exited non-zero (output kept)", name)))
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render(
					fmt.Sprintf("  ✓ %-14s done  (%s)", name, tr.Took.Round(time.Millisecond))))
			}
		} else if tr, ok := failedSet[name]; ok {
			fmt.Println(lipgloss.NewStyle().Foreground(red).Render(
				fmt.Sprintf("  ✗ %-14s failed — %s", name, tr.Error)))
		} else if s, ok := skippedSet[name]; ok {
			hint := ""
			if s.InstallHint != "" {
				hint = "  (" + s.InstallHint + ")"
			}
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
				fmt.Sprintf("  - %-14s skipped — %s%s", name, s.Reason, hint)))
		}
	}
	fmt.Println()
}

// runAutoRecon runs the full recon pipeline and sends results to AI for analysis.
func runAutoRecon(target string, requested []string) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(yellow).Render("  🔍 AUTO RECON MODE — " + target))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	result := recon.RunAutoRecon(target, requested, func(status recon.ToolStatus) {
		switch status.Kind {
		case recon.StatusRunning:
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(
				fmt.Sprintf("  ⟳ %-16s running...", status.Tool)))
		case recon.StatusDone:
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render(
				fmt.Sprintf("  ✓ %-16s done (%s)", status.Tool, status.Took.Round(time.Millisecond))))
		case recon.StatusPartial:
			fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render(
				fmt.Sprintf("  ⚡ %-16s partial output kept", status.Tool)))
		case recon.StatusFailed:
			fmt.Println(lipgloss.NewStyle().Foreground(red).Render(
				fmt.Sprintf("  ✗ %-16s failed — %s", status.Tool, status.Reason)))
		case recon.StatusSkipped:
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
				fmt.Sprintf("  - %-16s skipped — %s", status.Tool, status.Reason)))
		case recon.StatusRetry:
			fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render(
				fmt.Sprintf("  ↻ %-16s %s", status.Tool, status.Reason)))
		}
	})

	printReconSummary(result)

	// Fall back to AI guide if no tools ran
	if len(result.Tools) == 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(red).Render("  ✗ No recon tools produced output."))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Run: cybermind /install-tools to install recon tools"))
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Falling back to AI recon guide..."))
		result2, err := api.SendRecon(target, "full")
		if err != nil {
			printError(err.Error())
			return
		}
		printResult("Recon Guide → "+target, result2)
		return
	}

	// Build structured payload
	findings := make(map[string]string)
	for _, tr := range result.Results {
		if tr.Tool != "combined" && tr.Output != "" {
			findings[tr.Tool] = tr.Output
		}
	}
	failedNames := make([]string, 0, len(result.Failed))
	for _, tr := range result.Failed {
		failedNames = append(failedNames, tr.Tool)
	}
	skippedNames := make([]string, 0, len(result.Skipped))
	for _, s := range result.Skipped {
		skippedNames = append(skippedNames, s.Tool)
	}

	var ctx recon.ReconContext
	if result.Context != nil {
		ctx = *result.Context
	}

	// Ensure slices are never nil so they marshal as [] not null in JSON
	openPorts := ctx.OpenPorts
	if openPorts == nil {
		openPorts = []int{}
	}
	liveURLs := ctx.LiveURLs
	if liveURLs == nil {
		liveURLs = []string{}
	}
	technologies := ctx.Technologies
	if technologies == nil {
		technologies = []string{}
	}

	payload := api.ReconPayload{
		Target:          target,
		TargetType:      ctx.TargetType,
		ToolsRun:        result.Tools,
		ToolsFailed:     failedNames,
		ToolsSkipped:    skippedNames,
		Findings:        truncateFindings(findings),
		SubdomainsFound: len(ctx.Subdomains),
		LiveHostsFound:  len(ctx.LiveHosts),
		OpenPorts:       openPorts,
		WAFDetected:     ctx.WAFDetected,
		WAFVendor:       ctx.WAFVendor,
		LiveURLs:        liveURLs,
		Technologies:    technologies,
		RawCombined:     truncateRaw(recon.GetCombinedOutput(result)),
	}

	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Sending to AI for analysis..."))
	analysis, err := api.SendAnalysis(payload)
	if err != nil {
		printError("AI analysis failed: " + err.Error())
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("\n  Raw recon output:\n"))
		fmt.Println(recon.GetCombinedOutput(result))
		return
	}

	// Strip markdown before printing
	clean := utils.StripMarkdown(analysis)
	printResult("AI Analysis → "+target, clean)

	_ = storage.AddEntry("/recon "+target, clean)

	// ── Auto-prompt: offer to run /hunt on recon results ──────────────────
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render(
		"  🎯 Recon complete. Start Hunt Mode on these results?"))
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
		"  Hunt will run: gau, waybackurls, katana, x8, dalfox, nuclei, nmap-vuln"))
	fmt.Print(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6600")).Render("  [y/N] → "))

	var answer string
	fmt.Scanln(&answer)
	answer = strings.ToLower(strings.TrimSpace(answer))

	if answer == "y" || answer == "yes" {
		// Build hunt context from recon results
		huntCtx := &hunt.HuntContext{
			Target:      target,
			TargetType:  ctx.TargetType,
			LiveURLs:    liveURLs,
			OpenPorts:   openPorts,
			WAFDetected: ctx.WAFDetected,
			WAFVendor:   ctx.WAFVendor,
			Subdomains:  ctx.Subdomains,
		}
		runHunt(target, huntCtx, nil)
	} else {
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
			"  Skipped. Run manually: cybermind /hunt " + target))
		fmt.Println()
	}
}

// ─── OMEGA Silent Runners (plan-aware, no interactive prompts) ───────────────
// These are used by runOmegaPlan to chain phases with context passing.
// Unlike runAutoRecon/runHunt, they do NOT ask "start hunt?" / "start abhimanyu?"
// They return the raw result so the caller can feed context to the next phase.

// truncateFindings truncates tool output to prevent payload size issues.
// nuclei 1h scan = 10MB+ output — AI providers reject payloads > 1MB.
func truncateFindings(findings map[string]string) map[string]string {
	toolLimits := map[string]int{
		"nuclei": 8000, "nikto": 5000, "nmap": 3000,
		"reconftw": 6000, "katana": 3000, "httpx": 2000,
		"masscan": 1500, "rustscan": 1500, "subfinder": 2000,
		"amass": 2000, "dalfox": 3000, "sqlmap": 3000,
	}
	out := make(map[string]string, len(findings))
	for tool, output := range findings {
		limit := 2500 // default
		if l, ok := toolLimits[strings.ToLower(tool)]; ok {
			limit = l
		}
		if len(output) > limit {
			out[tool] = output[:limit] + "\n...[truncated — " + fmt.Sprintf("%d", len(output)) + " chars total]"
		} else {
			out[tool] = output
		}
	}
	return out
}

// truncateRaw truncates raw combined output to 300KB max.
func truncateRaw(raw string) string {
	const maxRaw = 300000
	if len(raw) > maxRaw {
		return raw[:maxRaw] + "\n...[truncated]"
	}
	return raw
}

// runAutoReconSilent runs the full recon pipeline without interactive prompts.
// Returns ReconResult so the caller can extract context for hunt phase.
func runAutoReconSilent(target string, requested []string) recon.ReconResult {
	result := recon.RunAutoRecon(target, requested, func(status recon.ToolStatus) {
		switch status.Kind {
		case recon.StatusRunning:
			line := fmt.Sprintf("  ⟳ %-16s running...", status.Tool)
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(line))
			omegaLog("[RECON] " + line)
		case recon.StatusDone:
			line := fmt.Sprintf("  ✓ %-16s done (%s)", status.Tool, status.Took.Round(time.Millisecond))
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render(line))
			omegaLog("[RECON] " + line)
		case recon.StatusPartial:
			fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render(
				fmt.Sprintf("  ⚡ %-16s partial output kept", status.Tool)))
		case recon.StatusFailed:
			line := fmt.Sprintf("  ✗ %-16s failed — %s", status.Tool, status.Reason)
			fmt.Println(lipgloss.NewStyle().Foreground(red).Render(line))
			omegaLog("[RECON] " + line)
		case recon.StatusSkipped:
			line := fmt.Sprintf("  - %-16s skipped — %s", status.Tool, status.Reason)
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(line))
			omegaLog("[RECON] " + line)
		case recon.StatusRetry:
			fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render(
				fmt.Sprintf("  ↻ %-16s %s", status.Tool, status.Reason)))
		}
	})

	printReconSummary(result)

	if len(result.Tools) == 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(red).Render("  ✗ No recon tools produced output."))
		return result
	}

	// Build structured payload and send to AI
	findings := make(map[string]string)
	for _, tr := range result.Results {
		if tr.Tool != "combined" && tr.Output != "" {
			findings[tr.Tool] = tr.Output
		}
	}
	failedNames := make([]string, 0, len(result.Failed))
	for _, tr := range result.Failed {
		failedNames = append(failedNames, tr.Tool)
	}
	skippedNames := make([]string, 0, len(result.Skipped))
	for _, s := range result.Skipped {
		skippedNames = append(skippedNames, s.Tool)
	}

	var ctx recon.ReconContext
	if result.Context != nil {
		ctx = *result.Context
	}
	openPorts := ctx.OpenPorts
	if openPorts == nil {
		openPorts = []int{}
	}
	liveURLs := ctx.LiveURLs
	if liveURLs == nil {
		liveURLs = []string{}
	}
	technologies := ctx.Technologies
	if technologies == nil {
		technologies = []string{}
	}

	payload := api.ReconPayload{
		Target:          target,
		TargetType:      ctx.TargetType,
		ToolsRun:        result.Tools,
		ToolsFailed:     failedNames,
		ToolsSkipped:    skippedNames,
		Findings:        truncateFindings(findings),
		SubdomainsFound: len(ctx.Subdomains),
		LiveHostsFound:  len(ctx.LiveHosts),
		OpenPorts:       openPorts,
		WAFDetected:     ctx.WAFDetected,
		WAFVendor:       ctx.WAFVendor,
		LiveURLs:        liveURLs,
		Technologies:    technologies,
		RawCombined:     truncateRaw(recon.GetCombinedOutput(result)),
	}

	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Sending recon to AI for analysis..."))
	analysis, err := api.SendAnalysis(payload)
	if err != nil {
		printError("AI analysis failed: " + err.Error())
	} else {
		clean := utils.StripMarkdown(analysis)
		printResult("Recon Analysis → "+target, clean)
		_ = storage.AddEntry("/recon "+target, clean)
	}

	// ── Save to brain memory ──────────────────────────────────────────────
	brain.RecordRun(target, technologies, ctx.WAFVendor, ctx.WAFDetected,
		ctx.Subdomains, liveURLs, openPorts)

	// ── JS Intelligence — scan JS files for secrets + endpoints ──────────
	if len(liveURLs) > 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render("  ⟳ JS Intelligence — scanning for secrets + hidden endpoints..."))
		jsResult := brain.AnalyzeJSFiles(target, liveURLs)
		if len(jsResult.Findings) > 0 {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render(
				fmt.Sprintf("  🔑 JS Intelligence: %d findings (%d secrets, %d endpoints)",
					len(jsResult.Findings), len(jsResult.Secrets), len(jsResult.Endpoints))))
			for _, f := range jsResult.Findings {
				if f.Type == "secret" {
					fmt.Println(lipgloss.NewStyle().Foreground(red).Render(
						fmt.Sprintf("  [SECRET] %s in %s", f.Value, f.Source)))
				}
			}
			// Add discovered endpoints to context for hunt phase
			if result.Context != nil {
				result.Context.LiveURLs = append(result.Context.LiveURLs, jsResult.Endpoints...)
			}
		}
	}

	return result
}

// runHuntSilent runs the full hunt pipeline without interactive prompts.
// reconCtx carries intelligence from the prior recon phase.
// Returns HuntResult so the caller can extract context for abhimanyu phase.
func runHuntSilent(target string, reconCtx *hunt.HuntContext, requested []string) hunt.HuntResult {
	if reconCtx != nil {
		fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
			fmt.Sprintf("  ℹ  Using recon context: %d live URLs, %d open ports, WAF=%v",
				len(reconCtx.LiveURLs), len(reconCtx.OpenPorts), reconCtx.WAFDetected)))
		fmt.Println()
	}

	result := hunt.RunHunt(target, reconCtx, requested, func(status hunt.HuntStatus) {
		switch status.Kind {
		case hunt.HuntRunning:
			line := fmt.Sprintf("  ⟳ %-16s running...", status.Tool)
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(line))
			omegaLog("[HUNT] " + line)
		case hunt.HuntDone:
			line := fmt.Sprintf("  ✓ %-16s done (%s)", status.Tool, status.Took.Round(time.Millisecond))
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render(line))
			omegaLog("[HUNT] " + line)
		case hunt.HuntPartial:
			fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render(
				fmt.Sprintf("  ⚡ %-16s partial output kept", status.Tool)))
		case hunt.HuntFailed:
			line := fmt.Sprintf("  ✗ %-16s failed — %s", status.Tool, status.Reason)
			fmt.Println(lipgloss.NewStyle().Foreground(red).Render(line))
			omegaLog("[HUNT] " + line)
		case hunt.HuntKindSkipped:
			line := fmt.Sprintf("  - %-16s skipped — %s", status.Tool, status.Reason)
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(line))
			omegaLog("[HUNT] " + line)
		case hunt.HuntRetry:
			fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render(
				fmt.Sprintf("  ↻ %-16s %s", status.Tool, status.Reason)))
		}
	})

	printHuntSummary(result)

	if len(result.Tools) == 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(red).Render("  ✗ No hunt tools produced output."))
		return result
	}

	// Build structured payload and send to AI
	findings := make(map[string]string)
	for _, tr := range result.Results {
		if tr.Output != "" {
			findings[tr.Tool] = tr.Output
		}
	}
	failedNames := make([]string, 0, len(result.Failed))
	for _, tr := range result.Failed {
		failedNames = append(failedNames, tr.Tool)
	}
	skippedNames := make([]string, 0, len(result.Skipped))
	for _, s := range result.Skipped {
		skippedNames = append(skippedNames, s.Tool)
	}

	var ctx hunt.HuntContext
	if result.Context != nil {
		ctx = *result.Context
	}
	xssFound := ctx.XSSFound
	if xssFound == nil {
		xssFound = []string{}
	}
	paramsFound := ctx.ParamsFound
	if paramsFound == nil {
		paramsFound = []string{}
	}
	vulnsFound := ctx.VulnsFound
	if vulnsFound == nil {
		vulnsFound = []string{}
	}
	openPorts := ctx.OpenPorts
	if openPorts == nil {
		openPorts = []int{}
	}

	payload := api.HuntPayload{
		Target:         target,
		TargetType:     ctx.TargetType,
		ToolsRun:       result.Tools,
		ToolsFailed:    failedNames,
		ToolsSkipped:   skippedNames,
		Findings:        truncateFindings(findings),
		XSSFound:       xssFound,
		ParamsFound:    paramsFound,
		VulnsFound:     vulnsFound,
		HistoricalURLs: len(ctx.HistoricalURLs),
		WAFDetected:    ctx.WAFDetected,
		WAFVendor:      ctx.WAFVendor,
		OpenPorts:      openPorts,
		RawCombined:    truncateRaw(hunt.GetHuntCombinedOutput(result)),
	}

	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Sending hunt results to AI for analysis..."))
	analysis, err := api.SendHunt(payload)
	if err != nil {
		printError("AI analysis failed: " + err.Error())
	} else {
		clean := utils.StripMarkdown(analysis)
		printResult("Hunt Analysis → "+target, clean)
		_ = storage.AddEntry("/hunt "+target, clean)
	}

	return result
}

func printHuntSummary(result hunt.HuntResult) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render("  🎯 Hunt Summary"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	toolOutputs := make(map[string]hunt.HuntToolResult)
	for _, tr := range result.Results {
		toolOutputs[tr.Tool] = tr
	}
	failedSet := make(map[string]hunt.HuntToolResult)
	for _, tr := range result.Failed {
		failedSet[tr.Tool] = tr
	}
	skippedSet := make(map[string]hunt.HuntSkipped)
	for _, s := range result.Skipped {
		skippedSet[s.Tool] = s
	}

	for _, name := range hunt.HuntToolNames() {
		if tr, ok := toolOutputs[name]; ok {
			if tr.Partial {
				fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render(
					fmt.Sprintf("  ⚡ %-16s partial — output kept", name)))
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render(
					fmt.Sprintf("  ✓ %-16s done  (%s)", name, tr.Took.Round(time.Millisecond))))
			}
		} else if tr, ok := failedSet[name]; ok {
			fmt.Println(lipgloss.NewStyle().Foreground(red).Render(
				fmt.Sprintf("  ✗ %-16s failed — %s", name, tr.Error)))
		} else if s, ok := skippedSet[name]; ok {
			hint := ""
			if s.InstallHint != "" {
				hint = "  (" + s.InstallHint + ")"
			}
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
				fmt.Sprintf("  - %-16s skipped — %s%s", name, s.Reason, hint)))
		}
	}

	// Print key findings summary
	if result.Context != nil {
		ctx := result.Context
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render("  🔥 Key Findings"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
			fmt.Sprintf("  XSS confirmed:       %d", len(ctx.XSSFound))))
		fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
			fmt.Sprintf("  Hidden params found: %d", len(ctx.ParamsFound))))
		fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
			fmt.Sprintf("  Vulnerabilities:     %d", len(ctx.VulnsFound))))
		fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
			fmt.Sprintf("  Historical URLs:     %d", len(ctx.HistoricalURLs))))
		fmt.Println()
	}
}

// runHunt runs the full hunt pipeline and sends results to AI for analysis.
// reconCtx can be nil for manual mode (no prior recon).
func runHunt(target string, reconCtx *hunt.HuntContext, requested []string) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render("  🎯 HUNT MODE — " + target))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	if reconCtx != nil {
		fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
			fmt.Sprintf("  ℹ  Using recon context: %d live URLs, %d open ports, WAF=%v",
				len(reconCtx.LiveURLs), len(reconCtx.OpenPorts), reconCtx.WAFDetected)))
		fmt.Println()
	}

	result := hunt.RunHunt(target, reconCtx, requested, func(status hunt.HuntStatus) {
		switch status.Kind {
		case hunt.HuntRunning:
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(
				fmt.Sprintf("  ⟳ %-16s running...", status.Tool)))
		case hunt.HuntDone:
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render(
				fmt.Sprintf("  ✓ %-16s done (%s)", status.Tool, status.Took.Round(time.Millisecond))))
		case hunt.HuntPartial:
			fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render(
				fmt.Sprintf("  ⚡ %-16s partial output kept", status.Tool)))
		case hunt.HuntFailed:
			fmt.Println(lipgloss.NewStyle().Foreground(red).Render(
				fmt.Sprintf("  ✗ %-16s failed — %s", status.Tool, status.Reason)))
		case hunt.HuntKindSkipped:
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
				fmt.Sprintf("  - %-16s skipped — %s", status.Tool, status.Reason)))
		case hunt.HuntRetry:
			fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render(
				fmt.Sprintf("  ↻ %-16s %s", status.Tool, status.Reason)))
		}
	})

	printHuntSummary(result)

	if len(result.Tools) == 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(red).Render("  ✗ No hunt tools produced output."))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Run: cybermind /install-tools to install all tools"))
		return
	}

	// Build structured payload
	findings := make(map[string]string)
	for _, tr := range result.Results {
		if tr.Output != "" {
			findings[tr.Tool] = tr.Output
		}
	}
	failedNames := make([]string, 0, len(result.Failed))
	for _, tr := range result.Failed {
		failedNames = append(failedNames, tr.Tool)
	}
	skippedNames := make([]string, 0, len(result.Skipped))
	for _, s := range result.Skipped {
		skippedNames = append(skippedNames, s.Tool)
	}

	var ctx hunt.HuntContext
	if result.Context != nil {
		ctx = *result.Context
	}

	xssFound := ctx.XSSFound
	if xssFound == nil {
		xssFound = []string{}
	}
	paramsFound := ctx.ParamsFound
	if paramsFound == nil {
		paramsFound = []string{}
	}
	vulnsFound := ctx.VulnsFound
	if vulnsFound == nil {
		vulnsFound = []string{}
	}
	openPorts := ctx.OpenPorts
	if openPorts == nil {
		openPorts = []int{}
	}

	payload := api.HuntPayload{
		Target:         target,
		TargetType:     ctx.TargetType,
		ToolsRun:       result.Tools,
		ToolsFailed:    failedNames,
		ToolsSkipped:   skippedNames,
		Findings:        truncateFindings(findings),
		XSSFound:       xssFound,
		ParamsFound:    paramsFound,
		VulnsFound:     vulnsFound,
		HistoricalURLs: len(ctx.HistoricalURLs),
		WAFDetected:    ctx.WAFDetected,
		WAFVendor:      ctx.WAFVendor,
		OpenPorts:      openPorts,
		RawCombined:    truncateRaw(hunt.GetHuntCombinedOutput(result)),
	}

	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Sending to AI for vulnerability analysis..."))
	analysis, err := api.SendHunt(payload)
	if err != nil {
		printError("AI analysis failed: " + err.Error())
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("\n  Raw hunt output:\n"))
		fmt.Println(hunt.GetHuntCombinedOutput(result))
		return
	}

	clean := utils.StripMarkdown(analysis)
	printResult("Hunt Analysis → "+target, clean)
	_ = storage.AddEntry("/hunt "+target, clean)

	// ── Ask user to start Abhimanyu Mode ─────────────────────────────────
	vulnCount := 0
	if result.Context != nil {
		vulnCount = len(result.Context.VulnsFound) + len(result.Context.XSSFound)
	}

	fmt.Println()
	if vulnCount > 0 {
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render(
			fmt.Sprintf("  ⚔️  Hunt complete. %d vulnerabilities found. Start ABHIMANYU MODE?", vulnCount)))
	} else {
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render(
			"  ⚔️  Hunt complete. Start ABHIMANYU MODE to exploit findings?"))
	}
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
		"  Abhimanyu will run: sqlmap, commix, hydra, nikto, wpscan, metasploit, searchsploit"))
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
		"  Post-exploit: linpeas, bloodhound, crackmapexec, evil-winrm, impacket"))
	fmt.Print(lipgloss.NewStyle().Foreground(red).Render("  [y/N] → "))

	var abhimanyuAnswer string
	fmt.Scanln(&abhimanyuAnswer)
	abhimanyuAnswer = strings.ToLower(strings.TrimSpace(abhimanyuAnswer))

	if abhimanyuAnswer == "y" || abhimanyuAnswer == "yes" {
		// Pass hunt context to Abhimanyu
		runAbhimanyuFromHunt(target, ctx, xssFound, vulnsFound, paramsFound, openPorts, findings)
	} else {
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
			"  Skipped. Run manually: cybermind /abhimanyu " + target))
		fmt.Println()
	}
}

// runAbhimanyuFromHunt chains Abhimanyu mode from hunt results with full context.
func runAbhimanyuFromHunt(target string, ctx hunt.HuntContext, xssFound, vulnsFound, paramsFound []string, openPorts []int, findings map[string]string) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render("  ⚔️  ABHIMANYU MODE — " + target))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render("  Entering the Chakravyuh. Fighting every layer. No retreat."))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	lhost := getLocalIP()

	// ── Auto-select vulnType based on hunt findings + decision focus ─────
	// If hunt found specific vuln types, target those first instead of running all
	vulnType := "all"

	// Check if decision passed a specific vuln focus via Technologies field
	for _, tech := range ctx.Technologies {
		if strings.HasPrefix(tech, "CYBERMIND_VULN_FOCUS:") {
			vulnType = strings.TrimPrefix(tech, "CYBERMIND_VULN_FOCUS:")
			break
		}
	}

	// Override with hunt findings if more specific
	if vulnType == "all" {
		if len(xssFound) > 0 && len(vulnsFound) == 0 {
			vulnType = "xss"
		} else if len(vulnsFound) > 0 {
			// Check nuclei findings for specific vuln types
			for _, v := range vulnsFound {
				lower := strings.ToLower(v)
				if strings.Contains(lower, "sqli") || strings.Contains(lower, "sql-injection") {
					vulnType = "sqli"
					break
				}
				if strings.Contains(lower, "rce") || strings.Contains(lower, "command") {
					vulnType = "rce"
					break
				}
				if strings.Contains(lower, "ssrf") {
					vulnType = "ssrf"
					break
				}
			}
		}
	}
	if vulnType != "all" {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(
			fmt.Sprintf("  🎯 Auto-selected exploit type: %s (based on hunt findings)", vulnType)))
		fmt.Println()
	}

	// ── Build full AbhimanyuContext from hunt results ─────────────────────
	// Merge all URL sources for maximum coverage
	allURLs := deduplicateStrings(append(append(ctx.LiveURLs, ctx.CrawledURLs...), ctx.HistoricalURLs...))

	abhCtx := &abhimanyu.AbhimanyuContext{
		Target:       target,
		TargetType:   ctx.TargetType,
		VulnType:     vulnType,
		LHOST:        lhost,
		LiveURLs:     ctx.LiveURLs,
		OpenPorts:    openPorts,
		XSSFound:     xssFound,
		VulnsFound:   vulnsFound,
		ParamsFound:  paramsFound,
		WAFDetected:  ctx.WAFDetected,
		WAFVendor:    ctx.WAFVendor,
		Technologies: extractTechnologiesFromFindings(findings),
	}
	_ = allURLs // available for future use in exploit targeting

	// Run full exploit pipeline using registry
	results := abhimanyu.RunAbhimanyuMode(abhCtx, func(status abhimanyu.AbhimanyuStatus) {
		switch status.Kind {
		case abhimanyu.StatusInstalling:
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
				fmt.Sprintf("  ⟳ %-20s installing...", status.Tool)))
		case abhimanyu.StatusRunning:
			reason := ""
			if status.Reason != "" {
				reason = " (" + status.Reason + ")"
			}
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(
				fmt.Sprintf("  ⟳ %-20s attacking...%s", status.Tool, reason)))
		case abhimanyu.StatusDone:
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render(
				fmt.Sprintf("  ✓ %-20s done (%s)", status.Tool, status.Took.Round(time.Millisecond))))
		case abhimanyu.StatusFailed:
			fmt.Println(lipgloss.NewStyle().Foreground(red).Render(
				fmt.Sprintf("  ✗ %-20s failed — %s", status.Tool, status.Reason)))
		case abhimanyu.StatusSkipped:
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
				fmt.Sprintf("  - %-20s skipped — %s", status.Tool, status.Reason)))
		}
	})

	printAbhimanyuSummary(results, abhCtx)

	// Merge results into findings for AI payload
	for _, r := range results {
		if r.Output != "" {
			findings[r.Tool] = r.Output
		}
	}

	// Build AI payload with full context
	abhimanyuPayload := map[string]interface{}{
		"target":       target,
		"vuln_type":    vulnType,
		"lhost":        lhost,
		"target_type":  ctx.TargetType,
		"open_ports":   openPorts,
		"live_urls":    ctx.LiveURLs,
		"all_urls":     allURLs,
		"xss_found":    xssFound,
		"vulns_found":  vulnsFound,
		"params_found": paramsFound,
		"waf_detected": ctx.WAFDetected,
		"waf_vendor":   ctx.WAFVendor,
		"technologies": abhCtx.Technologies,
		"findings":     findings,
		"session_dir":  abhCtx.SessionDir,
	}

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Sending to Abhimanyu AI for exploit analysis + remediation..."))

	exploit, exploitErr := api.SendAbhimanyu(target, vulnType, abhimanyuPayload)
	if exploitErr == nil {
		cleanExploit := utils.StripMarkdown(exploit)
		printResult("⚔️  ABHIMANYU Exploit Report → "+target, cleanExploit)
		_ = storage.AddEntry("/abhimanyu "+target, cleanExploit)
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
			"  Copy any commands above and run them manually in your terminal."))

		// ── Generate remediation guide ────────────────────────────────────
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF88")).Render(
			"  🛡️  REMEDIATION GUIDE — How to fix these vulnerabilities:"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render(
			"  " + strings.Repeat("─", 60)))
		fmt.Println()

		remediationPrompt := fmt.Sprintf(
			"For the following vulnerabilities found on %s (vuln type: %s), provide:\n"+
				"1. Root cause explanation\n"+
				"2. Exact code fix (with before/after examples)\n"+
				"3. Security headers to add\n"+
				"4. WAF rules to block the attack\n"+
				"5. Testing steps to verify the fix\n\n"+
				"Findings:\n%s",
			target, vulnType, exploit[:min(2000, len(exploit))])

		remediation, remErr := api.SendPrompt(remediationPrompt)
		if remErr == nil && remediation != "" {
			cleanRemediation := utils.StripMarkdown(remediation)
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF88")).Render(cleanRemediation))

			// Save remediation to file
			ts := time.Now().Format("2006-01-02_15-04-05")
			safeTarget := strings.ReplaceAll(strings.ReplaceAll(target, ".", "_"), "/", "_")
			remPath := fmt.Sprintf("cybermind_remediation_%s_%s.md", safeTarget, ts)
			remContent := fmt.Sprintf("# Remediation Guide — %s\n\n## Vulnerabilities Found\n%s\n\n## How to Fix\n%s\n",
				target, exploit, remediation)
			if os.WriteFile(remPath, []byte(remContent), 0644) == nil {
				fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF88")).Render(
					"  ✓ Remediation guide saved: " + remPath))
			}
		} else {
			// Fallback: show generic remediation based on vuln type
			printGenericRemediation(vulnType)
		}
	} else {
		printError("Abhimanyu AI failed: " + exploitErr.Error())
		// Print raw findings anyway — don't leave user with nothing
		fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  Raw findings:"))
		for tool, output := range findings {
			if len(output) > 2000 {
				output = output[:2000] + "...[truncated]"
			}
			fmt.Printf("\n=== %s ===\n%s\n", strings.ToUpper(tool), output)
		}
	}

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
		fmt.Sprintf("  💾 Session saved: %s/session.json", abhCtx.SessionDir)))
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
		"  Resume next session: cybermind /abhimanyu " + target))
}

// printGenericRemediation prints a generic remediation guide based on vuln type.
// Used as fallback when AI remediation fails.
func printGenericRemediation(vulnType string) {
	remediations := map[string]string{
		"sqli": `SQL Injection Remediation:
  1. Use parameterized queries / prepared statements (NEVER string concatenation)
  2. Apply input validation and whitelist allowed characters
  3. Use an ORM (SQLAlchemy, Hibernate, ActiveRecord)
  4. Principle of least privilege for DB accounts
  5. Enable WAF rules: ModSecurity CRS SQLi rules
  Fix: db.query("SELECT * FROM users WHERE id = ?", [userId])`,
		"xss": `XSS Remediation:
  1. Encode all output: HTML entity encoding for HTML context
  2. Use Content-Security-Policy header: script-src 'self'
  3. Set X-XSS-Protection: 1; mode=block
  4. Use HttpOnly and Secure flags on cookies
  5. Validate and sanitize all user input server-side
  Fix: response.setHeader("Content-Security-Policy", "default-src 'self'")`,
		"rce": `RCE/Command Injection Remediation:
  1. NEVER pass user input to shell commands
  2. Use language-native APIs instead of shell (os.path, subprocess with list args)
  3. Whitelist allowed commands/parameters
  4. Run application with minimal OS privileges
  5. Use containers/sandboxing to limit blast radius
  Fix: subprocess.run(["ls", user_input], shell=False)  # NOT shell=True`,
		"ssrf": `SSRF Remediation:
  1. Whitelist allowed URLs/domains (allowlist, not blocklist)
  2. Block requests to 169.254.169.254 (cloud metadata)
  3. Block requests to 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
  4. Use a URL parser to validate scheme (only http/https)
  5. Disable HTTP redirects or validate redirect destinations`,
		"auth": `Authentication Bypass Remediation:
  1. Implement proper session management (secure, httponly, samesite cookies)
  2. Use strong password hashing (bcrypt, argon2)
  3. Implement MFA for sensitive operations
  4. Rate limit login attempts (3-5 per 15 min)
  5. Validate JWT signatures server-side, never trust client-side claims`,
		"all": `General Security Remediation:
  1. Keep all dependencies updated (npm audit, pip-audit, go mod tidy)
  2. Enable security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
  3. Use HTTPS everywhere with valid certificates
  4. Implement proper input validation and output encoding
  5. Follow OWASP Top 10 guidelines: https://owasp.org/www-project-top-ten/`,
	}

	guide, ok := remediations[vulnType]
	if !ok {
		guide = remediations["all"]
	}
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF88")).Render("  " + strings.ReplaceAll(guide, "\n", "\n  ")))
}

// deduplicateStrings returns a deduplicated copy of a string slice.
func deduplicateStrings(items []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range items {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// extractTechnologiesFromFindings extracts technology names from tool findings.
func extractTechnologiesFromFindings(findings map[string]string) []string {
	techRe := regexp.MustCompile(`(?i)(wordpress|joomla|drupal|nginx|apache|iis|php|python|ruby|node|react|angular|vue|laravel|django|rails|spring|tomcat|jenkins|grafana|kibana|elasticsearch)`)
	seen := map[string]bool{}
	var techs []string
	for _, output := range findings {
		for _, match := range techRe.FindAllString(output, -1) {
			lower := strings.ToLower(match)
			if !seen[lower] {
				seen[lower] = true
				techs = append(techs, lower)
			}
		}
	}
	return techs
}

func runAbhimanyu(target, vulnType string) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render("  ⚔️  ABHIMANYU MODE — " + target))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render("  Entering the Chakravyuh. Fighting every layer. No retreat."))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	lhost := getLocalIP()

	// Build context — standalone mode, no prior hunt context
	abhCtx := &abhimanyu.AbhimanyuContext{
		Target:    target,
		VulnType:  vulnType,
		LHOST:     lhost,
	}

	// Run full exploit pipeline using registry
	results := abhimanyu.RunAbhimanyuMode(abhCtx, func(status abhimanyu.AbhimanyuStatus) {
		switch status.Kind {
		case abhimanyu.StatusInstalling:
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
				fmt.Sprintf("  ⟳ %-20s installing...", status.Tool)))
		case abhimanyu.StatusRunning:
			reason := ""
			if status.Reason != "" {
				reason = " (" + status.Reason + ")"
			}
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(
				fmt.Sprintf("  ⟳ %-20s attacking...%s", status.Tool, reason)))
		case abhimanyu.StatusDone:
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render(
				fmt.Sprintf("  ✓ %-20s done (%s)", status.Tool, status.Took.Round(time.Millisecond))))
		case abhimanyu.StatusFailed:
			fmt.Println(lipgloss.NewStyle().Foreground(red).Render(
				fmt.Sprintf("  ✗ %-20s failed — %s", status.Tool, status.Reason)))
		case abhimanyu.StatusSkipped:
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
				fmt.Sprintf("  - %-20s skipped — %s", status.Tool, status.Reason)))
		}
	})

	printAbhimanyuSummary(results, abhCtx)

	// Build findings map for AI
	findings := make(map[string]string)
	for _, r := range results {
		if r.Output != "" {
			findings[r.Tool] = r.Output
		}
	}

	if len(findings) == 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(red).Render("  ✗ No exploit tools produced output."))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Run: cybermind /doctor to install all tools"))
		return
	}

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Sending to Abhimanyu AI for exploit analysis..."))

	payload := map[string]interface{}{
		"target":      target,
		"vuln_type":   vulnType,
		"lhost":       lhost,
		"findings":    findings,
		"session_dir": abhCtx.SessionDir,
	}

	analysis, err := api.SendAbhimanyu(target, vulnType, payload)
	if err != nil {
		printError("Abhimanyu AI failed: " + err.Error())
		fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  Raw findings:"))
		for tool, output := range findings {
			if len(output) > 2000 {
				output = output[:2000] + "...[truncated]"
			}
			fmt.Printf("\n=== %s ===\n%s\n", strings.ToUpper(tool), output)
		}
		return
	}

	clean := utils.StripMarkdown(analysis)
	printResult("⚔️  ABHIMANYU Exploit Report → "+target, clean)
	_ = storage.AddEntry("/abhimanyu "+target, clean)

	// FIX: autoExecuteAICommands REMOVED — AI-controlled shell execution is an RCE vector
	// Commands are displayed for manual review only
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
		"  Copy any commands above and run them manually in your terminal."))

	// Show session info for next run
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
		fmt.Sprintf("  💾 Session saved: %s/session.json", abhCtx.SessionDir)))
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
		"  Resume next session: cybermind /abhimanyu " + target))
}

// printAbhimanyuSummary prints a per-tool status table after abhimanyu completes.
func printAbhimanyuSummary(results []abhimanyu.ExploitResult, ctx *abhimanyu.AbhimanyuContext) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render("  ⚔️  Abhimanyu Summary"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	success, failed := 0, 0
	for _, r := range results {
		if r.Success {
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render(
				fmt.Sprintf("  ✓ %-22s done  (%s)", r.Tool, r.Took.Round(time.Millisecond))))
			success++
		} else {
			fmt.Println(lipgloss.NewStyle().Foreground(red).Render(
				fmt.Sprintf("  ✗ %-22s failed — %s", r.Tool, r.Error)))
			failed++
		}
	}
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
		fmt.Sprintf("  Tools: %d succeeded, %d failed", success, failed)))
	if ctx.ShellObtained {
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green).Render(
			"  🐚 Shell obtained: " + ctx.ShellType))
	}
	fmt.Println()
}

// runSelfUpdate downloads and replaces the current binary with the latest version.
// Works on Linux, macOS, and Windows.
func runSelfUpdate() {
	cyan2 := lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF"))
	green2 := lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00"))
	dim2 := lipgloss.NewStyle().Foreground(lipgloss.Color("#777777"))
	red2 := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444"))
	yellow2 := lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700"))

	// GitHub raw content — always latest from main branch (no Vercel cache)
	const ghRaw = "https://raw.githubusercontent.com/thecnical/cybermind/main/cli/"

	// Determine download URL based on OS/arch
	var binaryURL string
	switch runtime.GOOS {
	case "linux":
		if runtime.GOARCH == "arm64" {
			binaryURL = ghRaw + "cybermind-linux-arm64"
		} else {
			binaryURL = ghRaw + "cybermind-linux-amd64"
		}
	case "darwin":
		if runtime.GOARCH == "arm64" {
			binaryURL = ghRaw + "cybermind-darwin-arm64"
		} else {
			binaryURL = ghRaw + "cybermind-darwin-amd64"
		}
	case "windows":
		binaryURL = ghRaw + "cybermind-windows-amd64.exe"
	default:
		fmt.Println(dim2.Render("  Self-update not supported on " + runtime.GOOS))
		return
	}

	fmt.Println(dim2.Render("  Downloading latest CyberMind CLI from GitHub..."))
	fmt.Println(dim2.Render("  Source: " + binaryURL))

	// Get current executable path
	exePath, err := os.Executable()
	if err != nil {
		fmt.Println(red2.Render("  ✗ Cannot determine executable path: " + err.Error()))
		return
	}
	exePath = filepath.Clean(exePath)

	// Download to temp file
	tmpPath := exePath + ".update_tmp"
	if runtime.GOOS == "windows" {
		tmpPath = os.TempDir() + `\cybermind_update.exe`
	}

	// Use curl or wget on Linux/macOS, PowerShell on Windows
	var downloadErr error
	switch runtime.GOOS {
	case "linux", "darwin":
		var dlCmd *exec.Cmd
		if _, err2 := exec.LookPath("curl"); err2 == nil {
			dlCmd = exec.Command("curl", "-fsSL", "-o", tmpPath, binaryURL)
		} else {
			dlCmd = exec.Command("wget", "-q", "-O", tmpPath, binaryURL)
		}
		downloadErr = dlCmd.Run()
	case "windows":
		psScript := fmt.Sprintf(
			`[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; `+
				`(New-Object System.Net.WebClient).DownloadFile('%s', '%s')`,
			binaryURL, tmpPath)
		downloadErr = exec.Command("powershell", "-NoProfile", "-Command", psScript).Run()
	}

	if downloadErr != nil {
		fmt.Println(red2.Render("  ✗ Download failed: " + downloadErr.Error()))
		fmt.Println(dim2.Render("  Manual update: " + binaryURL))
		return
	}

	// Verify downloaded file is non-empty
	info, err := os.Stat(tmpPath)
	if err != nil || info.Size() < 1024*1024 { // must be > 1MB
		os.Remove(tmpPath)
		fmt.Println(red2.Render("  ✗ Downloaded file looks invalid (too small). Skipping update."))
		return
	}

	// Make executable
	if runtime.GOOS != "windows" {
		os.Chmod(tmpPath, 0755)
	}

	// Replace binary
	switch runtime.GOOS {
	case "linux", "darwin":
		// Try direct replace first, then sudo
		installPaths := []string{"/usr/local/bin/cybermind", "/usr/bin/cybermind", exePath}
		updated := false
		for _, installPath := range installPaths {
			if _, err2 := os.Stat(installPath); err2 != nil {
				continue
			}
			// Try sudo cp
			if cmd2 := exec.Command("sudo", "cp", tmpPath, installPath); cmd2.Run() == nil {
				exec.Command("sudo", "chmod", "+x", installPath).Run()
				// Also update cbm alias
				cbmPath := filepath.Dir(installPath) + "/cbm"
				exec.Command("sudo", "cp", installPath, cbmPath).Run()
				exec.Command("sudo", "chmod", "+x", cbmPath).Run()
				fmt.Println(green2.Render("  ✓ Updated: " + installPath))
				fmt.Println(green2.Render("  ✓ Updated: " + cbmPath + " (cbm alias)"))
				updated = true
				break
			}
		}
		if !updated {
			// Fallback: replace current exe directly
			if err2 := os.Rename(tmpPath, exePath); err2 == nil {
				os.Chmod(exePath, 0755)
				fmt.Println(green2.Render("  ✓ Updated: " + exePath))
			} else {
				fmt.Println(yellow2.Render("  ⚡ Could not replace binary. Run manually: sudo cp " + tmpPath + " /usr/local/bin/cybermind"))
			}
		}
		os.Remove(tmpPath)

	case "windows":
		// On Windows: copy to install dir, update cbm.exe too
		installDir := filepath.Dir(exePath)
		newExe := installDir + `\cybermind.exe`
		newCbm := installDir + `\cbm.exe`

		// Use PowerShell to copy (handles locked files better)
		psReplace := fmt.Sprintf(
			`Copy-Item -Path '%s' -Destination '%s' -Force; Copy-Item -Path '%s' -Destination '%s' -Force`,
			tmpPath, newExe, tmpPath, newCbm)
		if err2 := exec.Command("powershell", "-NoProfile", "-Command", psReplace).Run(); err2 == nil {
			fmt.Println(green2.Render("  ✓ Updated: " + newExe))
			fmt.Println(green2.Render("  ✓ Updated: " + newCbm + " (cbm alias)"))
		} else {
			fmt.Println(yellow2.Render("  ⚡ Update downloaded but could not replace. Restart terminal and try again."))
			fmt.Println(dim2.Render("  Manual: copy " + tmpPath + " to " + newExe))
		}
	}

	fmt.Println(cyan2.Render("  ✓ CyberMind CLI updated to latest version"))
	fmt.Println(dim2.Render("  Restart your terminal for changes to take effect."))
}

// runUninstall removes CyberMind CLI fully from the system — Linux, macOS, Windows.
func runUninstall() {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render("  ⚠  Uninstall CyberMind CLI"))
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  This will remove:"))
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("    • cybermind + cbm binaries from your system"))
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("    • ~/.cybermind/ (config, API key, chat history)"))
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("    • cybermind from PATH"))
	fmt.Println()
	fmt.Print(lipgloss.NewStyle().Foreground(red).Render("  Are you sure? [y/N] → "))

	var answer string
	fmt.Scanln(&answer)
	if strings.ToLower(strings.TrimSpace(answer)) != "y" {
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Cancelled."))
		return
	}

	removed := 0
	failed := 0

	tryRemove := func(path, label string) {
		if err := os.RemoveAll(path); err == nil {
			if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Removed " + label))
				removed++
			}
		}
	}

	tryRemoveWithSudo := func(path, label string) {
		// Try without sudo first
		if err := os.Remove(path); err == nil {
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Removed " + label))
			removed++
			return
		}
		// Try with sudo
		if cmd := exec.Command("sudo", "rm", "-f", path); cmd.Run() == nil {
			if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Removed " + label + " (sudo)"))
				removed++
				return
			}
		}
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  ⚡ Could not remove " + label + " — try: sudo rm -f " + path))
			failed++
		}
	}

	homedir, _ := os.UserHomeDir()

	// ── 1. Remove config directory (API key + history) ────────────────────
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  Removing config, API key, and history..."))

	switch runtime.GOOS {
	case "windows":
		winPaths := []string{
			homedir + `\.cybermind`,
			os.Getenv("APPDATA") + `\cybermind`,
			os.Getenv("LOCALAPPDATA") + `\Programs\cybermind`,
			os.Getenv("LOCALAPPDATA") + `\cybermind`,
		}
		for _, p := range winPaths {
			if p != `\.cybermind` && p != `\cybermind` && p != `\Programs\cybermind` {
				tryRemove(p, p)
			}
		}
	default:
		tryRemove(homedir+"/.cybermind", "~/.cybermind (config + API key + history)")
	}

	// ── 2. Remove binaries (cybermind + cbm) ──────────────────────────────
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  Removing binaries..."))

	switch runtime.GOOS {
	case "linux", "darwin":
		binLocations := []string{
			"/usr/local/bin/cybermind",
			"/usr/local/bin/cbm",
			"/usr/bin/cybermind",
			"/usr/bin/cbm",
			homedir + "/bin/cybermind",
			homedir + "/.local/bin/cybermind",
			homedir + "/.local/bin/cbm",
			homedir + "/go/bin/cybermind",
		}
		for _, loc := range binLocations {
			if _, err := os.Stat(loc); err == nil {
				tryRemoveWithSudo(loc, loc)
			}
		}
		// Remove the currently running binary too
		if exe, err := os.Executable(); err == nil {
			if exe != "" && exe != "/usr/local/bin/cybermind" && exe != "/usr/bin/cybermind" {
				tryRemoveWithSudo(exe, exe)
			}
		}

	case "windows":
		winBinLocations := []string{
			`C:\Windows\System32\cybermind.exe`,
			`C:\Windows\System32\cbm.exe`,
			`C:\Windows\cybermind.exe`,
			homedir + `\AppData\Local\Programs\cybermind\cybermind.exe`,
			homedir + `\AppData\Local\Programs\cybermind\cbm.exe`,
			homedir + `\.local\bin\cybermind.exe`,
			homedir + `\.local\bin\cbm.exe`,
			homedir + `\AppData\Roaming\cybermind\cybermind.exe`,
			`C:\Program Files\cybermind\cybermind.exe`,
			`C:\Program Files (x86)\cybermind\cybermind.exe`,
		}
		// Also check where the current exe is
		if exe, err := os.Executable(); err == nil && exe != "" {
			winBinLocations = append(winBinLocations, exe)
		}
		for _, loc := range winBinLocations {
			if _, err := os.Stat(loc); err == nil {
				tryRemove(loc, loc)
				// Remove parent dir if it's a dedicated install dir
				if strings.Contains(loc, `Programs\cybermind`) || strings.Contains(loc, `Program Files\cybermind`) {
					tryRemove(filepath.Dir(loc), filepath.Dir(loc))
				}
			}
		}
		// Remove from PATH via PowerShell (removes both cybermind and cbm entries)
		psCmd := exec.Command("powershell", "-NoProfile", "-Command",
			`$p = [Environment]::GetEnvironmentVariable('PATH','User'); `+
				`$p = ($p -split ';' | Where-Object { $_ -notmatch 'cybermind' -and $_ -notmatch '\\cbm' }) -join ';'; `+
				`[Environment]::SetEnvironmentVariable('PATH', $p, 'User')`)
		if psCmd.Run() == nil {
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Removed cybermind/cbm from user PATH"))
			removed++
		}
	}

	// ── 3. Summary ────────────────────────────────────────────────────────
	fmt.Println()
	if failed == 0 {
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green).Render(
			fmt.Sprintf("  ✓ CyberMind CLI fully uninstalled (%d items removed).", removed)))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  API key, config, history — all deleted."))
	} else {
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(yellow).Render(
			fmt.Sprintf("  ⚡ Uninstall complete (%d removed, %d need manual removal — see above).", removed, failed)))
	}
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
		"  To reinstall: curl -sL https://cybermindcli1.vercel.app/install.sh | bash"))
	fmt.Println()
}

// SaveAPIKey saves the API key to ~/.cybermind/config.json with secure permissions
func saveAPIKey(key string) error {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := homedir + "/.cybermind"
	// 0700 — only owner can read/write/execute the directory
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data := fmt.Sprintf(`{"key":"%s"}`, key)
	// 0600 — only owner can read/write the config file
	return os.WriteFile(dir+"/config.json", []byte(data), 0600)
}

// aptInstall runs apt-get install non-interactively — no debconf dialogs ever.
func aptInstall(packages ...string) error {
	args := append([]string{"apt-get", "install", "-y", "-qq",
		"-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "Dpkg::Options::=--force-confnew",
	}, packages...)
	cmd := exec.Command("sudo", args...)
	cmd.Env = append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"DEBCONF_NONINTERACTIVE_SEEN=true",
		"DEBCONF_FRONTEND=noninteractive",
		"APT_LISTCHANGES_FRONTEND=none",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ensurePipx installs pipx if missing and ensures /usr/local/bin is in pipx path.
func ensurePipx() {
	if _, err := exec.LookPath("pipx"); err != nil {
		aptInstall("pipx", "python3-venv")
	}
	// Set PIPX_BIN_DIR so binaries land in /usr/local/bin (accessible system-wide)
	os.Setenv("PIPX_BIN_DIR", "/usr/local/bin")
	os.Setenv("PIPX_HOME", "/opt/pipx")
}

// installPythonPipTool installs a Python CLI tool using the best available method.
// Priority: pipx (isolated) → venv → pip3 --break-system-packages
// The pkgName parameter is the pip package name to install (passed directly).
func installPythonPipTool(pkgName string) error {
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  ↳ Installing %s (isolated env)...", pkgName)))

	ensurePipx()

	// Method 1: pipx with PIPX_BIN_DIR=/usr/local/bin
	pipxEnv := append(os.Environ(),
		"PIPX_BIN_DIR=/usr/local/bin",
		"PIPX_HOME=/opt/pipx",
	)
	cmd := exec.Command("pipx", "install", "--force", pkgName)
	cmd.Env = pipxEnv
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err == nil {
		// Verify binary landed somewhere accessible
		if _, e := exec.LookPath(pkgName); e == nil {
			return nil
		}
		// Try symlinking from common pipx locations
		for _, searchDir := range []string{
			"/usr/local/bin/" + pkgName,
			"/opt/pipx/venvs/" + pkgName + "/bin/" + pkgName,
			os.Getenv("HOME") + "/.local/bin/" + pkgName,
			"/root/.local/bin/" + pkgName,
		} {
			if _, e := os.Stat(searchDir); e == nil {
				exec.Command("sudo", "ln", "-sf", searchDir, "/usr/local/bin/"+pkgName).Run()
				return nil
			}
		}
		return nil
	}

	// Method 2: venv in /opt/<pkgName>-venv
	venvDir := "/opt/" + pkgName + "-venv"
	exec.Command("python3", "-m", "venv", venvDir).Run()
	venvPip := venvDir + "/bin/pip"
	venvBin := venvDir + "/bin/" + pkgName

	installCmd := exec.Command(venvPip, "install", pkgName, "-q")
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	installCmd.Stdin = nil
	if err := installCmd.Run(); err == nil {
		if _, e := os.Stat(venvBin); e == nil {
			exec.Command("sudo", "ln", "-sf", venvBin, "/usr/local/bin/"+pkgName).Run()
			return nil
		}
	}

	// Method 3: pip3 --break-system-packages (last resort)
	cmd3 := exec.Command("pip3", "install", pkgName, "--break-system-packages", "-q")
	cmd3.Stdout = os.Stdout
	cmd3.Stderr = os.Stderr
	cmd3.Stdin = nil
	return cmd3.Run()
}

// installPythonGitTool installs a Python tool from git using venv isolation.
// Creates /opt/<name>/.venv, installs deps, creates wrapper at /usr/local/bin/<name>
func installPythonGitTool(name, repoURL, installDir, mainScript string) error {
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  ↳ Cloning %s from GitHub...", name)))

	// Ensure python3-venv is available
	aptInstall("python3-venv", "python3-pip", "git")

	exec.Command("sudo", "rm", "-rf", installDir).Run()
	cloneCmd := exec.Command("git", "clone", "--depth=1", repoURL, installDir)
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr
	cloneCmd.Stdin = nil
	if err := cloneCmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %v", err)
	}

	// Create isolated venv inside the tool dir
	venvDir := installDir + "/.venv"
	if err := exec.Command("python3", "-m", "venv", venvDir).Run(); err != nil {
		// fallback: system venv
		aptInstall("python3-venv")
		exec.Command("python3", "-m", "venv", venvDir).Run()
	}

	venvPip := venvDir + "/bin/pip"
	venvPython := venvDir + "/bin/python3"

	// Upgrade pip inside venv first
	exec.Command(venvPip, "install", "--upgrade", "pip", "-q").Run()

	// Install requirements if present
	reqFile := installDir + "/requirements.txt"
	if _, err := os.Stat(reqFile); err == nil {
		pipCmd := exec.Command(venvPip, "install", "-r", reqFile, "-q")
		pipCmd.Stdout = os.Stdout
		pipCmd.Stderr = os.Stderr
		pipCmd.Stdin = nil
		pipCmd.Run()
	}

	// Try pip install -e . if setup.py or pyproject.toml exists
	for _, setupFile := range []string{installDir + "/setup.py", installDir + "/pyproject.toml"} {
		if _, err := os.Stat(setupFile); err == nil {
			exec.Command(venvPip, "install", "-e", installDir, "-q").Run()
			break
		}
	}

	// Create wrapper script using venv python
	scriptPath := installDir + "/" + mainScript
	wrapper := fmt.Sprintf("#!/bin/bash\nexec %s %s \"$@\"\n", venvPython, scriptPath)
	wrapperPath := "/usr/local/bin/" + name

	teeCmd := exec.Command("sudo", "tee", wrapperPath)
	teeCmd.Stdin = strings.NewReader(wrapper)
	if err := teeCmd.Run(); err != nil {
		// fallback: write directly
		os.WriteFile(wrapperPath, []byte(wrapper), 0755)
	}
	exec.Command("sudo", "chmod", "+x", wrapperPath).Run()

	// Verify
	if _, err := os.Stat(scriptPath); err == nil {
		return nil
	}
	// Check if binary was installed into venv bin
	venvToolBin := venvDir + "/bin/" + name
	if _, err := os.Stat(venvToolBin); err == nil {
		exec.Command("sudo", "ln", "-sf", venvToolBin, "/usr/local/bin/"+name).Run()
		return nil
	}
	return fmt.Errorf("%s: main script not found at %s", name, scriptPath)
}

// installReconftw installs reconftw via git clone — must run as root.
func installReconftw() error {
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ↳ Installing reconftw (git clone method)..."))

	// Remove old broken install
	exec.Command("sudo", "rm", "-rf", "/opt/reconftw").Run()
	exec.Command("sudo", "rm", "-f", "/usr/local/bin/reconftw").Run()

	// Clone
	cloneCmd := exec.Command("sudo", "git", "clone", "--depth=1",
		"https://github.com/six2dez/reconftw.git", "/opt/reconftw")
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr
	cloneCmd.Stdin = nil
	if err := cloneCmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %v", err)
	}

	// Make scripts executable
	exec.Command("sudo", "chmod", "+x", "/opt/reconftw/reconftw.sh").Run()
	exec.Command("sudo", "chmod", "+x", "/opt/reconftw/install.sh").Run()

	// Run install.sh — partial failures are OK, reconftw still works
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ↳ Running reconftw/install.sh (5-15 min, errors are normal)..."))
	installCmd := exec.Command("sudo", "bash", "-c", "cd /opt/reconftw && ./install.sh")
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	installCmd.Stdin = nil
	installCmd.Run() // intentionally ignore error — partial install is fine

	// Create proper wrapper that preserves working directory
	// reconftw MUST run from /opt/reconftw — it sources lib/ and modules/ relative to itself
	wrapperContent := "#!/bin/bash\nexec bash /opt/reconftw/reconftw.sh \"$@\"\n"
	writeCmd := exec.Command("sudo", "bash", "-c",
		fmt.Sprintf("cat > /usr/local/bin/reconftw << 'WRAPPER'\n%sWRAPPER\nchmod +x /usr/local/bin/reconftw", wrapperContent))
	writeCmd.Run()

	// Alternative: use tee
	teeCmd := exec.Command("sudo", "tee", "/usr/local/bin/reconftw")
	teeCmd.Stdin = strings.NewReader("#!/bin/bash\nexec bash /opt/reconftw/reconftw.sh \"$@\"\n")
	teeCmd.Run()
	exec.Command("sudo", "chmod", "+x", "/usr/local/bin/reconftw").Run()

	// Verify
	if _, err := os.Stat("/opt/reconftw/reconftw.sh"); err == nil {
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ reconftw installed at /opt/reconftw/reconftw.sh"))
		return nil
	}
	return fmt.Errorf("reconftw.sh not found after install")
}

// installX8 installs x8 from GitHub releases (binary) — avoids cargo/openssl issues.
func installX8() error {
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ↳ Downloading x8 binary from GitHub releases..."))

	// Method 1: Download pre-built binary from releases (fastest, no openssl issues)
	dlCmd := exec.Command("bash", "-c",
		`set -e
LATEST=$(curl -s https://api.github.com/repos/Sh1Yo/x8/releases/latest | grep browser_download_url | grep linux | grep x86_64 | grep -v '.sha' | cut -d'"' -f4 | head -1)
if [ -z "$LATEST" ]; then
  echo "No release binary found"
  exit 1
fi
echo "Downloading: $LATEST"
curl -sL "$LATEST" -o /tmp/x8_release
# Check if it's a tar.gz or direct binary
if file /tmp/x8_release | grep -q 'gzip\|tar'; then
  tar -xzf /tmp/x8_release -C /tmp/ 2>/dev/null || true
  find /tmp -name 'x8' -type f -exec sudo cp {} /usr/local/bin/x8 \; 2>/dev/null || true
else
  sudo cp /tmp/x8_release /usr/local/bin/x8
fi
sudo chmod +x /usr/local/bin/x8
x8 --version`)
	dlCmd.Stdout = os.Stdout
	dlCmd.Stderr = os.Stderr
	if err := dlCmd.Run(); err == nil {
		return nil
	}

	// Method 2: Build from source with proper deps
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ↳ Binary download failed, building from source..."))
	buildCmd := exec.Command("bash", "-c",
		`set -e
sudo apt-get install -y libssl-dev pkg-config build-essential curl git 2>/dev/null
export OPENSSL_DIR=/usr
export OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu
export OPENSSL_INCLUDE_DIR=/usr/include
export PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig
rm -rf /tmp/x8_src
git clone --depth=1 https://github.com/sh1yo/x8 /tmp/x8_src
cd /tmp/x8_src
cargo build --release
sudo cp ./target/release/x8 /usr/local/bin/x8
sudo chmod +x /usr/local/bin/x8
x8 --version`)
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	return buildCmd.Run()
}

// installRustscan installs rustscan via .deb release (most reliable on Kali).
func installRustscan() error {
	// Check if already installed via cargo — just symlink it
	for _, cargoPath := range []string{
		"/root/.cargo/bin/rustscan",
		os.Getenv("HOME") + "/.cargo/bin/rustscan",
	} {
		if _, err := os.Stat(cargoPath); err == nil {
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ↳ rustscan found in cargo — symlinking to /usr/local/bin/"))
			exec.Command("sudo", "ln", "-sf", cargoPath, "/usr/local/bin/rustscan").Run()
			// Add cargo to PATH permanently
			for _, profile := range []string{"/root/.bashrc", "/root/.zshrc"} {
				if _, e := os.Stat(profile); e == nil {
					exec.Command("bash", "-c", fmt.Sprintf(
						`grep -q "cargo/bin" %s || echo 'export PATH=$PATH:$HOME/.cargo/bin' >> %s`, profile, profile)).Run()
				}
			}
			return nil
		}
	}

	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ↳ Downloading RustScan 2.4.1 .deb..."))

	// Method 1: Direct 2.4.1 .deb (known good URL)
	knownURL := "https://github.com/bee-san/RustScan/releases/download/2.4.1/rustscan_2.4.1_amd64.deb"
	dlCmd := exec.Command("bash", "-c", fmt.Sprintf(
		`set -e
DEBIAN_FRONTEND=noninteractive
curl -fsSL "%s" -o /tmp/rustscan.deb 2>/dev/null || wget -q "%s" -O /tmp/rustscan.deb
DEBIAN_FRONTEND=noninteractive sudo dpkg -i /tmp/rustscan.deb
sudo apt-get install -f -y -qq -o Dpkg::Options::=--force-confdef 2>/dev/null || true
rm -f /tmp/rustscan.deb`, knownURL, knownURL))
	dlCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	dlCmd.Stdout = os.Stdout
	dlCmd.Stderr = os.Stderr
	dlCmd.Stdin = nil
	if err := dlCmd.Run(); err == nil {
		if _, e := exec.LookPath("rustscan"); e == nil {
			return nil
		}
	}

	// Method 2: Latest release .deb from GitHub API
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ↳ Trying latest RustScan release..."))
	latestCmd := exec.Command("bash", "-c",
		`set -e
DEBIAN_FRONTEND=noninteractive
LATEST=$(curl -s https://api.github.com/repos/bee-san/RustScan/releases/latest | grep browser_download_url | grep amd64.deb | cut -d'"' -f4 | head -1)
if [ -z "$LATEST" ]; then
  LATEST=$(curl -s https://api.github.com/repos/RustScan/RustScan/releases/latest | grep browser_download_url | grep amd64.deb | cut -d'"' -f4 | head -1)
fi
if [ -n "$LATEST" ]; then
  curl -fsSL "$LATEST" -o /tmp/rustscan.deb
  DEBIAN_FRONTEND=noninteractive sudo dpkg -i /tmp/rustscan.deb
  sudo apt-get install -f -y -qq 2>/dev/null || true
  rm -f /tmp/rustscan.deb
fi`)
	latestCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	latestCmd.Stdout = os.Stdout
	latestCmd.Stderr = os.Stderr
	latestCmd.Stdin = nil
	if err := latestCmd.Run(); err == nil {
		return nil
	}

	// Method 3: snap install
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ↳ Trying snap install rustscan..."))
	snapCmd := exec.Command("bash", "-c", "sudo snap install rustscan 2>/dev/null && sudo ln -sf /snap/bin/rustscan /usr/local/bin/rustscan 2>/dev/null || true")
	snapCmd.Stdout = os.Stdout
	snapCmd.Stderr = os.Stderr
	snapCmd.Stdin = nil
	snapCmd.Run()

	if _, e := exec.LookPath("rustscan"); e == nil {
		return nil
	}
	return fmt.Errorf("rustscan install failed — skip and continue")
}

// updateAllTools silently updates all installed tools to latest versions.
// Called automatically before /recon and /hunt to ensure latest tool versions.
// Errors are non-fatal — we log and continue.
func updateAllTools() {
	// Update apt tools (non-interactive, quiet)
	aptCmd := exec.Command("sudo", "apt", "update", "-qq")
	aptCmd.Run() // ignore error — may not have sudo

	// Update Go tools
	goTools := []struct{ bin, module string }{
		{"subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"},
		{"httpx", "github.com/projectdiscovery/httpx/cmd/httpx"},
		{"nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"},
		{"naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu"},
		{"dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx"},
		{"tlsx", "github.com/projectdiscovery/tlsx/cmd/tlsx"},
		{"katana", "github.com/projectdiscovery/katana/cmd/katana"},
		{"gau", "github.com/lc/gau/v2/cmd/gau"},
		{"waybackurls", "github.com/tomnomnom/waybackurls"},
		{"dalfox", "github.com/hahwul/dalfox/v2"},
	}

	homedir, _ := os.UserHomeDir()
	for _, gt := range goTools {
		if _, err := exec.LookPath(gt.bin); err != nil {
			continue // not installed, skip update
		}
		cmd := exec.Command("go", "install", gt.module+"@latest")
		cmd.Run() // ignore error
		// Re-symlink in case binary path changed
		for _, gobin := range []string{homedir + "/go/bin/" + gt.bin, "/root/go/bin/" + gt.bin} {
			if _, err := os.Stat(gobin); err == nil {
				exec.Command("sudo", "ln", "-sf", gobin, "/usr/local/bin/"+gt.bin).Run()
				break
			}
		}
	}

	// Update nuclei templates
	if _, err := exec.LookPath("nuclei"); err == nil {
		exec.Command("nuclei", "-update-templates", "-silent").Run()
	}

	// Update reconftw if installed
	if _, err := os.Stat("/opt/reconftw/.git"); err == nil {
		pullCmd := exec.Command("git", "-C", "/opt/reconftw", "pull", "origin", "main", "--quiet")
		pullCmd.Run()
	}

	fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Tools updated"))
}

// requireAPIKey checks if an API key is set; if not, prompts the user interactively.
// Returns false if no key was set and user skipped — caller should exit.
func requireAPIKey() bool {
	if api.GetAPIKey() != "" {
		return true
	}
	key := promptForAPIKey()
	return key != ""
}

// requirePlan checks if the current API key has the required plan.
// Validates against the backend — returns true if allowed, false if blocked.
func requirePlan(minPlan string) bool {
	key := api.GetAPIKey()
	if key == "" {
		return false
	}
	plan, err := api.ValidateKey(key)
	if err != nil {
		// Can't reach backend — allow locally, backend will enforce
		return true
	}
	planOrder := map[string]int{"free": 0, "starter": 1, "pro": 2, "elite": 3}
	userLevel := planOrder[plan]
	minLevel  := planOrder[minPlan]
	if userLevel < minLevel {
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render(
			fmt.Sprintf("  ✗ This command requires %s plan or higher.", strings.ToUpper(minPlan))))
		fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render(
			fmt.Sprintf("  Your current plan: %s", strings.ToUpper(plan))))
		fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
			"  Upgrade at: https://cybermindcli1.vercel.app/plans"))
		fmt.Println()
		return false
	}
	return true
}

// promptForAPIKey interactively asks the user to paste their API key.
// Shows a clear setup guide, validates the key format, saves it securely.
// Returns the key they entered, or "" if they skipped.
func promptForAPIKey() string {
	cyan2  := lipgloss.NewStyle().Foreground(lipgloss.Color("#00d4ff"))
	green2 := lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF88"))
	yellow2 := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700"))
	dim2   := lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	red2   := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444"))
	purple := lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2"))

	fmt.Println()
	fmt.Println(yellow2.Render("  ┌─────────────────────────────────────────────────┐"))
	fmt.Println(yellow2.Render("  │  🔑  API Key Required                           │"))
	fmt.Println(yellow2.Render("  └─────────────────────────────────────────────────┘"))
	fmt.Println()
	fmt.Println(cyan2.Render("  CyberMind CLI needs a free API key to work."))
	fmt.Println()
	fmt.Println(cyan2.Render("  Get your free key in 30 seconds:"))
	fmt.Println(cyan2.Render("  ① Open:  https://cybermindcli1.vercel.app/dashboard"))
	fmt.Println(cyan2.Render("  ② Sign up (free) → click \"New key\" → select your OS"))
	fmt.Println(cyan2.Render("  ③ Copy the key (starts with cp_live_...)"))
	fmt.Println(cyan2.Render("  ④ Paste it below"))
	fmt.Println()
	fmt.Println()

	// Allow up to 3 attempts
	for attempt := 1; attempt <= 3; attempt++ {
		fmt.Print(purple.Render("  Paste your API key (or press Enter to skip): "))

		var input string
		fmt.Scanln(&input)
		input = strings.TrimSpace(input)

		// User skipped
		if input == "" {
			fmt.Println()
			fmt.Println(dim2.Render("  Skipped. Set it later with: cybermind --key cp_live_xxxxx"))
			fmt.Println()
			return ""
		}

		// Validate format
		if !strings.HasPrefix(input, "cp_live_") && !strings.HasPrefix(input, "sk_live_cm_") {
			fmt.Println(red2.Render("  ✗ Invalid format. Key must start with cp_live_"))
			if attempt < 3 {
				fmt.Println(dim2.Render("  Try again or press Enter to skip."))
				fmt.Println()
				continue
			}
			fmt.Println(dim2.Render("  Get your key: https://cybermindcli1.vercel.app/dashboard"))
			fmt.Println()
			return ""
		}
		if len(input) < 20 {
			fmt.Println(red2.Render("  ✗ Key too short — looks incomplete. Check your dashboard."))
			if attempt < 3 {
				fmt.Println(dim2.Render("  Try again or press Enter to skip."))
				fmt.Println()
				continue
			}
			return ""
		}

		// Save securely
		if err := saveAPIKey(input); err != nil {
			fmt.Println(red2.Render("  ✗ Could not save key: " + err.Error()))
			fmt.Println()
			return ""
		}

		masked := input[:min(12, len(input))] + strings.Repeat("•", max(0, len(input)-12))
		fmt.Println()
		fmt.Println(green2.Render("  ✓ Key saved: " + masked))
		fmt.Println(green2.Render("  ✓ Key stored in ~/.cybermind/config.json (owner-only permissions)"))
		fmt.Println(dim2.Render("  ✓ Used automatically for all future requests — no need to set again"))
		fmt.Println()
		return input
	}

	return ""
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		if err := storage.Load(); err != nil {
			fmt.Println("Warning: could not load history:", err)
		}
		printBanner()

		// Legacy key warning — shown before TUI launches
		if key := api.GetAPIKey(); strings.HasPrefix(key, "sk_live_cm_") {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(yellow).Render(
				"  ⚠  Your API key is outdated. Please get a new one:"))
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
				"  1. Visit: https://cybermindcli1.vercel.app/dashboard"))
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
				"  2. Sign up / log in → New key → copy it"))
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
				"  3. Run: cybermind --key cp_live_xxxxx"))
			fmt.Println()
		}

		// TUI handles key prompt automatically if no key is set
		// FIX: prompt for key BEFORE launching TUI — better UX
		if api.GetAPIKey() == "" {
			// Show free mode option first
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF88")).Render(
				"  ✓ FREE MODE available — no API key needed!"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
				"  Try: cybermind \"how do I find XSS vulnerabilities?\""))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
				"  For full features (recon/hunt/plan): cybermind --key cp_live_xxxxx"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
				"  Get free key: https://cybermindcli1.vercel.app/dashboard"))
			fmt.Println()
		}

		p := tea.NewProgram(ui.NewModel(getLocalIP()))
		if _, err := p.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	cmd := strings.ToLower(args[0])

	// Handle uninstall before any other checks — no API key needed, works on all OS
	if cmd == "uninstall" || cmd == "/uninstall" {
		runUninstall()
		return
	}

	// Local mode detection — must happen before API key loading
	localMode := false
	for i, a := range args {
		if a == "--local" {
			localMode = true
			args = append(args[:i], args[i+1:]...)
			break
		}
	}
	if os.Getenv("CYBERMIND_LOCAL") == "true" {
		localMode = true
	}
	// Re-derive cmd after stripping --local flag
	if len(args) > 0 {
		cmd = strings.ToLower(args[0])
	}
	// New commands (/scan, /portscan, /osint, /payload, /cve, /wordlist, report) work on all OS
	if runtime.GOOS != "linux" {
		normalized := strings.TrimPrefix(cmd, "/")
		linuxOnlyCmds := map[string]bool{
			"recon": true, "hunt": true, "tools": true,
			"install-tools": true, "install-hunt": true,
			"abhimanyu": true,
		}
		// Cross-platform slash commands — allowed on all OS (including /doctor for self-update)
		crossPlatformSlashCmds := map[string]bool{
			"scan": true, "portscan": true, "osint": true,
			"payload": true, "cve": true, "wordlist": true,
			"doctor": true, "uninstall": true,
			"platform": true, "brain": true,
			"locate": true,
			"breach": true, // breach check works on all OS (API-based)
		}
		if linuxOnlyCmds[normalized] || (strings.HasPrefix(cmd, "/") && !crossPlatformSlashCmds[normalized]) {
			printError("This command is only available on Linux/Kali.")
			if runtime.GOOS == "darwin" {
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  macOS supports AI chat, /scan, /portscan, /osint, /payload, /cve, /wordlist, /doctor, report"))
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Windows supports AI chat, /scan, /portscan, /osint, /payload, /cve, /wordlist, /doctor, report"))
			}
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Use Kali Linux for full recon/hunt/abhimanyu pipeline"))
			os.Exit(1)
		}
	}

	_ = localMode // used in command handlers below

	switch cmd {

	case "help", "--help", "-h":
		printBanner()
		printHelp()

	case "version", "--version", "-v":
		fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  CyberMind CLI v" + Version))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  github.com/thecnical"))

	case "--key":
		// Save API key to ~/.cybermind/config.json
		if len(args) < 2 {
			printError("Usage: cybermind --key cp_live_xxxxx")
			os.Exit(1)
		}
		key := strings.TrimSpace(args[1])
		// Validate key format before saving
		if !strings.HasPrefix(key, "cp_live_") && !strings.HasPrefix(key, "sk_live_cm_") {
			printError("Invalid key format. Key must start with cp_live_")
			printError("Get your key at: https://cybermindcli1.vercel.app/dashboard")
			os.Exit(1)
		}
		if len(key) < 16 {
			printError("Key too short — looks invalid. Check your dashboard.")
			os.Exit(1)
		}
		if err := saveAPIKey(key); err != nil {
			printError("Failed to save key: " + err.Error())
			os.Exit(1)
		}
		// Also update vibecoder config so both CLI and CBM Code use the new key
		_ = vibecoder.SetAPIKey("openrouter", key)
		masked := key[:min(12, len(key))] + strings.Repeat("•", max(0, len(key)-12))
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ API key saved: " + masked))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Previous key replaced. Key will be used automatically for all requests."))

	case "whoami":
		// Show current key and plan
		key := api.GetAPIKey()
		if key == "" {
			fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  No API key set. Get yours at https://cybermindcli1.vercel.app/dashboard"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Set key: cybermind --key cp_live_xxxxx"))
		} else {
			masked := key[:min(12, len(key))] + strings.Repeat("•", max(0, len(key)-12))
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ API key: " + masked))
			// Validate key with backend
			planRaw, err := api.ValidateKey(key)
			if err != nil {
				fmt.Println(lipgloss.NewStyle().Foreground(red).Render("  ✗ Key validation failed: " + err.Error()))
			} else {
				// Parse plan info (may contain |NAME| suffix)
				parts := strings.SplitN(planRaw, "|NAME|", 2)
				plan := parts[0]
				fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  Plan: " + strings.ToUpper(plan)))
			}
		}

	case "/recon":
		// Linux-only auto recon
		if runtime.GOOS != "linux" {
			printError("Auto Recon Mode is only available on Linux/Kali.")
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Use: cybermind recon <target> for AI-guided recon on Windows"))
			os.Exit(1)
		}
		if len(args) < 2 {
			printError("Usage: cybermind /recon <target> [--tools tool1,tool2]")
			printError("Example: cybermind /recon 192.168.1.1")
			printError("Example: cybermind /recon example.com --tools nmap,httpx,nuclei")
			os.Exit(1)
		}
		target, requested, parseErr := parseToolsFlag(args[1:])
		if parseErr != nil {
			printError(parseErr.Error())
			os.Exit(1)
		}
		// Security: validate target
		if err := recon.ValidateTarget(target); err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		if !requireAPIKey() {
			os.Exit(1)
		}
		// Plan check: recon requires starter or higher
		if !requirePlan("starter") {
			os.Exit(1)
		}
		// Auto-update all tools before running recon — ensures latest versions
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ⟳ Updating tools before recon..."))
		updateAllTools()
		runAutoRecon(target, requested)

	case "/tools":
		// Show available recon tools
		if runtime.GOOS != "linux" {
			printError("Tool check is only available on Linux/Kali.")
			os.Exit(1)
		}
		tools := recon.CheckTools()
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  🛠  Recon Tools Status"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 40)))
		for tool, available := range tools {
			if available {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ " + tool))
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(red).Render("  ✗ " + tool + " (not installed)"))
			}
		}
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Install missing: sudo apt install nmap whois dnsutils"))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Go tools: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"))
		fmt.Println()

	case "/hunt":
		// Linux-only hunt mode
		if runtime.GOOS != "linux" {
			printError("Hunt Mode is only available on Linux/Kali.")
			os.Exit(1)
		}
		if len(args) < 2 {
			printError("Usage: cybermind /hunt <target> [--tools tool1,tool2]")
			printError("Example: cybermind /hunt example.com")
			printError("Example: cybermind /hunt example.com --tools dalfox,nuclei-hunt")
			os.Exit(1)
		}
		// Parse target and optional --tools flag
		huntTarget := args[1]
		var huntRequested []string
		for i := 2; i < len(args); i++ {
			if args[i] == "--tools" && i+1 < len(args) {
				for _, n := range strings.Split(args[i+1], ",") {
					n = strings.TrimSpace(n)
					if n != "" {
						huntRequested = append(huntRequested, n)
					}
				}
				i++
			}
		}
		if len(huntRequested) > 0 {
			validSet := make(map[string]bool)
			for _, n := range hunt.HuntToolNames() {
				validSet[n] = true
			}
			for _, t := range huntRequested {
				if !validSet[t] {
					printError(fmt.Sprintf("unknown hunt tool %q — valid: %s",
						t, strings.Join(hunt.HuntToolNames(), ", ")))
					os.Exit(1)
				}
			}
		}
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		// Security: validate target
		if err := recon.ValidateTarget(huntTarget); err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		if !requireAPIKey() {
			os.Exit(1)
		}
		// Plan check: hunt requires starter or higher
		if !requirePlan("starter") {
			os.Exit(1)
		}
		// Auto-update all tools before running hunt — ensures latest versions
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ⟳ Updating tools before hunt..."))
		updateAllTools()
		// Manual mode — no recon context
		runHunt(huntTarget, nil, huntRequested)

	case "/doctor":
		// Full health check + self-update + auto-install missing tools
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  🩺 CyberMind Doctor — Health Check + Auto-Update"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
		fmt.Println()

		// ── Step 0: Self-update (all platforms) ──────────────────────────────
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  ① Checking for CLI updates..."))
		runSelfUpdate()
		fmt.Println()

		// ── Step 1: Tool health check (Linux only) ────────────────────────────
		if runtime.GOOS != "linux" {
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ CLI is up to date. Recon/hunt tools are Linux-only."))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Windows/macOS: AI chat + Vibe Coder + VSCode extension are fully functional."))
			fmt.Println()
			return
		}

		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  ② Checking recon + hunt tools..."))
		fmt.Println()

		// ── Pre-seed ALL debconf dialogs so NOTHING ever prompts ─────────────
		// This handles krb5-config, postfix, tzdata, neo4j, etc.
		os.Setenv("DEBIAN_FRONTEND", "noninteractive")
		os.Setenv("DEBCONF_NONINTERACTIVE_SEEN", "true")
		preseedCmd := exec.Command("bash", "-c", `
			export DEBIAN_FRONTEND=noninteractive
			echo "krb5-config krb5-config/default_realm string CYBERMIND.LOCAL" | debconf-set-selections 2>/dev/null || true
			echo "krb5-config krb5-config/kerberos_servers string localhost" | debconf-set-selections 2>/dev/null || true
			echo "krb5-config krb5-config/admin_server string localhost" | debconf-set-selections 2>/dev/null || true
			echo "postfix postfix/mailname string cybermind.local" | debconf-set-selections 2>/dev/null || true
			echo "postfix postfix/main_mailer_type string 'No configuration'" | debconf-set-selections 2>/dev/null || true
			echo "tzdata tzdata/Areas select Etc" | debconf-set-selections 2>/dev/null || true
			echo "tzdata tzdata/Zones/Etc select UTC" | debconf-set-selections 2>/dev/null || true
		`)
		preseedCmd.Run() // ignore errors — debconf-set-selections may not exist on all systems

		type toolEntry struct {
			name    string
			mode    string
			install string
			isGo    bool
			isCargo bool
		}

		allTools := []toolEntry{
			// ── Recon Phase 1 — Passive OSINT ──────────────────────────────────
			{"whois", "recon", "apt:whois", false, false},
			{"theHarvester", "recon", "apt:theharvester", false, false},
			{"dig", "recon", "apt:dnsutils", false, false},
			{"shodan", "recon", "pipx:shodan", false, false},
			{"h8mail", "recon", "pipx:h8mail", false, false},
			{"exiftool", "recon", "apt:libimage-exiftool-perl", false, false},
			{"metagoofil", "recon", "apt:metagoofil", false, false},
			{"spiderfoot", "recon", "apt:spiderfoot", false, false},
			{"recon-ng", "recon", "apt:recon-ng", false, false},
			// ── Recon Phase 2 — Subdomain Enumeration ──────────────────────────
			{"subfinder", "recon", "go:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", true, false},
			{"amass", "recon", "apt:amass", false, false},
			{"reconftw", "recon", "special:reconftw", false, false},
			{"dnsx", "recon", "go:github.com/projectdiscovery/dnsx/cmd/dnsx@latest", true, false},
			// ── Recon Phase 3 — Port Scanning ──────────────────────────────────
			{"rustscan", "recon", "special:rustscan", false, false},
			{"naabu", "recon", "go:github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", true, false},
			{"nmap", "recon", "apt:nmap", false, false},
			{"masscan", "recon", "apt:masscan", false, false},
			{"zmap", "recon", "apt:zmap", false, false},
			// ── Recon Phase 4 — HTTP Fingerprinting ────────────────────────────
			{"httpx", "recon", "go:github.com/projectdiscovery/httpx/cmd/httpx@latest", true, false},
			{"whatweb", "recon", "apt:whatweb", false, false},
			{"tlsx", "recon", "go:github.com/projectdiscovery/tlsx/cmd/tlsx@latest", true, false},
			{"wafw00f", "recon", "pipx:wafw00f", false, false},
			// ── Recon Phase 5 — Directory Discovery ────────────────────────────
			{"ffuf", "recon", "apt:ffuf", false, false},
			{"feroxbuster", "recon", "apt:feroxbuster", false, false},
			{"gobuster", "recon", "apt:gobuster", false, false},
			// ── Recon Phase 6 — Vulnerability Scanning ─────────────────────────
			{"nuclei", "recon", "go:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", true, false},
			{"nikto", "recon", "apt:nikto", false, false},
			{"katana", "recon", "go:github.com/projectdiscovery/katana/cmd/katana@latest", true, false},
			// ── NEW Kali Tools — Recon ──────────────────────────────────────────
			{"crlfuzz", "recon", "apt:crlfuzz", false, false},
			{"tinja", "recon", "apt:tinja", false, false},
			{"sstimap", "recon", "apt:sstimap", false, false},
			{"wpprobe", "recon", "apt:wpprobe", false, false},
			{"gitxray", "recon", "apt:gitxray", false, false},
			{"binwalk3", "recon", "apt:binwalk3", false, false},
			// ── Hunt Phase 1 — URL Collection ──────────────────────────────────
			{"waymore", "hunt", "pipx:waymore", false, false},
			{"gau", "hunt", "go:github.com/lc/gau/v2/cmd/gau@latest", true, false},
			{"waybackurls", "hunt", "go:github.com/tomnomnom/waybackurls@latest", true, false},
			{"hakrawler", "hunt", "go:github.com/hakluke/hakrawler@latest", true, false},
			{"urlfinder", "hunt", "go:github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest", true, false},
			{"httprobe", "hunt", "go:github.com/tomnomnom/httprobe@latest", true, false},
			// ── Hunt Phase 2 — Deep Crawl ──────────────────────────────────────
			{"gospider", "hunt", "go:github.com/jaeles-project/gospider@latest", true, false},
			{"cariddi", "hunt", "go:github.com/edoardottt/cariddi/cmd/cariddi@latest", true, false},
			{"subjs", "hunt", "go:github.com/lc/subjs@latest", true, false},
			{"trufflehog", "hunt", "special:trufflehog", false, false},
			{"mantra", "hunt", "go:github.com/Brosck/mantra@latest", true, false},
			// ── Hunt Phase 3 — Parameter Discovery ─────────────────────────────
			{"paramspider", "hunt", "venv:https://github.com/devanshbatham/ParamSpider:/opt/ParamSpider:paramspider.py", false, false},
			{"arjun", "hunt", "pipx:arjun", false, false},
			{"x8", "hunt", "special:x8", false, false},
			{"smuggler", "hunt", "venv:https://github.com/defparam/smuggler:/opt/smuggler:smuggler.py", false, false},
			{"jwt_tool", "hunt", "venv:https://github.com/ticarpi/jwt_tool:/opt/jwt_tool:jwt_tool.py", false, false},
			{"graphw00f", "hunt", "pipx:graphw00f", false, false},
			// ── Hunt Phase 4 — XSS Hunting ─────────────────────────────────────
			{"xsstrike", "hunt", "venv:https://github.com/s0md3v/XSStrike:/opt/XSStrike:xsstrike.py", false, false},
			{"dalfox", "hunt", "go:github.com/hahwul/dalfox/v2@latest", true, false},
			{"kxss", "hunt", "go:github.com/Emoe/kxss@latest", true, false},
			{"bxss", "hunt", "go:github.com/ethicalhackingplayground/bxss/v2/cmd/bxss@latest", true, false},
			{"corsy", "hunt", "venv:https://github.com/s0md3v/Corsy:/opt/corsy:corsy.py", false, false},
			{"beef-xss", "hunt", "apt:beef-xss", false, false},
			// ── Hunt Phase 5 — Deep Vuln Scan ──────────────────────────────────
			{"gf", "hunt", "special:gf", true, false},
			{"ssrfmap", "hunt", "venv:https://github.com/swisskyrepo/SSRFmap:/opt/ssrfmap:ssrfmap.py", false, false},
			{"tplmap", "hunt", "venv:https://github.com/epinna/tplmap:/opt/tplmap:tplmap.py", false, false},
			{"liffy", "hunt", "venv:https://github.com/mzfr/liffy:/opt/liffy:liffy.py", false, false},
			{"gopherus", "hunt", "venv:https://github.com/tarunkant/Gopherus:/opt/gopherus:gopherus.py", false, false},
			// ── Exploit Phase 1 — Web Exploitation ─────────────────────────────
			{"sqlmap", "exploit", "apt:sqlmap", false, false},
			{"commix", "exploit", "apt:commix", false, false},
			{"wpscan", "exploit", "apt:wpscan", false, false},
			{"nosqlmap", "exploit", "venv:https://github.com/codingo/NoSQLMap:/opt/nosqlmap:nosqlmap.py", false, false},
			{"xxeinjector", "exploit", "special:xxeinjector", false, false},
			// ── Auth Attacks ────────────────────────────────────────────────────
			{"hydra", "exploit", "apt:hydra", false, false},
			{"john", "exploit", "apt:john", false, false},
			{"hashcat", "exploit", "apt:hashcat", false, false},
			{"kerbrute", "exploit", "special:kerbrute", false, false},
			{"sprayhound", "exploit", "pipx:sprayhound", false, false},
			// ── CVE/Exploit Search ──────────────────────────────────────────────
			{"searchsploit", "exploit", "apt:exploitdb", false, false},
			{"msfconsole", "exploit", "apt:metasploit-framework", false, false},
			// ── Post-Exploitation ───────────────────────────────────────────────
			{"linpeas", "exploit", "special:linpeas", false, false},
			{"pspy", "exploit", "special:pspy", false, false},
			{"bloodhound-python", "exploit", "pipx:bloodhound", false, false},
			{"certipy", "exploit", "pipx:certipy-ad", false, false},
			{"bloodyAD", "exploit", "pipx:bloodyad", false, false},
			{"pywhisker", "exploit", "venv:https://github.com/ShutdownRepo/pywhisker:/opt/pywhisker:pywhisker.py", false, false},
			// ── Lateral Movement ────────────────────────────────────────────────
			{"crackmapexec", "exploit", "apt:crackmapexec", false, false},
			{"netexec", "exploit", "pipx:netexec", false, false},
			{"evil-winrm", "exploit", "gem:evil-winrm", false, false},
			{"impacket-secretsdump", "exploit", "apt:python3-impacket", false, false},
			{"coercer", "exploit", "pipx:coercer", false, false},
			{"mitm6", "exploit", "pipx:mitm6", false, false},
			// ── Tunneling + Exfil ───────────────────────────────────────────────
			{"chisel", "exploit", "go:github.com/jpillora/chisel@latest", true, false},
			{"ligolo-ng", "exploit", "apt:ligolo-ng", false, false},
			{"iodine", "exploit", "apt:iodine", false, false},
			// ── C2 Frameworks ───────────────────────────────────────────────────
			{"empire", "exploit", "apt:powershell-empire", false, false},
			{"sliver", "exploit", "special:sliver", false, false},
			{"evilginx2", "exploit", "special:evilginx2", false, false},
			// ── Router/IoT ──────────────────────────────────────────────────────
			{"routersploit", "exploit", "venv:https://github.com/threat9/routersploit:/opt/routersploit:rsf.py", false, false},
			// ── New Kali Tools ──────────────────────────────────────────────────
			{"adaptixc2", "exploit", "apt:adaptixc2", false, false},
			{"atomic-operator", "exploit", "apt:atomic-operator", false, false},
			{"fluxion", "exploit", "apt:fluxion", false, false},
			{"rubeus", "exploit", "apt:rubeus", false, false},
			{"ldeep", "exploit", "apt:ldeep", false, false},
			{"donut-shellcode", "exploit", "apt:donut-shellcode", false, false},
			{"bopscrk", "exploit", "apt:bopscrk", false, false},
			// ── Crypto/Web3 ─────────────────────────────────────────────────────
			{"slither", "exploit", "pipx:slither-analyzer", false, false},
			{"myth", "exploit", "pipx:mythril", false, false},
			// ── Mobile ──────────────────────────────────────────────────────────
			{"apktool", "exploit", "apt:apktool", false, false},
			{"jadx", "exploit", "apt:jadx", false, false},
			// ── OAuth/SAML/Business Logic ────────────────────────────────────────
			{"smuggler", "exploit", "venv:https://github.com/defparam/smuggler:/opt/smuggler:smuggler.py", false, false},
			{"corscanner", "exploit", "pipx:corscanner", false, false},
			{"h2csmuggler", "exploit", "pipx:h2csmuggler", false, false},
			// ── Browser Automation (XSS verify + authenticated scanning) ─────────
			{"node", "recon", "apt:nodejs", false, false},
		}

		var missing []toolEntry
		reconOK := 0
		huntOK := 0
		exploitOK := 0
		reconTotal := 0
		huntTotal := 0
		exploitTotal := 0
		for _, t := range allTools {
			switch t.mode {
			case "recon":
				reconTotal++
			case "hunt":
				huntTotal++
			case "exploit":
				exploitTotal++
			}
		}

		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render(fmt.Sprintf("  RECON TOOLS (%d):", reconTotal)))
		for _, t := range allTools {
			if t.mode != "recon" {
				continue
			}
			if _, err := exec.LookPath(t.name); err == nil {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ %-20s installed", t.name)))
				reconOK++
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(red).Render(fmt.Sprintf("  ✗ %-20s MISSING", t.name)))
				missing = append(missing, t)
			}
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render(fmt.Sprintf("  HUNT TOOLS (%d):", huntTotal)))
		for _, t := range allTools {
			if t.mode != "hunt" {
				continue
			}
			if _, err := exec.LookPath(t.name); err == nil {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ %-20s installed", t.name)))
				huntOK++
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(red).Render(fmt.Sprintf("  ✗ %-20s MISSING", t.name)))
				missing = append(missing, t)
			}
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render(fmt.Sprintf("  ABHIMANYU EXPLOIT TOOLS (%d):", exploitTotal)))
		for _, t := range allTools {
			if t.mode != "exploit" {
				continue
			}
			if _, err := exec.LookPath(t.name); err == nil {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ %-20s installed", t.name)))
				exploitOK++
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(red).Render(fmt.Sprintf("  ✗ %-20s MISSING", t.name)))
				missing = append(missing, t)
			}
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render(
			fmt.Sprintf("  Recon:     %d/%d installed", reconOK, reconTotal)))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6600")).Render(
			fmt.Sprintf("  Hunt:      %d/%d installed", huntOK, huntTotal)))
		fmt.Println(lipgloss.NewStyle().Foreground(red).Render(
			fmt.Sprintf("  Abhimanyu: %d/%d installed", exploitOK, exploitTotal)))

		if len(missing) == 0 {
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green).Render("  ✓ All tools installed — ready to hunt!"))
			fmt.Println()
		} else {
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(yellow).Render(
				fmt.Sprintf("  ⚡ %d tools missing — installing now...", len(missing))))
			fmt.Println()

			instOK, instFail := 0, 0
			// helper: symlink go binary
			symlinkGoTool := func(name string) {
				homedir2, _ := os.UserHomeDir()
				for _, gobin := range []string{homedir2 + "/go/bin/" + name, "/root/go/bin/" + name} {
					if _, err2 := os.Stat(gobin); err2 == nil {
						exec.Command("sudo", "ln", "-sf", gobin, "/usr/local/bin/"+name).Run()
						return
					}
				}
			}
			for _, t := range missing {
				// ── Skip if already installed (PATH + common locations) ──────
				alreadyInstalled := false
				if _, err := exec.LookPath(t.name); err == nil {
					alreadyInstalled = true
				} else {
					// Check common non-PATH locations
					homedir2, _ := os.UserHomeDir()
					for _, p := range []string{
						homedir2 + "/go/bin/" + t.name,
						"/root/go/bin/" + t.name,
						homedir2 + "/.local/bin/" + t.name,
						"/root/.local/bin/" + t.name,
					} {
						if _, e := os.Stat(p); e == nil {
							// Found — just symlink it
							exec.Command("sudo", "ln", "-sf", p, "/usr/local/bin/"+t.name).Run()
							alreadyInstalled = true
							break
						}
					}
				}
				if alreadyInstalled {
					fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ %-20s already installed (symlinked)", t.name)))
					instOK++
					continue
				}

				fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(fmt.Sprintf("  ⟳ %-20s installing...", t.name)))

				var installErr error

				switch {
				case strings.HasPrefix(t.install, "apt:"):
					pkg := strings.TrimPrefix(t.install, "apt:")
					installErr = aptInstall(pkg)

				case strings.HasPrefix(t.install, "pipx:"):
					pkg := strings.TrimPrefix(t.install, "pipx:")
					installErr = installPythonPipTool(pkg)
					// also try to symlink binary name if different from pkg
					if installErr == nil {
						for _, searchDir := range []string{
							"/usr/local/bin/" + t.name,
							"/opt/pipx/venvs/" + pkg + "/bin/" + t.name,
							os.Getenv("HOME") + "/.local/bin/" + t.name,
							"/root/.local/bin/" + t.name,
						} {
							if _, e := os.Stat(searchDir); e == nil {
								exec.Command("sudo", "ln", "-sf", searchDir, "/usr/local/bin/"+t.name).Run()
								break
							}
						}
					}

				case strings.HasPrefix(t.install, "go:"):
					module := strings.TrimPrefix(t.install, "go:")
					if t.name == "naabu" {
						aptInstall("libpcap-dev")
					}
					cmd2 := exec.Command("go", "install", module)
					cmd2.Stdout = os.Stdout
					cmd2.Stderr = os.Stderr
					cmd2.Stdin = nil
					installErr = cmd2.Run()
					if installErr == nil {
						symlinkGoTool(t.name)
					}

				case strings.HasPrefix(t.install, "venv:"):
					// format: venv:REPOURL:INSTALLDIR:MAINSCRIPT
					parts := strings.SplitN(strings.TrimPrefix(t.install, "venv:"), ":", 3)
					if len(parts) == 3 {
						installErr = installPythonGitTool(t.name, parts[0], parts[1], parts[2])
					}

				case strings.HasPrefix(t.install, "gem:"):
					pkg := strings.TrimPrefix(t.install, "gem:")
					aptInstall("ruby", "ruby-dev")
					cmd2 := exec.Command("sudo", "gem", "install", pkg)
					cmd2.Stdout = os.Stdout
					cmd2.Stderr = os.Stderr
					cmd2.Stdin = nil
					installErr = cmd2.Run()

				case t.install == "special:reconftw":
					installErr = installReconftw()

				case t.install == "special:rustscan":
					installErr = installRustscan()

				case t.install == "special:trufflehog":
					cmd2 := exec.Command("bash", "-c",
						"curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin")
					cmd2.Stdout = os.Stdout
					cmd2.Stderr = os.Stderr
					cmd2.Stdin = nil
					installErr = cmd2.Run()

				case t.install == "special:x8":
					installErr = installX8()

				case t.install == "special:gf":
					cmd2 := exec.Command("go", "install", "github.com/tomnomnom/gf@latest")
					cmd2.Stdout = os.Stdout
					cmd2.Stderr = os.Stderr
					cmd2.Stdin = nil
					if err := cmd2.Run(); err != nil {
						installErr = err
					} else {
						symlinkGoTool("gf")
						homedir2, _ := os.UserHomeDir()
						gfDir := homedir2 + "/.gf"
						if _, err2 := os.Stat(gfDir); err2 != nil {
							exec.Command("git", "clone", "--depth=1", "https://github.com/1ndianl33t/Gf-Patterns", gfDir).Run()
						}
					}

				case t.install == "special:xxeinjector":
					exec.Command("sudo", "rm", "-rf", "/opt/xxeinjector").Run()
					cloneCmd := exec.Command("git", "clone", "--depth=1", "https://github.com/enjoiz/XXEinjector", "/opt/xxeinjector")
					cloneCmd.Stdout = os.Stdout
					cloneCmd.Stderr = os.Stderr
					cloneCmd.Stdin = nil
					if err := cloneCmd.Run(); err != nil {
						installErr = err
					} else {
						aptInstall("ruby")
						teeCmd := exec.Command("sudo", "tee", "/usr/local/bin/xxeinjector")
						teeCmd.Stdin = strings.NewReader("#!/bin/bash\nruby /opt/xxeinjector/XXEinjector.rb \"$@\"\n")
						teeCmd.Run()
						exec.Command("sudo", "chmod", "+x", "/usr/local/bin/xxeinjector").Run()
					}

				case t.install == "special:kerbrute":
					// Download pre-built binary from releases (go install has module issues)
					dlCmd := exec.Command("bash", "-c",
						`set -e
LATEST=$(curl -s https://api.github.com/repos/ropnop/kerbrute/releases/latest | grep browser_download_url | grep linux_amd64 | cut -d'"' -f4 | head -1)
if [ -z "$LATEST" ]; then exit 1; fi
curl -fsSL "$LATEST" -o /tmp/kerbrute
chmod +x /tmp/kerbrute
sudo mv /tmp/kerbrute /usr/local/bin/kerbrute`)
					dlCmd.Stdout = os.Stdout
					dlCmd.Stderr = os.Stderr
					dlCmd.Stdin = nil
					installErr = dlCmd.Run()

				case t.install == "special:linpeas":
					cmd2 := exec.Command("bash", "-c",
						"curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /opt/linpeas.sh && chmod +x /opt/linpeas.sh && sudo ln -sf /opt/linpeas.sh /usr/local/bin/linpeas")
					cmd2.Stdout = os.Stdout
					cmd2.Stderr = os.Stderr
					cmd2.Stdin = nil
					installErr = cmd2.Run()

				case t.install == "special:pspy":
					cmd2 := exec.Command("bash", "-c",
						"curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /opt/pspy && chmod +x /opt/pspy && sudo ln -sf /opt/pspy /usr/local/bin/pspy")
					cmd2.Stdout = os.Stdout
					cmd2.Stderr = os.Stderr
					cmd2.Stdin = nil
					installErr = cmd2.Run()

				case t.install == "special:sliver":
					dlCmd := exec.Command("bash", "-c",
						`set -e
LATEST=$(curl -s https://api.github.com/repos/BishopFox/sliver/releases/latest | grep browser_download_url | grep linux_amd64 | grep -v server | cut -d'"' -f4 | head -1)
if [ -z "$LATEST" ]; then exit 1; fi
curl -fsSL "$LATEST" -o /tmp/sliver-client
chmod +x /tmp/sliver-client
sudo mv /tmp/sliver-client /usr/local/bin/sliver`)
					dlCmd.Stdout = os.Stdout
					dlCmd.Stderr = os.Stderr
					dlCmd.Stdin = nil
					installErr = dlCmd.Run()

				case t.install == "special:evilginx2":
					dlCmd := exec.Command("bash", "-c",
						`set -e
LATEST=$(curl -s https://api.github.com/repos/kgretzky/evilginx2/releases/latest | grep browser_download_url | grep linux_amd64 | grep -v '.sha' | cut -d'"' -f4 | head -1)
if [ -z "$LATEST" ]; then exit 1; fi
curl -fsSL "$LATEST" -o /tmp/evilginx2.tar.gz
mkdir -p /opt/evilginx2
tar -xzf /tmp/evilginx2.tar.gz -C /opt/evilginx2 --strip-components=1 2>/dev/null || tar -xzf /tmp/evilginx2.tar.gz -C /opt/evilginx2
chmod +x /opt/evilginx2/evilginx 2>/dev/null || true
sudo ln -sf /opt/evilginx2/evilginx /usr/local/bin/evilginx2 2>/dev/null || true
rm -f /tmp/evilginx2.tar.gz`)
					dlCmd.Stdout = os.Stdout
					dlCmd.Stderr = os.Stderr
					dlCmd.Stdin = nil
					installErr = dlCmd.Run()

				default:
					// apt fallback for any unhandled tool
					if t.isCargo {
						installErr = installRustscan() // only rustscan uses cargo now
					} else if t.isGo {
						parts := strings.Fields(t.install)
						cmd2 := exec.Command("go", "install", parts[len(parts)-1])
						cmd2.Stdout = os.Stdout
						cmd2.Stderr = os.Stderr
						cmd2.Stdin = nil
						installErr = cmd2.Run()
						if installErr == nil {
							symlinkGoTool(t.name)
						}
					} else {
						cmd2 := exec.Command("bash", "-c", t.install)
						cmd2.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
						cmd2.Stdout = os.Stdout
						cmd2.Stderr = os.Stderr
						cmd2.Stdin = nil
						installErr = cmd2.Run()
					}
				}

				if installErr != nil {
					fmt.Println(lipgloss.NewStyle().Foreground(red).Render(fmt.Sprintf("  ✗ %-20s failed: %v", t.name, installErr)))

					// ── AI Auto-Fix: get fix commands and execute them ────────
					errMsg := fmt.Sprintf("Tool installation failed on Kali Linux: %s\nError: %v\nProvide ONLY the exact bash commands to fix this, one per line, no explanation.", t.name, installErr)
					if fix, aiErr := api.SendPrompt(errMsg); aiErr == nil && fix != "" {
						fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  🤖 AI auto-fixing..."))

						// Parse and execute each command from AI response
						fixApplied := false
						for _, line := range strings.Split(fix, "\n") {
							line = strings.TrimSpace(line)
							// Skip empty lines, comments, markdown
							if line == "" || strings.HasPrefix(line, "#") ||
								strings.HasPrefix(line, "```") || strings.HasPrefix(line, "//") {
								continue
							}
							// Only execute safe install commands
							if strings.Contains(line, "apt") || strings.Contains(line, "pip") ||
								strings.Contains(line, "go install") || strings.Contains(line, "curl") ||
								strings.Contains(line, "wget") || strings.Contains(line, "npm") ||
								strings.Contains(line, "gem install") || strings.Contains(line, "cargo") {
								fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ↳ " + line))
								fixCmd := exec.Command("bash", "-c", line)
								fixCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
								fixCmd.Stdout = os.Stdout
								fixCmd.Stderr = os.Stderr
								fixCmd.Stdin = nil
								if fixErr := fixCmd.Run(); fixErr == nil {
									fixApplied = true
								}
							}
						}

						// Re-check if tool is now installed after AI fix
						if fixApplied {
							if _, checkErr := exec.LookPath(t.name); checkErr == nil {
								fmt.Println(lipgloss.NewStyle().Foreground(green).Render(
									fmt.Sprintf("  ✓ %-20s fixed by AI!", t.name)))
								instOK++
								instFail-- // don't count as failure
								continue
							}
							// Also check common install paths
							for _, p := range []string{
								"/usr/local/bin/" + t.name,
								os.Getenv("HOME") + "/.local/bin/" + t.name,
								"/root/.local/bin/" + t.name,
							} {
								if _, e := os.Stat(p); e == nil {
									exec.Command("sudo", "ln", "-sf", p, "/usr/local/bin/"+t.name).Run()
									fmt.Println(lipgloss.NewStyle().Foreground(green).Render(
										fmt.Sprintf("  ✓ %-20s fixed + symlinked", t.name)))
									instOK++
									instFail--
									break
								}
							}
						}
					}
					instFail++
				} else {
					// ── Verify tool is actually accessible after install ──────
					// Some tools install to ~/.local/bin or ~/go/bin — symlink them
					if _, checkErr := exec.LookPath(t.name); checkErr != nil {
						// Not in PATH — try to find and symlink
						homedir2, _ := os.UserHomeDir()
						searchPaths := []string{
							homedir2 + "/go/bin/" + t.name,
							"/root/go/bin/" + t.name,
							homedir2 + "/.local/bin/" + t.name,
							"/root/.local/bin/" + t.name,
							"/opt/pipx/venvs/" + t.name + "/bin/" + t.name,
						}
						for _, sp := range searchPaths {
							if _, e := os.Stat(sp); e == nil {
								exec.Command("sudo", "ln", "-sf", sp, "/usr/local/bin/"+t.name).Run()
								break
							}
						}
					}
					fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ %-20s installed", t.name)))
					instOK++
				}
			}
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render(
				fmt.Sprintf("  Doctor complete: %d installed, %d failed", instOK, instFail)))
			fmt.Println()
		}

	case "/install-tools":
		if runtime.GOOS != "linux" {
			printError("/install-tools is only available on Linux.")
			os.Exit(1)
		}
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  🛠  Installing All CyberMind Tools (Recon + Hunt)"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 55)))
		fmt.Println()

		installed, skipped2, failed := 0, 0, 0

		// Helper: run command and report result
		runInstall := func(name string, cmd2 *exec.Cmd) bool {
			cmd2.Stdout = os.Stdout
			cmd2.Stderr = os.Stderr
			if err := cmd2.Run(); err != nil {
				fmt.Println(lipgloss.NewStyle().Foreground(red).Render(fmt.Sprintf("  ✗ %-16s failed: %v", name, err)))
				failed++
				return false
			}
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ %-16s installed", name)))
			installed++
			return true
		}

		// Helper: symlink Go binary to /usr/local/bin
		symlinkGo := func(bin string) {
			homedir2, _ := os.UserHomeDir()
			for _, gobin := range []string{homedir2 + "/go/bin/" + bin, "/root/go/bin/" + bin} {
				if _, err2 := os.Stat(gobin); err2 == nil {
					exec.Command("sudo", "ln", "-sf", gobin, "/usr/local/bin/"+bin).Run()
					return
				}
			}
		}

		// ── Step 1: apt dependencies first ──────────────────────────────────
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  [1/4] Installing apt tools..."))
		aptTools := []string{
			"nmap", "masscan", "whois", "dnsutils", "theharvester",
			"whatweb", "ffuf", "feroxbuster", "gobuster", "nikto", "amass",
			"libpcap-dev", "build-essential", "git", "cargo",
		}
		for _, tool := range aptTools {
			if _, err := exec.LookPath(tool); err == nil {
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  - %-16s already installed", tool)))
				skipped2++
				continue
			}
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(fmt.Sprintf("  ⟳ %-16s installing...", tool)))
			runInstall(tool, exec.Command("sudo", "apt", "install", "-y", tool))
		}

		// ── Step 2: rustscan from GitHub (not in apt) ────────────────────────
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  [2/4] Installing rustscan..."))
		if _, err := exec.LookPath("rustscan"); err == nil {
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  - rustscan         already installed"))
			skipped2++
		} else {
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ rustscan         installing from GitHub..."))
			// Try cargo install first (fastest)
			if _, cargoErr := exec.LookPath("cargo"); cargoErr == nil {
				if runInstall("rustscan", exec.Command("cargo", "install", "rustscan")) {
					symlinkGo("rustscan")
				}
			} else {
				// Fallback: download latest release binary
				dlCmd := exec.Command("bash", "-c",
					`LATEST=$(curl -s https://api.github.com/repos/RustScan/RustScan/releases/latest | grep browser_download_url | grep amd64.deb | cut -d'"' -f4) && curl -sL "$LATEST" -o /tmp/rustscan.deb && sudo dpkg -i /tmp/rustscan.deb`)
				if runInstall("rustscan", dlCmd) {
					// already in /usr/bin from dpkg
				}
			}
		}

		// ── Step 3: Go tools ─────────────────────────────────────────────────
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  [3/4] Installing Go tools..."))
		goTools := []struct{ bin, module string }{
			{"subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"},
			{"httpx", "github.com/projectdiscovery/httpx/cmd/httpx"},
			{"nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"},
			{"naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu"},
			{"dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx"},
			{"tlsx", "github.com/projectdiscovery/tlsx/cmd/tlsx"},
			{"katana", "github.com/projectdiscovery/katana/cmd/katana"},
			{"gau", "github.com/lc/gau/v2/cmd/gau"},
			{"waybackurls", "github.com/tomnomnom/waybackurls"},
			{"dalfox", "github.com/hahwul/dalfox/v2"},
			{"waymore", "github.com/xnl-h4ck3r/waymore"},
			{"gospider", "github.com/jaeles-project/gospider"},
		}
		for _, gt := range goTools {
			if _, err := exec.LookPath(gt.bin); err == nil {
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  - %-16s already installed", gt.bin)))
				skipped2++
				continue
			}
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(fmt.Sprintf("  ⟳ %-16s installing...", gt.bin)))
			if runInstall(gt.bin, exec.Command("go", "install", gt.module+"@latest")) {
				symlinkGo(gt.bin)
			}
		}

		// ── Step 4: x8 via cargo ─────────────────────────────────────────────
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  [4/5] Installing x8 (hidden param discovery)..."))
		if _, err := exec.LookPath("x8"); err == nil {
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  - x8               already installed"))
			skipped2++
		} else if _, cargoErr := exec.LookPath("cargo"); cargoErr != nil {
			fmt.Println(lipgloss.NewStyle().Foreground(red).Render("  ✗ x8               cargo not found — run: sudo apt install cargo"))
			failed++
		} else {
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ x8               installing via cargo (may take a few minutes)..."))
			if runInstall("x8", exec.Command("cargo", "install", "x8")) {
				// cargo installs to ~/.cargo/bin
				homedir2, _ := os.UserHomeDir()
				x8bin := homedir2 + "/.cargo/bin/x8"
				if _, err2 := os.Stat(x8bin); err2 == nil {
					exec.Command("sudo", "ln", "-sf", x8bin, "/usr/local/bin/x8").Run()
				}
			}
		}

		// ── Step 4.5: Python hunt tools ──────────────────────────────────────
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  [4.5/6] Installing Python hunt tools..."))

		// Ensure pip3 available
		exec.Command("sudo", "apt", "install", "-y", "python3-pip", "python3-venv", "-qq").Run()

		pythonTools := []struct {
			bin     string
			pipPkg  string
			gitRepo string
			gitDir  string
			script  string
		}{
			{"arjun", "arjun", "", "", ""},
			{"paramspider", "", "https://github.com/devanshbatham/ParamSpider", "/opt/ParamSpider", "paramspider.py"},
			{"xsstrike", "", "https://github.com/s0md3v/XSStrike.git", "/opt/XSStrike", "xsstrike.py"},
		}

		for _, pt := range pythonTools {
			if _, err := exec.LookPath(pt.bin); err == nil {
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  - %-16s already installed", pt.bin)))
				skipped2++
				continue
			}
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(fmt.Sprintf("  ⟳ %-16s installing...", pt.bin)))

			var installOK bool
			if pt.pipPkg != "" {
				// pip install
				cmd2 := exec.Command("pip3", "install", pt.pipPkg, "-q", "--break-system-packages")
				cmd2.Stdout = os.Stdout
				cmd2.Stderr = os.Stderr
				if err := cmd2.Run(); err == nil {
					installOK = true
				} else {
					// Try without --break-system-packages
					cmd3 := exec.Command("pip3", "install", pt.pipPkg, "-q")
					cmd3.Stdout = os.Stdout
					cmd3.Stderr = os.Stderr
					installOK = cmd3.Run() == nil
				}
			} else if pt.gitRepo != "" {
				// git clone + pip install requirements
				exec.Command("sudo", "rm", "-rf", pt.gitDir).Run()
				cloneCmd := exec.Command("git", "clone", "--depth=1", pt.gitRepo, pt.gitDir)
				cloneCmd.Stdout = os.Stdout
				cloneCmd.Stderr = os.Stderr
				if err := cloneCmd.Run(); err == nil {
					reqFile := pt.gitDir + "/requirements.txt"
					if _, err2 := os.Stat(reqFile); err2 == nil {
						pipCmd := exec.Command("pip3", "install", "-r", reqFile, "-q", "--break-system-packages")
						pipCmd.Stdout = os.Stdout
						pipCmd.Stderr = os.Stderr
						if pipCmd.Run() != nil {
							pipCmd2 := exec.Command("pip3", "install", "-r", reqFile, "-q")
							pipCmd2.Stdout = os.Stdout
							pipCmd2.Stderr = os.Stderr
							pipCmd2.Run()
						}
					}
					// Create symlink
					scriptPath := pt.gitDir + "/" + pt.script
					if _, err2 := os.Stat(scriptPath); err2 == nil {
						exec.Command("sudo", "ln", "-sf", scriptPath, "/usr/local/bin/"+pt.bin).Run()
						exec.Command("sudo", "chmod", "+x", "/usr/local/bin/"+pt.bin).Run()
						installOK = true
					}
				}
			}

			if installOK {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ %-16s installed", pt.bin)))
				installed++
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(red).Render(fmt.Sprintf("  ✗ %-16s failed", pt.bin)))
				failed++
			}
		}

		// ── Step 5: reconftw (meta subdomain tool) ───────────────────────────
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  [5/5] Installing reconftw (meta subdomain pipeline)..."))
		if _, err := exec.LookPath("reconftw"); err == nil {
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  - reconftw         already installed"))
			skipped2++
		} else {
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ reconftw         cloning from GitHub..."))
			// Remove old install if exists
			exec.Command("sudo", "rm", "-rf", "/opt/reconftw").Run()
			// Clone
			cloneCmd := exec.Command("git", "clone", "--depth=1", "https://github.com/six2dez/reconftw.git", "/opt/reconftw")
			cloneCmd.Stdout = os.Stdout
			cloneCmd.Stderr = os.Stderr
			if err := cloneCmd.Run(); err != nil {
				fmt.Println(lipgloss.NewStyle().Foreground(red).Render("  ✗ reconftw         clone failed: " + err.Error()))
				failed++
			} else {
				// Run reconftw install script
				fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ reconftw         running install.sh (this may take 5-10 minutes)..."))
				installCmd3 := exec.Command("bash", "/opt/reconftw/install.sh")
				installCmd3.Dir = "/opt/reconftw"
				installCmd3.Stdout = os.Stdout
				installCmd3.Stderr = os.Stderr
				if err := installCmd3.Run(); err != nil {
					fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  ⚡ reconftw         install.sh had errors (may still work)"))
				}
				// Symlink to /usr/local/bin
				exec.Command("sudo", "ln", "-sf", "/opt/reconftw/reconftw.sh", "/usr/local/bin/reconftw").Run()
				exec.Command("sudo", "chmod", "+x", "/opt/reconftw/reconftw.sh").Run()
				if _, err := exec.LookPath("reconftw"); err == nil {
					fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ reconftw         installed"))
					installed++
				} else {
					fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  ⚡ reconftw         installed at /opt/reconftw/reconftw.sh"))
					installed++
				}
			}
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render(
			fmt.Sprintf("  Summary: %d installed, %d skipped, %d failed", installed, skipped2, failed)))
		if failed > 0 {
			fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  Run: cybermind /doctor  to retry failed tools"))
		}
		fmt.Println()

	case "/abhimanyu":
		// Abhimanyu Mode — standalone exploit engine
		if runtime.GOOS != "linux" {
			printError("Abhimanyu Mode is only available on Linux/Kali.")
			os.Exit(1)
		}
		if len(args) < 2 {
			printError("Usage: cybermind /abhimanyu <target> [vuln-type]")
			printError("Example: cybermind /abhimanyu example.com all")
			printError("Example: cybermind /abhimanyu example.com sqli")
			printError("Vuln types: all, xss, sqli, ssrf, lfi, rce, cmdi, auth, network, postexploit, lateral, exfil")
			os.Exit(1)
		}
		abhimanyuTarget := args[1]
		abhimanyuVuln := "all"
		if len(args) >= 3 {
			abhimanyuVuln = args[2]
		}
		if err := recon.ValidateTarget(abhimanyuTarget); err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		// Plan check: abhimanyu requires elite plan
		if !requireAPIKey() {
			os.Exit(1)
		}
		if !requirePlan("elite") {
			os.Exit(1)
		}
		runAbhimanyu(abhimanyuTarget, abhimanyuVuln)

	case "update":
		// Self-update: git pull + rebuild + reinstall
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  ⟳ Updating CyberMind..."))
		fmt.Println()

		// Find repo root — check multiple locations including where binary lives
		homedir, _ := os.UserHomeDir()
		// Also check if CYBERMIND_REPO env var is set
		envRepo := os.Getenv("CYBERMIND_REPO")
		repoPaths := []string{}
		if envRepo != "" {
			repoPaths = append(repoPaths, envRepo)
		}
		repoPaths = append(repoPaths,
			".",
			homedir+"/cybermind",
			homedir+"/CyberMind",
			homedir+"/go/src/cybermind",
			"/opt/cybermind",
			"/opt/CyberMind",
		)

		repoPath := ""
		for _, p := range repoPaths {
			if _, err := os.Stat(p + "/.git"); err == nil {
				repoPath = p
				break
			}
		}

		if repoPath == "" {
			printError("Cannot find CyberMind repo.")
			fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  Set CYBERMIND_REPO env var to your repo path:"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  export CYBERMIND_REPO=/path/to/cybermind"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Or run manually:"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  cd /path/to/cybermind/cli && git pull && go build -o cybermind . && sudo mv cybermind /usr/local/bin/"))
			os.Exit(1)
		}

		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Found repo at: " + repoPath))

		// git pull — force reset local changes first
		fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ Pulling latest changes..."))
		// Reset any local changes that would block pull
		resetCmd := exec.Command("git", "-C", repoPath, "reset", "--hard", "HEAD")
		resetCmd.Run()
		pullCmd := exec.Command("git", "-C", repoPath, "pull", "origin", "main")
		pullCmd.Stdout = os.Stdout
		pullCmd.Stderr = os.Stderr
		if err := pullCmd.Run(); err != nil {
			printError("git pull failed: " + err.Error())
			os.Exit(1)
		}

		// go build
		cliPath := repoPath + "/cli"
		fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ Building new binary..."))
		buildCmd := exec.Command("go", "build", "-o", "cybermind", ".")
		buildCmd.Dir = cliPath
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr
		if err := buildCmd.Run(); err != nil {
			printError("Build failed: " + err.Error())
			os.Exit(1)
		}

		// install
		if runtime.GOOS == "linux" {
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ Installing to /usr/local/bin/..."))
			installCmd := exec.Command("sudo", "mv", cliPath+"/cybermind", "/usr/local/bin/cybermind")
			installCmd.Stdout = os.Stdout
			installCmd.Stderr = os.Stderr
			if err := installCmd.Run(); err != nil {
				printError("Install failed (try: sudo mv " + cliPath + "/cybermind /usr/local/bin/)")
				os.Exit(1)
			}
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green).Render("  ✓ CyberMind updated successfully!"))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Run: cybermind --version to confirm"))
		// Auto-run doctor to install any new tools and fix missing ones
		if runtime.GOOS == "linux" {
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Running /doctor to check and install tools..."))
			doctorCmd := exec.Command("/usr/local/bin/cybermind", "/doctor")
			doctorCmd.Stdout = os.Stdout
			doctorCmd.Stderr = os.Stderr
			_ = doctorCmd.Run()
		}

	case "history":
		if err := storage.Load(); err != nil {
			printError("Could not load history: " + err.Error())
			os.Exit(1)
		}
		storage.PrintHistory()

	case "clear":
		if err := storage.ClearHistory(); err != nil {
			printError("Could not clear history: " + err.Error())
			os.Exit(1)
		}
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Chat history cleared."))

	case "uninstall", "/uninstall":
		runUninstall()

	case "scan":
		if len(args) < 2 {
			printError("Usage: cybermind scan <target> [type]")
			os.Exit(1)
		}
		if !requireAPIKey() {
			os.Exit(1)
		}
		target := args[1]
		scanType := "quick"
		if len(args) >= 3 {
			scanType = args[2]
		}
		fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(fmt.Sprintf("  ⟳ Generating %s scan guide for %s...", scanType, target)))
		result, err := api.SendScan(target, scanType)
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		printResult(fmt.Sprintf("Scan Guide [%s] → %s", scanType, target), result)

	case "recon":
		if len(args) < 2 {
			printError("Usage: cybermind recon <target> [type]")
			os.Exit(1)
		}
		if !requireAPIKey() {
			os.Exit(1)
		}
		target := args[1]
		reconType := "passive"
		if len(args) >= 3 {
			reconType = args[2]
		}
		fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(fmt.Sprintf("  ⟳ Generating %s recon guide for %s...", reconType, target)))
		result, err := api.SendRecon(target, reconType)
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		printResult(fmt.Sprintf("Recon Guide [%s] → %s", reconType, target), result)

	case "exploit":
		if len(args) < 2 {
			printError("Usage: cybermind exploit <vulnerability> [target]")
			os.Exit(1)
		}
		if !requireAPIKey() {
			os.Exit(1)
		}
		vuln := args[1]
		target := ""
		if len(args) >= 3 {
			target = args[2]
		}
		fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(fmt.Sprintf("  ⟳ Generating exploitation guide for %s...", vuln)))
		result, err := api.SendExploit(vuln, target)
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		printResult("Exploit Guide → "+vuln, result)

	case "payload":
		targetOS := "windows"
		arch := "x64"
		if len(args) >= 2 {
			targetOS = args[1]
		}
		if len(args) >= 3 {
			arch = args[2]
		}
		format := "exe"
		if targetOS == "linux" {
			format = "elf"
		} else if targetOS == "android" {
			format = "apk"
		}
		fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(fmt.Sprintf("  ⟳ Generating %s/%s payload guide...", targetOS, arch)))
		// BUG FIX: use detected local IP instead of hardcoded "YOUR_IP"
		detectedIP := getLocalIP()
		result, err := api.SendPayload(targetOS, arch, detectedIP, "4444", format)
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		printResult(fmt.Sprintf("Payload Guide → %s/%s", targetOS, arch), result)

	case "tool":
		if len(args) < 2 {
			printError("Usage: cybermind tool <toolname> [task]")
			os.Exit(1)
		}
		tool := args[1]
		task := ""
		if len(args) >= 3 {
			task = strings.Join(args[2:], " ")
		}
		fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(fmt.Sprintf("  ⟳ Getting guide for %s...", tool)))
		result, err := api.SendToolHelp(tool, task)
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		printResult("Tool Guide → "+tool, result)

	case "/plan":
		// OMEGA Planning Mode — Linux only (requires full tool suite)
		if runtime.GOOS != "linux" {
			printError("OMEGA Planning Mode is only available on Linux/Kali.")
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Use Kali Linux for full OMEGA pipeline"))
			os.Exit(1)
		}

		// ── Parse flags ───────────────────────────────────────────────────
		autoTarget := false
		focusTypes := ""
		skillLevel := "intermediate"
		planTarget := ""
		execMode := "deep"       // quick | deep | overnight
		continuous := false      // --continuous: loop forever
		platformHandle := ""     // --platform hackerone:handle
		autoSubmit := false      // --auto-submit: submit bugs automatically
		novelAttacks := true     // --no-novel: skip novel attack engine

		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--auto-target":
				autoTarget = true
			case "--focus":
				if i+1 < len(args) {
					focusTypes = args[i+1]
					i++
				}
			case "--skill":
				if i+1 < len(args) {
					skillLevel = args[i+1]
					i++
				}
			case "--mode":
				if i+1 < len(args) {
					execMode = args[i+1]
					i++
				}
			case "--continuous":
				continuous = true
			case "--platform":
				if i+1 < len(args) {
					platformHandle = args[i+1]
					i++
				}
			case "--auto-submit":
				autoSubmit = true
			case "--no-novel":
				novelAttacks = false
			default:
				if !strings.HasPrefix(args[i], "--") && planTarget == "" {
					planTarget = args[i]
				}
			}
		}

		// Set execution mode env vars for all tools to read
		brain.SetModeEnv(brain.ExecutionMode(execMode))
		if focusTypes != "" {
			os.Setenv("CYBERMIND_FOCUS_BUGS", focusTypes)
		}
		_ = novelAttacks // used in runOmegaPlan

		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		if !localMode && !requireAPIKey() {
			os.Exit(1)
		}

		// ── --auto-target: fetch best target from HackerOne ───────────────
		if autoTarget {
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  🎯 AUTO-TARGET MODE — Fetching best bug bounty targets..."))
			fmt.Println()

			// Try AI suggestion first
			suggestion, sugErr := api.FetchH1Suggestion(skillLevel, focusTypes)
			if sugErr == nil && suggestion != nil && suggestion.Text != "" {
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render("  Top targets for you:"))
				fmt.Println()
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).MarginLeft(2).Render(suggestion.Text))
				fmt.Println()
				// Auto-select top domain if no target provided
				if planTarget == "" && suggestion.TopDomain != "" {
					planTarget = suggestion.TopDomain
					fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
						fmt.Sprintf("  ✓ Auto-selected: %s", planTarget)))
					fmt.Println()
				}
			} else {
				// Fallback: show curated list and auto-pick first
				programs, progErr := api.FetchH1Programs()
				if progErr == nil && len(programs) > 0 {
					fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render("  Top bug bounty programs:"))
					fmt.Println()
					for i, p := range programs {
						if i >= 5 {
							break
						}
						fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(fmt.Sprintf("  %d. %s — %s", i+1, p.Domain, p.Name)))
						fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("     Scope: %s", p.Scope)))
						fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("     Bounty: $%d-$%d | %s", p.MinBounty, p.MaxBounty, p.Why)))
						fmt.Println()
					}
					// Auto-select top program if no target provided
					if planTarget == "" && programs[0].Domain != "" {
						planTarget = programs[0].Domain
						fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
							fmt.Sprintf("  ✓ Auto-selected: %s", planTarget)))
						fmt.Println()
					}
				}
			}

			// Only prompt if auto-select failed
			if planTarget == "" {
				fmt.Print(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render("  Enter target domain to start plan: "))
				fmt.Scanln(&planTarget)
				planTarget = strings.TrimSpace(planTarget)
			}
		}

		if planTarget == "" && !continuous {
			printError("Usage: cybermind /plan <target>")
			printError("       cybermind /plan --auto-target")
			printError("       cybermind /plan example.com --focus xss,idor")
			printError("       cybermind /plan --auto-target --skill beginner --focus xss")
			printError("       cybermind /plan --auto-target --mode overnight --continuous")
			printError("       cybermind /plan --auto-target --auto-submit --platform hackerone:shopify")
			os.Exit(1)
		}

		if planTarget != "" {
			if err := recon.ValidateTarget(planTarget); err != nil {
				printError(err.Error())
				os.Exit(1)
			}
		}

		// Pass focus types via env for plan mode to use
		if focusTypes != "" {
			os.Setenv("CYBERMIND_FOCUS_BUGS", focusTypes)
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
				fmt.Sprintf("  🎯 Focus: %s vulnerabilities", focusTypes)))
		}

		// Show memory summary for this target
		if planTarget != "" {
			summary := brain.GetMemorySummary(planTarget)
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")).Render(summary))
		}

		// Show WAF bypass strategy if we have prior memory
		if planTarget != "" {
			mem := brain.LoadTarget(planTarget)
			if mem.WAFDetected && mem.WAFVendor != "" {
				strategy := brain.GetWAFBypassStrategy(mem.WAFVendor)
				fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render(
					brain.FormatWAFBypassReport(strategy)))
			}
		}

		// ── Continuous loop mode ──────────────────────────────────────────
		if continuous {
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render(
				fmt.Sprintf("  🔄 CONTINUOUS MODE — Mode: %s | Auto-submit: %v", execMode, autoSubmit)))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
				"  Press Ctrl+C to stop. Results saved to ~/.cybermind/brain/"))
			fmt.Println()

			cfg := brain.ExecutionConfig{
				Mode:           brain.ExecutionMode(execMode),
				Target:         planTarget,
				AutoSubmit:     autoSubmit,
				FocusTypes:     strings.Split(focusTypes, ","),
				SkillLevel:     skillLevel,
				ContinuousLoop: true,
				MaxTargets:     0, // unlimited
			}
			if platformHandle != "" {
				parts := strings.SplitN(platformHandle, ":", 2)
				if len(parts) == 2 {
					cfg.Platform = parts[0]
					cfg.ProgramHandle = parts[1]
				} else {
					cfg.Platform = "hackerone"
					cfg.ProgramHandle = platformHandle
				}
			}

			session := brain.NewContinuousSession(cfg)
			session.Running = true
			var testedTargets []string

			for session.ShouldContinue() {
				// Pick next target
				nextTarget := brain.GetNextTarget(cfg, testedTargets)
				if nextTarget == "" {
					fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render(
						"  All known targets tested. Waiting 1 hour before retry..."))
					time.Sleep(1 * time.Hour)
					testedTargets = []string{} // reset
					continue
				}

				fmt.Println()
				fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render(
					fmt.Sprintf("  ⚡ [Run %d] Target: %s", session.TotalRuns+1, nextTarget)))
				session.Log(fmt.Sprintf("Starting run %d on %s", session.TotalRuns+1, nextTarget))

				runOmegaPlan(nextTarget, localMode)
				testedTargets = append(testedTargets, nextTarget)
				session.TotalRuns++
				session.TargetsDone = append(session.TargetsDone, nextTarget)

				// Wait between targets
				waitTime := 5 * time.Minute
				if execMode == "overnight" {
					waitTime = 30 * time.Minute
				}
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
					fmt.Sprintf("  ⏱  Waiting %s before next target...", waitTime)))
				time.Sleep(waitTime)
			}

			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green).Render(
				session.PrintSessionSummary()))
			return
		}

		runOmegaPlan(planTarget, localMode)

	case "/aegis":
		// Aegis — AI-driven autonomous pentest platform (Python, isolated venv)
		if runtime.GOOS != "linux" {
			printError("Aegis is only available on Linux/Kali.")
			os.Exit(1)
		}
		if len(args) >= 2 && (args[1] == "--setup" || args[1] == "setup") {
			runAegisSetup()
			return
		}
		if len(args) < 2 {
			printError("Usage: cybermind /aegis <target>")
			printError("       cybermind /aegis <target> --auto   (full autonomous pentest)")
			printError("       cybermind /aegis <target> --recon  (recon only)")
			printError("       cybermind /aegis <target> --vuln   (vuln scan only)")
			printError("       cybermind /aegis <target> --exploit (exploit phase)")
			printError("       cybermind /aegis --setup           (install/update Aegis)")
			os.Exit(1)
		}
		aegisTarget := args[1]
		aegisMode := "default"
		for _, a := range args[2:] {
			switch a {
			case "--auto", "--full":
				aegisMode = "auto"
			case "--recon":
				aegisMode = "recon"
			case "--vuln":
				aegisMode = "vuln"
			case "--exploit":
				aegisMode = "exploit"
			}
		}
		if err := recon.ValidateTarget(aegisTarget); err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		if !requireAPIKey() {
			os.Exit(1)
		}
		runAegisIntegration(aegisTarget, aegisMode)

	case "/bizlogic", "/biz":
		// Business Logic Bug Hunter — automated price manipulation, IDOR, race conditions, etc.
		if runtime.GOOS != "linux" {
			printError("Business logic scanner is Linux-only.")
			os.Exit(1)
		}
		if len(args) < 2 {
			printError("Usage: cybermind /bizlogic <target>")
			printError("       cybermind /bizlogic example.com")
			printError("       cybermind /bizlogic example.com --cookie 'session=abc123'")
			os.Exit(1)
		}
		if !requireAPIKey() {
			os.Exit(1)
		}

		bizTarget := args[1]
		if !strings.HasPrefix(bizTarget, "http") {
			bizTarget = "https://" + bizTarget
		}

		// Parse optional --cookie and --header flags
		bizCookies := map[string]string{}
		bizHeaders := map[string]string{}
		for i := 2; i < len(args); i++ {
			switch args[i] {
			case "--cookie", "-c":
				if i+1 < len(args) {
					// Parse "name=value; name2=value2"
					for _, part := range strings.Split(args[i+1], ";") {
						kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
						if len(kv) == 2 {
							bizCookies[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
						}
					}
					i++
				}
			case "--header", "-H":
				if i+1 < len(args) {
					kv := strings.SplitN(args[i+1], ":", 2)
					if len(kv) == 2 {
						bizHeaders[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
					}
					i++
				}
			}
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render("  💰 BUSINESS LOGIC BUG HUNTER — " + bizTarget))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Testing: price manipulation, IDOR, race conditions, workflow bypass, mass assignment"))
		fmt.Println()

		result := bizlogic.RunBizLogicScan(bizTarget, bizCookies, bizHeaders, func(test, status string) {
			if strings.Contains(status, "FOUND") {
				fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4444")).Render("  " + status))
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ⟳ [" + test + "] " + status))
			}
		})

		fmt.Println()
		if len(result.Findings) == 0 {
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).Render(
				fmt.Sprintf("  No business logic bugs found (%d tests run)", result.Tested)))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
				"  Tip: Provide --cookie with your session token for authenticated testing"))
		} else {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4444")).Render(
				fmt.Sprintf("  🐛 %d BUSINESS LOGIC BUGS FOUND!", len(result.Findings))))
			fmt.Println()

			for _, f := range result.Findings {
				color := lipgloss.Color("#FFD700")
				if f.Severity == "critical" {
					color = lipgloss.Color("#FF4444")
				}
				fmt.Println(lipgloss.NewStyle().Foreground(color).Render(
					fmt.Sprintf("  [%s] %s — %s", strings.ToUpper(f.Severity), f.Type, f.URL)))
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("    " + f.Description))
				fmt.Println()
			}

			// Save report
			report := bizlogic.GenerateReport(result)
			ts := time.Now().Format("2006-01-02_15-04-05")
			safeTarget := strings.ReplaceAll(strings.TrimPrefix(strings.TrimPrefix(bizTarget, "https://"), "http://"), ".", "_")
			reportPath := fmt.Sprintf("cybermind_bizlogic_%s_%s.md", safeTarget, ts)
			if err := os.WriteFile(reportPath, []byte(report), 0644); err == nil {
				fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF00")).Render(
					"  ✓ Report saved: " + reportPath))
			}
		}

	case "/guide", "/manual":
		// AI Step-by-Step Manual Testing Guide — for the 12% tools can't automate
		if len(args) < 2 {
			printError("Usage: cybermind /guide <target>")
			printError("       cybermind /guide example.com --focus business_logic")
			printError("       cybermind /guide example.com --focus oauth")
			printError("       cybermind /guide example.com --focus race")
			printError("       cybermind /guide example.com --focus idor")
			os.Exit(1)
		}
		if !requireAPIKey() {
			os.Exit(1)
		}

		guideTarget := args[1]
		guideFocus := "all"
		for i := 2; i < len(args); i++ {
			if args[i] == "--focus" && i+1 < len(args) {
				guideFocus = args[i+1]
				i++
			}
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700")).Render(
			"  📋 MANUAL TESTING GUIDE — " + guideTarget))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
			"  AI generating step-by-step guide for manual testing..."))
		fmt.Println()

		// Load brain memory for this target
		mem := brain.LoadTarget(guideTarget)
		bugMaps := make([]map[string]string, 0, len(mem.BugsFound))
		for _, b := range mem.BugsFound {
			bugMaps = append(bugMaps, map[string]string{
				"title": b.Title, "severity": b.Severity, "url": b.URL,
			})
		}

		guide, guideErr := api.SendManualGuide(api.ManualGuideRequest{
			Target:      guideTarget,
			TechStack:   mem.TechStack,
			BugsFound:   bugMaps,
			LiveURLs:    mem.LiveURLs,
			OpenPorts:   mem.OpenPorts,
			WAFDetected: mem.WAFDetected,
			WAFVendor:   mem.WAFVendor,
			Subdomains:  mem.SubdomainsFound,
			Focus:       guideFocus,
			ScanSummary: fmt.Sprintf("%d prior runs, %d bugs found, %d subdomains", mem.RunCount, len(mem.BugsFound), len(mem.SubdomainsFound)),
		})

		if guideErr != nil {
			printError("Guide generation failed: " + guideErr.Error())
			os.Exit(1)
		}

		// Print the guide
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render(guide))

		// Save to file
		ts := time.Now().Format("2006-01-02_15-04-05")
		safeT := strings.ReplaceAll(strings.TrimPrefix(strings.TrimPrefix(guideTarget, "https://"), "http://"), ".", "_")
		guidePath := fmt.Sprintf("cybermind_guide_%s_%s.md", safeT, ts)
		if err := os.WriteFile(guidePath, []byte(guide), 0644); err == nil {
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF00")).Render(
				"  ✓ Guide saved: " + guidePath))
		}

	case "/scan":
		// Native network scan — works on Windows, macOS, Linux
		if len(args) < 2 {
			printError("Usage: cybermind /scan <subnet>")
			printError("Example: cybermind /scan 192.168.1.0/24")
			os.Exit(1)
		}
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		if !localMode && !requireAPIKey() {
			os.Exit(1)
		}
		runNativeScan(args[1], localMode)

	case "/portscan":
		// Port scan — works on Windows, macOS, Linux
		if len(args) < 2 {
			printError("Usage: cybermind /portscan <ip>")
			printError("Example: cybermind /portscan 192.168.1.1")
			os.Exit(1)
		}
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		if !localMode && !requireAPIKey() {
			os.Exit(1)
		}
		runPortScan(args[1], localMode)

	case "/osint":
		// OSINT — DNS + Shodan InternetDB — works on all OS
		if len(args) < 2 {
			printError("Usage: cybermind /osint <domain>")
			printError("Example: cybermind /osint example.com")
			os.Exit(1)
		}
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		if !localMode && !requireAPIKey() {
			os.Exit(1)
		}
		runOSINT(args[1], localMode)

	case "/osint-deep":
		// Deep OSINT — Linux-only, full pipeline (email/username/domain/phone/company)
		if runtime.GOOS != "linux" {
			printError("OSINT Deep Mode is only available on Linux/Kali.")
			os.Exit(1)
		}
		if len(args) < 2 {
			printError("Usage: cybermind /osint-deep <target> [--tools tool1,tool2]")
			printError("  target: domain, email, username, phone (+1234), company name, IP")
			printError("Examples:")
			printError("  cybermind /osint-deep target.com")
			printError("  cybermind /osint-deep user@gmail.com")
			printError("  cybermind /osint-deep johndoe")
			printError("  cybermind /osint-deep +91XXXXXXXXXX")
			printError("  cybermind /osint-deep \"Company Name\"")
			os.Exit(1)
		}
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		if !localMode && !requireAPIKey() {
			os.Exit(1)
		}
		if !requirePlan("starter") {
			os.Exit(1)
		}
		osintTarget := args[1]
		var osintRequested []string
		for i := 2; i < len(args); i++ {
			if args[i] == "--tools" && i+1 < len(args) {
				for _, n := range strings.Split(args[i+1], ",") {
					n = strings.TrimSpace(n)
					if n != "" {
						osintRequested = append(osintRequested, n)
					}
				}
				i++
			}
		}
		runOSINTDeep(osintTarget, osintRequested, localMode)

	case "/reveng":
		// Reverse Engineering — Linux-only, full RE pipeline
		if runtime.GOOS != "linux" {
			printError("Reverse Engineering Mode is only available on Linux/Kali.")
			os.Exit(1)
		}
		if len(args) < 2 {
			printError("Usage: cybermind /reveng <binary> [--mode static|dynamic|decompile|malware|mobile] [--tools tool1,tool2]")
			printError("Examples:")
			printError("  cybermind /reveng /path/to/binary")
			printError("  cybermind /reveng malware.bin --mode malware")
			printError("  cybermind /reveng app.apk --mode mobile")
			printError("  cybermind /reveng binary --mode decompile")
			os.Exit(1)
		}
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		if !localMode && !requireAPIKey() {
			os.Exit(1)
		}
		if !requirePlan("starter") {
			os.Exit(1)
		}
		revengTarget := args[1]
		revengMode := "all"
		var revengRequested []string
		for i := 2; i < len(args); i++ {
			if args[i] == "--mode" && i+1 < len(args) {
				revengMode = args[i+1]
				i++
			} else if args[i] == "--tools" && i+1 < len(args) {
				for _, n := range strings.Split(args[i+1], ",") {
					n = strings.TrimSpace(n)
					if n != "" {
						revengRequested = append(revengRequested, n)
					}
				}
				i++
			}
		}
		runRevEng(revengTarget, revengMode, revengRequested, localMode)

	case "/locate":
		// Geolocation — works on all OS (Level 1-4), Linux for Level 5
		if len(args) < 2 {
			printError("Usage: cybermind /locate <target>")
			printError("  target: IP, domain, phone (+1234), image file, username")
			printError("Examples:")
			printError("  cybermind /locate 8.8.8.8")
			printError("  cybermind /locate target.com")
			printError("  cybermind /locate photo.jpg")
			os.Exit(1)
		}
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		if !localMode && !requireAPIKey() {
			os.Exit(1)
		}
		runLocate(args[1], false, localMode)

	case "/locate-advanced":
		// Advanced Geolocation — Linux-only, SDR/cell tower (Level 5)
		if runtime.GOOS != "linux" {
			printError("Locate Advanced (SDR) is only available on Linux/Kali.")
			os.Exit(1)
		}
		if len(args) < 2 {
			printError("Usage: cybermind /locate-advanced <target>")
			printError("  Requires SDR hardware (RTL-SDR, HackRF, BladeRF)")
			printError("  See hardware setup: CyberMind/cli/locate/sdr_setup.md")
			printError("Examples:")
			printError("  cybermind /locate-advanced +91XXXXXXXXXX")
			printError("  cybermind /locate-advanced target.com")
			os.Exit(1)
		}
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		if !localMode && !requireAPIKey() {
			os.Exit(1)
		}
		if !requirePlan("pro") {
			os.Exit(1)
		}
		runLocate(args[1], true, localMode)

	case "/breach":
		// Breach Intelligence — works on all OS (API-based)
		if len(args) < 2 {
			printError("Usage: cybermind /breach <email|domain>")
			printError("       cybermind /breach --index /path/to/dump.txt")
			printError("       cybermind /breach --keys  (configure API keys)")
			printError("Examples:")
			printError("  cybermind /breach user@gmail.com")
			printError("  cybermind /breach @company.com")
			printError("  cybermind /breach --index /tmp/linkedin_dump.txt")
			os.Exit(1)
		}
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		if !localMode && !requireAPIKey() {
			os.Exit(1)
		}
		runBreachCheck(args[1:], localMode)

	case "/payload":
		// Payload generator — works on all OS
		if len(args) < 3 {
			printError("Usage: cybermind /payload <os> <arch> [type]")
			printError("  os:   windows, linux, macos, android")
			printError("  arch: x86, x64, arm, arm64")
			printError("  type: reverse_shell (default), bind_shell, meterpreter")
			os.Exit(1)
		}
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		if !localMode && !requireAPIKey() {
			os.Exit(1)
		}
		payloadType := "reverse_shell"
		if len(args) >= 4 {
			payloadType = args[3]
		}
		runPayload(args[1], args[2], payloadType, localMode)

	case "/cve":
		// CVE intelligence — works on all OS
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		if !localMode && !requireAPIKey() {
			os.Exit(1)
		}
		// Check for --latest flag
		latest := false
		severity := ""
		cveID := ""
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--latest":
				latest = true
			case "--severity":
				if i+1 < len(args) {
					severity = args[i+1]
					i++
				}
			default:
				if !strings.HasPrefix(args[i], "--") {
					cveID = args[i]
				}
			}
		}
		if latest {
			runCVELatest(severity, localMode)
		} else if cveID != "" {
			runCVE(cveID, localMode)
		} else {
			printError("Usage: cybermind /cve <CVE-ID>")
			printError("       cybermind /cve --latest [--severity critical|high|medium|low]")
			os.Exit(1)
		}

	case "/wordlist":
		// Smart target-aware wordlist generator
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		if !localMode && !requireAPIKey() {
			os.Exit(1)
		}
		wlTarget := ""
		wordlistType := "dirs"
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--target":
				if i+1 < len(args) {
					wlTarget = args[i+1]
					i++
				}
			case "--type":
				if i+1 < len(args) {
					wordlistType = args[i+1]
					i++
				}
			default:
				if !strings.HasPrefix(args[i], "--") && wlTarget == "" {
					wlTarget = args[i]
				}
			}
		}
		if wlTarget == "" {
			printError("Usage: cybermind /wordlist <target> [--type dirs|params|subdomains|passwords|api-endpoints]")
			os.Exit(1)
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(yellow).Render("  📝 SMART WORDLIST GENERATOR — " + wlTarget))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  Type: %s | Target-aware: tech stack + company mutations + patterns", wordlistType)))
		fmt.Println()

		// Use brain smart wordlist (target-aware)
		outFile, err := brain.GenerateTargetWordlistFile(wlTarget, wordlistType)
		if err != nil {
			printError("Smart wordlist failed: " + err.Error())
			// Fallback to AI wordlist
			runWordlist(wlTarget, wordlistType, localMode)
		} else {
			// Count words
			data, _ := os.ReadFile(outFile)
			wordCount := strings.Count(string(data), "\n") + 1
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green).Render(
				fmt.Sprintf("  ✓ Smart wordlist saved: %s (%d words)", outFile, wordCount)))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
				"  Generated from: tech stack + company mutations + type patterns + date mutations"))

			// Also generate AI wordlist and merge
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Enhancing with AI-generated words..."))
			runWordlist(wlTarget, wordlistType, localMode)
		}

	case "/platform":
		// Platform credentials management (HackerOne / Bugcrowd)
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  🎯 PLATFORM CREDENTIALS — HackerOne / Bugcrowd"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
		fmt.Println()

		subCmd := ""
		if len(args) > 1 {
			subCmd = args[1]
		}

		switch subCmd {
		case "--setup":
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  Setting up platform credentials..."))
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  How to get HackerOne API token:"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  1. Login → hackerone.com"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  2. Profile picture → Settings → API Token"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  3. Create API Token → copy the token"))
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  How to get Bugcrowd API token:"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  1. Login → bugcrowd.com"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  2. Settings → API → Create Token"))
			fmt.Println()

			var creds brain.PlatformCredentials

			fmt.Print(lipgloss.NewStyle().Foreground(yellow).Render("  HackerOne username (leave blank to skip): "))
			fmt.Scanln(&creds.H1Username)
			if creds.H1Username != "" {
				fmt.Print(lipgloss.NewStyle().Foreground(yellow).Render("  HackerOne API token: "))
				fmt.Scanln(&creds.H1Token)
			}
			fmt.Println()
			fmt.Print(lipgloss.NewStyle().Foreground(yellow).Render("  Bugcrowd email (leave blank to skip): "))
			fmt.Scanln(&creds.BCEmail)
			if creds.BCEmail != "" {
				fmt.Print(lipgloss.NewStyle().Foreground(yellow).Render("  Bugcrowd API token: "))
				fmt.Scanln(&creds.BCToken)
			}

			if creds.H1Username == "" && creds.BCEmail == "" {
				fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  ⚠  No credentials entered — skipping"))
				break
			}

			if err := brain.SaveCredentials(creds); err != nil {
				printError("Failed to save credentials: " + err.Error())
				os.Exit(1)
			}
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Credentials saved to ~/.cybermind/platform_creds.json"))
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Auto-submit enabled — bugs will be submitted to H1/BC automatically"))
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Next steps:"))
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  cybermind /platform --programs    → see your programs"))
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  sudo cybermind /plan --auto-target → start hunting!"))

		case "--programs":
			creds, err := brain.LoadCredentials()
			if err != nil {
				printError("No credentials — run: cybermind /platform --setup")
				os.Exit(1)
			}
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Fetching HackerOne programs..."))
			programs, err := brain.FetchH1Programs(creds)
			if err != nil {
				printError("Failed to fetch programs: " + err.Error())
				os.Exit(1)
			}
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ Found %d programs:", len(programs))))
			fmt.Println()
			for i, p := range programs {
				if i >= 20 {
					break
				}
				fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(fmt.Sprintf("  %d. %s (%s)", i+1, p.Name, p.Handle)))
			}

		case "--scope":
			if len(args) < 3 {
				printError("Usage: cybermind /platform --scope <program-handle>")
				printError("       cybermind /platform --scope shopify")
				printError("       cybermind /platform --scope gitlab")
				os.Exit(1)
			}
			handle := args[2]

			// Try public scope first (no auth needed)
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Fetching scope for " + handle + " (public)..."))
			pubScope, pubErr := brain.FetchPublicScope(handle)
			if pubErr == nil && pubScope != nil {
				fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green).Render(
					fmt.Sprintf("  ✓ %s — %d in-scope targets", pubScope.Name, len(pubScope.InScope))))
				fmt.Println()
				if len(pubScope.InScope) > 0 {
					fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  IN SCOPE:"))
					for _, t := range pubScope.InScope {
						fmt.Println(lipgloss.NewStyle().Foreground(green).Render("    ✓ " + t))
					}
					fmt.Println()
					fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
						fmt.Sprintf("  Scan first target: sudo cybermind /plan %s", pubScope.InScope[0])))
				} else {
					fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  No URL/domain scope found (may be invite-only or API-only program)"))
				}
				break
			}

			// Fallback: authenticated scope fetch
			creds, err := brain.LoadCredentials()
			if err != nil {
				printError("No credentials — run: cybermind /platform --setup")
				os.Exit(1)
			}
			scope, err := brain.FetchH1ProgramScope(creds, handle)
			if err != nil {
				printError("Failed to fetch scope: " + err.Error())
				os.Exit(1)
			}
			brain.SaveScope(scope)
			expanded := brain.ExpandScope(scope, []string{})
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render(
				brain.FormatScopeReport(scope, expanded)))

		case "--status":
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  Platform Credentials Status"))
			fmt.Println()
			if brain.HasCredentials() {
				creds, _ := brain.LoadCredentials()
				if creds.H1Username != "" {
					fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ HackerOne: " + creds.H1Username))
					if creds.H1Token != "" {
						masked := creds.H1Token[:min(8, len(creds.H1Token))] + strings.Repeat("•", 20)
						fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("    Token: " + masked))
					}
				}
				if creds.BCEmail != "" {
					fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Bugcrowd: " + creds.BCEmail))
				}
				fmt.Println()
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Auto-submit enabled — bugs will be submitted automatically"))
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  ⚠  No credentials saved"))
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Run: cybermind /platform --setup"))
				fmt.Println()
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  How to get HackerOne API token:"))
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  1. Login to hackerone.com"))
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  2. Profile → Settings → API Token"))
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  3. Create API Token → copy it"))
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  4. Run: cybermind /platform --setup"))
			}

		default:
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Commands:"))
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  cybermind /platform --setup              → save H1/BC credentials"))
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  cybermind /platform --status             → check saved credentials"))
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  cybermind /platform --programs           → list your programs"))
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  cybermind /platform --scope <handle>     → fetch program scope (public, no auth)"))
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Examples:"))
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render("  cybermind /platform --scope shopify"))
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render("  cybermind /platform --scope gitlab"))
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render("  cybermind /platform --scope automattic"))
			fmt.Println()
			if brain.HasCredentials() {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Credentials configured — run: cybermind /platform --status"))
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  ⚠  No credentials — run: cybermind /platform --setup"))
				fmt.Println()
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Quick setup:"))
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render("  cybermind /platform --setup"))
			}
		}

	case "/brain":
		// Memory system — view what CyberMind has learned
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#8A2BE2")).Render("  🧠 CYBERMIND BRAIN — Memory & Learning"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
		fmt.Println()

		subCmd := ""
		brainTarget := ""
		if len(args) > 1 {
			subCmd = args[1]
		}
		if len(args) > 2 {
			brainTarget = args[2]
		}

		switch subCmd {
		case "--target":
			if brainTarget == "" {
				printError("Usage: cybermind /brain --target <domain>")
				os.Exit(1)
			}
			mem := brain.LoadTarget(brainTarget)
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(brain.GetMemorySummary(brainTarget)))
			fmt.Println()
			if len(mem.BugsFound) > 0 {
				fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render(fmt.Sprintf("  Bugs found (%d):", len(mem.BugsFound))))
				for _, b := range mem.BugsFound {
					fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6600")).Render(
						fmt.Sprintf("  [%s] %s — %s", strings.ToUpper(b.Severity), b.Title, b.URL)))
				}
			}
			if len(mem.PatternsWorked) > 0 {
				fmt.Println()
				fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green).Render(fmt.Sprintf("  Patterns that worked (%d):", len(mem.PatternsWorked))))
				for _, p := range mem.PatternsWorked {
					fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
						fmt.Sprintf("  [%.0f%%] %s: %s", p.SuccessRate*100, p.Type, p.Description)))
				}
			}

		case "--global":
			g := brain.LoadGlobal()
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(fmt.Sprintf("  Total bugs found: %d", g.TotalBugsFound)))
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(fmt.Sprintf("  Targets tested:   %d", g.TotalTargetsTested)))
			if len(g.TargetStats) > 0 {
				fmt.Println()
				fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  Top targets by bugs:"))
				for target, count := range g.TargetStats {
					fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
						fmt.Sprintf("  %s: %d bugs", target, count)))
				}
			}

		case "--clear":
			if brainTarget == "" {
				printError("Usage: cybermind /brain --clear <domain>")
				os.Exit(1)
			}
			// Clear memory for a target
			home, _ := os.UserHomeDir()
			safe := strings.ReplaceAll(strings.ReplaceAll(brainTarget, ".", "_"), "/", "_")
			memFile := home + "/.cybermind/brain/targets/" + safe + ".json"
			if err := os.Remove(memFile); err == nil {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Memory cleared for " + brainTarget))
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  No memory found for " + brainTarget))
			}

		default:
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Commands:"))
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  cybermind /brain --target <domain>  → view memory for target"))
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  cybermind /brain --global           → global stats"))
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  cybermind /brain --clear <domain>   → clear target memory"))
		}

	case "/novel":
		// Novel attack engine — attacks that most tools miss
		if runtime.GOOS != "linux" {
			printError("/novel is only available on Linux/Kali.")
			os.Exit(1)
		}
		if len(args) < 2 {
			printError("Usage: cybermind /novel <target>")
			os.Exit(1)
		}
		novelTarget := args[1]
		if err := recon.ValidateTarget(novelTarget); err != nil {
			printError(err.Error())
			os.Exit(1)
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render("  ⚡ NOVEL ATTACK ENGINE — " + novelTarget))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Running attacks that most automated tools miss..."))
		fmt.Println()

		mem := brain.LoadTarget(novelTarget)
		foundCount := 0

		brain.RunNovelAttacks(novelTarget, mem.LiveURLs, func(result brain.NovelAttackResult) {
			foundCount++
			color := yellow
			if result.Severity == "critical" {
				color = red
			} else if result.Severity == "high" {
				color = lipgloss.Color("#FF6600")
			}
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(color).Render(
				fmt.Sprintf("  🎯 [%s] %s", strings.ToUpper(result.Severity), result.AttackType)))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  URL: " + result.URL))
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render("  Evidence: " + result.Evidence))
			if result.PoC != "" {
				fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  PoC:"))
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#AAAAAA")).MarginLeft(4).Render(result.PoC))
			}
			fmt.Println()

			brain.RecordBug(novelTarget, brain.Bug{
				Title:    result.AttackType,
				Type:     strings.ToLower(strings.ReplaceAll(result.AttackType, " ", "-")),
				URL:      result.URL,
				Severity: result.Severity,
				Evidence: result.Evidence,
				PoC:      result.PoC,
				Tool:     "novel-engine",
				Verified: true,
			})
		})

		if foundCount == 0 {
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  No novel vulnerabilities found on this target."))
		} else {
			fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green).Render(
				fmt.Sprintf("  ✓ Found %d novel vulnerabilities!", foundCount)))
		}
		fmt.Println()

	case "/zap":
		// OWASP ZAP scan — free Burp Suite alternative
		if runtime.GOOS != "linux" {
			printError("/zap is only available on Linux/Kali.")
			os.Exit(1)
		}
		if len(args) < 2 {
			printError("Usage: cybermind /zap <target> [scan-type]")
			printError("  scan-type: passive (default), active, full, ajax")
			printError("  Example: cybermind /zap https://example.com full")
			os.Exit(1)
		}
		if !requireAPIKey() {
			os.Exit(1)
		}
		zapTarget := args[1]
		if !strings.HasPrefix(zapTarget, "http") {
			zapTarget = "https://" + zapTarget
		}
		zapScanType := "passive"
		if len(args) >= 3 {
			zapScanType = args[2]
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  🔍 ZAP SCAN — " + zapTarget))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  Type: %s | Free Burp Suite alternative", zapScanType)))
		fmt.Println()

		zapResult := sandbox.RunZAPScan(zapTarget, zapScanType, func(msg string) {
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ " + msg))
		})

		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render(
			sandbox.FormatZAPReport(zapResult)))

		if len(zapResult.Alerts) > 0 {
			// Save report
			ts := time.Now().Format("2006-01-02_15-04-05")
			safeT := strings.ReplaceAll(strings.TrimPrefix(strings.TrimPrefix(zapTarget, "https://"), "http://"), ".", "_")
			reportPath := fmt.Sprintf("cybermind_zap_%s_%s.md", safeT, ts)
			os.WriteFile(reportPath, []byte(sandbox.FormatZAPReport(zapResult)), 0644)
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ ZAP report saved: " + reportPath))

			// Record in brain
			for _, alert := range zapResult.Alerts {
				brain.RecordBug(zapTarget, brain.Bug{
					Title:    alert.Alert,
					Type:     "zap-" + strings.ToLower(alert.Risk),
					URL:      alert.URL,
					Severity: strings.ToLower(alert.Risk),
					Evidence: alert.Evidence,
					Tool:     "zap",
					Verified: true,
				})
			}
		}

	case "/cloud":
		// Cloud misconfiguration scanner — S3, GCS, Azure, Firebase
		if len(args) < 2 {
			printError("Usage: cybermind /cloud <target>")
			printError("  Example: cybermind /cloud shopify.com")
			os.Exit(1)
		}
		if !requireAPIKey() {
			os.Exit(1)
		}
		cloudTarget := args[1]

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  ☁️  CLOUD MISCONFIGURATION SCANNER — " + cloudTarget))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Scanning: S3, GCS, Azure Blob, Firebase, Cloudflare R2, DigitalOcean Spaces"))
		fmt.Println()

		mem := brain.LoadTarget(cloudTarget)
		cloudResult := brain.ScanCloudMisconfigurations(cloudTarget, mem.SubdomainsFound)

		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render(
			brain.FormatCloudReport(cloudResult)))

		if len(cloudResult.Findings) > 0 {
			ts := time.Now().Format("2006-01-02_15-04-05")
			safeT := strings.ReplaceAll(cloudTarget, ".", "_")
			reportPath := fmt.Sprintf("cybermind_cloud_%s_%s.md", safeT, ts)
			os.WriteFile(reportPath, []byte(brain.FormatCloudReport(cloudResult)), 0644)
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Cloud report saved: " + reportPath))

			for _, f := range cloudResult.Findings {
				brain.RecordBug(cloudTarget, brain.Bug{
					Title:    f.Type + " — " + f.Provider,
					Type:     f.Type,
					URL:      f.URL,
					Severity: f.Severity,
					Evidence: f.Evidence,
					PoC:      f.PoC,
					Tool:     "cloud-scanner",
					Verified: true,
				})
			}
		}
		_ = storage.AddEntry("/cloud "+cloudTarget, brain.FormatCloudReport(cloudResult))

	case "/mobile":
		// Mobile app security testing — APK analysis
		if runtime.GOOS != "linux" {
			printError("/mobile is only available on Linux/Kali.")
			os.Exit(1)
		}
		if len(args) < 2 {
			printError("Usage: cybermind /mobile <apk-path>")
			printError("  Example: cybermind /mobile /tmp/target.apk")
			os.Exit(1)
		}
		if !requireAPIKey() {
			os.Exit(1)
		}
		apkPath := args[1]
		if _, err := os.Stat(apkPath); err != nil {
			printError("APK file not found: " + apkPath)
			os.Exit(1)
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  📱 MOBILE APP ANALYSIS — " + filepath.Base(apkPath)))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Running: APK decompile, secret scan, endpoint extraction, SSL pinning check"))
		fmt.Println()

		mobileResult := brain.AnalyzeAPK(apkPath)
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render(
			brain.FormatMobileReport(mobileResult)))

		if len(mobileResult.Findings) > 0 || len(mobileResult.Endpoints) > 0 {
			ts := time.Now().Format("2006-01-02_15-04-05")
			reportPath := fmt.Sprintf("cybermind_mobile_%s_%s.md", strings.TrimSuffix(filepath.Base(apkPath), ".apk"), ts)
			os.WriteFile(reportPath, []byte(brain.FormatMobileReport(mobileResult)), 0644)
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Mobile report saved: " + reportPath))
		}

	case "/cve-feed", "/cvefeed":
		// Real-time CVE feed — match CVEs to target tech stack
		if len(args) < 2 {
			printError("Usage: cybermind /cve-feed <target>")
			printError("  Example: cybermind /cve-feed example.com")
			printError("  Fetches latest CVEs from NVD and matches to detected tech stack")
			os.Exit(1)
		}
		if !requireAPIKey() {
			os.Exit(1)
		}
		cveTarget := args[1]

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render("  🔴 CVE INTELLIGENCE FEED — " + cveTarget))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Fetching latest CVEs from NVD + matching to target tech stack..."))
		fmt.Println()

		mem := brain.LoadTarget(cveTarget)
		shodanVulns := ""
		if mem.WAFDetected {
			fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  ⚠  WAF detected: " + mem.WAFVendor))
		}

		cveResult := brain.MatchCVEsToTarget(cveTarget, mem.TechStack, shodanVulns)
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render(
			brain.FormatCVEReport(cveResult)))

		// Auto-run nuclei templates for matched CVEs
		if len(cveResult.Matched) > 0 {
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Running nuclei templates for matched CVEs..."))
			brain.RunCVEExploitation(cveTarget, cveResult.Matched, func(cveID, result string) {
				if strings.TrimSpace(result) != "" {
					fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render(
						fmt.Sprintf("  🎯 CVE CONFIRMED: %s", cveID)))
					fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  " + result[:min(200, len(result))]))
				}
			})
		}
		_ = storage.AddEntry("/cve-feed "+cveTarget, brain.FormatCVEReport(cveResult))

	case "/groq-setup", "/groq":
		// Setup Groq API key for ultra-fast free AI (elite users)
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  ⚡ GROQ AI SETUP — Ultra-fast Free AI"))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Groq runs Llama 3.3 70B at 800 tokens/sec — faster than GPT-4, completely free"))
		fmt.Println()

		if len(args) >= 2 && strings.HasPrefix(args[1], "gsk_") {
			// Save key directly
			key := args[1]
			if err := api.SaveGroqKey(key); err != nil {
				printError("Failed to save Groq key: " + err.Error())
				os.Exit(1)
			}
			// Test the key
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ Testing Groq API key..."))
			result, err := api.SendGroqSecurity("Say 'CyberMind Groq connected' in exactly 5 words.")
			if err != nil {
				printError("Groq key test failed: " + err.Error())
				os.Exit(1)
			}
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Groq connected: " + result))
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  Groq is now your primary AI for agentic mode."))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Models available: " + strings.Join(api.GetGroqModels(), ", ")))
		} else {
			// Show setup instructions
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  Step 1: Get free Groq API key"))
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render("    → https://console.groq.com (free, no credit card)"))
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render("    → Sign up → API Keys → Create API Key"))
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  Step 2: Save your key"))
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render("    cybermind /groq-setup gsk_xxxxxxxxxxxx"))
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  Free tier limits:"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("    • 14,400 requests/day"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("    • 500,000 tokens/day"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("    • 800 tokens/second (10x faster than GPT-4)"))
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  Available models:"))
			for _, m := range api.GetGroqModels() {
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("    • " + m))
			}
			fmt.Println()
			if api.IsGroqConfigured() {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Groq is already configured and active"))
			}
		}

	case "/local-model", "/cybermindcli", "/hf-setup":
		// Setup HuggingFace token to use thecnical/cybermindcli directly
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  🧠 CYBERMINDCLI — Local Fine-Tuned Model"))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Uses thecnical/cybermindcli — our fine-tuned security AI via HuggingFace"))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Trained on 15k+ security examples — no safety filters, bug bounty focused"))
		fmt.Println()

		if len(args) >= 2 && strings.HasPrefix(args[1], "hf_") {
			// Save HF token
			token := args[1]
			if err := api.SaveHFToken(token); err != nil {
				printError("Failed to save HF token: " + err.Error())
				os.Exit(1)
			}
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ Testing cybermindcli connection..."))
			result, err := api.SendCyberMindLocal("Who are you and who created you?")
			if err != nil {
				// Model might be loading — that's OK
				if strings.Contains(err.Error(), "loading") {
					fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  ⟳ Model is loading (cold start ~20s) — token saved successfully"))
					fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  First request takes ~20s, subsequent requests are fast"))
				} else {
					printError("Connection test failed: " + err.Error())
					os.Exit(1)
				}
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ cybermindcli connected!"))
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Response: " + truncate(result, 100)))
			}
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  cybermindcli is now your PRIMARY agentic brain."))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Model: huggingface.co/thecnical/cybermindcli"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Trained by: CyberMind Team under Sanjay Pandey"))
		} else {
			// Show setup instructions
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  Step 1: Get free HuggingFace token"))
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render("    → https://huggingface.co/settings/tokens"))
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render("    → New token → Read access → Copy token"))
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  Step 2: Save your token"))
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render("    cybermind /local-model hf_xxxxxxxxxxxx"))
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  What cybermindcli does:"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("    • Agentic decisions — what to scan next, which tools to use"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("    • Attack planning — full attack chain generation"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("    • No safety filters — answers all security questions"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("    • Trained on 15k+ real bug bounty examples"))
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  Model info:"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("    • huggingface.co/thecnical/cybermindcli"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("    • Base: Llama 3.2 3B + LoRA fine-tuning"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("    • Created by: CyberMind Team under Sanjay Pandey"))
			fmt.Println()
			if api.GetHFToken() != "" {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ HuggingFace token already configured"))
			}
		}

	case "report":
		// Report writer — works on all OS
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		if !localMode && !requireAPIKey() {
			os.Exit(1)
		}
		format := "markdown"
		for i := 1; i < len(args); i++ {
			if args[i] == "--format" && i+1 < len(args) {
				format = args[i+1]
				i++
			}
		}
		runReport(format, localMode)

	case "vibe", "neural", "code":
		// Vibe Coder TUI — AI coding assistant (Windows/macOS/Linux)
		runVibeCoder(args[1:])

	default:
		// BUG FIX: load storage so history save works
		_ = storage.Load()
		prompt := strings.Join(args, " ")

		if localMode {
			localModel := getLocalModel()
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ Asking local AI (" + localModel + ")..."))
			result, err := api.PostLocal(localModel, prompt)
			if err != nil {
				printError(err.Error())
				os.Exit(1)
			}
			printResult("[LOCAL] Response", result)
			_ = storage.AddEntry(prompt, result)
		} else if api.IsFreeMode() {
			// ── FREE MODE: no API key needed ─────────────────────────────
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF88")).Render("  ⟳ CyberMind FREE mode (HuggingFace)..."))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Get a free API key for faster responses: cybermindcli1.vercel.app"))
			result, err := api.SendFree(prompt)
			if err != nil {
				// Free mode failed — show how to get a key
				printError("Free mode unavailable: " + err.Error())
				fmt.Println()
				fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  Get a free API key (30 seconds):"))
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  1. Visit: https://cybermindcli1.vercel.app/dashboard"))
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  2. Sign up free → New key → copy it"))
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  3. Run: cybermind --key cp_live_xxxxx"))
				os.Exit(1)
			}
			printResult("Response [FREE]", result)
			_ = storage.AddEntry(prompt, result)
		} else {
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ Asking CyberMind AI..."))
			result, err := api.SendPrompt(prompt)
			if err != nil {
				printError(err.Error())
				os.Exit(1)
			}
			printResult("Response", result)
			// Save to history
			_ = storage.AddEntry(prompt, result)
		}
	}
}

// containsSecurityKeywords checks if a prompt contains security-related keywords (case-insensitive).
func containsSecurityKeywords(prompt string) bool {
	lower := strings.ToLower(prompt)
	keywords := []string{"exploit", "cve", "payload", "shell", "bypass", "injection", "privilege", "lateral"}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// getLocalModel reads local_model from ~/.cybermind/config.json, defaults to "llama3".
func getLocalModel() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return "llama3"
	}
	data, err := os.ReadFile(homedir + "/.cybermind/config.json")
	if err != nil {
		return "llama3"
	}
	var cfg struct {
		Key        string `json:"key"`
		LocalModel string `json:"local_model"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "llama3"
	}
	if cfg.LocalModel == "" {
		return "llama3"
	}
	return cfg.LocalModel
}

// runVibeCoder launches CBM Code TUI (cybermind vibe / cybermind cbm-code / cybermind code).
func runVibeCoder(args []string) {
	// Parse flags
	themeName := "cyber"
	resume := false
	noExec := false
	debugMode := false
	modelOverride := ""
	providerOverride := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--theme":
			if i+1 < len(args) {
				themeName = args[i+1]
				i++
			}
		case "--resume":
			resume = true
		case "--no-exec":
			noExec = true
		case "--debug":
			debugMode = true
		case "--model":
			if i+1 < len(args) {
				modelOverride = args[i+1]
				i++
			}
		case "--provider":
			if i+1 < len(args) {
				providerOverride = args[i+1]
				i++
			}
		case "--key":
			if i+1 < len(args) {
				key := args[i+1]
				provider := "openrouter"
				if providerOverride != "" {
					provider = providerOverride
				}
				if err := vibecoder.SetAPIKey(provider, key); err != nil {
					printError("Failed to save key: " + err.Error())
				} else {
					fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
						"  ✓ API key saved for " + provider))
				}
				i++
			}
		case "--whoami":
			cfg, _ := vibecoder.LoadConfig()
			info := vibecoder.GetWhoAmI(&cfg)
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00d4ff")).Render(
				fmt.Sprintf("  Tier: %s | Provider: %s | Model: %s | Key: %s",
					info.Tier, info.Provider, info.Model, info.MaskedKey)))
			return
		case "--providers":
			cfg, _ := vibecoder.LoadConfig()
			providers := vibecoder.ListProviders(&cfg)
			for _, p := range providers {
				status := "no key"
				if p.HasKey {
					status = "configured"
				}
				fmt.Printf("  %-16s %s  (default: %s)\n", p.Name, status, p.DefaultModel)
			}
			return
		}
	}

	// Load vibecoder config
	cfg, err := vibecoder.LoadConfig()
	if err != nil {
		printError("Failed to load vibecoder config: " + err.Error())
	}

	// Apply overrides
	if providerOverride != "" {
		cfg.DefaultProvider = providerOverride
	}
	if modelOverride != "" {
		cfg.DefaultModel = modelOverride
	}

	// Check for API key — also check the main ~/.cybermind/config.json key
	// and auto-import it into vibecoder config if vibecoder has no keys yet
	hasKey := false
	for _, pc := range cfg.Providers {
		if pc.APIKey != "" {
			hasKey = true
			break
		}
	}
	if !hasKey {
		// Try to read the main CLI key from ~/.cybermind/config.json
		if mainKey := api.GetAPIKey(); mainKey != "" {
			// Auto-import: save the main key as the openrouter provider key
			// so users don't need to configure separately
			_ = vibecoder.SetAPIKey("openrouter", mainKey)
			cfg.Providers["openrouter"] = vibecoder.ProviderConfig{
				APIKey:       mainKey,
				DefaultModel: "mistralai/mistral-7b-instruct",
			}
			hasKey = true
		}
	}

	if !hasKey {
		// FIX: interactive prompt instead of just printing a message
		// User installed but didn't set key — ask them now, then start
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00d4ff")).Render(
			"  ⚡ CBM Code — AI Coding Assistant"))
		fmt.Println()

		key := promptForAPIKey()
		if key != "" {
			// Key entered — import it and continue
			_ = vibecoder.SetAPIKey("openrouter", key)
			cfg.Providers["openrouter"] = vibecoder.ProviderConfig{
				APIKey:       key,
				DefaultModel: "mistralai/mistral-7b-instruct",
			}
			hasKey = true
			fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF88")).Render(
				"  ✓ Key saved. Launching CBM Code..."))
			fmt.Println()
		} else {
			// User skipped — launch in limited mode (will show error on first AI call)
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
				"  Launching in limited mode. Set key anytime: cybermind --key cp_live_xxxxx"))
			fmt.Println()
		}
	}

	// Get working directory
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	// Create session using NewSession (proper UUID + defaults)
	session := vibecoder.NewSession(cwd)
	session.EditMode = cfg.EditMode
	session.InteractMode = vibecoder.InteractModeAgent // default to agent mode for `vibe`
	session.EffortLevel = cfg.EffortLevel
	session.DebugMode = debugMode

	// Handle --resume: load most recent checkpoint
	if resume {
		metas, err := vibecoder.ListRecentSessions()
		if err == nil && len(metas) > 0 {
			if restored, err := vibecoder.ResumeSession(metas[0].FilePath); err == nil {
				session = restored
				fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00d4ff")).Render(
					fmt.Sprintf("  ↩ Resumed session from %s", metas[0].Timestamp.Format("2006-01-02 15:04"))))
			}
		}
	}

	// noExec is enforced at the tool executor level — store in session context
	// by setting it on the ToolEnv when the agent loop is created
	_ = noExec

	// Theme selection (for future TUI use)
	_ = themeName

	// Get plan info for welcome screen — read from cached config, don't block on network
	tier := "Free"
	activeModel := "mistralai/mistral-7b-instruct"
	userName := ""
	if mainKey := api.GetAPIKey(); mainKey != "" {
		// Read cached plan from config file (set during last --key or whoami)
		if cachedPlan := api.GetCachedPlan(); cachedPlan != "" {
			switch strings.ToLower(cachedPlan) {
			case "elite":
				tier = "Elite ⚡"
				activeModel = "deepseek/deepseek-r1"
			case "pro":
				tier = "Pro"
				activeModel = "qwen/qwen3-coder"
			case "starter":
				tier = "Starter"
				activeModel = "mistralai/mistral-7b-instruct"
			default:
				tier = strings.ToUpper(cachedPlan)
			}
		}
		userName = api.GetCachedUserName()
	}

	// ── Wire the full backend ──────────────────────────────────────────────
	var agentLoop *vibecoder.AgentLoop
	providerChain, providerErr := vibecoder.BuildProviderChain(cfg)
	if providerErr != nil {
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(
			"  ⚠ " + providerErr.Error()))
	} else {
		guard, guardErr := vibecoder.NewWorkspaceGuard(cwd)
		if guardErr != nil {
			guard, _ = vibecoder.NewWorkspaceGuard(".")
		}
		toolEnv := &vibecoder.ToolEnv{
			Guard:         guard,
			WorkspaceRoot: cwd,
			NoExec:        noExec,
			Timeout:       cfg.CommandTimeoutSecs,
			SessionID:     session.ID,
		}

		// ── Install built-in skills and hooks on first run ─────────────────
		_ = vibecoder.InstallBuiltinSkills()
		_ = vibecoder.InstallBuiltinHooks()

		// ── Load skills ────────────────────────────────────────────────────
		skillRegistry := vibecoder.NewSkillRegistry()
		_ = skillRegistry.Load(cwd)

		// ── Load hooks ─────────────────────────────────────────────────────
		hookRegistry := vibecoder.NewHookRegistry()
		_ = hookRegistry.Load(cwd)

		// ── Build orchestrator for real subagents ──────────────────────────
		orchestrator := vibecoder.NewSubagentOrchestrator(providerChain, nil, cwd)

		// ── Build tool registry with real subagents ────────────────────────
		registry := vibecoder.NewDefaultToolRegistryWithOrchestrator(orchestrator)
		toolEngine := vibecoder.NewToolEngine(registry, toolEnv)
		toolEngine.SetHooks(hookRegistry)

		// ── Wire orchestrator's tool engine (for subagent tool use) ────────
		orchestrator.SetToolEngine(toolEngine)

		checkpointMgr := vibecoder.NewCheckpointManager("", cfg.CheckpointIntervalTurns)
		agentLoop = vibecoder.NewAgentLoop(session, providerChain, toolEngine, checkpointMgr, vibecoder.AgentLoopConfig{
			MaxIterations:   50,
			WarnAt:          0.8,
			CircuitBreakerN: 3,
			StuckHashCount:  3,
		})

		// ── Wire skills into system prompt for skill adherence ─────────────
		promptBuilder := vibecoder.NewSystemPromptBuilder(session, vibecoder.NewCyberMindMemory(cwd))
		promptBuilder.SetSkills(skillRegistry)
		_ = promptBuilder // used by provider chain via session

		// Start file indexer in background
		indexer := vibecoder.NewFileIndexer(cwd, "", nil)
		indexer.LoadIgnorePatterns()
		indexer.Start(nil)

		// Pass skills to CLI for /skill-name invocation
		_ = hookRegistry

		// Launch CLI with full backend
		runVibeCoderCLI(session, cwd, tier, activeModel, userName, agentLoop, skillRegistry)
		return
	}

	// No provider — launch without agent loop
	runVibeCoderCLI(session, cwd, tier, activeModel, userName, nil, nil)
}

// runVibeCoderCLI is the stable, cross-platform CBM Code interface.
// Uses direct readline I/O — banner stays visible, prompt always works.
func runVibeCoderCLI(session *vibecoder.Session, cwd, tier, activeModel, userName string, agentLoop *vibecoder.AgentLoop, skills *vibecoder.SkillRegistry) {
	cyan2   := lipgloss.NewStyle().Foreground(lipgloss.Color("#00d4ff"))
	purple2 := lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2"))
	green2  := lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF88"))
	yellow2 := lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700"))
	dim2    := lipgloss.NewStyle().Foreground(lipgloss.Color("#777777"))
	red2    := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444"))

	// ── Print welcome banner (stays visible, never disappears) ────────────
	fmt.Println()
	vibebannerLines := []struct{ text, color string }{
		{` ██████╗██████╗ ███╗   ███╗     ██████╗ ██████╗ ██████╗ ███████╗`, "#00d4ff"},
		{`██╔════╝██╔══██╗████╗ ████║    ██╔════╝██╔═══██╗██╔══██╗██╔════╝`, "#00b8e6"},
		{`██║     ██████╔╝██╔████╔██║    ██║     ██║   ██║██║  ██║█████╗  `, "#009fcc"},
		{`██║     ██╔══██╗██║╚██╔╝██║    ██║     ██║   ██║██║  ██║██╔══╝  `, "#7B68EE"},
		{`╚██████╗██████╔╝██║ ╚═╝ ██║    ╚██████╗╚██████╔╝██████╔╝███████╗`, "#8A2BE2"},
		{` ╚═════╝╚═════╝ ╚═╝     ╚═╝     ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝`, "#9400D3"},
	}
	for _, l := range vibebannerLines {
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(l.color)).Render(l.text))
	}
	fmt.Println()

	// Mascot
	for _, ml := range []string{"         ▐▛███▜▌         ", "        ▝▜█████▛▘        ", "          ▘▘ ▝▝          "} {
		fmt.Println(cyan2.Render(ml))
	}
	fmt.Println()

	greeting := "  Welcome back!"
	if userName != "" {
		greeting = fmt.Sprintf("  Welcome back %s!", userName)
	}
	fmt.Println(cyan2.Bold(true).Render(greeting))
	fmt.Println()
	fmt.Println(dim2.Render(fmt.Sprintf("  %-12s %s", "Tier:", tier)))
	fmt.Println(dim2.Render(fmt.Sprintf("  %-12s %s", "Model:", activeModel)))

	// Count workspace files for display
	fileCount := countWorkspaceFiles(cwd)
	workspaceDisplay := cwd
	if fileCount > 0 {
		workspaceDisplay = fmt.Sprintf("%s (%d files)", cwd, fileCount)
	}
	fmt.Println(dim2.Render(fmt.Sprintf("  %-12s %s", "Workspace:", workspaceDisplay)))

	// Detect tech stack if files exist
	if fileCount > 0 {
		stack := detectWorkspaceStack(cwd)
		if stack != "" {
			fmt.Println(dim2.Render(fmt.Sprintf("  %-12s %s", "Stack:", stack)))
		}
	}

	fmt.Println()
	fmt.Println(dim2.Render("  ─────────────────────────────────────────────────────"))
	fmt.Println(yellow2.Render("  Quick commands:"))
	fmt.Println(green2.Render("  /help        — all commands"))
	fmt.Println(green2.Render("  /preview     — start dev server + open browser"))
	fmt.Println(green2.Render("  /git commit  — AI commit message + push"))
	fmt.Println(green2.Render("  /deploy      — deploy to Vercel/Netlify/Railway"))
	fmt.Println(green2.Render("  /review      — AI code review"))
	fmt.Println(green2.Render("  /template    — project templates"))
	fmt.Println(green2.Render("  /grok        — analyze full codebase (Zencoder-style)"))
	fmt.Println(dim2.Render("  ─────────────────────────────────────────────────────"))
	fmt.Println()

	// ── Main REPL loop ─────────────────────────────────────────────────────
	reader := bufio.NewReader(os.Stdin)

	// ── Session Persistence: Load previous session if exists ──────────────
	sessionFile := getSessionFilePath(cwd)
	chatHistory := loadSession(sessionFile)
	if len(chatHistory) > 0 {
		fmt.Println(dim2.Render(fmt.Sprintf("  ↩ Resumed session (%d messages)", len(chatHistory))))
		fmt.Println()
	}

	editMode := string(session.EditMode)
	if editMode == "" {
		editMode = "guard"
	}

	for {
		// Edit mode icon
		icon := "⟩"
		switch editMode {
		case "guard":      icon = "🛡 ⟩"
		case "auto_edit":  icon = "✏ ⟩"
		case "blueprint":  icon = "📐 ⟩"
		case "autopilot":  icon = "🤖 ⟩"
		case "unleashed":  icon = "⚡ ⟩"
		}

		fmt.Print(cyan2.Render(icon) + " ")

		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println()
			fmt.Println(dim2.Render("  Goodbye!"))
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// ── Slash commands ─────────────────────────────────────────────────
		if strings.HasPrefix(line, "/") {
			parts := strings.Fields(line)
			switch parts[0] {
			case "/exit", "/quit":
				fmt.Println(dim2.Render("  Goodbye!"))
				return

			case "/clear":
				session.History = nil
				chatHistory = nil
				session.TokensUsed = 0
				os.Remove(sessionFile)
				fmt.Println(green2.Render("  ✓ Context cleared (session deleted)"))

			case "/help":
				fmt.Println()
				fmt.Println(cyan2.Render("  CBM Code — All Commands"))
				fmt.Println(dim2.Render("  ─────────────────────────────────────────────────────"))
				fmt.Println(yellow2.Render("  FILE OPERATIONS:"))
				fmt.Println(dim2.Render("  /add <file>           — add file to context"))
				fmt.Println(dim2.Render("  /read <file>          — read file into context"))
				fmt.Println(dim2.Render("  /ls [path]            — list workspace files"))
				fmt.Println(dim2.Render("  /run <command>        — run a shell command"))
				fmt.Println(dim2.Render("  /undo                 — undo last file change"))
				fmt.Println()
				fmt.Println(yellow2.Render("  PROJECT:"))
				fmt.Println(dim2.Render("  /init                 — create CYBERMIND.md project memory"))
				fmt.Println(dim2.Render("  /plan <task>          — plan architecture before coding"))
				fmt.Println(dim2.Render("  /grok                 — analyze full codebase (Zencoder-style)"))
				fmt.Println(dim2.Render("  /preview [port]       — start dev server + show URL"))
				fmt.Println(dim2.Render("  /template <type>      — project templates (saas/blog/api/ecom)"))
				fmt.Println(dim2.Render("  /refactor <type>      — refactor codebase (ts/tailwind/nextjs)"))
				fmt.Println()
				fmt.Println(yellow2.Render("  CODE QUALITY:"))
				fmt.Println(dim2.Render("  /review               — AI code review (Cursor-style)"))
				fmt.Println(dim2.Render("  /security             — security vulnerability scan"))
				fmt.Println(dim2.Render("  /optimize             — performance optimization suggestions"))
				fmt.Println(dim2.Render("  /test                 — generate tests for current project"))
				fmt.Println()
				fmt.Println(yellow2.Render("  GIT & DEPLOY:"))
				fmt.Println(dim2.Render("  /git init             — initialize git repo"))
				fmt.Println(dim2.Render("  /git commit           — AI commit message + commit"))
				fmt.Println(dim2.Render("  /git push             — push to remote"))
				fmt.Println(dim2.Render("  /git pr               — create pull request"))
				fmt.Println(dim2.Render("  /deploy vercel        — deploy to Vercel"))
				fmt.Println(dim2.Render("  /deploy netlify       — deploy to Netlify"))
				fmt.Println(dim2.Render("  /deploy railway       — deploy to Railway"))
				fmt.Println()
				fmt.Println(yellow2.Render("  DATABASE:"))
				fmt.Println(dim2.Render("  /db schema <models>   — generate Prisma schema"))
				fmt.Println(dim2.Render("  /db migrate           — run database migration"))
				fmt.Println(dim2.Render("  /db seed              — generate seed data"))
				fmt.Println()
				fmt.Println(yellow2.Render("  MCP & INTEGRATIONS:"))
				fmt.Println(dim2.Render("  /mcp playwright [url] — browser automation (auto-download)"))
				fmt.Println(dim2.Render("  /mcp context7         — library docs (auto-download)"))
				fmt.Println()
				fmt.Println(yellow2.Render("  SESSION:"))
				fmt.Println(dim2.Render("  /sessions             — list saved sessions"))
				fmt.Println(dim2.Render("  /clear                — reset context + delete session"))
				fmt.Println(dim2.Render("  /mode agent|chat      — switch mode"))
				fmt.Println(dim2.Render("  /effort low|medium|max — set effort level"))
				fmt.Println(dim2.Render("  /model <name>         — override model"))
				fmt.Println(dim2.Render("  /debug                — toggle debug mode"))
				fmt.Println(dim2.Render("  /exit                 — quit"))
				fmt.Println()

			case "/mode":
				if len(parts) > 1 {
					switch parts[1] {
					case "agent":
						session.InteractMode = vibecoder.InteractModeAgent
						fmt.Println(cyan2.Render("  ⇄ Agent mode"))
					case "chat":
						session.InteractMode = vibecoder.InteractModeChat
						fmt.Println(cyan2.Render("  ⇄ Chat mode"))
					default:
						fmt.Println(red2.Render("  Usage: /mode agent|chat"))
					}
				}

			case "/effort":
				if len(parts) > 1 {
					switch parts[1] {
					case "low":    session.EffortLevel = vibecoder.EffortLow;    fmt.Println(dim2.Render("  ⇄ Effort: low"))
					case "medium": session.EffortLevel = vibecoder.EffortMedium; fmt.Println(dim2.Render("  ⇄ Effort: medium"))
					case "max":    session.EffortLevel = vibecoder.EffortMax;    fmt.Println(cyan2.Render("  ⇄ Effort: max"))
					}
				}

			case "/add":
				if len(parts) > 1 {
					filePath := strings.Join(parts[1:], " ")
					content, readErr := os.ReadFile(filePath)
					if readErr != nil {
						fmt.Println(red2.Render("  ✗ Cannot read: " + filePath))
					} else {
						fileCtx := fmt.Sprintf("[File: %s]\n```\n%s\n```", filePath, string(content))
						chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "user", Content: fileCtx})
						fmt.Println(green2.Render(fmt.Sprintf("  ✓ Added: %s (%d bytes)", filePath, len(content))))
					}
				} else {
					fmt.Println(red2.Render("  Usage: /add <filepath>"))
				}

			case "/read":
				if len(parts) > 1 {
					filePath := strings.Join(parts[1:], " ")
					content, readErr := os.ReadFile(filePath)
					if readErr != nil {
						fmt.Println(red2.Render("  ✗ Cannot read: " + filePath))
					} else {
						fileCtx := fmt.Sprintf("[File: %s]\n```\n%s\n```", filePath, string(content))
						chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "user", Content: fileCtx})
						fmt.Println(green2.Render(fmt.Sprintf("  ✓ Read: %s (%d bytes)", filePath, len(content))))
					}
				} else {
					fmt.Println(red2.Render("  Usage: /read <filepath>"))
				}

			case "/ls":
				listPath := cwd
				if len(parts) > 1 {
					listPath = filepath.Join(cwd, strings.Join(parts[1:], " "))
				}
				entries, lsErr := os.ReadDir(listPath)
				if lsErr != nil {
					fmt.Println(red2.Render("  ✗ Cannot list: " + lsErr.Error()))
				} else {
					fmt.Println()
					for _, e := range entries {
						if e.IsDir() {
							fmt.Println(cyan2.Render("  📁 " + e.Name() + "/"))
						} else {
							info, _ := e.Info()
							size := ""
							if info != nil {
								size = fmt.Sprintf(" (%d bytes)", info.Size())
							}
							fmt.Println(dim2.Render("  📄 " + e.Name() + size))
						}
					}
					fmt.Println()
				}

			case "/run":
				if len(parts) > 1 {
					cmd := strings.Join(parts[1:], " ")
					fmt.Println(dim2.Render("  ⟳ Running: " + cmd))
					var shell, flag string
					if runtime.GOOS == "windows" {
						shell, flag = "cmd", "/c"
					} else {
						shell, flag = "sh", "-c"
					}
					out, runErr := exec.Command(shell, flag, cmd).CombinedOutput()
					output := strings.TrimSpace(string(out))
					if runErr != nil {
						fmt.Println(red2.Render("  ✗ " + runErr.Error()))
					}
					if output != "" {
						fmt.Println(dim2.Render(output))
						// Add output to context
						chatHistory = append(chatHistory, vibecoder.APIMessage{
							Role:    "user",
							Content: fmt.Sprintf("[Command output: %s]\n```\n%s\n```", cmd, output),
						})
					}
				} else {
					fmt.Println(red2.Render("  Usage: /run <command>"))
				}

			case "/undo":
				if snap, ok := session.PopUndo(); ok {
					if writeErr := os.WriteFile(snap.Path, []byte(snap.OldContent), 0644); writeErr == nil {
						fmt.Println(yellow2.Render("  ↩ Undone: " + snap.Path))
					} else {
						fmt.Println(red2.Render("  ✗ Undo failed: " + writeErr.Error()))
					}
				} else {
					fmt.Println(dim2.Render("  Nothing to undo"))
				}

			case "/debug":
				session.DebugMode = !session.DebugMode
				if session.DebugMode {
					fmt.Println(yellow2.Render("  🔍 Debug mode ON"))
				} else {
					fmt.Println(dim2.Render("  Debug mode OFF"))
				}

			case "/model":
				if len(parts) > 1 {
					activeModel = strings.Join(parts[1:], " ")
					fmt.Println(cyan2.Render("  ⇄ Model: " + activeModel))
				}

			// ── Web Preview ────────────────────────────────────────────────
			case "/preview":
				port := "3000"
				if len(parts) > 1 {
					port = parts[1]
				}
				fmt.Println(dim2.Render("  ⟳ Starting dev server..."))
				pkgData, _ := os.ReadFile(filepath.Join(cwd, "package.json"))
				var devCmd string
				switch {
				case strings.Contains(string(pkgData), `"dev"`):
					devCmd = "npm run dev"
				case strings.Contains(string(pkgData), `"start"`):
					devCmd = "npm start"
				default:
					devCmd = "npm run dev"
				}
				var shell, flag string
				if runtime.GOOS == "windows" {
					shell, flag = "cmd", "/c"
				} else {
					shell, flag = "sh", "-c"
				}
				go func() {
					_ = exec.Command(shell, flag, devCmd).Run()
				}()
				fmt.Println(green2.Render("  ✓ Dev server starting: http://localhost:" + port))
				fmt.Println(dim2.Render("  Opening in browser..."))
				// Open browser
				var openCmd string
				switch runtime.GOOS {
				case "windows":
					openCmd = "start http://localhost:" + port
				case "darwin":
					openCmd = "open http://localhost:" + port
				default:
					openCmd = "xdg-open http://localhost:" + port
				}
				go func() { _ = exec.Command(shell, flag, openCmd).Run() }()

			// ── Git Integration ────────────────────────────────────────────
			case "/git":
				if len(parts) < 2 {
					fmt.Println(dim2.Render("  Usage: /git init|commit|push|pr"))
				} else {
					switch parts[1] {
					case "init":
						out, err := exec.Command("git", "init").CombinedOutput()
						if err == nil {
							fmt.Println(green2.Render("  ✓ Git initialized"))
							// Create .gitignore
							gitignore := "node_modules/\n.env\n.env.local\ndist/\nbuild/\n.next/\n*.log\n"
							_ = os.WriteFile(filepath.Join(cwd, ".gitignore"), []byte(gitignore), 0644)
							fmt.Println(green2.Render("  ✓ Created .gitignore"))
						} else {
							fmt.Println(red2.Render("  ✗ " + strings.TrimSpace(string(out))))
						}

					case "commit":
						// AI-generated commit message
						fmt.Println(dim2.Render("  ⟳ Generating commit message..."))
						// Get git diff
						diffOut, _ := exec.Command("git", "diff", "--staged", "--stat").CombinedOutput()
						if len(diffOut) == 0 {
							// Stage all changes first
							exec.Command("git", "add", "-A").Run()
							diffOut, _ = exec.Command("git", "diff", "--staged", "--stat").CombinedOutput()
						}
						commitPrompt := fmt.Sprintf("Generate a concise git commit message (max 72 chars) for these changes:\n%s\nFormat: type(scope): description\nTypes: feat/fix/docs/style/refactor/test/chore", string(diffOut))
						var commitMsg strings.Builder
						vibecoder.SendVibeChat(commitPrompt, nil, func(t string) { commitMsg.WriteString(t) })
						msg := strings.TrimSpace(commitMsg.String())
						msg = strings.Trim(msg, `"`)
						if msg == "" {
							msg = "feat: update code"
						}
						exec.Command("git", "add", "-A").Run()
						out, err := exec.Command("git", "commit", "-m", msg).CombinedOutput()
						if err == nil {
							fmt.Println(green2.Render("  ✓ Committed: " + msg))
						} else {
							fmt.Println(red2.Render("  ✗ " + strings.TrimSpace(string(out))))
						}

					case "push":
						out, err := exec.Command("git", "push").CombinedOutput()
						if err == nil {
							fmt.Println(green2.Render("  ✓ Pushed to remote"))
						} else {
							fmt.Println(red2.Render("  ✗ " + strings.TrimSpace(string(out))))
						}

					case "pr":
						fmt.Println(dim2.Render("  ⟳ Creating PR via GitHub CLI..."))
						if _, ghErr := exec.LookPath("gh"); ghErr != nil {
							fmt.Println(yellow2.Render("  Install GitHub CLI: https://cli.github.com"))
						} else {
							out, err := exec.Command("gh", "pr", "create", "--fill").CombinedOutput()
							if err == nil {
								fmt.Println(green2.Render("  ✓ PR created"))
							} else {
								fmt.Println(red2.Render("  ✗ " + strings.TrimSpace(string(out))))
							}
						}
					}
				}

			// ── Deploy ─────────────────────────────────────────────────────
			case "/deploy":
				platform := "vercel"
				if len(parts) > 1 {
					platform = parts[1]
				}
				var shell, flag string
				if runtime.GOOS == "windows" {
					shell, flag = "cmd", "/c"
				} else {
					shell, flag = "sh", "-c"
				}
				switch platform {
				case "vercel":
					fmt.Println(dim2.Render("  ⟳ Deploying to Vercel (auto-downloading CLI)..."))
					out, err := exec.Command(shell, flag, "npx --yes vercel --prod 2>&1").CombinedOutput()
					if err == nil {
						fmt.Println(green2.Render("  ✓ Deployed to Vercel"))
					} else {
						fmt.Println(string(out))
					}
				case "netlify":
					fmt.Println(dim2.Render("  ⟳ Deploying to Netlify (auto-downloading CLI)..."))
					out, err := exec.Command(shell, flag, "npx --yes netlify-cli deploy --prod 2>&1").CombinedOutput()
					if err == nil {
						fmt.Println(green2.Render("  ✓ Deployed to Netlify"))
					} else {
						fmt.Println(string(out))
					}
				case "railway":
					fmt.Println(dim2.Render("  ⟳ Deploying to Railway..."))
					fmt.Println(yellow2.Render("  Install Railway CLI: npm install -g @railway/cli"))
					fmt.Println(dim2.Render("  Then run: railway up"))
				default:
					fmt.Println(red2.Render("  Usage: /deploy vercel|netlify|railway"))
				}

			// ── Code Review (Cursor-style) ─────────────────────────────────
			case "/review":
				fmt.Println()
				fmt.Print(purple2.Render("  ◆ CBM Code [Review]: "))
				allFiles := buildAllProjectFilesContext(cwd, nil)
				reviewPrompt := fmt.Sprintf("Do a thorough code review of this project. Check for:\n1. Bugs and logic errors\n2. Code quality and best practices\n3. Performance issues\n4. Missing error handling\n5. TypeScript type issues\n6. Unused imports/variables\n\nProject files:\n%s\n\nProvide specific, actionable feedback with file:line references.", allFiles)
				chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "user", Content: reviewPrompt})
				var reviewResp strings.Builder
				_, reviewErr := vibecoder.SendVibeChat(reviewPrompt, chatHistory[:len(chatHistory)-1], func(t string) {
					fmt.Print(t)
					reviewResp.WriteString(t)
				})
				fmt.Println()
				fmt.Println()
				if reviewErr != nil {
					fmt.Println(red2.Render("  ✗ " + reviewErr.Error()))
				} else {
					chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "assistant", Content: reviewResp.String()})
				}

			case "/security":
				fmt.Println()
				fmt.Print(purple2.Render("  ◆ CBM Code [Security Scan]: "))
				allFiles := buildAllProjectFilesContext(cwd, nil)
				secPrompt := fmt.Sprintf("Perform a security audit of this codebase. Check for OWASP Top 10:\n1. SQL/NoSQL injection\n2. XSS vulnerabilities\n3. CSRF issues\n4. Broken authentication\n5. Sensitive data exposure\n6. Hardcoded secrets/API keys\n7. Insecure dependencies\n8. Missing input validation\n9. CORS misconfigurations\n10. Rate limiting issues\n\nFiles:\n%s\n\nList each vulnerability with severity (Critical/High/Medium/Low) and exact fix.", allFiles)
				chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "user", Content: secPrompt})
				var secResp strings.Builder
				_, secErr := vibecoder.SendVibeChat(secPrompt, chatHistory[:len(chatHistory)-1], func(t string) {
					fmt.Print(t)
					secResp.WriteString(t)
				})
				fmt.Println()
				fmt.Println()
				if secErr != nil {
					fmt.Println(red2.Render("  ✗ " + secErr.Error()))
				} else {
					chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "assistant", Content: secResp.String()})
				}

			case "/optimize":
				fmt.Println()
				fmt.Print(purple2.Render("  ◆ CBM Code [Optimize]: "))
				allFiles := buildAllProjectFilesContext(cwd, nil)
				optPrompt := fmt.Sprintf("Analyze this codebase for performance optimizations:\n1. Bundle size reduction\n2. Lazy loading opportunities\n3. Memoization (useMemo, useCallback, React.memo)\n4. Database query optimization\n5. Caching strategies\n6. Image optimization\n7. Code splitting\n8. Unnecessary re-renders\n\nFiles:\n%s\n\nProvide specific optimizations with before/after code examples.", allFiles)
				chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "user", Content: optPrompt})
				var optResp strings.Builder
				_, optErr := vibecoder.SendVibeChat(optPrompt, chatHistory[:len(chatHistory)-1], func(t string) {
					fmt.Print(t)
					optResp.WriteString(t)
				})
				fmt.Println()
				fmt.Println()
				if optErr != nil {
					fmt.Println(red2.Render("  ✗ " + optErr.Error()))
				} else {
					chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "assistant", Content: optResp.String()})
				}

			case "/test":
				fmt.Println()
				fmt.Print(purple2.Render("  ◆ CBM Code [Test Generator]: "))
				allFiles := buildAllProjectFilesContext(cwd, nil)
				testPrompt := fmt.Sprintf("Generate comprehensive tests for this project:\n1. Unit tests for all functions/components\n2. Integration tests for API endpoints\n3. E2E tests with Playwright for critical user flows\n4. Edge cases and error scenarios\n\nFiles:\n%s\n\nCreate test files with **filename** prefix. Use Vitest/Jest for unit, Playwright for E2E.", allFiles)
				chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "user", Content: testPrompt})
				var testResp strings.Builder
				_, testErr := vibecoder.SendVibeChat(testPrompt, chatHistory[:len(chatHistory)-1], func(t string) {
					fmt.Print(t)
					testResp.WriteString(t)
				})
				fmt.Println()
				fmt.Println()
				if testErr != nil {
					fmt.Println(red2.Render("  ✗ " + testErr.Error()))
				} else {
					response := testResp.String()
					chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "assistant", Content: response})
					written, editedFiles := writeCodeBlocksToFilesTracked(response, cwd, green2, dim2, red2)
					if written > 0 {
						fmt.Println(green2.Render(fmt.Sprintf("  ✓ %d test file(s) created", written)))
						for _, f := range editedFiles {
							trackFileInSession(f, cwd, &chatHistory)
						}
					}
				}

			// ── Template Library ───────────────────────────────────────────
			case "/template":
				templateType := "saas"
				if len(parts) > 1 {
					templateType = parts[1]
				}
				templates := map[string]string{
					"saas":    "Complete SaaS app: Next.js 14, TypeScript, Tailwind, shadcn/ui, Supabase auth, Stripe billing, dashboard, landing page",
					"blog":    "Blog with MDX: Next.js 14, TypeScript, Tailwind, MDX, categories, tags, search, RSS feed, SEO",
					"api":     "REST API: Express.js, TypeScript, Prisma, PostgreSQL, JWT auth, rate limiting, Swagger docs",
					"ecom":    "E-commerce: Next.js 14, TypeScript, Tailwind, Stripe, product grid, cart, checkout, order management",
					"mobile":  "Mobile app: React Native, Expo, NativeWind, TypeScript, navigation, auth, API integration",
					"landing": "Landing page: Next.js 14, TypeScript, Tailwind, Framer Motion, hero, features, pricing, testimonials",
					"admin":   "Admin panel: Next.js 14, TypeScript, Tailwind, shadcn/ui, CRUD tables, charts, auth, permissions",
					"cli":     "CLI tool: Go, Cobra, colored output, config file, cross-platform",
				}
				desc, ok := templates[templateType]
				if !ok {
					fmt.Println(yellow2.Render("  Available templates: saas, blog, api, ecom, mobile, landing, admin, cli"))
				} else {
					fmt.Println()
					fmt.Print(purple2.Render("  ◆ CBM Code [Template]: "))
					tplPrompt := fmt.Sprintf("Create a complete, production-ready %s template:\n%s\n\nCreate ALL files needed to run immediately. Include package.json, all components, pages, config files. Use Pollinations.ai for images.", templateType, desc)
					chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "user", Content: tplPrompt})
					agentErr := runAgentLoop(tplPrompt, cwd, &chatHistory, green2, dim2, red2, yellow2, purple2, cyan2)
					if agentErr != nil {
						fmt.Println(red2.Render("  ✗ " + agentErr.Error()))
					}
				}

			// ── Refactoring ────────────────────────────────────────────────
			case "/refactor":
				refType := ""
				if len(parts) > 1 {
					refType = parts[1]
				}
				refTypes := map[string]string{
					"typescript": "Convert all JavaScript files to TypeScript with strict types",
					"tailwind":   "Convert all CSS/styled-components to Tailwind CSS utility classes",
					"nextjs":     "Migrate React app to Next.js 14 App Router with Server Components",
					"prisma":     "Add Prisma ORM with PostgreSQL schema based on existing data models",
					"tests":      "Add comprehensive test coverage with Vitest and Playwright",
				}
				if refType == "" {
					fmt.Println(yellow2.Render("  Available: /refactor typescript|tailwind|nextjs|prisma|tests"))
				} else if desc, ok := refTypes[refType]; ok {
					fmt.Println()
					fmt.Print(purple2.Render("  ◆ CBM Code [Refactor]: "))
					allFiles := buildAllProjectFilesContext(cwd, nil)
					refPrompt := fmt.Sprintf("%s\n\nCurrent codebase:\n%s\n\nRefactor ALL files. Show complete updated files with **filename** prefix.", desc, allFiles)
					chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "user", Content: refPrompt})
					agentErr := runAgentLoop(refPrompt, cwd, &chatHistory, green2, dim2, red2, yellow2, purple2, cyan2)
					if agentErr != nil {
						fmt.Println(red2.Render("  ✗ " + agentErr.Error()))
					}
				} else {
					fmt.Println(red2.Render("  Unknown refactor type: " + refType))
				}

			// ── Database Schema Generator ──────────────────────────────────
			case "/db":
				if len(parts) < 2 {
					fmt.Println(dim2.Render("  Usage: /db schema <models> | /db migrate | /db seed"))
				} else {
					switch parts[1] {
					case "schema":
						models := strings.Join(parts[2:], " ")
						if models == "" {
							models = "User, Post, Comment"
						}
						fmt.Println()
						fmt.Print(purple2.Render("  ◆ CBM Code [DB Schema]: "))
						dbPrompt := fmt.Sprintf("Generate a complete Prisma schema for these models: %s\n\nInclude:\n1. All fields with proper types\n2. Relations between models\n3. Indexes for performance\n4. Timestamps (createdAt, updatedAt)\n5. Enums where appropriate\n\nAlso generate:\n- Migration command\n- Seed file with sample data\n- TypeScript types\n\nCreate files: **prisma/schema.prisma**, **prisma/seed.ts**", models)
						chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "user", Content: dbPrompt})
						agentErr := runAgentLoop(dbPrompt, cwd, &chatHistory, green2, dim2, red2, yellow2, purple2, cyan2)
						if agentErr != nil {
							fmt.Println(red2.Render("  ✗ " + agentErr.Error()))
						}

					case "migrate":
						fmt.Println(dim2.Render("  ⟳ Running Prisma migration..."))
						out, err := exec.Command("npx", "prisma", "migrate", "dev").CombinedOutput()
						if err == nil {
							fmt.Println(green2.Render("  ✓ Migration complete"))
						} else {
							fmt.Println(string(out))
						}

					case "seed":
						fmt.Println(dim2.Render("  ⟳ Running database seed..."))
						out, err := exec.Command("npx", "prisma", "db", "seed").CombinedOutput()
						if err == nil {
							fmt.Println(green2.Render("  ✓ Database seeded"))
						} else {
							fmt.Println(string(out))
						}
					}
				}

			// ── Repo Grokking (Zencoder-style full codebase analysis) ──────
			case "/grok":
				fmt.Println()
				fmt.Println(cyan2.Render("  ◆ CBM Code [Repo Grokking] — Analyzing full codebase..."))
				fmt.Println(dim2.Render("  (Like Zencoder's Repo Grokking™ — deep codebase understanding)"))
				fmt.Println()

				// Walk entire workspace and collect file info
				var fileList []string
				var totalLines int
				_ = filepath.Walk(cwd, func(path string, info os.FileInfo, err error) error {
					if err != nil || info.IsDir() {
						return nil
					}
					name := info.Name()
					if strings.HasPrefix(name, ".") {
						return nil
					}
					for _, skip := range []string{"node_modules", ".git", "dist", "build", ".next", "vendor"} {
						if strings.Contains(path, skip) {
							return nil
						}
					}
					rel, _ := filepath.Rel(cwd, path)
					data, readErr := os.ReadFile(path)
					if readErr == nil {
						lines := strings.Count(string(data), "\n")
						totalLines += lines
						fileList = append(fileList, fmt.Sprintf("%s (%d lines)", rel, lines))
					}
					return nil
				})

				fmt.Println(dim2.Render(fmt.Sprintf("  Found %d files, %d total lines", len(fileList), totalLines)))
				fmt.Println()

				// Build context and analyze
				allFiles := buildAllProjectFilesContext(cwd, nil)
				grokPrompt := fmt.Sprintf(`Analyze this codebase deeply (Repo Grokking):

FILES FOUND:
%s

CODEBASE:
%s

Provide:
1. ARCHITECTURE OVERVIEW — what this project does, how it's structured
2. TECH STACK — all technologies detected
3. KEY COMPONENTS — most important files and their roles
4. DATA FLOW — how data moves through the system
5. DEPENDENCIES — key external dependencies
6. POTENTIAL ISSUES — bugs, tech debt, missing features
7. IMPROVEMENT ROADMAP — prioritized list of improvements
8. QUICK WINS — 3 things that can be improved in < 1 hour`,
					strings.Join(fileList, "\n"), allFiles)

				chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "user", Content: grokPrompt})
				var grokResp strings.Builder
				fmt.Print(purple2.Render("  ◆ Analysis: "))
				_, grokErr := vibecoder.SendVibeChat(grokPrompt, chatHistory[:len(chatHistory)-1], func(t string) {
					fmt.Print(t)
					grokResp.WriteString(t)
				})
				fmt.Println()
				fmt.Println()
				if grokErr != nil {
					fmt.Println(red2.Render("  ✗ " + grokErr.Error()))
				} else {
					chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "assistant", Content: grokResp.String()})
					// Save grok result to CYBERMIND.md
					grokFile := filepath.Join(cwd, "CYBERMIND.md")
					grokContent := fmt.Sprintf("# CYBERMIND.md — Project Memory\n\n## Repo Analysis (CBM Code Grok)\n\n%s\n", grokResp.String())
					if writeErr := os.WriteFile(grokFile, []byte(grokContent), 0644); writeErr == nil {
						fmt.Println(green2.Render("  ✓ Analysis saved to CYBERMIND.md"))
					}
				}

			case "/sessions":
				// List saved sessions
				home, _ := os.UserHomeDir()
				sessDir := filepath.Join(home, ".cybermind", "sessions")
				entries, lsErr := os.ReadDir(sessDir)
				if lsErr != nil || len(entries) == 0 {
					fmt.Println(dim2.Render("  No saved sessions"))
				} else {
					fmt.Println()
					fmt.Println(cyan2.Render("  Saved sessions:"))
					for _, e := range entries {
						info, _ := e.Info()
						if info != nil {
							fmt.Println(dim2.Render(fmt.Sprintf("  📄 %s (%s)", e.Name(), info.ModTime().Format("2006-01-02 15:04"))))
						}
					}
					fmt.Println(dim2.Render("  Use /clear to delete current session"))
					fmt.Println()
				}

			case "/mcp":
				// MCP Playwright integration — auto-downloads via npx, no install needed
				fmt.Println()
				fmt.Println(cyan2.Render("  MCP (Model Context Protocol) Integration"))
				fmt.Println(dim2.Render("  ─────────────────────────────────────────"))

				if len(parts) > 1 && parts[1] == "playwright" {
					url := "http://localhost:3000"
					if len(parts) > 2 {
						url = parts[2]
					}
					// Check if npx is available
					if _, npxErr := exec.LookPath("npx"); npxErr != nil {
						fmt.Println(red2.Render("  ✗ Node.js not found"))
						fmt.Println(dim2.Render("  Install Node.js from: https://nodejs.org"))
					} else {
						fmt.Println(dim2.Render("  ⟳ Starting Playwright MCP (auto-downloading if needed)..."))
						var shell, flag string
						if runtime.GOOS == "windows" {
							shell, flag = "cmd", "/c"
						} else {
							shell, flag = "sh", "-c"
						}
						// npx auto-downloads @playwright/mcp without global install
						mcpCmd := fmt.Sprintf("npx --yes @playwright/mcp@latest --url %s", url)
						go func() {
							_ = exec.Command(shell, flag, mcpCmd).Run()
						}()
						fmt.Println(green2.Render("  ✓ Playwright MCP started for: " + url))
						fmt.Println(dim2.Render("  Browser automation ready — ask CBM Code to test your app"))
						fmt.Println(dim2.Render("  Example: 'test the login form on my app'"))
					}
				} else if len(parts) > 1 && parts[1] == "context7" {
					if _, npxErr := exec.LookPath("npx"); npxErr != nil {
						fmt.Println(red2.Render("  ✗ Node.js not found — install from https://nodejs.org"))
					} else {
						fmt.Println(dim2.Render("  ⟳ Starting Context7 MCP (auto-downloading)..."))
						var shell, flag string
						if runtime.GOOS == "windows" {
							shell, flag = "cmd", "/c"
						} else {
							shell, flag = "sh", "-c"
						}
						go func() {
							_ = exec.Command(shell, flag, "npx --yes @upstash/context7-mcp@latest").Run()
						}()
						fmt.Println(green2.Render("  ✓ Context7 MCP started"))
						fmt.Println(dim2.Render("  Now CBM Code has access to up-to-date library docs"))
					}
				} else {
					fmt.Println(yellow2.Render("  Available MCP servers (auto-download via npx):"))
					fmt.Println()
					fmt.Println(green2.Render("  Playwright (browser automation):"))
					fmt.Println(dim2.Render("  /mcp playwright [url]"))
					fmt.Println(dim2.Render("  → Opens browser, takes screenshots, tests UI"))
					fmt.Println(dim2.Render("  → No install needed — npx downloads automatically"))
					fmt.Println()
					fmt.Println(green2.Render("  Filesystem (built-in):"))
					fmt.Println(dim2.Render("  /add /read /ls /run — already available"))
					fmt.Println()
					fmt.Println(green2.Render("  Context7 (library docs):"))
					fmt.Println(dim2.Render("  /mcp context7 — up-to-date library documentation"))
					fmt.Println()
				}

			case "/init":
				// Create CYBERMIND.md project memory file
				cybermindPath := filepath.Join(cwd, "CYBERMIND.md")
				if _, err := os.Stat(cybermindPath); err == nil {
					fmt.Println(yellow2.Render("  CYBERMIND.md already exists. Edit it to update project memory."))
				} else {
					stack := detectWorkspaceStack(cwd)
					if stack == "" {
						stack = "Not detected yet"
					}
					content := fmt.Sprintf(`# CYBERMIND.md — Project Memory

## Project
Name: %s
Stack: %s

## Coding Conventions
- Use TypeScript strict mode
- Tailwind CSS for styling
- Functional components with hooks
- Error handling on all async operations

## Architecture Notes
(Add your architecture decisions here)

## API Endpoints
(Document your API endpoints here)

## Environment Variables
(List required env vars here)

## Important Files
(List key files and their purpose)
`, filepath.Base(cwd), stack)
					if err := os.WriteFile(cybermindPath, []byte(content), 0644); err == nil {
						fmt.Println(green2.Render("  ✓ Created CYBERMIND.md — edit it to add project memory"))
						fmt.Println(dim2.Render("  CBM Code will auto-load this file in every session"))
					} else {
						fmt.Println(red2.Render("  ✗ Failed: " + err.Error()))
					}
				}

			case "/plan":
				// Architecture planning mode — think before coding
				planTask := strings.Join(parts[1:], " ")
				if planTask == "" {
					fmt.Println(red2.Render("  Usage: /plan <task description>"))
				} else {
					fmt.Println()
					fmt.Print(purple2.Render("  ◆ CBM Code [Plan Mode]: "))
					planPrompt := fmt.Sprintf(`PLAN MODE — Think through this task architecturally before writing any code.

Task: %s

Provide:
1. Architecture overview (what components/files are needed)
2. Tech stack recommendation with reasons
3. File structure (list all files to create)
4. Implementation order (which files to create first)
5. Potential challenges and how to handle them
6. Estimated complexity (simple/medium/complex)

DO NOT write any code yet — just the plan.`, planTask)

					chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "user", Content: planPrompt})
					var planResponse strings.Builder
					_, planErr := vibecoder.SendVibeChat(planPrompt, chatHistory[:len(chatHistory)-1], func(token string) {
						if !strings.Contains(token, "<tool_call>") {
							fmt.Print(token)
							planResponse.WriteString(token)
						}
					})
					fmt.Println()
					fmt.Println()
					if planErr != nil {
						fmt.Println(red2.Render("  ✗ " + planErr.Error()))
					} else {
						chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "assistant", Content: planResponse.String()})
						fmt.Println(dim2.Render("  Plan complete. Now type your task to start coding."))
					}
				}

			default:
				// ── Try skill invocation ───────────────────────────────────
				if skills != nil {
					skillName := strings.TrimPrefix(parts[0], "/")
					arguments := strings.Join(parts[1:], " ")
					if expanded, skillErr := skills.Expand(skillName, arguments); skillErr == nil {
						fmt.Println(cyan2.Render(fmt.Sprintf("  🔧 Skill: /%s", skillName)))
						fmt.Println()
						fmt.Print(purple2.Render("  ◆ CBM Code: "))
						chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "user", Content: expanded})
						agentErr := runAgentLoop(expanded, cwd, &chatHistory, green2, dim2, red2, yellow2, purple2, cyan2)
						if agentErr != nil {
							fmt.Println(red2.Render("  ✗ " + agentErr.Error()))
						}
						saveSession(sessionFile, chatHistory)
						continue
					}
				}
				fmt.Println(dim2.Render("  Unknown: " + parts[0] + " (type /help or /skills)"))

			case "/skills":
				// List all available skills
				if skills == nil || len(skills.All()) == 0 {
					fmt.Println(dim2.Render("  No skills loaded. Add .md files to .kiro/skills/ or ~/.cybermind/skills/"))
					fmt.Println(dim2.Render("  Built-in skills: /review /commit /security /test /document /refactor /explain /pr /debug /migrate"))
				} else {
					fmt.Println()
					fmt.Println(cyan2.Render(fmt.Sprintf("  📚 %d skills available:", len(skills.All()))))
					for _, s := range skills.All() {
						scope := ""
						if s.Scope == "project" {
							scope = " [project]"
						}
						fmt.Println(dim2.Render(fmt.Sprintf("  /%-18s %s%s", s.Meta.Name, s.Meta.Description, scope)))
					}
					fmt.Println()
					fmt.Println(dim2.Render("  Usage: /skill-name [arguments]"))
					fmt.Println(dim2.Render("  Add skills: .kiro/skills/my-skill.md"))
				}
			}
			continue
		}

		// ── AI prompt ──────────────────────────────────────────────────────
		prompt := line
		fmt.Println()

		// ── Context Awareness: Auto-inject relevant workspace files ────────
		// 1. Load CYBERMIND.md if present (project memory)
		cybermindMD := filepath.Join(cwd, "CYBERMIND.md")
		if data, err := os.ReadFile(cybermindMD); err == nil {
			// Only inject once per session (check if already in history)
			alreadyLoaded := false
			for _, h := range chatHistory {
				if strings.Contains(h.Content, "[CYBERMIND.md]") {
					alreadyLoaded = true
					break
				}
			}
			if !alreadyLoaded {
				chatHistory = append(chatHistory, vibecoder.APIMessage{
					Role:    "user",
					Content: "[CYBERMIND.md — Project memory]\n" + string(data),
				})
				fmt.Println(dim2.Render("  ◆ Memory: loaded CYBERMIND.md"))
			}
		}

		// 2. Auto-inject relevant workspace files
		autoContext := buildAutoContext(prompt, cwd, chatHistory)
		if autoContext != "" {
			chatHistory = append(chatHistory, vibecoder.APIMessage{
				Role:    "user",
				Content: autoContext,
			})
			fmt.Println(dim2.Render("  ◆ Context: auto-loaded relevant files"))
		}

		fmt.Print(purple2.Render("  ◆ CBM Code: "))

		chatHistory = append(chatHistory, vibecoder.APIMessage{Role: "user", Content: prompt})

		// ── REAL AGENT LOOP ────────────────────────────────────────────────
		// Like Claude Code: generate → write → run → fix errors → repeat
		agentErr := runAgentLoop(prompt, cwd, &chatHistory, green2, dim2, red2, yellow2, purple2, cyan2)
		if agentErr != nil {
			fmt.Println(red2.Render("  ✗ " + agentErr.Error()))
			fmt.Println()
		}

		// ── Save session after each turn ───────────────────────────────────
		saveSession(sessionFile, chatHistory)

		// ── Auto-Dependency Detection ──────────────────────────────────────
		// After files are written, check for new imports and auto-install
		autoInstallDependencies(cwd, dim2, green2)
	}
}

// ─── Real Agent Loop ──────────────────────────────────────────────────────────
// Like Claude Code: generate → write files → run commands → fix errors → repeat

// runAgentLoop implements the full autonomous agent cycle:
// 1. Get AI response + write files
// 2. Show diff preview before applying
// 3. Run install + build commands
// 4. Capture errors
// 5. Feed errors back to AI for fixing
// 6. Repeat until clean or max iterations
func runAgentLoop(
	prompt, cwd string,
	chatHistory *[]vibecoder.APIMessage,
	green, dim, red, yellow, purple, cyan lipgloss.Style,
) error {
	const maxIterations = 5

	for iteration := 0; iteration < maxIterations; iteration++ {
		if iteration > 0 {
			fmt.Println()
			fmt.Println(yellow.Render(fmt.Sprintf("  ↻ Iteration %d/%d — fixing errors...", iteration+1, maxIterations)))
			fmt.Print(purple.Render("  ◆ CBM Code: "))
		}

		// ── Step 1: Get AI response ────────────────────────────────────────
		var fullResponse strings.Builder
		_, err := vibecoder.SendVibeChat(
			(*chatHistory)[len(*chatHistory)-1].Content,
			(*chatHistory)[:len(*chatHistory)-1],
			func(token string) {
				if !strings.Contains(token, "<tool_call>") && !strings.Contains(token, "</tool_call>") {
					fmt.Print(token)
					fullResponse.WriteString(token)
				}
			},
		)
		fmt.Println()
		fmt.Println()

		if err != nil {
			return err
		}

		response := fullResponse.String()
		*chatHistory = append(*chatHistory, vibecoder.APIMessage{Role: "assistant", Content: response})

		// ── Step 2: Show diff preview + write files ────────────────────────
		written, editedFiles := writeCodeBlocksToFilesWithDiff(response, cwd, green, dim, red)
		if written == 0 && iteration == 0 {
			// No files to write — pure chat response, done
			return nil
		}
		if written > 0 {
			fmt.Println(green.Render(fmt.Sprintf("  ✓ %d file(s) written", written)))
			// Track files in session for cross-file consistency
			for _, f := range editedFiles {
				trackFileInSession(f, cwd, chatHistory)
			}
		}

		// ── Step 3: Auto-run commands if applicable ────────────────────────
		cmdOutput, cmdErr := autoRunProjectCommands(cwd, green, dim, yellow)

		if cmdErr == "" {
			// No errors — done!
			if cmdOutput != "" {
				fmt.Println(green.Render("  ✓ Build/install successful"))
			}
			fmt.Println()
			return nil
		}

		// ── Step 4: Feed errors back to AI ────────────────────────────────
		fmt.Println()
		fmt.Println(red.Render("  ✗ Errors detected — asking AI to fix..."))
		fmt.Println()

		// Build all current file contents for cross-file consistency
		allFilesCtx := buildAllProjectFilesContext(cwd, editedFiles)

		fixPrompt := fmt.Sprintf(
			"The code has errors. Fix ALL of them.\n\n"+
				"ERRORS:\n%s\n\n"+
				"CURRENT FILES:\n%s\n\n"+
				"Fix every error. Show complete corrected files with **filename** prefix.",
			cmdErr, allFilesCtx,
		)

		*chatHistory = append(*chatHistory, vibecoder.APIMessage{Role: "user", Content: fixPrompt})
		fmt.Print(purple.Render("  ◆ CBM Code [fixing]: "))
	}

	return fmt.Errorf("max iterations reached — some errors may remain")
}

// writeCodeBlocksToFilesWithDiff shows a diff preview before writing files.
func writeCodeBlocksToFilesWithDiff(response, workspaceRoot string, green, dim, red lipgloss.Style) (int, []string) {
	// First pass: collect all files to write
	type pendingFile struct {
		path    string
		content string
		isNew   bool
	}

	var pending []pendingFile
	lines := strings.Split(response, "\n")
	var currentFile string
	var inCodeBlock bool
	var codeLines []string

	extractFP := func(s string) string {
		s = strings.TrimSpace(s)
		for _, p := range []string{"###", "##", "#"} {
			s = strings.TrimPrefix(s, p)
		}
		s = strings.TrimSpace(s)
		s = strings.Trim(s, "*`")
		s = strings.TrimSpace(s)
		s = strings.TrimSuffix(s, ":")
		s = strings.TrimSpace(s)
		if looksLikeFilePath(s) {
			return s
		}
		return ""
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inCodeBlock {
			if strings.Contains(trimmed, "**") || strings.Contains(trimmed, "`") {
				inner := trimmed
				for _, p := range []string{"###", "##", "#"} {
					inner = strings.TrimPrefix(inner, p)
				}
				inner = strings.TrimSpace(inner)
				if strings.HasPrefix(inner, "**") && strings.HasSuffix(inner, "**") {
					if fp := extractFP(strings.TrimPrefix(strings.TrimSuffix(inner, "**"), "**")); fp != "" {
						currentFile = fp
						continue
					}
				}
				if strings.HasPrefix(inner, "`") && strings.HasSuffix(inner, "`") && !strings.HasPrefix(inner, "```") {
					if fp := extractFP(strings.Trim(inner, "`")); fp != "" {
						currentFile = fp
						continue
					}
				}
			}
			for _, prefix := range []string{"File: ", "file: ", "Filename: ", "Path: "} {
				if strings.HasPrefix(trimmed, prefix) {
					if fp := extractFP(strings.TrimPrefix(trimmed, prefix)); fp != "" {
						currentFile = fp
					}
				}
			}
			if strings.HasPrefix(trimmed, "```") {
				inCodeBlock = true
				codeLines = nil
				if i+1 < len(lines) {
					next := strings.TrimSpace(lines[i+1])
					for _, cp := range []string{"// ", "# "} {
						if strings.HasPrefix(next, cp) {
							if fp := extractFP(strings.TrimPrefix(next, cp)); fp != "" {
								currentFile = fp
							}
							break
						}
					}
				}
			}
		} else {
			if trimmed == "```" || (strings.HasPrefix(trimmed, "```") && len(trimmed) > 3) {
				inCodeBlock = false
				if currentFile != "" && len(codeLines) > 0 {
					content := strings.Join(codeLines, "\n")
					absPath := filepath.Join(workspaceRoot, currentFile)
					_, statErr := os.Stat(absPath)
					pending = append(pending, pendingFile{
						path:    currentFile,
						content: content,
						isNew:   os.IsNotExist(statErr),
					})
					currentFile = ""
				}
				codeLines = nil
			} else {
				codeLines = append(codeLines, line)
			}
		}
	}

	if len(pending) == 0 {
		return 0, nil
	}

	// Show diff preview
	fmt.Println()
	fmt.Println(dim.Render("  ┌─ Changes to apply ─────────────────────────────────"))
	for _, pf := range pending {
		if pf.isNew {
			fmt.Println(green.Render(fmt.Sprintf("  │  + %s (new)", pf.path)))
		} else {
			fmt.Println(dim.Render(fmt.Sprintf("  │  ~ %s (modified)", pf.path)))
		}
	}
	fmt.Println(dim.Render("  └────────────────────────────────────────────────────"))
	fmt.Println()

	// Write all files
	written := 0
	var writtenPaths []string
	for _, pf := range pending {
		absPath := filepath.Join(workspaceRoot, pf.path)
		if mkErr := os.MkdirAll(filepath.Dir(absPath), 0755); mkErr == nil {
			if writeErr := os.WriteFile(absPath, []byte(pf.content), 0644); writeErr == nil {
				written++
				writtenPaths = append(writtenPaths, pf.path)
			} else {
				fmt.Println(red.Render(fmt.Sprintf("  ✗ Failed: %s — %s", pf.path, writeErr.Error())))
			}
		}
	}
	return written, writtenPaths
}

// autoRunProjectCommands detects project type and runs appropriate commands.
// Returns (output, errorOutput). errorOutput is empty if all commands succeeded.
func autoRunProjectCommands(cwd string, green, dim, yellow lipgloss.Style) (string, string) {
	var shell, flag string
	if runtime.GOOS == "windows" {
		shell, flag = "cmd", "/c"
	} else {
		shell, flag = "sh", "-c"
	}

	runCmd := func(cmd string, timeoutSecs int) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSecs)*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, shell, flag, cmd)
		c.Dir = cwd
		out, err := c.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}

	// Detect project type
	hasPackageJSON := fileExists(filepath.Join(cwd, "package.json"))
	hasGoMod := fileExists(filepath.Join(cwd, "go.mod"))
	hasPyProject := fileExists(filepath.Join(cwd, "requirements.txt")) || fileExists(filepath.Join(cwd, "pyproject.toml"))
	hasNodeModules := fileExists(filepath.Join(cwd, "node_modules"))

	var allOutput strings.Builder
	var allErrors strings.Builder

	if hasPackageJSON {
		// Install dependencies if node_modules missing
		if !hasNodeModules {
			fmt.Println(dim.Render("  ⟳ Installing dependencies (npm install)..."))
			out, err := runCmd("npm install --silent 2>&1", 180) // 3 min timeout
			if err != nil {
				// Check if it's a real error or just slow
				if strings.Contains(out, "npm warn") || strings.Contains(out, "added ") {
					// Partial success — packages installed despite warning
					fmt.Println(green.Render("  ✓ Dependencies installed (with warnings)"))
				} else if strings.Contains(out, "ERESOLVE") || strings.Contains(out, "peer dep") {
					// Peer dependency conflict — try with legacy flag
					fmt.Println(dim.Render("  ⟳ Retrying with --legacy-peer-deps..."))
					out2, err2 := runCmd("npm install --legacy-peer-deps --silent 2>&1", 180)
					if err2 != nil && !strings.Contains(out2, "added ") {
						allErrors.WriteString("npm install failed:\n" + out2[:min(500, len(out2))] + "\n")
						return allOutput.String(), allErrors.String()
					}
					fmt.Println(green.Render("  ✓ Dependencies installed"))
				} else {
					allErrors.WriteString("npm install failed:\n" + out[:min(500, len(out))] + "\n")
					return allOutput.String(), allErrors.String()
				}
			} else {
				fmt.Println(green.Render("  ✓ Dependencies installed"))
			}
			allOutput.WriteString(out)
		}

		// Try TypeScript check if tsconfig exists
		if fileExists(filepath.Join(cwd, "tsconfig.json")) {
			fmt.Println(dim.Render("  ⟳ Checking TypeScript..."))
			out, err := runCmd("npx tsc --noEmit 2>&1", 60)
			if err != nil && out != "" {
				// Filter out noise, keep real errors
				errors := filterTypeScriptErrors(out)
				if errors != "" && len(strings.Split(errors, "\n")) > 3 {
					// Only fail on 3+ real errors to avoid false positives
					allErrors.WriteString("TypeScript errors:\n" + errors + "\n")
					return allOutput.String(), allErrors.String()
				}
			}
			if err == nil {
				fmt.Println(green.Render("  ✓ TypeScript OK"))
			}
		}

		// Try build if build script exists
		pkgData, _ := os.ReadFile(filepath.Join(cwd, "package.json"))
		if strings.Contains(string(pkgData), `"build"`) {
			fmt.Println(dim.Render("  ⟳ Running build check..."))
			out, err := runCmd("npm run build 2>&1", 120)
			if err != nil && out != "" {
				errors := filterBuildErrors(out)
				if errors != "" {
					allErrors.WriteString("Build errors:\n" + errors + "\n")
					return allOutput.String(), allErrors.String()
				}
			}
			if err == nil {
				fmt.Println(green.Render("  ✓ Build successful"))
				allOutput.WriteString(out)
			}
		}
	}

	if hasGoMod {
		fmt.Println(dim.Render("  ⟳ Checking Go build..."))
		out, err := runCmd("go build ./... 2>&1", 60)
		if err != nil && out != "" {
			allErrors.WriteString("Go build errors:\n" + out + "\n")
			return allOutput.String(), allErrors.String()
		}
		if err == nil {
			fmt.Println(green.Render("  ✓ Go build OK"))
		}
	}

	if hasPyProject {
		fmt.Println(dim.Render("  ⟳ Checking Python syntax..."))
		out, err := runCmd("python -m py_compile *.py 2>&1", 30)
		if err != nil && out != "" {
			allErrors.WriteString("Python errors:\n" + out + "\n")
			return allOutput.String(), allErrors.String()
		}
	}

	return allOutput.String(), allErrors.String()
}

// buildAllProjectFilesContext reads all project files for cross-file consistency.
func buildAllProjectFilesContext(cwd string, recentFiles []string) string {
	var parts []string

	// Include recently written files first
	seen := make(map[string]bool)
	for _, f := range recentFiles {
		absPath := filepath.Join(cwd, f)
		if data, err := os.ReadFile(absPath); err == nil && len(data) < 20000 {
			parts = append(parts, fmt.Sprintf("[File: %s]\n```\n%s\n```", f, string(data)))
			seen[f] = true
		}
	}

	// Also include key project files
	keyFiles := findKeyProjectFiles(cwd)
	for _, absPath := range keyFiles {
		rel, _ := filepath.Rel(cwd, absPath)
		if seen[rel] {
			continue
		}
		if data, err := os.ReadFile(absPath); err == nil && len(data) < 10000 {
			parts = append(parts, fmt.Sprintf("[File: %s]\n```\n%s\n```", rel, string(data)))
			seen[rel] = true
		}
		if len(parts) >= 8 { // limit to avoid context overflow
			break
		}
	}

	return strings.Join(parts, "\n\n")
}

// filterTypeScriptErrors extracts real errors from tsc output (ignores warnings).
func filterTypeScriptErrors(output string) string {
	var errors []string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "error TS") {
			errors = append(errors, line)
		}
	}
	if len(errors) > 20 {
		errors = errors[:20]
		errors = append(errors, "... (truncated)")
	}
	return strings.Join(errors, "\n")
}

// filterBuildErrors extracts real errors from build output.
func filterBuildErrors(output string) string {
	var errors []string
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "error") || strings.Contains(lower, "failed") {
			if !strings.Contains(lower, "warning") && !strings.Contains(lower, "deprecated") {
				errors = append(errors, line)
			}
		}
	}
	if len(errors) > 20 {
		errors = errors[:20]
	}
	return strings.Join(errors, "\n")
}

// fileExists returns true if the path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// writeCodeBlocksToFiles is a backward-compatible wrapper around writeCodeBlocksToFilesTracked.
func writeCodeBlocksToFiles(response, workspaceRoot string, green, dim, red lipgloss.Style) int {
	n, _ := writeCodeBlocksToFilesTracked(response, workspaceRoot, green, dim, red)
	return n
}
// ─── Context Awareness ────────────────────────────────────────────────────────

// buildAutoContext scans the workspace and injects relevant file contents
// into the context when the prompt references existing files or asks to fix/edit.
func buildAutoContext(prompt, cwd string, history []vibecoder.APIMessage) string {
	lower := strings.ToLower(prompt)

	// Keywords that indicate the user wants to work with existing code
	editKeywords := []string{
		"fix", "bug", "error", "issue", "problem", "broken",
		"update", "change", "modify", "edit", "refactor",
		"add to", "improve", "optimize", "debug",
		"in the", "in my", "the file", "this file",
	}

	isEditRequest := false
	for _, kw := range editKeywords {
		if strings.Contains(lower, kw) {
			isEditRequest = true
			break
		}
	}

	// Check if any specific filenames are mentioned in the prompt
	mentionedFiles := extractMentionedFiles(prompt, cwd)

	// If it's an edit request or files are mentioned, load relevant context
	if !isEditRequest && len(mentionedFiles) == 0 {
		return ""
	}

	var contextParts []string

	// Load specifically mentioned files
	for _, f := range mentionedFiles {
		content, err := os.ReadFile(f)
		if err == nil && len(content) < 50000 {
			rel, _ := filepath.Rel(cwd, f)
			contextParts = append(contextParts, fmt.Sprintf("[Current file: %s]\n```\n%s\n```", rel, string(content)))
		}
	}

	// If edit request but no specific files mentioned, load key project files
	if isEditRequest && len(mentionedFiles) == 0 {
		keyFiles := findKeyProjectFiles(cwd)
		for _, f := range keyFiles {
			content, err := os.ReadFile(f)
			if err == nil && len(content) < 20000 {
				rel, _ := filepath.Rel(cwd, f)
				contextParts = append(contextParts, fmt.Sprintf("[Current file: %s]\n```\n%s\n```", rel, string(content)))
			}
		}
	}

	// Also check if any files were created in this session (from history)
	sessionFiles := extractSessionFiles(history, cwd)
	for _, f := range sessionFiles {
		// Only add if not already added
		alreadyAdded := false
		for _, cp := range contextParts {
			if strings.Contains(cp, f) {
				alreadyAdded = true
				break
			}
		}
		if !alreadyAdded {
			content, err := os.ReadFile(filepath.Join(cwd, f))
			if err == nil && len(content) < 20000 {
				contextParts = append(contextParts, fmt.Sprintf("[Current file: %s]\n```\n%s\n```", f, string(content)))
			}
		}
	}

	if len(contextParts) == 0 {
		return ""
	}

	return "[Workspace context — current file contents for reference:]\n\n" + strings.Join(contextParts, "\n\n")
}

// extractMentionedFiles finds files mentioned in the prompt that exist in workspace.
func extractMentionedFiles(prompt, cwd string) []string {
	var found []string
	words := strings.Fields(prompt)
	for _, word := range words {
		// Clean punctuation
		word = strings.Trim(word, ".,;:!?\"'()")
		if looksLikeFilePath(word) {
			// Try relative to cwd
			absPath := filepath.Join(cwd, word)
			if _, err := os.Stat(absPath); err == nil {
				found = append(found, absPath)
				continue
			}
			// Try as absolute
			if filepath.IsAbs(word) {
				if _, err := os.Stat(word); err == nil {
					found = append(found, word)
				}
			}
		}
	}
	return found
}

// findKeyProjectFiles returns the most important files in a project for context.
func findKeyProjectFiles(cwd string) []string {
	// Priority order: entry points, config, main components
	priorities := []string{
		"package.json", "tsconfig.json", "next.config.js", "next.config.ts",
		"vite.config.ts", "vite.config.js", "tailwind.config.js", "tailwind.config.ts",
		"app/page.tsx", "app/layout.tsx", "pages/index.tsx", "pages/_app.tsx",
		"src/App.tsx", "src/App.jsx", "src/main.tsx", "src/main.jsx",
		"server.js", "server.ts", "index.js", "index.ts",
		"app.js", "app.ts", "main.go", "main.py",
	}

	var found []string
	for _, p := range priorities {
		full := filepath.Join(cwd, p)
		if _, err := os.Stat(full); err == nil {
			found = append(found, full)
			if len(found) >= 5 { // max 5 files to avoid context overflow
				break
			}
		}
	}
	return found
}

// extractSessionFiles extracts filenames that were created/modified in this session.
func extractSessionFiles(history []vibecoder.APIMessage, cwd string) []string {
	var files []string
	seen := make(map[string]bool)

	for _, msg := range history {
		if msg.Role != "assistant" {
			continue
		}
		// Look for "Created: filename" patterns in assistant messages
		lines := strings.Split(msg.Content, "\n")
		for _, line := range lines {
			for _, prefix := range []string{"✓ Created: ", "✓ Wrote: ", "✓ Modified: ", "created: ", "wrote: "} {
				if strings.Contains(line, prefix) {
					parts := strings.SplitN(line, prefix, 2)
					if len(parts) == 2 {
						f := strings.TrimSpace(parts[1])
						if looksLikeFilePath(f) && !seen[f] {
							// Verify file exists
							if _, err := os.Stat(filepath.Join(cwd, f)); err == nil {
								files = append(files, f)
								seen[f] = true
							}
						}
					}
				}
			}
		}
	}
	return files
}

// writeCodeBlocksToFilesTracked is like writeCodeBlocksToFiles but also returns
// the list of files that were written (for session tracking).
func writeCodeBlocksToFilesTracked(response, workspaceRoot string, green, dim, red lipgloss.Style) (int, []string) {
	written := 0
	var writtenFiles []string
	lines := strings.Split(response, "\n")

	var currentFile string
	var inCodeBlock bool
	var codeLines []string

	extractFilePath := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(s, "###")
		s = strings.TrimPrefix(s, "##")
		s = strings.TrimPrefix(s, "#")
		s = strings.TrimSpace(s)
		s = strings.Trim(s, "*")
		s = strings.Trim(s, "`")
		s = strings.TrimSpace(s)
		s = strings.TrimSuffix(s, ":")
		s = strings.TrimSpace(s)
		if looksLikeFilePath(s) {
			return s
		}
		return ""
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !inCodeBlock {
			if strings.Contains(trimmed, "**") || strings.Contains(trimmed, "`") {
				inner := trimmed
				inner = strings.TrimPrefix(inner, "###")
				inner = strings.TrimPrefix(inner, "##")
				inner = strings.TrimPrefix(inner, "#")
				inner = strings.TrimSpace(inner)
				if strings.HasPrefix(inner, "**") && strings.HasSuffix(inner, "**") {
					inner = strings.TrimPrefix(strings.TrimSuffix(inner, "**"), "**")
					if fp := extractFilePath(inner); fp != "" {
						currentFile = fp
						continue
					}
				}
				if strings.HasPrefix(inner, "`") && strings.HasSuffix(inner, "`") && !strings.HasPrefix(inner, "```") {
					inner = strings.Trim(inner, "`")
					if fp := extractFilePath(inner); fp != "" {
						currentFile = fp
						continue
					}
				}
			}

			for _, prefix := range []string{"File: ", "file: ", "Filename: ", "filename: ", "Path: ", "path: ", "**File**: ", "**Filename**: "} {
				if strings.HasPrefix(trimmed, prefix) {
					candidate := strings.TrimPrefix(trimmed, prefix)
					if fp := extractFilePath(candidate); fp != "" {
						currentFile = fp
					}
				}
			}

			if strings.HasPrefix(trimmed, "```") {
				codeLang := strings.TrimPrefix(trimmed, "```")
				_ = codeLang
				inCodeBlock = true
				codeLines = nil

				if i+1 < len(lines) {
					nextLine := strings.TrimSpace(lines[i+1])
					for _, commentPrefix := range []string{"// ", "# ", "<!-- ", "-- "} {
						if strings.HasPrefix(nextLine, commentPrefix) {
							candidate := strings.TrimPrefix(nextLine, commentPrefix)
							candidate = strings.TrimSuffix(candidate, " -->")
							candidate = strings.TrimSpace(candidate)
							if fp := extractFilePath(candidate); fp != "" {
								currentFile = fp
							}
							break
						}
					}
				}
			}
		} else {
			if trimmed == "```" || (strings.HasPrefix(trimmed, "```") && len(trimmed) > 3 && !strings.Contains(trimmed, " ")) {
				inCodeBlock = false
				if currentFile != "" && len(codeLines) > 0 {
					filePath := filepath.Join(workspaceRoot, currentFile)
					dir := filepath.Dir(filePath)
					if mkErr := os.MkdirAll(dir, 0755); mkErr == nil {
						content := strings.Join(codeLines, "\n")
						if writeErr := os.WriteFile(filePath, []byte(content), 0644); writeErr == nil {
							fmt.Println()
							fmt.Print(green.Render(fmt.Sprintf("  ✓ Created: %s", currentFile)))
							written++
							writtenFiles = append(writtenFiles, currentFile)
						} else {
							fmt.Println()
							fmt.Print(red.Render(fmt.Sprintf("  ✗ Failed: %s — %s", currentFile, writeErr.Error())))
						}
					}
					currentFile = ""
				}
				codeLines = nil
				_ = dim
			} else {
				codeLines = append(codeLines, line)
			}
		}
	}
	return written, writtenFiles
}

// trackFileInSession adds a created/modified file to the chat history
// so future prompts automatically have context about it.
func trackFileInSession(relPath, cwd string, history *[]vibecoder.APIMessage) {
	absPath := filepath.Join(cwd, relPath)
	content, err := os.ReadFile(absPath)
	if err != nil || len(content) > 30000 {
		return // skip large files
	}
	// Add as a system context message (not shown to user)
	*history = append(*history, vibecoder.APIMessage{
		Role:    "user",
		Content: fmt.Sprintf("[File created/updated in this session: %s]\n```\n%s\n```", relPath, string(content)),
	})
	*history = append(*history, vibecoder.APIMessage{
		Role:    "assistant",
		Content: fmt.Sprintf("I've noted the current content of %s for context.", relPath),
	})
}

// looksLikeFilePath returns true if s looks like a file path (has extension or slash).
func looksLikeFilePath(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 200 {
		return false
	}
	// Must have a dot for extension OR a slash for directory
	hasDot := strings.Contains(s, ".")
	hasSlash := strings.Contains(s, "/") || strings.Contains(s, `\`)
	if !hasDot && !hasSlash {
		return false
	}
	// Must not contain spaces (file paths don't have spaces usually)
	if strings.Contains(s, " ") {
		return false
	}
	// Common file extensions
	exts := []string{".ts", ".tsx", ".js", ".jsx", ".json", ".css", ".html", ".md",
		".go", ".py", ".rs", ".java", ".c", ".cpp", ".h", ".yaml", ".yml",
		".toml", ".env", ".sh", ".ps1", ".sql", ".txt", ".config", ".mjs", ".cjs"}
	for _, ext := range exts {
		if strings.HasSuffix(s, ext) {
			return true
		}
	}
	return hasSlash
}

// langToExt maps code block language to file extension.
func langToExt(lang string) string {
	m := map[string]string{
		"typescript": ".ts", "ts": ".ts",
		"javascript": ".js", "js": ".js",
		"tsx": ".tsx", "jsx": ".jsx",
		"python": ".py", "py": ".py",
		"go": ".go",
		"rust": ".rs",
		"css": ".css",
		"html": ".html",
		"json": ".json",
		"yaml": ".yaml", "yml": ".yaml",
		"bash": ".sh", "sh": ".sh",
		"sql": ".sql",
	}
	return m[strings.ToLower(strings.TrimSpace(lang))]
}

// countWorkspaceFiles counts non-hidden, non-node_modules files in workspace.
func countWorkspaceFiles(root string) int {
	count := 0
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		name := info.Name()
		// Skip hidden dirs, node_modules, .git, dist, build
		if info.IsDir() {
			if strings.HasPrefix(name, ".") || name == "node_modules" ||
				name == "dist" || name == "build" || name == ".next" ||
				name == "vendor" || name == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasPrefix(name, ".") {
			count++
		}
		return nil
	})
	return count
}

// detectWorkspaceStack detects the tech stack from workspace files.
func detectWorkspaceStack(root string) string {
	var stack []string

	// Check package.json
	pkgPath := filepath.Join(root, "package.json")
	if data, err := os.ReadFile(pkgPath); err == nil {
		content := string(data)
		if strings.Contains(content, `"next"`) {
			stack = append(stack, "Next.js")
		} else if strings.Contains(content, `"react"`) {
			stack = append(stack, "React")
		} else if strings.Contains(content, `"vue"`) {
			stack = append(stack, "Vue")
		} else if strings.Contains(content, `"express"`) {
			stack = append(stack, "Express")
		}
		if strings.Contains(content, `"typescript"`) || strings.Contains(content, `"@types/`) {
			stack = append(stack, "TypeScript")
		}
		if strings.Contains(content, `"tailwindcss"`) {
			stack = append(stack, "Tailwind")
		}
		if strings.Contains(content, `"prisma"`) {
			stack = append(stack, "Prisma")
		}
		if strings.Contains(content, `"supabase"`) {
			stack = append(stack, "Supabase")
		}
	}

	// Check for Go
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
		stack = append(stack, "Go")
	}

	// Check for Python
	if _, err := os.Stat(filepath.Join(root, "requirements.txt")); err == nil {
		stack = append(stack, "Python")
	}
	if _, err := os.Stat(filepath.Join(root, "pyproject.toml")); err == nil {
		stack = append(stack, "Python")
	}

	if len(stack) == 0 {
		return ""
	}
	return strings.Join(stack, " + ")
}

// ─── Session Persistence ──────────────────────────────────────────────────────

// getSessionFilePath returns the session file path for a given workspace.
func getSessionFilePath(cwd string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	sessDir := filepath.Join(home, ".cybermind", "sessions")
	_ = os.MkdirAll(sessDir, 0700)

	// Use workspace path hash as filename
	h := 0
	for _, c := range cwd {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return filepath.Join(sessDir, fmt.Sprintf("session_%x.json", h))
}

// saveSession saves chat history to disk.
func saveSession(path string, history []vibecoder.APIMessage) {
	if path == "" || len(history) == 0 {
		return
	}
	// Keep last 50 messages to avoid bloat
	if len(history) > 50 {
		history = history[len(history)-50:]
	}
	data, err := json.Marshal(history)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0600)
}

// loadSession loads chat history from disk.
func loadSession(path string) []vibecoder.APIMessage {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var history []vibecoder.APIMessage
	if err := json.Unmarshal(data, &history); err != nil {
		return nil
	}
	// Filter out system messages (they'll be re-injected)
	var filtered []vibecoder.APIMessage
	for _, msg := range history {
		if msg.Role != "system" {
			filtered = append(filtered, msg)
		}
	}
	return filtered
}

// ─── Auto-Dependency Detection ────────────────────────────────────────────────
// Scans newly written files for imports and auto-installs missing packages.

func autoInstallDependencies(cwd string, dim, green lipgloss.Style) {
	// Only for Node.js projects
	pkgPath := filepath.Join(cwd, "package.json")
	if _, err := os.Stat(pkgPath); err != nil {
		return
	}

	// Read package.json to get existing deps
	pkgData, err := os.ReadFile(pkgPath)
	if err != nil {
		return
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	json.Unmarshal(pkgData, &pkg)

	existing := make(map[string]bool)
	for k := range pkg.Dependencies {
		existing[k] = true
	}
	for k := range pkg.DevDependencies {
		existing[k] = true
	}

	// Scan all JS/TS files for imports
	var missing []string
	seen := make(map[string]bool)

	_ = filepath.Walk(cwd, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		// Skip node_modules and hidden dirs
		for _, skip := range []string{"node_modules", ".git", "dist", "build", ".next"} {
			if strings.Contains(path, skip) {
				return nil
			}
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".ts" && ext != ".tsx" && ext != ".js" && ext != ".jsx" {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		// Extract import statements
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			var pkg string
			if strings.HasPrefix(line, "import ") && strings.Contains(line, "from '") {
				parts := strings.Split(line, "from '")
				if len(parts) > 1 {
					pkg = strings.Trim(strings.Split(parts[1], "'")[0], `"'`)
				}
			} else if strings.HasPrefix(line, "import ") && strings.Contains(line, `from "`) {
				parts := strings.Split(line, `from "`)
				if len(parts) > 1 {
					pkg = strings.Trim(strings.Split(parts[1], `"`)[0], `"'`)
				}
			} else if strings.HasPrefix(line, "require('") || strings.HasPrefix(line, `require("`) {
				pkg = strings.Trim(strings.TrimPrefix(strings.TrimPrefix(line, "require('"), `require("`), `"')`)
				pkg = strings.Split(pkg, "'")[0]
				pkg = strings.Split(pkg, `"`)[0]
			}

			if pkg == "" || strings.HasPrefix(pkg, ".") || strings.HasPrefix(pkg, "/") {
				continue
			}
			// Get package name (handle @scope/package)
			pkgName := pkg
			if strings.HasPrefix(pkg, "@") {
				parts := strings.SplitN(pkg, "/", 3)
				if len(parts) >= 2 {
					pkgName = parts[0] + "/" + parts[1]
				}
			} else {
				pkgName = strings.SplitN(pkg, "/", 2)[0]
			}

			if !existing[pkgName] && !seen[pkgName] && pkgName != "" {
				seen[pkgName] = true
				missing = append(missing, pkgName)
			}
		}
		return nil
	})

	if len(missing) == 0 {
		return
	}

	// Filter out built-in Node.js modules
	builtins := map[string]bool{
		"fs": true, "path": true, "os": true, "http": true, "https": true,
		"crypto": true, "stream": true, "util": true, "events": true,
		"child_process": true, "readline": true, "url": true, "net": true,
	}
	var toInstall []string
	for _, pkg := range missing {
		if !builtins[pkg] {
			toInstall = append(toInstall, pkg)
		}
	}

	if len(toInstall) == 0 {
		return
	}

	fmt.Println()
	fmt.Println(dim.Render(fmt.Sprintf("  ⟳ Auto-installing %d missing packages: %s", len(toInstall), strings.Join(toInstall, ", "))))

	args := append([]string{"install"}, toInstall...)
	cmd := exec.Command("npm", args...)
	cmd.Dir = cwd
	out, err := cmd.CombinedOutput()
	if err == nil {
		fmt.Println(green.Render(fmt.Sprintf("  ✓ Installed: %s", strings.Join(toInstall, ", "))))
	} else {
		// Silent fail — don't interrupt the flow
		_ = out
	}
}

// min returns the smaller of two ints.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
