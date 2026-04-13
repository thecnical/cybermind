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
	"runtime"
	"strings"
	"time"

	"cybermind-cli/abhimanyu"
	"cybermind-cli/api"
	"cybermind-cli/hunt"
	"cybermind-cli/recon"
	"cybermind-cli/storage"
	"cybermind-cli/ui"
	"cybermind-cli/utils"
	"cybermind-cli/vibecoder"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	Version = "2.5.0"
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
	fmt.Println(g.Render("  cybermind /payload <os> <arch>") + d.Render("  → AI payload generator (no msfvenom)"))
	fmt.Println(g.Render("  cybermind /cve <CVE-ID>") + d.Render("         → CVE intelligence from NVD"))
	fmt.Println(g.Render("  cybermind /cve --latest") + d.Render("         → latest critical CVEs (7 days)"))
	fmt.Println(g.Render("  cybermind /wordlist <target>") + d.Render("    → custom wordlist generator"))
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
		Findings:        findings,
		SubdomainsFound: len(ctx.Subdomains),
		LiveHostsFound:  len(ctx.LiveHosts),
		OpenPorts:       openPorts,
		WAFDetected:     ctx.WAFDetected,
		WAFVendor:       ctx.WAFVendor,
		LiveURLs:        liveURLs,
		Technologies:    technologies,
		RawCombined:     recon.GetCombinedOutput(result),
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

// runAutoReconSilent runs the full recon pipeline without interactive prompts.
// Returns ReconResult so the caller can extract context for hunt phase.
func runAutoReconSilent(target string, requested []string) recon.ReconResult {
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
		Findings:        findings,
		SubdomainsFound: len(ctx.Subdomains),
		LiveHostsFound:  len(ctx.LiveHosts),
		OpenPorts:       openPorts,
		WAFDetected:     ctx.WAFDetected,
		WAFVendor:       ctx.WAFVendor,
		LiveURLs:        liveURLs,
		Technologies:    technologies,
		RawCombined:     recon.GetCombinedOutput(result),
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
		Findings:       findings,
		XSSFound:       xssFound,
		ParamsFound:    paramsFound,
		VulnsFound:     vulnsFound,
		HistoricalURLs: len(ctx.HistoricalURLs),
		WAFDetected:    ctx.WAFDetected,
		WAFVendor:      ctx.WAFVendor,
		OpenPorts:      openPorts,
		RawCombined:    hunt.GetHuntCombinedOutput(result),
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
		Findings:       findings,
		XSSFound:       xssFound,
		ParamsFound:    paramsFound,
		VulnsFound:     vulnsFound,
		HistoricalURLs: len(ctx.HistoricalURLs),
		WAFDetected:    ctx.WAFDetected,
		WAFVendor:      ctx.WAFVendor,
		OpenPorts:      openPorts,
		RawCombined:    hunt.GetHuntCombinedOutput(result),
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

	// Build AbhimanyuContext from hunt results
	abhCtx := &abhimanyu.AbhimanyuContext{
		Target:      target,
		TargetType:  ctx.TargetType,
		VulnType:    "all",
		LHOST:       lhost,
		LiveURLs:    ctx.LiveURLs,
		OpenPorts:   openPorts,
		XSSFound:    xssFound,
		VulnsFound:  vulnsFound,
		ParamsFound: paramsFound,
		WAFDetected: ctx.WAFDetected,
		WAFVendor:   ctx.WAFVendor,
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

	// Merge results into findings for AI payload
	for _, r := range results {
		if r.Output != "" {
			findings[r.Tool] = r.Output
		}
	}

	// Build AI payload
	abhimanyuPayload := map[string]interface{}{
		"target":       target,
		"vuln_type":    "all",
		"lhost":        lhost,
		"target_type":  ctx.TargetType,
		"open_ports":   openPorts,
		"live_urls":    ctx.LiveURLs,
		"xss_found":    xssFound,
		"vulns_found":  vulnsFound,
		"params_found": paramsFound,
		"waf_detected": ctx.WAFDetected,
		"waf_vendor":   ctx.WAFVendor,
		"findings":     findings,
		"session_dir":  abhCtx.SessionDir,
	}

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Sending to Abhimanyu AI for exploit analysis..."))

	exploit, exploitErr := api.SendAbhimanyu(target, "all", abhimanyuPayload)
	if exploitErr == nil {
		cleanExploit := utils.StripMarkdown(exploit)
		printResult("⚔️  ABHIMANYU Exploit Report → "+target, cleanExploit)
		_ = storage.AddEntry("/abhimanyu "+target, cleanExploit)

		// FIX: autoExecuteAICommands REMOVED — AI-controlled shell execution is an RCE vector
		// Commands are displayed for manual review only
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
			"  Copy any commands above and run them manually in your terminal."))
	} else {
		printError("Abhimanyu AI failed: " + exploitErr.Error())
		// Print raw findings anyway
		fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  Raw findings:"))
		for tool, output := range findings {
			if len(output) > 2000 {
				output = output[:2000] + "...[truncated]"
			}
			fmt.Printf("\n=== %s ===\n%s\n", strings.ToUpper(tool), output)
		}
	}

	// Show session info for next run
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render(
		fmt.Sprintf("  💾 Session saved: %s/session.json", abhCtx.SessionDir)))
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
		"  Resume next session: cybermind /abhimanyu " + target))
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

	// Determine download URL based on OS/arch
	var binaryURL string
	switch runtime.GOOS {
	case "linux":
		if runtime.GOARCH == "arm64" {
			binaryURL = "https://cybermindcli1.vercel.app/cybermind-linux-arm64"
		} else {
			binaryURL = "https://cybermindcli1.vercel.app/cybermind-linux-amd64"
		}
	case "darwin":
		if runtime.GOARCH == "arm64" {
			binaryURL = "https://cybermindcli1.vercel.app/cybermind-darwin-arm64"
		} else {
			binaryURL = "https://cybermindcli1.vercel.app/cybermind-darwin-amd64"
		}
	case "windows":
		binaryURL = "https://cybermindcli1.vercel.app/cybermind-windows-amd64.exe"
	default:
		fmt.Println(dim2.Render("  Self-update not supported on " + runtime.GOOS))
		return
	}

	fmt.Println(dim2.Render("  Downloading latest CyberMind CLI..."))

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

// installPythonPipTool installs a Python tool via pipx (Kali 2024.4+) with pip3 fallback.
// Kali 2024.4+ recommends pipx over pip3 for external packages.
func installPythonPipTool(name string) error {
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  ↳ Installing %s via pipx...", name)))

	// Ensure pipx is installed
	if _, err := exec.LookPath("pipx"); err != nil {
		exec.Command("sudo", "apt", "install", "-y", "pipx").Run()
		exec.Command("pipx", "ensurepath").Run()
	}

	// Method 1: pipx install (recommended for Kali 2024.4+)
	cmd := exec.Command("pipx", "install", name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err == nil {
		// Symlink from ~/.local/bin to /usr/local/bin
		homedir, _ := os.UserHomeDir()
		binPath := homedir + "/.local/bin/" + name
		if _, err2 := os.Stat(binPath); err2 == nil {
			exec.Command("sudo", "ln", "-sf", binPath, "/usr/local/bin/"+name).Run()
		}
		return nil
	}

	// Method 2: pip3 with --break-system-packages
	cmd2 := exec.Command("pip3", "install", name, "--break-system-packages")
	cmd2.Stdout = os.Stdout
	cmd2.Stderr = os.Stderr
	if err := cmd2.Run(); err == nil {
		return nil
	}

	// Method 3: pip3 in user space
	cmd3 := exec.Command("pip3", "install", "--user", name)
	cmd3.Stdout = os.Stdout
	cmd3.Stderr = os.Stderr
	return cmd3.Run()
}

// installPythonGitTool installs a Python tool from git using pipx or venv.
func installPythonGitTool(name, repoURL, installDir, mainScript string) error {
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  ↳ Cloning %s from GitHub...", name)))

	exec.Command("sudo", "rm", "-rf", installDir).Run()
	cloneCmd := exec.Command("git", "clone", "--depth=1", repoURL, installDir)
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr
	if err := cloneCmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %v", err)
	}

	// Method 1: pipx install from local dir (best for Kali 2024.4+)
	if _, err := exec.LookPath("pipx"); err == nil {
		pipxCmd := exec.Command("pipx", "install", installDir)
		pipxCmd.Stdout = os.Stdout
		pipxCmd.Stderr = os.Stderr
		if pipxCmd.Run() == nil {
			homedir, _ := os.UserHomeDir()
			binPath := homedir + "/.local/bin/" + name
			if _, err2 := os.Stat(binPath); err2 == nil {
				exec.Command("sudo", "ln", "-sf", binPath, "/usr/local/bin/"+name).Run()
				return nil
			}
		}
	}

	// Method 2: venv + pip install
	venvDir := installDir + "/.venv"
	exec.Command("python3", "-m", "venv", venvDir).Run()
	venvPip := venvDir + "/bin/pip"
	reqFile := installDir + "/requirements.txt"
	if _, err := os.Stat(reqFile); err == nil {
		pipCmd := exec.Command(venvPip, "install", "-r", reqFile, "-q")
		pipCmd.Stdout = os.Stdout
		pipCmd.Stderr = os.Stderr
		pipCmd.Run()
	}
	// Install the package itself
	exec.Command(venvPip, "install", "-e", installDir, "-q").Run()

	// Create wrapper that uses venv python
	scriptPath := installDir + "/" + mainScript
	venvPython := venvDir + "/bin/python3"
	wrapper := fmt.Sprintf("#!/bin/bash\n%s %s \"$@\"\n", venvPython, scriptPath)
	wrapperPath := "/usr/local/bin/" + name
	teeCmd := exec.Command("sudo", "tee", wrapperPath)
	teeCmd.Stdin = strings.NewReader(wrapper)
	teeCmd.Run()
	exec.Command("sudo", "chmod", "+x", wrapperPath).Run()

	// Method 3: pip3 with --break-system-packages as last resort
	if _, err := exec.LookPath(name); err != nil {
		reqFile := installDir + "/requirements.txt"
		if _, err2 := os.Stat(reqFile); err2 == nil {
			exec.Command("pip3", "install", "-r", reqFile, "--break-system-packages", "-q").Run()
		}
	}

	if _, err := os.Stat(scriptPath); err == nil {
		return nil
	}
	return fmt.Errorf("%s install incomplete", name)
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
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ↳ Downloading rustscan .deb from GitHub releases..."))
	dlCmd := exec.Command("bash", "-c",
		`LATEST=$(curl -s https://api.github.com/repos/RustScan/RustScan/releases/latest | grep browser_download_url | grep amd64.deb | cut -d'"' -f4) && `+
			`if [ -n "$LATEST" ]; then curl -sL "$LATEST" -o /tmp/rustscan.deb && sudo dpkg -i /tmp/rustscan.deb; `+
			`else echo "No .deb found"; exit 1; fi`)
	dlCmd.Stdout = os.Stdout
	dlCmd.Stderr = os.Stderr
	if err := dlCmd.Run(); err == nil {
		return nil
	}
	// Fallback: cargo install
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ↳ .deb failed, trying cargo install rustscan..."))
	exec.Command("sudo", "apt", "install", "-y", "libssl-dev", "pkg-config", "cargo").Run()
	cargoCmd := exec.Command("cargo", "install", "rustscan")
	cargoCmd.Stdout = os.Stdout
	cargoCmd.Stderr = os.Stderr
	return cargoCmd.Run()
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
			key := promptForAPIKey()
			if key == "" {
				// User skipped — still launch TUI in limited mode
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
					"  Launching in limited mode. Set key anytime: cybermind --key cp_live_xxxxx"))
				fmt.Println()
			}
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
			"doctor": true, // /doctor runs self-update on all platforms
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
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Windows/macOS: AI chat + CBM Code are fully functional."))
			fmt.Println()
			return
		}

		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  ② Checking recon + hunt tools..."))
		fmt.Println()

		type toolEntry struct {
			name    string
			mode    string
			install string
			isGo    bool
			isCargo bool
		}

		allTools := []toolEntry{
			// ── Recon Phase 1 — Passive OSINT ──────────────────────────────────
			{"whois", "recon", "sudo apt install whois", false, false},
			{"theHarvester", "recon", "sudo apt install theharvester", false, false},
			{"dig", "recon", "sudo apt install dnsutils", false, false},
			// ── Recon Phase 2 — Subdomain Enumeration ──────────────────────────
			{"subfinder", "recon", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", true, false},
			{"amass", "recon", "sudo apt install amass", false, false},
			{"reconftw", "recon", "git clone https://github.com/six2dez/reconftw.git /opt/reconftw && cd /opt/reconftw && ./install.sh", false, false},
			{"dnsx", "recon", "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", true, false},
			// ── Recon Phase 3 — Port Scanning ──────────────────────────────────
			{"rustscan", "recon", "cargo install rustscan", false, true},
			{"naabu", "recon", "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", true, false},
			{"nmap", "recon", "sudo apt install nmap", false, false},
			{"masscan", "recon", "sudo apt install masscan", false, false},
			// ── Recon Phase 4 — HTTP Fingerprinting ────────────────────────────
			{"httpx", "recon", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", true, false},
			{"whatweb", "recon", "sudo apt install whatweb", false, false},
			{"tlsx", "recon", "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest", true, false},
			// ── Recon Phase 5 — Directory Discovery ────────────────────────────
			{"ffuf", "recon", "sudo apt install ffuf", false, false},
			{"feroxbuster", "recon", "sudo apt install feroxbuster", false, false},
			{"gobuster", "recon", "sudo apt install gobuster", false, false},
			// ── Recon Phase 6 — Vulnerability Scanning ─────────────────────────
			{"nuclei", "recon", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", true, false},
			{"nikto", "recon", "sudo apt install nikto", false, false},
			{"katana", "recon", "go install github.com/projectdiscovery/katana/cmd/katana@latest", true, false},
			// ── Hunt Phase 1 — URL Collection ──────────────────────────────────
			{"waymore", "hunt", "pip3 install waymore --break-system-packages", false, false},
			{"gau", "hunt", "go install github.com/lc/gau/v2/cmd/gau@latest", true, false},
			{"waybackurls", "hunt", "go install github.com/tomnomnom/waybackurls@latest", true, false},
			// ── Hunt Phase 2 — Deep Crawl ──────────────────────────────────────
			{"gospider", "hunt", "go install github.com/jaeles-project/gospider@latest", true, false},
			// katana already in recon, shared
			// ── Hunt Phase 3 — Parameter Discovery ─────────────────────────────
			{"paramspider", "hunt", "git clone https://github.com/devanshbatham/ParamSpider /opt/ParamSpider && pip3 install -r /opt/ParamSpider/requirements.txt --break-system-packages && sudo ln -sf /opt/ParamSpider/paramspider.py /usr/local/bin/paramspider && sudo chmod +x /usr/local/bin/paramspider", false, false},
			{"arjun", "hunt", "pip3 install arjun --break-system-packages", false, false},
			{"x8", "hunt", "Download binary from https://github.com/Sh1Yo/x8/releases/latest", false, false},
			// ── Hunt Phase 4 — XSS Hunting ─────────────────────────────────────
			{"xsstrike", "hunt", "git clone https://github.com/s0md3v/XSStrike /opt/XSStrike && pip3 install -r /opt/XSStrike/requirements.txt --break-system-packages && sudo ln -sf /opt/XSStrike/xsstrike.py /usr/local/bin/xsstrike && sudo chmod +x /usr/local/bin/xsstrike", false, false},
			{"dalfox", "hunt", "go install github.com/hahwul/dalfox/v2@latest", true, false},
			// ── Hunt Phase 5 — Deep Vuln Scan ──────────────────────────────────
			{"gf", "hunt", "go install github.com/tomnomnom/gf@latest && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf", true, false},
			// nuclei already in recon, shared
			// ── Abhimanyu Phase 1 — Web Exploitation ───────────────────────────
			{"sqlmap", "exploit", "sudo apt install sqlmap -y", false, false},
			{"commix", "exploit", "sudo apt install commix -y", false, false},
			{"wpscan", "exploit", "sudo apt install wpscan -y", false, false},
			// nikto already in recon, shared
			// ── Abhimanyu Phase 2 — Auth Attacks ───────────────────────────────
			{"hydra", "exploit", "sudo apt install hydra -y", false, false},
			{"john", "exploit", "sudo apt install john -y", false, false},
			{"hashcat", "exploit", "sudo apt install hashcat -y", false, false},
			// ── Abhimanyu Phase 3 — CVE/Exploit Search ─────────────────────────
			{"searchsploit", "exploit", "sudo apt install exploitdb -y", false, false},
			{"msfconsole", "exploit", "sudo apt install metasploit-framework -y", false, false},
			// ── Abhimanyu Phase 4 — Post-Exploitation ──────────────────────────
			{"linpeas", "exploit", "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /opt/linpeas.sh && chmod +x /opt/linpeas.sh && sudo ln -sf /opt/linpeas.sh /usr/local/bin/linpeas", false, false},
			{"pspy", "exploit", "curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /opt/pspy && chmod +x /opt/pspy && sudo ln -sf /opt/pspy /usr/local/bin/pspy", false, false},
			{"bloodhound-python", "exploit", "pip3 install bloodhound --break-system-packages && sudo apt install neo4j -y", false, false},
			// ── Abhimanyu Phase 5 — Lateral Movement ───────────────────────────
			{"crackmapexec", "exploit", "sudo apt install crackmapexec -y", false, false},
			{"evil-winrm", "exploit", "sudo gem install evil-winrm", false, false},
			{"impacket-secretsdump", "exploit", "sudo apt install python3-impacket -y", false, false},
			// ── Abhimanyu Phase 6 — Persistence + Exfil ────────────────────────
			{"iodine", "exploit", "sudo apt install iodine -y", false, false},
		}

		var missing []toolEntry
		reconOK := 0
		huntOK := 0
		exploitOK := 0

		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  RECON TOOLS (20):"))
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
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render("  HUNT TOOLS (11):"))
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
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render("  ABHIMANYU EXPLOIT TOOLS (13):"))
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
			fmt.Sprintf("  Recon:     %d/20 installed", reconOK)))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6600")).Render(
			fmt.Sprintf("  Hunt:      %d/11 installed", huntOK)))
		fmt.Println(lipgloss.NewStyle().Foreground(red).Render(
			fmt.Sprintf("  Abhimanyu: %d/13 installed", exploitOK)))

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
			for _, t := range missing {
				fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(fmt.Sprintf("  ⟳ %-16s installing...", t.name)))

				var installErr error

				switch t.name {
				case "reconftw":
					installErr = installReconftw()

				case "x8":
					installErr = installX8()

				case "rustscan":
					installErr = installRustscan()

				case "naabu":
					exec.Command("sudo", "apt", "install", "-y", "libpcap-dev").Run()
					cmd2 := exec.Command("go", "install", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
					cmd2.Stdout = os.Stdout
					cmd2.Stderr = os.Stderr
					installErr = cmd2.Run()
					if installErr == nil {
						homedir2, _ := os.UserHomeDir()
						for _, gobin := range []string{homedir2 + "/go/bin/naabu", "/root/go/bin/naabu"} {
							if _, err2 := os.Stat(gobin); err2 == nil {
								exec.Command("sudo", "ln", "-sf", gobin, "/usr/local/bin/naabu").Run()
								break
							}
						}
					}

				case "paramspider":
					installErr = installPythonGitTool(
						"paramspider",
						"https://github.com/devanshbatham/ParamSpider",
						"/opt/ParamSpider",
						"paramspider.py",
					)

				case "arjun":
					installErr = installPythonPipTool("arjun")

				case "xsstrike":
					installErr = installPythonGitTool(
						"xsstrike",
						"https://github.com/s0md3v/XSStrike",
						"/opt/XSStrike",
						"xsstrike.py",
					)

				case "waymore":
					// waymore is a Python tool — pip3 install (NOT go install)
					installErr = func() error {
						cmd2 := exec.Command("pip3", "install", "waymore", "--break-system-packages", "-q")
						cmd2.Stdout = os.Stdout
						cmd2.Stderr = os.Stderr
						if err := cmd2.Run(); err == nil {
							for _, p := range []string{"/usr/local/bin/waymore", "/usr/bin/waymore"} {
								if _, e := os.Stat(p); e == nil {
									return nil
								}
							}
						}
						// Method 2: git clone
						exec.Command("sudo", "rm", "-rf", "/opt/waymore").Run()
						cloneCmd := exec.Command("git", "clone", "--depth=1", "https://github.com/xnl-h4ck3r/waymore.git", "/opt/waymore")
						cloneCmd.Stdout = os.Stdout
						cloneCmd.Stderr = os.Stderr
						if err := cloneCmd.Run(); err != nil {
							return err
						}
						exec.Command("pip3", "install", "-r", "/opt/waymore/requirements.txt", "--break-system-packages", "-q").Run()
						teeCmd := exec.Command("sudo", "tee", "/usr/local/bin/waymore")
						teeCmd.Stdin = strings.NewReader("#!/bin/bash\npython3 /opt/waymore/waymore.py \"$@\"\n")
						teeCmd.Run()
						exec.Command("sudo", "chmod", "+x", "/usr/local/bin/waymore").Run()
						return nil
					}()

				case "gf":
					installErr = func() error {
						cmd2 := exec.Command("go", "install", "github.com/tomnomnom/gf@latest")
						cmd2.Stdout = os.Stdout
						cmd2.Stderr = os.Stderr
						if err := cmd2.Run(); err != nil {
							return err
						}
						homedir2, _ := os.UserHomeDir()
						for _, gobin := range []string{homedir2 + "/go/bin/gf", "/root/go/bin/gf"} {
							if _, err2 := os.Stat(gobin); err2 == nil {
								exec.Command("sudo", "ln", "-sf", gobin, "/usr/local/bin/gf").Run()
								break
							}
						}
						// Install gf patterns
						gfDir := homedir2 + "/.gf"
						if _, err2 := os.Stat(gfDir); err2 != nil {
							exec.Command("git", "clone", "--depth=1", "https://github.com/1ndianl33t/Gf-Patterns", gfDir).Run()
						}
						return nil
					}()

				case "linpeas":
					installErr = func() error {
						cmd2 := exec.Command("bash", "-c",
							"curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /opt/linpeas.sh && chmod +x /opt/linpeas.sh && sudo ln -sf /opt/linpeas.sh /usr/local/bin/linpeas")
						cmd2.Stdout = os.Stdout
						cmd2.Stderr = os.Stderr
						return cmd2.Run()
					}()

				case "pspy":
					installErr = func() error {
						cmd2 := exec.Command("bash", "-c",
							"curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /opt/pspy && chmod +x /opt/pspy && sudo ln -sf /opt/pspy /usr/local/bin/pspy")
						cmd2.Stdout = os.Stdout
						cmd2.Stderr = os.Stderr
						return cmd2.Run()
					}()

				case "bloodhound-python":
					installErr = func() error {
						exec.Command("pip3", "install", "bloodhound", "--break-system-packages", "-q").Run()
						exec.Command("sudo", "apt", "install", "-y", "neo4j", "-qq").Run()
						return nil
					}()

				case "evil-winrm":
					installErr = func() error {
						exec.Command("sudo", "apt", "install", "-y", "ruby", "ruby-dev", "-qq").Run()
						cmd2 := exec.Command("sudo", "gem", "install", "evil-winrm")
						cmd2.Stdout = os.Stdout
						cmd2.Stderr = os.Stderr
						return cmd2.Run()
					}()

				case "impacket-secretsdump":
					installErr = func() error {
						cmd2 := exec.Command("sudo", "apt", "install", "-y", "python3-impacket")
						cmd2.Stdout = os.Stdout
						cmd2.Stderr = os.Stderr
						if err := cmd2.Run(); err == nil {
							return nil
						}
						cmd3 := exec.Command("pip3", "install", "impacket", "--break-system-packages", "-q")
						cmd3.Stdout = os.Stdout
						cmd3.Stderr = os.Stderr
						return cmd3.Run()
					}()

				case "iodine":
					installErr = func() error {
						cmd2 := exec.Command("sudo", "apt", "install", "-y", "iodine")
						cmd2.Stdout = os.Stdout
						cmd2.Stderr = os.Stderr
						return cmd2.Run()
					}()

				default:
					if t.isCargo {
						// Install openssl deps first for any cargo tool
						exec.Command("sudo", "apt", "install", "-y", "libssl-dev", "pkg-config").Run()
						if _, cargoErr := exec.LookPath("cargo"); cargoErr != nil {
							exec.Command("sudo", "apt", "install", "-y", "cargo").Run()
						}
						cmd2 := exec.Command("cargo", "install", t.name)
						cmd2.Stdout = os.Stdout
						cmd2.Stderr = os.Stderr
						installErr = cmd2.Run()
						if installErr == nil {
							homedir2, _ := os.UserHomeDir()
							cargobin := homedir2 + "/.cargo/bin/" + t.name
							if _, err2 := os.Stat(cargobin); err2 == nil {
								exec.Command("sudo", "ln", "-sf", cargobin, "/usr/local/bin/"+t.name).Run()
							}
						}
					} else if t.isGo {
						parts := strings.Fields(t.install)
						cmd2 := exec.Command("go", "install", parts[len(parts)-1])
						cmd2.Stdout = os.Stdout
						cmd2.Stderr = os.Stderr
						installErr = cmd2.Run()
						if installErr == nil {
							homedir2, _ := os.UserHomeDir()
							for _, gobin := range []string{homedir2 + "/go/bin/" + t.name, "/root/go/bin/" + t.name} {
								if _, err2 := os.Stat(gobin); err2 == nil {
									exec.Command("sudo", "ln", "-sf", gobin, "/usr/local/bin/"+t.name).Run()
									break
								}
							}
						}
					} else {
						// Python/git tools — use bash to run the install string
						cmd2 := exec.Command("bash", "-c", t.install)
						cmd2.Stdout = os.Stdout
						cmd2.Stderr = os.Stderr
						installErr = cmd2.Run()
					}
				}

				if installErr != nil {
					fmt.Println(lipgloss.NewStyle().Foreground(red).Render(fmt.Sprintf("  ✗ %-16s failed: %v", t.name, installErr)))
					// Send error to AI for diagnosis
					errMsg := fmt.Sprintf("Tool installation failed: %s\nError: %v\nOS: Linux/Kali\nPlease provide exact fix commands.", t.name, installErr)
					if fix, aiErr := api.SendPrompt(errMsg); aiErr == nil {
						fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  💡 AI Fix suggestion:"))
						fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).MarginLeft(4).Render(fix))
					}
					instFail++
				} else {
					fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ %-16s installed", t.name)))
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
		if len(args) < 2 {
			printError("Usage: cybermind /plan <target>")
			printError("Example: cybermind /plan example.com")
			printError("Example: cybermind /plan 192.168.1.1")
			os.Exit(1)
		}
		planTarget := args[1]
		if err := recon.ValidateTarget(planTarget); err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		if !localMode && !requireAPIKey() {
			os.Exit(1)
		}
		runOmegaPlan(planTarget, localMode)

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
		// Wordlist generator — works on all OS
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		if !localMode && !requireAPIKey() {
			os.Exit(1)
		}
		target := ""
		wordlistType := "passwords"
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--target":
				if i+1 < len(args) {
					target = args[i+1]
					i++
				}
			case "--type":
				if i+1 < len(args) {
					wordlistType = args[i+1]
					i++
				}
			}
		}
		if target == "" {
			printError("Usage: cybermind /wordlist --target <domain> [--type passwords|usernames|subdomains]")
			os.Exit(1)
		}
		runWordlist(target, wordlistType, localMode)

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

	case "vibe", "neural", "cbm-code", "cbmcode", "code":
		// CBM Code (formerly Vibe Coder) — all aliases supported
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
		registry := vibecoder.NewDefaultToolRegistry()
		toolEngine := vibecoder.NewToolEngine(registry, toolEnv)
		checkpointMgr := vibecoder.NewCheckpointManager("", cfg.CheckpointIntervalTurns)
		agentLoop = vibecoder.NewAgentLoop(session, providerChain, toolEngine, checkpointMgr, vibecoder.AgentLoopConfig{
			MaxIterations:   50,
			WarnAt:          0.8,
			CircuitBreakerN: 3,
			StuckHashCount:  3,
		})
		// Start file indexer in background
		indexer := vibecoder.NewFileIndexer(cwd, "", nil)
		indexer.LoadIgnorePatterns()
		indexer.Start(nil)
	}

	// ── Launch stable readline-based interface ─────────────────────────────
	// Replaces bubbletea which has Windows console compatibility issues.
	// Direct terminal I/O — works on Windows, macOS, Linux without any issues.
	runVibeCoderCLI(session, cwd, tier, activeModel, userName, agentLoop)
}

// runVibeCoderCLI is the stable, cross-platform CBM Code interface.
// Uses direct readline I/O — banner stays visible, prompt always works.
func runVibeCoderCLI(session *vibecoder.Session, cwd, tier, activeModel, userName string, agentLoop *vibecoder.AgentLoop) {
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
	fmt.Println(yellow2.Render("  Tips:"))
	fmt.Println(green2.Render("  Type your task and press Enter to get AI response"))
	fmt.Println(green2.Render("  /add <file>  — add file to context"))
	fmt.Println(green2.Render("  /ls          — list workspace files"))
	fmt.Println(green2.Render("  /read <file> — read file into context"))
	fmt.Println(green2.Render("  /run <cmd>   — run a command"))
	fmt.Println(green2.Render("  /clear       — reset context"))
	fmt.Println(green2.Render("  /help        — show all commands"))
	fmt.Println(green2.Render("  /exit        — quit"))
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
				fmt.Println(cyan2.Render("  CBM Code Commands:"))
				fmt.Println(dim2.Render("  /add <file>           — add file to context"))
				fmt.Println(dim2.Render("  /read <file>          — read file into context"))
				fmt.Println(dim2.Render("  /ls [path]            — list workspace files"))
				fmt.Println(dim2.Render("  /run <command>        — run a shell command"))
				fmt.Println(dim2.Render("  /init                 — create CYBERMIND.md project memory"))
				fmt.Println(dim2.Render("  /plan <task>          — plan architecture before coding"))
				fmt.Println(dim2.Render("  /mcp                  — MCP integrations (Playwright, etc.)"))
				fmt.Println(dim2.Render("  /sessions             — list saved sessions"))
				fmt.Println(dim2.Render("  /clear                — reset context + delete session"))
				fmt.Println(dim2.Render("  /mode agent|chat      — switch mode"))
				fmt.Println(dim2.Render("  /effort low|medium|max — set effort level"))
				fmt.Println(dim2.Render("  /model <name>         — override model"))
				fmt.Println(dim2.Render("  /undo                 — undo last file change"))
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
				// MCP Playwright integration
				fmt.Println()
				fmt.Println(cyan2.Render("  MCP (Model Context Protocol) Integration"))
				fmt.Println(dim2.Render("  ─────────────────────────────────────────"))
				fmt.Println(yellow2.Render("  Available MCP servers:"))
				fmt.Println(green2.Render("  1. Playwright MCP (browser automation)"))
				fmt.Println(dim2.Render("     Install: npx @playwright/mcp@latest"))
				fmt.Println(dim2.Render("     Use: /mcp playwright <url> — open browser"))
				fmt.Println()
				fmt.Println(green2.Render("  2. Filesystem MCP (file operations)"))
				fmt.Println(dim2.Render("     Built-in — use /add /read /ls commands"))
				fmt.Println()
				fmt.Println(green2.Render("  3. Context7 MCP (library docs)"))
				fmt.Println(dim2.Render("     Install: npx @upstash/context7-mcp@latest"))
				fmt.Println()
				if len(parts) > 1 && parts[1] == "playwright" {
					url := "http://localhost:3000"
					if len(parts) > 2 {
						url = parts[2]
					}
					fmt.Println(dim2.Render("  ⟳ Launching Playwright MCP..."))
					// Check if npx is available
					if _, npxErr := exec.LookPath("npx"); npxErr != nil {
						fmt.Println(red2.Render("  ✗ npx not found — install Node.js first"))
					} else {
						// Run playwright MCP in background
						var shell, flag string
						if runtime.GOOS == "windows" {
							shell, flag = "cmd", "/c"
						} else {
							shell, flag = "sh", "-c"
						}
						mcpCmd := fmt.Sprintf("npx @playwright/mcp@latest --url %s", url)
						go func() {
							out, _ := exec.Command(shell, flag, mcpCmd).CombinedOutput()
							_ = out
						}()
						fmt.Println(green2.Render("  ✓ Playwright MCP started for: " + url))
						fmt.Println(dim2.Render("  You can now ask CBM Code to test your app"))
					}
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
				fmt.Println(dim2.Render("  Unknown: " + parts[0] + " (type /help)"))
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
			out, err := runCmd("npm install --silent 2>&1", 120)
			if err != nil {
				allErrors.WriteString("npm install failed:\n" + out + "\n")
				return allOutput.String(), allErrors.String()
			}
			fmt.Println(green.Render("  ✓ Dependencies installed"))
			allOutput.WriteString(out)
		}

		// Try TypeScript check if tsconfig exists
		if fileExists(filepath.Join(cwd, "tsconfig.json")) {
			fmt.Println(dim.Render("  ⟳ Checking TypeScript..."))
			out, err := runCmd("npx tsc --noEmit 2>&1", 60)
			if err != nil && out != "" {
				// Filter out noise, keep real errors
				errors := filterTypeScriptErrors(out)
				if errors != "" {
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
