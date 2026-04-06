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
	Version = "2.4.1"
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
				fmt.Sprintf("  ⟳ %-14s running...", status.Tool)))
		case recon.StatusDone:
			fmt.Println(lipgloss.NewStyle().Foreground(green).Render(
				fmt.Sprintf("  ✓ %-14s done (%s)", status.Tool, status.Took.Round(time.Millisecond))))
		case recon.StatusPartial:
			fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render(
				fmt.Sprintf("  ⚡ %-14s partial output kept", status.Tool)))
		case recon.StatusFailed:
			fmt.Println(lipgloss.NewStyle().Foreground(red).Render(
				fmt.Sprintf("  ✗ %-14s failed — %s", status.Tool, status.Reason)))
		case recon.StatusSkipped:
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(
				fmt.Sprintf("  - %-14s skipped — %s", status.Tool, status.Reason)))
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
			// Hunt tools
			{"gau", "hunt", "go install github.com/lc/gau/v2/cmd/gau@latest", true, false},
			{"waybackurls", "hunt", "go install github.com/tomnomnom/waybackurls@latest", true, false},
			{"dalfox", "hunt", "go install github.com/hahwul/dalfox/v2@latest", true, false},
			{"x8", "hunt", "cargo install x8", false, true},
		}

		var missing []toolEntry
		reconOK, reconMissing := 0, 0
		huntOK, huntMissing := 0, 0

		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  RECON TOOLS (16):"))
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
				reconMissing++
			}
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF6600")).Render("  HUNT TOOLS (4):"))
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
				huntMissing++
			}
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
		fmt.Println(lipgloss.NewStyle().Foreground(green).Render(
			fmt.Sprintf("  Recon: %d/16 installed", reconOK)))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6600")).Render(
			fmt.Sprintf("  Hunt:  %d/4 installed", huntOK)))

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

				// Pre-deps: naabu needs libpcap-dev
				if t.name == "naabu" {
					exec.Command("sudo", "apt", "install", "-y", "libpcap-dev").Run()
				}

				var cmd2 *exec.Cmd
				if t.isCargo {
					if _, cargoErr := exec.LookPath("cargo"); cargoErr != nil {
						exec.Command("sudo", "apt", "install", "-y", "cargo").Run()
					}
					cmd2 = exec.Command("cargo", "install", t.name)
				} else if t.isGo {
					parts := strings.Fields(t.install)
					cmd2 = exec.Command("go", "install", parts[len(parts)-1])
				} else {
					cmd2 = exec.Command("sudo", "apt", "install", "-y", t.name)
				}
				cmd2.Stdout = os.Stdout
				cmd2.Stderr = os.Stderr
				if err := cmd2.Run(); err != nil {
					// rustscan fallback: download .deb release
					if t.name == "rustscan" {
						fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  ↳ trying .deb release..."))
						dlCmd := exec.Command("bash", "-c",
							`LATEST=$(curl -s https://api.github.com/repos/RustScan/RustScan/releases/latest | grep browser_download_url | grep amd64.deb | cut -d'"' -f4) && curl -sL "$LATEST" -o /tmp/rustscan.deb && sudo dpkg -i /tmp/rustscan.deb`)
						dlCmd.Stdout = os.Stdout
						dlCmd.Stderr = os.Stderr
						if err2 := dlCmd.Run(); err2 == nil {
							fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ %-16s installed", t.name)))
							instOK++
							continue
						}
					}
					fmt.Println(lipgloss.NewStyle().Foreground(red).Render(fmt.Sprintf("  ✗ %-16s failed: %v", t.name, err)))
					instFail++
				} else {
					homedir2, _ := os.UserHomeDir()
					// Symlink Go tools
					if t.isGo {
						for _, gobin := range []string{homedir2 + "/go/bin/" + t.name, "/root/go/bin/" + t.name} {
							if _, err2 := os.Stat(gobin); err2 == nil {
								exec.Command("sudo", "ln", "-sf", gobin, "/usr/local/bin/"+t.name).Run()
								break
							}
						}
					}
					// Symlink cargo tools
					if t.isCargo {
						cargobin := homedir2 + "/.cargo/bin/" + t.name
						if _, err2 := os.Stat(cargobin); err2 == nil {
							exec.Command("sudo", "ln", "-sf", cargobin, "/usr/local/bin/"+t.name).Run()
						}
					}
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
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  [4/4] Installing x8 (hidden param discovery)..."))
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

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render(
			fmt.Sprintf("  Summary: %d installed, %d skipped, %d failed", installed, skipped2, failed)))
		if failed > 0 {
			fmt.Println(lipgloss.NewStyle().Foreground(yellow).Render("  Run: cybermind /doctor  to retry failed tools"))
		}
		fmt.Println()

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

		// git pull
		fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ Pulling latest changes..."))
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
		// Auto-install any new tools added in this version
		if runtime.GOOS == "linux" {
			fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Checking for new/missing tools..."))
			installCmd2 := exec.Command("/usr/local/bin/cybermind", "/doctor")
			installCmd2.Stdout = os.Stdout
			installCmd2.Stderr = os.Stderr
			_ = installCmd2.Run()
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
