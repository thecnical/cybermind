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
	"cybermind-cli/recon"
	"cybermind-cli/storage"
	"cybermind-cli/ui"
	"cybermind-cli/utils"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	Version = "2.3.0"
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
		fmt.Println(y.Render("  🐧 LINUX ONLY — AUTO RECON:"))
		fmt.Println(g.Render("  cybermind /recon <target>") + d.Render("       → full auto recon + AI analysis"))
		fmt.Println(g.Render("  cybermind /recon <target> --tools nmap,httpx") + d.Render(" → run specific tools only"))
		fmt.Println(g.Render("  cybermind /tools") + d.Render("               → check installed recon tools"))
		fmt.Println(g.Render("  cybermind /install-tools") + d.Render("       → install all recon tools"))
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

	case "/install-tools":
		if runtime.GOOS != "linux" {
			printError("/install-tools is only available on Linux.")
			os.Exit(1)
		}
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  🛠  Installing Recon Tools"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 50)))
		fmt.Println()

		aptTools := []string{"nmap", "masscan", "rustscan", "whois", "dnsutils", "theharvester",
			"whatweb", "ffuf", "feroxbuster", "gobuster", "nikto", "amass"}
		goTools := []struct{ bin, module string }{
			{"subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"},
			{"httpx", "github.com/projectdiscovery/httpx/cmd/httpx"},
			{"nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"},
			{"naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu"},
			{"dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx"},
			{"tlsx", "github.com/projectdiscovery/tlsx/cmd/tlsx"},
			{"katana", "github.com/projectdiscovery/katana/cmd/katana"},
		}

		installed, skipped2, failed := 0, 0, 0

		for _, tool := range aptTools {
			if _, err := exec.LookPath(tool); err == nil {
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  - %-16s already installed", tool)))
				skipped2++
				continue
			}
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(fmt.Sprintf("  ⟳ %-16s installing...", tool)))
			cmd2 := exec.Command("sudo", "apt", "install", "-y", tool)
			cmd2.Stdout = os.Stdout
			cmd2.Stderr = os.Stderr
			if err := cmd2.Run(); err != nil {
				fmt.Println(lipgloss.NewStyle().Foreground(red).Render(fmt.Sprintf("  ✗ %-16s failed: %v", tool, err)))
				failed++
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ %-16s installed", tool)))
				installed++
			}
		}

		for _, gt := range goTools {
			if _, err := exec.LookPath(gt.bin); err == nil {
				fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("  - %-16s already installed", gt.bin)))
				skipped2++
				continue
			}
			fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(fmt.Sprintf("  ⟳ %-16s installing...", gt.bin)))
			cmd2 := exec.Command("go", "install", gt.module+"@latest")
			cmd2.Stdout = os.Stdout
			cmd2.Stderr = os.Stderr
			if err := cmd2.Run(); err != nil {
				fmt.Println(lipgloss.NewStyle().Foreground(red).Render(fmt.Sprintf("  ✗ %-16s failed: %v", gt.bin, err)))
				failed++
			} else {
				fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ %-16s installed", gt.bin)))
				installed++
			}
		}

		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render(
			fmt.Sprintf("  Summary: %d installed, %d skipped, %d failed", installed, skipped2, failed)))
		fmt.Println()

	case "update":
		// Self-update: git pull + rebuild + reinstall
		fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  ⟳ Updating CyberMind..."))
		fmt.Println()

		// Find repo root (go up from binary location or use GOPATH)
		// Try common locations
		homedir, _ := os.UserHomeDir()
		repoPaths := []string{
			".", // current dir
			homedir + "/cybermind",
			homedir + "/CyberMind",
			"/opt/cybermind",
		}

		repoPath := ""
		for _, p := range repoPaths {
			if _, err := os.Stat(p + "/.git"); err == nil {
				repoPath = p
				break
			}
		}

		if repoPath == "" {
			printError("Cannot find CyberMind repo. Run from inside the cloned repo:")
			fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  cd cybermind/cli && git pull && go build -ldflags=\"-X main.Version=2.2.0\" -o cybermind . && sudo mv cybermind /usr/local/bin/"))
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
		buildCmd := exec.Command("go", "build", "-ldflags=-X main.Version=2.3.0", "-o", "cybermind", ".")
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
