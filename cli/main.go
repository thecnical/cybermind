package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"cybermind-cli/api"
	"cybermind-cli/recon"
	"cybermind-cli/storage"
	"cybermind-cli/ui"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	Version = "2.2.0"
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
		fmt.Println(g.Render("  cybermind /tools") + d.Render("               → check installed recon tools"))
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

func runAutoRecon(target string) {
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(yellow).Render("  🔍 AUTO RECON MODE — " + target))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
	fmt.Println()

	// Run all tools with progress updates
	result := recon.RunAutoRecon(target, func(msg string) {
		fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ " + msg))
	})

	// Show what was collected
	fmt.Println()
	if len(result.Tools) == 0 {
		fmt.Println(lipgloss.NewStyle().Foreground(red).Render("  ✗ No recon tools found. Install: nmap, subfinder, httpx, dig, whois"))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Run: sudo apt install nmap whois dnsutils"))
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("  Run: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"))
		fmt.Println()
		// Fall back to AI guide
		fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Falling back to AI recon guide..."))
		result2, err := api.SendRecon(target, "full")
		if err != nil {
			printError(err.Error())
			return
		}
		printResult("Recon Guide → "+target, result2)
		return
	}

	fmt.Println(lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("  ✓ Collected data from: %s", strings.Join(result.Tools, ", "))))
	fmt.Println()

	// Send to AI for analysis
	fmt.Println(lipgloss.NewStyle().Foreground(cyan).Render("  ⟳ Sending to AI for analysis..."))
	combined := recon.GetCombinedOutput(result)
	analysis, err := api.SendAnalysis(target, combined, strings.Join(result.Tools, ", "))
	if err != nil {
		printError("AI analysis failed: " + err.Error())
		// Show raw output as fallback
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render("\n  Raw recon output:\n"))
		fmt.Println(combined)
		return
	}

	printResult("AI Analysis → "+target, analysis)

	// Save to history
	_ = storage.AddEntry("/recon "+target, analysis)
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		if err := storage.Load(); err != nil {
			fmt.Println("Warning: could not load history:", err)
		}
		printBanner()
		p := tea.NewProgram(ui.NewModel())
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
			printError("Usage: cybermind /recon <target>")
			printError("Example: cybermind /recon 192.168.1.1")
			printError("Example: cybermind /recon example.com")
			os.Exit(1)
		}
		target := args[1]
		if err := storage.Load(); err != nil {
			fmt.Println("Warning:", err)
		}
		runAutoRecon(target)

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
		result, err := api.SendPayload(targetOS, arch, "YOUR_IP", "4444", format)
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
		prompt := strings.Join(args, " ")
		fmt.Println(lipgloss.NewStyle().Foreground(purple).Render("  ⟳ Asking CyberMind AI..."))
		result, err := api.SendPrompt(prompt)
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		printResult("Response", result)
	}
}
