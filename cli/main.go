package main

import (
	"fmt"
	"os"
	"strings"

	"cybermind-cli/api"
	"cybermind-cli/storage"
	"cybermind-cli/ui"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	Version = "2.0.0" // set by build flag: -ldflags="-X main.Version=x.x.x"
	cyan    = lipgloss.Color("#00FFFF")
	green   = lipgloss.Color("#00FF00")
	purple  = lipgloss.Color("#8A2BE2")
	red     = lipgloss.Color("#FF4444")
	dim     = lipgloss.Color("#777777")
	credit  = lipgloss.Color("#555555")
)

func printBanner() {
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
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  ⚡ CyberMind CLI v"+Version+" – AI Powered Kali Linux Assistant"))
	fmt.Println(lipgloss.NewStyle().Foreground(credit).Render("  created by github.com/thecnical (Chandan Pandey)"))
	fmt.Println()
}

func printHelp() {
	s := lipgloss.NewStyle().Bold(true).Foreground(cyan)
	d := lipgloss.NewStyle().Foreground(dim)
	g := lipgloss.NewStyle().Foreground(green)

	fmt.Println()
	fmt.Println(s.Render("  ⚡ CyberMind CLI – Commands"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 55)))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(purple).Render("  INTERACTIVE:"))
	fmt.Println(g.Render("  cybermind") + d.Render("                    → start AI chat"))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(purple).Render("  KALI TOOLS:"))
	fmt.Println(g.Render("  cybermind scan <target> [type]") + d.Render("   → AI scan guide"))
	fmt.Println(g.Render("  cybermind recon <target> [type]") + d.Render("  → AI recon guide"))
	fmt.Println(g.Render("  cybermind exploit <vuln> [target]") + d.Render("→ exploitation guide"))
	fmt.Println(g.Render("  cybermind payload <os> [arch]") + d.Render("    → msfvenom payload"))
	fmt.Println(g.Render("  cybermind tool <name> [task]") + d.Render("     → tool usage guide"))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(purple).Render("  SCAN TYPES:"))
	fmt.Println(d.Render("  quick, full, stealth, web, vuln, subdomain, network, ad"))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(purple).Render("  RECON TYPES:"))
	fmt.Println(d.Render("  passive, active, subdomain, osint, web, network"))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(purple).Render("  HISTORY:"))
	fmt.Println(g.Render("  cybermind history") + d.Render("               → view chat history"))
	fmt.Println(g.Render("  cybermind clear") + d.Render("                 → clear history"))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(purple).Render("  EXAMPLES:"))
	fmt.Println(d.Render("  cybermind scan 192.168.1.1 full"))
	fmt.Println(d.Render("  cybermind recon example.com subdomain"))
	fmt.Println(d.Render("  cybermind exploit CVE-2021-44228 10.0.0.1"))
	fmt.Println(d.Render("  cybermind payload windows x64"))
	fmt.Println(d.Render("  cybermind tool sqlmap \"find SQLi in login form\""))
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

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		// Interactive mode
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
			printError("Types: quick, full, stealth, web, vuln, subdomain, network, ad")
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
			printError("Types: passive, active, subdomain, osint, web, network")
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
			printError("Usage: cybermind exploit <vulnerability|service> [target]")
			printError("Example: cybermind exploit CVE-2021-44228 10.0.0.1")
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
		printResult(fmt.Sprintf("Exploit Guide → %s", vuln), result)

	case "payload":
		targetOS := "windows"
		arch := "x64"
		if len(args) >= 2 {
			targetOS = args[1]
		}
		if len(args) >= 3 {
			arch = args[2]
		}
		lhost := "YOUR_IP"
		lport := "4444"
		format := "exe"
		if targetOS == "linux" {
			format = "elf"
		} else if targetOS == "android" {
			format = "apk"
		}
		fmt.Println(lipgloss.NewStyle().Foreground(purple).Render(fmt.Sprintf("  ⟳ Generating %s/%s payload guide...", targetOS, arch)))
		result, err := api.SendPayload(targetOS, arch, lhost, lport, format)
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		printResult(fmt.Sprintf("Payload Guide → %s/%s", targetOS, arch), result)

	case "tool":
		if len(args) < 2 {
			printError("Usage: cybermind tool <toolname> [task]")
			printError("Example: cybermind tool nmap \"scan for open ports\"")
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
		printResult(fmt.Sprintf("Tool Guide → %s", tool), result)

	default:
		// Treat unknown args as a direct chat prompt
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
