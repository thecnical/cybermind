package main

import (
	"fmt"
	"os"

	"cybermind-cli/storage"
	"cybermind-cli/ui"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func printBanner() {
	cyan := lipgloss.Color("#00FFFF")
	purple := lipgloss.Color("#8A2BE2")
	green := lipgloss.Color("#00FF00")
	dim := lipgloss.Color("#777777")
	credit := lipgloss.Color("#555555")

	lines := []struct {
		text  string
		color string
	}{
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
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  ⚡ CyberMind CLI – AI Powered Cyber Assistant"))
	fmt.Println(lipgloss.NewStyle().Foreground(credit).Render("  created by github.com/thecnical"))
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(purple).Render("  💡 Tips:"))
	tips := []string{
		"Ask cybersecurity questions",
		"Use commands or files",
		"Get real commands and techniques",
	}
	for i, t := range tips {
		fmt.Println(lipgloss.NewStyle().Foreground(dim).Render(fmt.Sprintf("     %d. %s", i+1, t)))
	}
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(green).Render("  ▶  Starting CLI..."))
	fmt.Println()

	_ = cyan
	_ = purple
	_ = green
	_ = dim
	_ = credit
}

func main() {
	// Handle non-interactive commands first
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "history":
			if err := storage.Load(); err != nil {
				fmt.Println("Error loading history:", err)
				os.Exit(1)
			}
			storage.PrintHistory()
			return

		case "clear":
			if err := storage.ClearHistory(); err != nil {
				fmt.Println("Error clearing history:", err)
				os.Exit(1)
			}
			fmt.Println(lipgloss.NewStyle().
				Foreground(lipgloss.Color("#00FF00")).
				Render("  ✓ Chat history cleared."))
			return

		case "help":
			fmt.Println("\n  CyberMind CLI – Commands:")
			fmt.Println("  cybermind            → start interactive chat")
			fmt.Println("  cybermind history    → view chat history")
			fmt.Println("  cybermind clear      → clear chat history")
			fmt.Println("  cybermind help       → show this help")
			fmt.Println()
			return
		}
	}

	// Load history into memory on startup
	if err := storage.Load(); err != nil {
		fmt.Println("Warning: could not load history:", err)
	}

	printBanner()

	p := tea.NewProgram(ui.NewModel())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
