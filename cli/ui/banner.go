package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

const asciiArt = ` ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗███╗   ██╗██████╗ 
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║██║  ██║
██║       ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██║  ██║
╚██████╗   ██║   ██║     ███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
 ╚═════╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝`

var bannerColors = []lipgloss.Color{
	"#00FFFF",
	"#00CFFF",
	"#009FFF",
	"#7B68EE",
	"#8A2BE2",
	"#9400D3",
}

func RenderBanner() string {
	var b strings.Builder

	b.WriteString("\n")

	lines := strings.Split(asciiArt, "\n")
	for i, line := range lines {
		c := bannerColors[i%len(bannerColors)]
		styled := lipgloss.NewStyle().Bold(true).Foreground(c).Render(line)
		b.WriteString(styled + "\n")
	}

	b.WriteString("\n")

	tagline := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00FFFF")).
		Render("  ⚡ CyberMind CLI – AI Powered Cyber Assistant")
	b.WriteString(tagline + "\n")

	sub := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#555555")).
		Render("  created by github.com/thecnical")
	b.WriteString(sub + "\n\n")

	tipsTitle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#8A2BE2")).Render("  💡 Tips:")
	b.WriteString(tipsTitle + "\n")

	tips := []string{
		"Ask cybersecurity questions",
		"Use commands or files",
		"Get real commands and techniques",
	}
	dimTip := lipgloss.NewStyle().Foreground(lipgloss.Color("#777777"))
	for i, tip := range tips {
		b.WriteString(dimTip.Render(fmt.Sprintf("     %d. %s", i+1, tip)) + "\n")
	}

	b.WriteString("\n")

	pressKey := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#00FF00")).
		Bold(true).
		Render("  ▶  Press any key to start...")
	b.WriteString(pressKey + "\n")

	return b.String()
}
