package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// mascotLines is the CyberMind pixel-art robot mascot.
var mascotLines = []string{
	"  ╔═══════╗  ",
	"  ║ ◉   ◉ ║  ",
	"  ║   ▲   ║  ",
	"  ║ ─────  ║  ",
	"  ╚═══╤═══╝  ",
	"    ╔═╧═╗    ",
	"  ╔═╡   ╞═╗  ",
	"  ╚═╡   ╞═╝  ",
	"    ╚═══╝    ",
}

var bannerLines = []string{
	"  ██████╗██████╗ ███╗   ███╗     ██████╗ ██████╗ ██████╗ ███████╗",
	" ██╔════╝██╔══██╗████╗ ████║    ██╔════╝██╔═══██╗██╔══██╗██╔════╝",
	" ██║     ██████╔╝██╔████╔██║    ██║     ██║   ██║██║  ██║█████╗  ",
	" ██║     ██╔══██╗██║╚██╔╝██║    ██║     ██║   ██║██║  ██║██╔══╝  ",
	" ╚██████╗██████╔╝██║ ╚═╝ ██║    ╚██████╗╚██████╔╝██████╔╝███████╗",
	"  ╚═════╝╚═════╝ ╚═╝     ╚═╝     ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝",
}

// RenderWelcome renders the welcome dashboard based on terminal width.
// Wide (≥100): two-panel layout with mascot + info left, quick start right
// Narrow (60-99): single column, compact mascot
// Minimal (<60): text-only, no ASCII art
func RenderWelcome(width int, theme Theme) string {
	switch {
	case width >= 100:
		return renderWelcomeWide(width, theme)
	case width >= 60:
		return renderWelcomeNarrow(width, theme)
	default:
		return renderWelcomeMinimal(width, theme)
	}
}

func renderWelcomeWide(width int, theme Theme) string {
	var sb strings.Builder

	// Banner
	for _, line := range bannerLines {
		sb.WriteString(theme.Cyan.Render(line))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	// Two-panel layout
	leftWidth := width/2 - 2
	rightWidth := width - leftWidth - 4

	// Left panel: mascot + user info
	var leftLines []string
	for _, ml := range mascotLines {
		leftLines = append(leftLines, theme.Cyan.Render(ml))
	}
	leftLines = append(leftLines, "")
	leftLines = append(leftLines, theme.Dim.Render("  TIER:      Free"))
	leftLines = append(leftLines, theme.Dim.Render("  MODEL:     mistralai/mistral-7b"))
	leftLines = append(leftLines, theme.Dim.Render("  WORKSPACE: ./"))

	// Right panel: quick start tips
	var rightLines []string
	rightLines = append(rightLines, theme.Yellow.Render("  QUICK START"))
	rightLines = append(rightLines, theme.Dim.Render("  ─────────────────────────────"))
	rightLines = append(rightLines, theme.Green.Render("  Type / to open the command menu."))
	rightLines = append(rightLines, theme.Green.Render("  Use /add to include files in context."))
	rightLines = append(rightLines, theme.Green.Render("  Use /mode to switch interaction mode."))
	rightLines = append(rightLines, theme.Green.Render("  Tab cycles through edit modes."))
	rightLines = append(rightLines, "")
	rightLines = append(rightLines, theme.Dim.Render("  EDIT MODES"))
	rightLines = append(rightLines, theme.Dim.Render("  ─────────────────────────────"))
	rightLines = append(rightLines, theme.Dim.Render("  guard      → approve everything"))
	rightLines = append(rightLines, theme.Dim.Render("  auto_edit  → auto-apply writes"))
	rightLines = append(rightLines, theme.Dim.Render("  blueprint  → plan only, no writes"))
	rightLines = append(rightLines, theme.Dim.Render("  autopilot  → smart auto-approve"))
	rightLines = append(rightLines, theme.Dim.Render("  unleashed  → full autonomy"))

	// Pad panels to same height
	maxLen := len(leftLines)
	if len(rightLines) > maxLen {
		maxLen = len(rightLines)
	}
	for len(leftLines) < maxLen {
		leftLines = append(leftLines, "")
	}
	for len(rightLines) < maxLen {
		rightLines = append(rightLines, "")
	}

	leftStyle := lipgloss.NewStyle().Width(leftWidth)
	rightStyle := lipgloss.NewStyle().Width(rightWidth)

	for i := 0; i < maxLen; i++ {
		row := lipgloss.JoinHorizontal(lipgloss.Top,
			leftStyle.Render(leftLines[i]),
			rightStyle.Render(rightLines[i]),
		)
		sb.WriteString(row)
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	sb.WriteString(theme.Selected.Render("  Press any key to start →"))
	sb.WriteString("\n")

	return sb.String()
}

func renderWelcomeNarrow(width int, theme Theme) string {
	var sb strings.Builder

	// Compact banner (just the title text)
	sb.WriteString(theme.Cyan.Bold(true).Render("  ⚡ CBM Code — AI Coding Assistant"))
	sb.WriteString("\n\n")

	// Mascot
	for _, ml := range mascotLines {
		sb.WriteString(theme.Cyan.Render(ml))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	// User info
	sb.WriteString(theme.Dim.Render("  TIER:  Free"))
	sb.WriteString("\n")
	sb.WriteString(theme.Dim.Render("  MODEL: mistralai/mistral-7b"))
	sb.WriteString("\n\n")

	// Tips
	sb.WriteString(theme.Green.Render("  Type / to open the command menu."))
	sb.WriteString("\n")
	sb.WriteString(theme.Green.Render("  Use /add to include files in context."))
	sb.WriteString("\n\n")

	sb.WriteString(theme.Selected.Render("  Press any key to start →"))
	sb.WriteString("\n")

	_ = width
	return sb.String()
}

func renderWelcomeMinimal(width int, theme Theme) string {
	var sb strings.Builder

	sb.WriteString(theme.Cyan.Render("  CBM Code — AI Coding Assistant"))
	sb.WriteString("\n\n")
	sb.WriteString(theme.Dim.Render("  TIER: Free"))
	sb.WriteString("\n")
	sb.WriteString(theme.Dim.Render("  Type / for commands. /add to add files."))
	sb.WriteString("\n\n")
	sb.WriteString(theme.Selected.Render("  Press any key to start →"))
	sb.WriteString("\n")

	_ = width
	return sb.String()
}
