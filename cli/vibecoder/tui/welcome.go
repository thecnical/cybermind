package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// mascotLines is the CBM Code robot mascot — similar style to Claude Code's mascot.
var mascotLines = []string{
	"         ▐▛███▜▌         ",
	"        ▝▜█████▛▘        ",
	"          ▘▘ ▝▝          ",
}

var bannerLines = []string{
	" ██████╗██████╗ ███╗   ███╗     ██████╗ ██████╗ ██████╗ ███████╗",
	"██╔════╝██╔══██╗████╗ ████║    ██╔════╝██╔═══██╗██╔══██╗██╔════╝",
	"██║     ██████╔╝██╔████╔██║    ██║     ██║   ██║██║  ██║█████╗  ",
	"██║     ██╔══██╗██║╚██╔╝██║    ██║     ██║   ██║██║  ██║██╔══╝  ",
	"╚██████╗██████╔╝██║ ╚═╝ ██║    ╚██████╗╚██████╔╝██████╔╝███████╗",
	" ╚═════╝╚═════╝ ╚═╝     ╚═╝     ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝",
}

// WelcomeInfo holds dynamic data to display in the welcome screen.
type WelcomeInfo struct {
	Tier      string // "Free" or "Pro" or "Elite"
	Model     string // active model name
	Workspace string // workspace path
	UserName  string // user name if available
}

// RenderWelcome renders the welcome dashboard based on terminal width.
// Wide (≥110): two-panel layout like Claude Code — mascot+info left, tips right
// Narrow (60-109): single column, compact
// Minimal (<60): text-only
func RenderWelcome(width int, theme Theme) string {
	return RenderWelcomeWithInfo(width, theme, WelcomeInfo{
		Tier:      "Free",
		Model:     "mistralai/mistral-7b-instruct",
		Workspace: "./",
	})
}

// RenderWelcomeWithInfo renders the welcome screen with dynamic user info.
func RenderWelcomeWithInfo(width int, theme Theme, info WelcomeInfo) string {
	switch {
	case width >= 110:
		return renderWelcomeWide(width, theme, info)
	case width >= 60:
		return renderWelcomeNarrow(width, theme, info)
	default:
		return renderWelcomeMinimal(width, theme, info)
	}
}

func renderWelcomeWide(width int, theme Theme, info WelcomeInfo) string {
	// ── Box style like Claude Code ──────────────────────────────────────────
	boxWidth := width - 4
	if boxWidth > 110 {
		boxWidth = 110
	}

	// Top border
	topBorder := "╭" + strings.Repeat("─", boxWidth-2) + "╮"
	botBorder := "╰" + strings.Repeat("─", boxWidth-2) + "╯"

	borderStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#333333"))
	cyanStyle := theme.Cyan
	dimStyle := theme.Dim
	greenStyle := theme.Green
	yellowStyle := theme.Yellow
	purpleStyle := theme.Purple

	var sb strings.Builder

	sb.WriteString(borderStyle.Render(topBorder))
	sb.WriteString("\n")

	// Split box into left (info) and right (tips) panels
	leftW := boxWidth/2 - 1
	rightW := boxWidth - leftW - 3

	// ── Left panel content ──────────────────────────────────────────────────
	var leftLines []string

	// Mascot
	for _, ml := range mascotLines {
		leftLines = append(leftLines, cyanStyle.Render(ml))
	}
	leftLines = append(leftLines, "")

	// User greeting
	greeting := "  Welcome back!"
	if info.UserName != "" {
		greeting = fmt.Sprintf("  Welcome back %s!", info.UserName)
	}
	leftLines = append(leftLines, cyanStyle.Bold(true).Render(greeting))
	leftLines = append(leftLines, "")

	// Info rows
	leftLines = append(leftLines, dimStyle.Render(fmt.Sprintf("  %-10s %s", "Tier:", info.Tier)))
	leftLines = append(leftLines, dimStyle.Render(fmt.Sprintf("  %-10s %s", "Model:", truncate(info.Model, leftW-14))))
	leftLines = append(leftLines, dimStyle.Render(fmt.Sprintf("  %-10s %s", "Workspace:", truncate(info.Workspace, leftW-14))))

	// ── Right panel content ─────────────────────────────────────────────────
	var rightLines []string

	rightLines = append(rightLines, yellowStyle.Render("  Tips for getting started"))
	rightLines = append(rightLines, dimStyle.Render("  "+strings.Repeat("─", rightW-4)))
	rightLines = append(rightLines, greenStyle.Render("  Type / to open the command menu"))
	rightLines = append(rightLines, greenStyle.Render("  Use /add <file> to add files to context"))
	rightLines = append(rightLines, greenStyle.Render("  Use /mode to switch Agent ↔ Chat"))
	rightLines = append(rightLines, greenStyle.Render("  Tab cycles through edit modes"))
	rightLines = append(rightLines, "")
	rightLines = append(rightLines, dimStyle.Render("  Edit modes"))
	rightLines = append(rightLines, dimStyle.Render("  "+strings.Repeat("─", rightW-4)))
	rightLines = append(rightLines, dimStyle.Render("  🛡 guard      → approve every action"))
	rightLines = append(rightLines, dimStyle.Render("  ✏ auto_edit  → auto-apply file writes"))
	rightLines = append(rightLines, dimStyle.Render("  📐 blueprint  → plan only, no writes"))
	rightLines = append(rightLines, dimStyle.Render("  🤖 autopilot  → smart auto-approve"))
	rightLines = append(rightLines, dimStyle.Render("  ⚡ unleashed  → full autonomy"))

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

	leftStyle := lipgloss.NewStyle().Width(leftW)
	rightStyle := lipgloss.NewStyle().Width(rightW)
	divider := borderStyle.Render("│")

	for i := 0; i < maxLen; i++ {
		row := "│" + leftStyle.Render(leftLines[i]) + divider + rightStyle.Render(rightLines[i]) + "│"
		sb.WriteString(borderStyle.Render("│"))
		sb.WriteString(leftStyle.Render(leftLines[i]))
		sb.WriteString(divider)
		sb.WriteString(rightStyle.Render(rightLines[i]))
		sb.WriteString(borderStyle.Render("│"))
		_ = row
		sb.WriteString("\n")
	}

	sb.WriteString(borderStyle.Render(botBorder))
	sb.WriteString("\n")

	// Version line below box
	sb.WriteString(purpleStyle.Render("  CBM Code v2.5.0"))
	sb.WriteString(dimStyle.Render("  ·  AI Coding Assistant  ·  cybermindcli1.vercel.app"))
	sb.WriteString("\n\n")

	return sb.String()
}

func renderWelcomeNarrow(width int, theme Theme, info WelcomeInfo) string {
	var sb strings.Builder

	sb.WriteString(theme.Cyan.Bold(true).Render("  ⚡ CBM Code — AI Coding Assistant"))
	sb.WriteString("\n\n")

	// Mascot
	for _, ml := range mascotLines {
		sb.WriteString(theme.Cyan.Render(ml))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	greeting := "  Welcome back!"
	if info.UserName != "" {
		greeting = fmt.Sprintf("  Welcome back %s!", info.UserName)
	}
	sb.WriteString(theme.Cyan.Render(greeting))
	sb.WriteString("\n\n")

	sb.WriteString(theme.Dim.Render(fmt.Sprintf("  Tier:  %s", info.Tier)))
	sb.WriteString("\n")
	sb.WriteString(theme.Dim.Render(fmt.Sprintf("  Model: %s", truncate(info.Model, 40))))
	sb.WriteString("\n\n")

	sb.WriteString(theme.Green.Render("  Type / for commands  ·  /add <file> to add context"))
	sb.WriteString("\n")
	sb.WriteString(theme.Dim.Render("  Tab cycles edit modes  ·  Ctrl+C to cancel  ·  /exit to quit"))
	sb.WriteString("\n\n")

	_ = width
	return sb.String()
}

func renderWelcomeMinimal(_ int, theme Theme, info WelcomeInfo) string {
	var sb strings.Builder

	sb.WriteString(theme.Cyan.Render("  CBM Code — AI Coding Assistant"))
	sb.WriteString("\n\n")
	sb.WriteString(theme.Dim.Render(fmt.Sprintf("  Tier: %s  ·  Model: %s", info.Tier, truncate(info.Model, 30))))
	sb.WriteString("\n")
	sb.WriteString(theme.Dim.Render("  Type / for commands. /add to add files."))
	sb.WriteString("\n\n")

	return sb.String()
}

// truncate shortens a string to maxLen, adding "..." if needed.
func truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return s
	}
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
