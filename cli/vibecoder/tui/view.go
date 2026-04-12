package tui

import (
	"fmt"
	"strings"

	"cybermind-cli/vibecoder"

	"github.com/charmbracelet/lipgloss"
)

// filterEmpty removes empty strings from a slice.
func filterEmpty(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// renderSession builds the full session view top-to-bottom.
func (m VibeModel) renderSession() string {
	statusBar := m.renderNeuralBar()
	chatArea := m.renderChatArea()

	diffSection := ""
	if m.diffPreview != nil && m.diffPreview.Visible {
		diffSection = m.renderDiffPreview()
	}

	approvalSection := ""
	if m.approvalGate != nil && m.approvalGate.Visible {
		approvalSection = m.renderApprovalGate()
	}

	inputLine := m.renderInputLine()

	return strings.Join(filterEmpty([]string{statusBar, chatArea, diffSection, approvalSection, inputLine}), "\n")
}

// renderNeuralBar renders the status bar at the top of the session view.
func (m VibeModel) renderNeuralBar() string {
	sb := m.statusBar

	// Truncate model name to 30 chars
	modelName := sb.Model
	if len(modelName) > 30 {
		modelName = modelName[:27] + "..."
	}
	if modelName == "" {
		modelName = string(m.session.EditMode)
	}

	// Context % color
	ctxStr := fmt.Sprintf("%.0f%% ctx", sb.ContextPct)
	var ctxStyle lipgloss.Style
	switch {
	case sb.ContextPct >= 90:
		ctxStyle = m.theme.Red
	case sb.ContextPct >= 70:
		ctxStyle = m.theme.Yellow
	default:
		ctxStyle = m.theme.Green
	}

	interactMode := sb.InteractMode
	if interactMode == "" {
		interactMode = string(m.session.InteractMode)
	}
	editMode := sb.EditMode
	if editMode == "" {
		editMode = string(m.session.EditMode)
	}
	effortLevel := sb.EffortLevel
	if effortLevel == "" {
		effortLevel = string(m.session.EffortLevel)
	}

	parts := []string{
		m.theme.Cyan.Render(interactMode),
		m.theme.Purple.Render(editMode),
		m.theme.Yellow.Render(effortLevel),
		m.theme.Dim.Render(modelName),
		ctxStyle.Render(ctxStr),
		m.theme.Dim.Render(sb.PermIndicator),
	}

	if sb.BgProcesses > 0 {
		parts = append(parts, m.theme.Yellow.Render(fmt.Sprintf("⟳ %d bg", sb.BgProcesses)))
	}

	bar := " STATUS: " + strings.Join(parts, " | ") + " "

	barStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("#111111")).
		Foreground(lipgloss.Color("#CCCCCC"))

	if m.width > 0 {
		barStyle = barStyle.Width(m.width)
	}

	return barStyle.Render(bar)
}

// renderChatArea renders the scrollable conversation area.
func (m VibeModel) renderChatArea() string {
	if len(m.chatLines) == 0 {
		return m.theme.Dim.Render("  ◆ Vibe Coder ready. Type a message or / for commands.")
	}

	// Calculate visible lines based on terminal height
	// Reserve rows for: status bar (1), input line (1), separators (2)
	visibleRows := m.height - 4
	if visibleRows < 1 {
		visibleRows = 20
	}

	lines := m.chatLines
	start := m.scrollOffset
	if start < 0 {
		start = 0
	}
	end := start + visibleRows
	if end > len(lines) {
		end = len(lines)
	}
	if start > end {
		start = end
	}

	var sb strings.Builder
	for _, line := range lines[start:end] {
		rendered := line.Style.Render(line.Content)
		sb.WriteString("  ")
		sb.WriteString(rendered)
		sb.WriteString("\n")
	}

	return sb.String()
}

// renderDiffPreview renders a color-coded diff panel.
func (m VibeModel) renderDiffPreview() string {
	if m.diffPreview == nil {
		return ""
	}
	diff := m.diffPreview.Diff

	var sb strings.Builder
	sb.WriteString(m.theme.Cyan.Render("  ┌─ DIFF: " + diff.Path + " "))
	sb.WriteString("\n")

	// Combine old and new lines for display
	allLines := append(diff.OldLines, diff.NewLines...)
	for _, dl := range allLines {
		switch dl.Kind {
		case vibecoder.DiffAdded:
			sb.WriteString(m.theme.Green.Render(fmt.Sprintf("  + %s", dl.Content)))
		case vibecoder.DiffRemoved:
			sb.WriteString(m.theme.Red.Render(fmt.Sprintf("  - %s", dl.Content)))
		default:
			sb.WriteString(m.theme.Dim.Render(fmt.Sprintf("    %s", dl.Content)))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(m.theme.Cyan.Render("  └" + strings.Repeat("─", 60)))
	sb.WriteString("\n")

	return sb.String()
}

// renderApprovalGate renders the approval prompt.
func (m VibeModel) renderApprovalGate() string {
	if m.approvalGate == nil {
		return ""
	}
	gate := m.approvalGate

	var sb strings.Builder
	sb.WriteString(m.theme.Yellow.Render(fmt.Sprintf("  ⚠  %s: %s", gate.Kind, gate.Description)))
	sb.WriteString("\n")
	sb.WriteString(m.theme.Selected.Render("  [A]pply  [S]kip  [E]dit manually"))
	sb.WriteString("\n")

	return sb.String()
}

// renderInputLine renders the input prompt at the bottom.
func (m VibeModel) renderInputLine() string {
	// Edit mode icon
	icon := "⟩"
	switch m.session.EditMode {
	case vibecoder.EditModeGuard:
		icon = "🛡 ⟩"
	case vibecoder.EditModeAutoEdit:
		icon = "✏ ⟩"
	case vibecoder.EditModeBlueprint:
		icon = "📐 ⟩"
	case vibecoder.EditModeAutopilot:
		icon = "🤖 ⟩"
	case vibecoder.EditModeUnleashed:
		icon = "⚡ ⟩"
	}

	prompt := m.theme.Cyan.Render(icon) + " " + m.inputBuf

	lineStyle := lipgloss.NewStyle().
		BorderTop(true).
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("#333333"))

	if m.width > 0 {
		lineStyle = lineStyle.Width(m.width)
	}

	return lineStyle.Render(prompt)
}
