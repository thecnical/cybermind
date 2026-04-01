package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func (m Model) View() string {
	return renderChat(m)
}

func renderChat(m Model) string {
	width := m.width
	if width < 60 {
		width = 60
	}

	divider := strings.Repeat("─", width-4)
	var b strings.Builder

	b.WriteString("\n")

	// Header
	b.WriteString(lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00FFFF")).
		Render("  ⚡ CyberMind  🧠 AI Mode  |  🔌 Connected  |  v1.0.0"))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#333333")).
		Render("  " + divider))
	b.WriteString("\n\n")

	// Input label
	b.WriteString(lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#8A2BE2")).
		Render("  › Query:"))
	b.WriteString("\n")

	// Input box — full width
	b.WriteString(lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#00FFFF")).
		Padding(0, 1).
		MarginLeft(2).
		Render(m.input.View()))
	b.WriteString("\n")

	// Hint
	b.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#444444")).
		Render("  Enter → send  •  Ctrl+C → exit"))
	b.WriteString("\n")

	// Loading
	if m.state == stateLoading {
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8A2BE2")).
			Render(fmt.Sprintf("\n  %s  Querying AI providers...", m.spinner.View())))
		b.WriteString("\n")
	}

	// Response area
	displayText := m.displayed
	if m.state == stateInput && m.fullResponse != "" {
		displayText = m.fullResponse
	}

	if displayText != "" {
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#333333")).
			Render("  " + divider))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF00")).
			Render("  ⚡ CyberMind AI →"))
		b.WriteString("\n\n")

		// Word-wrap response to terminal width
		responseWidth := width - 6
		if responseWidth < 40 {
			responseWidth = 80
		}
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E0E0E0")).
			MarginLeft(4).
			Width(responseWidth).
			Render(displayText))
		b.WriteString("\n")
	}

	// Error
	if m.errMsg != "" {
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF4444")).
			Render("  ✗ " + m.errMsg))
		b.WriteString("\n")
	}

	// Footer
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#333333")).
		Render("  " + divider))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#555555")).
		Render("  github.com/thecnical  •  CyberMind v1.0.0"))
	b.WriteString("\n")

	return b.String()
}
