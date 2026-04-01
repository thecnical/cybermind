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
	var b strings.Builder

	b.WriteString("\n")

	// Header
	b.WriteString(lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00FFFF")).
		Render("  ⚡ CyberMind CLI  🧠 AI Mode  |  🔌 Connected"))
	b.WriteString("\n\n")

	// Input label + field
	b.WriteString(lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#8A2BE2")).
		Render("  › Query:"))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#00FFFF")).
		Padding(0, 1).
		MarginLeft(2).
		Render(m.input.View()))
	b.WriteString("\n")

	// Spinner while loading
	if m.state == stateLoading {
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8A2BE2")).
			Render(fmt.Sprintf("\n  %s  Contacting AI providers...", m.spinner.View())))
		b.WriteString("\n")
	}

	// AI response
	displayText := m.displayed
	if m.state == stateInput && m.fullResponse != "" {
		displayText = m.fullResponse
	}
	if displayText != "" {
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF00")).
			Render("  ⚡ CyberMind AI →"))
		b.WriteString("\n")

		width := m.width - 6
		if width < 40 {
			width = 80
		}
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			MarginLeft(4).
			Width(width).
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
		Foreground(lipgloss.Color("#444444")).
		Render("  " + strings.Repeat("─", 62)))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#555555")).
		Render("  Enter → send  •  Ctrl+C → exit  •  github.com/thecnical"))
	b.WriteString("\n")

	return b.String()
}
