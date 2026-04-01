package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func (m Model) View() string {
	// Minimum terminal size guard
	if m.width < 40 || m.height < 10 {
		return "  Terminal too small. Please resize to at least 40x10.\n"
	}
	return renderChat(m)
}

func renderChat(m Model) string {
	width := m.width
	height := m.height

	divider := strings.Repeat("─", width-4)

	// ── Fixed UI chrome heights ──────────────────────────────
	// header(2) + divider(1) + inputLabel(1) + inputBox(3) + hint(1) + footer(2) = 10
	const chromeLines = 10
	// Lines available for the response area
	responseAreaHeight := height - chromeLines
	if responseAreaHeight < 3 {
		responseAreaHeight = 3
	}

	var b strings.Builder

	// ── HEADER ───────────────────────────────────────────────
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00FFFF")).
		Render(fmt.Sprintf("  ⚡ CyberMind  🧠 AI Mode  |  🔌 Connected  |  v%s", "2.1.0")))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#222222")).
		Render("  " + divider))
	b.WriteString("\n")

	// ── RESPONSE / STATUS AREA ───────────────────────────────
	responseWidth := width - 6
	if responseWidth < 20 {
		responseWidth = 20
	}

	switch m.state {
	case stateWaking:
		// Connecting message
		for i := 0; i < responseAreaHeight-1; i++ {
			b.WriteString("\n")
		}
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FFFF")).
			Render(fmt.Sprintf("  %s  Connecting to CyberMind backend...", m.spinner.View())))
		b.WriteString("\n")

	case stateLoading:
		// Show previous history + loading spinner
		historyLines := renderHistory(m, responseWidth, responseAreaHeight-2)
		b.WriteString(historyLines)
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8A2BE2")).
			Render(fmt.Sprintf("  %s  Querying AI providers...", m.spinner.View())))
		b.WriteString("\n")

	case stateTyping, stateInput:
		// Build full response text
		displayText := m.displayed
		// Only show currentDisplay if we are actively typing (not yet in history)
		if m.state == stateInput {
			displayText = "" // already moved to history
		}

		if displayText != "" || len(m.history) > 0 {
			// Render history + current response, clipped to available height
			content := buildResponseContent(m, displayText, responseWidth)
			lines := strings.Split(content, "\n")

			// Apply scroll offset
			totalLines := len(lines)
			maxScroll := totalLines - responseAreaHeight
			if maxScroll < 0 {
				maxScroll = 0
			}
			offset := m.scrollOffset
			if offset > maxScroll {
				offset = maxScroll
			}

			// Slice visible window from bottom (newest content at bottom)
			start := totalLines - responseAreaHeight - offset
			if start < 0 {
				start = 0
			}
			end := start + responseAreaHeight
			if end > totalLines {
				end = totalLines
			}

			visible := lines[start:end]
			// Pad to fill area
			for len(visible) < responseAreaHeight {
				visible = append([]string{""}, visible...)
			}

			b.WriteString(strings.Join(visible, "\n"))
			b.WriteString("\n")

			// Scroll indicator
			if maxScroll > 0 {
				scrollHint := ""
				if offset > 0 {
					scrollHint = fmt.Sprintf("  ↑ scrolled up %d lines  (↓ to scroll down)", offset)
				} else {
					scrollHint = "  ↑ PgUp/↑ to scroll  •  ↓ PgDn/↓ to scroll down"
				}
				b.WriteString(lipgloss.NewStyle().
					Foreground(lipgloss.Color("#555555")).
					Render(scrollHint))
				b.WriteString("\n")
			}
		} else {
			// Empty state — fill with blank lines
			for i := 0; i < responseAreaHeight; i++ {
				b.WriteString("\n")
			}
		}
	}

	// ── ERROR ────────────────────────────────────────────────
	if m.errMsg != "" {
		errText := m.errMsg
		if len(errText) > width-6 {
			errText = errText[:width-9] + "..."
		}
		b.WriteString(lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF4444")).
			Render("  ✗ " + errText))
		b.WriteString("\n")
	}

	// ── DIVIDER ──────────────────────────────────────────────
	b.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#222222")).
		Render("  " + divider))
	b.WriteString("\n")

	// ── INPUT — always at bottom ─────────────────────────────
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

	// ── FOOTER ───────────────────────────────────────────────
	b.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#444444")).
		Render("  Enter → send  •  Ctrl+C → exit  •  ↑↓ scroll"))
	b.WriteString("\n")

	return b.String()
}

// buildResponseContent builds the full scrollable content string
func buildResponseContent(m Model, currentDisplay string, responseWidth int) string {
	var b strings.Builder

	// Previous history entries (dimmed)
	for _, entry := range m.history {
		// User prompt
		b.WriteString(lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#8A2BE2")).
			Render("  › " + truncateLine(entry.Prompt, responseWidth-4)))
		b.WriteString("\n")

		// AI response
		b.WriteString(lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF00")).
			Render("  ⚡ CyberMind →"))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888")).
			MarginLeft(4).
			Width(responseWidth).
			Render(entry.Response))
		b.WriteString("\n\n")
	}

	// Current response being typed (only during stateTyping, not after)
	if currentDisplay != "" {
		b.WriteString(lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#8A2BE2")).
			Render("  › " + truncateLine(m.lastPrompt, responseWidth-4)))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF00")).
			Render("  ⚡ CyberMind →"))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E0E0E0")).
			MarginLeft(4).
			Width(responseWidth).
			Render(currentDisplay))
		b.WriteString("\n")
	}

	return b.String()
}

// renderHistory renders previous history entries clipped to available lines
func renderHistory(m Model, responseWidth, maxLines int) string {
	full := buildResponseContent(m, "", responseWidth)
	lines := strings.Split(full, "\n")
	if len(lines) <= maxLines {
		// Pad top
		padding := maxLines - len(lines)
		return strings.Repeat("\n", padding) + full
	}
	// Show last maxLines
	return strings.Join(lines[len(lines)-maxLines:], "\n") + "\n"
}

func truncateLine(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max-3]) + "..."
}
