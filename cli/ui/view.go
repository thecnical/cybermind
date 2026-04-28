package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Version is injected from main package at build time via ldflags.
// Fallback: read from binary version string.
var Version = "5.4.0"

// Fixed bottom section height: divider(1) + input label(1) + input box(3) + footer(1) = 6
const bottomHeight = 6

func (m Model) View() string {
	if m.width < 30 || m.height < 8 {
		return "  Resize terminal (min 30x8)\n"
	}

	w := m.width
	rw := w - 8 // response content width
	if rw < 20 {
		rw = 20
	}

	// Available lines for chat area = total height - header(2) - bottom(6)
	chatAreaHeight := m.height - 2 - bottomHeight
	if chatAreaHeight < 2 {
		chatAreaHeight = 2
	}

	var b strings.Builder

	// ── HEADER (2 lines, no gap) ──────────────────────────────
	b.WriteString(lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00FFFF")).
		Render(fmt.Sprintf("  ⚡ CyberMind v%s  🧠 AI  |  🔌 Live  |  PgUp/PgDn scroll  |  Ctrl+L clear", Version)))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#1a1a1a")).
		Render("  " + strings.Repeat("─", w-4)))
	b.WriteString("\n")

	// ── CHAT AREA ────────────────────────────────────────────
	switch m.state {

	case stateWaking:
		for i := 0; i < chatAreaHeight-1; i++ {
			b.WriteString("\n")
		}
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FFFF")).
			Render(fmt.Sprintf("  %s  Connecting to CyberMind backend...", m.spinner.View())))
		b.WriteString("\n")

	case stateLoading:
		lines := buildChatLines(m, rw)
		lines = append(lines, lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8A2BE2")).
			Render(fmt.Sprintf("  %s  Thinking... (backend auto-wakes if sleeping — ~30s first time)", m.spinner.View())))
		b.WriteString(renderChatArea(lines, chatAreaHeight, m.scrollOffset))

	case stateKeyPrompt:
		// Full-screen key setup on first launch
		for i := 0; i < chatAreaHeight-7; i++ {
			b.WriteString("\n")
		}
		b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700")).
			Render("  ⚡ Welcome to CyberMind CLI"))
		b.WriteString("\n\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).
			Render("  An API key is required to use CyberMind."))
		b.WriteString("\n\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).
			Render("  1. Visit  → https://cybermindcli1.vercel.app/dashboard"))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).
			Render("  2. Sign up / log in → click \"New key\" → copy it"))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).
			Render("  3. Paste your key below and press Enter"))
		b.WriteString("\n\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")).
			Render("  Free plan: 20 req/day  |  Pro: 200/day  |  Elite: unlimited"))
		b.WriteString("\n")

	case stateTyping, stateInput:
		lines := buildChatLines(m, rw)
		b.WriteString(renderChatArea(lines, chatAreaHeight, m.scrollOffset))
	}

	// ── ERROR / INFO ─────────────────────────────────────────
	if m.infoMsg != "" {
		b.WriteString(lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF88")).
			Render("  ✓ " + m.infoMsg))
		b.WriteString("\n")
	}
	if m.errMsg != "" {
		msg := m.errMsg
		if len([]rune(msg)) > w-6 {
			msg = string([]rune(msg)[:w-9]) + "..."
		}
		b.WriteString(lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF4444")).
			Render("  ✗ " + msg))
		b.WriteString("\n")
	}

	// ── BOTTOM — always visible ───────────────────────────────
	b.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#1a1a1a")).
		Render("  " + strings.Repeat("─", w-4)))
	b.WriteString("\n")

	if m.state == stateKeyPrompt {
		b.WriteString(lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFD700")).
			Render("  🔑"))
		b.WriteString(" ")
		b.WriteString(m.keyInput.View())
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#333333")).
			Render("  Enter=save key  Esc=cancel  Key is masked while typing"))
	} else {
		b.WriteString(lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#8A2BE2")).
			Render("  ›"))
		b.WriteString(" ")
		b.WriteString(m.input.View())
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#333333")).
			Render("  Enter=send  Ctrl+C=exit  PgUp/PgDn=scroll"))
		if m.lastUsage != "" {
			b.WriteString("  ")
			b.WriteString(lipgloss.NewStyle().
				Foreground(lipgloss.Color("#444444")).
				Render("│  " + m.lastUsage))
		}
	}
	b.WriteString("\n")

	return b.String()
}

// buildChatLines builds all chat lines (history + current typing)
func buildChatLines(m Model, rw int) []string {
	var lines []string

	// Past history entries
	for _, entry := range m.history {
		// User line
		lines = append(lines,
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#8A2BE2")).
				Render("  › "+truncateLine(entry.Prompt, rw)))

		// AI response — wrap into lines
		lines = append(lines,
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF00")).
				Render("  ⚡ CyberMind"))

		respLines := wrapText(entry.Response, rw)
		for _, rl := range respLines {
			lines = append(lines,
				lipgloss.NewStyle().Foreground(lipgloss.Color("#CCCCCC")).
					Render("    "+rl))
		}
		// Context usage line — shows tokens used for this exchange
		promptRunes := len([]rune(entry.Prompt))
		respRunes := len([]rune(entry.Response))
		totalChars := promptRunes + respRunes
		lines = append(lines,
			lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).
				Render(fmt.Sprintf("  ─ context: ~%d chars used this exchange", totalChars)))
		lines = append(lines, "") // blank separator
	}

	// Currently typing response
	if m.displayed != "" {
		lines = append(lines,
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#8A2BE2")).
				Render("  › "+truncateLine(m.lastPrompt, rw)))
		lines = append(lines,
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF00")).
				Render("  ⚡ CyberMind"))
		respLines := wrapText(m.displayed, rw)
		for _, rl := range respLines {
			lines = append(lines,
				lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).
					Render("    "+rl))
		}
	}

	return lines
}

// renderChatArea shows the visible window of chat lines, newest at bottom
func renderChatArea(lines []string, height, scrollOffset int) string {
	total := len(lines)

	// Clamp scroll
	maxScroll := total - height
	if maxScroll < 0 {
		maxScroll = 0
	}
	if scrollOffset > maxScroll {
		scrollOffset = maxScroll
	}

	// Window: show lines ending at (total - scrollOffset)
	end := total - scrollOffset
	if end < 0 {
		end = 0
	}
	start := end - height
	if start < 0 {
		start = 0
	}

	visible := lines[start:end]

	var b strings.Builder
	// Pad top if not enough lines
	for i := len(visible); i < height; i++ {
		b.WriteString("\n")
	}
	for _, l := range visible {
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.String()
}

// wrapText wraps text to fit within maxWidth runes per line
func wrapText(text string, maxWidth int) []string {
	if maxWidth < 10 {
		maxWidth = 10
	}
	var result []string
	paragraphs := strings.Split(text, "\n")
	for _, para := range paragraphs {
		if para == "" {
			result = append(result, "")
			continue
		}
		runes := []rune(para)
		for len(runes) > maxWidth {
			// Try to break at space
			breakAt := maxWidth
			for i := maxWidth; i > maxWidth-20 && i > 0; i-- {
				if runes[i] == ' ' {
					breakAt = i
					break
				}
			}
			result = append(result, string(runes[:breakAt]))
			runes = runes[breakAt:]
			// Trim leading space
			for len(runes) > 0 && runes[0] == ' ' {
				runes = runes[1:]
			}
		}
		if len(runes) > 0 {
			result = append(result, string(runes))
		}
	}
	return result
}

func truncateLine(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-3]) + "..."
}
