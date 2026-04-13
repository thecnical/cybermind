package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// SlashCommand represents a single slash command entry.
type SlashCommand struct {
	Name        string
	Description string
	Category    string
}

var allCommands = []SlashCommand{
	{"/init", "Initialize CYBERMIND.md for this project", "File"},
	{"/clear", "Reset context window", "Session"},
	{"/add", "Add file(s) to context", "File"},
	{"/undo", "Undo last file change", "File"},
	{"/exit", "End session", "Session"},
	{"/mode", "Switch interaction or edit mode", "Mode"},
	{"/model", "Override active model", "Model"},
	{"/debug", "Enter debug mode", "Debug"},
	{"/plan", "Enter blueprint/plan mode", "Mode"},
	{"/help", "Show help", "Help"},
	{"/resume", "Resume a previous session", "Session"},
	{"/providers", "List configured providers", "Model"},
	{"/compress", "Compress context window", "Session"},
	{"/history", "View session history", "Session"},
	{"/style", "Change UI style preset", "Mode"},
	{"/template", "Use a project template", "File"},
	{"/run", "Start dev server", "Cyber"},
	{"/build", "Run production build", "Cyber"},
	{"/deploy", "Deploy to hosting provider", "Cyber"},
	{"/explain", "Explain a file in plain language", "Help"},
	{"/scan", "Vulnerability scan", "Cyber"},
	{"/cve-check", "Check dependencies for CVEs", "Cyber"},
	{"/fix-vuln", "Fix a detected vulnerability", "Cyber"},
	{"/audit", "Generate security audit report", "Cyber"},
	{"/skills", "List all available skills", "Skills"},
	{"/hooks", "Show hook configuration", "Skills"},
	// Built-in skills (always shown)
	{"/review", "Code review — correctness, security, performance", "Skills"},
	{"/commit", "Generate conventional commit message", "Skills"},
	{"/security", "Deep security audit (OWASP Top 10)", "Skills"},
	{"/test", "Generate comprehensive tests", "Skills"},
	{"/document", "Generate documentation", "Skills"},
	{"/refactor", "Refactor for clarity and performance", "Skills"},
	{"/explain", "Explain code in plain language", "Skills"},
	{"/pr", "Generate pull request description", "Skills"},
	{"/debug", "Systematically debug an issue", "Skills"},
	{"/migrate", "Generate database migration", "Skills"},
}

// SlashMenuModel manages the slash command popup state.
type SlashMenuModel struct {
	commands []SlashCommand
	filtered []SlashCommand
	selected int
}

// NewSlashMenuModel creates a new SlashMenuModel with all commands visible.
func NewSlashMenuModel() SlashMenuModel {
	return SlashMenuModel{
		commands: allCommands,
		filtered: allCommands,
		selected: 0,
	}
}

// Filter filters commands by prefix (case-insensitive).
func (m *SlashMenuModel) Filter(prefix string) {
	prefix = strings.ToLower(prefix)
	m.filtered = nil
	for _, cmd := range m.commands {
		if strings.Contains(strings.ToLower(cmd.Name), prefix) ||
			strings.Contains(strings.ToLower(cmd.Description), prefix) {
			m.filtered = append(m.filtered, cmd)
		}
	}
	if m.selected >= len(m.filtered) {
		m.selected = 0
	}
}

// MoveUp moves selection up.
func (m *SlashMenuModel) MoveUp() {
	if m.selected > 0 {
		m.selected--
	}
}

// MoveDown moves selection down.
func (m *SlashMenuModel) MoveDown() {
	if m.selected < len(m.filtered)-1 {
		m.selected++
	}
}

// Selected returns the currently selected command name, or "" if none.
func (m *SlashMenuModel) Selected() string {
	if len(m.filtered) == 0 {
		return ""
	}
	return m.filtered[m.selected].Name
}

// Render renders the slash menu as a lipgloss overlay.
func (m SlashMenuModel) Render(width int, theme Theme) string {
	if len(m.filtered) == 0 {
		return lipgloss.NewStyle().Foreground(theme.Dim.GetForeground()).Render("  (no matching commands)")
	}

	var lines []string
	maxShow := 8
	if len(m.filtered) < maxShow {
		maxShow = len(m.filtered)
	}

	for i := 0; i < maxShow; i++ {
		cmd := m.filtered[i]
		line := fmt.Sprintf("  %-16s %s", cmd.Name, cmd.Description)
		if i == m.selected {
			lines = append(lines, theme.Selected.Render("▶ "+line))
		} else {
			lines = append(lines, theme.Dim.Render("  "+line))
		}
	}

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(theme.Cyan.GetForeground()).
		Width(min(width-4, 70)).
		Render(strings.Join(lines, "\n"))

	return box
}

// AddSkillCommands adds dynamically loaded skills to the command list.
func (m *SlashMenuModel) AddSkillCommands(skills []SlashCommand) {
	// Remove existing skill entries to avoid duplicates
	var base []SlashCommand
	for _, cmd := range m.commands {
		if cmd.Category != "Skills" {
			base = append(base, cmd)
		}
	}
	m.commands = append(base, skills...)
	m.filtered = m.commands
}
