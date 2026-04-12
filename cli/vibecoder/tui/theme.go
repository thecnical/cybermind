package tui

import "github.com/charmbracelet/lipgloss"

// Theme holds all color styles for the TUI.
type Theme struct {
	Cyan     lipgloss.Style
	Purple   lipgloss.Style
	Green    lipgloss.Style
	Red      lipgloss.Style
	Yellow   lipgloss.Style
	Dim      lipgloss.Style
	User     lipgloss.Style
	Error    lipgloss.Style
	Selected lipgloss.Style
	Name     string
}

// CyberTheme is the default cyan/purple theme.
func CyberTheme() Theme {
	return Theme{
		Name:     "cyber",
		Cyan:     lipgloss.NewStyle().Foreground(lipgloss.Color("#00d4ff")),
		Purple:   lipgloss.NewStyle().Foreground(lipgloss.Color("#8A2BE2")),
		Green:    lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")),
		Red:      lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")),
		Yellow:   lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")),
		Dim:      lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")),
		User:     lipgloss.NewStyle().Foreground(lipgloss.Color("#00d4ff")).Bold(true),
		Error:    lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Bold(true),
		Selected: lipgloss.NewStyle().Foreground(lipgloss.Color("#00d4ff")).Bold(true),
	}
}

// MatrixTheme is the green-on-black matrix theme.
func MatrixTheme() Theme {
	return Theme{
		Name:     "matrix",
		Cyan:     lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")),
		Purple:   lipgloss.NewStyle().Foreground(lipgloss.Color("#00AA00")),
		Green:    lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")),
		Red:      lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")),
		Yellow:   lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFF00")),
		Dim:      lipgloss.NewStyle().Foreground(lipgloss.Color("#004400")),
		User:     lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true),
		Error:    lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true),
		Selected: lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true),
	}
}

// MinimalTheme is the monochrome minimal theme.
func MinimalTheme() Theme {
	return Theme{
		Name:     "minimal",
		Cyan:     lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")),
		Purple:   lipgloss.NewStyle().Foreground(lipgloss.Color("#AAAAAA")),
		Green:    lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")),
		Red:      lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true),
		Yellow:   lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")),
		Dim:      lipgloss.NewStyle().Foreground(lipgloss.Color("#666666")),
		User:     lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true),
		Error:    lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true),
		Selected: lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true),
	}
}

// ThemeByName returns a theme by name, defaulting to CyberTheme.
func ThemeByName(name string) Theme {
	switch name {
	case "matrix":
		return MatrixTheme()
	case "minimal":
		return MinimalTheme()
	default:
		return CyberTheme()
	}
}
