package ui

import "github.com/charmbracelet/lipgloss"

var (
	cyan   = lipgloss.Color("#00FFFF")
	green  = lipgloss.Color("#00FF00")
	purple = lipgloss.Color("#8A2BE2")
	gray   = lipgloss.Color("#444444")
	white  = lipgloss.Color("#FFFFFF")
	red    = lipgloss.Color("#FF4444")

	HeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(cyan).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(purple).
			Padding(0, 2).
			MarginBottom(1)

	LabelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(purple)

	InputBoxStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(cyan).
			Padding(0, 1)

	OutputBoxStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(green).
			Padding(1, 2).
			MarginTop(1)

	AILabelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(green)

	ResponseStyle = lipgloss.NewStyle().
			Foreground(white)

	ErrorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(red)

	DimStyle = lipgloss.NewStyle().
			Foreground(gray)

	FooterStyle = lipgloss.NewStyle().
			Foreground(gray).
			MarginTop(1)
)
