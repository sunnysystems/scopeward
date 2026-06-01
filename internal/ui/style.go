// Package ui holds the Sunny Systems visual identity (amber/copper) as a small
// set of lipgloss styles shared by every renderer and the Bubble Tea UI.
//
// lipgloss honors NO_COLOR and detects non-TTY output automatically, so these
// styles degrade to plain text in CI without any extra handling.
package ui

import "github.com/charmbracelet/lipgloss"

// Sunny brand palette.
var (
	Amber  = lipgloss.Color("#FFB000")
	Copper = lipgloss.Color("#B87333")
	Sand   = lipgloss.Color("#E8C9A0")
	Slate  = lipgloss.Color("#8A8A8A")

	Green = lipgloss.Color("#3FB950")
	Red   = lipgloss.Color("#F85149")
)

// Shared styles.
var (
	Title   = lipgloss.NewStyle().Bold(true).Foreground(Amber)
	Accent  = lipgloss.NewStyle().Foreground(Copper)
	Subtle  = lipgloss.NewStyle().Foreground(Slate)
	Label   = lipgloss.NewStyle().Foreground(Sand)
	Good    = lipgloss.NewStyle().Foreground(Green)
	Bad     = lipgloss.NewStyle().Bold(true).Foreground(Red)
	WarnTag = lipgloss.NewStyle().Foreground(Amber)
)
