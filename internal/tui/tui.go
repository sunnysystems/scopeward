// Package tui provides an optional interactive terminal UI for browsing an
// audit: it collects asynchronously (as a tea.Cmd) behind a spinner, then lets
// the user navigate findings with a live detail pane. It is purely a viewer over
// a report.Audit and performs no I/O itself — the audit is injected.
package tui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sunnysystems/scopeward/internal/report"
)

// AuditFunc runs the audit and returns its result. The TUI invokes it inside a
// tea.Cmd so the UI stays responsive while collection runs.
type AuditFunc func(ctx context.Context) (report.Audit, error)

// Run starts the interactive program for an org and blocks until the user quits.
func Run(ctx context.Context, org string, audit AuditFunc) error {
	m := newModel(ctx, org, audit)
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}
