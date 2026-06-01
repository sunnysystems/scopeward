// Package check defines the pluggable Check interface, a self-registering
// registry, and the Runner that evaluates checks against a collected Snapshot.
//
// Checks are pure functions over a Snapshot: they perform no I/O. Each declares
// which DataKinds it needs; the Runner skips a check when that data was not
// fully collected and records it as "not evaluated" — never a false pass.
package check

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/model"
)

// CheckMeta is the static description of a check.
type CheckMeta struct {
	ID              string           // stable, e.g. "human.no-2fa"
	Title           string           // short human label
	Axis            model.Axis       // governance dimension
	DefaultSeverity model.Severity   // severity used unless a finding overrides it
	RequiresData    []model.DataKind // inputs that must be fully collected to evaluate
	Description     string           // what the check looks for and why it matters
}

// Check evaluates one governance concern against the snapshot.
type Check interface {
	Meta() CheckMeta
	Run(ctx context.Context, s *model.Snapshot) []model.Finding
}

// Skipped records a check that could not be evaluated because required data was
// missing or only partially collected.
type Skipped struct {
	CheckID string           `json:"check_id"`
	Title   string           `json:"title"`
	Axis    model.Axis       `json:"axis"`
	Missing []model.DataKind `json:"missing_data"`
}

// Report is the outcome of a Runner pass.
type Report struct {
	Findings []model.Finding `json:"findings"`
	Skipped  []Skipped       `json:"not_evaluated,omitempty"`
}
