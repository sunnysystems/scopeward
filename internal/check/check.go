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
	// SurvivesArchiving marks a check whose findings remain true after the
	// repository is archived. Almost nothing does: archiving makes a repo
	// read-only, so who may push to it stops mattering. A leaked credential does
	// not stop mattering, which is why the distinction has to be recorded rather
	// than assumed. Reporting reads this to avoid promising that archiving
	// resolves a finding it would not.
	SurvivesArchiving bool
}

// Check evaluates one governance concern against the snapshot.
type Check interface {
	Meta() CheckMeta
	Run(ctx context.Context, s *model.Snapshot) []model.Finding
}

// Limiter is an optional interface for a check whose scope can be narrowed by
// something other than missing data — today, a paid entitlement the org does not
// hold, which makes a finding's remediation impossible rather than merely
// unperformed (issue #50).
//
// It exists because the two states the Runner already models cannot express
// this one. RequiresData is all-or-nothing: a check either evaluates or is
// skipped. But push protection is free on public repositories and paid on
// private ones, so the honest answer for an org without the entitlement is
// neither "evaluated" nor "not evaluated" — it is "evaluated on 3 of 42". A
// check that just dropped the unfixable resources would report a clean bill for
// the 39 it never looked at, which is the silent pass the Runner exists to
// prevent.
//
// A check implements this in addition to Run, and must keep the two consistent:
// whatever Run leaves out is what Limitation must account for.
type Limiter interface {
	// Limitation describes the scope this check could not assess, or nil when it
	// assessed everything.
	Limitation(s *model.Snapshot) *Limitation
}

// Limitation records that a check ran, but not over its whole scope.
type Limitation struct {
	CheckID string     `json:"check_id"`
	Title   string     `json:"title"`
	Axis    model.Axis `json:"axis"`
	// Reason states what put the omitted resources out of reach, in the reader's
	// terms ("requires GitHub Secret Protection"), not the mechanism's.
	Reason string `json:"reason"`
	// Assessed and Omitted are resource counts, so the reader can size the gap
	// rather than infer it. Assessed == 0 means nothing was evaluated at all,
	// which the Runner promotes to Skipped.
	Assessed int `json:"assessed"`
	Omitted  int `json:"omitted"`
}

// Skipped records a check that was not evaluated: required data was missing or
// partial, or its entire scope was out of reach.
type Skipped struct {
	CheckID string           `json:"check_id"`
	Title   string           `json:"title"`
	Axis    model.Axis       `json:"axis"`
	Missing []model.DataKind `json:"missing_data,omitempty"`
	// Reason is set when the check was skipped for something other than missing
	// data, where naming the DataKinds would not tell the reader anything
	// actionable ("requires GitHub Secret Protection").
	Reason string `json:"reason,omitempty"`
}

// Report is the outcome of a Runner pass.
type Report struct {
	Findings []model.Finding `json:"findings"`
	Skipped  []Skipped       `json:"not_evaluated,omitempty"`
	Limited  []Limitation    `json:"partially_evaluated,omitempty"`
}
