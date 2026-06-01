// Package report renders an audit result for humans (clean, branded stdout) and
// for machines (JSON for CI). It is the single place output formatting lives, so
// later renderers (Markdown, HTML) slot in alongside these.
package report

import (
	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/score"
)

// Audit bundles everything produced by a run: what was collected, what checks
// found, and the resulting score.
type Audit struct {
	Snapshot *model.Snapshot
	Report   check.Report
	Score    score.Score
	// Suppressed lists findings hidden by the ignore config (.scopeward.yml); they
	// do not count toward the score or --fail-on.
	Suppressed []model.Finding

	// Baseline comparison (set when --baseline is used).
	HasBaseline   bool
	NewKeys       map[string]bool // FindingKey of findings absent from the baseline
	ResolvedCount int             // baseline findings no longer present
}

// FindingKey is the stable identity of a finding for baseline comparison: the
// same finding across runs produces the same key.
func FindingKey(f model.Finding) string {
	return f.CheckID + "\x00" + f.Resource.Name + "\x00" + f.Title
}

// IsNew reports whether a finding is new relative to the baseline.
func (a Audit) IsNew(f model.Finding) bool {
	return a.NewKeys != nil && a.NewKeys[FindingKey(f)]
}
