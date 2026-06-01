package check

import (
	"context"
	"sort"

	"github.com/sunnysystems/scopeward/internal/model"
)

// Run evaluates the given checks against the snapshot. A check runs only when
// every DataKind it requires was fully collected (coverage status OK); otherwise
// it is recorded as not-evaluated. Findings are returned sorted by severity
// (most urgent first), then check ID for stability.
func Run(ctx context.Context, snap *model.Snapshot, checks []Check) Report {
	var rep Report

	for _, c := range checks {
		meta := c.Meta()
		if missing := unmetData(snap, meta.RequiresData); len(missing) > 0 {
			rep.Skipped = append(rep.Skipped, Skipped{
				CheckID: meta.ID,
				Title:   meta.Title,
				Axis:    meta.Axis,
				Missing: missing,
			})
			continue
		}
		rep.Findings = append(rep.Findings, c.Run(ctx, snap)...)
	}

	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		return a.CheckID < b.CheckID
	})
	return rep
}

// unmetData returns the required kinds that were not collected with full (OK)
// coverage. Partial coverage counts as unmet: we would rather report "not
// evaluated" than risk a false pass on incomplete data.
func unmetData(snap *model.Snapshot, required []model.DataKind) []model.DataKind {
	var missing []model.DataKind
	for _, kind := range required {
		c, ok := snap.Coverage.Get(kind)
		if !ok || c.Status != model.CoverageOK {
			missing = append(missing, kind)
		}
	}
	return missing
}
