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
		found := c.Run(ctx, snap)

		// A check may have run over only part of its scope. Record that next to
		// the findings, or — when nothing at all was in reach — as not evaluated,
		// so a fully-gated check never reads as a clean pass.
		if l, ok := c.(Limiter); ok {
			if lim := l.Limitation(snap); lim != nil && lim.Omitted > 0 {
				// Nothing in reach and nothing reported: not evaluated. The
				// len(found) guard is deliberate — a check whose Limitation and Run
				// disagree is a bug in that check, and the safe way to fail is to
				// keep its findings visible rather than let a bad count hide them.
				if lim.Assessed == 0 && len(found) == 0 {
					rep.Skipped = append(rep.Skipped, Skipped{
						CheckID: meta.ID,
						Title:   meta.Title,
						Axis:    meta.Axis,
						Reason:  lim.Reason,
					})
					continue
				}
				rep.Limited = append(rep.Limited, *lim)
			}
		}

		// Stamp the axis from the check's metadata rather than asking each check
		// to set it on every finding it builds. One place, so it cannot be
		// forgotten on one finding out of eighty, and it cannot disagree with the
		// check that produced it.
		for i := range found {
			found[i].Kind = meta.Kind
		}
		rep.Findings = append(rep.Findings, found...)
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
