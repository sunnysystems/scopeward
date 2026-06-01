package check

import (
	"context"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

// fakeCheck is a configurable Check used to exercise the Runner in isolation
// from the real registry.
type fakeCheck struct {
	id       string
	requires []model.DataKind
	emit     int // number of findings to emit when run
}

func (f fakeCheck) Meta() CheckMeta {
	return CheckMeta{ID: f.id, Title: f.id, Axis: model.AxisIdentity, RequiresData: f.requires}
}

func (f fakeCheck) Run(context.Context, *model.Snapshot) []model.Finding {
	out := make([]model.Finding, f.emit)
	for i := range out {
		out[i] = model.Finding{CheckID: f.id, Axis: model.AxisIdentity, Severity: model.SevMedium}
	}
	return out
}

func TestRun_GatesOnCoverage(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Coverage.OK(model.DataMembers, 3)
	snap.Coverage.Partial(model.DataOrg, 1, "owner-only fields hidden")
	// DataMember2FA intentionally never recorded → missing.

	checks := []Check{
		fakeCheck{id: "runs", requires: []model.DataKind{model.DataMembers}, emit: 2},
		fakeCheck{id: "skip-missing", requires: []model.DataKind{model.DataMember2FA}, emit: 1},
		fakeCheck{id: "skip-partial", requires: []model.DataKind{model.DataOrg}, emit: 1},
	}

	rep := Run(context.Background(), snap, checks)

	if len(rep.Findings) != 2 {
		t.Errorf("findings = %d, want 2 (only the OK-covered check runs)", len(rep.Findings))
	}
	if len(rep.Skipped) != 2 {
		t.Fatalf("skipped = %d, want 2", len(rep.Skipped))
	}
	skippedIDs := map[string]bool{}
	for _, s := range rep.Skipped {
		skippedIDs[s.CheckID] = true
	}
	if !skippedIDs["skip-missing"] || !skippedIDs["skip-partial"] {
		t.Errorf("expected both missing and partial checks skipped, got %v", skippedIDs)
	}
}

func TestRun_SortsBySeverity(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Coverage.OK(model.DataMembers, 1)

	low := model.Finding{CheckID: "a", Severity: model.SevLow}
	crit := model.Finding{CheckID: "b", Severity: model.SevCritical}

	emitter := func(id string, f model.Finding) Check {
		return staticCheck{id: id, findings: []model.Finding{f}}
	}
	rep := Run(context.Background(), snap, []Check{emitter("a", low), emitter("b", crit)})

	if len(rep.Findings) != 2 || rep.Findings[0].Severity != model.SevCritical {
		t.Fatalf("expected critical first, got %+v", rep.Findings)
	}
}

type staticCheck struct {
	id       string
	findings []model.Finding
}

func (s staticCheck) Meta() CheckMeta {
	return CheckMeta{ID: s.id, RequiresData: []model.DataKind{model.DataMembers}}
}
func (s staticCheck) Run(context.Context, *model.Snapshot) []model.Finding { return s.findings }
