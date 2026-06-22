package checks

import (
	"context"
	"testing"
	"time"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestDormantMember(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	old := now.Add(-300 * 24 * time.Hour) // well past the 90-day threshold
	recent := now.Add(-10 * 24 * time.Hour)

	snap := model.NewSnapshot("acme")
	snap.CollectedAt = now
	snap.Members = []model.Member{
		{Login: "stale", LastActiveAt: &old},
		{Login: "active", LastActiveAt: &recent},
		{Login: "unknown"}, // no LastActiveAt → not flagged
	}

	findings := dormantMember{}.Run(context.Background(), snap)

	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (only the stale member)", len(findings))
	}
	f := findings[0]
	if f.CheckID != "human.dormant-member" || f.Resource.Name != "stale" {
		t.Errorf("unexpected finding: %+v", f)
	}
	if f.Severity != model.SevLow || f.Axis != model.AxisIdentity {
		t.Errorf("severity/axis = %v/%v, want low/identity", f.Severity, f.Axis)
	}
	if days, ok := f.Evidence["inactive_days"].(int); !ok || days < 290 {
		t.Errorf("inactive_days evidence = %v, want ~300", f.Evidence["inactive_days"])
	}
}

func TestDormantMemberRequiresActivityData(t *testing.T) {
	// The check declares DataMemberActivity; the runner skips it when that data
	// isn't collected (e.g. GitHub, or a non-admin GitLab token). This asserts the
	// declared dependency so that gating holds.
	meta := dormantMember{}.Meta()
	var hasActivity bool
	for _, k := range meta.RequiresData {
		if k == model.DataMemberActivity {
			hasActivity = true
		}
	}
	if !hasActivity {
		t.Error("human.dormant-member must require DataMemberActivity so it gates on coverage")
	}
}
