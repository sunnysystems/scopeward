package checks

import (
	"context"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestRepoDependabotAlertsOff_FlagsOnlyDisabled(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Repos = []model.Repo{
		{Name: "off", DependabotAlertsEnabled: boolPtr(false)},
		{Name: "on", DependabotAlertsEnabled: boolPtr(true)},
		{Name: "unknown", DependabotAlertsEnabled: nil}, // not assessed — must not flag
	}

	findings := repoDependabotAlertsOff{}.Run(context.Background(), snap)

	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if got := findings[0].Resource.Name; got != "acme/off" {
		t.Errorf("flagged %q, want acme/off", got)
	}
	if findings[0].Severity != model.SevMedium {
		t.Errorf("severity = %v, want medium", findings[0].Severity)
	}
	if findings[0].GHFix == "" {
		t.Error("alerts-off finding should carry a GHFix command")
	}
}

func TestOpenDependabotAlerts_SeverityTracksHighestBand(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Repos = []model.Repo{
		{Name: "crit", OpenDependabotAlerts: &model.DependabotAlertSummary{Critical: 1, Medium: 3}},
		{Name: "high", OpenDependabotAlerts: &model.DependabotAlertSummary{High: 2}},
		{Name: "med", OpenDependabotAlerts: &model.DependabotAlertSummary{Medium: 1, Low: 4}},
		{Name: "clean", OpenDependabotAlerts: &model.DependabotAlertSummary{}}, // total 0 — must not flag
		{Name: "unknown", OpenDependabotAlerts: nil},                           // unavailable — must not flag
	}

	findings := openDependabotAlerts{}.Run(context.Background(), snap)

	want := map[string]model.Severity{
		"acme/crit": model.SevCritical,
		"acme/high": model.SevHigh,
		"acme/med":  model.SevMedium,
	}
	if len(findings) != len(want) {
		t.Fatalf("findings = %d, want %d", len(findings), len(want))
	}
	for _, f := range findings {
		wantSev, ok := want[f.Resource.Name]
		if !ok {
			t.Errorf("unexpected finding for %q", f.Resource.Name)
			continue
		}
		if f.Severity != wantSev {
			t.Errorf("%s severity = %v, want %v", f.Resource.Name, f.Severity, wantSev)
		}
	}

	// The critical repo's total spans bands (1 critical + 3 medium = 4).
	for _, f := range findings {
		if f.Resource.Name == "acme/crit" {
			if f.Evidence["total"] != 4 {
				t.Errorf("crit total = %v, want 4", f.Evidence["total"])
			}
		}
	}
}
