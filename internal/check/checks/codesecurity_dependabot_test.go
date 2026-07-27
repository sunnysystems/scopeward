package checks

import (
	"context"
	"strings"
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

// Two repos at the same severity can differ enormously in how much work they
// represent. Severity answers "how urgent", volume answers "how much" — and the
// report used to render both identically, leaving triage order unanswerable.
func TestOpenDependabotAlerts_VolumeIsVisibleAtAGlance(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Repos = []model.Repo{
		{Name: "a", OpenDependabotAlerts: &model.DependabotAlertSummary{Critical: 3, High: 13, Medium: 9}},
		{Name: "b", OpenDependabotAlerts: &model.DependabotAlertSummary{Critical: 1, High: 50, Medium: 37, Low: 11}},
	}
	findings := openDependabotAlerts{}.Run(context.Background(), snap)
	byRepo := map[string]model.Finding{}
	for _, f := range findings {
		byRepo[f.Evidence["repo"].(string)] = f
	}

	// Both are critical — that part is right and unchanged.
	if byRepo["a"].Severity != model.SevCritical || byRepo["b"].Severity != model.SevCritical {
		t.Fatal("both repos should stay critical: severity tracks the worst alert")
	}
	// But the titles must no longer be interchangeable.
	if byRepo["a"].Title == byRepo["b"].Title {
		t.Fatal("a 25-alert repo and a 99-alert repo render identically")
	}
	for want, title := range map[string]string{
		"25 open Dependabot alert(s) (3 critical, 13 high, 9 medium)":          byRepo["a"].Title,
		"99 open Dependabot alert(s) (1 critical, 50 high, 37 medium, 11 low)": byRepo["b"].Title,
	} {
		if !strings.Contains(title, want) {
			t.Errorf("title %q should contain %q", title, want)
		}
	}
	// Empty bands are omitted rather than printed as zeros.
	if strings.Contains(byRepo["a"].Title, "0 low") {
		t.Errorf("title %q should omit empty severity bands", byRepo["a"].Title)
	}
	// The remediation names the urgent count instead of saying "start with the
	// critical ones" to someone looking at 51 of them.
	if !strings.Contains(byRepo["b"].Remediation, "51 critical/high") {
		t.Errorf("remediation %q should quantify the urgent work", byRepo["b"].Remediation)
	}
}
