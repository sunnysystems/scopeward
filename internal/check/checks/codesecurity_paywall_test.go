package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

// paywallSnapshot builds an org with one public and two private repos, all with
// push protection off, and the given secret-protection state.
func paywallSnapshot(state model.EntitlementState) *model.Snapshot {
	off := false
	snap := model.NewSnapshot("acme")
	snap.Repos = []model.Repo{
		{Name: "site", Private: false, PushProtection: &off},
		{Name: "api", Private: true, PushProtection: &off},
		{Name: "billing", Private: true, PushProtection: &off},
	}
	if state != "" {
		snap.SetEntitlement(model.EntitlementStatus{
			Entitlement: model.EntSecretProtection,
			State:       state,
			Reason:      "test",
		})
	}
	return snap
}

func firedRepos(findings []model.Finding) []string {
	var out []string
	for _, f := range findings {
		out = append(out, f.Evidence["repo"].(string))
	}
	return out
}

// TestPushProtectionPaywall covers the three entitlement states. Absent is the
// only one that suppresses: reporting a finding whose sole remediation is a
// purchase hands the reader an invoice, and suppressing on merely-unknown would
// hide exposure the org can in fact fix (#50).
func TestPushProtectionPaywall(t *testing.T) {
	cases := []struct {
		name  string
		state model.EntitlementState
		want  []string
	}{
		{"absent suppresses private only", model.EntitlementAbsent, []string{"site"}},
		{"granted reports everything", model.EntitlementGranted, []string{"site", "api", "billing"}},
		{"unknown reports everything", model.EntitlementUnknown, []string{"site", "api", "billing"}},
		{"unprobed reports everything", "", []string{"site", "api", "billing"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := firedRepos(repoNoPushProtection{}.Run(context.Background(), paywallSnapshot(tc.state)))
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("fired on %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPushProtectionLimitation pins that suppression is always accounted for.
// Dropping the private repos silently would report a clean bill of health for
// repositories nothing looked at.
func TestPushProtectionLimitation(t *testing.T) {
	lim := repoNoPushProtection{}.Limitation(paywallSnapshot(model.EntitlementAbsent))
	if lim == nil {
		t.Fatal("absent entitlement must produce a limitation")
	}
	if lim.Assessed != 1 || lim.Omitted != 2 {
		t.Errorf("assessed=%d omitted=%d, want 1 and 2", lim.Assessed, lim.Omitted)
	}
	if !strings.Contains(lim.Reason, "Secret Protection") {
		t.Errorf("reason must name the entitlement: %q", lim.Reason)
	}

	for _, state := range []model.EntitlementState{model.EntitlementGranted, model.EntitlementUnknown} {
		if l := (repoNoPushProtection{}).Limitation(paywallSnapshot(state)); l != nil {
			t.Errorf("%s: nothing is out of reach, want no limitation, got %+v", state, l)
		}
	}
}

// TestPushProtectionFullyPaywalledIsNotEvaluated covers the all-private org: the
// check has nothing in reach, so the runner must report it as not evaluated
// rather than let an empty findings list read as a pass.
func TestPushProtectionFullyPaywalledIsNotEvaluated(t *testing.T) {
	off := false
	snap := model.NewSnapshot("acme")
	snap.Repos = []model.Repo{
		{Name: "api", Private: true, PushProtection: &off},
		{Name: "billing", Private: true, PushProtection: &off},
	}
	snap.SetEntitlement(model.EntitlementStatus{
		Entitlement: model.EntSecretProtection,
		State:       model.EntitlementAbsent,
		Reason:      "no seats provisioned",
	})
	snap.Coverage.OK(model.DataRepoSecurity, 2)

	rep := check.Run(context.Background(), snap, []check.Check{repoNoPushProtection{}})
	if len(rep.Findings) != 0 {
		t.Errorf("want no findings, got %d", len(rep.Findings))
	}
	if len(rep.Limited) != 0 {
		t.Errorf("nothing was assessed, so this belongs in Skipped, not Limited: %+v", rep.Limited)
	}
	if len(rep.Skipped) != 1 {
		t.Fatalf("want 1 not-evaluated entry, got %d", len(rep.Skipped))
	}
	if !strings.Contains(rep.Skipped[0].Reason, "Secret Protection") {
		t.Errorf("skip reason must name the entitlement: %q", rep.Skipped[0].Reason)
	}
}

// TestPushProtectionPartialIsLimitedNotSkipped is the other half: with something
// still in reach the check runs, so it must report findings *and* the gap, never
// be filed as untried.
func TestPushProtectionPartialIsLimitedNotSkipped(t *testing.T) {
	snap := paywallSnapshot(model.EntitlementAbsent)
	snap.Coverage.OK(model.DataRepoSecurity, 3)

	rep := check.Run(context.Background(), snap, []check.Check{repoNoPushProtection{}})
	if len(rep.Findings) != 1 {
		t.Errorf("want the public repo reported, got %d findings", len(rep.Findings))
	}
	if len(rep.Skipped) != 0 {
		t.Errorf("the check did run, so it is not 'not evaluated': %+v", rep.Skipped)
	}
	if len(rep.Limited) != 1 || rep.Limited[0].Omitted != 2 {
		t.Errorf("want one limitation omitting 2 repos, got %+v", rep.Limited)
	}
}
