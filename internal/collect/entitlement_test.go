package collect

import (
	"errors"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func bptr(b bool) *bool { return &b }

// TestSecretProtectionFromEvidence pins the free probe: repository state can
// prove the entitlement is held, but never that it is missing.
func TestSecretProtectionFromEvidence(t *testing.T) {
	cases := []struct {
		name  string
		repos []model.Repo
		want  model.EntitlementState // "" = inconclusive, must fall through to billing
	}{
		{
			name:  "private repo with push protection on proves it",
			repos: []model.Repo{{Name: "api", Private: true, PushProtection: bptr(true)}},
			want:  model.EntitlementGranted,
		},
		{
			name:  "archived private repo counts: it was enabled while writable",
			repos: []model.Repo{{Name: "old", Private: true, Archived: true, PushProtection: bptr(true)}},
			want:  model.EntitlementGranted,
		},
		{
			// The whole reason the gate is per repository: public repos get push
			// protection free on every plan, so they prove nothing about the paid
			// product.
			name:  "public repo with it on proves nothing",
			repos: []model.Repo{{Name: "site", Private: false, PushProtection: bptr(true)}},
		},
		{
			name:  "private repos with it off are inconclusive, not absent",
			repos: []model.Repo{{Name: "api", Private: true, PushProtection: bptr(false)}},
		},
		{
			name:  "unknown state is inconclusive",
			repos: []model.Repo{{Name: "api", Private: true}},
		},
		{name: "no repos at all is inconclusive"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := model.NewSnapshot("acme")
			snap.Repos = tc.repos
			got := secretProtectionFromEvidence(snap)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("want inconclusive (nil), got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("want %s, got inconclusive", tc.want)
			}
			if got.State != tc.want {
				t.Errorf("state = %s, want %s", got.State, tc.want)
			}
			if got.Reason == "" {
				t.Error("a conclusion that suppresses or permits findings must record its evidence")
			}
		})
	}
}

// TestSecretProtectionFromSeats pins the billing probe, and in particular that a
// failed probe never reads as Absent — Absent suppresses findings, so a token
// without admin:org would otherwise silently hide real exposure.
func TestSecretProtectionFromSeats(t *testing.T) {
	cases := []struct {
		name  string
		seats int
		err   error
		want  model.EntitlementState
	}{
		{"seats provisioned", 5, nil, model.EntitlementGranted},
		{"no seats", 0, nil, model.EntitlementAbsent},
		{"probe failed", 0, errors.New("403 forbidden"), model.EntitlementUnknown},
		{"probe failed with a stale count", 5, errors.New("boom"), model.EntitlementUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := secretProtectionFromSeats(tc.seats, tc.err)
			if got.State != tc.want {
				t.Errorf("state = %s, want %s", got.State, tc.want)
			}
			if got.Entitlement != model.EntSecretProtection {
				t.Errorf("entitlement = %s", got.Entitlement)
			}
			if got.Reason == "" {
				t.Error("reason must be recorded")
			}
		})
	}
}

// TestUnrecordedEntitlementIsUnknown pins the default. A provider that never
// probes, or a --quick run, must not leave checks reading Absent and suppressing.
func TestUnrecordedEntitlementIsUnknown(t *testing.T) {
	snap := model.NewSnapshot("acme")
	st := snap.Entitlement(model.EntSecretProtection)
	if st.State != model.EntitlementUnknown {
		t.Errorf("state = %s, want unknown", st.State)
	}
	if !strings.Contains(st.Reason, "not determined") {
		t.Errorf("reason = %q", st.Reason)
	}
}
