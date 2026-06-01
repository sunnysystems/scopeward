package checks

import (
	"context"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestUnprotectedDefaultBranch(t *testing.T) {
	yes, no := true, false
	snap := model.NewSnapshot("acme")
	snap.Repos = []model.Repo{
		{Name: "protected", DefaultBranch: "main", DefaultBranchProtected: &yes}, // ok
		{Name: "open", DefaultBranch: "main", DefaultBranchProtected: &no},       // flag
		{Name: "unknown", DefaultBranch: "main", DefaultBranchProtected: nil},    // skip (unknown)
	}
	got := unprotectedDefaultBranch{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Evidence["repo"] != "open" {
		t.Fatalf("got %+v, want only the 'open' repo", got)
	}
	if got[0].Severity != model.SevHigh {
		t.Errorf("severity = %v, want high", got[0].Severity)
	}
}

func TestRulesetNotEnforced(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.OrgRulesets = []model.Ruleset{
		{Name: "active-one", Enforcement: "active"}, // ok
		{Name: "dry-run", Enforcement: "evaluate"},  // flag
		{Name: "off", Enforcement: "disabled"},      // flag
	}
	got := rulesetNotEnforced{}.Run(context.Background(), snap)
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (evaluate + disabled)", len(got))
	}
}

func TestElevatedCustomRole(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.CustomRoles = []model.CustomRole{
		{Name: "deployer", BaseRole: "write"},   // ok
		{Name: "lead", BaseRole: "maintain"},    // flag
		{Name: "superadmin", BaseRole: "admin"}, // flag
	}
	got := elevatedCustomRole{}.Run(context.Background(), snap)
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (maintain + admin)", len(got))
	}
	for _, f := range got {
		if f.Severity != model.SevMedium {
			t.Errorf("%s severity = %v, want medium", f.Resource.Name, f.Severity)
		}
	}
}
