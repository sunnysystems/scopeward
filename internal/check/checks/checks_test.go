package checks

import (
	"context"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func boolPtr(b bool) *bool { return &b }

func TestNo2FA_FlagsOnlyDisabled(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Members = []model.Member{
		{Login: "alice", TwoFactorEnabled: boolPtr(true)},
		{Login: "bob", TwoFactorEnabled: boolPtr(false)},
		{Login: "carol", TwoFactorEnabled: nil}, // unknown — must not be flagged
	}

	findings := no2FA{}.Run(context.Background(), snap)

	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Resource.Name != "bob" {
		t.Errorf("flagged %q, want bob", findings[0].Resource.Name)
	}
	if findings[0].Severity != model.SevHigh {
		t.Errorf("severity = %v, want high", findings[0].Severity)
	}
}

func TestOwnerSprawl_RatioThreshold(t *testing.T) {
	snap := model.NewSnapshot("acme")
	// 3 owners out of 12 members = 25% > 10% ratio, and 12 >= min size → flag.
	snap.Members = make([]model.Member, 12)
	for i := range snap.Members {
		snap.Members[i] = model.Member{Login: "m", Role: "member"}
	}
	snap.Members[0].Role, snap.Members[1].Role, snap.Members[2].Role = "admin", "admin", "admin"

	findings := ownerSprawl{}.Run(context.Background(), snap)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (ratio exceeded)", len(findings))
	}
	if got := findings[0].Evidence["owner_count"]; got != 3 {
		t.Errorf("owner_count = %v, want 3", got)
	}
}

func TestOwnerSprawl_TinyOrgNotFlagged(t *testing.T) {
	snap := model.NewSnapshot("acme")
	// 2 owners out of 3 members: high ratio, but the org is too small to call
	// this sprawl, and the count is under the absolute threshold → no finding.
	snap.Members = []model.Member{
		{Login: "a", Role: "admin"},
		{Login: "b", Role: "admin"},
		{Login: "c", Role: "member"},
	}
	if got := (ownerSprawl{}).Run(context.Background(), snap); len(got) != 0 {
		t.Errorf("findings = %d, want 0 (tiny org)", len(got))
	}
}

func TestOwnerSprawl_WithinBounds(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Members = make([]model.Member, 100)
	for i := range snap.Members {
		snap.Members[i] = model.Member{Role: "member"}
	}
	snap.Members[0].Role = "admin" // 1/100 = 1% and under count threshold

	if got := (ownerSprawl{}).Run(context.Background(), snap); len(got) != 0 {
		t.Errorf("findings = %d, want 0 (within bounds)", len(got))
	}
}

func TestBasePermissionOpen(t *testing.T) {
	cases := []struct {
		perm    string
		want    int
		wantSev model.Severity
	}{
		{"read", 0, 0},
		{"none", 0, 0},
		{"write", 1, model.SevMedium},
		{"admin", 1, model.SevHigh},
		{"", 0, 0}, // not visible → no false positive
	}
	for _, tc := range cases {
		snap := model.NewSnapshot("acme")
		snap.Org.DefaultRepoPermission = tc.perm
		got := basePermissionOpen{}.Run(context.Background(), snap)
		if len(got) != tc.want {
			t.Errorf("perm %q: findings = %d, want %d", tc.perm, len(got), tc.want)
			continue
		}
		if tc.want == 1 && got[0].Severity != tc.wantSev {
			t.Errorf("perm %q: severity = %v, want %v", tc.perm, got[0].Severity, tc.wantSev)
		}
	}
}

func TestDeepNesting(t *testing.T) {
	snap := model.NewSnapshot("acme")
	// root -> mid -> leaf -> deep  (depths 1,2,3,4); only leaf(3) and deep(4) flagged.
	snap.Teams = []model.Team{
		{Slug: "root", Name: "root"},
		{Slug: "mid", Name: "mid", ParentSlug: "root"},
		{Slug: "leaf", Name: "leaf", ParentSlug: "mid"},
		{Slug: "deep", Name: "deep", ParentSlug: "leaf"},
	}
	got := deepNesting{}.Run(context.Background(), snap)
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (leaf, deep)", len(got))
	}
}

func TestDirectGrantsSplitByPermission(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Repos = []model.Repo{{
		Name: "api",
		DirectCollaborators: []model.RepoGrant{
			{Login: "alice", Permission: "admin"},
			{Login: "bob", Permission: "write"},
			{Login: "carol", Permission: "read"},
		},
	}}

	admins := directAdminGrant{}.Run(context.Background(), snap)
	if len(admins) != 1 || admins[0].Evidence["login"] != "alice" {
		t.Errorf("admin grants = %+v, want only alice", admins)
	}
	if admins[0].Severity != model.SevHigh {
		t.Errorf("admin grant severity = %v, want high", admins[0].Severity)
	}

	others := directRepoGrant{}.Run(context.Background(), snap)
	if len(others) != 2 {
		t.Errorf("non-admin grants = %d, want 2 (bob, carol)", len(others))
	}
}

func TestCheckIDsAreStable(t *testing.T) {
	// Stable IDs are part of the contract (CI may pin/ignore by ID), so guard
	// them explicitly.
	want := map[string]string{
		"no2FA":                no2FA{}.Meta().ID,
		"orgNo2FAEnforcement":  orgNo2FAEnforcement{}.Meta().ID,
		"notSSOLinked":         notSSOLinked{}.Meta().ID,
		"outsideCollaborators": outsideCollaborators{}.Meta().ID,
		"ownerSprawl":          ownerSprawl{}.Meta().ID,
	}
	expected := map[string]string{
		"no2FA":                "human.no-2fa",
		"orgNo2FAEnforcement":  "human.org-2fa-not-enforced",
		"notSSOLinked":         "human.not-sso-linked",
		"outsideCollaborators": "human.outside-collaborator",
		"ownerSprawl":          "human.owner-sprawl",
	}
	for name, id := range want {
		if id != expected[name] {
			t.Errorf("%s ID = %q, want %q", name, id, expected[name])
		}
	}
}
