package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sunnysystems/scopeward/internal/model"
)

func policySnap(p *model.Policy) *model.Snapshot {
	s := model.NewSnapshot("acme")
	s.Policy = p
	return s
}

func strs(xs ...string) *[]string { return &xs }
func iptr(i int) *int             { return &i }

// TestInvariantsSilentWithoutPolicy is the load-bearing default: adding these
// checks must not change a single existing run. Every invariant is opt-in.
func TestInvariantsSilentWithoutPolicy(t *testing.T) {
	s := model.NewSnapshot("acme")
	s.Repos = []model.Repo{
		{Name: "site", Private: false, DirectCollaborators: []model.RepoGrant{{Login: "ana", Permission: "admin"}}},
	}
	s.Teams = []model.Team{{Slug: "eng", Name: "Eng", RepoGrants: []model.TeamRepoGrant{{Repo: "site", Permission: "admin"}}}}

	for _, c := range []interface {
		Run(context.Context, *model.Snapshot) []model.Finding
	}{
		policyAdminSource{}, policyPublicRepos{}, policyDirectCollaborators{}, policyOwningTeam{},
	} {
		if got := c.Run(context.Background(), s); len(got) != 0 {
			t.Errorf("%T fired with no policy declared: %+v", c, got)
		}
	}
}

func TestPolicyAdminSource(t *testing.T) {
	s := policySnap(&model.Policy{
		Version:    1,
		Invariants: model.PolicyInvariants{RepoAdminOnlyFromTeam: "platform"},
	})
	s.Teams = []model.Team{
		{Slug: "platform", Name: "Platform", RepoGrants: []model.TeamRepoGrant{{Repo: "api", Permission: "admin"}}},
		{Slug: "eng", Name: "Eng", RepoGrants: []model.TeamRepoGrant{
			{Repo: "api", Permission: "admin"}, // violation: another team confers admin
			{Repo: "web", Permission: "write"}, // fine: not admin
		}},
	}
	s.Repos = []model.Repo{
		{Name: "api", DirectCollaborators: []model.RepoGrant{
			{Login: "ana", Permission: "admin"}, // violation: bypasses every team
			{Login: "bo", Permission: "write"},  // fine
		}},
	}

	got := policyAdminSource{}.Run(context.Background(), s)
	if len(got) != 2 {
		t.Fatalf("want 2 violations, got %d: %+v", len(got), got)
	}
	sources := map[string]bool{}
	for _, f := range got {
		if !f.Policy {
			t.Errorf("a policy finding must be marked as one: %+v", f)
		}
		sources[f.Evidence["source"].(string)] = true
	}
	if !sources["team"] || !sources["direct"] {
		t.Errorf("both admin sources must be reported, got %v", sources)
	}

	// The approved team itself is never a violation.
	s.Repos = nil
	s.Teams = s.Teams[:1]
	if got := (policyAdminSource{}).Run(context.Background(), s); len(got) != 0 {
		t.Errorf("the approved team must not violate its own invariant: %+v", got)
	}
}

func TestPolicyPublicRepos(t *testing.T) {
	s := policySnap(&model.Policy{
		Version:    1,
		Invariants: model.PolicyInvariants{PublicRepos: strs("docs-site")},
	})
	s.Repos = []model.Repo{
		{Name: "docs-site", Private: false},               // allowed
		{Name: "DOCS-SITE", Private: false},               // allowed: names are case-insensitive
		{Name: "payments", Private: false},                // violation
		{Name: "internal", Private: true},                 // fine
		{Name: "retired", Private: false, Archived: true}, // violation: archiving does not make it private
	}

	got := policyPublicRepos{}.Run(context.Background(), s)
	if len(got) != 2 {
		t.Fatalf("want 2 violations, got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if f.Severity != model.SevCritical || !f.Policy {
			t.Errorf("want a critical policy finding, got %+v", f)
		}
	}

	// An empty allowlist is a real assertion — no repository may be public —
	// and must be distinguishable from not declaring the invariant at all.
	s.Policy.Invariants.PublicRepos = strs()
	if got := (policyPublicRepos{}).Run(context.Background(), s); len(got) != 4 {
		t.Errorf("an empty allowlist forbids all four public repos, got %d", len(got))
	}
	s.Policy.Invariants.PublicRepos = nil
	if got := (policyPublicRepos{}).Run(context.Background(), s); len(got) != 0 {
		t.Errorf("an undeclared invariant asserts nothing, got %d", len(got))
	}
}

func TestPolicyDirectCollaboratorsAndOwningTeam(t *testing.T) {
	s := policySnap(&model.Policy{
		Version: 1,
		Invariants: model.PolicyInvariants{
			ForbidDirectCollaborators: true,
			RequireOwningTeam:         true,
		},
	})
	s.Repos = []model.Repo{
		{Name: "api", DirectCollaborators: []model.RepoGrant{{Login: "ana", Permission: "read"}}},
		{Name: "web"},
		{Name: "retired", Archived: true, DirectCollaborators: []model.RepoGrant{{Login: "zed", Permission: "admin"}}},
	}
	s.Teams = []model.Team{{Slug: "eng", RepoGrants: []model.TeamRepoGrant{{Repo: "api", Permission: "write"}}}}

	// Even a read grant violates "access comes through teams" — the invariant is
	// stricter than the product default, which is the point of declaring it.
	direct := policyDirectCollaborators{}.Run(context.Background(), s)
	if len(direct) != 1 || direct[0].Evidence["login"] != "ana" {
		t.Errorf("want the one active-repo direct grant, got %+v", direct)
	}

	owning := policyOwningTeam{}.Run(context.Background(), s)
	if len(owning) != 1 || owning[0].Evidence["repo"] != "web" {
		t.Errorf("want only the unowned active repo, got %+v", owning)
	}
}

// TestPolicySupersedesProductChecks: when the org has declared its own rule on a
// concern, the product's opinion must stand down, or one problem is reported
// twice and the report argues with itself.
func TestPolicySupersedesProductChecks(t *testing.T) {
	// Each check needs a fixture it actually fires on: direct-admin-grant only
	// reports admin, direct-repo-grant only the lesser grants.
	grant := func(perm string) []model.Repo {
		return []model.Repo{{Name: "api", DirectCollaborators: []model.RepoGrant{{Login: "ana", Permission: perm}}}}
	}
	cases := []struct {
		checkID string
		repos   []model.Repo
		policy  model.PolicyInvariants
	}{
		{"teams.repo-no-owning-team", grant("admin"), model.PolicyInvariants{RequireOwningTeam: true}},
		{"perms.direct-admin-grant", grant("admin"), model.PolicyInvariants{ForbidDirectCollaborators: true}},
		{"perms.direct-repo-grant", grant("write"), model.PolicyInvariants{ForbidDirectCollaborators: true}},
	}
	for _, tc := range cases {
		t.Run(tc.checkID, func(t *testing.T) {
			c := byID(t, tc.checkID)

			bare := model.NewSnapshot("acme")
			bare.Repos = tc.repos
			if len(c.Run(context.Background(), bare)) == 0 {
				t.Fatalf("fixture does not trigger %s, so the assertion below would pass vacuously", tc.checkID)
			}

			withPolicy := model.NewSnapshot("acme")
			withPolicy.Repos = bare.Repos
			withPolicy.Policy = &model.Policy{Version: 1, Invariants: tc.policy}
			if got := c.Run(context.Background(), withPolicy); len(got) != 0 {
				t.Errorf("%s should stand down under a declared invariant, got %+v", tc.checkID, got)
			}
		})
	}
}

func TestPolicyThresholdOverrides(t *testing.T) {
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	t.Run("dormancy window", func(t *testing.T) {
		last := now.AddDate(0, 0, -70) // dormant at 60 days, active at the 90-day default
		s := model.NewSnapshot("acme")
		s.CollectedAt = now
		s.Members = []model.Member{{Login: "ana", LastActiveAt: &last}}

		if got := (dormantMember{}).Run(context.Background(), s); len(got) != 0 {
			t.Errorf("70 days is inside the 90-day default, got %+v", got)
		}
		s.Policy = &model.Policy{Version: 1, Thresholds: model.PolicyThresholds{DormantAfterDays: iptr(60)}}
		if got := (dormantMember{}).Run(context.Background(), s); len(got) != 1 {
			t.Errorf("70 days is past a declared 60-day window, got %d", len(got))
		}
	})

	t.Run("stale repo horizon", func(t *testing.T) {
		pushed := now.AddDate(0, 0, -200)
		s := model.NewSnapshot("acme")
		s.CollectedAt = now
		s.Repos = []model.Repo{{Name: "api", PushedAt: &pushed}}

		if got := (staleRepo{}).Run(context.Background(), s); len(got) != 0 {
			t.Errorf("200 days is inside the 365-day default, got %+v", got)
		}
		s.Policy = &model.Policy{Version: 1, Thresholds: model.PolicyThresholds{StaleRepoAfterDays: iptr(180)}}
		if got := (staleRepo{}).Run(context.Background(), s); len(got) != 1 {
			t.Errorf("200 days is past a declared 180-day horizon, got %d", len(got))
		}
	})

	t.Run("team count limit", func(t *testing.T) {
		s := model.NewSnapshot("acme")
		s.Members = make([]model.Member, 20)
		s.Teams = make([]model.Team, 12) // fewer teams than members: silent by default

		if got := (teamSprawl{}).Run(context.Background(), s); len(got) != 0 {
			t.Errorf("12 teams for 20 members is not sprawl by default, got %+v", got)
		}
		s.Policy = &model.Policy{Version: 1, Thresholds: model.PolicyThresholds{MaxTeams: iptr(10)}}
		got := teamSprawl{}.Run(context.Background(), s)
		if len(got) != 1 {
			t.Fatalf("12 teams is over a declared limit of 10, got %d", len(got))
		}
		if !got[0].Policy {
			t.Error("a finding produced by a declared limit must be marked as policy-sourced")
		}
		if !strings.Contains(got[0].Title, "declared limit") {
			t.Errorf("the title should name the org's own number: %q", got[0].Title)
		}
	})
}
