package checks

import (
	"context"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

// designSnap builds a snapshot with a representative spread of team shapes.
func designSnap() *model.Snapshot {
	s := model.NewSnapshot("acme")
	s.Teams = []model.Team{
		// healthy: members, a maintainer, repo grants
		{Slug: "payments", Name: "Payments", Members: []string{"a", "b"}, Maintainers: []string{"a"},
			RepoGrants: []model.TeamRepoGrant{{Repo: "api", Permission: "write"}}},
		// ghost: members but no repos
		{Slug: "ghosts", Name: "Ghosts", Members: []string{"c", "d"}, Maintainers: []string{"c"}},
		// orphan: members, no maintainer
		{Slug: "orphans", Name: "Orphans", Members: []string{"e", "f"},
			RepoGrants: []model.TeamRepoGrant{{Repo: "api", Permission: "read"}}},
		// empty: no members
		{Slug: "empties", Name: "Empties"},
		// singleton: one member
		{Slug: "solo", Name: "Solo", Members: []string{"g"}, Maintainers: []string{"g"},
			RepoGrants: []model.TeamRepoGrant{{Repo: "api", Permission: "read"}}},
		// parent team: no members of its own, but has a child — must be excluded everywhere
		{Slug: "eng", Name: "Engineering"},
		{Slug: "eng-sub", Name: "Eng Sub", ParentSlug: "eng", Members: []string{"h", "i"}, Maintainers: []string{"h"},
			RepoGrants: []model.TeamRepoGrant{{Repo: "api", Permission: "write"}}},
	}
	return s
}

func TestGhostTeam(t *testing.T) {
	got := (ghostTeam{}).Run(context.Background(), designSnap())
	if len(got) != 1 || got[0].Evidence["slug"] != "ghosts" {
		t.Fatalf("got %+v, want only 'ghosts'", got)
	}
}

func TestOrphanTeam(t *testing.T) {
	got := (orphanTeam{}).Run(context.Background(), designSnap())
	if len(got) != 1 || got[0].Evidence["slug"] != "orphans" {
		t.Fatalf("got %+v, want only 'orphans'", got)
	}
	if got[0].Severity != model.SevMedium {
		t.Errorf("severity = %v, want medium", got[0].Severity)
	}
}

func TestEmptyTeam(t *testing.T) {
	got := (emptyTeam{}).Run(context.Background(), designSnap())
	// "empties" qualifies; "eng" is a parent and must be excluded.
	if len(got) != 1 || got[0].Evidence["slug"] != "empties" {
		t.Fatalf("got %+v, want only 'empties' (parent 'eng' excluded)", got)
	}
}

func TestSingletonTeam(t *testing.T) {
	got := (singletonTeam{}).Run(context.Background(), designSnap())
	if len(got) != 1 || got[0].Evidence["slug"] != "solo" {
		t.Fatalf("got %+v, want only 'solo'", got)
	}
	if got[0].Evidence["member"] != "g" {
		t.Errorf("member = %v, want g", got[0].Evidence["member"])
	}
}

func TestTierFor(t *testing.T) {
	cases := []struct {
		members int
		want    string
	}{
		{5, "micro (<10 members)"},
		{30, "small (10–50 members)"},
		{120, "medium (50–200 members)"},
		{500, "large (200+ members)"},
	}
	for _, tc := range cases {
		if got := tierFor(tc.members).name; got != tc.want {
			t.Errorf("tierFor(%d) = %q, want %q", tc.members, got, tc.want)
		}
	}
}

func TestSizeTierAdvice(t *testing.T) {
	s := model.NewSnapshot("acme")
	// 250 members → large tier → must advise SSO/SCIM provisioning.
	s.Members = make([]model.Member, 250)
	s.Teams = []model.Team{{Slug: "t", Name: "T"}}
	got := (teamSizeTierAdvice{}).Run(context.Background(), s)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if got[0].Evidence["members"] != 250 {
		t.Errorf("members evidence = %v, want 250", got[0].Evidence["members"])
	}
	if !contains(got[0].Description, "SSO") {
		t.Errorf("large-tier advice should mention SSO/SCIM, got: %q", got[0].Description)
	}

	// No members → no advice (honest, not a false "tiny org" reading).
	empty := model.NewSnapshot("acme")
	if got := (teamSizeTierAdvice{}).Run(context.Background(), empty); got != nil {
		t.Errorf("zero members should yield no advice, got %+v", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
