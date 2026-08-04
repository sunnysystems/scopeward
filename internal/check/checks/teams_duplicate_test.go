package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

// team is a terse constructor for the fixtures below: name, parent, members, and
// one grant per repo:permission pair.
func team(name, parent string, members []string, grants ...string) model.Team {
	t := model.Team{Name: name, Slug: strings.ToLower(name), ParentSlug: parent, Members: members}
	for _, g := range grants {
		repo, perm, _ := strings.Cut(g, ":")
		t.RepoGrants = append(t.RepoGrants, model.TeamRepoGrant{Repo: repo, Permission: perm})
	}
	return t
}

func dupSnapshot(teams ...model.Team) *model.Snapshot {
	s := model.NewSnapshot("acme")
	s.Teams = teams
	return s
}

func TestDuplicateRoster(t *testing.T) {
	five := []string{"ana", "bo", "cy", "di", "eve"}

	cases := []struct {
		name  string
		teams []model.Team
		want  int
		sev   model.Severity
	}{
		{
			name: "identical rosters, both granting",
			teams: []model.Team{
				team("Platform", "", five, "api:write"),
				team("Infra", "", five, "infra:write"),
			},
			want: 1, sev: model.SevHigh, // each grants a repo the other does not
		},
		{
			// The pair is one finding, not one from each side.
			name: "identical rosters and identical grants report once",
			teams: []model.Team{
				team("Platform", "", five, "api:write"),
				team("Infra", "", five, "api:write"),
			},
			want: 1, sev: model.SevMedium,
		},
		{
			// 3 shared of 6 union = 0.5, below the 0.9 default. Two overlapping
			// but real functions, not a duplicate.
			name: "partial overlap below threshold is not a duplicate",
			teams: []model.Team{
				team("Backend", "", []string{"ana", "bo", "cy", "di"}, "api:write"),
				team("Data", "", []string{"ana", "bo", "cy", "eve", "fay"}, "etl:write"),
			},
			want: 0,
		},
		{
			name: "disjoint rosters",
			teams: []model.Team{
				team("Backend", "", []string{"ana", "bo"}, "api:write"),
				team("Design", "", []string{"cy", "di"}, "web:write"),
			},
			want: 0,
		},
		{
			// teams.ghost already reports a team with members and no grants; the
			// redundancy only matters when both confer access.
			name: "one side grants nothing",
			teams: []model.Team{
				team("Platform", "", five, "api:write"),
				team("Infra", "", five),
			},
			want: 0,
		},
		{
			// Nesting is supposed to share members. teams.deep-nesting judges depth.
			name: "parent and child may share a roster",
			teams: []model.Team{
				team("Platform", "", five, "api:write"),
				team("Infra", "platform", five, "infra:write"),
			},
			want: 0,
		},
		{
			name: "empty teams are not duplicates of each other",
			teams: []model.Team{
				team("Alpha", "", nil, "api:write"),
				team("Beta", "", nil, "api:write"),
			},
			want: 0,
		},
		{
			// A maintainer missing from Members must not make a twin look different.
			name: "maintainers count toward the roster",
			teams: []model.Team{
				func() model.Team {
					x := team("Platform", "", []string{"ana", "bo", "cy", "di"}, "api:write")
					x.Maintainers = []string{"eve"}
					return x
				}(),
				team("Infra", "", five, "api:write"),
			},
			want: 1, sev: model.SevMedium,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := duplicateRoster{}.Run(context.Background(), dupSnapshot(tc.teams...))
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v", len(got), tc.want, got)
			}
			if tc.want > 0 && got[0].Severity != tc.sev {
				t.Errorf("severity = %v, want %v", got[0].Severity, tc.sev)
			}
		})
	}
}

// TestDuplicateRosterEscalatesOnWiderGrant pins the severity rule: a twin that
// grants *more* is the dangerous direction, because the team nobody discusses is
// the one carrying the wider access.
func TestDuplicateRosterEscalatesOnWiderGrant(t *testing.T) {
	five := []string{"ana", "bo", "cy", "di", "eve"}

	same := duplicateRoster{}.Run(context.Background(), dupSnapshot(
		team("Platform", "", five, "api:write"),
		team("Infra", "", five, "api:write"),
	))
	if len(same) != 1 || same[0].Severity != model.SevMedium {
		t.Fatalf("identical grants should stay medium, got %+v", same)
	}

	wider := duplicateRoster{}.Run(context.Background(), dupSnapshot(
		team("Platform", "", five, "api:write"),
		team("Infra", "", five, "api:admin"),
	))
	if len(wider) != 1 || wider[0].Severity != model.SevHigh {
		t.Fatalf("a duplicate granting more should escalate to high, got %+v", wider)
	}
	if !strings.Contains(wider[0].Description, "api:admin") {
		t.Errorf("the wider grant should be named: %q", wider[0].Description)
	}

	// A twin granting *less* is not the dangerous direction.
	narrower := duplicateRoster{}.Run(context.Background(), dupSnapshot(
		team("Platform", "", five, "api:admin", "web:admin"),
		team("Infra", "", five, "api:read"),
	))
	if len(narrower) != 1 || narrower[0].Severity != model.SevHigh {
		// Platform still exceeds Infra on web, so high is right here; the assertion
		// is that Infra's weaker api grant is not what produced it.
		t.Fatalf("got %+v", narrower)
	}
	if strings.Contains(narrower[0].Description, "api:read") {
		t.Errorf("a weaker permission must not count as exceeding: %q", narrower[0].Description)
	}
}

func TestDuplicateRosterThresholdIsConfigurable(t *testing.T) {
	// 3 shared of 6 union = 0.5: below the 0.9 default, at a 0.5 threshold.
	teams := []model.Team{
		team("Backend", "", []string{"ana", "bo", "cy", "di"}, "api:write"),
		team("Data", "", []string{"ana", "bo", "cy", "eve", "fay"}, "etl:write"),
	}

	snap := dupSnapshot(teams...)
	if got := (duplicateRoster{}).Run(context.Background(), snap); len(got) != 0 {
		t.Fatalf("default threshold should not match, got %+v", got)
	}

	snap.DuplicateRosterSimilarity = 0.5
	if got := (duplicateRoster{}).Run(context.Background(), snap); len(got) != 1 {
		t.Fatalf("lowered threshold should match, got %d", len(got))
	}
}

// TestDuplicateRosterReportsThePair: which team to keep is a human call, so the
// finding must name both and prescribe neither.
func TestDuplicateRosterReportsThePair(t *testing.T) {
	five := []string{"ana", "bo", "cy", "di", "eve"}
	got := duplicateRoster{}.Run(context.Background(), dupSnapshot(
		team("Platform", "", five, "api:write"),
		team("Infra", "", five, "api:write"),
	))
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	f := got[0]
	for _, want := range []string{"Infra", "Platform"} {
		if !strings.Contains(f.Title, want) {
			t.Errorf("title must name both teams, missing %q: %q", want, f.Title)
		}
	}
	if f.Resource.Type != "org" {
		t.Errorf("resource should anchor on the org, not imply one team is the culprit: %+v", f.Resource)
	}
	if f.GHFix != "" {
		t.Errorf("deleting a team is destructive and the choice is human; no fix command: %q", f.GHFix)
	}
	if union, ok := f.Evidence["grants"].([]string); !ok || len(union) != 1 || union[0] != "api" {
		t.Errorf("evidence should carry the union of grants, got %v", f.Evidence["grants"])
	}
}

func TestJaccard(t *testing.T) {
	set := func(xs ...string) map[string]bool {
		m := map[string]bool{}
		for _, x := range xs {
			m[x] = true
		}
		return m
	}
	cases := []struct {
		a, b map[string]bool
		want float64
	}{
		{set("a", "b"), set("a", "b"), 1},
		{set("a", "b"), set("c", "d"), 0},
		{set("a", "b", "c"), set("a", "b"), 2.0 / 3.0},
		// Two empty sets are an undefined ratio, and must not read as identical.
		{set(), set(), 0},
		{set("a"), set(), 0},
	}
	for _, tc := range cases {
		if got := jaccard(tc.a, tc.b); got != tc.want {
			t.Errorf("jaccard(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
