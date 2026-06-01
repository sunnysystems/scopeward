package checks

import (
	"context"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestRepoNoOwningTeam(t *testing.T) {
	s := model.NewSnapshot("acme")
	s.Repos = []model.Repo{
		{Name: "owned"},  // a team grants access → ok
		{Name: "orphan"}, // no team → flag
		{Name: "archived-orphan", Archived: true}, // archived → skip
	}
	s.Teams = []model.Team{
		{Slug: "payments", RepoGrants: []model.TeamRepoGrant{{Repo: "owned", Permission: "maintain"}}},
	}
	got := (repoNoOwningTeam{}).Run(context.Background(), s)
	if len(got) != 1 || got[0].Evidence["repo"] != "orphan" {
		t.Fatalf("got %+v, want only 'orphan'", got)
	}
	if got[0].Severity != model.SevMedium {
		t.Errorf("severity = %v, want medium", got[0].Severity)
	}
}

func TestRepoNoOwningProperty(t *testing.T) {
	// Adopted org: one repo has the property, one is missing it, one archived.
	s := model.NewSnapshot("acme")
	s.OwningTeamProperty = "owning-team"
	s.Repos = []model.Repo{
		{Name: "tagged", Properties: map[string]string{"owning-team": "payments"}}, // ok
		{Name: "untagged", Properties: map[string]string{"tier": "gold"}},          // flag (has props, not owning-team)
		{Name: "archived", Archived: true, Properties: map[string]string{}},        // skip
	}
	got := (repoNoOwningProperty{}).Run(context.Background(), s)
	if len(got) != 1 || got[0].Evidence["repo"] != "untagged" {
		t.Fatalf("got %+v, want only 'untagged'", got)
	}

	// Not adopted: no repo carries any property → check stays silent.
	none := model.NewSnapshot("acme")
	none.OwningTeamProperty = "owning-team"
	none.Repos = []model.Repo{{Name: "a"}, {Name: "b"}}
	if got := (repoNoOwningProperty{}).Run(context.Background(), none); got != nil {
		t.Errorf("un-adopted org should yield no findings, got %+v", got)
	}
}

func TestRepoNoCodeowner(t *testing.T) {
	yes, no := true, false
	s := model.NewSnapshot("acme")
	s.Repos = []model.Repo{
		{Name: "team-owned", DefaultBranch: "main", CodeownersPresent: &yes, CodeownersTeams: []string{"@acme/payments"}}, // ok
		{Name: "no-file", DefaultBranch: "main", CodeownersPresent: &no},                                                  // flag (missing)
		{Name: "individuals", DefaultBranch: "main", CodeownersPresent: &yes},                                             // flag (no team)
		{Name: "unassessed", DefaultBranch: "main", CodeownersPresent: nil},                                               // skip (unknown)
		{Name: "empty-repo", DefaultBranch: "", CodeownersPresent: &no},                                                   // skip (no default branch)
	}
	got := (repoNoCodeowner{}).Run(context.Background(), s)
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (no-file + individuals)", len(got))
	}
	names := map[string]bool{}
	for _, f := range got {
		names[f.Evidence["repo"].(string)] = true
	}
	if !names["no-file"] || !names["individuals"] {
		t.Errorf("flagged repos = %v, want no-file + individuals", names)
	}
}
