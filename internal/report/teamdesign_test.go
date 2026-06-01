package report

import (
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func tdSnapshot() *model.Snapshot {
	s := model.NewSnapshot("acme")
	s.Members = make([]model.Member, 20) // small tier (10–50)
	s.Coverage.OK(model.DataTeamMembers, 4)
	s.Coverage.OK(model.DataTeamRepos, 4)
	yes := true
	s.Teams = []model.Team{
		{Slug: "payments", Members: []string{"a", "b"}, Maintainers: []string{"a"},
			RepoGrants: []model.TeamRepoGrant{{Repo: "api", Permission: "write"}}},
		{Slug: "ghosts", Members: []string{"c"}, Maintainers: []string{"c"}}, // singleton AND ghost
		{Slug: "orphans", Members: []string{"d", "e"}},                       // orphan + ghost
		{Slug: "empties"}, // empty
	}
	s.Repos = []model.Repo{
		{Name: "api", CodeownersPresent: &yes, CodeownersTeams: []string{"@acme/payments"},
			Properties: map[string]string{"owning-team": "payments"}},
		{Name: "web"},                 // no owning team, no codeowners assessed
		{Name: "old", Archived: true}, // excluded
	}
	return s
}

func TestSummarizeTeamDesign(t *testing.T) {
	td := summarizeTeamDesign(tdSnapshot())
	if td == nil {
		t.Fatal("expected a summary when team data is present")
	}
	if td.tierName != "small (10–50 members)" {
		t.Errorf("tier = %q", td.tierName)
	}
	if td.empty != 1 {
		t.Errorf("empty = %d, want 1", td.empty)
	}
	if td.singleton != 1 {
		t.Errorf("singleton = %d, want 1", td.singleton)
	}
	if td.orphan != 1 {
		t.Errorf("orphan = %d, want 1", td.orphan)
	}
	if td.ghost != 2 { // ghosts (1 member, no repo) + orphans (2 members, no repo)
		t.Errorf("ghost = %d, want 2", td.ghost)
	}
	if td.reposTotal != 2 { // api + web; old is archived
		t.Errorf("reposTotal = %d, want 2", td.reposTotal)
	}
	if td.reposOwnedByTeam != 1 { // only api
		t.Errorf("reposOwnedByTeam = %d, want 1", td.reposOwnedByTeam)
	}
	if !td.propertyAdopted {
		t.Error("propertyAdopted should be true (api has owning-team)")
	}
}

func TestSummarizeTeamDesign_SkippedWithoutData(t *testing.T) {
	s := model.NewSnapshot("acme")
	s.Teams = []model.Team{{Slug: "x"}}
	// No DataTeamMembers/DataTeamRepos coverage → section must be skipped.
	if td := summarizeTeamDesign(s); td != nil {
		t.Errorf("expected nil when per-team data not collected, got %+v", td)
	}
}

func TestTeamDesignRendersInText(t *testing.T) {
	var sb strings.Builder
	renderTeamDesignText(&sb, summarizeTeamDesign(tdSnapshot()))
	out := sb.String()
	for _, want := range []string{"Team Design", "small (10–50 members)", "Ownership", "owning team"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\n%s", want, out)
		}
	}
}
