package collect

import (
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestMatchRepo(t *testing.T) {
	cases := []struct {
		name     string
		patterns []string
		want     bool
	}{
		// GitHub-style bare names.
		{"api", []string{"api"}, true},
		{"api", []string{"web"}, false},
		{"api", []string{"web", "api"}, true},
		{"API-Server", []string{"api-server"}, true}, // case-insensitive
		{"api-server", []string{"API-*"}, true},      // glob, case-insensitive
		{"api", []string{"ap"}, false},               // no substring matching

		// GitLab-style project paths: any '/'-aligned suffix matches.
		{"acme/team-a/api", []string{"api"}, true},
		{"acme/team-a/api", []string{"team-a/api"}, true},
		{"acme/team-a/api", []string{"acme/team-a/api"}, true},
		{"acme/team-a/api", []string{"team-a"}, false}, // not a full suffix
		{"acme/team-a/api", []string{"*/api"}, true},   // matches the team-a/api suffix
		{"acme/team-a/api", []string{"team-*/api"}, true},
		{"acme/team-a/api", []string{"acme/*"}, false}, // '*' does not cross '/'
	}
	for _, c := range cases {
		if got := MatchRepo(c.name, c.patterns); got != c.want {
			t.Errorf("MatchRepo(%q, %v) = %v, want %v", c.name, c.patterns, got, c.want)
		}
	}
}

func TestFilterRepos(t *testing.T) {
	repos := []model.Repo{{Name: "api"}, {Name: "web"}, {Name: "api-docs"}}

	// No patterns: the list passes through untouched.
	if got := FilterRepos(repos, nil); len(got) != 3 {
		t.Errorf("FilterRepos(nil) kept %d repos, want all 3", len(got))
	}

	got := FilterRepos(repos, []string{"api*"})
	if len(got) != 2 || got[0].Name != "api" || got[1].Name != "api-docs" {
		t.Errorf("FilterRepos(api*) = %+v, want [api api-docs]", got)
	}

	if got := FilterRepos(repos, []string{"nope"}); len(got) != 0 {
		t.Errorf("FilterRepos(nope) = %+v, want empty", got)
	}
}

func TestRecordRepoListCoverage(t *testing.T) {
	// Unfiltered: plain OK with the full count.
	snap := model.NewSnapshot("acme")
	snap.Repos = []model.Repo{{Name: "api"}, {Name: "web"}}
	recordRepoListCoverage(snap, Options{}, 2)
	if c, _ := snap.Coverage.Get(model.DataRepos); c.Status != model.CoverageOK || c.Count != 2 {
		t.Errorf("unfiltered coverage = %+v, want ok/2", c)
	}

	// Filtered: partial, with a note that names the flag so the report is honest.
	snap = model.NewSnapshot("acme")
	snap.Repos = []model.Repo{{Name: "api"}}
	recordRepoListCoverage(snap, Options{Repos: []string{"api"}}, 5)
	c, _ := snap.Coverage.Get(model.DataRepos)
	if c.Status != model.CoveragePartial || c.Count != 1 {
		t.Errorf("filtered coverage = %+v, want partial/1", c)
	}
	if !strings.Contains(c.Reason, "--repo") || !strings.Contains(c.Reason, "1 of 5") {
		t.Errorf("filtered coverage reason = %q, want it to mention --repo and 1 of 5", c.Reason)
	}
}

func TestValidateRepoPatterns(t *testing.T) {
	if err := ValidateRepoPatterns([]string{"api", "api-*", "team-*/api"}); err != nil {
		t.Errorf("valid patterns rejected: %v", err)
	}
	if err := ValidateRepoPatterns([]string{"api["}); err == nil {
		t.Error("malformed glob \"api[\" accepted, want error")
	}
}
