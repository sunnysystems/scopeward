package collect

import (
	"fmt"
	"path"
	"strings"

	"github.com/sunnysystems/scopeward/internal/model"
)

// MatchRepo reports whether a repository matches any of the --repo patterns.
// Each pattern is a path.Match glob compared case-insensitively against every
// '/'-aligned suffix of the name, so for the GitLab project
// "group/team-a/api" the patterns "api", "team-a/api", and "group/team-a/api"
// all match — and on GitHub, where names have no '/', a pattern is simply
// matched against the repository name.
func MatchRepo(name string, patterns []string) bool {
	segs := strings.Split(strings.ToLower(name), "/")
	for _, p := range patterns {
		lp := strings.ToLower(p)
		for i := range segs {
			if ok, _ := path.Match(lp, strings.Join(segs[i:], "/")); ok {
				return true
			}
		}
	}
	return false
}

// FilterRepos returns the repos matching any of the --repo patterns; with no
// patterns the input is returned unchanged.
func FilterRepos(repos []model.Repo, patterns []string) []model.Repo {
	if len(patterns) == 0 {
		return repos
	}
	out := make([]model.Repo, 0, len(repos))
	for _, r := range repos {
		if MatchRepo(r.Name, patterns) {
			out = append(out, r)
		}
	}
	return out
}

// recordRepoListCoverage records the repo-list coverage after any --repo
// filtering: partial with an explicit note when filtered, so the report never
// reads as a full scan; plain OK otherwise. total is the pre-filter count.
func recordRepoListCoverage(snap *model.Snapshot, opts Options, total int) {
	if len(opts.Repos) == 0 {
		snap.Coverage.OK(model.DataRepos, len(snap.Repos))
		return
	}
	snap.Coverage.Partial(model.DataRepos, len(snap.Repos),
		fmt.Sprintf("filtered to %d of %d repositories (--repo)", len(snap.Repos), total))
}

// ValidateRepoPatterns rejects malformed --repo globs before any API call is
// made, instead of letting a bad pattern silently match nothing. Matching a
// pattern against itself forces path.Match to parse it fully.
func ValidateRepoPatterns(patterns []string) error {
	for _, p := range patterns {
		if _, err := path.Match(p, p); err != nil {
			return fmt.Errorf("invalid --repo pattern %q: %w", p, err)
		}
	}
	return nil
}
