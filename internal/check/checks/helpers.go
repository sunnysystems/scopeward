// Package checks holds the concrete governance checks. Each check lives in its
// own file and registers itself with the check registry from init(), so adding
// a check never requires editing a central list.
//
// Import this package for side effects to load every check:
//
//	import _ "github.com/sunnysystems/scopeward/internal/check/checks"
package checks

import (
	"strconv"
	"strings"

	"github.com/sunnysystems/scopeward/internal/model"
)

// memberRef builds a ResourceRef pointing at a member's GitHub profile.
func memberRef(m model.Member) model.ResourceRef {
	return model.ResourceRef{
		Type: "member",
		ID:   strconv.FormatInt(m.ID, 10),
		Name: m.Login,
		URL:  "https://github.com/" + m.Login,
	}
}

// orgRef builds a ResourceRef pointing at the organization.
func orgRef(o model.Organization) model.ResourceRef {
	return model.ResourceRef{
		Type: "org",
		ID:   strconv.FormatInt(o.ID, 10),
		Name: o.Login,
		URL:  "https://github.com/" + o.Login,
	}
}

// repoRef builds a ResourceRef pointing at a repository.
func repoRef(org string, r model.Repo) model.ResourceRef {
	return model.ResourceRef{
		Type: "repo",
		ID:   strconv.FormatInt(r.ID, 10),
		Name: org + "/" + r.Name,
		URL:  "https://github.com/" + org + "/" + r.Name,
	}
}

// repoDisplay is the human path of a repo for the current provider: GitHub repos
// are "org/name"; GitLab project names already carry their full namespace path,
// so prefixing the group would double it (acme/acme/api).
func repoDisplay(s *model.Snapshot, r model.Repo) string {
	if s.Provider == model.ProviderGitLab {
		return r.Name
	}
	return s.Org.Login + "/" + r.Name
}

// repoResource builds a provider-aware ResourceRef for a repository/project. On
// GitLab the web URL is derived from the instance host (when known) rather than
// github.com.
func repoResource(s *model.Snapshot, r model.Repo) model.ResourceRef {
	if s.Provider == model.ProviderGitLab {
		url := ""
		if s.Host != "" {
			url = strings.TrimRight(s.Host, "/") + "/" + r.Name
		}
		return model.ResourceRef{Type: "repo", ID: strconv.FormatInt(r.ID, 10), Name: r.Name, URL: url}
	}
	return repoRef(s.Org.Login, r)
}

// activeRepos returns the repositories a check should assess: every repo that is
// not archived. Range over this instead of s.Repos.
//
// An archived repository is read-only. Nothing can be pushed to it, no workflow
// runs in it, and no grant on it confers write in practice — so a finding about
// who may change its code is moot, and telling an operator to harden a repo they
// have already retired is noise.
//
// Checks used to get this behaviour by accident: the collector skips archived
// repos when filling in detail fields, so most checks saw only nil and stayed
// quiet. That coupling lived in another package, was stated nowhere, and held
// only as long as every snapshot came from that collector — a fixture, a snapshot
// cached before the repo was archived, or a future collector that stops filtering
// would light up findings on repos nobody can push to. This states the intent
// where the decision belongs.
//
// Two checks deliberately do not use it, and say so at their loop: a credential
// committed to an archived repo is still leaked (codesecurity.open-secret-alerts),
// and hygiene.stale-repo needs to see the archived flag to decide anything.
func activeRepos(s *model.Snapshot) []model.Repo {
	out := make([]model.Repo, 0, len(s.Repos))
	for _, r := range s.Repos {
		if !r.Archived {
			out = append(out, r)
		}
	}
	return out
}

// teamRef builds a ResourceRef pointing at a team.
func teamRef(org string, t model.Team) model.ResourceRef {
	return model.ResourceRef{
		Type: "team",
		ID:   strconv.FormatInt(t.ID, 10),
		Name: t.Name,
		URL:  "https://github.com/orgs/" + org + "/teams/" + t.Slug,
	}
}

// reviewExpected reports whether requiring a second-person PR approval is viable:
// it needs at least two members and must not be overridden by --solo. With fewer
// members (a solo account, --me/--user mode, or a one-person org), or with --solo
// set, requiring an approval would lock the branch, since GitHub forbids
// approving your own pull request.
func reviewExpected(s *model.Snapshot) bool {
	return !s.Solo && len(s.Members) >= 2
}

// withFix sets a finding's suggested-fix command and its verification command
// from a fix, returning the finding so it reads naturally in a literal:
//
//	withFix(model.Finding{...}, ghOrgPatch(org, field, value))
func withFix(f model.Finding, x fix) model.Finding {
	f.GHFix, f.GHVerify = x.cmd, x.verify
	return f
}
