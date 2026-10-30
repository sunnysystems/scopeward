// Package checks holds the concrete governance checks. Each check lives in its
// own file and registers itself with the check registry from init(), so adding
// a check never requires editing a central list.
//
// Import this package for side effects to load every check:
//
//	import _ "github.com/sunnysystems/scopeward/internal/check/checks"
package checks

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sunnysystems/scopeward/internal/access"
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

// reviewBench sizes branch-protection advice by who could review a change to a
// repository: the people who can push to it, by any path, from the access
// graph (access.Graph.Writers).
//
// It used to be the org's member count. That read a 10-member org where base
// permission is read and only the three owners can push (one of whom does all
// the work) as big enough to require an approval with no admin bypass, which
// is a lockout for the one active developer: the #37 failure, reached through
// a different door (#99). Who is in the org says nothing about who can review;
// who can push does.
//
// When the graph has gaps (a --quick run, unreadable teams or collaborators) or
// the provider has no per-repository access yet, the bench falls back to the
// member count and records why. Undercounting writers would suggest no review
// at all, which is the worse error.
type reviewBench struct {
	s     *model.Snapshot
	graph *access.Graph // nil when falling back to members
	why   string        // why it fell back; empty when using the graph
}

func newReviewBench(s *model.Snapshot) reviewBench {
	if s.Provider == model.ProviderGitLab {
		return reviewBench{s: s, why: "repository access is not resolved on GitLab yet"}
	}
	g := access.Build(s)
	if gaps := g.Gaps(); len(gaps) > 0 {
		return reviewBench{s: s, why: gaps[0]}
	}
	return reviewBench{s: s, graph: g}
}

// benchSize is the bench for one repository and what it was measured from.
type benchSize struct {
	n        int
	writers  bool   // measured from people who can push, not org members
	fallback string // why it is the member count, when it is
	solo     bool
}

func (b reviewBench) of(repo string) benchSize {
	if b.graph == nil {
		return benchSize{n: len(b.s.Members), fallback: b.why, solo: b.s.Solo}
	}
	return benchSize{n: len(b.graph.Writers(repo)), writers: true, solo: b.s.Solo}
}

// reviewExpected reports whether requiring a second-person PR approval is
// viable: it needs at least two people who could review, and must not be
// overridden by --solo. With fewer, requiring an approval would lock the
// branch, since GitHub forbids approving your own pull request.
func (z benchSize) reviewExpected() bool {
	return !z.solo && z.n >= 2
}

// breakGlassThreshold is the bench size below which scopeward stops asking an
// organization to give up its administrator bypass on protected branches.
//
// The number is a judgement call, not a standard. Requiring an approving review
// means every change waits on one of the other N-1 people; removing the admin
// bypass on top of that means there is no path at all when nobody is available.
// Below roughly five people that pool is thin enough that one holiday or one
// timezone blocks a production fix, and the observed outcome is not a stricter
// org — it is an operator who turns the whole thing off, or never applies it.
const breakGlassThreshold = 5

// adminBypassExpected reports whether keeping an administrator bypass
// (enforce_admins off) is the configuration scopeward should recommend for this
// repository: protection that binds everyone day to day, with owners retaining
// a documented emergency path.
//
// Deliberately inferred rather than flagged. A small team that does want strict
// enforcement simply sets it and is never flagged, since the bypass check only
// fires when the bypass exists; a larger one that wants a break-glass path
// accepts that one finding in .scopeward.yml, where the reason is now recorded
// and reported. Both directions are covered without another flag to learn.
//
// Bench size only, deliberately not --solo. That flag means "do not suggest a
// fix requiring a second approver", which is about the suggested command; letting
// it also decide a finding's severity would let a flag silently move the score,
// which is the invisible-discount problem ignore rules were made visible to
// avoid. A genuine single-developer repository has a bench below the threshold
// anyway, so the honest signal already covers the case the flag was named for.
func (z benchSize) adminBypassExpected() bool {
	return z.n < breakGlassThreshold
}

// people describes the bench in a sentence, e.g. "3 people who can push to
// this repository" or "10 organization members".
func (z benchSize) people() string {
	if z.writers {
		noun := "people who can push"
		if z.n == 1 {
			noun = "person who can push"
		}
		return fmt.Sprintf("%d %s to this repository", z.n, noun)
	}
	return fmt.Sprintf("%d organization member(s)", z.n)
}

// evidence records what the advice was sized on, so the reasoning stays
// visible in the report and the JSON.
func (z benchSize) evidence(ev map[string]any) map[string]any {
	ev["review_bench"] = z.n
	if z.writers {
		ev["review_bench_source"] = "people who can push"
	} else {
		ev["review_bench_source"] = "organization members"
		ev["review_bench_fallback"] = z.fallback
	}
	return ev
}

// withFix sets a finding's suggested-fix command and its verification command
// from a fix, returning the finding so it reads naturally in a literal:
//
//	withFix(model.Finding{...}, ghOrgPatch(org, field, value))
func withFix(f model.Finding, x fix) model.Finding {
	f.GHFix, f.GHVerify, f.GHScopes = x.cmd, x.verify, x.scopes
	return f
}
