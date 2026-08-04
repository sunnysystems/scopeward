package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(duplicateRoster{}) }

// DefaultDuplicateRosterSimilarity is the Jaccard threshold at which two teams
// are treated as the same group of people. 0.9 is deliberately near-identical:
// the finding claims a team is *redundant*, and at lower similarity the honest
// reading is often two overlapping-but-real functions (backend and platform
// sharing four of five people is a normal org, not a duplicate).
const DefaultDuplicateRosterSimilarity = 0.9

// duplicateRoster flags two teams holding effectively the same people while both
// grant repository access.
//
// Every other team check judges one team on its own, and a duplicate pair is
// invisible to all of them by construction: neither team is empty, neither is a
// singleton, both have maintainers, and both grant repos, so each looks
// individually healthy. The finding is the *relationship*, which is why this is
// the only check in the package that compares teams to each other.
//
// It matters more than team sprawl because it defeats access review rather than
// merely cluttering it. Reviewing the roster of the team people actually use is
// worthless while a twin grants the same or broader access under a name that
// never comes up in the review — which is the ordinary residue of a rename or a
// reorg, where the new team gets adopted and the old one keeps its grants.
type duplicateRoster struct{}

func (duplicateRoster) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.duplicate-roster",
		Title:           "Teams with duplicate rosters",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevMedium,
		RequiresData:    []model.DataKind{model.DataTeamMembers, model.DataTeamRepos},
		Description:     "Two teams holding effectively the same members while both grant repository access.",
	}
}

func (c duplicateRoster) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	candidates := duplicateCandidates(s.Teams)
	threshold := s.DuplicateRosterSimilarity
	if threshold <= 0 {
		threshold = DefaultDuplicateRosterSimilarity
	}

	var out []model.Finding
	// Pairwise, i < j, so a pair yields exactly one finding rather than one from
	// each side. O(n^2) over teams is nothing at realistic team counts, and it
	// needs no extra API call: the rosters are already in the snapshot.
	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			a, b := candidates[i], candidates[j]
			if related(a, b) {
				continue
			}
			sim := jaccard(rosterOf(a), rosterOf(b))
			if sim < threshold {
				continue
			}
			out = append(out, c.finding(s, a, b, sim))
		}
	}
	return out
}

// duplicateCandidates are the teams a pair can be drawn from: they must have
// members to compare and grants to make the redundancy matter. A team with no
// grants is already covered by teams.ghost, and one with no members by
// teams.empty — reporting them here would double-count what those checks say
// better.
func duplicateCandidates(teams []model.Team) []model.Team {
	out := make([]model.Team, 0, len(teams))
	for _, t := range teams {
		if len(t.Members) > 0 && len(t.RepoGrants) > 0 {
			out = append(out, t)
		}
	}
	return out
}

// related reports whether two teams are in a parent/child relationship. Nesting
// legitimately shares members — that is what it is for — so a parent and its
// child having identical rosters is a design, not residue. Depth is judged by
// teams.deep-nesting instead.
func related(a, b model.Team) bool {
	return a.ParentSlug == b.Slug || b.ParentSlug == a.Slug
}

// rosterOf is a team's people. Maintainers are folded in rather than compared
// separately: GitHub reports a maintainer as a member too, but not every
// collector path guarantees that, and a team whose maintainer is missing from
// Members would otherwise read as a slightly different roster than its twin.
func rosterOf(t model.Team) map[string]bool {
	set := make(map[string]bool, len(t.Members)+len(t.Maintainers))
	for _, m := range t.Members {
		set[m] = true
	}
	for _, m := range t.Maintainers {
		set[m] = true
	}
	return set
}

// jaccard is |A∩B| / |A∪B|: 1 for identical rosters, 0 for disjoint ones. Two
// empty sets are 0, not 1 — an undefined ratio must not read as a perfect match.
func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for m := range a {
		if b[m] {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func (c duplicateRoster) finding(s *model.Snapshot, a, b model.Team, sim float64) model.Finding {
	sev := model.SevMedium
	desc := "These two teams hold effectively the same people, and both grant repository access. " +
		"Every other team check judges a team on its own, so a pair like this passes all of them: neither is empty, " +
		"neither lacks a maintainer, and both grant repos. The problem is the relationship. " +
		"Access review is the control it defeats — reviewing the roster of the team people actually use is worthless " +
		"while a twin grants the same access under a name that never comes up in the review."

	// A duplicate that grants *more* is the dangerous direction: the team nobody
	// discusses is the one carrying the wider access, so a review of the team
	// people do discuss understates what its members can reach.
	if extra := exceeds(a, b); len(extra) > 0 {
		sev = model.SevHigh
		desc += fmt.Sprintf(" Here the duplicate grants access the other does not (%s), so reviewing only one of them understates what these people can reach.",
			strings.Join(extra, "; "))
	}

	names := []string{a.Name, b.Name}
	sort.Strings(names)
	return model.Finding{
		CheckID:  c.Meta().ID,
		Title:    fmt.Sprintf("Teams %q and %q share %.0f%% of their members and both grant repository access", names[0], names[1], sim*100),
		Severity: sev,
		Axis:     model.AxisTeams,
		// The pair is the finding, but a ResourceRef points at one thing. Anchor on
		// the org and name both teams in the title and evidence, rather than
		// implying one of them is the culprit — which one to keep is the reviewer's
		// call, and the tool does not know.
		Resource: orgRef(s.Org),
		Evidence: map[string]any{
			"teams":      []string{a.Slug, b.Slug},
			"similarity": sim,
			"members":    len(rosterOf(a)),
			"grants":     grantUnion(a, b),
		},
		Description: desc,
		// No fix command. Deleting a team is destructive and irreversible in the
		// way that matters (the grants are gone and nobody remembers what they
		// were), and which twin to keep is a human judgement about which name the
		// org actually uses.
		Remediation: fmt.Sprintf("Decide which of %q and %q is the real team. Move any grant the other holds onto it, then delete the duplicate. Check the union of their grants first — the redundant team may be the one carrying access nobody reviews.", names[0], names[1]),
		DocsURL:     teamsDocsURL,
	}
}

// exceeds describes repository access the first team grants beyond the second,
// and vice versa, as human strings. A permission that is merely *different*
// counts only when it is stronger: a twin granting read where the other grants
// admin is not the dangerous direction.
func exceeds(a, b model.Team) []string {
	var out []string
	for _, pair := range [2][2]model.Team{{a, b}, {b, a}} {
		lhs, rhs := pair[0], pair[1]
		other := make(map[string]string, len(rhs.RepoGrants))
		for _, g := range rhs.RepoGrants {
			other[g.Repo] = g.Permission
		}
		var extra []string
		for _, g := range lhs.RepoGrants {
			if have, ok := other[g.Repo]; !ok || model.Role(g.Permission).Rank() > model.Role(have).Rank() {
				extra = append(extra, g.Repo+":"+g.Permission)
			}
		}
		if len(extra) > 0 {
			sort.Strings(extra)
			out = append(out, fmt.Sprintf("%q grants %s", lhs.Name, strings.Join(extra, ", ")))
		}
	}
	return out
}

// grantUnion is every repo either team grants, so the reviewer can see the whole
// access surface the pair represents before deciding which one to keep.
func grantUnion(a, b model.Team) []string {
	set := map[string]bool{}
	for _, t := range []model.Team{a, b} {
		for _, g := range t.RepoGrants {
			set[g.Repo] = true
		}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
