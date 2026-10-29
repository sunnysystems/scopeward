package access

import (
	"sort"

	"github.com/sunnysystems/scopeward/internal/model"
)

// teamTree indexes teams for path finding. GitHub lists a team's members
// including the members of its child teams, though they are not direct members
// of the parent; child teams inherit the parent's access. So a parent's grant
// reaches everyone in its member list, and the path is found by walking down
// to the deepest child team the person is in.
type teamTree struct {
	team     map[string]model.Team
	parent   map[string]string
	inTeam   map[string]map[string]bool
	children map[string][]string
	slugs    []string
}

// maxTeamDepth bounds every walk of the tree against a parent cycle GitHub
// itself would not allow.
const maxTeamDepth = 32

func newTeamTree(teams []model.Team) teamTree {
	tt := teamTree{team: map[string]model.Team{}, parent: map[string]string{}, inTeam: map[string]map[string]bool{}, children: map[string][]string{}}
	for _, t := range teams {
		tt.team[t.Slug] = t
		tt.slugs = append(tt.slugs, t.Slug)
		set := map[string]bool{}
		for _, m := range t.Members {
			set[m] = true
		}
		tt.inTeam[t.Slug] = set
		if t.ParentSlug != "" {
			tt.parent[t.Slug] = t.ParentSlug
			tt.children[t.ParentSlug] = append(tt.children[t.ParentSlug], t.Slug)
		}
	}
	for _, cs := range tt.children {
		sort.Strings(cs)
	}
	sort.Strings(tt.slugs)
	return tt
}

func (tt teamTree) members(slug string) []string { return tt.team[slug].Members }

// chain is the path from slug down to the deepest descendant team login is in.
// Where two child teams both hold the person, the first by name is taken.
func (tt teamTree) chain(slug, login string) []string {
	path := []string{slug}
	for cur, depth := slug, 0; depth < maxTeamDepth; depth++ {
		next := ""
		for _, c := range tt.children[cur] {
			if tt.inTeam[c][login] {
				next = c
				break
			}
		}
		if next == "" {
			break
		}
		path = append(path, next)
		cur = next
	}
	return path
}

// ancestors are slug's parent teams, root first.
func (tt teamTree) ancestors(slug string) []string {
	var up []string
	for cur, depth := tt.parent[slug], 0; cur != "" && depth < maxTeamDepth; cur, depth = tt.parent[cur], depth+1 {
		up = append([]string{cur}, up...)
	}
	return up
}

// grantOn is the level a team's own grant gives it on a repository.
func (tt teamTree) grantOn(slug, repo string) (Level, bool) {
	for _, g := range tt.team[slug].RepoGrants {
		if g.Repo == repo {
			return ParseLevel(g.Permission), true
		}
	}
	return None, false
}

// ancestorHolds reports whether any ancestor of slug has a grant on repo, in
// which case slug shows up nested under it rather than on its own.
func (tt teamTree) ancestorHolds(slug, repo string) bool {
	for _, a := range tt.ancestors(slug) {
		if _, ok := tt.grantOn(a, repo); ok {
			return true
		}
	}
	return false
}

// node builds slug's place in a repository's team tree. inherited is the level
// the parent passes down (None at a root). A child's own grant counts only when
// it is stronger than what it inherits: an equal one is the copy GitHub lists
// on the child, not a second grant.
func (tt teamTree) node(slug, repo string, inherited Level, depth int) TeamNode {
	n := TeamNode{Team: slug, Level: inherited, Inherited: inherited > None, Roster: len(tt.team[slug].Members)}
	if own, ok := tt.grantOn(slug, repo); ok && own > inherited {
		n.Level, n.Inherited = own, false
	}
	inChild := map[string]bool{}
	for _, c := range tt.children[slug] {
		for _, m := range tt.team[c].Members {
			inChild[m] = true
		}
	}
	for _, m := range tt.team[slug].Members {
		if !inChild[m] {
			n.Members = append(n.Members, m)
		}
	}
	sort.Strings(n.Members)
	if depth < maxTeamDepth {
		for _, c := range tt.children[slug] {
			n.Children = append(n.Children, tt.node(c, repo, n.Level, depth+1))
		}
	}
	return n
}

// ownTeams are the teams login belongs to directly as far as the rosters can
// tell: those whose roster has them and none of whose child teams does. Each
// comes with its ancestor chain, root first.
func (tt teamTree) ownTeams(login string) [][]string {
	var out [][]string
	for _, slug := range tt.slugs {
		if !tt.inTeam[slug][login] {
			continue
		}
		inChild := false
		for _, c := range tt.children[slug] {
			inChild = inChild || tt.inTeam[c][login]
		}
		if !inChild {
			out = append(out, append(tt.ancestors(slug), slug))
		}
	}
	return out
}
