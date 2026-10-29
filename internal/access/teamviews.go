package access

import (
	"sort"
)

// TeamNode is a team in a repository's view: the level it reaches the
// repository at, the members listed at this level, and the child teams that
// inherit from it. Each person appears once in a tree, under the deepest team
// they are in: GitHub lists child-team members in the parent's roster too, so
// Roster keeps the full count while Members leaves the children's out.
type TeamNode struct {
	Team      string
	Level     Level
	Inherited bool // reached through an ancestor's grant, with no stronger one of its own
	Roster    int
	Members   []string
	Children  []TeamNode
}

// DirectGrant is a collaborator grant on the repository itself.
type DirectGrant struct {
	Login   string
	Level   Level
	Outside bool
	Bot     bool
}

// TeamRepo is a repository a team reaches, and the team whose grant it is:
// the team itself, or an ancestor it inherits from.
type TeamRepo struct {
	Repo  string
	Level Level
	From  string
}

// TeamView is one team: where it sits, who is in it, and what it reaches.
type TeamView struct {
	Team        string
	Name        string
	Ancestors   []string // root first
	Children    []string
	Members     []string // the roster as GitHub reports it, child teams' members included
	Maintainers []string
	Repos       []TeamRepo // strongest first
	OrgRoles    []Grant    // all-repository organization roles the team holds
}

// Teams lists the team slugs, sorted.
func (g *Graph) Teams() []string { return g.tree.slugs }

// ForTeam is one team's place and reach; ok is false for a slug the graph does
// not know. A grant the team holds and one it inherits at the same level are
// one access, credited to the ancestor that explains it.
func (g *Graph) ForTeam(slug string, opts Options) (TeamView, bool) {
	t, ok := g.tree.team[slug]
	if !ok {
		return TeamView{}, false
	}
	v := TeamView{
		Team: slug, Name: t.Name,
		Ancestors:   g.tree.ancestors(slug),
		Children:    g.tree.children[slug],
		Members:     sortedCopy(t.Members),
		Maintainers: sortedCopy(t.Maintainers),
		OrgRoles:    g.teamRoles[slug],
	}
	best := map[string]TeamRepo{}
	for _, s := range append(append([]string{}, v.Ancestors...), slug) {
		for _, gr := range g.tree.team[s].RepoGrants {
			level := ParseLevel(gr.Permission)
			if level > best[gr.Repo].Level {
				best[gr.Repo] = TeamRepo{Repo: gr.Repo, Level: level, From: s}
			}
		}
	}
	for repo, tr := range best {
		if r, known := g.repos[repo]; known && r.Archived && !opts.IncludeArchived {
			continue
		}
		v.Repos = append(v.Repos, tr)
	}
	sort.Slice(v.Repos, func(i, j int) bool {
		if v.Repos[i].Level != v.Repos[j].Level {
			return v.Repos[i].Level > v.Repos[j].Level
		}
		return v.Repos[i].Repo < v.Repos[j].Repo
	})
	return v, true
}

// teamNodes are the teams that hold a grant on repo, each with the child teams
// that inherit it nested underneath, strongest first.
func (g *Graph) teamNodes(repo string) []TeamNode {
	var roots []TeamNode
	for _, slug := range g.tree.slugs {
		if _, ok := g.tree.grantOn(slug, repo); !ok || g.tree.ancestorHolds(slug, repo) {
			continue
		}
		roots = append(roots, g.tree.node(slug, repo, None, 0))
	}
	sort.SliceStable(roots, func(i, j int) bool { return roots[i].Level > roots[j].Level })
	return roots
}

// directGrants are the collaborator grants on the repository itself,
// strongest first.
func (g *Graph) directGrants(repo string) []DirectGrant {
	var out []DirectGrant
	for _, dc := range g.repos[repo].DirectCollaborators {
		out = append(out, DirectGrant{Login: dc.Login, Level: ParseLevel(dc.Permission), Outside: g.outside[dc.Login], Bot: g.bots[dc.Login]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Level != out[j].Level {
			return out[i].Level > out[j].Level
		}
		return out[i].Login < out[j].Login
	})
	return out
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
