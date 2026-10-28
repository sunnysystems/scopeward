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
	membersOf map[string][]string
	inTeam    map[string]map[string]bool
	children  map[string][]string
}

func newTeamTree(teams []model.Team) teamTree {
	tt := teamTree{membersOf: map[string][]string{}, inTeam: map[string]map[string]bool{}, children: map[string][]string{}}
	for _, t := range teams {
		tt.membersOf[t.Slug] = t.Members
		set := map[string]bool{}
		for _, m := range t.Members {
			set[m] = true
		}
		tt.inTeam[t.Slug] = set
		if t.ParentSlug != "" {
			tt.children[t.ParentSlug] = append(tt.children[t.ParentSlug], t.Slug)
		}
	}
	for _, cs := range tt.children {
		sort.Strings(cs)
	}
	return tt
}

func (tt teamTree) members(slug string) []string { return tt.membersOf[slug] }

// chain is the path from slug down to the deepest descendant team login is in.
// Where two child teams both hold the person, the first by name is taken; the
// depth bound guards against a parent cycle GitHub itself would not allow.
func (tt teamTree) chain(slug, login string) []string {
	path := []string{slug}
	for cur, depth := slug, 0; depth < 32; depth++ {
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
