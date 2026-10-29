// Package access resolves who can reach which repository, at what level, and
// by which path — the view GitHub's own UI cannot give: effective permission is
// the union of org ownership, the base permission, organization roles, team
// grants through any depth of nesting, and direct collaborator grants, and the
// UI shows each in a different place, one repository at a time.
//
// It is a lens over data the checks already collect, not a check: no severity,
// no new reads. It covers role-based access only. Machine identities — GitHub
// Apps, deploy keys, fine-grained tokens — reach repositories outside this
// graph and are the Non-Human Identities axis' subject.
//
// Grants that apply to every repository (ownership, the base permission,
// all-repository organization roles) are kept as single org-wide lines rather
// than expanded per repository: a thousand members on two thousand
// repositories would otherwise be two million rows saying "read".
package access

import (
	"sort"
	"strings"

	"github.com/sunnysystems/scopeward/internal/model"
)

// SourceKind is where a grant comes from.
type SourceKind string

const (
	SourceOwner   SourceKind = "owner"    // organization owner: admin on every repository
	SourceBase    SourceKind = "base"     // the organization's base permission
	SourceOrgRole SourceKind = "org-role" // an organization role with repository access
	SourceTeam    SourceKind = "team"     // a team's grant on the repository
	SourceDirect  SourceKind = "direct"   // a collaborator grant on the repository itself
)

// Grant is one way a person reaches a level.
type Grant struct {
	Level Level
	Kind  SourceKind
	// Teams is the chain for a team grant (or a role held through a team):
	// the team holding the grant first, then down to the child team the person
	// is in. Child teams inherit their parent's access, so a grant on
	// "platform" reaches a member of "payments" as ["platform", "payments"].
	Teams []string
	Role  string // the organization role's name
}

// Path renders where the grant comes from, for a person reading it.
func (g Grant) Path() string {
	switch g.Kind {
	case SourceOwner:
		return "organization owner"
	case SourceBase:
		return "organization base permission"
	case SourceOrgRole:
		if len(g.Teams) > 0 {
			return "organization role " + g.Role + " via team " + strings.Join(g.Teams, " → ")
		}
		return "organization role " + g.Role
	case SourceTeam:
		return "team " + strings.Join(g.Teams, " → ")
	default:
		return "direct grant"
	}
}

// Access is what one person has on one repository: the effective level and
// the repository-specific grants behind it, strongest first. Effective also
// counts the person's org-wide grants, so a direct grant below the base
// permission shows as adding nothing.
type Access struct {
	Login     string
	Repo      string
	Effective Level
	Grants    []Grant
	Outside   bool // not an organization member: an outside collaborator
	Bot       bool
	// RaisedBy is the org-wide grant that sets Effective when it beats every
	// repository-specific one (an owner's admin over a team's write); nil
	// otherwise. The specific grants then matter only if it goes away.
	RaisedBy *Grant
}

// TopSpecific is the strongest repository-specific grant's level.
func (a Access) TopSpecific() Level {
	top := None
	for _, g := range a.Grants {
		top = max(top, g.Level)
	}
	return top
}

// MemberView is one person's reach.
type MemberView struct {
	Login   string
	Outside bool
	// Teams are the teams the person is in, each as its chain from the root
	// team down ("platform", "payments").
	Teams [][]string
	// OrgWide are the grants that apply to every repository.
	OrgWide []Grant
	// Repos are the repositories where something repository-specific applies,
	// strongest first.
	Repos []Access
}

// OrgWide is a grant every repository carries, and who holds it.
type OrgWide struct {
	Grant    Grant
	Everyone bool     // every organization member: the base permission
	Logins   []string // otherwise, who holds it
}

// RepoView is everyone who can reach one repository.
type RepoView struct {
	Repo     string
	Public   bool // anyone can read it
	Archived bool // read-only: write grants are inert until it is unarchived
	OrgWide  []OrgWide
	// Teams are the teams holding a grant on the repository, with the child
	// teams that inherit it nested underneath; Direct are collaborator grants
	// on the repository itself. Together they say why; People says who.
	Teams  []TeamNode
	Direct []DirectGrant
	// People are those with a repository-specific grant, strongest first.
	People []Access
}

// Options narrow the views.
type Options struct {
	// IncludeArchived lists archived repositories in a member's reach. They are
	// read-only, so they are left out unless asked for; a repository view
	// requested by name is always answered.
	IncludeArchived bool
}

// Graph is the resolved access of one organization.
type Graph struct {
	repos     map[string]model.Repo
	members   map[string]bool
	outside   map[string]bool
	bots      map[string]bool
	orgWide   map[string][]Grant            // login → grants on every repository
	specific  map[string]map[string][]Grant // login → repo → grants
	tree      teamTree
	teamRoles map[string][]Grant // team → all-repository org roles it holds
	gaps      []string
}

// Build resolves a snapshot's access. It never fails: what was not collected
// is recorded as a gap, and the views say so rather than guess.
func Build(s *model.Snapshot) *Graph {
	g := &Graph{
		repos:     map[string]model.Repo{},
		members:   map[string]bool{},
		outside:   map[string]bool{},
		bots:      map[string]bool{},
		orgWide:   map[string][]Grant{},
		specific:  map[string]map[string][]Grant{},
		teamRoles: map[string][]Grant{},
	}
	g.gaps = gaps(s)
	for _, r := range s.Repos {
		g.repos[r.Name] = r
	}

	base := ParseLevel(s.Org.DefaultRepoPermission)
	for _, m := range s.Members {
		g.members[m.Login] = true
		if m.IsBot {
			g.bots[m.Login] = true
		}
		if m.Role == "admin" {
			g.orgWide[m.Login] = append(g.orgWide[m.Login], Grant{Level: Admin, Kind: SourceOwner})
		}
		if base > None {
			g.orgWide[m.Login] = append(g.orgWide[m.Login], Grant{Level: base, Kind: SourceBase})
		}
	}

	teams := newTeamTree(s.Teams)
	g.tree = teams
	for _, role := range s.OrgRoles {
		level := ParseLevel(role.BaseRole)
		if level == None {
			continue // an org-only role: no repository access
		}
		holders := map[string][]Grant{}
		viaTeam := map[string]bool{}
		for _, t := range role.Teams {
			g.teamRoles[t.Slug] = append(g.teamRoles[t.Slug], Grant{Level: level, Kind: SourceOrgRole, Role: role.Name})
			for _, login := range teams.members(t.Slug) {
				holders[login] = append(holders[login], Grant{Level: level, Kind: SourceOrgRole, Role: role.Name, Teams: teams.chain(t.Slug, login)})
				viaTeam[login] = true
			}
		}
		for _, u := range role.Users {
			switch {
			case u.Assignment != "indirect":
				holders[u.Login] = append(holders[u.Login], Grant{Level: level, Kind: SourceOrgRole, Role: role.Name})
			case !viaTeam[u.Login]:
				// Held through a team whose membership was not read: the access
				// is real, the path is not known.
				holders[u.Login] = append(holders[u.Login], Grant{Level: level, Kind: SourceOrgRole, Role: role.Name, Teams: []string{"(team not read)"}})
			}
		}
		for login, gs := range holders {
			g.orgWide[login] = append(g.orgWide[login], gs...)
		}
	}

	for _, t := range s.Teams {
		for _, tg := range t.RepoGrants {
			level := ParseLevel(tg.Permission)
			for _, login := range teams.members(t.Slug) {
				g.addSpecific(login, tg.Repo, Grant{Level: level, Kind: SourceTeam, Teams: teams.chain(t.Slug, login)})
			}
		}
	}
	for _, r := range s.Repos {
		for _, dc := range r.DirectCollaborators {
			g.addSpecific(dc.Login, r.Name, Grant{Level: ParseLevel(dc.Permission), Kind: SourceDirect})
			if dc.IsBot {
				g.bots[dc.Login] = true
			}
			if !g.members[dc.Login] {
				g.outside[dc.Login] = true
			}
		}
	}

	for _, byRepo := range g.specific {
		for repo, gs := range byRepo {
			byRepo[repo] = dropInherited(gs)
		}
	}
	for login, gs := range g.orgWide {
		g.orgWide[login] = sortGrants(gs)
	}
	return g
}

func (g *Graph) addSpecific(login, repo string, gr Grant) {
	if g.specific[login] == nil {
		g.specific[login] = map[string][]Grant{}
	}
	g.specific[login][repo] = append(g.specific[login][repo], gr)
}

// dropInherited removes the copy of a parent team's grant that a child team's
// repository list may also carry: when one grant's chain passes through the
// team holding another at the same level, the parent's grant is the one that
// explains the access.
func dropInherited(gs []Grant) []Grant {
	out := make([]Grant, 0, len(gs))
	for i, a := range gs {
		inherited := false
		for j, b := range gs {
			if i == j || a.Kind != SourceTeam || b.Kind != SourceTeam || a.Level != b.Level || len(b.Teams) <= 1 {
				continue
			}
			for _, t := range b.Teams[1:] {
				if t == a.Teams[0] {
					inherited = true
				}
			}
		}
		if !inherited {
			out = append(out, a)
		}
	}
	return sortGrants(out)
}

// Members lists everyone the graph knows, members and outside collaborators,
// sorted.
func (g *Graph) Members() []string {
	set := map[string]bool{}
	for l := range g.members {
		set[l] = true
	}
	for l := range g.outside {
		set[l] = true
	}
	return sortedKeys(set)
}

// Repos lists the repositories, sorted; archived ones only when asked.
func (g *Graph) Repos(opts Options) []string {
	set := map[string]bool{}
	for name, r := range g.repos {
		if opts.IncludeArchived || !r.Archived {
			set[name] = true
		}
	}
	return sortedKeys(set)
}

// Gaps says what the graph could not resolve, and why.
func (g *Graph) Gaps() []string { return g.gaps }

// ForMember is one person's reach; ok is false for a login the graph does not
// know.
func (g *Graph) ForMember(login string, opts Options) (MemberView, bool) {
	if !g.members[login] && !g.outside[login] {
		return MemberView{}, false
	}
	v := MemberView{Login: login, Outside: g.outside[login], OrgWide: g.orgWide[login], Teams: g.tree.ownTeams(login)}
	for repo, gs := range g.specific[login] {
		r, known := g.repos[repo]
		if known && r.Archived && !opts.IncludeArchived {
			continue
		}
		v.Repos = append(v.Repos, g.access(login, repo, gs))
	}
	sortAccess(v.Repos, func(a Access) string { return a.Repo })
	return v, true
}

// ForRepo is everyone who can reach one repository; ok is false for a name the
// graph does not know.
func (g *Graph) ForRepo(repo string) (RepoView, bool) {
	r, ok := g.repos[repo]
	if !ok {
		return RepoView{}, false
	}
	v := RepoView{Repo: repo, Public: !r.Private, Archived: r.Archived, Teams: g.teamNodes(repo), Direct: g.directGrants(repo)}

	// Org-wide grants, grouped by source: the base permission once for
	// everyone, then each other source with who holds it.
	groups := map[string]*OrgWide{}
	var order []string
	for _, login := range sortedKeys(g.members) {
		for _, gr := range g.orgWide[login] {
			key := string(gr.Kind) + "\x00" + gr.Role + "\x00" + gr.Level.String()
			ow := groups[key]
			if ow == nil {
				ow = &OrgWide{Grant: Grant{Level: gr.Level, Kind: gr.Kind, Role: gr.Role}, Everyone: gr.Kind == SourceBase}
				groups[key] = ow
				order = append(order, key)
			}
			if !ow.Everyone {
				ow.Logins = append(ow.Logins, login)
			}
		}
	}
	for _, key := range order {
		v.OrgWide = append(v.OrgWide, *groups[key])
	}
	sort.SliceStable(v.OrgWide, func(i, j int) bool { return v.OrgWide[i].Grant.Level > v.OrgWide[j].Grant.Level })

	for login, byRepo := range g.specific {
		if gs, ok := byRepo[repo]; ok {
			v.People = append(v.People, g.access(login, repo, gs))
		}
	}
	sortAccess(v.People, func(a Access) string { return a.Login })
	return v, true
}

func (g *Graph) access(login, repo string, gs []Grant) Access {
	a := Access{Login: login, Repo: repo, Grants: gs, Outside: g.outside[login], Bot: g.bots[login]}
	a.Effective = a.TopSpecific()
	// orgWide is sorted strongest first.
	if ow := g.orgWide[login]; len(ow) > 0 && ow[0].Level > a.Effective {
		top := ow[0]
		a.Effective, a.RaisedBy = top.Level, &top
	}
	return a
}

// gaps names what was not collected well enough to resolve, from the
// coverage report. An edge scopeward could not read is said, never filled in.
func gaps(s *model.Snapshot) []string {
	cov := s.Coverage
	var out []string
	missing := func(kind model.DataKind) bool { return cov == nil || !cov.Available(kind) }
	partial := func(kind model.DataKind) bool {
		if cov == nil {
			return false
		}
		c, ok := cov.Get(kind)
		return ok && c.Status == model.CoveragePartial
	}
	switch {
	case missing(model.DataMembers):
		out = append(out, "organization members were not listed, so no member's access is resolved")
	case missing(model.DataMemberRoles):
		out = append(out, "member roles were not read, so organization owners (admin everywhere) are not identified")
	}
	if s.Org.DefaultRepoPermission == "" {
		out = append(out, "the organization base permission was not read")
	}
	if missing(model.DataTeamMembers) || missing(model.DataTeamRepos) {
		out = append(out, "team membership or team grants were not read (--quick skips them), so access through teams is not assessed")
	} else if partial(model.DataTeamMembers) || partial(model.DataTeamRepos) {
		out = append(out, "some teams' membership or grants could not be read, so access through those teams is missing")
	}
	if missing(model.DataRepoDirectCollaborators) {
		out = append(out, "direct collaborator grants were not read, so direct and outside-collaborator access is not assessed")
	} else if partial(model.DataRepoDirectCollaborators) {
		out = append(out, "direct collaborator grants could not be read on some repositories")
	}
	if missing(model.DataOrgRoles) {
		out = append(out, "organization roles were not readable, so all-repository roles are not assessed")
	}
	return out
}

func sortGrants(gs []Grant) []Grant {
	sort.SliceStable(gs, func(i, j int) bool {
		if gs[i].Level != gs[j].Level {
			return gs[i].Level > gs[j].Level
		}
		return gs[i].Path() < gs[j].Path()
	})
	return gs
}

func sortAccess(as []Access, key func(Access) string) {
	sort.Slice(as, func(i, j int) bool {
		if as[i].Effective != as[j].Effective {
			return as[i].Effective > as[j].Effective
		}
		return key(as[i]) < key(as[j])
	})
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
