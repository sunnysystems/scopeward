package report

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sunnysystems/scopeward/internal/access"
	"github.com/sunnysystems/scopeward/internal/accessview"
	"github.com/sunnysystems/scopeward/internal/model"
)

// accessRowLimit bounds the Access section. Past it the static page would be
// dominated by one section, so the report points at `scopeward access` and the
// TUI's Access tab instead of rendering it. A variable so tests can lower it.
var accessRowLimit = 25000

// accessHTMLView is the report's Access section: the access graph by member
// and by repository, rendered server-side as <details> rows so it reads
// without JavaScript, like the findings. A script only adds search and opens
// the row a finding links to.
type accessHTMLView struct {
	Scope    string
	Gaps     []string
	Members  []accessRowView
	Teams    []accessRowView
	Repos    []accessRowView
	Archived int    // archived repositories left out
	TooLarge string // set instead of the rows when the graph is too large
}

// accessRowView is one member or repository: its summary line and the
// grants behind it.
type accessRowView struct {
	Anchor  string
	Name    string
	Tag     string // "owner", "outside collaborator", "public", "archived", or a team's parent chain
	Summary string
	Notes   []string
	Facts   []accessFact     // labelled facts: a member's teams, a team's parent and roster
	OrgWide []accessLineView // grants on every repository
	Teams   []accessTeamLine // a repository's teams, the tree flattened
	Direct  []accessLineView // a repository's direct grants
	// Lines are the row's main list under LinesHeading: a member's or a
	// team's repositories, a repository's people.
	LinesHeading string
	Lines        []accessLineView
	Search       string
}

// accessFact is one labelled fact in a row.
type accessFact struct{ Label, Value string }

// accessTeamLine is one team in a repository's tree, flattened with its depth.
type accessTeamLine struct {
	Depth      int // 0 for a team holding the grant, capped at 3 for indentation
	Team       string
	Level      string
	LevelClass string
	About      string // roster size, and whether the level is inherited
	Members    string // members listed at this level of the tree
}

// accessLineView is one row of grants: the level, who or what it is about,
// and the path that grants it.
type accessLineView struct {
	Level      string
	LevelClass string
	Subject    string
	Path       string
	Note       string
}

var anchorUnsafe = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

// accessAnchor is the element id of a member's ("m") or repository's ("r")
// row, so a finding about it can link there.
func accessAnchor(kind, name string) string {
	return "access-" + kind + "-" + anchorUnsafe.ReplaceAllString(name, "-")
}

// findingAccessAnchor is the access row a finding is about, if it is about a
// repository or a person.
func findingAccessAnchor(r model.ResourceRef) string {
	switch r.Type {
	case "repo":
		return accessAnchor("r", r.Name[strings.LastIndex(r.Name, "/")+1:])
	case "member":
		return accessAnchor("m", r.Name)
	case "team":
		// Team findings carry the display name; the slug ends their URL.
		if i := strings.LastIndex(r.URL, "/teams/"); i >= 0 {
			return accessAnchor("t", r.URL[i+len("/teams/"):])
		}
	}
	return ""
}

func levelClass(l access.Level) string {
	switch {
	case l >= access.Admin:
		return "lvl-admin"
	case l >= access.Write:
		return "lvl-write"
	default:
		return "lvl-read"
	}
}

func buildAccessHTML(s *model.Snapshot) *accessHTMLView {
	if s == nil || len(s.Members) == 0 && len(s.Repos) == 0 {
		return nil
	}
	g := access.Build(s)
	v := &accessHTMLView{Scope: accessview.Scope, Gaps: g.Gaps()}
	v.Archived = len(g.Repos(access.Options{IncludeArchived: true})) - len(g.Repos(access.Options{}))

	rows := 0
	for _, login := range g.Members() {
		m, _ := g.ForMember(login, access.Options{})
		rows += len(m.Repos)
	}
	for _, name := range g.Repos(access.Options{}) {
		r, _ := g.ForRepo(name)
		rows += len(r.People)
	}
	for _, slug := range g.Teams() {
		t, _ := g.ForTeam(slug, access.Options{})
		rows += len(t.Repos)
	}
	if rows > accessRowLimit {
		v.TooLarge = fmt.Sprintf("This organization's access graph has %d rows, too many for a static report. Run `scopeward access --org %s member <login>` or `repo <name>`, or open the Access tab in `scopeward tui`.", rows, s.Org.Login)
		return v
	}

	for _, login := range g.Members() {
		m, _ := g.ForMember(login, access.Options{})
		v.Members = append(v.Members, memberRow(m))
	}
	for _, slug := range g.Teams() {
		t, _ := g.ForTeam(slug, access.Options{})
		v.Teams = append(v.Teams, teamRow(t))
	}
	for _, name := range g.Repos(access.Options{}) {
		r, _ := g.ForRepo(name)
		v.Repos = append(v.Repos, repoRow(r))
	}
	return v
}

func teamRow(t access.TeamView) accessRowView {
	row := accessRowView{
		Anchor: accessAnchor("t", t.Team), Name: t.Team, LinesHeading: "Repositories",
		Summary: plural(len(t.Members), "member") + " · " + repositories(len(t.Repos)),
	}
	if len(t.Ancestors) > 0 {
		row.Tag = "in " + strings.Join(t.Ancestors, " → ")
	}
	search := []string{t.Team, t.Name}
	if len(t.Children) > 0 {
		row.Facts = append(row.Facts, accessFact{"Children", strings.Join(t.Children, ", ")})
	}
	if len(t.Maintainers) > 0 {
		row.Facts = append(row.Facts, accessFact{"Maintainers", strings.Join(t.Maintainers, ", ")})
	}
	for _, r := range t.OrgRoles {
		row.Facts = append(row.Facts, accessFact{"Org role", r.Level.String() + " " + r.Role + " (every repository)"})
	}
	row.Facts = append(row.Facts, accessFact{fmt.Sprintf("Members (%d)", len(t.Members)), strings.Join(t.Members, ", ")})
	if len(t.Children) > 0 {
		row.Notes = append(row.Notes, "GitHub counts child teams' members in this roster.")
	}
	for _, r := range t.Repos {
		line := accessLineView{Level: r.Level.String(), LevelClass: levelClass(r.Level), Subject: r.Repo}
		if r.From != t.Team {
			line.Path = "inherited from " + r.From
		}
		row.Lines = append(row.Lines, line)
		search = append(search, r.Repo)
	}
	search = append(search, t.Members...)
	row.Search = strings.ToLower(strings.Join(search, " "))
	return row
}

// repositories counts repositories; plural would spell it "repositorys".
func repositories(n int) string {
	if n == 1 {
		return "1 repository"
	}
	return fmt.Sprintf("%d repositories", n)
}

// teamLines flattens a repository's team tree for the template.
func teamLines(ns []access.TeamNode, depth int) []accessTeamLine {
	var out []accessTeamLine
	for _, n := range ns {
		about := plural(n.Roster, "member")
		if n.Inherited {
			about = "inherited · " + about
		}
		out = append(out, accessTeamLine{
			Depth: min(depth, 3), Team: n.Team, Level: n.Level.String(), LevelClass: levelClass(n.Level),
			About: about, Members: strings.Join(n.Members, ", "),
		})
		out = append(out, teamLines(n.Children, depth+1)...)
	}
	return out
}

func memberRow(m access.MemberView) accessRowView {
	row := accessRowView{Anchor: accessAnchor("m", m.Login), Name: m.Login, LinesHeading: "Specific repositories"}
	search := []string{m.Login}
	if len(m.Teams) > 0 {
		chains := accessview.TeamChains(m.Teams)
		row.Facts = append(row.Facts, accessFact{"Teams", chains})
		search = append(search, chains)
	}
	top := access.None
	for _, g := range m.OrgWide {
		row.OrgWide = append(row.OrgWide, accessLineView{Level: g.Level.String(), LevelClass: levelClass(g.Level), Path: g.Path()})
		top = max(top, g.Level)
	}
	owner := len(m.OrgWide) > 0 && m.OrgWide[0].Kind == access.SourceOwner
	switch {
	case owner:
		row.Tag = "owner"
	case m.Outside:
		row.Tag = "outside collaborator"
	}

	// An owner's specific grants are all under their admin: said once.
	overridden := len(m.OrgWide) > 0 && len(m.Repos) > 0
	for _, a := range m.Repos {
		overridden = overridden && a.TopSpecific() <= m.OrgWide[0].Level
		top = max(top, a.Effective)
	}
	if overridden {
		row.Notes = append(row.Notes, fmt.Sprintf("None of the grants below goes beyond %s (%s everywhere); they matter only if that changes.", m.OrgWide[0].Path(), m.OrgWide[0].Level))
	}
	for _, a := range m.Repos {
		level := a.Effective
		if overridden {
			level = a.TopSpecific()
		}
		line := accessLineView{Level: level.String(), LevelClass: levelClass(level), Subject: a.Repo, Path: grantPathsText(a.Grants)}
		if a.RaisedBy != nil && !overridden {
			line.Note = a.Effective.String() + " as " + a.RaisedBy.Path()
		}
		row.Lines = append(row.Lines, line)
		search = append(search, a.Repo, line.Path)
	}

	if owner {
		row.Summary = "admin everywhere"
	} else {
		row.Summary = repositories(len(m.Repos)) + " · up to " + top.String()
	}
	row.Search = strings.ToLower(strings.Join(search, " "))
	return row
}

func repoRow(r access.RepoView) accessRowView {
	row := accessRowView{Anchor: accessAnchor("r", r.Repo), Name: r.Repo, Notes: accessview.RepoNotes(r), LinesHeading: "People", Teams: teamLines(r.Teams, 0)}
	for _, d := range r.Direct {
		subject := d.Login
		if d.Bot {
			subject += " (bot)"
		}
		if d.Outside {
			subject += " (outside collaborator)"
		}
		row.Direct = append(row.Direct, accessLineView{Level: d.Level.String(), LevelClass: levelClass(d.Level), Subject: subject})
	}
	switch {
	case r.Archived:
		row.Tag = "archived"
	case r.Public:
		row.Tag = "public"
	}
	search := []string{r.Repo}
	for _, ow := range r.OrgWide {
		row.OrgWide = append(row.OrgWide, accessLineView{
			Level: ow.Grant.Level.String(), LevelClass: levelClass(ow.Grant.Level),
			Subject: accessview.OrgWideWho(ow, 12), Path: ow.Grant.Path(),
		})
	}
	writers := 0
	for _, a := range r.People {
		if a.Effective >= access.Write {
			writers++
		}
		line := accessLineView{Level: a.Effective.String(), LevelClass: levelClass(a.Effective), Subject: accessview.PersonLabel(a), Path: grantPathsText(a.Grants)}
		if a.RaisedBy != nil {
			line.Note = a.Effective.String() + " as " + a.RaisedBy.Path()
		}
		row.Lines = append(row.Lines, line)
		search = append(search, a.Login, line.Path)
	}
	row.Summary = fmt.Sprintf("%d with a specific grant · %d can write", len(r.People), writers)
	row.Search = strings.ToLower(strings.Join(search, " "))
	return row
}

// grantPathsText is the path column: the level already has its own, so the
// first grant is its path alone and any others read "also <level> <path>".
func grantPathsText(gs []access.Grant) string {
	parts := make([]string, 0, len(gs))
	for i, g := range gs {
		if i == 0 {
			parts = append(parts, g.Path())
		} else {
			parts = append(parts, "also "+g.Level.String()+" "+g.Path())
		}
	}
	return strings.Join(parts, "; ")
}

// linkFindingsToAccess keeps a finding's "access" link only where the
// section has a row to land on: an archived repository, or a graph too large
// to render, leaves the finding without one rather than with a dead link.
func linkFindingsToAccess(v *htmlView) {
	rows := map[string]bool{}
	if v.Access != nil {
		for _, r := range v.Access.Members {
			rows[r.Anchor] = true
		}
		for _, r := range v.Access.Teams {
			rows[r.Anchor] = true
		}
		for _, r := range v.Access.Repos {
			rows[r.Anchor] = true
		}
	}
	for ai := range v.Axes {
		for gi := range v.Axes[ai].Groups {
			items := v.Axes[ai].Groups[gi].Items
			for ii := range items {
				if !rows[items[ii].AccessAnchor] {
					items[ii].AccessAnchor = ""
				}
			}
		}
	}
}
