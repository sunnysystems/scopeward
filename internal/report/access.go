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
	Repos    []accessRowView
	Archived int    // archived repositories left out
	TooLarge string // set instead of the rows when the graph is too large
}

// accessRowView is one member or repository: its summary line and the
// grants behind it.
type accessRowView struct {
	Anchor  string
	Name    string
	Tag     string // "owner", "outside collaborator", "bot", "public", "archived"
	Summary string
	Notes   []string
	OrgWide []accessLineView
	Lines   []accessLineView
	Search  string
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
	if rows > accessRowLimit {
		v.TooLarge = fmt.Sprintf("This organization's access graph has %d rows, too many for a static report. Run `scopeward access --org %s member <login>` or `repo <name>`, or open the Access tab in `scopeward tui`.", rows, s.Org.Login)
		return v
	}

	for _, login := range g.Members() {
		m, _ := g.ForMember(login, access.Options{})
		v.Members = append(v.Members, memberRow(m))
	}
	for _, name := range g.Repos(access.Options{}) {
		r, _ := g.ForRepo(name)
		v.Repos = append(v.Repos, repoRow(r))
	}
	return v
}

func memberRow(m access.MemberView) accessRowView {
	row := accessRowView{Anchor: accessAnchor("m", m.Login), Name: m.Login}
	search := []string{m.Login}
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
		row.Summary = fmt.Sprintf("%d repositories · up to %s", len(m.Repos), top)
	}
	row.Search = strings.ToLower(strings.Join(search, " "))
	return row
}

func repoRow(r access.RepoView) accessRowView {
	row := accessRowView{Anchor: accessAnchor("r", r.Repo), Name: r.Repo, Notes: accessview.RepoNotes(r)}
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
