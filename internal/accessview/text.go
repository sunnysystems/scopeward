// Package accessview renders the access graph as terminal text, the same way
// in the `scopeward access` command and in the TUI's Access tab. The caller
// owns the heading; these write the body.
package accessview

import (
	"fmt"
	"io"
	"strings"

	"github.com/sunnysystems/scopeward/internal/access"
	"github.com/sunnysystems/scopeward/internal/ui"
)

// Scope is said wherever access is shown: the graph is role-based, and the
// identities that reach repositories outside it are a different axis.
const Scope = "Role-based access only: GitHub Apps, deploy keys and fine-grained tokens reach repositories outside this view (see the Non-Human Identities axis)."

// MemberOptions tune a member's view.
type MemberOptions struct {
	IncludeArchived bool
	// ArchivedHint tells the reader how to show archived repositories when
	// they are hidden, e.g. "pass --include-archived" or "press x".
	ArchivedHint string
}

// Member writes one person's reach: org-wide grants, then each repository
// with something more specific, strongest first.
func Member(out io.Writer, v access.MemberView, gaps []string, opts MemberOptions) {
	if len(v.OrgWide) > 0 {
		fmt.Fprintln(out, "  "+ui.Label.Render("Every repository"))
		for _, g := range v.OrgWide {
			fmt.Fprintf(out, "    %s  %s\n", levelCell(g.Level), g.Path())
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintf(out, "  %s %s\n", ui.Label.Render("Specific repositories"), ui.Subtle.Render(fmt.Sprint(len(v.Repos))))
	if len(v.Repos) == 0 {
		fmt.Fprintln(out, "    "+ui.Subtle.Render("none beyond what every repository grants"))
	}
	// When an org-wide grant beats every specific one (an owner), say so once
	// instead of on every line: the list then only matters if that changes.
	overridden := len(v.OrgWide) > 0 && len(v.Repos) > 0
	for _, a := range v.Repos {
		overridden = overridden && a.TopSpecific() <= v.OrgWide[0].Level
	}
	if overridden {
		top := v.OrgWide[0]
		fmt.Fprintln(out, "    "+ui.Subtle.Render(fmt.Sprintf("none goes beyond %s (%s everywhere); they matter only if that changes", top.Path(), top.Level)))
	}
	width := 0
	for _, a := range v.Repos {
		width = max(width, len(a.Repo))
	}
	for _, a := range v.Repos {
		if overridden {
			a.Effective, a.RaisedBy = a.TopSpecific(), nil
		}
		fmt.Fprintf(out, "    %s  %-*s  %s\n", levelCell(a.Effective), width, a.Repo, describeGrants(a))
	}
	fmt.Fprintln(out)
	if !opts.IncludeArchived {
		fmt.Fprintln(out, "  "+ui.Subtle.Render("Archived repositories are not listed (read-only); "+opts.ArchivedHint+" to see them."))
	}
	footer(out, gaps)
}

// Repo writes everyone who can reach one repository: its notes, the org-wide
// groups, then each person with a repository-specific grant.
func Repo(out io.Writer, v access.RepoView, gaps []string) {
	for _, note := range RepoNotes(v) {
		fmt.Fprintln(out, "  "+ui.WarnTag.Render(note))
	}
	if len(RepoNotes(v)) > 0 {
		fmt.Fprintln(out)
	}
	if len(v.OrgWide) > 0 {
		fmt.Fprintln(out, "  "+ui.Label.Render("Org-wide"))
		for _, ow := range v.OrgWide {
			fmt.Fprintf(out, "    %s  %s  %s\n", levelCell(ow.Grant.Level), ow.Grant.Path(), ui.Subtle.Render(OrgWideWho(ow, 8)))
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintf(out, "  %s %s\n", ui.Label.Render("Repository-specific"), ui.Subtle.Render(fmt.Sprint(len(v.People))))
	width := 0
	for _, a := range v.People {
		width = max(width, len(a.Login))
	}
	for _, a := range v.People {
		fmt.Fprintf(out, "    %s  %-*s  %s\n", levelCell(a.Effective), width, a.Login, describeGrants(a))
	}
	fmt.Fprintln(out)
	footer(out, gaps)
}

// RepoNotes are the facts about a repository that change how to read it.
func RepoNotes(v access.RepoView) []string {
	var notes []string
	if v.Public {
		notes = append(notes, "public: anyone can read it")
	}
	if v.Archived {
		notes = append(notes, "archived: read-only, and its direct grants are not collected")
	}
	return notes
}

// GrantPaths lists grants as "level path", joined.
func GrantPaths(gs []access.Grant) string {
	ps := make([]string, 0, len(gs))
	for _, g := range gs {
		ps = append(ps, g.Level.String()+" "+g.Path())
	}
	return strings.Join(ps, "; ")
}

// PersonLabel is a login with what kind of account it is.
func PersonLabel(a access.Access) string {
	label := a.Login
	if a.Bot {
		label += " (bot)"
	}
	if a.Outside {
		label += " (outside collaborator)"
	}
	return label
}

// OrgWideWho names who holds an org-wide grant, up to limit logins.
func OrgWideWho(ow access.OrgWide, limit int) string {
	if ow.Everyone {
		return "every member"
	}
	if len(ow.Logins) <= limit {
		return strings.Join(ow.Logins, ", ")
	}
	return strings.Join(ow.Logins[:limit], ", ") + fmt.Sprintf(" and %d more", len(ow.Logins)-limit)
}

// levelCell is a fixed-width level, coloured by how much it can do.
func levelCell(l access.Level) string {
	cell := fmt.Sprintf("%-8s", l)
	switch {
	case l >= access.Admin:
		return ui.Bad.Render(cell)
	case l >= access.Write:
		return ui.WarnTag.Render(cell)
	default:
		return ui.Subtle.Render(cell)
	}
}

// describeGrants is the first path, then any others, then the org-wide grant
// that raises the effective level above every specific one.
func describeGrants(a access.Access) string {
	parts := []string{}
	for i, g := range a.Grants {
		if i == 0 {
			parts = append(parts, g.Path())
		} else {
			parts = append(parts, ui.Subtle.Render("also "+g.Level.String()+" "+g.Path()))
		}
	}
	if a.RaisedBy != nil {
		parts = append(parts, ui.Subtle.Render("("+a.Effective.String()+" as "+a.RaisedBy.Path()+")"))
	}
	var tags []string
	if a.Bot {
		tags = append(tags, "bot")
	}
	if a.Outside {
		tags = append(tags, "outside collaborator")
	}
	if len(tags) > 0 {
		parts = append(parts, ui.Accent.Render(strings.Join(tags, " · ")))
	}
	return strings.Join(parts, "  ")
}

func footer(out io.Writer, gaps []string) {
	fmt.Fprintln(out, "  "+ui.Subtle.Render(Scope))
	for _, gap := range gaps {
		fmt.Fprintln(out, "  "+ui.WarnTag.Render("Not assessed: ")+gap)
	}
}
