package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sunnysystems/scopeward/internal/access"
	"github.com/sunnysystems/scopeward/internal/collect"
	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/provider"
	"github.com/sunnysystems/scopeward/internal/ui"
)

// accessScope is said wherever access is shown: the graph is role-based, and
// the identities that reach repositories outside it are a different axis.
const accessScope = "Role-based access only: GitHub Apps, deploy keys and fine-grained tokens reach repositories outside this view (see the Non-Human Identities axis)."

// newAccessCommand builds `scopeward access`: who can reach what in an
// organization, and by which path. It answers the two questions an access
// review starts with, which GitHub's own UI spreads across a page per repository.
func newAccessCommand(opts *options) *cobra.Command {
	var includeArchived bool
	cmd := &cobra.Command{
		Use:   "access",
		Short: "Show who can reach what in an org, and by which path",
		Long: "Resolve effective repository access: org ownership, the base permission,\n" +
			"organization roles, team grants through nested teams, and direct grants.\n\n" +
			"  scopeward access --org acme member alice   what alice can reach, and how\n" +
			"  scopeward access --org acme repo api       who can reach api, and why",
	}
	cmd.PersistentFlags().BoolVar(&includeArchived, "include-archived", false, "list archived (read-only) repositories in a member's reach")

	cmd.AddCommand(&cobra.Command{
		Use:   "member <login>",
		Short: "Every repository a member or outside collaborator can reach, and through what",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAccess(cmd.Context(), cmd.OutOrStdout(), opts, accessQuery{member: args[0], includeArchived: includeArchived})
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "repo <name>",
		Short: "Everyone who can reach a repository, and why",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAccess(cmd.Context(), cmd.OutOrStdout(), opts, accessQuery{repo: args[0]})
		},
	})
	return cmd
}

type accessQuery struct {
	member, repo    string
	includeArchived bool
}

func runAccess(ctx context.Context, out io.Writer, opts *options, q accessQuery) error {
	applyColorPolicy(opts.noColor)
	if opts.org == "" || opts.me || opts.user != "" {
		return errors.New("access needs --org <name>: it resolves an organization's teams, roles and grants")
	}
	format := opts.format
	switch format {
	case "auto", "text", "json", "markdown":
	default:
		return fmt.Errorf("access supports --format auto|text|json|markdown, not %q", format)
	}

	kind, err := provider.Parse(opts.provider, opts.host)
	if err != nil {
		return err
	}
	if kind != model.ProviderGitHub {
		return fmt.Errorf("access is not available for %s yet", provider.Title(kind))
	}
	tok, tokenSource, err := provider.ResolveToken(kind, os.Stderr)
	if err != nil {
		return err
	}
	coll, err := provider.New(provider.Config{Provider: kind, Host: opts.host, Token: tok, TokenSource: tokenSource})
	if err != nil {
		return err
	}
	if _, err := coll.Preflight(ctx); err != nil {
		return err
	}
	defer openCache(opts, coll, opts.org, tok)()

	// A repository question only needs that repository's direct grants.
	co := collect.Options{AccessOnly: true, MaxRepos: opts.maxRepos, Repos: opts.repos}
	if q.repo != "" {
		co.Repos = []string{q.repo}
	}
	prog := newProgress(opts, coll, kind)
	prog.Start()
	snap, err := coll.Collect(ctx, provider.Args{Subject: opts.org, Options: co, Progress: prog})
	prog.Stop()
	if err != nil {
		return err
	}

	g := access.Build(snap)
	if q.repo != "" {
		v, ok := g.ForRepo(q.repo)
		if !ok {
			return fmt.Errorf("no repository %q in %s", q.repo, opts.org)
		}
		return renderAccessRepo(out, format, opts.org, v, g.Gaps())
	}
	v, ok := g.ForMember(q.member, access.Options{IncludeArchived: q.includeArchived})
	if !ok {
		return fmt.Errorf("%s is neither a member nor an outside collaborator of %s", q.member, opts.org)
	}
	return renderAccessMember(out, format, opts.org, v, g.Gaps(), q.includeArchived)
}

// --- JSON ---

type grantJSON struct {
	Level  string   `json:"level"`
	Source string   `json:"source"`
	Path   string   `json:"path"`
	Teams  []string `json:"teams,omitempty"`
	Role   string   `json:"role,omitempty"`
}

func grantsJSON(gs []access.Grant) []grantJSON {
	out := make([]grantJSON, 0, len(gs))
	for _, g := range gs {
		out = append(out, grantJSON{Level: g.Level.String(), Source: string(g.Kind), Path: g.Path(), Teams: g.Teams, Role: g.Role})
	}
	return out
}

type accessJSON struct {
	Login     string      `json:"login,omitempty"`
	Repo      string      `json:"repo,omitempty"`
	Effective string      `json:"effective"`
	Grants    []grantJSON `json:"grants"`
	Outside   bool        `json:"outside_collaborator,omitempty"`
	Bot       bool        `json:"bot,omitempty"`
}

// nonNil keeps an empty list a list in JSON, so a consumer never has to tell
// null from nothing.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func writeJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// --- member ---

func renderAccessMember(out io.Writer, format, org string, v access.MemberView, gaps []string, includeArchived bool) error {
	switch format {
	case "json":
		repos := make([]accessJSON, 0, len(v.Repos))
		for _, a := range v.Repos {
			repos = append(repos, accessJSON{Repo: a.Repo, Effective: a.Effective.String(), Grants: grantsJSON(a.Grants)})
		}
		return writeJSON(out, map[string]any{
			"org": org, "member": v.Login, "outside_collaborator": v.Outside,
			"every_repository": grantsJSON(v.OrgWide), "repositories": repos,
			"archived_included": includeArchived, "not_assessed": nonNil(gaps), "scope": accessScope,
		})
	case "markdown":
		fmt.Fprintf(out, "# Access · %s · %s\n\n", org, v.Login)
		if len(v.OrgWide) > 0 {
			fmt.Fprintln(out, "**Every repository**")
			fmt.Fprintln(out)
			for _, g := range v.OrgWide {
				fmt.Fprintf(out, "- `%s` %s\n", g.Level, g.Path())
			}
			fmt.Fprintln(out)
		}
		fmt.Fprintf(out, "| Repository | Effective | Through |\n|---|---|---|\n")
		for _, a := range v.Repos {
			fmt.Fprintf(out, "| %s | %s | %s |\n", a.Repo, a.Effective, grantPaths(a.Grants))
		}
		fmt.Fprintln(out)
		writeAccessFooterMarkdown(out, gaps)
		return nil
	}

	who := v.Login
	if v.Outside {
		who += ui.Subtle.Render(" (outside collaborator)")
	}
	fmt.Fprintln(out, ui.Title.Render("scopeward")+ui.Subtle.Render(" · access · "+org+" · ")+ui.Accent.Render(who))
	fmt.Fprintln(out)
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
	if !includeArchived {
		fmt.Fprintln(out, "  "+ui.Subtle.Render("Archived repositories are not listed (read-only); pass --include-archived to see them."))
	}
	writeAccessFooter(out, gaps)
	return nil
}

// --- repo ---

func renderAccessRepo(out io.Writer, format, org string, v access.RepoView, gaps []string) error {
	switch format {
	case "json":
		groups := make([]map[string]any, 0, len(v.OrgWide))
		for _, ow := range v.OrgWide {
			gj := grantsJSON([]access.Grant{ow.Grant})[0]
			group := map[string]any{
				"level": gj.Level, "source": gj.Source, "path": gj.Path,
				"every_member": ow.Everyone, "logins": nonNil(ow.Logins),
			}
			if gj.Role != "" {
				group["role"] = gj.Role
			}
			groups = append(groups, group)
		}
		people := make([]accessJSON, 0, len(v.People))
		for _, a := range v.People {
			people = append(people, accessJSON{Login: a.Login, Effective: a.Effective.String(), Grants: grantsJSON(a.Grants), Outside: a.Outside, Bot: a.Bot})
		}
		return writeJSON(out, map[string]any{
			"org": org, "repo": v.Repo, "public": v.Public, "archived": v.Archived,
			"org_wide": groups, "people": people, "not_assessed": nonNil(gaps), "scope": accessScope,
		})
	case "markdown":
		fmt.Fprintf(out, "# Access · %s/%s\n\n", org, v.Repo)
		for _, note := range repoNotes(v) {
			fmt.Fprintf(out, "_%s_\n\n", note)
		}
		fmt.Fprintf(out, "| Who | Level | Through |\n|---|---|---|\n")
		for _, ow := range v.OrgWide {
			fmt.Fprintf(out, "| %s | %s | %s |\n", orgWideWho(ow, 1<<30), ow.Grant.Level, ow.Grant.Path())
		}
		for _, a := range v.People {
			fmt.Fprintf(out, "| %s | %s | %s |\n", personLabel(a), a.Effective, grantPaths(a.Grants))
		}
		fmt.Fprintln(out)
		writeAccessFooterMarkdown(out, gaps)
		return nil
	}

	fmt.Fprintln(out, ui.Title.Render("scopeward")+ui.Subtle.Render(" · access · ")+ui.Accent.Render(org+"/"+v.Repo))
	for _, note := range repoNotes(v) {
		fmt.Fprintln(out, "  "+ui.WarnTag.Render(note))
	}
	fmt.Fprintln(out)
	if len(v.OrgWide) > 0 {
		fmt.Fprintln(out, "  "+ui.Label.Render("Org-wide"))
		for _, ow := range v.OrgWide {
			fmt.Fprintf(out, "    %s  %s  %s\n", levelCell(ow.Grant.Level), ow.Grant.Path(), ui.Subtle.Render(orgWideWho(ow, 8)))
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
	writeAccessFooter(out, gaps)
	return nil
}

func repoNotes(v access.RepoView) []string {
	var notes []string
	if v.Public {
		notes = append(notes, "public: anyone can read it")
	}
	if v.Archived {
		notes = append(notes, "archived: read-only, and its direct grants are not collected")
	}
	return notes
}

// --- shared ---

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

// describeGrants is the first path, then any others, then what makes the
// effective level higher than every specific grant.
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

func grantPaths(gs []access.Grant) string {
	ps := make([]string, 0, len(gs))
	for _, g := range gs {
		ps = append(ps, g.Level.String()+" "+g.Path())
	}
	return strings.Join(ps, "; ")
}

func personLabel(a access.Access) string {
	label := a.Login
	if a.Bot {
		label += " (bot)"
	}
	if a.Outside {
		label += " (outside collaborator)"
	}
	return label
}

func orgWideWho(ow access.OrgWide, limit int) string {
	if ow.Everyone {
		return "every member"
	}
	if len(ow.Logins) <= limit {
		return strings.Join(ow.Logins, ", ")
	}
	return strings.Join(ow.Logins[:limit], ", ") + fmt.Sprintf(" and %d more", len(ow.Logins)-limit)
}

func writeAccessFooter(out io.Writer, gaps []string) {
	fmt.Fprintln(out, "  "+ui.Subtle.Render(accessScope))
	for _, gap := range gaps {
		fmt.Fprintln(out, "  "+ui.WarnTag.Render("Not assessed: ")+gap)
	}
}

func writeAccessFooterMarkdown(out io.Writer, gaps []string) {
	fmt.Fprintf(out, "_%s_\n", accessScope)
	for _, gap := range gaps {
		fmt.Fprintf(out, "\n**Not assessed:** %s\n", gap)
	}
}
