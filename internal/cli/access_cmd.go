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
	"github.com/sunnysystems/scopeward/internal/accessview"
	"github.com/sunnysystems/scopeward/internal/collect"
	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/provider"
	"github.com/sunnysystems/scopeward/internal/ui"
)

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
			"  scopeward access --org acme repo api       who can reach api, and why\n" +
			"  scopeward access --org acme team platform  who is in platform, and what it reaches",
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
		Use:   "team <slug>",
		Short: "A team's place, members, and every repository it reaches",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAccess(cmd.Context(), cmd.OutOrStdout(), opts, accessQuery{team: args[0], includeArchived: includeArchived})
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
	member, repo, team string
	includeArchived    bool
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
	if q.team != "" {
		v, ok := g.ForTeam(q.team, access.Options{IncludeArchived: q.includeArchived})
		if !ok {
			return fmt.Errorf("no team %q in %s (teams are named by slug, e.g. %q)", q.team, opts.org, "platform-eng")
		}
		return renderAccessTeam(out, format, opts.org, v, g.Gaps(), q.includeArchived)
	}
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

// --- team ---

func renderAccessTeam(out io.Writer, format, org string, v access.TeamView, gaps []string, includeArchived bool) error {
	switch format {
	case "json":
		repos := make([]map[string]any, 0, len(v.Repos))
		for _, r := range v.Repos {
			repos = append(repos, map[string]any{"repo": r.Repo, "level": r.Level.String(), "from": r.From, "inherited": r.From != v.Team})
		}
		return writeJSON(out, map[string]any{
			"org": org, "team": v.Team, "name": v.Name,
			"ancestors": nonNil(v.Ancestors), "children": nonNil(v.Children),
			"members": nonNil(v.Members), "maintainers": nonNil(v.Maintainers),
			"org_roles": grantsJSON(v.OrgRoles), "repositories": repos,
			"archived_included": includeArchived, "not_assessed": nonNil(gaps), "scope": accessview.Scope,
		})
	case "markdown":
		fmt.Fprintf(out, "# Access · %s · team %s\n\n", org, v.Team)
		if len(v.Ancestors) > 0 {
			fmt.Fprintf(out, "**Parent:** %s  \n", strings.Join(v.Ancestors, " → "))
		}
		if len(v.Children) > 0 {
			fmt.Fprintf(out, "**Children:** %s  \n", strings.Join(v.Children, ", "))
		}
		fmt.Fprintf(out, "**Members (%d):** %s\n\n", len(v.Members), strings.Join(v.Members, ", "))
		fmt.Fprintf(out, "| Repository | Level | From |\n|---|---|---|\n")
		for _, r := range v.Repos {
			from := "own grant"
			if r.From != v.Team {
				from = "inherited from " + r.From
			}
			fmt.Fprintf(out, "| %s | %s | %s |\n", r.Repo, r.Level, from)
		}
		fmt.Fprintln(out)
		writeAccessFooterMarkdown(out, gaps)
		return nil
	}

	fmt.Fprintln(out, ui.Title.Render("scopeward")+ui.Subtle.Render(" · access · "+org+" · team ")+ui.Accent.Render(v.Team))
	fmt.Fprintln(out)
	accessview.Team(out, v, gaps, accessview.MemberOptions{IncludeArchived: includeArchived, ArchivedHint: "pass --include-archived"})
	return nil
}

func teamNodesJSON(ns []access.TeamNode) []map[string]any {
	out := make([]map[string]any, 0, len(ns))
	for _, n := range ns {
		out = append(out, map[string]any{
			"team": n.Team, "level": n.Level.String(), "inherited": n.Inherited,
			"roster": n.Roster, "members": nonNil(n.Members), "children": teamNodesJSON(n.Children),
		})
	}
	return out
}

func writeTeamNodesMarkdown(out io.Writer, ns []access.TeamNode, depth int) {
	for _, n := range ns {
		name := n.Team
		if depth > 0 {
			name = strings.Repeat("&nbsp;&nbsp;", depth-1) + "└ " + n.Team
		}
		level := n.Level.String()
		if n.Inherited {
			level += " (inherited)"
		}
		fmt.Fprintf(out, "| %s | %s | %d: %s |\n", name, level, n.Roster, strings.Join(n.Members, ", "))
		writeTeamNodesMarkdown(out, n.Children, depth+1)
	}
}

func nonNilChains(c [][]string) [][]string {
	if c == nil {
		return [][]string{}
	}
	return c
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
			"org": org, "member": v.Login, "outside_collaborator": v.Outside, "teams": nonNilChains(v.Teams),
			"every_repository": grantsJSON(v.OrgWide), "repositories": repos,
			"archived_included": includeArchived, "not_assessed": nonNil(gaps), "scope": accessview.Scope,
		})
	case "markdown":
		fmt.Fprintf(out, "# Access · %s · %s\n\n", org, v.Login)
		if len(v.Teams) > 0 {
			fmt.Fprintf(out, "**Teams:** %s\n\n", accessview.TeamChains(v.Teams))
		}
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
			fmt.Fprintf(out, "| %s | %s | %s |\n", a.Repo, a.Effective, accessview.GrantPaths(a.Grants))
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
	accessview.Member(out, v, gaps, accessview.MemberOptions{IncludeArchived: includeArchived, ArchivedHint: "pass --include-archived"})
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
		direct := make([]map[string]any, 0, len(v.Direct))
		for _, d := range v.Direct {
			direct = append(direct, map[string]any{"login": d.Login, "level": d.Level.String(), "outside_collaborator": d.Outside, "bot": d.Bot})
		}
		return writeJSON(out, map[string]any{
			"org": org, "repo": v.Repo, "public": v.Public, "archived": v.Archived,
			"org_wide": groups, "teams": teamNodesJSON(v.Teams), "direct": direct, "people": people,
			"not_assessed": nonNil(gaps), "scope": accessview.Scope,
		})
	case "markdown":
		fmt.Fprintf(out, "# Access · %s/%s\n\n", org, v.Repo)
		for _, note := range accessview.RepoNotes(v) {
			fmt.Fprintf(out, "_%s_\n\n", note)
		}
		if len(v.Teams) > 0 {
			fmt.Fprintf(out, "**Teams**\n\n| Team | Level | Members |\n|---|---|---|\n")
			writeTeamNodesMarkdown(out, v.Teams, 0)
			fmt.Fprintln(out)
		}
		if len(v.Direct) > 0 {
			fmt.Fprintf(out, "**Direct grants**\n\n| Who | Level |\n|---|---|\n")
			for _, d := range v.Direct {
				fmt.Fprintf(out, "| %s | %s |\n", d.Login, d.Level)
			}
			fmt.Fprintln(out)
		}
		fmt.Fprintf(out, "**People**\n\n| Who | Level | Through |\n|---|---|---|\n")
		for _, ow := range v.OrgWide {
			fmt.Fprintf(out, "| %s | %s | %s |\n", accessview.OrgWideWho(ow, 1<<30), ow.Grant.Level, ow.Grant.Path())
		}
		for _, a := range v.People {
			fmt.Fprintf(out, "| %s | %s | %s |\n", accessview.PersonLabel(a), a.Effective, accessview.GrantPaths(a.Grants))
		}
		fmt.Fprintln(out)
		writeAccessFooterMarkdown(out, gaps)
		return nil
	}

	fmt.Fprintln(out, ui.Title.Render("scopeward")+ui.Subtle.Render(" · access · ")+ui.Accent.Render(org+"/"+v.Repo))
	fmt.Fprintln(out)
	accessview.Repo(out, v, gaps)
	return nil
}

func writeAccessFooterMarkdown(out io.Writer, gaps []string) {
	fmt.Fprintf(out, "_%s_\n", accessview.Scope)
	for _, gap := range gaps {
		fmt.Fprintf(out, "\n**Not assessed:** %s\n", gap)
	}
}
