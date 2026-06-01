package report

import (
	"fmt"
	"io"

	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/ui"
)

// teamDesign is an aggregate portrait of an org's team structure, synthesized
// from the snapshot for the narrative "Team Design" section. Counts mirror the
// teams.* checks so the section and the findings never disagree.
type teamDesign struct {
	org       string
	members   int
	teams     int
	maxDepth  int
	tierName  string
	tierModel string

	ghost, orphan, empty, singleton int

	reposTotal       int // non-archived
	reposOwnedByTeam int
	codeownersKnown  int // non-archived repos where CODEOWNERS was assessed
	codeownersTeam   int // ...of those, with a team code owner
	propertyAdopted  bool
	propertyTagged   int

	gaps []string
}

// summarizeTeamDesign builds the portrait, or returns nil when the per-team data
// was not collected (user/account mode, or --quick) — so the section only shows
// when it can be accurate.
func summarizeTeamDesign(s *model.Snapshot) *teamDesign {
	if !s.Coverage.Available(model.DataTeamMembers) || !s.Coverage.Available(model.DataTeamRepos) {
		return nil
	}

	td := &teamDesign{org: s.Org.Login, members: len(s.Members), teams: len(s.Teams)}
	td.tierName, td.tierModel = teamSizeTier(td.members)

	parent := make(map[string]string, len(s.Teams))
	isParent := make(map[string]bool, len(s.Teams))
	for _, t := range s.Teams {
		parent[t.Slug] = t.ParentSlug
		if t.ParentSlug != "" {
			isParent[t.ParentSlug] = true
		}
	}
	for _, t := range s.Teams {
		if d := teamChainDepth(t.Slug, parent); d > td.maxDepth {
			td.maxDepth = d
		}
		switch {
		case len(t.Members) == 0:
			if !isParent[t.Slug] {
				td.empty++
			}
		case len(t.Members) == 1 && !isParent[t.Slug]:
			td.singleton++
		}
		if len(t.Members) > 0 && len(t.Maintainers) == 0 {
			td.orphan++
		}
		if len(t.Members) > 0 && len(t.RepoGrants) == 0 && !isParent[t.Slug] {
			td.ghost++
		}
	}

	owned := make(map[string]bool)
	for _, t := range s.Teams {
		for _, g := range t.RepoGrants {
			owned[g.Repo] = true
		}
	}
	prop := s.OwningTeamProperty
	if prop == "" {
		prop = "owning-team"
	}
	for _, r := range s.Repos {
		if r.Archived {
			continue
		}
		td.reposTotal++
		if owned[r.Name] {
			td.reposOwnedByTeam++
		}
		if r.CodeownersPresent != nil {
			td.codeownersKnown++
			if *r.CodeownersPresent && len(r.CodeownersTeams) > 0 {
				td.codeownersTeam++
			}
		}
		if len(r.Properties) > 0 {
			td.propertyAdopted = true
		}
		if r.Properties[prop] != "" {
			td.propertyTagged++
		}
	}

	td.gaps = td.computeGaps()
	return td
}

// computeGaps lists where the observed structure diverges from what its size
// tier expects, plus ownership coverage. Phrased as orientation, not verdicts.
func (td *teamDesign) computeGaps() []string {
	var gaps []string
	switch {
	case td.members < 10:
		if td.maxDepth > 1 {
			gaps = append(gaps, "team nesting adds little at this size — flat teams are easier to reason about")
		}
	case td.members < 50:
		if td.teams == 0 {
			gaps = append(gaps, "no teams exist yet — access is likely granted person-by-person rather than by team")
		}
	case td.members < 200:
		if td.maxDepth < 2 && td.teams > 0 {
			gaps = append(gaps, "teams are flat — grouping squads under an area team makes inherited access clearer at this size")
		}
	default:
		if td.maxDepth < 2 {
			gaps = append(gaps, "the team hierarchy is flat for an org this large — mirroring the org chart usually needs structure")
		}
		gaps = append(gaps, "at this scale, team membership should be provisioned from your identity provider (SSO/SCIM) rather than by hand")
	}
	if td.reposTotal > 0 && td.reposOwnedByTeam < td.reposTotal {
		n := td.reposTotal - td.reposOwnedByTeam
		gaps = append(gaps, fmt.Sprintf("%d of %d repositories have no owning team — their access comes only from direct grants", n, td.reposTotal))
	}
	if td.ghost > 0 {
		gaps = append(gaps, fmt.Sprintf("%d team(s) grant no repository access — overhead without value", td.ghost))
	}
	return gaps
}

// teamSizeTier classifies an org by member count, mirroring the bands used by
// the teams.size-tier-advice check.
func teamSizeTier(members int) (name, expected string) {
	switch {
	case members < 10:
		return "micro (<10 members)", "one or two flat teams; access granted through teams, no nesting needed"
	case members < 50:
		return "small (10–50 members)", "teams per squad plus one or two role teams (admins, security); shallow or no nesting"
	case members < 200:
		return "medium (50–200 members)", "a shallow hierarchy (an area team grouping its squads), formalized role teams, and org rulesets instead of per-repo branch protection"
	default:
		return "large (200+ members)", "teams mirroring the org chart provisioned via SSO/SCIM, with minimal-scope role teams and no manual access grants"
	}
}

// teamChainDepth walks the parent chain to compute nesting depth (top-level = 1),
// guarding against cycles with an iteration cap.
func teamChainDepth(slug string, parent map[string]string) int {
	depth, cur := 1, slug
	for i := 0; i < len(parent)+1; i++ {
		p, ok := parent[cur]
		if !ok || p == "" {
			break
		}
		depth++
		cur = p
	}
	return depth
}

func pct(n, total int) string {
	if total == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%d/%d (%.0f%%)", n, total, 100*float64(n)/float64(total))
}

// renderTeamDesignText writes the Team Design section to a terminal.
func renderTeamDesignText(out io.Writer, td *teamDesign) {
	fmt.Fprintln(out, ui.Label.Render("Team Design"))
	fmt.Fprintf(out, "  %s · %s · %s\n",
		ui.Accent.Render(td.org),
		td.tierName,
		fmt.Sprintf("%d teams, depth %d", td.teams, td.maxDepth),
	)
	fmt.Fprintf(out, "  %s\n\n", ui.Subtle.Render("Expected here: "+td.tierModel+"."))

	type row struct {
		n     int
		label string
	}
	structure := []row{
		{td.ghost, "grant no repository access"},
		{td.orphan, "have no maintainer"},
		{td.empty, "are empty"},
		{td.singleton, "have a single member"},
	}
	any := false
	for _, r := range structure {
		if r.n > 0 {
			any = true
			break
		}
	}
	if any {
		for _, r := range structure {
			if r.n > 0 {
				fmt.Fprintf(out, "  %s %s\n", ui.WarnTag.Render(fmt.Sprintf("%2d teams", r.n)), ui.Subtle.Render(r.label))
			}
		}
	} else {
		fmt.Fprintln(out, "  "+ui.Good.Render("team structure looks clean"))
	}
	fmt.Fprintln(out)

	fmt.Fprintln(out, "  "+ui.Label.Render("Ownership"))
	fmt.Fprintf(out, "    repos with an owning team ...... %s\n", pct(td.reposOwnedByTeam, td.reposTotal))
	fmt.Fprintf(out, "    repos with a team code owner ... %s\n", pct(td.codeownersTeam, td.reposTotal))
	if td.propertyAdopted {
		fmt.Fprintf(out, "    owning-team property ........... %s\n", pct(td.propertyTagged, td.reposTotal))
	} else {
		fmt.Fprintf(out, "    owning-team property ........... %s\n", ui.Subtle.Render("not adopted"))
	}
	fmt.Fprintln(out)

	if len(td.gaps) > 0 {
		fmt.Fprintln(out, "  "+ui.Label.Render("Gaps"))
		for _, g := range td.gaps {
			fmt.Fprintf(out, "    %s %s\n", ui.WarnTag.Render("•"), g)
		}
		fmt.Fprintln(out)
	}
}

// renderTeamDesignMarkdown writes the Team Design section as Markdown.
func renderTeamDesignMarkdown(out io.Writer, td *teamDesign) {
	fmt.Fprintf(out, "## Team Design\n\n")
	fmt.Fprintf(out, "**%s** · %s · %d teams, depth %d\n\n", td.org, td.tierName, td.teams, td.maxDepth)
	fmt.Fprintf(out, "_Expected here: %s._\n\n", td.tierModel)

	lines := []struct {
		n     int
		label string
	}{
		{td.ghost, "grant no repository access"},
		{td.orphan, "have no maintainer"},
		{td.empty, "are empty"},
		{td.singleton, "have a single member"},
	}
	wrote := false
	for _, l := range lines {
		if l.n > 0 {
			fmt.Fprintf(out, "- %d teams %s\n", l.n, l.label)
			wrote = true
		}
	}
	if !wrote {
		fmt.Fprintln(out, "- Team structure looks clean.")
	}
	fmt.Fprintln(out)

	fmt.Fprintln(out, "**Ownership**")
	fmt.Fprintf(out, "- repos with an owning team: %s\n", pct(td.reposOwnedByTeam, td.reposTotal))
	fmt.Fprintf(out, "- repos with a team code owner: %s\n", pct(td.codeownersTeam, td.reposTotal))
	if td.propertyAdopted {
		fmt.Fprintf(out, "- `owning-team` property: %s\n", pct(td.propertyTagged, td.reposTotal))
	} else {
		fmt.Fprintln(out, "- `owning-team` property: not adopted")
	}
	fmt.Fprintln(out)

	if len(td.gaps) > 0 {
		fmt.Fprintln(out, "**Gaps**")
		for _, g := range td.gaps {
			fmt.Fprintf(out, "- %s\n", g)
		}
		fmt.Fprintln(out)
	}
}
