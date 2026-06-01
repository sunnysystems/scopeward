package checks

import (
	"context"
	"fmt"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(ghostTeam{})
	check.Register(orphanTeam{})
	check.Register(emptyTeam{})
	check.Register(singletonTeam{})
	check.Register(teamSizeTierAdvice{})
}

const teamsDocsURL = "https://docs.github.com/organizations/organizing-members-into-teams/about-teams"

// teamHasChildren returns the set of team slugs that are a parent of some other
// team. Parent teams legitimately carry no direct members or repos (they exist
// to group child teams), so structural checks exclude them.
func teamHasChildren(teams []model.Team) map[string]bool {
	parents := make(map[string]bool, len(teams))
	for _, t := range teams {
		if t.ParentSlug != "" {
			parents[t.ParentSlug] = true
		}
	}
	return parents
}

// ghostTeam flags teams that have members but grant access to no repository:
// governance overhead (members to manage, reviews to run) with no value.
type ghostTeam struct{}

func (ghostTeam) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.ghost",
		Title:           "Teams that grant no repository access",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevLow,
		RequiresData:    []model.DataKind{model.DataTeamMembers, model.DataTeamRepos},
		Description:     "Teams with members but no repository grants add governance overhead without conferring access.",
	}
}

func (c ghostTeam) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	parents := teamHasChildren(s.Teams)
	var out []model.Finding
	for _, t := range s.Teams {
		if parents[t.Slug] || len(t.Members) == 0 || len(t.RepoGrants) > 0 {
			continue
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       fmt.Sprintf("Team %q has %d members but grants no repository access", t.Name, len(t.Members)),
			Severity:    model.SevLow,
			Axis:        model.AxisTeams,
			Resource:    teamRef(s.Org.Login, t),
			Evidence:    map[string]any{"slug": t.Slug, "members": len(t.Members)},
			Description: "This team has members to manage and access reviews to run, yet it confers no repository access. It is usually a leftover, a renamed team, or access that was meant to be granted and never was.",
			Remediation: "Either grant the team the repository access it was meant to have, or remove it and move its members to a team that maps to a real function.",
			DocsURL:     teamsDocsURL,
		})
	}
	return out
}

// orphanTeam flags teams with members but no maintainer: nobody is accountable
// for approving who joins or leaves, so membership drifts unmanaged.
type orphanTeam struct{}

func (orphanTeam) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.orphan",
		Title:           "Teams without a maintainer",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevMedium,
		RequiresData:    []model.DataKind{model.DataTeamMembers},
		Description:     "Teams with members but no maintainer have no one accountable for membership changes.",
	}
}

func (c orphanTeam) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, t := range s.Teams {
		if len(t.Members) == 0 || len(t.Maintainers) > 0 {
			continue
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       fmt.Sprintf("Team %q has %d members but no maintainer", t.Name, len(t.Members)),
			Severity:    model.SevMedium,
			Axis:        model.AxisTeams,
			Resource:    teamRef(s.Org.Login, t),
			Evidence:    map[string]any{"slug": t.Slug, "members": len(t.Members)},
			Description: "With no maintainer, no one is responsible for reviewing who is added or removed from this team, so its membership (and therefore the repository access it grants) drifts without oversight.",
			Remediation: "Assign at least one maintainer who owns this team's membership and access.",
			GHFix:       fmt.Sprintf("gh api -X PUT orgs/%s/teams/%s/memberships/USERNAME -f role=maintainer", s.Org.Login, t.Slug),
			GHVerify:    fmt.Sprintf("gh api orgs/%s/teams/%s/members?role=maintainer --jq '.[].login'", s.Org.Login, t.Slug),
			DocsURL:     teamsDocsURL,
		})
	}
	return out
}

// emptyTeam flags teams with no members (and no child teams). They are residue
// that clutters the permission model and can mask stale repo grants.
type emptyTeam struct{}

func (emptyTeam) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.empty",
		Title:           "Empty teams",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevInfo,
		RequiresData:    []model.DataKind{model.DataTeamMembers},
		Description:     "Teams with no members (and no child teams) are residue that clutters the permission model.",
	}
}

func (c emptyTeam) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	parents := teamHasChildren(s.Teams)
	var out []model.Finding
	for _, t := range s.Teams {
		if parents[t.Slug] || len(t.Members) > 0 {
			continue
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       fmt.Sprintf("Team %q has no members", t.Name),
			Severity:    model.SevInfo,
			Axis:        model.AxisTeams,
			Resource:    teamRef(s.Org.Login, t),
			Evidence:    map[string]any{"slug": t.Slug, "repo_grants": len(t.RepoGrants)},
			Description: "An empty team grants nothing useful but still appears in the org's structure. If it still holds repository grants, those become invisible, member-less access paths.",
			Remediation: "Remove the team, or populate it if it maps to a real function.",
			GHFix:       fmt.Sprintf("gh api -X DELETE orgs/%s/teams/%s", s.Org.Login, t.Slug),
			GHVerify:    fmt.Sprintf("gh api orgs/%s/teams --jq '.[].slug'", s.Org.Login),
			DocsURL:     teamsDocsURL,
		})
	}
	return out
}

// singletonTeam flags teams with exactly one member and no child teams. A
// one-person team is almost always a direct grant in disguise: it carries the
// overhead of a team but maps access to a single individual.
type singletonTeam struct{}

func (singletonTeam) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.singleton",
		Title:           "One-person teams",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevLow,
		RequiresData:    []model.DataKind{model.DataTeamMembers},
		Description:     "A team with a single member usually models access to one person; effectively a direct grant wearing a team's clothes.",
	}
}

func (c singletonTeam) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	parents := teamHasChildren(s.Teams)
	var out []model.Finding
	for _, t := range s.Teams {
		if parents[t.Slug] || len(t.Members) != 1 {
			continue
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       fmt.Sprintf("Team %q has only one member (%s)", t.Name, t.Members[0]),
			Severity:    model.SevLow,
			Axis:        model.AxisTeams,
			Resource:    teamRef(s.Org.Login, t),
			Evidence:    map[string]any{"slug": t.Slug, "member": t.Members[0], "repo_grants": len(t.RepoGrants)},
			Description: "A single-member team grants access to exactly one person, which is what a direct grant does, but with extra structure to maintain. It often signals access that was personalized rather than role-based.",
			Remediation: "If the access is role-based, fold this person into a shared team for that role. If it is genuinely personal, consider whether they need it at all.",
			DocsURL:     teamsDocsURL,
		})
	}
	return out
}

// teamSizeTier classifies an organization by member count, which determines what
// team structure is healthy. The bands are deliberately coarse.
type teamSizeTier struct {
	name    string
	model   string // the team-structure model expected at this size
	wantSSO bool   // whether provisioning via SSO/SCIM is expected
}

func tierFor(members int) teamSizeTier {
	switch {
	case members < 10:
		return teamSizeTier{"micro (<10 members)", "one or two flat teams; access granted through teams, no nesting needed", false}
	case members < 50:
		return teamSizeTier{"small (10–50 members)", "teams per squad plus one or two role teams (admins, security); shallow or no nesting", false}
	case members < 200:
		return teamSizeTier{"medium (50–200 members)", "a shallow hierarchy (an area team grouping its squads), formalized role teams, and org rulesets instead of per-repo branch protection", false}
	default:
		return teamSizeTier{"large (200+ members)", "teams mirroring the org chart provisioned via SSO/SCIM, with minimal-scope role teams and no manual access grants", true}
	}
}

// teamSizeTierAdvice emits a single advisory finding describing the team model
// expected at the org's size and the gaps observed against it. It never asserts
// an ideal team or squad size — only the structural model that fits the scale.
type teamSizeTierAdvice struct{}

func (teamSizeTierAdvice) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.size-tier-advice",
		Title:           "Team structure for organization size",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevInfo,
		RequiresData:    []model.DataKind{model.DataMembers, model.DataTeams},
		Description:     "Advises the team-structure model that fits the organization's size, and notes gaps against it.",
	}
}

func (c teamSizeTierAdvice) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	members := len(s.Members)
	if members == 0 {
		return nil
	}
	tier := tierFor(members)

	// Observed signals to ground the advice.
	parent := make(map[string]string, len(s.Teams))
	for _, t := range s.Teams {
		parent[t.Slug] = t.ParentSlug
	}
	maxDepth := 0
	for _, t := range s.Teams {
		if d := teamDepth(t.Slug, parent); d > maxDepth {
			maxDepth = d
		}
	}

	gaps := tierGaps(tier, len(s.Teams), members, maxDepth)
	desc := fmt.Sprintf(
		"At %d members this organization is %s. A healthy structure here is: %s.",
		members, tier.name, tier.model,
	)
	if len(gaps) > 0 {
		desc += " Observed gaps: " + joinSentences(gaps)
	} else {
		desc += " The current structure broadly matches this model."
	}

	return []model.Finding{{
		CheckID:     c.Meta().ID,
		Title:       fmt.Sprintf("Organization is %s: %d members, %d teams", tier.name, members, len(s.Teams)),
		Severity:    model.SevInfo,
		Axis:        model.AxisTeams,
		Resource:    orgRef(s.Org),
		Evidence:    map[string]any{"members": members, "teams": len(s.Teams), "max_team_depth": maxDepth},
		Description: desc,
		Remediation: "Use this as orientation, not a hard rule: align the team model to the scale, then let the more specific team checks pinpoint individual issues.",
		DocsURL:     teamsDocsURL,
	}}
}

// tierGaps lists where the observed structure diverges from what the tier expects.
func tierGaps(tier teamSizeTier, teams, members, maxDepth int) []string {
	var gaps []string
	switch {
	case members < 10:
		if maxDepth > 1 {
			gaps = append(gaps, "team nesting exists but adds little at this size; flat teams are easier to reason about")
		}
	case members < 50:
		if teams == 0 {
			gaps = append(gaps, "no teams exist yet; access is likely granted person-by-person rather than by team")
		}
	case members < 200:
		if maxDepth < 2 && teams > 0 {
			gaps = append(gaps, "teams are flat; at this size grouping squads under an area team makes inherited access clearer")
		}
	default:
		if maxDepth < 2 {
			gaps = append(gaps, "the team hierarchy is flat for an org this large; mirroring the org chart usually needs structure")
		}
	}
	if tier.wantSSO {
		gaps = append(gaps, "at this scale, team membership should be provisioned from your identity provider (SSO/SCIM) rather than managed by hand")
	}
	return gaps
}

// joinSentences joins clauses into a single readable sentence ending with a period.
func joinSentences(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "; "
		}
		out += p
	}
	return out + "."
}
