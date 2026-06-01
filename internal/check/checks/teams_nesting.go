package checks

import (
	"context"
	"fmt"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(deepNesting{})
	check.Register(teamSprawl{})
}

// maxTeamDepth is the deepest nesting (top-level = 1) considered healthy. Beyond
// this, inherited permissions become hard to reason about.
const maxTeamDepth = 2

// deepNesting flags teams nested more deeply than maxTeamDepth, where permission
// inheritance gets hard to follow.
type deepNesting struct{}

func (deepNesting) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.deep-nesting",
		Title:           "Deeply nested teams",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevLow,
		RequiresData:    []model.DataKind{model.DataTeams},
		Description:     "Teams nested several levels deep make inherited repository access hard to audit.",
	}
}

func (c deepNesting) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	parent := make(map[string]string, len(s.Teams))
	for _, t := range s.Teams {
		parent[t.Slug] = t.ParentSlug
	}

	var out []model.Finding
	for _, t := range s.Teams {
		depth := teamDepth(t.Slug, parent)
		if depth <= maxTeamDepth {
			continue
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       fmt.Sprintf("Team %q is nested %d levels deep", t.Name, depth),
			Severity:    model.SevLow,
			Axis:        model.AxisTeams,
			Resource:    teamRef(s.Org.Login, t),
			Evidence:    map[string]any{"slug": t.Slug, "depth": depth},
			Description: "Deep team nesting means a member's effective repository access is the union of several inherited grants, which is easy to misjudge during reviews and offboarding.",
			Remediation: "Flatten the team hierarchy so access is granted at a level that is easy to reason about.",
			DocsURL:     "https://docs.github.com/organizations/organizing-members-into-teams/about-teams",
		})
	}
	return out
}

// teamDepth walks the parent chain to compute nesting depth (top-level = 1),
// guarding against cycles with an iteration cap.
func teamDepth(slug string, parent map[string]string) int {
	depth := 1
	cur := slug
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

// teamSprawl flags organizations with more teams than members — a sign of teams
// outliving the structure they were meant to model.
type teamSprawl struct{}

func (teamSprawl) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.sprawl",
		Title:           "Team sprawl",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevLow,
		RequiresData:    []model.DataKind{model.DataTeams, model.DataMembers},
		Description:     "More teams than members suggests accumulated, possibly stale, team structure.",
	}
}

func (c teamSprawl) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	teams, members := len(s.Teams), len(s.Members)
	if members == 0 || teams <= members {
		return nil
	}
	return []model.Finding{{
		CheckID:     c.Meta().ID,
		Title:       fmt.Sprintf("Organization has %d teams for %d members", teams, members),
		Severity:    model.SevLow,
		Axis:        model.AxisTeams,
		Resource:    orgRef(s.Org),
		Evidence:    map[string]any{"team_count": teams, "member_count": members},
		Description: "Having more teams than members usually means teams have accumulated over time without cleanup, making the permission model harder to audit and stale grants easier to miss.",
		Remediation: "Review teams for ones that are empty, redundant, or no longer mapped to a real function, and remove them.",
		DocsURL:     "https://docs.github.com/organizations/organizing-members-into-teams/about-teams",
	}}
}
