package checks

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(rulesetNotEnforced{}) }

// rulesetNotEnforced flags org rulesets that exist but are not actively
// enforcing — in "evaluate" (dry-run) or "disabled" mode — so the protection
// they describe is configured but not actually applied.
type rulesetNotEnforced struct{}

func (rulesetNotEnforced) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.ruleset-not-enforced",
		Title:           "Org rulesets not enforced",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevMedium,
		RequiresData:    []model.DataKind{model.DataOrgRulesets},
		Description:     "Organization rulesets in evaluate/disabled mode rather than actively enforcing.",
	}
}

func (c rulesetNotEnforced) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, rs := range s.OrgRulesets {
		if rs.Enforcement == "active" {
			continue
		}
		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    "Ruleset \"" + rs.Name + "\" is not enforced (" + rs.Enforcement + ")",
			Severity: model.SevMedium,
			Axis:     model.AxisTeams,
			Resource: model.ResourceRef{
				Type: "ruleset",
				Name: rs.Name,
				URL:  "https://github.com/organizations/" + s.Org.Login + "/settings/rules",
			},
			Evidence:    map[string]any{"ruleset": rs.Name, "target": rs.Target, "enforcement": rs.Enforcement},
			Description: "This ruleset is configured but not actively enforcing (it is in evaluate/disabled mode), so the branch, tag, or push protections it defines do not actually block anything yet.",
			Remediation: "If the ruleset is ready, set its enforcement to Active. If it was a dry run, finish validating it and enable it.",
			DocsURL:     "https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets",
		})
	}
	return out
}
