package checks

import (
	"context"
	"strings"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(weakBranchProtection{}) }

// weakBranchProtection flags default branches that are protected but weakly: no
// required pull-request review, or force-pushes allowed. (Repos protected via a
// ruleset rather than classic branch protection are not assessed here — their
// detail is not exposed by the classic endpoint — and unprotected branches are
// covered by teams.unprotected-default-branch.)
type weakBranchProtection struct{}

func (weakBranchProtection) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.weak-branch-protection",
		Title:           "Weak branch protection",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevHigh,
		RequiresData:    []model.DataKind{model.DataBranchProtection},
		Description:     "Default branches protected without requiring review or while allowing force-pushes.",
	}
}

func (c weakBranchProtection) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range s.Repos {
		// Only classically-protected branches have assessable detail.
		if r.BranchReqPRReview == nil {
			continue
		}
		var weaknesses []string
		if !*r.BranchReqPRReview {
			weaknesses = append(weaknesses, "no required pull-request review")
		}
		if r.BranchAllowForcePush != nil && *r.BranchAllowForcePush {
			weaknesses = append(weaknesses, "force-pushes allowed")
		}
		if len(weaknesses) == 0 {
			continue
		}
		f := model.Finding{
			CheckID:     c.Meta().ID,
			Title:       "Weak protection on " + s.Org.Login + "/" + r.Name + " (" + strings.Join(weaknesses, ", ") + ")",
			Severity:    model.SevHigh,
			Axis:        model.AxisTeams,
			Resource:    repoRef(s.Org.Login, r),
			Evidence:    map[string]any{"repo": r.Name, "default_branch": r.DefaultBranch, "weaknesses": weaknesses},
			Description: "The default branch is protected, but the protection has gaps: changes can land without review, or history can be rewritten with a force-push. Either undermines the guarantee that what is on main was reviewed and is immutable.",
			Remediation: "Require at least one approving pull-request review and disable force-pushes on the default branch (also consider requiring status checks and signed commits).",
			DocsURL:     "https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches",
		}
		if branchProtectable(r.Private, s.Org.Plan) {
			f = withFix(f, ghProtectBranch(s.Org.Login, r.Name, r.DefaultBranch, reviewExpected(s)))
		}
		out = append(out, f)
	}
	return out
}
