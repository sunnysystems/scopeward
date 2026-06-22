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
	gitlab := s.Provider == model.ProviderGitLab
	var out []model.Finding
	for _, r := range s.Repos {
		// Each weakness is assessed independently on whatever detail was collected:
		// on GitLab Free, force-push is knowable from protected branches while
		// required-review (approval rules) is not, so they must not gate each other.
		var weaknesses []string
		// Requiring review only makes sense when a second person can approve; --solo
		// or a <2-member group suppresses it (you cannot approve your own change).
		if r.BranchReqPRReview != nil && !*r.BranchReqPRReview && reviewExpected(s) {
			weaknesses = append(weaknesses, "no required pull-request review")
		}
		if r.BranchAllowForcePush != nil && *r.BranchAllowForcePush {
			weaknesses = append(weaknesses, "force-pushes allowed")
		}
		if len(weaknesses) == 0 {
			continue
		}
		docs := "https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches"
		remediation := "Require at least one approving pull-request review and disable force-pushes on the default branch (also consider requiring status checks and signed commits)."
		if gitlab {
			docs = glBranchDocs
			remediation = "Require merge-request approvals (Premium) and disable force-push on the protected branch; protection takes effect when the relevant branches are themselves protected."
		}
		f := model.Finding{
			CheckID:     c.Meta().ID,
			Title:       "Weak protection on " + repoDisplay(s, r) + " (" + strings.Join(weaknesses, ", ") + ")",
			Severity:    model.SevHigh,
			Axis:        model.AxisTeams,
			Resource:    repoResource(s, r),
			Evidence:    map[string]any{"repo": r.Name, "default_branch": r.DefaultBranch, "weaknesses": weaknesses},
			Description: "The default branch is protected, but the protection has gaps: changes can land without review, or history can be rewritten with a force-push. Either undermines the guarantee that what is on main was reviewed and is immutable.",
			Remediation: remediation,
			DocsURL:     docs,
		}
		if !gitlab && branchProtectable(r.Private, s.Org.Plan) {
			f = withFix(f, ghProtectBranch(s.Org.Login, r.Name, r.DefaultBranch, reviewExpected(s)))
		}
		out = append(out, f)
	}
	return out
}
