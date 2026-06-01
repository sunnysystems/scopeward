package checks

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(unprotectedDefaultBranch{}) }

// unprotectedDefaultBranch flags repositories whose default branch has no
// protection — neither classic branch protection nor a ruleset — meaning code
// can be pushed (or force-pushed) straight to it with no review.
type unprotectedDefaultBranch struct{}

func (unprotectedDefaultBranch) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.unprotected-default-branch",
		Title:           "Unprotected default branches",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevHigh,
		RequiresData:    []model.DataKind{model.DataBranchProtection},
		Description:     "Repositories whose default branch is not covered by branch protection or a ruleset.",
	}
}

func (c unprotectedDefaultBranch) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range s.Repos {
		if r.DefaultBranchProtected == nil || *r.DefaultBranchProtected {
			continue // unknown or protected
		}
		f := model.Finding{
			CheckID:  c.Meta().ID,
			Title:    "Default branch \"" + r.DefaultBranch + "\" of " + s.Org.Login + "/" + r.Name + " is not protected",
			Severity: model.SevHigh,
			Axis:     model.AxisTeams,
			Resource: repoRef(s.Org.Login, r),
			Evidence: map[string]any{
				"repo":           r.Name,
				"default_branch": r.DefaultBranch,
				"private":        r.Private,
				"org_plan":       s.Org.Plan,
			},
			Description: "Anyone with write access can push — or force-push — directly to this branch with no pull request, review, or status check. That removes the main guardrail against mistakes and malicious or AI-agent commits reaching production code.",
			Remediation: branchRemediation(r.Private, s.Org.Plan),
			DocsURL:     "https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets",
		}
		// Only suggest a command where protecting the branch is actually possible:
		// it is free for public repos but needs GitHub Team+ for private repos.
		if branchProtectable(r.Private, s.Org.Plan) {
			f = withFix(f, ghProtectBranch(s.Org.Login, r.Name, r.DefaultBranch, reviewExpected(s)))
		}
		out = append(out, f)
	}
	return out
}

// branchProtectable reports whether branch protection can be applied at all:
// always for public repos, and for private repos only off the Free plan.
func branchProtectable(private bool, plan string) bool {
	return !private || plan != "free"
}

// branchRemediation tailors the advice to whether protecting this branch is even
// possible on the org's plan: branch protection / rulesets are free for public
// repos but require GitHub Team+ for private repos.
func branchRemediation(private bool, plan string) string {
	const protect = "Protect the default branch with a ruleset (or branch protection): require a pull request and review, block force-pushes and deletion, and require status checks."
	if !private {
		return protect
	}
	switch plan {
	case "free":
		return "This is a private repository on the Free plan, where branch protection is unavailable. Upgrade the organization to GitHub Team (or Enterprise), or make the repository public, then protect the default branch."
	case "":
		return protect + " Note: for a private repository this requires GitHub Team or Enterprise (it is unavailable on the Free plan)."
	default:
		return protect
	}
}
