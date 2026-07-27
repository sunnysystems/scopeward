package checks

import (
	"context"
	"strings"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(mrApprovalBypassable{}) }

// mrApprovalBypassable flags GitLab merge-request approval settings that let an
// author clear the review requirement themselves: when the author may approve
// their own merge request, or approvals are not reset when new commits are
// pushed (so a reviewed MR can be changed after approval). Both turn required
// review into a formality.
//
// The setting is a GitLab Premium feature, so the check is gated on
// DataMRApprovalSettings and reports "not evaluated" on Free where it cannot be
// assessed.
type mrApprovalBypassable struct{}

func (mrApprovalBypassable) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.mr-approval-bypassable",
		Title:           "Bypassable MR approvals",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevMedium,
		RequiresData:    []model.DataKind{model.DataMRApprovalSettings},
		Description:     "Projects where the merge-request author can approve their own MR, or approvals are not reset on a new push.",
	}
}

func (c mrApprovalBypassable) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	// Approval bypass only matters when review is actually expected; a solo or
	// <2-member group cannot get a second approver anyway.
	if !reviewExpected(s) {
		return nil
	}
	var out []model.Finding
	for _, r := range activeRepos(s) {
		var weaknesses []string
		if r.MRAuthorCanApprove != nil && *r.MRAuthorCanApprove {
			weaknesses = append(weaknesses, "author can approve their own MR")
		}
		if r.MRResetApprovalsOnPush != nil && !*r.MRResetApprovalsOnPush {
			weaknesses = append(weaknesses, "approvals not reset on new push")
		}
		if len(weaknesses) == 0 {
			continue
		}
		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    "Merge-request approvals are bypassable on " + repoDisplay(s, r) + " (" + strings.Join(weaknesses, ", ") + ")",
			Severity: model.SevMedium,
			Axis:     model.AxisTeams,
			Resource: repoResource(s, r),
			Evidence: map[string]any{
				"repo":                    r.Name,
				"author_can_approve":      r.MRAuthorCanApprove != nil && *r.MRAuthorCanApprove,
				"reset_approvals_on_push": r.MRResetApprovalsOnPush != nil && *r.MRResetApprovalsOnPush,
				"weaknesses":              weaknesses,
			},
			Description: "Required approvals are meant to guarantee a second person reviewed a change. When the author can approve their own merge request, or approvals survive new commits pushed after review, that guarantee is hollow: a single person (or an automated/AI actor acting as the author) can satisfy the rule without independent review.",
			Remediation: "Disable \"Prevent approval by author\" being off (i.e. prevent authors approving their own MRs), and enable \"Remove all approvals when commits are added\" so approvals must be re-earned after changes.",
			DocsURL:     "https://docs.gitlab.com/ee/user/project/merge_requests/approvals/settings.html",
		})
	}
	return out
}
