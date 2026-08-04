package checks

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(actionsTokenWriteDefault{})
	check.Register(tokenCanApprovePRs{})
}

// tokenCanApprovePRs flags the org setting that lets GitHub Actions create and
// approve pull requests — which can be used to bypass required review.
type tokenCanApprovePRs struct{}

func (tokenCanApprovePRs) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.actions-can-approve-prs",
		Title:           "Actions can approve pull requests",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevMedium,
		Kind:            check.KindCoverage,
		RequiresData:    []model.DataKind{model.DataActionsTokenDefault},
		Description:     "Whether GitHub Actions workflows are allowed to approve pull requests.",
	}
}

func (c tokenCanApprovePRs) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	if !s.ActionsToken.CanApprovePullRequestReviews {
		return nil
	}
	return []model.Finding{withFix(model.Finding{
		CheckID:     c.Meta().ID,
		Title:       "GitHub Actions is allowed to approve pull requests",
		Severity:    model.SevMedium,
		Axis:        model.AxisNonHuman,
		Resource:    orgRef(s.Org),
		Evidence:    map[string]any{"can_approve_pull_request_reviews": true},
		Description: "A workflow can submit an approving review, which can satisfy a required-review rule without any human looking at the change. That turns code review from a control into a formality an automated (or AI) actor can self-clear.",
		Remediation: "Disable \"Allow GitHub Actions to create and approve pull requests\" in the org's Actions settings.",
		DocsURL:     "https://docs.github.com/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization#preventing-github-actions-from-creating-or-approving-pull-requests",
	}, ghHardenWorkflowToken(s.Org.Login))}
}

// actionsTokenWriteDefault flags the org default that grants the automatic
// GITHUB_TOKEN write permissions in every workflow run — broad standing write
// access handed to CI by default.
type actionsTokenWriteDefault struct{}

func (actionsTokenWriteDefault) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.actions-token-write-default",
		Title:           "GITHUB_TOKEN defaults to write",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevHigh,
		Kind:            check.KindCoverage,
		RequiresData:    []model.DataKind{model.DataActionsTokenDefault},
		Description:     "The default GITHUB_TOKEN permission granted to Actions workflows across the org.",
	}
}

func (c actionsTokenWriteDefault) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	if s.ActionsToken.DefaultWorkflowPermissions != "write" {
		return nil
	}
	return []model.Finding{withFix(model.Finding{
		CheckID:     c.Meta().ID,
		Title:       "Actions GITHUB_TOKEN defaults to read/write",
		Severity:    model.SevHigh,
		Axis:        model.AxisNonHuman,
		Resource:    orgRef(s.Org),
		Evidence:    map[string]any{"default_workflow_permissions": "write", "can_approve_pull_request_reviews": s.ActionsToken.CanApprovePullRequestReviews},
		Description: "Every workflow run receives a token with write access to the repository by default. A malicious or compromised dependency in any workflow can then push code, alter releases, or tamper with the repo using that standing token.",
		Remediation: "Set the default workflow permissions to read-only org-wide, and have workflows request the specific write scopes they need via the job's permissions block.",
		DocsURL:     "https://docs.github.com/actions/security-for-github-actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token",
	}, ghHardenWorkflowToken(s.Org.Login))}
}
