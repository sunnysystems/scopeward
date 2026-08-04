package checks

import (
	"context"
	"fmt"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(actionsPolicyOpen{})
	check.Register(selfHostedRunners{})
}

// actionsPolicyOpen flags an org that allows any GitHub Action (including
// arbitrary third-party actions) to run, rather than restricting to vetted ones.
type actionsPolicyOpen struct{}

func (actionsPolicyOpen) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.actions-policy-open",
		Title:           "Unrestricted Actions policy",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevMedium,
		Kind:            check.KindCoverage,
		RequiresData:    []model.DataKind{model.DataActionsPolicy},
		Description:     "The org allows any action to run, including arbitrary third-party actions.",
	}
}

func (c actionsPolicyOpen) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	if s.ActionsPolicy.AllowedActions != "all" {
		return nil
	}
	return []model.Finding{withFix(model.Finding{
		CheckID:     c.Meta().ID,
		Title:       "Any GitHub Action is allowed to run",
		Severity:    model.SevMedium,
		Axis:        model.AxisNonHuman,
		Resource:    orgRef(s.Org),
		Evidence:    map[string]any{"allowed_actions": "all"},
		Description: "Workflows can use any third-party action, each of which runs with access to the job's GITHUB_TOKEN and secrets. A single compromised or malicious action becomes code execution inside your CI.",
		Remediation: "Restrict allowed actions to GitHub-authored and verified creators (or an explicit allowlist), and pin third-party actions to a full commit SHA.",
		DocsURL:     "https://docs.github.com/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization",
	}, ghRestrictActions(s.Org.Login, s.ActionsPolicy.EnabledRepositories))}
}

// selfHostedRunners flags the presence of org-level self-hosted runners, which
// are persistent machines that execute workflow code and are a known lateral-
// movement and persistence vector (especially if reachable by public repos).
type selfHostedRunners struct{}

func (selfHostedRunners) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.self-hosted-runner",
		Title:           "Self-hosted runners",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevMedium,
		Kind:            check.KindDebt,
		RequiresData:    []model.DataKind{model.DataSelfHostedRunners},
		Description:     "Org-level self-hosted Actions runners, which execute workflow code on your infrastructure.",
	}
}

func (c selfHostedRunners) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	if len(s.SelfHostedRunners) == 0 {
		return nil
	}
	names := make([]string, 0, len(s.SelfHostedRunners))
	for _, r := range s.SelfHostedRunners {
		names = append(names, r.Name)
	}
	return []model.Finding{{
		CheckID:     c.Meta().ID,
		Title:       fmt.Sprintf("%d self-hosted runner(s) registered at the org level", len(s.SelfHostedRunners)),
		Severity:    model.SevMedium,
		Axis:        model.AxisNonHuman,
		Resource:    orgRef(s.Org),
		Evidence:    map[string]any{"count": len(s.SelfHostedRunners), "runners": names},
		Description: "Self-hosted runners execute workflow code on machines you own and persist between jobs. If any public repository can target them, untrusted pull-request code can run on your infrastructure; even private-only use means a workflow compromise can pivot into your network.",
		Remediation: "Confirm each runner is necessary, scope runners to specific repos/groups, never use self-hosted runners with public repositories, and prefer ephemeral runners.",
		DocsURL:     "https://docs.github.com/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",
	}}
}
