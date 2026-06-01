package checks

import (
	"context"
	"fmt"
	"sort"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(unpinnedActions{})
	check.Register(pullRequestTarget{})
}

// unpinnedActions flags repos whose workflows reference third-party actions by a
// mutable tag/branch instead of a full commit SHA — the tag can be moved to
// point at malicious code, so the action is not actually trusted.
type unpinnedActions struct{}

func (unpinnedActions) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "supplychain.unpinned-action",
		Title:           "Unpinned third-party actions",
		Axis:            model.AxisSupplyChain,
		DefaultSeverity: model.SevMedium,
		RequiresData:    []model.DataKind{model.DataWorkflows},
		Description:     "Workflows using third-party actions pinned to a tag/branch rather than a commit SHA.",
	}
}

func (c unpinnedActions) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range s.Repos {
		refs := map[string]bool{}
		for _, w := range r.WorkflowIssues {
			if w.Kind == "unpinned-action" {
				refs[w.Detail] = true
			}
		}
		if len(refs) == 0 {
			continue
		}
		list := make([]string, 0, len(refs))
		for ref := range refs {
			list = append(list, ref)
		}
		sort.Strings(list)
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       fmt.Sprintf("%s/%s uses %d third-party action(s) not pinned to a SHA", s.Org.Login, r.Name, len(list)),
			Severity:    model.SevMedium,
			Axis:        model.AxisSupplyChain,
			Resource:    repoRef(s.Org.Login, r),
			Evidence:    map[string]any{"repo": r.Name, "actions": list},
			Description: "These actions are referenced by a tag or branch, which the author can move to point at new code at any time. A compromised or hijacked action then runs inside your CI with access to the job's token and secrets.",
			Remediation: "Pin third-party actions to a full commit SHA (e.g. uses: owner/action@<40-char-sha>) and update them deliberately, ideally via Dependabot.",
			DocsURL:     "https://docs.github.com/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
		})
	}
	return out
}

// pullRequestTarget flags workflows triggered by pull_request_target, which runs
// with the base repo's secrets in the context of (untrusted) fork PRs — a common
// source of CI compromise.
type pullRequestTarget struct{}

func (pullRequestTarget) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "supplychain.pull-request-target",
		Title:           "Risky pull_request_target workflows",
		Axis:            model.AxisSupplyChain,
		DefaultSeverity: model.SevHigh,
		RequiresData:    []model.DataKind{model.DataWorkflows},
		Description:     "Workflows using the pull_request_target trigger, which exposes secrets to fork PRs.",
	}
}

func (c pullRequestTarget) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range s.Repos {
		var files []string
		for _, w := range r.WorkflowIssues {
			if w.Kind == "pull-request-target" {
				files = append(files, w.File)
			}
		}
		if len(files) == 0 {
			continue
		}
		sort.Strings(files)
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       s.Org.Login + "/" + r.Name + " has workflows using pull_request_target",
			Severity:    model.SevHigh,
			Axis:        model.AxisSupplyChain,
			Resource:    repoRef(s.Org.Login, r),
			Evidence:    map[string]any{"repo": r.Name, "files": files},
			Description: "pull_request_target runs with the base repository's secrets and write token even for pull requests from forks. If such a workflow checks out and runs the PR's code, an outside contributor can exfiltrate secrets or push to the repo.",
			Remediation: "Avoid pull_request_target where possible; if required, never check out or execute the PR head, and gate on explicit maintainer approval. Prefer the pull_request trigger.",
			DocsURL:     "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
		})
	}
	return out
}
