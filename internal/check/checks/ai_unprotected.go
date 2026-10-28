package checks

import (
	"context"
	"strings"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(agentOnUnprotectedBranch{}) }

// agentOnUnprotectedBranch flags repositories where machine/bot identities push
// code and the default branch has no protection — an automated actor writing
// straight to an unguarded main, with no review in the path.
//
// Commits people made with a coding agent's mark do not trigger it on their own.
// The mark is voluntary, so charging for it would score a team that strips its
// trailers above one that keeps them; that population is reported, without a
// penalty, by ai.agent-inventory. When both are present the finding says so.
type agentOnUnprotectedBranch struct{}

func (agentOnUnprotectedBranch) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "ai.agent-on-unprotected-branch",
		Title:           "Agents pushing to unprotected branches",
		Axis:            model.AxisAIAgents,
		DefaultSeverity: model.SevMedium,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataCommitAuthors, model.DataBranchProtection},
		Description:     "Repos where bot/agent identities commit and the default branch is unprotected.",
	}
}

func (c agentOnUnprotectedBranch) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range activeRepos(s) {
		if r.DefaultBranchProtected == nil || *r.DefaultBranchProtected || len(r.BotCommitters) == 0 {
			continue
		}
		bots := make([]string, 0, len(r.BotCommitters))
		for _, bc := range r.BotCommitters {
			bots = append(bots, bc.Login)
		}
		assisted := assistedAgentNames(r)

		evidence := map[string]any{"repo": r.Name, "default_branch": r.DefaultBranch, "agents": bots}
		var title, lead string
		if len(assisted) == 0 {
			title = "Machine identities push to the unprotected default branch of " + s.Org.Login + "/" + r.Name
			lead = "Bot/agent identities (" + strings.Join(bots, ", ") + ") commit to this repository, whose default branch has no protection."
		} else {
			evidence["assisted_agents"] = assisted
			title = "Machine identities and coding agents push to the unprotected default branch of " + s.Org.Login + "/" + r.Name
			lead = "Bot/agent identities (" + strings.Join(bots, ", ") + ") commit to this repository, whose default branch has no protection, and other recent commits carry the mark of " + strings.Join(assisted, ", ") + "."
		}

		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       title,
			Severity:    model.SevMedium,
			Axis:        model.AxisAIAgents,
			Resource:    repoRef(s.Org.Login, r),
			Evidence:    evidence,
			Description: lead + " An automated or AI agent can therefore write directly to main with no pull request or review; the highest-leverage path for a misbehaving agent to ship code.",
			Remediation: "Protect the default branch (require a pull request and review) so even automated changes go through a gate, and scope each agent's write access to what it needs.",
			DocsURL:     "https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets",
		})
	}
	return out
}
