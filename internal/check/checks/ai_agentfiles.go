package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(agentInstructionsUnowned{})
	check.Register(agentSettingsPermissive{})
}

// agentInstructionsUnowned flags agent-control files — instructions, agent
// settings, MCP configs — that CODEOWNERS leaves without an owner, or owns while
// the branch does not require that owner's review. Editing one changes what
// every agent does in the repository, for everyone who works in it.
//
// A repository with no CODEOWNERS file at all is left to
// teams.repo-no-codeowner rather than charged twice for one missing file.
type agentInstructionsUnowned struct{}

func (agentInstructionsUnowned) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "ai.agent-instructions-unowned",
		Title:           "Agent instructions and config with no code owner",
		Axis:            model.AxisAIAgents,
		DefaultSeverity: model.SevLow,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataAgentFiles, model.DataCodeowners},
		Description:     "Files that steer AI agents (AGENTS.md, CLAUDE.md, Copilot and Cursor rules, agent settings, MCP configs) that no CODEOWNERS rule owns.",
	}
}

func (c agentInstructionsUnowned) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	bench := newReviewBench(s)
	var out []model.Finding
	for _, r := range activeRepos(s) {
		if r.CodeownersPresent == nil || !*r.CodeownersPresent || len(r.AgentControlFiles) == 0 {
			continue
		}
		// An owner whose review the branch does not require is advisory: the team
		// reviews pull requests, but any reviewer can approve a change to what the
		// agents do. Where no review is required at all, that is
		// teams.weak-branch-protection's finding, not a second one here; and with
		// --solo, or nobody else who can push, nobody can approve their own pull
		// request, so it is not the fix.
		advisoryOnly := bench.of(r.Name).reviewExpected() &&
			r.BranchReqPRReview != nil && *r.BranchReqPRReview &&
			r.CodeOwnerApprovalRequired != nil && !*r.CodeOwnerApprovalRequired
		var unowned, advisory []string
		for _, f := range r.AgentControlFiles {
			switch {
			case len(codeownersFor(r.CodeownersRules, f.Path)) == 0:
				unowned = append(unowned, f.Path)
			case advisoryOnly:
				advisory = append(advisory, f.Path)
			}
		}
		if len(unowned) == 0 && len(advisory) == 0 {
			continue
		}

		var title, lead string
		switch {
		case len(unowned) > 0:
			title = fmt.Sprintf("%s in %s/%s %s no code owner", plural(len(unowned), "agent-control file"), s.Org.Login, r.Name, hasHave(len(unowned)))
			lead = "No CODEOWNERS rule covers " + strings.Join(unowned, ", ") + ", so any writer can change what agents do here with a review from anyone."
			if len(advisory) > 0 {
				lead += " The rest have an owner whose review the default branch does not require."
			}
		default:
			title = fmt.Sprintf("%s in %s/%s %s an owner whose review is not required", plural(len(advisory), "agent-control file"), s.Org.Login, r.Name, hasHave(len(advisory)))
			lead = "CODEOWNERS names an owner for " + strings.Join(advisory, ", ") + ", but the default branch does not require code-owner review, so the rule is advisory."
		}
		evidence := map[string]any{"repo": r.Name}
		if len(unowned) > 0 {
			evidence["unowned"] = unowned
		}
		if len(advisory) > 0 {
			evidence["owner_review_not_required"] = advisory
		}
		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    title,
			Severity: model.SevLow,
			Axis:     model.AxisAIAgents,
			Resource: repoRef(s.Org.Login, r),
			Evidence: evidence,
			Description: lead + " These files tell AI agents what to do or what they may do, for everyone who works in the repository: " +
				"editing one is changing a policy, not a README.",
			Remediation: "Give the agent files an owner in CODEOWNERS (for example `/AGENTS.md`, `/.claude/` and `/.github/copilot-instructions.md` to the team that owns how agents work here) and require code-owner review on the default branch.",
			DocsURL:     "https://docs.github.com/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners",
		})
	}
	return out
}

func hasHave(n int) string {
	if n == 1 {
		return "has"
	}
	return "have"
}

// agentSettingsPermissive flags committed agent settings that pre-approve
// every shell command for everyone who works in the repository, or ask for the
// permission prompts to be switched off altogether.
type agentSettingsPermissive struct{}

func (agentSettingsPermissive) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "ai.agent-settings-permissive",
		Title:           "Committed agent settings that pre-approve any shell command",
		Axis:            model.AxisAIAgents,
		DefaultSeverity: model.SevMedium,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataAgentFiles},
		Description:     "Committed Claude Code settings with blanket shell allow rules (Bash, Bash(*)) or defaultMode: bypassPermissions.",
	}
}

func (c agentSettingsPermissive) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range activeRepos(s) {
		var broad, bypass []string
		for _, st := range r.AgentSettings {
			for _, rule := range st.BroadAllow {
				broad = append(broad, st.File+": "+rule)
			}
			if st.DefaultMode == "bypassPermissions" {
				bypass = append(bypass, st.File)
			}
		}
		if len(broad) == 0 && len(bypass) == 0 {
			continue
		}
		sort.Strings(broad)

		sev := model.SevLow
		title := fmt.Sprintf("Committed agent settings in %s/%s ask to skip every permission prompt", s.Org.Login, r.Name)
		var desc []string
		evidence := map[string]any{"repo": r.Name}
		if len(broad) > 0 {
			sev = model.SevMedium
			title = fmt.Sprintf("Committed agent settings in %s/%s pre-approve any shell command", s.Org.Login, r.Name)
			evidence["broad_allow"] = broad
			desc = append(desc, "These allow rules ("+strings.Join(broad, "; ")+") let Claude Code run any shell command without asking, for every developer who trusts this folder: "+
				"including whatever a prompt-injected instruction in an issue, a dependency's README or a web page asks for.")
		}
		if len(bypass) > 0 {
			evidence["bypass_permissions"] = bypass
			desc = append(desc, "defaultMode: bypassPermissions in "+strings.Join(bypass, ", ")+" asks for no prompts at all. "+
				"Current Claude Code ignores that mode from a project file (since v2.1.257); older clients honour it.")
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       title,
			Severity:    sev,
			Axis:        model.AxisAIAgents,
			Resource:    repoRef(s.Org.Login, r),
			Evidence:    evidence,
			Description: strings.Join(desc, " "),
			Remediation: "Replace blanket shell rules with the specific commands the team runs (for example Bash(npm run test:*)), keep personal approvals in an uncommitted .claude/settings.local.json, and drop defaultMode: bypassPermissions from project settings.",
			DocsURL:     "https://code.claude.com/docs/en/permissions",
		})
	}
	return out
}
