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
	check.Register(agentInventory{})
	check.Register(unidentifiedCommitter{})
	check.Register(agentBroadWrite{})
}

// knownPlatformBots are widely-used machine identities whose presence is
// expected and self-explanatory, so they are not flagged as unidentified.
var knownPlatformBots = map[string]bool{
	"github-actions": true,
	"dependabot":     true,
	"renovate":       true,
	"codecov":        true,
	"snyk-bot":       true,
	"mergify":        true,
	"imgbot":         true,
	"pre-commit-ci":  true,
	"sonarcloud":     true,
}

// agent is a machine/bot identity that has committed code, enriched with what we
// can infer about the credential behind it and how broad its write access is.
type agent struct {
	Login         string
	Commits       int
	Repos         int
	AppSlug       string
	AppBacked     bool
	KnownPlatform bool
	Breadth       string // "admin" | "all-write" | "selected-write" | "github_token-write" | ""
}

// buildAgents aggregates bot committers across repos and correlates each with an
// installed App (by slug) or the default GITHUB_TOKEN to infer write breadth.
func buildAgents(s *model.Snapshot) []agent {
	agg := map[string]*agent{}
	for _, r := range activeRepos(s) {
		for _, bc := range r.BotCommitters {
			a := agg[bc.Login]
			if a == nil {
				a = &agent{Login: bc.Login}
				agg[bc.Login] = a
			}
			a.Commits += bc.Commits
			a.Repos++
		}
	}

	appBySlug := map[string]model.AppInstallation{}
	for _, app := range s.AppInstallations {
		appBySlug[app.AppSlug] = app
	}

	for _, a := range agg {
		slug := strings.TrimSuffix(a.Login, "[bot]")
		a.KnownPlatform = knownPlatformBots[slug]
		if app, ok := appBySlug[slug]; ok {
			a.AppBacked = true
			a.AppSlug = slug
			a.Breadth = appBreadth(app)
		}
		if slug == "github-actions" && s.ActionsToken.DefaultWorkflowPermissions == "write" {
			a.Breadth = "github_token-write"
		}
	}

	out := make([]agent, 0, len(agg))
	for _, a := range agg {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Login < out[j].Login })
	return out
}

// assistedAgent is a coding agent that acted through human accounts: commits
// those people authored carry its mark.
type assistedAgent struct {
	Agent        string
	Commits      int
	Repos        int
	Authors      []string // GitHub logins, sorted
	Unattributed int      // commits that name no person (see model.AgentAssist)
	// UnprotectedRepos are the repos, sorted, where this agent's code reached a
	// default branch with no protection.
	UnprotectedRepos []string
}

// buildAssisted aggregates agent-assisted commits across repos, per agent.
func buildAssisted(s *model.Snapshot) []assistedAgent {
	agg := map[string]*assistedAgent{}
	authors := map[string]map[string]bool{}
	for _, r := range activeRepos(s) {
		inRepo := map[string]bool{}
		unprotected := r.DefaultBranchProtected != nil && !*r.DefaultBranchProtected
		for _, aa := range r.AgentAssistedCommits {
			a := agg[aa.Agent]
			if a == nil {
				a = &assistedAgent{Agent: aa.Agent}
				agg[aa.Agent] = a
				authors[aa.Agent] = map[string]bool{}
			}
			a.Commits += aa.Commits
			if !inRepo[aa.Agent] {
				inRepo[aa.Agent] = true
				a.Repos++
				if unprotected {
					a.UnprotectedRepos = append(a.UnprotectedRepos, r.Name)
				}
			}
			if aa.Author == "" {
				a.Unattributed += aa.Commits
			} else {
				authors[aa.Agent][aa.Author] = true
			}
		}
	}

	out := make([]assistedAgent, 0, len(agg))
	for name, a := range agg {
		for login := range authors[name] {
			a.Authors = append(a.Authors, login)
		}
		sort.Strings(a.Authors)
		sort.Strings(a.UnprotectedRepos)
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Agent < out[j].Agent })
	return out
}

// assistedAgentNames lists the agents whose mark is on a repo's recent commits.
func assistedAgentNames(r model.Repo) []string {
	seen := map[string]bool{}
	var names []string
	for _, aa := range r.AgentAssistedCommits {
		if !seen[aa.Agent] {
			seen[aa.Agent] = true
			names = append(names, aa.Agent)
		}
	}
	sort.Strings(names)
	return names
}

func appBreadth(app model.AppInstallation) string {
	_, hasAdmin, hasWrite := elevatedPermissions(app.Permissions)
	switch {
	case hasAdmin:
		return "admin"
	case hasWrite && app.RepositorySelection == "all":
		return "all-write"
	case hasWrite:
		return "selected-write"
	default:
		return ""
	}
}

// agentInventory emits a single informational finding enumerating the AI/machine
// identities that committed code — the brand's "agent governance" view. Info
// severity, so it carries no score penalty.
type agentInventory struct{}

func (agentInventory) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "ai.agent-inventory",
		Title:           "AI / machine commit identities",
		Axis:            model.AxisAIAgents,
		DefaultSeverity: model.SevInfo,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataCommitAuthors},
		Description:     "Inventory of bot/agent identities that have recently committed code, and of coding agents whose mark is on commits people authored.",
	}
}

func (c agentInventory) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	agents := buildAgents(s)
	assisted := buildAssisted(s)
	if len(agents) == 0 && len(assisted) == 0 {
		return nil
	}

	evidence := map[string]any{}
	var title string
	description := ""
	if len(agents) > 0 {
		summary := make([]map[string]any, 0, len(agents))
		for _, a := range agents {
			summary = append(summary, map[string]any{
				"login": a.Login, "commits": a.Commits, "repos": a.Repos,
				"app_backed": a.AppBacked, "known_platform": a.KnownPlatform, "write_breadth": a.Breadth,
			})
		}
		evidence["agents"] = summary
		description = "These non-human identities push code to your repositories. Treat each as an actor whose credential, scope, and necessity should be governed like a human's, especially as AI coding agents proliferate."
	}
	if len(assisted) > 0 {
		summary := make([]map[string]any, 0, len(assisted))
		for _, a := range assisted {
			summary = append(summary, map[string]any{
				"agent": a.Agent, "commits": a.Commits, "repos": a.Repos,
				"authors": a.Authors, "unattributed_commits": a.Unattributed,
				"unprotected_repos": a.UnprotectedRepos,
			})
		}
		evidence["assisted"] = summary
		if description != "" {
			description += " Coding agents also"
		} else {
			description = "Coding agents"
		}
		description += " wrote code that people committed under their own accounts, so it reached your repositories with those people's credentials. " +
			"Each is identified by the mark it leaves on a commit (a co-author trailer, an author-name suffix); a developer can remove it and some agents leave none, so these counts are a floor, not a census. " +
			"The account named is the commit's author, which is not necessarily the credential that pushed it."
		if n := len(unprotectedAssistedRepos(assisted)); n > 0 {
			where := "1 repository"
			if n != 1 {
				where = fmt.Sprintf("%d repositories", n)
			}
			description += " In " + where + " the default branch has no protection, so that code reached it with no review in the path (see teams.unprotected-default-branch)."
		}
	}

	remediation := "Review the list: confirm each agent is expected, tie it to an owner, and ensure its write scope matches its job."
	if len(assisted) > 0 {
		remediation += " A coding agent acting through a person's account holds that person's access, so its gate is review on the default branch, not a narrower credential."
	}

	switch {
	case len(assisted) == 0:
		title = fmt.Sprintf("%d machine identities committed code in the last 90 days", len(agents))
	case len(agents) == 0:
		title = fmt.Sprintf("%s co-wrote %s in the last 90 days", plural(len(assisted), "coding agent"), plural(assistedCommits(assisted), "commit"))
	default:
		title = fmt.Sprintf("%d machine identities and %s committed code in the last 90 days", len(agents), plural(len(assisted), "coding agent"))
	}

	return []model.Finding{{
		CheckID:     c.Meta().ID,
		Title:       title,
		Severity:    model.SevInfo,
		Axis:        model.AxisAIAgents,
		Resource:    orgRef(s.Org),
		Evidence:    evidence,
		Description: description,
		Remediation: remediation,
		DocsURL:     "https://docs.github.com/apps/overview",
	}}
}

// unprotectedAssistedRepos is the union of the repos where any agent's code
// reached an unprotected default branch.
func unprotectedAssistedRepos(as []assistedAgent) map[string]bool {
	repos := map[string]bool{}
	for _, a := range as {
		for _, r := range a.UnprotectedRepos {
			repos[r] = true
		}
	}
	return repos
}

func assistedCommits(as []assistedAgent) int {
	n := 0
	for _, a := range as {
		n += a.Commits
	}
	return n
}

// unidentifiedCommitter flags bot identities committing code that map to neither
// an installed GitHub App nor a known platform bot — a machine actor pushing
// code through a credential we cannot account for.
type unidentifiedCommitter struct{}

func (unidentifiedCommitter) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "ai.unidentified-committer",
		Title:           "Unidentified bot committers",
		Axis:            model.AxisAIAgents,
		DefaultSeverity: model.SevMedium,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataCommitAuthors, model.DataAppInstallations},
		Description:     "Bot identities committing code that match no installed App and no known platform bot.",
	}
}

func (c unidentifiedCommitter) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, a := range buildAgents(s) {
		if a.AppBacked || a.KnownPlatform {
			continue
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       "Unidentified bot \"" + a.Login + "\" is committing code",
			Severity:    model.SevMedium,
			Axis:        model.AxisAIAgents,
			Resource:    model.ResourceRef{Type: "agent", Name: a.Login, URL: "https://github.com/" + strings.TrimSuffix(a.Login, "[bot]")},
			Evidence:    map[string]any{"login": a.Login, "commits": a.Commits, "repos": a.Repos},
			Description: "This machine identity pushes commits but does not correspond to a GitHub App installed on the org or a recognized platform bot. It may be an unmanaged automation, a personal token acting as a bot, or an AI agent set up outside governance.",
			Remediation: "Identify what credential this bot uses (App, deploy key, or PAT), assign an owner, and bring it under the org's app/token policy, or remove its access.",
			DocsURL:     "https://docs.github.com/organizations/managing-programmatic-access-to-your-organization",
		})
	}
	return out
}

// agentBroadWrite flags committing agents whose inferred write access is broad:
// admin or write-across-all-repos (High), or reliance on a write-by-default
// GITHUB_TOKEN (Medium).
type agentBroadWrite struct{}

func (agentBroadWrite) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "ai.agent-broad-write",
		Title:           "Agents committing with broad write",
		Axis:            model.AxisAIAgents,
		DefaultSeverity: model.SevHigh,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataCommitAuthors, model.DataAppInstallations, model.DataActionsTokenDefault},
		Description:     "Machine identities that commit code while holding broad write access to the org.",
	}
}

func (c agentBroadWrite) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, a := range buildAgents(s) {
		var sev model.Severity
		var rationale string
		switch a.Breadth {
		case "admin", "all-write":
			sev, rationale = model.SevHigh, "write/admin across all repositories"
		case "github_token-write":
			sev, rationale = model.SevMedium, "standing write via the default GITHUB_TOKEN"
		default:
			continue // selected-write or unknown breadth is not flagged here
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       "Agent \"" + a.Login + "\" commits with " + rationale,
			Severity:    sev,
			Axis:        model.AxisAIAgents,
			Resource:    model.ResourceRef{Type: "agent", Name: a.Login, URL: "https://github.com/" + strings.TrimSuffix(a.Login, "[bot]")},
			Evidence:    map[string]any{"login": a.Login, "commits": a.Commits, "repos": a.Repos, "write_breadth": a.Breadth, "app_slug": a.AppSlug},
			Description: "This agent both pushes code and holds broad write access. The blast radius of a compromised or misbehaving agent (including AI coding agents) is the full reach of its credential, not just the repos it touched.",
			Remediation: "Scope the agent down: restrict the App to selected repositories at least privilege, or set the default GITHUB_TOKEN to read-only and grant write per-workflow.",
			DocsURL:     "https://docs.github.com/apps/using-github-apps/reviewing-and-modifying-installed-github-apps",
		})
	}
	return out
}
