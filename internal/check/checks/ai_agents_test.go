package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

// aiSnapshot builds a snapshot with three committing bots: a known platform bot
// on a write-by-default GITHUB_TOKEN, an app-backed agent with write-to-all, and
// an unidentified bot.
func aiSnapshot() *model.Snapshot {
	s := model.NewSnapshot("acme")
	s.ActionsToken = model.ActionsTokenSettings{DefaultWorkflowPermissions: "write"}
	s.AppInstallations = []model.AppInstallation{
		{AppSlug: "ai-refactor", RepositorySelection: "all", Permissions: map[string]string{"contents": "write"}},
	}
	s.Repos = []model.Repo{
		{Name: "api", BotCommitters: []model.CommitActivity{
			{Login: "github-actions[bot]", Commits: 10},
			{Login: "ai-refactor[bot]", Commits: 4},
			{Login: "mystery[bot]", Commits: 2},
		}},
		{Name: "web", BotCommitters: []model.CommitActivity{
			{Login: "ai-refactor[bot]", Commits: 1},
		}},
	}
	return s
}

func TestBuildAgents(t *testing.T) {
	agents := buildAgents(aiSnapshot())
	if len(agents) != 3 {
		t.Fatalf("agents = %d, want 3", len(agents))
	}
	by := map[string]agent{}
	for _, a := range agents {
		by[a.Login] = a
	}

	if a := by["ai-refactor[bot]"]; !a.AppBacked || a.Breadth != "all-write" || a.Repos != 2 || a.Commits != 5 {
		t.Errorf("ai-refactor agent = %+v, want app-backed all-write across 2 repos / 5 commits", a)
	}
	if a := by["github-actions[bot]"]; !a.KnownPlatform || a.Breadth != "github_token-write" {
		t.Errorf("github-actions agent = %+v, want known platform with github_token-write", a)
	}
	if a := by["mystery[bot]"]; a.AppBacked || a.KnownPlatform || a.Breadth != "" {
		t.Errorf("mystery agent = %+v, want unidentified with no breadth", a)
	}
}

func TestUnidentifiedCommitter(t *testing.T) {
	got := unidentifiedCommitter{}.Run(context.Background(), aiSnapshot())
	if len(got) != 1 || got[0].Evidence["login"] != "mystery[bot]" {
		t.Errorf("got %+v, want only mystery[bot]", got)
	}
}

func TestAgentBroadWrite(t *testing.T) {
	got := agentBroadWrite{}.Run(context.Background(), aiSnapshot())
	bySev := map[model.Severity]string{}
	for _, f := range got {
		bySev[f.Severity] = f.Evidence["login"].(string)
	}
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (ai-refactor high, github-actions medium)", len(got))
	}
	if bySev[model.SevHigh] != "ai-refactor[bot]" {
		t.Errorf("high finding = %q, want ai-refactor[bot]", bySev[model.SevHigh])
	}
	if bySev[model.SevMedium] != "github-actions[bot]" {
		t.Errorf("medium finding = %q, want github-actions[bot]", bySev[model.SevMedium])
	}
}

func TestAgentInventory(t *testing.T) {
	got := agentInventory{}.Run(context.Background(), aiSnapshot())
	if len(got) != 1 || got[0].Severity != model.SevInfo {
		t.Fatalf("got %+v, want one info finding", got)
	}
	agents, ok := got[0].Evidence["agents"].([]map[string]any)
	if !ok || len(agents) != 3 {
		t.Errorf("inventory agents = %v, want 3", got[0].Evidence["agents"])
	}
}

// assistedSnapshot has two repos whose people committed agent-written code, one
// of them unprotected, and no committing bots at all.
func assistedSnapshot() *model.Snapshot {
	s := model.NewSnapshot("acme")
	s.Repos = []model.Repo{
		{Name: "api", DefaultBranch: "main", DefaultBranchProtected: boolPtr(false), AgentAssistedCommits: []model.AgentAssist{
			{Agent: "Claude Code", Author: "alice", Commits: 7},
			{Agent: "Claude Code", Author: "", Commits: 2},
			{Agent: "Cursor", Author: "bob", Commits: 1},
		}},
		{Name: "web", DefaultBranch: "main", DefaultBranchProtected: boolPtr(true), AgentAssistedCommits: []model.AgentAssist{
			{Agent: "Claude Code", Author: "alice", Commits: 3},
			{Agent: "Claude Code", Author: "carol", Commits: 1},
		}},
	}
	return s
}

func TestBuildAssisted(t *testing.T) {
	got := buildAssisted(assistedSnapshot())
	if len(got) != 2 {
		t.Fatalf("assisted agents = %d, want 2", len(got))
	}
	claude := got[0]
	if claude.Agent != "Claude Code" || claude.Commits != 13 || claude.Repos != 2 || claude.Unattributed != 2 {
		t.Errorf("claude = %+v, want 13 commits across 2 repos, 2 unattributed", claude)
	}
	if len(claude.Authors) != 2 || claude.Authors[0] != "alice" || claude.Authors[1] != "carol" {
		t.Errorf("claude authors = %v, want [alice carol] (each once, unattributed excluded)", claude.Authors)
	}
	if len(claude.UnprotectedRepos) != 1 || claude.UnprotectedRepos[0] != "api" {
		t.Errorf("claude unprotected repos = %v, want [api]", claude.UnprotectedRepos)
	}
	if cursor := got[1]; cursor.Agent != "Cursor" || cursor.Commits != 1 || cursor.Repos != 1 {
		t.Errorf("cursor = %+v, want 1 commit in 1 repo", cursor)
	}
}

func TestAgentInventory_AssistedOnly(t *testing.T) {
	got := agentInventory{}.Run(context.Background(), assistedSnapshot())
	if len(got) != 1 || got[0].Severity != model.SevInfo {
		t.Fatalf("got %+v, want one info finding", got)
	}
	f := got[0]
	if want := "2 coding agents co-wrote 14 commits in the last 90 days"; f.Title != want {
		t.Errorf("title = %q, want %q", f.Title, want)
	}
	if _, ok := f.Evidence["agents"]; ok {
		t.Errorf("evidence has a bot list with no bots: %v", f.Evidence["agents"])
	}
	if assisted, ok := f.Evidence["assisted"].([]map[string]any); !ok || len(assisted) != 2 {
		t.Errorf("assisted evidence = %v, want 2 agents", f.Evidence["assisted"])
	}
	// The inventory must say it is a floor: absence of a mark is not absence of an agent.
	if !strings.Contains(f.Description, "floor") {
		t.Errorf("description does not state the counts are a floor: %q", f.Description)
	}
	if !strings.HasPrefix(f.Description, "Coding agents wrote code") {
		t.Errorf("description of an org with no bots should open on the agents: %q", f.Description)
	}
	if !strings.Contains(f.Description, "In 1 repository the default branch has no protection") {
		t.Errorf("description does not name the unprotected landing: %q", f.Description)
	}
}

func TestAgentInventory_BothPopulations(t *testing.T) {
	s := aiSnapshot()
	s.Repos[0].AgentAssistedCommits = []model.AgentAssist{{Agent: "Claude Code", Author: "alice", Commits: 1}}
	got := agentInventory{}.Run(context.Background(), s)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if want := "3 machine identities and 1 coding agent committed code in the last 90 days"; got[0].Title != want {
		t.Errorf("title = %q, want %q", got[0].Title, want)
	}
}

// A bot-only org must read exactly as it did before agent-assisted commits
// existed, so the reports and baselines of orgs without them do not move.
func TestAgentInventory_BotOnlyUnchanged(t *testing.T) {
	f := agentInventory{}.Run(context.Background(), aiSnapshot())[0]
	if _, ok := f.Evidence["assisted"]; ok {
		t.Errorf("bot-only evidence grew an assisted key: %v", f.Evidence)
	}
	if strings.Contains(f.Description, "floor") || strings.Contains(f.Remediation, "person's account") {
		t.Errorf("bot-only text changed: %q / %q", f.Description, f.Remediation)
	}
}

// An agent's mark is voluntary. If it cost points, a team that strips its
// trailers would outscore one that keeps them, so assisted commits alone never
// raise this finding; the inventory reports them at zero penalty.
func TestAgentOnUnprotectedBranch_AssistedAloneIsNotCharged(t *testing.T) {
	got := agentOnUnprotectedBranch{}.Run(context.Background(), assistedSnapshot())
	if len(got) != 0 {
		t.Errorf("findings = %+v, want none for agent-assisted commits alone", got)
	}
}

// When a bot already triggers the finding, the assisted agents on the same
// branch are named in it: one missing gate, one finding.
func TestAgentOnUnprotectedBranch_NamesAssistedAlongsideBots(t *testing.T) {
	s := assistedSnapshot()
	s.Repos[0].BotCommitters = []model.CommitActivity{{Login: "renovate[bot]", Commits: 3}}
	got := agentOnUnprotectedBranch{}.Run(context.Background(), s)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if !strings.HasPrefix(got[0].Title, "Machine identities and coding agents push") {
		t.Errorf("title = %q", got[0].Title)
	}
	names, _ := got[0].Evidence["assisted_agents"].([]string)
	if len(names) != 2 || names[0] != "Claude Code" || names[1] != "Cursor" {
		t.Errorf("assisted_agents = %v, want [Claude Code Cursor]", got[0].Evidence["assisted_agents"])
	}
}
