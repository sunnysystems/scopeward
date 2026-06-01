package checks

import (
	"context"
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
