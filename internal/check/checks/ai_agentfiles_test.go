package checks

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func agentFilesRepo(mutate func(*model.Repo)) model.Repo {
	r := model.Repo{
		Name:              "api",
		CodeownersPresent: boolPtr(true),
		CodeownersRules: []model.CodeownersRule{
			{Pattern: "/src/", Owners: []string{"@acme/backend"}},
			{Pattern: "/.claude/", Owners: []string{"@acme/platform"}},
		},
		AgentControlFiles: []model.AgentControlFile{
			{Path: "AGENTS.md", Kind: "instructions"},
			{Path: ".claude/settings.json", Kind: "settings"},
			{Path: ".mcp.json", Kind: "mcp"},
		},
	}
	if mutate != nil {
		mutate(&r)
	}
	return r
}

func teamSnapshot(repos ...model.Repo) *model.Snapshot {
	s := model.NewSnapshot("acme")
	s.Members = []model.Member{{Login: "alice"}, {Login: "bob"}}
	s.Repos = repos
	return s
}

func TestAgentInstructionsUnowned(t *testing.T) {
	got := agentInstructionsUnowned{}.Run(context.Background(), teamSnapshot(agentFilesRepo(nil)))
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	f := got[0]
	if f.Severity != model.SevLow || f.Title != "2 agent-control files in acme/api have no code owner" {
		t.Errorf("got %v %q", f.Severity, f.Title)
	}
	if !reflect.DeepEqual(f.Evidence["unowned"], []string{"AGENTS.md", ".mcp.json"}) {
		t.Errorf("unowned = %v", f.Evidence["unowned"])
	}
}

func TestAgentInstructionsUnowned_AdvisoryOwner(t *testing.T) {
	owned := func(r *model.Repo) {
		r.CodeownersRules = []model.CodeownersRule{{Pattern: "*", Owners: []string{"@acme/platform"}}}
		r.BranchReqPRReview = boolPtr(true)
		r.CodeOwnerApprovalRequired = boolPtr(false)
	}
	got := agentInstructionsUnowned{}.Run(context.Background(), teamSnapshot(agentFilesRepo(owned)))
	if len(got) != 1 || !strings.Contains(got[0].Title, "an owner whose review is not required") {
		t.Fatalf("got %+v, want one advisory-owner finding", got)
	}

	// With --solo nobody can approve their own pull request: requiring
	// code-owner review is not the fix, so an owned file is enough.
	solo := teamSnapshot(agentFilesRepo(owned))
	solo.Solo = true
	if got := (agentInstructionsUnowned{}).Run(context.Background(), solo); len(got) != 0 {
		t.Errorf("solo: got %+v, want none", got)
	}
	// No review required at all is teams.weak-branch-protection's finding.
	noReview := func(r *model.Repo) {
		owned(r)
		r.BranchReqPRReview = boolPtr(false)
	}
	if got := (agentInstructionsUnowned{}).Run(context.Background(), teamSnapshot(agentFilesRepo(noReview))); len(got) != 0 {
		t.Errorf("no review required: got %+v, want none", got)
	}
	// Enforced owners: nothing to say.
	enforced := func(r *model.Repo) {
		owned(r)
		r.CodeOwnerApprovalRequired = boolPtr(true)
	}
	if got := (agentInstructionsUnowned{}).Run(context.Background(), teamSnapshot(agentFilesRepo(enforced))); len(got) != 0 {
		t.Errorf("enforced: got %+v, want none", got)
	}
}

// No CODEOWNERS file at all is teams.repo-no-codeowner's finding, not a second
// one here; and an unread CODEOWNERS is not assessed.
func TestAgentInstructionsUnowned_LeavesMissingCodeownersAlone(t *testing.T) {
	for _, present := range []*bool{boolPtr(false), nil} {
		r := agentFilesRepo(func(r *model.Repo) { r.CodeownersPresent = present })
		if got := (agentInstructionsUnowned{}).Run(context.Background(), teamSnapshot(r)); len(got) != 0 {
			t.Errorf("CodeownersPresent=%v: got %+v, want none", present, got)
		}
	}
}

func TestMCPServerUnpinned(t *testing.T) {
	r := agentFilesRepo(func(r *model.Repo) {
		r.MCPServers = []model.MCPServer{
			{File: ".mcp.json", Name: "playwright", Launch: "npx -y @playwright/mcp@latest", Package: "@playwright/mcp@latest", Unpinned: "tag"},
			{File: ".mcp.json", Name: "ours", Package: "@acme/mcp", Unpinned: "no version", FirstParty: true},
			{File: ".mcp.json", Name: "remote", Launch: "https://mcp.example.com", Remote: true},
			{File: ".mcp.json", Name: "pinned", Package: "pkg@1.2.3"},
		}
	})
	got := mcpServerUnpinned{}.Run(context.Background(), teamSnapshot(r))
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	f := got[0]
	if f.Severity != model.SevMedium || f.Axis != model.AxisSupplyChain || f.Volume != 1 {
		t.Errorf("got %v / %v / volume %d", f.Severity, f.Axis, f.Volume)
	}
	servers := f.Evidence["servers"].([]map[string]any)
	if len(servers) != 1 || servers[0]["name"] != "playwright" {
		t.Errorf("servers = %v, want only the third-party unpinned one", servers)
	}
}

func TestAgentSettingsPermissive(t *testing.T) {
	broad := agentFilesRepo(func(r *model.Repo) {
		r.AgentSettings = []model.AgentSettings{{File: ".claude/settings.json", BroadAllow: []string{"Bash(*)"}, DefaultMode: "bypassPermissions"}}
	})
	got := agentSettingsPermissive{}.Run(context.Background(), teamSnapshot(broad))
	if len(got) != 1 || got[0].Severity != model.SevMedium || !strings.Contains(got[0].Title, "pre-approve any shell command") {
		t.Fatalf("got %+v, want one medium finding for the blanket rule", got)
	}
	if !strings.Contains(got[0].Description, "v2.1.257") {
		t.Errorf("description should say current clients ignore bypassPermissions: %q", got[0].Description)
	}

	bypassOnly := agentFilesRepo(func(r *model.Repo) {
		r.AgentSettings = []model.AgentSettings{{File: ".claude/settings.json", DefaultMode: "bypassPermissions"}}
	})
	if got := (agentSettingsPermissive{}).Run(context.Background(), teamSnapshot(bypassOnly)); len(got) != 1 || got[0].Severity != model.SevLow {
		t.Errorf("bypass only: got %+v, want one low finding", got)
	}

	scoped := agentFilesRepo(func(r *model.Repo) {
		r.AgentSettings = []model.AgentSettings{{File: ".claude/settings.json", DefaultMode: "acceptEdits"}}
	})
	if got := (agentSettingsPermissive{}).Run(context.Background(), teamSnapshot(scoped)); len(got) != 0 {
		t.Errorf("scoped settings: got %+v, want none", got)
	}
}

func TestAgentInventory_Configured(t *testing.T) {
	r := agentFilesRepo(func(r *model.Repo) {
		r.MCPServers = []model.MCPServer{{File: ".mcp.json", Name: "playwright"}}
	})
	got := agentInventory{}.Run(context.Background(), teamSnapshot(r))
	if len(got) != 1 || got[0].Title != "1 repository carries files that steer AI agents" {
		t.Fatalf("got %+v", got)
	}
	configured := got[0].Evidence["configured"].([]map[string]any)
	if len(configured) != 1 || !reflect.DeepEqual(configured[0]["mcp_servers"], []string{"playwright"}) {
		t.Errorf("configured = %v", configured)
	}
}

// Alongside committers, the configured repositories extend the title rather than
// replace it.
func TestAgentInventory_ConfiguredAlongsideCommitters(t *testing.T) {
	s := aiSnapshot()
	s.Repos[0].AgentControlFiles = []model.AgentControlFile{{Path: "CLAUDE.md", Kind: "instructions"}}
	got := agentInventory{}.Run(context.Background(), s)
	if want := "3 machine identities committed code in the last 90 days; 1 repository carries agent files"; got[0].Title != want {
		t.Errorf("title = %q, want %q", got[0].Title, want)
	}
}
