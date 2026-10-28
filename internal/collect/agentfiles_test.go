package collect

import (
	"reflect"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestClassifyAgentPath(t *testing.T) {
	cases := map[string]string{
		"AGENTS.md":                                     "instructions",
		"CLAUDE.md":                                     "instructions",
		".claude/agents/reviewer.md":                    "instructions",
		".claude/commands/release/notes.md":             "instructions",
		".github/copilot-instructions.md":               "instructions",
		".github/instructions/go.instructions.md":       "instructions",
		".github/instructions/README.md":                "",
		".cursor/rules/style.mdc":                       "instructions",
		".claude/settings.json":                         "settings",
		".claude/settings.local.json":                   "settings",
		".gemini/settings.json":                         "settings",
		".mcp.json":                                     "mcp",
		".vscode/mcp.json":                              "mcp",
		".cursor/mcp.json":                              "mcp",
		"docs/AGENTS.md":                                "", // nested: not read
		".github/workflows/ci.yml":                      "",
		"README.md":                                     "",
		".claude/agents/reviewer.txt":                   "",
		".github/instructions/nested/x.instructions.md": "instructions",
	}
	for p, want := range cases {
		if got := classifyAgentPath(p); got != want {
			t.Errorf("classifyAgentPath(%q) = %q, want %q", p, got, want)
		}
	}
}

func TestLaunchPinning(t *testing.T) {
	cases := []struct {
		name, command string
		args          []string
		pkg           string
		pinned        bool
	}{
		{"npx latest tag", "npx", []string{"-y", "@playwright/mcp@latest"}, "@playwright/mcp@latest", false},
		{"npx no version", "npx", []string{"-y", "@modelcontextprotocol/server-github"}, "@modelcontextprotocol/server-github", false},
		{"npx caret range", "npx", []string{"some-mcp@^1.2.0"}, "some-mcp@^1.2.0", false},
		{"npx exact", "npx", []string{"-y", "@acme/mcp@1.4.2"}, "@acme/mcp@1.4.2", true},
		{"npx package flag", "npx", []string{"-p", "tool@2.0.0", "tool-mcp"}, "tool@2.0.0", true},
		{"windows npx.cmd", `C:\Program Files\nodejs\npx.cmd`, []string{"srv"}, "srv", false},
		{"pnpm dlx", "pnpm", []string{"dlx", "srv@3.1.0"}, "srv@3.1.0", true},
		{"uvx unpinned", "uvx", []string{"mcp-server-git"}, "mcp-server-git", false},
		{"uvx exact", "uvx", []string{"mcp-server-git==0.6.2"}, "mcp-server-git==0.6.2", true},
		{"uvx from", "uvx", []string{"--from", "pkg==1.0.0", "cmd"}, "pkg==1.0.0", true},
		{"docker by tag", "docker", []string{"run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/github/github-mcp-server"}, "ghcr.io/github/github-mcp-server", false},
		{"docker by digest", "docker", []string{"run", "-i", "img@sha256:abc"}, "img@sha256:abc", true},
		{"npm exec without --no", "npm", []string{"exec", "--", "some-mcp"}, "some-mcp", false},
		{"npm exec --no runs the lockfile's", "npm", []string{"exec", "--no", "--", "component-explorer", "mcp"}, "", true},
		{"node on a repo file", "node", []string{"./tools/mcp.js"}, "", true},
		{"installed binary", "github-mcp-server", []string{"stdio"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg, why := launchPinning(tc.command, tc.args)
			if pkg != tc.pkg || (why == "") != tc.pinned {
				t.Errorf("launchPinning = (%q, %q), want package %q pinned=%v", pkg, why, tc.pkg, tc.pinned)
			}
		})
	}
}

func TestParseMCPConfig(t *testing.T) {
	// VS Code's shape, with the comments and trailing commas it accepts.
	vscode := `{
	  // servers every contributor's Copilot launches
	  "servers": {
	    "github": { "type": "http", "url": "https://api.githubcopilot.com/mcp/" },
	    "playwright": { "command": "npx", "args": ["-y", "@playwright/mcp@latest",], },
	    /* the org's own */
	    "internal": { "command": "npx", "args": ["@acme/mcp-tools"] },
	    "url-in-string": { "command": "echo", "args": ["http://x/*not a comment*/", "a,]"] },
	  },
	}`
	got := parseMCPConfig(".vscode/mcp.json", vscode, "acme")
	want := []model.MCPServer{
		{File: ".vscode/mcp.json", Name: "github", Launch: "https://api.githubcopilot.com/mcp/", Remote: true},
		{File: ".vscode/mcp.json", Name: "internal", Launch: "npx @acme/mcp-tools", Package: "@acme/mcp-tools",
			Unpinned: "no version: unless the lockfile installs @acme/mcp-tools, npm fetches whatever is latest on each launch", FirstParty: true},
		{File: ".vscode/mcp.json", Name: "playwright", Launch: "npx -y @playwright/mcp@latest", Package: "@playwright/mcp@latest",
			Unpinned: "version \"latest\" is a range or tag: npm resolves @playwright/mcp to whatever matches on each launch"},
		{File: ".vscode/mcp.json", Name: "url-in-string", Launch: "echo http://x/*not a comment*/ a,]"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}

	claude := `{"mcpServers": {"git": {"command": "uvx", "args": ["mcp-server-git"]}}}`
	if got := parseMCPConfig(".mcp.json", claude, "acme"); len(got) != 1 || got[0].Unpinned == "" {
		t.Errorf("mcpServers shape: got %+v, want one unpinned server", got)
	}
	if got := parseMCPConfig(".mcp.json", "not json", "acme"); got != nil {
		t.Errorf("unparseable config: got %+v, want nothing", got)
	}
}

func TestParseClaudeSettings(t *testing.T) {
	st, ok := parseClaudeSettings(".claude/settings.json", `{
	  "permissions": {
	    "allow": ["Bash(npm run test:*)", "Bash", "Bash(*)", "Bash(*:*)", "Read", "Bash(git diff:*)"],
	    "defaultMode": "bypassPermissions"
	  }
	}`)
	if !ok {
		t.Fatal("settings did not parse")
	}
	if !reflect.DeepEqual(st.BroadAllow, []string{"Bash", "Bash(*)", "Bash(*:*)"}) {
		t.Errorf("broad allow = %v, want only the rules that approve every shell command", st.BroadAllow)
	}
	if st.DefaultMode != "bypassPermissions" {
		t.Errorf("default mode = %q", st.DefaultMode)
	}
}

func TestParseCodeownersRules(t *testing.T) {
	content := `# owners
*            @acme/platform
/docs/       @acme/docs-team @alice   # inline comment
[Section]
/apps/github
`
	got := parseCodeownersRules(content)
	want := []model.CodeownersRule{
		{Pattern: "*", Owners: []string{"@acme/platform"}},
		{Pattern: "/docs/", Owners: []string{"@acme/docs-team", "@alice"}},
		{Pattern: "/apps/github", Owners: []string{}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestRulesToProtection_CodeOwnerReview(t *testing.T) {
	rule := branchRule{Type: "pull_request"}
	rule.Parameters.RequiredApprovingReviewCount = 1
	rule.Parameters.RequireCodeOwnerReview = true
	d := rulesToProtection([]branchRule{rule})
	if d.codeOwners == nil || !*d.codeOwners {
		t.Errorf("code-owner review = %v, want required", d.codeOwners)
	}
}

// Every agent path must say where the convention is documented.
func TestAgentPathsCiteASource(t *testing.T) {
	for _, a := range agentPaths {
		if a.kind == "" || a.match == "" || a.source == "" {
			t.Errorf("agent path %+v: want kind, match and source", a)
		}
	}
}
