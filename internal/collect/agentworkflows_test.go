package collect

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func scanOne(t *testing.T, content string) model.AgentWorkflow {
	t.Helper()
	got, _ := scanAgentWorkflows(map[string]string{"agent.yml": content}, "acme/api")
	if len(got) != 1 {
		t.Fatalf("agent jobs = %d (%+v), want 1", len(got), got)
	}
	return got[0]
}

func TestScanAgentWorkflows_ClaudeActionDefaultGateIsClosed(t *testing.T) {
	aw := scanOne(t, `
on:
  issue_comment:
    types: [created]
  pull_request_review_comment:
jobs:
  claude:
    permissions:
      contents: write
      pull-requests: write
      issues: read
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`)
	want := model.AgentWorkflow{
		File: "agent.yml", Job: "claude", Agent: "Claude Code", Via: "anthropics/claude-code-action@v1",
		UntrustedTriggers: []string{"issue_comment", "pull_request_review_comment"},
		Gate:              "closed",
		WriteScopes:       []string{"contents", "pull-requests"},
		ModelSecrets:      []string{"ANTHROPIC_API_KEY"},
		Credentials:       []string{"checkout credentials persisted in .git/config", "the action's own GitHub token"},
	}
	if !reflect.DeepEqual(aw, want) {
		t.Errorf("got  %+v\nwant %+v", aw, want)
	}
}

func TestScanAgentWorkflows_ClaudeActionOpenedToEveryone(t *testing.T) {
	aw := scanOne(t, `
on: [issues]
permissions: write-all
jobs:
  triage:
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          github_token: ${{ secrets.ORG_PAT }}
          claude_code_oauth_token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
          prompt: "Triage: ${{ github.event.issue.title }} ${{ github.event.issue.body }}"
`)
	if aw.Gate != "open" || aw.GateDetail != "allowed_non_write_users: *" {
		t.Errorf("gate = %q (%q), want open", aw.Gate, aw.GateDetail)
	}
	if !reflect.DeepEqual(aw.WriteScopes, []string{"all"}) {
		t.Errorf("write scopes = %v, want [all] from write-all", aw.WriteScopes)
	}
	// A PAT handed to the agent is the worst secret in reach: it is not the
	// model's key and it reaches beyond this repository.
	if !reflect.DeepEqual(aw.Secrets, []string{"ORG_PAT"}) || !reflect.DeepEqual(aw.ModelSecrets, []string{"CLAUDE_CODE_OAUTH_TOKEN"}) {
		t.Errorf("secrets = %v, model = %v", aw.Secrets, aw.ModelSecrets)
	}
	if !reflect.DeepEqual(aw.Interpolated, []string{"github.event.issue.body", "github.event.issue.title"}) {
		t.Errorf("interpolated = %v", aw.Interpolated)
	}
}

func TestScanAgentWorkflows_NamedAndBotGates(t *testing.T) {
	codex := scanOne(t, `
on: issue_comment
jobs:
  codex:
    steps:
      - uses: openai/codex-action@v1
        with:
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          allow-users: alice,bob
`)
	if codex.Gate != "named" || codex.GateDetail != "allow-users: alice,bob" {
		t.Errorf("codex gate = %q (%q), want named", codex.Gate, codex.GateDetail)
	}
	bots := scanOne(t, `
on: issue_comment
jobs:
  codex:
    steps:
      - uses: openai/codex-action@v1
        with:
          allow-bots: true
`)
	if bots.Gate != "open" {
		t.Errorf("allow-bots gate = %q, want open", bots.Gate)
	}
}

func TestScanAgentWorkflows_CLIHasNoGateAndTakesTheDefaultToken(t *testing.T) {
	aw := scanOne(t, `
on:
  issues:
    types: [opened]
jobs:
  fix:
    runs-on: ubuntu-latest
    env:
      DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
    steps:
      - run: |
          npx -y @anthropic-ai/claude-code -p "Fix: ${{ github.event.issue.body }}"
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
`)
	if aw.Agent != "Claude Code" || aw.Via != "run" || aw.Gate != "none" {
		t.Errorf("agent = %+v, want Claude Code via run with no gate", aw)
	}
	if !aw.TokenDefault || aw.WriteScopes != nil {
		t.Errorf("token default = %v, writes = %v; want the org default", aw.TokenDefault, aw.WriteScopes)
	}
	if !reflect.DeepEqual(aw.Secrets, []string{"DEPLOY_KEY"}) || !reflect.DeepEqual(aw.ModelSecrets, []string{"ANTHROPIC_API_KEY"}) {
		t.Errorf("secrets = %v, model = %v", aw.Secrets, aw.ModelSecrets)
	}
}

// A secret used only before the agent's step left with that step; one used
// after it is in reach of a shell-capable agent.
func TestScanAgentWorkflows_SecretsFromTheAgentStepOnward(t *testing.T) {
	aw := scanOne(t, `
on: issues
jobs:
  triage:
    steps:
      - uses: actions/create-github-app-token@v2
        with:
          private-key: ${{ secrets.APP_PRIVATE_KEY }}
      - run: npx -y @google/gemini-cli --prompt "triage"
      - run: |
          curl -H "key: $KEY" https://metrics.example.com
        env:
          KEY: ${{ secrets.METRICS_KEY }}
`)
	if !reflect.DeepEqual(aw.Secrets, []string{"METRICS_KEY"}) {
		t.Errorf("secrets = %v, want [METRICS_KEY] only", aw.Secrets)
	}
}

// The hardened triage pattern: the agent only reads files, its step blanks
// the token, the checkout keeps no credentials, the issue arrives as a file,
// and a later step parses the agent's output as data.
const hardenedTriage = `
on:
  issues:
    types: [opened]
permissions:
  contents: read
  issues: write
  actions: write
  statuses: write
jobs:
  triage:
    env:
      GITHUB_TOKEN: ${{ github.token }}
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
      - uses: actions/create-github-app-token@v2
        id: app
        with:
          private-key: ${{ secrets.PRIVATE_KEY }}
      - run: echo "$BODY" > issue.md
        env:
          BODY: ${{ github.event.issue.body }}
      - id: agent
        uses: google-github-actions/run-gemini-cli@v0
        env:
          GITHUB_TOKEN: ''
        with:
          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
          settings: |-
            { "tools": { "core": ["read_file", "glob"] } }
          prompt: Read issue.md and pick one label.
      - uses: actions/github-script@v7
        env:
          LABELS: ${{ steps.agent.outputs.summary }}
        with:
          github-token: ${{ steps.app.outputs.token }}
          script: |
            const labels = JSON.parse(process.env.LABELS)
`

func TestScanAgentWorkflows_AgentReach(t *testing.T) {
	aw := scanOne(t, hardenedTriage)
	if !aw.ReadOnly || aw.Credentials != nil || aw.OutputExecuted {
		t.Errorf("hardened triage: read-only %v, credentials %v, output executed %v; want read-only, none, false",
			aw.ReadOnly, aw.Credentials, aw.OutputExecuted)
	}

	cases := []struct {
		name, from, to string
		check          func(model.AgentWorkflow) bool
	}{
		{"a shell tool is not read-only", `"core": ["read_file", "glob"]`, `"core": ["read_file", "run_shell_command(gh)"]`,
			func(aw model.AgentWorkflow) bool { return !aw.ReadOnly }},
		{"a web fetch is an exfiltration channel", `"core": ["read_file", "glob"]`, `"core": ["read_file", "web_fetch"]`,
			func(aw model.AgentWorkflow) bool { return !aw.ReadOnly }},
		{"no allowlist means the defaults", `{ "tools": { "core": ["read_file", "glob"] } }`, `{}`,
			func(aw model.AgentWorkflow) bool { return !aw.ReadOnly }},
		{"the job's token reaches an agent step that does not blank it", "          GITHUB_TOKEN: ''\n", "          FOO: bar\n",
			func(aw model.AgentWorkflow) bool {
				return reflect.DeepEqual(aw.Credentials, []string{"env GITHUB_TOKEN"})
			}},
		{"a checkout that persists credentials puts the token in .git/config", "persist-credentials: false", "fetch-depth: 1",
			func(aw model.AgentWorkflow) bool {
				return reflect.DeepEqual(aw.Credentials, []string{"checkout credentials persisted in .git/config"})
			}},
		{"output expanded into a later script runs", "            const labels = JSON.parse(process.env.LABELS)",
			"            const labels = ${{ steps.agent.outputs.summary }}",
			func(aw model.AgentWorkflow) bool { return aw.OutputExecuted }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(hardenedTriage, tc.from) {
				t.Fatalf("fixture has no %q", tc.from)
			}
			aw := scanOne(t, strings.Replace(hardenedTriage, tc.from, tc.to, 1))
			if !tc.check(aw) {
				t.Errorf("got read-only %v, credentials %v, output executed %v", aw.ReadOnly, aw.Credentials, aw.OutputExecuted)
			}
		})
	}
}

func TestScanAgentWorkflows_CodexReadOnlySandbox(t *testing.T) {
	aw := scanOne(t, `
on: issues
jobs:
  codex:
    steps:
      - uses: openai/codex-action@v1
        with:
          allow-users: "*"
          safety-strategy: read-only
`)
	if !aw.ReadOnly || aw.Credentials != nil {
		t.Errorf("read-only %v credentials %v, want read-only and none", aw.ReadOnly, aw.Credentials)
	}
	// Without it the action runs the workspace-write sandbox.
	if aw := scanOne(t, "on: issues\njobs:\n  c:\n    steps:\n      - uses: openai/codex-action@v1\n"); aw.ReadOnly {
		t.Error("default codex sandbox read as read-only")
	}
}

func TestScanAgentWorkflows_IfGuards(t *testing.T) {
	guarded := scanOne(t, `
on: issue_comment
jobs:
  gemini:
    if: contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
`)
	if guarded.Gate != "closed" {
		t.Errorf("author_association guard: gate = %q, want closed", guarded.Gate)
	}
	// Gemini's action documents no actor check of its own.
	bare := scanOne(t, `
on: issue_comment
jobs:
  gemini:
    if: github.actor != 'dependabot[bot]'
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
`)
	if bare.Gate != "none" {
		t.Errorf("a negative actor test admits everyone else: gate = %q, want none", bare.Gate)
	}
	step := scanOne(t, `
on: issue_comment
jobs:
  agent:
    steps:
      - if: github.actor == 'alice'
        run: codex exec "summarise"
`)
	if step.Gate != "closed" {
		t.Errorf("step-level equality guard: gate = %q, want closed", step.Gate)
	}
}

// claude-code-action documents allowed_non_write_users as taking effect only
// with a github_token input; under its App authentication the gate stays shut.
func TestScanAgentWorkflows_AllowListIgnoredWithoutGithubToken(t *testing.T) {
	aw := scanOne(t, `
on: issues
jobs:
  triage:
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
`)
	if aw.Gate != "closed" || aw.GateDetail != "allowed_non_write_users: * (ignored without a github_token input)" {
		t.Errorf("gate = %q (%q), want closed and why", aw.Gate, aw.GateDetail)
	}
}

// The guard that only covers comments: an opened issue reaches the agent with
// no association test at all, so issues is exposed and issue_comment is not.
func TestScanAgentWorkflows_GuardCoveringOnlyComments(t *testing.T) {
	aw := scanOne(t, `
on:
  issues:
    types: [opened]
  issue_comment:
    types: [created]
jobs:
  triage:
    if: |-
      github.repository == 'acme/api' &&
      (github.event_name == 'issues' ||
       (github.event_name == 'issue_comment' &&
        contains(github.event.comment.body, '@bot /triage') &&
        (github.event.comment.author_association == 'OWNER' ||
         github.event.comment.author_association == 'MEMBER')))
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
`)
	if aw.Gate != "none" || !reflect.DeepEqual(aw.UntrustedTriggers, []string{"issues"}) {
		t.Errorf("gate %q triggers %v, want none on [issues] only", aw.Gate, aw.UntrustedTriggers)
	}
}

func TestScanAgentWorkflows_CallerConditionClosesTheCallee(t *testing.T) {
	got, _ := scanAgentWorkflows(map[string]string{
		"on-comment.yml": `
on: issue_comment
jobs:
  call:
    if: github.event.comment.author_association == 'MEMBER'
    uses: ./.github/workflows/agent.yml
`,
		"agent.yml": `
on: workflow_call
jobs:
  run:
    steps:
      - run: codex exec "fix it"
`,
	}, "acme/api")
	if len(got) != 1 || got[0].Gate != "closed" || got[0].UntrustedTriggers != nil {
		t.Errorf("got %+v, want one job closed by the caller's if:", got)
	}
}

func TestScanAgentWorkflows_SameRepoReusableWorkflow(t *testing.T) {
	got, external := scanAgentWorkflows(map[string]string{
		"on-comment.yml": `
on: issue_comment
jobs:
  call:
    uses: ./.github/workflows/agent.yml
    secrets: inherit
`,
		"agent.yml": `
on: workflow_call
jobs:
  run:
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
        with:
          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
`,
	}, "acme/api")
	if len(external) != 0 {
		t.Errorf("external = %v, want none", external)
	}
	// Reported once, through the caller that carries the trigger.
	if len(got) != 1 {
		t.Fatalf("agent jobs = %+v, want 1", got)
	}
	aw := got[0]
	if aw.File != "on-comment.yml" || aw.Job != "call -> agent.yml#run" {
		t.Errorf("location = %s / %s", aw.File, aw.Job)
	}
	if !reflect.DeepEqual(aw.UntrustedTriggers, []string{"issue_comment"}) || aw.Gate != "none" || !aw.TokenDefault {
		t.Errorf("got %+v, want caller's trigger, no gate, default token", aw)
	}
	if !reflect.DeepEqual(aw.Secrets, []string{"*"}) {
		t.Errorf("secrets = %v, want [*] for secrets: inherit", aw.Secrets)
	}
}

func TestScanAgentWorkflows_ExternalCallsAreNotAssessed(t *testing.T) {
	got, external := scanAgentWorkflows(map[string]string{
		"ci.yml": `
on: [pull_request_target, push]
jobs:
  review:
    uses: acme/shared/.github/workflows/review.yml@main
  build:
    uses: acme/shared/.github/workflows/build.yml@main
`,
		"nightly.yml": `
on: schedule
jobs:
  report:
    uses: acme/shared/.github/workflows/report.yml@main
`,
	}, "acme/api")
	if len(got) != 0 {
		t.Errorf("agent jobs = %+v, want none", got)
	}
	want := []string{
		"ci.yml#build -> acme/shared/.github/workflows/build.yml@main",
		"ci.yml#review -> acme/shared/.github/workflows/review.yml@main",
	}
	if !reflect.DeepEqual(external, want) {
		t.Errorf("external = %v, want %v (only calls a non-writer can trigger)", external, want)
	}
}

func TestScanAgentWorkflows_InventoryAndNoise(t *testing.T) {
	got, _ := scanAgentWorkflows(map[string]string{
		// Trusted trigger: still an agent in CI, for the inventory.
		"review.yml": "on: pull_request\njobs:\n  r:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n",
		// Mentions of agents that do not run one.
		"install.yml": "on: issues\njobs:\n  i:\n    steps:\n      - run: npm install -g @anthropic-ai/claude-code\n      - run: echo claude is great\n",
		// A field of an unexpected type does not hide the agent beside it.
		"odd.yml": "on: issues\njobs:\n  o:\n    steps:\n      - run: [not, a, script]\n      - uses: openai/codex-action@v1\n",
		// Not YAML GitHub would run.
		"broken.yml": "on: [issues\njobs: {",
	}, "acme/api")
	if len(got) != 2 || got[0].File != "odd.yml" || got[1].File != "review.yml" || got[1].UntrustedTriggers != nil {
		t.Errorf("got %+v, want odd.yml, and review.yml with no untrusted trigger", got)
	}
}

// Every agent action must say where its gate behaviour is documented.
func TestAgentActionsCiteASource(t *testing.T) {
	for _, a := range agentActions {
		if a.agent == "" || a.repo == "" || a.source == "" || (a.gated && a.gate == nil) {
			t.Errorf("agent action %+v: want agent, repo, source, and a gate reader when gated", a)
		}
	}
}
