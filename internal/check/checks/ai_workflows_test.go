package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func agentWorkflowSnapshot(defaultToken string, repos ...model.Repo) *model.Snapshot {
	s := model.NewSnapshot("acme")
	s.ActionsToken = model.ActionsTokenSettings{DefaultWorkflowPermissions: defaultToken}
	s.Repos = repos
	return s
}

func agentJob(gate string, mutate func(*model.AgentWorkflow)) model.AgentWorkflow {
	aw := model.AgentWorkflow{
		File: "claude.yml", Job: "triage", Agent: "Claude Code", Via: "anthropics/claude-code-action@v1",
		UntrustedTriggers: []string{"issue_comment"}, Gate: gate,
	}
	if mutate != nil {
		mutate(&aw)
	}
	return aw
}

func runAgentWorkflowCheck(t *testing.T, s *model.Snapshot) []model.Finding {
	t.Helper()
	return agentWorkflowUntrustedTrigger{}.Run(context.Background(), s)
}

func TestAgentWorkflow_Severity(t *testing.T) {
	withWrite := func(aw *model.AgentWorkflow) { aw.WriteScopes = []string{"contents"} }
	withSecret := func(aw *model.AgentWorkflow) { aw.Secrets = []string{"ORG_PAT"} }
	issuesOnly := func(aw *model.AgentWorkflow) { aw.WriteScopes = []string{"id-token", "issues"} }
	readOnly := func(aw *model.AgentWorkflow) {}

	cases := []struct {
		name    string
		private bool
		gate    string
		mutate  func(*model.AgentWorkflow)
		want    model.Severity
	}{
		{"public, open gate, write token", false, "open", withWrite, model.SevHigh},
		{"public, no gate, extra secret", false, "none", withSecret, model.SevHigh},
		{"private, open gate, write token", true, "open", withWrite, model.SevMedium},
		{"public, open gate, read-only", false, "open", readOnly, model.SevLow},
		{"public, open gate, issues and id-token write", false, "open", issuesOnly, model.SevLow},
		{"private, open gate, read-only", true, "open", readOnly, model.SevLow},
		{"named, write token", false, "named", withWrite, model.SevMedium},
		{"named, read-only", false, "named", readOnly, model.SevLow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := model.Repo{Name: "api", Private: tc.private, AgentWorkflows: []model.AgentWorkflow{agentJob(tc.gate, tc.mutate)}}
			got := runAgentWorkflowCheck(t, agentWorkflowSnapshot("read", r))
			if len(got) != 1 || got[0].Severity != tc.want {
				t.Fatalf("got %+v, want one %v finding", got, tc.want)
			}
		})
	}
}

// The action's own write-access check, or an if: on the actor, is a gate; a
// workflow no non-writer can trigger needs none. Neither is a finding.
func TestAgentWorkflow_ClosedOrTrustedIsSilent(t *testing.T) {
	r := model.Repo{Name: "api", AgentWorkflows: []model.AgentWorkflow{
		agentJob("closed", func(aw *model.AgentWorkflow) { aw.WriteScopes = []string{"contents"} }),
		agentJob("none", func(aw *model.AgentWorkflow) { aw.UntrustedTriggers = nil }),
	}}
	if got := runAgentWorkflowCheck(t, agentWorkflowSnapshot("write", r)); len(got) != 0 {
		t.Errorf("got %+v, want none", got)
	}
}

// With no permissions block the job takes the org default: write makes it
// dangerous, and an unreadable default is never guessed into a write.
func TestAgentWorkflow_DefaultToken(t *testing.T) {
	job := agentJob("none", func(aw *model.AgentWorkflow) { aw.Via, aw.TokenDefault = "run", true })
	r := model.Repo{Name: "api", AgentWorkflows: []model.AgentWorkflow{job}}

	if got := runAgentWorkflowCheck(t, agentWorkflowSnapshot("write", r)); got[0].Severity != model.SevHigh {
		t.Errorf("org default write: severity = %v, want high", got[0].Severity)
	}
	got := runAgentWorkflowCheck(t, agentWorkflowSnapshot("", r))
	if got[0].Severity != model.SevLow || !strings.Contains(got[0].Description, "not assessed") {
		t.Errorf("unreadable default: got %v / %q, want it priced as read, and a not-assessed note", got[0].Severity, got[0].Description)
	}
}

// Write limited to issues is named in the title, and the OIDC credential is
// noted without being priced.
func TestAgentWorkflow_MinorWriteAndOIDC(t *testing.T) {
	job := agentJob("open", func(aw *model.AgentWorkflow) { aw.WriteScopes = []string{"id-token", "issues"} })
	r := model.Repo{Name: "api", AgentWorkflows: []model.AgentWorkflow{job}}
	f := runAgentWorkflowCheck(t, agentWorkflowSnapshot("read", r))[0]
	if want := "Claude Code in acme/api answers to anyone, with write access to issues only"; f.Title != want {
		t.Errorf("title = %q, want %q", f.Title, want)
	}
	if !strings.Contains(f.Description, "OIDC") {
		t.Errorf("description does not note the OIDC credential: %q", f.Description)
	}
}

func TestAgentWorkflow_OneFindingPerRepoLedByTheWorstJob(t *testing.T) {
	r := model.Repo{Name: "api", AgentWorkflows: []model.AgentWorkflow{
		agentJob("named", func(aw *model.AgentWorkflow) { aw.Job = "summarise" }),
		agentJob("open", func(aw *model.AgentWorkflow) {
			aw.Job, aw.GateDetail = "fix", "allowed_non_write_users: *"
			aw.WriteScopes = []string{"contents", "pull-requests"}
			aw.Interpolated = []string{"github.event.comment.body"}
		}),
	}}
	got := runAgentWorkflowCheck(t, agentWorkflowSnapshot("read", r))
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1 per repo", len(got))
	}
	f := got[0]
	if f.Severity != model.SevHigh || f.Volume != 2 || f.Resource.Type != "repo" {
		t.Errorf("severity %v volume %d resource %q, want high / 2 / repo", f.Severity, f.Volume, f.Resource.Type)
	}
	want := "Claude Code in acme/api answers to anyone, with write access (2 workflow jobs)"
	if f.Title != want {
		t.Errorf("title = %q, want %q", f.Title, want)
	}
	for _, frag := range []string{"claude.yml#fix", "allowed_non_write_users: *", "github.event.comment.body"} {
		if !strings.Contains(f.Description+f.Remediation, frag) {
			t.Errorf("description/remediation missing %q", frag)
		}
	}
	jobs := f.Evidence["jobs"].([]map[string]any)
	if jobs[0]["job"] != "fix" || jobs[0]["severity"] != "high" {
		t.Errorf("evidence not led by the worst job: %v", jobs[0])
	}
}

func TestAgentInventory_CIAgents(t *testing.T) {
	r := model.Repo{
		Name: "api",
		AgentWorkflows: []model.AgentWorkflow{
			agentJob("open", nil),
			agentJob("closed", func(aw *model.AgentWorkflow) { aw.Job = "review" }),
		},
		UntrustedExternalCalls: []string{"ci.yml#review -> acme/shared/.github/workflows/review.yml@main"},
	}
	got := agentInventory{}.Run(context.Background(), agentWorkflowSnapshot("read", r))
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	if want := "2 workflow jobs run an AI agent in CI"; f.Title != want {
		t.Errorf("title = %q, want %q", f.Title, want)
	}
	if ci, _ := f.Evidence["ci"].([]map[string]any); len(ci) != 2 {
		t.Errorf("ci evidence = %v, want 2 jobs", f.Evidence["ci"])
	}
	for _, frag := range []string{"1 of them can be steered", "not assessed"} {
		if !strings.Contains(f.Description, frag) {
			t.Errorf("description missing %q: %q", frag, f.Description)
		}
	}
}

// #83: price what the agent reaches, not only what the job holds. A hardened
// triage job holds actions and statuses write, and its agent can touch none of it.
func TestAgentWorkflow_AgentReach(t *testing.T) {
	jobWrite := func(aw *model.AgentWorkflow) {
		aw.Via, aw.Agent = "google-github-actions/run-gemini-cli@v0", "Gemini CLI"
		aw.Gate = "none"
		aw.WriteScopes = []string{"actions", "id-token", "issues", "statuses"}
		aw.Secrets = []string{"METRICS_KEY"} // a later step's: out of reach without a shell
		aw.ReadOnly = true
	}
	cases := []struct {
		name   string
		mutate func(*model.AgentWorkflow)
		want   model.Severity
		phrase string
	}{
		{"contained", func(aw *model.AgentWorkflow) {}, model.SevLow, "read-only tools and no credential"},
		{"read-only holding the persisted checkout token", func(aw *model.AgentWorkflow) {
			aw.Credentials = []string{"checkout credentials persisted in .git/config"}
		}, model.SevHigh, "write access"},
		{"read-only holding a secret in its own step", func(aw *model.AgentWorkflow) {
			aw.WriteScopes = []string{"issues"}
			aw.Credentials = []string{"secret DEPLOY_KEY"}
		}, model.SevHigh, "secrets in reach"},
		{"output run by a later step", func(aw *model.AgentWorkflow) { aw.OutputExecuted = true }, model.SevHigh, "write access and secrets in reach"},
		{"not read-only", func(aw *model.AgentWorkflow) { aw.ReadOnly = false }, model.SevHigh, "write access and secrets in reach"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job := agentJob("none", func(aw *model.AgentWorkflow) {
				jobWrite(aw)
				tc.mutate(aw)
			})
			r := model.Repo{Name: "cli", AgentWorkflows: []model.AgentWorkflow{job}}
			got := runAgentWorkflowCheck(t, agentWorkflowSnapshot("read", r))
			if len(got) != 1 || got[0].Severity != tc.want || !strings.HasSuffix(got[0].Title, tc.phrase) {
				t.Fatalf("got %+v, want %v ending %q", got, tc.want, tc.phrase)
			}
			if tc.name == "contained" && (!strings.Contains(got[0].Description, "shapes its output") || strings.Contains(got[0].Description, "OIDC")) {
				t.Errorf("contained description: %q", got[0].Description)
			}
		})
	}
}
