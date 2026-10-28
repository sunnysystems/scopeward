package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(agentWorkflowUntrustedTrigger{}) }

// agentWorkflowUntrustedTrigger flags Actions jobs that run an AI coding agent on
// an event an account without write access can fire, past a gate that does not
// stop them. Whatever that account writes in the issue or comment reaches the
// agent as instructions, and the agent acts with the job's token and secrets:
// "can open an issue" becomes "can push code or exfiltrate secrets".
//
// A closed gate — the action's own write-access check, or an if: that tests the
// actor — produces nothing. Indirect injection (a writer asks the agent to read
// an outsider's issue) is real but not decidable from the workflow file.
type agentWorkflowUntrustedTrigger struct{}

func (agentWorkflowUntrustedTrigger) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "ai.agent-workflow-untrusted-trigger",
		Title:           "AI agents in workflows steerable by non-writers",
		Axis:            model.AxisAIAgents,
		DefaultSeverity: model.SevHigh,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataWorkflows},
		Description:     "Workflows that run an AI agent on events a non-writer can fire (issues, comments, pull_request_target) with no actor check in the way.",
	}
}

// codeWriteScopes are the token permissions whose write reaches code, CI or what
// ships: push to a branch, open or approve a pull request, rerun or poison a
// workflow, publish a package, report a status that satisfies a required check.
// Write on issues or discussions lets an injected agent deface and mislabel,
// not ship; id-token mints an OIDC credential whose reach depends on cloud
// trust policies scopeward cannot see, so it is noted, never priced.
var codeWriteScopes = map[string]bool{
	"all": true, "contents": true, "pull-requests": true, "actions": true,
	"packages": true, "deployments": true, "checks": true, "statuses": true,
	"security-events": true, "pages": true,
}

// agentJobRisk is one exposed job, with what the check concluded about it.
type agentJobRisk struct {
	aw       model.AgentWorkflow
	severity model.Severity
	canWrite bool     // write that reaches code, CI or what ships
	minor    []string // write scopes that do not
	oidc     bool
	token    string // how the token's write access was established
	// contained: the agent only reads files, holds no credential, and nothing
	// executes its output. Whoever steers it shapes its output; it cannot act.
	contained bool
	secrets   []string // the secrets in the agent's reach
}

func (c agentWorkflowUntrustedTrigger) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range activeRepos(s) {
		var risks []agentJobRisk
		for _, aw := range r.AgentWorkflows {
			if len(aw.UntrustedTriggers) == 0 || aw.Gate == "closed" {
				continue
			}
			risks = append(risks, assessAgentJob(s, r, aw))
		}
		if len(risks) == 0 {
			continue
		}
		sort.SliceStable(risks, func(i, j int) bool {
			return risks[i].severity > risks[j].severity
		})
		out = append(out, c.finding(s, r, risks))
	}
	return out
}

// assessAgentJob prices one exposed job. Who can reach it (anyone on a public
// repository, the org's readers on a private one, or only named accounts) and
// what it holds (a write token, secrets beyond the model's own key) set the
// severity.
func assessAgentJob(s *model.Snapshot, r model.Repo, aw model.AgentWorkflow) agentJobRisk {
	risk := agentJobRisk{aw: aw, token: "explicit permissions"}
	for _, scope := range aw.WriteScopes {
		switch {
		case codeWriteScopes[scope]:
			risk.canWrite = true
		case scope == "id-token":
			risk.oidc = true
		default:
			risk.minor = append(risk.minor, scope)
		}
	}
	if aw.TokenDefault {
		switch s.ActionsToken.DefaultWorkflowPermissions {
		case "write":
			risk.canWrite, risk.token = true, "org default: write"
		case "read":
			risk.token = "org default: read"
		default:
			// Never guessed: priced as read, and the finding says so.
			risk.token = "org default: not assessed"
		}
	}
	// What the agent reaches is not always what the job holds (#83).
	//   - Read-only tools, no credential, output not executed: contained.
	//   - Read-only but holding a credential: it can read the credential and
	//     leak it through its output, so the token and its own step's secrets
	//     count. Later steps do not: without a shell, $GITHUB_ENV is out of reach.
	//   - Otherwise a shell-capable agent reaches the job, later steps included.
	readOnly := aw.ReadOnly && !aw.OutputExecuted
	switch {
	case readOnly && len(aw.Credentials) == 0:
		risk.contained, risk.canWrite = true, false
	case readOnly:
		for _, c := range aw.Credentials {
			if name, ok := strings.CutPrefix(c, "secret "); ok {
				risk.secrets = append(risk.secrets, name)
			}
		}
	default:
		risk.secrets = aw.Secrets
	}

	// Without write that ships and without a secret beyond the model's key, an
	// injected agent escalates nothing: whoever triggers it can already read the
	// repository. What is left is its quota and its outputs.
	dangerous := risk.canWrite || len(risk.secrets) > 0

	switch {
	case !dangerous:
		risk.severity = model.SevLow
	case aw.Gate == "named", r.Private:
		risk.severity = model.SevMedium
	default:
		risk.severity = model.SevHigh
	}
	return risk
}

func (c agentWorkflowUntrustedTrigger) finding(s *model.Snapshot, r model.Repo, risks []agentJobRisk) model.Finding {
	worst := risks[0]
	jobs := make([]map[string]any, 0, len(risks))
	for _, k := range risks {
		j := map[string]any{
			"file": k.aw.File, "job": k.aw.Job, "agent": k.aw.Agent, "via": k.aw.Via,
			"triggers": k.aw.UntrustedTriggers, "gate": k.aw.Gate, "token": k.token,
			"severity": k.severity.String(),
		}
		if k.aw.GateDetail != "" {
			j["gate_detail"] = k.aw.GateDetail
		}
		if len(k.aw.WriteScopes) > 0 {
			j["write_scopes"] = k.aw.WriteScopes
		}
		if len(k.secrets) > 0 {
			j["secrets"] = k.secrets
		}
		if len(k.aw.Interpolated) > 0 {
			j["interpolated"] = k.aw.Interpolated
		}
		j["agent_read_only"] = k.aw.ReadOnly
		if len(k.aw.Credentials) > 0 {
			j["agent_credentials"] = k.aw.Credentials
		}
		if k.aw.OutputExecuted {
			j["output_executed"] = true
		}
		jobs = append(jobs, j)
	}

	who := "anyone"
	if r.Private {
		who = "anyone who can read it"
	}
	if worst.aw.Gate == "named" {
		who = "named accounts without write access"
	}
	title := fmt.Sprintf("%s in %s/%s answers to %s, with %s", worst.aw.Agent, s.Org.Login, r.Name, who, reachPhrase(worst))
	if len(risks) > 1 {
		title += fmt.Sprintf(" (%d workflow jobs)", len(risks))
	}

	desc := fmt.Sprintf("%s runs %s on %s, events an account without write access can fire, and %s. "+
		"Whatever that account writes in the issue or comment reaches the agent as instructions (prompt injection, published against agent workflows as PromptPwnd in December 2025). %s",
		worst.aw.File+"#"+worst.aw.Job, worst.aw.Agent, strings.Join(worst.aw.UntrustedTriggers, ", "), gateSentence(worst.aw), reachSentence(worst))
	if len(worst.aw.Interpolated) > 0 {
		desc += " The workflow also expands " + strings.Join(worst.aw.Interpolated, ", ") + " straight into the agent's input, so the injection needs no tool call at all."
	}
	if worst.severity == model.SevLow && !worst.contained {
		desc += " With no write to code or CI and no secret beyond the model's own key, an injected agent is limited to what its token allows on issues and comments, and to spending the model's quota."
	}
	if worst.oidc && !worst.contained {
		desc += " The job can also mint an OIDC token (id-token: write); what that reaches depends on cloud trust policies scopeward cannot see."
	}
	if worst.token == "org default: not assessed" {
		desc += " The job takes the org's default token permission, which was not readable, so write access through it was not assessed."
	}
	if len(risks) > 1 {
		desc += fmt.Sprintf(" %d jobs in this repository are exposed; the evidence lists each.", len(risks))
	}

	remediation := "Gate the job on who triggered it: keep the agent action's own write-access check"
	if worst.aw.GateDetail != "" && worst.aw.Gate != "none" {
		remediation += " (remove " + worst.aw.GateDetail + ")"
	}
	remediation += ", or add an if: on author_association (OWNER, MEMBER, COLLABORATOR). " +
		"Grant the job only the permissions it needs, pass no secret beyond the model's own key, and never expand event text into the prompt; let the agent read it as data. " +
		"Or contain the agent itself: restrict its tools to reading files, keep tokens out of its step (blank GITHUB_TOKEN, checkout with persist-credentials: false), and parse its output as data rather than running it."

	return model.Finding{
		CheckID:     c.Meta().ID,
		Title:       title,
		Severity:    worst.severity,
		Axis:        model.AxisAIAgents,
		Resource:    repoRef(s.Org.Login, r),
		Evidence:    map[string]any{"repo": r.Name, "private": r.Private, "jobs": jobs},
		Description: desc,
		Remediation: remediation,
		DocsURL:     "https://docs.github.com/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
		Volume:      len(risks),
	}
}

func reachPhrase(k agentJobRisk) string {
	secrets := len(k.secrets) > 0
	switch {
	case k.contained:
		return "read-only tools and no credential"
	case k.canWrite && secrets:
		return "write access and secrets in reach"
	case k.canWrite:
		return "write access"
	case secrets:
		return "secrets in reach"
	case len(k.minor) > 0:
		return "write access to " + strings.Join(k.minor, ", ") + " only"
	default:
		return "a read-only token"
	}
}

// reachSentence says what an injected agent can do with what it holds: the
// agent's own tools and environment, not only the job's permissions (#83).
func reachSentence(k agentJobRisk) string {
	switch {
	case k.contained:
		return "Its tools only read files and its environment holds no credential, so whoever steers it shapes its output and nothing more: the job's write access and secrets stay out of its reach."
	case k.aw.ReadOnly && !k.aw.OutputExecuted:
		return "Its tools only read files, but its environment holds " + strings.Join(k.aw.Credentials, ", ") + ", which it can read and leak through its output."
	case k.aw.OutputExecuted:
		return "A later step expands the agent's output into a script, so steering the agent is running code with the job's token and secrets."
	default:
		return "The agent acts with the job's token and every secret from its step onward (a shell-capable agent reaches later steps through $GITHUB_ENV and the workspace)."
	}
}

func gateSentence(aw model.AgentWorkflow) string {
	switch aw.Gate {
	case "open":
		return "the agent's actor check is opened to everyone (" + aw.GateDetail + ")"
	case "named":
		return "the agent's actor check admits named accounts without write access (" + aw.GateDetail + ")"
	default:
		if aw.Via == "run" {
			return "nothing checks who triggered it: an agent CLI refuses nobody, and no if: condition tests the actor"
		}
		return "nothing checks who triggered it: " + aw.Via + " documents no actor check of its own, and no if: condition tests the actor"
	}
}
