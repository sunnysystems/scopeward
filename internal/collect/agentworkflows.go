package collect

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sunnysystems/scopeward/internal/model"
)

// agentAction is a GitHub Action that runs an AI coding agent. Each entry cites
// the documentation its gate behaviour comes from: a default that changes in a
// later release makes the entry stale, and the source is what makes that
// reviewable.
type agentAction struct {
	agent string
	repo  string // owner/repo, matched case-insensitively before "@"
	// gated means the action itself refuses actors without write access unless
	// its inputs say otherwise; gate reads those inputs.
	gated bool
	gate  func(with map[string]string) (state, detail string)
	// modelKeys are the inputs that carry the model's own credential.
	modelKeys []string
	source    string
}

var agentActions = []agentAction{
	{
		agent: "Claude Code", repo: "anthropics/claude-code-action", gated: true,
		gate: func(w map[string]string) (string, string) {
			if st, d := listGate("allowed_non_write_users", w["allowed_non_write_users"]); st != "" {
				// Documented to take effect only alongside a github_token input;
				// with the action's App authentication it is ignored.
				if strings.TrimSpace(w["github_token"]) == "" {
					return "closed", d + " (ignored without a github_token input)"
				}
				return st, d
			}
			return listGate("allowed_bots", w["allowed_bots"])
		},
		modelKeys: []string{"anthropic_api_key", "claude_code_oauth_token"},
		source:    "https://github.com/anthropics/claude-code-action/blob/main/docs/security.md",
	},
	{
		agent: "Codex", repo: "openai/codex-action", gated: true,
		gate: func(w map[string]string) (string, string) {
			if strings.EqualFold(strings.TrimSpace(w["allow-bots"]), "true") {
				return "open", "allow-bots: true"
			}
			if st, d := listGate("allow-users", w["allow-users"]); st != "" {
				return st, d
			}
			return listGate("allow-bot-users", w["allow-bot-users"])
		},
		modelKeys: []string{"openai-api-key"},
		source:    "https://github.com/openai/codex-action",
	},
	{
		// Documents no actor check of its own: the workflow's if: is the gate.
		agent: "Gemini CLI", repo: "google-github-actions/run-gemini-cli",
		modelKeys: []string{"gemini_api_key", "google_api_key"},
		source:    "https://github.com/google-github-actions/run-gemini-cli",
	},
}

// listGate reads an allow-list input: "*" admits anyone, a list admits those
// named, empty leaves the action's own check in place.
func listGate(input, value string) (string, string) {
	v := strings.TrimSpace(value)
	switch {
	case v == "":
		return "", ""
	case v == "*":
		return "open", input + ": *"
	default:
		return "named", input + ": " + v
	}
}

// agentCLIs recognise an agent run from a script step. A CLI checks nobody's
// permissions, so a job running one is gated only by its if: conditions.
var agentCLIs = []struct {
	agent string
	re    *regexp.Regexp
}{
	{"Claude Code", regexp.MustCompile(`(^|[\s;&|(])(claude\s+(-p|--print)\b|npx\s+(-y\s+)?@anthropic-ai/claude-code\b)`)},
	{"Codex", regexp.MustCompile(`(^|[\s;&|(])(codex\s+exec\b|npx\s+(-y\s+)?@openai/codex\b)`)},
	{"Gemini CLI", regexp.MustCompile(`(^|[\s;&|(])(gemini\s+(-p|--prompt)\b|npx\s+(-y\s+)?@google/gemini-cli\b)`)},
}

// modelKeyEnv are environment variables that hand a CLI the model's credential.
var modelKeyEnv = map[string]bool{
	"ANTHROPIC_API_KEY": true, "CLAUDE_CODE_OAUTH_TOKEN": true,
	"OPENAI_API_KEY": true, "GEMINI_API_KEY": true, "GOOGLE_API_KEY": true,
}

// untrustedEvents are the triggers an actor without write access can fire on a
// repository they can read. pull_request is absent on purpose: a fork's
// pull_request run gets a read-only token and no secrets.
var untrustedEvents = []string{
	"issues", "issue_comment", "pull_request_target",
	"pull_request_review", "pull_request_review_comment",
	"discussion", "discussion_comment",
}

var (
	secretRefRe = regexp.MustCompile(`secrets\.([A-Za-z_][A-Za-z0-9_]*)`)
	exprRe      = regexp.MustCompile(`\$\{\{([^}]*)\}\}`)
	// untrustedFieldRe matches event fields whose text the triggering actor
	// writes. Expanded into a prompt or a script, they are the injection.
	untrustedFieldRe = regexp.MustCompile(`github\.event\.(issue\.(title|body)|comment\.body|review\.body|review_comment\.body|discussion\.(title|body)|pull_request\.(title|body|head\.ref|head\.label)|head_commit\.message)|github\.head_ref`)
)

type wfDoc struct {
	On          yaml.Node        `yaml:"on"`
	Permissions yaml.Node        `yaml:"permissions"`
	Env         any              `yaml:"env"`
	Jobs        map[string]wfJob `yaml:"jobs"`
}

type wfJob struct {
	If          any       `yaml:"if"`
	Permissions yaml.Node `yaml:"permissions"`
	Env         any       `yaml:"env"`
	Steps       []wfStep  `yaml:"steps"`
	Uses        string    `yaml:"uses"`
	Secrets     yaml.Node `yaml:"secrets"`
}

type wfStep struct {
	If   any            `yaml:"if"`
	Uses string         `yaml:"uses"`
	Run  string         `yaml:"run"`
	With map[string]any `yaml:"with"`
	Env  any            `yaml:"env"`
}

// scanAgentWorkflows finds the jobs in a repository's workflows that run an AI
// coding agent, keyed by file name; repo is "owner/name", which if: conditions
// often test. It follows reusable workflows in the same repository, where the
// trigger lives in the caller and the agent in the callee; calls into other
// repositories from a trigger a non-writer can fire are returned separately, as
// not assessed. A file that does not parse is skipped: GitHub would not run it
// either. Pure, so it is tested directly.
func scanAgentWorkflows(files map[string]string, repo string) ([]model.AgentWorkflow, []string) {
	docs := map[string]*wfDoc{}
	for name, content := range files {
		var d wfDoc
		if err := yaml.Unmarshal([]byte(content), &d); err != nil {
			// A field of an unexpected type still leaves the rest decoded;
			// only a file that is not YAML at all is skipped.
			var typeErr *yaml.TypeError
			if !errors.As(err, &typeErr) {
				continue
			}
		}
		docs[name] = &d
	}

	// Callees reached from a caller in this repo are reported through the
	// caller, which carries the trigger; on their own they only say workflow_call.
	calledLocally := map[string]bool{}
	for _, d := range docs {
		for _, j := range d.Jobs {
			if callee, ok := localCallee(j.Uses); ok {
				calledLocally[callee] = true
			}
		}
	}

	var out []model.AgentWorkflow
	var external []string
	for _, name := range sortedKeys(docs) {
		d := docs[name]
		triggers := untrustedTriggers(d.On)
		for _, jobName := range sortedKeys(d.Jobs) {
			j := d.Jobs[jobName]
			if j.Uses == "" {
				if calledLocally[name] && len(triggers) == 0 {
					continue
				}
				for _, aw := range agentJobs(d, j, triggers, repo) {
					aw.File, aw.Job = name, jobName
					out = append(out, aw)
				}
				continue
			}

			callee, local := localCallee(j.Uses)
			reach := admitted(j.If, triggers, repo)
			if !local {
				if len(reach) > 0 {
					external = append(external, name+"#"+jobName+" -> "+j.Uses)
				}
				continue
			}
			cd := docs[callee]
			if cd == nil {
				continue
			}
			for _, cjName := range sortedKeys(cd.Jobs) {
				cj := cd.Jobs[cjName]
				// A called workflow sees the caller's event, so the callee's
				// conditions are evaluated against the triggers the caller let in.
				for _, aw := range agentJobs(cd, cj, reach, repo) {
					aw.File = name
					aw.Job = jobName + " -> " + callee + "#" + cjName
					if len(triggers) > 0 && len(reach) == 0 {
						aw.Gate, aw.GateDetail = "closed", "if: "+stringOf(j.If)
					}
					// The callee may only narrow the caller's token.
					if !hasPermissions(cj.Permissions) && !hasPermissions(cd.Permissions) {
						aw.WriteScopes, aw.TokenDefault = effectivePermissions(d, j)
					}
					aw.Secrets = without(passedSecrets(j), aw.ModelSecrets)
					out = append(out, aw)
				}
			}
		}
	}
	return out, external
}

// admitted filters events to those an if: lets a non-writer through on.
func admitted(cond any, events []string, repo string) []string {
	var out []string
	for _, ev := range events {
		if admitsNonWriter(cond, ev, repo) {
			out = append(out, ev)
		}
	}
	return out
}

// agentJobs reports one AgentWorkflow per agent a job runs, with the job's own
// facts filled in; File and Job are left to the caller. triggers are the
// untrusted events that reach the job; each step's exposure is what is left of
// them after the job's and the step's if: conditions.
//
// UntrustedTriggers on the result are the events that reach the agent past
// those conditions, and Gate is the action's own check in front of it. When
// the conditions refuse non-writers on every event, the gate is closed by the
// condition and named in GateDetail.
func agentJobs(d *wfDoc, j wfJob, triggers []string, repo string) []model.AgentWorkflow {
	type step struct {
		gate, detail string
		cond         any
		reach        []string
	}
	type hit struct {
		aw    model.AgentWorkflow
		steps []step
		order int
	}
	jobReach := admitted(j.If, triggers, repo)
	byAgent := map[string]*hit{}
	for i, st := range j.Steps {
		agent, via, gate, detail, keyInputs := identifyStep(st)
		if agent == "" {
			continue
		}
		h := byAgent[agent]
		if h == nil {
			h = &hit{aw: model.AgentWorkflow{Agent: agent, Via: via}, order: i}
			byAgent[agent] = h
		}
		h.steps = append(h.steps, step{gate: gate, detail: detail, cond: st.If, reach: admitted(st.If, jobReach, repo)})
		h.aw.ModelSecrets = append(h.aw.ModelSecrets, modelSecrets(st, keyInputs)...)
		h.aw.Interpolated = append(h.aw.Interpolated, interpolated(st)...)
	}
	if len(byAgent) == 0 {
		return nil
	}

	writes, tokenDefault := effectivePermissions(d, j)
	hits := make([]*hit, 0, len(byAgent))
	for _, h := range byAgent {
		hits = append(hits, h)
	}
	sort.Slice(hits, func(a, b int) bool { return hits[a].order < hits[b].order })

	out := make([]model.AgentWorkflow, 0, len(hits))
	for _, h := range hits {
		aw := h.aw
		// Several steps can run the same agent: the weakest gate that some
		// untrusted event actually reaches is the gate.
		best := -1
		var reach []string
		for _, st := range h.steps {
			if len(triggers) > 0 && len(st.reach) == 0 {
				continue
			}
			switch r := gateRank(st.gate); {
			case r > best:
				best, aw.Gate, aw.GateDetail, reach = r, st.gate, st.detail, st.reach
			case r == best:
				reach = append(reach, st.reach...)
			}
		}
		if best < 0 {
			// Untrusted events exist, and the conditions refuse non-writers on
			// every one of them.
			cond := j.If
			if len(jobReach) > 0 {
				cond = h.steps[0].cond // the job let them in; the step refused them
			}
			aw.Gate, aw.GateDetail = "closed", "if: "+stringOf(cond)
		}
		aw.UntrustedTriggers = orderedEvents(reach)
		aw.WriteScopes, aw.TokenDefault = writes, tokenDefault
		aw.ModelSecrets = dedupe(aw.ModelSecrets)
		aw.Secrets = without(jobSecrets(d, j, h.order), aw.ModelSecrets)
		aw.Interpolated = dedupe(aw.Interpolated)
		out = append(out, aw)
	}
	return out
}

// orderedEvents dedupes events into the fixed order of untrustedEvents.
func orderedEvents(events []string) []string {
	set := map[string]bool{}
	for _, e := range events {
		set[e] = true
	}
	var out []string
	for _, e := range untrustedEvents {
		if set[e] {
			out = append(out, e)
		}
	}
	return out
}

// identifyStep names the agent a step runs, if any, and the gate it applies on
// its own: "closed" for an action that refuses non-writers by default, "named"
// or "open" when its inputs admit others, "none" when nothing checks the actor.
func identifyStep(st wfStep) (agent, via, gate, detail string, modelKeys []string) {
	if st.Uses != "" {
		ref := strings.ToLower(st.Uses)
		if at := strings.Index(ref, "@"); at >= 0 {
			ref = ref[:at]
		}
		for _, a := range agentActions {
			if ref != a.repo && !strings.HasPrefix(ref, a.repo+"/") {
				continue
			}
			gate = "none"
			if a.gated {
				gate = "closed"
				if state, d := a.gate(stringMap(st.With)); state != "" {
					gate, detail = state, d
				}
			}
			return a.agent, st.Uses, gate, detail, a.modelKeys
		}
		return "", "", "", "", nil
	}
	for _, c := range agentCLIs {
		if c.re.MatchString(st.Run) {
			return c.agent, "run", "none", "", nil
		}
	}
	return "", "", "", "", nil
}

func gateRank(g string) int {
	switch g {
	case "none", "open":
		return 2
	case "named":
		return 1
	default:
		return 0
	}
}

// untrustedTriggers lists the events in on: a non-writer can fire, in a fixed
// order. on: is a single event, a list of events, or a map keyed by event.
func untrustedTriggers(on yaml.Node) []string {
	events := map[string]bool{}
	switch on.Kind {
	case yaml.ScalarNode:
		events[on.Value] = true
	case yaml.SequenceNode:
		for _, n := range on.Content {
			events[n.Value] = true
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(on.Content); i += 2 {
			events[on.Content[i].Value] = true
		}
	}
	var out []string
	for e := range events {
		out = append(out, e)
	}
	return orderedEvents(out)
}

func hasPermissions(n yaml.Node) bool { return n.Kind != 0 }

// effectivePermissions is the job's permissions block, else the workflow's;
// with neither, the token gets the org default and tokenDefault is set.
func effectivePermissions(d *wfDoc, j wfJob) (writes []string, tokenDefault bool) {
	n := j.Permissions
	if !hasPermissions(n) {
		n = d.Permissions
	}
	if !hasPermissions(n) {
		return nil, true
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Value == "write-all" {
			return []string{"all"}, false
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i+1].Value == "write" {
				writes = append(writes, n.Content[i].Value)
			}
		}
		sort.Strings(writes)
	}
	return writes, false
}

// jobSecrets are the secrets an agent starting at step index from can reach,
// sorted: the workflow and job env, its own step, and every step after it — a
// prompt-injected agent with a shell reaches those through $GITHUB_ENV,
// $GITHUB_PATH and the workspace. A secret used only before the agent ran left
// with its step.
func jobSecrets(d *wfDoc, j wfJob, from int) []string {
	var texts []string
	texts = append(texts, flatten(d.Env)...)
	texts = append(texts, flatten(j.Env)...)
	for _, st := range j.Steps[from:] {
		texts = append(texts, st.Run)
		texts = append(texts, flatten(st.Env)...)
		texts = append(texts, flatten(st.With)...)
	}
	return secretNames(texts)
}

// passedSecrets are the secrets a reusable-workflow call hands the callee, by
// the names the callee sees them under: "*" for secrets: inherit, else the
// mapping's keys. The callee's own references resolve only to what was passed.
func passedSecrets(j wfJob) []string {
	switch j.Secrets.Kind {
	case yaml.ScalarNode:
		if j.Secrets.Value == "inherit" {
			return []string{"*"}
		}
	case yaml.MappingNode:
		var names []string
		for i := 0; i+1 < len(j.Secrets.Content); i += 2 {
			names = append(names, j.Secrets.Content[i].Value)
		}
		return dedupe(names)
	}
	return nil
}

// without returns list minus the names in drop, keeping order.
func without(list, drop []string) []string {
	skip := map[string]bool{}
	for _, d := range drop {
		skip[d] = true
	}
	var out []string
	for _, s := range list {
		if !skip[s] {
			out = append(out, s)
		}
	}
	return out
}

func modelSecrets(st wfStep, keyInputs []string) []string {
	var texts []string
	with := stringMap(st.With)
	for _, k := range keyInputs {
		texts = append(texts, with[k])
	}
	for k, v := range stringMap(st.Env) {
		if modelKeyEnv[k] {
			texts = append(texts, v)
		}
	}
	return secretNames(texts)
}

// interpolated lists the untrusted event fields a step expands into the agent's
// inputs or script.
func interpolated(st wfStep) []string {
	texts := append([]string{st.Run}, flatten(st.With)...)
	var out []string
	for _, t := range texts {
		for _, m := range exprRe.FindAllStringSubmatch(t, -1) {
			out = append(out, untrustedFieldRe.FindAllString(m[1], -1)...)
		}
	}
	return out
}

func secretNames(texts []string) []string {
	var names []string
	for _, t := range texts {
		for _, m := range secretRefRe.FindAllStringSubmatch(t, -1) {
			if m[1] != "GITHUB_TOKEN" {
				names = append(names, m[1])
			}
		}
	}
	return dedupe(names)
}

// localCallee resolves a same-repository reusable workflow reference
// ("./.github/workflows/x.yml") to the file name the collector keys it by.
func localCallee(uses string) (string, bool) {
	if !strings.HasPrefix(uses, "./") {
		return "", false
	}
	return path.Base(uses), true
}

// stringMap renders a YAML mapping's values as strings; env: may also be a
// single expression, which yields an empty map.
func stringMap(v any) map[string]string {
	out := map[string]string{}
	if m, ok := v.(map[string]any); ok {
		for k, val := range m {
			out[k] = fmt.Sprint(val)
		}
	}
	return out
}

// flatten renders a YAML value as the strings it contains.
func flatten(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case map[string]any:
		var out []string
		for _, val := range t {
			out = append(out, flatten(val)...)
		}
		return out
	case []any:
		var out []string
		for _, val := range t {
			out = append(out, flatten(val)...)
		}
		return out
	default:
		return []string{fmt.Sprint(t)}
	}
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
