package checks

import (
	"context"
	"strconv"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(ciVariableUnprotected{})
	check.Register(ciRunnerUnprotected{})
	check.Register(ciJobTokenOpen{})
}

// ciVariableUnprotected flags GitLab CI/CD variables that were masked (i.e.
// treated as secrets) but are not protected, so they are injected into pipelines
// on any branch or tag — including ones an attacker or low-trust contributor can
// create — where masking is trivial to bypass and the secret can be exfiltrated.
type ciVariableUnprotected struct{}

func (ciVariableUnprotected) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.ci-variable-unprotected",
		Title:           "Unprotected CI/CD secret variables",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevMedium,
		Kind:            check.KindDebt,
		RequiresData:    []model.DataKind{model.DataCIVariables},
		Description:     "Masked CI/CD variables that are not protected, so they are exposed to pipelines on unprotected branches and tags.",
	}
}

func (c ciVariableUnprotected) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, v := range s.CIVariables {
		// Masking marks a value as secret; an unprotected masked variable is the
		// real exposure. Unmasked variables are usually plain config, so we don't
		// flag them (avoids noise on non-secret values).
		if !v.Masked || v.Protected {
			continue
		}
		scope := v.EnvironmentScope
		if scope == "" {
			scope = "*"
		}
		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    v.Kind + " CI/CD variable " + v.Key + " is masked but not protected (" + v.Holder + ")",
			Severity: model.SevMedium,
			Axis:     model.AxisNonHuman,
			Resource: model.ResourceRef{Type: "ci_variable", Name: v.Holder + " / " + v.Key},
			Evidence: map[string]any{
				"key": v.Key, "kind": v.Kind, "holder": v.Holder, "scope_id": v.ScopeID,
				"masked": v.Masked, "protected": v.Protected, "environment_scope": scope,
			},
			Description: "This variable is masked, so it is intended to be a secret, but it is not protected. Unprotected variables are passed to pipelines running on any branch or tag, so anyone who can push a branch or open a merge request can run a job that prints or exfiltrates the value (masking only hides it from logs and is easy to bypass).",
			Remediation: "Mark the variable protected so it is only available to pipelines on protected branches/tags, and narrow its environment scope. Protection only takes effect when the source and target refs are themselves protected.",
			DocsURL:     "https://docs.gitlab.com/ee/ci/variables/#cicd-variable-security",
		})
	}
	return out
}

// ciRunnerUnprotected flags runners that are not ref-protected, so they pick up
// jobs from unprotected branches and tags. A shared (instance) runner in this
// state can run untrusted pipeline code from any project on shared infrastructure.
type ciRunnerUnprotected struct{}

func (ciRunnerUnprotected) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.ci-runner-unprotected",
		Title:           "Runners usable from unprotected refs",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevMedium,
		Kind:            check.KindDebt,
		RequiresData:    []model.DataKind{model.DataCIRunners},
		Description:     "CI runners not restricted to protected branches/tags; shared runners in this state run untrusted code from any project.",
	}
}

func (c ciRunnerUnprotected) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range s.CIRunners {
		if r.RefProtected {
			continue // only runs jobs from protected refs: the safe state
		}
		sev := model.SevMedium
		kind := "group/project"
		desc := "This runner picks up jobs from unprotected branches and tags, so pipeline code on any ref a contributor can create runs on it."
		if r.Shared {
			sev = model.SevHigh
			kind = "shared (instance)"
			desc = "This shared runner picks up jobs from unprotected branches and tags across every project on the instance. Untrusted pipeline code (from a fork, a feature branch, or a low-trust project) runs on shared infrastructure, a known lateral-movement and secret-theft vector."
		}
		name := r.Description
		if name == "" {
			name = "runner #" + strconv.FormatInt(r.ID, 10)
		}
		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    kind + " runner \"" + name + "\" runs jobs from unprotected refs",
			Severity: sev,
			Axis:     model.AxisNonHuman,
			Resource: model.ResourceRef{Type: "ci_runner", ID: strconv.FormatInt(r.ID, 10), Name: name},
			Evidence: map[string]any{
				"runner_id": r.ID, "runner_type": r.RunnerType, "shared": r.Shared,
				"ref_protected": r.RefProtected, "locked": r.Locked, "holder": r.Holder, "tags": r.TagList,
			},
			Description: desc,
			Remediation: "Set the runner to run untagged/protected jobs only (enable \"Protected\" / ref_protected), scope shared runners away from low-trust projects, and prefer ephemeral runners. Protection only matters when the relevant branches/tags are themselves protected.",
			DocsURL:     "https://docs.gitlab.com/ee/ci/runners/configure_runners.html#prevent-runners-from-revealing-sensitive-information",
		})
	}
	return out
}

// ciJobTokenOpen flags projects whose CI_JOB_TOKEN inbound allowlist is disabled,
// so any other project's job token can authenticate to this project's API. This
// is the GitLab analogue of a default-write CI token: standing, broad access
// handed to automation by default.
type ciJobTokenOpen struct{}

func (ciJobTokenOpen) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.ci-job-token-open",
		Title:           "CI_JOB_TOKEN allowlist disabled",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevHigh,
		Kind:            check.KindCoverage,
		RequiresData:    []model.DataKind{model.DataJobTokenScope},
		Description:     "Projects with the CI_JOB_TOKEN inbound allowlist disabled, so any project's job token can access them.",
	}
}

func (c ciJobTokenOpen) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range activeRepos(s) {
		if r.JobTokenInboundEnabled == nil || *r.JobTokenInboundEnabled {
			continue // unknown, or the allowlist is enforced (the safe state)
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       "CI_JOB_TOKEN allowlist is disabled on " + repoDisplay(s, r),
			Severity:    model.SevHigh,
			Axis:        model.AxisNonHuman,
			Resource:    repoResource(s, r),
			Evidence:    map[string]any{"repo": r.Name, "inbound_enabled": false},
			Description: "With the inbound job-token allowlist disabled, a CI_JOB_TOKEN minted by any other project's pipeline can authenticate to this project. A single compromised pipeline anywhere on the instance gains this project's CI access, with no explicit grant — the same standing-broad-access risk as a default-write CI token.",
			Remediation: "Enable \"Limit access to this project\" (the inbound CI_JOB_TOKEN allowlist) and add only the projects whose pipelines legitimately need access.",
			DocsURL:     "https://docs.gitlab.com/ee/ci/jobs/ci_job_token.html",
		})
	}
	return out
}
