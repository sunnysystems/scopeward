package checks

import (
	"context"
	"testing"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func TestCIVariableUnprotected(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Provider = model.ProviderGitLab
	snap.CIVariables = []model.CIVariable{
		{Key: "SECRET_TOKEN", Kind: "group", Holder: "acme", Masked: true, Protected: false, EnvironmentScope: "*"}, // flag
		{Key: "PROD_KEY", Kind: "group", Holder: "acme", Masked: true, Protected: true},                             // protected → ok
		{Key: "BUILD_FLAG", Kind: "project", Holder: "acme/api", Masked: false, Protected: false},                   // unmasked config → ok
	}
	got := ciVariableUnprotected{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Evidence["key"] != "SECRET_TOKEN" {
		t.Fatalf("got %+v, want only the masked-but-unprotected variable", got)
	}
	if got[0].Severity != model.SevMedium {
		t.Errorf("severity = %v, want medium", got[0].Severity)
	}
}

func TestCIRunnerUnprotected(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.CIRunners = []model.CIRunner{
		{ID: 1, Description: "shared-1", RunnerType: "instance_type", Shared: true, RefProtected: false}, // shared+unprotected → high
		{ID: 2, Description: "grp-2", RunnerType: "group_type", Shared: false, RefProtected: false},      // group+unprotected → medium
		{ID: 3, Description: "grp-3", RunnerType: "group_type", Shared: false, RefProtected: true},       // ref-protected → ok
	}
	got := ciRunnerUnprotected{}.Run(context.Background(), snap)
	bySev := map[model.Severity]int{}
	byID := map[int64]bool{}
	for _, f := range got {
		bySev[f.Severity]++
		byID[f.Evidence["runner_id"].(int64)] = true
	}
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (shared + group, both unprotected)", len(got))
	}
	if bySev[model.SevHigh] != 1 || bySev[model.SevMedium] != 1 {
		t.Errorf("severities = %v, want one high (shared) + one medium (group)", bySev)
	}
	if byID[3] {
		t.Error("ref-protected runner must not be flagged")
	}
}

func TestCIJobTokenOpen(t *testing.T) {
	open := false
	enforced := true
	snap := model.NewSnapshot("acme")
	snap.Provider = model.ProviderGitLab
	snap.Host = "https://gitlab.example.com"
	snap.Repos = []model.Repo{
		{ID: 1, Name: "acme/open", JobTokenInboundEnabled: &open},       // flag
		{ID: 2, Name: "acme/locked", JobTokenInboundEnabled: &enforced}, // ok
		{ID: 3, Name: "acme/unknown"},                                   // nil → skip (unknown)
	}
	got := ciJobTokenOpen{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Evidence["repo"] != "acme/open" {
		t.Fatalf("got %+v, want only the project with the allowlist disabled", got)
	}
	if got[0].Severity != model.SevHigh {
		t.Errorf("severity = %v, want high", got[0].Severity)
	}
	if got[0].Title != "CI_JOB_TOKEN allowlist is disabled on acme/open" {
		t.Errorf("title = %q, want the full project path (not doubled)", got[0].Title)
	}
}

// TestCICDChecksGatedOnCoverage confirms the CI checks run on a GitLab snapshot
// when their coverage is present, and are skipped (not passed) when it is absent.
func TestCICDChecksGatedOnCoverage(t *testing.T) {
	open := false
	snap := model.NewSnapshot("acme")
	snap.Provider = model.ProviderGitLab
	snap.CIVariables = []model.CIVariable{{Key: "S", Kind: "group", Holder: "acme", Masked: true}}
	snap.CIRunners = []model.CIRunner{{ID: 1, Shared: true, RunnerType: "instance_type"}}
	snap.Repos = []model.Repo{{ID: 1, Name: "acme/api", JobTokenInboundEnabled: &open}}
	snap.Coverage.OK(model.DataCIVariables, 1)
	snap.Coverage.OK(model.DataCIRunners, 1)
	snap.Coverage.OK(model.DataJobTokenScope, 1)
	snap.Coverage.OK(model.DataRepos, 1)

	rep := check.Run(context.Background(), snap, check.All())
	found := map[string]bool{}
	for _, f := range rep.Findings {
		found[f.CheckID] = true
	}
	for _, want := range []string{"nonhuman.ci-variable-unprotected", "nonhuman.ci-runner-unprotected", "nonhuman.ci-job-token-open"} {
		if !found[want] {
			t.Errorf("expected %q to fire on the GitLab snapshot", want)
		}
	}

	// Without coverage the checks must be skipped, never a false pass.
	bare := model.NewSnapshot("acme")
	bare.Provider = model.ProviderGitLab
	bare.CIRunners = snap.CIRunners
	rep2 := check.Run(context.Background(), bare, check.All())
	skipped := map[string]bool{}
	for _, sk := range rep2.Skipped {
		skipped[sk.CheckID] = true
	}
	if !skipped["nonhuman.ci-runner-unprotected"] {
		t.Error("ci-runner check should be not-evaluated without DataCIRunners coverage")
	}
	for _, f := range rep2.Findings {
		if f.CheckID == "nonhuman.ci-runner-unprotected" {
			t.Error("ci-runner check must not run without coverage")
		}
	}
}
