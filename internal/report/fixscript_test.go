package report

import (
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func TestFixScript(t *testing.T) {
	snap := model.NewSnapshot("acme")
	twoFA := "gh api -X PATCH orgs/acme -F two_factor_requirement_enabled=true"
	pushProt := "gh api -X PATCH repos/acme/api -F 'security_and_analysis[secret_scanning_push_protection][status]=enabled'"
	findings := []model.Finding{
		// Same org-wide command flagged by two findings → must appear once.
		{CheckID: "human.no-2fa", Title: "bob no 2fa", Severity: model.SevHigh, Resource: model.ResourceRef{Name: "bob"}, GHFix: twoFA},
		{CheckID: "human.org-2fa-not-enforced", Title: "org 2fa off", Severity: model.SevHigh, Resource: model.ResourceRef{Name: "acme"}, GHFix: twoFA},
		// No command → omitted.
		{CheckID: "human.owner-sprawl", Title: "too many owners", Severity: model.SevMedium, Resource: model.ResourceRef{Name: "acme"}},
		// Distinct repo-level command.
		{CheckID: "codesecurity.repo-no-push-protection", Title: "pp off", Severity: model.SevHigh, Resource: model.ResourceRef{Name: "acme/api"}, GHFix: pushProt},
	}

	var sb strings.Builder
	FixScript(&sb, Audit{Snapshot: snap, Report: check.Report{Findings: findings}})
	out := sb.String()

	if !strings.HasPrefix(out, "#!/usr/bin/env bash") {
		t.Error("missing shebang")
	}
	// Every gh command must be commented out (no active command line).
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "gh ") {
			t.Errorf("found an uncommented command: %q", line)
		}
	}
	// The shared 2FA command appears exactly once despite two findings.
	if n := strings.Count(out, twoFA); n != 1 {
		t.Errorf("2FA command appears %d times, want 1 (deduped)", n)
	}
	// Both affected resources for the deduped command are listed.
	if !strings.Contains(out, "- bob") || !strings.Contains(out, "- acme") {
		t.Error("deduped command should list both affected findings")
	}
	// The owner-sprawl finding (no GHFix) must not appear.
	if strings.Contains(out, "owner-sprawl") {
		t.Error("findings without a command must be omitted")
	}
	if !strings.Contains(out, pushProt) {
		t.Error("repo-level command missing")
	}
}

// The script must declare the scopes its commands need and name the ones this
// token is missing, rather than letting the operator discover them one failed
// command at a time — several of these endpoints answer 404, not 403.
func TestFixScriptDeclaresTokenScopes(t *testing.T) {
	findings := []model.Finding{
		{CheckID: "teams.unprotected-default-branch", Severity: model.SevHigh, Resource: model.ResourceRef{Name: "acme/api"},
			GHFix: "gh api -X PUT repos/acme/api/branches/main/protection", GHScopes: []string{"repo"}},
		{CheckID: "teams.base-permission-open", Severity: model.SevHigh, Resource: model.ResourceRef{Name: "acme"},
			GHFix: "gh api -X PATCH orgs/acme -F default_repository_permission=read", GHScopes: []string{"admin:org"}},
	}
	base := Audit{Snapshot: model.NewSnapshot("acme"), Report: check.Report{Findings: findings}}

	t.Run("missing scope is called out", func(t *testing.T) {
		a := base
		a.TokenScopes = []string{"repo", "read:org"}
		var sb strings.Builder
		FixScript(&sb, a)
		out := sb.String()

		for _, want := range []string{
			"needs these token scopes: admin:org, repo",
			"Your token has: repo, read:org",
			"Missing — blocks marked below will fail: admin:org",
			"404", // the trap: a missing scope reads as "not found"
		} {
			if !strings.Contains(out, want) {
				t.Errorf("header missing %q", want)
			}
		}
		// Only the block the token cannot run is marked.
		if n := strings.Count(out, "YOUR TOKEN LACKS THIS"); n != 1 {
			t.Errorf("marked %d blocks as failing, want 1 (only admin:org)", n)
		}
	})

	t.Run("sufficient token is told so", func(t *testing.T) {
		a := base
		a.TokenScopes = []string{"repo", "admin:org"}
		var sb strings.Builder
		FixScript(&sb, a)
		out := sb.String()
		if !strings.Contains(out, "Nothing missing") {
			t.Error("a token holding every scope should be told nothing is missing")
		}
		if strings.Contains(out, "YOUR TOKEN LACKS THIS") {
			t.Error("no block should be marked as failing")
		}
	})

	// A fine-grained PAT or App token reports no scopes. Absent scopes must read
	// as unknown, never as missing — claiming a block will fail when we cannot
	// tell is worse than saying nothing.
	t.Run("unknown scopes are not reported as missing", func(t *testing.T) {
		a := base
		a.TokenScopesUnknown = true
		var sb strings.Builder
		FixScript(&sb, a)
		out := sb.String()
		if !strings.Contains(out, "could not be read") {
			t.Error("unknown scopes should be stated as unknown")
		}
		for _, unwanted := range []string{"Missing —", "YOUR TOKEN LACKS THIS"} {
			if strings.Contains(out, unwanted) {
				t.Errorf("must not claim %q when scopes are unknown", unwanted)
			}
		}
	})
}
