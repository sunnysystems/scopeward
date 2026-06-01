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
