package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/score"
)

func sampleAudit() Audit {
	snap := model.NewSnapshot("acme")
	snap.Org = model.Organization{Login: "acme", Name: "Acme Corp"}
	snap.CollectedAt = time.Unix(1748600000, 0).UTC()
	snap.Coverage.OK(model.DataMembers, 42)
	snap.Coverage.Missing(model.DataFineGrainedPATs, "org has not enabled the fine-grained PAT policy")

	findings := []model.Finding{
		{CheckID: "human.no-2fa", Title: "Member has 2FA disabled", Severity: model.SevHigh, Axis: model.AxisIdentity,
			Resource:    model.ResourceRef{Type: "member", Name: "bob", URL: "https://github.com/bob"},
			Description: "Soft target.", Remediation: "Enable 2FA.", Evidence: map[string]any{"login": "bob"}, DocsURL: "https://docs.github.com/x"},
		{CheckID: "ai.agent-broad-write", Title: "Agent commits with broad write", Severity: model.SevHigh, Axis: model.AxisAIAgents,
			Resource: model.ResourceRef{Type: "agent", Name: "ai-refactor[bot]"}, Description: "Big blast radius."},
		{CheckID: "ai.agent-inventory", Title: "3 machine identities committed code", Severity: model.SevInfo, Axis: model.AxisAIAgents,
			Resource: model.ResourceRef{Type: "org", Name: "acme"}, Description: "Inventory."},
	}
	skipped := []check.Skipped{{CheckID: "nonhuman.pat-no-expiry", Title: "Non-expiring PATs", Axis: model.AxisNonHuman, Missing: []model.DataKind{model.DataFineGrainedPATs}}}

	return Audit{Snapshot: snap, Report: check.Report{Findings: findings, Skipped: skipped}, Score: score.Grade(findings)}
}

func TestHTMLContainsKeySections(t *testing.T) {
	var sb strings.Builder
	if err := HTML(&sb, sampleAudit()); err != nil {
		t.Fatalf("HTML render: %v", err)
	}
	out := sb.String()

	for _, want := range []string{
		"<!doctype html>",
		"scopeward",
		"Acme Corp (acme)",
		"grade " + score.Grade(sampleAudit().Report.Findings).Grade,
		"Human Identity", // axis section title
		"AI Agents",
		"Member has 2FA disabled",
		"ai-refactor[bot]",
		"Not evaluated",
		"fine-grained PAT policy", // coverage reason
		"no data left your machine",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}

	// Must be self-contained: no external stylesheet/script references.
	if strings.Contains(out, "<link") || strings.Contains(out, "src=") {
		t.Error("HTML report references external assets; must be self-contained")
	}

	// Write a copy for manual inspection when running with -v.
	if testing.Verbose() {
		p := filepath.Join(os.TempDir(), "scopeward-report.html")
		_ = os.WriteFile(p, []byte(out), 0o644)
		t.Logf("wrote sample report to %s", p)
	}
}
