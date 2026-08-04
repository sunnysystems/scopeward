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
	// Four active repos and one archived: the score normalizes by the active
	// count, so the fixture has to carry one for the rate to be exercised at all.
	snap.Repos = []model.Repo{{Name: "api"}, {Name: "web"}, {Name: "docs"}, {Name: "infra"}, {Name: "retired", Archived: true}}
	snap.Coverage.Missing(model.DataFineGrainedPATs, "org has not enabled the fine-grained PAT policy")

	findings := []model.Finding{
		{CheckID: "human.no-2fa", Title: "Member has 2FA disabled", Severity: model.SevHigh, Axis: model.AxisIdentity, Kind: model.KindDebt,
			Resource:    model.ResourceRef{Type: "member", Name: "bob", URL: "https://github.com/bob"},
			Description: "Soft target.", Remediation: "Enable 2FA.", Evidence: map[string]any{"login": "bob"}, DocsURL: "https://docs.github.com/x"},
		{CheckID: "ai.agent-broad-write", Title: "Agent commits with broad write", Severity: model.SevHigh, Axis: model.AxisAIAgents, Kind: model.KindDebt,
			Resource: model.ResourceRef{Type: "agent", Name: "ai-refactor[bot]"}, Description: "Big blast radius."},
		// Repo-scoped and volume-bearing, so the golden files lock the two things
		// the score model reads: the rate denominator and the collapsed count.
		{CheckID: "codesecurity.open-dependabot-alerts", Title: "acme/api has 42 open Dependabot alert(s)",
			Severity: model.SevCritical, Axis: model.AxisCodeSecurity, Kind: model.KindDebt, Volume: 42,
			Resource: model.ResourceRef{Type: "repo", Name: "acme/api"}, Description: "Known-vulnerable dependencies."},
		{CheckID: "codesecurity.repo-no-push-protection", Title: "Push protection is off on acme/api",
			Severity: model.SevMedium, Axis: model.AxisCodeSecurity, Kind: model.KindCoverage,
			Resource: model.ResourceRef{Type: "repo", Name: "acme/api"}, Description: "Secrets are only caught after the push."},
		{CheckID: "ai.agent-inventory", Title: "3 machine identities committed code", Severity: model.SevInfo, Axis: model.AxisAIAgents, Kind: model.KindDebt,
			Resource: model.ResourceRef{Type: "org", Name: "acme"}, Description: "Inventory."},
	}
	skipped := []check.Skipped{{CheckID: "nonhuman.pat-no-expiry", Title: "Non-expiring PATs", Axis: model.AxisNonHuman, Missing: []model.DataKind{model.DataFineGrainedPATs}}}
	// A check that ran but not over everything it covers. Present in the fixture
	// so the golden files lock the rendering of the partially-evaluated state in
	// every format, not just its existence in the struct.
	limited := []check.Limitation{{
		CheckID: "codesecurity.repo-no-push-protection", Title: "Repos without push protection",
		Axis:     model.AxisCodeSecurity,
		Reason:   "private repositories require GitHub Secret Protection, which this organization does not have",
		Assessed: 3, Omitted: 39,
	}}

	return Audit{Snapshot: snap, Report: check.Report{Findings: findings, Skipped: skipped, Limited: limited}, Score: score.Grade(findings, score.Scale{ActiveRepos: snap.ActiveRepoCount()})}
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
		"grade " + sampleAudit().Score.Grade, // the rendered grade, not one recomputed at a different scale
		"Human Identity",                     // axis section title
		"AI Agents",
		"Member has 2FA disabled",
		"ai-refactor[bot]",
		"Not evaluated",
		"fine-grained PAT policy", // coverage reason
		"Built by Sunny Systems",
		"products/scopeward",     // footer product link
		"data:image/png;base64,", // Sunny logo embedded, not fetched
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}

	// Fully self-contained: an inline filter script is allowed, but nothing may be
	// fetched over the network — no external scripts, stylesheets, or assets. The
	// Sunny logo is embedded as a data URI. (href links are fine; they are
	// user-clicked, not auto-loaded on open.)
	if strings.Contains(out, "<script src") || strings.Contains(out, "<link") {
		t.Error("HTML report must not pull external scripts or stylesheets")
	}
	if strings.Contains(out, `src="http`) {
		t.Error("HTML report must not fetch remote assets; embed them as data URIs instead")
	}

	// Write a copy for manual inspection when running with -v.
	if testing.Verbose() {
		p := filepath.Join(os.TempDir(), "scopeward-report.html")
		_ = os.WriteFile(p, []byte(out), 0o644)
		t.Logf("wrote sample report to %s", p)
	}
}
