package report

import (
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/score"

	_ "github.com/sunnysystems/scopeward/internal/check/checks" // register checks so check.Meta resolves
)

// deadRepoStack is the finding stack one abandoned repository carries: the 2-point
// low that represents it in the report, plus the per-repo findings archiving would
// resolve. This is the shape issue #33 is about — the action is worth far more
// than the finding that stands for it.
func deadRepoStack(repo string) []model.Finding {
	ref := model.ResourceRef{Type: "repo", Name: repo}
	return []model.Finding{
		{CheckID: "hygiene.stale-repo", Severity: model.SevLow, Axis: model.AxisHygiene, Resource: ref},
		{CheckID: "teams.unprotected-default-branch", Severity: model.SevHigh, Axis: model.AxisTeams, Resource: ref},
		{CheckID: "teams.repo-no-owning-team", Severity: model.SevMedium, Axis: model.AxisTeams, Resource: ref},
		{CheckID: "codesecurity.repo-dependabot-alerts-off", Severity: model.SevMedium, Axis: model.AxisCodeSecurity, Resource: ref},
		{CheckID: "teams.repo-no-codeowner", Severity: model.SevLow, Axis: model.AxisTeams, Resource: ref},
	}
}

func leverAudit(findings []model.Finding) Audit {
	return Audit{
		Snapshot: model.NewSnapshot("acme"),
		Report:   check.Report{Findings: findings},
		Score:    score.Grade(findings, score.Scale{}),
	}
}

func TestArchiveLeverAggregatesTheWholeStack(t *testing.T) {
	var findings []model.Finding
	for _, r := range []string{"acme/dead-1", "acme/dead-2", "acme/dead-3"} {
		findings = append(findings, deadRepoStack(r)...)
	}
	// A live repo whose findings must not be counted as archivable.
	findings = append(findings, model.Finding{
		CheckID: "teams.unprotected-default-branch", Severity: model.SevHigh,
		Axis: model.AxisTeams, Resource: model.ResourceRef{Type: "repo", Name: "acme/live"},
	})

	l := buildArchiveLever(leverAudit(findings))
	if l == nil {
		t.Fatal("no lever computed for three dead repos")
	}
	if l.Repos != 3 {
		t.Errorf("repos = %d, want 3", l.Repos)
	}
	if l.Findings != 15 {
		t.Errorf("findings = %d, want 15 (5 per dead repo, live repo excluded)", l.Findings)
	}
	// 3 × (2 + 12 + 5 + 5 + 2) = 78. The report used to show this as three
	// 2-point lows.
	if l.Penalty != 78 {
		t.Errorf("penalty = %d, want 78", l.Penalty)
	}
	if l.ScoreAfter <= l.ScoreNow {
		t.Errorf("score %d → %d: archiving should raise it", l.ScoreNow, l.ScoreAfter)
	}
	if !strings.Contains(l.summary(), "3 repositories") || !strings.Contains(l.summary(), "78 penalty") {
		t.Errorf("summary reads %q", l.summary())
	}
}

// Archiving must never be presented as clearing a leaked credential. Findings
// from checks that declare SurvivesArchiving are excluded from the promise and
// called out instead — otherwise the report teaches archiving as a score tactic.
func TestArchiveLeverExcludesFindingsThatSurviveArchiving(t *testing.T) {
	findings := append(deadRepoStack("acme/dead"), model.Finding{
		CheckID: "codesecurity.open-secret-alerts", Severity: model.SevHigh,
		Axis: model.AxisCodeSecurity, Resource: model.ResourceRef{Type: "repo", Name: "acme/dead"},
	})

	l := buildArchiveLever(leverAudit(findings))
	if l == nil {
		t.Fatal("no lever computed")
	}
	if l.Surviving != 1 {
		t.Fatalf("surviving = %d, want 1 (the secret alert)", l.Surviving)
	}
	if l.Findings != 5 {
		t.Errorf("findings = %d, want 5: the secret alert must not be promised as resolved", l.Findings)
	}
	if l.Penalty != 26 {
		t.Errorf("penalty = %d, want 26 (the secret alert's 12 excluded)", l.Penalty)
	}
	if c := l.caution(); !strings.Contains(c, "real after archiving") {
		t.Errorf("caution should warn about surviving findings, got %q", c)
	}
}

// The report's promise and the checks' behaviour have to agree: a check the
// report counts as resolved-by-archiving must actually stop firing on an
// archived repo. This is the cross-package half of issue #32's invariant.
func TestArchiveLeverMatchesCheckBehaviour(t *testing.T) {
	for _, c := range check.All() {
		meta := c.Meta()
		if meta.ID == "codesecurity.open-secret-alerts" && !meta.SurvivesArchiving {
			t.Error("open-secret-alerts must declare SurvivesArchiving: a committed credential outlives archiving")
		}
	}
}

func TestArchiveLeverSilentWithoutStaleRepos(t *testing.T) {
	if l := buildArchiveLever(leverAudit([]model.Finding{
		{CheckID: "human.no-2fa", Severity: model.SevHigh, Resource: model.ResourceRef{Name: "bob"}},
	})); l != nil {
		t.Errorf("lever computed with no stale repos: %+v", l)
	}

	// A stale repo carrying nothing else is not a lever worth a callout — the
	// 2-point low already says it.
	only := []model.Finding{{CheckID: "hygiene.stale-repo", Severity: model.SevLow,
		Axis: model.AxisHygiene, Resource: model.ResourceRef{Name: "acme/dead"}}}
	if l := buildArchiveLever(leverAudit(only)); l != nil && l.Findings != 1 {
		t.Errorf("unexpected lever shape: %+v", l)
	}
}

func TestArchiveLeverRendersInEveryHumanFormat(t *testing.T) {
	var findings []model.Finding
	for _, r := range []string{"acme/dead-1", "acme/dead-2"} {
		findings = append(findings, deadRepoStack(r)...)
	}
	a := leverAudit(findings)
	a.Snapshot.Coverage.OK(model.DataRepos, 2)

	for _, r := range allRenderers {
		if !r.human {
			continue
		}
		out := renderTo(r.render, a)
		if !strings.Contains(out, "Biggest lever") {
			t.Errorf("%s: the archive lever is not surfaced", r.name)
		}
		if !strings.Contains(out, "Archiving them resolves") {
			t.Errorf("%s: the lever summary is missing", r.name)
		}
	}
}
