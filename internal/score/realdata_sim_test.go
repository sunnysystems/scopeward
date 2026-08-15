package score

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

// TestAgainstRealOrgSnapshot replays #27's dogfooding scenario against a real
// organization's finding distribution, when one is supplied:
//
//	SCOPEWARD_SIM_REPORT=report.json go test ./internal/score/ -run RealOrg -v
//
// Skipped otherwise, so CI never depends on data that is not in the repository.
// It exists because the synthetic tests prove the invariant on numbers chosen to
// prove it; a real org's mix of severities and repositories is the case that
// actually bit.
func TestAgainstRealOrgSnapshot(t *testing.T) {
	path := os.Getenv("SCOPEWARD_SIM_REPORT")
	if path == "" {
		t.Skip("set SCOPEWARD_SIM_REPORT to a --format json report to replay it")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Findings []model.Finding `json:"findings"`
		Score    struct {
			ActiveRepos int `json:"active_repos"`
		} `json:"score"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	repos := payload.Score.ActiveRepos
	if repos == 0 {
		t.Skip("report carries no repository denominator")
	}

	// "After": the org as it is today, fully instrumented.
	after := Grade(payload.Findings, Scale{ActiveRepos: repos})

	dark := func(f model.Finding) model.Finding {
		return model.Finding{
			CheckID: alertsOff, Severity: model.SevMedium, Kind: model.KindCoverage,
			Axis: f.Axis, Resource: f.Resource,
		}
	}

	// "Before": the campaign #27 actually observed — Dependabot off across the
	// whole organization, then switched on everywhere. Every repository that
	// reports alerts today goes dark, and so do the ones that report none: a
	// repository instrumented and clean leaves no finding in the report, but it
	// was dark before the campaign too, and it is in the denominator either way.
	var before []model.Finding
	alerting := 0
	for _, f := range payload.Findings {
		if f.CheckID != alertsOpen {
			before = append(before, f)
			continue
		}
		alerting++
		before = append(before, dark(f))
	}
	for i := alerting; i < repos; i++ {
		before = append(before, dark(model.Finding{
			Axis: model.AxisCodeSecurity,
			Resource: model.ResourceRef{
				Type: "repo",
				Name: fmt.Sprintf("clean-and-instrumented-%d", i),
			},
		}))
	}
	b := Grade(before, Scale{ActiveRepos: repos})

	t.Logf("before enabling Dependabot: score %d (penalty %d, %d estimated)", b.Value, b.Penalty, b.Estimated)
	t.Logf("after  enabling Dependabot: score %d (penalty %d, %d estimated)", after.Value, after.Penalty, after.Estimated)

	// The real content of this assertion, now that debt carries volume: it asks
	// whether one critical finding per dark repository still covers what this
	// organization's repositories actually hold on average. If an org's alert
	// backlogs are dense enough that the average repository is worth more than
	// the floor, the floor is too low for it and #27 is back — on that org, on
	// its real numbers, which is the only way we would find out.
	if after.Penalty > b.Penalty {
		t.Errorf("on real data, enabling monitoring across the org raised the penalty %d → %d:"+
			" volume-weighted debt has outgrown the unknown floor of one critical per dark repo",
			b.Penalty, after.Penalty)
	}

	// The partial rewind: only the repositories that report alerts today go
	// dark, so every repository the estimator can observe is clean by
	// construction while every repository it must price is dirty. No
	// evidence-based estimate survives that, and the alternative — pricing every
	// dark repository at the volume cap — was measured and rejected (see
	// unknownFloor). Reported, never asserted: it is the shape of the known hole,
	// and worth seeing on real data.
	partial := before[:0:0]
	for _, f := range payload.Findings {
		if f.CheckID == alertsOpen {
			partial = append(partial, dark(f))
			continue
		}
		partial = append(partial, f)
	}
	p := Grade(partial, Scale{ActiveRepos: repos})
	t.Logf("partial rewind (%d dark, all of them dirty, the rest clean): penalty %d → %d (%+d)",
		alerting, p.Penalty, after.Penalty, after.Penalty-p.Penalty)
}
