package score

import (
	"encoding/json"
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

	// "Before": rewind the remediation. Every repo carrying open Dependabot
	// alerts is put back to having the control switched off, which is what the
	// org looked like before anyone enabled it.
	var before []model.Finding
	for _, f := range payload.Findings {
		if f.CheckID != alertsOpen {
			before = append(before, f)
			continue
		}
		before = append(before, model.Finding{
			CheckID: alertsOff, Severity: model.SevMedium, Kind: model.KindCoverage,
			Axis: f.Axis, Resource: f.Resource,
		})
	}
	b := Grade(before, Scale{ActiveRepos: repos})

	t.Logf("before enabling Dependabot: score %d (penalty %d, %d estimated)", b.Value, b.Penalty, b.Estimated)
	t.Logf("after  enabling Dependabot: score %d (penalty %d, %d estimated)", after.Value, after.Penalty, after.Estimated)

	if after.Penalty > b.Penalty {
		t.Errorf("on real data, enabling monitoring still raised the penalty %d → %d", b.Penalty, after.Penalty)
	}
}
