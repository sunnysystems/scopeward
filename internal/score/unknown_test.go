package score

import (
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

const (
	alertsOff  = "codesecurity.repo-dependabot-alerts-off"
	alertsOpen = "codesecurity.open-dependabot-alerts"
)

func ctrlOff(repo string) model.Finding {
	return model.Finding{
		CheckID: alertsOff, Severity: model.SevMedium, Kind: model.KindCoverage,
		Axis: model.AxisCodeSecurity, Resource: model.ResourceRef{Type: "repo", Name: repo},
	}
}

func openAlerts(repo string, sev model.Severity) model.Finding {
	return model.Finding{
		CheckID: alertsOpen, Severity: sev, Kind: model.KindDebt,
		Axis: model.AxisCodeSecurity, Resource: model.ResourceRef{Type: "repo", Name: repo},
	}
}

// TestEnablingAControlNeverRaisesThePenalty is issue #27 stated as an invariant
// rather than as a hope about calibration.
//
// The scenario is the one observed while dogfooding: an org with some
// instrumented repositories carrying real CVEs, and some repositories with
// alerts switched off. Turning the remaining controls on reveals debt that was
// always there. The vulnerabilities do not change; only visibility does, and the
// penalty must not go up for the act of looking.
func TestEnablingAControlNeverRaisesThePenalty(t *testing.T) {
	const repos = 10

	// Five instrumented repos, each carrying a critical backlog; five with the
	// control off.
	before := []model.Finding{}
	for i := 0; i < 5; i++ {
		before = append(before, openAlerts("instrumented", model.SevCritical))
	}
	for i := 0; i < 5; i++ {
		before = append(before, ctrlOff("dark"))
	}

	// After: the five dark repos get the control enabled and turn out to hold
	// exactly what the instrumented ones do.
	after := []model.Finding{}
	for i := 0; i < 10; i++ {
		after = append(after, openAlerts("now-visible", model.SevCritical))
	}

	b := Grade(before, Scale{ActiveRepos: repos})
	a := Grade(after, Scale{ActiveRepos: repos})

	if a.Penalty > b.Penalty {
		t.Errorf("enabling monitoring raised the penalty %d → %d: the tool is still rewarding blindness",
			b.Penalty, a.Penalty)
	}
	if b.Estimated == 0 {
		t.Error("the disabled controls should have been priced from the observed rate, and the estimate disclosed")
	}
}

// TestACleanSampleDoesNotPriceTheUnsampled records a belief this test suite got
// wrong first, because the mistake is the easy one to make twice.
//
// The obvious reading of "estimate from the org's own rate" is that an org whose
// instrumented repositories are clean should pay nothing for the ones it cannot
// see. That is wrong, and replaying a real organization's report proved it: with
// the rate alone, enabling Dependabot moved the penalty from 149 to 208 — #27,
// unfixed, in the single most common shape. A clean sample says nothing about
// the repositories nobody sampled.
//
// So the observed rate can only raise the price above the floor, never below it.
func TestACleanSampleDoesNotPriceTheUnsampled(t *testing.T) {
	clean := Grade([]model.Finding{ctrlOff("dark")}, Scale{ActiveRepos: 3})
	if clean.Estimated == 0 {
		t.Error("a dark repository must be priced even when the visible ones are clean")
	}

	// An org carrying more than one critical's worth per instrumented repo prices
	// its dark repos above the floor: its own evidence is worse than the default
	// assumption.
	heavy := []model.Finding{ctrlOff("dark")}
	for i := 0; i < 4; i++ {
		heavy = append(heavy, openAlerts("a", model.SevCritical))
	}
	loaded := Grade(heavy, Scale{ActiveRepos: 3})
	if loaded.Estimated <= clean.Estimated {
		t.Errorf("an org with heavy observed debt should price the unknown higher: %d vs %d",
			loaded.Estimated, clean.Estimated)
	}
}

// TestNoInstrumentedRepoFallsBackToThePrior: with every repository dark there is
// no rate to learn from, and the fallback must still be large enough that
// enabling the first control cannot raise the penalty.
func TestNoInstrumentedRepoFallsBackToThePrior(t *testing.T) {
	const repos = 3
	allDark := []model.Finding{ctrlOff("a"), ctrlOff("b"), ctrlOff("c")}
	before := Grade(allDark, Scale{ActiveRepos: repos})

	// One repo gets the control enabled and turns out to hold a critical backlog.
	after := Grade([]model.Finding{
		openAlerts("a", model.SevCritical), ctrlOff("b"), ctrlOff("c"),
	}, Scale{ActiveRepos: repos})

	if after.Penalty > before.Penalty {
		t.Errorf("with no prior observation, looking still cost points: %d → %d",
			before.Penalty, after.Penalty)
	}
	if before.Estimated == 0 {
		t.Error("an org with nothing instrumented is entirely estimated and must say so")
	}
}

// TestUnpairedCoverageChecksAreNotEstimated: only controls that genuinely hide
// pre-existing debt get an estimate. Push protection blocks future commits and
// reveals nothing, so pricing it would invent a cost.
func TestUnpairedCoverageChecksAreNotEstimated(t *testing.T) {
	got := Grade([]model.Finding{
		{CheckID: "codesecurity.repo-no-push-protection", Severity: model.SevMedium,
			Kind: model.KindCoverage, Resource: model.ResourceRef{Type: "repo", Name: "a"}},
		openAlerts("b", model.SevCritical),
	}, Scale{ActiveRepos: 4})

	if got.Estimated != 0 {
		t.Errorf("an unpaired control was priced as if it hid debt: %d", got.Estimated)
	}
}

// TestEstimateOnlyEverRaises: the mechanism prices the unknown up, never down.
// A control-off finding must always cost at least its own severity weight, so a
// low observed rate can never turn into a discount.
func TestEstimateOnlyEverRaises(t *testing.T) {
	f := []model.Finding{ctrlOff("dark"), openAlerts("a", model.SevLow)}
	got := Grade(f, Scale{ActiveRepos: 10})

	base := float64(severityWeight[model.SevMedium]) // the finding's own weight
	if float64(got.PenaltyAbsolute) < base {
		t.Errorf("penalty %d fell below the finding's own weight %v", got.PenaltyAbsolute, base)
	}
	if got.Estimated <= 0 {
		t.Error("a dark repo is priced at the floor, and that pricing must be disclosed")
	}
}

// TestEstimateRequiresADenominator: with the per-repo pass skipped there is no
// instrumented count, so there is nothing to estimate from and nothing may be
// invented.
func TestEstimateRequiresADenominator(t *testing.T) {
	got := Grade([]model.Finding{ctrlOff("a"), openAlerts("b", model.SevCritical)}, Scale{})
	if got.Estimated != 0 {
		t.Errorf("estimated %d without a denominator", got.Estimated)
	}
}
