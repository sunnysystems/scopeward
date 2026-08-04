package score

import (
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

// TestKindAndVolumeDoNotMoveTheScore pins the contract of the first step of the
// score-model redesign (#39): classification and volume are recorded, and
// nothing consumes them yet.
//
// The redesign's whole risk is that adopters cannot tell why their number moved.
// Landing the metadata inert means the reweighting arrives as one reviewable
// change later, instead of leaking in ahead of the model that explains it.
func TestKindAndVolumeDoNotMoveTheScore(t *testing.T) {
	base := []model.Finding{
		{CheckID: "a", Severity: model.SevCritical, Axis: model.AxisCodeSecurity},
		{CheckID: "b", Severity: model.SevHigh, Axis: model.AxisTeams},
		{CheckID: "c", Severity: model.SevMedium, Axis: model.AxisIdentity},
		{CheckID: "d", Severity: model.SevLow, Axis: model.AxisHygiene},
	}

	// The same findings, each standing for a large backlog.
	withVolume := make([]model.Finding, len(base))
	copy(withVolume, base)
	for i := range withVolume {
		withVolume[i].Volume = 99
	}

	want, got := Grade(base, Scale{}), Grade(withVolume, Scale{})
	if want.Penalty != got.Penalty || want.Value != got.Value || want.Grade != got.Grade {
		t.Errorf("volume already moves the score: %d/%s (penalty %d) vs %d/%s (penalty %d).\n"+
			"Step 1 of #39 records the data; the weight function lands with the model that explains it.",
			want.Value, want.Grade, want.Penalty, got.Value, got.Grade, got.Penalty)
	}
}

// TestSeverityWeightsUnchanged guards the transition baseline. Every number in
// the epic's worked example, and every adopter's current score, is computed from
// these; a quiet edit here would make the v1-versus-v2 comparison meaningless
// before it is ever drawn.
func TestSeverityWeightsUnchanged(t *testing.T) {
	want := map[model.Severity]int{
		model.SevCritical: 25,
		model.SevHigh:     12,
		model.SevMedium:   5,
		model.SevLow:      2,
		model.SevInfo:     0,
	}
	for sev, w := range want {
		if got := severityWeight[sev]; got != w {
			t.Errorf("%s weighs %d, baseline is %d", sev, got, w)
		}
	}
	if halfLife != 100.0 {
		t.Errorf("halfLife is %v, baseline is 100", halfLife)
	}
}
