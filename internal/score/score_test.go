package score

import (
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestGrade(t *testing.T) {
	findings := []model.Finding{
		{Severity: model.SevHigh, Axis: model.AxisIdentity},   // -12
		{Severity: model.SevHigh, Axis: model.AxisIdentity},   // -12
		{Severity: model.SevMedium, Axis: model.AxisNonHuman}, // -5
		{Severity: model.SevInfo, Axis: model.AxisIdentity},   // -0
	}

	s := Grade(findings, Scale{})

	if s.Penalty != 29 {
		t.Errorf("penalty = %d, want 29", s.Penalty)
	}
	// 100 / (1 + 29/100) = 77.5 → 78.
	if s.Value != 78 {
		t.Errorf("value = %d, want 78", s.Value)
	}
	// A under the re-derived bands (A ≥ 75). Four findings and no repository
	// denominator is a small absolute penalty, and the bands now describe an
	// exemplary org rather than a spotless one.
	if s.Grade != "A" {
		t.Errorf("grade = %q, want A", s.Grade)
	}
	if s.ByAxis[model.AxisIdentity] != 24 {
		t.Errorf("identity penalty = %d, want 24", s.ByAxis[model.AxisIdentity])
	}
	if s.BySeverity[model.SevHigh] != 2 {
		t.Errorf("high count = %d, want 2", s.BySeverity[model.SevHigh])
	}
}

func TestGrade_HeavyPenaltyStaysPositive(t *testing.T) {
	var findings []model.Finding
	for i := 0; i < 10; i++ {
		findings = append(findings, model.Finding{Severity: model.SevCritical})
	}
	s := Grade(findings, Scale{}) // 10 * 25 = 250 penalty → 100/(1+2.5) ≈ 29
	if s.Value != 29 {
		t.Errorf("value = %d, want 29", s.Value)
	}
	if s.Value <= 0 {
		t.Error("score must decay smoothly, never cliff to 0")
	}
	if s.Grade != "F" {
		t.Errorf("grade = %q, want F", s.Grade)
	}
}

// TestGrade_Monotonic confirms more/worse findings never raise the score.
func TestGrade_Monotonic(t *testing.T) {
	prev := Grade(nil, Scale{}).Value
	var findings []model.Finding
	for i := 0; i < 30; i++ {
		findings = append(findings, model.Finding{Severity: model.SevHigh})
		v := Grade(findings, Scale{}).Value
		if v > prev {
			t.Fatalf("score rose from %d to %d after adding a finding", prev, v)
		}
		prev = v
	}
	if prev <= 0 {
		t.Errorf("30 high findings → %d, want a small positive score", prev)
	}
}

func TestGrade_Clean(t *testing.T) {
	s := Grade(nil, Scale{})
	if s.Value != 100 || s.Grade != "A" {
		t.Errorf("clean audit = %d/%s, want 100/A", s.Value, s.Grade)
	}
}

// TestSeverityWeightsUnchanged guards the transition baseline. Every number in
// the score-model epic's worked example, and every adopter's current score, is
// computed from these; a quiet edit here would make the v1-versus-v2 comparison
// meaningless before it is ever drawn.
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
