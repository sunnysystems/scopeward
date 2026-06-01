// Package score turns a set of findings into a transparent governance score.
//
// Each finding adds a fixed penalty by severity; the penalty maps to a 0..100
// score through a smooth decay, score = 100 / (1 + penalty/halfLife), which
// halves the score for every halfLife penalty points. This degrades gracefully
// — a heavily-flagged org lands low but never cliffs to a flat 0, so scores stay
// comparable instead of all saturating. The breakdown (penalty per axis, counts
// per severity) is returned so the score is never a black box.
package score

import (
	"math"

	"github.com/sunnysystems/scopeward/internal/model"
)

// halfLife is the penalty at which the score is halved (100 → 50). Chosen so a
// handful of high findings dents the score meaningfully without saturating.
const halfLife = 100.0

// severityWeight is the score penalty per finding at each severity.
var severityWeight = map[model.Severity]int{
	model.SevCritical: 25,
	model.SevHigh:     12,
	model.SevMedium:   5,
	model.SevLow:      2,
	model.SevInfo:     0,
}

// Score is the computed governance score with its supporting breakdown.
type Score struct {
	Value      int                    `json:"value"` // 0..100
	Grade      string                 `json:"grade"` // A..F
	Penalty    int                    `json:"penalty"`
	BySeverity map[model.Severity]int `json:"by_severity"` // finding counts
	ByAxis     map[model.Axis]int     `json:"by_axis"`     // penalty per axis
}

// Grade computes the score from findings.
func Grade(findings []model.Finding) Score {
	s := Score{
		Value:      100,
		BySeverity: map[model.Severity]int{},
		ByAxis:     map[model.Axis]int{},
	}
	for _, f := range findings {
		w := severityWeight[f.Severity]
		s.Penalty += w
		s.BySeverity[f.Severity]++
		s.ByAxis[f.Axis] += w
	}
	s.Value = int(math.Round(100 / (1 + float64(s.Penalty)/halfLife)))
	s.Grade = letter(s.Value)
	return s
}

func letter(v int) string {
	switch {
	case v >= 90:
		return "A"
	case v >= 75:
		return "B"
	case v >= 60:
		return "C"
	case v >= 40:
		return "D"
	default:
		return "F"
	}
}
