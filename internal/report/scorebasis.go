package report

import (
	"fmt"

	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/score"
)

// scoreBasis is the one-line explanation of what the number is built from: the
// two axes it sums and the per-repository rate behind the normalization.
//
// The axes are shown because they move in opposite directions. Enabling a
// control raises coverage and reveals debt, and a reader who sees only the
// composite reads that as getting worse when they have merely started looking
// (issue #27).
//
// Shared by every renderer rather than written three times, because three
// copies of an explanation drift and the wrong one is always the one someone
// pastes into a review.
func scoreBasis(sc score.Score) string {
	cov, debt := sc.ByKind[model.KindCoverage], sc.ByKind[model.KindDebt]
	if sc.Penalty == 0 || cov+debt == 0 {
		return ""
	}
	s := fmt.Sprintf("penalty %d · %d not instrumented, %d open findings", sc.Penalty, cov, debt)
	if sc.ActiveRepos > 0 {
		s += fmt.Sprintf(" · %.1f per repo across %d repos", sc.PerRepo, sc.ActiveRepos)
	}
	return s
}

// scoreTransition names the number the previous model would have produced.
//
// This is the release that rescales the score, so the report itself says so. An
// adopter whose number jumps should not have to find the changelog to learn
// that their organization did not change.
func scoreTransition(sc score.Score) string {
	if sc.ActiveRepos == 0 || sc.ValueAbsolute == sc.Value {
		return ""
	}
	return fmt.Sprintf(
		"the previous scoring model gave %d (%s); per-repo penalty is now a rate, so the number no longer tracks org size",
		sc.ValueAbsolute, score.Letter(sc.ValueAbsolute))
}
