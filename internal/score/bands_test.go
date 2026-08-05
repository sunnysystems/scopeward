package score

import (
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

// TestBandsMeanWhatTheyClaim ties each letter to the per-repository rate its
// doc comment promises. The bands are a product decision, so the thing worth
// pinning is not the constants — it is that an organization with the posture a
// letter describes actually receives that letter.
func TestBandsMeanWhatTheyClaim(t *testing.T) {
	// An org at the top of each band: the stated rate, plus the ~20 absolute
	// penalty an otherwise-exemplary org still carries at the org level.
	cases := []struct {
		letter string
		rate   float64
	}{
		{"A", 1.3},
		{"B", 3.4},
		{"C", 6.2},
		{"D", 13},
	}
	for _, tc := range cases {
		t.Run(tc.letter, func(t *testing.T) {
			const repos = 20
			// Exactly the 20 absolute points the bands were derived against: four
			// org-level settings short of ideal. The bands sit on the boundary by
			// construction, so a fixture off by even one finding lands a letter low.
			var findings []model.Finding
			for i := 0; i < 4; i++ {
				findings = append(findings, model.Finding{
					Severity: model.SevMedium, Kind: model.KindCoverage,
					Resource: model.ResourceRef{Type: "org"},
				})
			}
			// Per-repo debt at the band's rate, as low findings (2 points each).
			for i := 0; i < int(tc.rate*repos/2); i++ {
				findings = append(findings, model.Finding{
					Severity: model.SevLow, Kind: model.KindDebt,
					Resource: model.ResourceRef{Type: "repo"},
				})
			}
			got := Grade(findings, Scale{ActiveRepos: repos})
			if got.Grade != tc.letter {
				t.Errorf("rate %.1f/repo scored %d (%s), the bands promise %s",
					tc.rate, got.Value, got.Grade, tc.letter)
			}
		})
	}
}

// TestBandsAreOrdered guards the constants against an edit that crosses them,
// which would make some scores unreachable by any letter.
func TestBandsAreOrdered(t *testing.T) {
	if !(gradeA > gradeB && gradeB > gradeC && gradeC > gradeD && gradeD > 0) {
		t.Fatalf("bands out of order: A=%d B=%d C=%d D=%d", gradeA, gradeB, gradeC, gradeD)
	}
	for v, want := range map[int]string{100: "A", gradeA: "A", gradeA - 1: "B", gradeB: "B",
		gradeB - 1: "C", gradeC: "C", gradeC - 1: "D", gradeD: "D", gradeD - 1: "F", 0: "F"} {
		if got := letter(v); got != want {
			t.Errorf("score %d graded %s, want %s", v, got, want)
		}
	}
}

// TestRealOrgsLandWhereMeasured pins the calibration sample. These are the
// penalties three real organizations produced under this model; if a later
// change moves their letters, that is a decision someone should be making
// deliberately rather than discovering.
func TestRealOrgsLandWhereMeasured(t *testing.T) {
	for _, tc := range []struct {
		name    string
		penalty float64
		want    string
	}{
		{"23 active repos, 15.2 per repo", 208, "F"},
		{"581 active repos, 15.4 per repo", 416, "F"},
		{"36 active repos, 45.4 per repo", 613, "F"},
	} {
		if got := letter(decay(tc.penalty)); got != tc.want {
			t.Errorf("%s: penalty %.0f → %d (%s), want %s",
				tc.name, tc.penalty, decay(tc.penalty), got, tc.want)
		}
	}
}
