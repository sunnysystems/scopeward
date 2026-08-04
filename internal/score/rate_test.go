package score

import (
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func repoFinding(sev model.Severity, kind model.Kind) model.Finding {
	return model.Finding{
		Severity: sev, Kind: kind, Axis: model.AxisCodeSecurity,
		Resource: model.ResourceRef{Type: "repo", Name: "acme/api"},
	}
}

func orgFinding(sev model.Severity, kind model.Kind) model.Finding {
	return model.Finding{
		Severity: sev, Kind: kind, Axis: model.AxisIdentity,
		Resource: model.ResourceRef{Type: "org", Name: "acme"},
	}
}

// TestScoreIsFlatAcrossOrgSize is the whole claim of #30: the same
// misconfiguration *rate* must produce the same number at any organization
// size. Under the old absolute sum this spanned 46 to 6.
func TestScoreIsFlatAcrossOrgSize(t *testing.T) {
	var first Score
	for i, repos := range []int{4, 23, 100} {
		findings := []model.Finding{orgFinding(model.SevHigh, model.KindDebt)}
		for r := 0; r < repos; r++ {
			findings = append(findings, repoFinding(model.SevMedium, model.KindCoverage))
		}
		got := Grade(findings, Scale{ActiveRepos: repos})
		if i == 0 {
			first = got
			continue
		}
		if got.Value != first.Value {
			t.Errorf("%d repos scored %d, 4 repos scored %d — the number still tracks size",
				repos, got.Value, first.Value)
		}
	}
}

// TestFixingHalfTheReposShows: normalization must not flatten real improvement
// into nothing. Halving the misconfigured share has to move the number.
func TestFixingHalfTheRepos(t *testing.T) {
	const repos = 40
	all := make([]model.Finding, 0, repos)
	for r := 0; r < repos; r++ {
		all = append(all, repoFinding(model.SevMedium, model.KindCoverage))
	}
	before := Grade(all, Scale{ActiveRepos: repos})
	after := Grade(all[:repos/2], Scale{ActiveRepos: repos})

	if after.Value <= before.Value {
		t.Errorf("fixing half the repos did not improve the score: %d → %d", before.Value, after.Value)
	}
	if before.PerRepo != 5 || after.PerRepo != 2.5 {
		t.Errorf("per-repo rate should halve: %v → %v", before.PerRepo, after.PerRepo)
	}
}

// TestOrgFindingsStayAbsolute: an org-level problem exists once and must not be
// diluted by owning more repositories.
func TestOrgFindingsStayAbsolute(t *testing.T) {
	f := []model.Finding{orgFinding(model.SevCritical, model.KindDebt)}
	small := Grade(f, Scale{ActiveRepos: 3})
	large := Grade(f, Scale{ActiveRepos: 300})
	if small.Penalty != large.Penalty || small.Penalty != 25 {
		t.Errorf("org penalty should be 25 at any size, got %d and %d", small.Penalty, large.Penalty)
	}
}

// TestUnknownDenominatorFallsBackToTheSum: a rate without a denominator is not
// a rate. Reporting the older, coarser number beats inventing a divisor.
func TestUnknownDenominatorFallsBackToTheSum(t *testing.T) {
	f := []model.Finding{repoFinding(model.SevCritical, model.KindDebt), orgFinding(model.SevHigh, model.KindDebt)}
	got := Grade(f, Scale{})
	if got.Penalty != got.PenaltyAbsolute || got.Value != got.ValueAbsolute {
		t.Errorf("with no denominator the score must equal the absolute sum: %+v", got)
	}
	if got.PerRepo != 0 {
		t.Errorf("no denominator means no rate to report, got %v", got.PerRepo)
	}
}

// TestBreakdownReconciles: the package's contract is that the score is never a
// black box, so every breakdown has to add up to the number it explains.
// Independent per-bucket rounding silently violates this.
func TestBreakdownReconciles(t *testing.T) {
	// 4 repos against a reference of 10 gives a 2.5 factor, so every repo weight
	// lands on a half and every bucket is a rounding candidate.
	f := []model.Finding{
		repoFinding(model.SevMedium, model.KindCoverage), //  5 → 12.5
		repoFinding(model.SevCritical, model.KindDebt),   // 25 → 62.5
		orgFinding(model.SevHigh, model.KindDebt),        // 12 → 12
		orgFinding(model.SevHigh, model.KindCoverage),    // 12 → 12
	}
	got := Grade(f, Scale{ActiveRepos: 4})

	sum := func(m map[string]int) int {
		t := 0
		for _, v := range m {
			t += v
		}
		return t
	}
	axis := map[string]int{}
	for k, v := range got.ByAxis {
		axis[string(k)] = v
	}
	kind := map[string]int{}
	for k, v := range got.ByKind {
		kind[string(k)] = v
	}
	if s := sum(axis); s != got.Penalty {
		t.Errorf("by_axis sums to %d, penalty is %d", s, got.Penalty)
	}
	if s := sum(kind); s != got.Penalty {
		t.Errorf("by_kind sums to %d, penalty is %d", s, got.Penalty)
	}
}

// TestTheTwoAxesAreReported: #27's whole argument is that a reader has to see
// visibility and debt apart, or a rising number after enabling a control reads
// as getting worse.
func TestTheTwoAxesAreReported(t *testing.T) {
	got := Grade([]model.Finding{
		orgFinding(model.SevHigh, model.KindCoverage),
		orgFinding(model.SevCritical, model.KindDebt),
	}, Scale{ActiveRepos: 10})

	if got.ByKind[model.KindCoverage] != 12 || got.ByKind[model.KindDebt] != 25 {
		t.Errorf("axes not split: %+v", got.ByKind)
	}
}

// TestRoundSharesIsDeterministic: two buckets tied on the fraction must always
// resolve the same way, or the same findings produce different reports run to
// run and every baseline diff is noise.
func TestRoundSharesIsDeterministic(t *testing.T) {
	in := map[model.Axis]float64{"a": 1.5, "b": 1.5, "c": 1.0}
	first := roundShares(in, 4)
	for i := 0; i < 50; i++ {
		if got := roundShares(in, 4); got["a"] != first["a"] || got["b"] != first["b"] {
			t.Fatalf("unstable: %v then %v", first, got)
		}
	}
	if first["a"]+first["b"]+first["c"] != 4 {
		t.Errorf("shares do not sum to the total: %v", first)
	}
}
