package score

import (
	"math"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

// TestVolumeCurve pins the published curve. These four numbers appear in the
// score model spec and in docs/scoring.md, so an adopter can recompute a weight
// by hand and get what the tool got. Changing them is a model change, not a
// refactor.
func TestVolumeCurve(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want float64
	}{
		{0, 1.00},     // a check that never set Volume
		{1, 1.00},     // one item: exactly the old weight
		{10, 1.83},    //
		{99, 2.66},    //
		{256, 3.00},   // the cap, first reached here
		{99999, 3.00}, // and never exceeded
	} {
		if got := volumeFactor(tc.n); math.Abs(got-tc.want) > 0.005 {
			t.Errorf("volumeFactor(%d) = %.3f, want %.2f", tc.n, got, tc.want)
		}
	}
}

// TestASingleItemWeighsExactlyAsBefore is the compatibility guarantee. Roughly
// seventy-eight of the ~80 checks report one thing and leave Volume at zero;
// their contribution to every adopter's score must be bit-identical after this
// change, so that a number that moved moved because of a backlog and not
// because of the release.
func TestASingleItemWeighsExactlyAsBefore(t *testing.T) {
	findings := []model.Finding{
		{CheckID: "a", Severity: model.SevCritical, Axis: model.AxisCodeSecurity},
		{CheckID: "b", Severity: model.SevHigh, Axis: model.AxisTeams},
		{CheckID: "c", Severity: model.SevMedium, Axis: model.AxisIdentity, Volume: 1},
		{CheckID: "d", Severity: model.SevLow, Axis: model.AxisHygiene, Volume: 1},
		{CheckID: "e", Severity: model.SevInfo, Axis: model.AxisHygiene},
	}

	// The v1 weight function, written out rather than called, so this test still
	// says what the old number was after the implementation moves on.
	want := 0
	for _, f := range findings {
		want += severityWeight[f.Severity]
	}

	if got := Grade(findings, Scale{}).Penalty; got != want {
		t.Errorf("penalty = %d, want the unchanged %d: volume weighting leaked into findings that stand for one thing", got, want)
	}
}

// TestABacklogWeighsMoreThanOneAlert is the point of the change (#31, #70): a
// repository with ninety-nine open CVEs and a repository with one were the same
// 25 points, and a report that prices them identically cannot tell a reviewer of
// 198 flagged repositories where to start.
func TestABacklogWeighsMoreThanOneAlert(t *testing.T) {
	one := Grade([]model.Finding{{Severity: model.SevCritical, Volume: 1}}, Scale{})
	many := Grade([]model.Finding{{Severity: model.SevCritical, Volume: 99}}, Scale{})

	if many.Penalty <= one.Penalty {
		t.Errorf("99 alerts weigh %d, one alert weighs %d: the count still does not reach the score",
			many.Penalty, one.Penalty)
	}

	// Sub-linear, and by a lot: ninety-nine times the items is under three times
	// the weight. The second CVE in a repository is not as bad as the first —
	// it is the same dependency bump, and the repository was already vulnerable.
	if float64(many.Penalty) > 3*float64(one.Penalty) {
		t.Errorf("99 alerts cost %d against %d for one: weight is meant to grow with log₂(n), not with n",
			many.Penalty, one.Penalty)
	}
}

// TestOneRepositoryCannotDominateTheEstate is why the curve is capped.
//
// With an uncapped log₂(1+n), a single 99-alert repository lands at 166 points —
// more than a third of a real organization's entire penalty — and the score
// stops describing an estate and starts describing its worst repository. The cap
// is the model choice; the arithmetic under it is not.
func TestOneRepositoryCannotDominateTheEstate(t *testing.T) {
	worst := Grade([]model.Finding{{Severity: model.SevCritical, Volume: 100000}}, Scale{})

	ceiling := int(math.Round(volumeCap * float64(severityWeight[model.SevCritical])))
	if worst.Penalty != ceiling {
		t.Errorf("a single finding reached %d penalty, cap is %d", worst.Penalty, ceiling)
	}
	if worst.Penalty >= 166 {
		t.Errorf("a single finding costs %d: that is the uncapped curve, which is what the cap exists to prevent",
			worst.Penalty)
	}
}

// TestSeverityCountsFindingsNotItems: volume moves weight and must never move
// the counts. "3 critical" in a report means three findings, and a reader who
// sees it turn into three hundred because one of them stands for a backlog has
// lost the ability to read the summary at all.
//
// The other half of #31 — severity tracks the worst item, never the number of
// items — lives in the checks that set Severity. This is its counterpart in the
// score: nothing here may reinterpret a severity by how much it stands for.
func TestSeverityCountsFindingsNotItems(t *testing.T) {
	got := Grade([]model.Finding{
		{Severity: model.SevCritical, Volume: 99},
		{Severity: model.SevCritical},
	}, Scale{})

	if got.BySeverity[model.SevCritical] != 2 {
		t.Errorf("critical count = %d, want 2 findings", got.BySeverity[model.SevCritical])
	}
}
