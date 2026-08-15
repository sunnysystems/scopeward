package score

import "github.com/sunnysystems/scopeward/internal/model"

// MonitoringControls pairs a check that reports "this control is off" with the
// check that reports what the control would have found.
//
// This pairing exists to close issue #27. Turning a control on used to raise the
// penalty: alerts disabled was a flat medium (5 points), while alerts enabled
// with open CVEs was a critical (25). The vulnerabilities were identical in both
// rows — the only difference was whether the org could see them, and looking
// cost twenty points per repository. Observed on a real org, enabling Dependabot
// across the active repositories moved the penalty up by ~173 points while
// nothing about the actual exposure changed.
//
// Only pairs where enabling the control genuinely *reveals* pre-existing debt
// belong here. Push protection is deliberately absent: it blocks future commits
// of secrets and surfaces nothing that already happened, so turning it on cannot
// raise the debt axis and needs no estimate. Secret scanning does reveal
// existing alerts, but the check that reports it also reports push protection,
// and pairing a conflated check would price the wrong control. Untangling that
// check is the prerequisite for adding the pair, not a reason to add it now.
var MonitoringControls = map[string]string{
	"codesecurity.repo-dependabot-alerts-off": "codesecurity.open-dependabot-alerts",
}

// unknownFloor is the least a disabled control may cost: one critical finding
// standing for a single item.
//
// The floor, not the average, is what delivers the guarantee. An average alone
// fails in the ordinary case — an org whose instrumented repositories happen to
// be clean observes a rate of zero, prices its dark repositories at the flat
// weight, and watches its score fall the moment it enables monitoring, which is
// #27 unfixed. Verified by replaying a real organization's report: the average
// on its own let the penalty rise from 149 to 208.
//
// Pricing an unexamined repository as though it held a critical finding is
// deliberately pessimistic, and that is the honest reading of not looking: the
// repository could hold one, and nobody knows.
//
// # What volume weighting did to this number
//
// Before #70 the floor was also a ceiling: a revealed finding could not weigh
// more than one critical, so enabling a control could never raise the penalty,
// for any repository, under any data. Volume weighting ends that. A revealed
// backlog reaches 3× (see volumeCap), and a floor that kept the old promise
// would have to price every dark repository at 75.
//
// It was measured rather than argued. At a floor of 75 a normal 584-repository
// org lands at penalty 268 with 64% of it estimated, against 144 with 34%
// estimated at the current floor — a full grade band lost by every adopter, on
// no change in their organization, to buy back a case the evidence says does not
// happen. A score mostly made of assumption is a worse instrument than a
// guarantee that holds against evidence, so the floor stays where it is.
//
// What holds instead: the estimate and the measurement share a weight function
// (see estimateUnknown), so the price of a dark repository is the measured cost
// of an instrumented one. When the repositories being lit up resemble the estate,
// the two sides cancel — 800 simulated enablement campaigns across 10% to 90%
// dark, and not one raised the penalty.
//
// What does not hold: an org with no observed debt at all, every one of whose
// dark repositories hides a backlog, can see its penalty rise on enabling. The
// estimator has no evidence in that case and prices from the prior, and the
// prior is wrong. It is a real hole, it is stated in docs/scoring.md rather than
// papered over, and closing it costs more than it is worth.
//
// This all holds because a paired check emits at most one finding per
// repository. A check that could emit several would need a higher floor, which
// is a constraint on what may be paired, not a detail of the arithmetic.
var unknownFloor = float64(severityWeight[model.SevCritical])

// estimateUnknown returns, per control-off check ID, what one disabled control
// should cost: the debt actually observed on the org's instrumented
// repositories, spread over them.
//
// The estimate is deliberately the org's own rate rather than a product
// constant. An org whose instrumented repos average four open CVEs is telling
// us what its uninstrumented repos probably hold; assuming instead that every
// org is average would be a number nobody could argue with or act on. It also
// means enabling a control replaces an estimate with a measurement, so the score
// moves by however wrong the estimate was — in either direction — instead of
// systematically downward for the act of looking.
//
// Only findings are available here, not the repository inventory, which is
// enough: the repositories with the control off are exactly the ones that
// produced a control-off finding, so the instrumented count is the rest.
func estimateUnknown(findings []model.Finding, activeRepos int) map[string]float64 {
	if activeRepos <= 0 {
		return nil // no denominator, so no rate to estimate from
	}

	offCount := map[string]int{}
	debtTotal := map[string]float64{}
	for _, f := range findings {
		if _, gated := MonitoringControls[f.CheckID]; gated {
			offCount[f.CheckID]++
		}
	}
	for control, revealed := range MonitoringControls {
		for _, f := range findings {
			if f.CheckID == revealed {
				// Priced with the same weight function as the revealed finding
				// itself, volume included. That equality is what keeps #27's
				// guarantee standing: the estimate is the average cost of one
				// instrumented repository measured exactly as it will be charged
				// once the dark ones are measured, so an org whose repositories
				// carry backlogs of forty prices its dark repositories from
				// backlogs of forty and not from single alerts. Summing raw
				// severity here while charging volume-scaled weight there would
				// price the unknown below what looking reveals, by construction.
				debtTotal[control] += weigh(f)
			}
		}
	}

	out := make(map[string]float64, len(MonitoringControls))
	for control := range MonitoringControls {
		off := offCount[control]
		if off == 0 {
			continue // nothing disabled, nothing to price
		}
		// The observed rate raises the price above the floor for an org whose
		// instrumented repositories carry more than one critical's worth each; it
		// never lowers it, because a clean sample says nothing about the repos
		// nobody sampled.
		est := unknownFloor
		if instrumented := activeRepos - off; instrumented > 0 {
			if observed := debtTotal[control] / float64(instrumented); observed > est {
				est = observed
			}
		}
		out[control] = est
	}
	return out
}

// pricedWeight is what a finding costs once the unknown is priced: for a
// control-off finding, the larger of its own severity weight and the debt it is
// estimated to hide.
//
// The max is the guarantee. If a disabled control never costs less than the
// typical cost of having it enabled, then enabling it cannot raise the penalty
// of an estate that resembles itself — which is what #27 asks for, stated as an
// invariant rather than as a hope about calibration. "Typical" is doing real
// work in that sentence now that debt carries volume; unknownFloor spells out
// exactly how much.
func pricedWeight(f model.Finding, estimates map[string]float64) (weight, estimated float64) {
	base := weigh(f)
	est, ok := estimates[f.CheckID]
	if !ok || est <= base {
		return base, 0
	}
	return est, est - base
}
