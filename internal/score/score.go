// Package score turns a set of findings into a transparent governance score.
//
// Each finding adds a penalty by severity; the penalty maps to a 0..100 score
// through a smooth decay, score = 100 / (1 + penalty/halfLife), which halves the
// score for every halfLife penalty points. This degrades gracefully — a
// heavily-flagged org lands low but never cliffs to a flat 0, so scores stay
// comparable instead of all saturating.
//
// Per-repository penalty is a *rate*, not a sum. Most checks run per repository,
// so an absolute sum made the grade track repository count: the same
// misconfiguration rate scored A at four repos and F at a hundred, and a healthy
// org's number drifted downward as it grew, which reads as a regression when
// nothing regressed (issue #30). Repository penalty is therefore divided by the
// repositories audited and re-expressed at a fixed reference size, so two orgs
// of different sizes are comparable and "we fixed half our repos" is visible.
//
// The breakdown — penalty per axis, per kind, counts per severity, and the
// un-normalized figure — is returned so the score is never a black box.
package score

import (
	"math"
	"sort"

	"github.com/sunnysystems/scopeward/internal/model"
)

// halfLife is the penalty at which the score is halved (100 → 50). Chosen so a
// handful of high findings dents the score meaningfully without saturating.
const halfLife = 100.0

// ReferenceRepos is the organization size a normalized score reads as: the
// number answers "what would this org's per-repository posture cost an
// organization of ten repositories". Raising it makes every score harsher
// without changing what the number compares — a calibration constant, not a
// model choice.
const ReferenceRepos = 10

// severityWeight is the score penalty per finding at each severity.
var severityWeight = map[model.Severity]int{
	model.SevCritical: 25,
	model.SevHigh:     12,
	model.SevMedium:   5,
	model.SevLow:      2,
	model.SevInfo:     0,
}

// volumeCap bounds how far standing for many items may multiply a finding's
// weight.
//
// The cap is load-bearing, not a safety rail. An uncapped log₂ puts a single
// 99-alert repository at 166 points — more than a third of a real
// organization's entire penalty — so one repository would dominate a number
// meant to describe an estate. Three times the worst case is as much as any
// single finding may say.
const volumeCap = 3.0

// weigh is what one finding costs before the unknown is priced: its severity
// weight, scaled sub-linearly by how many underlying items it stands for.
//
//	weight = severityWeight × min(1 + log₂(n)/4, 3)
//
// n=1 → 1.0× (exactly today's weight, so nothing moves for the ~78 checks that
// report a single thing), n=10 → 1.83×, n=99 → 2.66×, capped at 3× from n=256.
//
// Severity keeps tracking the worst item, which was always right: a repository
// with one critical CVE and a repository with one critical plus ninety-eight
// others are both critical. What was wrong is that they were also both 25
// points (issue #31). How bad is the worst one and how many are there are two
// questions, and the score used to answer only the first — leaving a report that
// could not tell a reviewer of 198 flagged repositories where to start.
//
// Sub-linear because the second CVE in a repository is not as bad as the first:
// the fix is one dependency bump either way, and the marginal risk of one more
// known vulnerability in an already-vulnerable repository is not the risk of
// going from clean to vulnerable.
func weigh(f model.Finding) float64 {
	return float64(severityWeight[f.Severity]) * volumeFactor(f.Count())
}

// volumeFactor is the multiplier for a finding standing for n items. Read n
// through model.Finding.Count(), never the raw field: log₂(0) is -Inf.
func volumeFactor(n int) float64 {
	if n <= 1 {
		return 1
	}
	return math.Min(1+math.Log2(float64(n))/4, volumeCap)
}

// Scale is the size of what was audited, so per-repository penalty can be
// expressed as a rate rather than a sum.
type Scale struct {
	// ActiveRepos is how many non-archived repositories the audit covered.
	//
	// Zero means the denominator is unknown, and the score falls back to the
	// absolute sum. That is deliberate: a rate without a denominator is not a
	// rate, and inventing one would be worse than reporting the older, coarser
	// number. Callers that know the count must pass it.
	ActiveRepos int
}

// Score is the computed governance score with its supporting breakdown.
type Score struct {
	Value   int    `json:"value"` // 0..100
	Grade   string `json:"grade"` // A..F
	Penalty int    `json:"penalty"`

	// PenaltyAbsolute and ValueAbsolute are the un-normalized figures: the plain
	// sum of finding weights, and the score it would produce. Carried so a reader
	// comparing this run against an older one can see that the number moved
	// because the model changed, not because their organization did.
	PenaltyAbsolute int `json:"penalty_absolute"`
	ValueAbsolute   int `json:"value_absolute"`

	// PerRepo is repository-scoped penalty divided by repositories audited — the
	// rate the normalized score is built from, reported directly because
	// "72 penalty across 36 repos" is the sentence that makes the number
	// actionable.
	PerRepo     float64 `json:"per_repo"`
	ActiveRepos int     `json:"active_repos,omitempty"`

	// Estimated is how much of Penalty is priced from what a disabled control is
	// estimated to hide, rather than measured. Disclosed because a score partly
	// built on an estimate has to say so: a reader comparing two runs needs to
	// know which part of the number came from evidence.
	Estimated int `json:"estimated,omitempty"`

	BySeverity map[model.Severity]int `json:"by_severity"` // finding counts
	ByAxis     map[model.Axis]int     `json:"by_axis"`     // normalized penalty per axis
	// ByKind splits penalty into the two questions the score answers: coverage
	// ("are you instrumented?") and debt ("what do the instruments report?").
	// They move in opposite directions when an operator enables a control, and a
	// reader who cannot see the split reads a rising number as getting worse
	// when they have only started looking (issue #27).
	ByKind map[model.Kind]int `json:"by_kind"`
}

// Grade computes the score from findings, normalizing repository-scoped penalty
// by the audited repository count.
func Grade(findings []model.Finding, sc Scale) Score {
	s := Score{
		BySeverity:  map[model.Severity]int{},
		ActiveRepos: sc.ActiveRepos,
	}

	// factor rescales a repository-scoped finding from "one of N repos" to "one
	// of ReferenceRepos". With no denominator it stays 1 and the score is the
	// old absolute sum.
	factor := 1.0
	if sc.ActiveRepos > 0 {
		factor = float64(ReferenceRepos) / float64(sc.ActiveRepos)
	}

	// What a disabled monitoring control should cost, learned from the org's own
	// instrumented repositories. See unknown.go: this is what stops the score
	// from falling when an operator turns a control on.
	estimates := estimateUnknown(findings, sc.ActiveRepos)

	var absolute, normalized, repoAbsolute, estimated float64
	byAxis := map[model.Axis]float64{}
	byKind := map[model.Kind]float64{}

	for _, f := range findings {
		w, est := pricedWeight(f, estimates)
		s.BySeverity[f.Severity]++
		absolute += w

		// Every slice of the breakdown is accumulated from the same scaled weight
		// as the total, so the parts sum to the whole. A breakdown that does not
		// add up is worse than no breakdown: it invites the reader to trust an
		// arithmetic that is not there.
		scaled := w
		scaledEst := est
		if isRepoScoped(f) {
			repoAbsolute += w
			scaled, scaledEst = w*factor, est*factor
		}
		estimated += scaledEst
		normalized += scaled
		byAxis[f.Axis] += scaled
		byKind[f.Kind] += scaled
	}

	s.Penalty = int(math.Round(normalized))
	s.ByAxis = roundShares(byAxis, s.Penalty)
	s.ByKind = roundShares(byKind, s.Penalty)
	if sc.ActiveRepos > 0 {
		s.PerRepo = repoAbsolute / float64(sc.ActiveRepos)
	}

	s.Estimated = int(math.Round(estimated))
	s.PenaltyAbsolute = int(math.Round(absolute))
	s.Value = decay(normalized)
	s.ValueAbsolute = decay(absolute)
	s.Grade = letter(s.Value)
	return s
}

// isRepoScoped reports whether a finding is one of the many a larger
// organization simply has more of, and so belongs in the rate rather than the
// absolute term.
//
// Read from the finding's resource type rather than the check's metadata: the
// resource is already on the finding, and one check can legitimately report
// against different resources. Findings about members, teams, tokens, apps and
// keys stay absolute — #30's claim is specifically about per-repository checks,
// and an org with fifty non-expiring tokens is worse off than one with five
// regardless of how many repositories either has.
func isRepoScoped(f model.Finding) bool { return f.Resource.Type == "repo" }

func decay(penalty float64) int {
	return int(math.Round(100 / (1 + penalty/halfLife)))
}

// Letter is the grade band for a score value, exported so a report can label
// the previous model's number during the transition.
func Letter(v int) string { return letter(v) }

// Grade bands, derived from what each letter should mean rather than inherited
// from the absolute-sum model they were calibrated against.
//
// The anchor is A: an exemplary organization — controls on everywhere, residual
// debt only, a couple of org-level settings short of ideal. That is roughly 1.3
// penalty per repository plus ~20 absolute, which the decay puts at 75. The
// remaining bands follow from the rate each should tolerate:
//
//	A ≥ 75   ≤ 1.3 per repo   exemplary; residual debt only
//	B ≥ 65   ≤ 3.4 per repo   solid, with gaps you could name
//	C ≥ 55   ≤ 6.2 per repo   visible gaps across the estate
//	D ≥ 40   ≤  13 per repo   systemic gaps
//	F                          worse
//
// 75–100 is consequently dead range, and that is a real cost of leaving the
// score value alone. No choice of halfLife puts an exemplary org at 90 while
// keeping the lower bands meaningfully spaced — the decay's shape and the band
// spacing are in conflict, and moving the letters was chosen over rescaling the
// number a second time in one release. Reshaping the curve remains open.
//
// Calibrated against three real organizations of 23, 36 and 581 active
// repositories. All three land F, which is the honest reading of their data —
// two of them are missing push protection or CODEOWNERS on nearly every
// repository. Worth stating plainly: no organization above F was available to
// measure, so the A/B/C boundaries rest on the definition above and not on
// evidence.
const (
	gradeA = 75
	gradeB = 65
	gradeC = 55
	gradeD = 40
)

func letter(v int) string {
	switch {
	case v >= gradeA:
		return "A"
	case v >= gradeB:
		return "B"
	case v >= gradeC:
		return "C"
	case v >= gradeD:
		return "D"
	default:
		return "F"
	}
}

// roundShares turns a breakdown of fractional penalties into integers that add
// up to total exactly, by largest remainder: floor everything, then hand the
// leftover points to the buckets that lost the most to flooring.
//
// Rounding each bucket on its own is the obvious implementation and it is
// wrong. Two buckets at 12.5 and 86.5 both round up, and the reader is shown a
// breakdown summing to 100 beside a total of 99. For a package whose whole
// contract is that the score is never a black box, a breakdown that does not
// reconcile is worse than none — it invites trust in an arithmetic that is not
// there.
//
// Ties break on the key so the same findings always produce the same report.
func roundShares[K ~string](in map[K]float64, total int) map[K]int {
	out := make(map[K]int, len(in))
	type share struct {
		key  K
		frac float64
	}
	shares := make([]share, 0, len(in))
	assigned := 0
	for k, v := range in {
		floor := int(math.Floor(v))
		out[k] = floor
		assigned += floor
		shares = append(shares, share{k, v - math.Floor(v)})
	}
	sort.Slice(shares, func(i, j int) bool {
		if shares[i].frac != shares[j].frac {
			return shares[i].frac > shares[j].frac
		}
		return shares[i].key < shares[j].key
	})
	for i := 0; i < total-assigned && i < len(shares); i++ {
		out[shares[i].key]++
	}
	return out
}
