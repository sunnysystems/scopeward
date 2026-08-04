package report

import (
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/score"
)

// jsonPayload is the stable machine-readable shape of an audit, focused on
// results and coverage (the data CI acts on). The full inventory is intentionally
// not dumped here.
type jsonPayload struct {
	Org          model.Organization `json:"org"`
	CollectedAt  time.Time          `json:"collected_at"`
	Score        score.Score        `json:"score"`
	Findings     []model.Finding    `json:"findings"`
	NotEvaluated []check.Skipped    `json:"not_evaluated,omitempty"`
	// PartiallyEvaluated names checks that ran over only part of their scope,
	// with what was left out and why. Without it, CI reading this file would take
	// the absence of findings for the omitted resources as a pass.
	PartiallyEvaluated []check.Limitation `json:"partially_evaluated,omitempty"`
	Suppressed         []Suppression      `json:"suppressed,omitempty"`
	// UnsuppressedScore is the score without the ignore config applied, present
	// only when something was suppressed. It lets CI audit the acceptances
	// themselves rather than only the number they produced.
	UnsuppressedScore *score.Score     `json:"unsuppressed_score,omitempty"`
	Baseline          *baselineSummary `json:"baseline,omitempty"`
	Coverage          []model.Coverage `json:"coverage"`
	// Entitlements are the paid capabilities we probed for, with how each was
	// concluded. Emitted whether or not anything was suppressed: an entitlement
	// decides which findings exist at all, so a reader comparing two runs needs to
	// see it to tell a real improvement from a changed conclusion.
	Entitlements []model.EntitlementStatus `json:"entitlements,omitempty"`
}

// entitlementList flattens the snapshot's entitlement map into a slice ordered
// by name, so the JSON is byte-stable across runs (Go map iteration is not).
func entitlementList(snap *model.Snapshot) []model.EntitlementStatus {
	if len(snap.Entitlements) == 0 {
		return nil
	}
	out := make([]model.EntitlementStatus, 0, len(snap.Entitlements))
	for _, st := range snap.Entitlements {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Entitlement < out[j].Entitlement })
	return out
}

type baselineSummary struct {
	New      int `json:"new"`
	Resolved int `json:"resolved"`
}

// JSON writes the audit as indented JSON.
func JSON(out io.Writer, a Audit) error {
	payload := jsonPayload{
		Org:                a.Snapshot.Org,
		CollectedAt:        a.Snapshot.CollectedAt,
		Score:              a.Score,
		Findings:           a.Report.Findings,
		NotEvaluated:       a.Report.Skipped,
		PartiallyEvaluated: a.Report.Limited,
		Suppressed:         a.Suppressed,
		Coverage:           a.Snapshot.Coverage.All(),
		Entitlements:       entitlementList(a.Snapshot),
	}
	if len(a.Suppressed) > 0 {
		u := a.UnsuppressedScore
		payload.UnsuppressedScore = &u
	}
	if a.HasBaseline {
		payload.Baseline = &baselineSummary{New: len(a.NewKeys), Resolved: a.ResolvedCount}
	}
	if payload.Findings == nil {
		payload.Findings = []model.Finding{}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}
