package report

import (
	"encoding/json"
	"io"
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
	Suppressed   []model.Finding    `json:"suppressed,omitempty"`
	Baseline     *baselineSummary   `json:"baseline,omitempty"`
	Coverage     []model.Coverage   `json:"coverage"`
}

type baselineSummary struct {
	New      int `json:"new"`
	Resolved int `json:"resolved"`
}

// JSON writes the audit as indented JSON.
func JSON(out io.Writer, a Audit) error {
	payload := jsonPayload{
		Org:          a.Snapshot.Org,
		CollectedAt:  a.Snapshot.CollectedAt,
		Score:        a.Score,
		Findings:     a.Report.Findings,
		NotEvaluated: a.Report.Skipped,
		Suppressed:   a.Suppressed,
		Coverage:     a.Snapshot.Coverage.All(),
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
