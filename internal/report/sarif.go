package report

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/sunnysystems/scopeward/internal/model"
)

// SARIF writes the findings as a SARIF 2.1.0 log, which security dashboards and
// GitHub code scanning can ingest. Each check becomes a rule; each finding a
// result whose level maps from severity.
// Suppressed findings are emitted too, carrying SARIF's native suppressions
// object so a dashboard shows them as accepted risks with their justification
// rather than not showing them at all.
func SARIF(out io.Writer, a Audit) error {
	rules := map[string]sarifRule{}
	var results []sarifResult

	result := func(f model.Finding) sarifResult {
		if _, ok := rules[f.CheckID]; !ok {
			rules[f.CheckID] = sarifRule{
				ID:               f.CheckID,
				Name:             f.CheckID,
				ShortDescription: sarifText{Text: f.Title},
				HelpURI:          f.DocsURL,
				Properties:       map[string]any{"axis": string(f.Axis)},
			}
		}
		return sarifResult{
			RuleID:  f.CheckID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Title},
			Properties: map[string]any{
				"severity": f.Severity.String(),
				"resource": f.Resource.Name,
			},
		}
	}

	for _, f := range a.Report.Findings {
		results = append(results, result(f))
	}
	for _, s := range a.Suppressed {
		r := result(s.Finding)
		// kind "external": the acceptance lives in .scopeward.yml, not in the
		// audited source. An empty justification is emitted as-is, so a rule that
		// documented nothing stays visibly undocumented downstream.
		r.Suppressions = []sarifSuppression{{Kind: "external", Justification: s.Reason}}
		results = append(results, r)
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "scopeward",
				InformationURI: "https://github.com/sunnysystems/scopeward",
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}
	if doc.Runs[0].Results == nil {
		doc.Runs[0].Results = []sarifResult{}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// sarifLevel maps a severity to a SARIF level (error/warning/note).
func sarifLevel(s model.Severity) string {
	switch s {
	case model.SevCritical, model.SevHigh:
		return "error"
	case model.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}
type sarifResult struct {
	RuleID       string             `json:"ruleId"`
	Level        string             `json:"level"`
	Message      sarifText          `json:"message"`
	Properties   map[string]any     `json:"properties,omitempty"`
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
}
type sarifSuppression struct {
	Kind          string `json:"kind"` // "external" | "inSource"
	Justification string `json:"justification"`
}
type sarifText struct {
	Text string `json:"text"`
}
