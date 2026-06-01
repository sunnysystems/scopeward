package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/report"
)

// loadBaselineKeys reads a previous scopeward JSON report and returns the set of
// finding keys it contained, for diffing against the current run.
func loadBaselineKeys(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading baseline %q: %w", path, err)
	}
	var doc struct {
		Findings []struct {
			CheckID  string `json:"check_id"`
			Title    string `json:"title"`
			Resource struct {
				Name string `json:"name"`
			} `json:"resource"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing baseline %q (expected scopeward --format json output): %w", path, err)
	}
	keys := make(map[string]bool, len(doc.Findings))
	for _, f := range doc.Findings {
		keys[report.FindingKey(model.Finding{CheckID: f.CheckID, Title: f.Title, Resource: model.ResourceRef{Name: f.Resource.Name}})] = true
	}
	return keys, nil
}

// diffBaseline classifies current findings against the baseline keys, returning
// the set of new findings' keys and how many baseline findings are now resolved.
func diffBaseline(current []model.Finding, baseline map[string]bool) (newKeys map[string]bool, resolved int) {
	newKeys = map[string]bool{}
	currentKeys := make(map[string]bool, len(current))
	for _, f := range current {
		k := report.FindingKey(f)
		currentKeys[k] = true
		if !baseline[k] {
			newKeys[k] = true
		}
	}
	for k := range baseline {
		if !currentKeys[k] {
			resolved++
		}
	}
	return newKeys, resolved
}

// keepNew filters findings to only those that are new relative to newKeys.
func keepNew(findings []model.Finding, newKeys map[string]bool) []model.Finding {
	var out []model.Finding
	for _, f := range findings {
		if newKeys[report.FindingKey(f)] {
			out = append(out, f)
		}
	}
	return out
}
