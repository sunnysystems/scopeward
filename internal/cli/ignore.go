package cli

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/report"
)

// ignoreCandidates are the default config filenames looked for in the working
// directory when --config is not given.
var ignoreCandidates = []string{".scopeward.yml", ".scopeward.yaml"}

// ignoreRule suppresses a finding the operator has reviewed and accepted.
type ignoreRule struct {
	Check    string `yaml:"check"`              // required: check ID to suppress
	Resource string `yaml:"resource,omitempty"` // optional: only this resource name
	Reason   string `yaml:"reason,omitempty"`   // why the risk was accepted; carried into every output
}

type ignoreConfig struct {
	Ignore []ignoreRule `yaml:"ignore"`
}

// loadIgnore reads the ignore config from an explicit path, or auto-detects one
// of ignoreCandidates in the working directory. It returns (nil, "", nil) when
// no config is present; an explicit but unreadable path is an error.
func loadIgnore(explicit string) (*ignoreConfig, string, error) {
	path := explicit
	if path == "" {
		for _, name := range ignoreCandidates {
			if _, err := os.Stat(name); err == nil {
				path = name
				break
			}
		}
		if path == "" {
			return nil, "", nil
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("reading ignore file %q: %w", path, err)
	}
	var cfg ignoreConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, "", fmt.Errorf("parsing ignore file %q: %w", path, err)
	}
	for i, r := range cfg.Ignore {
		if r.Check == "" {
			return nil, "", fmt.Errorf("%s: ignore entry %d has no \"check\"", path, i+1)
		}
	}
	return &cfg, path, nil
}

// apply partitions findings into those kept and those suppressed by the rules.
// Each suppression carries the reason from the rule that matched it, so the
// justification reaches the report rather than staying in the YAML file.
func (cfg *ignoreConfig) apply(findings []model.Finding) (kept []model.Finding, suppressed []report.Suppression) {
	for _, f := range findings {
		if r := cfg.match(f); r != nil {
			suppressed = append(suppressed, report.Suppression{Finding: f, Reason: r.Reason})
		} else {
			kept = append(kept, f)
		}
	}
	return kept, suppressed
}

// match returns the first rule suppressing this finding, or nil. The first match
// wins, so a specific resource rule listed before a check-wide one supplies the
// more precise reason.
func (cfg *ignoreConfig) match(f model.Finding) *ignoreRule {
	for i, r := range cfg.Ignore {
		if r.Check != f.CheckID {
			continue
		}
		if r.Resource == "" || r.Resource == f.Resource.Name {
			return &cfg.Ignore[i]
		}
	}
	return nil
}
