package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/sunnysystems/scopeward/internal/check"
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
	// Policy is what the org decided, as opposed to what it accepted. `ignore`
	// can only remove a finding; `policy` states a rule and can produce one.
	Policy *model.Policy `yaml:"policy"`
}

// policySchemaVersion is the highest policy schema this build understands. A
// file declaring a newer one is rejected rather than parsed leniently: silently
// ignoring fields we do not know is how a policy ends up asserting less than its
// author believes, which is worse than having no policy at all.
const policySchemaVersion = 1

// validatePolicy checks the block beyond what YAML decoding can. Errors, not
// warnings: a malformed ignore rule fails open (a finding stays visible), but a
// malformed policy fails closed — the org believes it is being measured against
// a rule that is not running.
func validatePolicy(path string, p *model.Policy) error {
	if p == nil {
		return nil
	}
	switch {
	case p.Version == 0:
		return fmt.Errorf("%s: policy block needs \"version: %d\"", path, policySchemaVersion)
	case p.Version > policySchemaVersion:
		return fmt.Errorf("%s: policy version %d is newer than this build understands (%d); upgrade scopeward",
			path, p.Version, policySchemaVersion)
	case p.Version < 0:
		return fmt.Errorf("%s: policy version must be positive, got %d", path, p.Version)
	}

	for name, days := range map[string]*int{
		"dormant_after_days":    p.Thresholds.DormantAfterDays,
		"stale_repo_after_days": p.Thresholds.StaleRepoAfterDays,
	} {
		if days != nil && *days <= 0 {
			return fmt.Errorf("%s: policy.thresholds.%s must be a positive number of days, got %d", path, name, *days)
		}
	}
	if m := p.Thresholds.MaxTeams; m != nil && *m < 0 {
		return fmt.Errorf("%s: policy.thresholds.max_teams cannot be negative, got %d", path, *m)
	}

	// The invariants-not-inventory rule, enforced rather than only documented. A
	// policy that needs one entry per repository has stopped declaring a property
	// and started maintaining a copy of the org, which is a job for a tool that
	// applies state — and a copy nobody updates asserts the wrong thing forever.
	if l := p.Invariants.PublicRepos; l != nil && len(*l) > maxPublicAllowlist {
		return fmt.Errorf("%s: policy.invariants.public_repos lists %d repositories (limit %d). "+
			"A policy declares properties, not inventory — if most repositories are meant to be public, "+
			"the invariant to write is the exception, not the list", path, len(*l), maxPublicAllowlist)
	}
	return nil
}

// maxPublicAllowlist is where an allowlist stops being a decision and starts
// being a database. The number is a judgement call, not a standard.
const maxPublicAllowlist = 100

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
	// KnownFields, so a typo is an error rather than a line that quietly does
	// nothing. That matters most for `policy`: a misspelled invariant would leave
	// the org believing it declared a rule that never ran.
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, "", fmt.Errorf("parsing config %q: %w", path, err)
	}
	for i, r := range cfg.Ignore {
		if r.Check == "" {
			return nil, "", fmt.Errorf("%s: ignore entry %d has no \"check\"", path, i+1)
		}
	}
	if err := validatePolicy(path, cfg.Policy); err != nil {
		return nil, "", err
	}
	return &cfg, path, nil
}

// unknownChecks returns the check IDs referenced by rules that no registered
// check answers to, in file order.
//
// A rule naming a check that does not exist is dead config: it suppresses
// nothing and looks like it does. That happens from a typo, and from a check
// being split or renamed between releases — in which case the operator's
// accepted risk has quietly stopped being accepted. Worth a warning rather than
// an error: an unknown ID is never dangerous by itself, and failing the run
// would be a poor trade for a stale line in a config file.
func (cfg *ignoreConfig) unknownChecks() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range cfg.Ignore {
		if _, ok := check.Meta(r.Check); ok || seen[r.Check] {
			continue
		}
		seen[r.Check] = true
		out = append(out, r.Check)
	}
	return out
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
