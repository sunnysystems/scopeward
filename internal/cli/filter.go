package cli

import (
	"fmt"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

// knownAxes is the set of axis identifiers accepted by --only/--skip (alongside
// check IDs).
var knownAxes = map[string]bool{
	string(model.AxisIdentity): true, string(model.AxisTeams): true,
	string(model.AxisCodeSecurity): true, string(model.AxisNonHuman): true,
	string(model.AxisAIAgents): true, string(model.AxisHygiene): true,
	string(model.AxisSupplyChain): true,
}

// filterChecks applies --only / --skip selectors (each an axis name or a check
// ID) to the full check set. only acts as an allowlist when non-empty; skip
// removes afterward. Unknown selectors are an error so a typo fails loudly
// rather than silently auditing nothing.
func filterChecks(all []check.Check, only, skip []string) ([]check.Check, error) {
	if err := validateSelectors(all, only); err != nil {
		return nil, err
	}
	if err := validateSelectors(all, skip); err != nil {
		return nil, err
	}
	onlySet, skipSet := toSet(only), toSet(skip)

	var out []check.Check
	for _, c := range all {
		m := c.Meta()
		if len(onlySet) > 0 && !onlySet[m.ID] && !onlySet[string(m.Axis)] {
			continue
		}
		if skipSet[m.ID] || skipSet[string(m.Axis)] {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

func validateSelectors(all []check.Check, sels []string) error {
	ids := map[string]bool{}
	for _, c := range all {
		ids[c.Meta().ID] = true
	}
	for _, s := range sels {
		if !ids[s] && !knownAxes[s] {
			return fmt.Errorf("unknown check or axis %q (use a check ID or one of: identity, teams, code_security, nonhuman, ai_agents, hygiene)", s)
		}
	}
	return nil
}

func toSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}
