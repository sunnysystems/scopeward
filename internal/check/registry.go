package check

import (
	"fmt"
	"sort"
)

// registry holds every check, keyed by ID. Checks register themselves from
// init() in the checks package, so adding a check is one new file with no
// central wiring to edit.
var registry = map[string]Check{}

// Register adds a check to the global registry. It panics on a duplicate ID,
// which can only happen at init time and indicates a programming error.
func Register(c Check) {
	meta := c.Meta()
	id := meta.ID
	if id == "" {
		panic("check: registered check has empty ID")
	}
	// Deliberately a panic and not a default. Kind decides which axis a finding
	// lands on, so an unclassified check would move the score quietly and in a
	// direction nobody chose — the exact failure #39 exists to prevent. Failing
	// at init means a new check cannot be merged without someone deciding.
	if meta.Kind != KindCoverage && meta.Kind != KindDebt {
		panic(fmt.Sprintf("check %q must declare Kind (KindCoverage or KindDebt); see check.Kind", id))
	}
	if _, dup := registry[id]; dup {
		panic(fmt.Sprintf("check: duplicate check ID %q", id))
	}
	registry[id] = c
}

// Meta returns the static metadata for a registered check by ID. The second
// result is false when no check with that ID is registered (e.g. in a test that
// does not import the checks package).
func Meta(id string) (CheckMeta, bool) {
	c, ok := registry[id]
	if !ok {
		return CheckMeta{}, false
	}
	return c.Meta(), true
}

// All returns every registered check, sorted by ID for deterministic runs.
func All() []Check {
	out := make([]Check, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Meta().ID < out[j].Meta().ID })
	return out
}
