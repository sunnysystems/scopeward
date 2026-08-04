package check

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

// stub is a minimal Check whose metadata the test controls.
type stub struct{ meta CheckMeta }

func (s stub) Meta() CheckMeta                                    { return s.meta }
func (stub) Run(context.Context, *model.Snapshot) []model.Finding { return nil }

// TestRegisterRejectsUnclassifiedCheck is the guard that makes the zero value
// safe. Kind decides which axis a finding moves, so defaulting an unclassified
// check to either one would shift the score in a direction nobody chose — the
// failure the whole redesign exists to prevent. Failing at init means a new
// check cannot merge without someone deciding.
func TestRegisterRejectsUnclassifiedCheck(t *testing.T) {
	cases := []struct {
		name string
		kind model.Kind
		want bool // want panic
	}{
		{"unset", "", true},
		{"nonsense", model.Kind("maybe"), true},
		{"coverage", model.KindCoverage, false},
		{"debt", model.KindDebt, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := "test.kind-" + tc.name
			// The registry is a package-level global, so the two accepted cases
			// would otherwise leave phantom checks in it for the rest of the test
			// binary — invisible until some later test enumerates All() and reports
			// an off-by-two nobody can explain.
			t.Cleanup(func() { delete(registry, id) })

			defer func() {
				// fmt.Sprint, not r.(string): the panic value's type is not part of
				// any contract, and asserting it would turn a changed panic into a
				// crash inside the recover handler.
				r := recover()
				switch {
				case tc.want && r == nil:
					t.Error("an unclassified check was accepted")
				case tc.want && !strings.Contains(fmt.Sprint(r), "must declare Kind"):
					t.Errorf("panic should say what is missing: %v", r)
				case !tc.want && r != nil:
					t.Errorf("a classified check was rejected: %v", r)
				}
			}()
			Register(stub{CheckMeta{ID: id, Kind: tc.kind}}) // distinct IDs: the duplicate guard must not be what fires
		})
	}
}
