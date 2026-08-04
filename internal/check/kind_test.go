package check

import (
	"context"
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
		kind Kind
		want bool // want panic
	}{
		{"unset", "", true},
		{"nonsense", Kind("maybe"), true},
		{"coverage", KindCoverage, false},
		{"debt", KindDebt, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				r := recover()
				switch {
				case tc.want && r == nil:
					t.Error("an unclassified check was accepted")
				case tc.want && !strings.Contains(r.(string), "must declare Kind"):
					t.Errorf("panic should say what is missing: %v", r)
				case !tc.want && r != nil:
					t.Errorf("a classified check was rejected: %v", r)
				}
			}()
			// Distinct IDs so the duplicate guard is not what fires.
			Register(stub{CheckMeta{ID: "test.kind-" + tc.name, Kind: tc.kind}})
		})
	}
}
