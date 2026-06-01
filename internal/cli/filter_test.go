package cli

import (
	"context"
	"testing"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

type fakeCheck struct {
	id   string
	axis model.Axis
}

func (f fakeCheck) Meta() check.CheckMeta                                { return check.CheckMeta{ID: f.id, Axis: f.axis} }
func (f fakeCheck) Run(context.Context, *model.Snapshot) []model.Finding { return nil }

func TestFilterChecks(t *testing.T) {
	all := []check.Check{
		fakeCheck{"human.no-2fa", model.AxisIdentity},
		fakeCheck{"human.owner-sprawl", model.AxisIdentity},
		fakeCheck{"teams.unprotected-default-branch", model.AxisTeams},
		fakeCheck{"hygiene.stale-repo", model.AxisHygiene},
	}

	// only by axis
	got, err := filterChecks(all, []string{"identity"}, nil)
	if err != nil || len(got) != 2 {
		t.Fatalf("only identity: got %d, err %v", len(got), err)
	}

	// only by axis, skip one ID within it
	got, err = filterChecks(all, []string{"identity"}, []string{"human.owner-sprawl"})
	if err != nil || len(got) != 1 || got[0].Meta().ID != "human.no-2fa" {
		t.Fatalf("only+skip: got %+v, err %v", got, err)
	}

	// skip an axis
	got, _ = filterChecks(all, nil, []string{"teams"})
	for _, c := range got {
		if c.Meta().Axis == model.AxisTeams {
			t.Error("teams should have been skipped")
		}
	}

	// unknown selector errors
	if _, err := filterChecks(all, []string{"bogus"}, nil); err == nil {
		t.Error("expected error for unknown selector")
	}
}
