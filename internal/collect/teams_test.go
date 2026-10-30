package collect

import (
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

// TestZeroTeamsIsCollected pins #97: an org with no teams has complete team data
// for an owner token, so the checks that need it run (repo-no-owning-team then
// reports every repository). For a token below owner, the empty list may hide
// secret teams, so the gap stays a gap with a reason that says so.
func TestZeroTeamsIsCollected(t *testing.T) {
	cases := []struct {
		name     string
		org      func(*model.CoverageReport)
		want     model.CoverageStatus
		inReason string
	}{
		{"owner token: zero teams is a complete answer", func(c *model.CoverageReport) { c.OK(model.DataOrg, 1) }, model.CoverageOK, ""},
		{"member token: secret teams may be unseen", func(c *model.CoverageReport) { c.Partial(model.DataOrg, 1, "owner-only") }, model.CoverageMissing, "secret teams"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := model.NewSnapshot("acme")
			tc.org(snap.Coverage)
			snap.Coverage.OK(model.DataTeams, 0)
			collectTeamDetails(nil, nil, "acme", snap)
			for _, k := range []model.DataKind{model.DataTeamMembers, model.DataTeamRepos} {
				c, ok := snap.Coverage.Get(k)
				if !ok || c.Status != tc.want {
					t.Fatalf("%s: status = %+v, want %s", k, c, tc.want)
				}
				if tc.inReason != "" && !strings.Contains(c.Reason, tc.inReason) {
					t.Errorf("%s: reason %q should mention %q", k, c.Reason, tc.inReason)
				}
			}
		})
	}
}

// TestUnlistableTeamsStayMissing keeps the original behavior for a listing that
// failed outright.
func TestUnlistableTeamsStayMissing(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Coverage.OK(model.DataOrg, 1)
	snap.Coverage.Missing(model.DataTeams, "403")
	collectTeamDetails(nil, nil, "acme", snap)
	if c, _ := snap.Coverage.Get(model.DataTeamRepos); c.Status != model.CoverageMissing || c.Reason != "teams could not be listed" {
		t.Errorf("got %+v", c)
	}
}
