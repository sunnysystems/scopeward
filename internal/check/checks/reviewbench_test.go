package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

// writersOrg is the shape from #99: ten members, base permission read, no teams
// and no direct grants, so only the owners can push. Coverage is complete, so
// the bench comes from the access graph.
func writersOrg(owners int, base string) *model.Snapshot {
	snap := model.NewSnapshot("acme")
	snap.Org.Plan = "team"
	snap.Org.DefaultRepoPermission = base
	for i := 0; i < 10; i++ {
		role := "member"
		if i < owners {
			role = "admin"
		}
		snap.Members = append(snap.Members, model.Member{Login: fmt.Sprintf("m%d", i), Role: role})
	}
	snap.Repos = []model.Repo{{Name: "api", Private: true, DefaultBranch: "main", DefaultBranchProtected: bptr(false)}}
	for _, k := range []model.DataKind{model.DataMembers, model.DataMemberRoles, model.DataTeamMembers, model.DataTeamRepos, model.DataRepoDirectCollaborators, model.DataOrgRoles} {
		snap.Coverage.OK(k, 1)
	}
	return snap
}

// TestBranchFixSizedByWriters pins #99: ten members of whom three can push get
// one approval with the admin bypass kept, not the no-bypass configuration a
// ten-person bench would earn. When base permission makes all ten writers, the
// strict configuration comes back.
func TestBranchFixSizedByWriters(t *testing.T) {
	cases := []struct {
		name          string
		snap          *model.Snapshot
		wantBench     int
		wantSource    string
		enforceAdmins bool
	}{
		{"three owners, base read", writersOrg(3, "read"), 3, "people who can push", false},
		{"base write makes everyone a writer", writersOrg(3, "write"), 10, "people who can push", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := unprotectedDefaultBranch{}.Run(context.Background(), tc.snap)
			if len(got) != 1 {
				t.Fatalf("want one finding, got %d", len(got))
			}
			f := got[0]
			if f.Evidence["review_bench"] != tc.wantBench || f.Evidence["review_bench_source"] != tc.wantSource {
				t.Errorf("bench = %v (%v), want %d (%s)", f.Evidence["review_bench"], f.Evidence["review_bench_source"], tc.wantBench, tc.wantSource)
			}
			if !strings.Contains(f.GHFix, `"required_approving_review_count":1`) {
				t.Errorf("fix should require one approval: %s", f.GHFix)
			}
			if want := fmt.Sprintf(`"enforce_admins":%v`, tc.enforceAdmins); !strings.Contains(f.GHFix, want) {
				t.Errorf("fix should set %s: %s", want, f.GHFix)
			}
		})
	}
}

// TestBenchFallsBackToMembers pins the fallback: with team data missing, writers
// cannot be counted without undercounting, so the bench is the member count
// and the evidence says why.
func TestBenchFallsBackToMembers(t *testing.T) {
	snap := writersOrg(3, "read")
	snap.Coverage.Missing(model.DataTeamRepos, "--quick")
	f := unprotectedDefaultBranch{}.Run(context.Background(), snap)[0]
	if f.Evidence["review_bench"] != 10 || f.Evidence["review_bench_source"] != "organization members" {
		t.Errorf("bench = %v (%v), want 10 organization members", f.Evidence["review_bench"], f.Evidence["review_bench_source"])
	}
	if reason, _ := f.Evidence["review_bench_fallback"].(string); !strings.Contains(reason, "team") {
		t.Errorf("fallback reason = %q, want it to name the team-data gap", reason)
	}
}

// TestBypassSeverityFollowsWriters: the admin break-glass path is the suggested
// configuration for a three-writer repository, so it is info there even in a
// ten-member org.
func TestBypassSeverityFollowsWriters(t *testing.T) {
	snap := writersOrg(3, "read")
	snap.Repos[0].DefaultBranchProtected = bptr(true)
	snap.Repos[0].BranchReqPRReview = bptr(true)
	snap.Repos[0].BranchEnforceAdmins = bptr(false)
	got := bypassableBranchProtection{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Severity != model.SevInfo || got[0].GHFix != "" {
		t.Fatalf("want one info finding with no fix, got %+v", got)
	}
	if !strings.Contains(got[0].Description, "3 people who can push") {
		t.Errorf("description should state the bench: %q", got[0].Description)
	}
}

// TestBotsAreNotReviewers: a bot with write can push but cannot review, so it
// does not raise the bench.
func TestBotsAreNotReviewers(t *testing.T) {
	snap := writersOrg(1, "read")
	snap.Repos[0].DirectCollaborators = []model.RepoGrant{{Login: "deploy[bot]", Permission: "write", IsBot: true}}
	f := unprotectedDefaultBranch{}.Run(context.Background(), snap)[0]
	if f.Evidence["review_bench"] != 1 {
		t.Errorf("bench = %v, want 1 (the bot does not count)", f.Evidence["review_bench"])
	}
	if strings.Contains(f.GHFix, `"required_approving_review_count":1`) {
		t.Errorf("one human writer cannot get a review: %s", f.GHFix)
	}
}
