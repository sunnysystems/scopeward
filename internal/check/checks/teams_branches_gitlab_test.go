package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func bp(v bool) *bool { return &v }

func TestMRApprovalBypassable(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Provider = model.ProviderGitLab
	snap.Members = make([]model.Member, 3) // a team, so review is expected
	snap.Repos = []model.Repo{
		{Name: "acme/self", MRAuthorCanApprove: bp(true), MRResetApprovalsOnPush: bp(true)},    // author self-approval → flag
		{Name: "acme/stale", MRAuthorCanApprove: bp(false), MRResetApprovalsOnPush: bp(false)}, // no reset → flag
		{Name: "acme/good", MRAuthorCanApprove: bp(false), MRResetApprovalsOnPush: bp(true)},   // healthy → ok
	}
	got := mrApprovalBypassable{}.Run(context.Background(), snap)
	byRepo := map[string]model.Finding{}
	for _, f := range got {
		byRepo[f.Evidence["repo"].(string)] = f
	}
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2", len(got))
	}
	if _, ok := byRepo["acme/good"]; ok {
		t.Error("healthy approval settings must not be flagged")
	}
	if !strings.Contains(byRepo["acme/self"].Title, "acme/self") {
		t.Errorf("title should use the full project path, got %q", byRepo["acme/self"].Title)
	}
}

func TestMRApprovalBypassableSoloSuppressed(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Provider = model.ProviderGitLab
	snap.Members = make([]model.Member, 1) // solo → no second approver possible
	snap.Repos = []model.Repo{{Name: "acme/self", MRAuthorCanApprove: bp(true)}}
	got := mrApprovalBypassable{}.Run(context.Background(), snap)
	if len(got) != 0 {
		t.Errorf("solo: want 0 findings, got %d", len(got))
	}
}

// TestBranchChecksProviderGuardedOnGitLab confirms the reused branch/CODEOWNERS
// checks fire on a GitLab snapshot with correct (non-doubled) paths and no gh fix
// command, and the approval check is gated on its Premium coverage.
func TestBranchChecksProviderGuardedOnGitLab(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Provider = model.ProviderGitLab
	snap.Host = "https://gitlab.example.com"
	snap.Members = make([]model.Member, 3)
	snap.Teams = []model.Team{{Slug: "acme/backend"}}
	snap.Repos = []model.Repo{{
		ID: 101, Name: "acme/api", DefaultBranch: "main",
		DefaultBranchProtected: bp(false),
		CodeownersPresent:      bp(false),
	}}
	snap.Coverage.OK(model.DataRepos, 1)
	snap.Coverage.OK(model.DataTeams, 1)
	snap.Coverage.OK(model.DataTeamRepos, 0)
	snap.Coverage.OK(model.DataBranchProtection, 1)
	snap.Coverage.OK(model.DataCodeowners, 1)

	rep := check.Run(context.Background(), snap, check.All())
	byID := map[string]model.Finding{}
	for _, f := range rep.Findings {
		byID[f.CheckID] = f
	}

	up, ok := byID["teams.unprotected-default-branch"]
	if !ok {
		t.Fatal("unprotected-default-branch should fire on the GitLab snapshot")
	}
	if strings.Contains(up.Title, "acme/acme/api") {
		t.Errorf("title doubles the group path: %q", up.Title)
	}
	if up.GHFix != "" {
		t.Errorf("no gh fix command should be attached on GitLab, got %q", up.GHFix)
	}
	if !strings.Contains(up.DocsURL, "gitlab") {
		t.Errorf("docs URL should be GitLab's, got %q", up.DocsURL)
	}
	if _, ok := byID["teams.repo-no-codeowner"]; !ok {
		t.Error("repo-no-codeowner should fire (no CODEOWNERS) on the GitLab snapshot")
	}

	// Approval check is Premium-gated: without DataMRApprovalSettings it is skipped.
	skipped := map[string]bool{}
	for _, sk := range rep.Skipped {
		skipped[sk.CheckID] = true
	}
	if !skipped["teams.mr-approval-bypassable"] {
		t.Error("mr-approval-bypassable should be not-evaluated without DataMRApprovalSettings (Free)")
	}
}
