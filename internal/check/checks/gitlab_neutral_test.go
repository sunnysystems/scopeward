package checks

import (
	"context"
	"testing"
	"time"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

// TestProviderNeutralChecksRunOnGitLabSnapshot is acceptance criterion 3 of the
// provider-neutral Snapshot work: a hand-built GitLab-shaped snapshot, passed to
// the real check runner, must produce sensible findings for the provider-neutral
// checks while GitHub-only checks are skipped (not silently passed).
//
// It also exercises the role normalization: a GitLab "Owner" access level maps to
// the canonical "admin" role, which the over-privilege check understands.
func TestProviderNeutralChecksRunOnGitLabSnapshot(t *testing.T) {
	snap := model.NewSnapshot("acme-group")
	snap.Provider = model.ProviderGitLab
	snap.Host = "gitlab.example.com" // self-managed
	snap.Org.Login = "acme-group"

	twoFAOff := false
	snap.Members = []model.Member{
		// Top-level group Owner → canonical org role "admin", 2FA disabled.
		{Login: "root-owner", Role: "admin", TwoFactorEnabled: &twoFAOff},
		{Login: "dev", Role: "member", TwoFactorEnabled: &twoFAOff},
	}

	// A project with a member granted GitLab Owner (50) directly — normalized to
	// the canonical "admin" repo role, which is over-privilege outside a group.
	adminRole := model.RoleFromGitLabAccessLevel(model.GitLabOwner)
	if adminRole != model.RoleAdmin {
		t.Fatalf("GitLab Owner should map to admin, got %q", adminRole)
	}
	snap.Repos = []model.Repo{{
		Name: "billing-svc",
		DirectCollaborators: []model.RepoGrant{
			{Login: "contractor", Permission: string(adminRole)},
		},
	}}

	// Mark only the provider-neutral data as collected. GitHub-only kinds (apps,
	// fine-grained PATs, ...) are left uncollected, so their checks must skip.
	snap.Coverage.OK(model.DataMembers, len(snap.Members))
	snap.Coverage.OK(model.DataMemberRoles, 1)
	snap.Coverage.OK(model.DataMember2FA, 2)
	snap.Coverage.OK(model.DataRepoDirectCollaborators, 1)

	rep := check.Run(context.Background(), snap, check.All())

	found := map[string]bool{}
	for _, f := range rep.Findings {
		found[f.CheckID] = true
	}
	for _, want := range []string{"human.owner-without-2fa", "perms.direct-admin-grant"} {
		if !found[want] {
			t.Errorf("expected provider-neutral check %q to fire on the GitLab snapshot", want)
		}
	}

	skipped := map[string]bool{}
	for _, s := range rep.Skipped {
		skipped[s.CheckID] = true
	}
	// A representative GitHub-only check must be skipped, never a false pass.
	if !skipped["nonhuman.app-broad-permissions"] {
		t.Error("GitHub-only check nonhuman.app-broad-permissions should be skipped on a GitLab snapshot, not evaluated as clean")
	}
	if found["nonhuman.app-broad-permissions"] {
		t.Error("GitHub-only check must not produce findings on a GitLab snapshot")
	}
}

// TestNonHumanTokenChecksRunOnGitLabSnapshot is acceptance criterion 1 of #6:
// the no-expiry, broad-scope, and staleness checks must evaluate on a GitLab
// snapshot, gated by the access-token coverage. When that coverage is absent
// (e.g. --quick), the same checks must be skipped, never silently pass.
func TestNonHumanTokenChecksRunOnGitLabSnapshot(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Provider = model.ProviderGitLab
	snap.Host = "https://gitlab.example.com"
	snap.CollectedAt = time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC)

	old := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	snap.AccessTokens = []model.AccessToken{
		// Non-expiring, broad ("api") scope, and unused for over a year: trips all three.
		{ID: 1, Name: "ci-pat", Kind: "personal", Holder: "alice", Active: true, Scopes: []string{"api"}, LastUsedAt: &old},
	}
	snap.DeployTokens = []model.DeployToken{{ID: 1, Name: "dt", Kind: "group", Holder: "acme"}}
	snap.OAuthApps = []model.OAuthApp{{ID: 1, Name: "dash", Trusted: true, Confidential: true}}
	snap.Coverage.OK(model.DataAccessTokens, 1)
	snap.Coverage.OK(model.DataDeployTokens, 1)
	snap.Coverage.OK(model.DataOAuthApps, 1)

	rep := check.Run(context.Background(), snap, check.All())
	found := map[string]bool{}
	for _, f := range rep.Findings {
		found[f.CheckID] = true
	}
	for _, want := range []string{
		"nonhuman.token-no-expiry", "nonhuman.token-broad-scope", "nonhuman.token-stale",
		"nonhuman.deploy-token-no-expiry", "nonhuman.oauth-app-trusted",
	} {
		if !found[want] {
			t.Errorf("expected %q to fire on the GitLab snapshot", want)
		}
	}

	// Without access-token coverage, the token checks must be skipped, not passed.
	bare := model.NewSnapshot("acme")
	bare.Provider = model.ProviderGitLab
	bare.AccessTokens = snap.AccessTokens // present, but coverage not recorded
	rep2 := check.Run(context.Background(), bare, check.All())
	for _, f := range rep2.Findings {
		if f.CheckID == "nonhuman.token-no-expiry" {
			t.Error("token check must not run without DataAccessTokens coverage")
		}
	}
	skipped := map[string]bool{}
	for _, s := range rep2.Skipped {
		skipped[s.CheckID] = true
	}
	if !skipped["nonhuman.token-no-expiry"] {
		t.Error("token check should be reported as not-evaluated when coverage is absent")
	}
}
