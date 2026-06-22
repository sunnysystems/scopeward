package checks

import (
	"context"
	"testing"

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
