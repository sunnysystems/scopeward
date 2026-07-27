package checks

import (
	"strings"
	"testing"
)

// TestPushProtectionFixEnablesScanning guards against regressing the fix to a
// single field: push protection is silently ignored by the API unless secret
// scanning is also enabled, so the command must set both.
func TestPushProtectionFixEnablesScanning(t *testing.T) {
	f := ghRepoEnablePushProtection("acme", "api")
	if !strings.Contains(f.cmd, "security_and_analysis[secret_scanning][status]=enabled") {
		t.Errorf("command must enable secret scanning, got: %q", f.cmd)
	}
	if !strings.Contains(f.cmd, "security_and_analysis[secret_scanning_push_protection][status]=enabled") {
		t.Errorf("command must enable push protection, got: %q", f.cmd)
	}
	if !strings.HasPrefix(f.cmd, "gh api -X PATCH repos/acme/api ") {
		t.Errorf("command should PATCH the repo, got: %q", f.cmd)
	}
	if f.verify == "" {
		t.Error("push-protection fix should include a verify command")
	}
}

// TestRestrictActionsSuppliesEnabledRepositories guards against regressing the
// fix to omit enabled_repositories, which the PUT endpoint requires (422
// otherwise). The org's current value must be carried through, not invented.
func TestRestrictActionsSuppliesEnabledRepositories(t *testing.T) {
	got := ghRestrictActions("acme", "selected")
	if !strings.Contains(got.cmd, "enabled_repositories=selected") {
		t.Errorf("must preserve the org's enabled_repositories value, got: %q", got.cmd)
	}
	if !strings.Contains(got.cmd, "allowed_actions=selected") {
		t.Errorf("must restrict allowed_actions, got: %q", got.cmd)
	}
	// The allowlist must be configured too, or selected blocks legitimate workflows.
	if !strings.Contains(got.cmd, "selected-actions") || !strings.Contains(got.cmd, "github_owned_allowed=true") {
		t.Errorf("must configure the selected-actions allowlist, got: %q", got.cmd)
	}
	// Unknown current value falls back to the API-required default.
	if def := ghRestrictActions("acme", ""); !strings.Contains(def.cmd, "enabled_repositories=all") {
		t.Errorf("empty value should default to all, got: %q", def.cmd)
	}
}

func TestNewFixCommands(t *testing.T) {
	cases := []struct {
		name string
		got  fix
		want []string // substrings the cmd must contain
	}{
		{"protect-branch-team", ghProtectBranch("acme", "api", "main", true, true),
			[]string{"PUT repos/acme/api/branches/main/protection", `"enforce_admins":true`, `"required_approving_review_count":1`}},
		{"protect-branch-solo", ghProtectBranch("acme", "api", "main", false, false),
			[]string{"PUT repos/acme/api/branches/main/protection", `"enforce_admins":false`, `"required_approving_review_count":0`}},
		// A small team gets the middle configuration: review required, admin
		// break-glass retained, so the branch is guarded without being a lockout.
		{"protect-branch-small-team", ghProtectBranch("acme", "api", "main", true, false),
			[]string{`"enforce_admins":false`, `"required_approving_review_count":1`}},
		{"webhook-ssl-repo", ghFixWebhookSSL("repos/acme/api", 42),
			[]string{"PATCH repos/acme/api/hooks/42", "config[insecure_ssl]=0"}},
		{"webhook-ssl-org", ghFixWebhookSSL("orgs/acme", 7),
			[]string{"PATCH orgs/acme/hooks/7", "config[insecure_ssl]=0"}},
		{"copilot-seat", ghRemoveCopilotSeat("acme", "bob"),
			[]string{"DELETE orgs/acme/copilot/billing/selected_users", "selected_usernames[]=bob"}},
		{"archive-repo", ghArchiveRepo("acme", "old"),
			[]string{"PATCH repos/acme/old", "archived=true"}},
		{"cancel-invitation", ghCancelInvitation("acme", 555),
			[]string{"DELETE orgs/acme/invitations/555"}},
		{"revoke-credential", ghRevokeCredential("acme", 999),
			[]string{"DELETE orgs/acme/credential-authorizations/999"}},
		{"enable-dependabot-alerts", ghRepoEnableDependabotAlerts("acme", "api"),
			[]string{"PUT repos/acme/api/vulnerability-alerts"}},
	}
	for _, tc := range cases {
		if tc.got.verify == "" {
			t.Errorf("%s: missing verify command", tc.name)
		}
		for _, w := range tc.want {
			if !strings.Contains(tc.got.cmd, w) {
				t.Errorf("%s: cmd %q missing %q", tc.name, tc.got.cmd, w)
			}
		}
	}
}

// Every suggested command must declare the scopes it needs. A fix that forgets
// is the exact failure #36 is about: the operator finds out only when the block
// fails, and often with a 404 that reads as "that does not exist".
func TestEveryFixDeclaresItsScopes(t *testing.T) {
	valid := map[string]bool{
		scopeRepo: true, scopeAdminOrg: true, scopeAdminOrgHook: true, scopeManageCopilot: true,
	}
	cases := map[string]fix{
		"ghOrgPatch":                   ghOrgPatch("acme", "f", "v"),
		"ghHardenWorkflowToken":        ghHardenWorkflowToken("acme"),
		"ghRepoEnablePushProtection":   ghRepoEnablePushProtection("acme", "api"),
		"ghRepoEnableDependabotAlerts": ghRepoEnableDependabotAlerts("acme", "api"),
		"ghProtectBranch":              ghProtectBranch("acme", "api", "main", true, true),
		"ghEnforceAdmins":              ghEnforceAdmins("acme", "api", "main"),
		"ghFixWebhookSSL/repo":         ghFixWebhookSSL("repos/acme/api", 1),
		"ghFixWebhookSSL/org":          ghFixWebhookSSL("orgs/acme", 1),
		"ghRemoveCopilotSeat":          ghRemoveCopilotSeat("acme", "bob"),
		"ghArchiveRepo":                ghArchiveRepo("acme", "old"),
		"ghRemoveOutsideCollaborator":  ghRemoveOutsideCollaborator("acme", "bob"),
		"ghCancelInvitation":           ghCancelInvitation("acme", 1),
		"ghRevokeCredential":           ghRevokeCredential("acme", 1),
		"ghDeleteDeployKey":            ghDeleteDeployKey("acme", "api", "1"),
		"ghRestrictActions":            ghRestrictActions("acme", "all"),
	}
	for name, f := range cases {
		if len(f.scopes) == 0 {
			t.Errorf("%s: declares no scopes", name)
		}
		for _, s := range f.scopes {
			if !valid[s] {
				t.Errorf("%s: unknown scope %q — add it to the named constants", name, s)
			}
		}
	}
	// An org hook is not covered by repo, so the two webhook levels must differ.
	if ghFixWebhookSSL("orgs/acme", 1).scopes[0] == ghFixWebhookSSL("repos/acme/api", 1).scopes[0] {
		t.Error("org and repo webhook fixes need different scopes")
	}
}
