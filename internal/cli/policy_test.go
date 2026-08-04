package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig drops a config file in a temp dir and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".scopeward.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPolicyParses(t *testing.T) {
	cfg, _, err := loadIgnore(writeConfig(t, `
ignore:
  - check: human.no-2fa
    resource: contractor-bot
    reason: service account, exempt by agreement
policy:
  version: 1
  thresholds:
    dormant_after_days: 60
    stale_repo_after_days: 180
    max_teams: 20
  invariants:
    repo_admin_only_from_team: platform-admins
    public_repos: [docs-site, brand-assets]
    forbid_direct_collaborators: true
    require_owning_team: true
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p := cfg.Policy
	if p == nil {
		t.Fatal("policy block did not parse")
	}
	if *p.Thresholds.DormantAfterDays != 60 || *p.Thresholds.StaleRepoAfterDays != 180 || *p.Thresholds.MaxTeams != 20 {
		t.Errorf("thresholds: %+v", p.Thresholds)
	}
	if p.Invariants.RepoAdminOnlyFromTeam != "platform-admins" ||
		!p.Invariants.ForbidDirectCollaborators || !p.Invariants.RequireOwningTeam {
		t.Errorf("invariants: %+v", p.Invariants)
	}
	if p.Invariants.PublicRepos == nil || len(*p.Invariants.PublicRepos) != 2 {
		t.Errorf("public_repos: %+v", p.Invariants.PublicRepos)
	}
	// `ignore` must keep working exactly as before alongside a policy block.
	if len(cfg.Ignore) != 1 || cfg.Ignore[0].Check != "human.no-2fa" {
		t.Errorf("ignore rules: %+v", cfg.Ignore)
	}
	if !p.Declared() {
		t.Error("a policy with thresholds and invariants must report as declared")
	}
}

// TestPolicyRejectsUnknownKeys is the acceptance criterion that matters most. A
// typo that parses is a policy the org believes is running and is not: it
// asserts nothing while looking like it asserts something, which is strictly
// worse than having written no policy at all.
func TestPolicyRejectsUnknownKeys(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "misspelled invariant",
			body: "policy:\n  version: 1\n  invariants:\n    require_owning_teams: true\n",
			want: "require_owning_teams",
		},
		{
			name: "misspelled threshold",
			body: "policy:\n  version: 1\n  thresholds:\n    dormant_days: 60\n",
			want: "dormant_days",
		},
		{
			name: "unknown top-level block",
			body: "polciy:\n  version: 1\n",
			want: "polciy",
		},
		{
			name: "unknown key inside ignore",
			body: "ignore:\n  - check: human.no-2fa\n    resorce: bot\n",
			want: "resorce",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := loadIgnore(writeConfig(t, tc.body))
			if err == nil {
				t.Fatalf("unknown key %q was accepted", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should name the offending key %q: %v", tc.want, err)
			}
		})
	}
}

func TestPolicyValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"missing version", "policy:\n  invariants:\n    require_owning_team: true\n", "version"},
		{"future version", "policy:\n  version: 99\n", "newer than this build"},
		{"zero threshold", "policy:\n  version: 1\n  thresholds:\n    dormant_after_days: 0\n", "positive"},
		{"negative threshold", "policy:\n  version: 1\n  thresholds:\n    stale_repo_after_days: -5\n", "positive"},
		{"negative max_teams", "policy:\n  version: 1\n  thresholds:\n    max_teams: -1\n", "negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := loadIgnore(writeConfig(t, tc.body))
			if err == nil {
				t.Fatalf("invalid policy accepted: %s", tc.body)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should explain %q: %v", tc.want, err)
			}
		})
	}
}

// TestPolicyRejectsInventory enforces the design constraint rather than only
// documenting it: a policy declares properties, and an allowlist with an entry
// per repository has become a copy of the org that nobody will update.
func TestPolicyRejectsInventory(t *testing.T) {
	var b strings.Builder
	b.WriteString("policy:\n  version: 1\n  invariants:\n    public_repos:\n")
	for i := 0; i <= maxPublicAllowlist; i++ {
		b.WriteString("      - repo-")
		b.WriteString(strings.Repeat("x", 1))
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString(strings.Repeat("y", i%7))
		b.WriteString("\n")
	}
	_, _, err := loadIgnore(writeConfig(t, b.String()))
	if err == nil {
		t.Fatal("an allowlist past the limit was accepted")
	}
	if !strings.Contains(err.Error(), "not inventory") {
		t.Errorf("the error should state the design rule: %v", err)
	}
}

// TestNoPolicyBlockIsFine: policy is opt-in, so an existing ignore-only config
// must keep working untouched.
func TestNoPolicyBlockIsFine(t *testing.T) {
	cfg, _, err := loadIgnore(writeConfig(t, "ignore:\n  - check: human.no-2fa\n    reason: accepted\n"))
	if err != nil {
		t.Fatalf("ignore-only config failed: %v", err)
	}
	if cfg.Policy != nil {
		t.Errorf("no policy block should leave Policy nil, got %+v", cfg.Policy)
	}
	if cfg.Policy.Declared() {
		t.Error("a nil policy must not report as declared")
	}
	if cfg.Policy.Supersedes("perms.direct-admin-grant") {
		t.Error("a nil policy must supersede nothing")
	}
}
