package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

// byID returns the registered check with the given ID, failing the test when it
// is not registered. Going through the registry rather than constructing the
// check directly also asserts that init() actually wired it up.
func byID(t *testing.T, id string) check.Check {
	t.Helper()
	for _, c := range check.All() {
		if c.Meta().ID == id {
			return c
		}
	}
	t.Fatalf("check %q is not registered", id)
	return nil
}

// memberPrivilegeCases pairs each privilege check with the org field it reads
// and the API field its fix must patch (#51).
var memberPrivilegeCases = []struct {
	id       string
	apiField string
	sev      model.Severity
	set      func(*model.Organization, *bool)
}{
	{
		id:       "teams.members-can-change-repo-visibility",
		apiField: "members_can_change_repo_visibility",
		sev:      model.SevHigh,
		set:      func(o *model.Organization, v *bool) { o.MembersCanChangeRepoVisibility = v },
	},
	{
		id:       "teams.members-can-delete-repos",
		apiField: "members_can_delete_repositories",
		sev:      model.SevMedium,
		set:      func(o *model.Organization, v *bool) { o.MembersCanDeleteRepos = v },
	},
	{
		id:       "teams.members-can-invite-outside-collaborators",
		apiField: "members_can_invite_outside_collaborators",
		sev:      model.SevMedium,
		set:      func(o *model.Organization, v *bool) { o.MembersCanInviteOutsideCollabs = v },
	},
}

// TestMemberPrivilegeChecks covers the three states each toggle can be in:
// granted (finding), restricted (silence), and not visible to the token
// (silence here — the runner reports it as not evaluated via DataOrg coverage,
// which TestMemberPrivilegeNotEvaluated pins).
func TestMemberPrivilegeChecks(t *testing.T) {
	for _, tc := range memberPrivilegeCases {
		t.Run(tc.id, func(t *testing.T) {
			c := byID(t, tc.id)

			granted := model.NewSnapshot("acme")
			tc.set(&granted.Org, bptr(true))
			got := c.Run(context.Background(), granted)
			if len(got) != 1 {
				t.Fatalf("granted: want 1 finding, got %d", len(got))
			}
			f := got[0]
			if f.Severity != tc.sev {
				t.Errorf("severity = %v, want %v", f.Severity, tc.sev)
			}
			if f.Evidence[tc.apiField] != true {
				t.Errorf("evidence missing %q=true: %v", tc.apiField, f.Evidence)
			}
			// These three settings are readable on GET /orgs/{org} but not writable
			// on PATCH /orgs/{org} — the endpoint answers 200 and leaves the value
			// alone (verified against a live org; see memberPrivilege's doc comment).
			// A fix command would therefore report success and do nothing, so the
			// absence of one is the assertion, not an omission.
			if f.GHFix != "" {
				t.Errorf("no `gh` fix can set %s; got %q", tc.apiField, f.GHFix)
			}
			if f.DocsURL == "" || f.Remediation == "" {
				t.Errorf("finding needs both docs URL and remediation text: %+v", f)
			}
			if !strings.Contains(f.Remediation, "web-UI only") {
				t.Errorf("remediation must say the setting cannot be scripted: %q", f.Remediation)
			}

			restricted := model.NewSnapshot("acme")
			tc.set(&restricted.Org, bptr(false))
			if got := c.Run(context.Background(), restricted); len(got) != 0 {
				t.Errorf("restricted: want 0 findings, got %d", len(got))
			}

			unknown := model.NewSnapshot("acme") // nil: not visible to this token
			if got := c.Run(context.Background(), unknown); len(got) != 0 {
				t.Errorf("nil: want 0 findings, got %d", len(got))
			}
		})
	}
}

// TestMemberPrivilegeNotEvaluated pins the other half of the nil case: a token
// that cannot see owner-only org settings must leave these checks reported as
// not evaluated, never as a silent pass.
func TestMemberPrivilegeNotEvaluated(t *testing.T) {
	want := map[string]bool{}
	var checks []check.Check
	for _, tc := range memberPrivilegeCases {
		want[tc.id] = true
		checks = append(checks, byID(t, tc.id))
	}

	// DataOrg partial is what collectOrg records when owner-only fields are absent.
	snap := model.NewSnapshot("acme")
	snap.Coverage.Partial(model.DataOrg, 1, "not visible to this token")
	rep := check.Run(context.Background(), snap, checks)
	if len(rep.Findings) != 0 {
		t.Errorf("partial org coverage must produce no findings, got %d", len(rep.Findings))
	}
	for _, s := range rep.Skipped {
		delete(want, s.CheckID)
	}
	if len(want) != 0 {
		t.Errorf("not reported as not-evaluated: %v", want)
	}
}
