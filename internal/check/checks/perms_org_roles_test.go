package checks

import (
	"context"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestOrgWideAdminRole(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.OrgRoles = []model.OrgRole{
		{Name: "all_repo_admin", BaseRole: "admin", Users: []model.OrgRoleAssignee{{Login: "alice"}}},    // flag
		{Name: "all_repo_admin_empty", BaseRole: "admin"},                                                // skip (no assignees)
		{Name: "all_repo_write", BaseRole: "write", Teams: []model.OrgRoleTeamGrant{{Slug: "platform"}}}, // skip (not admin)
	}
	got := orgWideAdminRole{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Evidence["role"] != "all_repo_admin" {
		t.Fatalf("got %+v, want only all_repo_admin", got)
	}
	if got[0].Severity != model.SevHigh {
		t.Errorf("severity = %v, want high", got[0].Severity)
	}
}

func TestOrgWideWriteRole(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.OrgRoles = []model.OrgRole{
		{Name: "writers", BaseRole: "write", Teams: []model.OrgRoleTeamGrant{{Slug: "platform"}}},   // flag
		{Name: "maintainers", BaseRole: "maintain", Users: []model.OrgRoleAssignee{{Login: "bob"}}}, // flag
		{Name: "readers", BaseRole: "read", Users: []model.OrgRoleAssignee{{Login: "carol"}}},       // skip
		{Name: "writers_empty", BaseRole: "write"},                                                  // skip (no assignees)
	}
	got := orgWideWriteRole{}.Run(context.Background(), snap)
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (write + maintain)", len(got))
	}
	for _, f := range got {
		if f.Severity != model.SevMedium {
			t.Errorf("%s severity = %v, want medium", f.Resource.Name, f.Severity)
		}
	}
}

func TestNonhumanOrgRole(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.OrgRoles = []model.OrgRole{
		{Name: "all_repo_admin", BaseRole: "admin", Users: []model.OrgRoleAssignee{
			{Login: "deploy-bot", IsBot: true}, // flag, high (privileged)
			{Login: "alice"},                   // skip (human)
		}},
		{Name: "custom_reader", BaseRole: "read", Users: []model.OrgRoleAssignee{
			{Login: "audit-bot", IsBot: true}, // flag, medium (not privileged)
		}},
	}
	got := nonhumanOrgRole{}.Run(context.Background(), snap)
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 bots", len(got))
	}
	sev := map[string]model.Severity{}
	for _, f := range got {
		sev[f.Evidence["login"].(string)] = f.Severity
	}
	if sev["deploy-bot"] != model.SevHigh {
		t.Errorf("deploy-bot severity = %v, want high", sev["deploy-bot"])
	}
	if sev["audit-bot"] != model.SevMedium {
		t.Errorf("audit-bot severity = %v, want medium", sev["audit-bot"])
	}
}

func TestElevatedOrgRole(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.OrgRoles = []model.OrgRole{
		// flag: no base role, privileged org perm, assigned
		{Name: "org-webhook-admin", Source: "Organization",
			Permissions: []string{"read_organization_audit_log", "manage_organization_webhooks"},
			Users:       []model.OrgRoleAssignee{{Login: "alice"}}},
		// skip: only read/view permissions
		{Name: "org-auditor", Source: "Organization",
			Permissions: []string{"read_organization_audit_log", "view_organization_metrics"},
			Teams:       []model.OrgRoleTeamGrant{{Slug: "sec"}}},
		// skip: has a base role (covered by org-wide-* checks)
		{Name: "all_repo_admin", BaseRole: "admin",
			Permissions: []string{"manage_organization_webhooks"},
			Users:       []model.OrgRoleAssignee{{Login: "bob"}}},
		// skip: privileged perm but nobody assigned
		{Name: "unused-org-role", Source: "Organization",
			Permissions: []string{"delete_organization_oauth_app_credentials"}},
	}
	got := elevatedOrgRole{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Evidence["role"] != "org-webhook-admin" {
		t.Fatalf("got %+v, want only org-webhook-admin", got)
	}
	if got[0].Severity != model.SevMedium {
		t.Errorf("severity = %v, want medium", got[0].Severity)
	}
	priv := got[0].Evidence["privileged_permissions"].([]string)
	if len(priv) != 1 || priv[0] != "manage_organization_webhooks" {
		t.Errorf("privileged_permissions = %v, want [manage_organization_webhooks]", priv)
	}
}

func TestCountPhrase(t *testing.T) {
	cases := []struct {
		role model.OrgRole
		want string
	}{
		{model.OrgRole{Users: []model.OrgRoleAssignee{{Login: "a"}}}, "1 user"},
		{model.OrgRole{Users: []model.OrgRoleAssignee{{Login: "a"}, {Login: "b"}}}, "2 users"},
		{model.OrgRole{Teams: []model.OrgRoleTeamGrant{{Slug: "t"}}}, "1 team"},
		{model.OrgRole{
			Users: []model.OrgRoleAssignee{{Login: "a"}},
			Teams: []model.OrgRoleTeamGrant{{Slug: "t"}, {Slug: "u"}},
		}, "1 user and 2 teams"},
	}
	for _, c := range cases {
		if got := countPhrase(c.role); got != c.want {
			t.Errorf("countPhrase = %q, want %q", got, c.want)
		}
	}
}
