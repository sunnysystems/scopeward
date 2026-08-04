package checks

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(basePermissionOpen{}) }

// basePermissionOpen flags an organization whose default repository permission
// grants every member write or admin to every repo by default — the opposite of
// least privilege.
type basePermissionOpen struct{}

func (basePermissionOpen) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.base-permission-open",
		Title:           "Org base permission too permissive",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevHigh,
		Kind:            model.KindCoverage,
		RequiresData:    []model.DataKind{model.DataOrg},
		Description:     "The organization's default repository permission grants broad access to all members.",
	}
}

func (c basePermissionOpen) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	perm := s.Org.DefaultRepoPermission
	if perm != "write" && perm != "admin" {
		return nil // read / none are acceptable defaults
	}

	sev := model.SevMedium
	if perm == "admin" {
		sev = model.SevHigh
	}
	return []model.Finding{withFix(model.Finding{
		CheckID:     c.Meta().ID,
		Title:       "Organization base permission is \"" + perm + "\"",
		Severity:    sev,
		Axis:        model.AxisTeams,
		Resource:    orgRef(s.Org),
		Evidence:    map[string]any{"default_repository_permission": perm},
		Description: "Every member receives " + perm + " access to every repository by default, so access is granted broadly rather than per need. This makes a single compromised member far more damaging.",
		Remediation: "Set the base permission to \"read\" (or \"none\") and grant write/admin explicitly through teams.",
		DocsURL:     "https://docs.github.com/organizations/managing-organization-settings/setting-base-permissions-for-an-organization",
	}, ghOrgPatch(s.Org.Login, "default_repository_permission", "read"))}
}
