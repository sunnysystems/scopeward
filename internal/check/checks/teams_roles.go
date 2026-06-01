package checks

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(elevatedCustomRole{}) }

// elevatedCustomRole flags custom repository roles built on a privileged base
// (admin or maintain). A custom role inherits everything its base role grants,
// so an "admin-based" custom role is broad access wearing a friendly name.
type elevatedCustomRole struct{}

func (elevatedCustomRole) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.custom-role-elevated",
		Title:           "Elevated custom roles",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevMedium,
		RequiresData:    []model.DataKind{model.DataCustomRoles},
		Description:     "Custom repository roles whose base role is admin or maintain.",
	}
}

func (c elevatedCustomRole) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, role := range s.CustomRoles {
		if role.BaseRole != "admin" && role.BaseRole != "maintain" {
			continue
		}
		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    "Custom role \"" + role.Name + "\" is based on " + role.BaseRole,
			Severity: model.SevMedium,
			Axis:     model.AxisTeams,
			Resource: model.ResourceRef{
				Type: "role",
				Name: role.Name,
				URL:  "https://github.com/organizations/" + s.Org.Login + "/settings/roles",
			},
			Evidence:    map[string]any{"role": role.Name, "base_role": role.BaseRole, "added_permissions": role.Permissions},
			Description: "This custom role inherits everything its base role (" + role.BaseRole + ") grants, plus any added permissions. Roles built on admin/maintain hand out broad control under a name that can read as harmless during access reviews.",
			Remediation: "Rebuild the role on the least-privileged base that works (read/triage/write) and add only the specific permissions needed.",
			DocsURL:     "https://docs.github.com/organizations/managing-peoples-access-to-your-organization-with-roles/managing-custom-repository-roles-for-an-organization",
		})
	}
	return out
}
