package checks

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(orgWideAdminRole{})
	check.Register(orgWideWriteRole{})
	check.Register(nonhumanOrgRole{})
	check.Register(elevatedOrgRole{})
}

// orgRoleAssignmentsURL points at the page where org role assignments are managed.
func orgRoleAssignmentsURL(org string) string {
	return "https://github.com/organizations/" + org + "/settings/org_role_assignments"
}

// orgRoleRef builds a ResourceRef for an organization role.
func orgRoleRef(org string, r model.OrgRole) model.ResourceRef {
	return model.ResourceRef{
		Type: "org_role",
		ID:   strconv.FormatInt(r.ID, 10),
		Name: r.Name,
		URL:  orgRoleAssignmentsURL(org),
	}
}

// assigneeLogins returns the user logins assigned to a role.
func assigneeLogins(r model.OrgRole) []string {
	out := make([]string, 0, len(r.Users))
	for _, u := range r.Users {
		out = append(out, u.Login)
	}
	return out
}

// teamSlugs returns the team slugs assigned to a role.
func teamSlugs(r model.OrgRole) []string {
	out := make([]string, 0, len(r.Teams))
	for _, t := range r.Teams {
		out = append(out, t.Slug)
	}
	return out
}

// hasAssignees reports whether anyone (user or team) holds the role.
func hasAssignees(r model.OrgRole) bool {
	return len(r.Users) > 0 || len(r.Teams) > 0
}

// orgWideAdminRole flags organization roles whose base role is admin (e.g. the
// predefined all_repo_admin) and that are assigned to anyone. Such a role hands
// admin on every repository in the org through a single grant, invisible to
// per-repo access reviews.
type orgWideAdminRole struct{}

func (orgWideAdminRole) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "perms.org-wide-admin",
		Title:           "Org-wide admin role assigned",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevHigh,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataOrgRoles},
		Description:     "Organization roles with an admin base role assigned to users or teams, granting admin across every repository at once.",
	}
}

func (c orgWideAdminRole) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range s.OrgRoles {
		if r.BaseRole != "admin" || !hasAssignees(r) {
			continue
		}
		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    "Org role \"" + r.Name + "\" grants org-wide admin to " + countPhrase(r),
			Severity: model.SevHigh,
			Axis:     model.AxisTeams,
			Resource: orgRoleRef(s.Org.Login, r),
			Evidence: map[string]any{
				"role": r.Name, "base_role": r.BaseRole, "source": r.Source,
				"users": assigneeLogins(r), "teams": teamSlugs(r),
			},
			Description: "This organization role is built on the admin base role, so every user and team assigned to it holds admin on all of the org's repositories at once. That access does not show up in per-repository collaborator reviews and survives team changes.",
			Remediation: "Review the assignments on the org role assignments page and remove org-wide admin. Grant admin only on the specific repositories that need it, through a team at the least privilege required.",
			DocsURL:     "https://docs.github.com/organizations/managing-peoples-access-to-your-organization-with-roles/using-organization-roles",
		})
	}
	return out
}

// orgWideWriteRole flags organization roles whose base role is write or maintain
// and that are assigned to anyone: org-wide write access across all repos. Lower
// severity than org-wide admin, but still broad standing access outside the
// per-repo model.
type orgWideWriteRole struct{}

func (orgWideWriteRole) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "perms.org-wide-write",
		Title:           "Org-wide write role assigned",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevMedium,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataOrgRoles},
		Description:     "Organization roles with a write or maintain base role assigned to users or teams, granting standing write access across every repository.",
	}
}

func (c orgWideWriteRole) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range s.OrgRoles {
		if r.BaseRole != "write" && r.BaseRole != "maintain" {
			continue
		}
		if !hasAssignees(r) {
			continue
		}
		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    "Org role \"" + r.Name + "\" grants org-wide " + r.BaseRole + " to " + countPhrase(r),
			Severity: model.SevMedium,
			Axis:     model.AxisTeams,
			Resource: orgRoleRef(s.Org.Login, r),
			Evidence: map[string]any{
				"role": r.Name, "base_role": r.BaseRole, "source": r.Source,
				"users": assigneeLogins(r), "teams": teamSlugs(r),
			},
			Description: "This organization role grants " + r.BaseRole + " on every repository in the org to everyone assigned to it. Standing org-wide write is broader than most contributors need and bypasses per-repository access reviews.",
			Remediation: "Confirm each assignment still needs org-wide reach. Where it does not, replace the org role with team-based access scoped to the repositories actually worked on.",
			DocsURL:     "https://docs.github.com/organizations/managing-peoples-access-to-your-organization-with-roles/using-organization-roles",
		})
	}
	return out
}

// nonhumanOrgRole flags organization roles assigned to a non-human identity
// (a bot/app account). A machine identity holding an org-wide role is the kind
// of standing, broad, easily-forgotten access the non-human axis exists to
// surface — escalated when the role is privileged.
type nonhumanOrgRole struct{}

func (nonhumanOrgRole) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.org-role-grant",
		Title:           "Non-human identity holds an org role",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevHigh,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataOrgRoles},
		Description:     "Bot or app identities assigned an organization role, granting a machine account org-wide standing access.",
	}
}

func (c nonhumanOrgRole) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range s.OrgRoles {
		privileged := r.BaseRole == "admin" || r.BaseRole == "write" || r.BaseRole == "maintain"
		for _, u := range r.Users {
			if !u.IsBot {
				continue
			}
			sev := model.SevMedium
			if privileged {
				sev = model.SevHigh
			}
			out = append(out, model.Finding{
				CheckID:  c.Meta().ID,
				Title:    "Non-human identity " + u.Login + " holds org role \"" + r.Name + "\"",
				Severity: sev,
				Axis:     model.AxisNonHuman,
				Resource: orgRoleRef(s.Org.Login, r),
				Evidence: map[string]any{
					"login": u.Login, "role": r.Name, "base_role": r.BaseRole,
					"assignment": u.Assignment, "source": r.Source,
				},
				Description: "A machine identity is assigned an organization role, giving a non-human account org-wide standing access independent of any repository's collaborator list. Machine grants like this are rarely revisited and are easy to miss when rotating or retiring an automation.",
				Remediation: "Confirm this automation still needs the role and scope it down: prefer a GitHub App with least-privilege, per-repo permissions over an org-wide role on a bot account.",
				DocsURL:     "https://docs.github.com/organizations/managing-peoples-access-to-your-organization-with-roles/using-organization-roles",
			})
		}
	}
	return out
}

// privilegedOrgPermVerbs are the action prefixes on a fine-grained organization
// permission that let the holder change org-level configuration, as opposed to
// read_/view_ permissions that only observe it.
var privilegedOrgPermVerbs = []string{"write_", "manage_", "delete_", "admin_", "create_", "remove_", "edit_"}

// privilegedOrgPermissions returns the role's permissions that confer org-level
// management (write/manage/delete/...), sorted for stable output.
func privilegedOrgPermissions(r model.OrgRole) []string {
	var out []string
	for _, p := range r.Permissions {
		for _, v := range privilegedOrgPermVerbs {
			if strings.HasPrefix(p, v) {
				out = append(out, p)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// elevatedOrgRole flags custom organization roles that carry no repository base
// role (so the org-wide-admin/write checks never see them) yet grant standing
// org-level management permissions. These are pure org-administration grants
// hiding under a custom name — the gap left by the base-role checks.
type elevatedOrgRole struct{}

func (elevatedOrgRole) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "perms.org-role-elevated",
		Title:           "Elevated custom org role",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevMedium,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataOrgRoles},
		Description:     "Custom organization roles with no repository base role that grant org-level management permissions (write/manage/delete on org resources).",
	}
}

func (c elevatedOrgRole) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range s.OrgRoles {
		if r.BaseRole != "" || !hasAssignees(r) {
			continue // base-role roles are covered by the org-wide-admin/write checks
		}
		priv := privilegedOrgPermissions(r)
		if len(priv) == 0 {
			continue // a read-only org role is not over-privilege
		}
		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    "Custom org role \"" + r.Name + "\" grants org-level management to " + countPhrase(r),
			Severity: model.SevMedium,
			Axis:     model.AxisTeams,
			Resource: orgRoleRef(s.Org.Login, r),
			Evidence: map[string]any{
				"role": r.Name, "source": r.Source,
				"privileged_permissions": priv,
				"users":                  assigneeLogins(r), "teams": teamSlugs(r),
			},
			Description: "This organization role has no repository base role, so it does not show up as repo access, but it grants standing org-level management permissions (" + strings.Join(priv, ", ") + "). That is administrative reach over the org's configuration handed out under a custom name that reads as harmless during access reviews.",
			Remediation: "Confirm each assignee genuinely needs these org-management permissions. Remove the ones that are not required, and prefer scoping administrative tasks to the org owner role or a tightly-held custom role.",
			DocsURL:     "https://docs.github.com/organizations/managing-peoples-access-to-your-organization-with-roles/using-organization-roles",
		})
	}
	return out
}

// countPhrase renders the assignee count of a role as "N users and M teams",
// omitting a zero side.
func countPhrase(r model.OrgRole) string {
	u, t := len(r.Users), len(r.Teams)
	switch {
	case u > 0 && t > 0:
		return plural(u, "user") + " and " + plural(t, "team")
	case t > 0:
		return plural(t, "team")
	default:
		return plural(u, "user")
	}
}

// plural renders "1 user" / "3 users".
func plural(n int, noun string) string {
	s := strconv.Itoa(n) + " " + noun
	if n != 1 {
		s += "s"
	}
	return s
}
