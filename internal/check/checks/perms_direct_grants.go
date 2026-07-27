package checks

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(directRepoGrant{})
	check.Register(directAdminGrant{})
}

// directAdminGrant flags users granted admin directly on a repository (outside
// any team). Admin is the maximum repo privilege; granting it ad hoc is the
// clearest over-privilege signal.
type directAdminGrant struct{}

func (directAdminGrant) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "perms.direct-admin-grant",
		Title:           "Direct admin on repositories",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevHigh,
		RequiresData:    []model.DataKind{model.DataRepoDirectCollaborators},
		Description:     "Users with admin permission granted directly on a repo, bypassing team-based governance.",
	}
}

func (c directAdminGrant) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range activeRepos(s) {
		for _, g := range r.DirectCollaborators {
			if g.Permission != "admin" {
				continue
			}
			out = append(out, model.Finding{
				CheckID:     c.Meta().ID,
				Title:       g.Login + " has direct admin on " + s.Org.Login + "/" + r.Name,
				Severity:    model.SevHigh,
				Axis:        model.AxisTeams,
				Resource:    repoRef(s.Org.Login, r),
				Evidence:    map[string]any{"login": g.Login, "repo": r.Name, "permission": g.Permission, "is_bot": g.IsBot},
				Description: "This account holds repository admin granted directly to it rather than through a team, so the access is invisible to team-level reviews and survives team changes.",
				Remediation: "Move the access into a team at the least privilege needed; remove the direct grant. Reserve admin for those who truly manage the repo.",
				DocsURL:     "https://docs.github.com/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization",
			})
		}
	}
	return out
}

// directRepoGrant flags non-admin permissions granted directly on a repository.
// Lower severity than directAdminGrant, but still access that lives outside the
// team model.
type directRepoGrant struct{}

func (directRepoGrant) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "perms.direct-repo-grant",
		Title:           "Direct repository grants",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevLow,
		RequiresData:    []model.DataKind{model.DataRepoDirectCollaborators},
		Description:     "Users granted access directly on a repo (non-admin), bypassing team-based governance.",
	}
}

func (c directRepoGrant) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range activeRepos(s) {
		for _, g := range r.DirectCollaborators {
			if g.Permission == "admin" {
				continue // covered by perms.direct-admin-grant at higher severity
			}
			out = append(out, model.Finding{
				CheckID:     c.Meta().ID,
				Title:       "Direct " + g.Permission + " grant to " + g.Login + " on " + s.Org.Login + "/" + r.Name,
				Severity:    model.SevLow,
				Axis:        model.AxisTeams,
				Resource:    repoRef(s.Org.Login, r),
				Evidence:    map[string]any{"login": g.Login, "repo": r.Name, "permission": g.Permission, "is_bot": g.IsBot},
				Description: "This access was granted directly on the repository rather than through a team, so it falls outside team-based access reviews and is easy to forget during offboarding.",
				Remediation: "Grant access through a team at the least privilege required, and remove the direct grant.",
				DocsURL:     "https://docs.github.com/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization",
			})
		}
	}
	return out
}
