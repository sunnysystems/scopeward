package checks

import (
	"context"
	"fmt"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(repoNoOwningTeam{})
	check.Register(repoNoOwningProperty{})
	check.Register(repoNoCodeowner{})
}

const ownershipDocsURL = "https://docs.github.com/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners"

const glCodeownersDocsURL = "https://docs.gitlab.com/ee/user/project/codeowners/"

// ownershipDocs returns the provider-appropriate code-ownership docs URL.
func ownershipDocs(s *model.Snapshot) string {
	if s.Provider == model.ProviderGitLab {
		return glCodeownersDocsURL
	}
	return ownershipDocsURL
}

// repoNoOwningTeam flags repositories that no team has any access to. Access
// then flows only from direct grants (or org-owner admin), so there is no team
// accountable for the repo and offboarding has to be done person-by-person.
type repoNoOwningTeam struct{}

func (repoNoOwningTeam) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.repo-no-owning-team",
		Title:           "Repositories with no owning team",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevMedium,
		Kind:            check.KindCoverage,
		RequiresData:    []model.DataKind{model.DataRepos, model.DataTeamRepos},
		Description:     "Repositories that no team has access to are governed only by direct grants, leaving no team accountable for them.",
	}
}

func (c repoNoOwningTeam) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	// A declared invariant on this concern replaces the product opinion, so one
	// problem is reported once and at the severity the org chose.
	if s.PolicySuperseded(c.Meta().ID) {
		return nil
	}
	owned := make(map[string]bool)
	for _, t := range s.Teams {
		for _, g := range t.RepoGrants {
			owned[g.Repo] = true
		}
	}

	var out []model.Finding
	for _, r := range activeRepos(s) {
		if owned[r.Name] {
			continue
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       fmt.Sprintf("Repository %s has no team with access", repoDisplay(s, r)),
			Severity:    model.SevMedium,
			Axis:        model.AxisTeams,
			Resource:    repoResource(s, r),
			Evidence:    map[string]any{"repo": r.Name, "direct_collaborators": len(r.DirectCollaborators)},
			Description: "No team grants access to this repository, so whatever access exists comes from individual direct grants or org-wide admin. There is no team that owns it, which makes access reviews and offboarding error-prone.",
			Remediation: "Grant an owning team (maintain or admin) the access it needs, and move individual grants into that team.",
			DocsURL:     ownershipDocs(s),
		})
	}
	return out
}

// repoNoOwningProperty flags repositories missing the org custom-property that
// names their owning team. It is opt-in: if no repository carries any custom
// property, the org has not adopted the convention and the check stays silent.
type repoNoOwningProperty struct{}

func (repoNoOwningProperty) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.repo-no-owning-property",
		Title:           "Repositories missing the owning-team property",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevLow,
		Kind:            check.KindCoverage,
		RequiresData:    []model.DataKind{model.DataRepos, model.DataCustomProperties},
		Description:     "When the org uses a custom property to record each repo's owning team, repositories missing it have undocumented ownership.",
	}
}

func (c repoNoOwningProperty) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	// Opt-in by adoption: skip entirely if the org sets no custom properties at all.
	adopted := false
	// s.Repos here on purpose: adoption is an org-wide question, and a property set
	// on a since-archived repo is still evidence the org uses the convention.
	for _, r := range s.Repos {
		if len(r.Properties) > 0 {
			adopted = true
			break
		}
	}
	if !adopted {
		return nil
	}

	prop := s.OwningTeamProperty
	if prop == "" {
		prop = "owning-team"
	}

	var out []model.Finding
	for _, r := range activeRepos(s) {
		if r.Properties[prop] != "" {
			continue
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       fmt.Sprintf("Repository %s/%s has no %q property set", s.Org.Login, r.Name, prop),
			Severity:    model.SevLow,
			Axis:        model.AxisTeams,
			Resource:    repoRef(s.Org.Login, r),
			Evidence:    map[string]any{"repo": r.Name, "property": prop},
			Description: fmt.Sprintf("This organization records repository ownership via the %q custom property, but this repository has no value set, so its owning team is undocumented.", prop),
			Remediation: fmt.Sprintf("Set the %q custom property on this repository to its owning team.", prop),
			DocsURL:     "https://docs.github.com/organizations/managing-organization-settings/managing-custom-properties-for-repositories-in-your-organization",
		})
	}
	return out
}

// repoNoCodeowner flags repositories whose CODEOWNERS does not assign a team as
// code owner — either no CODEOWNERS file at all, or one that names only
// individuals. Team-based code ownership keeps review responsibility with a
// group rather than a person who may leave.
type repoNoCodeowner struct{}

func (repoNoCodeowner) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.repo-no-codeowner",
		Title:           "Repositories without a team code owner",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevLow,
		Kind:            check.KindCoverage,
		RequiresData:    []model.DataKind{model.DataCodeowners, model.DataTeams},
		Description:     "Repositories with no CODEOWNERS file, or one that assigns no team, lack group-based review ownership.",
	}
}

func (c repoNoCodeowner) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range activeRepos(s) {
		// Skip when unassessed, or an empty repo (no default branch).
		if r.CodeownersPresent == nil || r.DefaultBranch == "" {
			continue
		}
		if *r.CodeownersPresent && len(r.CodeownersTeams) > 0 {
			continue // a team owns the code — healthy
		}

		var title, why string
		if !*r.CodeownersPresent {
			title = fmt.Sprintf("Repository %s has no CODEOWNERS file", repoDisplay(s, r))
			why = "There is no CODEOWNERS file, so no team is automatically requested to review changes and ownership of the code is undocumented."
		} else {
			title = fmt.Sprintf("Repository %s has a CODEOWNERS file that names no team", repoDisplay(s, r))
			why = "The CODEOWNERS file assigns only individuals, so review ownership rests on people rather than a team and breaks when they leave."
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       title,
			Severity:    model.SevLow,
			Axis:        model.AxisTeams,
			Resource:    repoResource(s, r),
			Evidence:    map[string]any{"repo": r.Name, "codeowners_present": *r.CodeownersPresent, "teams": r.CodeownersTeams},
			Description: why,
			Remediation: "Add a CODEOWNERS file that assigns an owning team (e.g. \"* @" + s.Org.Login + "/your-team\") so reviews route to a group.",
			DocsURL:     ownershipDocs(s),
		})
	}
	return out
}
