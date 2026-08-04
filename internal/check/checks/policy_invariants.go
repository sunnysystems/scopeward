// Policy invariants: checks that assert what the organization declared in
// .scopeward.yml, rather than what the product thinks.
//
// Every one of them is silent when no policy declares it, so the default
// experience is unchanged. When one is declared but cannot be evaluated — the
// data was not collected, or the token could not see it — the runner reports it
// as not evaluated through the ordinary RequiresData path. That matters more
// here than for a product check: a policy file that quietly asserts nothing is
// worse than no policy file, because the org believes it is being measured.
package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(policyAdminSource{})
	check.Register(policyPublicRepos{})
	check.Register(policyDirectCollaborators{})
	check.Register(policyOwningTeam{})
}

const policyDocsURL = "https://github.com/sunnysystems/scopeward#declaring-policy"

// policyFinding stamps the shared fields every invariant finding carries, so the
// policy marker cannot be forgotten on one of them.
func policyFinding(f model.Finding) model.Finding {
	f.Policy = true
	if f.DocsURL == "" {
		f.DocsURL = policyDocsURL
	}
	return f
}

// policyAdminSource asserts that repository admin originates from exactly one
// named team.
//
// No fixed check can know which team that is, which is why this cannot be a
// product default. The product measures admin *breadth* (perms.direct-admin-grant,
// perms.org-wide-admin); only the org can say where admin is supposed to come
// from, and that is the statement an access review can actually close.
type policyAdminSource struct{}

func (policyAdminSource) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "policy.admin-outside-approved-team",
		Title:           "Repository admin outside the approved team",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevHigh,
		Kind:            check.KindDebt,
		RequiresData:    []model.DataKind{model.DataTeamRepos, model.DataRepoDirectCollaborators},
		Description:     "Repository admin conferred by anything other than the team the organization named.",
	}
}

func (c policyAdminSource) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	approved := ""
	if s.Policy != nil {
		approved = s.Policy.Invariants.RepoAdminOnlyFromTeam
	}
	if approved == "" {
		return nil
	}

	var out []model.Finding
	for _, t := range s.Teams {
		if t.Slug == approved {
			continue
		}
		for _, g := range t.RepoGrants {
			if model.Role(g.Permission) != model.RoleAdmin {
				continue
			}
			out = append(out, policyFinding(model.Finding{
				CheckID:     c.Meta().ID,
				Title:       fmt.Sprintf("Team %q grants admin on %s, outside the approved team %q", t.Name, g.Repo, approved),
				Severity:    model.SevHigh,
				Axis:        model.AxisTeams,
				Resource:    teamRef(s.Org.Login, t),
				Evidence:    map[string]any{"team": t.Slug, "repo": g.Repo, "approved_team": approved, "source": "team"},
				Description: fmt.Sprintf("The organization declared that repository admin comes only from %q. This team confers it too, so the roster that governs admin is larger than the one being reviewed.", approved),
				Remediation: fmt.Sprintf("Remove this team's admin grant on %s, or move the people who need it into %q.", g.Repo, approved),
			}))
		}
	}
	for _, r := range activeRepos(s) {
		for _, g := range r.DirectCollaborators {
			if model.Role(g.Permission) != model.RoleAdmin {
				continue
			}
			out = append(out, policyFinding(model.Finding{
				CheckID:     c.Meta().ID,
				Title:       fmt.Sprintf("%s holds admin directly on %s, outside the approved team %q", g.Login, repoDisplay(s, r), approved),
				Severity:    model.SevHigh,
				Axis:        model.AxisTeams,
				Resource:    repoResource(s, r),
				Evidence:    map[string]any{"login": g.Login, "repo": r.Name, "approved_team": approved, "source": "direct"},
				Description: fmt.Sprintf("The organization declared that repository admin comes only from %q. This grant bypasses that team entirely, so removing someone from %q would not remove their admin.", approved, approved),
				Remediation: fmt.Sprintf("Remove the direct admin grant and, if the access is warranted, add %s to %q.", g.Login, approved),
			}))
		}
	}
	return out
}

// policyPublicRepos asserts that only an explicit allowlist may be public.
//
// The product has no opinion on which repositories should be public — that is
// entirely a business decision — so without a declared list there is nothing to
// check. With one, a repository going public is a violation the moment it
// happens, which is the only framing that gates a pipeline.
type policyPublicRepos struct{}

func (policyPublicRepos) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "policy.unlisted-public-repo",
		Title:           "Public repository not on the allowlist",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevCritical,
		Kind:            check.KindDebt,
		RequiresData:    []model.DataKind{model.DataRepos},
		Description:     "Repositories that are public without being on the organization's allowlist.",
		// Archiving a repository does not make it private, so the exposure
		// outlives the archive flag.
		SurvivesArchiving: true,
	}
}

func (c policyPublicRepos) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	if s.Policy == nil || s.Policy.Invariants.PublicRepos == nil {
		return nil
	}
	allowed := map[string]bool{}
	for _, name := range *s.Policy.Invariants.PublicRepos {
		allowed[strings.ToLower(name)] = true
	}

	var out []model.Finding
	// Deliberately s.Repos: an archived repository that is public is still
	// public, and it is precisely the one nobody is reviewing.
	for _, r := range s.Repos {
		if r.Private || allowed[strings.ToLower(r.Name)] {
			continue
		}
		out = append(out, policyFinding(model.Finding{
			CheckID:     c.Meta().ID,
			Title:       fmt.Sprintf("%s is public and not on the allowlist", repoDisplay(s, r)),
			Severity:    model.SevCritical,
			Axis:        model.AxisTeams,
			Resource:    repoResource(s, r),
			Evidence:    map[string]any{"repo": r.Name, "archived": r.Archived, "allowlist_size": len(allowed)},
			Description: "The organization declared which repositories may be public. This one is public and is not among them, so either it was published without the decision being revisited, or the decision was made and never written down.",
			Remediation: fmt.Sprintf("Make %s private, or add it to policy.invariants.public_repos with the decision recorded alongside it.", r.Name),
		}))
	}
	return out
}

// policyDirectCollaborators asserts that repository access comes through teams.
//
// The product already reports direct grants, but as an observation about
// structure rather than a rule: perms.direct-admin-grant says admin bypassing a
// team is risky, and perms.direct-repo-grant says the same of lesser grants.
// Declaring the invariant makes any direct grant a violation at the severity the
// org chose, and supersedes both product checks so one problem is reported once.
type policyDirectCollaborators struct{}

func (policyDirectCollaborators) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "policy.direct-collaborator",
		Title:           "Direct repository grant",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevHigh,
		Kind:            check.KindDebt,
		RequiresData:    []model.DataKind{model.DataRepoDirectCollaborators},
		Description:     "Repository access granted directly to a user rather than through a team.",
	}
}

func (c policyDirectCollaborators) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	if s.Policy == nil || !s.Policy.Invariants.ForbidDirectCollaborators {
		return nil
	}
	var out []model.Finding
	for _, r := range activeRepos(s) {
		for _, g := range r.DirectCollaborators {
			out = append(out, policyFinding(model.Finding{
				CheckID:     c.Meta().ID,
				Title:       fmt.Sprintf("%s holds %s directly on %s", g.Login, g.Permission, repoDisplay(s, r)),
				Severity:    model.SevHigh,
				Axis:        model.AxisTeams,
				Resource:    repoResource(s, r),
				Evidence:    map[string]any{"login": g.Login, "permission": g.Permission, "repo": r.Name, "bot": g.IsBot},
				Description: "The organization declared that repository access comes through teams. A direct grant is invisible to team-based access review: it survives every team change, including removing the person from every team they are in.",
				Remediation: fmt.Sprintf("Remove the direct grant and, if the access is warranted, confer it through a team %s belongs to.", g.Login),
			}))
		}
	}
	return out
}

// policyOwningTeam asserts every repository has an owning team.
//
// teams.repo-no-owning-team already reports this as a product opinion, and this
// supersedes it. The difference is standing, not detection: the same gap
// reported as "no owning team" is an observation a reviewer can decline, while
// "violates the ownership rule this org declared" is one they have to answer.
type policyOwningTeam struct{}

func (policyOwningTeam) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "policy.repo-without-owning-team",
		Title:           "Repository without an owning team",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevMedium,
		Kind:            check.KindCoverage,
		RequiresData:    []model.DataKind{model.DataRepos, model.DataTeamRepos},
		Description:     "Repositories with no team granting access, where the organization requires one.",
	}
}

func (c policyOwningTeam) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	if s.Policy == nil || !s.Policy.Invariants.RequireOwningTeam {
		return nil
	}
	owned := map[string]bool{}
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
		out = append(out, policyFinding(model.Finding{
			CheckID:     c.Meta().ID,
			Title:       fmt.Sprintf("%s has no owning team", repoDisplay(s, r)),
			Severity:    model.SevMedium,
			Axis:        model.AxisTeams,
			Resource:    repoResource(s, r),
			Evidence:    map[string]any{"repo": r.Name},
			Description: "The organization declared that every repository has an owning team. This one is granted to no team, so there is nobody to route a review, an incident, or an offboarding question to.",
			Remediation: fmt.Sprintf("Grant %s to the team that owns it. If no team does, that is the finding.", r.Name),
		}))
	}
	return out
}

// declaredPublicRepos is used by tests and by the config layer to normalize an
// allowlist into the comparison form the check uses.
func declaredPublicRepos(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}
