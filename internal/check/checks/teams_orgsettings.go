package checks

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(membersCanCreatePublic{})
	check.Register(membersCanForkPrivate{})
}

// membersCanCreatePublic flags orgs that let any member publish a public repo,
// which can expose code unintentionally.
type membersCanCreatePublic struct{}

func (membersCanCreatePublic) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.members-can-create-public-repos",
		Title:           "Members can create public repos",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevMedium,
		RequiresData:    []model.DataKind{model.DataOrg},
		Description:     "Whether any member can create public repositories in the org.",
	}
}

func (c membersCanCreatePublic) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	if s.Org.MembersCanCreatePublicRepos == nil || !*s.Org.MembersCanCreatePublicRepos {
		return nil
	}
	return []model.Finding{{
		CheckID:     c.Meta().ID,
		Title:       "Any member can create public repositories",
		Severity:    model.SevMedium,
		Axis:        model.AxisTeams,
		Resource:    orgRef(s.Org),
		Evidence:    map[string]any{"members_can_create_public_repositories": true},
		Description: "Any member can publish a public repository under the org. A mistaken or rushed publish can expose source code, configuration, or secrets to the whole internet.",
		// No safe one-command fix: setting members_can_create_public_repositories
		// alone implies a private-only creation policy, which GitHub rejects (422)
		// on orgs that don't support it. The reliable lever is owners-only repo
		// creation, but that is broader than this finding, so it is left to the
		// operator rather than auto-suggested.
		Remediation: "In Settings → Member privileges → Repository creation, either set creation to owners-only, or (on plans that allow it) keep private/internal but uncheck Public. Note: forbidding public while allowing private requires a plan that supports a private-only creation policy.",
		DocsURL:     "https://docs.github.com/organizations/managing-organization-settings/restricting-repository-creation-in-your-organization",
	}}
}

// membersCanForkPrivate flags orgs that allow forking private/internal repos,
// which moves private code into personal namespaces outside org governance.
type membersCanForkPrivate struct{}

func (membersCanForkPrivate) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.members-can-fork-private-repos",
		Title:           "Members can fork private repos",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevHigh,
		RequiresData:    []model.DataKind{model.DataOrg},
		Description:     "Whether members can fork private/internal repositories.",
	}
}

func (c membersCanForkPrivate) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	if s.Org.MembersCanForkPrivateRepos == nil || !*s.Org.MembersCanForkPrivateRepos {
		return nil
	}
	return []model.Finding{withFix(model.Finding{
		CheckID:     c.Meta().ID,
		Title:       "Members can fork private repositories",
		Severity:    model.SevHigh,
		Axis:        model.AxisTeams,
		Resource:    orgRef(s.Org),
		Evidence:    map[string]any{"members_can_fork_private_repositories": true},
		Description: "Members can fork private and internal repositories into personal accounts, copying private code into namespaces the org does not control and cannot reliably audit or revoke.",
		Remediation: "Disable forking of private/internal repositories at the org level unless a specific workflow requires it.",
		DocsURL:     "https://docs.github.com/organizations/managing-organization-settings/managing-the-forking-policy-for-your-organization",
	}, ghOrgPatch(s.Org.Login, "members_can_fork_private_repositories", "false"))}
}
