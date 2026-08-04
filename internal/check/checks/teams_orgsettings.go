package checks

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(membersCanCreatePublic{})
	check.Register(membersCanForkPrivate{})

	// Privileges over repositories that already exist. The creation toggles above
	// govern what a member can bring into being — an empty repo. These govern what
	// a member can do to the repos already holding the company's source history,
	// which is the larger blast radius, and they are multiplicative with how
	// broadly repo admin is held (see perms.direct-admin-grant, perms.org-wide-admin).
	check.Register(memberPrivilege{
		id:    "teams.members-can-change-repo-visibility",
		title: "Members can change repo visibility",
		short: "Members can change repository visibility",
		field: "members_can_change_repo_visibility",
		sev:   model.SevHigh,
		get:   func(o model.Organization) *bool { return o.MembersCanChangeRepoVisibility },
		desc: "Any member with admin on a repository can flip it from private to public. " +
			"Unlike creating a new public repository, this exposes a repository that already " +
			"carries the org's source, history, and whatever was ever committed to it — " +
			"including secrets that were removed from HEAD but remain reachable in past commits.",
		remediation: "In Settings → Member privileges → Repository visibility change, restrict " +
			"visibility changes to organization owners.",
		docs: "https://docs.github.com/organizations/managing-organization-settings/restricting-repository-visibility-changes-in-your-organization",
	})
	check.Register(memberPrivilege{
		id:    "teams.members-can-delete-repos",
		title: "Members can delete repos",
		short: "Members can delete or transfer repositories",
		field: "members_can_delete_repositories",
		sev:   model.SevMedium,
		get:   func(o model.Organization) *bool { return o.MembersCanDeleteRepos },
		desc: "Any member with admin on a repository can delete it, or transfer it out of the " +
			"organization entirely. Deletion is recoverable only within GitHub's restore window " +
			"and only by an owner; a transfer moves the repository under an account the org " +
			"does not control.",
		remediation: "In Settings → Member privileges → Repository deletion and transfer, " +
			"restrict deletion and transfer to organization owners.",
		docs: "https://docs.github.com/organizations/managing-organization-settings/setting-permissions-for-deleting-or-transferring-repositories",
	})
	check.Register(memberPrivilege{
		id:    "teams.members-can-invite-outside-collaborators",
		title: "Members can invite outside collaborators",
		short: "Members can invite outside collaborators",
		field: "members_can_invite_outside_collaborators",
		sev:   model.SevMedium,
		get:   func(o model.Organization) *bool { return o.MembersCanInviteOutsideCollabs },
		desc: "Any member with admin on a repository can grant an account outside the " +
			"organization access to a private repository, without owner review. Outside " +
			"collaborators are not covered by org-wide 2FA enforcement or SAML SSO, so each " +
			"one is an access path the org's identity controls do not reach. This reports the " +
			"door; human.outside-collaborator reports who already walked through it.",
		remediation: "In Settings → Member privileges → Repository invitations, restrict " +
			"outside-collaborator invitations to organization owners.",
		docs: "https://docs.github.com/organizations/managing-organization-settings/setting-permissions-for-adding-outside-collaborators",
	})
}

// memberPrivilege is a reusable check over a single boolean org setting that
// grants every member a privilege. It is the mirror of orgDefault: that one
// fires when a security default is off, this one fires when a privilege is on.
//
// A nil value means the setting was not visible to this token. It yields no
// finding here, and the runner has already reported the check as not evaluated —
// collectOrg marks DataOrg partial whenever owner-only fields are absent, which
// is the same condition that makes these fields nil.
//
// None of these carries a `gh` fix command. The three fields are readable on
// GET /orgs/{org} but are not writable through PATCH /orgs/{org}: sending any of
// them returns 200 and leaves the value unchanged. That was verified against a
// live org, with an invalid value on a documented field (default_repository_
// permission) as the control — that one answers 422, so the body does reach and
// is validated by the endpoint; these three are simply ignored. A fix command
// here would be a command that reports success and does nothing, which is worse
// than no command, so remediation is the UI path only.
type memberPrivilege struct {
	id, title, short, desc, remediation, docs, field string
	sev                                              model.Severity
	get                                              func(model.Organization) *bool
}

// noAPIRoute is appended to every memberPrivilege remediation. Stated once here
// rather than three times in the registrations, and worth stating at all: a
// reader who sees no fix command will otherwise reach for `gh api -X PATCH`,
// which answers 200 and changes nothing.
const noAPIRoute = "This setting is web-UI only — the REST API exposes it for reading but silently ignores it on write, so it cannot be scripted."

func (c memberPrivilege) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              c.id,
		Title:           c.title,
		Axis:            model.AxisTeams,
		DefaultSeverity: c.sev,
		Kind:            model.KindCoverage,
		RequiresData:    []model.DataKind{model.DataOrg},
		Description:     c.short + ".",
	}
}

func (c memberPrivilege) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	v := c.get(s.Org)
	if v == nil || !*v { // not visible, or the privilege is not granted
		return nil
	}
	return []model.Finding{{
		CheckID:     c.id,
		Title:       c.short,
		Severity:    c.sev,
		Axis:        model.AxisTeams,
		Resource:    orgRef(s.Org),
		Evidence:    map[string]any{c.field: true},
		Description: c.desc,
		Remediation: c.remediation + " " + noAPIRoute,
		DocsURL:     c.docs,
	}}
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
		Kind:            model.KindCoverage,
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
		Kind:            model.KindCoverage,
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
