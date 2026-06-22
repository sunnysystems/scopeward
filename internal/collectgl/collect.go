// Package collectgl performs the read-only GitLab API calls that fill a
// provider-neutral model.Snapshot for the human-identity axis. It mirrors the
// internal/collect (GitHub) package: collectors do all the I/O and record
// coverage; the pure checks read the resulting snapshot and never re-query.
//
// The identity (#4), teams/permissions (#5), non-human identity (#6,
// tokens/deploy keys/OAuth), CI/CD (#7, variables/runners/job-token scope), and
// branch-protection/approval/CODEOWNERS (#8) axes are implemented here. Data
// that is not yet collected (SAML/SCIM) is recorded as a coverage gap so
// dependent checks degrade to "not evaluated" rather than a false pass; that
// axis lands in #9.
package collectgl

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/sunnysystems/scopeward/internal/collect"
	"github.com/sunnysystems/scopeward/internal/glclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// Now is the clock used to stamp the snapshot; overridable in tests.
var Now = time.Now

// noopReporter is used when the caller passes no Reporter.
type noopReporter struct{}

func (noopReporter) Stage(string)             {}
func (noopReporter) SetRepoProgress(int, int) {}

// RunGroup audits a GitLab top-level group's human-identity axis: members and
// their neutral roles, 2FA (group enforcement plus per-member where the token is
// an instance admin), and member dormancy. A hard failure reading the group
// returns an error; everything finer-grained becomes a coverage gap so the audit
// degrades honestly.
func RunGroup(ctx context.Context, client *glclient.Client, group, host string, prog collect.Reporter, opts collect.Options) (*model.Snapshot, error) {
	if prog == nil {
		prog = noopReporter{}
	}
	snap := model.NewSnapshot(group)
	snap.Provider = model.ProviderGitLab
	snap.Host = host

	prog.Stage("resolving group " + group)
	if err := collectGroup(ctx, client, group, snap); err != nil {
		return nil, fmt.Errorf("cannot read group %q: %w", group, err)
	}

	prog.Stage("collecting members")
	members, err := fetchMembers(ctx, client, group)
	if err != nil {
		snap.Coverage.Missing(model.DataMembers, reasonFor(err, "listing group members"))
	} else {
		snap.Members = members
		snap.Coverage.OK(model.DataMembers, len(members))
		// Access level is returned inline with each member, so the role view is
		// as complete as the member list itself.
		snap.Coverage.OK(model.DataMemberRoles, len(members))
		enrichMembers(ctx, client, snap)
	}

	prog.Stage("collecting subgroups & projects")
	collectTeamsAndProjects(ctx, client, group, snap, opts)

	prog.Stage("collecting tokens, deploy keys & OAuth apps")
	collectNonHuman(ctx, client, snap, opts)

	prog.Stage("collecting CI/CD variables, runners & job-token scope")
	collectCICD(ctx, client, snap, opts)

	prog.Stage("collecting protected branches, approval rules & CODEOWNERS")
	collectBranches(ctx, client, snap, opts)

	markNotCollected(snap)

	snap.CollectedAt = Now()
	return snap, nil
}

// collectTeamsAndProjects maps the GitLab subgroup tree onto neutral teams and
// projects onto repositories — including each team's repo grants and each
// project's direct member grants. The group-level lists (subgroups, projects) are
// always fetched; the per-subgroup and per-project membership passes are skipped
// in --quick mode, mirroring the GitHub collector.
func collectTeamsAndProjects(ctx context.Context, client *glclient.Client, group string, snap *model.Snapshot, opts collect.Options) {
	if teams, err := fetchSubgroups(ctx, client, group, snap.Org.ID); err != nil {
		snap.Coverage.Missing(model.DataTeams, reasonFor(err, "listing subgroups"))
	} else {
		snap.Teams = teams
		snap.Coverage.OK(model.DataTeams, len(teams))
	}

	collectProjects(ctx, client, group, snap)

	if opts.Quick {
		snap.Coverage.Missing(model.DataTeamMembers, "skipped in --quick mode (group-level only)")
		snap.Coverage.Missing(model.DataRepoDirectCollaborators, "skipped in --quick mode (group-level only)")
		return
	}
	collectSubgroupMembers(ctx, client, snap)
	collectProjectMembers(ctx, client, snap)
}

// collectGroup reads group-level settings, notably the 2FA-enforcement flag that
// the org-2FA check reads. The group's display name and id are recorded too.
func collectGroup(ctx context.Context, client *glclient.Client, group string, snap *model.Snapshot) error {
	var dto struct {
		ID                   int64  `json:"id"`
		Name                 string `json:"name"`
		FullPath             string `json:"full_path"`
		RequireTwoFactorAuth *bool  `json:"require_two_factor_authentication"`
	}
	if _, err := client.Get(ctx, "/groups/"+url.PathEscape(group), nil, &dto); err != nil {
		return err
	}

	snap.Org.Name = dto.Name
	snap.Org.ID = dto.ID
	if dto.FullPath != "" {
		snap.Org.Login = dto.FullPath
	}
	if dto.RequireTwoFactorAuth != nil {
		snap.Org.TwoFactorRequired = *dto.RequireTwoFactorAuth
		snap.Coverage.OK(model.DataOrg, 1)
	} else {
		snap.Coverage.Partial(model.DataOrg, 1, "group 2FA-enforcement setting not visible to this token")
	}
	return nil
}

// markNotCollected records the identity-adjacent axes that GitLab exposes
// differently or that land in later issues, so their checks report "not
// evaluated" with a clear reason instead of silently passing.
func markNotCollected(snap *model.Snapshot) {
	snap.Coverage.Missing(model.DataSAMLIdentities, "GitLab SSO/SAML & SCIM identities are collected separately (#9)")
	snap.Coverage.Missing(model.DataOutsideCollaborators, "GitLab has no direct equivalent; outside-collaborator modeling lands later")
	snap.Coverage.Missing(model.DataPendingInvitations, "pending group invitations are not collected yet")
	// Teams-axis concepts with no GitLab equivalent (or gated by tier): the
	// dependent checks report "not evaluated" rather than a false pass.
	snap.Coverage.Missing(model.DataCustomRoles, "GitLab custom roles are Ultimate-only; not evaluated")
	snap.Coverage.Missing(model.DataOrgRoles, "GitLab has no organization-roles equivalent")
	snap.Coverage.Missing(model.DataOrgRulesets, "GitLab uses per-project protected branches & push rules (collected as branch protection, #8)")
	snap.Coverage.Missing(model.DataCustomProperties, "GitLab has no repository custom-properties equivalent")
	// Branch protection, MR approval rules & CODEOWNERS are collected by
	// collectBranches (#8); they are not marked here.
}

// reasonFor turns a GitLab API error into a short human reason for a coverage
// gap, distinguishing 403 (permission/role) from 404 (absent/invisible).
func reasonFor(err error, action string) string {
	msg := glclient.Message(err)
	switch glclient.StatusCode(err) {
	case http.StatusForbidden:
		const hint = "check token scope or role"
		if msg != "" {
			return fmt.Sprintf("%s: forbidden, %s (%s)", action, msg, hint)
		}
		return fmt.Sprintf("%s: forbidden (%s)", action, hint)
	case http.StatusNotFound:
		const hint = "the resource may not exist or be visible to this token"
		if msg != "" {
			return fmt.Sprintf("%s: not found, %s (%s)", action, msg, hint)
		}
		return fmt.Sprintf("%s: not found (%s)", action, hint)
	}
	return fmt.Sprintf("%s: %v", action, err)
}
