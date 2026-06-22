// Package collectgl performs the read-only GitLab API calls that fill a
// provider-neutral model.Snapshot for the human-identity axis. It mirrors the
// internal/collect (GitHub) package: collectors do all the I/O and record
// coverage; the pure checks read the resulting snapshot and never re-query.
//
// Only the identity axis is implemented here (#4). Data that needs more than
// identity (teams/projects, SAML/SCIM, invitations, outside collaborators) is
// recorded as a coverage gap so dependent checks degrade to "not evaluated"
// rather than a false pass; those axes land in #5–#9.
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

	markNotCollected(snap)

	snap.CollectedAt = Now()
	return snap, nil
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
	snap.Coverage.Missing(model.DataOutsideCollaborators, "GitLab has no direct equivalent; modeled via project membership, collected with projects (#5)")
	snap.Coverage.Missing(model.DataPendingInvitations, "pending group invitations are not collected yet")
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
