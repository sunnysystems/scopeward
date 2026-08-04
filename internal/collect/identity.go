package collect

import (
	"context"
	"errors"
	"net/url"

	"github.com/sunnysystems/scopeward/internal/ghclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// errSAMLNotConfigured means the org has no SAML identity provider, so there is
// nothing to compare members against (not a permission problem).
var errSAMLNotConfigured = errors.New("SAML SSO is not configured for this organization")

// userDTO is the shared shape of GitHub "simple user" objects.
type userDTO struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Type  string `json:"type"` // "User" | "Bot" | "Organization"
}

func (u userDTO) isBot() bool { return u.Type == "Bot" }

// collectOrg reads org-level settings. It returns adminVisible=true when fields
// that GitHub only exposes to org owners came back, which we use to decide
// whether owner-only data (like the 2FA filter) can be trusted.
func collectOrg(ctx context.Context, client *ghclient.Client, org string, snap *model.Snapshot) (adminVisible bool, err error) {
	var dto struct {
		Login                       string  `json:"login"`
		Name                        string  `json:"name"`
		ID                          int64   `json:"id"`
		DefaultRepoPermission       *string `json:"default_repository_permission"`
		TwoFactorRequirementEnabled *bool   `json:"two_factor_requirement_enabled"`
		Plan                        *struct {
			Name string `json:"name"`
		} `json:"plan"`
		MembersCanCreatePublicRepos *bool `json:"members_can_create_public_repositories"`
		MembersCanForkPrivateRepos  *bool `json:"members_can_fork_private_repositories"`
		// Undocumented in the REST reference for GET /orgs/{org}, but present on
		// the payload and owner-visible; verified against a live org. Absent for a
		// token that cannot see owner-only settings, which is already the condition
		// that marks DataOrg partial below.
		MembersCanChangeRepoVisibility *bool `json:"members_can_change_repo_visibility"`
		MembersCanDeleteRepos          *bool `json:"members_can_delete_repositories"`
		MembersCanInviteOutsideCollabs *bool `json:"members_can_invite_outside_collaborators"`
		SecretScanningDefault          *bool `json:"secret_scanning_enabled_for_new_repositories"`
		PushProtectionDefault          *bool `json:"secret_scanning_push_protection_enabled_for_new_repositories"`
		DependabotAlertsDefault        *bool `json:"dependabot_alerts_enabled_for_new_repositories"`
		WebCommitSignoffRequired       *bool `json:"web_commit_signoff_required"`
	}
	if _, err := client.Get(ctx, "/orgs/"+org, nil, &dto); err != nil {
		return false, err
	}

	snap.Org.Login = dto.Login
	snap.Org.Name = dto.Name
	snap.Org.ID = dto.ID
	if dto.Plan != nil {
		snap.Org.Plan = dto.Plan.Name
	}
	snap.Org.MembersCanCreatePublicRepos = dto.MembersCanCreatePublicRepos
	snap.Org.MembersCanForkPrivateRepos = dto.MembersCanForkPrivateRepos
	snap.Org.MembersCanChangeRepoVisibility = dto.MembersCanChangeRepoVisibility
	snap.Org.MembersCanDeleteRepos = dto.MembersCanDeleteRepos
	snap.Org.MembersCanInviteOutsideCollabs = dto.MembersCanInviteOutsideCollabs
	snap.Org.SecretScanningDefault = dto.SecretScanningDefault
	snap.Org.PushProtectionDefault = dto.PushProtectionDefault
	snap.Org.DependabotAlertsDefault = dto.DependabotAlertsDefault
	snap.Org.WebCommitSignoffRequired = dto.WebCommitSignoffRequired
	if dto.DefaultRepoPermission != nil {
		snap.Org.DefaultRepoPermission = *dto.DefaultRepoPermission
	}
	if dto.TwoFactorRequirementEnabled != nil {
		snap.Org.TwoFactorRequired = *dto.TwoFactorRequirementEnabled
	}

	adminVisible = dto.TwoFactorRequirementEnabled != nil
	if adminVisible {
		snap.Coverage.OK(model.DataOrg, 1)
	} else {
		snap.Coverage.Partial(model.DataOrg, 1, "org-owner-only settings (base permission, 2FA enforcement) not visible to this token")
	}
	return adminVisible, nil
}

// fetchMembers lists all organization members.
func fetchMembers(ctx context.Context, client *ghclient.Client, org string) ([]model.Member, error) {
	dtos, err := ghclient.GetAll[userDTO](ctx, client, "/orgs/"+org+"/members", nil)
	if err != nil {
		return nil, err
	}
	members := make([]model.Member, 0, len(dtos))
	for _, u := range dtos {
		members = append(members, model.Member{Login: u.Login, ID: u.ID, IsBot: u.isBot()})
	}
	return members, nil
}

// fetchLogins lists members filtered by a single query parameter and returns
// the set of logins, used for the 2FA-disabled and owner (role=admin) views.
func fetchLogins(ctx context.Context, client *ghclient.Client, org, key, val string) (map[string]bool, error) {
	q := url.Values{key: {val}}
	dtos, err := ghclient.GetAll[userDTO](ctx, client, "/orgs/"+org+"/members", q)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(dtos))
	for _, u := range dtos {
		set[u.Login] = true
	}
	return set, nil
}

// fetchOutsideCollaborators lists outside collaborators (non-members with repo
// access).
func fetchOutsideCollaborators(ctx context.Context, client *ghclient.Client, org string) ([]model.Collaborator, error) {
	dtos, err := ghclient.GetAll[userDTO](ctx, client, "/orgs/"+org+"/outside_collaborators", nil)
	if err != nil {
		return nil, err
	}
	out := make([]model.Collaborator, 0, len(dtos))
	for _, u := range dtos {
		out = append(out, model.Collaborator{Login: u.Login, ID: u.ID, IsBot: u.isBot()})
	}
	return out, nil
}

// samlQuery pages through the org's SAML external identities via GraphQL.
const samlQuery = `
query($login: String!, $cursor: String) {
  organization(login: $login) {
    samlIdentityProvider {
      externalIdentities(first: 100, after: $cursor) {
        pageInfo { hasNextPage endCursor }
        nodes { user { login } samlIdentity { nameId } }
      }
    }
  }
}`

// fetchSAMLIdentities returns a map of member login -> SAML nameId (the identity
// the IdP asserts, usually the corporate email). A login with an empty nameId is
// still present in the map (linked, but no usable identifier). If SAML SSO is not
// configured, samlIdentityProvider is null and we surface that as a coverage gap
// rather than an empty (misleading) result.
func fetchSAMLIdentities(ctx context.Context, client *ghclient.Client, org string) (map[string]string, error) {
	linked := make(map[string]string)
	var cursor *string

	for {
		var data struct {
			Organization struct {
				SAMLIdentityProvider *struct {
					ExternalIdentities struct {
						PageInfo struct {
							HasNextPage bool   `json:"hasNextPage"`
							EndCursor   string `json:"endCursor"`
						} `json:"pageInfo"`
						Nodes []struct {
							User *struct {
								Login string `json:"login"`
							} `json:"user"`
							SamlIdentity *struct {
								NameID string `json:"nameId"`
							} `json:"samlIdentity"`
						} `json:"nodes"`
					} `json:"externalIdentities"`
				} `json:"samlIdentityProvider"`
			} `json:"organization"`
		}

		vars := map[string]any{"login": org, "cursor": cursor}
		if err := client.GraphQL(ctx, samlQuery, vars, &data); err != nil {
			return nil, err
		}

		idp := data.Organization.SAMLIdentityProvider
		if idp == nil {
			return nil, errSAMLNotConfigured
		}
		for _, n := range idp.ExternalIdentities.Nodes {
			if n.User == nil || n.User.Login == "" {
				continue
			}
			nameID := ""
			if n.SamlIdentity != nil {
				nameID = n.SamlIdentity.NameID
			}
			linked[n.User.Login] = nameID
		}
		if !idp.ExternalIdentities.PageInfo.HasNextPage {
			return linked, nil
		}
		end := idp.ExternalIdentities.PageInfo.EndCursor
		cursor = &end
	}
}
