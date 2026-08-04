package checks

import (
	"context"
	"strings"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(classicPATBroadScope{}) }

// broadScopes are classic-PAT scopes that grant wide, coarse access. "repo" is
// full control of all repos the user can see; the admin/delete scopes are
// org/infra-level.
var broadScopes = map[string]bool{
	"repo":             true,
	"admin:org":        true,
	"write:org":        true,
	"delete_repo":      true,
	"admin:repo_hook":  true,
	"admin:public_key": true,
	"workflow":         true,
}

// classicPATBroadScope flags SSO-authorized classic personal access tokens that
// carry broad scopes. Classic PATs are long-lived, coarse-grained credentials;
// a broad one is a wide blast radius tied to a single user.
type classicPATBroadScope struct{}

func (classicPATBroadScope) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.classic-pat-broad-scope",
		Title:           "Broadly-scoped classic PATs",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevHigh,
		Kind:            check.KindDebt,
		RequiresData:    []model.DataKind{model.DataCredentialAuthorizations},
		Description:     "SSO-authorized classic personal access tokens holding broad scopes.",
	}
}

func (c classicPATBroadScope) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, cred := range s.CredentialAuthorizations {
		if !strings.Contains(strings.ToLower(cred.CredentialType), "personal access token") {
			continue
		}
		var broad []string
		hasAdmin := false
		for _, sc := range cred.Scopes {
			if broadScopes[sc] {
				broad = append(broad, sc)
				if strings.HasPrefix(sc, "admin:") || sc == "delete_repo" {
					hasAdmin = true
				}
			}
		}
		if len(broad) == 0 {
			continue
		}
		sev := model.SevMedium
		if hasAdmin {
			sev = model.SevHigh
		}
		f := model.Finding{
			CheckID:     c.Meta().ID,
			Title:       cred.Login + " has a classic PAT with broad scopes (" + strings.Join(broad, ", ") + ")",
			Severity:    sev,
			Axis:        model.AxisNonHuman,
			Resource:    model.ResourceRef{Type: "member", Name: cred.Login, URL: "https://github.com/" + cred.Login},
			Evidence:    map[string]any{"login": cred.Login, "scopes": cred.Scopes, "broad_scopes": broad},
			Description: "Classic personal access tokens are long-lived and coarse: a single broad scope like \"repo\" grants full control of every repository the user can access. Tied to one person, leaked or phished, it is a wide and durable breach.",
			Remediation: "Ask the owner to replace it with a fine-grained token scoped to the specific repos and permissions needed, with an expiration; consider an org policy restricting classic PATs.",
			DocsURL:     "https://docs.github.com/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization",
		}
		// Revoking the SSO authorization immediately cuts off this token's org
		// access (the owner re-authorizes a properly-scoped one if still needed).
		if cred.CredentialID != 0 {
			f = withFix(f, ghRevokeCredential(s.Org.Login, cred.CredentialID))
		}
		out = append(out, f)
	}
	return out
}
