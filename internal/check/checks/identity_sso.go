package checks

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(notSSOLinked{}) }

// notSSOLinked flags members who have no SAML identity linked, meaning their
// access is not governed by the organization's identity provider.
type notSSOLinked struct{}

func (notSSOLinked) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "human.not-sso-linked",
		Title:           "Members outside SSO",
		Axis:            model.AxisIdentity,
		DefaultSeverity: model.SevMedium,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataMembers, model.DataSAMLIdentities},
		Description:     "Members with no SAML identity linked to the org's identity provider.",
	}
}

func (c notSSOLinked) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, m := range s.Members {
		if m.SAMLLinked == nil || *m.SAMLLinked {
			continue
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       "Member is not linked to the SSO identity provider",
			Severity:    model.SevMedium,
			Axis:        model.AxisIdentity,
			Resource:    memberRef(m),
			Evidence:    map[string]any{"login": m.Login},
			Description: "This member's access is not tied to the central identity provider, so deprovisioning them in the IdP will not revoke their GitHub access.",
			Remediation: "Have the member authenticate through SSO to link their identity, or remove them if they should no longer have access.",
			DocsURL:     "https://docs.github.com/organizations/managing-saml-single-sign-on-for-your-organization/about-identity-and-access-management-with-saml-single-sign-on",
		})
	}
	return out
}
