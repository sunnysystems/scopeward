package checks

import (
	"context"
	"strings"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(emailOutsideCompany{}) }

// emailOutsideCompany flags members whose SSO (SAML) identity resolves to an
// email outside the company's domains. The SAML nameId is the identifier the
// identity provider asserts — usually the corporate email — so a non-company
// domain can mean a personal account linked to org access, or an external party
// who should be governed deliberately.
type emailOutsideCompany struct{}

func (emailOutsideCompany) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "human.email-outside-company",
		Title:           "SSO identity outside company domain",
		Axis:            model.AxisIdentity,
		DefaultSeverity: model.SevMedium,
		Kind:            model.KindDebt,
		RequiresData:    []model.DataKind{model.DataSAMLIdentities, model.DataCompanyDomains},
		Description:     "Members whose SAML/SSO identity email is not on a company domain.",
	}
}

func (c emailOutsideCompany) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, m := range s.Members {
		domain, ok := emailDomain(m.SAMLNameID)
		if !ok {
			continue // no SAML identity, or nameId is not an email we can judge
		}
		if domainAllowed(domain, s.CompanyDomains) {
			continue
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       m.Login + " signs in via SSO with a non-company email (@" + domain + ")",
			Severity:    model.SevMedium,
			Axis:        model.AxisIdentity,
			Resource:    memberRef(m),
			Evidence:    map[string]any{"login": m.Login, "saml_name_id": m.SAMLNameID, "email_domain": domain},
			Description: "This member's SSO identity resolves to an email outside the configured company domains. It may be a personal account linked to org access, or an external collaborator who should be governed and offboarded deliberately.",
			Remediation: "Confirm this identity is expected. Require members to authenticate with a managed corporate account, and remove access that should not exist.",
			DocsURL:     "https://docs.github.com/organizations/managing-saml-single-sign-on-for-your-organization/about-identity-and-access-management-with-saml-single-sign-on",
		})
	}
	return out
}

// emailDomain extracts the lowercased domain from a value that looks like an
// email. Returns ok=false when the value is empty or not an email (e.g. an
// opaque SAML nameId), so non-email identifiers are not misjudged.
func emailDomain(nameID string) (string, bool) {
	at := strings.LastIndex(nameID, "@")
	if at < 0 || at == len(nameID)-1 {
		return "", false
	}
	domain := strings.ToLower(strings.TrimSpace(nameID[at+1:]))
	if domain == "" || strings.ContainsAny(domain, " @") {
		return "", false
	}
	return domain, true
}

// domainAllowed reports whether domain belongs to one of the company domains,
// matching exact domains and their subdomains (eng.mycompany.com ⊂ mycompany.com).
func domainAllowed(domain string, company []string) bool {
	for _, d := range company {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}
