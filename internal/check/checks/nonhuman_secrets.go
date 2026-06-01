package checks

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(orgSecretVisibleAll{}) }

// orgSecretVisibleAll flags org Actions secrets readable by every repository,
// which spreads a single credential across the entire org's CI.
type orgSecretVisibleAll struct{}

func (orgSecretVisibleAll) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.org-secret-visible-all",
		Title:           "Org secrets exposed to all repos",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevMedium,
		RequiresData:    []model.DataKind{model.DataOrgSecrets},
		Description:     "Organization Actions secrets available to every repository (visibility: all).",
	}
}

func (c orgSecretVisibleAll) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, sec := range s.OrgSecrets {
		if sec.Visibility != "all" {
			continue
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       "Org secret " + sec.Name + " is readable by every repository",
			Severity:    model.SevMedium,
			Axis:        model.AxisNonHuman,
			Resource:    model.ResourceRef{Type: "secret", Name: sec.Name},
			Evidence:    map[string]any{"secret": sec.Name, "visibility": "all"},
			Description: "This secret is exposed to every repository in the org, so any workflow in any repo (including low-trust or experimental ones) can read it. One compromised workflow leaks a credential the whole org depends on.",
			Remediation: "Scope the secret to the specific repositories that need it (visibility: selected), or move it to those repos.",
			DocsURL:     "https://docs.github.com/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions#organization-secrets",
		})
	}
	return out
}
