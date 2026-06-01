package checks

import (
	"context"
	"strconv"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(patNoExpiry{}) }

// patNoExpiry flags fine-grained personal access tokens with org access that
// never expire. A non-expiring token is a standing credential that stays valid
// long after the person's need (or employment) ends.
type patNoExpiry struct{}

func (patNoExpiry) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.pat-no-expiry",
		Title:           "Non-expiring PATs",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevMedium,
		RequiresData:    []model.DataKind{model.DataFineGrainedPATs},
		Description:     "Fine-grained personal access tokens with org access that have no expiration.",
	}
}

func (c patNoExpiry) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, p := range s.PATs {
		if p.ExpiresAt != nil {
			continue
		}
		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    "Non-expiring PAT owned by " + p.OwnerLogin,
			Severity: model.SevMedium,
			Axis:     model.AxisNonHuman,
			Resource: model.ResourceRef{
				Type: "pat",
				ID:   strconv.FormatInt(p.ID, 10),
				Name: p.OwnerLogin,
				URL:  "https://github.com/" + p.OwnerLogin,
			},
			Evidence:    map[string]any{"owner": p.OwnerLogin, "permission_count": len(p.Permissions)},
			Description: "This token has access to org resources and no expiry, so it remains a valid credential indefinitely, including after the owner changes roles or leaves. Leaked or forgotten, it is durable access no one is watching.",
			Remediation: "Require an expiration on fine-grained PATs via org policy, and ask the owner to reissue this token with a bounded lifetime.",
			DocsURL:     "https://docs.github.com/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization",
		})
	}
	return out
}
