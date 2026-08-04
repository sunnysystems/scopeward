package checks

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(ownerWithout2FA{}) }

// ownerWithout2FA flags organization owners who have 2FA disabled — the worst
// combination, since an owner account controls the entire org and a missing
// second factor makes it the softest possible target.
type ownerWithout2FA struct{}

func (ownerWithout2FA) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "human.owner-without-2fa",
		Title:           "Owners without 2FA",
		Axis:            model.AxisIdentity,
		DefaultSeverity: model.SevCritical,
		Kind:            check.KindDebt,
		RequiresData:    []model.DataKind{model.DataMembers, model.DataMemberRoles, model.DataMember2FA},
		Description:     "Organization owners whose account has two-factor authentication disabled.",
	}
}

func (c ownerWithout2FA) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, m := range s.Members {
		if m.Role != "admin" || m.TwoFactorEnabled == nil || *m.TwoFactorEnabled {
			continue
		}
		out = append(out, withFix(model.Finding{
			CheckID:     c.Meta().ID,
			Title:       "Org owner " + m.Login + " has 2FA disabled",
			Severity:    model.SevCritical,
			Axis:        model.AxisIdentity,
			Resource:    memberRef(m),
			Evidence:    map[string]any{"login": m.Login, "role": "admin"},
			Description: "This account has full control of the organization and can sign in with only a password. Compromising it compromises every repository, setting, and secret in the org.",
			Remediation: "Require this owner to enable 2FA immediately, and enforce 2FA organization-wide so it cannot be turned off.",
			DocsURL:     "https://docs.github.com/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization",
		}, ghOrgPatch(s.Org.Login, "two_factor_requirement_enabled", "true")))
	}
	return out
}
