package checks

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(no2FA{})
	check.Register(orgNo2FAEnforcement{})
}

// no2FA flags individual members who can authenticate without a second factor.
type no2FA struct{}

func (no2FA) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "human.no-2fa",
		Title:           "Members without 2FA",
		Axis:            model.AxisIdentity,
		DefaultSeverity: model.SevHigh,
		Kind:            check.KindDebt,
		RequiresData:    []model.DataKind{model.DataMembers, model.DataMember2FA},
		Description:     "Org members whose account has two-factor authentication disabled.",
	}
}

func (c no2FA) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, m := range s.Members {
		if m.TwoFactorEnabled == nil || *m.TwoFactorEnabled {
			continue
		}
		out = append(out, withFix(model.Finding{
			CheckID:     c.Meta().ID,
			Title:       "Member has two-factor authentication disabled",
			Severity:    model.SevHigh,
			Axis:        model.AxisIdentity,
			Resource:    memberRef(m),
			Evidence:    map[string]any{"login": m.Login, "role": m.Role},
			Description: "This account can sign in with only a password, making it a soft target for credential theft and account takeover.",
			Remediation: "Ask the member to enable 2FA, then enforce 2FA organization-wide so it cannot be turned off.",
			DocsURL:     "https://docs.github.com/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization",
		}, ghOrgPatch(s.Org.Login, "two_factor_requirement_enabled", "true")))
	}
	return out
}

// orgNo2FAEnforcement flags the org when it does not require 2FA for everyone.
type orgNo2FAEnforcement struct{}

func (orgNo2FAEnforcement) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "human.org-2fa-not-enforced",
		Title:           "Org-wide 2FA not enforced",
		Axis:            model.AxisIdentity,
		DefaultSeverity: model.SevHigh,
		Kind:            check.KindCoverage,
		RequiresData:    []model.DataKind{model.DataOrg},
		Description:     "Whether the organization requires two-factor authentication for all members.",
	}
}

func (c orgNo2FAEnforcement) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	if s.Org.TwoFactorRequired {
		return nil
	}
	return []model.Finding{withFix(model.Finding{
		CheckID:     c.Meta().ID,
		Title:       "Organization does not enforce 2FA for all members",
		Severity:    model.SevHigh,
		Axis:        model.AxisIdentity,
		Resource:    orgRef(s.Org),
		Evidence:    map[string]any{"two_factor_required": false},
		Description: "Without org-wide enforcement, any member or future member can disable 2FA, leaving a gap that per-account checks cannot durably close.",
		Remediation: "Enable \"Require two-factor authentication\" in the organization's authentication security settings.",
		DocsURL:     "https://docs.github.com/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization",
	}, ghOrgPatch(s.Org.Login, "two_factor_requirement_enabled", "true"))}
}
