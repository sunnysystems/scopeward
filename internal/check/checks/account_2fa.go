package checks

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(accountNo2FA{}) }

// accountNo2FA flags the audited account itself having 2FA disabled (user/--me
// mode). It is the single most important control for an individual account.
type accountNo2FA struct{}

func (accountNo2FA) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "account.no-2fa",
		Title:           "Account without 2FA",
		Axis:            model.AxisIdentity,
		DefaultSeverity: model.SevHigh,
		RequiresData:    []model.DataKind{model.DataAccount},
		Description:     "Whether the audited account has two-factor authentication enabled.",
	}
}

func (c accountNo2FA) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	if s.AccountTwoFactor == nil || *s.AccountTwoFactor {
		return nil
	}
	return []model.Finding{{
		CheckID:     c.Meta().ID,
		Title:       "Account " + s.Org.Login + " has 2FA disabled",
		Severity:    model.SevHigh,
		Axis:        model.AxisIdentity,
		Resource:    model.ResourceRef{Type: "account", Name: s.Org.Login, URL: "https://github.com/" + s.Org.Login},
		Evidence:    map[string]any{"login": s.Org.Login, "two_factor_authentication": false},
		Description: "This account can sign in with only a password. For an account that owns repositories and may hold tokens, a missing second factor is the easiest path to full takeover.",
		Remediation: "Enable two-factor authentication on the account now (Settings → Password and authentication).",
		DocsURL:     "https://docs.github.com/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication",
	}}
}
