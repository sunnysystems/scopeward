package checks

import (
	"context"
	"strconv"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(oauthAppTrusted{}) }

// oauthAppTrusted flags OAuth applications that bypass the user consent screen.
// A "trusted" GitLab application is authorized for every user automatically, and
// a non-confidential (public) one cannot keep a client secret — both widen the
// blast radius of the app's access without an explicit per-user grant.
type oauthAppTrusted struct{}

func (oauthAppTrusted) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "nonhuman.oauth-app-trusted",
		Title:           "Trusted or public OAuth apps",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevMedium,
		Kind:            check.KindDebt,
		RequiresData:    []model.DataKind{model.DataOAuthApps},
		Description:     "OAuth applications that skip the user consent screen (trusted) or cannot hold a client secret (non-confidential).",
	}
}

func (c oauthAppTrusted) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, app := range s.OAuthApps {
		if !app.Trusted && app.Confidential {
			continue // a confidential, consent-gated app is the expected case
		}
		reason := "is non-confidential (cannot keep a client secret)"
		sev := model.SevLow
		if app.Trusted {
			reason = "is trusted (authorized for every user without consent)"
			sev = model.SevMedium
		}
		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    "OAuth app \"" + app.Name + "\" " + reason,
			Severity: sev,
			Axis:     model.AxisNonHuman,
			Resource: model.ResourceRef{Type: "oauth_app", ID: strconv.FormatInt(app.ID, 10), Name: app.Name},
			Evidence: map[string]any{
				"name": app.Name, "app_id": app.ID,
				"trusted": app.Trusted, "confidential": app.Confidential, "callback_url": app.CallbackURL,
			},
			Description: "Trusted OAuth applications are granted to every user without the consent screen, so their access is never reviewed per user; non-confidential apps cannot protect a client secret. Either way the application's reach is wider and less attributable than a standard confidential app.",
			Remediation: "Confirm the application still needs to be trusted; prefer confidential apps with explicit per-user authorization, and remove unused applications.",
			DocsURL:     "https://docs.gitlab.com/ee/integration/oauth_provider.html",
		})
	}
	return out
}
