package checks

import (
	"context"
	"strings"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(webhookHygiene{scope: "org"})
	check.Register(webhookHygiene{scope: "repo"})
}

// webhookHygiene flags active webhooks that lack a payload secret (so deliveries
// cannot be verified and can be spoofed) or disable SSL verification (so
// payloads — which may carry tokens — can be intercepted). One instance scans
// org-level hooks, the other repo-level, so each gates on its own coverage.
type webhookHygiene struct {
	scope string // "org" | "repo"
}

func (c webhookHygiene) Meta() check.CheckMeta {
	if c.scope == "org" {
		return check.CheckMeta{
			ID:              "nonhuman.org-webhook-insecure",
			Title:           "Insecure org webhooks",
			Axis:            model.AxisNonHuman,
			DefaultSeverity: model.SevMedium,
			RequiresData:    []model.DataKind{model.DataOrgWebhooks},
			Description:     "Org-level webhooks without a secret or with SSL verification disabled.",
		}
	}
	return check.CheckMeta{
		ID:              "nonhuman.repo-webhook-insecure",
		Title:           "Insecure repo webhooks",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevMedium,
		RequiresData:    []model.DataKind{model.DataRepoWebhooks},
		Description:     "Repository webhooks without a secret or with SSL verification disabled.",
	}
}

type scopedHook struct {
	hook    model.Webhook
	res     model.ResourceRef
	where   string
	apiPath string // REST path prefix for this hook: "orgs/{org}" or "repos/{org}/{repo}"
}

func (c webhookHygiene) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var items []scopedHook
	if c.scope == "org" {
		for _, h := range s.OrgWebhooks {
			items = append(items, scopedHook{hook: h, res: orgRef(s.Org), where: s.Org.Login, apiPath: "orgs/" + s.Org.Login})
		}
	} else {
		for _, r := range s.Repos {
			for _, h := range r.Webhooks {
				items = append(items, scopedHook{hook: h, res: repoRef(s.Org.Login, r), where: s.Org.Login + "/" + r.Name, apiPath: "repos/" + s.Org.Login + "/" + r.Name})
			}
		}
	}

	var out []model.Finding
	for _, it := range items {
		h := it.hook
		if !h.Active {
			continue // inactive hooks deliver nothing
		}
		if h.HasSecret && !h.InsecureSSL {
			continue // healthy
		}

		sev := model.SevMedium
		var reasons []string
		if h.InsecureSSL {
			sev = model.SevHigh
			reasons = append(reasons, "SSL verification disabled")
		}
		if !h.HasSecret {
			reasons = append(reasons, "no payload secret")
		}

		f := model.Finding{
			CheckID:     c.Meta().ID,
			Title:       "Insecure webhook on " + it.where + " (" + strings.Join(reasons, ", ") + ")",
			Severity:    sev,
			Axis:        model.AxisNonHuman,
			Resource:    it.res,
			Evidence:    map[string]any{"url": h.URL, "has_secret": h.HasSecret, "insecure_ssl": h.InsecureSSL, "issues": reasons},
			Description: "Webhooks send event payloads to an external endpoint. Without a secret the receiver cannot verify deliveries actually came from GitHub, and with SSL verification off the payload (which can include tokens) is exposed to interception.",
			Remediation: "Configure a webhook secret and verify the signature on the receiver; enable SSL verification and use an https endpoint.",
			DocsURL:     "https://docs.github.com/webhooks/using-webhooks/securing-your-webhooks",
		}
		// Only the SSL aspect is mechanically fixable; a missing secret needs a
		// value the operator chooses (so that stays in the remediation text).
		if h.InsecureSSL {
			f = withFix(f, ghFixWebhookSSL(it.apiPath, h.ID))
		}
		out = append(out, f)
	}
	return out
}
