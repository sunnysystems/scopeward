package checks

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(repoNoPushProtection{}) }

// repoNoPushProtection flags repositories without secret-scanning push
// protection, which blocks secrets from being committed in the first place.
type repoNoPushProtection struct{}

func (repoNoPushProtection) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "codesecurity.repo-no-push-protection",
		Title:           "Repos without push protection",
		Axis:            model.AxisCodeSecurity,
		DefaultSeverity: model.SevHigh,
		RequiresData:    []model.DataKind{model.DataRepoSecurity},
		Description:     "Repositories where secret-scanning push protection is not enabled.",
	}
}

// paywalled reports whether this repo's push protection is behind an
// entitlement the org does not hold. Push protection is free on public
// repositories on every plan, so the gate is per repository: an org-level gate
// would go silent on exactly the repos where an exposed secret is worst.
//
// Only a confirmed-absent entitlement suppresses. Unknown reports as before —
// suppressing on "we could not tell" would hide fixable exposure, which is the
// failure this gate exists to avoid, pointed the other way.
func paywalled(s *model.Snapshot, r model.Repo) bool {
	return r.Private && s.Entitlement(model.EntSecretProtection).State == model.EntitlementAbsent
}

// Limitation reports the private repositories left unassessed because the org
// cannot enable push protection on them. Without this, dropping them would read
// as a clean bill of health for repos nobody looked at.
func (c repoNoPushProtection) Limitation(s *model.Snapshot) *check.Limitation {
	var assessed, omitted int
	for _, r := range activeRepos(s) {
		if paywalled(s, r) {
			omitted++
			continue
		}
		assessed++
	}
	if omitted == 0 {
		return nil
	}
	return &check.Limitation{
		CheckID:  c.Meta().ID,
		Title:    c.Meta().Title,
		Axis:     model.AxisCodeSecurity,
		Reason:   "private repositories require GitHub Secret Protection, which this organization does not have: " + s.Entitlement(model.EntSecretProtection).Reason,
		Assessed: assessed,
		Omitted:  omitted,
	}
}

func (c repoNoPushProtection) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range activeRepos(s) {
		if r.PushProtection == nil || *r.PushProtection {
			continue // unknown or enabled
		}
		// The only remediation is a purchase, so this is not a finding — it is an
		// invoice. Reported via Limitation instead (issue #50).
		if paywalled(s, r) {
			continue
		}
		scanningOff := r.SecretScanning != nil && !*r.SecretScanning

		// Public repos get push protection for free on every plan. Private repos
		// need GitHub Secret Protection: when the org holds it the fix is the same
		// one command, and when it does not the repo never reaches this loop.
		// Severity stays lower for private repos because the exposure of a leaked
		// secret is bounded by who can read the repository.
		sev := model.SevHigh
		remediation := "Enable secret-scanning push protection on this repository (and org-wide for new repos)."
		if r.Private {
			sev = model.SevMedium
			remediation = "Enable push protection on this repo, and org-wide for new private repos. This is covered by the organization's GitHub Secret Protection entitlement."
		}

		title := "Push protection is off on " + s.Org.Login + "/" + r.Name
		if scanningOff {
			title = "Secret scanning and push protection are off on " + s.Org.Login + "/" + r.Name
		}

		fx := ghRepoEnablePushProtection(s.Org.Login, r.Name)
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       title,
			Severity:    sev,
			Axis:        model.AxisCodeSecurity,
			Resource:    repoRef(s.Org.Login, r),
			Evidence:    map[string]any{"repo": r.Name, "private": r.Private, "secret_scanning": r.SecretScanning, "push_protection": false},
			Description: "Without push protection, a committed secret is only detected after it has already been pushed (if at all); by then it must be treated as leaked and rotated. Push protection blocks the commit at the source.",
			Remediation: remediation,
			GHFix:       fx.cmd,
			GHVerify:    fx.verify,
			DocsURL:     "https://docs.github.com/code-security/secret-scanning/push-protection-for-repositories-and-organizations",
		})
	}
	return out
}
