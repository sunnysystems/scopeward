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

func (c repoNoPushProtection) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range activeRepos(s) {
		if r.PushProtection == nil || *r.PushProtection {
			continue // unknown or enabled
		}
		scanningOff := r.SecretScanning != nil && !*r.SecretScanning

		// Public repos get secret scanning + push protection for free; private
		// repos need GitHub Advanced Security, so the fix differs and the
		// actionability (hence severity) is lower.
		sev := model.SevHigh
		remediation := "Enable secret-scanning push protection on this repository (and org-wide for new repos)."
		if r.Private {
			sev = model.SevMedium
			remediation = "Enable push protection on this repo. For private repositories this requires GitHub Advanced Security; enable GHAS, or move the code to a context where it is covered."
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
