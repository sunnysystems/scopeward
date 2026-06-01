package checks

import (
	"context"
	"fmt"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(openSecretAlerts{}) }

// openSecretAlerts flags repositories with open secret-scanning alerts — secrets
// that have actually been committed and are, until rotated, live credentials.
type openSecretAlerts struct{}

func (openSecretAlerts) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "codesecurity.open-secret-alerts",
		Title:           "Open secret-scanning alerts",
		Axis:            model.AxisCodeSecurity,
		DefaultSeverity: model.SevHigh,
		RequiresData:    []model.DataKind{model.DataOpenSecretAlerts},
		Description:     "Repositories with unresolved secret-scanning alerts (committed secrets).",
	}
}

func (c openSecretAlerts) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range s.Repos {
		if r.OpenSecretAlerts == nil || *r.OpenSecretAlerts == 0 {
			continue
		}
		n := *r.OpenSecretAlerts
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       fmt.Sprintf("%s/%s has %d open secret-scanning alert(s)", s.Org.Login, r.Name, n),
			Severity:    model.SevHigh,
			Axis:        model.AxisCodeSecurity,
			Resource:    repoRef(s.Org.Login, r),
			Evidence:    map[string]any{"repo": r.Name, "open_alerts": n},
			Description: "Secret scanning has found credentials committed to this repository that are still unresolved. A committed secret must be assumed compromised: anyone with read access (and anyone the history later reaches) can use it.",
			Remediation: "Rotate the exposed credentials now, then resolve the alerts. Removing the commit is not enough — the secret was already exposed and must be invalidated.",
			DocsURL:     "https://docs.github.com/code-security/secret-scanning/managing-alerts-from-secret-scanning",
		})
	}
	return out
}
