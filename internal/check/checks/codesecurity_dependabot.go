package checks

import (
	"context"
	"fmt"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(repoDependabotAlertsOff{})
	check.Register(openDependabotAlerts{})
}

// repoDependabotAlertsOff flags repositories where Dependabot vulnerability
// alerts are disabled. Alerts are free for every repository, so this is a
// straightforward gap with a single-command fix.
type repoDependabotAlertsOff struct{}

func (repoDependabotAlertsOff) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "codesecurity.repo-dependabot-alerts-off",
		Title:           "Repos without Dependabot alerts",
		Axis:            model.AxisCodeSecurity,
		DefaultSeverity: model.SevMedium,
		RequiresData:    []model.DataKind{model.DataDependabotEnabled},
		Description:     "Repositories where Dependabot vulnerability alerts are disabled.",
	}
}

func (c repoDependabotAlertsOff) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range activeRepos(s) {
		if r.DependabotAlertsEnabled == nil || *r.DependabotAlertsEnabled {
			continue // unknown or enabled
		}
		fx := ghRepoEnableDependabotAlerts(s.Org.Login, r.Name)
		out = append(out, withFix(model.Finding{
			CheckID:     c.Meta().ID,
			Title:       "Dependabot alerts are off on " + s.Org.Login + "/" + r.Name,
			Severity:    model.SevMedium,
			Axis:        model.AxisCodeSecurity,
			Resource:    repoRef(s.Org.Login, r),
			Evidence:    map[string]any{"repo": r.Name, "dependabot_alerts": false},
			Description: "Dependabot vulnerability alerts are free for every repository and warn when a dependency has a known CVE. With them off, vulnerable dependencies go unflagged until someone notices by hand.",
			Remediation: "Enable Dependabot alerts on this repository (Settings -> Code security), and set it as an org default so new repos get it automatically.",
			DocsURL:     "https://docs.github.com/code-security/dependabot/dependabot-alerts/configuring-dependabot-alerts",
		}, fx))
	}
	return out
}

// openDependabotAlerts flags repositories that have open Dependabot alerts on
// their dependencies, deriving severity from the highest-severity open alert.
type openDependabotAlerts struct{}

func (openDependabotAlerts) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "codesecurity.open-dependabot-alerts",
		Title:           "Repos with open Dependabot alerts",
		Axis:            model.AxisCodeSecurity,
		DefaultSeverity: model.SevHigh,
		RequiresData:    []model.DataKind{model.DataOpenDependabotAlerts},
		Description:     "Repositories with open Dependabot vulnerability alerts on their dependencies.",
	}
}

func (c openDependabotAlerts) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	for _, r := range activeRepos(s) {
		a := r.OpenDependabotAlerts
		if a == nil || a.Total() == 0 {
			continue
		}
		// Severity tracks the most urgent open alert: a single critical CVE
		// outweighs any number of mediums.
		sev := model.SevMedium
		switch {
		case a.Critical > 0:
			sev = model.SevCritical
		case a.High > 0:
			sev = model.SevHigh
		}
		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    fmt.Sprintf("%s/%s has %d open Dependabot alert(s)", s.Org.Login, r.Name, a.Total()),
			Severity: sev,
			Axis:     model.AxisCodeSecurity,
			Resource: repoRef(s.Org.Login, r),
			Evidence: map[string]any{
				"repo":     r.Name,
				"critical": a.Critical,
				"high":     a.High,
				"medium":   a.Medium,
				"low":      a.Low,
				"total":    a.Total(),
			},
			Description: "Dependabot has flagged dependencies with known vulnerabilities in this repository. Critical and high-severity alerts are the most urgent to patch, since exploits are usually public.",
			Remediation: "Review the open Dependabot alerts and update the affected dependencies (or apply the suggested fix PRs). Start with the critical and high-severity ones.",
			DocsURL:     "https://docs.github.com/code-security/dependabot/dependabot-alerts/viewing-and-updating-dependabot-alerts",
		})
	}
	return out
}
