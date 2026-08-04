package checks

import (
	"context"
	"fmt"
	"strings"

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
		Kind:            model.KindCoverage,
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
//
// Severity and weight are different questions, and this check answers only the
// first. "One critical CVE outweighs any number of mediums" is right for how
// urgent a repository is; it says nothing about how much work it represents. A
// repo with 1 critical and a repo with 1 critical plus 98 others are both
// critical, and triage order is the main thing a reader wants here — so the
// counts appear in the title and the remediation rather than being buried in the
// evidence. Making volume move the *score* is a scoring-model question, left to
// the model redesign so it is decided once rather than patched per check.
type openDependabotAlerts struct{}

// alertBreakdown renders the per-severity counts, omitting empty bands, so a
// 99-alert repo is distinguishable from a 1-alert one at a glance.
func alertBreakdown(a model.DependabotAlertSummary) string {
	var parts []string
	for _, band := range []struct {
		n    int
		name string
	}{{a.Critical, "critical"}, {a.High, "high"}, {a.Medium, "medium"}, {a.Low, "low"}} {
		if band.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", band.n, band.name))
		}
	}
	return strings.Join(parts, ", ")
}

func (openDependabotAlerts) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "codesecurity.open-dependabot-alerts",
		Title:           "Repos with open Dependabot alerts",
		Axis:            model.AxisCodeSecurity,
		DefaultSeverity: model.SevHigh,
		Kind:            model.KindDebt,
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
		urgent := a.Critical + a.High
		remediation := "Review the open Dependabot alerts and update the affected dependencies (or apply the suggested fix PRs)."
		if urgent > 0 {
			remediation = fmt.Sprintf("Start with the %d critical/high alert(s) — those are where exploits are usually public — then work through the remaining %d. Applying Dependabot's suggested fix PRs handles most of them.",
				urgent, a.Total()-urgent)
		}
		out = append(out, model.Finding{
			CheckID:  c.Meta().ID,
			Title:    fmt.Sprintf("%s/%s has %d open Dependabot alert(s) (%s)", s.Org.Login, r.Name, a.Total(), alertBreakdown(*a)),
			Severity: sev,
			Axis:     model.AxisCodeSecurity,
			// Severity stays driven by the worst alert, which is right. Volume
			// carries how many there are, which is a different question the score
			// currently ignores — one critical CVE and one critical plus
			// ninety-eight others weigh the same today (#31).
			Volume:   a.Total(),
			Resource: repoRef(s.Org.Login, r),
			Evidence: map[string]any{
				"repo":     r.Name,
				"critical": a.Critical,
				"high":     a.High,
				"medium":   a.Medium,
				"low":      a.Low,
				"total":    a.Total(),
			},
			Description: "Dependabot has flagged dependencies with known vulnerabilities in this repository. Severity here reflects the most urgent alert, not how many there are — the counts in the title are what tells you how much work this repository represents relative to the others.",
			Remediation: remediation,
			DocsURL:     "https://docs.github.com/code-security/dependabot/dependabot-alerts/viewing-and-updating-dependabot-alerts",
		})
	}
	return out
}
