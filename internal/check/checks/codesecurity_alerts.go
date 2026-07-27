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
		// A committed secret is exposed whether or not the repo is read-only.
		SurvivesArchiving: true,
	}
}

func (c openSecretAlerts) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	var out []model.Finding
	// Deliberately s.Repos, not activeRepos: archiving a repository makes it
	// read-only, it does not un-leak a credential that is already in its history
	// and still valid. This is the one axis where archiving must not resolve the
	// finding, or the tool would teach archiving as a way to clear leaked secrets.
	//
	// The collector runs a narrow extra pass over archived repos for exactly this
	// signal, so the exemption is real rather than theoretical.
	for _, r := range s.Repos {
		if r.OpenSecretAlerts == nil || *r.OpenSecretAlerts == 0 {
			continue
		}
		n := *r.OpenSecretAlerts
		title := fmt.Sprintf("%s/%s has %d open secret-scanning alert(s)", s.Org.Login, r.Name, n)
		desc := "Secret scanning has found credentials committed to this repository that are still unresolved. A committed secret must be assumed compromised: anyone with read access (and anyone the history later reaches) can use it."
		fix := "Rotate the exposed credentials now, then resolve the alerts. Removing the commit is not enough; the secret was already exposed and must be invalidated."
		if r.Archived {
			// The usual repo-level advice does not apply: the repo is already
			// read-only and already archived, and the finding is about a credential
			// that lives outside it.
			title = fmt.Sprintf("Archived %s/%s still has %d open secret-scanning alert(s)", s.Org.Login, r.Name, n)
			desc = "Secret scanning found credentials committed to this repository, and archiving it did not resolve them. An archived repo is read-only, which stops new commits; it does nothing to a credential that is already in the history and still valid. These are the easiest exposures to forget, because nobody reviews a repository that was retired."
			fix = "Rotate these credentials. The repository being archived is not a mitigation — the secret is live wherever it is used, and revoking it there is the only fix. Deleting the repository would hide the alert without invalidating anything."
		}
		out = append(out, model.Finding{
			CheckID:     c.Meta().ID,
			Title:       title,
			Severity:    model.SevHigh,
			Axis:        model.AxisCodeSecurity,
			Resource:    repoRef(s.Org.Login, r),
			Evidence:    map[string]any{"repo": r.Name, "open_alerts": n, "archived": r.Archived},
			Description: desc,
			Remediation: fix,
			DocsURL:     "https://docs.github.com/code-security/secret-scanning/managing-alerts-from-secret-scanning",
		})
	}
	return out
}
