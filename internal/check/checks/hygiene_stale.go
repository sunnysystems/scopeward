package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() { check.Register(staleRepo{}) }

// defaultStaleThreshold is used when the snapshot carries no configured value
// (e.g. direct unit tests); the CLI sets Snapshot.StaleAfter from --stale-after-days.
const defaultStaleThreshold = 365 * 24 * time.Hour

// staleRepo flags non-archived repositories with no push in over a year.
// Forgotten repos still carry access (collaborators, deploy keys, webhooks,
// secrets) that no one is reviewing — quiet attack surface.
type staleRepo struct{}

func (staleRepo) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "hygiene.stale-repo",
		Title:           "Stale repositories",
		Axis:            model.AxisHygiene,
		DefaultSeverity: model.SevLow,
		RequiresData:    []model.DataKind{model.DataRepos},
		Description:     "Active (non-archived) repositories with no commits in over a year.",
	}
}

func (c staleRepo) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	now := s.CollectedAt
	if now.IsZero() {
		now = time.Now()
	}
	// Precedence: the org's declared horizon, then --stale-after-days, then the
	// product default. A written-down decision outranks a flag someone typed,
	// because the flag is per-run and the policy file is the org's position.
	threshold := s.StaleAfter
	if threshold <= 0 {
		threshold = defaultStaleThreshold
	}
	if s.Policy != nil && s.Policy.Thresholds.StaleRepoAfterDays != nil {
		threshold = time.Duration(*s.Policy.Thresholds.StaleRepoAfterDays) * 24 * time.Hour
	}

	var out []model.Finding
	// Deliberately s.Repos, not activeRepos: this check is about the archived flag
	// itself — an archived repo is the outcome it recommends, so it has to see one
	// to know not to flag it.
	for _, r := range s.Repos {
		if r.Archived || r.PushedAt == nil {
			continue // archived is intentional; nil push date is unknown
		}
		age := now.Sub(*r.PushedAt)
		if age < threshold {
			continue
		}
		days := int(age.Hours() / 24)
		out = append(out, withFix(model.Finding{
			CheckID:     c.Meta().ID,
			Title:       fmt.Sprintf("%s/%s has no commits in %d days (last push %s)", s.Org.Login, r.Name, days, r.PushedAt.Format("2006-01-02")),
			Severity:    model.SevLow,
			Axis:        model.AxisHygiene,
			Resource:    repoRef(s.Org.Login, r),
			Evidence:    map[string]any{"repo": r.Name, "pushed_at": r.PushedAt.Format(time.RFC3339), "days_since_push": days, "private": r.Private},
			Description: "This repository has not received a commit in over a year but is not archived. Abandoned repos keep their collaborators, deploy keys, webhooks, and secrets active; access that survives offboarding and is rarely reviewed.",
			Remediation: "If the repo is no longer needed, archive it (which makes it read-only and removes it from active governance noise) or delete it. If it is still needed, confirm its access and credentials are still appropriate.",
			DocsURL:     "https://docs.github.com/repositories/archiving-a-github-repository/archiving-repositories",
		}, ghArchiveRepo(s.Org.Login, r.Name)))
	}
	return out
}
