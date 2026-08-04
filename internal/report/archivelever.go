package report

import (
	"fmt"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/score"
)

// archiveLever quantifies what archiving the organization's dead repositories
// would resolve.
//
// For most orgs with history this is the highest-return remediation available,
// and nothing in the report used to say so: the action was represented only by
// hygiene.stale-repo, a low worth 2 points, while the same repos each carried a
// full stack of per-repo findings — unprotected branch, no owning team, alerts
// off, no CODEOWNERS. The report meanwhile suggested fixing those repos one by
// one, generating branch-protection and CODEOWNERS advice for repositories
// nobody has pushed to in three years. That is backwards on both effort and
// correctness: hardening an abandoned repo is busywork, archiving it is the
// governance-correct outcome, and it is reversible.
type archiveLever struct {
	Repos      int    // stale repositories
	Findings   int    // findings archiving would resolve
	Penalty    int    // penalty those findings carry
	ScoreNow   int    // the current score
	ScoreAfter int    // the score once those findings are gone
	GradeAfter string // the grade once those findings are gone
	Surviving  int    // findings on the same repos that archiving does NOT resolve
}

// buildArchiveLever computes the lever, or nil when there is nothing to say —
// no stale repos, or archiving them would not move the score.
//
// Findings from checks that declare SurvivesArchiving are counted separately
// rather than promised as resolved. Archiving a repository does not un-leak a
// credential committed to it, and a report that quietly counted those as fixed
// would be teaching archiving as a way to clear secret findings.
func buildArchiveLever(a Audit) *archiveLever {
	stale := map[string]bool{}
	for _, f := range a.Report.Findings {
		if f.CheckID == "hygiene.stale-repo" && f.Resource.Name != "" {
			stale[f.Resource.Name] = true
		}
	}
	if len(stale) == 0 {
		return nil
	}

	var remaining []model.Finding
	lever := archiveLever{Repos: len(stale), ScoreNow: a.Score.Value}
	for _, f := range a.Report.Findings {
		if !stale[f.Resource.Name] {
			remaining = append(remaining, f)
			continue
		}
		if meta, ok := check.Meta(f.CheckID); ok && meta.SurvivesArchiving {
			lever.Surviving++
			remaining = append(remaining, f)
			continue
		}
		lever.Findings++
	}
	if lever.Findings == 0 {
		return nil
	}

	// Archiving shrinks the denominator as well as the numerator, so the
	// hypothetical has to be scored at the size the org would then be. Scoring it
	// against today's repo count would credit archiving with a rate improvement
	// it does not produce — the archive lever is supposed to surface real
	// return, not manufacture it, and under a rate model the honest answer is
	// sometimes that archiving barely moves the number (issue #30).
	after := score.Grade(remaining, score.Scale{
		ActiveRepos: a.Snapshot.AssessedRepoCount() - lever.Repos,
	})
	lever.Penalty = a.Score.Penalty - after.Penalty
	lever.ScoreAfter, lever.GradeAfter = after.Value, after.Grade
	if lever.ScoreAfter <= lever.ScoreNow {
		return nil // nothing worth pointing at
	}
	return &lever
}

// summary is the one-sentence version used by every renderer.
func (l archiveLever) summary() string {
	repos := "1 repository has"
	if l.Repos != 1 {
		repos = fmt.Sprintf("%d repositories have", l.Repos)
	}
	return fmt.Sprintf(
		"%s had no push past the stale threshold. Archiving them resolves %s worth %d penalty (score %d → %d %s).",
		repos, plural(l.Findings, "finding"), l.Penalty,
		l.ScoreNow, l.ScoreAfter, l.GradeAfter)
}

// caution warns that archiving is not a scoring tactic: some findings on those
// repos stay true afterwards, and users should not learn to archive to make a
// number move.
func (l archiveLever) caution() string {
	if l.Surviving == 0 {
		return "Archiving is reversible and makes a repo read-only; it does not delete anything."
	}
	stay := "stay"
	if l.Surviving == 1 {
		stay = "stays"
	}
	return fmt.Sprintf(
		"Not counted above: %s on these repositories %s real after archiving — a committed credential is exposed whether or not the repo is read-only. Rotate those first.",
		plural(l.Surviving, "finding"), stay)
}
