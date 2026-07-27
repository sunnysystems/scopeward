package checks

import (
	"context"
	"testing"
	"time"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

// archivedExempt lists the checks that assess archived repositories on purpose.
// Everything else must stay silent on a repo nobody can push to. Adding an entry
// here is a deliberate decision, not a way to make this test pass.
var archivedExempt = map[string]string{
	"codesecurity.open-secret-alerts": "archiving makes a repo read-only; it does not un-leak a committed credential",
}

// loudRepo is a repository in the worst shape the model can express: every
// pointer field set to its bad value, every list populated with something a check
// should flag. Used to prove a fixture actually exercises the checks (when
// active) and that archiving silences them (when archived).
func loudRepo(archived bool) model.Repo {
	pushed := time.Now().Add(-3 * 365 * 24 * time.Hour)
	no, yes := false, true
	alerts := 3
	return model.Repo{
		Name:                   "abandoned",
		ID:                     1,
		Archived:               archived,
		PushedAt:               &pushed,
		DefaultBranch:          "main",
		DefaultBranchProtected: &no,
		DirectCollaborators: []model.RepoGrant{
			{Login: "carol", Permission: "admin"},
			{Login: "dan", Permission: "write"},
		},
		DeployKeys:              []model.DeployKey{{ID: 7, Title: "ci", ReadOnly: false}},
		Webhooks:                []model.Webhook{{ID: 9, URL: "http://hook.example", Active: true, HasSecret: false, InsecureSSL: true}},
		BotCommitters:           []model.CommitActivity{{Login: "release-bot", Commits: 40}},
		SecretScanning:          &no,
		PushProtection:          &no,
		OpenSecretAlerts:        &alerts,
		DependabotAlertsEnabled: &no,
		OpenDependabotAlerts:    &model.DependabotAlertSummary{Critical: 2, High: 9},
		BranchReqPRReview:       &no,
		BranchAllowForcePush:    &yes,
		BranchReqStatusChecks:   &no,
		BranchEnforceAdmins:     &no,
		WorkflowIssues: []model.WorkflowIssue{
			{File: "ci.yml", Kind: "unpinned-action", Detail: "third-party/scan@v1"},
			{File: "ci.yml", Kind: "internal-unpinned-action", Detail: "acme/infra/.github/workflows/deploy.yml@main"},
			{File: "ci.yml", Kind: "pull-request-target", Detail: "pull_request_target"},
		},
		CodeownersPresent:      &no,
		JobTokenInboundEnabled: &no,
	}
}

// firedChecks runs every registered check against a snapshot holding the given
// repos and returns the set of check IDs that produced a finding. It calls the
// checks directly rather than through the Runner, because the Runner's coverage
// gating would mask exactly the behaviour under test.
func firedChecks(t *testing.T, repos []model.Repo) map[string]bool {
	t.Helper()
	snap := model.NewSnapshot("acme")
	snap.Members = make([]model.Member, 2) // a team, so review-based checks are in scope
	snap.Repos = repos
	fired := map[string]bool{}
	for _, c := range check.All() {
		if len(c.Run(context.Background(), snap)) > 0 {
			fired[c.Meta().ID] = true
		}
	}
	return fired
}

// TestArchivedReposAreNotAssessed pins the invariant that used to live in the
// collector: a snapshot carrying an archived repo with fully populated detail
// fields must not produce findings about that repo. Checks used to be quiet here
// only because the collector left those fields nil — a coupling across packages
// that nothing stated and no test enforced (issue #32).
func TestArchivedReposAreNotAssessed(t *testing.T) {
	// Org-level checks fire regardless of any repo; subtract them out so this test
	// only judges repo-driven findings.
	orgLevel := firedChecks(t, nil)
	active := firedChecks(t, []model.Repo{loudRepo(false)})
	archived := firedChecks(t, []model.Repo{loudRepo(true)})

	repoDriven := func(got map[string]bool) []string {
		var out []string
		for id := range got {
			if !orgLevel[id] {
				out = append(out, id)
			}
		}
		return out
	}

	// Guard against a vacuous pass: if the fixture stopped triggering checks, the
	// archived assertion below would hold for the wrong reason.
	if n := len(repoDriven(active)); n < 15 {
		t.Fatalf("fixture only triggered %d repo-driven checks; it should exercise most of them", n)
	}

	for _, id := range repoDriven(archived) {
		if _, ok := archivedExempt[id]; !ok {
			t.Errorf("%s fires on an archived repository; add an explicit archived guard "+
				"(range activeRepos(s)) or, if assessing archived repos is intended, "+
				"document it in archivedExempt", id)
		}
	}

	// The exemptions must actually be reachable, or they are stale entries that
	// would quietly permit a future regression.
	for id, why := range archivedExempt {
		if !archived[id] {
			t.Errorf("archivedExempt lists %s (%s) but it does not fire on an archived repo; "+
				"drop the exemption", id, why)
		}
	}
}
