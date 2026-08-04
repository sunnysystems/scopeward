package checks

import (
	"sort"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/check"
)

// coverageChecks is the classification, pinned. It is written out rather than
// derived so that changing which axis a check lands on is a visible diff — under
// the score model this decides which half of the number a finding moves, and a
// quiet reclassification would shift scores with nothing to review (#39).
//
// Coverage means a control, protection or policy that should be on is off, weak
// or absent; the fix is a setting. Everything else is debt: a thing exists and
// is a problem, and the fix removes, rotates or revokes it.
var coverageChecks = map[string]bool{
	// Monitoring controls. These are the ones whose *enabling* reveals debt, so
	// they are the reason the two axes have to be separated at all (#27).
	"codesecurity.repo-dependabot-alerts-off":    true,
	"codesecurity.repo-no-push-protection":       true,
	"codesecurity.secret-scanning-default-off":   true,
	"codesecurity.push-protection-default-off":   true,
	"codesecurity.dependabot-alerts-default-off": true,

	"human.org-2fa-not-enforced": true,

	"teams.unprotected-default-branch":   true,
	"teams.weak-branch-protection":       true,
	"teams.branch-protection-bypassable": true,
	"teams.ruleset-not-enforced":         true,
	"teams.mr-approval-bypassable":       true,

	"teams.repo-no-codeowner":         true,
	"teams.repo-no-owning-team":       true,
	"teams.repo-no-owning-property":   true,
	"policy.repo-without-owning-team": true,

	"teams.base-permission-open":                     true,
	"teams.members-can-create-public-repos":          true,
	"teams.members-can-fork-private-repos":           true,
	"teams.members-can-change-repo-visibility":       true,
	"teams.members-can-delete-repos":                 true,
	"teams.members-can-invite-outside-collaborators": true,

	"nonhuman.actions-policy-open":         true,
	"nonhuman.actions-token-write-default": true,
	"nonhuman.actions-can-approve-prs":     true,
	"nonhuman.ci-job-token-open":           true,
}

// TestEveryCheckDeclaresItsKind: the registry panics on an unclassified check,
// so reaching this test at all proves every registered check declared one. What
// this adds is that the declaration matches the reviewed classification above.
func TestEveryCheckDeclaresItsKind(t *testing.T) {
	var wrong []string
	for _, c := range check.All() {
		m := c.Meta()
		want := check.KindDebt
		if coverageChecks[m.ID] {
			want = check.KindCoverage
		}
		if m.Kind != want {
			wrong = append(wrong, m.ID+": is "+string(m.Kind)+", table says "+string(want))
		}
	}
	if len(wrong) > 0 {
		sort.Strings(wrong)
		t.Errorf("classification drifted from the reviewed table:\n  %s", strings.Join(wrong, "\n  "))
	}
}

// TestCoverageTableHasNoStaleEntries: an entry naming a check that no longer
// exists is dead config that looks like a decision. Renaming a check without
// updating the table would silently move it to debt.
func TestCoverageTableHasNoStaleEntries(t *testing.T) {
	live := map[string]bool{}
	for _, c := range check.All() {
		live[c.Meta().ID] = true
	}
	for id := range coverageChecks {
		if !live[id] {
			t.Errorf("coverageChecks names %q, which is not registered", id)
		}
	}
}

// TestBothKindsArePopulated guards against a vacuous pass: if a refactor made
// every check one kind, the assertions above would still hold.
func TestBothKindsArePopulated(t *testing.T) {
	var cov, debt int
	for _, c := range check.All() {
		if c.Meta().Kind == check.KindCoverage {
			cov++
		} else {
			debt++
		}
	}
	if cov < 10 || debt < 10 {
		t.Errorf("coverage=%d debt=%d — one axis is nearly empty, which is not a real classification", cov, debt)
	}
	t.Logf("coverage=%d debt=%d of %d checks", cov, debt, len(check.All()))
}
