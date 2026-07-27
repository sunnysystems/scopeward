package collect

import (
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func prRule(approvals int) branchRule {
	r := branchRule{Type: "pull_request"}
	r.Parameters.RequiredApprovingReviewCount = approvals
	return r
}

// A ruleset-protected branch must land on the same neutral fields classic
// protection fills, so the checks assess both mechanisms identically. Before
// this, ruleset-protected repos were checked for whether protection existed and
// never for whether it was any good (issue #34).
func TestRulesToProtection(t *testing.T) {
	cases := []struct {
		name       string
		rules      []branchRule
		wantPR     bool
		wantForce  bool // force-pushes allowed
		wantChecks bool
	}{
		{
			name: "strong ruleset",
			rules: []branchRule{
				prRule(2),
				{Type: "non_fast_forward"},
				{Type: "required_status_checks"},
				{Type: "deletion"},
			},
			wantPR: true, wantForce: false, wantChecks: true,
		},
		{
			// The case the check could not previously tell apart from a strong one.
			name:   "deliberately weak ruleset",
			rules:  []branchRule{prRule(0)},
			wantPR: false, wantForce: true, wantChecks: false,
		},
		{
			// A PR is required but nobody has to look at it — classic protection
			// reports this same state as "no required review".
			name:   "pull request with zero approvals is not a review",
			rules:  []branchRule{prRule(0), {Type: "non_fast_forward"}},
			wantPR: false, wantForce: false, wantChecks: false,
		},
		{
			// Rules merge across repository- and organization-level rulesets; the
			// strongest pull_request rule wins.
			name:   "merged rulesets take the strongest review requirement",
			rules:  []branchRule{prRule(0), prRule(1)},
			wantPR: true, wantForce: true, wantChecks: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rulesToProtection(tc.rules)
			if got == nil {
				t.Fatal("no protection detail produced")
			}
			if got.source != model.BranchProtectionRuleset {
				t.Errorf("source = %q, want ruleset", got.source)
			}
			if *got.reqPR != tc.wantPR {
				t.Errorf("reqPR = %v, want %v", *got.reqPR, tc.wantPR)
			}
			if *got.allowForce != tc.wantForce {
				t.Errorf("allowForce = %v, want %v", *got.allowForce, tc.wantForce)
			}
			if *got.reqChecks != tc.wantChecks {
				t.Errorf("reqChecks = %v, want %v", *got.reqChecks, tc.wantChecks)
			}
			// Bypass actors live on the ruleset object, not on the effective rules,
			// so admin enforcement stays unknown rather than being guessed at.
			if got.enforceAdmins != nil {
				t.Errorf("enforceAdmins = %v, want nil (not readable from effective rules)", *got.enforceAdmins)
			}
		})
	}
}

// No rules means no ruleset covers the branch. That must read as "not assessed",
// never as a clean pass — the whole point of #34 is that silence looked like
// approval.
func TestRulesToProtection_NoRulesIsNotAssessed(t *testing.T) {
	if got := rulesToProtection(nil); got != nil {
		t.Errorf("got %+v, want nil for a branch no ruleset covers", got)
	}
	if got := rulesToProtection([]branchRule{}); got != nil {
		t.Errorf("got %+v, want nil for an empty rule list", got)
	}
}
