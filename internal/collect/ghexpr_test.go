package collect

import "testing"

func TestAdmitsNonWriter(t *testing.T) {
	const repo = "acme/api"
	cases := []struct {
		name, cond, event string
		want              bool
	}{
		{"no condition", "", "issues", true},
		{"association allow-list", `contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)`, "issue_comment", false},
		{"association equality chain", `github.event.comment.author_association == 'OWNER' || github.event.comment.author_association == 'MEMBER'`, "issue_comment", false},
		{"association excludes only NONE", `github.event.comment.author_association != 'NONE'`, "issue_comment", true},
		{"named actor", `github.actor == 'alice'`, "issues", false},
		{"actor allow-list", `contains(fromJSON('["alice","bob"]'), github.actor)`, "issues", false},
		{"negative actor test admits everyone else", `github.actor != 'dependabot[bot]'`, "issues", true},
		{"comment body is the attacker's", `contains(github.event.comment.body, '@claude')`, "issue_comment", true},
		{"fork guard alone", `github.repository == 'acme/api'`, "issues", true},
		{"fork guard for another repo never runs here", `github.repository == 'acme/other'`, "issues", false},
		{"unknown variable never proves a gate", `vars.AGENT_ENABLED == 'true'`, "issues", true},
		{"strings compare without case", `github.event.comment.author_association == 'owner'`, "issue_comment", false},
		{"wrapped in ${{ }}", `${{ github.actor == 'alice' }}`, "issues", false},
		{"unparseable", `github.actor == 'alice`, "issues", true},
		// The shape that motivated evaluating per event: the association test
		// only guards comments, so an opened issue goes straight through.
		{
			"guard covers comments, issues open: issues", `(github.event_name == 'issues' || github.event_name == 'issue_comment') &&
			  (github.event_name != 'issue_comment' || (
			    contains(github.event.comment.body, '@bot /triage') &&
			    (github.event.comment.author_association == 'OWNER' || github.event.comment.author_association == 'MEMBER')
			  )) && !contains(github.event.issue.labels.*.name, 'triaged')`,
			"issues", true,
		},
		{
			"guard covers comments, issues open: issue_comment", `(github.event_name == 'issues' || github.event_name == 'issue_comment') &&
			  (github.event_name != 'issue_comment' || (
			    contains(github.event.comment.body, '@bot /triage') &&
			    (github.event.comment.author_association == 'OWNER' || github.event.comment.author_association == 'MEMBER')
			  ))`,
			"issue_comment", false,
		},
		{"event the job never runs on", `github.event_name == 'workflow_dispatch'`, "issues", false},
		{"true literal", "true", "issues", true},
		{"false literal", "false", "issues", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cond any = tc.cond
			if tc.cond == "" {
				cond = nil
			}
			if got := admitsNonWriter(cond, tc.event, repo); got != tc.want {
				t.Errorf("admitsNonWriter(%q, %s) = %v, want %v", tc.cond, tc.event, got, tc.want)
			}
		})
	}
	// YAML decodes `if: false` to a bool, not a string.
	if admitsNonWriter(false, "issues", repo) {
		t.Error("if: false (bool) admitted a non-writer")
	}
}
