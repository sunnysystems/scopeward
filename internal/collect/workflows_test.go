package collect

import "testing"

func TestScanWorkflow(t *testing.T) {
	content := `
name: ci
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@8c5b4f0  # short tag, official → ignored
      - uses: third-party/scan@v1
      - uses: vendor/tool@a1b2c3d4e5f60718293a4b5c6d7e8f9012345678
      - uses: ./local-action
`
	issues := scanWorkflow("ci.yml", content, "acme")

	var unpinned, prt int
	for _, i := range issues {
		switch i.Kind {
		case "unpinned-action":
			unpinned++
			if i.Detail != "third-party/scan@v1" {
				t.Errorf("unexpected unpinned action: %q", i.Detail)
			}
		case "pull-request-target":
			prt++
		}
	}
	if unpinned != 1 {
		t.Errorf("unpinned = %d, want 1 (third-party/scan@v1 only; official + SHA-pinned + local skipped)", unpinned)
	}
	if prt != 1 {
		t.Errorf("pull_request_target = %d, want 1", prt)
	}
}

// A reference into the caller's own namespace is first-party: same review, same
// branch protection. It must not be reported as third-party supply-chain risk.
func TestScanWorkflow_SameOwnerIsInternal(t *testing.T) {
	content := `
jobs:
  deploy:
    uses: acme/infra/.github/workflows/deploy.yml@main
  lint:
    steps:
      - uses: ACME/lint-action@v2   # login case differs; still first-party
      - uses: other-org/scan@v1
`
	var internal, thirdParty []string
	for _, i := range scanWorkflow("ci.yml", content, "acme") {
		switch i.Kind {
		case "internal-unpinned-action":
			internal = append(internal, i.Detail)
		case "unpinned-action":
			thirdParty = append(thirdParty, i.Detail)
		}
	}
	if len(internal) != 2 {
		t.Errorf("internal = %v, want the two acme/* refs", internal)
	}
	if len(thirdParty) != 1 || thirdParty[0] != "other-org/scan@v1" {
		t.Errorf("third-party = %v, want [other-org/scan@v1]", thirdParty)
	}
}

// With no owner known (an empty org), every non-official ref stays third-party
// rather than silently becoming first-party.
func TestScanWorkflow_NoOwnerKeepsThirdParty(t *testing.T) {
	issues := scanWorkflow("ci.yml", "steps:\n  - uses: acme/tool@v1\n", "")
	if len(issues) != 1 || issues[0].Kind != "unpinned-action" {
		t.Errorf("got %+v, want one unpinned-action", issues)
	}
}

func TestScanWorkflow_CommentedTriggerIgnored(t *testing.T) {
	content := "on:\n  push:\n# pull_request_target is mentioned only in a comment\n"
	for _, i := range scanWorkflow("x.yml", content, "acme") {
		if i.Kind == "pull-request-target" {
			t.Error("commented pull_request_target should not be flagged")
		}
	}
}
