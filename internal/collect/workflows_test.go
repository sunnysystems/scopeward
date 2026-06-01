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
	issues := scanWorkflow("ci.yml", content)

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

func TestScanWorkflow_CommentedTriggerIgnored(t *testing.T) {
	content := "on:\n  push:\n# pull_request_target is mentioned only in a comment\n"
	for _, i := range scanWorkflow("x.yml", content) {
		if i.Kind == "pull-request-target" {
			t.Error("commented pull_request_target should not be flagged")
		}
	}
}
