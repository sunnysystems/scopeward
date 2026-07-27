package checks

import (
	"context"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestSupplyChainChecks(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Repos = []model.Repo{
		{Name: "api", WorkflowIssues: []model.WorkflowIssue{
			{File: "ci.yml", Kind: "unpinned-action", Detail: "third-party/a@v1"},
			{File: "ci.yml", Kind: "unpinned-action", Detail: "third-party/b@main"},
			{File: "ci.yml", Kind: "internal-unpinned-action", Detail: "acme/infra/.github/workflows/deploy.yml@main"},
			{File: "ci.yml", Kind: "pull-request-target", Detail: "pull_request_target"},
		}},
		{Name: "clean", WorkflowIssues: nil},
	}

	unpinned := unpinnedActions{}.Run(context.Background(), snap)
	if len(unpinned) != 1 {
		t.Fatalf("unpinned: want 1 finding (api), got %d", len(unpinned))
	}
	if acts, ok := unpinned[0].Evidence["actions"].([]string); !ok || len(acts) != 2 {
		t.Errorf("expected 2 unpinned actions, got %v", unpinned[0].Evidence["actions"])
	}

	// The org's own reusable workflow is inventory, not third-party risk: it must
	// stay out of the scored check and land in the info one instead.
	internal := internalUnpinnedActions{}.Run(context.Background(), snap)
	if len(internal) != 1 || internal[0].Severity != model.SevInfo {
		t.Fatalf("internal unpinned: want 1 info finding (api), got %+v", internal)
	}
	if acts, _ := internal[0].Evidence["actions"].([]string); len(acts) != 1 {
		t.Errorf("expected 1 internal action, got %v", internal[0].Evidence["actions"])
	}

	prt := pullRequestTarget{}.Run(context.Background(), snap)
	if len(prt) != 1 || prt[0].Severity != model.SevHigh {
		t.Fatalf("pull_request_target: want 1 high, got %+v", prt)
	}
}
