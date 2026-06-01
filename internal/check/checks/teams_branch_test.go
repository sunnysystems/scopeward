package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestUnprotectedBranchFix(t *testing.T) {
	no := false
	find := func(repo model.Repo, plan string, members int) model.Finding {
		s := model.NewSnapshot("acme")
		s.Org.Plan = plan
		s.Members = make([]model.Member, members)
		s.Repos = []model.Repo{repo}
		got := unprotectedDefaultBranch{}.Run(context.Background(), s)
		if len(got) != 1 {
			t.Fatalf("findings = %d, want 1", len(got))
		}
		return got[0]
	}

	// Public repo in a team (2+ members): fix requires an approving review.
	pub := find(model.Repo{Name: "instana", DefaultBranch: "main", DefaultBranchProtected: &no, Private: false}, "free", 3)
	if !strings.Contains(pub.GHFix, "repos/acme/instana/branches/main/protection") {
		t.Errorf("public repo should get a protect command, got: %q", pub.GHFix)
	}
	if !strings.Contains(pub.GHFix, `"required_approving_review_count":1`) {
		t.Errorf("team repo should require a review, got: %q", pub.GHFix)
	}
	if pub.GHVerify == "" {
		t.Error("public repo fix should include a verify command")
	}

	// Solo (0–1 members): requiring an approval would lock the branch, so the
	// fix requires a PR with 0 approvals instead.
	solo := find(model.Repo{Name: "instana", DefaultBranch: "main", DefaultBranchProtected: &no, Private: false}, "free", 1)
	if !strings.Contains(solo.GHFix, `"required_approving_review_count":0`) {
		t.Errorf("solo repo should not require a review, got: %q", solo.GHFix)
	}

	// Private repo on Free: protection is impossible, so no command — only advice.
	priv := find(model.Repo{Name: "secret", DefaultBranch: "main", DefaultBranchProtected: &no, Private: true}, "free", 3)
	if priv.GHFix != "" {
		t.Errorf("private+free repo must not get a command, got: %q", priv.GHFix)
	}

	// Private repo on a paid plan: protection is possible, so a command is offered.
	privPaid := find(model.Repo{Name: "secret", DefaultBranch: "main", DefaultBranchProtected: &no, Private: true}, "team", 3)
	if privPaid.GHFix == "" {
		t.Error("private repo on a paid plan should get a protect command")
	}
}

// TestSoloFlagOverridesMemberCount confirms --solo forces no-reviewer fixes even
// when the org has multiple members.
func TestSoloFlagOverridesMemberCount(t *testing.T) {
	no := false
	s := model.NewSnapshot("acme")
	s.Solo = true
	s.Members = make([]model.Member, 5) // a real team...
	s.Repos = []model.Repo{{Name: "api", DefaultBranch: "main", DefaultBranchProtected: &no}}
	got := unprotectedDefaultBranch{}.Run(context.Background(), s)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].GHFix, `"required_approving_review_count":0`) {
		t.Errorf("--solo must force 0 reviews despite 5 members, got: %q", got[0].GHFix)
	}
}

func TestBranchProtectable(t *testing.T) {
	cases := []struct {
		private bool
		plan    string
		want    bool
	}{
		{false, "free", true}, // public is always protectable
		{true, "free", false}, // private on free is not
		{true, "team", true},  // private on a paid plan is
		{true, "", true},      // unknown plan: best-effort yes
	}
	for _, tc := range cases {
		if got := branchProtectable(tc.private, tc.plan); got != tc.want {
			t.Errorf("branchProtectable(%v, %q) = %v, want %v", tc.private, tc.plan, got, tc.want)
		}
	}
}
