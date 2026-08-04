package model

import "testing"

// TestAssessedRepoCountRequiresTheRepoPass pins the denominator's honesty rule.
//
// With the per-repository pass skipped or truncated there are no repository
// findings at all, so dividing zero penalty by the repositories that merely
// exist would print "0.0 per repo across 23 repos" — a clean bill of health for
// repositories nothing examined. Reporting no denominator is the truthful
// answer, and the score falls back to an absolute sum.
func TestAssessedRepoCountRequiresTheRepoPass(t *testing.T) {
	newSnap := func() *Snapshot {
		s := NewSnapshot("acme")
		s.Repos = []Repo{{Name: "a"}, {Name: "b"}, {Name: "c", Archived: true}}
		return s
	}

	t.Run("no per-repo coverage recorded (--quick)", func(t *testing.T) {
		s := newSnap()
		s.Coverage.OK(DataRepos, 3) // the listing ran; the per-repo pass did not
		if got := s.AssessedRepoCount(); got != 0 {
			t.Errorf("got %d, want 0 — nothing was assessed", got)
		}
	})

	t.Run("per-repo coverage truncated (--max-repos)", func(t *testing.T) {
		s := newSnap()
		s.Coverage.Partial(DataBranchProtection, 1, "scanned 1 of 2 repos (--max-repos)")
		if got := s.AssessedRepoCount(); got != 0 {
			t.Errorf("got %d, want 0 — a partial pass is not a denominator", got)
		}
	})

	t.Run("per-repo pass completed", func(t *testing.T) {
		s := newSnap()
		s.Coverage.OK(DataBranchProtection, 2)
		if got := s.AssessedRepoCount(); got != 2 {
			t.Errorf("got %d, want 2 active repos", got)
		}
	})

	t.Run("archived repos are never in the denominator", func(t *testing.T) {
		s := newSnap()
		s.Coverage.OK(DataRepoSecurity, 3)
		if got := s.ActiveRepoCount(); got != 2 {
			t.Errorf("active count = %d, want 2", got)
		}
	})
}
