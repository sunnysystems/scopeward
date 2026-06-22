package model

import "testing"

func TestRoleFromGitLabAccessLevel(t *testing.T) {
	cases := []struct {
		level int
		want  Role
	}{
		{GitLabGuest, RoleRead},
		{GitLabReporter, RoleTriage},
		{GitLabDeveloper, RoleWrite},
		{GitLabMaintainer, RoleMaintain},
		{GitLabOwner, RoleAdmin},
		{60, RoleAdmin}, // above Owner still maps to admin
		{15, RoleRead},  // between Guest and Reporter rounds down to read
		{5, ""},         // below Guest (e.g. Minimal Access) is unknown
		{0, ""},         // no access level seen
		{-1, ""},        // defensive
	}
	for _, c := range cases {
		if got := RoleFromGitLabAccessLevel(c.level); got != c.want {
			t.Errorf("RoleFromGitLabAccessLevel(%d) = %q, want %q", c.level, got, c.want)
		}
	}
}

func TestRoleRankOrdering(t *testing.T) {
	// The canonical ladder must be strictly increasing read < triage < write <
	// maintain < admin, with unknown roles below everything.
	ladder := []Role{RoleRead, RoleTriage, RoleWrite, RoleMaintain, RoleAdmin}
	for i := 1; i < len(ladder); i++ {
		if ladder[i].Rank() <= ladder[i-1].Rank() {
			t.Errorf("rank not increasing: %q (%d) should outrank %q (%d)",
				ladder[i], ladder[i].Rank(), ladder[i-1], ladder[i-1].Rank())
		}
	}
	if (Role("nonsense")).Rank() != 0 {
		t.Errorf("unknown role should rank 0, got %d", Role("nonsense").Rank())
	}
	if RoleRead.Rank() <= Role("").Rank() {
		t.Error("read should outrank an unknown/empty role")
	}
}
