package checks

import (
	"context"
	"testing"
	"time"

	"github.com/sunnysystems/scopeward/internal/model"
)

func bptr(b bool) *bool { return &b }

func TestOwnerWithout2FA(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Members = []model.Member{
		{Login: "owner-no2fa", Role: "admin", TwoFactorEnabled: bptr(false)},   // flag (critical)
		{Login: "owner-ok", Role: "admin", TwoFactorEnabled: bptr(true)},       // ok
		{Login: "member-no2fa", Role: "member", TwoFactorEnabled: bptr(false)}, // not an owner → not here
	}
	got := ownerWithout2FA{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Resource.Name != "owner-no2fa" || got[0].Severity != model.SevCritical {
		t.Fatalf("got %+v, want one critical for owner-no2fa", got)
	}
}

func TestOrgSettingsChecks(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Org.MembersCanCreatePublicRepos = bptr(true)
	snap.Org.MembersCanForkPrivateRepos = bptr(true)
	if got := (membersCanCreatePublic{}).Run(context.Background(), snap); len(got) != 1 {
		t.Errorf("create-public: want 1, got %d", len(got))
	}
	if got := (membersCanForkPrivate{}).Run(context.Background(), snap); len(got) != 1 || got[0].Severity != model.SevHigh {
		t.Errorf("fork-private: want 1 high, got %+v", got)
	}
	// nil (not visible) → no false positive
	snap2 := model.NewSnapshot("acme")
	if got := (membersCanCreatePublic{}).Run(context.Background(), snap2); len(got) != 0 {
		t.Errorf("nil setting must not flag, got %d", len(got))
	}
}

func TestOrgDefaultCheck(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Org.PushProtectionDefault = bptr(false) // disabled → flag
	c := orgDefault{id: "x", sev: model.SevMedium, get: func(o model.Organization) *bool { return o.PushProtectionDefault }}
	if got := c.Run(context.Background(), snap); len(got) != 1 {
		t.Errorf("disabled default: want 1, got %d", len(got))
	}
	snap.Org.PushProtectionDefault = bptr(true) // enabled → ok
	if got := c.Run(context.Background(), snap); len(got) != 0 {
		t.Errorf("enabled default: want 0, got %d", len(got))
	}
}

func TestActionsAndRunners(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.ActionsPolicy = model.ActionsPolicy{AllowedActions: "all"}
	if got := (actionsPolicyOpen{}).Run(context.Background(), snap); len(got) != 1 {
		t.Errorf("actions all: want 1, got %d", len(got))
	}
	snap.ActionsPolicy = model.ActionsPolicy{AllowedActions: "selected"}
	if got := (actionsPolicyOpen{}).Run(context.Background(), snap); len(got) != 0 {
		t.Errorf("actions selected: want 0, got %d", len(got))
	}

	snap.SelfHostedRunners = []model.Runner{{Name: "r1"}, {Name: "r2"}}
	if got := (selfHostedRunners{}).Run(context.Background(), snap); len(got) != 1 {
		t.Errorf("runners: want 1, got %d", len(got))
	}
}

func TestAgentOnUnprotectedBranch(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Repos = []model.Repo{
		{Name: "open", DefaultBranchProtected: bptr(false), BotCommitters: []model.CommitActivity{{Login: "bot[bot]", Commits: 3}}}, // flag
		{Name: "guarded", DefaultBranchProtected: bptr(true), BotCommitters: []model.CommitActivity{{Login: "bot[bot]"}}},           // protected → ok
		{Name: "humanonly", DefaultBranchProtected: bptr(false)},                                                                    // no bots → ok
	}
	got := agentOnUnprotectedBranch{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Evidence["repo"] != "open" {
		t.Fatalf("got %+v, want only 'open'", got)
	}
}

func TestRepoNoPushProtection(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Repos = []model.Repo{
		{Name: "pub", Private: false, PushProtection: bptr(false)}, // high
		{Name: "priv", Private: true, PushProtection: bptr(false)}, // medium
		{Name: "ok", PushProtection: bptr(true)},                   // ok
		{Name: "unknown", PushProtection: nil},                     // skip
	}
	got := repoNoPushProtection{}.Run(context.Background(), snap)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
	bySev := map[model.Severity]string{}
	for _, f := range got {
		bySev[f.Severity] = f.Evidence["repo"].(string)
	}
	if bySev[model.SevHigh] != "pub" || bySev[model.SevMedium] != "priv" {
		t.Errorf("severities = %v, want pub=high priv=medium", bySev)
	}
}

func TestWeakBranchProtection(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Repos = []model.Repo{
		{Name: "noreview", BranchReqPRReview: bptr(false), BranchAllowForcePush: bptr(false)}, // flag
		{Name: "forcepush", BranchReqPRReview: bptr(true), BranchAllowForcePush: bptr(true)},  // flag
		{Name: "good", BranchReqPRReview: bptr(true), BranchAllowForcePush: bptr(false)},      // ok
		{Name: "ruleset", BranchReqPRReview: nil},                                             // not assessed → skip
	}
	got := weakBranchProtection{}.Run(context.Background(), snap)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d (%+v)", len(got), got)
	}
}

func TestStaleInvitation(t *testing.T) {
	now := time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC)
	old := now.Add(-60 * 24 * time.Hour)
	recent := now.Add(-3 * 24 * time.Hour)
	snap := model.NewSnapshot("acme")
	snap.CollectedAt = now
	snap.PendingInvitations = []model.Invitation{
		{Login: "old-invite", CreatedAt: &old},       // flag
		{Login: "recent-invite", CreatedAt: &recent}, // ok
	}
	got := staleInvitation{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Evidence["invitee"] != "old-invite" {
		t.Fatalf("got %+v, want only old-invite", got)
	}
}
