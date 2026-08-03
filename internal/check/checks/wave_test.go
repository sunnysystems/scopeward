package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/score"
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
	// A team (>=2 members) so the "no required review" weakness is in scope; with
	// fewer members reviewExpected suppresses it (you cannot approve your own change).
	snap.Members = make([]model.Member, 2)
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

	// With a solo account, the review weakness is suppressed but force-push is not.
	solo := model.NewSnapshot("acme")
	solo.Solo = true
	solo.Members = make([]model.Member, 2)
	solo.Repos = snap.Repos
	soloGot := weakBranchProtection{}.Run(context.Background(), solo)
	if len(soloGot) != 1 {
		t.Fatalf("--solo: want 1 (force-push only), got %d (%+v)", len(soloGot), soloGot)
	}
}

// A weak ruleset must be reported like a weak classic config — that is the point
// of #34 — but remediated differently. Suggesting the classic-protection PUT here
// would leave the weak rule in place and stack a second mechanism beside it.
func TestWeakBranchProtection_RulesetRemediation(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Members = make([]model.Member, 2)
	snap.Repos = []model.Repo{
		{Name: "by-ruleset", BranchReqPRReview: bptr(false), BranchAllowForcePush: bptr(true),
			BranchProtectionSource: model.BranchProtectionRuleset},
		{Name: "by-classic", BranchReqPRReview: bptr(false), BranchAllowForcePush: bptr(true),
			BranchProtectionSource: model.BranchProtectionClassic},
	}
	got := weakBranchProtection{}.Run(context.Background(), snap)
	if len(got) != 2 {
		t.Fatalf("want both repos flagged, got %d", len(got))
	}

	byRepo := map[string]model.Finding{}
	for _, f := range got {
		byRepo[f.Evidence["repo"].(string)] = f
	}
	ruleset, classic := byRepo["by-ruleset"], byRepo["by-classic"]

	if ruleset.GHFix != "" {
		t.Errorf("ruleset repo got a classic-protection command: %q", ruleset.GHFix)
	}
	if !strings.Contains(ruleset.Remediation, "ruleset") {
		t.Errorf("ruleset remediation does not mention the ruleset: %q", ruleset.Remediation)
	}
	if !strings.Contains(ruleset.DocsURL, "rulesets") {
		t.Errorf("ruleset docs URL = %q, want the rulesets page", ruleset.DocsURL)
	}
	// The classic repo is unaffected: same severity, and it keeps its command.
	if classic.GHFix == "" {
		t.Error("classic repo lost its suggested fix")
	}
	if ruleset.Severity != classic.Severity {
		t.Errorf("severities differ (%v vs %v): a weak ruleset is as weak as weak classic protection",
			ruleset.Severity, classic.Severity)
	}
}

// Ruleset-protected repos are assessed for protection quality but not for admin
// bypass: bypass actors live on the ruleset object, not in the effective rules.
// Silence there would read as "admins are bound", which is the exact failure #34
// is about, so the gap is stated explicitly at info.
func TestBypassableBranchProtection_RulesetGapIsStated(t *testing.T) {
	snap := bypassSnapshot(20)
	snap.Repos = append(snap.Repos, model.Repo{
		Name: "by-ruleset", BranchReqPRReview: bptr(true), BranchAllowForcePush: bptr(false),
		BranchEnforceAdmins: nil, BranchProtectionSource: model.BranchProtectionRuleset,
	})

	var note model.Finding
	for _, f := range (bypassableBranchProtection{}).Run(context.Background(), snap) {
		if strings.Contains(f.Title, "not assessed") {
			note = f
		}
	}
	if note.CheckID == "" {
		t.Fatal("the unassessed admin bypass on a ruleset-protected repo is not surfaced")
	}
	if note.Severity != model.SevInfo {
		t.Errorf("severity = %v, want info: this states a gap, it does not assert a defect", note.Severity)
	}
	if repos, _ := note.Evidence["repos"].([]string); len(repos) != 1 || repos[0] != "by-ruleset" {
		t.Errorf("evidence names %v, want [by-ruleset]", note.Evidence["repos"])
	}

	// Repos assessed through classic protection are never reported as unassessed,
	// whether the setting is on ("enforced") or off ("bypassable").
	for _, f := range (bypassableBranchProtection{}).Run(context.Background(), bypassSnapshot(20)) {
		if strings.Contains(f.Title, "not assessed") {
			t.Errorf("classic-protected repos reported as unassessed: %q", f.Title)
		}
	}
}

func bypassSnapshot(members int) *model.Snapshot {
	snap := model.NewSnapshot("acme")
	snap.Members = make([]model.Member, members)
	snap.Repos = []model.Repo{
		// Protection that looks clean to every other branch check, but admins bypass it.
		{Name: "bypassable", BranchReqPRReview: bptr(true), BranchAllowForcePush: bptr(false), BranchEnforceAdmins: bptr(false)},
		{Name: "enforced", BranchReqPRReview: bptr(true), BranchAllowForcePush: bptr(false), BranchEnforceAdmins: bptr(true)},
		{Name: "ruleset", BranchEnforceAdmins: nil}, // not assessed → skip, never assumed off
	}
	return snap
}

func TestBypassableBranchProtection(t *testing.T) {
	snap := bypassSnapshot(breakGlassThreshold) // big enough to lose the bypass
	got := bypassableBranchProtection{}.Run(context.Background(), snap)
	if len(got) != 1 {
		t.Fatalf("want 1 finding (bypassable), got %d (%+v)", len(got), got)
	}
	if got[0].Evidence["repo"] != "bypassable" || got[0].Severity != model.SevMedium {
		t.Errorf("got %q at %v, want bypassable at medium", got[0].Evidence["repo"], got[0].Severity)
	}
	// The suggested fix must touch only enforce_admins: the full protection PUT
	// would replace every rule and drop any required status checks.
	if !strings.Contains(got[0].GHFix, "/protection/enforce_admins") {
		t.Errorf("fix = %q, want the dedicated enforce_admins endpoint", got[0].GHFix)
	}

	// weakBranchProtection must stay silent here — the rules themselves are fine.
	if weak := (weakBranchProtection{}).Run(context.Background(), snap); len(weak) != 0 {
		t.Errorf("weak-branch-protection should not fire on admin bypass, got %+v", weak)
	}
}

// Below the threshold the admin bypass is what scopeward's own suggested fix
// configures, so reporting it as a defect would penalize following the advice.
// It stays listed at info — visible, zero penalty, and with no command attached.
func TestBypassableBranchProtection_SmallTeamIsInventory(t *testing.T) {
	got := bypassableBranchProtection{}.Run(context.Background(), bypassSnapshot(breakGlassThreshold-1))
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d (%+v)", len(got), got)
	}
	if got[0].Severity != model.SevInfo {
		t.Errorf("severity = %v, want info for a team below the threshold", got[0].Severity)
	}
	if got[0].GHFix != "" {
		t.Errorf("fix = %q, want none: the tool must not suggest undoing what it recommends", got[0].GHFix)
	}
	if score.Grade(got).Penalty != 0 {
		t.Error("an expected break-glass path must not cost penalty")
	}

	// --solo must NOT reach this check. The flag means "do not suggest a fix
	// requiring a second approver" — letting it also downgrade a finding would let
	// a command-line switch silently move the score on an org large enough to
	// enforce, which is the discount ignore rules were made visible to prevent.
	solo := bypassSnapshot(50)
	solo.Solo = true
	if s := (bypassableBranchProtection{}).Run(context.Background(), solo); s[0].Severity != model.SevMedium {
		t.Errorf("--solo severity = %v, want medium: a 50-member org has the bench to enforce, flag or no flag", s[0].Severity)
	}
}

// The suggested branch-protection command and the bypass check have to agree: a
// configuration the fix produces must never be reported as a defect, at any size.
func TestSuggestedProtectionIsNotSelfContradictory(t *testing.T) {
	for _, tc := range []struct {
		members int
		solo    bool
	}{{0, false}, {1, false}, {2, false}, {breakGlassThreshold - 1, false},
		{breakGlassThreshold, false}, {20, false},
		// --solo must not make the suggestion and the checks disagree either.
		{2, true}, {20, true},
	} {
		members := tc.members
		snap := model.NewSnapshot("acme")
		snap.Solo = tc.solo
		snap.Members = make([]model.Member, members)
		snap.Repos = []model.Repo{{Name: "api", DefaultBranch: "main", DefaultBranchProtected: bptr(false)}}

		found := unprotectedDefaultBranch{}.Run(context.Background(), snap)
		if len(found) != 1 || found[0].GHFix == "" {
			t.Fatalf("%d members: expected a suggested fix, got %+v", members, found)
		}
		suggestsBypass := strings.Contains(found[0].GHFix, `"enforce_admins":false`)

		// Now the repo as the fix would leave it, assessed under the same flags —
		// --solo changes what you are told to do, so comparing across it would be
		// comparing two different questions.
		applied := model.NewSnapshot("acme")
		applied.Solo = snap.Solo
		applied.Members = snap.Members
		applied.Repos = []model.Repo{{
			Name: "api", DefaultBranch: "main", DefaultBranchProtected: bptr(true),
			BranchReqPRReview:    bptr(strings.Contains(found[0].GHFix, `"required_approving_review_count":1`)),
			BranchAllowForcePush: bptr(false),
			BranchEnforceAdmins:  bptr(!suggestsBypass),
		}}
		for _, f := range append(
			weakBranchProtection{}.Run(context.Background(), applied),
			bypassableBranchProtection{}.Run(context.Background(), applied)...,
		) {
			if f.Severity > model.SevInfo {
				t.Errorf("%d members: applying the suggested fix still yields %s (%s)",
					members, f.CheckID, f.Severity)
			}
		}
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
