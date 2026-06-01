package checks

import (
	"context"
	"testing"
	"time"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestTokenCanApprovePRs(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.ActionsToken = model.ActionsTokenSettings{CanApprovePullRequestReviews: true}
	if got := (tokenCanApprovePRs{}).Run(context.Background(), snap); len(got) != 1 {
		t.Errorf("want 1, got %d", len(got))
	}
	snap.ActionsToken = model.ActionsTokenSettings{CanApprovePullRequestReviews: false}
	if got := (tokenCanApprovePRs{}).Run(context.Background(), snap); len(got) != 0 {
		t.Errorf("want 0, got %d", len(got))
	}
}

func TestOrgSecretVisibleAll(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.OrgSecrets = []model.OrgSecret{
		{Name: "SHARED", Visibility: "all"},      // flag
		{Name: "SCOPED", Visibility: "selected"}, // ok
	}
	got := orgSecretVisibleAll{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Evidence["secret"] != "SHARED" {
		t.Fatalf("got %+v, want only SHARED", got)
	}
}

func TestClassicPATBroadScope(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.CredentialAuthorizations = []model.CredentialAuthorization{
		{Login: "alice", CredentialType: "personal access token", Scopes: []string{"admin:org", "repo"}}, // high
		{Login: "bob", CredentialType: "personal access token", Scopes: []string{"repo"}},                // medium
		{Login: "carol", CredentialType: "personal access token", Scopes: []string{"read:user"}},         // ok (narrow)
		{Login: "key", CredentialType: "SSH key", Scopes: nil},                                           // not a PAT
	}
	got := classicPATBroadScope{}.Run(context.Background(), snap)
	bySev := map[model.Severity]string{}
	for _, f := range got {
		bySev[f.Severity] = f.Evidence["login"].(string)
	}
	if len(got) != 2 || bySev[model.SevHigh] != "alice" || bySev[model.SevMedium] != "bob" {
		t.Fatalf("got %+v, want alice=high bob=medium", got)
	}
}

func TestCopilotChecks(t *testing.T) {
	now := time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC)
	idle := now.Add(-120 * 24 * time.Hour)
	active := now.Add(-2 * 24 * time.Hour)
	snap := model.NewSnapshot("acme")
	snap.CollectedAt = now
	snap.Members = []model.Member{{Login: "alice"}, {Login: "bob"}}
	snap.CopilotSeats = []model.CopilotSeat{
		{Login: "alice", LastActivityAt: &active}, // active member → ok
		{Login: "bob", LastActivityAt: &idle},     // idle → inactive flag
		{Login: "carol", LastActivityAt: nil},     // never used + non-member → both flags
	}

	inactive := copilotSeatInactive{}.Run(context.Background(), snap)
	if len(inactive) != 2 { // bob (idle) + carol (never)
		t.Errorf("inactive: want 2, got %d", len(inactive))
	}
	nonmember := copilotSeatNonMember{}.Run(context.Background(), snap)
	if len(nonmember) != 1 || nonmember[0].Evidence["login"] != "carol" {
		t.Errorf("non-member: want only carol, got %+v", nonmember)
	}
}

func TestOpenSecretAlerts(t *testing.T) {
	n3, n0 := 3, 0
	snap := model.NewSnapshot("acme")
	snap.Repos = []model.Repo{
		{Name: "leaky", OpenSecretAlerts: &n3},   // flag
		{Name: "clean", OpenSecretAlerts: &n0},   // ok
		{Name: "unknown", OpenSecretAlerts: nil}, // skip
	}
	got := openSecretAlerts{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Evidence["repo"] != "leaky" {
		t.Fatalf("got %+v, want only leaky", got)
	}
}
