package checks

import (
	"context"
	"testing"
	"time"

	"github.com/sunnysystems/scopeward/internal/model"
)

func ptime(s string) *time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return &t
}

func TestTokenNoExpiry(t *testing.T) {
	exp := ptime("2027-01-01")
	snap := model.NewSnapshot("acme")
	snap.Provider = model.ProviderGitLab
	snap.AccessTokens = []model.AccessToken{
		{ID: 1, Name: "live-forever", Kind: "personal", Holder: "alice", Active: true, ExpiresAt: nil}, // flag
		{ID: 2, Name: "bounded", Kind: "group", Holder: "acme", Active: true, ExpiresAt: exp},          // ok
		{ID: 3, Name: "revoked", Kind: "personal", Holder: "bob", Active: true, Revoked: true},         // skip (revoked)
		{ID: 4, Name: "inactive", Kind: "personal", Holder: "eve", Active: false},                      // skip (inactive)
	}
	got := tokenNoExpiry{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Evidence["token_id"].(int64) != 1 {
		t.Fatalf("got %+v, want only the active non-expiring token", got)
	}
}

func TestTokenBroadScope(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.AccessTokens = []model.AccessToken{
		{ID: 1, Name: "full-api", Active: true, Scopes: []string{"api"}},                       // high
		{ID: 2, Name: "writer", Active: true, Scopes: []string{"write_repository"}},            // medium
		{ID: 3, Name: "reader", Active: true, Scopes: []string{"read_repository", "read_api"}}, // none → skip
		{ID: 4, Name: "broad-revoked", Active: true, Revoked: true, Scopes: []string{"api"}},   // skip (revoked)
	}
	got := tokenBroadScope{}.Run(context.Background(), snap)
	bySev := map[model.Severity]model.Finding{}
	for _, f := range got {
		bySev[f.Severity] = f
	}
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (api=high, write_repository=medium)", len(got))
	}
	if _, ok := bySev[model.SevHigh]; !ok {
		t.Error("api scope should produce a high finding")
	}
	if _, ok := bySev[model.SevMedium]; !ok {
		t.Error("write_repository scope should produce a medium finding")
	}
}

func TestTokenStale(t *testing.T) {
	now := time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC)
	snap := model.NewSnapshot("acme")
	snap.CollectedAt = now
	recent := ptime("2026-06-01")
	old := ptime("2024-01-01")
	created := ptime("2025-01-01")
	snap.AccessTokens = []model.AccessToken{
		{ID: 1, Name: "fresh", Active: true, LastUsedAt: recent},                    // ~20d → ok
		{ID: 2, Name: "idle", Active: true, LastUsedAt: old},                        // >1y → stale low
		{ID: 3, Name: "never-used", Active: true, CreatedAt: created},               // never used, old → stale medium
		{ID: 4, Name: "unknown-age", Active: true},                                  // no timestamps → skip
		{ID: 5, Name: "idle-revoked", Active: true, Revoked: true, LastUsedAt: old}, // skip (revoked)
	}
	got := tokenStale{}.Run(context.Background(), snap)
	byID := map[int64]model.Finding{}
	for _, f := range got {
		byID[f.Evidence["token_id"].(int64)] = f
	}
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (idle + never-used), got %+v", len(got), got)
	}
	if f, ok := byID[2]; !ok || f.Severity != model.SevLow {
		t.Errorf("idle token = %+v, want low", f)
	}
	if f, ok := byID[3]; !ok || f.Severity != model.SevMedium || f.Evidence["never_used"] != true {
		t.Errorf("never-used token = %+v, want medium with never_used=true", f)
	}
}

func TestDeployTokenNoExpiry(t *testing.T) {
	exp := ptime("2027-01-01")
	snap := model.NewSnapshot("acme")
	snap.DeployTokens = []model.DeployToken{
		{ID: 1, Name: "forever", Kind: "group", Holder: "acme", ExpiresAt: nil},       // flag
		{ID: 2, Name: "bounded", Kind: "project", Holder: "acme/api", ExpiresAt: exp}, // ok
		{ID: 3, Name: "revoked", Kind: "group", Holder: "acme", Revoked: true},        // skip
	}
	got := deployTokenNoExpiry{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Evidence["token_id"].(int64) != 1 {
		t.Fatalf("got %+v, want only the non-expiring, non-revoked deploy token", got)
	}
}

func TestOAuthAppTrusted(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.OAuthApps = []model.OAuthApp{
		{ID: 1, Name: "trusted-app", Confidential: true, Trusted: true},  // medium (trusted)
		{ID: 2, Name: "public-app", Confidential: false, Trusted: false}, // low (non-confidential)
		{ID: 3, Name: "normal-app", Confidential: true, Trusted: false},  // ok → skip
	}
	got := oauthAppTrusted{}.Run(context.Background(), snap)
	byName := map[string]model.Finding{}
	for _, f := range got {
		byName[f.Evidence["name"].(string)] = f
	}
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (trusted + public)", len(got))
	}
	if byName["trusted-app"].Severity != model.SevMedium {
		t.Errorf("trusted app severity = %v, want medium", byName["trusted-app"].Severity)
	}
	if byName["public-app"].Severity != model.SevLow {
		t.Errorf("public app severity = %v, want low", byName["public-app"].Severity)
	}
	if _, flagged := byName["normal-app"]; flagged {
		t.Error("confidential, non-trusted app must not be flagged")
	}
}

// TestWritableDeployKeyGitLab checks the provider guard: on a GitLab snapshot the
// finding uses the project's full path (not group/path doubled) and carries no
// gh fix command (the glab equivalent lands with the fixer abstraction, #10).
func TestWritableDeployKeyGitLab(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Provider = model.ProviderGitLab
	snap.Host = "https://gitlab.example.com"
	snap.Org.Login = "acme"
	snap.Repos = []model.Repo{{
		ID:   101,
		Name: "acme/api", // GitLab project name already carries the namespace
		DeployKeys: []model.DeployKey{
			{ID: 2, Title: "ci-push", ReadOnly: false, ExpiresAt: ptime("2026-09-01")},
		},
	}}
	got := writableDeployKey{}.Run(context.Background(), snap)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	f := got[0]
	if f.Title != `Writable deploy key "ci-push" on acme/api` {
		t.Errorf("title = %q, want the full project path without doubling the group", f.Title)
	}
	if f.GHFix != "" {
		t.Errorf("GHFix = %q, want empty on GitLab (no gh command)", f.GHFix)
	}
	if f.Evidence["expires_at"] != "2026-09-01" {
		t.Errorf("expires_at evidence = %v, want 2026-09-01", f.Evidence["expires_at"])
	}
}
