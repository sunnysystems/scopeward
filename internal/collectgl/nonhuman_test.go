package collectgl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/collect"
	"github.com/sunnysystems/scopeward/internal/model"
)

// nonhumanMock serves a group "acme" (id 10) with one subgroup and one project,
// plus the non-human endpoints: a personal access token, a group access token,
// a project access token, a group deploy token, project deploy keys, and one
// OAuth application.
func nonhumanMock(t *testing.T) *httptest.Server {
	t.Helper()
	body := map[string]string{
		"/api/v4/groups/acme":                   `{"id":10,"name":"Acme","full_path":"acme","require_two_factor_authentication":true}`,
		"/api/v4/groups/acme/members/all":       `[{"id":7,"username":"owner","access_level":50}]`,
		"/api/v4/user":                          `{"id":7,"username":"owner","is_admin":false}`,
		"/api/v4/groups/acme/descendant_groups": `[{"id":11,"name":"Team","full_path":"acme/team","parent_id":10}]`,
		"/api/v4/groups/acme/projects":          `[{"id":101,"path_with_namespace":"acme/api","visibility":"private","namespace":{"full_path":"acme"},"shared_with_groups":[]}]`,
		"/api/v4/groups/11/members":             `[]`,
		"/api/v4/projects/101/members":          `[]`,

		// Personal access token: non-expiring, broad ("api") scope, owned by the caller.
		"/api/v4/personal_access_tokens": `[{"id":1,"name":"ci-pat","scopes":["api"],"active":true,"revoked":false,"expires_at":null,"last_used_at":"2026-06-01T00:00:00Z","created_at":"2024-01-01T00:00:00Z","user_id":7}]`,
		// Group access token: expiring, narrow scope.
		"/api/v4/groups/10/access_tokens": `[{"id":2,"name":"group-tok","scopes":["read_repository"],"active":true,"revoked":false,"expires_at":"2026-12-31","last_used_at":"2026-06-10T00:00:00Z","created_at":"2025-01-01T00:00:00Z"}]`,
		"/api/v4/groups/11/access_tokens": `[]`,
		// Project access token.
		"/api/v4/projects/101/access_tokens": `[{"id":3,"name":"proj-tok","scopes":["read_api"],"active":true,"revoked":false,"expires_at":"2027-01-01","last_used_at":"2024-01-01T00:00:00Z","created_at":"2023-01-01T00:00:00Z"}]`,
		// Deploy tokens: one non-expiring group token; none on the project.
		"/api/v4/groups/10/deploy_tokens":    `[{"id":1,"name":"dt","username":"gitlab+deploy-token-1","scopes":["read_repository"],"expires_at":null,"revoked":false}]`,
		"/api/v4/groups/11/deploy_tokens":    `[]`,
		"/api/v4/projects/101/deploy_tokens": `[]`,
		// Deploy keys: one writable (can_push), one read-only with an expiry.
		"/api/v4/projects/101/deploy_keys": `[{"id":10,"title":"writable","can_push":true,"expires_at":null},{"id":11,"title":"ro","can_push":false,"expires_at":"2026-09-01"}]`,
		// One trusted OAuth application.
		"/api/v4/applications": `[{"id":1,"application_name":"dashboard","callback_url":"https://app.example.com/cb","confidential":true,"trusted":true}]`,
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if b, ok := body[r.URL.Path]; ok {
			_, _ = w.Write([]byte(b))
			return
		}
		// CI/CD (#7) endpoints: the non-human fixtures carry no CI data.
		p := r.URL.Path
		if strings.HasSuffix(p, "/variables") || strings.HasSuffix(p, "/runners") {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if strings.HasSuffix(p, "/job_token_scope") {
			_, _ = w.Write([]byte(`{"inbound_enabled":true}`))
			return
		}
		t.Errorf("unexpected request path: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestRunGroupCollectsNonHuman(t *testing.T) {
	srv := nonhumanMock(t)
	defer srv.Close()

	snap, err := RunGroup(context.Background(), newClient(srv), "acme", "https://gitlab.example.com", nil, collect.Options{})
	if err != nil {
		t.Fatalf("RunGroup: %v", err)
	}

	// Access tokens: personal + group + project, mapped to the neutral shape.
	if len(snap.AccessTokens) != 3 {
		t.Fatalf("access tokens = %d, want 3", len(snap.AccessTokens))
	}
	byName := map[string]model.AccessToken{}
	for _, tk := range snap.AccessTokens {
		byName[tk.Name] = tk
	}
	pat := byName["ci-pat"]
	if pat.Kind != "personal" || pat.Holder != "owner" {
		t.Errorf("personal token kind/holder = %q/%q, want personal/owner", pat.Kind, pat.Holder)
	}
	if pat.ExpiresAt != nil {
		t.Errorf("ci-pat ExpiresAt = %v, want nil (non-expiring)", pat.ExpiresAt)
	}
	if len(pat.Scopes) != 1 || pat.Scopes[0] != "api" {
		t.Errorf("ci-pat scopes = %v, want [api]", pat.Scopes)
	}
	if gt := byName["group-tok"]; gt.Kind != "group" || gt.Holder != "acme" || gt.ScopeID != 10 || gt.ExpiresAt == nil {
		t.Errorf("group-tok = %+v, want kind group holder acme scope 10 with expiry", gt)
	}
	if pt := byName["proj-tok"]; pt.Kind != "project" || pt.Holder != "acme/api" || pt.ScopeID != 101 {
		t.Errorf("proj-tok = %+v, want kind project holder acme/api scope 101", pt)
	}

	// Deploy tokens.
	if len(snap.DeployTokens) != 1 {
		t.Fatalf("deploy tokens = %d, want 1", len(snap.DeployTokens))
	}
	if dt := snap.DeployTokens[0]; dt.Name != "dt" || dt.Kind != "group" || dt.ExpiresAt != nil {
		t.Errorf("deploy token = %+v, want name dt, kind group, no expiry", dt)
	}

	// OAuth apps.
	if len(snap.OAuthApps) != 1 || !snap.OAuthApps[0].Trusted {
		t.Fatalf("oauth apps = %+v, want one trusted app", snap.OAuthApps)
	}

	// Deploy keys on the project: writable + read-only.
	if len(snap.Repos) != 1 {
		t.Fatalf("repos = %d, want 1", len(snap.Repos))
	}
	keys := snap.Repos[0].DeployKeys
	if len(keys) != 2 {
		t.Fatalf("deploy keys = %d, want 2", len(keys))
	}
	var writable, readonly bool
	for _, k := range keys {
		if k.Title == "writable" && !k.ReadOnly {
			writable = true
		}
		if k.Title == "ro" && k.ReadOnly && k.ExpiresAt != nil {
			readonly = true
		}
	}
	if !writable || !readonly {
		t.Errorf("deploy keys = %+v, want a writable (can_push) and a read-only with expiry", keys)
	}

	// Coverage: collected kinds OK; GitHub-only kinds explicitly not evaluated.
	for _, kind := range []model.DataKind{model.DataAccessTokens, model.DataDeployTokens, model.DataDeployKeys, model.DataOAuthApps} {
		if coverageStatus(t, snap, kind) != model.CoverageOK {
			t.Errorf("%s should be OK", kind)
		}
	}
	for _, kind := range []model.DataKind{model.DataAppInstallations, model.DataFineGrainedPATs} {
		if coverageStatus(t, snap, kind) != model.CoverageMissing {
			t.Errorf("%s should be Missing (no GitLab equivalent)", kind)
		}
	}
}

func TestRunGroupQuickSkipsCredentialPass(t *testing.T) {
	srv := nonhumanMock(t)
	defer srv.Close()

	snap, err := RunGroup(context.Background(), newClient(srv), "acme", "", nil, collect.Options{Quick: true})
	if err != nil {
		t.Fatalf("RunGroup: %v", err)
	}

	// The per-resource credential pass is skipped: no tokens/keys collected.
	if len(snap.AccessTokens) != 0 || len(snap.DeployTokens) != 0 {
		t.Errorf("quick mode should collect no tokens, got %d access / %d deploy", len(snap.AccessTokens), len(snap.DeployTokens))
	}
	for _, kind := range []model.DataKind{model.DataAccessTokens, model.DataDeployTokens, model.DataDeployKeys} {
		if coverageStatus(t, snap, kind) != model.CoverageMissing {
			t.Errorf("%s should be Missing in --quick mode", kind)
		}
	}
	// OAuth apps are a single instance-level call and are still collected.
	if coverageStatus(t, snap, model.DataOAuthApps) != model.CoverageOK {
		t.Error("DataOAuthApps should still be OK in --quick mode (instance-level)")
	}
}
