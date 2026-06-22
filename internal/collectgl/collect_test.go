package collectgl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/auth"
	"github.com/sunnysystems/scopeward/internal/collect"
	"github.com/sunnysystems/scopeward/internal/glclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// gitlabMock serves the minimal GitLab endpoints RunGroup touches. isAdmin
// toggles whether /user reports an instance admin and whether /users/:id exposes
// the admin-only 2FA/activity fields.
func gitlabMock(t *testing.T, isAdmin bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v4/groups/acme":
			_, _ = w.Write([]byte(`{"id":10,"name":"Acme","full_path":"acme","require_two_factor_authentication":true}`))
		case r.URL.Path == "/api/v4/groups/acme/members/all":
			_, _ = w.Write([]byte(`[{"id":1,"username":"root","access_level":50},{"id":2,"username":"dev","access_level":30}]`))
		case r.URL.Path == "/api/v4/groups/acme/descendant_groups", r.URL.Path == "/api/v4/groups/acme/projects":
			// No subgroups/projects in the identity-axis fixtures.
			_, _ = w.Write([]byte(`[]`))
		case r.URL.Path == "/api/v4/user":
			if isAdmin {
				_, _ = w.Write([]byte(`{"username":"root","is_admin":true}`))
			} else {
				_, _ = w.Write([]byte(`{"username":"owner","is_admin":false}`))
			}
		case strings.HasPrefix(r.URL.Path, "/api/v4/users/"):
			// Admin-only fields; a non-admin token would not see them, but RunGroup
			// never reaches here unless isAdmin (it gates on /user first).
			id := strings.TrimPrefix(r.URL.Path, "/api/v4/users/")
			if id == "1" {
				_, _ = w.Write([]byte(`{"two_factor_enabled":true,"last_activity_on":"2020-01-01"}`))
			} else {
				_, _ = w.Write([]byte(`{"two_factor_enabled":false,"last_activity_on":"2024-12-01"}`))
			}
		case r.URL.Path == "/api/v4/applications",
			r.URL.Path == "/api/v4/personal_access_tokens",
			strings.HasSuffix(r.URL.Path, "/access_tokens"),
			strings.HasSuffix(r.URL.Path, "/deploy_tokens"),
			strings.HasSuffix(r.URL.Path, "/deploy_keys"),
			strings.HasSuffix(r.URL.Path, "/variables"),
			strings.HasSuffix(r.URL.Path, "/runners"):
			// Non-human & CI/CD axes: identity-axis fixtures carry none.
			_, _ = w.Write([]byte(`[]`))
		case strings.HasSuffix(r.URL.Path, "/job_token_scope"):
			_, _ = w.Write([]byte(`{"inbound_enabled":true}`))
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func newClient(srv *httptest.Server) *glclient.Client {
	return glclient.New(auth.NewSecret("glpat-x")).WithHost(srv.URL)
}

func coverageStatus(t *testing.T, snap *model.Snapshot, kind model.DataKind) model.CoverageStatus {
	t.Helper()
	c, ok := snap.Coverage.Get(kind)
	if !ok {
		t.Fatalf("no coverage recorded for %s", kind)
	}
	return c.Status
}

func TestRunGroupAdminToken(t *testing.T) {
	srv := gitlabMock(t, true)
	defer srv.Close()

	snap, err := RunGroup(context.Background(), newClient(srv), "acme", "https://gitlab.example.com", nil, collect.Options{})
	if err != nil {
		t.Fatalf("RunGroup: %v", err)
	}

	if snap.Provider != model.ProviderGitLab || snap.Host != "https://gitlab.example.com" {
		t.Errorf("provider/host = %q/%q, want gitlab/https://gitlab.example.com", snap.Provider, snap.Host)
	}
	if !snap.Org.TwoFactorRequired {
		t.Error("group 2FA enforcement should be true")
	}
	if coverageStatus(t, snap, model.DataOrg) != model.CoverageOK {
		t.Error("DataOrg should be OK")
	}

	if len(snap.Members) != 2 {
		t.Fatalf("members = %d, want 2", len(snap.Members))
	}
	byLogin := map[string]model.Member{}
	for _, m := range snap.Members {
		byLogin[m.Login] = m
	}
	if byLogin["root"].Role != "admin" {
		t.Errorf("root role = %q, want admin (Owner 50)", byLogin["root"].Role)
	}
	if byLogin["dev"].Role != "member" {
		t.Errorf("dev role = %q, want member (Developer 30)", byLogin["dev"].Role)
	}

	// Admin token → per-member 2FA + activity collected.
	for _, kind := range []model.DataKind{model.DataMembers, model.DataMemberRoles, model.DataMember2FA, model.DataMemberActivity} {
		if coverageStatus(t, snap, kind) != model.CoverageOK {
			t.Errorf("%s should be OK for an admin token", kind)
		}
	}
	if got := byLogin["root"].TwoFactorEnabled; got == nil || !*got {
		t.Errorf("root 2FA = %v, want enabled", got)
	}
	if got := byLogin["dev"].TwoFactorEnabled; got == nil || *got {
		t.Errorf("dev 2FA = %v, want disabled", got)
	}
	if byLogin["root"].LastActiveAt == nil {
		t.Error("root LastActiveAt should be parsed from last_activity_on")
	}

	// Identity-adjacent axes that GitLab handles differently / land later: gaps.
	for _, kind := range []model.DataKind{model.DataSAMLIdentities, model.DataOutsideCollaborators, model.DataPendingInvitations} {
		if coverageStatus(t, snap, kind) != model.CoverageMissing {
			t.Errorf("%s should be Missing (not collected in #4)", kind)
		}
	}
}

func TestRunGroupNonAdminGatesSensitiveData(t *testing.T) {
	srv := gitlabMock(t, false)
	defer srv.Close()

	snap, err := RunGroup(context.Background(), newClient(srv), "acme", "https://gitlab.example.com", nil, collect.Options{})
	if err != nil {
		t.Fatalf("RunGroup: %v", err)
	}

	// Members and roles are still visible to a group owner...
	if len(snap.Members) != 2 {
		t.Fatalf("members = %d, want 2", len(snap.Members))
	}
	for _, kind := range []model.DataKind{model.DataMembers, model.DataMemberRoles, model.DataOrg} {
		if coverageStatus(t, snap, kind) != model.CoverageOK {
			t.Errorf("%s should be OK for a group-owner token", kind)
		}
	}
	// ...but per-member 2FA and activity require an instance admin → not evaluated.
	for _, kind := range []model.DataKind{model.DataMember2FA, model.DataMemberActivity} {
		if coverageStatus(t, snap, kind) != model.CoverageMissing {
			t.Errorf("%s should be Missing for a non-admin token (honest coverage)", kind)
		}
	}
	for _, m := range snap.Members {
		if m.TwoFactorEnabled != nil {
			t.Errorf("%s 2FA should be nil (unknown) for a non-admin token", m.Login)
		}
	}
}
