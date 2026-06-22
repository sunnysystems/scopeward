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

// cicdMock serves group "acme" (id 10) with one subgroup (11) and one project
// (101), plus the CI/CD endpoints: variables, runner listings + detail, and the
// project job-token scope. Non-human (#6) endpoints return empty so the run
// completes without erroring.
func cicdMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		write := func(s string) { _, _ = w.Write([]byte(s)) }
		switch {
		// identity / teams
		case p == "/api/v4/groups/acme":
			write(`{"id":10,"name":"Acme","full_path":"acme","require_two_factor_authentication":true}`)
		case p == "/api/v4/groups/acme/members/all":
			write(`[{"id":7,"username":"owner","access_level":50}]`)
		case p == "/api/v4/user":
			write(`{"id":7,"username":"owner","is_admin":false}`)
		case p == "/api/v4/groups/acme/descendant_groups":
			write(`[{"id":11,"name":"Team","full_path":"acme/team","parent_id":10}]`)
		case p == "/api/v4/groups/acme/projects":
			write(`[{"id":101,"path_with_namespace":"acme/api","visibility":"private","namespace":{"full_path":"acme"},"shared_with_groups":[]}]`)
		case p == "/api/v4/groups/11/members", p == "/api/v4/projects/101/members":
			write(`[]`)

		// CI/CD variables
		case p == "/api/v4/groups/10/variables":
			write(`[{"key":"SECRET_TOKEN","variable_type":"env_var","protected":false,"masked":true,"environment_scope":"*"},
			        {"key":"PROD_KEY","variable_type":"env_var","protected":true,"masked":true,"environment_scope":"production"}]`)
		case p == "/api/v4/projects/101/variables":
			write(`[{"key":"BUILD_FLAG","variable_type":"env_var","protected":false,"masked":false,"environment_scope":"*"}]`)
		case strings.HasSuffix(p, "/variables"):
			write(`[]`)

		// CI runners: list (ids) + detail
		case p == "/api/v4/groups/10/runners":
			write(`[{"id":1},{"id":2}]`)
		case strings.HasSuffix(p, "/runners"):
			write(`[]`)
		case p == "/api/v4/runners/1":
			write(`{"id":1,"description":"shared-1","runner_type":"instance_type","access_level":"not_protected","locked":false,"online":true,"tag_list":["docker"]}`)
		case p == "/api/v4/runners/2":
			write(`{"id":2,"description":"grp-2","runner_type":"group_type","access_level":"ref_protected","locked":true,"online":false,"tag_list":["deploy"]}`)

		// CI_JOB_TOKEN scope
		case p == "/api/v4/projects/101/job_token_scope":
			write(`{"inbound_enabled":false}`)

		// non-human (#6) endpoints: empty here
		case p == "/api/v4/personal_access_tokens", p == "/api/v4/applications",
			strings.HasSuffix(p, "/access_tokens"), strings.HasSuffix(p, "/deploy_tokens"),
			strings.HasSuffix(p, "/deploy_keys"):
			write(`[]`)

		default:
			if !serveAuxEndpoints(w, p) {
				t.Errorf("unexpected request path: %s", p)
				w.WriteHeader(http.StatusNotFound)
			}
		}
	}))
}

func TestRunGroupCollectsCICD(t *testing.T) {
	srv := cicdMock(t)
	defer srv.Close()

	snap, err := RunGroup(context.Background(), newClient(srv), "acme", "https://gitlab.example.com", nil, collect.Options{})
	if err != nil {
		t.Fatalf("RunGroup: %v", err)
	}

	// CI/CD variables: 2 from the group + 1 from the project.
	if len(snap.CIVariables) != 3 {
		t.Fatalf("ci variables = %d, want 3", len(snap.CIVariables))
	}
	byKey := map[string]model.CIVariable{}
	for _, v := range snap.CIVariables {
		byKey[v.Key] = v
	}
	if v := byKey["SECRET_TOKEN"]; !v.Masked || v.Protected || v.Kind != "group" || v.EnvironmentScope != "*" {
		t.Errorf("SECRET_TOKEN = %+v, want masked, unprotected, group, scope *", v)
	}
	if v := byKey["PROD_KEY"]; !v.Protected {
		t.Errorf("PROD_KEY should be protected, got %+v", v)
	}
	if v := byKey["BUILD_FLAG"]; v.Kind != "project" || v.Holder != "acme/api" {
		t.Errorf("BUILD_FLAG = %+v, want project holder acme/api", v)
	}

	// Runners: shared/unprotected vs group/protected.
	if len(snap.CIRunners) != 2 {
		t.Fatalf("ci runners = %d, want 2", len(snap.CIRunners))
	}
	byID := map[int64]model.CIRunner{}
	for _, rn := range snap.CIRunners {
		byID[rn.ID] = rn
	}
	if r1 := byID[1]; !r1.Shared || r1.RefProtected || r1.Holder != "" {
		t.Errorf("runner 1 = %+v, want shared, not ref-protected, no holder", r1)
	}
	if r2 := byID[2]; r2.Shared || !r2.RefProtected || r2.Holder != "acme" {
		t.Errorf("runner 2 = %+v, want group, ref-protected, holder acme", r2)
	}

	// Job-token scope on the project.
	if len(snap.Repos) != 1 {
		t.Fatalf("repos = %d, want 1", len(snap.Repos))
	}
	if got := snap.Repos[0].JobTokenInboundEnabled; got == nil || *got {
		t.Errorf("JobTokenInboundEnabled = %v, want false (allowlist disabled)", got)
	}

	// Coverage: CI kinds OK; GitHub Actions kinds explicitly not evaluated.
	for _, kind := range []model.DataKind{model.DataCIVariables, model.DataCIRunners, model.DataJobTokenScope} {
		if coverageStatus(t, snap, kind) != model.CoverageOK {
			t.Errorf("%s should be OK", kind)
		}
	}
	for _, kind := range []model.DataKind{model.DataActionsPolicy, model.DataActionsTokenDefault, model.DataSelfHostedRunners, model.DataOrgSecrets} {
		if coverageStatus(t, snap, kind) != model.CoverageMissing {
			t.Errorf("%s should be Missing (no GitLab equivalent)", kind)
		}
	}
}

func TestRunGroupQuickSkipsCICD(t *testing.T) {
	srv := cicdMock(t)
	defer srv.Close()

	snap, err := RunGroup(context.Background(), newClient(srv), "acme", "", nil, collect.Options{Quick: true})
	if err != nil {
		t.Fatalf("RunGroup: %v", err)
	}
	if len(snap.CIVariables) != 0 || len(snap.CIRunners) != 0 {
		t.Errorf("quick mode should collect no CI data, got %d vars / %d runners", len(snap.CIVariables), len(snap.CIRunners))
	}
	for _, kind := range []model.DataKind{model.DataCIVariables, model.DataCIRunners, model.DataJobTokenScope} {
		if coverageStatus(t, snap, kind) != model.CoverageMissing {
			t.Errorf("%s should be Missing in --quick mode", kind)
		}
	}
}
