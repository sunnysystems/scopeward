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

// teamsMock serves a small GitLab group tree: top group "acme" (id 10) with
// subgroups backend (11, top-level) and payments (12, nested under backend), two
// projects, and members at varying access levels.
func teamsMock(t *testing.T) *httptest.Server {
	t.Helper()
	body := map[string]string{
		"/api/v4/groups/acme":             `{"id":10,"name":"Acme","full_path":"acme","require_two_factor_authentication":false}`,
		"/api/v4/groups/acme/members/all": `[{"id":9,"username":"root","access_level":50}]`,
		"/api/v4/user":                    `{"username":"owner","is_admin":false}`,
		"/api/v4/groups/acme/descendant_groups": `[
			{"id":11,"name":"Backend","full_path":"acme/backend","parent_id":10},
			{"id":12,"name":"Payments","full_path":"acme/backend/payments","parent_id":11}
		]`,
		"/api/v4/groups/11/members": `[{"id":1,"username":"alice","access_level":50},{"id":2,"username":"bob","access_level":30}]`,
		"/api/v4/groups/12/members": `[{"id":3,"username":"carol","access_level":40}]`,
		"/api/v4/groups/acme/projects": `[
			{"id":101,"path_with_namespace":"acme/backend/api","visibility":"private","default_branch":"main","namespace":{"full_path":"acme/backend"},"shared_with_groups":[]},
			{"id":102,"path_with_namespace":"acme/shared-lib","visibility":"private","namespace":{"full_path":"acme"},"shared_with_groups":[{"group_full_path":"acme/backend/payments","group_access_level":30}]}
		]`,
		"/api/v4/projects/101/members": `[{"id":7,"username":"dave","access_level":50}]`,
		"/api/v4/projects/102/members": `[{"id":8,"username":"erin","access_level":30}]`,
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if b, ok := body[r.URL.Path]; ok {
			_, _ = w.Write([]byte(b))
			return
		}
		// Non-human axis (#6) endpoints: the teams fixtures carry no tokens.
		p := r.URL.Path
		if p == "/api/v4/applications" || p == "/api/v4/personal_access_tokens" ||
			strings.HasSuffix(p, "/access_tokens") || strings.HasSuffix(p, "/deploy_tokens") ||
			strings.HasSuffix(p, "/deploy_keys") {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		t.Errorf("unexpected request path: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestRunGroupCollectsSubgroupsAndProjects(t *testing.T) {
	srv := teamsMock(t)
	defer srv.Close()

	snap, err := RunGroup(context.Background(), newClient(srv), "acme", "https://gitlab.example.com", nil, collect.Options{})
	if err != nil {
		t.Fatalf("RunGroup: %v", err)
	}

	// Subgroups → Team tree with correct nesting.
	teams := map[string]model.Team{}
	for _, tm := range snap.Teams {
		teams[tm.Slug] = tm
	}
	if len(teams) != 2 {
		t.Fatalf("teams = %d, want 2", len(teams))
	}
	if p := teams["acme/backend"].ParentSlug; p != "" {
		t.Errorf("acme/backend ParentSlug = %q, want empty (top-level team, parent is the group)", p)
	}
	if p := teams["acme/backend/payments"].ParentSlug; p != "acme/backend" {
		t.Errorf("payments ParentSlug = %q, want acme/backend", p)
	}

	// Members + maintainers (access_level >= Maintainer 40).
	be := teams["acme/backend"]
	if len(be.Members) != 2 {
		t.Errorf("backend members = %v, want 2", be.Members)
	}
	if len(be.Maintainers) != 1 || be.Maintainers[0] != "alice" {
		t.Errorf("backend maintainers = %v, want [alice] (Owner 50)", be.Maintainers)
	}
	if pay := teams["acme/backend/payments"]; len(pay.Maintainers) != 1 || pay.Maintainers[0] != "carol" {
		t.Errorf("payments maintainers = %v, want [carol] (Maintainer 40)", pay.Maintainers)
	}

	// RepoGrants: owned project on the owning subgroup; shared project on the sharee.
	if len(be.RepoGrants) != 1 || be.RepoGrants[0].Repo != "acme/backend/api" {
		t.Errorf("backend RepoGrants = %v, want [acme/backend/api]", be.RepoGrants)
	}
	if pay := teams["acme/backend/payments"]; len(pay.RepoGrants) != 1 || pay.RepoGrants[0].Permission != "write" {
		t.Errorf("payments RepoGrants = %v, want one share at write (Developer 30)", pay.RepoGrants)
	}

	// Projects → Repos with direct member grants mapped to neutral roles.
	repos := map[string]model.Repo{}
	for _, r := range snap.Repos {
		repos[r.Name] = r
	}
	if len(repos) != 2 {
		t.Fatalf("repos = %d, want 2", len(repos))
	}
	api := repos["acme/backend/api"]
	if len(api.DirectCollaborators) != 1 || api.DirectCollaborators[0].Permission != "admin" {
		t.Errorf("api direct collaborators = %v, want dave at admin (Owner 50)", api.DirectCollaborators)
	}
	if lib := repos["acme/shared-lib"]; len(lib.DirectCollaborators) != 1 || lib.DirectCollaborators[0].Permission != "write" {
		t.Errorf("shared-lib direct collaborators = %v, want erin at write (Developer 30)", lib.DirectCollaborators)
	}

	// Teams/perms coverage is OK; GitHub-only teams data is "not evaluated".
	for _, kind := range []model.DataKind{model.DataTeams, model.DataTeamMembers, model.DataTeamRepos, model.DataRepos, model.DataRepoDirectCollaborators} {
		if coverageStatus(t, snap, kind) != model.CoverageOK {
			t.Errorf("%s should be OK", kind)
		}
	}
	for _, kind := range []model.DataKind{model.DataCustomRoles, model.DataOrgRoles, model.DataOrgRulesets} {
		if coverageStatus(t, snap, kind) != model.CoverageMissing {
			t.Errorf("%s should be Missing (no GitLab equivalent / Ultimate-gated)", kind)
		}
	}
}

func TestRunGroupQuickSkipsMembershipPasses(t *testing.T) {
	srv := teamsMock(t)
	defer srv.Close()

	snap, err := RunGroup(context.Background(), newClient(srv), "acme", "", nil, collect.Options{Quick: true})
	if err != nil {
		t.Fatalf("RunGroup: %v", err)
	}
	// Group-level lists are still collected...
	if coverageStatus(t, snap, model.DataTeams) != model.CoverageOK || coverageStatus(t, snap, model.DataRepos) != model.CoverageOK {
		t.Error("subgroups and projects should still be listed in --quick")
	}
	// ...but the per-subgroup and per-project membership passes are skipped.
	for _, kind := range []model.DataKind{model.DataTeamMembers, model.DataRepoDirectCollaborators} {
		if coverageStatus(t, snap, kind) != model.CoverageMissing {
			t.Errorf("%s should be Missing in --quick mode", kind)
		}
	}
}
