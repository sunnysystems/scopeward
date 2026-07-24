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

// repoFilterMock serves group "acme" with two projects (101 acme/api, 102
// acme/web) and fails the test if any per-project endpoint of 102 is queried —
// the --repo filter must keep the scan away from filtered-out projects.
func repoFilterMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		write := func(s string) { _, _ = w.Write([]byte(s)) }
		switch {
		case p == "/api/v4/groups/acme":
			write(`{"id":10,"name":"Acme","full_path":"acme","require_two_factor_authentication":true}`)
		case p == "/api/v4/groups/acme/members/all":
			write(`[{"id":7,"username":"owner","access_level":50}]`)
		case p == "/api/v4/user":
			write(`{"id":7,"username":"owner","is_admin":false}`)
		case p == "/api/v4/groups/acme/descendant_groups":
			write(`[]`)
		case p == "/api/v4/groups/acme/projects":
			write(`[{"id":101,"path_with_namespace":"acme/api","visibility":"private","default_branch":"main","namespace":{"full_path":"acme"},"shared_with_groups":[]},
			        {"id":102,"path_with_namespace":"acme/web","visibility":"private","default_branch":"main","namespace":{"full_path":"acme"},"shared_with_groups":[]}]`)
		case p == "/api/v4/projects/101/members":
			write(`[]`)
		default:
			if strings.Contains(p, "/projects/102") {
				t.Errorf("filtered-out project 102 was queried: %s", p)
			}
			if !serveAuxEndpoints(w, p) {
				t.Errorf("unexpected request path: %s", p)
				w.WriteHeader(http.StatusNotFound)
			}
		}
	}))
}

func TestRunGroupRepoFilter(t *testing.T) {
	srv := repoFilterMock(t)
	defer srv.Close()

	snap, err := RunGroup(context.Background(), newClient(srv), "acme", "https://gitlab.example.com", nil,
		collect.Options{Repos: []string{"api"}})
	if err != nil {
		t.Fatalf("RunGroup: %v", err)
	}

	if len(snap.Repos) != 1 || snap.Repos[0].Name != "acme/api" {
		t.Fatalf("repos = %+v, want just acme/api", snap.Repos)
	}

	// Coverage must say the project list was narrowed, never implying a full scan.
	c, ok := snap.Coverage.Get(model.DataRepos)
	if !ok || c.Status != model.CoveragePartial {
		t.Errorf("DataRepos coverage = %+v, want partial", c)
	}
	if !strings.Contains(c.Reason, "--repo") || !strings.Contains(c.Reason, "1 of 2") {
		t.Errorf("DataRepos reason = %q, want it to mention --repo and 1 of 2", c.Reason)
	}
}

func TestRunGroupRepoFilterNoMatch(t *testing.T) {
	srv := repoFilterMock(t)
	defer srv.Close()

	_, err := RunGroup(context.Background(), newClient(srv), "acme", "https://gitlab.example.com", nil,
		collect.Options{Repos: []string{"nope"}})
	if err == nil || !strings.Contains(err.Error(), "--repo") {
		t.Fatalf("RunGroup err = %v, want a no-project-matched --repo error", err)
	}
}
