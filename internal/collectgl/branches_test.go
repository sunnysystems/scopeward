package collectgl

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/collect"
	"github.com/sunnysystems/scopeward/internal/model"
)

// branchesMock serves group "acme" (id 10) with one project (101, default branch
// main) and the #8 endpoints: a protected default branch allowing force-push,
// Premium approval rules requiring one approval with author self-approval on, and
// a CODEOWNERS file at docs/CODEOWNERS naming a subgroup.
func branchesMock(t *testing.T) *httptest.Server {
	t.Helper()
	codeowners := base64.StdEncoding.EncodeToString([]byte("# owners\n*       @acme/backend\ndocs/*  @alice\n"))
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
			write(`[{"id":11,"name":"Backend","full_path":"acme/backend","parent_id":10}]`)
		case p == "/api/v4/groups/acme/projects":
			write(`[{"id":101,"path_with_namespace":"acme/api","visibility":"private","default_branch":"main","namespace":{"full_path":"acme"},"shared_with_groups":[]}]`)
		case p == "/api/v4/groups/11/members", p == "/api/v4/projects/101/members":
			write(`[]`)

		// #8: protected branches — default branch protected, force-push allowed.
		case p == "/api/v4/projects/101/protected_branches":
			write(`[{"name":"main","allow_force_push":true,"code_owner_approval_required":false},
			        {"name":"release/*","allow_force_push":false,"code_owner_approval_required":true}]`)
		// #8: approval rules (Premium) + settings.
		case p == "/api/v4/projects/101/approval_rules":
			write(`[{"approvals_required":1}]`)
		case p == "/api/v4/projects/101/approvals":
			write(`{"approvals_before_merge":0,"reset_approvals_on_push":false,"merge_requests_author_approval":true}`)
		// #8: CODEOWNERS — absent at CODEOWNERS, present at docs/CODEOWNERS. The
		// client sends the path URL-encoded (%2F), but the test server exposes the
		// decoded path on r.URL.Path.
		case p == "/api/v4/projects/101/repository/files/CODEOWNERS":
			w.WriteHeader(http.StatusNotFound)
			write(`{"message":"404 File Not Found"}`)
		case p == "/api/v4/projects/101/repository/files/docs/CODEOWNERS":
			write(`{"content":"` + codeowners + `","encoding":"base64"}`)

		default:
			if !serveAuxEndpoints(w, p) {
				t.Errorf("unexpected request path: %s", p)
				w.WriteHeader(http.StatusNotFound)
			}
		}
	}))
}

func TestRunGroupCollectsBranches(t *testing.T) {
	srv := branchesMock(t)
	defer srv.Close()

	snap, err := RunGroup(context.Background(), newClient(srv), "acme", "https://gitlab.example.com", nil, collect.Options{})
	if err != nil {
		t.Fatalf("RunGroup: %v", err)
	}
	if len(snap.Repos) != 1 {
		t.Fatalf("repos = %d, want 1", len(snap.Repos))
	}
	r := snap.Repos[0]

	// Protected branch: default branch "main" matched a protected entry that allows force-push.
	if r.DefaultBranchProtected == nil || !*r.DefaultBranchProtected {
		t.Errorf("DefaultBranchProtected = %v, want true", r.DefaultBranchProtected)
	}
	if r.BranchAllowForcePush == nil || !*r.BranchAllowForcePush {
		t.Errorf("BranchAllowForcePush = %v, want true (the main rule allows it)", r.BranchAllowForcePush)
	}

	// Approval rules (Premium): one approval required → BranchReqPRReview true;
	// author self-approval allowed; approvals not reset on push.
	if r.MRApprovalsRequired == nil || *r.MRApprovalsRequired != 1 {
		t.Errorf("MRApprovalsRequired = %v, want 1", r.MRApprovalsRequired)
	}
	if r.BranchReqPRReview == nil || !*r.BranchReqPRReview {
		t.Errorf("BranchReqPRReview = %v, want true (1 approval required)", r.BranchReqPRReview)
	}
	if r.MRAuthorCanApprove == nil || !*r.MRAuthorCanApprove {
		t.Errorf("MRAuthorCanApprove = %v, want true", r.MRAuthorCanApprove)
	}
	if r.MRResetApprovalsOnPush == nil || *r.MRResetApprovalsOnPush {
		t.Errorf("MRResetApprovalsOnPush = %v, want false", r.MRResetApprovalsOnPush)
	}

	// CODEOWNERS: present at docs/CODEOWNERS, names the @acme/backend subgroup (the
	// @alice individual is not counted as a team).
	if r.CodeownersPresent == nil || !*r.CodeownersPresent {
		t.Errorf("CodeownersPresent = %v, want true", r.CodeownersPresent)
	}
	if len(r.CodeownersTeams) != 1 || r.CodeownersTeams[0] != "@acme/backend" {
		t.Errorf("CodeownersTeams = %v, want [@acme/backend]", r.CodeownersTeams)
	}

	for _, kind := range []model.DataKind{model.DataBranchProtection, model.DataMRApprovalSettings, model.DataCodeowners} {
		if coverageStatus(t, snap, kind) != model.CoverageOK {
			t.Errorf("%s should be OK", kind)
		}
	}
}

// TestRunGroupBranchesApprovalRulesFree simulates a Free instance where the
// approval-rules endpoint is forbidden: approval settings degrade to "not
// evaluated" while protected-branch data (free) is still collected.
func TestRunGroupBranchesApprovalRulesFree(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		write := func(s string) { _, _ = w.Write([]byte(s)) }
		switch {
		case p == "/api/v4/groups/acme":
			write(`{"id":10,"name":"Acme","full_path":"acme"}`)
		case p == "/api/v4/groups/acme/members/all":
			write(`[{"id":7,"username":"owner","access_level":50}]`)
		case p == "/api/v4/user":
			write(`{"id":7,"username":"owner","is_admin":false}`)
		case p == "/api/v4/groups/acme/descendant_groups":
			write(`[]`)
		case p == "/api/v4/groups/acme/projects":
			write(`[{"id":101,"path_with_namespace":"acme/api","default_branch":"main","namespace":{"full_path":"acme"}}]`)
		case p == "/api/v4/projects/101/members":
			write(`[]`)
		case p == "/api/v4/projects/101/protected_branches":
			write(`[]`) // not protected
		case p == "/api/v4/projects/101/approval_rules":
			w.WriteHeader(http.StatusForbidden) // Premium-only on this instance
			write(`{"message":"403 Forbidden"}`)
		case strings.Contains(p, "/repository/files/"):
			w.WriteHeader(http.StatusNotFound)
			write(`{"message":"404 Not Found"}`)
		default:
			if !serveAuxEndpoints(w, p) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`[]`))
			}
		}
	}))
	defer srv.Close()

	snap, err := RunGroup(context.Background(), newClient(srv), "acme", "", nil, collect.Options{})
	if err != nil {
		t.Fatalf("RunGroup: %v", err)
	}
	// Protected-branch data still collected (free).
	if coverageStatus(t, snap, model.DataBranchProtection) != model.CoverageOK {
		t.Error("DataBranchProtection should be OK on Free")
	}
	if r := snap.Repos[0]; r.DefaultBranchProtected == nil || *r.DefaultBranchProtected {
		t.Errorf("default branch should be collected as unprotected, got %v", r.DefaultBranchProtected)
	}
	// Approval rules forbidden → not evaluated.
	if coverageStatus(t, snap, model.DataMRApprovalSettings) != model.CoverageMissing {
		t.Error("DataMRApprovalSettings should be Missing when approval rules are forbidden (Free)")
	}
	if snap.Repos[0].BranchReqPRReview != nil {
		t.Error("BranchReqPRReview should stay nil on Free (review enforcement unknown)")
	}
}
