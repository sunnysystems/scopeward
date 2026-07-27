package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/score"
)

// appFixture covers the shapes that matter: read-only, ordinary CI write (the
// case that used to produce a permanent unclearable finding), and the narrow set
// that genuinely escalates past the app's own job.
func appFixture() *model.Snapshot {
	snap := model.NewSnapshot("acme")
	snap.AppInstallations = []model.AppInstallation{
		{AppSlug: "readonly", RepositorySelection: "all", Permissions: map[string]string{"contents": "read"}},
		{AppSlug: "ci-bot", RepositorySelection: "all", Permissions: map[string]string{"contents": "write", "checks": "write", "pull_requests": "write"}},
		{AppSlug: "deployer", RepositorySelection: "selected", Permissions: map[string]string{"contents": "write", "deployments": "write"}},
		{AppSlug: "org-manager", RepositorySelection: "selected", Permissions: map[string]string{"members": "write"}},
		{AppSlug: "iac", RepositorySelection: "all", Permissions: map[string]string{"administration": "write", "contents": "write"}},
	}
	return snap
}

// The old check flagged any write at all, so an org running CI could never clear
// it — the finding had no remedy but uninstalling a working integration. Ordinary
// write must now be inventory, and only the narrow escalating set a finding.
func TestAppDangerousPermissions(t *testing.T) {
	got := appDangerousPermissions{}.Run(context.Background(), appFixture())
	bySlug := map[string]model.Finding{}
	for _, f := range got {
		bySlug[f.Evidence["app_slug"].(string)] = f
	}

	for _, ordinary := range []string{"readonly", "ci-bot", "deployer"} {
		if f, flagged := bySlug[ordinary]; flagged {
			t.Errorf("%s must not be flagged (%q): ordinary automation write is inventory, not a defect",
				ordinary, f.Title)
		}
	}

	// members:write on selected repos — real, but bounded.
	if f := bySlug["org-manager"]; f.Severity != model.SevMedium {
		t.Errorf("org-manager severity = %v, want medium (dangerous but scoped)", f.Severity)
	}
	// administration:write across every repo — can remove branch protection anywhere.
	iac := bySlug["iac"]
	if iac.Severity != model.SevHigh {
		t.Errorf("iac severity = %v, want high (dangerous across all repos)", iac.Severity)
	}
	if perms, _ := iac.Evidence["dangerous_permissions"].([]string); len(perms) != 1 || perms[0] != "administration:write" {
		t.Errorf("evidence = %v, want only administration:write — contents:write is its job", iac.Evidence["dangerous_permissions"])
	}
	if !strings.Contains(iac.Title, "branch protection") {
		t.Errorf("title %q should say what the permission enables, not just name it", iac.Title)
	}
}

// Grade A has to be reachable for an org that runs CI: with only ordinary
// automation installed, the app checks must cost nothing.
func TestAppChecksAreClearable(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.AppInstallations = []model.AppInstallation{
		{AppSlug: "ci-bot", RepositorySelection: "all", Permissions: map[string]string{"contents": "write", "checks": "write"}},
		{AppSlug: "deployer", RepositorySelection: "selected", Permissions: map[string]string{"deployments": "write"}},
	}
	var all []model.Finding
	all = append(all, appDangerousPermissions{}.Run(context.Background(), snap)...)
	all = append(all, appInventory{}.Run(context.Background(), snap)...)

	if p := score.Grade(all).Penalty; p != 0 {
		t.Errorf("penalty = %d, want 0: an org whose only apps are ordinary automation must be able to reach grade A", p)
	}
}

func TestAppInventory(t *testing.T) {
	got := appInventory{}.Run(context.Background(), appFixture())
	if len(got) != 1 {
		t.Fatalf("want one aggregate inventory finding, got %d", len(got))
	}
	if got[0].Severity != model.SevInfo {
		t.Errorf("severity = %v, want info", got[0].Severity)
	}
	apps, _ := got[0].Evidence["apps"].([]map[string]any)
	if len(apps) != 5 {
		t.Fatalf("inventory lists %d apps, want all 5 including read-only", len(apps))
	}
	if apps[0]["app_slug"] != "ci-bot" {
		t.Errorf("inventory should be sorted by slug, got %v first", apps[0]["app_slug"])
	}
	if !strings.Contains(got[0].Title, "4 with write or admin") {
		t.Errorf("title %q should count the apps holding write", got[0].Title)
	}

	// No apps, no inventory line.
	if got := (appInventory{}).Run(context.Background(), model.NewSnapshot("acme")); len(got) != 0 {
		t.Errorf("empty org produced %d findings", len(got))
	}
}

func TestActionsTokenWriteDefault(t *testing.T) {
	snap := model.NewSnapshot("acme")

	snap.ActionsToken = model.ActionsTokenSettings{DefaultWorkflowPermissions: "read"}
	if got := (actionsTokenWriteDefault{}).Run(context.Background(), snap); len(got) != 0 {
		t.Errorf("read default: findings = %d, want 0", len(got))
	}

	snap.ActionsToken = model.ActionsTokenSettings{DefaultWorkflowPermissions: "write"}
	got := actionsTokenWriteDefault{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Severity != model.SevHigh {
		t.Errorf("write default: got %+v, want one high finding", got)
	}
}

func TestWritableDeployKey(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Repos = []model.Repo{{
		Name: "api",
		DeployKeys: []model.DeployKey{
			{ID: 1, Title: "readonly", ReadOnly: true},
			{ID: 2, Title: "ci-push", ReadOnly: false},
		},
	}}
	got := writableDeployKey{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Evidence["title"] != "ci-push" {
		t.Errorf("got %+v, want only the writable key", got)
	}
}

func TestWebhookHygiene(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.OrgWebhooks = []model.Webhook{
		{ID: 1, Active: true, HasSecret: true, InsecureSSL: false}, // healthy
		{ID: 2, Active: true, HasSecret: false},                    // no secret → medium
		{ID: 3, Active: true, HasSecret: true, InsecureSSL: true},  // insecure ssl → high
		{ID: 4, Active: false, HasSecret: false},                   // inactive → skipped
	}

	got := webhookHygiene{scope: "org"}.Run(context.Background(), snap)
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (no-secret + insecure-ssl; healthy and inactive skipped)", len(got))
	}
	counts := map[model.Severity]int{}
	for _, f := range got {
		counts[f.Severity]++
	}
	if counts[model.SevMedium] != 1 || counts[model.SevHigh] != 1 {
		t.Errorf("severities = %v, want one medium (no secret) and one high (insecure ssl)", counts)
	}
}

func TestPATNoExpiry(t *testing.T) {
	exp := time.Unix(1800000000, 0)
	snap := model.NewSnapshot("acme")
	snap.PATs = []model.PAT{
		{ID: 1, OwnerLogin: "alice", ExpiresAt: nil}, // never expires → flag
		{ID: 2, OwnerLogin: "bob", ExpiresAt: &exp},  // expires → ok
	}
	got := patNoExpiry{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Evidence["owner"] != "alice" {
		t.Errorf("got %+v, want only alice", got)
	}
}
