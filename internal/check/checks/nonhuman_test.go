package checks

import (
	"context"
	"testing"
	"time"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestAppBroadPermissions(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.AppInstallations = []model.AppInstallation{
		{AppSlug: "readonly", RepositorySelection: "all", Permissions: map[string]string{"contents": "read"}},
		{AppSlug: "writer-selected", RepositorySelection: "selected", Permissions: map[string]string{"contents": "write"}},
		{AppSlug: "writer-all", RepositorySelection: "all", Permissions: map[string]string{"contents": "write"}},
		{AppSlug: "admin-app", RepositorySelection: "selected", Permissions: map[string]string{"administration": "admin"}},
	}

	got := appBroadPermissions{}.Run(context.Background(), snap)
	bySlug := map[string]model.Finding{}
	for _, f := range got {
		bySlug[f.Evidence["app_slug"].(string)] = f
	}

	if _, flagged := bySlug["readonly"]; flagged {
		t.Error("read-only app must not be flagged")
	}
	if f := bySlug["writer-selected"]; f.Severity != model.SevMedium {
		t.Errorf("writer-selected severity = %v, want medium", f.Severity)
	}
	if f := bySlug["writer-all"]; f.Severity != model.SevHigh {
		t.Errorf("writer-all severity = %v, want high (write across all repos)", f.Severity)
	}
	if f := bySlug["admin-app"]; f.Severity != model.SevHigh {
		t.Errorf("admin-app severity = %v, want high", f.Severity)
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
