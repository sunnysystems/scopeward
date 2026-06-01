package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestDiffBaseline(t *testing.T) {
	baseline := map[string]bool{
		fkey("human.no-2fa", "bob", "t1"):        true,
		fkey("human.owner-sprawl", "acme", "t2"): true, // will be resolved
	}
	current := []model.Finding{
		{CheckID: "human.no-2fa", Resource: model.ResourceRef{Name: "bob"}, Title: "t1"},                        // existing
		{CheckID: "teams.unprotected-default-branch", Resource: model.ResourceRef{Name: "acme/x"}, Title: "t3"}, // new
	}

	newKeys, resolved := diffBaseline(current, baseline)
	if len(newKeys) != 1 {
		t.Errorf("new = %d, want 1", len(newKeys))
	}
	if resolved != 1 {
		t.Errorf("resolved = %d, want 1 (owner-sprawl gone)", resolved)
	}

	only := keepNew(current, newKeys)
	if len(only) != 1 || only[0].CheckID != "teams.unprotected-default-branch" {
		t.Errorf("keepNew = %+v, want only the new branch finding", only)
	}
}

// fkey mirrors report.FindingKey for building test baselines.
func fkey(check, resource, title string) string {
	return check + "\x00" + resource + "\x00" + title
}

func TestLoadBaselineKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "base.json")
	js := `{"findings":[{"check_id":"human.no-2fa","title":"Member has 2FA disabled","resource":{"name":"bob"}}]}`
	os.WriteFile(path, []byte(js), 0o644)

	keys, err := loadBaselineKeys(path)
	if err != nil || len(keys) != 1 {
		t.Fatalf("load = (%v, %v)", keys, err)
	}
	if !keys[fkey("human.no-2fa", "bob", "Member has 2FA disabled")] {
		t.Errorf("expected key not found in %v", keys)
	}

	if _, err := loadBaselineKeys(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected error for missing baseline")
	}
}
