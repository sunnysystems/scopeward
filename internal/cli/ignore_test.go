package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestIgnoreApply(t *testing.T) {
	cfg := &ignoreConfig{Ignore: []ignoreRule{
		{Check: "human.owner-sprawl"}, // suppress all of this check; no reason given
		{Check: "teams.unprotected-default-branch", Resource: "acme/instana", Reason: "docs-only mirror, reviewed 2026-07"},
	}}

	findings := []model.Finding{
		{CheckID: "human.owner-sprawl", Resource: model.ResourceRef{Name: "acme"}},
		{CheckID: "teams.unprotected-default-branch", Resource: model.ResourceRef{Name: "acme/instana"}}, // suppressed
		{CheckID: "teams.unprotected-default-branch", Resource: model.ResourceRef{Name: "acme/other"}},   // kept (different repo)
		{CheckID: "human.no-2fa", Resource: model.ResourceRef{Name: "bob"}},                              // kept
	}

	kept, suppressed := cfg.apply(findings)
	if len(suppressed) != 2 {
		t.Fatalf("suppressed = %d, want 2", len(suppressed))
	}
	if len(kept) != 2 {
		t.Fatalf("kept = %d, want 2", len(kept))
	}
	for _, f := range kept {
		if f.CheckID == "human.owner-sprawl" {
			t.Error("owner-sprawl should have been suppressed")
		}
		if f.Resource.Name == "acme/instana" {
			t.Error("instana branch finding should have been suppressed")
		}
	}

	// The reason must reach the suppression, and a rule that documented nothing
	// must stay visibly undocumented rather than borrowing another rule's reason.
	byCheck := map[string]string{}
	for _, s := range suppressed {
		byCheck[s.Finding.CheckID] = s.Reason
	}
	if got := byCheck["teams.unprotected-default-branch"]; got != "docs-only mirror, reviewed 2026-07" {
		t.Errorf("reason = %q, want the rule's reason", got)
	}
	if got := byCheck["human.owner-sprawl"]; got != "" {
		t.Errorf("reason = %q, want empty for a rule with no reason", got)
	}
}

// A rule naming a specific resource must win over a later check-wide rule, so the
// more precise reason is the one reported.
func TestIgnoreApply_FirstMatchSuppliesTheReason(t *testing.T) {
	cfg := &ignoreConfig{Ignore: []ignoreRule{
		{Check: "nonhuman.app-broad-permissions", Resource: "acme-monitoring", Reason: "our monitoring integration"},
		{Check: "nonhuman.app-broad-permissions", Reason: "blanket acceptance"},
	}}
	_, suppressed := cfg.apply([]model.Finding{
		{CheckID: "nonhuman.app-broad-permissions", Resource: model.ResourceRef{Name: "acme-monitoring"}},
		{CheckID: "nonhuman.app-broad-permissions", Resource: model.ResourceRef{Name: "some-other-app"}},
	})
	if len(suppressed) != 2 {
		t.Fatalf("suppressed = %d, want 2", len(suppressed))
	}
	if suppressed[0].Reason != "our monitoring integration" {
		t.Errorf("specific rule reason = %q", suppressed[0].Reason)
	}
	if suppressed[1].Reason != "blanket acceptance" {
		t.Errorf("fallback rule reason = %q", suppressed[1].Reason)
	}
}

func TestLoadIgnore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ig.yml")
	os.WriteFile(path, []byte("ignore:\n  - check: human.no-2fa\n    reason: accepted\n"), 0o644)

	cfg, resolved, err := loadIgnore(path)
	if err != nil || cfg == nil || resolved != path || len(cfg.Ignore) != 1 {
		t.Fatalf("load = (%+v, %q, %v)", cfg, resolved, err)
	}

	// Missing explicit path is an error; empty (no file in cwd) is not.
	if _, _, err := loadIgnore(filepath.Join(dir, "nope.yml")); err == nil {
		t.Error("expected error for missing explicit config path")
	}

	// Entry without a check is rejected.
	bad := filepath.Join(dir, "bad.yml")
	os.WriteFile(bad, []byte("ignore:\n  - reason: oops\n"), 0o644)
	if _, _, err := loadIgnore(bad); err == nil {
		t.Error("expected error for ignore entry without a check")
	}
}
