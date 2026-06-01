package checks

import (
	"context"
	"testing"
	"time"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestStaleRepo(t *testing.T) {
	now := time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) *time.Time { tm := now.Add(-d); return &tm }

	snap := model.NewSnapshot("acme")
	snap.CollectedAt = now
	snap.Repos = []model.Repo{
		{Name: "fresh", PushedAt: ago(30 * 24 * time.Hour)},                         // recent → ok
		{Name: "stale", PushedAt: ago(400 * 24 * time.Hour)},                        // >1y → flag
		{Name: "archived-old", Archived: true, PushedAt: ago(800 * 24 * time.Hour)}, // archived → skip
		{Name: "never-pushed", PushedAt: nil},                                       // unknown → skip
	}

	got := staleRepo{}.Run(context.Background(), snap)
	if len(got) != 1 || got[0].Evidence["repo"] != "stale" {
		t.Fatalf("got %+v, want only the 'stale' repo", got)
	}
	if got[0].Severity != model.SevLow {
		t.Errorf("severity = %v, want low", got[0].Severity)
	}
	if days, ok := got[0].Evidence["days_since_push"].(int); !ok || days < 365 {
		t.Errorf("days_since_push = %v, want >= 365", got[0].Evidence["days_since_push"])
	}
}

func TestStaleRepo_ConfiguredThreshold(t *testing.T) {
	now := time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC)
	pushed := now.Add(-60 * 24 * time.Hour)

	snap := model.NewSnapshot("acme")
	snap.CollectedAt = now
	snap.StaleAfter = 30 * 24 * time.Hour // tighter than the 1-year default
	snap.Repos = []model.Repo{{Name: "r", PushedAt: &pushed}}

	if got := (staleRepo{}).Run(context.Background(), snap); len(got) != 1 {
		t.Errorf("findings = %d, want 1 (60d > 30d threshold)", len(got))
	}

	// Same repo is fine under the default 1-year threshold.
	snap.StaleAfter = 0
	if got := (staleRepo{}).Run(context.Background(), snap); len(got) != 0 {
		t.Errorf("findings = %d, want 0 (60d < 365d default)", len(got))
	}
}
