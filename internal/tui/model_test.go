package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/report"
	"github.com/sunnysystems/scopeward/internal/score"
)

func sampleAudit() report.Audit {
	snap := model.NewSnapshot("acme")
	snap.Org = model.Organization{Login: "acme", Name: "Acme Corp"}
	findings := []model.Finding{
		{CheckID: "human.no-2fa", Title: "Member has 2FA disabled", Severity: model.SevHigh, Axis: model.AxisIdentity,
			Resource: model.ResourceRef{Type: "member", Name: "bob"}, Description: "soft target", Remediation: "enable 2FA"},
	}
	return report.Audit{Snapshot: snap, Report: check.Report{Findings: findings}, Score: score.Grade(findings)}
}

func newTestModel() appModel {
	return newModel(context.Background(), "acme", func(context.Context) (report.Audit, error) {
		return sampleAudit(), nil
	})
}

func TestLoadingView(t *testing.T) {
	m := newTestModel()
	if cmd := m.Init(); cmd == nil {
		t.Error("Init should dispatch the async collect + spinner commands")
	}
	if !strings.Contains(m.View(), "collecting") {
		t.Errorf("loading view = %q, want it to mention collecting", m.View())
	}
}

func TestReadyViewAfterCollect(t *testing.T) {
	m := newTestModel()
	// size first, then deliver the collected audit
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	next, _ = next.Update(collectedMsg{audit: sampleAudit()})
	m = next.(appModel)

	if m.state != stateReady {
		t.Fatalf("state = %v, want ready", m.state)
	}
	view := m.View()
	// Grouped by problem type: the list shows the check title and the detail pane
	// (group selected) lists the affected resource.
	for _, want := range []string{"scopeward", "Problems (1)", "Members without 2FA", "bob"} {
		if !strings.Contains(view, want) {
			t.Errorf("ready view missing %q", want)
		}
	}
}

func TestExpandGroup(t *testing.T) {
	m := newTestModel()
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	next, _ = next.Update(collectedMsg{audit: sampleAudit()})
	m = next.(appModel)

	// Collapsed: one row (the group).
	if got := len(m.list.Items()); got != 1 {
		t.Fatalf("collapsed items = %d, want 1", got)
	}
	// Press enter to expand → group row + its one finding child.
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(appModel)
	if got := len(m.list.Items()); got != 2 {
		t.Fatalf("expanded items = %d, want 2 (group + child)", got)
	}
	if !m.expanded["human.no-2fa"] {
		t.Error("group should be marked expanded")
	}
}

func TestErrorView(t *testing.T) {
	m := newTestModel()
	next, _ := m.Update(errMsg{err: errors.New("token rejected")})
	m = next.(appModel)
	if m.state != stateError || !strings.Contains(m.View(), "token rejected") {
		t.Errorf("error view = %q, want it to surface the error", m.View())
	}
}

func TestQuitOnQ(t *testing.T) {
	m := newTestModel()
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Error("pressing q should return a quit command")
	}
}
