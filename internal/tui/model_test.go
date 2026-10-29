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
	return report.Audit{Snapshot: snap, Report: check.Report{Findings: findings}, Score: score.Grade(findings, score.Scale{ActiveRepos: snap.ActiveRepoCount()})}
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

// accessAudit is sampleAudit with an access graph behind it: bob and alice in
// team platform, which can write to api; alice also holds a direct admin grant
// on infra, which a finding is about; legacy is archived.
func accessAudit() report.Audit {
	a := sampleAudit()
	snap := a.Snapshot
	snap.Org.DefaultRepoPermission = "read"
	snap.Members = []model.Member{{Login: "alice", Role: "member"}, {Login: "bob", Role: "member"}}
	snap.Teams = []model.Team{{Slug: "platform", Members: []string{"alice", "bob"}, RepoGrants: []model.TeamRepoGrant{{Repo: "api", Permission: "write"}}}}
	snap.Repos = []model.Repo{
		{Name: "api", Private: true},
		{Name: "infra", Private: true, DirectCollaborators: []model.RepoGrant{{Login: "alice", Permission: "admin"}}},
		{Name: "legacy", Private: true, Archived: true},
	}
	for _, k := range []model.DataKind{model.DataMembers, model.DataMemberRoles, model.DataTeamMembers, model.DataTeamRepos, model.DataRepoDirectCollaborators, model.DataOrgRoles} {
		snap.Coverage.OK(k, 1)
	}
	a.Report.Findings = append(a.Report.Findings, model.Finding{
		CheckID: "perms.direct-admin-grant", Title: "alice has direct admin on acme/infra", Severity: model.SevMedium,
		Axis: model.AxisTeams, Resource: model.ResourceRef{Type: "repo", Name: "acme/infra"},
	})
	return a
}

func readyAccessModel(t *testing.T) appModel {
	t.Helper()
	m := newTestModel()
	next, _ := m.Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	next, _ = next.Update(collectedMsg{audit: accessAudit()})
	return next.(appModel)
}

func press(m appModel, key string) appModel {
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
	if key == "tab" {
		msg = tea.KeyMsg{Type: tea.KeyTab}
	}
	next, _ := m.Update(msg)
	return next.(appModel)
}

func TestAccessTab(t *testing.T) {
	m := press(readyAccessModel(t), "tab")
	if m.tab != tabAccess {
		t.Fatal("tab did not switch to Access")
	}
	view := m.View()
	for _, want := range []string{"Members (2)", "alice", "Every repository", "infra", "direct grant", "Role-based access only"} {
		if !strings.Contains(view, want) {
			t.Errorf("access view missing %q", want)
		}
	}

	m = press(m, "p")
	if view := m.View(); !strings.Contains(view, "Repositories (2)") || !strings.Contains(view, "People") {
		t.Errorf("pivot to repositories:\n%s", view)
	}
	// Archived repositories are hidden until asked for.
	m = press(m, "x")
	if !strings.Contains(m.View(), "Repositories (3)") {
		t.Errorf("x should list the archived repository too:\n%s", m.View())
	}

	m = press(m, "tab")
	if m.tab != tabFindings || !strings.Contains(m.View(), "Problems (") {
		t.Error("tab should return to the findings")
	}
}

// From a finding, the access behind it is one keypress away.
func TestOpenAccessFromFinding(t *testing.T) {
	m := readyAccessModel(t)
	// Groups are ordered by severity: the high 2FA group first, then the
	// direct-admin group, which holds a single finding about acme/infra.
	m.list.Select(1)
	m = press(m, "a")
	if m.tab != tabAccess || m.pivot != pivotRepos {
		t.Fatalf("a on a repo finding: tab %v pivot %v", m.tab, m.pivot)
	}
	item, ok := m.accessList.SelectedItem().(repoItem)
	if !ok || item.v.Repo != "infra" {
		t.Fatalf("selected %+v, want infra", m.accessList.SelectedItem())
	}
	if !strings.Contains(m.View(), "acme/infra") || !strings.Contains(m.View(), "alice") {
		t.Errorf("detail should show who reaches infra:\n%s", m.View())
	}

	// A finding about a member opens that member.
	m = press(m, "tab")
	m.list.Select(0)
	m = press(m, "a")
	if mi, ok := m.accessList.SelectedItem().(memberItem); !ok || mi.v.Login != "bob" || m.pivot != pivotMembers {
		t.Errorf("a on bob's finding selected %+v", m.accessList.SelectedItem())
	}
}
