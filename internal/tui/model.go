package tui

import (
	"context"
	"fmt"
	"sort"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/sunnysystems/scopeward/internal/check"
	_ "github.com/sunnysystems/scopeward/internal/check/checks" // ensure check titles are registered
	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/report"
	"github.com/sunnysystems/scopeward/internal/ui"
)

type state int

const (
	stateLoading state = iota
	stateReady
	stateError
)

const (
	listWidth   = 52
	headerLines = 3
	footerLines = 1
)

// groupData is one problem type (a check) and the findings under it.
type groupData struct {
	checkID  string
	title    string
	axis     model.Axis
	severity model.Severity // highest severity in the group
	findings []model.Finding
}

type appModel struct {
	ctx   context.Context
	org   string
	audit AuditFunc

	state    state
	spinner  spinner.Model
	list     list.Model
	viewport viewport.Model
	result   report.Audit
	err      error

	groups   []groupData
	expanded map[string]bool

	width, height int
	vpReady       bool
}

// messages produced by the async audit command.
type collectedMsg struct{ audit report.Audit }
type errMsg struct{ err error }

func newModel(ctx context.Context, org string, audit AuditFunc) appModel {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(ui.Amber)
	return appModel{ctx: ctx, org: org, audit: audit, state: stateLoading, spinner: sp, expanded: map[string]bool{}}
}

func (m appModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.collect())
}

// collect runs the (blocking) audit inside a tea.Cmd goroutine so the spinner
// keeps animating while GitHub is queried.
func (m appModel) collect() tea.Cmd {
	return func() tea.Msg {
		audit, err := m.audit(m.ctx)
		if err != nil {
			return errMsg{err}
		}
		return collectedMsg{audit}
	}
}

func (m appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		return m, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		// While the list's filter is active, let it consume keystrokes.
		filtering := m.state == stateReady && m.list.FilterState() == list.Filtering
		if !filtering {
			switch msg.String() {
			case "q", "esc":
				return m, tea.Quit
			}
		}
		if m.state == stateReady && !filtering {
			switch msg.String() {
			case "enter", " ", "right", "l":
				m.toggleSelected(true)
				return m, nil
			case "left", "h":
				m.toggleSelected(false)
				return m, nil
			}
		}

	case errMsg:
		m.state, m.err = stateError, msg.err
		return m, nil

	case collectedMsg:
		m.result = msg.audit
		m.state = stateReady
		m.initReady()
		return m, nil

	case spinner.TickMsg:
		if m.state == stateLoading {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
		return m, nil
	}

	if m.state == stateReady {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		m.syncDetail()
		return m, cmd
	}
	return m, nil
}

// initReady groups the findings by problem type and builds the list + detail.
func (m *appModel) initReady() {
	m.groups = buildGroups(m.result.Report.Findings)

	delegate := list.NewDefaultDelegate()
	m.list = list.New(m.buildItems(), delegate, 0, 0)
	m.list.Title = fmt.Sprintf("Problems (%d)", len(m.groups))
	m.list.SetShowStatusBar(false)
	m.list.Styles.Title = lipgloss.NewStyle().Foreground(ui.Copper).Bold(true)

	m.viewport = viewport.New(0, 0)
	m.vpReady = true
	m.layout()
	m.syncDetail()
}

// buildGroups clusters findings by check ID, labels each with the check's title,
// and orders groups by highest severity then title.
func buildGroups(findings []model.Finding) []groupData {
	titles := map[string]string{}
	for _, c := range check.All() {
		titles[c.Meta().ID] = c.Meta().Title
	}

	byID := map[string]*groupData{}
	var order []string
	for _, f := range findings {
		g := byID[f.CheckID]
		if g == nil {
			label := titles[f.CheckID]
			if label == "" {
				label = f.CheckID
			}
			g = &groupData{checkID: f.CheckID, title: label, axis: f.Axis, severity: f.Severity}
			byID[f.CheckID] = g
			order = append(order, f.CheckID)
		}
		g.findings = append(g.findings, f)
		if f.Severity > g.severity {
			g.severity = f.Severity
		}
	}

	groups := make([]groupData, 0, len(order))
	for _, id := range order {
		groups = append(groups, *byID[id])
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].severity != groups[j].severity {
			return groups[i].severity > groups[j].severity
		}
		return groups[i].title < groups[j].title
	})
	return groups
}

// buildItems flattens groups into list items, inserting a group's findings right
// after it when expanded.
func (m *appModel) buildItems() []list.Item {
	var items []list.Item
	for _, g := range m.groups {
		items = append(items, groupItem{g: g, expanded: m.expanded[g.checkID]})
		if m.expanded[g.checkID] {
			for _, f := range g.findings {
				items = append(items, findingItem{f})
			}
		}
	}
	return items
}

// toggleSelected expands/collapses based on the selected row. expand=false from a
// finding collapses its parent group and moves the cursor to it.
func (m *appModel) toggleSelected(expand bool) {
	switch v := m.list.SelectedItem().(type) {
	case groupItem:
		if expand {
			m.expanded[v.g.checkID] = !m.expanded[v.g.checkID]
		} else {
			m.expanded[v.g.checkID] = false
		}
		idx := m.list.Index()
		m.list.SetItems(m.buildItems())
		m.list.Select(idx)
	case findingItem:
		if !expand {
			m.expanded[v.f.CheckID] = false
			m.list.SetItems(m.buildItems())
			m.list.Select(m.indexOfGroup(v.f.CheckID))
		}
	}
	m.syncDetail()
}

func (m *appModel) indexOfGroup(checkID string) int {
	for i, it := range m.list.Items() {
		if g, ok := it.(groupItem); ok && g.g.checkID == checkID {
			return i
		}
	}
	return 0
}

// layout sizes the list and viewport to the current terminal dimensions.
func (m *appModel) layout() {
	if m.state != stateReady || !m.vpReady {
		return
	}
	bodyHeight := m.height - headerLines - footerLines
	if bodyHeight < 3 {
		bodyHeight = 3
	}
	m.list.SetSize(listWidth, bodyHeight)

	vpWidth := m.width - listWidth - 3
	if vpWidth < 20 {
		vpWidth = 20
	}
	m.viewport.Width = vpWidth
	m.viewport.Height = bodyHeight
	m.syncDetail()
}

// syncDetail refreshes the detail pane for the selected row (a problem summary
// for a group, or the full finding for a leaf).
func (m *appModel) syncDetail() {
	if !m.vpReady {
		return
	}
	switch v := m.list.SelectedItem().(type) {
	case findingItem:
		m.viewport.SetContent(detailView(v.f, m.viewport.Width))
	case groupItem:
		m.viewport.SetContent(groupDetailView(v.g, m.viewport.Width))
	default:
		m.viewport.SetContent(ui.Subtle.Render("No findings — every evaluated check passed."))
	}
}

func (m appModel) View() string {
	switch m.state {
	case stateError:
		return ui.Bad.Render("audit failed: ") + m.err.Error() + "\n"
	case stateLoading:
		return fmt.Sprintf("\n  %s collecting %s …\n", m.spinner.View(), ui.Accent.Render(m.org))
	}
	return m.readyView()
}

// ensure model implements tea.Model
var _ tea.Model = appModel{}
