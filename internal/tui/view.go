package tui

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/ui"
)

// groupItem is a problem type (a check) shown as a collapsible row.
type groupItem struct {
	g        groupData
	expanded bool
}

func (i groupItem) Title() string {
	caret := "▸"
	if i.expanded {
		caret = "▾"
	}
	return severityStyle(i.g.severity).Render(badge(i.g.severity)) + " " + caret + " " + i.g.title
}

func (i groupItem) Description() string {
	return fmt.Sprintf("   %d affected · %s", len(i.g.findings), i.g.axis.Title())
}

func (i groupItem) FilterValue() string { return i.g.title + " " + i.g.checkID }

// findingItem adapts a model.Finding to a (child) row under its problem group:
// the affected resource is the headline, the specific message the subtitle.
type findingItem struct{ f model.Finding }

func (i findingItem) Title() string {
	name := i.f.Resource.Name
	if name == "" {
		name = i.f.Title
	}
	return "    " + ui.Accent.Render(name)
}

func (i findingItem) Description() string {
	return "    " + ui.Subtle.Render(i.f.Title)
}

func (i findingItem) FilterValue() string {
	return i.f.Title + " " + i.f.CheckID + " " + i.f.Resource.Name
}

func badge(s model.Severity) string {
	return strings.ToUpper(s.String()[:1])
}

func severityStyle(s model.Severity) lipgloss.Style {
	switch s {
	case model.SevCritical, model.SevHigh:
		return ui.Bad
	case model.SevMedium:
		return ui.WarnTag
	case model.SevLow:
		return ui.Accent
	default:
		return ui.Subtle
	}
}

// readyView composes the header, the list+detail body, and the footer.
func (m appModel) readyView() string {
	header := m.headerView()
	footer := ui.Subtle.Render("  ↑/↓ navigate · ↵/→ expand · ← collapse · / filter · q quit")

	detail := lipgloss.NewStyle().
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(ui.Copper).
		BorderLeft(true).
		PaddingLeft(2).
		Render(m.viewport.View())

	body := lipgloss.JoinHorizontal(lipgloss.Top, m.list.View(), detail)
	return lipgloss.JoinVertical(lipgloss.Left, header, body, footer)
}

func (m appModel) headerView() string {
	org := m.result.Snapshot.Org.Login
	if name := m.result.Snapshot.Org.Name; name != "" {
		org = name
	}
	sc := m.result.Score
	gradeStyle := ui.Good
	switch sc.Grade {
	case "C", "D":
		gradeStyle = ui.WarnTag
	case "F":
		gradeStyle = ui.Bad
	}
	title := ui.Title.Render("scopeward") + ui.Subtle.Render(" · ") + ui.Accent.Render(org)
	scoreLine := fmt.Sprintf("%s  %s",
		ui.Label.Render("score"),
		gradeStyle.Render(fmt.Sprintf("%d/100 (%s)", sc.Value, sc.Grade)),
	)
	return title + "    " + scoreLine + "\n"
}

// detailView renders the full detail of one finding, wrapped to width.
func detailView(f model.Finding, width int) string {
	if width < 10 {
		width = 10
	}
	wrap := lipgloss.NewStyle().Width(width)
	var b strings.Builder

	b.WriteString(severityStyle(f.Severity).Render(strings.ToUpper(f.Severity.String())))
	b.WriteString(ui.Subtle.Render("  " + string(f.Axis)))
	b.WriteString("\n\n")
	b.WriteString(ui.Title.Render(wrap.Render(f.Title)))
	b.WriteString("\n")

	if f.Resource.Name != "" {
		b.WriteString(ui.Label.Render(f.Resource.Type + ": "))
		b.WriteString(ui.Accent.Render(f.Resource.Name))
		b.WriteString("\n")
	}
	b.WriteString(ui.Subtle.Render(f.CheckID))
	b.WriteString("\n\n")

	if f.Description != "" {
		b.WriteString(wrap.Render(f.Description))
		b.WriteString("\n\n")
	}
	if f.Remediation != "" {
		b.WriteString(ui.Label.Render("Fix"))
		b.WriteString("\n")
		b.WriteString(wrap.Render(f.Remediation))
		b.WriteString("\n\n")
	}
	if len(f.Evidence) > 0 {
		b.WriteString(ui.Label.Render("Evidence"))
		b.WriteString("\n")
		if js, err := json.MarshalIndent(f.Evidence, "", "  "); err == nil {
			b.WriteString(ui.Subtle.Render(string(js)))
			b.WriteString("\n\n")
		}
	}
	if f.GHFix != "" {
		b.WriteString(ui.Label.Render("Suggested gh command"))
		b.WriteString(ui.Subtle.Render(" (review before running; scopeward never runs it)"))
		b.WriteString("\n")
		b.WriteString(ui.Accent.Render(f.GHFix))
		b.WriteString("\n")
		if f.GHVerify != "" {
			b.WriteString(ui.Subtle.Render("verify: "))
			b.WriteString(ui.Accent.Render(f.GHVerify))
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if f.DocsURL != "" {
		b.WriteString(ui.Accent.Render(f.DocsURL))
		b.WriteString("\n")
	}
	return b.String()
}

// groupDetailView summarizes a problem type and lists every affected resource.
func groupDetailView(g groupData, width int) string {
	if width < 10 {
		width = 10
	}
	wrap := lipgloss.NewStyle().Width(width)
	var b strings.Builder

	b.WriteString(severityStyle(g.severity).Render(strings.ToUpper(g.severity.String())))
	b.WriteString(ui.Subtle.Render("  " + g.axis.Title()))
	b.WriteString("\n\n")
	b.WriteString(ui.Title.Render(wrap.Render(g.title)))
	b.WriteString("\n")
	b.WriteString(ui.Subtle.Render(g.checkID))
	b.WriteString("\n\n")

	rep := g.findings[0] // representative; description/remediation are shared per check
	if rep.Description != "" {
		b.WriteString(wrap.Render(rep.Description))
		b.WriteString("\n\n")
	}

	b.WriteString(ui.Label.Render(fmt.Sprintf("Affected (%d)", len(g.findings))))
	b.WriteString(ui.Subtle.Render("  press ↵ to expand"))
	b.WriteString("\n")
	for _, f := range g.findings {
		name := f.Resource.Name
		if name == "" {
			name = f.Title
		}
		b.WriteString("  • " + ui.Accent.Render(name) + "\n")
	}
	b.WriteString("\n")

	if rep.Remediation != "" {
		b.WriteString(ui.Label.Render("Fix"))
		b.WriteString("\n")
		b.WriteString(wrap.Render(rep.Remediation))
		b.WriteString("\n")
	}
	if rep.GHFix != "" {
		b.WriteString("\n")
		b.WriteString(ui.Label.Render("Suggested gh command"))
		b.WriteString(ui.Subtle.Render(" (per resource; expand for each)"))
		b.WriteString("\n")
		b.WriteString(ui.Accent.Render(rep.GHFix))
		b.WriteString("\n")
		if rep.GHVerify != "" {
			b.WriteString(ui.Subtle.Render("verify: "))
			b.WriteString(ui.Accent.Render(rep.GHVerify))
			b.WriteString("\n")
		}
	}
	return b.String()
}
