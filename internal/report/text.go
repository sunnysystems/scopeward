package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/ui"
)

// Text renders the audit to a terminal: a branded header, the score, findings
// most-urgent first, the checks that could not be evaluated, and a coverage
// table so counts are read as "what we saw", not "what exists".
func Text(out io.Writer, a Audit) {
	renderHeader(out, a.Snapshot)
	renderScore(out, a)
	if a.HasBaseline {
		fmt.Fprintf(out, "  %s %s · %s\n\n",
			ui.Label.Render("vs baseline"),
			ui.WarnTag.Render(fmt.Sprintf("%d new", len(a.NewKeys))),
			ui.Good.Render(fmt.Sprintf("%d resolved", a.ResolvedCount)),
		)
	}
	renderFindings(out, a)
	if td := summarizeTeamDesign(a.Snapshot); td != nil {
		renderTeamDesignText(out, td)
	}
	renderNotEvaluated(out, a.Report.Skipped)
	if n := len(a.Suppressed); n > 0 {
		fmt.Fprintln(out, ui.Subtle.Render(fmt.Sprintf("%d finding(s) suppressed by ignore config.", n)))
		fmt.Fprintln(out)
	}
	renderCoverage(out, a.Snapshot.Coverage)
}

func renderHeader(out io.Writer, snap *model.Snapshot) {
	header := snap.Org.Login
	if snap.Org.Name != "" {
		header = fmt.Sprintf("%s (%s)", snap.Org.Name, snap.Org.Login)
	}
	fmt.Fprintln(out, ui.Title.Render("scopeward")+ui.Subtle.Render(" · audit · ")+ui.Accent.Render(header))
	fmt.Fprintln(out)
}

func renderScore(out io.Writer, a Audit) {
	sc := a.Score
	gradeStyle := ui.Good
	switch sc.Grade {
	case "C", "D":
		gradeStyle = ui.WarnTag
	case "F":
		gradeStyle = ui.Bad
	}
	fmt.Fprintf(out, "  %s  %s  %s\n",
		ui.Label.Render("Governance score"),
		gradeStyle.Render(fmt.Sprintf("%d/100", sc.Value)),
		gradeStyle.Render("("+sc.Grade+")"),
	)

	// Severity tally, most urgent first, omitting empties.
	order := []model.Severity{model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevInfo}
	parts := make([]string, 0, len(order))
	for _, sev := range order {
		if n := sc.BySeverity[sev]; n > 0 {
			parts = append(parts, severityStyle(sev).Render(fmt.Sprintf("%d %s", n, sev)))
		}
	}
	if len(parts) == 0 {
		fmt.Fprintln(out, "  "+ui.Good.Render("No findings."))
	} else {
		fmt.Fprint(out, "  ")
		for i, p := range parts {
			if i > 0 {
				fmt.Fprint(out, ui.Subtle.Render("  ·  "))
			}
			fmt.Fprint(out, p)
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintln(out)
}

// axisOrder fixes the section order, matching the HTML report.
var axisOrder = []model.Axis{model.AxisIdentity, model.AxisTeams, model.AxisCodeSecurity, model.AxisSupplyChain, model.AxisNonHuman, model.AxisAIAgents, model.AxisHygiene}

func renderFindings(out io.Writer, a Audit) {
	findings := a.Report.Findings
	if len(findings) == 0 {
		return
	}
	byAxis := map[model.Axis][]model.Finding{}
	for _, f := range findings {
		byAxis[f.Axis] = append(byAxis[f.Axis], f)
	}

	for _, axis := range axisOrder {
		group := byAxis[axis]
		if len(group) == 0 {
			continue
		}
		fmt.Fprintln(out, ui.Label.Render(axis.Title()))
		for _, f := range group {
			chip := severityStyle(f.Severity).Render(fmt.Sprintf("%-8s", f.Severity.String()))
			title := f.Title
			if a.IsNew(f) {
				title = ui.WarnTag.Render("NEW ") + title
			}
			fmt.Fprintf(out, "  %s %s\n", chip, title)
			meta := f.Resource.Name
			if meta != "" {
				meta += ui.Subtle.Render(" · ")
			}
			fmt.Fprintf(out, "  %s\n", ui.Subtle.Render("         "+meta+f.CheckID))
		}
		fmt.Fprintln(out)
	}
}

func renderNotEvaluated(out io.Writer, skipped []check.Skipped) {
	if len(skipped) == 0 {
		return
	}
	fmt.Fprintln(out, ui.Label.Render("Not evaluated"))
	for _, s := range skipped {
		fmt.Fprintf(out, "  %s %s %s\n",
			ui.WarnTag.Render("~"),
			s.Title,
			ui.Subtle.Render(fmt.Sprintf("· %s · needs %s", s.CheckID, joinKinds(s.Missing))),
		)
	}
	fmt.Fprintln(out)
}

func renderCoverage(out io.Writer, cov *model.CoverageReport) {
	items := cov.All()
	sort.Slice(items, func(i, j int) bool { return items[i].Kind < items[j].Kind })

	fmt.Fprintln(out, ui.Label.Render("Coverage"))
	for _, c := range items {
		var mark string
		switch c.Status {
		case model.CoverageOK:
			mark = ui.Good.Render("✓")
		case model.CoveragePartial:
			mark = ui.WarnTag.Render("~")
		default:
			mark = ui.Bad.Render("✗")
		}
		detail := ""
		if c.Reason != "" {
			detail = ui.Subtle.Render(" (" + c.Reason + ")")
		}
		fmt.Fprintf(out, "  %s %s%s\n", mark, string(c.Kind), detail)
	}
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

func joinKinds(kinds []model.DataKind) string {
	parts := make([]string, len(kinds))
	for i, k := range kinds {
		parts[i] = string(k)
	}
	return strings.Join(parts, ", ")
}
