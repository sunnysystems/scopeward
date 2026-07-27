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
	renderArchiveLever(out, a)
	renderFindings(out, a)
	if td := summarizeTeamDesign(a.Snapshot); td != nil {
		renderTeamDesignText(out, td)
	}
	renderNotEvaluated(out, a.Report.Skipped)
	renderAcceptedRisks(out, a)
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

// renderArchiveLever surfaces the aggregate return on archiving dead repos ahead
// of the findings list, because it is usually the largest single move available
// and the findings list buries it: it appears there only as one 2-point low per
// repo, beneath every high it would resolve.
func renderArchiveLever(out io.Writer, a Audit) {
	l := buildArchiveLever(a)
	if l == nil {
		return
	}
	fmt.Fprintln(out, ui.Label.Render("Biggest lever"))
	fmt.Fprintf(out, "  %s\n", l.summary())
	fmt.Fprintf(out, "  %s\n", ui.Subtle.Render(l.caution()))
	fmt.Fprintln(out)
}

// renderAcceptedRisks lists what the ignore config suppressed, with the reason
// each rule recorded and the score the suppressions bought. A count alone told
// the reader that something was hidden but not what, why, or at what discount —
// and since the score is computed after filtering, that discount is real.
func renderAcceptedRisks(out io.Writer, a Audit) {
	if len(a.Suppressed) == 0 {
		return
	}
	fmt.Fprintln(out, ui.Label.Render("Accepted risks"))
	for _, s := range a.Suppressed {
		reason := s.Reason
		if reason == "" {
			// Not an error: an undocumented acceptance is still an acceptance. But it
			// is the one worth prompting about, since nobody will remember it later.
			reason = ui.WarnTag.Render("no reason recorded")
		}
		name := s.Finding.Resource.Name
		if name == "" {
			name = a.Snapshot.Org.Login
		}
		// Title then "resource · check-id", matching the findings list, with the
		// accepted reason on its own line so it is the thing that reads as content.
		fmt.Fprintf(out, "  %s %s\n", ui.Subtle.Render("·"), s.Finding.Title)
		fmt.Fprintf(out, "    %s\n", ui.Subtle.Render(name+" · "+s.Finding.CheckID))
		fmt.Fprintf(out, "    %s %s\n", ui.Subtle.Render("accepted:"), reason)
	}
	if u := a.UnsuppressedScore; u.Value != a.Score.Value {
		fmt.Fprintln(out, ui.Subtle.Render(fmt.Sprintf(
			"  %d suppressed · score without them: %d %s (currently %d %s)",
			len(a.Suppressed), u.Value, u.Grade, a.Score.Value, a.Score.Grade)))
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
