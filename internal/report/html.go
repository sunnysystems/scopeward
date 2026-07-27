package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/score"
)

//go:embed assets/report.html.tmpl
var htmlTemplateSrc string

var htmlTemplate = template.Must(template.New("report").Parse(htmlTemplateSrc))

type htmlView struct {
	OrgLogin         string
	OrgDisplay       string
	GeneratedAt      string
	Score            score.Score
	GradeColor       string
	Dashboard        dashboardView
	FindingCount     int
	AxisCount        int
	CheckCount       int
	Severities       []sevCount
	Axes             []axisGroup
	TeamDesign       *teamDesignView
	NotEvaluated     []nevalView
	AcceptedRisks    []acceptedRiskView
	SuppressionDelta string // "3 suppressed · score without them: 61 C (currently 72 C)"
	ArchiveLever     *archiveLeverView
	Coverage         []covView
	CoverageSummary  string   // compact tally for the collapsed coverage header
	Suggestions      []string // autocomplete entries for the findings search box
}

type teamDesignView struct {
	Tier       string
	Expected   string
	Teams      int
	Depth      int
	Structure  []string // human lines like "3 teams grant no repository access"
	OwningTeam string   // "32/40 (80%)"
	CodeOwner  string
	Property   string // pct, or "not adopted"
	Gaps       []string
}

type sevCount struct {
	Key   string
	Count int
}

type axisGroup struct {
	Title  string
	Groups []problemGroup
}

// problemGroup collapses every finding from one check into a single card: the
// shared description/remediation/docs are shown once, and the affected resources
// are listed beneath. This keeps a report readable when one check fires across
// hundreds of repositories.
type problemGroup struct {
	Severity      string // label of the most urgent finding in the group
	SeverityClass string
	sevRank       int  // numeric severity for ordering (not rendered)
	Mixed         bool // findings span more than one severity → show per-row chips
	Label         string
	Count         int
	CountLabel    string // e.g. "376 repos", "1 user"
	Open          bool   // expanded by default for small groups
	Description   string // shared across the group
	Remediation   string // shared across the group
	DocsURL       string // shared across the group
	CheckID       string
	Search        string // lowercased label/check/axis/category, for client-side filtering
	Items         []problemItem
}

type problemItem struct {
	Severity      string
	SeverityClass string
	ShowChip      bool // group spans multiple severities → label this row's own
	Title         string
	ResourceURL   string
	AsideName     string // resource name, shown only when not already in the title
	Search        string // lowercased title/resource, for client-side filtering
	Evidence      string
	GHFix         string
	GHVerify      string
}

type nevalView struct {
	Title   string
	CheckID string
	Missing string
}

// archiveLeverView is the aggregate return on archiving dead repositories, shown
// above the findings so the largest available move is not buried under the highs
// it would resolve.
type archiveLeverView struct {
	Summary string
	Caution string
}

// acceptedRiskView is one finding the ignore config suppressed, shown with the
// reason the rule gave. Rendered so a reader can audit the acceptances, not just
// learn that some exist.
type acceptedRiskView struct {
	Title   string
	CheckID string
	Reason  string
}

type covView struct {
	Kind   string
	Mark   string
	Class  string
	Reason string
}

// HTML renders the audit as a self-contained HTML page (inline CSS, no external
// assets, no JavaScript required) suitable for opening directly in a browser.
func HTML(w io.Writer, a Audit) error {
	return htmlTemplate.Execute(w, buildHTMLView(a))
}

func buildHTMLView(a Audit) htmlView {
	org := a.Snapshot.Org
	display := org.Login
	if org.Name != "" {
		display = org.Name + " (" + org.Login + ")"
	}

	v := htmlView{
		OrgLogin:     org.Login,
		OrgDisplay:   display,
		GeneratedAt:  a.Snapshot.CollectedAt.Format("2006-01-02 15:04 MST"),
		Score:        a.Score,
		GradeColor:   gradeColor(a.Score.Grade),
		Dashboard:    buildDashboard(a),
		FindingCount: len(a.Report.Findings),
		CheckCount:   len(a.Report.Findings) + len(a.Report.Skipped),
		Severities:   severityTally(a.Score),
		Axes:         groupByAxis(a.Report.Findings),
		TeamDesign:   teamDesignHTML(summarizeTeamDesign(a.Snapshot)),
		NotEvaluated: nevalViews(a.Report.Skipped),
		Coverage:     covViews(a.Snapshot.Coverage),
	}
	v.AxisCount = len(v.Axes)
	v.CoverageSummary = coverageSummary(v.Coverage)
	v.Suggestions = filterSuggestions(a.Report.Findings)
	v.AcceptedRisks, v.SuppressionDelta = acceptedRiskViews(a)
	if l := buildArchiveLever(a); l != nil {
		v.ArchiveLever = &archiveLeverView{Summary: l.summary(), Caution: l.caution()}
	}
	return v
}

// acceptedRiskViews renders the ignore config's suppressions and, when they moved
// the number, what the score would be without them.
func acceptedRiskViews(a Audit) ([]acceptedRiskView, string) {
	if len(a.Suppressed) == 0 {
		return nil, ""
	}
	out := make([]acceptedRiskView, 0, len(a.Suppressed))
	for _, s := range a.Suppressed {
		out = append(out, acceptedRiskView{
			Title:   s.Finding.Title,
			CheckID: s.Finding.CheckID,
			Reason:  s.Reason,
		})
	}
	delta := ""
	if u := a.UnsuppressedScore; u.Value != a.Score.Value {
		delta = fmt.Sprintf("%s · score without them: %d %s (currently %d %s)",
			plural(len(a.Suppressed), "suppressed finding"), u.Value, u.Grade, a.Score.Value, a.Score.Grade)
	}
	return out, delta
}

// filterSuggestions collects the distinct terms worth offering as search
// autocomplete: affected resource names, problem labels, governance areas, and
// action categories. Returned sorted for a stable, scannable datalist.
func filterSuggestions(findings []model.Finding) []string {
	set := map[string]bool{}
	for _, f := range findings {
		if f.Resource.Name != "" {
			set[f.Resource.Name] = true
		}
		set[f.Axis.Title()] = true
		set[categoryOf(f.CheckID)] = true
		if meta, ok := check.Meta(f.CheckID); ok && meta.Title != "" {
			set[meta.Title] = true
		} else {
			set[f.Title] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// coverageSummary tallies coverage by status into a compact line (e.g.
// "8 ok · 1 partial · 3 missing") shown when the section is collapsed.
func coverageSummary(views []covView) string {
	var ok, partial, missing int
	for _, c := range views {
		switch c.Class {
		case "partial":
			partial++
		case "missing":
			missing++
		default:
			ok++
		}
	}
	var parts []string
	for _, p := range []struct {
		n     int
		label string
	}{{ok, "ok"}, {partial, "partial"}, {missing, "missing"}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.label))
		}
	}
	return strings.Join(parts, " · ")
}

// teamDesignHTML adapts the portrait to a template-friendly view, or nil.
func teamDesignHTML(td *teamDesign) *teamDesignView {
	if td == nil {
		return nil
	}
	v := &teamDesignView{
		Tier: td.tierName, Expected: td.tierModel, Teams: td.teams, Depth: td.maxDepth,
		OwningTeam: pct(td.reposOwnedByTeam, td.reposTotal),
		CodeOwner:  pct(td.codeownersTeam, td.reposTotal),
		Gaps:       td.gaps,
	}
	for _, r := range []struct {
		n     int
		label string
	}{
		{td.ghost, "grant no repository access"},
		{td.orphan, "have no maintainer"},
		{td.empty, "are empty"},
		{td.singleton, "have a single member"},
	} {
		if r.n > 0 {
			v.Structure = append(v.Structure, plural(r.n, "team")+" "+r.label)
		}
	}
	if td.propertyAdopted {
		v.Property = pct(td.propertyTagged, td.reposTotal)
	} else {
		v.Property = "not adopted"
	}
	return v
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func gradeColor(grade string) string {
	switch grade {
	case "A", "B":
		return "#3FB950"
	case "C", "D":
		return "#FFB61F"
	default:
		return "#F85149"
	}
}

func severityTally(s score.Score) []sevCount {
	order := []model.Severity{model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevInfo}
	var out []sevCount
	for _, sev := range order {
		if n := s.BySeverity[sev]; n > 0 {
			out = append(out, sevCount{Key: sev.String(), Count: n})
		}
	}
	return out
}

// groupByAxis buckets findings by axis, then collapses each axis's findings into
// one problemGroup per check. Groups are ordered most-urgent first, then by how
// widespread they are, so the worst, most pervasive problems lead each section.
func groupByAxis(findings []model.Finding) []axisGroup {
	byAxisCheck := map[model.Axis]map[string][]model.Finding{}
	checkOrder := map[model.Axis][]string{}
	for _, f := range findings {
		if byAxisCheck[f.Axis] == nil {
			byAxisCheck[f.Axis] = map[string][]model.Finding{}
		}
		if _, seen := byAxisCheck[f.Axis][f.CheckID]; !seen {
			checkOrder[f.Axis] = append(checkOrder[f.Axis], f.CheckID)
		}
		byAxisCheck[f.Axis][f.CheckID] = append(byAxisCheck[f.Axis][f.CheckID], f)
	}

	var out []axisGroup
	for _, axis := range axisOrder {
		checks := byAxisCheck[axis]
		if len(checks) == 0 {
			continue
		}
		groups := make([]problemGroup, 0, len(checks))
		for _, cid := range checkOrder[axis] {
			groups = append(groups, toProblemGroup(checks[cid]))
		}
		sort.SliceStable(groups, func(i, j int) bool {
			if groups[i].sevRank != groups[j].sevRank {
				return groups[i].sevRank > groups[j].sevRank
			}
			if groups[i].Count != groups[j].Count {
				return groups[i].Count > groups[j].Count
			}
			return groups[i].Label < groups[j].Label
		})
		out = append(out, axisGroup{Title: axis.Title(), Groups: groups})
	}
	return out
}

// toProblemGroup builds one card from all findings of a single check. They share
// a description, remediation, and docs link (rendered once); per-resource detail
// lives in the item rows.
func toProblemGroup(fs []model.Finding) problemGroup {
	first := fs[0]
	maxSev := first.Severity
	mixed := false
	for _, f := range fs[1:] {
		if f.Severity != first.Severity {
			mixed = true
		}
		if f.Severity > maxSev {
			maxSev = f.Severity
		}
	}

	label := first.Title
	if meta, ok := check.Meta(first.CheckID); ok && meta.Title != "" {
		label = meta.Title
	}

	items := make([]problemItem, 0, len(fs))
	for _, f := range fs {
		aside := ""
		if f.Resource.Name != "" && !strings.Contains(f.Title, f.Resource.Name) {
			aside = f.Resource.Name
		}
		items = append(items, problemItem{
			Severity:      f.Severity.String(),
			SeverityClass: f.Severity.String(),
			ShowChip:      mixed,
			Title:         f.Title,
			ResourceURL:   f.Resource.URL,
			AsideName:     aside,
			Search:        strings.ToLower(f.Title + " " + aside),
			Evidence:      evidenceJSON(f.Evidence),
			GHFix:         f.GHFix,
			GHVerify:      f.GHVerify,
		})
	}

	return problemGroup{
		Severity:      maxSev.String(),
		SeverityClass: maxSev.String(),
		sevRank:       int(maxSev),
		Mixed:         mixed,
		Label:         label,
		Count:         len(fs),
		CountLabel:    countLabel(fs),
		Open:          len(fs) <= 3,
		Description:   first.Description,
		Remediation:   first.Remediation,
		DocsURL:       first.DocsURL,
		CheckID:       first.CheckID,
		Search:        strings.ToLower(label + " " + first.CheckID + " " + first.Axis.Title() + " " + categoryOf(first.CheckID)),
		Items:         items,
	}
}

// countLabel renders the affected-resource count with a unit drawn from the
// resource type when every finding shares one (e.g. "376 repos"), else "findings".
func countLabel(fs []model.Finding) string {
	unit := fs[0].Resource.Type
	for _, f := range fs[1:] {
		if f.Resource.Type != unit {
			unit = ""
			break
		}
	}
	if unit == "" {
		unit = "finding"
	}
	if len(fs) == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", len(fs), unit)
}

func evidenceJSON(ev map[string]any) string {
	if len(ev) == 0 {
		return ""
	}
	b, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

func nevalViews(skipped []check.Skipped) []nevalView {
	out := make([]nevalView, 0, len(skipped))
	for _, s := range skipped {
		out = append(out, nevalView{Title: s.Title, CheckID: s.CheckID, Missing: joinKinds(s.Missing)})
	}
	return out
}

func covViews(cov *model.CoverageReport) []covView {
	items := cov.All()
	sort.Slice(items, func(i, j int) bool { return items[i].Kind < items[j].Kind })
	out := make([]covView, 0, len(items))
	for _, c := range items {
		mark, class := "✓", "ok"
		switch c.Status {
		case model.CoveragePartial:
			mark, class = "~", "partial"
		case model.CoverageMissing:
			mark, class = "✗", "missing"
		}
		out = append(out, covView{Kind: string(c.Kind), Mark: mark, Class: class, Reason: c.Reason})
	}
	return out
}
