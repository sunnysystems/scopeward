package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/score"
)

//go:embed assets/report.html.tmpl
var htmlTemplateSrc string

var htmlTemplate = template.Must(template.New("report").Parse(htmlTemplateSrc))

type htmlView struct {
	OrgLogin     string
	OrgDisplay   string
	GeneratedAt  string
	Score        score.Score
	GradeColor   string
	FindingCount int
	AxisCount    int
	CheckCount   int
	Severities   []sevCount
	Axes         []axisGroup
	TeamDesign   *teamDesignView
	NotEvaluated []nevalView
	Coverage     []covView
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
	Title    string
	Findings []findingView
}

type findingView struct {
	Severity      string
	SeverityClass string
	Title         string
	ResourceType  string
	ResourceName  string
	ResourceURL   string
	Description   string
	Remediation   string
	GHFix         string
	GHVerify      string
	Evidence      string
	CheckID       string
	DocsURL       string
}

type nevalView struct {
	Title   string
	CheckID string
	Missing string
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
		FindingCount: len(a.Report.Findings),
		CheckCount:   len(a.Report.Findings) + len(a.Report.Skipped),
		Severities:   severityTally(a.Score),
		Axes:         groupByAxis(a.Report.Findings),
		TeamDesign:   teamDesignHTML(summarizeTeamDesign(a.Snapshot)),
		NotEvaluated: nevalViews(a.Report.Skipped),
		Coverage:     covViews(a.Snapshot.Coverage),
	}
	v.AxisCount = len(v.Axes)
	return v
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
		return "#FFB000"
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

func groupByAxis(findings []model.Finding) []axisGroup {
	byAxis := map[model.Axis][]model.Finding{}
	for _, f := range findings {
		byAxis[f.Axis] = append(byAxis[f.Axis], f)
	}
	var groups []axisGroup
	for _, axis := range axisOrder {
		fs := byAxis[axis]
		if len(fs) == 0 {
			continue
		}
		// findings arrive globally severity-sorted; keep that order within the axis.
		views := make([]findingView, 0, len(fs))
		for _, f := range fs {
			views = append(views, toFindingView(f))
		}
		groups = append(groups, axisGroup{Title: axis.Title(), Findings: views})
	}
	return groups
}

func toFindingView(f model.Finding) findingView {
	return findingView{
		Severity:      f.Severity.String(),
		SeverityClass: f.Severity.String(),
		Title:         f.Title,
		ResourceType:  f.Resource.Type,
		ResourceName:  f.Resource.Name,
		ResourceURL:   f.Resource.URL,
		Description:   f.Description,
		Remediation:   f.Remediation,
		GHFix:         f.GHFix,
		GHVerify:      f.GHVerify,
		Evidence:      evidenceJSON(f.Evidence),
		CheckID:       f.CheckID,
		DocsURL:       f.DocsURL,
	}
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
