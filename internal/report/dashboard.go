package report

import (
	"fmt"
	"sort"

	"github.com/sunnysystems/scopeward/internal/model"
)

// dashboardView is the at-a-glance summary rendered above the findings: headline
// stats, a severity distribution bar, and two breakdowns (by governance area and
// by action category).
type dashboardView struct {
	Total         int
	Critical      int
	High          int
	AffectedRepos int
	Categories    int // distinct action categories with at least one finding
	SevBar        []barSeg
	SevLegend     []barSeg
	ByArea        []breakdownRow
	ByCategory    []breakdownRow
}

// barSeg is one severity slice of a stacked bar.
type barSeg struct {
	Key       string // severity name, used as a CSS class
	Count     int
	Width     string // CSS width, e.g. "42.5%"
	ShowLabel bool   // wide enough to print the count inside the segment
}

// breakdownRow is one labelled bar: an outer width sized against the largest row,
// filled with per-severity segments sized within the row's own total.
type breakdownRow struct {
	Label    string
	Count    int
	BarWidth string // outer width relative to the largest row in the group
	Segs     []barSeg
}

var sevOrder = []model.Severity{model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevInfo}

func buildDashboard(a Audit) dashboardView {
	findings := a.Report.Findings

	total := map[model.Severity]int{}
	repos := map[string]bool{}
	byAxis := map[model.Axis]map[model.Severity]int{}
	byCat := map[string]map[model.Severity]int{}

	for _, f := range findings {
		total[f.Severity]++
		if f.Resource.Type == "repo" && f.Resource.Name != "" {
			repos[f.Resource.Name] = true
		}
		if byAxis[f.Axis] == nil {
			byAxis[f.Axis] = map[model.Severity]int{}
		}
		byAxis[f.Axis][f.Severity]++
		cat := categoryOf(f.CheckID)
		if byCat[cat] == nil {
			byCat[cat] = map[model.Severity]int{}
		}
		byCat[cat][f.Severity]++
	}

	d := dashboardView{
		Total:         len(findings),
		Critical:      total[model.SevCritical],
		High:          total[model.SevHigh],
		AffectedRepos: len(repos),
		Categories:    len(byCat),
		SevBar:        sevSegments(total, len(findings)),
		SevLegend:     sevSegments(total, len(findings)), // same data; rendered as chips
	}

	// By governance area: one row per axis with findings, in the fixed axis order
	// then re-sorted by count so the most-affected area leads.
	areaRows := make([]breakdownRow, 0, len(byAxis))
	for _, axis := range axisOrder {
		counts, ok := byAxis[axis]
		if !ok {
			continue
		}
		areaRows = append(areaRows, breakdownRow{Label: axis.Title(), Count: sum(counts), Segs: sevSegments(counts, sum(counts))})
	}
	d.ByArea = rankRows(areaRows)

	catRows := make([]breakdownRow, 0, len(byCat))
	for cat, counts := range byCat {
		catRows = append(catRows, breakdownRow{Label: cat, Count: sum(counts), Segs: sevSegments(counts, sum(counts))})
	}
	d.ByCategory = rankRows(catRows)

	return d
}

// sevSegments turns per-severity counts into stacked-bar segments in urgency
// order. Widths are percentages of total; segments are labelled when wide enough
// to fit the count.
func sevSegments(counts map[model.Severity]int, total int) []barSeg {
	var segs []barSeg
	for _, s := range sevOrder {
		n := counts[s]
		if n == 0 {
			continue
		}
		pct := 0.0
		if total > 0 {
			pct = float64(n) / float64(total) * 100
		}
		segs = append(segs, barSeg{
			Key:       s.String(),
			Count:     n,
			Width:     fmt.Sprintf("%.3f%%", pct),
			ShowLabel: pct >= 6,
		})
	}
	return segs
}

// rankRows sorts rows most-affected first and sets each outer bar width relative
// to the largest row, so bar length reads as magnitude at a glance.
func rankRows(rows []breakdownRow) []breakdownRow {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Label < rows[j].Label
	})
	max := 0
	for _, r := range rows {
		if r.Count > max {
			max = r.Count
		}
	}
	for i := range rows {
		pct := 100.0
		if max > 0 {
			pct = float64(rows[i].Count) / float64(max) * 100
		}
		rows[i].BarWidth = fmt.Sprintf("%.3f%%", pct)
	}
	return rows
}

func sum(counts map[model.Severity]int) int {
	n := 0
	for _, c := range counts {
		n += c
	}
	return n
}
