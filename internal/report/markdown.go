package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sunnysystems/scopeward/internal/model"
)

// Markdown writes the audit as GitHub-flavored Markdown. The CLI may render this
// to the terminal via Glamour, or it can be saved/piped as-is.
func Markdown(w io.Writer, a Audit) {
	org := a.Snapshot.Org.Login
	if a.Snapshot.Org.Name != "" {
		org = fmt.Sprintf("%s (%s)", a.Snapshot.Org.Name, a.Snapshot.Org.Login)
	}
	fmt.Fprintf(w, "# scopeward: %s\n\n", org)
	fmt.Fprintf(w, "**Governance score: %d/100 (%s)**\n\n", a.Score.Value, a.Score.Grade)

	if tally := severityTally(a.Score); len(tally) > 0 {
		parts := make([]string, 0, len(tally))
		for _, s := range tally {
			parts = append(parts, fmt.Sprintf("%d %s", s.Count, s.Key))
		}
		fmt.Fprintf(w, "%s\n\n", joinMd(parts, " · "))
	} else {
		fmt.Fprint(w, "No findings.\n\n")
	}

	if a.HasBaseline {
		fmt.Fprintf(w, "_vs baseline: %d new · %d resolved_\n\n", len(a.NewKeys), a.ResolvedCount)
	}

	if l := buildArchiveLever(a); l != nil {
		fmt.Fprint(w, "## Biggest lever\n\n")
		fmt.Fprintf(w, "%s\n\n", l.summary())
		fmt.Fprintf(w, "_%s_\n\n", l.caution())
	}

	byAxis := map[model.Axis][]model.Finding{}
	for _, f := range a.Report.Findings {
		byAxis[f.Axis] = append(byAxis[f.Axis], f)
	}
	for _, axis := range axisOrder {
		fs := byAxis[axis]
		if len(fs) == 0 {
			continue
		}
		fmt.Fprintf(w, "## %s\n\n", axis.Title())
		for _, f := range fs {
			// POLICY marks a finding produced by a rule the org declared, as
			// opposed to a product default — the two carry different weight in a
			// review and the reader has to be able to tell them apart.
			mark := ""
			if f.Policy {
				mark = "`POLICY` "
			}
			fmt.Fprintf(w, "- **[%s]** %s%s  \n", upper(f.Severity.String()), mark, f.Title)
			meta := "`" + f.CheckID + "`"
			if f.Resource.Name != "" {
				meta = f.Resource.Name + " · " + meta
			}
			fmt.Fprintf(w, "  %s  \n", meta)
			if f.Description != "" {
				fmt.Fprintf(w, "  %s  \n", f.Description)
			}
			if f.Remediation != "" {
				fmt.Fprintf(w, "  _Fix:_ %s  \n", f.Remediation)
			}
			if f.GHFix != "" {
				// A fix may be multiple commands; a fenced block keeps them readable.
				if strings.Contains(f.GHFix, "\n") {
					fmt.Fprintf(w, "\n```sh\n%s\n```\n", f.GHFix)
				} else {
					fmt.Fprintf(w, "  `%s`\n", f.GHFix)
				}
				if f.GHVerify != "" {
					fmt.Fprintf(w, "  _Verify:_ `%s`\n", f.GHVerify)
				}
			}
		}
		fmt.Fprintln(w)
	}

	if td := summarizeTeamDesign(a.Snapshot); td != nil {
		renderTeamDesignMarkdown(w, td)
	}

	if limited := a.Report.Limited; len(limited) > 0 {
		fmt.Fprint(w, "## Partially evaluated\n\n")
		for _, l := range limited {
			fmt.Fprintf(w, "- ~ %s (`%s`): assessed %d, %d not assessed — %s\n",
				l.Title, l.CheckID, l.Assessed, l.Omitted, l.Reason)
		}
		fmt.Fprintln(w)
	}

	if skipped := a.Report.Skipped; len(skipped) > 0 {
		fmt.Fprint(w, "## Not evaluated\n\n")
		for _, s := range skipped {
			fmt.Fprintf(w, "- ~ %s (`%s`): %s\n", s.Title, s.CheckID, skipCause(s))
		}
		fmt.Fprintln(w)
	}

	if len(a.Suppressed) > 0 {
		fmt.Fprint(w, "## Accepted risks\n\n")
		for _, s := range a.Suppressed {
			reason := s.Reason
			if reason == "" {
				reason = "**no reason recorded**"
			}
			fmt.Fprintf(w, "- %s (`%s`) — %s\n", s.Finding.Title, s.Finding.CheckID, reason)
		}
		if u := a.UnsuppressedScore; u.Value != a.Score.Value {
			fmt.Fprintf(w, "\n_Score without these suppressions: %d/100 (%s)_\n", u.Value, u.Grade)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprint(w, "## Coverage\n\n")
	items := a.Snapshot.Coverage.All()
	sort.Slice(items, func(i, j int) bool { return items[i].Kind < items[j].Kind })
	for _, c := range items {
		mark := "✓"
		switch c.Status {
		case model.CoveragePartial:
			mark = "~"
		case model.CoverageMissing:
			mark = "✗"
		}
		line := fmt.Sprintf("- %s %s", mark, c.Kind)
		if c.Reason != "" {
			line += " (" + c.Reason + ")"
		}
		fmt.Fprintln(w, line)
	}
}

func upper(sev string) string {
	b := []byte(sev)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

func joinMd(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}
