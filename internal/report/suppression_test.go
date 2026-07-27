package report

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/score"
)

// suppressedAudit is sampleAudit with two findings moved behind ignore rules:
// one documented, one not.
func suppressedAudit() Audit {
	a := sampleAudit()
	a.Suppressed = []Suppression{
		{
			Finding: model.Finding{
				CheckID: "nonhuman.app-dangerous-permissions", Title: "acme-monitoring holds write permissions",
				Severity: model.SevMedium, Axis: model.AxisNonHuman,
				Resource: model.ResourceRef{Type: "app", Name: "acme-monitoring"},
			},
			Reason: "active monitoring integration, reviewed 2026-07",
		},
		{
			Finding: model.Finding{
				CheckID: "human.outside-collaborator", Title: "dana is an outside collaborator",
				Severity: model.SevMedium, Axis: model.AxisIdentity,
				Resource: model.ResourceRef{Type: "member", Name: "dana"},
			},
			// No reason: the case the report has to make visible rather than hide.
		},
	}
	all := append(append([]model.Finding{}, a.Report.Findings...),
		a.Suppressed[0].Finding, a.Suppressed[1].Finding)
	a.UnsuppressedScore = score.Grade(all)
	return a
}

// TestSuppressionReasonReachesEveryOutput pins issue #35: the reason was parsed
// and thrown away, so a suppression that moved the score carried no visible
// justification. Every renderer must now show both the reason and the fact that
// a rule recorded none.
func TestSuppressionReasonReachesEveryOutput(t *testing.T) {
	a := suppressedAudit()

	for _, r := range allRenderers {
		t.Run(r.name, func(t *testing.T) {
			out := renderTo(r.render, a)
			if !strings.Contains(out, "active monitoring integration, reviewed 2026-07") {
				t.Error("the documented reason does not appear in the output")
			}
			if !strings.Contains(out, "acme-monitoring") {
				t.Error("the suppressed finding's resource does not appear in the output")
			}
		})
	}

	// The human-facing renderers must also flag the undocumented one, since that is
	// the suppression a reader should question.
	for _, r := range allRenderers {
		if !r.human {
			continue
		}
		if !strings.Contains(renderTo(r.render, a), "no reason recorded") {
			t.Errorf("%s: a rule with no reason is not flagged", r.name)
		}
	}
}

// allRenderers is every output format an audit can take. human marks the ones a
// person reads, which are the ones that must call out a missing reason.
var allRenderers = []struct {
	name   string
	human  bool
	render func(io.Writer, Audit)
}{
	{"text", true, Text},
	{"markdown", true, func(w io.Writer, a Audit) { Markdown(w, a) }},
	{"html", true, func(w io.Writer, a Audit) { HTML(w, a) }},
	{"json", false, func(w io.Writer, a Audit) { JSON(w, a) }},
	{"sarif", false, func(w io.Writer, a Audit) { SARIF(w, a) }},
}

func renderTo(f func(io.Writer, Audit), a Audit) string {
	var buf bytes.Buffer
	f(&buf, a)
	return buf.String()
}

// The score delta a suppression buys must be machine-readable, so CI can audit
// the acceptances rather than only the number they produced.
func TestSuppressionScoreDeltaInJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, suppressedAudit()); err != nil {
		t.Fatal(err)
	}
	// Decoded into minimal shapes: score.Score marshals its severity map keys as
	// names, which have no matching unmarshaler.
	var got struct {
		Score struct {
			Value int `json:"value"`
		} `json:"score"`
		UnsuppressedScore *struct {
			Value int `json:"value"`
		} `json:"unsuppressed_score"`
		Suppressed []struct {
			Finding struct {
				CheckID string `json:"check_id"`
			} `json:"finding"`
			Reason string `json:"reason"`
		} `json:"suppressed"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.UnsuppressedScore == nil {
		t.Fatal("unsuppressed_score is absent while findings were suppressed")
	}
	if got.UnsuppressedScore.Value >= got.Score.Value {
		t.Errorf("unsuppressed score %d should be below the filtered score %d",
			got.UnsuppressedScore.Value, got.Score.Value)
	}
	if len(got.Suppressed) != 2 || got.Suppressed[0].Reason == "" {
		t.Errorf("suppressed entries lost their reason: %+v", got.Suppressed)
	}
}

// SARIF has a native suppressions object; a dashboard should see an accepted risk
// with its justification rather than nothing at all.
func TestSuppressionsUseNativeSARIFShape(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, suppressedAudit()); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID       string `json:"ruleId"`
				Suppressions []struct {
					Kind          string `json:"kind"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	results := log.Runs[0].Results
	var suppressed, plain int
	for _, r := range results {
		if len(r.Suppressions) > 0 {
			suppressed++
			if r.Suppressions[0].Kind != "external" {
				t.Errorf("%s: kind = %q, want external (the rule lives in .scopeward.yml)", r.RuleID, r.Suppressions[0].Kind)
			}
		} else {
			plain++
		}
	}
	if suppressed != 2 {
		t.Errorf("suppressed results = %d, want 2", suppressed)
	}
	if plain != len(sampleAudit().Report.Findings) {
		t.Errorf("unsuppressed results = %d, want %d", plain, len(sampleAudit().Report.Findings))
	}
}

// No ignore config means no accepted-risks section and no second score, so the
// common case stays exactly as it was.
func TestNoSuppressionsRendersNothingExtra(t *testing.T) {
	a := sampleAudit()
	for _, r := range allRenderers {
		if !r.human {
			continue
		}
		if strings.Contains(renderTo(r.render, a), "Accepted risks") {
			t.Errorf("%s: accepted-risks section rendered with nothing suppressed", r.name)
		}
	}
	if out := renderTo(allRenderers[3].render, a); strings.Contains(out, "unsuppressed_score") {
		t.Error("json: unsuppressed_score emitted with nothing suppressed")
	}
}
