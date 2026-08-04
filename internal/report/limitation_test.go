package report

import (
	"io"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

// TestLimitationReachesEveryHumanFormat is the point of the whole mechanism: a
// check that ran over part of its scope has to say so wherever a person reads
// the report. If any format drops it, that reader sees an empty findings list
// for resources nothing assessed and takes it for a pass (#50).
func TestLimitationReachesEveryHumanFormat(t *testing.T) {
	a := sampleAudit()

	for _, r := range allRenderers {
		if !r.human {
			continue
		}
		out := renderTo(r.render, a)
		for _, want := range []string{
			"Partially evaluated",
			"Repos without push protection",
			"Secret Protection", // the reason, so the reader knows why
			"39",                // the size of the gap, so they can judge it
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: missing %q", r.name, want)
			}
		}
	}
}

// TestNoLimitationRendersNothingExtra: the section must not appear for an audit
// that assessed everything, or every clean report grows a confusing empty
// heading.
func TestNoLimitationRendersNothingExtra(t *testing.T) {
	a := sampleAudit()
	a.Report.Limited = nil

	for _, r := range allRenderers {
		if strings.Contains(renderTo(r.render, a), "Partially evaluated") ||
			strings.Contains(renderTo(r.render, a), "partially_evaluated") {
			t.Errorf("%s: renders the section with nothing to report", r.name)
		}
	}
}

// TestSkipReasonPreferredOverDataKinds: when a check was skipped for a reason
// that is not missing data, the reader must get that reason. Naming the
// DataKinds instead ("needs repos.security_analysis") describes the mechanism
// and hides the only thing that matters — that the fix is a purchase.
func TestSkipReasonPreferredOverDataKinds(t *testing.T) {
	a := sampleAudit()
	a.Report.Limited = nil
	a.Report.Skipped = []check.Skipped{{
		CheckID: "codesecurity.repo-no-push-protection",
		Title:   "Repos without push protection",
		Axis:    model.AxisCodeSecurity,
		Reason:  "every repository is private and this org has no GitHub Secret Protection",
	}}

	for _, r := range allRenderers {
		if !r.human {
			continue
		}
		out := renderTo(r.render, a)
		if !strings.Contains(out, "no GitHub Secret Protection") {
			t.Errorf("%s: the skip reason is not shown", r.name)
		}
		if strings.Contains(out, "needs \n") || strings.Contains(out, "needs <") {
			t.Errorf("%s: rendered an empty DataKind list instead of the reason", r.name)
		}
	}
}

// TestEntitlementsAreMachineReadable: an entitlement decides which findings
// exist, so a run has to disclose what it concluded. Without it, a report with
// fewer findings is indistinguishable from an org that improved.
func TestEntitlementsAreMachineReadable(t *testing.T) {
	a := sampleAudit()
	a.Snapshot.SetEntitlement(model.EntitlementStatus{
		Entitlement: model.EntSecretProtection,
		State:       model.EntitlementAbsent,
		Reason:      "no seats provisioned",
	})

	out := renderTo(func(w io.Writer, a Audit) { JSON(w, a) }, a)
	for _, want := range []string{`"secret_protection"`, `"absent"`, "no seats provisioned"} {
		if !strings.Contains(out, want) {
			t.Errorf("json is missing %q", want)
		}
	}
}
