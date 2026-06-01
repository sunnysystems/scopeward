package cli

import (
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestFailThreshold(t *testing.T) {
	cases := []struct {
		in      string
		wantSev model.Severity
		wantOn  bool
		wantErr bool
	}{
		{"none", 0, false, false},
		{"", 0, false, false},
		{"low", model.SevLow, true, false},
		{"high", model.SevHigh, true, false},
		{"critical", model.SevCritical, true, false},
		{"bogus", 0, false, true},
	}
	for _, tc := range cases {
		sev, on, err := failThreshold(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("%q: err = %v, wantErr %v", tc.in, err, tc.wantErr)
		}
		if err != nil {
			continue
		}
		if sev != tc.wantSev || on != tc.wantOn {
			t.Errorf("%q: got (%v,%v), want (%v,%v)", tc.in, sev, on, tc.wantSev, tc.wantOn)
		}
	}
}

func TestMaxSeverity(t *testing.T) {
	if got := maxSeverity(nil); got != model.SevInfo {
		t.Errorf("empty = %v, want info", got)
	}
	findings := []model.Finding{
		{Severity: model.SevLow},
		{Severity: model.SevHigh},
		{Severity: model.SevMedium},
	}
	if got := maxSeverity(findings); got != model.SevHigh {
		t.Errorf("max = %v, want high", got)
	}
}
