package checks

import (
	"context"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestAccountNo2FA(t *testing.T) {
	off, on := false, true
	snap := model.NewSnapshot("alice")
	snap.AccountTwoFactor = &off
	if got := (accountNo2FA{}).Run(context.Background(), snap); len(got) != 1 || got[0].Severity != model.SevHigh {
		t.Fatalf("2FA off: got %+v, want one high", got)
	}
	snap.AccountTwoFactor = &on
	if got := (accountNo2FA{}).Run(context.Background(), snap); len(got) != 0 {
		t.Errorf("2FA on: want 0, got %d", len(got))
	}
	snap.AccountTwoFactor = nil
	if got := (accountNo2FA{}).Run(context.Background(), snap); len(got) != 0 {
		t.Errorf("unknown: want 0, got %d", len(got))
	}
}
