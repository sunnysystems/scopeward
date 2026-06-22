package glclient

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/sunnysystems/scopeward/internal/auth"
)

func headerWith(remaining int, resetUnix int64) http.Header {
	h := http.Header{}
	h.Set("RateLimit-Remaining", strconv.Itoa(remaining))
	h.Set("RateLimit-Reset", strconv.FormatInt(resetUnix, 10))
	return h
}

func TestUpdateRateAndStatus(t *testing.T) {
	c := New(auth.NewSecret("glpat-x"))
	if _, _, known, _ := c.RateStatus(); known {
		t.Error("fresh client should not know the rate budget yet")
	}

	future := time.Now().Add(30 * time.Minute).Unix()
	c.updateRate(headerWith(42, future))

	rem, resetIn, known, waiting := c.RateStatus()
	if !known || rem != 42 || waiting || resetIn <= 0 {
		t.Errorf("status = (%d, %v, known=%v, waiting=%v), want 42 remaining, known, not waiting, positive resetIn", rem, resetIn, known, waiting)
	}
}

func TestUpdateRateIgnoresMissingHeaders(t *testing.T) {
	// Self-managed GitLab often sends no RateLimit-* headers; the budget must
	// stay unknown so gating is a no-op rather than blocking forever.
	c := New(auth.NewSecret("glpat-x"))
	c.updateRate(http.Header{})
	if _, _, known, _ := c.RateStatus(); known {
		t.Error("budget should stay unknown when no RateLimit headers are present")
	}
}

func TestGateProceedsWhenBudgetHealthy(t *testing.T) {
	c := New(auth.NewSecret("glpat-x"))
	c.updateRate(headerWith(4000, time.Now().Add(time.Hour).Unix()))

	done := make(chan error, 1)
	go func() { done <- c.gate(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("gate returned %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Error("gate blocked despite a healthy budget")
	}
}

func TestGateWaitsWhenExhaustedAndRespectsContext(t *testing.T) {
	c := New(auth.NewSecret("glpat-x"))
	// Budget exhausted, reset far in the future → gate must block...
	c.updateRate(headerWith(0, time.Now().Add(time.Hour).Unix()))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // ...but a cancelled context unblocks it promptly.

	if err := c.gate(ctx); err != context.Canceled {
		t.Errorf("gate err = %v, want context.Canceled", err)
	}
}
