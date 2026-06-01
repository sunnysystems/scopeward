package ghclient

import (
	"net/http"
	"testing"
	"time"
)

func TestRateLimitWait(t *testing.T) {
	now := time.Unix(1_000_000, 0)

	mk := func(status int, h map[string]string) *http.Response {
		r := &http.Response{StatusCode: status, Header: http.Header{}}
		for k, v := range h {
			r.Header.Set(k, v)
		}
		return r
	}

	cases := []struct {
		name      string
		resp      *http.Response
		wantWait  time.Duration
		wantLimit bool
	}{
		{"ok status", mk(200, nil), 0, false},
		{"plain 403 not a limit", mk(403, nil), 0, false},
		{"secondary retry-after seconds", mk(403, map[string]string{"Retry-After": "30"}), 30 * time.Second, true},
		{"429 retry-after", mk(429, map[string]string{"Retry-After": "5"}), 5 * time.Second, true},
		{"primary remaining 0", mk(403, map[string]string{
			"X-RateLimit-Remaining": "0",
			"X-RateLimit-Reset":     "1000045", // now + 45s
		}), 45 * time.Second, true},
		{"primary reset in past clamps to 0", mk(403, map[string]string{
			"X-RateLimit-Remaining": "0",
			"X-RateLimit-Reset":     "999990",
		}), 0, true},
		{"remaining>0 not a limit", mk(403, map[string]string{"X-RateLimit-Remaining": "7"}), 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wait, limited := rateLimitWait(tc.resp, now)
			if limited != tc.wantLimit || wait != tc.wantWait {
				t.Errorf("got (%v, %v), want (%v, %v)", wait, limited, tc.wantWait, tc.wantLimit)
			}
		})
	}
}
