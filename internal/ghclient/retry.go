package ghclient

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	maxRetries = 4
	maxWait    = 60 * time.Second
)

// do executes a request, transparently waiting out GitHub rate limits (both the
// primary X-RateLimit budget and the secondary Retry-After throttle) up to a
// bounded number of attempts. It never retries ordinary errors — only genuine
// rate-limit signals — so a real 403 (permission denied) is returned as-is.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		if err := c.gate(req.Context()); err != nil {
			return nil, err
		}

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		c.updateRate(resp.Header)

		wait, limited := rateLimitWait(resp, time.Now())
		if !limited || attempt >= maxRetries || wait > maxWait {
			return resp, nil
		}

		// Discard and close the throttled response before retrying.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if wait < time.Second {
			wait = time.Second
		}
		select {
		case <-time.After(wait):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}

		// Rewind the body for the retry (GETs have none; GraphQL sets GetBody).
		if req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			req.Body = body
		}
	}
}

// gate proactively pauses before the primary rate-limit budget is exhausted:
// once remaining drops to the reserve, it waits until the window resets rather
// than firing requests that would 403. Concurrent callers all wait out the same
// window; only the first notifies via onWait. After waking, the budget is marked
// unknown so it is relearned from the next response.
func (c *Client) gate(ctx context.Context) error {
	c.mu.Lock()
	known, remaining, reset := c.rateKnown, c.remaining, c.reset
	c.mu.Unlock()

	if !known || remaining > c.reserve {
		return nil
	}

	wait := time.Until(reset) + time.Second
	if wait <= 0 {
		c.mu.Lock()
		c.rateKnown = false
		c.mu.Unlock()
		return nil
	}

	first := c.waiting.CompareAndSwap(false, true)
	if first && c.onWait != nil {
		c.onWait(wait)
	}

	defer func() {
		if first {
			c.mu.Lock()
			c.rateKnown = false // relearn from the next response after reset
			c.mu.Unlock()
			c.waiting.Store(false)
		}
	}()

	select {
	case <-time.After(wait):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// rateLimitWait reports how long to wait before retrying, and whether the
// response indicates a rate limit at all. It recognizes the secondary-limit
// Retry-After header (seconds or HTTP date) and the primary-limit pairing of
// X-RateLimit-Remaining: 0 with X-RateLimit-Reset.
func rateLimitWait(resp *http.Response, now time.Time) (time.Duration, bool) {
	if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusForbidden {
		return 0, false
	}

	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil {
			return time.Duration(secs) * time.Second, true
		}
		if t, err := http.ParseTime(ra); err == nil {
			return clampNonNegative(t.Sub(now)), true
		}
	}

	if resp.Header.Get("X-RateLimit-Remaining") == "0" {
		if reset := atoi(resp.Header.Get("X-RateLimit-Reset")); reset > 0 {
			return clampNonNegative(time.Unix(int64(reset), 0).Sub(now)), true
		}
	}

	return 0, false
}

func clampNonNegative(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	return d
}
