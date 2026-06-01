// Package ghclient is a thin, read-only wrapper over the GitHub REST API. It
// owns concerns that every collector shares: authentication, rate-limit
// awareness, and probing what the token is actually allowed to see (so the
// audit can degrade honestly instead of reporting false negatives).
//
// It deliberately does NOT expose any write verbs.
package ghclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sunnysystems/scopeward/internal/auth"
)

const (
	defaultBaseURL = "https://api.github.com"
	apiVersion     = "2022-11-28"
	userAgent      = "scopeward (+https://github.com/sunnysystems/scopeward)"
)

// Client performs authenticated read-only calls against the GitHub API. It
// tracks the primary rate-limit budget from response headers and proactively
// pauses before exhausting it (see gate), in addition to the reactive backoff
// in do().
type Client struct {
	http    *http.Client
	baseURL string
	token   auth.Secret

	mu        sync.Mutex
	remaining int
	reset     time.Time
	rateKnown bool
	reserve   int // pause once remaining drops to this, leaving headroom
	waiting   atomic.Bool
	onWait    func(time.Duration)

	cache Cache // optional ETag cache; nil disables conditional requests
}

// Cache stores ETag-conditional responses so unchanged resources can be served
// from a 304 (which does not consume the primary rate limit). Implementations
// must be safe for concurrent use.
type Cache interface {
	Get(key string) (etag string, body []byte, link string, ok bool)
	Put(key, etag string, body []byte, link string)
}

// SetCache enables ETag-based conditional requests backed by c.
func (c *Client) SetCache(cache Cache) { c.cache = cache }

// New builds a client. The token stays wrapped in a Secret and is only exposed
// when set on the Authorization header.
func New(token auth.Secret) *Client {
	return &Client{
		http:    &http.Client{Timeout: 30 * time.Second},
		baseURL: defaultBaseURL,
		token:   token,
		reserve: 1,
	}
}

// SetOnWait registers a callback invoked once when the client begins pausing for
// a rate-limit reset (used to inform the user). The duration is the wait length.
func (c *Client) SetOnWait(fn func(time.Duration)) { c.onWait = fn }

// RateStatus returns the last-known primary rate-limit budget: how many requests
// remain, how long until the window resets, whether we have learned the budget
// yet, and whether the client is currently paused waiting for a reset.
func (c *Client) RateStatus() (remaining int, resetIn time.Duration, known, waiting bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	resetIn = time.Until(c.reset)
	if resetIn < 0 {
		resetIn = 0
	}
	return c.remaining, resetIn, c.rateKnown, c.waiting.Load()
}

// updateRate records the rate-limit budget from a response's headers.
func (c *Client) updateRate(h http.Header) {
	rem := h.Get("X-RateLimit-Remaining")
	if rem == "" {
		return
	}
	c.mu.Lock()
	c.remaining = atoi(rem)
	if r := atoi(h.Get("X-RateLimit-Reset")); r > 0 {
		c.reset = time.Unix(int64(r), 0)
	}
	c.rateKnown = true
	c.mu.Unlock()
}

// RateLimit captures the primary rate-limit state from response headers.
type RateLimit struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	ResetAt   time.Time `json:"reset_at"`
}

// TokenType is inferred from the token prefix; it drives what coverage to expect.
type TokenType string

const (
	TokenClassicPAT     TokenType = "classic_pat"        // ghp_
	TokenFineGrainedPAT TokenType = "fine_grained_pat"   // github_pat_
	TokenOAuth          TokenType = "oauth"              // gho_
	TokenAppInstall     TokenType = "app_installation"   // ghs_
	TokenUserToServer   TokenType = "app_user_to_server" // ghu_
	TokenUnknown        TokenType = "unknown"
)

// Probe is the result of validating the token: who it belongs to, what it can
// see, and how much budget is left. It carries no secret material.
type Probe struct {
	Login          string    `json:"login"`
	TokenType      TokenType `json:"token_type"`
	Scopes         []string  `json:"scopes"`          // classic PATs only; empty otherwise
	AcceptedScopes []string  `json:"accepted_scopes"` // what GitHub says this endpoint accepts
	RateLimit      RateLimit `json:"rate_limit"`
}

// ProbeToken validates the token via GET /user and reads the headers GitHub
// returns about scopes and rate limits. This is the first call the audit makes:
// it both confirms the token works and seeds the coverage report.
func (c *Client) ProbeToken(ctx context.Context) (*Probe, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/user", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("calling GitHub: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// proceed
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("token rejected by GitHub (401): check the token is valid and not expired")
	case http.StatusForbidden:
		return nil, fmt.Errorf("token forbidden (403): it may lack basic read scopes or be rate-limited")
	default:
		return nil, fmt.Errorf("unexpected status from GitHub: %s", resp.Status)
	}

	var body struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decoding GitHub response: %w", err)
	}

	return &Probe{
		Login:          body.Login,
		TokenType:      classifyToken(c.token.Expose()),
		Scopes:         splitScopes(resp.Header.Get("X-OAuth-Scopes")),
		AcceptedScopes: splitScopes(resp.Header.Get("X-Accepted-OAuth-Scopes")),
		RateLimit:      parseRateLimit(resp.Header),
	}, nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, query url.Values) (*http.Request, error) {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token.Expose())
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("User-Agent", userAgent)
	return req, nil
}

func classifyToken(raw string) TokenType {
	switch {
	case strings.HasPrefix(raw, "github_pat_"):
		return TokenFineGrainedPAT
	case strings.HasPrefix(raw, "ghp_"):
		return TokenClassicPAT
	case strings.HasPrefix(raw, "gho_"):
		return TokenOAuth
	case strings.HasPrefix(raw, "ghs_"):
		return TokenAppInstall
	case strings.HasPrefix(raw, "ghu_"):
		return TokenUserToServer
	default:
		return TokenUnknown
	}
}

func splitScopes(h string) []string {
	h = strings.TrimSpace(h)
	if h == "" {
		return nil
	}
	parts := strings.Split(h, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parseRateLimit(h http.Header) RateLimit {
	rl := RateLimit{
		Limit:     atoi(h.Get("X-RateLimit-Limit")),
		Remaining: atoi(h.Get("X-RateLimit-Remaining")),
	}
	if reset := atoi(h.Get("X-RateLimit-Reset")); reset > 0 {
		rl.ResetAt = time.Unix(int64(reset), 0)
	}
	return rl
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
