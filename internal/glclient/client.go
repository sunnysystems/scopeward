// Package glclient is a thin, read-only wrapper over the GitLab REST and GraphQL
// APIs. It mirrors ghclient's contract — authentication, rate-limit awareness,
// conditional ETag caching, and token probing — so a GitLab collector uses it
// the same way a GitHub collector uses ghclient.
//
// Like ghclient, it deliberately exposes no write verbs. GitLab differs from
// GitHub in a few transport details handled here: the /api/v4 REST prefix, the
// /api/graphql endpoint, PRIVATE-TOKEN vs Bearer auth headers, and RateLimit-*
// response headers (no X- prefix).
package glclient

import (
	"context"
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
	defaultBaseURL = "https://gitlab.com"
	apiV4          = "/api/v4"
	graphQLPath    = "/api/graphql"
	userAgent      = "scopeward (+https://github.com/sunnysystems/scopeward)"
)

// Client performs authenticated read-only calls against a GitLab instance. It
// tracks the rate-limit budget from response headers and proactively pauses
// before exhausting it (see gate), in addition to the reactive backoff in do().
type Client struct {
	http    *http.Client
	baseURL string // instance root, e.g. https://gitlab.com (no /api/v4)
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
// from a 304. Implementations must be safe for concurrent use. It is identical
// to ghclient.Cache, so a single *cache.Disk satisfies both.
type Cache interface {
	Get(key string) (etag string, body []byte, link string, ok bool)
	Put(key, etag string, body []byte, link string)
}

// SetCache enables ETag-based conditional requests backed by c.
func (c *Client) SetCache(cache Cache) { c.cache = cache }

// New builds a client targeting gitlab.com. Use WithHost for a self-managed
// instance. The token stays wrapped in a Secret and is only exposed when set on
// the request's auth header.
func New(token auth.Secret) *Client {
	return &Client{
		http:    &http.Client{Timeout: 30 * time.Second},
		baseURL: defaultBaseURL,
		token:   token,
		reserve: 1,
	}
}

// WithHost points the client at a self-managed GitLab instance (e.g.
// "https://gitlab.example.com"). A missing scheme defaults to https; a trailing
// slash and any /api/v4 suffix are trimmed. Returns c for chaining.
func (c *Client) WithHost(host string) *Client {
	host = strings.TrimSpace(host)
	if host == "" {
		return c
	}
	if !strings.Contains(host, "://") {
		host = "https://" + host
	}
	host = strings.TrimRight(host, "/")
	host = strings.TrimSuffix(host, apiV4)
	c.baseURL = strings.TrimRight(host, "/")
	return c
}

// SetOnWait registers a callback invoked once when the client begins pausing for
// a rate-limit reset (used to inform the user). The duration is the wait length.
func (c *Client) SetOnWait(fn func(time.Duration)) { c.onWait = fn }

// RateStatus returns the last-known rate-limit budget: how many requests remain,
// how long until the window resets, whether we have learned the budget yet, and
// whether the client is currently paused waiting for a reset.
func (c *Client) RateStatus() (remaining int, resetIn time.Duration, known, waiting bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	resetIn = time.Until(c.reset)
	if resetIn < 0 {
		resetIn = 0
	}
	return c.remaining, resetIn, c.rateKnown, c.waiting.Load()
}

// updateRate records the rate-limit budget from a response's headers. GitLab.com
// sends RateLimit-* headers; self-managed instances often send none, in which
// case the budget stays unknown and gating is a no-op (graceful degradation).
func (c *Client) updateRate(h http.Header) {
	rem := h.Get("RateLimit-Remaining")
	if rem == "" {
		return
	}
	c.mu.Lock()
	c.remaining = atoi(rem)
	if r := atoi(h.Get("RateLimit-Reset")); r > 0 {
		c.reset = time.Unix(int64(r), 0)
	}
	c.rateKnown = true
	c.mu.Unlock()
}

// RateLimit captures the rate-limit state from response headers.
type RateLimit struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	ResetAt   time.Time `json:"reset_at"`
}

// TokenType is inferred from the token prefix; it drives what coverage to expect.
type TokenType string

const (
	TokenPAT            TokenType = "personal_access_token" // glpat-
	TokenServiceAccount TokenType = "service_account_token" // glsoat-
	TokenOAuth          TokenType = "oauth"                 // opaque OAuth access token
	TokenJob            TokenType = "ci_job_token"          // $CI_JOB_TOKEN
	TokenUnknown        TokenType = "unknown"
)

// Probe is the result of validating the token: who it belongs to, what it can
// see, and how much budget is left. It carries no secret material.
type Probe struct {
	Login     string    `json:"login"`
	TokenType TokenType `json:"token_type"`
	Scopes    []string  `json:"scopes"` // from /personal_access_tokens/self; empty otherwise
	RateLimit RateLimit `json:"rate_limit"`
}

// ProbeToken validates the token via GET /user, then reads the token's own
// scopes via GET /personal_access_tokens/self (available to PATs with read_api).
// This is the first call the audit makes: it confirms the token works and seeds
// the coverage report. A failure to read scopes is non-fatal — scopes stay empty.
func (c *Client) ProbeToken(ctx context.Context) (*Probe, error) {
	var user struct {
		Username string `json:"username"`
	}
	resp, err := c.Get(ctx, "/user", nil, &user)
	if err != nil {
		switch StatusCode(err) {
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("token rejected by GitLab (401): check the token is valid and not expired")
		case http.StatusForbidden:
			return nil, fmt.Errorf("token forbidden (403): it may lack read scopes or be rate-limited")
		default:
			return nil, fmt.Errorf("calling GitLab: %w", err)
		}
	}

	probe := &Probe{
		Login:     user.Username,
		TokenType: classifyToken(c.token.Expose()),
		RateLimit: parseRateLimit(resp.Header),
	}

	// Best-effort scope read; missing/forbidden is fine (e.g. OAuth or job token).
	var self struct {
		Scopes []string `json:"scopes"`
	}
	if _, err := c.Get(ctx, "/personal_access_tokens/self", nil, &self); err == nil {
		probe.Scopes = self.Scopes
	}
	return probe, nil
}

// newRequest builds a REST request against baseURL + /api/v4 + path.
func (c *Client) newRequest(ctx context.Context, method, path string, query url.Values) (*http.Request, error) {
	u := c.baseURL + apiV4 + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	c.setAuth(req)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	return req, nil
}

// setAuth applies GitLab's auth header: PRIVATE-TOKEN for personal/service-account
// tokens, Authorization: Bearer for OAuth and CI job tokens (which Bearer accepts).
func (c *Client) setAuth(req *http.Request) {
	raw := c.token.Expose()
	switch classifyToken(raw) {
	case TokenPAT, TokenServiceAccount:
		req.Header.Set("PRIVATE-TOKEN", raw)
	default:
		req.Header.Set("Authorization", "Bearer "+raw)
	}
}

func classifyToken(raw string) TokenType {
	switch {
	case strings.HasPrefix(raw, "glpat-"):
		return TokenPAT
	case strings.HasPrefix(raw, "glsoat-"):
		return TokenServiceAccount
	case strings.HasPrefix(raw, "gloas-"):
		return TokenOAuth
	default:
		return TokenUnknown
	}
}

func parseRateLimit(h http.Header) RateLimit {
	rl := RateLimit{
		Limit:     atoi(h.Get("RateLimit-Limit")),
		Remaining: atoi(h.Get("RateLimit-Remaining")),
	}
	if reset := atoi(h.Get("RateLimit-Reset")); reset > 0 {
		rl.ResetAt = time.Unix(int64(reset), 0)
	}
	return rl
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
