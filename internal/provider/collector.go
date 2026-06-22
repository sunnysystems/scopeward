// Package provider is the thin abstraction that lets scopeward target GitHub or
// GitLab through one flow. It defines the Collector interface (the single seam
// between provider-specific collection and the provider-neutral checks), a
// factory that builds the right collector from a Config, and provider-aware
// token resolution and scope guidance.
//
// Collection itself is provider-specific and lives behind each Collector: GitHub
// delegates to internal/collect; GitLab delegates to internal/collectgl, which
// currently covers the human-identity axis (#4) with the remaining axes (#5–#9)
// landing as coverage gaps until built. CollectsData reports whether a provider
// can audit at all yet.
package provider

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sunnysystems/scopeward/internal/auth"
	"github.com/sunnysystems/scopeward/internal/collect"
	"github.com/sunnysystems/scopeward/internal/model"
)

// Cache is the disk ETag cache shared by the underlying clients; *cache.Disk
// satisfies it (and ghclient.Cache / glclient.Cache) structurally.
type Cache interface {
	Get(key string) (etag string, body []byte, link string, ok bool)
	Put(key, etag string, body []byte, link string)
}

// RateLimit is the provider-neutral rate-limit snapshot shown in the preflight.
type RateLimit struct {
	Limit     int `json:"limit"`
	Remaining int `json:"remaining"`
}

// Preflight is the provider-neutral result of validating a token: who it belongs
// to, what it can see, and how much budget is left. It carries no secret material.
type Preflight struct {
	Provider      model.Provider `json:"provider"`
	Host          string         `json:"host,omitempty"`
	Login         string         `json:"login"`
	TokenType     string         `json:"token_type"`
	TokenSource   string         `json:"token_source"`
	Scopes        []string       `json:"scopes,omitempty"`
	Missing       []string       `json:"missing_recommended_scopes,omitempty"`
	ScopesUnknown bool           `json:"scopes_unknown,omitempty"` // scopes can't be enumerated (e.g. fine-grained PAT / OAuth)
	RateLimit     RateLimit      `json:"rate_limit"`
}

// Args are the inputs to a collection run.
type Args struct {
	Subject  string
	UserMode bool
	Self     bool
	Options  collect.Options
	Progress collect.Reporter
}

// Collector audits one provider. Collect and Preflight are provider-specific; the
// rest of the pipeline (checks, scoring, rendering) reads only the neutral
// Snapshot it returns.
type Collector interface {
	Kind() model.Provider
	Preflight(ctx context.Context) (*Preflight, error)
	CollectsData() bool
	Collect(ctx context.Context, args Args) (*model.Snapshot, error)
	RateStatus() (remaining int, resetIn time.Duration, known, waiting bool)
	SetCache(Cache)
	SetOnWait(func(time.Duration))
}

// Config selects and configures a collector.
type Config struct {
	Provider    model.Provider
	Host        string      // self-managed instance base (GitLab); empty = SaaS
	Token       auth.Secret //
	TokenSource string      // human label of where the token came from, e.g. "env (GITLAB_TOKEN)"
}

// New builds the collector for cfg.Provider.
func New(cfg Config) (Collector, error) {
	switch cfg.Provider {
	case model.ProviderGitHub:
		return newGitHubCollector(cfg), nil
	case model.ProviderGitLab:
		return newGitLabCollector(cfg), nil
	default:
		return nil, fmt.Errorf("unknown provider %q (want github or gitlab)", cfg.Provider)
	}
}

// Parse resolves the --provider flag and --host into a concrete provider. An
// explicit flag wins; otherwise a host that looks like GitLab implies gitlab; the
// default is GitHub.
func Parse(flag, host string) (model.Provider, error) {
	switch strings.ToLower(strings.TrimSpace(flag)) {
	case "github":
		return model.ProviderGitHub, nil
	case "gitlab":
		return model.ProviderGitLab, nil
	case "", "auto":
		if looksLikeGitLab(host) {
			return model.ProviderGitLab, nil
		}
		return model.ProviderGitHub, nil
	default:
		return "", fmt.Errorf("unknown --provider %q (want github or gitlab)", flag)
	}
}

func looksLikeGitLab(host string) bool {
	return strings.Contains(strings.ToLower(host), "gitlab")
}

// Title is the display name for a provider.
func Title(p model.Provider) string {
	switch p {
	case model.ProviderGitLab:
		return "GitLab"
	default:
		return "GitHub"
	}
}

// tokenSpec is the env-var/prompt sourcing for a provider's token.
func tokenSpec(p model.Provider) auth.TokenSpec {
	switch p {
	case model.ProviderGitLab:
		return auth.TokenSpec{EnvVars: []string{"GITLAB_TOKEN", "CI_JOB_TOKEN"}, PromptNoun: "GitLab"}
	default:
		return auth.TokenSpec{EnvVars: []string{"GITHUB_TOKEN", "GH_TOKEN"}, PromptNoun: "GitHub"}
	}
}

// ResolveToken sources p's token (env or prompt) and returns it plus a human
// label of where it came from (e.g. "env (GITLAB_TOKEN)" or "prompt").
func ResolveToken(p model.Provider, prompt io.Writer) (auth.Secret, string, error) {
	tok, src, envVar, err := auth.Resolve(tokenSpec(p), prompt)
	if err != nil {
		return auth.Secret{}, "", err
	}
	label := string(src)
	if src == auth.SourceEnv && envVar != "" {
		label = fmt.Sprintf("env (%s)", envVar)
	}
	return tok, label, nil
}
