package provider

import (
	"context"
	"time"

	"github.com/sunnysystems/scopeward/internal/collect"
	"github.com/sunnysystems/scopeward/internal/ghclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// githubCollector audits GitHub via ghclient and the existing collect package.
type githubCollector struct {
	client      *ghclient.Client
	tokenSource string
}

func newGitHubCollector(cfg Config) *githubCollector {
	return &githubCollector{
		client:      ghclient.New(cfg.Token),
		tokenSource: cfg.TokenSource,
	}
}

func (g *githubCollector) Kind() model.Provider { return model.ProviderGitHub }
func (g *githubCollector) CollectsData() bool   { return true }

func (g *githubCollector) SetCache(c Cache)                 { g.client.SetCache(c) }
func (g *githubCollector) SetOnWait(fn func(time.Duration)) { g.client.SetOnWait(fn) }

func (g *githubCollector) RateStatus() (int, time.Duration, bool, bool) {
	return g.client.RateStatus()
}

func (g *githubCollector) Preflight(ctx context.Context) (*Preflight, error) {
	p, err := g.client.ProbeToken(ctx)
	if err != nil {
		return nil, err
	}
	pf := &Preflight{
		Provider:    model.ProviderGitHub,
		Login:       p.Login,
		TokenType:   string(p.TokenType),
		TokenSource: g.tokenSource,
		Scopes:      p.Scopes,
		RateLimit:   RateLimit{Limit: p.RateLimit.Limit, Remaining: p.RateLimit.Remaining},
	}
	// Fine-grained PATs don't expose scopes via headers; permissions resolve
	// per call, so we can't pre-judge coverage.
	if p.TokenType == ghclient.TokenFineGrainedPAT {
		pf.ScopesUnknown = true
	} else {
		pf.Missing = missingGitHubScopes(p.Scopes)
	}
	return pf, nil
}

func (g *githubCollector) Collect(ctx context.Context, a Args) (*model.Snapshot, error) {
	if a.UserMode {
		return collect.RunUser(ctx, g.client, a.Subject, a.Self, a.Progress, a.Options)
	}
	return collect.Run(ctx, g.client, a.Subject, a.Progress, a.Options)
}
