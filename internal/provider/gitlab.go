package provider

import (
	"context"
	"time"

	"github.com/sunnysystems/scopeward/internal/glclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// gitlabCollector wires GitLab auth + client + preflight. Data collection itself
// is not implemented yet (#4–#9): CollectsData reports false so the CLI stops
// after a successful preflight rather than producing a misleading empty audit.
type gitlabCollector struct {
	client      *glclient.Client
	host        string
	tokenSource string
}

func newGitLabCollector(cfg Config) *gitlabCollector {
	return &gitlabCollector{
		client:      glclient.New(cfg.Token).WithHost(cfg.Host),
		host:        cfg.Host,
		tokenSource: cfg.TokenSource,
	}
}

func (g *gitlabCollector) Kind() model.Provider { return model.ProviderGitLab }
func (g *gitlabCollector) CollectsData() bool   { return false } // until #4–#9

func (g *gitlabCollector) SetCache(c Cache)                 { g.client.SetCache(c) }
func (g *gitlabCollector) SetOnWait(fn func(time.Duration)) { g.client.SetOnWait(fn) }

func (g *gitlabCollector) RateStatus() (int, time.Duration, bool, bool) {
	return g.client.RateStatus()
}

func (g *gitlabCollector) Preflight(ctx context.Context) (*Preflight, error) {
	p, err := g.client.ProbeToken(ctx)
	if err != nil {
		return nil, err
	}
	pf := &Preflight{
		Provider:    model.ProviderGitLab,
		Host:        g.host,
		Login:       p.Login,
		TokenType:   string(p.TokenType),
		TokenSource: g.tokenSource,
		Scopes:      p.Scopes,
		RateLimit:   RateLimit{Limit: p.RateLimit.Limit, Remaining: p.RateLimit.Remaining},
	}
	// OAuth and CI job tokens can't enumerate their scopes via the API, so we
	// can't pre-judge coverage.
	if len(p.Scopes) == 0 {
		pf.ScopesUnknown = true
	} else {
		pf.Missing = missingGitLabScopes(p.Scopes)
	}
	return pf, nil
}

func (g *gitlabCollector) Collect(_ context.Context, _ Args) (*model.Snapshot, error) {
	return nil, ErrNotImplemented
}
