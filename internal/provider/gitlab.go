package provider

import (
	"context"
	"errors"
	"time"

	"github.com/sunnysystems/scopeward/internal/collectgl"
	"github.com/sunnysystems/scopeward/internal/glclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// gitlabCollector wires GitLab auth + client + preflight, and collects the
// human-identity axis for a group (#4). Other axes (teams/projects, non-human,
// CI, branches, SSO) land in #5–#9 and are recorded as coverage gaps until then.
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
func (g *gitlabCollector) CollectsData() bool   { return true }

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

func (g *gitlabCollector) Collect(ctx context.Context, a Args) (*model.Snapshot, error) {
	if a.UserMode {
		// GitLab user/account audits aren't modeled yet; group audits are the
		// governance focus. Surface this clearly rather than silently empty.
		return nil, errors.New("GitLab user/account audits aren't supported yet — audit a group with --org")
	}
	return collectgl.RunGroup(ctx, g.client, a.Subject, g.host, a.Progress, a.Options)
}
