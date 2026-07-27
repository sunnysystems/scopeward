package collectgl

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/sunnysystems/scopeward/internal/collect"
	"github.com/sunnysystems/scopeward/internal/glclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// collectNonHuman gathers GitLab's machine identities: personal/project/group
// access tokens, deploy tokens, per-project deploy keys, and (instance-admin
// only) OAuth applications. GitLab's token model is richer than GitHub's, so
// these populate the neutral AccessToken/DeployToken/OAuthApp slices that the
// no-expiry, broad-scope, and staleness checks read.
//
// OAuth apps are a single instance-level call and are always attempted. The
// access/deploy-token and deploy-key passes fan out per group and per project,
// so they are skipped in --quick mode (group-level audit only), mirroring the
// per-repo passes of the GitHub collector. GitHub-only concepts (GitHub Apps,
// the fine-grained PAT policy) are recorded as coverage gaps so their checks
// report "not evaluated" rather than a false pass.
func collectNonHuman(ctx context.Context, client *glclient.Client, snap *model.Snapshot, opts collect.Options) {
	if apps, err := fetchOAuthApps(ctx, client); err != nil {
		snap.Coverage.Missing(model.DataOAuthApps, reasonFor(err, "listing OAuth applications"))
	} else {
		snap.OAuthApps = apps
		snap.Coverage.OK(model.DataOAuthApps, len(apps))
	}

	// GitHub Apps have no GitLab equivalent; GitLab tokens are collected as
	// access tokens rather than through a fine-grained PAT policy. Record both
	// so the GitHub App checks, the AI-agent checks, and
	// nonhuman.pat-no-expiry degrade to "not evaluated".
	snap.Coverage.Missing(model.DataAppInstallations, "GitHub Apps have no GitLab equivalent; GitLab uses OAuth applications & access tokens")
	snap.Coverage.Missing(model.DataFineGrainedPATs, "GitLab access tokens are collected separately; there is no GitHub fine-grained-PAT policy")

	if opts.Quick {
		for _, k := range []model.DataKind{model.DataAccessTokens, model.DataDeployTokens, model.DataDeployKeys} {
			snap.Coverage.Missing(k, "skipped in --quick mode (group-level audit only)")
		}
		return
	}

	collectTokens(ctx, client, snap)
	collectProjectDeployKeys(ctx, client, snap)
}

// collectTokens fills snap.AccessTokens and snap.DeployTokens from personal
// access tokens (the caller's own, or all when an instance admin), the group
// tree's access & deploy tokens, and each project's access & deploy tokens.
// Appends are guarded by a mutex since the per-group and per-project passes run
// concurrently into shared slices.
func collectTokens(ctx context.Context, client *glclient.Client, snap *model.Snapshot) {
	var (
		mu      sync.Mutex
		atTally covTally // access tokens (personal + group + project)
		dtTally covTally // deploy tokens (group + project)
	)
	addAccess := func(toks []model.AccessToken) {
		mu.Lock()
		snap.AccessTokens = append(snap.AccessTokens, toks...)
		mu.Unlock()
	}
	addDeploy := func(toks []model.DeployToken) {
		mu.Lock()
		snap.DeployTokens = append(snap.DeployTokens, toks...)
		mu.Unlock()
	}

	// Personal access tokens (single instance-level call).
	if me, err := currentUser(ctx, client); err != nil {
		atTally.fail(reasonFor(err, "identifying the current user for personal access tokens"))
	} else if toks, err := fetchPersonalAccessTokens(ctx, client, me); err != nil {
		atTally.fail(reasonFor(err, "listing personal access tokens"))
	} else {
		addAccess(toks)
		atTally.add(len(toks))
	}

	// Group access & deploy tokens: the top group plus every subgroup.
	groups := []tokenScope{{id: snap.Org.ID, path: snap.Org.Login}}
	for _, t := range snap.Teams {
		groups = append(groups, tokenScope{id: t.ID, path: t.Slug})
	}
	forEachIndex(ctx, defaultConcurrency, len(groups), func(ctx context.Context, i int) {
		g := groups[i]
		if toks, err := fetchAccessTokens(ctx, client, "groups", g, "group"); err != nil {
			atTally.fail(reasonFor(err, "listing group access tokens"))
		} else {
			addAccess(toks)
			atTally.add(len(toks))
		}
		if toks, err := fetchDeployTokens(ctx, client, "groups", g, "group"); err != nil {
			dtTally.fail(reasonFor(err, "listing group deploy tokens"))
		} else {
			addDeploy(toks)
			dtTally.add(len(toks))
		}
	})

	// Project access & deploy tokens.
	forEachIndex(ctx, defaultConcurrency, len(snap.Repos), func(ctx context.Context, i int) {
		p := tokenScope{id: snap.Repos[i].ID, path: snap.Repos[i].Name}
		if toks, err := fetchAccessTokens(ctx, client, "projects", p, "project"); err != nil {
			atTally.fail(reasonFor(err, "listing project access tokens"))
		} else {
			addAccess(toks)
			atTally.add(len(toks))
		}
		if toks, err := fetchDeployTokens(ctx, client, "projects", p, "project"); err != nil {
			dtTally.fail(reasonFor(err, "listing project deploy tokens"))
		} else {
			addDeploy(toks)
			dtTally.add(len(toks))
		}
	})

	atTally.record(snap.Coverage, model.DataAccessTokens, 1+len(groups)+len(snap.Repos))
	dtTally.record(snap.Coverage, model.DataDeployTokens, len(groups)+len(snap.Repos))
}

// collectProjectDeployKeys fills each project's deploy keys (SSH keys). GitLab's
// can_push maps onto the neutral ReadOnly flag so the writable-deploy-key check
// evaluates unchanged. Each goroutine writes a distinct Repo, so no lock needed.
func collectProjectDeployKeys(ctx context.Context, client *glclient.Client, snap *model.Snapshot) {
	if !snap.Coverage.Available(model.DataRepos) || len(snap.Repos) == 0 {
		snap.Coverage.Missing(model.DataDeployKeys, "projects could not be listed")
		return
	}
	var keys covTally
	forEachIndex(ctx, defaultConcurrency, len(snap.Repos), func(ctx context.Context, i int) {
		r := &snap.Repos[i]
		dtos, err := glclient.GetAll[glDeployKeyDTO](ctx, client, "/projects/"+strconv.FormatInt(r.ID, 10)+"/deploy_keys", nil)
		if err != nil {
			keys.fail(reasonFor(err, "listing project deploy keys"))
			return
		}
		for _, d := range dtos {
			r.DeployKeys = append(r.DeployKeys, d.toModel())
		}
		keys.add(len(dtos))
	})
	keys.record(snap.Coverage, model.DataDeployKeys, len(snap.Repos))
}

// tokenScope identifies the group or project a token hangs off: its numeric id
// (for the API path and the future revoke fixer) and full path (for findings).
type tokenScope struct {
	id   int64
	path string
}

// --- API helpers ---

// currentUser identifies the authenticated user so personal access tokens can
// be attributed to a login rather than a bare numeric id.
func currentUser(ctx context.Context, client *glclient.Client) (userIdentity, error) {
	var u userIdentity
	_, err := client.Get(ctx, "/user", nil, &u)
	return u, err
}

type userIdentity struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

// fetchPersonalAccessTokens lists the personal access tokens visible to the
// token: the caller's own, or every user's when the caller is an instance
// admin. Each is attributed to the owning login when it is the caller, else to
// "user #<id>" since resolving every owner would cost a lookup per token.
func fetchPersonalAccessTokens(ctx context.Context, client *glclient.Client, me userIdentity) ([]model.AccessToken, error) {
	dtos, err := glclient.GetAll[glAccessTokenDTO](ctx, client, "/personal_access_tokens", nil)
	if err != nil {
		return nil, err
	}
	toks := make([]model.AccessToken, 0, len(dtos))
	for _, d := range dtos {
		holder := me.Username
		if d.UserID != 0 && d.UserID != me.ID {
			holder = fmt.Sprintf("user #%d", d.UserID)
		}
		toks = append(toks, d.toModel("personal", holder, 0))
	}
	return toks, nil
}

// fetchAccessTokens lists a group's or project's access tokens (resource is
// "groups" or "projects").
func fetchAccessTokens(ctx context.Context, client *glclient.Client, resource string, scope tokenScope, kind string) ([]model.AccessToken, error) {
	path := "/" + resource + "/" + strconv.FormatInt(scope.id, 10) + "/access_tokens"
	dtos, err := glclient.GetAll[glAccessTokenDTO](ctx, client, path, nil)
	if err != nil {
		return nil, err
	}
	toks := make([]model.AccessToken, 0, len(dtos))
	for _, d := range dtos {
		toks = append(toks, d.toModel(kind, scope.path, scope.id))
	}
	return toks, nil
}

// fetchDeployTokens lists a group's or project's deploy tokens.
func fetchDeployTokens(ctx context.Context, client *glclient.Client, resource string, scope tokenScope, kind string) ([]model.DeployToken, error) {
	path := "/" + resource + "/" + strconv.FormatInt(scope.id, 10) + "/deploy_tokens"
	dtos, err := glclient.GetAll[glDeployTokenDTO](ctx, client, path, nil)
	if err != nil {
		return nil, err
	}
	toks := make([]model.DeployToken, 0, len(dtos))
	for _, d := range dtos {
		toks = append(toks, d.toModel(kind, scope.path, scope.id))
	}
	return toks, nil
}

// fetchOAuthApps lists instance-wide OAuth applications. The /applications
// endpoint is instance-admin-only, so a group-owner token gets 403 here and the
// caller records the gap rather than treating it as "no apps".
func fetchOAuthApps(ctx context.Context, client *glclient.Client) ([]model.OAuthApp, error) {
	dtos, err := glclient.GetAll[glOAuthAppDTO](ctx, client, "/applications", nil)
	if err != nil {
		return nil, err
	}
	apps := make([]model.OAuthApp, 0, len(dtos))
	for _, d := range dtos {
		apps = append(apps, model.OAuthApp{
			ID:           d.ID,
			Name:         d.Name,
			CallbackURL:  d.CallbackURL,
			Confidential: d.Confidential,
			Trusted:      d.Trusted,
		})
	}
	return apps, nil
}

// --- DTOs ---

// glAccessTokenDTO is a GitLab personal/project/group access token. expires_at
// is a date ("2006-01-02"); created_at and last_used_at are full timestamps and
// may be null (never used).
type glAccessTokenDTO struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	Active     bool       `json:"active"`
	Revoked    bool       `json:"revoked"`
	ExpiresAt  string     `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  *time.Time `json:"created_at"`
	UserID     int64      `json:"user_id"`
}

func (d glAccessTokenDTO) toModel(kind, holder string, scopeID int64) model.AccessToken {
	return model.AccessToken{
		ID:         d.ID,
		ScopeID:    scopeID,
		Name:       d.Name,
		Kind:       kind,
		Holder:     holder,
		Scopes:     d.Scopes,
		ExpiresAt:  parseGLTime(d.ExpiresAt),
		LastUsedAt: d.LastUsedAt,
		CreatedAt:  d.CreatedAt,
		Active:     d.Active,
		Revoked:    d.Revoked,
	}
}

// glDeployTokenDTO is a GitLab deploy token. The secret is never returned; the
// API exposes the username, scopes, expiry, and whether it was revoked.
type glDeployTokenDTO struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	Username  string   `json:"username"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expires_at"`
	Revoked   bool     `json:"revoked"`
}

func (d glDeployTokenDTO) toModel(kind, holder string, scopeID int64) model.DeployToken {
	return model.DeployToken{
		ID:        d.ID,
		ScopeID:   scopeID,
		Name:      d.Name,
		Username:  d.Username,
		Kind:      kind,
		Holder:    holder,
		Scopes:    d.Scopes,
		ExpiresAt: parseGLTime(d.ExpiresAt),
		Revoked:   d.Revoked,
	}
}

// glDeployKeyDTO is a GitLab project deploy key. can_push is the inverse of the
// neutral ReadOnly flag.
type glDeployKeyDTO struct {
	ID        int64  `json:"id"`
	Title     string `json:"title"`
	CanPush   bool   `json:"can_push"`
	ExpiresAt string `json:"expires_at"`
}

func (d glDeployKeyDTO) toModel() model.DeployKey {
	return model.DeployKey{
		ID:        d.ID,
		Title:     d.Title,
		ReadOnly:  !d.CanPush,
		ExpiresAt: parseGLTime(d.ExpiresAt),
	}
}

// glOAuthAppDTO is an instance OAuth application from GET /applications.
type glOAuthAppDTO struct {
	ID           int64  `json:"id"`
	Name         string `json:"application_name"`
	CallbackURL  string `json:"callback_url"`
	Confidential bool   `json:"confidential"`
	Trusted      bool   `json:"trusted"`
}

// parseGLTime parses a GitLab timestamp, accepting both the date-only form that
// token expiries use ("2006-01-02") and the RFC3339 form that deploy tokens and
// keys use. It returns nil for an empty or unparseable value (e.g. no expiry).
func parseGLTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}
