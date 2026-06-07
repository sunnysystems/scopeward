package collect

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sunnysystems/scopeward/internal/ghclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// collectNonHuman gathers org-level machine identities: installed GitHub Apps,
// org webhooks, the default GITHUB_TOKEN workflow permission, and (best effort)
// fine-grained PATs with org access. Per-repo machine credentials (deploy keys,
// repo webhooks) are collected alongside repo details in the teams pass.
func collectNonHuman(ctx context.Context, client *ghclient.Client, org string, snap *model.Snapshot) {
	if apps, err := fetchAppInstallations(ctx, client, org); err != nil {
		snap.Coverage.Missing(model.DataAppInstallations, reasonFor(err, "listing GitHub App installations"))
	} else {
		snap.AppInstallations = apps
		snap.Coverage.OK(model.DataAppInstallations, len(apps))
	}

	if hooks, err := fetchOrgWebhooks(ctx, client, org); err != nil {
		snap.Coverage.Missing(model.DataOrgWebhooks, reasonFor(err, "listing org webhooks"))
	} else {
		snap.OrgWebhooks = hooks
		snap.Coverage.OK(model.DataOrgWebhooks, len(hooks))
	}

	if settings, err := fetchActionsTokenDefault(ctx, client, org); err != nil {
		snap.Coverage.Missing(model.DataActionsTokenDefault, reasonFor(err, "reading default workflow permissions"))
	} else {
		snap.ActionsToken = settings
		snap.Coverage.OK(model.DataActionsTokenDefault, 1)
	}

	if pol, err := fetchActionsPolicy(ctx, client, org); err != nil {
		snap.Coverage.Missing(model.DataActionsPolicy, reasonFor(err, "reading Actions policy"))
	} else {
		snap.ActionsPolicy = pol
		snap.Coverage.OK(model.DataActionsPolicy, 1)
	}

	if runners, err := fetchSelfHostedRunners(ctx, client, org); err != nil {
		snap.Coverage.Missing(model.DataSelfHostedRunners, reasonFor(err, "listing self-hosted runners"))
	} else {
		snap.SelfHostedRunners = runners
		snap.Coverage.OK(model.DataSelfHostedRunners, len(runners))
	}

	if invites, err := fetchPendingInvitations(ctx, client, org); err != nil {
		snap.Coverage.Missing(model.DataPendingInvitations, reasonFor(err, "listing pending invitations"))
	} else {
		snap.PendingInvitations = invites
		snap.Coverage.OK(model.DataPendingInvitations, len(invites))
	}

	if secrets, err := fetchOrgSecrets(ctx, client, org); err != nil {
		snap.Coverage.Missing(model.DataOrgSecrets, reasonFor(err, "listing org Actions secrets"))
	} else {
		snap.OrgSecrets = secrets
		snap.Coverage.OK(model.DataOrgSecrets, len(secrets))
	}

	if creds, err := fetchCredentialAuthorizations(ctx, client, org); err != nil {
		snap.Coverage.Missing(model.DataCredentialAuthorizations, reasonFor(err, "listing SSO credential authorizations"))
	} else {
		snap.CredentialAuthorizations = creds
		snap.Coverage.OK(model.DataCredentialAuthorizations, len(creds))
	}

	if seats, err := fetchCopilotSeats(ctx, client, org); err != nil {
		snap.Coverage.Missing(model.DataCopilotSeats, reasonFor(err, "listing Copilot seats"))
	} else {
		snap.CopilotSeats = seats
		snap.Coverage.OK(model.DataCopilotSeats, len(seats))
	}

	if pats, err := fetchFineGrainedPATs(ctx, client, org); err != nil {
		// Usually means the org has not enabled the fine-grained PAT policy
		// (GitHub Enterprise Cloud feature); record honestly rather than as a pass.
		snap.Coverage.Missing(model.DataFineGrainedPATs, reasonFor(err, "listing fine-grained PATs"))
	} else {
		snap.PATs = pats
		snap.Coverage.OK(model.DataFineGrainedPATs, len(pats))
	}
}

// --- GitHub App installations ---

func fetchAppInstallations(ctx context.Context, client *ghclient.Client, org string) ([]model.AppInstallation, error) {
	// This endpoint wraps results in {total_count, installations:[...]} rather
	// than a bare array, so it is paged manually.
	var out []model.AppInstallation
	page := 1
	for {
		var body struct {
			Installations []struct {
				AppID               int64             `json:"app_id"`
				AppSlug             string            `json:"app_slug"`
				RepositorySelection string            `json:"repository_selection"`
				Permissions         map[string]string `json:"permissions"`
			} `json:"installations"`
		}
		q := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		resp, err := client.Get(ctx, "/orgs/"+org+"/installations", q, &body)
		if err != nil {
			return nil, err
		}
		for _, i := range body.Installations {
			out = append(out, model.AppInstallation{
				AppID:               i.AppID,
				AppSlug:             i.AppSlug,
				RepositorySelection: i.RepositorySelection,
				Permissions:         i.Permissions,
			})
		}
		if !ghclient.HasNextPage(resp) {
			return out, nil
		}
		page++
	}
}

// --- Webhooks ---

type hookDTO struct {
	ID     int64          `json:"id"`
	Active bool           `json:"active"`
	Events []string       `json:"events"`
	Config map[string]any `json:"config"`
}

func (h hookDTO) toModel() model.Webhook {
	w := model.Webhook{ID: h.ID, Active: h.Active, Events: h.Events}
	if u, ok := h.Config["url"].(string); ok {
		w.URL = u
	}
	if s, ok := h.Config["secret"]; ok {
		if str, isStr := s.(string); !isStr || str != "" {
			w.HasSecret = true
		}
	}
	switch v := h.Config["insecure_ssl"].(type) {
	case string:
		w.InsecureSSL = v == "1"
	case float64:
		w.InsecureSSL = v == 1
	}
	return w
}

func fetchOrgWebhooks(ctx context.Context, client *ghclient.Client, org string) ([]model.Webhook, error) {
	return fetchWebhooks(ctx, client, "/orgs/"+org+"/hooks")
}

func fetchRepoWebhooks(ctx context.Context, client *ghclient.Client, org, repo string) ([]model.Webhook, error) {
	return fetchWebhooks(ctx, client, "/repos/"+org+"/"+repo+"/hooks")
}

func fetchWebhooks(ctx context.Context, client *ghclient.Client, path string) ([]model.Webhook, error) {
	dtos, err := ghclient.GetAll[hookDTO](ctx, client, path, nil)
	if err != nil {
		return nil, err
	}
	hooks := make([]model.Webhook, 0, len(dtos))
	for _, d := range dtos {
		hooks = append(hooks, d.toModel())
	}
	return hooks, nil
}

// --- Deploy keys ---

func fetchDeployKeys(ctx context.Context, client *ghclient.Client, org, repo string) ([]model.DeployKey, error) {
	type keyDTO struct {
		ID       int64  `json:"id"`
		Title    string `json:"title"`
		ReadOnly bool   `json:"read_only"`
	}
	dtos, err := ghclient.GetAll[keyDTO](ctx, client, "/repos/"+org+"/"+repo+"/keys", nil)
	if err != nil {
		return nil, err
	}
	keys := make([]model.DeployKey, 0, len(dtos))
	for _, d := range dtos {
		keys = append(keys, model.DeployKey{ID: d.ID, Title: d.Title, ReadOnly: d.ReadOnly})
	}
	return keys, nil
}

// --- Actions policy, self-hosted runners, pending invitations ---

func fetchActionsPolicy(ctx context.Context, client *ghclient.Client, org string) (model.ActionsPolicy, error) {
	var dto struct {
		EnabledRepositories string `json:"enabled_repositories"`
		AllowedActions      string `json:"allowed_actions"`
	}
	if _, err := client.Get(ctx, "/orgs/"+org+"/actions/permissions", nil, &dto); err != nil {
		return model.ActionsPolicy{}, err
	}
	return model.ActionsPolicy{EnabledRepositories: dto.EnabledRepositories, AllowedActions: dto.AllowedActions}, nil
}

func fetchSelfHostedRunners(ctx context.Context, client *ghclient.Client, org string) ([]model.Runner, error) {
	var out []model.Runner
	page := 1
	for {
		var body struct {
			Runners []struct {
				ID     int64  `json:"id"`
				Name   string `json:"name"`
				OS     string `json:"os"`
				Status string `json:"status"`
				Labels []struct {
					Name string `json:"name"`
				} `json:"labels"`
			} `json:"runners"`
		}
		q := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		resp, err := client.Get(ctx, "/orgs/"+org+"/actions/runners", q, &body)
		if err != nil {
			return nil, err
		}
		for _, r := range body.Runners {
			labels := make([]string, 0, len(r.Labels))
			for _, l := range r.Labels {
				labels = append(labels, l.Name)
			}
			out = append(out, model.Runner{ID: r.ID, Name: r.Name, OS: r.OS, Status: r.Status, Labels: labels})
		}
		if !ghclient.HasNextPage(resp) {
			return out, nil
		}
		page++
	}
}

func fetchPendingInvitations(ctx context.Context, client *ghclient.Client, org string) ([]model.Invitation, error) {
	type invDTO struct {
		ID        int64      `json:"id"`
		Login     string     `json:"login"`
		Email     string     `json:"email"`
		Role      string     `json:"role"`
		CreatedAt *time.Time `json:"created_at"`
	}
	dtos, err := ghclient.GetAll[invDTO](ctx, client, "/orgs/"+org+"/invitations", nil)
	if err != nil {
		return nil, err
	}
	out := make([]model.Invitation, 0, len(dtos))
	for _, d := range dtos {
		out = append(out, model.Invitation{ID: d.ID, Login: d.Login, Email: d.Email, Role: d.Role, CreatedAt: d.CreatedAt})
	}
	return out, nil
}

// --- Commit authors (which machine identities push code) ---

// botCommitWindow bounds how far back commit history is scanned per repo.
const botCommitWindow = 90 * 24 * time.Hour

// fetchRecentBotCommitters scans recent commits on the default branch and
// returns the bot/machine identities among the authors, with commit counts. An
// empty repository (409) yields no committers rather than an error.
func fetchRecentBotCommitters(ctx context.Context, client *ghclient.Client, org, repo string, now time.Time) ([]model.CommitActivity, error) {
	type commitDTO struct {
		Author *struct {
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"author"`
	}
	q := url.Values{"since": {now.Add(-botCommitWindow).Format(time.RFC3339)}}
	dtos, err := ghclient.GetAll[commitDTO](ctx, client, "/repos/"+org+"/"+repo+"/commits", q)
	if err != nil {
		if ghclient.StatusCode(err) == 409 {
			return nil, nil // empty repository
		}
		return nil, err
	}

	counts := map[string]int{}
	for _, c := range dtos {
		if c.Author == nil {
			continue // unlinked author (no GitHub account attached)
		}
		if isBotLogin(c.Author.Login, c.Author.Type) {
			counts[c.Author.Login]++
		}
	}
	out := make([]model.CommitActivity, 0, len(counts))
	for login, n := range counts {
		out = append(out, model.CommitActivity{Login: login, Commits: n})
	}
	return out, nil
}

// isBotLogin recognizes machine identities by GitHub account type or the
// conventional "[bot]" login suffix.
func isBotLogin(login, accountType string) bool {
	return accountType == "Bot" || strings.HasSuffix(login, "[bot]")
}

// --- Org Actions secrets, SSO credentials, Copilot seats ---

func fetchOrgSecrets(ctx context.Context, client *ghclient.Client, org string) ([]model.OrgSecret, error) {
	var out []model.OrgSecret
	page := 1
	for {
		var body struct {
			Secrets []struct {
				Name       string `json:"name"`
				Visibility string `json:"visibility"`
			} `json:"secrets"`
		}
		q := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		resp, err := client.Get(ctx, "/orgs/"+org+"/actions/secrets", q, &body)
		if err != nil {
			return nil, err
		}
		for _, s := range body.Secrets {
			out = append(out, model.OrgSecret{Name: s.Name, Visibility: s.Visibility})
		}
		if !ghclient.HasNextPage(resp) {
			return out, nil
		}
		page++
	}
}

func fetchCredentialAuthorizations(ctx context.Context, client *ghclient.Client, org string) ([]model.CredentialAuthorization, error) {
	type credDTO struct {
		CredentialID   int64      `json:"credential_id"`
		Login          string     `json:"login"`
		CredentialType string     `json:"credential_type"`
		Scopes         []string   `json:"scopes"`
		AccessedAt     *time.Time `json:"credential_accessed_at"`
		ExpiresAt      *time.Time `json:"authorized_credential_expires_at"`
	}
	dtos, err := ghclient.GetAll[credDTO](ctx, client, "/orgs/"+org+"/credential-authorizations", nil)
	if err != nil {
		return nil, err
	}
	out := make([]model.CredentialAuthorization, 0, len(dtos))
	for _, d := range dtos {
		out = append(out, model.CredentialAuthorization{
			CredentialID: d.CredentialID, Login: d.Login, CredentialType: d.CredentialType, Scopes: d.Scopes,
			AccessedAt: d.AccessedAt, ExpiresAt: d.ExpiresAt,
		})
	}
	return out, nil
}

func fetchCopilotSeats(ctx context.Context, client *ghclient.Client, org string) ([]model.CopilotSeat, error) {
	var out []model.CopilotSeat
	page := 1
	for {
		var body struct {
			Seats []struct {
				Assignee struct {
					Login string `json:"login"`
				} `json:"assignee"`
				LastActivityAt *time.Time `json:"last_activity_at"`
				CreatedAt      *time.Time `json:"created_at"`
			} `json:"seats"`
		}
		q := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		resp, err := client.Get(ctx, "/orgs/"+org+"/copilot/billing/seats", q, &body)
		if err != nil {
			return nil, err
		}
		for _, s := range body.Seats {
			out = append(out, model.CopilotSeat{Login: s.Assignee.Login, LastActivityAt: s.LastActivityAt, CreatedAt: s.CreatedAt})
		}
		if !ghclient.HasNextPage(resp) {
			return out, nil
		}
		page++
	}
}

// fetchOpenSecretAlerts counts open secret-scanning alerts for a repo. Returns
// nil when secret scanning is unavailable for the repo (404), distinct from 0.
func fetchOpenSecretAlerts(ctx context.Context, client *ghclient.Client, org, repo string) (*int, error) {
	var alerts []struct {
		Number int `json:"number"`
	}
	q := url.Values{"state": {"open"}, "per_page": {"100"}}
	if _, err := client.Get(ctx, "/repos/"+org+"/"+repo+"/secret-scanning/alerts", q, &alerts); err != nil {
		if ghclient.StatusCode(err) == 404 {
			return nil, nil // secret scanning not available/enabled for this repo
		}
		return nil, err
	}
	n := len(alerts)
	return &n, nil
}

// fetchDependabotEnabled reports whether Dependabot vulnerability alerts are
// enabled for a repo. The dedicated endpoint answers 204 (enabled) or 404
// (disabled); any other error (e.g. 403) leaves the state unknown (nil).
func fetchDependabotEnabled(ctx context.Context, client *ghclient.Client, org, repo string) (*bool, error) {
	if _, err := client.Get(ctx, "/repos/"+org+"/"+repo+"/vulnerability-alerts", nil, nil); err != nil {
		if ghclient.StatusCode(err) == 404 {
			f := false
			return &f, nil
		}
		return nil, err
	}
	t := true
	return &t, nil
}

// fetchOpenDependabotAlerts summarizes a repo's open Dependabot alerts by
// advisory severity. Returns nil when Dependabot alerts are unavailable (404 or
// 403), distinct from an all-zero summary.
//
// The endpoint paginates by an opaque cursor (?after=), not ?page=N, so GetAll
// cannot be used — we follow the Link header's rel="next" cursor by hand.
func fetchOpenDependabotAlerts(ctx context.Context, client *ghclient.Client, org, repo string) (*model.DependabotAlertSummary, error) {
	type alertDTO struct {
		SecurityAdvisory struct {
			Severity string `json:"severity"`
		} `json:"security_advisory"`
	}
	var s model.DependabotAlertSummary
	q := url.Values{"state": {"open"}, "per_page": {"100"}}
	for {
		var batch []alertDTO
		resp, err := client.Get(ctx, "/repos/"+org+"/"+repo+"/dependabot/alerts", q, &batch)
		if err != nil {
			if c := ghclient.StatusCode(err); c == 404 || c == 403 {
				return nil, nil // Dependabot alerts not available/enabled for this repo
			}
			return nil, err
		}
		for _, a := range batch {
			switch a.SecurityAdvisory.Severity {
			case "critical":
				s.Critical++
			case "high":
				s.High++
			case "medium":
				s.Medium++
			case "low":
				s.Low++
			}
		}
		after := ghclient.NextPageCursor(resp, "after")
		if after == "" {
			break
		}
		q.Set("after", after)
	}
	return &s, nil
}

// --- Per-repo code security (secret scanning / push protection) ---

// fetchRepoSecurity reads a repo's security_and_analysis settings. Returns nil
// pointers when the field is absent (older repos or insufficient visibility) or
// the repo is missing (404), distinct from a confident "disabled".
func fetchRepoSecurity(ctx context.Context, client *ghclient.Client, org, repo string) (secretScanning, pushProtection *bool, err error) {
	var dto struct {
		SecurityAndAnalysis *struct {
			SecretScanning *struct {
				Status string `json:"status"`
			} `json:"secret_scanning"`
			SecretScanningPushProtection *struct {
				Status string `json:"status"`
			} `json:"secret_scanning_push_protection"`
		} `json:"security_and_analysis"`
	}
	if _, e := client.Get(ctx, "/repos/"+org+"/"+repo, nil, &dto); e != nil {
		if ghclient.StatusCode(e) == 404 {
			return nil, nil, nil
		}
		return nil, nil, e
	}
	sa := dto.SecurityAndAnalysis
	if sa == nil {
		return nil, nil, nil
	}
	if sa.SecretScanning != nil {
		v := sa.SecretScanning.Status == "enabled"
		secretScanning = &v
	}
	if sa.SecretScanningPushProtection != nil {
		v := sa.SecretScanningPushProtection.Status == "enabled"
		pushProtection = &v
	}
	return secretScanning, pushProtection, nil
}

// --- Default GITHUB_TOKEN workflow permissions ---

func fetchActionsTokenDefault(ctx context.Context, client *ghclient.Client, org string) (model.ActionsTokenSettings, error) {
	var dto struct {
		DefaultWorkflowPermissions   string `json:"default_workflow_permissions"`
		CanApprovePullRequestReviews bool   `json:"can_approve_pull_request_reviews"`
	}
	if _, err := client.Get(ctx, "/orgs/"+org+"/actions/permissions/workflow", nil, &dto); err != nil {
		return model.ActionsTokenSettings{}, err
	}
	return model.ActionsTokenSettings{
		DefaultWorkflowPermissions:   dto.DefaultWorkflowPermissions,
		CanApprovePullRequestReviews: dto.CanApprovePullRequestReviews,
	}, nil
}

// --- Fine-grained PATs (GitHub Enterprise Cloud) ---

func fetchFineGrainedPATs(ctx context.Context, client *ghclient.Client, org string) ([]model.PAT, error) {
	type patDTO struct {
		ID    int64 `json:"id"`
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
		Permissions  map[string]string `json:"permissions"`
		TokenExpired bool              `json:"token_expired"`
		ExpiresAt    *time.Time        `json:"token_expires_at"`
	}
	dtos, err := ghclient.GetAll[patDTO](ctx, client, "/orgs/"+org+"/personal-access-tokens", nil)
	if err != nil {
		return nil, err
	}
	pats := make([]model.PAT, 0, len(dtos))
	for _, d := range dtos {
		pats = append(pats, model.PAT{
			ID:          d.ID,
			OwnerLogin:  d.Owner.Login,
			ExpiresAt:   d.ExpiresAt,
			Permissions: d.Permissions,
		})
	}
	return pats, nil
}
