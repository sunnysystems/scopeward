package collect

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/sunnysystems/scopeward/internal/ghclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// RunUser audits a user account and its repositories instead of an organization.
// The org-only collectors are skipped, so org-scoped checks degrade to
// "not evaluated"; the per-repo pass (code security, supply chain, webhooks,
// keys, commits, branch protection) runs identically.
//
// When self is true the target is the authenticated user: own 2FA is read and
// private repos are included. Otherwise only the target's public repos are seen.
func RunUser(ctx context.Context, client *ghclient.Client, login string, self bool, prog Reporter, opts Options) (*model.Snapshot, error) {
	if prog == nil {
		prog = noopReporter{}
	}
	snap := model.NewSnapshot(login)

	if self {
		prog.Stage("reading account settings")
		if tfa, err := fetchAccountTwoFactor(ctx, client); err != nil {
			snap.Coverage.Missing(model.DataAccount, reasonFor(err, "reading account 2FA"))
		} else {
			snap.AccountTwoFactor = tfa
			snap.Coverage.OK(model.DataAccount, 1)
		}
	}

	prog.Stage("listing repositories for " + login)
	repos, err := fetchUserRepos(ctx, client, login, self)
	if err != nil {
		return nil, fmt.Errorf("cannot read repositories for %q: %w", login, err)
	}
	snap.Repos = FilterRepos(repos, opts.Repos)
	if len(opts.Repos) > 0 && len(snap.Repos) == 0 {
		return nil, fmt.Errorf("no repository of %q matched --repo %s", login, strings.Join(opts.Repos, ", "))
	}
	recordRepoListCoverage(snap, opts, len(repos))

	if opts.Quick {
		for _, k := range perRepoKinds {
			snap.Coverage.Missing(k, "skipped in --quick mode (account-level only)")
		}
	} else {
		collectRepoDetails(ctx, client, login, snap, prog, opts)
	}

	snap.CollectedAt = Now()
	return snap, nil
}

// fetchAccountTwoFactor reads the authenticated user's own 2FA state.
func fetchAccountTwoFactor(ctx context.Context, client *ghclient.Client) (*bool, error) {
	var dto struct {
		TwoFactorAuthentication *bool `json:"two_factor_authentication"`
	}
	if _, err := client.Get(ctx, "/user", nil, &dto); err != nil {
		return nil, err
	}
	return dto.TwoFactorAuthentication, nil
}

// fetchUserRepos lists a user's repositories: owned (incl. private) for the
// authenticated user, or public-only for any other user.
func fetchUserRepos(ctx context.Context, client *ghclient.Client, login string, self bool) ([]model.Repo, error) {
	path := "/users/" + login + "/repos"
	var query url.Values
	if self {
		path = "/user/repos"
		query = url.Values{"affiliation": {"owner"}}
	}
	dtos, err := ghclient.GetAll[repoDTO](ctx, client, path, query)
	if err != nil {
		return nil, err
	}
	repos := make([]model.Repo, 0, len(dtos))
	for _, r := range dtos {
		repos = append(repos, model.Repo{
			Name: r.Name, ID: r.ID, Private: r.Private, Archived: r.Archived,
			PushedAt: r.PushedAt, DefaultBranch: r.DefaultBranch,
		})
	}
	return repos, nil
}
