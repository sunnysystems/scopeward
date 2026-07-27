package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sunnysystems/scopeward/internal/ghclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// collectTeamsAndPermissions gathers teams, repositories, and the direct
// (non-team) collaborator grants on each repo. The per-repo grant calls run with
// bounded concurrency.
func collectTeamsAndPermissions(ctx context.Context, client *ghclient.Client, org string, snap *model.Snapshot, prog Reporter, opts Options) {
	teams, err := fetchTeams(ctx, client, org)
	if err != nil {
		snap.Coverage.Missing(model.DataTeams, reasonFor(err, "listing teams"))
	} else {
		snap.Teams = teams
		snap.Coverage.OK(model.DataTeams, len(teams))
	}

	repos, err := fetchRepos(ctx, client, org)
	if err != nil {
		snap.Coverage.Missing(model.DataRepos, reasonFor(err, "listing repositories"))
		snap.Coverage.Missing(model.DataRepoDirectCollaborators, "repositories could not be listed")
		return
	}
	snap.Repos = FilterRepos(repos, opts.Repos)
	recordRepoListCoverage(snap, opts, len(repos))

	if rulesets, err := fetchOrgRulesets(ctx, client, org); err != nil {
		snap.Coverage.Missing(model.DataOrgRulesets, reasonFor(err, "listing org rulesets"))
	} else {
		snap.OrgRulesets = rulesets
		snap.Coverage.OK(model.DataOrgRulesets, len(rulesets))
	}

	if roles, err := fetchCustomRoles(ctx, client, org); err != nil {
		snap.Coverage.Missing(model.DataCustomRoles, reasonFor(err, "listing custom repository roles"))
	} else {
		snap.CustomRoles = roles
		snap.Coverage.OK(model.DataCustomRoles, len(roles))
	}

	if orgRoles, err := fetchOrgRoles(ctx, client, org); err != nil {
		snap.Coverage.Missing(model.DataOrgRoles, reasonFor(err, "listing organization roles"))
	} else {
		snap.OrgRoles = orgRoles
		snap.Coverage.OK(model.DataOrgRoles, len(orgRoles))
	}

	// Custom-property values are org-level (one call), so collect them even in
	// --quick mode, mapping each repo's values onto its Repo entry.
	if props, err := fetchCustomProperties(ctx, client, org); err != nil {
		snap.Coverage.Missing(model.DataCustomProperties, reasonFor(err, "reading repository custom properties"))
	} else {
		n := 0
		for i := range snap.Repos {
			if v, ok := props[snap.Repos[i].Name]; ok {
				snap.Repos[i].Properties = v
				n++
			}
		}
		snap.Coverage.OK(model.DataCustomProperties, n)
	}

	if opts.Quick {
		for _, k := range perRepoKinds {
			snap.Coverage.Missing(k, "skipped in --quick mode (org-level only)")
		}
		for _, k := range perTeamKinds {
			snap.Coverage.Missing(k, "skipped in --quick mode (org-level only)")
		}
		return
	}
	collectTeamDetails(ctx, client, org, snap)
	collectRepoDetails(ctx, client, org, snap, prog, opts)
}

// perTeamKinds are the DataKinds produced only by the per-team detail pass.
var perTeamKinds = []model.DataKind{model.DataTeamMembers, model.DataTeamRepos}

// collectTeamDetails fills each team's members, maintainers, and repo grants in
// a single bounded-concurrency pass. Each goroutine writes a distinct slice
// element, so the team data needs no locking. Skipped entirely if teams could
// not be listed.
func collectTeamDetails(ctx context.Context, client *ghclient.Client, org string, snap *model.Snapshot) {
	if !snap.Coverage.Available(model.DataTeams) || len(snap.Teams) == 0 {
		snap.Coverage.Missing(model.DataTeamMembers, "teams could not be listed")
		snap.Coverage.Missing(model.DataTeamRepos, "teams could not be listed")
		return
	}

	var members, repos covTally
	forEachIndex(ctx, defaultConcurrency, len(snap.Teams), func(ctx context.Context, i int) {
		t := &snap.Teams[i]

		if all, err := fetchTeamMembers(ctx, client, org, t.Slug, "all"); err != nil {
			members.fail(reasonFor(err, "listing team members"))
		} else {
			t.Members = all
			members.add(len(all))
			// Maintainers are a subset; only worth a second call when the team has members.
			if len(all) > 0 {
				if maint, err := fetchTeamMembers(ctx, client, org, t.Slug, "maintainer"); err == nil {
					t.Maintainers = maint
				}
			}
		}

		if g, err := fetchTeamRepos(ctx, client, org, t.Slug); err != nil {
			repos.fail(reasonFor(err, "listing team repositories"))
		} else {
			t.RepoGrants = g
			repos.add(len(g))
		}
	})

	members.record(snap.Coverage, model.DataTeamMembers, len(snap.Teams))
	repos.record(snap.Coverage, model.DataTeamRepos, len(snap.Teams))
}

// collectRepoDetails fills each repo's direct collaborators, deploy keys, and
// webhooks in a single bounded-concurrency pass. Each goroutine writes a
// distinct slice element, so the repo data needs no locking; only the per-kind
// coverage bookkeeping is synchronized.
func collectRepoDetails(ctx context.Context, client *ghclient.Client, org string, snap *model.Snapshot, prog Reporter, opts Options) {
	var grants, keys, hooks, commits, protection, security, alerts, dependabot, depAlerts, workflows, codeowners covTally
	now := Now()

	// Build the target list: non-archived repos, deterministically ordered, and
	// optionally capped by --max-repos.
	var targets []int
	for i := range snap.Repos {
		if !snap.Repos[i].Archived {
			targets = append(targets, i)
		}
	}
	sort.Slice(targets, func(a, b int) bool { return snap.Repos[targets[a]].Name < snap.Repos[targets[b]].Name })
	total := len(targets)
	capped := false
	if opts.MaxRepos > 0 && len(targets) > opts.MaxRepos {
		targets = targets[:opts.MaxRepos]
		capped = true
	}
	attempted := len(targets)

	stage := fmt.Sprintf("scanning %d repositories", attempted)
	if capped {
		stage = fmt.Sprintf("scanning %d of %d repositories (--max-repos)", attempted, total)
	}
	prog.Stage(stage)
	prog.SetRepoProgress(0, attempted)
	var scanned atomic.Int64

	forEachIndex(ctx, defaultConcurrency, len(targets), func(ctx context.Context, t int) {
		r := &snap.Repos[targets[t]]
		defer func() { prog.SetRepoProgress(int(scanned.Add(1)), attempted) }()

		if g, err := fetchRepoDirectCollaborators(ctx, client, org, r.Name); err != nil {
			grants.fail(reasonFor(err, "listing direct collaborators"))
		} else {
			r.DirectCollaborators = g
			grants.add(len(g))
		}

		if k, err := fetchDeployKeys(ctx, client, org, r.Name); err != nil {
			keys.fail(reasonFor(err, "listing deploy keys"))
		} else {
			r.DeployKeys = k
			keys.add(len(k))
		}

		if w, err := fetchRepoWebhooks(ctx, client, org, r.Name); err != nil {
			hooks.fail(reasonFor(err, "listing repository webhooks"))
		} else {
			r.Webhooks = w
			hooks.add(len(w))
		}

		if bc, err := fetchRecentBotCommitters(ctx, client, org, r.Name, now); err != nil {
			commits.fail(reasonFor(err, "scanning commit authors"))
		} else {
			r.BotCommitters = bc
			commits.add(len(bc))
		}

		if p, err := fetchDefaultBranchProtected(ctx, client, org, r.Name, r.DefaultBranch); err != nil {
			protection.fail(reasonFor(err, "reading branch protection"))
		} else if p != nil {
			r.DefaultBranchProtected = p
			protection.add(1)
			if *p {
				// Only protected branches have detail worth fetching. Classic protection
				// first; a nil result means the branch is guarded by a ruleset instead,
				// which the classic endpoint cannot see, so read the effective rules.
				d, derr := fetchBranchProtectionDetail(ctx, client, org, r.Name, r.DefaultBranch)
				if derr == nil && d == nil {
					d, derr = fetchBranchRules(ctx, client, org, r.Name, r.DefaultBranch)
				}
				if derr == nil && d != nil {
					r.BranchReqPRReview, r.BranchAllowForcePush = d.reqPR, d.allowForce
					r.BranchReqStatusChecks, r.BranchEnforceAdmins = d.reqChecks, d.enforceAdmins
					r.BranchProtectionSource = d.source
				}
			}
		}

		if ss, pp, err := fetchRepoSecurity(ctx, client, org, r.Name); err != nil {
			security.fail(reasonFor(err, "reading code security settings"))
		} else {
			r.SecretScanning = ss
			r.PushProtection = pp
			security.add(1)
		}

		// Open secret-scanning alerts only exist where scanning is on; skip the
		// call otherwise to avoid guaranteed 404s.
		if r.SecretScanning != nil && *r.SecretScanning {
			if n, err := fetchOpenSecretAlerts(ctx, client, org, r.Name); err != nil {
				alerts.fail(reasonFor(err, "counting open secret-scanning alerts"))
			} else if n != nil {
				r.OpenSecretAlerts = n
				alerts.add(1)
			}
		}

		// Dependabot vulnerability alerts: first whether they're enabled, then —
		// only if so — the count of open alerts (off repos would 403/404).
		if de, err := fetchDependabotEnabled(ctx, client, org, r.Name); err != nil {
			dependabot.fail(reasonFor(err, "reading Dependabot alerts setting"))
		} else {
			r.DependabotAlertsEnabled = de
			dependabot.add(1)
			if de != nil && *de {
				if sum, aerr := fetchOpenDependabotAlerts(ctx, client, org, r.Name); aerr != nil {
					depAlerts.fail(reasonFor(aerr, "counting open Dependabot alerts"))
				} else if sum != nil {
					r.OpenDependabotAlerts = sum
					depAlerts.add(1)
				}
			}
		}

		if wf, err := fetchWorkflowIssues(ctx, client, org, r.Name); err != nil {
			workflows.fail(reasonFor(err, "scanning Actions workflows"))
		} else {
			r.WorkflowIssues = wf
			workflows.add(len(wf))
		}

		if present, teams, err := fetchCodeowners(ctx, client, org, r.Name); err != nil {
			codeowners.fail(reasonFor(err, "reading CODEOWNERS"))
		} else {
			applyCodeowners(r, present, teams)
			codeowners.add(1)
		}
	})

	grants.record(snap.Coverage, model.DataRepoDirectCollaborators, attempted)
	keys.record(snap.Coverage, model.DataDeployKeys, attempted)
	hooks.record(snap.Coverage, model.DataRepoWebhooks, attempted)
	commits.record(snap.Coverage, model.DataCommitAuthors, attempted)
	protection.record(snap.Coverage, model.DataBranchProtection, attempted)
	security.record(snap.Coverage, model.DataRepoSecurity, attempted)
	alerts.record(snap.Coverage, model.DataOpenSecretAlerts, attempted)
	dependabot.record(snap.Coverage, model.DataDependabotEnabled, attempted)
	depAlerts.record(snap.Coverage, model.DataOpenDependabotAlerts, attempted)
	workflows.record(snap.Coverage, model.DataWorkflows, attempted)
	codeowners.record(snap.Coverage, model.DataCodeowners, attempted)

	// When capped, downgrade the otherwise-OK per-repo coverage to partial so the
	// report never reads as if every repo was scanned.
	if capped {
		note := fmt.Sprintf("scanned %d of %d repos (--max-repos)", attempted, total)
		for _, k := range perRepoKinds {
			if c, ok := snap.Coverage.Get(k); ok && c.Status == model.CoverageOK {
				snap.Coverage.Partial(k, c.Count, note)
			}
		}
	}
}

type teamDTO struct {
	Slug    string   `json:"slug"`
	Name    string   `json:"name"`
	ID      int64    `json:"id"`
	Privacy string   `json:"privacy"`
	Parent  *teamDTO `json:"parent"`
}

func fetchTeams(ctx context.Context, client *ghclient.Client, org string) ([]model.Team, error) {
	dtos, err := ghclient.GetAll[teamDTO](ctx, client, "/orgs/"+org+"/teams", nil)
	if err != nil {
		return nil, err
	}
	teams := make([]model.Team, 0, len(dtos))
	for _, t := range dtos {
		team := model.Team{Slug: t.Slug, Name: t.Name, ID: t.ID, Privacy: t.Privacy}
		if t.Parent != nil {
			team.ParentSlug = t.Parent.Slug
		}
		teams = append(teams, team)
	}
	return teams, nil
}

// fetchTeamMembers lists a team's members filtered by role ("all" or
// "maintainer"), returning their logins.
func fetchTeamMembers(ctx context.Context, client *ghclient.Client, org, slug, role string) ([]string, error) {
	q := map[string][]string{"role": {role}}
	dtos, err := ghclient.GetAll[teamMemberDTO](ctx, client, "/orgs/"+org+"/teams/"+slug+"/members", q)
	if err != nil {
		return nil, err
	}
	logins := make([]string, 0, len(dtos))
	for _, d := range dtos {
		logins = append(logins, d.Login)
	}
	return logins, nil
}

type teamMemberDTO struct {
	Login string `json:"login"`
}

// fetchTeamRepos lists the repositories a team grants access to, with the
// permission normalized to a single level.
func fetchTeamRepos(ctx context.Context, client *ghclient.Client, org, slug string) ([]model.TeamRepoGrant, error) {
	dtos, err := ghclient.GetAll[teamRepoDTO](ctx, client, "/orgs/"+org+"/teams/"+slug+"/repos", nil)
	if err != nil {
		return nil, err
	}
	grants := make([]model.TeamRepoGrant, 0, len(dtos))
	for _, d := range dtos {
		grants = append(grants, model.TeamRepoGrant{
			Repo:       d.Name,
			Permission: d.permissionLevel(),
		})
	}
	return grants, nil
}

// teamRepoDTO is a repo as returned by the team-repos endpoint: the repo name
// plus the team's permission object on it.
type teamRepoDTO struct {
	Name        string `json:"name"`
	Permissions struct {
		Admin    bool `json:"admin"`
		Maintain bool `json:"maintain"`
		Push     bool `json:"push"`
		Triage   bool `json:"triage"`
		Pull     bool `json:"pull"`
	} `json:"permissions"`
}

func (d teamRepoDTO) permissionLevel() string {
	switch {
	case d.Permissions.Admin:
		return "admin"
	case d.Permissions.Maintain:
		return "maintain"
	case d.Permissions.Push:
		return "write"
	case d.Permissions.Triage:
		return "triage"
	default:
		return "read"
	}
}

// fetchCustomProperties lists each repository's org custom-property values,
// keyed by repository name. Property names are lowercased so lookups are
// case-insensitive. Available on any plan; an org with no properties yields an
// empty map rather than an error.
func fetchCustomProperties(ctx context.Context, client *ghclient.Client, org string) (map[string]map[string]string, error) {
	dtos, err := ghclient.GetAll[repoPropertyValuesDTO](ctx, client, "/orgs/"+org+"/properties/values", nil)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]string, len(dtos))
	for _, d := range dtos {
		vals := make(map[string]string, len(d.Properties))
		for _, p := range d.Properties {
			vals[strings.ToLower(p.PropertyName)] = p.value()
		}
		out[d.RepositoryName] = vals
	}
	return out, nil
}

type repoPropertyValuesDTO struct {
	RepositoryName string             `json:"repository_name"`
	Properties     []propertyValueDTO `json:"properties"`
}

type propertyValueDTO struct {
	PropertyName string          `json:"property_name"`
	Value        json.RawMessage `json:"value"` // string, or array of strings, or null
}

// value renders a property value as a string: a JSON string verbatim, an array
// joined by commas, anything else by its raw JSON. Empty when null.
func (p propertyValueDTO) value() string {
	if len(p.Value) == 0 || string(p.Value) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(p.Value, &s) == nil {
		return s
	}
	var arr []string
	if json.Unmarshal(p.Value, &arr) == nil {
		return strings.Join(arr, ",")
	}
	return string(p.Value)
}

type repoDTO struct {
	Name          string     `json:"name"`
	ID            int64      `json:"id"`
	Private       bool       `json:"private"`
	Archived      bool       `json:"archived"`
	PushedAt      *time.Time `json:"pushed_at"`
	DefaultBranch string     `json:"default_branch"`
}

func fetchRepos(ctx context.Context, client *ghclient.Client, org string) ([]model.Repo, error) {
	dtos, err := ghclient.GetAll[repoDTO](ctx, client, "/orgs/"+org+"/repos", nil)
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

// fetchDefaultBranchProtected reports whether a repo's default branch is
// protected (by classic branch protection or a ruleset). A nil result means the
// answer is unknown (empty repo / no default branch), distinct from "false".
func fetchDefaultBranchProtected(ctx context.Context, client *ghclient.Client, org, repo, branch string) (*bool, error) {
	if branch == "" {
		return nil, nil
	}
	var dto struct {
		Protected bool `json:"protected"`
	}
	if _, err := client.Get(ctx, "/repos/"+org+"/"+repo+"/branches/"+branch, nil, &dto); err != nil {
		if ghclient.StatusCode(err) == 404 {
			return nil, nil // empty repo or branch gone
		}
		return nil, err
	}
	return &dto.Protected, nil
}

// branchProtectionDetail is the protection detail for one branch, from either
// mechanism GitHub offers. Every field is a pointer so "not assessed" stays
// distinguishable from "off"; a nil *branchProtectionDetail means neither
// mechanism had anything to say about the branch.
type branchProtectionDetail struct {
	reqPR         *bool
	allowForce    *bool
	reqChecks     *bool
	enforceAdmins *bool
	source        string // model.BranchProtectionClassic | model.BranchProtectionRuleset
}

// fetchBranchProtectionDetail reads the classic branch-protection settings for a
// branch. The endpoint 404s when the branch is protected only by a ruleset (not
// classic protection), in which case it returns nil so the quality checks skip
// the repo rather than reporting a false weakness.
func fetchBranchProtectionDetail(ctx context.Context, client *ghclient.Client, org, repo, branch string) (*branchProtectionDetail, error) {
	var dto struct {
		RequiredPullRequestReviews *struct {
			RequiredApprovingReviewCount int `json:"required_approving_review_count"`
		} `json:"required_pull_request_reviews"`
		AllowForcePushes *struct {
			Enabled bool `json:"enabled"`
		} `json:"allow_force_pushes"`
		RequiredStatusChecks *struct {
			Contexts []string `json:"contexts"`
		} `json:"required_status_checks"`
		EnforceAdmins *struct {
			Enabled bool `json:"enabled"`
		} `json:"enforce_admins"`
	}
	if _, e := client.Get(ctx, "/repos/"+org+"/"+repo+"/branches/"+branch+"/protection", nil, &dto); e != nil {
		if ghclient.StatusCode(e) == 404 {
			return nil, nil // ruleset-protected or not classically protected
		}
		return nil, e
	}
	pr := dto.RequiredPullRequestReviews != nil && dto.RequiredPullRequestReviews.RequiredApprovingReviewCount > 0
	force := dto.AllowForcePushes != nil && dto.AllowForcePushes.Enabled
	checks := dto.RequiredStatusChecks != nil
	d := &branchProtectionDetail{reqPR: &pr, allowForce: &force, reqChecks: &checks, source: model.BranchProtectionClassic}
	// Absent enforce_admins is left unknown rather than assumed off, so a shape we
	// did not anticipate degrades to "not evaluated" instead of a false finding.
	if dto.EnforceAdmins != nil {
		d.enforceAdmins = &dto.EnforceAdmins.Enabled
	}
	return d, nil
}

// fetchBranchRules reads the *effective* rules for a branch: the merged result
// of every repository- and organization-level ruleset that applies to it.
//
// This is the path by which ruleset-protected branches get assessed at all.
// Listing org rulesets needs a plan that exposes them and otherwise degrades to
// "not available", and the classic protection endpoint 404s for a branch guarded
// only by a ruleset — so before this, such repos were checked for *whether*
// protection existed and never for whether it was any good. A deliberately weak
// ruleset read exactly like a strong one.
//
// The rules map onto the same neutral fields classic protection fills, so the
// checks never need to know which mechanism produced them:
//
//	pull_request with required_approving_review_count >= 1 → review required
//	non_fast_forward present                               → force-push blocked
//	required_status_checks present                         → status checks required
//
// Bypass actors are deliberately not read here: they live on the ruleset object,
// one extra call per distinct ruleset, so enforceAdmins stays nil and the
// admin-bypass check reports ruleset-protected repos as not assessed rather than
// guessing. An empty rule list means no ruleset covers the branch.
func fetchBranchRules(ctx context.Context, client *ghclient.Client, org, repo, branch string) (*branchProtectionDetail, error) {
	path := "/repos/" + org + "/" + repo + "/rules/branches/" + url.PathEscape(branch)
	rules, err := ghclient.GetAll[branchRule](ctx, client, path, nil)
	if err != nil {
		if ghclient.StatusCode(err) == 404 {
			return nil, nil // no such branch, or rulesets unavailable here
		}
		return nil, err
	}
	return rulesToProtection(rules), nil
}

// branchRule is one effective rule as the rulesets API reports it.
type branchRule struct {
	Type       string `json:"type"`
	Parameters struct {
		RequiredApprovingReviewCount int `json:"required_approving_review_count"`
	} `json:"parameters"`
}

// rulesToProtection maps effective ruleset rules onto the neutral protection
// fields the checks consume. Pure (no I/O) so it can be unit-tested directly.
// Returns nil when no rule covers the branch, which reads as "not assessed"
// rather than as an all-clear.
func rulesToProtection(rules []branchRule) *branchProtectionDetail {
	if len(rules) == 0 {
		return nil
	}
	var pr, checks, blocksForce bool
	for _, r := range rules {
		switch r.Type {
		case "pull_request":
			// A pull_request rule with zero required approvals routes merges through a
			// PR but does not require anyone to look at it — the same state classic
			// protection reports as "no required review".
			pr = pr || r.Parameters.RequiredApprovingReviewCount > 0
		case "required_status_checks":
			checks = true
		case "non_fast_forward":
			blocksForce = true
		}
	}
	force := !blocksForce
	return &branchProtectionDetail{
		reqPR: &pr, allowForce: &force, reqChecks: &checks,
		source: model.BranchProtectionRuleset,
	}
}

// fetchOrgRulesets lists the organization's repository rulesets.
func fetchOrgRulesets(ctx context.Context, client *ghclient.Client, org string) ([]model.Ruleset, error) {
	type rulesetDTO struct {
		ID          int64  `json:"id"`
		Name        string `json:"name"`
		Target      string `json:"target"`
		Enforcement string `json:"enforcement"`
	}
	dtos, err := ghclient.GetAll[rulesetDTO](ctx, client, "/orgs/"+org+"/rulesets", nil)
	if err != nil {
		return nil, err
	}
	out := make([]model.Ruleset, 0, len(dtos))
	for _, r := range dtos {
		out = append(out, model.Ruleset{ID: r.ID, Name: r.Name, Target: r.Target, Enforcement: r.Enforcement})
	}
	return out, nil
}

// fetchCustomRoles lists the org's custom repository roles (the /settings/roles
// page). The endpoint wraps results in {custom_roles:[...]}.
func fetchCustomRoles(ctx context.Context, client *ghclient.Client, org string) ([]model.CustomRole, error) {
	var body struct {
		CustomRoles []struct {
			ID          int64    `json:"id"`
			Name        string   `json:"name"`
			BaseRole    string   `json:"base_role"`
			Permissions []string `json:"permissions"`
		} `json:"custom_roles"`
	}
	if _, err := client.Get(ctx, "/orgs/"+org+"/custom-repository-roles", nil, &body); err != nil {
		return nil, err
	}
	out := make([]model.CustomRole, 0, len(body.CustomRoles))
	for _, r := range body.CustomRoles {
		out = append(out, model.CustomRole{ID: r.ID, Name: r.Name, BaseRole: r.BaseRole, Permissions: r.Permissions})
	}
	return out, nil
}

// fetchOrgRoles lists the org's organization roles (the /settings/organization-roles
// page) and, for each, the users and teams assigned to it (the assignments shown
// on /settings/org_role_assignments). The roles endpoint wraps results in
// {roles:[...]}; the per-role users/teams endpoints return plain arrays. The
// per-role assignment calls run with bounded concurrency, each writing a distinct
// slice element so no locking is needed.
func fetchOrgRoles(ctx context.Context, client *ghclient.Client, org string) ([]model.OrgRole, error) {
	var body struct {
		Roles []struct {
			ID          int64    `json:"id"`
			Name        string   `json:"name"`
			BaseRole    string   `json:"base_role"`
			Source      string   `json:"source"`
			Permissions []string `json:"permissions"`
		} `json:"roles"`
	}
	if _, err := client.Get(ctx, "/orgs/"+org+"/organization-roles", nil, &body); err != nil {
		return nil, err
	}
	out := make([]model.OrgRole, len(body.Roles))
	for i, r := range body.Roles {
		out[i] = model.OrgRole{ID: r.ID, Name: r.Name, BaseRole: r.BaseRole, Source: r.Source, Permissions: r.Permissions}
	}

	forEachIndex(ctx, defaultConcurrency, len(out), func(ctx context.Context, i int) {
		roleID := strconv.FormatInt(out[i].ID, 10)
		base := "/orgs/" + org + "/organization-roles/" + roleID
		if users, err := ghclient.GetAll[orgRoleUserDTO](ctx, client, base+"/users", nil); err == nil {
			for _, u := range users {
				out[i].Users = append(out[i].Users, model.OrgRoleAssignee{
					Login: u.Login, Assignment: u.Assignment, IsBot: u.Type == "Bot",
				})
			}
		}
		if teams, err := ghclient.GetAll[orgRoleTeamDTO](ctx, client, base+"/teams", nil); err == nil {
			for _, t := range teams {
				out[i].Teams = append(out[i].Teams, model.OrgRoleTeamGrant{Slug: t.Slug, Assignment: t.Assignment})
			}
		}
	})
	return out, nil
}

type orgRoleUserDTO struct {
	Login      string `json:"login"`
	Type       string `json:"type"`       // "User" | "Bot"
	Assignment string `json:"assignment"` // "direct" | "indirect" | "mixed"
}

type orgRoleTeamDTO struct {
	Slug       string `json:"slug"`
	Assignment string `json:"assignment"` // "direct" | "indirect"
}

type collaboratorDTO struct {
	Login       string `json:"login"`
	ID          int64  `json:"id"`
	Type        string `json:"type"`
	Permissions struct {
		Admin    bool `json:"admin"`
		Maintain bool `json:"maintain"`
		Push     bool `json:"push"`
		Triage   bool `json:"triage"`
		Pull     bool `json:"pull"`
	} `json:"permissions"`
}

// permissionLevel normalizes the permissions object to the highest single level.
func (c collaboratorDTO) permissionLevel() string {
	switch {
	case c.Permissions.Admin:
		return "admin"
	case c.Permissions.Maintain:
		return "maintain"
	case c.Permissions.Push:
		return "write"
	case c.Permissions.Triage:
		return "triage"
	default:
		return "read"
	}
}

// fetchRepoDirectCollaborators lists collaborators granted directly on a repo
// (affiliation=direct excludes access inherited via team membership).
func fetchRepoDirectCollaborators(ctx context.Context, client *ghclient.Client, org, repo string) ([]model.RepoGrant, error) {
	q := map[string][]string{"affiliation": {"direct"}}
	dtos, err := ghclient.GetAll[collaboratorDTO](ctx, client, "/repos/"+org+"/"+repo+"/collaborators", q)
	if err != nil {
		return nil, err
	}
	grants := make([]model.RepoGrant, 0, len(dtos))
	for _, d := range dtos {
		grants = append(grants, model.RepoGrant{
			Login:      d.Login,
			Permission: d.permissionLevel(),
			IsBot:      d.Type == "Bot",
		})
	}
	return grants, nil
}
