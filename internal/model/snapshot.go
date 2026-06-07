package model

import "time"

// Organization holds org-level governance settings. Some fields are only
// returned to org owners/admins; zero values combined with CoverageReport tell
// the checks whether a field is genuinely false or simply unseen.
type Organization struct {
	Login                 string `json:"login"`
	Name                  string `json:"name,omitempty"`
	ID                    int64  `json:"id"`
	DefaultRepoPermission string `json:"default_repo_permission,omitempty"` // base permission: read/write/admin/none
	TwoFactorRequired     bool   `json:"two_factor_required"`               // org-wide 2FA enforcement
	Plan                  string `json:"plan,omitempty"`                    // free | team | enterprise (owner-visible)

	// Owner-visible policy/security settings; nil = not visible to this token.
	MembersCanCreatePublicRepos *bool `json:"members_can_create_public_repos,omitempty"`
	MembersCanForkPrivateRepos  *bool `json:"members_can_fork_private_repos,omitempty"`
	SecretScanningDefault       *bool `json:"secret_scanning_default,omitempty"`   // for new repos
	PushProtectionDefault       *bool `json:"push_protection_default,omitempty"`   // for new repos
	DependabotAlertsDefault     *bool `json:"dependabot_alerts_default,omitempty"` // for new repos
	WebCommitSignoffRequired    *bool `json:"web_commit_signoff_required,omitempty"`
}

// Runner is a self-hosted Actions runner registered at the org level.
type Runner struct {
	ID     int64    `json:"id"`
	Name   string   `json:"name"`
	OS     string   `json:"os,omitempty"`
	Status string   `json:"status,omitempty"`
	Labels []string `json:"labels,omitempty"`
}

// Invitation is a pending organization membership invitation.
type Invitation struct {
	ID        int64      `json:"id,omitempty"`
	Login     string     `json:"login,omitempty"`
	Email     string     `json:"email,omitempty"`
	Role      string     `json:"role,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

// ActionsPolicy captures the org's GitHub Actions usage policy.
type ActionsPolicy struct {
	EnabledRepositories string `json:"enabled_repositories,omitempty"` // all | none | selected
	AllowedActions      string `json:"allowed_actions,omitempty"`      // all | local_only | selected
}

// OrgSecret is an organization-level Actions secret (name + visibility only; the
// value is never retrieved).
type OrgSecret struct {
	Name       string `json:"name"`
	Visibility string `json:"visibility"` // all | private | selected
}

// CredentialAuthorization is an SSO-authorized credential (classic PAT, SSH key,
// OAuth token) for a SAML-enabled org.
type CredentialAuthorization struct {
	CredentialID   int64      `json:"credential_id,omitempty"`
	Login          string     `json:"login"`
	CredentialType string     `json:"credential_type"`
	Scopes         []string   `json:"scopes,omitempty"`
	AccessedAt     *time.Time `json:"accessed_at,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}

// CopilotSeat is an assigned GitHub Copilot seat.
type CopilotSeat struct {
	Login          string     `json:"login"`
	LastActivityAt *time.Time `json:"last_activity_at,omitempty"` // nil = never used
	CreatedAt      *time.Time `json:"created_at,omitempty"`
}

// Member is a human member of the organization, enriched with governance flags.
// Pointer flags are nil when the data could not be collected (distinct from a
// confident false).
type Member struct {
	Login            string `json:"login"`
	ID               int64  `json:"id"`
	Role             string `json:"role,omitempty"`               // "admin" (owner) | "member"
	TwoFactorEnabled *bool  `json:"two_factor_enabled,omitempty"` // nil = unknown
	SAMLLinked       *bool  `json:"saml_linked,omitempty"`        // nil = unknown / SAML off
	SAMLNameID       string `json:"saml_name_id,omitempty"`       // IdP-asserted identity (usually corporate email)
	IsBot            bool   `json:"is_bot"`                       // GitHub account type == Bot
}

// Collaborator is an outside collaborator (not an org member) with repo access.
type Collaborator struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	IsBot bool   `json:"is_bot"`
}

// Team is an organization team. ParentSlug is empty for top-level teams; a
// non-empty value records nesting.
type Team struct {
	Slug       string `json:"slug"`
	Name       string `json:"name"`
	ID         int64  `json:"id"`
	ParentSlug string `json:"parent_slug,omitempty"`
	Privacy    string `json:"privacy,omitempty"` // "secret" | "closed"
	// Team-design detail, filled by the per-team collection pass (skipped in
	// --quick). nil/empty means "not collected" — checks gate on coverage.
	Members     []string        `json:"members,omitempty"`     // all member logins
	Maintainers []string        `json:"maintainers,omitempty"` // members with the maintainer role
	RepoGrants  []TeamRepoGrant `json:"repo_grants,omitempty"` // repos this team grants access to
}

// TeamRepoGrant is the access a team confers on a repository. Permission is
// normalized to read, triage, write, maintain, or admin.
type TeamRepoGrant struct {
	Repo       string `json:"repo"`
	Permission string `json:"permission"`
}

// RepoGrant is a permission granted directly to a user on a repository (i.e. not
// inherited through a team). Permission is normalized to one of:
// read, triage, write, maintain, admin.
type RepoGrant struct {
	Login      string `json:"login"`
	Permission string `json:"permission"`
	IsBot      bool   `json:"is_bot"`
}

// Repo is an organization repository plus the direct grants and machine
// credentials attached to it.
type Repo struct {
	Name                   string           `json:"name"`
	ID                     int64            `json:"id"`
	Private                bool             `json:"private"`
	Archived               bool             `json:"archived"`
	PushedAt               *time.Time       `json:"pushed_at,omitempty"` // last push; nil = never/unknown
	DefaultBranch          string           `json:"default_branch,omitempty"`
	DefaultBranchProtected *bool            `json:"default_branch_protected,omitempty"` // nil = unknown
	DirectCollaborators    []RepoGrant      `json:"direct_collaborators,omitempty"`
	DeployKeys             []DeployKey      `json:"deploy_keys,omitempty"`
	Webhooks               []Webhook        `json:"webhooks,omitempty"`
	BotCommitters          []CommitActivity `json:"bot_committers,omitempty"`
	SecretScanning         *bool            `json:"secret_scanning,omitempty"`    // nil = unknown
	PushProtection         *bool            `json:"push_protection,omitempty"`    // nil = unknown
	OpenSecretAlerts       *int             `json:"open_secret_alerts,omitempty"` // nil = unknown/unavailable
	// Dependabot vulnerability alerts. Enabled is nil when not assessed (insufficient
	// visibility); OpenDependabotAlerts is nil when alerts are off/unavailable, distinct
	// from an all-zero summary.
	DependabotAlertsEnabled *bool                   `json:"dependabot_alerts_enabled,omitempty"`
	OpenDependabotAlerts    *DependabotAlertSummary `json:"open_dependabot_alerts,omitempty"`
	// Classic branch-protection detail for the default branch. nil = not assessed
	// (unprotected, or protected via a ruleset which the classic endpoint can't see).
	BranchReqPRReview     *bool           `json:"branch_requires_pr_review,omitempty"`
	BranchAllowForcePush  *bool           `json:"branch_allows_force_push,omitempty"`
	BranchReqStatusChecks *bool           `json:"branch_requires_status_checks,omitempty"`
	WorkflowIssues        []WorkflowIssue `json:"workflow_issues,omitempty"`
	// Ownership signals. Properties holds this repo's org custom-property values
	// (lowercased keys). CodeownersPresent is nil when not assessed; CodeownersTeams
	// are the team references (@org/team) found in the CODEOWNERS file.
	Properties        map[string]string `json:"properties,omitempty"`
	CodeownersPresent *bool             `json:"codeowners_present,omitempty"`
	CodeownersTeams   []string          `json:"codeowners_teams,omitempty"`
}

// DependabotAlertSummary counts a repo's open Dependabot (vulnerability) alerts
// by advisory severity. A finding derives its severity from the highest band
// that is non-zero.
type DependabotAlertSummary struct {
	Critical int `json:"critical,omitempty"`
	High     int `json:"high,omitempty"`
	Medium   int `json:"medium,omitempty"`
	Low      int `json:"low,omitempty"`
}

// Total is the count of open alerts across all severities.
func (d DependabotAlertSummary) Total() int { return d.Critical + d.High + d.Medium + d.Low }

// WorkflowIssue is a supply-chain concern found in a repo's Actions workflow.
type WorkflowIssue struct {
	File   string `json:"file"`
	Kind   string `json:"kind"`   // "unpinned-action" | "pull-request-target"
	Detail string `json:"detail"` // e.g. the action reference
}

// Ruleset is an organization repository ruleset (the /settings/rules page):
// branch/tag/push protection applied across repos.
type Ruleset struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Target      string `json:"target"`      // "branch" | "tag" | "push"
	Enforcement string `json:"enforcement"` // "active" | "evaluate" | "disabled"
}

// CustomRole is a custom repository role defined on the org (the /settings/roles
// page), built on top of a base role with extra permissions.
type CustomRole struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	BaseRole    string   `json:"base_role"` // read | triage | write | maintain | admin
	Permissions []string `json:"permissions,omitempty"`
}

// OrgRole is an organization role (the /settings/organization-roles page, whose
// assignments live under /settings/org_role_assignments). Org roles grant
// org-wide or all-repo permissions independent of per-repo collaborator grants;
// Users and Teams record who holds the role and whether the grant is direct or
// inherited through a team.
type OrgRole struct {
	ID          int64              `json:"id"`
	Name        string             `json:"name"`
	BaseRole    string             `json:"base_role,omitempty"` // read | triage | write | maintain | admin (empty for org-only custom roles)
	Source      string             `json:"source,omitempty"`    // "Predefined" | "Organization" | "Enterprise"
	Permissions []string           `json:"permissions,omitempty"`
	Users       []OrgRoleAssignee  `json:"users,omitempty"`
	Teams       []OrgRoleTeamGrant `json:"teams,omitempty"`
}

// OrgRoleAssignee is a user holding an organization role.
type OrgRoleAssignee struct {
	Login      string `json:"login"`
	Assignment string `json:"assignment,omitempty"` // "direct" | "indirect" | "mixed"
	IsBot      bool   `json:"is_bot"`
}

// OrgRoleTeamGrant is a team holding an organization role; every member inherits
// the role's permissions.
type OrgRoleTeamGrant struct {
	Slug       string `json:"slug"`
	Assignment string `json:"assignment,omitempty"` // "direct" | "indirect"
}

// CommitActivity summarizes recent commits authored by a single machine/bot
// identity in a repository. Used to see which agents actually push code.
type CommitActivity struct {
	Login   string `json:"login"`   // e.g. "dependabot[bot]"
	Commits int    `json:"commits"` // commits by this identity in the scanned window
}

// AppInstallation is a GitHub App installed on the organization, with the
// permissions it was granted.
type AppInstallation struct {
	AppID               int64             `json:"app_id"`
	AppSlug             string            `json:"app_slug"`
	RepositorySelection string            `json:"repository_selection"` // "all" | "selected"
	Permissions         map[string]string `json:"permissions"`          // permission -> read|write|admin
}

// DeployKey is an SSH key granting access to a single repository.
type DeployKey struct {
	ID       int64  `json:"id"`
	Title    string `json:"title"`
	ReadOnly bool   `json:"read_only"`
}

// Webhook is an org- or repo-level webhook. The payload secret is never
// retrieved; HasSecret only reflects whether one is configured.
type Webhook struct {
	ID          int64    `json:"id"`
	URL         string   `json:"url"`
	Active      bool     `json:"active"`
	Events      []string `json:"events,omitempty"`
	HasSecret   bool     `json:"has_secret"`
	InsecureSSL bool     `json:"insecure_ssl"`
}

// PAT is a fine-grained personal access token with access to org resources.
// Only available when the org has the fine-grained PAT policy enabled.
type PAT struct {
	ID          int64             `json:"id"`
	OwnerLogin  string            `json:"owner_login"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"` // nil = never expires
	Permissions map[string]string `json:"permissions,omitempty"`
}

// ActionsTokenSettings captures the default GITHUB_TOKEN permission granted to
// workflow runs across the org.
type ActionsTokenSettings struct {
	DefaultWorkflowPermissions   string `json:"default_workflow_permissions"` // "read" | "write"
	CanApprovePullRequestReviews bool   `json:"can_approve_pull_request_reviews"`
}

// Snapshot is the immutable inventory collected from GitHub. Checks read it;
// they never mutate it. Fields fill in as more axes are implemented.
type Snapshot struct {
	Org            Organization   `json:"org"`
	Members        []Member       `json:"members,omitempty"`
	OutsideCollabs []Collaborator `json:"outside_collaborators,omitempty"`
	Teams          []Team         `json:"teams,omitempty"`
	Repos          []Repo         `json:"repos,omitempty"`

	AppInstallations         []AppInstallation         `json:"app_installations,omitempty"`
	OrgWebhooks              []Webhook                 `json:"org_webhooks,omitempty"`
	PATs                     []PAT                     `json:"fine_grained_pats,omitempty"`
	ActionsToken             ActionsTokenSettings      `json:"actions_token"`
	OrgRulesets              []Ruleset                 `json:"org_rulesets,omitempty"`
	CustomRoles              []CustomRole              `json:"custom_roles,omitempty"`
	OrgRoles                 []OrgRole                 `json:"org_roles,omitempty"`
	SelfHostedRunners        []Runner                  `json:"self_hosted_runners,omitempty"`
	PendingInvitations       []Invitation              `json:"pending_invitations,omitempty"`
	ActionsPolicy            ActionsPolicy             `json:"actions_policy"`
	OrgSecrets               []OrgSecret               `json:"org_secrets,omitempty"`
	CredentialAuthorizations []CredentialAuthorization `json:"credential_authorizations,omitempty"`
	CopilotSeats             []CopilotSeat             `json:"copilot_seats,omitempty"`

	// AccountTwoFactor is the authenticated user's own 2FA state (user/--me mode).
	AccountTwoFactor *bool `json:"account_two_factor,omitempty"`

	// CompanyDomains is audit configuration (not collected): the email domains
	// considered to belong to the organization, used by the email-domain check.
	CompanyDomains []string `json:"company_domains,omitempty"`
	// StaleAfter is the age past which a repo with no pushes is considered stale.
	// Audit configuration; zero means "use the check default".
	StaleAfter time.Duration `json:"-"`
	// OwningTeamProperty is the custom-property name expected to name a repo's
	// owning team. Audit configuration; empty means "use the check default".
	OwningTeamProperty string `json:"-"`
	// Solo forces single-developer mode: suggested branch-protection fixes never
	// require an approving review (you cannot approve your own PR). Audit config.
	Solo bool `json:"-"`

	Coverage    *CoverageReport `json:"-"`
	CollectedAt time.Time       `json:"collected_at"`
}

// NewSnapshot returns an empty snapshot for an org with an initialized coverage
// report.
func NewSnapshot(org string) *Snapshot {
	return &Snapshot{
		Org:      Organization{Login: org},
		Coverage: NewCoverageReport(),
	}
}

// Owners returns members with the org owner (admin) role.
func (s *Snapshot) Owners() []Member {
	var out []Member
	for _, m := range s.Members {
		if m.Role == "admin" {
			out = append(out, m)
		}
	}
	return out
}
