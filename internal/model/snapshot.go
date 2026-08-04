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
	// Member privileges over repositories that already exist. Distinct from the
	// creation toggles above: these act on the repos holding the org's history.
	MembersCanChangeRepoVisibility *bool `json:"members_can_change_repo_visibility,omitempty"`
	MembersCanDeleteRepos          *bool `json:"members_can_delete_repos,omitempty"`
	MembersCanInviteOutsideCollabs *bool `json:"members_can_invite_outside_collaborators,omitempty"`
	SecretScanningDefault          *bool `json:"secret_scanning_default,omitempty"`   // for new repos
	PushProtectionDefault          *bool `json:"push_protection_default,omitempty"`   // for new repos
	DependabotAlertsDefault        *bool `json:"dependabot_alerts_default,omitempty"` // for new repos
	WebCommitSignoffRequired       *bool `json:"web_commit_signoff_required,omitempty"`
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
	// LastActiveAt is the member's last activity timestamp, when the provider
	// exposes it (GitLab last_activity_on, instance-admin-only). nil = unknown /
	// not collected; the dormant-member check gates on DataMemberActivity coverage.
	LastActiveAt *time.Time `json:"last_active_at,omitempty"`
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
	BranchReqPRReview     *bool `json:"branch_requires_pr_review,omitempty"`
	BranchAllowForcePush  *bool `json:"branch_allows_force_push,omitempty"`
	BranchReqStatusChecks *bool `json:"branch_requires_status_checks,omitempty"`
	// BranchEnforceAdmins reports whether the protection also applies to
	// administrators. false means every org owner and repo admin can push straight
	// to the protected branch, so the protection is bypassable by exactly the
	// identities that most need it.
	BranchEnforceAdmins *bool `json:"branch_enforce_admins,omitempty"`
	// BranchProtectionSource records which mechanism the assessed rules came from.
	// Empty = not assessed. It matters for remediation: a ruleset is edited at
	// repository or organization level, and applying classic branch protection on
	// top of one adds a second, parallel mechanism rather than fixing the weak rule.
	BranchProtectionSource string          `json:"branch_protection_source,omitempty"`
	WorkflowIssues         []WorkflowIssue `json:"workflow_issues,omitempty"`
	// Ownership signals. Properties holds this repo's org custom-property values
	// (lowercased keys). CodeownersPresent is nil when not assessed; CodeownersTeams
	// are the team references (@org/team) found in the CODEOWNERS file.
	Properties        map[string]string `json:"properties,omitempty"`
	CodeownersPresent *bool             `json:"codeowners_present,omitempty"`
	CodeownersTeams   []string          `json:"codeowners_teams,omitempty"`
	// JobTokenInboundEnabled reports whether this project enforces the
	// CI_JOB_TOKEN inbound allowlist (GitLab): true = only allowlisted projects'
	// job tokens may access it; false = any project's token can. nil = unknown.
	JobTokenInboundEnabled *bool `json:"job_token_inbound_enabled,omitempty"`
	// GitLab merge-request approval settings (Premium). nil = not collected (Free
	// tier or insufficient access), so the approval check reports "not evaluated".
	// MRApprovalsRequired feeds the neutral BranchReqPRReview (>=1 → review required).
	MRApprovalsRequired       *int  `json:"mr_approvals_required,omitempty"`
	MRAuthorCanApprove        *bool `json:"mr_author_can_approve,omitempty"`      // true = author may approve own MR
	MRResetApprovalsOnPush    *bool `json:"mr_reset_approvals_on_push,omitempty"` // false = stale approvals survive a new push
	CodeOwnerApprovalRequired *bool `json:"code_owner_approval_required,omitempty"`
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

// The mechanisms that can guard a branch. GitHub is steadily moving orgs from
// classic branch protection to rulesets, so an assessment that only understood
// the classic endpoint would go blind as that migration proceeds.
const (
	BranchProtectionClassic = "classic"
	BranchProtectionRuleset = "ruleset"
)

// WorkflowIssue is a supply-chain concern found in a repo's Actions workflow.
type WorkflowIssue struct {
	File   string `json:"file"`
	Kind   string `json:"kind"`   // "unpinned-action" | "internal-unpinned-action" | "pull-request-target"
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
	ID        int64      `json:"id"`
	Title     string     `json:"title"`
	ReadOnly  bool       `json:"read_only"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // nil = never expires / not exposed
}

// AccessToken is a scoped, expiring API credential not tied to an interactive
// login. GitLab populates it from personal, project, and group access tokens;
// the neutral shape (scopes, expiry, last use, active/revoked) lets the same
// no-expiry / broad-scope / staleness checks evaluate any provider that fills it.
type AccessToken struct {
	ID         int64      `json:"id"`
	ScopeID    int64      `json:"scope_id,omitempty"` // project/group numeric id (0 for personal); the revoke path needs it
	Name       string     `json:"name,omitempty"`
	Kind       string     `json:"kind"`             // "personal" | "project" | "group"
	Holder     string     `json:"holder,omitempty"` // owner username or project/group full path
	Scopes     []string   `json:"scopes,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`   // nil = never expires
	LastUsedAt *time.Time `json:"last_used_at,omitempty"` // nil = never used / not exposed
	CreatedAt  *time.Time `json:"created_at,omitempty"`
	Active     bool       `json:"active"`
	Revoked    bool       `json:"revoked"`
}

// DeployToken is a GitLab deploy token: a project- or group-scoped credential
// (a username plus repository/registry scopes) used by automation. Unlike an
// access token it has no per-token last-use, and the API never reveals the
// secret.
type DeployToken struct {
	ID        int64      `json:"id"`
	ScopeID   int64      `json:"scope_id,omitempty"` // owning project/group numeric id
	Name      string     `json:"name"`
	Username  string     `json:"username,omitempty"`
	Kind      string     `json:"kind"`             // "project" | "group"
	Holder    string     `json:"holder,omitempty"` // owning project/group full path
	Scopes    []string   `json:"scopes,omitempty"` // read_repository, write_repository, read_registry, ...
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Revoked   bool       `json:"revoked"`
}

// OAuthApp is an OAuth application registered on the instance. Enumeration is
// instance-admin-only on GitLab, so it is usually not collected; when it is,
// Trusted (skips the user consent screen) and Confidential are the risk signals.
type OAuthApp struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	CallbackURL  string `json:"callback_url,omitempty"`
	Confidential bool   `json:"confidential"`
	Trusted      bool   `json:"trusted"`
}

// CIVariable is a GitLab CI/CD variable defined on a project or group. The value
// is never collected. Protected limits the variable to pipelines on protected
// branches/tags; Masked hides it in job logs; Hidden (17.4+) also prevents the
// value from being read back via the API; EnvironmentScope ("*" = all) bounds
// which environments may use it.
type CIVariable struct {
	Key              string `json:"key"`
	Kind             string `json:"kind"`             // "project" | "group"
	Holder           string `json:"holder,omitempty"` // owning project/group full path
	ScopeID          int64  `json:"scope_id,omitempty"`
	VariableType     string `json:"variable_type,omitempty"` // "env_var" | "file"
	Protected        bool   `json:"protected"`
	Masked           bool   `json:"masked"`
	Hidden           bool   `json:"hidden,omitempty"`
	EnvironmentScope string `json:"environment_scope,omitempty"`
}

// CIRunner is a GitLab CI runner. RunnerType is instance_type (shared across all
// projects), group_type, or project_type. RefProtected reports whether the
// runner only picks up jobs from protected branches/tags; Online and the other
// fields come from the runner detail endpoint.
type CIRunner struct {
	ID           int64    `json:"id"`
	Description  string   `json:"description,omitempty"`
	RunnerType   string   `json:"runner_type,omitempty"` // instance_type | group_type | project_type
	Shared       bool     `json:"shared"`                // instance_type: available to every project
	RefProtected bool     `json:"ref_protected"`         // access_level == ref_protected
	Locked       bool     `json:"locked"`
	Online       *bool    `json:"online,omitempty"` // nil = unknown
	TagList      []string `json:"tag_list,omitempty"`
	Holder       string   `json:"holder,omitempty"` // owning group/project path (group/project runners)
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

// Snapshot is the immutable inventory collected from a forge. Checks read it;
// they never mutate it. Fields fill in as more axes are implemented.
//
// The model is provider-neutral: the same pure checks evaluate a GitHub- or
// GitLab-collected snapshot. A handful of fields below have no equivalent on
// every provider (see the GitHub-only group); a collector simply leaves them
// empty and records no coverage for them, so the checks that need them are
// skipped as "not evaluated" rather than silently passing.
type Snapshot struct {
	// Provider records which forge this was collected from; Host is the base
	// host for self-managed instances (empty = the provider's SaaS default).
	Provider Provider `json:"provider,omitempty"`
	Host     string   `json:"host,omitempty"`

	Org            Organization   `json:"org"`
	Members        []Member       `json:"members,omitempty"`
	OutsideCollabs []Collaborator `json:"outside_collaborators,omitempty"`
	Teams          []Team         `json:"teams,omitempty"`
	Repos          []Repo         `json:"repos,omitempty"`

	OrgWebhooks        []Webhook    `json:"org_webhooks,omitempty"`
	OrgRulesets        []Ruleset    `json:"org_rulesets,omitempty"`
	SelfHostedRunners  []Runner     `json:"self_hosted_runners,omitempty"`
	PendingInvitations []Invitation `json:"pending_invitations,omitempty"`
	OrgSecrets         []OrgSecret  `json:"org_secrets,omitempty"`

	// Provider-neutral scoped credentials. Currently populated by GitLab
	// (personal/project/group access tokens, deploy tokens, OAuth apps); a
	// GitHub collector leaves them empty and records no coverage, so their
	// checks are skipped rather than reported clean.
	AccessTokens []AccessToken `json:"access_tokens,omitempty"`
	DeployTokens []DeployToken `json:"deploy_tokens,omitempty"`
	OAuthApps    []OAuthApp    `json:"oauth_apps,omitempty"`

	// GitLab CI/CD hardening (#7): project & group CI/CD variables and runners.
	// The per-project CI_JOB_TOKEN allowlist lives on each Repo.
	CIVariables []CIVariable `json:"ci_variables,omitempty"`
	CIRunners   []CIRunner   `json:"ci_runners,omitempty"`

	// GitHub-only: concepts with no GitLab equivalent. A non-GitHub collector
	// leaves these empty and records no coverage for them, so the checks that
	// read them are skipped (not evaluated) rather than reported as clean.
	//   - AppInstallations: GitHub Apps (GitLab has no equivalent).
	//   - PATs: fine-grained PAT policy (GitHub-specific shape/visibility).
	//   - ActionsToken / ActionsPolicy: GitHub Actions GITHUB_TOKEN + usage policy.
	//   - CustomRoles / OrgRoles: GitHub custom repo roles & organization roles.
	//   - CredentialAuthorizations: SAML SSO-authorized credentials (GitHub SAML).
	//   - CopilotSeats: GitHub Copilot billing.
	AppInstallations         []AppInstallation         `json:"app_installations,omitempty"`
	PATs                     []PAT                     `json:"fine_grained_pats,omitempty"`
	ActionsToken             ActionsTokenSettings      `json:"actions_token"`
	ActionsPolicy            ActionsPolicy             `json:"actions_policy"`
	CustomRoles              []CustomRole              `json:"custom_roles,omitempty"`
	OrgRoles                 []OrgRole                 `json:"org_roles,omitempty"`
	CredentialAuthorizations []CredentialAuthorization `json:"credential_authorizations,omitempty"`
	CopilotSeats             []CopilotSeat             `json:"copilot_seats,omitempty"`

	// AccountTwoFactor is the authenticated user's own 2FA state (user/--me mode).
	AccountTwoFactor *bool `json:"account_two_factor,omitempty"`

	// Entitlements are the paid capabilities we probed for. Read through
	// Snapshot.Entitlement, which answers Unknown for anything unrecorded.
	Entitlements map[Entitlement]EntitlementStatus `json:"entitlements,omitempty"`

	// The fields below are provider-neutral audit configuration (not collected
	// from any forge); they apply identically to every provider.
	//
	// CompanyDomains is the set of email domains considered to belong to the
	// organization, used by the email-domain check.
	CompanyDomains []string `json:"company_domains,omitempty"`
	// StaleAfter is the age past which a repo with no pushes is considered stale.
	// Audit configuration; zero means "use the check default".
	StaleAfter time.Duration `json:"-"`
	// OwningTeamProperty is the custom-property name expected to name a repo's
	// owning team. Audit configuration; empty means "use the check default".
	OwningTeamProperty string `json:"-"`
	// DuplicateRosterSimilarity is the Jaccard threshold at which two teams count
	// as holding the same people. Audit configuration; zero means "use the check
	// default". How much overlap is redundancy rather than legitimate structure
	// depends on how the org draws its teams, so it is an opinion the org can set.
	DuplicateRosterSimilarity float64 `json:"-"`
	// Solo forces single-developer mode: suggested branch-protection fixes never
	// require an approving review (you cannot approve your own PR). Audit config.
	Solo bool `json:"-"`
	// Policy is what the organization declared in .scopeward.yml, as distinct
	// from what the product thinks. nil when no policy block is present, which
	// checks must read as "use the product default" — see policy.go.
	Policy *Policy `json:"-"`

	Coverage    *CoverageReport `json:"-"`
	CollectedAt time.Time       `json:"collected_at"`
}

// NewSnapshot returns an empty snapshot for an org with an initialized coverage
// report. The provider defaults to GitHub; collectors for other forges set
// Provider (and Host) explicitly.
func NewSnapshot(org string) *Snapshot {
	return &Snapshot{
		Provider: ProviderGitHub,
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
