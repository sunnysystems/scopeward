package model

import "sync"

// DataKind names a slice of the inventory a collector is responsible for. Checks
// declare which kinds they need; the runner skips a check when its kind was not
// collected, emitting "not evaluated" instead of a false pass.
type DataKind string

const (
	DataOrg                  DataKind = "org"
	DataMembers              DataKind = "members"
	DataMember2FA            DataKind = "members.2fa"
	DataMemberRoles          DataKind = "members.roles"
	DataSAMLIdentities       DataKind = "members.saml"
	DataOutsideCollaborators DataKind = "outside_collaborators"

	DataTeams                   DataKind = "teams"
	DataTeamMembers             DataKind = "teams.members"
	DataTeamRepos               DataKind = "teams.repos"
	DataCustomProperties        DataKind = "repos.custom_properties"
	DataCodeowners              DataKind = "repos.codeowners"
	DataRepos                   DataKind = "repos"
	DataRepoDirectCollaborators DataKind = "repos.direct_collaborators"

	DataAppInstallations    DataKind = "app_installations"
	DataActionsTokenDefault DataKind = "actions.token_default"
	DataDeployKeys          DataKind = "repos.deploy_keys"
	DataOrgWebhooks         DataKind = "org_webhooks"
	DataRepoWebhooks        DataKind = "repos.webhooks"
	DataFineGrainedPATs     DataKind = "fine_grained_pats"

	DataCommitAuthors DataKind = "repos.commit_authors"

	DataBranchProtection         DataKind = "repos.branch_protection"
	DataOrgRulesets              DataKind = "org_rulesets"
	DataCustomRoles              DataKind = "custom_roles"
	DataOrgRoles                 DataKind = "org_roles"
	DataSelfHostedRunners        DataKind = "self_hosted_runners"
	DataPendingInvitations       DataKind = "pending_invitations"
	DataActionsPolicy            DataKind = "actions_policy"
	DataRepoSecurity             DataKind = "repos.security_analysis"
	DataOrgSecrets               DataKind = "org_secrets"
	DataCredentialAuthorizations DataKind = "credential_authorizations"
	DataCopilotSeats             DataKind = "copilot_seats"
	DataOpenSecretAlerts         DataKind = "repos.open_secret_alerts"
	DataDependabotEnabled        DataKind = "repos.dependabot_enabled"
	DataOpenDependabotAlerts     DataKind = "repos.open_dependabot_alerts"
	DataWorkflows                DataKind = "repos.workflows"

	DataAccount DataKind = "account" // authenticated user's own account facts

	DataCompanyDomains DataKind = "config.company_domains"
)

// CoverageStatus says how completely a DataKind was collected.
type CoverageStatus string

const (
	CoverageOK      CoverageStatus = "ok"      // fully collected
	CoveragePartial CoverageStatus = "partial" // some data, with caveats
	CoverageMissing CoverageStatus = "missing" // could not be collected at all
)

// Coverage is the outcome of trying to collect one DataKind.
type Coverage struct {
	Kind   DataKind       `json:"kind"`
	Status CoverageStatus `json:"status"`
	Reason string         `json:"reason,omitempty"` // why partial/missing (scope, feature off, ...)
	Count  int            `json:"count,omitempty"`  // how many items, when meaningful
}

// CoverageReport is a thread-safe set of Coverage entries, written concurrently
// by collectors and read by the check runner and renderers.
type CoverageReport struct {
	mu    sync.Mutex
	items map[DataKind]Coverage
}

// NewCoverageReport returns an empty report.
func NewCoverageReport() *CoverageReport {
	return &CoverageReport{items: make(map[DataKind]Coverage)}
}

// Set records (or overwrites) the coverage for a DataKind.
func (r *CoverageReport) Set(c Coverage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items[c.Kind] = c
}

// OK is a shortcut for a fully-collected kind.
func (r *CoverageReport) OK(kind DataKind, count int) {
	r.Set(Coverage{Kind: kind, Status: CoverageOK, Count: count})
}

// Missing is a shortcut for a kind that could not be collected.
func (r *CoverageReport) Missing(kind DataKind, reason string) {
	r.Set(Coverage{Kind: kind, Status: CoverageMissing, Reason: reason})
}

// Partial is a shortcut for a kind collected with caveats.
func (r *CoverageReport) Partial(kind DataKind, count int, reason string) {
	r.Set(Coverage{Kind: kind, Status: CoveragePartial, Count: count, Reason: reason})
}

// Get returns the coverage for a kind and whether it was recorded.
func (r *CoverageReport) Get(kind DataKind) (Coverage, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.items[kind]
	return c, ok
}

// Available reports whether a kind was collected well enough to evaluate checks
// against it (ok or partial).
func (r *CoverageReport) Available(kind DataKind) bool {
	c, ok := r.Get(kind)
	return ok && c.Status != CoverageMissing
}

// All returns a copy of every recorded coverage entry.
func (r *CoverageReport) All() []Coverage {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Coverage, 0, len(r.items))
	for _, c := range r.items {
		out = append(out, c)
	}
	return out
}
