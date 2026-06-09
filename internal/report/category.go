package report

// Action categories group checks by the kind of remediation they call for,
// cutting across the governance axes. They drive the dashboard's "by category"
// breakdown: where the axes answer "which area of GitHub", categories answer
// "what kind of action fixes this". This is a curated, presentation-only map —
// adjust freely as checks are added; anything unmapped falls under "Other".
var checkCategory = map[string]string{
	// Branch protection — merge gates, required reviews, protected branches.
	"teams.unprotected-default-branch": "Branch protection",
	"teams.weak-branch-protection":     "Branch protection",
	"teams.ruleset-not-enforced":       "Branch protection",
	"ai.agent-on-unprotected-branch":   "Branch protection",

	// Vulnerability remediation — known-vulnerable dependencies.
	"codesecurity.open-dependabot-alerts":     "Vulnerability remediation",
	"codesecurity.repo-dependabot-alerts-off": "Vulnerability remediation",

	// Secret protection — secret scanning, push protection, webhook/secret exposure.
	"codesecurity.open-secret-alerts":      "Secret protection",
	"codesecurity.repo-no-push-protection": "Secret protection",
	"nonhuman.org-secret-visible-all":      "Secret protection",
	"nonhuman.org-webhook-insecure":        "Secret protection",
	"nonhuman.repo-webhook-insecure":       "Secret protection",

	// Supply chain security — Actions workflows, runners, tokens.
	"supplychain.unpinned-action":          "Supply chain security",
	"supplychain.pull-request-target":      "Supply chain security",
	"nonhuman.actions-policy-open":         "Supply chain security",
	"nonhuman.actions-token-write-default": "Supply chain security",
	"nonhuman.actions-can-approve-prs":     "Supply chain security",
	"nonhuman.self-hosted-runner":          "Supply chain security",

	// Access management — repo/org permissions, roles, direct grants.
	"perms.direct-admin-grant":   "Access management",
	"perms.direct-repo-grant":    "Access management",
	"perms.org-role-elevated":    "Access management",
	"perms.org-wide-admin":       "Access management",
	"perms.org-wide-write":       "Access management",
	"teams.base-permission-open": "Access management",
	"teams.custom-role-elevated": "Access management",
	"nonhuman.org-role-grant":    "Access management",

	// Non-human credentials — apps, PATs, deploy keys.
	"nonhuman.app-broad-permissions":   "Non-human credentials",
	"nonhuman.classic-pat-broad-scope": "Non-human credentials",
	"nonhuman.pat-no-expiry":           "Non-human credentials",
	"nonhuman.deploy-key-write":        "Non-human credentials",

	// Identity & 2FA — human accounts, SSO, two-factor, offboarding.
	"account.no-2fa":              "Identity & 2FA",
	"human.no-2fa":                "Identity & 2FA",
	"human.owner-without-2fa":     "Identity & 2FA",
	"human.org-2fa-not-enforced":  "Identity & 2FA",
	"human.not-sso-linked":        "Identity & 2FA",
	"human.email-outside-company": "Identity & 2FA",
	"human.outside-collaborator":  "Identity & 2FA",
	"human.stale-invitation":      "Identity & 2FA",
	"human.owner-sprawl":          "Identity & 2FA",

	// Team & ownership structure — team design, repo ownership, member powers.
	"teams.deep-nesting":                    "Team & ownership structure",
	"teams.sprawl":                          "Team & ownership structure",
	"teams.empty":                           "Team & ownership structure",
	"teams.ghost":                           "Team & ownership structure",
	"teams.orphan":                          "Team & ownership structure",
	"teams.singleton":                       "Team & ownership structure",
	"teams.size-tier-advice":                "Team & ownership structure",
	"teams.repo-no-owning-team":             "Team & ownership structure",
	"teams.repo-no-owning-property":         "Team & ownership structure",
	"teams.repo-no-codeowner":               "Team & ownership structure",
	"teams.members-can-create-public-repos": "Team & ownership structure",
	"teams.members-can-fork-private-repos":  "Team & ownership structure",

	// AI agent governance — machine identities committing code.
	"ai.agent-broad-write":       "AI agent governance",
	"ai.agent-inventory":         "AI agent governance",
	"ai.unidentified-committer":  "AI agent governance",
	"ai.copilot-seat-inactive":   "AI agent governance",
	"ai.copilot-seat-non-member": "AI agent governance",

	// Repository hygiene — stale/abandoned repositories.
	"hygiene.stale-repo": "Repository hygiene",
}

const otherCategory = "Other"

// categoryOf returns the action category for a check, or "Other" if unmapped.
func categoryOf(checkID string) string {
	if c, ok := checkCategory[checkID]; ok {
		return c
	}
	return otherCategory
}
