package model

// Role is the provider-neutral access level a principal holds on a repository or
// scope. The canonical vocabulary is GitHub's repository-role scale, which the
// checks already speak; other providers normalize into it at collection time so
// the same pure checks evaluate either forge.
//
// Permission/base-role string fields elsewhere in the model (TeamRepoGrant,
// RepoGrant, CustomRole, OrgRole) carry these same values; they stay typed as
// string for now so existing checks and serialized output are unchanged.
type Role string

const (
	RoleRead     Role = "read"
	RoleTriage   Role = "triage"
	RoleWrite    Role = "write"
	RoleMaintain Role = "maintain"
	RoleAdmin    Role = "admin"
)

// Rank orders the canonical roles so checks can reason about "at least write"
// without hard-coding a provider's ladder: read=1 … admin=5. An unrecognized
// role ranks 0, below every known level.
func (r Role) Rank() int {
	switch r {
	case RoleRead:
		return 1
	case RoleTriage:
		return 2
	case RoleWrite:
		return 3
	case RoleMaintain:
		return 4
	case RoleAdmin:
		return 5
	default:
		return 0
	}
}

// GitLab access levels (the integer scale the GitLab API returns for members).
const (
	GitLabGuest      = 10
	GitLabReporter   = 20
	GitLabDeveloper  = 30
	GitLabMaintainer = 40
	GitLabOwner      = 50
)

// RoleFromGitLabAccessLevel maps a GitLab access level onto the canonical Role
// scale so a GitLab collector emits values the existing checks understand:
//
//	Guest 10      → read
//	Reporter 20   → triage
//	Developer 30  → write
//	Maintainer 40 → maintain
//	Owner 50      → admin
//
// Levels at or above Owner map to admin; an unknown/zero level returns "" so the
// caller can record a coverage gap rather than imply a confident least-privilege
// result. (GitLab's Reporter has no exact GitHub twin; triage is the closest
// read-plus-light-triage analogue.)
func RoleFromGitLabAccessLevel(level int) Role {
	switch {
	case level >= GitLabOwner:
		return RoleAdmin
	case level >= GitLabMaintainer:
		return RoleMaintain
	case level >= GitLabDeveloper:
		return RoleWrite
	case level >= GitLabReporter:
		return RoleTriage
	case level >= GitLabGuest:
		return RoleRead
	default:
		return ""
	}
}
