package model

import "time"

// Policy is what the organization decided, as distinct from what the product
// thinks. Every finding a fixed check produces says at most "this is unusual";
// a policy says "this violates what we agreed", which is the only sentence that
// gates a pipeline without argument and the only review that converges.
//
// Design constraint: invariants, not inventory. A policy declares *predicates*
// ("no repository admin outside team X"), never *resources* ("user U is admin on
// repo R"). Writing desired state is infrastructure-as-code's job and tools that
// apply state already do it well; scopeward asserts properties of whatever
// state exists. If a policy block starts needing one entry per repository, the
// design has drifted and should be reconsidered rather than extended.
//
// Lives in model rather than in the config package so checks — which are pure
// functions over a Snapshot — can read it without importing the CLI.
type Policy struct {
	// Version is the schema version, so the shape can evolve without silently
	// reinterpreting an older file.
	Version int `yaml:"version" json:"version"`

	Thresholds PolicyThresholds `yaml:"thresholds" json:"thresholds,omitempty"`
	Invariants PolicyInvariants `yaml:"invariants" json:"invariants,omitempty"`
}

// PolicyThresholds override numbers that checks otherwise hardcode. Those
// defaults are product opinions applied uniformly, which is the right default
// and the wrong final answer: an org that decided 60 days should be measured
// against its own decision, not against ours.
//
// Pointers throughout, because zero is a meaningful value and "unset" has to be
// distinguishable from "set to zero".
type PolicyThresholds struct {
	DormantAfterDays   *int `yaml:"dormant_after_days" json:"dormant_after_days,omitempty"`
	StaleRepoAfterDays *int `yaml:"stale_repo_after_days" json:"stale_repo_after_days,omitempty"`
	MaxTeams           *int `yaml:"max_teams" json:"max_teams,omitempty"`
}

// PolicyInvariants are properties the org asserts. Each produces findings of its
// own when violated, distinct in every output from product-default findings —
// a reader has to be able to tell org opinion from tool opinion.
type PolicyInvariants struct {
	// RepoAdminOnlyFromTeam names the single team allowed to confer repository
	// admin. Any other source — a direct grant or another team's grant — is a
	// violation. No fixed check can know which team that is.
	RepoAdminOnlyFromTeam string `yaml:"repo_admin_only_from_team" json:"repo_admin_only_from_team,omitempty"`

	// PublicRepos is the allowlist of repositories permitted to be public. A nil
	// slice means the invariant was not declared; an empty one means no
	// repository may be public, which is a real and different assertion.
	PublicRepos *[]string `yaml:"public_repos" json:"public_repos,omitempty"`

	// ForbidDirectCollaborators asserts that access comes through teams only.
	ForbidDirectCollaborators bool `yaml:"forbid_direct_collaborators" json:"forbid_direct_collaborators,omitempty"`

	// RequireOwningTeam asserts every repository has an owning team.
	RequireOwningTeam bool `yaml:"require_owning_team" json:"require_owning_team,omitempty"`
}

// Declared reports whether a policy carries anything at all. A file with an
// empty policy block is not an error, but nothing should claim to be measuring
// against it either.
func (p *Policy) Declared() bool {
	if p == nil {
		return false
	}
	t, i := p.Thresholds, p.Invariants
	return t.DormantAfterDays != nil || t.StaleRepoAfterDays != nil || t.MaxTeams != nil ||
		i.RepoAdminOnlyFromTeam != "" || i.PublicRepos != nil ||
		i.ForbidDirectCollaborators || i.RequireOwningTeam
}

// supersededBy maps a product check to the invariant that replaces it. When the
// org has declared its own rule on a concern, reporting both the product's
// opinion and the org's would double-count one problem and make the report argue
// with itself. The org's rule wins: it is the one a review can act on.
//
// Kept as an explicit table rather than inferred, because a silent overlap
// between a new invariant and an existing check is exactly the kind of drift
// nobody notices until the score moves.
var supersededBy = map[string]func(PolicyInvariants) bool{
	"teams.repo-no-owning-team": func(i PolicyInvariants) bool { return i.RequireOwningTeam },
	"perms.direct-admin-grant":  func(i PolicyInvariants) bool { return i.ForbidDirectCollaborators },
	"perms.direct-repo-grant":   func(i PolicyInvariants) bool { return i.ForbidDirectCollaborators },
}

// Supersedes reports whether a declared invariant replaces this product check.
func (p *Policy) Supersedes(checkID string) bool {
	if p == nil {
		return false
	}
	fn, ok := supersededBy[checkID]
	return ok && fn(p.Invariants)
}

// PolicySuperseded returns whether the snapshot's policy replaces this check,
// so a check can stand down in one line.
func (s *Snapshot) PolicySuperseded(checkID string) bool {
	return s.Policy.Supersedes(checkID)
}

// DormantAfter is the inactivity window for the dormant-member check: the org's
// declared value when it set one, otherwise the argument (the product default).
func (s *Snapshot) DormantAfter(def time.Duration) time.Duration {
	if s.Policy != nil && s.Policy.Thresholds.DormantAfterDays != nil {
		return time.Duration(*s.Policy.Thresholds.DormantAfterDays) * 24 * time.Hour
	}
	return def
}
