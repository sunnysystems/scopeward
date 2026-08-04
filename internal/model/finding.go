package model

// ResourceRef identifies what a finding is about: a member, repo, team, app, or
// the org itself. Kept generic so any check can point at any GitHub entity.
type ResourceRef struct {
	Type string `json:"type"` // "member", "repo", "team", "app", "org", ...
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// Finding is a single governance issue produced by a check. Checks are pure
// functions over a Snapshot, so a Finding carries everything needed to render
// it without re-querying GitHub.
type Finding struct {
	CheckID     string         `json:"check_id"` // stable id, e.g. "human.no-2fa"
	Title       string         `json:"title"`
	Severity    Severity       `json:"severity"`
	Axis        Axis           `json:"axis"`
	Resource    ResourceRef    `json:"resource"`
	Evidence    map[string]any `json:"evidence,omitempty"`    // raw data backing the finding
	Description string         `json:"description"`           // what it is and why it matters
	Remediation string         `json:"remediation,omitempty"` // advice only — the tool never writes
	GHFix       string         `json:"gh_fix,omitempty"`      // suggested `gh` command(s), newline-separated (NOT run by scopeward)
	GHVerify    string         `json:"gh_verify,omitempty"`   // read-only `gh` command to confirm the fix took effect
	// GHScopes are the token scopes GHFix needs. Declared by the fix that builds
	// the command rather than inferred from its text, so the fix script can state
	// up front which of them the current token is missing instead of letting the
	// operator discover it one failed command at a time.
	GHScopes []string `json:"gh_scopes,omitempty"`
	DocsURL  string   `json:"docs_url,omitempty"`
	// Policy marks a finding produced by an invariant the organization declared,
	// rather than by a product default. The two make different claims — "this
	// violates what you decided" versus "this is unusual" — and only the first
	// settles a review, so a reader has to be able to tell them apart.
	Policy bool `json:"policy,omitempty"`
}
