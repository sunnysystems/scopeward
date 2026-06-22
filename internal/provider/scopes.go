package provider

import "sort"

// Recommended read-only scopes that unlock a full audit. Missing ones don't fail
// the run — affected checks degrade to "not evaluated" — but the preflight
// surfaces the gap up front.
var (
	githubRecommendedScopes = []string{
		"read:org",  // org members, teams, base permissions
		"repo",      // private repo metadata, collaborators, deploy keys, webhooks
		"admin:org", // 2FA status, SSO, org-level apps/PATs (read paths)
		"read:user", // member profile / activity signals
	}
	gitlabRecommendedScopes = []string{
		"read_api",  // read-only access to groups, projects, members, settings
		"read_user", // the authenticated user's profile
	}
)

func missingGitHubScopes(scopes []string) []string {
	return missing(scopes, githubRecommendedScopes, githubSatisfiedByParent)
}

func missingGitLabScopes(scopes []string) []string {
	return missing(scopes, gitlabRecommendedScopes, gitlabSatisfiedByParent)
}

// missing returns the recommended scopes absent from the granted set. When no
// scopes are reported we cannot judge coverage, so we return nothing.
func missing(scopes, recommended []string, satisfiedByParent func(string, map[string]bool) bool) []string {
	if len(scopes) == 0 {
		return nil
	}
	have := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		have[s] = true
	}
	var out []string
	for _, want := range recommended {
		if !have[want] && !satisfiedByParent(want, have) {
			out = append(out, want)
		}
	}
	sort.Strings(out)
	return out
}

// githubSatisfiedByParent treats a broader granted scope as covering a narrower
// one (e.g. admin:org implies read:org).
func githubSatisfiedByParent(want string, have map[string]bool) bool {
	switch want {
	case "read:org":
		return have["admin:org"]
	case "read:user":
		return have["user"]
	}
	return false
}

// gitlabSatisfiedByParent treats the full "api" scope as covering every read
// scope it supersedes.
func gitlabSatisfiedByParent(_ string, have map[string]bool) bool {
	return have["api"]
}
