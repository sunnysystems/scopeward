package checks

import "fmt"

// Builders for suggested `gh` (GitHub CLI) remediation commands. scopeward is
// read-only and never runs these — they are copy-paste suggestions the operator
// reviews and runs themselves. They assume `gh` is authenticated with a token
// that has the needed admin scope.
//
// Each builder returns a fix: one or more commands to apply (newline-separated)
// plus a read-only command to verify the change took effect.

// fix bundles a remediation command sequence with a way to confirm it worked.
type fix struct {
	cmd    string // one or more `gh` commands, newline-separated
	verify string // read-only `gh` command to confirm the change; may be empty
}

// ghOrgPatch sets a single org setting via the REST API.
func ghOrgPatch(org, field, value string) fix {
	return fix{
		cmd:    fmt.Sprintf("gh api -X PATCH orgs/%s -F %s=%s", org, field, value),
		verify: fmt.Sprintf("gh api orgs/%s --jq '.%s'", org, field),
	}
}

// ghHardenWorkflowToken sets the org's default workflow-token permissions to the
// secure state. The PUT replaces the whole object, so a command touching only
// one field can reset the other to a default; we set both together (read-only
// token, no Actions PR approval) so the command is self-contained whichever
// finding surfaces it. Setting an already-secure field is a harmless no-op.
func ghHardenWorkflowToken(org string) fix {
	return fix{
		cmd: fmt.Sprintf("gh api -X PUT orgs/%s/actions/permissions/workflow "+
			"-F default_workflow_permissions=read "+
			"-F can_approve_pull_request_reviews=false", org),
		verify: fmt.Sprintf("gh api orgs/%s/actions/permissions/workflow", org),
	}
}

// ghRepoEnablePushProtection enables secret-scanning push protection on a repo.
// Push protection requires secret scanning to be enabled first, so the command
// sets both in one PATCH — enabling secret scanning when it is already on is a
// harmless no-op, but setting push protection alone while scanning is off is
// silently ignored by the API.
func ghRepoEnablePushProtection(org, repo string) fix {
	return fix{
		cmd: fmt.Sprintf("gh api -X PATCH repos/%s/%s "+
			"-F 'security_and_analysis[secret_scanning][status]=enabled' "+
			"-F 'security_and_analysis[secret_scanning_push_protection][status]=enabled'", org, repo),
		verify: fmt.Sprintf("gh api repos/%s/%s --jq '.security_and_analysis'", org, repo),
	}
}

// ghRepoEnableDependabotAlerts enables Dependabot vulnerability alerts on a repo.
// The dedicated endpoint takes a bodyless PUT; verifying reads the same endpoint,
// which answers 204 when enabled and 404 when not, so we surface the status line.
func ghRepoEnableDependabotAlerts(org, repo string) fix {
	return fix{
		cmd:    fmt.Sprintf("gh api -X PUT repos/%s/%s/vulnerability-alerts", org, repo),
		verify: fmt.Sprintf("gh api -i repos/%s/%s/vulnerability-alerts | head -1", org, repo),
	}
}

// ghProtectBranch applies classic branch protection to a repo's branch: require
// a pull request, enforce on admins, and block force-pushes and deletion. The
// protection PUT requires all four top-level keys (required_status_checks,
// enforce_admins, required_pull_request_reviews, restrictions) even when null,
// so the body is passed as JSON via a here-string on one line rather than -F.
//
// requireReview controls the approval count: 1 for a team (a second person must
// approve), but 0 when there is effectively one developer — GitHub forbids
// approving your own PR, so requiring an approval would lock the branch. With 0
// the PR flow and force-push/deletion blocks still apply; only the second-person
// approval is dropped.
func ghProtectBranch(org, repo, branch string, requireReview bool) fix {
	reviews := `"required_pull_request_reviews":{"required_approving_review_count":0}`
	if requireReview {
		reviews = `"required_pull_request_reviews":{"required_approving_review_count":1,"dismiss_stale_reviews":true}`
	}
	body := `{"required_status_checks":null,"enforce_admins":true,` + reviews +
		`,"restrictions":null,"allow_force_pushes":false,"allow_deletions":false}`
	return fix{
		cmd:    fmt.Sprintf("gh api -X PUT repos/%s/%s/branches/%s/protection --input - <<< '%s'", org, repo, branch, body),
		verify: fmt.Sprintf("gh api repos/%s/%s/branches/%s/protection --jq '{review:.required_pull_request_reviews.required_approving_review_count,admins:.enforce_admins.enabled}'", org, repo, branch),
	}
}

// ghFixWebhookSSL re-enables SSL verification on a webhook. apiPath is the
// hook's REST path without the trailing /hooks/{id} (e.g. "orgs/acme" or
// "repos/acme/api"). Only the insecure-SSL aspect is mechanically fixable; a
// missing payload secret needs a value the operator must choose.
func ghFixWebhookSSL(apiPath string, hookID int64) fix {
	return fix{
		cmd:    fmt.Sprintf("gh api -X PATCH %s/hooks/%d -F 'config[insecure_ssl]=0'", apiPath, hookID),
		verify: fmt.Sprintf("gh api %s/hooks/%d --jq '.config.insecure_ssl'", apiPath, hookID),
	}
}

// ghRemoveCopilotSeat unassigns a user's Copilot seat (org-wide Copilot billing).
func ghRemoveCopilotSeat(org, login string) fix {
	return fix{
		cmd:    fmt.Sprintf("gh api -X DELETE orgs/%s/copilot/billing/selected_users -f 'selected_usernames[]=%s'", org, login),
		verify: fmt.Sprintf("gh api orgs/%s/copilot/billing/seats --jq '.seats[].assignee.login'", org),
	}
}

// ghArchiveRepo archives a repository, making it read-only and removing it from
// active governance. Reversible (set archived=false to unarchive).
func ghArchiveRepo(org, repo string) fix {
	return fix{
		cmd:    fmt.Sprintf("gh api -X PATCH repos/%s/%s -F archived=true", org, repo),
		verify: fmt.Sprintf("gh api repos/%s/%s --jq '.archived'", org, repo),
	}
}

// ghRemoveOutsideCollaborator removes an outside collaborator from the org.
func ghRemoveOutsideCollaborator(org, login string) fix {
	return fix{
		cmd:    fmt.Sprintf("gh api -X DELETE orgs/%s/outside_collaborators/%s", org, login),
		verify: fmt.Sprintf("gh api orgs/%s/outside_collaborators --jq '.[].login'", org),
	}
}

// ghCancelInvitation cancels a pending org invitation by id.
func ghCancelInvitation(org string, id int64) fix {
	return fix{
		cmd:    fmt.Sprintf("gh api -X DELETE orgs/%s/invitations/%d", org, id),
		verify: fmt.Sprintf("gh api orgs/%s/invitations --jq '.[].login'", org),
	}
}

// ghRevokeCredential revokes an SSO credential authorization (e.g. a classic PAT
// authorized for the org) by its credential id.
func ghRevokeCredential(org string, credentialID int64) fix {
	return fix{
		cmd:    fmt.Sprintf("gh api -X DELETE orgs/%s/credential-authorizations/%d", org, credentialID),
		verify: fmt.Sprintf("gh api orgs/%s/credential-authorizations --jq '.[].login'", org),
	}
}

// ghDeleteDeployKey removes a deploy key from a repo.
func ghDeleteDeployKey(org, repo, keyID string) fix {
	return fix{
		cmd:    fmt.Sprintf("gh api -X DELETE repos/%s/%s/keys/%s", org, repo, keyID),
		verify: fmt.Sprintf("gh api repos/%s/%s/keys --jq '.[].id'", org, repo),
	}
}

// ghRestrictActions limits the org to selected actions instead of all. The PUT
// replaces the whole permissions object, so enabled_repositories is required
// (omitting it is a 422); we carry the org's current value through unchanged so
// the command only narrows allowed_actions. Switching to "selected" also needs
// the allowlist configured, or legitimate workflows break — so a second command
// allows GitHub-owned and verified-creator actions. Defaults to "all" when the
// current value is unknown.
func ghRestrictActions(org, enabledRepositories string) fix {
	if enabledRepositories == "" {
		enabledRepositories = "all"
	}
	return fix{
		cmd: fmt.Sprintf(
			"gh api -X PUT orgs/%s/actions/permissions -F enabled_repositories=%s -F allowed_actions=selected\n"+
				"gh api -X PUT orgs/%s/actions/permissions/selected-actions -F github_owned_allowed=true -F verified_allowed=true",
			org, enabledRepositories, org),
		verify: fmt.Sprintf("gh api orgs/%s/actions/permissions", org),
	}
}
