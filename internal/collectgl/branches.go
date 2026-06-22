package collectgl

import (
	"context"
	"encoding/base64"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/sunnysystems/scopeward/internal/collect"
	"github.com/sunnysystems/scopeward/internal/glclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// collectBranches gathers each project's protected-branch settings, merge-request
// approval rules (Premium), and CODEOWNERS file. These map GitHub's branch
// protection / required-review / code-ownership checks onto GitLab.
//
// Protected branches are available on every tier; approval rules are Premium, so
// when their endpoint is not accessible the approval settings degrade to "not
// evaluated" rather than implying review is unenforced. The whole pass is
// per-project and skipped in --quick mode.
func collectBranches(ctx context.Context, client *glclient.Client, snap *model.Snapshot, opts collect.Options) {
	kinds := []model.DataKind{model.DataBranchProtection, model.DataMRApprovalSettings, model.DataCodeowners}

	if opts.Quick {
		for _, k := range kinds {
			snap.Coverage.Missing(k, "skipped in --quick mode (group-level audit only)")
		}
		return
	}
	if !snap.Coverage.Available(model.DataRepos) || len(snap.Repos) == 0 {
		for _, k := range kinds {
			snap.Coverage.Missing(k, "projects could not be listed")
		}
		return
	}

	var prot, appr, codeowners covTally
	forEachIndex(ctx, defaultConcurrency, len(snap.Repos), func(ctx context.Context, i int) {
		r := &snap.Repos[i]
		if err := collectProtectedBranch(ctx, client, r); err != nil {
			prot.fail(reasonFor(err, "listing protected branches"))
		} else {
			prot.add(1)
		}
		if err := collectApprovalSettings(ctx, client, r); err != nil {
			appr.fail(reasonFor(err, "reading MR approval rules (Premium)"))
		} else {
			appr.add(1)
		}
		if err := collectProjectCodeowners(ctx, client, r); err != nil {
			codeowners.fail(reasonFor(err, "reading CODEOWNERS"))
		} else {
			codeowners.add(1)
		}
	})
	prot.record(snap.Coverage, model.DataBranchProtection, len(snap.Repos))
	appr.record(snap.Coverage, model.DataMRApprovalSettings, len(snap.Repos))
	codeowners.record(snap.Coverage, model.DataCodeowners, len(snap.Repos))
}

// collectProtectedBranch sets whether the project's default branch is protected,
// and (when it is) the force-push and code-owner-approval settings of the
// matching rule. An empty repository (no default branch) is left unassessed.
func collectProtectedBranch(ctx context.Context, client *glclient.Client, r *model.Repo) error {
	dtos, err := glclient.GetAll[glProtectedBranchDTO](ctx, client, "/projects/"+strconv.FormatInt(r.ID, 10)+"/protected_branches", nil)
	if err != nil {
		return err
	}
	if r.DefaultBranch == "" {
		return nil // empty repo: nothing to protect, leave DefaultBranchProtected nil
	}
	protected := false
	for _, d := range dtos {
		if branchMatches(d.Name, r.DefaultBranch) {
			protected = true
			fp := d.AllowForcePush
			r.BranchAllowForcePush = &fp
			co := d.CodeOwnerApprovalRequired
			r.CodeOwnerApprovalRequired = &co
			break
		}
	}
	r.DefaultBranchProtected = &protected
	return nil
}

// collectApprovalSettings reads the project's MR approval rules and settings.
// The approval-rules endpoint is Premium, so an error here (commonly 403/404 on
// Free) leaves the approval data uncollected and the dependent check skipped.
// When review is actually required (a rule needs >=1 approval) the neutral
// BranchReqPRReview is set so the weak-branch-protection check can evaluate it;
// it is left nil otherwise so Free tiers are not flagged for unenforceable review.
func collectApprovalSettings(ctx context.Context, client *glclient.Client, r *model.Repo) error {
	pid := strconv.FormatInt(r.ID, 10)
	rules, err := glclient.GetAll[glApprovalRuleDTO](ctx, client, "/projects/"+pid+"/approval_rules", nil)
	if err != nil {
		return err
	}
	var settings glApprovalSettingsDTO
	if _, err := client.Get(ctx, "/projects/"+pid+"/approvals", nil, &settings); err != nil {
		return err
	}

	required := settings.ApprovalsBeforeMerge
	for _, rule := range rules {
		if rule.ApprovalsRequired > required {
			required = rule.ApprovalsRequired
		}
	}
	r.MRApprovalsRequired = &required
	if required >= 1 {
		yes := true
		r.BranchReqPRReview = &yes
	}
	author := settings.MergeRequestsAuthorApproval
	r.MRAuthorCanApprove = &author
	reset := settings.ResetApprovalsOnPush
	r.MRResetApprovalsOnPush = &reset
	return nil
}

// glCodeownersLocations are the paths GitLab recognizes for a CODEOWNERS file.
var glCodeownersLocations = []string{"CODEOWNERS", "docs/CODEOWNERS", ".gitlab/CODEOWNERS"}

// collectProjectCodeowners looks for a CODEOWNERS file on the default branch and
// records its presence plus the group (subgroup) references it assigns. An empty
// repository is left unassessed.
func collectProjectCodeowners(ctx context.Context, client *glclient.Client, r *model.Repo) error {
	if r.DefaultBranch == "" {
		return nil
	}
	for _, path := range glCodeownersLocations {
		content, found, err := fetchGLFile(ctx, client, r.ID, path, r.DefaultBranch)
		if err != nil {
			return err
		}
		if found {
			present := true
			r.CodeownersPresent = &present
			r.CodeownersTeams = parseGLCodeownersTeams(content)
			return nil
		}
	}
	present := false
	r.CodeownersPresent = &present
	return nil
}

// fetchGLFile gets a single repository file's decoded text via the Repository
// Files API. The path is URL-encoded (slashes become %2F) as the endpoint
// requires. found is false on 404.
func fetchGLFile(ctx context.Context, client *glclient.Client, projectID int64, path, ref string) (string, bool, error) {
	var file struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	endpoint := "/projects/" + strconv.FormatInt(projectID, 10) + "/repository/files/" + url.QueryEscape(path)
	if _, err := client.Get(ctx, endpoint, url.Values{"ref": {ref}}, &file); err != nil {
		if glclient.StatusCode(err) == 404 {
			return "", false, nil
		}
		return "", false, err
	}
	if file.Encoding == "base64" {
		if decoded, derr := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", "")); derr == nil {
			return string(decoded), true, nil
		}
	}
	return file.Content, true, nil
}

// glTeamMentionRe matches a group code-owner reference: an @-mention whose path
// contains a slash (e.g. @acme/backend or @acme/backend/team). GitLab group
// paths may be several segments deep; a slashless @name is an individual or a
// top-level group and is treated as non-team, matching the GitHub convention.
var glTeamMentionRe = regexp.MustCompile(`@[A-Za-z0-9][A-Za-z0-9._/-]*`)

// parseGLCodeownersTeams extracts the distinct group references (containing a
// slash) from a GitLab CODEOWNERS file, skipping comments and section headers.
func parseGLCodeownersTeams(content string) []string {
	seen := map[string]bool{}
	var teams []string
	for _, line := range strings.Split(content, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, m := range glTeamMentionRe.FindAllString(line, -1) {
			if !strings.Contains(m, "/") || seen[m] {
				continue // slashless mention = individual/top-level; or already seen
			}
			seen[m] = true
			teams = append(teams, m)
		}
	}
	return teams
}

// branchMatches reports whether a protected-branch pattern (which may contain *
// wildcards) covers the given branch name.
func branchMatches(pattern, branch string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == branch
	}
	segs := strings.Split(pattern, "*")
	for i := range segs {
		segs[i] = regexp.QuoteMeta(segs[i])
	}
	ok, err := regexp.MatchString("^"+strings.Join(segs, ".*")+"$", branch)
	return err == nil && ok
}

// --- DTOs ---

type glProtectedBranchDTO struct {
	Name                      string `json:"name"`
	AllowForcePush            bool   `json:"allow_force_push"`
	CodeOwnerApprovalRequired bool   `json:"code_owner_approval_required"`
}

type glApprovalRuleDTO struct {
	ApprovalsRequired int `json:"approvals_required"`
}

type glApprovalSettingsDTO struct {
	ApprovalsBeforeMerge        int  `json:"approvals_before_merge"`
	ResetApprovalsOnPush        bool `json:"reset_approvals_on_push"`
	MergeRequestsAuthorApproval bool `json:"merge_requests_author_approval"`
}
