package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(weakBranchProtection{})
	check.Register(bypassableBranchProtection{})
}

// weakBranchProtection flags default branches that are protected but weakly: no
// required pull-request review, or force-pushes allowed. (Repos protected via a
// ruleset rather than classic branch protection are not assessed here — their
// detail is not exposed by the classic endpoint — and unprotected branches are
// covered by teams.unprotected-default-branch.)
type weakBranchProtection struct{}

func (weakBranchProtection) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.weak-branch-protection",
		Title:           "Weak branch protection",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevHigh,
		RequiresData:    []model.DataKind{model.DataBranchProtection},
		Description:     "Default branches protected without requiring review or while allowing force-pushes.",
	}
}

func (c weakBranchProtection) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	gitlab := s.Provider == model.ProviderGitLab
	var out []model.Finding
	for _, r := range activeRepos(s) {
		// Each weakness is assessed independently on whatever detail was collected:
		// on GitLab Free, force-push is knowable from protected branches while
		// required-review (approval rules) is not, so they must not gate each other.
		var weaknesses []string
		// Requiring review only makes sense when a second person can approve; --solo
		// or a <2-member group suppresses it (you cannot approve your own change).
		if r.BranchReqPRReview != nil && !*r.BranchReqPRReview && reviewExpected(s) {
			weaknesses = append(weaknesses, "no required pull-request review")
		}
		if r.BranchAllowForcePush != nil && *r.BranchAllowForcePush {
			weaknesses = append(weaknesses, "force-pushes allowed")
		}
		if len(weaknesses) == 0 {
			continue
		}
		docs := "https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches"
		remediation := "Require at least one approving pull-request review and disable force-pushes on the default branch (also consider requiring status checks and signed commits)."
		if gitlab {
			docs = glBranchDocs
			remediation = "Require merge-request approvals (Premium) and disable force-push on the protected branch; protection takes effect when the relevant branches are themselves protected."
		}
		f := model.Finding{
			CheckID:     c.Meta().ID,
			Title:       "Weak protection on " + repoDisplay(s, r) + " (" + strings.Join(weaknesses, ", ") + ")",
			Severity:    model.SevHigh,
			Axis:        model.AxisTeams,
			Resource:    repoResource(s, r),
			Evidence:    map[string]any{"repo": r.Name, "default_branch": r.DefaultBranch, "weaknesses": weaknesses},
			Description: "The default branch is protected, but the protection has gaps: changes can land without review, or history can be rewritten with a force-push. Either undermines the guarantee that what is on main was reviewed and is immutable.",
			Remediation: remediation,
			DocsURL:     docs,
		}
		if !gitlab && branchProtectable(r.Private, s.Org.Plan) {
			f = withFix(f, ghProtectBranch(s.Org.Login, r.Name, r.DefaultBranch, reviewExpected(s), !adminBypassExpected(s)))
		}
		out = append(out, f)
	}
	return out
}

// bypassableBranchProtection flags default branches whose protection does not
// apply to administrators — every org owner and repo admin can push straight to
// the branch, so the rules that the other branch checks report as satisfied are
// optional for the most privileged (and most frequently compromised) identities.
//
// It is separate from weakBranchProtection because it is a different claim: the
// rules are there and are fine, they simply do not bind everyone. Keeping it its
// own check also lets an org that deliberately keeps a break-glass path accept
// exactly this one finding without silencing protection quality as a whole.
//
// Severity follows organization size. Below breakGlassThreshold the bypass is the
// configuration scopeward itself suggests, so reporting it as a defect would mean
// penalizing an org for following the tool's own advice — an unclearable finding
// with a lockout as the only way to clear it. There it drops to info: still
// listed, worth zero penalty, phrased as something to revisit as the team grows.
type bypassableBranchProtection struct{}

func (bypassableBranchProtection) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "teams.branch-protection-bypassable",
		Title:           "Branch protection does not apply to admins",
		Axis:            model.AxisTeams,
		DefaultSeverity: model.SevMedium,
		RequiresData:    []model.DataKind{model.DataBranchProtection},
		Description:     "Default branches whose protection exempts administrators, who can then push directly.",
	}
}

func (c bypassableBranchProtection) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	expected := adminBypassExpected(s)

	title := " is bypassable by admins"
	sev := model.SevMedium
	desc := "The default branch is protected, but the protection is not enforced on administrators. Org owners and repo admins can push directly, bypassing review and force-push rules — including any bot or AI agent running with an admin token. The other branch checks report this repo as protected, so the gap is invisible in the rest of the report."
	fix := "Enable \"Do not allow bypassing the above settings\" (enforce_admins) on the default branch. If admins deliberately keep a break-glass path, record that decision as an ignore rule with a reason rather than leaving it undocumented."
	if expected {
		title = " keeps an admin break-glass path"
		sev = model.SevInfo
		desc = fmt.Sprintf("The default branch is protected, but not for administrators: owners and repo admins can push directly. At %d member(s) that is the configuration scopeward suggests — with a required review and no admin bypass, one person being unavailable would block every change, including an urgent fix. Listed so the exposure is visible, not because it needs fixing today: anyone with admin, and any bot or agent holding an admin token, is outside the protection.", len(s.Members))
		fix = fmt.Sprintf("Nothing to do while the team is this small. Revisit once there are %d or more members and a reviewer is reliably reachable: enable \"Do not allow bypassing the above settings\" (enforce_admins) then. In the meantime, keep the number of admins small, since admin is what the bypass is keyed to.", breakGlassThreshold)
	}

	var out []model.Finding
	for _, r := range activeRepos(s) {
		// nil = not assessed: no classic protection, ruleset-protected, or a
		// provider that does not expose the setting. Only an explicit false is a
		// finding.
		if r.BranchEnforceAdmins == nil || *r.BranchEnforceAdmins {
			continue
		}
		f := model.Finding{
			CheckID:     c.Meta().ID,
			Title:       "Protection on " + repoDisplay(s, r) + title,
			Severity:    sev,
			Axis:        model.AxisTeams,
			Resource:    repoResource(s, r),
			Evidence:    map[string]any{"repo": r.Name, "default_branch": r.DefaultBranch, "enforce_admins": false, "members": len(s.Members)},
			Description: desc,
			Remediation: fix,
			DocsURL:     "https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#include-administrators",
		}
		// No suggested command when the bypass is the recommended state — the tool
		// must not hand out a fix for something it just said not to change.
		if !expected && s.Provider != model.ProviderGitLab && branchProtectable(r.Private, s.Org.Plan) {
			f = withFix(f, ghEnforceAdmins(s.Org.Login, r.Name, r.DefaultBranch))
		}
		out = append(out, f)
	}
	return out
}
