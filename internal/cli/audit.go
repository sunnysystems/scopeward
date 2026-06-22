package cli

import (
	"context"
	"errors"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/collect"
	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/provider"
	"github.com/sunnysystems/scopeward/internal/report"
	"github.com/sunnysystems/scopeward/internal/score"
)

// orgScopedKinds are DataKinds that only exist for an organization. A check that
// requires any of them is org-scoped and is skipped in user/account mode.
var orgScopedKinds = map[model.DataKind]bool{
	model.DataOrg: true, model.DataMembers: true, model.DataMember2FA: true,
	model.DataMemberRoles: true, model.DataSAMLIdentities: true, model.DataOutsideCollaborators: true,
	model.DataTeams: true, model.DataTeamMembers: true, model.DataTeamRepos: true,
	model.DataCustomProperties: true,
	model.DataAppInstallations: true, model.DataActionsTokenDefault: true,
	model.DataOrgWebhooks: true, model.DataFineGrainedPATs: true, model.DataOrgRulesets: true,
	model.DataCustomRoles: true, model.DataOrgRoles: true, model.DataSelfHostedRunners: true, model.DataPendingInvitations: true,
	model.DataActionsPolicy: true, model.DataOrgSecrets: true, model.DataCredentialAuthorizations: true,
	model.DataCopilotSeats: true, model.DataCompanyDomains: true,
}

// checkScope classifies a check by the data it needs: "org", "account", or
// "repo" (applies to both).
func checkScope(m check.CheckMeta) string {
	account := false
	for _, k := range m.RequiresData {
		if orgScopedKinds[k] {
			return "org"
		}
		if k == model.DataAccount {
			account = true
		}
	}
	if account {
		return "account"
	}
	return "repo"
}

// filterByMode drops checks that cannot apply to the chosen target: org-scoped
// checks in user mode, and account-scoped checks in org mode.
func filterByMode(checks []check.Check, userMode bool) []check.Check {
	var out []check.Check
	for _, c := range checks {
		switch checkScope(c.Meta()) {
		case "org":
			if userMode {
				continue
			}
		case "account":
			if !userMode {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// validateTargetFlags ensures at most one of --org/--me/--user is set.
func validateTargetFlags(o *options) error {
	n := 0
	if o.org != "" {
		n++
	}
	if o.me {
		n++
	}
	if o.user != "" {
		n++
	}
	if n > 1 {
		return errors.New("use only one of --org, --me, or --user")
	}
	return nil
}

// target resolves the audit subject and mode. probeLogin supplies --me's login.
func (o *options) target(probeLogin string) (subject string, userMode, self bool) {
	switch {
	case o.me:
		return probeLogin, true, true
	case o.user != "":
		return o.user, true, false
	default:
		return o.org, false, false
	}
}

// buildAudit collects the subject (org or user) through the provider's
// collector, runs the mode-appropriate checks, and scores them. Ignore/baseline
// filtering is applied by the caller.
func buildAudit(ctx context.Context, coll provider.Collector, subject string, userMode, self bool, opts *options, prog collect.Reporter) (report.Audit, error) {
	co := collect.Options{Quick: opts.quick, MaxRepos: opts.maxRepos}

	snap, err := coll.Collect(ctx, provider.Args{
		Subject:  subject,
		UserMode: userMode,
		Self:     self,
		Options:  co,
		Progress: prog,
	})
	if err != nil {
		return report.Audit{}, err
	}
	configureAudit(snap, opts)

	checks, err := filterChecks(check.All(), opts.only, opts.skip)
	if err != nil {
		return report.Audit{}, err
	}
	checks = filterByMode(checks, userMode)

	rep := check.Run(ctx, snap, checks)
	return report.Audit{Snapshot: snap, Report: rep, Score: score.Grade(rep.Findings)}, nil
}
