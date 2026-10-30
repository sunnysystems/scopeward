package checks

import (
	"context"
	"strings"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(orgDefault{
		id:     "codesecurity.secret-scanning-default-off",
		title:  "Secret scanning off by default",
		sev:    model.SevMedium,
		what:   "secret scanning",
		paid:   true,
		get:    func(d model.SecurityDefaults) bool { return d.SecretScanning },
		legacy: func(o model.Organization) *bool { return o.SecretScanningDefault },
		desc:   "New repositories do not get secret scanning automatically, so leaked credentials committed to fresh repos go undetected until someone enables it manually.",
		fix:    "Create a Code Security configuration with secret scanning enabled and set it as the org default (Settings → Code security → Configurations).",
	})
	check.Register(orgDefault{
		id:     "codesecurity.push-protection-default-off",
		title:  "Push protection off by default",
		sev:    model.SevMedium,
		what:   "secret-scanning push protection",
		paid:   true,
		get:    func(d model.SecurityDefaults) bool { return d.PushProtection },
		legacy: func(o model.Organization) *bool { return o.PushProtectionDefault },
		desc:   "Without push protection, secrets are only caught after they are already committed and pushed; push protection blocks them at commit time, which is the difference between a near-miss and a real leak.",
		fix:    "Create a Code Security configuration with push protection enabled and set it as the org default (Settings → Code security → Configurations).",
	})
	check.Register(orgDefault{
		id:     "codesecurity.dependabot-alerts-default-off",
		title:  "Dependabot alerts off by default",
		sev:    model.SevLow,
		what:   "Dependabot alerts",
		get:    func(d model.SecurityDefaults) bool { return d.DependabotAlerts },
		legacy: func(o model.Organization) *bool { return o.DependabotAlertsDefault },
		desc:   "New repositories will not be told when their dependencies have known vulnerabilities, leaving vulnerable code unflagged.",
		fix:    "Create a Code Security configuration with Dependabot alerts enabled and set it as the org default (Settings → Code security → Configurations).",
	})
}

// orgDefault is a reusable check over one security setting that new
// repositories should get by default. It flags when the setting is visibly off
// for a visibility the org creates repositories in.
//
// The default is read from the org's default Code Security configurations,
// which is where GitHub keeps it since the org-level booleans were deprecated
// (2026-04-21). Those booleans are not updated when a configuration becomes the
// default, so they are only a fallback for an org with no default configuration
// (#100). Configurations are a multi-step flow with no safe single-command
// equivalent, so these checks carry remediation guidance but no GHFix.
type orgDefault struct {
	id, title, what, desc, fix string
	sev                        model.Severity
	// paid marks a setting that needs GitHub Secret Protection on private
	// repositories. Without the entitlement, asking for a private default is an
	// invoice, which #50 withholds and Limitation reports.
	paid   bool
	get    func(model.SecurityDefaults) bool
	legacy func(model.Organization) *bool
}

func (c orgDefault) short() string { return "New repositories are created without " + c.what }

func (c orgDefault) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              c.id,
		Title:           c.title,
		Axis:            model.AxisCodeSecurity,
		DefaultSeverity: c.sev,
		Kind:            model.KindCoverage,
		RequiresData:    []model.DataKind{model.DataOrg},
		Description:     c.short() + ".",
	}
}

// withheld reports whether the private-repository default is out of reach: the
// setting is paid there and the org is confirmed not to hold the entitlement.
func (c orgDefault) withheld(s *model.Snapshot) bool {
	return c.paid && s.Entitlement(model.EntSecretProtection).State == model.EntitlementAbsent
}

// visibilities are the new-repository visibilities this check asks a default
// for. Private always, since every plan can create private repositories, unless
// the setting is withheld there. Public only when the org has public
// repositories or lets members create them, so a private-only org is not told
// to configure a default it will never use.
func (c orgDefault) visibilities(s *model.Snapshot) []string {
	var out []string
	if !c.withheld(s) {
		out = append(out, "private")
	}
	if createsPublicRepos(s) {
		out = append(out, "public")
	}
	return out
}

func createsPublicRepos(s *model.Snapshot) bool {
	if v := s.Org.MembersCanCreatePublicRepos; v != nil && *v {
		return true
	}
	for _, r := range activeRepos(s) {
		if !r.Private {
			return true
		}
	}
	return false
}

func (c orgDefault) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	vis := c.visibilities(s)
	if len(vis) == 0 {
		return nil // nothing in reach; Limitation says why
	}

	var missing []string
	source := "code_security_configuration"
	if d := s.Org.NewRepoSecurity; d != nil {
		for _, v := range vis {
			if !c.get(d.For(v)) {
				missing = append(missing, v)
			}
		}
	} else {
		source = "legacy_org_setting"
		v := c.legacy(s.Org)
		if v == nil || *v { // unknown or enabled
			return nil
		}
		missing = vis
	}
	if len(missing) == 0 {
		return nil
	}

	// Name the visibilities only when that narrows the claim: "new repositories"
	// would overstate a gap that covers private repositories but not public ones.
	title, fix := c.short(), c.fix
	if len(missing) < len(vis) || c.withheld(s) {
		scope := strings.Join(missing, " and ")
		title = "New " + scope + " repositories are created without " + c.what
		fix += " Make sure the default applies to " + scope + " repositories."
	}

	return []model.Finding{{
		CheckID:     c.id,
		Title:       title,
		Severity:    c.sev,
		Axis:        model.AxisCodeSecurity,
		Resource:    orgRef(s.Org),
		Evidence:    map[string]any{"setting": c.id, "enabled_for_new_repos": false, "visibilities": missing, "source": source},
		Description: c.desc,
		Remediation: fix,
		DocsURL:     "https://docs.github.com/code-security/securing-your-organization/enabling-security-features-in-your-organization/applying-the-github-recommended-security-configuration-in-your-organization",
	}}
}

// Limitation accounts for the private-repository default when it is withheld.
// Without it, a private-only org lacking Secret Protection would read as having
// passed a check nobody could evaluate.
func (c orgDefault) Limitation(s *model.Snapshot) *check.Limitation {
	if !c.withheld(s) {
		return nil
	}
	assessed := 0
	if createsPublicRepos(s) {
		assessed = 1
	}
	return &check.Limitation{
		CheckID:  c.id,
		Title:    c.title,
		Axis:     model.AxisCodeSecurity,
		Reason:   "a default for new private repositories requires GitHub Secret Protection, which this organization does not have: " + s.Entitlement(model.EntSecretProtection).Reason,
		Assessed: assessed,
		Omitted:  1,
	}
}
