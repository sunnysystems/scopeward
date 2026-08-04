package checks

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func init() {
	check.Register(orgDefault{
		id:    "codesecurity.secret-scanning-default-off",
		title: "Secret scanning off by default",
		sev:   model.SevMedium,
		get:   func(o model.Organization) *bool { return o.SecretScanningDefault },
		short: "New repositories are created without secret scanning enabled",
		desc:  "New repositories do not get secret scanning automatically, so leaked credentials committed to fresh repos go undetected until someone enables it manually.",
		fix:   "Create a Code Security configuration with secret scanning enabled and set it as the org default (Settings → Code security → Configurations).",
	})
	check.Register(orgDefault{
		id:    "codesecurity.push-protection-default-off",
		title: "Push protection off by default",
		sev:   model.SevMedium,
		get:   func(o model.Organization) *bool { return o.PushProtectionDefault },
		short: "New repositories are created without secret-scanning push protection",
		desc:  "Without push protection, secrets are only caught after they are already committed and pushed; push protection blocks them at commit time, which is the difference between a near-miss and a real leak.",
		fix:   "Create a Code Security configuration with push protection enabled and set it as the org default (Settings → Code security → Configurations).",
	})
	check.Register(orgDefault{
		id:    "codesecurity.dependabot-alerts-default-off",
		title: "Dependabot alerts off by default",
		sev:   model.SevLow,
		get:   func(o model.Organization) *bool { return o.DependabotAlertsDefault },
		short: "New repositories are created without Dependabot alerts",
		desc:  "New repositories will not be told when their dependencies have known vulnerabilities, leaving vulnerable code unflagged.",
		fix:   "Create a Code Security configuration with Dependabot alerts enabled and set it as the org default (Settings → Code security → Configurations).",
	})
}

// orgDefault is a reusable check over a single boolean org security default that
// should be enabled. It flags when the setting is visibly disabled.
//
// These settings are now managed through Code Security configurations rather
// than the org-level boolean PATCH fields (deprecated 2026-04-21), which is a
// multi-step flow with no safe single-command equivalent — so these checks
// carry remediation guidance but no GHFix.
type orgDefault struct {
	id, title, short, desc, fix string
	sev                         model.Severity
	get                         func(model.Organization) *bool
}

func (c orgDefault) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              c.id,
		Title:           c.title,
		Axis:            model.AxisCodeSecurity,
		DefaultSeverity: c.sev,
		Kind:            check.KindCoverage,
		RequiresData:    []model.DataKind{model.DataOrg},
		Description:     c.short + ".",
	}
}

func (c orgDefault) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	v := c.get(s.Org)
	if v == nil || *v { // unknown or enabled
		return nil
	}
	return []model.Finding{{
		CheckID:     c.id,
		Title:       c.short,
		Severity:    c.sev,
		Axis:        model.AxisCodeSecurity,
		Resource:    orgRef(s.Org),
		Evidence:    map[string]any{"setting": c.id, "enabled_for_new_repos": false},
		Description: c.desc,
		Remediation: c.fix,
		DocsURL:     "https://docs.github.com/code-security/securing-your-organization/enabling-security-features-in-your-organization/applying-the-github-recommended-security-configuration-in-your-organization",
	}}
}
