package collect

import (
	"context"

	"github.com/sunnysystems/scopeward/internal/ghclient"
	"github.com/sunnysystems/scopeward/internal/model"
)

// collectSecurityDefaults reads what new repositories get from the org's default
// Code Security configurations.
//
// GitHub deprecated the org-level *_enabled_for_new_repositories booleans on
// 2026-04-21 in favor of these configurations, and does not update the booleans
// when a configuration becomes the default. Reading only the booleans meant an
// org that followed the remediation ("set a configuration as the org default")
// kept being told its new repositories were unprotected (#100).
//
// A failure here is not a coverage gap of its own: snap.Org keeps the legacy
// booleans, and the checks fall back to them when NewRepoSecurity is nil.
func collectSecurityDefaults(ctx context.Context, client *ghclient.Client, org string, snap *model.Snapshot) {
	var dtos []securityDefaultDTO
	if _, err := client.Get(ctx, "/orgs/"+org+"/code-security/configurations/defaults", nil, &dtos); err != nil {
		return
	}
	snap.Org.NewRepoSecurity = newRepoSecurity(dtos)
}

type securityDefaultDTO struct {
	DefaultForNewRepos string `json:"default_for_new_repos"` // all | none | private_and_internal | public
	Configuration      struct {
		DependabotAlerts string `json:"dependabot_alerts"`
		SecretScanning   string `json:"secret_scanning"`
		PushProtection   string `json:"secret_scanning_push_protection"`
	} `json:"configuration"`
}

// newRepoSecurity folds the default configurations into per-visibility settings,
// or returns nil when none applies to new repositories, so the legacy booleans
// stand. Only "enabled" turns a setting on: "not_set" leaves a new repository at
// GitHub's own default, which is off.
func newRepoSecurity(dtos []securityDefaultDTO) *model.NewRepoSecurity {
	var out model.NewRepoSecurity
	applied := false
	for _, d := range dtos {
		var targets []*model.SecurityDefaults
		switch d.DefaultForNewRepos {
		case "all":
			targets = []*model.SecurityDefaults{&out.Public, &out.Private}
		case "public":
			targets = []*model.SecurityDefaults{&out.Public}
		case "private_and_internal":
			targets = []*model.SecurityDefaults{&out.Private}
		default:
			continue
		}
		applied = true
		c := d.Configuration
		for _, t := range targets {
			t.DependabotAlerts = t.DependabotAlerts || c.DependabotAlerts == "enabled"
			t.SecretScanning = t.SecretScanning || c.SecretScanning == "enabled"
			t.PushProtection = t.PushProtection || c.PushProtection == "enabled"
		}
	}
	if !applied {
		return nil
	}
	return &out
}
