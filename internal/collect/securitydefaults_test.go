package collect

import (
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func securityDefault(target, dependabot, scanning, push string) securityDefaultDTO {
	var d securityDefaultDTO
	d.DefaultForNewRepos = target
	d.Configuration.DependabotAlerts = dependabot
	d.Configuration.SecretScanning = scanning
	d.Configuration.PushProtection = push
	return d
}

func TestNewRepoSecurity(t *testing.T) {
	cases := []struct {
		name string
		dtos []securityDefaultDTO
		want *model.NewRepoSecurity
	}{
		{"no defaults keeps the legacy booleans", nil, nil},
		{"a default that applies to nothing is no default", []securityDefaultDTO{securityDefault("none", "enabled", "enabled", "enabled")}, nil},
		{
			"all covers both visibilities",
			[]securityDefaultDTO{securityDefault("all", "enabled", "disabled", "disabled")},
			&model.NewRepoSecurity{Public: model.SecurityDefaults{DependabotAlerts: true}, Private: model.SecurityDefaults{DependabotAlerts: true}},
		},
		{
			"not_set is off",
			[]securityDefaultDTO{securityDefault("all", "not_set", "not_set", "not_set")},
			&model.NewRepoSecurity{},
		},
		{
			"per-visibility defaults combine",
			[]securityDefaultDTO{
				securityDefault("public", "enabled", "enabled", "enabled"),
				securityDefault("private_and_internal", "enabled", "disabled", "disabled"),
			},
			&model.NewRepoSecurity{
				Public:  model.SecurityDefaults{DependabotAlerts: true, SecretScanning: true, PushProtection: true},
				Private: model.SecurityDefaults{DependabotAlerts: true},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := newRepoSecurity(tc.dtos)
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("want nil, got %+v", *got)
			case tc.want != nil && (got == nil || *got != *tc.want):
				t.Fatalf("got %+v, want %+v", got, *tc.want)
			}
		})
	}
}
