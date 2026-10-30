package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

func orgDefaultByID(t *testing.T, id string) orgDefault {
	t.Helper()
	for _, c := range check.All() {
		if od, ok := c.(orgDefault); ok && od.id == id {
			return od
		}
	}
	t.Fatalf("check %s not registered", id)
	return orgDefault{}
}

// privateOrg is a private-only org whose legacy booleans all read "off", the
// state GitHub leaves them in after the default moves to a configuration.
func privateOrg() *model.Snapshot {
	snap := model.NewSnapshot("acme")
	snap.Coverage.OK(model.DataOrg, 1)
	snap.Repos = []model.Repo{{Name: "api", Private: true}}
	snap.Org.MembersCanCreatePublicRepos = bptr(false)
	snap.Org.DependabotAlertsDefault = bptr(false)
	snap.Org.SecretScanningDefault = bptr(false)
	snap.Org.PushProtectionDefault = bptr(false)
	return snap
}

// TestOrgDefaultReadsConfigurations pins #100: a default configuration that
// enables the setting clears the finding even though the deprecated boolean
// still reads false, which is exactly what following the remediation produces.
func TestOrgDefaultReadsConfigurations(t *testing.T) {
	c := orgDefaultByID(t, "codesecurity.dependabot-alerts-default-off")
	on := model.SecurityDefaults{DependabotAlerts: true}

	cases := []struct {
		name      string
		defaults  *model.NewRepoSecurity
		public    bool
		wantTitle string // "" = no finding
	}{
		{"configuration for all clears it", &model.NewRepoSecurity{Public: on, Private: on}, false, ""},
		{"no configuration falls back to the legacy boolean", nil, false, "New repositories are created without Dependabot alerts"},
		{"private default is enough for a private-only org", &model.NewRepoSecurity{Private: on}, false, ""},
		{"public-only default leaves private uncovered", &model.NewRepoSecurity{Public: on}, true, "New private repositories are created without Dependabot alerts"},
		{"private-only default leaves public uncovered", &model.NewRepoSecurity{Private: on}, true, "New public repositories are created without Dependabot alerts"},
		{"configuration that leaves it off", &model.NewRepoSecurity{}, false, "New repositories are created without Dependabot alerts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := privateOrg()
			snap.Org.NewRepoSecurity = tc.defaults
			if tc.public {
				snap.Repos = append(snap.Repos, model.Repo{Name: "site"})
			}
			got := c.Run(context.Background(), snap)
			switch {
			case tc.wantTitle == "" && len(got) != 0:
				t.Fatalf("want no finding, got %q", got[0].Title)
			case tc.wantTitle != "" && len(got) != 1:
				t.Fatalf("want %q, got %d findings", tc.wantTitle, len(got))
			case tc.wantTitle != "" && got[0].Title != tc.wantTitle:
				t.Errorf("title = %q, want %q", got[0].Title, tc.wantTitle)
			}
		})
	}
}

// TestOrgDefaultLegacyUnknownIsSilent keeps the old contract for orgs with no
// configuration: an unseen or enabled boolean never flags.
func TestOrgDefaultLegacyUnknownIsSilent(t *testing.T) {
	c := orgDefaultByID(t, "codesecurity.dependabot-alerts-default-off")
	for _, v := range []*bool{nil, bptr(true)} {
		snap := privateOrg()
		snap.Org.DependabotAlertsDefault = v
		if got := c.Run(context.Background(), snap); len(got) != 0 {
			t.Errorf("legacy %v: want no finding, got %q", v, got[0].Title)
		}
	}
}

// TestPaidOrgDefaultWithheldWithoutEntitlement pins the #96 follow-up: for a
// private-only org without Secret Protection, the secret-scanning defaults are
// an invoice, so they are not evaluated rather than flagged. With public
// repositories in play, the free public half is still assessed.
func TestPaidOrgDefaultWithheldWithoutEntitlement(t *testing.T) {
	for _, id := range []string{"codesecurity.secret-scanning-default-off", "codesecurity.push-protection-default-off"} {
		c := orgDefaultByID(t, id)

		snap := privateOrg()
		snap.SetEntitlement(model.EntitlementStatus{Entitlement: model.EntSecretProtection, State: model.EntitlementAbsent, Reason: "none"})
		rep := check.Run(context.Background(), snap, []check.Check{c})
		if len(rep.Findings) != 0 || len(rep.Skipped) != 1 || !strings.Contains(rep.Skipped[0].Reason, "Secret Protection") {
			t.Errorf("%s private-only: want not evaluated, got findings=%d skipped=%+v", id, len(rep.Findings), rep.Skipped)
		}

		snap.Repos = append(snap.Repos, model.Repo{Name: "site"})
		rep = check.Run(context.Background(), snap, []check.Check{c})
		if len(rep.Findings) != 1 || !strings.HasPrefix(rep.Findings[0].Title, "New public repositories") || len(rep.Limited) != 1 {
			t.Errorf("%s with public repos: want one public finding and a limitation, got %+v / %+v", id, rep.Findings, rep.Limited)
		}

		snap = privateOrg()
		snap.SetEntitlement(model.EntitlementStatus{Entitlement: model.EntSecretProtection, State: model.EntitlementUnknown, Reason: "403"})
		if got := c.Run(context.Background(), snap); len(got) != 1 {
			t.Errorf("%s unknown entitlement: must still report, got %d", id, len(got))
		}
	}
}
