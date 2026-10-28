package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

// accessSnapshot: olga owns the org; dev reaches api through team platform and
// holds a direct admin grant on infra; vic is an outside collaborator on api;
// legacy is archived.
func accessSnapshot() *model.Snapshot {
	s := model.NewSnapshot("acme")
	s.Org.DefaultRepoPermission = "read"
	s.Members = []model.Member{{Login: "olga", Role: "admin"}, {Login: "dev", Role: "member"}}
	s.Teams = []model.Team{{Slug: "platform", Members: []string{"dev"}, RepoGrants: []model.TeamRepoGrant{{Repo: "api", Permission: "write"}}}}
	s.Repos = []model.Repo{
		{Name: "api", Private: true, DirectCollaborators: []model.RepoGrant{{Login: "vic", Permission: "write"}}},
		{Name: "infra", Private: true, DirectCollaborators: []model.RepoGrant{{Login: "dev", Permission: "admin"}}},
		{Name: "legacy", Private: true, Archived: true},
	}
	for _, k := range []model.DataKind{model.DataMembers, model.DataMemberRoles, model.DataTeamMembers, model.DataTeamRepos, model.DataRepoDirectCollaborators, model.DataOrgRoles} {
		s.Coverage.OK(k, 1)
	}
	return s
}

func TestBuildAccessHTML(t *testing.T) {
	v := buildAccessHTML(accessSnapshot())
	if v == nil || len(v.Members) != 3 || len(v.Repos) != 2 || v.Archived != 1 {
		t.Fatalf("view = %+v, want 3 people, 2 repositories, 1 archived left out", v)
	}
	byName := map[string]accessRowView{}
	for _, r := range append(v.Members, v.Repos...) {
		byName[r.Name] = r
	}
	if dev := byName["dev"]; dev.Summary != "2 repositories · up to admin" || dev.Anchor != "access-m-dev" || !strings.Contains(dev.Search, "platform") {
		t.Errorf("dev row = %+v", dev)
	}
	if olga := byName["olga"]; olga.Tag != "owner" || olga.Summary != "admin everywhere" {
		t.Errorf("olga row = %+v", olga)
	}
	if vic := byName["vic"]; vic.Tag != "outside collaborator" {
		t.Errorf("vic row = %+v", vic)
	}
	api := byName["api"]
	if api.Summary != "2 with a specific grant · 2 can write" || len(api.OrgWide) != 2 {
		t.Errorf("api row = %+v", api)
	}
}

func TestBuildAccessHTML_TooLarge(t *testing.T) {
	defer func(n int) { accessRowLimit = n }(accessRowLimit)
	accessRowLimit = 1
	v := buildAccessHTML(accessSnapshot())
	if v.TooLarge == "" || v.Members != nil || !strings.Contains(v.TooLarge, "scopeward access --org acme") {
		t.Errorf("too large: %+v", v)
	}
}

// A finding links to the Access row it is about, and only when that row is
// rendered: never a link to nowhere.
func TestHTML_FindingsLinkToAccess(t *testing.T) {
	findings := []model.Finding{
		{CheckID: "perms.direct-admin-grant", Title: "dev has direct admin on acme/infra", Severity: model.SevMedium, Axis: model.AxisTeams,
			Resource: model.ResourceRef{Type: "repo", Name: "acme/infra"}},
		{CheckID: "hygiene.stale-repo", Title: "acme/legacy is stale", Severity: model.SevLow, Axis: model.AxisHygiene,
			Resource: model.ResourceRef{Type: "repo", Name: "acme/legacy"}},
	}
	a := Audit{Snapshot: accessSnapshot(), Report: check.Report{Findings: findings}}
	var buf bytes.Buffer
	if err := HTML(&buf, a); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		`id="access"`, `id="access-r-infra"`, `id="access-m-dev"`,
		`href="#access-r-infra"`, "Role-based access only", "1 archived not listed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("html missing %q", want)
		}
	}
	if strings.Contains(out, `href="#access-r-legacy"`) {
		t.Error("archived repository is not rendered, so the finding must not link to it")
	}
}
