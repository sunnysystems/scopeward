package access

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

// org builds a small organization exercising every source:
//
//   - owner "olga" (admin everywhere); base permission read for every member;
//   - team "platform" with child "payments": platform holds write on "api",
//     payments holds admin on "billing". GitHub lists child members in the
//     parent's roster, so "pat" (in payments) appears in both;
//   - "dev" is a direct member of platform only;
//   - "carl" holds the all-repository role "all_repo_write" through team
//     "sre", and "erin" holds it directly;
//   - "vic" is an outside collaborator with write on "api";
//   - "deploy-bot[bot]" holds a direct grant on "api";
//   - "legacy" is archived; "site" is public.
func org() *model.Snapshot {
	s := model.NewSnapshot("acme")
	s.Org.DefaultRepoPermission = "read"
	s.Members = []model.Member{
		{Login: "olga", Role: "admin"},
		{Login: "dev", Role: "member"},
		{Login: "pat", Role: "member"},
		{Login: "carl", Role: "member"},
		{Login: "erin", Role: "member"},
	}
	s.Teams = []model.Team{
		{Slug: "platform", Members: []string{"dev", "pat"}, RepoGrants: []model.TeamRepoGrant{{Repo: "api", Permission: "write"}}},
		{Slug: "payments", ParentSlug: "platform", Members: []string{"pat"}, RepoGrants: []model.TeamRepoGrant{
			{Repo: "billing", Permission: "admin"},
			// The inherited copy a child team's repository list may carry.
			{Repo: "api", Permission: "write"},
		}},
		{Slug: "sre", Members: []string{"carl"}},
	}
	s.OrgRoles = []model.OrgRole{
		{Name: "all_repo_write", BaseRole: "write",
			Users: []model.OrgRoleAssignee{{Login: "carl", Assignment: "indirect"}, {Login: "erin", Assignment: "direct"}},
			Teams: []model.OrgRoleTeamGrant{{Slug: "sre", Assignment: "direct"}}},
		{Name: "security_manager"}, // org-only: no repository access
	}
	s.Repos = []model.Repo{
		{Name: "api", Private: true, DirectCollaborators: []model.RepoGrant{
			{Login: "vic", Permission: "write"},
			{Login: "deploy-bot[bot]", Permission: "write", IsBot: true},
			{Login: "dev", Permission: "read"}, // below what the team gives
		}},
		{Name: "billing", Private: true},
		{Name: "legacy", Private: true, Archived: true, DirectCollaborators: []model.RepoGrant{{Login: "dev", Permission: "admin"}}},
		{Name: "site", Private: false},
	}
	for _, k := range []model.DataKind{model.DataMembers, model.DataMemberRoles, model.DataTeamMembers, model.DataTeamRepos, model.DataRepoDirectCollaborators, model.DataOrgRoles} {
		s.Coverage.OK(k, 1)
	}
	return s
}

func paths(gs []Grant) []string {
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.Level.String()+" "+g.Path())
	}
	return out
}

func TestForMember_NestedTeamPathAndInheritedCopy(t *testing.T) {
	g := Build(org())
	v, ok := g.ForMember("pat", Options{})
	if !ok {
		t.Fatal("pat unknown")
	}
	got := map[string][]string{}
	for _, a := range v.Repos {
		got[a.Repo] = paths(a.Grants)
	}
	want := map[string][]string{
		"billing": {"admin team payments"},
		// platform's grant reaches pat through payments; the copy on payments'
		// own list is the same access, not a second path.
		"api": {"write team platform → payments"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("pat's repos = %v, want %v", got, want)
	}
	if v.Repos[0].Repo != "billing" {
		t.Errorf("strongest first: got %s first", v.Repos[0].Repo)
	}
	if !reflect.DeepEqual(paths(v.OrgWide), []string{"read organization base permission"}) {
		t.Errorf("pat's org-wide = %v", paths(v.OrgWide))
	}
}

func TestForMember_ArchivedHiddenUnlessAsked(t *testing.T) {
	g := Build(org())
	v, _ := g.ForMember("dev", Options{})
	for _, a := range v.Repos {
		if a.Repo == "legacy" {
			t.Error("archived repository listed by default")
		}
	}
	v, _ = g.ForMember("dev", Options{IncludeArchived: true})
	found := false
	for _, a := range v.Repos {
		found = found || a.Repo == "legacy"
	}
	if !found {
		t.Error("archived repository missing when asked for")
	}
}

func TestForMember_EffectiveCountsOrgWide(t *testing.T) {
	g := Build(org())
	v, _ := g.ForMember("dev", Options{})
	var api Access
	for _, a := range v.Repos {
		if a.Repo == "api" {
			api = a
		}
	}
	// The direct read grant adds nothing over platform's write; both are shown.
	if api.Effective != Write || !reflect.DeepEqual(paths(api.Grants), []string{"write team platform", "read direct grant"}) {
		t.Errorf("dev on api = %v %v", api.Effective, paths(api.Grants))
	}
	if api.RaisedBy != nil {
		t.Errorf("dev's base read does not beat the team's write: raised by %v", api.RaisedBy.Path())
	}
}

// An owner's admin beats any team grant: the access names what raised it.
func TestAccess_RaisedByOrgWide(t *testing.T) {
	s := org()
	s.Teams[0].Members = append(s.Teams[0].Members, "olga")
	g := Build(s)
	v, _ := g.ForRepo("api")
	for _, a := range v.People {
		if a.Login != "olga" {
			continue
		}
		if a.Effective != Admin || a.TopSpecific() != Write || a.RaisedBy == nil || a.RaisedBy.Kind != SourceOwner {
			t.Errorf("olga on api = effective %v, specific %v, raised by %v", a.Effective, a.TopSpecific(), a.RaisedBy)
		}
		return
	}
	t.Error("olga missing from api's people")
}

func TestForMember_OwnerAndOrgRoles(t *testing.T) {
	g := Build(org())
	olga, _ := g.ForMember("olga", Options{})
	if len(olga.OrgWide) == 0 || olga.OrgWide[0].Kind != SourceOwner || olga.OrgWide[0].Level != Admin {
		t.Errorf("owner org-wide = %v", paths(olga.OrgWide))
	}
	carl, _ := g.ForMember("carl", Options{})
	if !reflect.DeepEqual(paths(carl.OrgWide), []string{"write organization role all_repo_write via team sre", "read organization base permission"}) {
		t.Errorf("carl org-wide = %v", paths(carl.OrgWide))
	}
	erin, _ := g.ForMember("erin", Options{})
	if !reflect.DeepEqual(paths(erin.OrgWide), []string{"write organization role all_repo_write", "read organization base permission"}) {
		t.Errorf("erin org-wide = %v", paths(erin.OrgWide))
	}
}

func TestForMember_OutsideCollaboratorAndUnknown(t *testing.T) {
	g := Build(org())
	v, ok := g.ForMember("vic", Options{})
	if !ok || !v.Outside || len(v.OrgWide) != 0 || len(v.Repos) != 1 || v.Repos[0].Effective != Write {
		t.Errorf("vic = %+v, want an outside collaborator with write on api only and no base permission", v)
	}
	if _, ok := g.ForMember("nobody", Options{}); ok {
		t.Error("unknown login resolved")
	}
}

func TestForRepo(t *testing.T) {
	g := Build(org())
	v, ok := g.ForRepo("api")
	if !ok {
		t.Fatal("api unknown")
	}
	var people []string
	for _, a := range v.People {
		label := a.Login + "=" + a.Effective.String()
		if a.Outside {
			label += " outside"
		}
		if a.Bot {
			label += " bot"
		}
		people = append(people, label)
	}
	want := []string{"deploy-bot[bot]=write outside bot", "dev=write", "pat=write", "vic=write outside"}
	if !reflect.DeepEqual(people, want) {
		t.Errorf("api people = %v, want %v", people, want)
	}
	var groups []string
	for _, ow := range v.OrgWide {
		who := strings.Join(ow.Logins, ",")
		if ow.Everyone {
			who = "everyone"
		}
		groups = append(groups, ow.Grant.Level.String()+" "+ow.Grant.Path()+": "+who)
	}
	wantGroups := []string{
		"admin organization owner: olga",
		"write organization role all_repo_write: carl,erin",
		"read organization base permission: everyone",
	}
	if !reflect.DeepEqual(groups, wantGroups) {
		t.Errorf("api org-wide = %v, want %v", groups, wantGroups)
	}

	site, _ := g.ForRepo("site")
	legacy, _ := g.ForRepo("legacy")
	if !site.Public || !legacy.Archived {
		t.Errorf("site public %v, legacy archived %v", site.Public, legacy.Archived)
	}
	if _, ok := g.ForRepo("nope"); ok {
		t.Error("unknown repository resolved")
	}
}

func TestReposHidesArchived(t *testing.T) {
	g := Build(org())
	if got := g.Repos(Options{}); !reflect.DeepEqual(got, []string{"api", "billing", "site"}) {
		t.Errorf("repos = %v", got)
	}
	if got := g.Repos(Options{IncludeArchived: true}); len(got) != 4 {
		t.Errorf("repos with archived = %v", got)
	}
}

// What was not collected is said, never guessed: --quick leaves teams unread,
// and an unreadable team roster still keeps an org role held through it.
func TestGapsAndUnreadTeamRoster(t *testing.T) {
	s := org()
	s.Coverage = model.NewSnapshot("acme").Coverage
	s.Coverage.OK(model.DataMembers, 5)
	s.Coverage.OK(model.DataMemberRoles, 5)
	s.Coverage.Missing(model.DataTeamMembers, "--quick")
	s.Coverage.Missing(model.DataTeamRepos, "--quick")
	s.Coverage.OK(model.DataRepoDirectCollaborators, 4)
	s.Coverage.Missing(model.DataOrgRoles, "plan")
	for i := range s.Teams {
		s.Teams[i].Members, s.Teams[i].RepoGrants = nil, nil
	}
	g := Build(s)
	joined := strings.Join(g.Gaps(), " | ")
	for _, want := range []string{"access through teams is not assessed", "all-repository roles are not assessed"} {
		if !strings.Contains(joined, want) {
			t.Errorf("gaps %q missing %q", joined, want)
		}
	}
	carl, _ := g.ForMember("carl", Options{})
	if len(carl.OrgWide) == 0 || carl.OrgWide[0].Path() != "organization role all_repo_write via team (team not read)" {
		t.Errorf("carl org-wide = %v", paths(carl.OrgWide))
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]Level{"admin": Admin, "maintain": Maintain, "write": Write, "triage": Triage, "read": Read, "none": None, "": None, "custom": None} {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}
