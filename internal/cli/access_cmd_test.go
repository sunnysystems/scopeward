package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/sunnysystems/scopeward/internal/access"
	"github.com/sunnysystems/scopeward/internal/model"
)

// accessGraph is an org where "olga" owns everything, "dev" reaches api
// through team platform and holds a direct admin grant on infra, and "vic" is
// an outside collaborator.
func accessGraph() *access.Graph {
	s := model.NewSnapshot("acme")
	s.Org.DefaultRepoPermission = "read"
	s.Members = []model.Member{{Login: "olga", Role: "admin"}, {Login: "dev", Role: "member"}}
	s.Teams = []model.Team{{Slug: "platform", Members: []string{"dev", "olga"}, RepoGrants: []model.TeamRepoGrant{{Repo: "api", Permission: "write"}}}}
	s.Repos = []model.Repo{
		{Name: "api", Private: true, DirectCollaborators: []model.RepoGrant{{Login: "vic", Permission: "write"}}},
		{Name: "infra", Private: true, DirectCollaborators: []model.RepoGrant{{Login: "dev", Permission: "admin"}}},
	}
	for _, k := range []model.DataKind{model.DataMembers, model.DataMemberRoles, model.DataTeamMembers, model.DataTeamRepos, model.DataRepoDirectCollaborators} {
		s.Coverage.OK(k, 1)
	}
	s.Coverage.Missing(model.DataOrgRoles, "plan")
	return access.Build(s)
}

func plainOutput(t *testing.T) {
	t.Helper()
	lipgloss.SetColorProfile(termenv.Ascii)
}

func TestRenderAccessMember_Text(t *testing.T) {
	plainOutput(t)
	g := accessGraph()
	v, _ := g.ForMember("dev", access.Options{})
	var buf bytes.Buffer
	if err := renderAccessMember(&buf, "text", "acme", v, g.Gaps(), false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"scopeward · access · acme · dev",
		"read      organization base permission",
		"admin     infra  direct grant",
		"write     api    team platform",
		"--include-archived",
		"Role-based access only",
		"Not assessed: organization roles were not readable",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("member text missing %q:\n%s", want, out)
		}
	}
}

// An owner's specific grants are all under their org-wide admin: said once,
// not on every line.
func TestRenderAccessMember_OwnerOverrideSaidOnce(t *testing.T) {
	plainOutput(t)
	g := accessGraph()
	v, _ := g.ForMember("olga", access.Options{})
	var buf bytes.Buffer
	_ = renderAccessMember(&buf, "text", "acme", v, nil, false)
	out := buf.String()
	if !strings.Contains(out, "none goes beyond organization owner (admin everywhere)") || strings.Contains(out, "as organization owner)") {
		t.Errorf("owner override not said exactly once:\n%s", out)
	}
	if !strings.Contains(out, "write     api  team platform") {
		t.Errorf("an overridden line should show its own level:\n%s", out)
	}
}

func TestRenderAccessRepo_TextAndJSON(t *testing.T) {
	plainOutput(t)
	g := accessGraph()
	v, _ := g.ForRepo("api")
	var buf bytes.Buffer
	_ = renderAccessRepo(&buf, "text", "acme", v, g.Gaps())
	out := buf.String()
	for _, want := range []string{
		"admin     organization owner  olga",
		"read      organization base permission  every member",
		"admin     olga  team platform  (admin as organization owner)",
		"write     vic   direct grant  outside collaborator",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("repo text missing %q:\n%s", want, out)
		}
	}

	buf.Reset()
	if err := renderAccessRepo(&buf, "json", "acme", v, nil); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		NotAssessed []string `json:"not_assessed"`
		People      []struct {
			Login   string `json:"login"`
			Outside bool   `json:"outside_collaborator"`
		} `json:"people"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, buf.String())
	}
	if doc.NotAssessed == nil || len(doc.People) != 3 || doc.People[2].Login != "vic" || !doc.People[2].Outside {
		t.Errorf("json = %+v", doc)
	}
	if !strings.Contains(buf.String(), `"not_assessed": []`) {
		t.Errorf("an empty gap list must be [] not null:\n%s", buf.String())
	}
}

func TestRenderAccess_Markdown(t *testing.T) {
	g := accessGraph()
	v, _ := g.ForRepo("api")
	var buf bytes.Buffer
	_ = renderAccessRepo(&buf, "markdown", "acme", v, g.Gaps())
	if !strings.Contains(buf.String(), "| vic (outside collaborator) | write | write direct grant |") {
		t.Errorf("markdown:\n%s", buf.String())
	}
}
