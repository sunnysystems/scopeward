package access

import (
	"reflect"
	"strconv"
	"testing"
)

// nodeShape flattens a team tree for comparison: "team level[inherited] members".
func nodeShape(ns []TeamNode, depth int) []string {
	var out []string
	for _, n := range ns {
		inh := ""
		if n.Inherited {
			inh = " inherited"
		}
		indent := ""
		for i := 0; i < depth; i++ {
			indent += "  "
		}
		out = append(out, indent+n.Team+" "+n.Level.String()+inh+" "+joinLogins(n.Members)+" /"+strconv.Itoa(n.Roster))
		out = append(out, nodeShape(n.Children, depth+1)...)
	}
	return out
}

func joinLogins(ls []string) string {
	s := "["
	for i, l := range ls {
		if i > 0 {
			s += ","
		}
		s += l
	}
	return s + "]"
}

func TestForRepo_TeamTree(t *testing.T) {
	g := Build(org())
	api, _ := g.ForRepo("api")
	// platform holds write; payments inherits it (its own equal grant is the
	// copy GitHub lists on the child). pat is shown under payments only, while
	// platform's roster still counts them.
	want := []string{
		"platform write [dev] /2",
		"  payments write inherited [pat] /1",
	}
	if got := nodeShape(api.Teams, 0); !reflect.DeepEqual(got, want) {
		t.Errorf("api teams = %v, want %v", got, want)
	}
	var direct []string
	for _, d := range api.Direct {
		label := d.Login + "=" + d.Level.String()
		if d.Outside {
			label += " outside"
		}
		direct = append(direct, label)
	}
	if want := []string{"deploy-bot[bot]=write outside", "vic=write outside", "dev=read"}; !reflect.DeepEqual(direct, want) {
		t.Errorf("api direct = %v, want %v", direct, want)
	}

	// billing is granted to the child alone: it stands as a root.
	billing, _ := g.ForRepo("billing")
	if got := nodeShape(billing.Teams, 0); !reflect.DeepEqual(got, []string{"payments admin [pat] /1"}) {
		t.Errorf("billing teams = %v", got)
	}
}

// A child's own grant counts when it is stronger than what it inherits.
func TestForRepo_ChildStrongerThanParent(t *testing.T) {
	s := org()
	s.Teams[1].RepoGrants[1].Permission = "admin" // payments: admin on api, above platform's write
	g := Build(s)
	api, _ := g.ForRepo("api")
	if got := nodeShape(api.Teams, 0); got[1] != "  payments admin [pat] /1" {
		t.Errorf("child with its own stronger grant = %v", got)
	}
}

func TestForTeam(t *testing.T) {
	g := Build(org())
	if got := g.Teams(); !reflect.DeepEqual(got, []string{"payments", "platform", "sre"}) {
		t.Errorf("teams = %v", got)
	}
	pay, ok := g.ForTeam("payments", Options{})
	if !ok || !reflect.DeepEqual(pay.Ancestors, []string{"platform"}) || !reflect.DeepEqual(pay.Members, []string{"pat"}) {
		t.Fatalf("payments = %+v", pay)
	}
	// billing is its own; api is platform's grant, which it inherits.
	want := []TeamRepo{{Repo: "billing", Level: Admin, From: "payments"}, {Repo: "api", Level: Write, From: "platform"}}
	if !reflect.DeepEqual(pay.Repos, want) {
		t.Errorf("payments repos = %+v, want %+v", pay.Repos, want)
	}
	plat, _ := g.ForTeam("platform", Options{})
	if !reflect.DeepEqual(plat.Children, []string{"payments"}) || !reflect.DeepEqual(plat.Members, []string{"dev", "pat"}) {
		t.Errorf("platform = %+v", plat)
	}
	sre, _ := g.ForTeam("sre", Options{})
	if len(sre.OrgRoles) != 1 || sre.OrgRoles[0].Role != "all_repo_write" {
		t.Errorf("sre org roles = %+v", sre.OrgRoles)
	}
	if _, ok := g.ForTeam("nope", Options{}); ok {
		t.Error("unknown team resolved")
	}
}

func TestForMember_Teams(t *testing.T) {
	g := Build(org())
	for login, want := range map[string][][]string{
		"pat":  {{"platform", "payments"}},
		"dev":  {{"platform"}},
		"carl": {{"sre"}},
		"olga": nil,
	} {
		v, _ := g.ForMember(login, Options{})
		if !reflect.DeepEqual(v.Teams, want) {
			t.Errorf("%s teams = %v, want %v", login, v.Teams, want)
		}
	}
}
