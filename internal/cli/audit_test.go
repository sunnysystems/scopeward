package cli

import (
	"context"
	"testing"

	"github.com/sunnysystems/scopeward/internal/check"
	"github.com/sunnysystems/scopeward/internal/model"
)

type scopedCheck struct {
	id    string
	kinds []model.DataKind
}

func (s scopedCheck) Meta() check.CheckMeta {
	return check.CheckMeta{ID: s.id, RequiresData: s.kinds}
}
func (s scopedCheck) Run(context.Context, *model.Snapshot) []model.Finding { return nil }

func TestCheckScope(t *testing.T) {
	cases := []struct {
		kinds []model.DataKind
		want  string
	}{
		{[]model.DataKind{model.DataMembers}, "org"},
		{[]model.DataKind{model.DataRepos, model.DataBranchProtection}, "repo"},
		{[]model.DataKind{model.DataAccount}, "account"},
		{[]model.DataKind{model.DataAccount, model.DataMembers}, "org"}, // org wins
		{[]model.DataKind{model.DataWorkflows}, "repo"},
	}
	for _, tc := range cases {
		if got := checkScope(check.CheckMeta{RequiresData: tc.kinds}); got != tc.want {
			t.Errorf("scope(%v) = %q, want %q", tc.kinds, got, tc.want)
		}
	}
}

func TestFilterByMode(t *testing.T) {
	all := []check.Check{
		scopedCheck{"org", []model.DataKind{model.DataMembers}},
		scopedCheck{"repo", []model.DataKind{model.DataRepos}},
		scopedCheck{"account", []model.DataKind{model.DataAccount}},
	}

	user := filterByMode(all, true)
	if has(user, "org") || !has(user, "repo") || !has(user, "account") {
		t.Errorf("user mode = %v, want repo+account, no org", ids(user))
	}
	org := filterByMode(all, false)
	if !has(org, "org") || !has(org, "repo") || has(org, "account") {
		t.Errorf("org mode = %v, want org+repo, no account", ids(org))
	}
}

func TestTargetSelection(t *testing.T) {
	if s, u, self := (&options{me: true}).target("alice"); s != "alice" || !u || !self {
		t.Errorf("--me → (%q,%v,%v)", s, u, self)
	}
	if s, u, self := (&options{user: "bob"}).target("alice"); s != "bob" || !u || self {
		t.Errorf("--user → (%q,%v,%v)", s, u, self)
	}
	if s, u, _ := (&options{org: "acme"}).target("alice"); s != "acme" || u {
		t.Errorf("--org → (%q,%v)", s, u)
	}
	if s, _, _ := (&options{}).target("alice"); s != "" {
		t.Errorf("none → %q, want empty", s)
	}
}

func TestValidateTargetFlags(t *testing.T) {
	if err := validateTargetFlags(&options{org: "a", me: true}); err == nil {
		t.Error("org+me should error")
	}
	if err := validateTargetFlags(&options{user: "u"}); err != nil {
		t.Errorf("single target should be ok: %v", err)
	}
	if err := validateTargetFlags(&options{}); err != nil {
		t.Errorf("no target should be ok: %v", err)
	}
}

func TestValidateRepoFlags(t *testing.T) {
	if err := validateRepoFlags(&options{repos: []string{"api"}}); err == nil {
		t.Error("--repo without a target should error")
	}
	if err := validateRepoFlags(&options{org: "a", repos: []string{"api"}, quick: true}); err == nil {
		t.Error("--repo with --quick should error")
	}
	if err := validateRepoFlags(&options{org: "a", repos: []string{"api["}}); err == nil {
		t.Error("malformed glob should error")
	}
	if err := validateRepoFlags(&options{org: "a", repos: []string{"api-*"}}); err != nil {
		t.Errorf("--org with --repo should be ok: %v", err)
	}
	if err := validateRepoFlags(&options{me: true, repos: []string{"api"}}); err != nil {
		t.Errorf("--me with --repo should be ok: %v", err)
	}
	if err := validateRepoFlags(&options{quick: true}); err != nil {
		t.Errorf("no --repo should be ok whatever else is set: %v", err)
	}
}

func has(cs []check.Check, id string) bool {
	for _, c := range cs {
		if c.Meta().ID == id {
			return true
		}
	}
	return false
}
func ids(cs []check.Check) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Meta().ID)
	}
	return out
}
