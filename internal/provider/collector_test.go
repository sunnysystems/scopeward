package provider

import (
	"context"
	"io"
	"testing"

	"github.com/sunnysystems/scopeward/internal/auth"
	"github.com/sunnysystems/scopeward/internal/model"
)

func TestParse(t *testing.T) {
	cases := []struct {
		flag, host string
		want       model.Provider
		wantErr    bool
	}{
		{"github", "", model.ProviderGitHub, false},
		{"gitlab", "", model.ProviderGitLab, false},
		{"GitLab", "", model.ProviderGitLab, false},                     // case-insensitive
		{"", "", model.ProviderGitHub, false},                           // default
		{"", "https://gitlab.example.com", model.ProviderGitLab, false}, // auto-detect from host
		{"auto", "https://gitlab.com", model.ProviderGitLab, false},
		{"github", "https://gitlab.com", model.ProviderGitHub, false}, // explicit flag wins over host hint
		{"bitbucket", "", "", true},
	}
	for _, c := range cases {
		got, err := Parse(c.flag, c.host)
		if c.wantErr {
			if err == nil {
				t.Errorf("Parse(%q,%q) expected error", c.flag, c.host)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q,%q) unexpected error: %v", c.flag, c.host, err)
		}
		if got != c.want {
			t.Errorf("Parse(%q,%q) = %q, want %q", c.flag, c.host, got, c.want)
		}
	}
}

func TestResolveTokenFromEnv(t *testing.T) {
	t.Run("github", func(t *testing.T) {
		t.Setenv("GITHUB_TOKEN", "ghp_secret")
		tok, label, err := ResolveToken(model.ProviderGitHub, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if tok.Expose() != "ghp_secret" {
			t.Errorf("token = %q", tok.Expose())
		}
		if label != "env (GITHUB_TOKEN)" {
			t.Errorf("label = %q, want env (GITHUB_TOKEN)", label)
		}
	})

	t.Run("gitlab prefers GITLAB_TOKEN over CI_JOB_TOKEN", func(t *testing.T) {
		t.Setenv("GITLAB_TOKEN", "glpat-primary")
		t.Setenv("CI_JOB_TOKEN", "job-fallback")
		tok, label, err := ResolveToken(model.ProviderGitLab, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if tok.Expose() != "glpat-primary" {
			t.Errorf("token = %q, want the GITLAB_TOKEN value", tok.Expose())
		}
		if label != "env (GITLAB_TOKEN)" {
			t.Errorf("label = %q, want env (GITLAB_TOKEN)", label)
		}
	})

	t.Run("gitlab falls back to CI_JOB_TOKEN", func(t *testing.T) {
		t.Setenv("GITLAB_TOKEN", "")
		t.Setenv("CI_JOB_TOKEN", "job-token")
		tok, label, err := ResolveToken(model.ProviderGitLab, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if tok.Expose() != "job-token" || label != "env (CI_JOB_TOKEN)" {
			t.Errorf("got (%q, %q), want job-token / env (CI_JOB_TOKEN)", tok.Expose(), label)
		}
	})
}

func TestNewUnknownProvider(t *testing.T) {
	if _, err := New(Config{Provider: model.Provider("bitbucket")}); err == nil {
		t.Error("New with unknown provider should error")
	}
}

func TestGitLabCollector(t *testing.T) {
	coll, err := New(Config{
		Provider: model.ProviderGitLab,
		Host:     "https://gitlab.example.com",
		Token:    auth.NewSecret("glpat-x"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if coll.Kind() != model.ProviderGitLab {
		t.Errorf("Kind = %q, want gitlab", coll.Kind())
	}
	if !coll.CollectsData() {
		t.Error("GitLab collector now collects the identity axis (#4)")
	}
	// User/account audits aren't modeled yet; that path must error without a
	// network call (group collection is exercised in internal/collectgl).
	if _, err := coll.Collect(context.Background(), Args{UserMode: true, Subject: "someone"}); err == nil {
		t.Error("GitLab user-mode Collect should return an error")
	}
}

func TestGitHubCollectorCollectsData(t *testing.T) {
	coll, err := New(Config{Provider: model.ProviderGitHub, Token: auth.NewSecret("ghp_x")})
	if err != nil {
		t.Fatal(err)
	}
	if !coll.CollectsData() {
		t.Error("GitHub collector should report CollectsData() == true")
	}
	if coll.Kind() != model.ProviderGitHub {
		t.Errorf("Kind = %q, want github", coll.Kind())
	}
}
