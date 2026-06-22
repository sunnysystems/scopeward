package cli

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/provider"
)

var update = flag.Bool("update", false, "regenerate preflight golden files")

func githubPreflight() *provider.Preflight {
	return &provider.Preflight{
		Provider:    model.ProviderGitHub,
		Login:       "octocat",
		TokenType:   "classic_pat",
		TokenSource: "env (GITHUB_TOKEN)",
		Scopes:      []string{"read:org", "repo"},
		Missing:     []string{"admin:org"},
		RateLimit:   provider.RateLimit{Limit: 5000, Remaining: 4983},
	}
}

func gitlabPreflight() *provider.Preflight {
	return &provider.Preflight{
		Provider:    model.ProviderGitLab,
		Host:        "https://gitlab.example.com",
		Login:       "root",
		TokenType:   "personal_access_token",
		TokenSource: "env (GITLAB_TOKEN)",
		Scopes:      []string{"read_api", "read_user"},
		RateLimit:   provider.RateLimit{Limit: 2000, Remaining: 1999},
	}
}

// TestPreflightJSONGolden locks the machine-readable preflight shape for both
// providers across the render refactor.
func TestPreflightJSONGolden(t *testing.T) {
	cases := map[string]*provider.Preflight{
		"preflight_github.json": githubPreflight(),
		"preflight_gitlab.json": gitlabPreflight(),
	}
	for name, pf := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := renderProbeJSON(&buf, pf); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", name)
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run with -update to seed): %v", err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("%s differs from golden:\n%s", name, buf.String())
			}
		})
	}
}

// TestPreflightTextContent asserts the human output carries the key facts. It
// checks content rather than exact bytes because the Text renderer emits
// lipgloss ANSI that varies with the terminal environment.
func TestPreflightTextContent(t *testing.T) {
	t.Run("github", func(t *testing.T) {
		var buf bytes.Buffer
		renderProbeText(&buf, githubPreflight())
		out := buf.String()
		for _, want := range []string{"preflight (github)", "octocat", "env (GITHUB_TOKEN)", "read:org, repo", "admin:org", "limited coverage"} {
			if !strings.Contains(out, want) {
				t.Errorf("github preflight text missing %q\n%s", want, out)
			}
		}
	})

	t.Run("gitlab", func(t *testing.T) {
		var buf bytes.Buffer
		renderProbeText(&buf, gitlabPreflight())
		out := buf.String()
		for _, want := range []string{"preflight (gitlab)", "gitlab.example.com", "root", "env (GITLAB_TOKEN)", "read_api, read_user", "recommended read scopes"} {
			if !strings.Contains(out, want) {
				t.Errorf("gitlab preflight text missing %q\n%s", want, out)
			}
		}
	})
}
