package checks

import (
	"reflect"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

// The cases are GitHub's own CODEOWNERS documentation examples.
func TestCodeownersPattern(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"*", "AGENTS.md", true},
		{"*", ".claude/settings.json", true},
		{"*.js", "src/app.js", true},
		{"*.js", "src/app.ts", false},
		{"/build/logs/", "build/logs/out.txt", true},
		{"/build/logs/", "x/build/logs/out.txt", false},
		{"docs/*", "docs/getting-started.md", true},
		{"docs/*", "docs/build-app/troubleshooting.md", false},
		{"apps/", "apps/a.go", true},
		{"apps/", "deep/apps/a.go", true},
		{"/docs/", "docs/a/b.md", true},
		{"/docs/", "src/docs/a.md", false},
		{"**/logs", "a/b/logs/x.txt", true},
		{"**/logs", "logs/x.txt", true},
		{"/scripts/", "scripts/deploy.sh", true},
		{"/AGENTS.md", "AGENTS.md", true},
		{"/AGENTS.md", "docs/AGENTS.md", false},
		{"AGENTS.md", "docs/AGENTS.md", true},
		{".claude", ".claude/settings.json", true},
		{"/.github/", ".github/copilot-instructions.md", true},
		{"docs/**", "docs/a/b/c.md", true},
		{"a/**/b", "a/x/y/b", true},
		{"a/**/b", "a/b", true},
		{"/AGENTS.md", "agents.md", false}, // paths are case-sensitive
	}
	for _, tc := range cases {
		re := codeownersPattern(tc.pattern)
		if got := re != nil && re.MatchString(tc.path); got != tc.want {
			t.Errorf("pattern %q on %q = %v, want %v (re %v)", tc.pattern, tc.path, got, tc.want, re)
		}
	}
}

func TestCodeownersFor_LastMatchWinsAndEmptyUnowns(t *testing.T) {
	rules := []model.CodeownersRule{
		{Pattern: "*", Owners: []string{"@acme/platform"}},
		{Pattern: "/apps/", Owners: []string{"@acme/apps"}},
		{Pattern: "/apps/github"},
	}
	if got := codeownersFor(rules, "apps/web/x.go"); !reflect.DeepEqual(got, []string{"@acme/apps"}) {
		t.Errorf("apps/web = %v, want the later, more specific owner", got)
	}
	if got := codeownersFor(rules, "apps/github/x.go"); len(got) != 0 {
		t.Errorf("apps/github = %v, want unowned by the owner-less rule", got)
	}
	if got := codeownersFor(nil, "AGENTS.md"); got != nil {
		t.Errorf("no rules = %v, want nil", got)
	}
}
