package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// newRepo creates an isolated git work tree in a temp dir. The user's global and
// system git config are neutralised so a personal core.excludesFile cannot
// decide the outcome of these tests.
func newRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)

	dir := t.TempDir()
	if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	return dir
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInspectOutput(t *testing.T) {
	t.Run("ignored file is safe", func(t *testing.T) {
		repo := newRepo(t)
		write(t, filepath.Join(repo, ".gitignore"), "fixes*.sh\n")
		out := filepath.Join(repo, "fixes.sh")
		write(t, out, "# commands")

		if got := inspectOutput(context.Background(), out); got != outputSafe {
			t.Errorf("got %v, want outputSafe", got)
		}
	})

	t.Run("unignored file is committable", func(t *testing.T) {
		repo := newRepo(t)
		out := filepath.Join(repo, "acme-fixes.sh")
		write(t, out, "# commands")

		if got := inspectOutput(context.Background(), out); got != outputCommittable {
			t.Errorf("got %v, want outputCommittable", got)
		}
	})

	t.Run("subdirectory output is still seen", func(t *testing.T) {
		repo := newRepo(t)
		out := filepath.Join(repo, "reports", "audit.html")
		write(t, out, "<html>")

		if got := inspectOutput(context.Background(), out); got != outputCommittable {
			t.Errorf("got %v, want outputCommittable", got)
		}
	})

	// A tracked file reports as "not ignored" even when a pattern matches it,
	// because exclude rules stop applying once a path is in the index. It has to
	// be told apart, or we suggest a .gitignore line that would do nothing.
	t.Run("tracked file is reported as tracked", func(t *testing.T) {
		repo := newRepo(t)
		write(t, filepath.Join(repo, ".gitignore"), "fixes*.sh\n")
		out := filepath.Join(repo, "fixes.sh")
		write(t, out, "# commands")
		if o, err := exec.Command("git", "-C", repo, "add", "-f", "fixes.sh").CombinedOutput(); err != nil {
			t.Fatalf("git add: %v: %s", err, o)
		}

		if got := inspectOutput(context.Background(), out); got != outputTracked {
			t.Errorf("got %v, want outputTracked", got)
		}
	})

	t.Run("outside a work tree says nothing", func(t *testing.T) {
		if _, err := exec.LookPath("git"); err != nil {
			t.Skip("git not installed")
		}
		dir := t.TempDir()
		// Stop git walking up into a repository that happens to contain TMPDIR.
		t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
		out := filepath.Join(dir, "fixes.sh")
		write(t, out, "# commands")

		if got := inspectOutput(context.Background(), out); got != outputSafe {
			t.Errorf("got %v, want outputSafe", got)
		}
	})
}

func TestIgnoreLineFor(t *testing.T) {
	repo := newRepo(t)

	t.Run("anchors to the repository root", func(t *testing.T) {
		out := filepath.Join(repo, "acme-fixes.sh")
		write(t, out, "# commands")

		if got, want := ignoreLineFor(context.Background(), out), "/acme-fixes.sh"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("keeps the subdirectory", func(t *testing.T) {
		out := filepath.Join(repo, "reports", "audit.html")
		write(t, out, "<html>")

		if got, want := ignoreLineFor(context.Background(), out), "/reports/audit.html"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("falls back to the filename with no repository", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
		out := filepath.Join(dir, "acme-fixes.sh")
		write(t, out, "# commands")

		if got, want := ignoreLineFor(context.Background(), out), "acme-fixes.sh"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestWarnIfExposed(t *testing.T) {
	t.Run("names the file and the pattern to add", func(t *testing.T) {
		repo := newRepo(t)
		out := filepath.Join(repo, "acme-fixes.sh")
		write(t, out, "# commands")

		var buf bytes.Buffer
		warnIfExposed(context.Background(), &buf, out, false)

		got := buf.String()
		for _, want := range []string{out, "not ignored", "/acme-fixes.sh"} {
			if !strings.Contains(got, want) {
				t.Errorf("warning missing %q:\n%s", want, got)
			}
		}
	})

	t.Run("tells you to untrack an already-committed file", func(t *testing.T) {
		repo := newRepo(t)
		out := filepath.Join(repo, "acme-fixes.sh")
		write(t, out, "# commands")
		if o, err := exec.Command("git", "-C", repo, "add", "acme-fixes.sh").CombinedOutput(); err != nil {
			t.Fatalf("git add: %v: %s", err, o)
		}

		var buf bytes.Buffer
		warnIfExposed(context.Background(), &buf, out, false)

		got := buf.String()
		for _, want := range []string{"tracked by git", "git rm --cached"} {
			if !strings.Contains(got, want) {
				t.Errorf("warning missing %q:\n%s", want, got)
			}
		}
	})

	t.Run("quiet suppresses it", func(t *testing.T) {
		repo := newRepo(t)
		out := filepath.Join(repo, "acme-fixes.sh")
		write(t, out, "# commands")

		var buf bytes.Buffer
		warnIfExposed(context.Background(), &buf, out, true)

		if buf.Len() != 0 {
			t.Errorf("--quiet still printed: %s", buf.String())
		}
	})

	t.Run("silent when the file is ignored", func(t *testing.T) {
		repo := newRepo(t)
		write(t, filepath.Join(repo, ".gitignore"), "fixes*.sh\n")
		out := filepath.Join(repo, "fixes.sh")
		write(t, out, "# commands")

		var buf bytes.Buffer
		warnIfExposed(context.Background(), &buf, out, false)

		if buf.Len() != 0 {
			t.Errorf("warned about an ignored file: %s", buf.String())
		}
	})

	t.Run("silent outside a work tree", func(t *testing.T) {
		if _, err := exec.LookPath("git"); err != nil {
			t.Skip("git not installed")
		}
		dir := t.TempDir()
		t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
		out := filepath.Join(dir, "acme-fixes.sh")
		write(t, out, "# commands")

		var buf bytes.Buffer
		warnIfExposed(context.Background(), &buf, out, false)

		if buf.Len() != 0 {
			t.Errorf("warned outside a repository: %s", buf.String())
		}
	})
}
