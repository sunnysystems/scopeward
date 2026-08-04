package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sunnysystems/scopeward/internal/ui"
)

// A fix script or report names the organization, its repositories, its team
// slugs and — ordered by severity — exactly where it is weakest. Committed to a
// repository, that is a targeting document. `.gitignore` covers the filenames
// the README documents, but the output path is the operator's argument to
// choose, so no pattern can cover every run. This is the backstop: after
// writing, ask git whether the file we just produced is one `git add .` away
// from being published.
//
// The check is advisory and must never be what makes an audit fail or hang:
// every error path here resolves to silence.

// gitProbeTimeout bounds the git invocations behind the warning.
const gitProbeTimeout = 2 * time.Second

// outputState is what git thinks of a file we just wrote.
type outputState int

const (
	// outputSafe covers both "git ignores it" and "we cannot tell" — not inside
	// a work tree, git is not installed, or git errored. Claiming nothing is the
	// only honest option when the answer is unknown, and a false alarm here
	// would train operators to ignore the one that matters.
	outputSafe outputState = iota
	// outputCommittable: inside a work tree, not ignored, not yet tracked.
	outputCommittable
	// outputTracked: already in the index. The exposure has happened; adding a
	// `.gitignore` line now would not undo it, so the advice has to differ.
	outputTracked
)

// inspectOutput asks git whether path is ignored, and if not, whether it is
// already tracked.
func inspectOutput(ctx context.Context, path string) outputState {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	// check-ignore exits 0 when a pattern matches, 1 when none does, and 128
	// when there is no repository here — which is also what we get when git is
	// missing, and both mean "say nothing".
	code, ok := gitExit(ctx, dir, "check-ignore", "-q", "--", base)
	if !ok || code != 1 {
		return outputSafe
	}

	// Not ignored. A tracked file reports as "not ignored" too, since exclude
	// rules do not apply once a path is in the index — worth separating, because
	// telling someone to add a pattern for a file they already committed is
	// advice that quietly does nothing.
	if code, ok := gitExit(ctx, dir, "ls-files", "--error-unmatch", "--", base); ok && code == 0 {
		return outputTracked
	}
	return outputCommittable
}

// warnIfExposed prints one warning when the file just written could be
// committed. It is suppressed by --quiet and whenever git cannot answer.
func warnIfExposed(ctx context.Context, w io.Writer, path string, quiet bool) {
	if quiet {
		return
	}
	switch inspectOutput(ctx, path) {
	case outputCommittable:
		fmt.Fprintln(w, ui.WarnTag.Render("⚠ "+path+" is in a git repository and is not ignored"))
		fmt.Fprintln(w, ui.Subtle.Render("  It maps where your organization is weakest. Add to .gitignore: ")+ui.Accent.Render(ignoreLineFor(ctx, path)))
	case outputTracked:
		fmt.Fprintln(w, ui.WarnTag.Render("⚠ "+path+" is tracked by git"))
		fmt.Fprintln(w, ui.Subtle.Render("  It maps where your organization is weakest, and it is already committed."))
		fmt.Fprintln(w, ui.Subtle.Render("  Untrack it: ")+ui.Accent.Render("git rm --cached "+path))
	}
}

// ignoreLineFor builds the `.gitignore` line to suggest: the path anchored to
// the repository root, so the suggestion ignores this file and nothing else.
// Falls back to the bare filename when the root cannot be resolved.
func ignoreLineFor(ctx context.Context, path string) string {
	base := filepath.Base(path)

	root, ok := gitOutput(ctx, filepath.Dir(path), "rev-parse", "--show-toplevel")
	if !ok {
		return base
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return base
	}
	// show-toplevel resolves symlinks; Abs does not. Without this they disagree
	// wherever the work tree sits behind one (/tmp on macOS, most notably) and
	// Rel escapes the root.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return base
	}
	return "/" + filepath.ToSlash(rel)
}

// gitExit runs git in dir and returns its exit code. ok is false when git could
// not be run at all (not installed, timed out), which is distinct from git
// running and reporting a non-zero status.
func gitExit(ctx context.Context, dir string, args ...string) (code int, ok bool) {
	if err := runGit(ctx, dir, nil, args...); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), true
		}
		return 0, false
	}
	return 0, true
}

// gitOutput runs git in dir and returns its trimmed stdout.
func gitOutput(ctx context.Context, dir string, args ...string) (string, bool) {
	var buf strings.Builder
	if err := runGit(ctx, dir, &buf, args...); err != nil {
		return "", false
	}
	return strings.TrimSpace(buf.String()), true
}

// runGit executes git with an explicit argument list — never a shell — so a
// path chosen by the operator cannot be reinterpreted as a command.
func runGit(ctx context.Context, dir string, stdout io.Writer, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, gitProbeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Stdout = stdout
	return cmd.Run()
}
