// Package auth resolves the GitHub token from the environment or an interactive
// prompt and holds it in memory only. The token is never persisted to disk,
// logs, traces, or crash dumps — see Secret.
package auth

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sunnysystems/scopeward/internal/term"
	xterm "golang.org/x/term"
)

// EnvVars are the environment variables checked, in order, for a token.
var EnvVars = []string{"GITHUB_TOKEN", "GH_TOKEN"}

// ErrNoToken means no token was found in the environment and we could not
// prompt for one (no interactive stdin).
var ErrNoToken = errors.New("no GitHub token found: set GITHUB_TOKEN (or GH_TOKEN), or run in a terminal to be prompted")

// Source describes where the token came from, for honest reporting.
type Source string

const (
	SourceEnv    Source = "env"
	SourcePrompt Source = "prompt"
)

// Resolve obtains the token, preferring the environment so headless runs work
// with zero interaction, and falling back to a no-echo prompt when interactive.
func Resolve(prompt io.Writer) (Secret, Source, error) {
	for _, name := range EnvVars {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return NewSecret(v), SourceEnv, nil
		}
	}

	if !term.IsStdinTTY() {
		return Secret{}, "", ErrNoToken
	}

	tok, err := promptNoEcho(prompt)
	if err != nil {
		return Secret{}, "", err
	}
	if tok == "" {
		return Secret{}, "", ErrNoToken
	}
	return NewSecret(tok), SourcePrompt, nil
}

// promptNoEcho reads a token from the terminal without echoing it.
func promptNoEcho(prompt io.Writer) (string, error) {
	if prompt == nil {
		prompt = os.Stderr
	}
	fmt.Fprint(prompt, "GitHub token (read-only scopes; not stored): ")
	b, err := xterm.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(prompt)
	if err != nil {
		return "", fmt.Errorf("reading token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}
