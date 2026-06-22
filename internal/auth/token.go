// Package auth resolves the provider token (GitHub or GitLab) from the
// environment or an interactive prompt and holds it in memory only. The token is
// never persisted to disk, logs, traces, or crash dumps — see Secret.
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

// TokenSpec describes how to source a provider's token: which environment
// variables to check (in order) and the provider noun shown in the prompt.
type TokenSpec struct {
	EnvVars    []string
	PromptNoun string // e.g. "GitHub" or "GitLab"
}

// ErrNoToken means no token was found in the environment and we could not prompt
// for one (no interactive stdin). Callers can match it with errors.Is.
var ErrNoToken = errors.New("no token found")

// Source describes where the token came from, for honest reporting.
type Source string

const (
	SourceEnv    Source = "env"
	SourcePrompt Source = "prompt"
)

// Resolve obtains the token per spec, preferring the environment so headless
// runs work with zero interaction, and falling back to a no-echo prompt when
// interactive. The returned envVar is the matched variable name (empty when
// prompted), for honest reporting.
func Resolve(spec TokenSpec, prompt io.Writer) (Secret, Source, string, error) {
	for _, name := range spec.EnvVars {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return NewSecret(v), SourceEnv, name, nil
		}
	}

	if !term.IsStdinTTY() {
		return Secret{}, "", "", fmt.Errorf("%w: set %s, or run in a terminal to be prompted",
			ErrNoToken, strings.Join(spec.EnvVars, " or "))
	}

	tok, err := promptNoEcho(spec.PromptNoun, prompt)
	if err != nil {
		return Secret{}, "", "", err
	}
	if tok == "" {
		return Secret{}, "", "", ErrNoToken
	}
	return NewSecret(tok), SourcePrompt, "", nil
}

// promptNoEcho reads a token from the terminal without echoing it.
func promptNoEcho(noun string, prompt io.Writer) (string, error) {
	if prompt == nil {
		prompt = os.Stderr
	}
	if noun == "" {
		noun = "API"
	}
	fmt.Fprintf(prompt, "%s token (read-only scopes; not stored): ", noun)
	b, err := xterm.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(prompt)
	if err != nil {
		return "", fmt.Errorf("reading token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}
