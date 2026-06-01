// Package term centralizes TTY detection so the rest of the tool can decide
// between the interactive experience (prompts, spinners, the Bubble Tea UI) and
// clean headless output (CI, SSH without a TTY).
package term

import (
	"os"

	"golang.org/x/term"
)

// IsInteractive reports whether both stdin and stdout are attached to a
// terminal. We require both: stdin so we can prompt for a token without echo,
// and stdout so styled/animated output makes sense.
func IsInteractive() bool {
	return IsStdinTTY() && IsStdoutTTY()
}

// IsStdinTTY reports whether stdin is a terminal (can we prompt the user?).
func IsStdinTTY() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// IsStdoutTTY reports whether stdout is a terminal (can we render styled output?).
func IsStdoutTTY() bool { return term.IsTerminal(int(os.Stdout.Fd())) }

// IsStderrTTY reports whether stderr is a terminal. Progress indicators write to
// stderr (keeping stdout clean for piped output), so this gates the spinner.
func IsStderrTTY() bool { return term.IsTerminal(int(os.Stderr.Fd())) }
