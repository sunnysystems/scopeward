// Package progress shows what a long-running collection is doing. On a terminal
// it animates a single spinner line on stderr; without a TTY (CI, SSH) it falls
// back to plain one-line-per-stage logs. It always writes to stderr so stdout
// stays clean for piped text/JSON output.
package progress

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/sunnysystems/scopeward/internal/ui"
)

var frames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner implements collect.Reporter. The zero value is not usable; call New.
type Spinner struct {
	w   io.Writer
	tty bool

	mu        sync.Mutex
	msg       string
	repoDone  int
	repoTotal int
	frame     int
	rate      func() (remaining int, resetIn time.Duration, known, waiting bool)

	stop chan struct{}
	done chan struct{}
}

// New returns a Spinner writing to w. When tty is false it logs plain lines
// instead of animating; pass term.IsStderrTTY() for w == os.Stderr.
func New(w io.Writer, tty bool) *Spinner {
	return &Spinner{w: w, tty: tty, stop: make(chan struct{}), done: make(chan struct{})}
}

// SetRateFunc supplies live rate-limit status to display on the spinner line.
func (s *Spinner) SetRateFunc(fn func() (remaining int, resetIn time.Duration, known, waiting bool)) {
	s.mu.Lock()
	s.rate = fn
	s.mu.Unlock()
}

// Notice prints a one-off message. On a TTY it is suppressed (the animated line
// already reflects state, e.g. the rate-limit pause); on a non-TTY it logs a
// line so headless runs still surface events like a rate-limit wait.
func (s *Spinner) Notice(msg string) {
	if !s.tty {
		fmt.Fprintf(s.w, "  %s\n", msg)
	}
}

// Start begins animating (TTY only). Call Stop when collection finishes.
func (s *Spinner) Start() {
	if !s.tty {
		close(s.done)
		return
	}
	go s.loop()
}

func (s *Spinner) loop() {
	defer close(s.done)
	ticker := time.NewTicker(90 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			s.clearLine()
			return
		case <-ticker.C:
			s.render()
		}
	}
}

// Stage announces a new phase. On a TTY it updates the live line; otherwise it
// prints one line.
func (s *Spinner) Stage(msg string) {
	s.mu.Lock()
	s.msg = msg
	s.repoTotal = 0 // reset any per-repo counter from a previous stage
	s.mu.Unlock()
	if !s.tty {
		fmt.Fprintf(s.w, "  %s…\n", msg)
	}
}

// SetRepoProgress updates the scanned/total repo counter shown on the line.
// On a non-TTY it is a no-op (the stage line already told the user the count).
func (s *Spinner) SetRepoProgress(done, total int) {
	if !s.tty {
		return
	}
	s.mu.Lock()
	s.repoDone, s.repoTotal = done, total
	s.mu.Unlock()
}

// Stop ends the animation and clears the line.
func (s *Spinner) Stop() {
	if s.tty {
		close(s.stop)
	}
	<-s.done
}

func (s *Spinner) render() {
	s.mu.Lock()
	frame := frames[s.frame%len(frames)]
	s.frame++
	line := s.msg
	if s.repoTotal > 0 {
		line = fmt.Sprintf("%s (%d/%d)", s.msg, s.repoDone, s.repoTotal)
	}
	rate := s.rate
	s.mu.Unlock()

	if rate != nil {
		if rem, resetIn, known, waiting := rate(); waiting {
			line += ui.Subtle.Render(fmt.Sprintf("  · paused %s for rate reset", resetIn.Round(time.Second)))
		} else if known {
			line += ui.Subtle.Render(fmt.Sprintf("  · %d req left", rem))
		}
	}
	fmt.Fprintf(s.w, "\r\033[K%s %s", ui.Accent.Render(frame), line)
}

func (s *Spinner) clearLine() {
	fmt.Fprint(s.w, "\r\033[K")
}
