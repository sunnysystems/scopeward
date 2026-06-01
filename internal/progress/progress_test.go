package progress

import (
	"strings"
	"testing"
)

func TestNonTTYLogsStageLines(t *testing.T) {
	var buf strings.Builder
	s := New(&buf, false)
	s.Start()
	s.Stage("collecting members")
	s.SetRepoProgress(3, 10) // no-op on non-TTY
	s.Stage("scanning 10 repositories")
	s.Stop()

	out := buf.String()
	if !strings.Contains(out, "collecting members") || !strings.Contains(out, "scanning 10 repositories") {
		t.Errorf("non-TTY output missing stage lines: %q", out)
	}
	if strings.Contains(out, "\r") || strings.Contains(out, "\033[K") {
		t.Errorf("non-TTY output must not contain terminal control codes: %q", out)
	}
	if strings.Contains(out, "(3/10)") {
		t.Errorf("non-TTY must not render the live repo counter: %q", out)
	}
}

func TestTTYRenderShowsRepoCounter(t *testing.T) {
	var buf strings.Builder
	s := New(&buf, true)
	s.Stage("scanning repositories")
	s.SetRepoProgress(7, 42)
	s.render() // render directly to avoid the async ticker

	out := buf.String()
	if !strings.Contains(out, "scanning repositories") || !strings.Contains(out, "(7/42)") {
		t.Errorf("TTY render missing message/counter: %q", out)
	}
	if !strings.Contains(out, "\r") {
		t.Errorf("TTY render should rewrite the line with CR: %q", out)
	}
}
