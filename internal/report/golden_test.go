package report

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// update regenerates the golden files instead of comparing against them:
//
//	go test ./internal/report/ -run TestGolden -update
//
// This is the regression net for the GitLab initiative: it locks the GitHub
// output so later provider work (collector factory, GitLab collectors, provider
// guards) cannot silently change what an audit reports for GitHub.
var update = flag.Bool("update", false, "regenerate report golden files")

// Only the deterministic, ANSI-free formats are locked here. The Text renderer
// emits lipgloss ANSI keyed off stdout's TTY state (so its bytes differ between
// a local terminal and CI), and HTML already has a content assertion in
// html_test.go; Markdown captures the same findings/score/coverage content as
// Text without the environment fragility.
func TestGoldenReports(t *testing.T) {
	cases := []struct {
		name   string
		render func(io.Writer, Audit) error
	}{
		{"golden.json", JSON},
		{"golden.sarif", SARIF},
		{"golden.md", func(w io.Writer, a Audit) error { Markdown(w, a); return nil }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.render(&buf, sampleAudit()); err != nil {
				t.Fatalf("render %s: %v", tc.name, err)
			}
			path := filepath.Join("testdata", tc.name)

			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("wrote golden %s (%d bytes)", path, buf.Len())
				return
			}

			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden %s (run with -update to seed): %v", path, err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("%s differs from golden; re-run with -update if the change is intended.\n--- got ---\n%s", tc.name, buf.String())
			}
		})
	}
}
