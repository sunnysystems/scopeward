package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/sunnysystems/scopeward/internal/model"
)

// fixScriptMaxAffected caps how many affected resources are listed per command
// so a command covering hundreds of repos doesn't bloat the script.
const fixScriptMaxAffected = 12

// FixScript writes a shell script of the suggested `gh` fixes, with every
// command commented out. scopeward never runs anything; the operator reviews the
// script, uncomments what they want, and runs it themselves. Identical commands
// (e.g. one org-wide setting flagged by many findings) are emitted once, with
// the findings they address listed as comments.
func FixScript(w io.Writer, a Audit) {
	org := a.Snapshot.Org.Login

	fmt.Fprintln(w, "#!/usr/bin/env bash")
	fmt.Fprintf(w, "# scopeward — suggested fixes for %s\n", org)
	if !a.Snapshot.CollectedAt.IsZero() {
		fmt.Fprintf(w, "# data collected: %s\n", a.Snapshot.CollectedAt.Format("2006-01-02 15:04 MST"))
	}
	fmt.Fprintln(w, "#")
	fmt.Fprintln(w, "# scopeward is READ-ONLY: it did NOT run any of these commands.")
	fmt.Fprintln(w, "# Review each block, uncomment the command you want, and run it yourself.")
	fmt.Fprintln(w, "# Requires the GitHub CLI authenticated with an admin-scoped token (gh auth login).")
	fmt.Fprintln(w, "# Findings without a safe one-command fix are not listed — see the full report.")
	fmt.Fprintln(w, "#")
	fmt.Fprintln(w, "# Nothing below runs until you remove the leading '# ' from a command line.")
	fmt.Fprintln(w, "# Commands are independent: a failure on one (e.g. a private repo that needs")
	fmt.Fprintln(w, "# GitHub Advanced Security) is reported but does not stop the others.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "set -uo pipefail")
	fmt.Fprintln(w)

	// Group findings by their suggested command, preserving first-seen order
	// (findings arrive severity-sorted, so the most urgent fixes come first).
	type entry struct {
		cmd      string
		verify   string
		affected []model.Finding
	}
	index := map[string]int{}
	var entries []*entry
	for _, f := range a.Report.Findings {
		if f.GHFix == "" {
			continue
		}
		i, ok := index[f.GHFix]
		if !ok {
			i = len(entries)
			index[f.GHFix] = i
			entries = append(entries, &entry{cmd: f.GHFix, verify: f.GHVerify})
		}
		entries[i].affected = append(entries[i].affected, f)
	}

	if len(entries) == 0 {
		fmt.Fprintln(w, "# No findings with a one-command fix. Nothing to do here.")
		return
	}

	for _, e := range entries {
		head := e.affected[0]
		fmt.Fprintf(w, "# [%s] %s\n", upper(head.Severity.String()), head.CheckID)
		fmt.Fprintf(w, "#   fixes %d finding(s):\n", len(e.affected))
		for i, f := range e.affected {
			if i >= fixScriptMaxAffected {
				fmt.Fprintf(w, "#     … (+%d more)\n", len(e.affected)-fixScriptMaxAffected)
				break
			}
			name := f.Resource.Name
			if name == "" {
				name = f.Title
			}
			fmt.Fprintf(w, "#     - %s\n", name)
		}
		// A fix may be more than one command (e.g. a PUT plus its allowlist);
		// comment each line so uncommenting the block runs the whole sequence.
		for _, line := range strings.Split(e.cmd, "\n") {
			fmt.Fprintf(w, "# %s\n", line)
		}
		if e.verify != "" {
			fmt.Fprintf(w, "#   verify: %s\n", e.verify)
		}
		fmt.Fprintln(w)
	}
}
