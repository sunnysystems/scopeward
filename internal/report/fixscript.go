package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sunnysystems/scopeward/internal/model"
)

// fixScriptMaxAffected caps how many affected resources are listed per command
// so a command covering hundreds of repos doesn't bloat the script.
const fixScriptMaxAffected = 12

// renderScopePreflight states which token scopes the emitted commands need and
// which of them the audit's own token is missing.
//
// Without this, a token with `repo` alone runs most of the script and fails on
// the rest — and the failures are misleading rather than merely unhelpful: the
// Contents API answers a bare 404 for a missing `workflow` scope, so the error
// reads as "that file does not exist". With `set -uo pipefail` and independent
// commands, those errors also scroll past in a long script.
//
// Scopes we could not read (a fine-grained PAT, a GitHub App token) are reported
// as unknown rather than as missing: claiming a block will fail when we cannot
// tell would be worse than saying nothing.
func renderScopePreflight(w io.Writer, needed, granted []string, unknown bool) {
	if len(needed) == 0 {
		return
	}
	fmt.Fprintf(w, "# This script needs these token scopes: %s\n", strings.Join(needed, ", "))
	switch {
	case unknown || len(granted) == 0:
		fmt.Fprintln(w, "# Your token's scopes could not be read (fine-grained PAT, GitHub App, or")
		fmt.Fprintln(w, "# an endpoint that does not report them), so this script cannot tell you in")
		fmt.Fprintln(w, "# advance which blocks will be refused. Check the token's permissions if a")
		fmt.Fprintln(w, "# command fails.")
	default:
		fmt.Fprintf(w, "# Your token has: %s\n", strings.Join(granted, ", "))
		held := scopeSet(granted)
		var missing []string
		for _, s := range needed {
			if !held[s] {
				missing = append(missing, s)
			}
		}
		if len(missing) == 0 {
			fmt.Fprintln(w, "# Nothing missing: every block below is within this token's scopes.")
		} else {
			fmt.Fprintf(w, "# Missing — blocks marked below will fail: %s\n", strings.Join(missing, ", "))
		}
	}
	fmt.Fprintln(w, "#")
	fmt.Fprintln(w, "# Note: `gh api` often answers 404 rather than 403 when a scope is missing, so")
	fmt.Fprintln(w, "# a \"Not Found\" here usually means the token is not allowed, not that the")
	fmt.Fprintln(w, "# resource is absent. `gh auth status` shows the scopes you currently hold.")
	fmt.Fprintln(w)
}

func scopeSet(scopes []string) map[string]bool {
	set := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		set[strings.TrimSpace(s)] = true
	}
	return set
}

func hasAll(held map[string]bool, want []string) bool {
	for _, s := range want {
		if !held[s] {
			return false
		}
	}
	return true
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FixScript writes a shell script of the suggested `gh` fixes, with every
// command commented out. scopeward never runs anything; the operator reviews the
// script, uncomments what they want, and runs it themselves. Identical commands
// (e.g. one org-wide setting flagged by many findings) are emitted once, with
// the findings they address listed as comments.
func FixScript(w io.Writer, a Audit) {
	org := a.Snapshot.Org.Login

	fmt.Fprintln(w, "#!/usr/bin/env bash")
	fmt.Fprintf(w, "# scopeward: suggested fixes for %s\n", org)
	if !a.Snapshot.CollectedAt.IsZero() {
		fmt.Fprintf(w, "# data collected: %s\n", a.Snapshot.CollectedAt.Format("2006-01-02 15:04 MST"))
	}
	fmt.Fprintln(w, "#")
	fmt.Fprintln(w, "# scopeward is READ-ONLY: it did NOT run any of these commands.")
	fmt.Fprintln(w, "# Review each block, uncomment the command you want, and run it yourself.")
	fmt.Fprintln(w, "# Findings without a safe one-command fix are not listed; see the full report.")
	fmt.Fprintln(w, "#")
	fmt.Fprintln(w, "# Nothing below runs until you remove the leading '# ' from a command line.")
	fmt.Fprintln(w, "# Commands are independent: a failure on one (e.g. a private repo that needs")
	fmt.Fprintln(w, "# GitHub Advanced Security) is reported but does not stop the others.")
	fmt.Fprintln(w)

	// Group findings by their suggested command, preserving first-seen order
	// (findings arrive severity-sorted, so the most urgent fixes come first).
	type entry struct {
		cmd      string
		verify   string
		scopes   []string
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
			entries = append(entries, &entry{cmd: f.GHFix, verify: f.GHVerify, scopes: f.GHScopes})
		}
		entries[i].affected = append(entries[i].affected, f)
	}

	if len(entries) == 0 {
		fmt.Fprintln(w, "# No findings with a one-command fix. Nothing to do here.")
		return
	}

	needed := map[string]bool{}
	for _, e := range entries {
		for _, s := range e.scopes {
			needed[s] = true
		}
	}
	renderScopePreflight(w, sortedKeys(needed), a.TokenScopes, a.TokenScopesUnknown)

	fmt.Fprintln(w, "set -uo pipefail")
	fmt.Fprintln(w)

	held := scopeSet(a.TokenScopes)
	for _, e := range entries {
		head := e.affected[0]
		fmt.Fprintf(w, "# [%s] %s\n", upper(head.Severity.String()), head.CheckID)
		if len(e.scopes) > 0 {
			line := "#   needs scope: " + strings.Join(e.scopes, ", ")
			// Only claim a block will fail when we could actually read the scopes.
			if !a.TokenScopesUnknown && len(a.TokenScopes) > 0 && !hasAll(held, e.scopes) {
				line += "   ← YOUR TOKEN LACKS THIS; this block will fail"
			}
			fmt.Fprintln(w, line)
		}
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
