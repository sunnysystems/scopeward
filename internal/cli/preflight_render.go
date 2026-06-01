package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sunnysystems/scopeward/internal/auth"
	"github.com/sunnysystems/scopeward/internal/ghclient"
	"github.com/sunnysystems/scopeward/internal/ui"
)

// recommendedScopes are the read-only classic-PAT scopes that unlock the full
// org-owner audit. Missing ones don't fail the run — later checks degrade to
// "not evaluated" — but we surface the gap up front.
var recommendedScopes = []string{
	"read:org",  // org members, teams, base permissions
	"repo",      // private repo metadata, collaborators, deploy keys, webhooks
	"admin:org", // 2FA status, SSO, org-level apps/PATs (read paths)
	"read:user", // member profile / activity signals
}

func renderProbeJSON(out io.Writer, src auth.Source, p *ghclient.Probe) error {
	payload := struct {
		TokenSource string          `json:"token_source"`
		Probe       *ghclient.Probe `json:"probe"`
		Missing     []string        `json:"missing_recommended_scopes,omitempty"`
	}{
		TokenSource: string(src),
		Probe:       p,
		Missing:     missingScopes(p),
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func renderProbeText(out io.Writer, src auth.Source, p *ghclient.Probe) {
	fmt.Fprintln(out, ui.Title.Render("scopeward")+ui.Subtle.Render(" · preflight"))
	fmt.Fprintln(out)

	line := func(label, value string) {
		fmt.Fprintf(out, "  %s %s\n", ui.Label.Render(fmt.Sprintf("%-14s", label)), value)
	}

	line("Authenticated", ui.Accent.Render(p.Login))
	line("Token source", string(src))
	line("Token type", string(p.TokenType))

	if len(p.Scopes) > 0 {
		line("Scopes", strings.Join(p.Scopes, ", "))
	} else if p.TokenType == ghclient.TokenFineGrainedPAT {
		line("Scopes", ui.Subtle.Render("(fine-grained token — permissions resolve per call)"))
	} else {
		line("Scopes", ui.Subtle.Render("(none reported)"))
	}

	rl := p.RateLimit
	line("Rate limit", fmt.Sprintf("%d/%d remaining", rl.Remaining, rl.Limit))

	fmt.Fprintln(out)
	if missing := missingScopes(p); len(missing) > 0 {
		fmt.Fprintln(out, ui.WarnTag.Render("⚠ limited coverage"))
		fmt.Fprintf(out, "  Missing recommended read scopes: %s\n", ui.Accent.Render(strings.Join(missing, ", ")))
		fmt.Fprintln(out, ui.Subtle.Render("  Affected checks will report \"not evaluated\" rather than a false pass."))
	} else {
		fmt.Fprintln(out, ui.Good.Render("✓ token has the recommended read scopes for a full org audit"))
	}
}

// missingScopes reports recommended scopes absent from a classic PAT. For
// fine-grained tokens GitHub does not expose scopes via headers, so we cannot
// pre-judge coverage and return nothing here (per-call results decide later).
func missingScopes(p *ghclient.Probe) []string {
	if p.TokenType == ghclient.TokenFineGrainedPAT || len(p.Scopes) == 0 {
		return nil
	}
	have := make(map[string]bool, len(p.Scopes))
	for _, s := range p.Scopes {
		have[s] = true
	}
	var missing []string
	for _, want := range recommendedScopes {
		if !have[want] && !satisfiedByParent(want, have) {
			missing = append(missing, want)
		}
	}
	sort.Strings(missing)
	return missing
}

// satisfiedByParent treats a broader granted scope as covering a narrower one
// (e.g. admin:org implies read:org).
func satisfiedByParent(want string, have map[string]bool) bool {
	switch want {
	case "read:org":
		return have["admin:org"]
	case "read:user":
		return have["user"]
	}
	return false
}
