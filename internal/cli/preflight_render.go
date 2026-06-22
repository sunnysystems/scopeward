package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sunnysystems/scopeward/internal/provider"
	"github.com/sunnysystems/scopeward/internal/ui"
)

func renderProbeJSON(out io.Writer, pf *provider.Preflight) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(pf)
}

func renderProbeText(out io.Writer, pf *provider.Preflight) {
	fmt.Fprintln(out, ui.Title.Render("scopeward")+ui.Subtle.Render(" · preflight ("+string(pf.Provider)+")"))
	fmt.Fprintln(out)

	line := func(label, value string) {
		fmt.Fprintf(out, "  %s %s\n", ui.Label.Render(fmt.Sprintf("%-14s", label)), value)
	}

	line("Authenticated", ui.Accent.Render(pf.Login))
	if pf.Host != "" {
		line("Host", pf.Host)
	}
	line("Token source", pf.TokenSource)
	line("Token type", pf.TokenType)

	switch {
	case len(pf.Scopes) > 0:
		line("Scopes", strings.Join(pf.Scopes, ", "))
	case pf.ScopesUnknown:
		line("Scopes", ui.Subtle.Render("(token does not expose scopes; permissions resolve per call)"))
	default:
		line("Scopes", ui.Subtle.Render("(none reported)"))
	}

	line("Rate limit", fmt.Sprintf("%d/%d remaining", pf.RateLimit.Remaining, pf.RateLimit.Limit))

	fmt.Fprintln(out)
	if len(pf.Missing) > 0 {
		fmt.Fprintln(out, ui.WarnTag.Render("⚠ limited coverage"))
		fmt.Fprintf(out, "  Missing recommended read scopes: %s\n", ui.Accent.Render(strings.Join(pf.Missing, ", ")))
		fmt.Fprintln(out, ui.Subtle.Render("  Affected checks will report \"not evaluated\" rather than a false pass."))
	} else if !pf.ScopesUnknown {
		fmt.Fprintln(out, ui.Good.Render("✓ token has the recommended read scopes for a full audit"))
	}
}
