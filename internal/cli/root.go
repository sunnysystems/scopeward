// Package cli wires the cobra command tree, flag parsing, and dependency setup.
// For now it implements the preflight: resolve a token, validate it, and report
// what the token is allowed to see — the foundation every later audit builds on.
package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/charmbracelet/glamour"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"

	"github.com/sunnysystems/scopeward/internal/auth"
	"github.com/sunnysystems/scopeward/internal/cache"
	_ "github.com/sunnysystems/scopeward/internal/check/checks" // register all checks
	"github.com/sunnysystems/scopeward/internal/model"
	"github.com/sunnysystems/scopeward/internal/progress"
	"github.com/sunnysystems/scopeward/internal/provider"
	"github.com/sunnysystems/scopeward/internal/report"
	"github.com/sunnysystems/scopeward/internal/score"
	"github.com/sunnysystems/scopeward/internal/term"
	"github.com/sunnysystems/scopeward/internal/ui"

	"github.com/charmbracelet/lipgloss"
)

// version is overridden at build time via -ldflags.
var version = "dev"

type options struct {
	provider       string // github | gitlab (empty = auto-detect; default github)
	host           string // self-managed instance base URL (e.g. https://gitlab.example.com)
	org            string
	me             bool   // audit the authenticated user's account/repos
	user           string // audit a user's public account/repos
	format         string // auto | text | json
	noColor        bool
	failOn         string   // none | low | medium | high | critical
	htmlPath       string   // when set, also write a self-contained HTML report here
	open           bool     // open the HTML report in the default browser
	companyDomains []string // email domains considered to belong to the org
	staleAfterDays int      // days without a push before a repo is "stale"

	owningTeamProperty string   // custom-property name expected to name a repo's owning team
	solo               bool     // single-developer mode: suggested branch fixes never require a reviewer
	configPath         string   // path to the ignore config; auto-detected if empty
	quick              bool     // org-level only; skip the per-repo pass
	maxRepos           int      // cap repos scanned in the per-repo pass (0 = no cap)
	only               []string // run only these axes/check-IDs
	skip               []string // exclude these axes/check-IDs
	baseline           string   // prior JSON report to diff against
	newOnly            bool     // with --baseline: keep only findings new since baseline
	cache              bool     // use a disk ETag cache for conditional requests
	refresh            bool     // with --cache: ignore and rewrite cached entries this run
	fixScript          string   // write suggested gh fix commands (commented) to this path

	exitCode int // set during the run; returned by Execute
}

// exitFindings is the process exit code when --fail-on is triggered. It is
// distinct from 1 (operational error) so CI can tell "audit found issues" apart
// from "the tool failed to run".
const exitFindings = 2

// Execute builds and runs the root command, returning a process exit code.
func Execute() int {
	opts := &options{}

	root := &cobra.Command{
		Use:           "scopeward",
		Short:         "Local-first, read-only GitHub governance auditor",
		Long:          "scopeward audits GitHub organization governance from your machine.\nIt is read-only, never persists your token, and runs with zero hosted infrastructure.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			applyColorPolicy(opts.noColor)
			return runPreflight(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	root.PersistentFlags().StringVar(&opts.provider, "provider", "", "forge to audit: github|gitlab (default github; gitlab when --host is a GitLab URL)")
	root.PersistentFlags().StringVar(&opts.host, "host", "", "self-managed instance base URL, e.g. https://gitlab.example.com (default: the provider's SaaS host)")
	root.PersistentFlags().StringVarP(&opts.org, "org", "o", "", "organization (GitHub) or top-level group (GitLab) to audit")
	root.PersistentFlags().BoolVar(&opts.me, "me", false, "audit your own account and repositories (includes private)")
	root.PersistentFlags().StringVar(&opts.user, "user", "", "audit a user's public account and repositories")
	root.PersistentFlags().StringVarP(&opts.format, "format", "f", "auto", "output format: auto|text|json|markdown|sarif")
	root.PersistentFlags().BoolVar(&opts.noColor, "no-color", false, "disable colored output")
	root.PersistentFlags().StringVar(&opts.failOn, "fail-on", "none", "exit non-zero if a finding at or above this severity exists: none|low|medium|high|critical")
	root.PersistentFlags().StringVar(&opts.configPath, "config", "", "ignore-rules file (default: auto-detect .scopeward.yml)")
	root.PersistentFlags().StringVar(&opts.htmlPath, "html", "", "also write a self-contained HTML report to this path")
	root.PersistentFlags().BoolVar(&opts.open, "open", false, "open the HTML report in the default browser (requires --html)")
	root.PersistentFlags().StringSliceVar(&opts.companyDomains, "company-domain", nil, "company email domain(s) for the SSO email check, e.g. mycompany.com (repeatable)")
	root.PersistentFlags().IntVar(&opts.staleAfterDays, "stale-after-days", 365, "days without a push before a repository is flagged as stale")
	root.PersistentFlags().StringVar(&opts.owningTeamProperty, "owning-team-property", defaultOwningTeamProperty, "org custom-property name expected to name each repo's owning team")
	root.PersistentFlags().BoolVar(&opts.solo, "solo", false, "single-developer mode: suggested branch-protection fixes require a PR but no approving review (you cannot approve your own PR)")
	root.PersistentFlags().BoolVar(&opts.quick, "quick", false, "org-level checks only; skip the slower per-repo scan")
	root.PersistentFlags().IntVar(&opts.maxRepos, "max-repos", 0, "cap how many repos the per-repo scan covers (0 = all)")
	root.PersistentFlags().StringSliceVar(&opts.only, "only", nil, "run only these axes or check IDs (repeatable)")
	root.PersistentFlags().StringSliceVar(&opts.skip, "skip", nil, "exclude these axes or check IDs (repeatable)")
	root.PersistentFlags().StringVar(&opts.baseline, "baseline", "", "prior JSON report to diff against (reports new/resolved findings)")
	root.PersistentFlags().BoolVar(&opts.newOnly, "new-only", false, "with --baseline: show and fail only on findings new since the baseline")
	root.PersistentFlags().BoolVar(&opts.cache, "cache", false, "cache ETags on disk so unchanged data returns 304 (faster, saves rate limit; may lag just-changed settings; use --refresh after applying fixes)")
	root.PersistentFlags().BoolVar(&opts.refresh, "refresh", false, "with --cache: ignore cached data this run and rewrite it with fresh responses")
	root.PersistentFlags().StringVar(&opts.fixScript, "fix-script", "", "write suggested gh fix commands (commented, never run) to this .sh path")

	root.AddCommand(newTUICommand(opts))

	root.SetVersionTemplate("scopeward {{.Version}}\n")

	if err := root.ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, ui.Bad.Render("error:"), err)
		return 1
	}
	return opts.exitCode
}

// failThreshold parses the --fail-on value into a severity and whether failing
// is enabled at all.
func failThreshold(s string) (model.Severity, bool, error) {
	switch s {
	case "none", "":
		return 0, false, nil
	case "low":
		return model.SevLow, true, nil
	case "medium":
		return model.SevMedium, true, nil
	case "high":
		return model.SevHigh, true, nil
	case "critical":
		return model.SevCritical, true, nil
	default:
		return 0, false, fmt.Errorf("invalid --fail-on %q: want none|low|medium|high|critical", s)
	}
}

// applyColorPolicy disables color when asked or when output is not a terminal.
// lipgloss also honors NO_COLOR on its own; this makes the --no-color flag and
// headless detection explicit.
func applyColorPolicy(noColor bool) {
	if noColor || !term.IsStdoutTTY() {
		lipgloss.SetColorProfile(termenv.Ascii)
	}
}

// runPreflight resolves the token, probes it against the API, and reports the
// effective coverage. This is intentionally the whole job for step 1.
func runPreflight(ctx context.Context, out io.Writer, opts *options) error {
	threshold, failEnabled, err := failThreshold(opts.failOn)
	if err != nil {
		return err
	}
	if err := validateTargetFlags(opts); err != nil {
		return err
	}

	kind, err := provider.Parse(opts.provider, opts.host)
	if err != nil {
		return err
	}

	tok, tokenSource, err := provider.ResolveToken(kind, os.Stderr)
	if err != nil {
		return err
	}

	coll, err := provider.New(provider.Config{
		Provider:    kind,
		Host:        opts.host,
		Token:       tok,
		TokenSource: tokenSource,
	})
	if err != nil {
		return err
	}

	pf, err := coll.Preflight(ctx)
	if err != nil {
		return err
	}

	subject, userMode, self := opts.target(pf.Login)

	// No subject given: this is just a token preflight.
	if subject == "" {
		if opts.format == "json" {
			return renderProbeJSON(out, pf)
		}
		renderProbeText(out, pf)
		fmt.Fprintln(out)
		fmt.Fprintln(out, ui.Subtle.Render("Pass --org <name>, --user <login>, or --me to run an audit."))
		return nil
	}

	// Provider whose data collection is not built yet (GitLab → #4–#9): show the
	// preflight so auth/connectivity/scopes are confirmed, then stop honestly
	// rather than producing a misleading empty audit.
	if !coll.CollectsData() {
		if opts.format == "json" {
			return renderProbeJSON(out, pf)
		}
		renderProbeText(out, pf)
		fmt.Fprintln(out)
		fmt.Fprintln(out, ui.WarnTag.Render("⚠ "+provider.Title(kind)+" data collection is not implemented yet"))
		fmt.Fprintln(out, ui.Subtle.Render("  Tracked in #4–#9. This release wires auth + client only."))
		return nil
	}

	ignoreCfg, _, err := loadIgnore(opts.configPath)
	if err != nil {
		return err
	}

	var baselineKeys map[string]bool
	if opts.baseline != "" {
		baselineKeys, err = loadBaselineKeys(opts.baseline)
		if err != nil {
			return err
		}
	}

	if opts.cache || opts.refresh {
		if dc, err := cache.Open(subject + "-" + tokenFingerprint(tok)); err != nil {
			fmt.Fprintln(os.Stderr, ui.Subtle.Render("cache disabled: "+err.Error()))
		} else {
			if opts.refresh {
				dc.Clear() // fetch everything fresh this run, then rewrite the cache
			}
			coll.SetCache(dc)
			defer func() { _ = dc.Save() }()
		}
	}

	prog := progress.New(os.Stderr, term.IsStderrTTY())
	prog.SetRateFunc(coll.RateStatus)
	coll.SetOnWait(func(d time.Duration) {
		prog.Notice(fmt.Sprintf("%s rate limit reached; pausing %s for reset", provider.Title(kind), d.Round(time.Second)))
	})
	prog.Start()
	audit, err := buildAudit(ctx, coll, subject, userMode, self, opts, prog)
	prog.Stop()
	if err != nil {
		return err
	}

	if ignoreCfg != nil {
		var suppressed []model.Finding
		audit.Report.Findings, suppressed = ignoreCfg.apply(audit.Report.Findings)
		audit.Suppressed = suppressed
	}

	if opts.baseline != "" {
		newKeys, resolved := diffBaseline(audit.Report.Findings, baselineKeys)
		if opts.newOnly {
			audit.Report.Findings = keepNew(audit.Report.Findings, newKeys)
		}
		audit.HasBaseline, audit.NewKeys, audit.ResolvedCount = true, newKeys, resolved
	}

	// Score reflects what remains after ignore/baseline filtering.
	audit.Score = score.Grade(audit.Report.Findings)

	if err := renderAudit(out, opts.format, audit); err != nil {
		return err
	}

	if opts.htmlPath != "" {
		if err := writeHTMLReport(opts, audit); err != nil {
			return err
		}
	}

	if opts.fixScript != "" {
		if err := writeFixScript(opts, audit); err != nil {
			return err
		}
	}

	if failEnabled && maxSeverity(audit.Report.Findings) >= threshold {
		opts.exitCode = exitFindings
	}
	return nil
}

// renderAudit writes the audit to out in the requested stdout format.
func renderAudit(out io.Writer, format string, audit report.Audit) error {
	switch format {
	case "json":
		return report.JSON(out, audit)
	case "sarif":
		return report.SARIF(out, audit)
	case "markdown", "md":
		var buf bytes.Buffer
		report.Markdown(&buf, audit)
		if term.IsStdoutTTY() {
			if rendered, err := glamour.Render(buf.String(), "dark"); err == nil {
				_, err = io.WriteString(out, rendered)
				return err
			}
		}
		_, err := io.WriteString(out, buf.String())
		return err
	default:
		report.Text(out, audit)
		return nil
	}
}

// writeHTMLReport renders the audit to a self-contained HTML file and optionally
// opens it. Status goes to stderr so it never corrupts JSON on stdout.
func writeHTMLReport(opts *options, audit report.Audit) error {
	f, err := os.Create(opts.htmlPath)
	if err != nil {
		return fmt.Errorf("creating HTML report: %w", err)
	}
	if err := report.HTML(f, audit); err != nil {
		f.Close()
		return fmt.Errorf("writing HTML report: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, ui.Subtle.Render("HTML report written to ")+ui.Accent.Render(opts.htmlPath))
	if opts.open {
		if err := openInBrowser(opts.htmlPath); err != nil {
			fmt.Fprintln(os.Stderr, ui.Subtle.Render("could not open browser: "+err.Error()))
		}
	}
	return nil
}

// tokenFingerprint returns a short, non-reversible tag for a token so the cache
// can be namespaced per credential without storing the token itself.
func tokenFingerprint(tok auth.Secret) string {
	sum := sha256.Sum256([]byte(tok.Expose()))
	return hex.EncodeToString(sum[:])[:8]
}

// writeFixScript writes the suggested gh commands (commented) to a shell file.
func writeFixScript(opts *options, audit report.Audit) error {
	f, err := os.OpenFile(opts.fixScript, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("creating fix script: %w", err)
	}
	report.FixScript(f, audit)
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, ui.Subtle.Render("fix script written to ")+ui.Accent.Render(opts.fixScript)+ui.Subtle.Render(" (commands are commented; review before running)"))
	return nil
}

// maxSeverity returns the highest severity among findings, or SevInfo if none.
func maxSeverity(findings []model.Finding) model.Severity {
	worst := model.SevInfo
	for _, f := range findings {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	return worst
}
