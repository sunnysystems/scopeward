package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sunnysystems/scopeward/internal/provider"
	"github.com/sunnysystems/scopeward/internal/report"
	"github.com/sunnysystems/scopeward/internal/term"
	"github.com/sunnysystems/scopeward/internal/tui"
)

// newTUICommand builds the `scopeward tui` subcommand: an interactive browser for
// the audit. It collects asynchronously behind a spinner, then lets the user
// navigate findings with a live detail pane.
func newTUICommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Browse an org or user audit in an interactive terminal UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateTargetFlags(opts); err != nil {
				return err
			}
			if !term.IsInteractive() {
				return errors.New("the tui requires an interactive terminal; use the default command for headless output")
			}

			kind, err := provider.Parse(opts.provider, opts.host)
			if err != nil {
				return err
			}
			tok, tokenSource, err := provider.ResolveToken(kind, os.Stderr)
			if err != nil {
				return err
			}
			coll, err := provider.New(provider.Config{Provider: kind, Host: opts.host, Token: tok, TokenSource: tokenSource})
			if err != nil {
				return err
			}
			if !coll.CollectsData() {
				return fmt.Errorf("the tui is not available for %s yet", provider.Title(kind))
			}
			pf, err := coll.Preflight(cmd.Context())
			if err != nil {
				return err
			}

			subject, userMode, self := opts.target(pf.Login)
			if subject == "" {
				return errors.New("the tui requires --org <name>, --user <login>, or --me")
			}

			audit := func(ctx context.Context) (report.Audit, error) {
				return buildAudit(ctx, coll, subject, userMode, self, opts, nil)
			}
			return tui.Run(cmd.Context(), subject, audit)
		},
	}
}
