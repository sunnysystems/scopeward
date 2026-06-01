// Command scopeward is a local-first, read-only GitHub governance auditor.
//
// It never persists the token, never writes to GitHub, and degrades to clean
// log output when run without a TTY (CI/SSH).
package main

import (
	"os"

	"github.com/sunnysystems/scopeward/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
