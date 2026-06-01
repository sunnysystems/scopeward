We're building an open-source CLI tool for GitHub governance auditing, in Go.
Name: scopeward (scope + ward/guardian; the guardian of token/permission scope
and non-human identities). The github.com/scopeward handle and scopeward.dev
are free and checked; no collision in software/security. Publish as
github.com/sunnysystems/scopeward. It's a Sunny Systems project and a brand
asset, so polish and DX matter as much as the checks themselves.

NON-NEGOTIABLE PRINCIPLES
- Local-first: runs on the user's machine/CI. We never host anything.
- Read-only: read scopes only. The tool never writes to GitHub.
- The token is NEVER persisted to disk, log, trace, or crash dump. It comes
  from an env var or prompt, lives in memory, and is gone at the end.
- Single cross-platform binary. Adoption is "one command, zero config".
- Degrades to clean log output when running headless (CI/SSH with no TTY).

WHAT TO AUDIT (axes)
- Human identity: members without 2FA, accounts outside SSO, outside
  collaborators, dormant accounts, offboarding gaps.
- Teams and permissions: team sprawl, nesting, direct repo grants,
  over-privilege (admin where write was enough), org base permission.
- Non-human identities (DIFFERENTIATOR): GitHub Apps, OAuth Apps, classic
  PATs vs fine-grained by scope and expiration, deploy keys, webhooks,
  Actions secrets, self-hosted runners, GITHUB_TOKEN with default write.
- The 2026 angle (the brand highlight): AI AGENT governance — which
  machine/bot identities commit code, with which token and which scope.

STACK
- Go. TUI with Bubble Tea (loop/state), Lipgloss (style, Sunny visual
  identity in amber/copper), Bubbles (spinner, table, viewport), Glamour
  (Markdown report in the terminal).
- Concurrent GitHub API calls, fired as async tea.Cmd.

OUTPUT
- Clean stdout with a governance score by default.
- A flag to emit a self-contained static HTML report, Sunny-branded, that
  opens in the browser with no server at all.
- Optional interactive TUI to browse the permission graph live.

NOT YET: no backend, no hosted layer, no telemetry.

Before writing code: propose the package architecture, the finding data
model, the interface for a pluggable "check", and the implementation order.
We review the plan before starting.
