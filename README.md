# scopeward

**Local-first, read-only GitHub governance auditor.** One command, zero config,
nothing hosted. It scores your organization's governance posture across human
identities, teams & permissions, non-human (machine) identities, and — the 2026
angle — the AI/agent identities committing your code.

Built by [Sunny Systems](https://github.com/sunnysystems).

---

## Principles

- **Local-first** — runs on your machine or CI. We host nothing.
- **Read-only** — only read scopes; the tool never writes to GitHub.
- **Your token never touches disk** — it comes from an env var or a no-echo
  prompt, lives in memory, and is gone when the process exits. It is never
  logged, traced, or written to a crash dump.
- **Honest coverage** — when a token can't see something, the audit reports it
  as *not evaluated* instead of a false pass.
- **Single binary** — multiplatform, no runtime dependencies.
- **Degrades cleanly headless** — clean log output on CI/SSH with no TTY.

## Install

```sh
go install github.com/sunnysystems/scopeward/cmd/scopeward@latest
```

Or grab a binary from the [releases](https://github.com/sunnysystems/scopeward/releases),
or build from source:

```sh
make build   # produces ./scopeward
```

## Usage

Provide a token via `GITHUB_TOKEN` (or `GH_TOKEN`); if absent and you're in a
terminal, you'll be prompted without echo.

```sh
# Validate the token and see what it can audit
scopeward

# Audit an organization
scopeward --org my-org

# Machine-readable output for CI
scopeward --org my-org --format json

# Self-contained HTML report, opened in your browser
scopeward --org my-org --html report.html --open

# Interactive terminal UI
scopeward tui --org my-org

# Fail CI when a finding at or above a severity exists
scopeward --org my-org --fail-on high
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Audit ran (no `--fail-on` trigger) |
| `1`  | Operational error (bad token, org not accessible, bad flag) |
| `2`  | `--fail-on` threshold met by at least one finding |

## What it audits

| Axis | Examples |
|------|----------|
| **Human Identity** | members without 2FA, org-wide 2FA not enforced, accounts outside SSO, outside collaborators, owner sprawl |
| **Teams & Permissions** | over-permissive base permission, direct admin/repo grants that bypass teams, deep team nesting, team sprawl |
| **Non-Human Identities** | GitHub Apps with write/admin, writable deploy keys, webhooks without a secret or with SSL disabled, non-expiring PATs, `GITHUB_TOKEN` defaulting to write |
| **AI Agents** | which machine/bot identities commit code, correlated with their credential and write breadth; unidentified bot committers |

## Token scopes

Designed for an **organization owner** token for full coverage. The recommended
read-only classic-PAT scopes are:

- `read:org` — members, teams, base permission
- `repo` — private repo metadata, collaborators, deploy keys, webhooks
- `admin:org` — 2FA status, SSO, org apps & default workflow token (read paths)
- `read:user` — member activity signals

Missing scopes don't fail the run; the affected checks degrade to *not
evaluated* and the gap is shown up front and in the coverage report.

## License

[MIT](LICENSE) © Sunny Systems
