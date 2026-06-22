<div align="center">

# scopeward

**The guardian of scope.** A local-first, read-only auditor for GitHub
organization governance. It covers human identities, teams & permissions,
non-human (machine) identities, and the 2026 angle: the **AI agents committing
your code**.

[![license](https://img.shields.io/github/license/sunnysystems/scopeward?color=d98324)](LICENSE)
[![go](https://img.shields.io/github/go-mod/go-version/sunnysystems/scopeward?color=d98324)](go.mod)
![read-only](https://img.shields.io/badge/scope-read--only-d98324)
![local-first](https://img.shields.io/badge/runtime-local--first-d98324)

One command. Zero config. Nothing hosted. Built by [Sunny Systems](https://github.com/sunnysystems).

</div>

---

`scopeward` connects to GitHub with a **read-only** token, scores your
organization's governance posture across **68 checks in seven axes**, and tells
you exactly what to fix, all without ever writing to GitHub, persisting your
token, or sending a single byte off your machine.

```text
  scopeward · audit · acme-co

  Governance score   72  C        ▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░

  ● 1 critical   ● 4 high   ● 9 medium   ● 6 low

  Human Identity
    ● high      3 members without 2FA               alice, ben, cora
    ● medium    org 2FA enforcement is off
  Non-Human Identities
    ● high      deploy key with write access        acme-co/payments
    ● medium    2 PATs never expire
  AI Agents
    ● medium    release-bot commits with a token that can write to all repos
  …

  Not evaluated: fine-grained PATs (needs GitHub Enterprise)

  Fix the top findings:  scopeward --org acme-co --fix-script fixes.sh
```

> The example above is illustrative. Run it against your own org to see the real thing.

## Why scopeward

Most audit tools stop at humans and 2FA. The risk in 2026 lives elsewhere:

- **Non-human identities:** GitHub Apps, OAuth Apps, classic vs fine-grained
  PATs, deploy keys, webhooks, Actions secrets, self-hosted runners, and the
  default `GITHUB_TOKEN` write permission. The machine accounts that quietly
  hold more access than any person.
- **AI agents:** `scopeward` inventories which bot/machine identities actually
  **commit code**, correlates each to its credential and write breadth, and
  flags agents committing with over-broad scope or onto unprotected branches.
  Governing who (human *or* agent) pushes code, and with what scope, is the
  whole point.

## Install

```sh
go install github.com/sunnysystems/scopeward/cmd/scopeward@latest
```

Or grab a binary from [releases](https://github.com/sunnysystems/scopeward/releases),
or build from source (single binary, no runtime deps):

```sh
make build   # produces ./scopeward
```

## Quick start

Provide a token via `GITHUB_TOKEN` (or `GH_TOKEN`). If it's absent and you're in
a terminal, you'll be prompted without echo. The token lives in memory only.

```sh
scopeward                              # validate the token, show what it can audit
scopeward --org my-org                 # audit an organization
scopeward --me                         # audit your own account & repos (incl. private)
scopeward --user some-login            # audit any user's public account
scopeward tui --org my-org             # browse findings in an interactive TUI
```

## Output & CI

| Flag | What you get |
|------|--------------|
| *(default)* | branded, color terminal report with a governance score |
| `--format json` | machine-readable findings + coverage for pipelines |
| `--format sarif` | SARIF 2.1.0 for GitHub code scanning / security tooling |
| `--format markdown` | Markdown (rendered in-terminal on a TTY, raw otherwise) |
| `--html report.html [--open]` | self-contained, Sunny-branded HTML report; no server, opens in the browser |
| `--fail-on high` | exit non-zero when a finding at/above a severity exists (CI gate) |
| `--baseline prior.json [--new-only]` | diff against a prior run; report or fail only on *new* findings |
| `--fix-script fixes.sh` | write suggested `gh` remediation commands, **all commented out**; nothing runs until you uncomment |

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Audit ran (no `--fail-on` trigger) |
| `1`  | Operational error (bad token, org not accessible, bad flag) |
| `2`  | `--fail-on` threshold met by at least one finding |

## What it audits

| Axis | Examples |
|------|----------|
| **Human Identity** | members without 2FA, org-wide 2FA not enforced, accounts outside SSO, SSO emails off the company domain, outside collaborators, owner sprawl, stale invitations |
| **Teams & Permissions** | over-permissive base permission, direct admin/repo grants that bypass teams, deep nesting, team sprawl, ghost/orphan/empty/singleton teams, ownership gaps (no owning team / CODEOWNERS), weak or unenforced branch protection & rulesets, elevated custom roles |
| **Non-Human Identities** | GitHub Apps with write/admin, writable deploy keys, webhooks without a secret or with SSL disabled, non-expiring PATs, broad classic PATs, org secrets visible to all repos, open Actions policy, self-hosted runners, `GITHUB_TOKEN` defaulting to write, Actions that can approve PRs; on GitLab: non-expiring / broadly-scoped / stale personal, project & group access tokens, non-expiring deploy tokens, trusted or public OAuth apps, unprotected CI/CD secret variables, runners usable from unprotected refs, CI_JOB_TOKEN allowlist disabled |
| **AI Agents** | inventory of bot/machine committers, agents committing with over-broad write scope, unidentified bot committers, agents pushing to unprotected branches, idle/non-member Copilot seats |
| **Code Security** | secret scanning / push protection / Dependabot alerts off by default, repos without push protection or with Dependabot alerts disabled, open (leaked) secret-scanning alerts, open Dependabot vulnerability alerts |
| **Supply Chain** | unpinned third-party Actions, `pull_request_target` triggers |
| **Repository Hygiene** | stale repositories with no pushes past a threshold |

## Suppressing findings

Drop a `.scopeward.yml` in your repo (auto-detected, or point at it with
`--config`) to allowlist accepted risks. Suppressed findings are excluded from
the score and from `--fail-on`, and are still listed so nothing is hidden silently.

```yaml
ignore:
  - check: human.outside-collaborator
    resource: acme-co/public-docs
    reason: intentional external docs contributor
```

## Token scopes

Designed for an **organization owner** token for full coverage. Recommended
read-only classic-PAT scopes:

| Scope | Unlocks |
|-------|---------|
| `read:org` | members, teams, base permission |
| `repo` | private repo metadata, collaborators, deploy keys, webhooks |
| `admin:org` | 2FA status, SSO, org apps & default workflow token (read paths) |
| `read:user` | member activity signals |

Missing scopes never fail the run. Affected checks degrade to *not evaluated*,
and the gap is shown up front and in the coverage report. Some checks
(fine-grained PAT inventory, custom roles) require GitHub Enterprise and are
reported as not evaluated elsewhere.

> Working solo? Add `--solo` so suggested branch-protection fixes require a PR
> but no approving review (you can't approve your own PR).

## License

[MIT](LICENSE) © Sunny Systems
