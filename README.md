<div align="center">

# scopeward

**The guardian of scope.**

Audit **GitHub and GitLab** governance from your own terminal — human identities,
teams and permissions, machine identities, and the 2026 problem nobody has a
dashboard for: **the AI agents committing your code**.

[![ci](https://github.com/sunnysystems/scopeward/actions/workflows/ci.yml/badge.svg)](https://github.com/sunnysystems/scopeward/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/sunnysystems/scopeward?color=d98324)](https://github.com/sunnysystems/scopeward/releases)
[![go report card](https://goreportcard.com/badge/github.com/sunnysystems/scopeward)](https://goreportcard.com/report/github.com/sunnysystems/scopeward)
[![license](https://img.shields.io/github/license/sunnysystems/scopeward?color=d98324)](LICENSE)

**80 checks · 7 axes · read-only · nothing hosted · one static binary**

[Quick start](#quick-start) · [What it audits](#what-it-audits) · [Output & CI](#output--ci) · [Design notes](#design-notes) · [Contributing](CONTRIBUTING.md)

</div>

---

```sh
scopeward --org acme-co
```

That is the whole setup. No account, no agent, no SaaS, no config file. It reads
your organization, scores its governance posture, and tells you what to fix —
**read-only by construction**: it never writes to the forge, never persists your
token, and never sends a byte anywhere except the API you pointed it at.

```text
  scopeward · audit · acme-co

  Governance score   72  C        ▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░

  ● 1 critical   ● 4 high   ● 9 medium   ● 6 low
  penalty 39 · 14 not instrumented, 25 open findings · 2.4 per repo across 36 repos

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

<sub>Illustrative output. Run it against your own org to see the real thing.</sub>

## Why scopeward

Most audit tools stop at humans and 2FA. In 2026 that is the smallest part of
the attack surface, and six design decisions follow from saying so out loud.

**Machine identities are the subject, not an appendix.** GitHub Apps, OAuth
Apps, classic vs fine-grained PATs, deploy keys, webhooks, Actions secrets,
self-hosted runners, and the `GITHUB_TOKEN` that defaults to write. On GitLab:
project, group and deploy tokens, CI/CD variables, runner exposure. These are
the accounts that quietly hold more access than any person on the team.

**AI agents get their own axis.** `scopeward` inventories which bot and machine
identities *actually commit code*, correlates each to its credential and its
write breadth, and flags agents committing with over-broad scope or onto
unprotected branches. Governing who — human *or* agent — pushes code, and with
what scope, is the entire point of the tool.

**The score never punishes looking.** Enabling Dependabot used to *lower* a
score: hidden vulnerabilities cost nothing, visible ones cost points. So a
disabled monitoring control is priced at the debt it hides, not at a flat
weight, and turning a control on can only improve the number or hold it.
→ [how the score works](docs/scoring.md)

**It never guesses.** Data the token could not read is reported as *not
evaluated*, never as a pass. A false clean bill of health is the worst thing an
audit tool can produce, so a check that cannot see something says so — up front
and in the coverage report.

**A finding you cannot fix without buying is not a finding, it's an invoice.**
Where remediation needs a paid capability your org does not hold, the finding is
withheld and the omission is reported instead — and entitlement is established
from evidence, never from your plan name. → [entitlements](docs/entitlements.md)

**Policy declares invariants, not inventory.** `.scopeward.yml` lets you assert
properties ("no repo admin outside team X"), so findings can say *"this violates
what we decided"* instead of only *"this is unusual"*. Unknown keys are errors —
a misspelled rule you believe is running is worse than no rule at all.
→ [policy](docs/policy.md)

## Install

```sh
go install github.com/sunnysystems/scopeward/cmd/scopeward@latest
```

Or grab a binary for Linux, macOS or Windows from
[releases](https://github.com/sunnysystems/scopeward/releases) — a single static
file, no runtime dependencies. To build from source:

```sh
make build   # produces ./scopeward
```

## Quick start

Provide a token via `GITHUB_TOKEN` / `GH_TOKEN` (or `GITLAB_TOKEN`). If it is
absent and you are in a terminal, you will be prompted without echo. The token
lives in memory only — it never reaches disk, a log, a trace or any report.

```sh
scopeward                                   # validate the token, show what it can audit
scopeward --org my-org                      # audit an organization
scopeward --org my-org --repo api           # audit a single repository (repeatable; globs ok)
scopeward --me                              # audit your own account & repos (incl. private)
scopeward --user some-login                 # audit any user's public account
scopeward tui --org my-org                  # browse findings in an interactive TUI

scopeward --provider gitlab --org my-group  # GitLab.com
scopeward --host https://gitlab.acme.com \
          --org platform                    # self-managed GitLab
```

Scopes: `read:org`, `repo`, `admin:org`, `read:user` on GitHub; `read_api`,
`read_user` on GitLab. `scopeward` only ever reads — though note that GitHub's
classic `repo` scope has no read-only variant, so you can also omit it and let
the private-repo checks report as *not evaluated*. Missing scopes never fail the
run. → [token scopes](docs/entitlements.md#recommended-scopes)

## What it audits

| Axis | Examples |
|------|----------|
| **Human Identity** | members without 2FA, org-wide 2FA not enforced, accounts outside SSO, SSO emails off the company domain, outside collaborators, owner sprawl, stale invitations, dormant accounts |
| **Teams & Permissions** | over-permissive base permission, direct admin grants that bypass teams, deep nesting, team sprawl, ghost/orphan/empty/singleton teams, ownership gaps, weak or admin-bypassable branch protection and rulesets, elevated custom roles |
| **Non-Human Identities** | installed GitHub Apps and what they can change, writable deploy keys, webhooks with no secret or SSL off, non-expiring and over-broad PATs, org secrets visible to every repo, open Actions policy, self-hosted runners, `GITHUB_TOKEN` defaulting to write, Actions that can approve PRs |
| **AI Agents** | inventory of bot/machine committers, agents committing with over-broad write scope, unidentified bot committers, agents pushing to unprotected branches, idle or non-member Copilot seats |
| **Code Security** | secret scanning, push protection and Dependabot off by default or per repo, open leaked-secret alerts, open vulnerability alerts |
| **Supply Chain** | unpinned third-party Actions, internal reusable workflows tracked by branch, `pull_request_target` triggers |
| **Repository Hygiene** | stale repositories with no pushes past a threshold, and the access that outlived them |

**On GitLab**, the same axes map to that forge: unprotected default branches,
force-push allowed, missing CODEOWNERS, merge-request approvals the author can
self-clear or that survive a new push (Premium), non-expiring or stale personal,
project, group and deploy tokens, trusted or public OAuth apps, unprotected
CI/CD variables, runners usable from unprotected refs, and a disabled
`CI_JOB_TOKEN` allowlist.

## Output & CI

| Flag | What you get |
|------|--------------|
| *(default)* | branded, colour terminal report with a governance score |
| `--format json` | machine-readable findings + coverage for pipelines |
| `--format sarif` | SARIF 2.1.0 for GitHub code scanning and security tooling |
| `--format markdown` | Markdown (rendered in-terminal on a TTY, raw otherwise) |
| `--html report.html [--open]` | self-contained branded HTML report; no server, opens in the browser |
| `--fail-on high` | exit non-zero when a finding at or above a severity exists (CI gate) |
| `--baseline prior.json [--new-only]` | diff against a prior run; report or fail only on *new* findings |
| `--fix-script fixes.sh` | suggested `gh` commands, **all commented out** — nothing runs until you uncomment |
| `--quiet` | suppress progress on stderr; the report and errors are unaffected |

It degrades to clean log output when there is no TTY, so CI reads the same as a
terminal. The action installs a checksum-verified release — no Go toolchain in
the critical path of a governance control:

```yaml
- uses: sunnysystems/scopeward@v0.1.0
  env:
    GITHUB_TOKEN: ${{ secrets.SCOPEWARD_TOKEN }}   # env only — never an input
  with:
    org: my-org
    fail-on: high
```

Pair it with `--baseline` and the weekly job goes quiet until posture actually
regresses, which is the difference between a control people read and one they
mute. → [full CI guide, action inputs, SARIF upload](docs/ci.md)

> **Keep audit output out of git.** A report or fix script carries your org
> login, repository names, team slugs and an ordered map of where you are
> weakest — in a public repo that is a targeting document. `scopeward` asks git
> whether the file it just wrote is ignored, and warns when it is not.

## Design notes

The reasoning behind the parts that are easy to get wrong:

| Document | What it covers |
|---|---|
| [**How the score works**](docs/scoring.md) | per-repo normalization, the grade bands and their honest caveats, why enabling a control can never cost points, the biggest-lever report |
| [**Suppressions and policy**](docs/policy.md) | accepting risk with a recorded reason, declaring invariants, why unknown keys are errors |
| [**Scopes and entitlements**](docs/entitlements.md) | recommended read-only scopes, how missing coverage is reported, why findings that need a purchase are withheld |
| [**Remediation**](docs/remediation.md) | fix scripts that never run themselves, branch protection scaled to team size, rulesets vs classic protection |
| [**Running in CI**](docs/ci.md) | the action, baselines, exit codes, SARIF in code scanning |

## Contributing

Contributions are welcome, and checks are the easiest place to start: one check
is **one new file** with no central wiring to edit — the registry populates
itself, and tests are plain Go structs with no network and no fixtures.

[CONTRIBUTING.md](CONTRIBUTING.md) has the five constraints that get a PR
rejected regardless of code quality (local-first, read-only, never persist the
token, single binary, degrade honestly) and a worked example of adding a check.
Good first issues are labelled
[`good first issue`](https://github.com/sunnysystems/scopeward/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).

Found a check that reports the wrong thing? That is a
[bug](https://github.com/sunnysystems/scopeward/issues/new/choose), and there is
an issue template for it. Found a way to break the read-only or
never-persist-the-token guarantee? That is a vulnerability —
[SECURITY.md](SECURITY.md) has the private channel.

By participating you agree to the [code of conduct](CODE_OF_CONDUCT.md).

## License

[MIT](LICENSE) © [Sunny Systems](https://github.com/sunnysystems)
