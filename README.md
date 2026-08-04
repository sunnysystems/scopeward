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
organization's governance posture across **80 checks in seven axes**, and tells
you exactly what to fix, all without ever writing to GitHub, persisting your
token, or sending a single byte off your machine.

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

> The example above is illustrative. Run it against your own org to see the real thing.
>
> Note the repository count: per-repo penalty is scored as a **rate**, so a
> score is only interpretable next to the size of the organization it came
> from. Two orgs with the same number have the same posture, whether one has
> four repositories and the other four hundred.

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
scopeward --org my-org --repo api      # audit a single repository (repeatable; globs ok)
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
| `--fix-script fixes.sh` | write suggested `gh` remediation commands, **all commented out**; nothing runs until you uncomment. The header states which token scopes the commands need and which your token is missing, and each block names its own scope |
| `--quiet` | suppress progress and informational messages on stderr; the report and errors are unaffected |

> **Keep the output out of git.** A fix script or report carries your org login,
> repository names, team slugs and an ordered map of where you are weakest — in
> a public repository that is a targeting document.
>
> The output path is yours to choose, so no `.gitignore` pattern can cover every
> run. Instead, after writing a file scopeward asks git whether it is ignored,
> and says so when it is not:
>
> ```text
> ⚠ acme-fixes.sh is in a git repository and is not ignored
>   It maps where your organization is weakest. Add to .gitignore: /acme-fixes.sh
> ```
>
> The warning is silent outside a git work tree, when the file is already
> ignored, and under `--quiet`. It is advisory: it never changes the exit code.

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Audit ran (no `--fail-on` trigger) |
| `1`  | Operational error (bad token, org not accessible, bad flag) |
| `2`  | `--fail-on` threshold met by at least one finding |

### Run it continuously

Governance is not a thing you check once. The action below installs a pinned
release (checksum-verified, no Go toolchain needed), runs the audit headless,
and uploads the report:

> The action installs a published release, so it works from the first tagged
> release onward. Until then, build from source in the job — this repository's
> own [`governance.yml`](.github/workflows/governance.yml) shows that shape.

```yaml
- uses: sunnysystems/scopeward@v1
  env:
    GITHUB_TOKEN: ${{ secrets.SCOPEWARD_TOKEN }}   # env only — never an input
  with:
    org: my-org
    fail-on: high
```

The token is deliberately **not** an input. Inputs are echoed in the run's own
parameter display and leak under a debug `set -x`; the environment is the only
place it belongs. Note the workflow's built-in `GITHUB_TOKEN` cannot read
organization settings — you need a read-only PAT with `read:org`, `repo`,
`admin:org` and `read:user`, stored as a secret.

A weekly audit that reports every known finding every week is one people stop
reading. Feed the previous run's report back in as a baseline and the job goes
quiet until posture actually regresses:

```yaml
name: governance
on:
  schedule: [{ cron: "0 6 * * 1" }]
  workflow_dispatch:

permissions:
  contents: read
  actions: read           # to read the previous run's report
  security-events: write  # to upload SARIF to code scanning

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Fetch the previous report as a baseline
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          prev=$(gh run list --workflow governance.yml --status success \
                   --limit 1 --json databaseId --jq '.[0].databaseId' \
                   --repo "$GITHUB_REPOSITORY" 2>/dev/null || true)
          [ -n "$prev" ] && gh run download "$prev" --name scopeward-report --dir baseline || \
            echo "no previous report; this run establishes the baseline"

      - uses: sunnysystems/scopeward@v1
        env:
          GITHUB_TOKEN: ${{ secrets.SCOPEWARD_TOKEN }}
        with:
          org: my-org
          baseline: baseline/scopeward-report.json
          new-only: "true"      # speak only about what changed
          fail-on: high         # exit 2 → the job fails → someone looks
```

The first run has no predecessor and simply establishes the baseline. After
that the job passes silently and only speaks up when something new appears at
or above `high`.

| Action input | Default | Notes |
|---|---|---|
| `org` | *(none)* | omit to audit the token's own account |
| `version` | `latest` | pin to a tag for a reproducible job |
| `format` | `json` | `json` \| `sarif` \| `markdown` \| `text` |
| `output` | `scopeward-report.json` | where the report is written |
| `fail-on` | `none` | `low` \| `medium` \| `high` \| `critical` |
| `baseline` / `new-only` | *(none)* / `false` | report only what changed |
| `config` / `repo` / `args` | *(none)* | policy file, repo filter, extra flags |
| `upload-artifact` / `artifact-name` | `true` / `scopeward-report` | artifact upload |

Outputs: `report`, `exit-code`, `score`, `grade`. Both failure modes fail the
job, and the job summary tells them apart — exit `2` is a posture regression to
triage, exit `1` is a broken job to fix. Linux and macOS runners; on Windows,
install the binary from the releases page.

For SARIF in code scanning, set `format: sarif` and pass the report to
`github/codeql-action/upload-sarif`. This repository's own
[`governance.yml`](.github/workflows/governance.yml) does exactly that on a
schedule, which is also what keeps the headless path honest.

## What it audits

| Axis | Examples |
|------|----------|
| **Human Identity** | members without 2FA, org-wide 2FA not enforced, accounts outside SSO, SSO emails off the company domain, outside collaborators, owner sprawl, stale invitations |
| **Teams & Permissions** | over-permissive base permission, direct admin/repo grants that bypass teams, deep nesting, team sprawl, ghost/orphan/empty/singleton teams, ownership gaps (no owning team / CODEOWNERS), weak, admin-bypassable or unenforced branch protection & rulesets, elevated custom roles; on GitLab: unprotected default branches, force-push allowed, missing CODEOWNERS, and (Premium) merge-request approvals that the author can self-clear or that survive a new push |
| **Non-Human Identities** | inventory of installed GitHub Apps, apps that can change org settings / membership / secrets / runners / workflow files, writable deploy keys, webhooks without a secret or with SSL disabled, non-expiring PATs, broad classic PATs, org secrets visible to all repos, open Actions policy, self-hosted runners, `GITHUB_TOKEN` defaulting to write, Actions that can approve PRs; on GitLab: non-expiring / broadly-scoped / stale personal, project & group access tokens, non-expiring deploy tokens, trusted or public OAuth apps, unprotected CI/CD secret variables, runners usable from unprotected refs, CI_JOB_TOKEN allowlist disabled |
| **AI Agents** | inventory of bot/machine committers, agents committing with over-broad write scope, unidentified bot committers, agents pushing to unprotected branches, idle/non-member Copilot seats |
| **Code Security** | secret scanning / push protection / Dependabot alerts off by default, repos without push protection or with Dependabot alerts disabled, open (leaked) secret-scanning alerts, open Dependabot vulnerability alerts |
| **Supply Chain** | unpinned third-party Actions, internal reusable workflows tracked by branch, `pull_request_target` triggers |
| **Repository Hygiene** | stale repositories with no pushes past a threshold |

For most organizations with history the largest single fix is archiving dead
repositories, since one abandoned repo carries a whole stack of per-repo findings.
The report leads with the aggregate rather than burying it under one 2-point
`low` per repo:

```text
  Biggest lever
    12 repositories have had no push past the stale threshold. Archiving them
    resolves 65 findings worth 345 penalty (score 33 → 49 D).
    Not counted above: 2 findings on these repositories stay real after
    archiving — a committed credential is exposed whether or not the repo is
    read-only. Rotate those first.
```

`--fix-script` emits the `gh` archive commands (reversible; archiving makes a
repo read-only, it does not delete anything).

Archived repositories are skipped by the per-repo checks — nothing can be pushed
to a read-only repo, so its branch protection and grants are moot — with one
exception: they are still scanned for **leaked secrets**. Archiving does not
un-leak a credential already in the history, and a retired repository is exactly
where nobody looks. Those get their own `--max-repos` budget, so a graveyard of
archived repos never eats the cap meant for the active ones.

## The score never punishes looking

Turning a security control **on** used to lower the score. A repository with
Dependabot alerts disabled scored one medium finding; the same repository with
alerts enabled and a critical CVE open scored a critical. The vulnerabilities
were identical — the only difference was whether you could see them, and looking
cost twenty points per repository.

So a disabled monitoring control is not priced at a flat weight. It is priced at
the debt it hides: at least what one critical finding would cost, and more when
your own instrumented repositories carry more than that each. Enabling the
control then replaces an estimate with a measurement, and the number can only
improve or hold.

```text
  penalty 236 · 138 not instrumented, 98 open findings · 10.3 per repo across 23 repos
  87 of that penalty is estimated: repositories with monitoring off are priced at
  the debt your instrumented repositories actually carry, so enabling a control
  never costs you points
```

The estimated portion is always disclosed — in the terminal, in the HTML report,
and as `estimated` in `--format json`. A score partly built on an assumption has
to say which part.

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

Every suppression is reported back under **Accepted risks**, with its `reason`
and the score the suppressions bought:

```text
  Accepted risks
    · dana is an outside collaborator
      acme-co/public-docs · human.outside-collaborator
      accepted: intentional external docs contributor
    1 suppressed · score without them: 75 B (currently 81 B)
```

`reason` is optional but recommended — a rule without one is reported as
*no reason recorded*, since documented risk acceptance is the point of the
mechanism. The reason also reaches `--format json` (with an
`unsuppressed_score`), the HTML report, and `--format sarif` (as a native
`suppressions` entry, so dashboards show accepted risks with their
justification).

## Declaring policy

`ignore` has one verb: it removes a finding. That limits every finding to one
sentence — *"this is unusual"*. The sentence governance actually runs on is the
other one: *"this violates what we decided."* Only the second gates a pipeline
without argument, and only the second produces a review that converges.

Add a `policy` block to the same `.scopeward.yml`:

```yaml
policy:
  version: 1

  # Numbers the product otherwise hardcodes. The defaults are opinions applied
  # uniformly — the right default, and the wrong final answer for an org that
  # has actually decided.
  thresholds:
    dormant_after_days: 60        # default 90
    stale_repo_after_days: 180    # default 365
    max_teams: 20                 # default: flag when teams outnumber members

  # Properties you assert. Each produces findings of its own when violated.
  invariants:
    repo_admin_only_from_team: platform-admins
    public_repos: [docs-site, brand-assets]
    forbid_direct_collaborators: true
    require_owning_team: true
```

Policy findings are marked `POLICY` in every output, so a reader can tell org
opinion from tool opinion:

```text
  Teams & Permissions
    ● critical  POLICY acme/payments is public and not on the allowlist
                acme/payments · policy.unlisted-public-repo
```

Where an invariant covers the same ground as a product check, the invariant
wins and the product check stands down — `require_owning_team` replaces
`teams.repo-no-owning-team`, and `forbid_direct_collaborators` replaces both
`perms.direct-admin-grant` and `perms.direct-repo-grant`. One problem, reported
once, at the severity you chose.

**Invariants, not inventory.** A policy declares *predicates* ("no repository
admin outside team X"), never *resources* ("user U is admin on repo R"). Writing
desired state is infrastructure-as-code's job, and Terraform and settings
reconcilers already do it well; scopeward asserts properties of whatever state
exists. If a policy block starts needing one entry per repository, the design has
drifted — which is why an over-long `public_repos` list is rejected rather than
accepted. The invariant to write is the exception, not the list.

Unknown keys are **errors**, not warnings. A misspelled invariant that parsed
would leave you believing a rule is running when it is not, which is strictly
worse than having written no policy at all. For the same reason, an invariant
that cannot be evaluated (missing scope, uncollected data) is reported as *not
evaluated* rather than passing quietly.

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

### Paid features you do not have

A finding whose only remediation is a purchase is not a finding — it is an
invoice, and at scale it buries the ones you can act on. So scopeward separates
what it can *see* from what you can *fix*: where a fix needs a paid capability
your organization does not hold, the finding is withheld and the omission is
reported instead.

Push protection is the case that matters most. It is free on public
repositories on every plan and paid on private ones, so the test is per
repository — an org-wide switch would go quiet on exactly the repos where a
leaked secret is worst. When some scope is out of reach the report says so
under **Partially evaluated**, with what was left out and why; when none of it
is reachable the check reads as *not evaluated*. Either way the score is
unaffected by capabilities you were never sold.

The entitlement is established from evidence, never from your plan name.
GitHub sells Secret Protection independently of the plan tier, so a Team org
may hold it and an Enterprise org may not — a repository that already has push
protection on proves the point at no API cost, and only when nothing proves it
either way does scopeward ask the billing endpoint. If that cannot be answered
(no `admin:org`, for instance), the result is *unknown*, and unknown reports
everything: withholding on a guess would hide exposure you can in fact fix.
Each run discloses what it concluded under `entitlements` in the JSON output.

### Branch protection is scaled to your team

A remediation nobody can live with is a remediation nobody applies, so the
suggested branch-protection command adapts to the organization's size — no flag
required:

| Members | Suggested protection |
|---|---|
| 1 | pull request required, no approving review, admin bypass kept |
| 2–4 | pull request + 1 approving review, admin bypass kept |
| 5+ | pull request + 1 approving review, enforced on admins too |

Below five people, requiring a review *and* removing the admin bypass leaves a
team with no way to land an urgent fix when one person is away. So scopeward
keeps the owner break-glass path, reports it as an `info` (zero penalty) so the
exposure stays visible, and tells you to revisit it as the team grows — rather
than recommending a lockout and then flagging you for the workaround.

`--solo` affects only the *approving review* column: it never changes a finding's
severity. A flag that moved the score would be an invisible discount, which is
exactly what `.scopeward.yml` reasons exist to prevent. Whether the admin bypass
is expected is decided by member count alone — and a genuine solo account is
below the threshold anyway.

Protection quality is assessed for **both** mechanisms — classic branch
protection and rulesets — by reading each branch's effective rules, so a
deliberately weak ruleset no longer reads the same as a strong one. Remediation
follows the mechanism: for a ruleset-protected branch scopeward points at the
ruleset rather than suggesting classic protection, which would stack a second
mechanism beside the weak rule instead of fixing it. A ruleset's bypass actors
are not exposed with its rules, so admin bypass on those repos is reported as
explicitly *not assessed* rather than passing silently.

Above the threshold, an admin bypass becomes a `medium` finding
(`teams.branch-protection-bypassable`). If you keep one deliberately, accept it
in `.scopeward.yml` with a `reason` — it will then be reported under
**Accepted risks** with your justification.

> Working solo? Add `--solo` so suggested branch-protection fixes require a PR
> but no approving review (you can't approve your own PR).

## License

[MIT](LICENSE) © Sunny Systems
