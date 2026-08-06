# Running scopeward in CI

Governance is not a thing you check once. The action installs a pinned release
(checksum-verified, no Go toolchain needed), runs the audit headless, and
uploads the report.

```yaml
- uses: sunnysystems/scopeward@v0.1.0
  env:
    GITHUB_TOKEN: ${{ secrets.SCOPEWARD_TOKEN }}   # env only — never an input
  with:
    org: my-org
    fail-on: high
```

While `scopeward` is pre-1.0, pin the exact tag as above; a floating major tag
will track releases from 1.0 onward.

## The token is deliberately not an input

Inputs are echoed in the run's own parameter display and leak under a debug
`set -x`; the environment is the only place a token belongs.

Note that the workflow's built-in `GITHUB_TOKEN` **cannot read organization
settings** — you need a read-only PAT with `read:org`, `repo`, `admin:org` and
`read:user`, stored as a secret. See [entitlements.md](entitlements.md).

## Report only what changed

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

      - uses: sunnysystems/scopeward@v0.1.0
        env:
          GITHUB_TOKEN: ${{ secrets.SCOPEWARD_TOKEN }}
        with:
          org: my-org
          baseline: baseline/scopeward-report.json
          new-only: "true"      # speak only about what changed
          fail-on: high         # exit 2 → the job fails → someone looks
```

The first run has no predecessor and simply establishes the baseline. After that
the job passes silently and only speaks up when something new appears at or
above `high`.

## Action inputs

| Input | Default | Notes |
|---|---|---|
| `org` | *(none)* | omit to audit the token's own account |
| `version` | `latest` | pin to a tag for a reproducible job |
| `format` | `json` | `json` \| `sarif` \| `markdown` \| `text` |
| `output` | `scopeward-report.json` | where the report is written |
| `fail-on` | `none` | `low` \| `medium` \| `high` \| `critical` |
| `baseline` / `new-only` | *(none)* / `false` | report only what changed |
| `config` / `repo` / `args` | *(none)* | policy file, repo filter, extra flags |
| `upload-artifact` / `artifact-name` | `true` / `scopeward-report` | artifact upload |

Outputs: `report`, `exit-code`, `score`, `grade`.

Linux and macOS runners. On Windows, install the binary from the
[releases page](https://github.com/sunnysystems/scopeward/releases).

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Audit ran (no `--fail-on` trigger) |
| `1`  | Operational error (bad token, org not accessible, bad flag) |
| `2`  | `--fail-on` threshold met by at least one finding |

Both failure modes fail the job, and the job summary tells them apart — exit `2`
is a posture regression to triage, exit `1` is a broken job to fix.

## SARIF in code scanning

Set `format: sarif` and pass the report to `github/codeql-action/upload-sarif`.
Findings then land in the Security tab alongside code scanning results, and
suppressions from `.scopeward.yml` arrive as native SARIF `suppressions` so
accepted risks show with their justification.

This repository's own
[`governance.yml`](../.github/workflows/governance.yml) does exactly that on a
schedule, which is also what keeps the headless path honest.
