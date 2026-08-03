<!--
Keep this short. Delete any section that does not apply.
See CONTRIBUTING.md for the constraints a change has to hold.
-->

## What and why

<!-- One or two sentences. Link the issue: Fixes #NN -->

## Report diff

<!--
For anything that changes what the user sees or scores, paste the before and
after of the relevant lines (redacted). The terminal report is the product; a
diff of it reviews better than prose. Delete if this is internal-only.
-->

## Checklist

- [ ] `make fmt`, `make vet` and `make test` pass locally
- [ ] Read-only: no new write to the GitHub or GitLab API
- [ ] The token cannot reach disk, a log, an error message or any report format
- [ ] No new dependency, or the PR explains why one is warranted
- [ ] No audit output committed (fix scripts, HTML reports, SARIF, baselines)

<!-- If any of these apply, keep the line and say what changed. -->

- [ ] **Changes a check ID** — breaks existing `.scopeward.yml` suppressions and
      SARIF baselines; state the old and new ID
- [ ] **Changes scoring** — scores are compared across runs, so a reweighting
      shows up in the user's org as a regression; state the effect
- [ ] **Needs a new token scope or plan tier** — state which, and confirm the
      check degrades to *not evaluated* rather than failing without it
