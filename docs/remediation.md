# Remediation

## Fix scripts that never run themselves

`--fix-script fixes.sh` writes suggested `gh` remediation commands, **all
commented out**. Nothing runs until you uncomment it. A read-only tool that
shipped a script which executes on `sh fixes.sh` would not be a read-only tool
in any sense a reviewer cares about.

The header states which token scopes the commands need and which your token is
missing, and each block names its own scope — so you find out before running
half a fix, not after.

### Keep the output out of git

A fix script or report carries your org login, repository names, team slugs and
an ordered map of where you are weakest. In a public repository that is a
targeting document.

The output path is yours to choose, so no `.gitignore` pattern can cover every
run. Instead, after writing a file `scopeward` asks git whether it is ignored,
and says so when it is not:

```text
⚠ acme-fixes.sh is in a git repository and is not ignored
  It maps where your organization is weakest. Add to .gitignore: /acme-fixes.sh
```

The warning is silent outside a git work tree, when the file is already ignored,
and under `--quiet`. It is advisory: it never changes the exit code.

## Branch protection is scaled to your team

A remediation nobody can live with is a remediation nobody applies, so the
suggested branch-protection command adapts to the organization's size — no flag
required:

| Members | Suggested protection |
|---|---|
| 1 | pull request required, no approving review, admin bypass kept |
| 2–4 | pull request + 1 approving review, admin bypass kept |
| 5+ | pull request + 1 approving review, enforced on admins too |

Below five people, requiring a review *and* removing the admin bypass leaves a
team with no way to land an urgent fix when one person is away. So `scopeward`
keeps the owner break-glass path, reports it as an `info` (zero penalty) so the
exposure stays visible, and tells you to revisit it as the team grows — rather
than recommending a lockout and then flagging you for the workaround.

`--solo` affects only the *approving review* column: it never changes a
finding's severity. A flag that moved the score would be an invisible discount,
which is exactly what `.scopeward.yml` reasons exist to prevent. Whether the
admin bypass is expected is decided by member count alone — and a genuine solo
account is below the threshold anyway.

Above the threshold, an admin bypass becomes a `medium` finding
(`teams.branch-protection-bypassable`). If you keep one deliberately, accept it
in `.scopeward.yml` with a `reason` — it will then be reported under **Accepted
risks** with your justification. See [policy.md](policy.md).

## Both protection mechanisms are assessed

Protection quality is assessed for **classic branch protection and rulesets**
alike, by reading each branch's effective rules, so a deliberately weak ruleset
no longer reads the same as a strong one.

Remediation follows the mechanism: for a ruleset-protected branch `scopeward`
points at the ruleset rather than suggesting classic protection, which would
stack a second mechanism beside the weak rule instead of fixing it.

A ruleset's bypass actors are not exposed with its rules, so admin bypass on
those repositories is reported as explicitly *not assessed* rather than passing
silently.
