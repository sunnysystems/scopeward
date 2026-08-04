# Security policy

`scopeward` is a security tool that runs on a developer's machine with a token
that can read an entire GitHub organization. Its security properties are the
product, so we treat a break in them as a vulnerability rather than a bug.

## Reporting a vulnerability

Report privately through GitHub, not in a public issue:

**[Open a private security advisory](https://github.com/sunnysystems/scopeward/security/advisories/new)**

Include the version (`scopeward --version`), the platform, the flags used, and
the smallest reproduction you have. If a reproduction requires a real
organization, describe the shape of it instead — **never paste a token, a fix
script, an HTML report or SARIF output into a report.** Those artifacts contain
the org login, repository names, team slugs and the exact set of weak points,
which is precisely what an attacker would want.

We are a small team. You will get an acknowledgement, and we will tell you
honestly whether and when we can fix it rather than quote an SLA we cannot
hold. We will credit you in the advisory unless you ask us not to.

## Supported versions

`scopeward` is pre-1.0. Fixes land on `main` and go out in the next release;
older tags are not patched. Run the latest release.

## In scope

These are the guarantees the tool makes. Any way to break one is a
vulnerability, not a feature request:

| Guarantee | A break looks like |
|---|---|
| **The token is never persisted** | the token reaching disk, a log line, a trace, an error message, a crash dump, the cache, or any report format |
| **Read-only** | any code path that issues a write to GitHub or GitLab, however it is reached |
| **Local-first** | any byte sent anywhere other than the configured API host |
| **Nothing runs by itself** | `--fix-script` emitting a command that is not commented out, or output that executes when sourced |
| **Report artifacts stay local** | output written somewhere the user would not expect, or world-readable when it should not be |

Also in scope: a dependency vulnerability that is reachable from `scopeward`'s
own code paths, and anything that lets a hostile API response cause code
execution, path traversal or resource exhaustion on the auditing machine.

## Out of scope

- **False positives and false negatives in checks.** A check that reports a
  clean org as broken, or misses a real problem, is a correctness bug — please
  [open an issue](https://github.com/sunnysystems/scopeward/issues/new/choose)
  so it can be discussed in the open.
- **Findings about your own organization.** `scopeward` reporting that your org
  has non-expiring PATs is the tool working. Fix the org.
- Missing coverage that GitHub only exposes on a paid tier, which is reported
  as *not evaluated* by design.
- Vulnerabilities in GitHub or GitLab themselves — report those to their
  respective programs.

## Disclosure

We prefer coordinated disclosure. Once a fix is released we publish the
advisory, and we would rather you write about it publicly with the fix
available than sit on it indefinitely.
