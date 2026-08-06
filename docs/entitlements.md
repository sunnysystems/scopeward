# Token scopes, missing coverage and paid features

`scopeward` is designed for an **organization owner** token, and degrades
predictably when it does not have one.

## Recommended scopes

GitHub (classic PAT):

| Scope | Unlocks |
|-------|---------|
| `read:org` | members, teams, base permission |
| `repo` | private repo metadata, collaborators, deploy keys, webhooks |
| `admin:org` | 2FA status, SSO, org apps & default workflow token (read paths) |
| `read:user` | member activity signals |

GitLab: `read_api` and `read_user`. Use `--host https://gitlab.example.com` for
a self-managed instance; the provider is inferred from the host.

`scopeward` only ever reads. It has no code path that writes to either forge,
and a way to make one write is a vulnerability rather than a bug — see
[SECURITY.md](../SECURITY.md).

One honest caveat about the token you create for it: GitHub's classic `repo`
scope has **no read-only variant**. It is the coarsest scope on the list and it
grants write on paper, whatever this tool does with it. If that is not a
trade you want to make, audit only public repositories by omitting it and let
the private-repo checks report as *not evaluated* — a narrower audit you can
justify beats a broader one you cannot.

## Missing scopes never fail the run

Affected checks degrade to *not evaluated*, and the gap is shown up front and in
the coverage report. You get a partial audit that says which part is partial,
rather than an error or — much worse — a clean result that was never measured.

Some checks (fine-grained PAT inventory, custom roles) require GitHub Enterprise
and are reported as not evaluated elsewhere.

## Paid features you do not have

A finding whose only remediation is a purchase is not a finding — it is an
invoice, and at scale it buries the ones you can act on. So `scopeward`
separates what it can *see* from what you can *fix*: where a fix needs a paid
capability your organization does not hold, the finding is withheld and the
omission is reported instead.

Push protection is the case that matters most. It is free on public repositories
on every plan and paid on private ones, so the test is **per repository** — an
org-wide switch would go quiet on exactly the repos where a leaked secret is
worst.

When some scope is out of reach the report says so under **Partially
evaluated**, with what was left out and why; when none of it is reachable the
check reads as *not evaluated*. Either way the score is unaffected by
capabilities you were never sold.

## Entitlement is established from evidence, never from your plan name

GitHub sells Secret Protection independently of the plan tier, so a Team org may
hold it and an Enterprise org may not.

1. A repository that already has push protection on **proves** the entitlement,
   at no API cost.
2. Only when nothing proves it either way does `scopeward` ask the billing
   endpoint.
3. If that cannot be answered (no `admin:org`, for instance) the result is
   *unknown* — and unknown reports everything. Withholding on a guess would hide
   exposure you can in fact fix.

Each run discloses what it concluded under `entitlements` in the JSON output.
