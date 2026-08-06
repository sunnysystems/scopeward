# Suppressions and policy

Two mechanisms live in the same file, `.scopeward.yml` (auto-detected, or point
at it with `--config`). They answer different questions.

- `ignore` removes a finding. It says *"we accept this."*
- `policy` declares what your organization decided. It produces findings of its
  own when reality disagrees.

## Suppressing findings

Allowlist accepted risks. Suppressed findings are excluded from the score and
from `--fail-on`, and are still listed so nothing is hidden silently.

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

`reason` is optional but recommended — a rule without one is reported as *no
reason recorded*, since documented risk acceptance is the point of the
mechanism. The reason also reaches `--format json` (with an
`unsuppressed_score`), the HTML report, and `--format sarif` (as a native
`suppressions` entry, so dashboards show accepted risks with their
justification).

## Declaring policy

`ignore` has one verb: it removes a finding. That limits every finding to one
sentence — *"this is unusual"*. The sentence governance actually runs on is the
other one: *"this violates what we decided."* Only the second gates a pipeline
without argument, and only the second produces a review that converges.

Add a `policy` block to the same file:

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

### The invariant wins

Where an invariant covers the same ground as a product check, the invariant wins
and the product check stands down — `require_owning_team` replaces
`teams.repo-no-owning-team`, and `forbid_direct_collaborators` replaces both
`perms.direct-admin-grant` and `perms.direct-repo-grant`. One problem, reported
once, at the severity you chose.

### Invariants, not inventory

A policy declares *predicates* ("no repository admin outside team X"), never
*resources* ("user U is admin on repo R"). Writing desired state is
infrastructure-as-code's job, and Terraform and settings reconcilers already do
it well; `scopeward` asserts properties of whatever state exists.

If a policy block starts needing one entry per repository, the design has
drifted — which is why an over-long `public_repos` list is rejected rather than
accepted. The invariant to write is the exception, not the list.

### Unknown keys are errors

A misspelled invariant that parsed would leave you believing a rule is running
when it is not, which is strictly worse than having written no policy at all.

For the same reason, an invariant that cannot be evaluated (missing scope,
uncollected data) is reported as *not evaluated* rather than passing quietly.
See [scoring.md](scoring.md#not-evaluated-is-not-a-pass).
