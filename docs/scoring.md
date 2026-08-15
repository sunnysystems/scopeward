# How the score works

`scopeward` prints one number. This is what is behind it, because a governance
score you cannot interrogate is a governance score nobody should act on.

## The score is a rate, not a count

Penalty is normalized **per repository**. A score is only interpretable next to
the size of the organization it came from, and two orgs with the same number
have the same posture whether one has four repositories and the other four
hundred.

```text
  penalty 39 · 14 not instrumented, 25 open findings · 2.4 per repo across 36 repos
```

Without normalization every large organization scores F by arithmetic alone,
and the number stops carrying information about how the org is actually run.

## Ninety-nine open CVEs do not weigh like one

A finding is not always one thing. `acme/api has 42 open Dependabot alert(s)` is
forty-two things reported as one row, and until recently it scored exactly what a
repository with a single alert scored. A report of 198 flagged repositories that
prices them all identically cannot tell a reviewer where to start, which is most
of what the report is for.

So weight scales with the count, sub-linearly and with a ceiling:

```text
weight = severity weight × min(1 + log₂(n)/4, 3)
```

| open alerts | multiplier |
|---:|---:|
| 1 | 1.00× |
| 10 | 1.83× |
| 99 | 2.66× |
| 256 or more | 3.00× (capped) |

Sub-linear because the second known vulnerability in a repository is not as bad
as the first: it is the same dependency bump either way, and the repository was
already exposed. Capped because without a ceiling a single 99-alert repository
lands at 166 points — over a third of a real organization's whole penalty — and
the score would describe its worst repository rather than its estate.

Severity is untouched by this: it still tracks the **worst** item, so a
repository with one critical and ninety-eight lows is critical. How bad is the
worst one and how many are there are two questions, and the score now answers
both. The counts in the summary stay counts of findings — "3 critical" means
three findings, never three hundred alerts.

Checks that report a single thing — around seventy-eight of them — are
unaffected: n=1 is exactly 1.00×.

## What the grades mean

The letters are cut by penalty per repository, so they mean the same thing at
any organization size:

| Grade | Per-repo rate | Reads as |
|---|---|---|
| **A** ≥ 75 | ≤ 1.3 | exemplary — controls on, residual debt only |
| **B** ≥ 65 | ≤ 3.4 | solid, with gaps you could name |
| **C** ≥ 55 | ≤ 6.2 | visible gaps across the estate |
| **D** ≥ 40 | ≤ 13 | systemic gaps |
| **F** | worse | |

`A` is deliberately not "no findings". An organization doing everything right
still carries residual debt, and a grade nobody can reach is a grade nobody
aims at.

Two honest caveats. Scores above 75 are unreachable in practice — no setting of
the decay constant puts an exemplary organization at 90 while keeping the lower
bands meaningfully apart, and moving the letters was preferred to rescaling the
number again. And the bands were calibrated against three real organizations of
23, 36 and 581 active repositories, **all of which land F**; the A/B/C
boundaries rest on the definition above rather than on measurement.

## The score never punishes looking

Turning a security control **on** used to lower the score. A repository with
Dependabot alerts disabled scored one medium finding; the same repository with
alerts enabled and a critical CVE open scored a critical. The vulnerabilities
were identical — the only difference was whether you could see them, and looking
cost twenty points per repository.

That is a scoring bug with a real-world consequence: it pays to stay blind.

So a disabled monitoring control is not priced at a flat weight. It is priced at
**the debt it hides**: at least what one critical finding would cost, and more
when your own instrumented repositories carry more than that each. Enabling the
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

One honest limit, since weighting debt by volume made the estimate an estimate of
a bigger number. The price of a dark repository is learned from your own
instrumented ones, measured exactly as the dark ones will be charged once you can
see them, so it holds whenever what you light up resembles what you already see:
across 800 simulated enablement campaigns, from 10% to 90% of repositories dark,
the penalty fell every single time. It does not hold in one shape — an
organization with no observed debt at all, whose unmonitored repositories each
turn out to hide a large backlog. There the estimate had nothing to learn from,
priced from the prior, and the prior was wrong. Closing that case means pricing
every unmonitored repository as though it hid the maximum, which measures out at
64% of the score being assumption. A number mostly made of assumption is a worse
instrument than a guarantee that holds against evidence.

## Coverage and debt are two different axes

Checks are classified as either **coverage** (is the control on?) or **debt**
(what did the control find?). They are reported separately rather than summed
into an undifferentiated pile, because they lead to different work: coverage
gaps are a configuration change, debt is a backlog.

## The biggest lever

For most organizations with history the largest single fix is archiving dead
repositories, since one abandoned repo carries a whole stack of per-repo
findings. The report leads with the aggregate rather than burying it under one
2-point `low` per repository:

```text
  Biggest lever
    12 repositories have had no push past the stale threshold. Archiving them
    resolves 65 findings worth 345 penalty (score 33 → 49 D).
    Not counted above: 2 findings on these repositories stay real after
    archiving — a committed credential is exposed whether or not the repo is
    read-only. Rotate those first.
```

`--fix-script` emits the `gh` archive commands. Archiving is reversible: it
makes a repository read-only, it does not delete anything.

## Archived repositories

Archived repositories are skipped by the per-repo checks — nothing can be pushed
to a read-only repo, so its branch protection and grants are moot — with one
exception: they are still scanned for **leaked secrets**. Archiving does not
un-leak a credential already in the history, and a retired repository is exactly
where nobody looks.

Those get their own `--max-repos` budget, so a graveyard of archived repos never
eats the cap meant for the active ones.

## Not evaluated is not a pass

Data the token could not read is reported as *not evaluated*, never as a pass,
and never silently. A check that cannot see something says so — a false clean
bill of health is the worst output an audit tool can produce.

```text
  Not evaluated: fine-grained PATs (needs GitHub Enterprise)
```

See [entitlements.md](entitlements.md) for how this interacts with features your
plan does not include.
