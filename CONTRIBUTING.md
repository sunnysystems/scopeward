# Contributing to scopeward

Thanks for wanting to help. This document covers the things that are specific
to this project — the constraints that get a PR rejected no matter how good the
code is, and how to add a check.

## The five constraints

These are not style preferences. A change that breaks one will not be merged,
so it is worth reading them before writing code:

1. **Local-first.** The tool runs on the user's machine or in their CI. It
   talks to the GitHub or GitLab API and to nothing else. No telemetry, no
   phone-home, no hosted component.
2. **Read-only.** Read scopes only. No code path may write to GitHub or
   GitLab — including "harmless" writes. `--fix-script` emits commands
   **commented out**; the tool never runs them.
3. **The token is never persisted.** It comes from an env var or a no-echo
   prompt, lives in memory, and is gone when the process exits. It must never
   reach disk, a log line, a trace, an error message, the cache, or any report
   format. Be careful with `%v` on structs that carry it.
4. **Single binary, zero config.** One cross-platform binary, no runtime
   dependencies. `go install` has to be the whole install story. New
   third-party dependencies need a reason in the PR description.
5. **Degrade honestly, never guess.** Data the token could not read is
   reported as *not evaluated*, never as a pass. A check that cannot see
   something must say so — a false clean bill of health is the worst output
   this tool can produce.

## Development

```sh
make build   # ./scopeward
make test    # go test -race ./...
make vet
make fmt     # checks formatting; fails if gofmt would change anything
```

CI runs exactly these, plus a cross-compile of every release target. Run them
before pushing and there should be no surprises.

**Never commit audit output.** Fix scripts, HTML reports and SARIF files
contain your organization's login, repository names, team slugs and an ordered
map of its weak points. `.gitignore` covers the documented filenames, but the
output path is your argument to choose — check `git status` before committing.

## Adding a check

Checks are pure functions over a collected snapshot. They perform **no I/O**:
collection already happened, and a check that made its own API call would break
the concurrency model and the coverage accounting.

One check is one new file in `internal/check/checks/`, with no central wiring
to edit — the registry is self-populating:

```go
func init() { check.Register(myCheck{}) }

type myCheck struct{}

func (myCheck) Meta() check.CheckMeta {
	return check.CheckMeta{
		ID:              "axis.short-slug",       // stable; it is a public API
		Title:           "Short human label",
		Axis:            model.AxisNonHuman,
		DefaultSeverity: model.SevMedium,
		RequiresData:    []model.DataKind{model.DataAppInstallations},
		Description:     "What it looks for and why it matters.",
	}
}

func (c myCheck) Run(_ context.Context, s *model.Snapshot) []model.Finding {
	// read s, return findings
}
```

Things that are easy to get wrong:

- **`RequiresData` is the honesty mechanism.** List every `DataKind` the check
  reads. If any of them was not fully collected, the Runner skips the check and
  reports it as *not evaluated*. Under-declaring turns a missing-scope run into
  a silent pass.
- **The `ID` is a stable identifier**, not a label. Users pin it in
  `.scopeward.yml` suppressions and in SARIF baselines. Renaming one breaks
  their config, so choose it carefully and treat a change as breaking.
- **Skip archived repositories** — use the `activeRepos(s)` helper. An archived
  repo is read-only, so who may push to it is moot. The exception is a check
  whose finding stays true after archiving (a leaked credential does); set
  `SurvivesArchiving: true` so reporting does not promise that archiving
  resolves it.
- **Severity has to survive contact with a real org.** If a finding cannot be
  acted on, or is normal in a healthy organization, it is `info` (zero penalty)
  or it is not a check.
- **Write the finding for someone who has to fix it.** `Title` names the
  specific resource, `Evidence` carries the raw values, `Description` explains
  the exposure, and remediation says what to actually do.

Add tests next to the check. The existing ones build a `model.Snapshot`
literal and assert on the findings — no network, no fixtures beyond Go structs.

## Pull requests

- Branch from `main`, one concern per PR.
- Conventional commits, matching the existing history:
  `fix(checks): --solo must not move the score`. Scopes in use include
  `checks`, `cli`, `report`, `collect`, `score`, `tui`.
- Reference the issue (`Fixes #56`). For a behaviour change, say in the
  description what the output looked like before and after — the terminal
  report is the product, and a diff of it reviews better than prose.
- Green CI is required. If a check's score weighting changes, say so
  explicitly: scores are compared across runs and a silent reweighting looks
  like a regression in the user's org.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md)
for private reporting and for what counts as one — a check reporting the wrong
thing is a bug, not a vulnerability.
