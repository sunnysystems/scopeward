package model

// Kind separates the two questions a governance report answers, which today's
// score sums into one number and should not (issue #39).
//
//   - KindCoverage — "are you instrumented?" A control or protection that should
//     be on is off, weak, or absent. The fix is a setting.
//   - KindDebt — "what do the instruments report?" A thing exists and is a
//     problem: a member, a credential, an alert, a grant, a repository. The fix
//     removes, rotates, or revokes it.
//
// They matter because they move in opposite directions when an operator acts.
// Enabling Dependabot raises coverage and *reveals* debt; summed into one
// number, the act of looking costs points, which is the perverse incentive #27
// describes. Kept apart, the composite can be built so that it never does.
//
// The operational test, when a check is ambiguous: does the finding describe a
// setting that should be flipped (coverage), or an entity that should be dealt
// with (debt)? An org secret visible to every repo is debt — the secret exists —
// while an org that lets any member fork private repos is coverage.
type Kind string

const (
	KindCoverage Kind = "coverage"
	KindDebt     Kind = "debt"
)
