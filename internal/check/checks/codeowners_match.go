package checks

import (
	"regexp"
	"strings"

	"github.com/sunnysystems/scopeward/internal/model"
)

// codeownersFor returns the owners CODEOWNERS assigns to a path: the last rule
// whose pattern matches decides, and a rule that names nobody leaves the path
// deliberately unowned.
func codeownersFor(rules []model.CodeownersRule, path string) []string {
	var owners []string
	for _, r := range rules {
		if re := codeownersPattern(r.Pattern); re != nil && re.MatchString(path) {
			owners = r.Owners
		}
	}
	return owners
}

// codeownersPattern compiles a CODEOWNERS pattern with GitHub's gitignore-like
// rules:
//
//   - a pattern with a slash at the start or in the middle is anchored at the
//     repository root; otherwise it matches at any depth ("apps/", "*.md");
//   - a trailing slash matches a directory and everything under it;
//   - "*" and "?" stop at a slash, "**" crosses any number of directories;
//   - a last segment without a wildcard covers a directory of that name and
//     everything under it, while one with a wildcard matches only at its own
//     level ("docs/*" owns docs/a.md but not docs/build/b.md).
//
// Negation and character ranges do not exist in CODEOWNERS. A pattern that does
// not compile matches nothing, as GitHub skips an invalid line.
func codeownersPattern(pattern string) *regexp.Regexp {
	dirOnly := strings.HasSuffix(pattern, "/")
	p := strings.Trim(pattern, "/")
	if p == "" {
		return nil
	}
	anchored := strings.HasPrefix(pattern, "/") || strings.Contains(p, "/")
	segs := strings.Split(p, "/")

	var b strings.Builder
	b.WriteString("^")
	if !anchored {
		b.WriteString("(?:.*/)?")
	}
	for i, seg := range segs {
		last := i == len(segs)-1
		if seg == "**" {
			if last {
				b.WriteString(".*")
			} else {
				b.WriteString("(?:.*/)?")
			}
			continue
		}
		for _, c := range seg {
			switch c {
			case '*':
				b.WriteString("[^/]*")
			case '?':
				b.WriteString("[^/]")
			default:
				b.WriteString(regexp.QuoteMeta(string(c)))
			}
		}
		if !last {
			b.WriteString("/")
		}
	}
	lastSeg := segs[len(segs)-1]
	switch {
	case dirOnly:
		b.WriteString("/.*")
	case lastSeg != "**" && !strings.ContainsAny(lastSeg, "*?"):
		b.WriteString("(?:/.*)?")
	}
	b.WriteString("$")

	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}
