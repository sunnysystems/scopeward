package collect

import (
	"encoding/json"
	"strconv"
	"strings"
	"unicode"
)

// This file evaluates GitHub Actions if: expressions far enough to answer one
// question: can this condition let an actor without write access through on a
// given event? A guard that tests author_association on comments but not on
// opened issues closes one door and leaves the other open, and only evaluating
// the expression per event tells the two apart.
//
// Evaluation is three-valued. Whatever the workflow cannot know in advance —
// the comment body, a repository variable, a label — is unknown, and unknown
// never proves a gate: only a condition that is false for every non-writer
// closes the job to them.

type exprKind int

const (
	xUnknown exprKind = iota
	xNull
	xBool
	xNum
	xStr
	xArr
)

type exprVal struct {
	kind exprKind
	b    bool
	n    float64
	s    string
	arr  []exprVal
}

var unknownVal = exprVal{kind: xUnknown}

// tri is a three-valued truth: -1 false, 0 unknown, 1 true.
type tri int

func (v exprVal) truth() tri {
	switch v.kind {
	case xUnknown:
		return 0
	case xNull:
		return -1
	case xBool:
		return boolTri(v.b)
	case xNum:
		return boolTri(v.n != 0)
	case xStr:
		return boolTri(v.s != "")
	default:
		return 1
	}
}

func boolTri(b bool) tri {
	if b {
		return 1
	}
	return -1
}

func triVal(t tri) exprVal {
	if t == 0 {
		return unknownVal
	}
	return exprVal{kind: xBool, b: t > 0}
}

// exprContext resolves a context path such as "github.event_name"; paths it
// cannot know resolve to unknown.
type exprContext func(path string) exprVal

// evalCondition evaluates an if: condition. A condition that does not parse is
// unknown: a gate scopeward cannot read is not a gate it may assert.
func evalCondition(cond string, ctx exprContext) tri {
	cond = strings.TrimSpace(cond)
	if strings.HasPrefix(cond, "${{") && strings.HasSuffix(cond, "}}") {
		cond = strings.TrimSpace(cond[3 : len(cond)-2])
	}
	p := &exprParser{toks: lexExpr(cond), ctx: ctx}
	if p.toks == nil {
		return 0
	}
	v := p.or()
	if p.err || p.pos != len(p.toks) {
		return 0
	}
	return v.truth()
}

type exprTok struct {
	kind string // "id", "str", "num", "op", "(", ")", "[", "]", ","
	val  string
}

// lexExpr tokenises an expression, or returns nil on a character it does not
// recognise.
func lexExpr(s string) []exprTok {
	var toks []exprTok
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case unicode.IsSpace(rune(c)):
			i++
		case c == '\'':
			var b strings.Builder
			i++
			for {
				if i >= len(s) {
					return nil
				}
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						b.WriteByte('\'')
						i += 2
						continue
					}
					i++
					break
				}
				b.WriteByte(s[i])
				i++
			}
			toks = append(toks, exprTok{"str", b.String()})
		case strings.ContainsRune("()[],", rune(c)):
			toks = append(toks, exprTok{string(c), string(c)})
			i++
		case strings.HasPrefix(s[i:], "&&"), strings.HasPrefix(s[i:], "||"),
			strings.HasPrefix(s[i:], "=="), strings.HasPrefix(s[i:], "!="),
			strings.HasPrefix(s[i:], "<="), strings.HasPrefix(s[i:], ">="):
			toks = append(toks, exprTok{"op", s[i : i+2]})
			i += 2
		case c == '!' || c == '<' || c == '>':
			toks = append(toks, exprTok{"op", string(c)})
			i++
		case c >= '0' && c <= '9' || c == '-':
			j := i + 1
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == '.' || s[j] == 'x' || s[j] >= 'a' && s[j] <= 'f') {
				j++
			}
			toks = append(toks, exprTok{"num", s[i:j]})
			i = j
		case c == '_' || unicode.IsLetter(rune(c)):
			j := i
			for j < len(s) && (s[j] == '_' || s[j] == '-' || s[j] == '.' || s[j] == '*' || unicode.IsLetter(rune(s[j])) || unicode.IsDigit(rune(s[j]))) {
				j++
			}
			toks = append(toks, exprTok{"id", s[i:j]})
			i = j
		default:
			return nil
		}
	}
	if toks == nil {
		toks = []exprTok{}
	}
	return toks
}

type exprParser struct {
	toks []exprTok
	pos  int
	ctx  exprContext
	err  bool
}

func (p *exprParser) peek() exprTok {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return exprTok{}
}

func (p *exprParser) next() exprTok {
	t := p.peek()
	if p.pos < len(p.toks) {
		p.pos++
	} else {
		p.err = true
	}
	return t
}

func (p *exprParser) or() exprVal {
	v := p.and()
	for p.peek().val == "||" {
		p.next()
		r := p.and()
		a, b := v.truth(), r.truth()
		switch {
		case a > 0 || b > 0:
			v = triVal(1)
		case a < 0 && b < 0:
			v = triVal(-1)
		default:
			v = unknownVal
		}
	}
	return v
}

func (p *exprParser) and() exprVal {
	v := p.equality()
	for p.peek().val == "&&" {
		p.next()
		r := p.equality()
		a, b := v.truth(), r.truth()
		switch {
		case a < 0 || b < 0:
			v = triVal(-1)
		case a > 0 && b > 0:
			v = triVal(1)
		default:
			v = unknownVal
		}
	}
	return v
}

func (p *exprParser) equality() exprVal {
	v := p.comparison()
	for op := p.peek().val; op == "==" || op == "!="; op = p.peek().val {
		p.next()
		eq := exprEqual(v, p.comparison())
		if op == "!=" {
			eq = -eq
		}
		v = triVal(eq)
	}
	return v
}

func (p *exprParser) comparison() exprVal {
	v := p.unary()
	for op := p.peek().val; op == "<" || op == "<=" || op == ">" || op == ">="; op = p.peek().val {
		p.next()
		p.unary()
		v = unknownVal // ordering never decides an actor gate
	}
	return v
}

func (p *exprParser) unary() exprVal {
	if p.peek().val == "!" {
		p.next()
		return triVal(-p.unary().truth())
	}
	return p.primary()
}

func (p *exprParser) primary() exprVal {
	t := p.next()
	switch t.kind {
	case "(":
		v := p.or()
		if p.next().kind != ")" {
			p.err = true
		}
		return v
	case "str":
		return exprVal{kind: xStr, s: t.val}
	case "num":
		n, err := strconv.ParseFloat(t.val, 64)
		if err != nil {
			if i, ierr := strconv.ParseInt(t.val, 0, 64); ierr == nil {
				n = float64(i)
			} else {
				return unknownVal
			}
		}
		return exprVal{kind: xNum, n: n}
	case "id":
		switch strings.ToLower(t.val) {
		case "true":
			return exprVal{kind: xBool, b: true}
		case "false":
			return exprVal{kind: xBool, b: false}
		case "null":
			return exprVal{kind: xNull}
		}
		if p.peek().kind == "(" {
			return p.call(strings.ToLower(t.val))
		}
		path := t.val
		for p.peek().kind == "[" {
			p.next()
			idx := p.next()
			if p.next().kind != "]" {
				p.err = true
			}
			path += "." + idx.val
		}
		return p.ctx(strings.ToLower(path))
	}
	p.err = true
	return unknownVal
}

func (p *exprParser) call(name string) exprVal {
	p.next() // (
	var args []exprVal
	for p.peek().kind != ")" {
		args = append(args, p.or())
		if p.peek().kind == "," {
			p.next()
		} else if p.peek().kind != ")" {
			p.err = true
			return unknownVal
		}
		if p.err {
			return unknownVal
		}
	}
	p.next() // )

	arg := func(i int) exprVal {
		if i < len(args) {
			return args[i]
		}
		return unknownVal
	}
	switch name {
	case "contains":
		return triVal(exprContains(arg(0), arg(1)))
	case "startswith", "endswith":
		h, n := arg(0), arg(1)
		if h.kind != xStr || n.kind != xStr {
			return unknownVal
		}
		hs, ns := strings.ToLower(h.s), strings.ToLower(n.s)
		if name == "startswith" {
			return triVal(boolTri(strings.HasPrefix(hs, ns)))
		}
		return triVal(boolTri(strings.HasSuffix(hs, ns)))
	case "fromjson":
		if s := arg(0); s.kind == xStr {
			return fromJSONVal(s.s)
		}
		return unknownVal
	case "always", "success":
		return triVal(1)
	default:
		return unknownVal
	}
}

// exprEqual compares as GitHub does for the cases a gate uses: strings ignore
// case. Anything unknown, or of mismatched kinds, is unknown.
func exprEqual(a, b exprVal) tri {
	if a.kind == xUnknown || b.kind == xUnknown || a.kind != b.kind {
		return 0
	}
	switch a.kind {
	case xStr:
		return boolTri(strings.EqualFold(a.s, b.s))
	case xBool:
		return boolTri(a.b == b.b)
	case xNum:
		return boolTri(a.n == b.n)
	case xNull:
		return 1
	default:
		return 0
	}
}

func exprContains(hay, needle exprVal) tri {
	switch hay.kind {
	case xArr:
		result := tri(-1)
		for _, el := range hay.arr {
			switch exprEqual(el, needle) {
			case 1:
				return 1
			case 0:
				result = 0
			}
		}
		return result
	case xStr:
		if needle.kind != xStr {
			return 0
		}
		return boolTri(strings.Contains(strings.ToLower(hay.s), strings.ToLower(needle.s)))
	default:
		return 0
	}
}

func fromJSONVal(s string) exprVal {
	var raw any
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return unknownVal
	}
	return jsonToVal(raw)
}

func jsonToVal(raw any) exprVal {
	switch t := raw.(type) {
	case nil:
		return exprVal{kind: xNull}
	case bool:
		return exprVal{kind: xBool, b: t}
	case float64:
		return exprVal{kind: xNum, n: t}
	case string:
		return exprVal{kind: xStr, s: t}
	case []any:
		arr := make([]exprVal, 0, len(t))
		for _, el := range t {
			arr = append(arr, jsonToVal(el))
		}
		return exprVal{kind: xArr, arr: arr}
	default:
		return unknownVal
	}
}

// nonWriterAssociations are the author_association values an account without
// write access can carry; OWNER, MEMBER and COLLABORATOR are the others.
var nonWriterAssociations = []string{"NONE", "FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "CONTRIBUTOR"}

// outsiderLogin stands for the non-writer's login: it equals no login a
// workflow can name.
const outsiderLogin = "\x00outsider"

// admitsNonWriter reports whether an if: can let an account without write
// access through on event, in repository repo ("owner/name"). It tries each
// association such an account can carry; one that is not refused is enough.
func admitsNonWriter(cond any, event, repo string) bool {
	if cond == nil {
		return true
	}
	text := strings.TrimSpace(stringOf(cond))
	if text == "" {
		return true
	}
	owner, _, _ := strings.Cut(repo, "/")
	for _, assoc := range nonWriterAssociations {
		ctx := func(path string) exprVal {
			switch {
			case path == "github.event_name":
				return exprVal{kind: xStr, s: event}
			case path == "github.repository":
				return exprVal{kind: xStr, s: repo}
			case path == "github.repository_owner":
				return exprVal{kind: xStr, s: owner}
			case strings.HasSuffix(path, ".author_association"):
				return exprVal{kind: xStr, s: assoc}
			case path == "github.actor", path == "github.triggering_actor",
				path == "github.event.sender.login", path == "github.event.comment.user.login",
				path == "github.event.review.user.login":
				return exprVal{kind: xStr, s: outsiderLogin}
			}
			return unknownVal
		}
		if evalCondition(text, ctx) >= 0 {
			return true
		}
	}
	return false
}

func stringOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}
