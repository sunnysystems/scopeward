package access

// Level is a repository permission level, ordered so the effective level of
// several grants is their maximum.
type Level int

const (
	None Level = iota
	Read
	Triage
	Write
	Maintain
	Admin
)

var levelNames = [...]string{"none", "read", "triage", "write", "maintain", "admin"}

func (l Level) String() string {
	if l < None || l > Admin {
		return "unknown"
	}
	return levelNames[l]
}

// ParseLevel reads a level as the collectors normalize it, including the
// org base permission's spelling ("none", "read", "write", "admin"). An
// unrecognized value is None: a level scopeward cannot read is never assumed.
func ParseLevel(s string) Level {
	for i, n := range levelNames {
		if n == s {
			return Level(i)
		}
	}
	return None
}
