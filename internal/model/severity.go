package model

import (
	"fmt"
	"strconv"
)

// Severity ranks findings. Ordered so higher values are more urgent, which lets
// scoring and sorting treat it numerically.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "info"
	case SevLow:
		return "low"
	case SevMedium:
		return "medium"
	case SevHigh:
		return "high"
	case SevCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// MarshalJSON renders severity as its name rather than an opaque integer.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(s.String())), nil
}

// MarshalText makes Severity render as its name when used as a JSON map key
// (encoding/json uses TextMarshaler, not JSONMarshaler, for map keys).
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// ParseSeverity is the inverse of String. The second result is false for a name
// no severity answers to.
func ParseSeverity(name string) (Severity, bool) {
	for _, s := range []Severity{SevInfo, SevLow, SevMedium, SevHigh, SevCritical} {
		if s.String() == name {
			return s, true
		}
	}
	return SevInfo, false
}

// UnmarshalJSON reads back what MarshalJSON wrote.
//
// Without it the JSON report is a machine-readable format its own types cannot
// read: --baseline works only because it decodes into a narrow struct that
// avoids Severity entirely, and anything wanting whole findings back — a score
// trajectory across archived runs (#57), a test replaying a real report — fails
// on the first finding. A format that cannot round-trip is a format with one
// consumer.
func (s *Severity) UnmarshalJSON(b []byte) error {
	name, err := strconv.Unquote(string(b))
	if err != nil {
		return fmt.Errorf("severity must be a JSON string, got %s", b)
	}
	parsed, ok := ParseSeverity(name)
	if !ok {
		return fmt.Errorf("unknown severity %q", name)
	}
	*s = parsed
	return nil
}

// UnmarshalText is the map-key counterpart of MarshalText, so a by_severity
// breakdown decodes as well as it encodes.
func (s *Severity) UnmarshalText(b []byte) error {
	parsed, ok := ParseSeverity(string(b))
	if !ok {
		return fmt.Errorf("unknown severity %q", b)
	}
	*s = parsed
	return nil
}
