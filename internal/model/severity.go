package model

import "strconv"

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
