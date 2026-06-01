package auth

// Secret wraps a sensitive string (the GitHub token) so it cannot leak through
// the usual accidental paths: fmt verbs, structured logs, JSON marshaling, or a
// panic dump. The raw value is only reachable through Expose(), which forces the
// caller to be explicit. The token is never written to disk and lives only for
// the lifetime of the process.
type Secret struct {
	v string
}

// NewSecret wraps a raw token value.
func NewSecret(v string) Secret { return Secret{v: v} }

// Expose returns the raw value. Call sites should be rare and obvious — only
// where the token is actually handed to an HTTP Authorization header.
func (s Secret) Expose() string { return s.v }

// IsEmpty reports whether no token was provided.
func (s Secret) IsEmpty() bool { return s.v == "" }

const redacted = "***redacted***"

// String implements fmt.Stringer so %s / %v never print the token.
func (s Secret) String() string { return redacted }

// GoString implements fmt.GoStringer so %#v never prints the token.
func (s Secret) GoString() string { return redacted }

// MarshalJSON ensures the token is redacted if a Secret ever ends up inside a
// struct that gets serialized (e.g. a debug dump of config).
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
