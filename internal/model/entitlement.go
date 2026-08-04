package model

// Entitlement names a paid capability whose absence makes a remediation
// impossible rather than merely unperformed.
//
// This is deliberately separate from DataKind. A DataKind answers "could we see
// it?"; an Entitlement answers "could they fix it?". The two come apart: an org
// on a plan without GitHub Secret Protection reports its private repositories'
// push-protection state perfectly well (the data is there), but cannot turn it
// on. Reporting that as a finding hands the reader an invoice, not a fix, and at
// the scale of a few hundred private repositories it crowds out the findings
// they could act on (issue #50).
type Entitlement string

const (
	// EntSecretProtection is GitHub Secret Protection: secret scanning and push
	// protection on private repositories. Free on public repositories on every
	// plan, which is why checks that read it must gate per repository rather
	// than per organization.
	EntSecretProtection Entitlement = "secret_protection"
)

// EntitlementState is what we managed to establish about an entitlement.
//
// Unknown is a first-class answer, not a failure. Absent suppresses findings, so
// treating "we could not tell" as Absent would silently hide real, fixable
// exposure — the false negative this whole mechanism exists to avoid. Checks
// must therefore behave on Unknown exactly as they did before entitlements
// existed: report, and let the reader judge.
type EntitlementState string

const (
	EntitlementGranted EntitlementState = "granted"
	EntitlementAbsent  EntitlementState = "absent"
	EntitlementUnknown EntitlementState = "unknown"
)

// EntitlementStatus records what we concluded and how. Reason is not decoration:
// an entitlement decides whether findings appear at all, so the reader is owed
// the evidence behind a suppression as much as the suppression itself.
type EntitlementStatus struct {
	Entitlement Entitlement      `json:"entitlement"`
	State       EntitlementState `json:"state"`
	Reason      string           `json:"reason,omitempty"`
}

// Entitlement returns what is known about an entitlement. An unrecorded
// entitlement reads as Unknown, so a collector that never ran (another provider,
// --quick, a failed call) degrades to the conservative state rather than to
// Absent.
func (s *Snapshot) Entitlement(e Entitlement) EntitlementStatus {
	if st, ok := s.Entitlements[e]; ok {
		return st
	}
	return EntitlementStatus{Entitlement: e, State: EntitlementUnknown, Reason: "not determined"}
}

// SetEntitlement records the outcome of an entitlement probe.
func (s *Snapshot) SetEntitlement(st EntitlementStatus) {
	if s.Entitlements == nil {
		s.Entitlements = make(map[Entitlement]EntitlementStatus, 1)
	}
	s.Entitlements[st.Entitlement] = st
}
