package collect

import (
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestApplyEnrichment_KnownData(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Members = []model.Member{
		{Login: "alice"},
		{Login: "bob"},
		{Login: "carol"},
	}

	noTwoFA := map[string]bool{"bob": true}
	owners := map[string]bool{"alice": true}
	saml := map[string]string{"alice": "alice@mycompany.com", "bob": ""} // carol not linked

	applyEnrichment(snap, noTwoFA, owners, saml)

	byLogin := map[string]model.Member{}
	for _, m := range snap.Members {
		byLogin[m.Login] = m
	}

	if got := byLogin["alice"]; got.Role != "admin" {
		t.Errorf("alice role = %q, want admin", got.Role)
	}
	if got := byLogin["bob"]; got.Role != "member" {
		t.Errorf("bob role = %q, want member", got.Role)
	}

	// 2FA: bob is in the disabled set, alice/carol are not.
	if got := byLogin["bob"].TwoFactorEnabled; got == nil || *got {
		t.Errorf("bob 2FA = %v, want enabled=false", got)
	}
	if got := byLogin["alice"].TwoFactorEnabled; got == nil || !*got {
		t.Errorf("alice 2FA = %v, want enabled=true", got)
	}

	// SAML: carol is not linked.
	if got := byLogin["carol"].SAMLLinked; got == nil || *got {
		t.Errorf("carol SAML = %v, want linked=false", got)
	}
	// SAML nameId is captured for linked members.
	if got := byLogin["alice"].SAMLNameID; got != "alice@mycompany.com" {
		t.Errorf("alice SAML nameId = %q, want alice@mycompany.com", got)
	}
}

func TestApplyEnrichment_UnknownStaysNil(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.Members = []model.Member{{Login: "alice"}}

	// All sets nil = data not collected; pointer flags must remain nil so checks
	// treat them as unknown, not as a confident "false".
	applyEnrichment(snap, nil, nil, nil)

	m := snap.Members[0]
	if m.TwoFactorEnabled != nil {
		t.Errorf("2FA = %v, want nil (unknown)", *m.TwoFactorEnabled)
	}
	if m.SAMLLinked != nil {
		t.Errorf("SAML = %v, want nil (unknown)", *m.SAMLLinked)
	}
	if m.Role != "" {
		t.Errorf("role = %q, want empty (unknown)", m.Role)
	}
}
