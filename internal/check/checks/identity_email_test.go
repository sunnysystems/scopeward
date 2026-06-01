package checks

import (
	"context"
	"testing"

	"github.com/sunnysystems/scopeward/internal/model"
)

func TestEmailOutsideCompany(t *testing.T) {
	snap := model.NewSnapshot("acme")
	snap.CompanyDomains = []string{"mycompany.com"}
	snap.Members = []model.Member{
		{Login: "alice", SAMLNameID: "alice@mycompany.com"}, // company → ok
		{Login: "bob", SAMLNameID: "bob@eng.mycompany.com"}, // subdomain → ok
		{Login: "carol", SAMLNameID: "carol@gmail.com"},     // external → flag
		{Login: "dave", SAMLNameID: ""},                     // not SSO-linked → skip
		{Login: "erin", SAMLNameID: "opaque-saml-id-12345"}, // non-email nameId → skip
		{Login: "frank", SAMLNameID: "frank@contractor.io"}, // external → flag
	}

	got := emailOutsideCompany{}.Run(context.Background(), snap)
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (carol, frank)", len(got))
	}
	flagged := map[string]bool{}
	for _, f := range got {
		flagged[f.Evidence["login"].(string)] = true
		if f.Severity != model.SevMedium {
			t.Errorf("%s severity = %v, want medium", f.Resource.Name, f.Severity)
		}
	}
	if !flagged["carol"] || !flagged["frank"] {
		t.Errorf("flagged = %v, want carol and frank", flagged)
	}
}

func TestEmailDomain(t *testing.T) {
	cases := []struct {
		in     string
		domain string
		ok     bool
	}{
		{"a@mycompany.com", "mycompany.com", true},
		{"a@MyCompany.COM", "mycompany.com", true},
		{"", "", false},
		{"no-at-sign", "", false},
		{"trailing@", "", false},
	}
	for _, tc := range cases {
		d, ok := emailDomain(tc.in)
		if ok != tc.ok || d != tc.domain {
			t.Errorf("emailDomain(%q) = (%q,%v), want (%q,%v)", tc.in, d, ok, tc.domain, tc.ok)
		}
	}
}
