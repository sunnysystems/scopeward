package model

import "testing"

func TestNewSnapshotDefaultsToGitHub(t *testing.T) {
	s := NewSnapshot("acme")
	if s.Provider != ProviderGitHub {
		t.Errorf("NewSnapshot provider = %q, want %q", s.Provider, ProviderGitHub)
	}
	if s.Host != "" {
		t.Errorf("NewSnapshot host = %q, want empty (SaaS default)", s.Host)
	}
	if s.Org.Login != "acme" {
		t.Errorf("NewSnapshot org login = %q, want %q", s.Org.Login, "acme")
	}
	if s.Coverage == nil {
		t.Error("NewSnapshot must initialize Coverage")
	}
}

func TestOwnersSelectsAdmins(t *testing.T) {
	s := NewSnapshot("acme")
	s.Members = []Member{
		{Login: "owner1", Role: "admin"},
		{Login: "dev1", Role: "member"},
		{Login: "owner2", Role: "admin"},
		{Login: "nobody", Role: ""},
	}
	owners := s.Owners()
	if len(owners) != 2 {
		t.Fatalf("Owners() returned %d, want 2", len(owners))
	}
	for _, o := range owners {
		if o.Role != "admin" {
			t.Errorf("Owners() included non-admin %q (role %q)", o.Login, o.Role)
		}
	}
}

func TestCoverageAllSortedByKind(t *testing.T) {
	r := NewCoverageReport()
	r.OK(DataRepos, 3)
	r.OK(DataMembers, 2)
	r.Missing(DataAppInstallations, "n/a")
	all := r.All()
	for i := 1; i < len(all); i++ {
		if all[i].Kind < all[i-1].Kind {
			t.Errorf("All() not sorted by Kind: %q before %q", all[i-1].Kind, all[i].Kind)
		}
	}
}
