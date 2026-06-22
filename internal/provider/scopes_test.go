package provider

import (
	"reflect"
	"testing"
)

func TestMissingGitHubScopes(t *testing.T) {
	cases := []struct {
		name   string
		scopes []string
		want   []string
	}{
		{"none reported can't judge", nil, nil},
		{"admin:org satisfies read:org", []string{"repo", "admin:org", "read:user"}, nil},
		{"only read:org leaves the rest", []string{"read:org"}, []string{"admin:org", "read:user", "repo"}},
		{"user satisfies read:user", []string{"read:org", "repo", "admin:org", "user"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := missingGitHubScopes(c.scopes); !reflect.DeepEqual(got, c.want) {
				t.Errorf("missingGitHubScopes(%v) = %v, want %v", c.scopes, got, c.want)
			}
		})
	}
}

func TestMissingGitLabScopes(t *testing.T) {
	cases := []struct {
		name   string
		scopes []string
		want   []string
	}{
		{"none reported can't judge", nil, nil},
		{"read_api + read_user is complete", []string{"read_api", "read_user"}, nil},
		{"only read_api leaves read_user", []string{"read_api"}, []string{"read_user"}},
		{"full api supersedes both", []string{"api"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := missingGitLabScopes(c.scopes); !reflect.DeepEqual(got, c.want) {
				t.Errorf("missingGitLabScopes(%v) = %v, want %v", c.scopes, got, c.want)
			}
		})
	}
}
