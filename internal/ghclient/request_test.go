package ghclient

import (
	"net/http"
	"testing"
)

func TestHasNextPage(t *testing.T) {
	cases := []struct {
		name string
		link string
		want bool
	}{
		{"empty", "", false},
		{"only last", `<https://api.github.com/...?page=3>; rel="last"`, false},
		{"has next", `<https://api.github.com/...?page=2>; rel="next", <https://api.github.com/...?page=3>; rel="last"`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			if tc.link != "" {
				resp.Header.Set("Link", tc.link)
			}
			if got := HasNextPage(resp); got != tc.want {
				t.Errorf("HasNextPage(%q) = %v, want %v", tc.link, got, tc.want)
			}
		})
	}
}

func TestNextPageCursor(t *testing.T) {
	cases := []struct {
		name string
		link string
		want string
	}{
		{"empty", "", ""},
		{"no next", `<https://api.github.com/repositories/1/dependabot/alerts?state=open&per_page=100&before=z>; rel="prev"`, ""},
		{"cursor next", `<https://api.github.com/repositories/1/dependabot/alerts?state=open&per_page=100&after=Y3Vyc29y>; rel="next", <...>; rel="first"`, "Y3Vyc29y"},
		{"param absent in next", `<https://api.github.com/repositories/1/dependabot/alerts?state=open>; rel="next"`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			if tc.link != "" {
				resp.Header.Set("Link", tc.link)
			}
			if got := NextPageCursor(resp, "after"); got != tc.want {
				t.Errorf("NextPageCursor(%q) = %q, want %q", tc.link, got, tc.want)
			}
		})
	}
}

func TestClassifyToken(t *testing.T) {
	cases := map[string]TokenType{
		"ghp_abc":        TokenClassicPAT,
		"github_pat_abc": TokenFineGrainedPAT,
		"gho_abc":        TokenOAuth,
		"ghs_abc":        TokenAppInstall,
		"ghu_abc":        TokenUserToServer,
		"weird":          TokenUnknown,
	}
	for raw, want := range cases {
		if got := classifyToken(raw); got != want {
			t.Errorf("classifyToken(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestSplitScopes(t *testing.T) {
	got := splitScopes("repo, read:org ,, admin:org")
	want := []string{"repo", "read:org", "admin:org"}
	if len(got) != len(want) {
		t.Fatalf("splitScopes len = %d (%v), want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("scope[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
