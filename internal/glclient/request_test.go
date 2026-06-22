package glclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sunnysystems/scopeward/internal/auth"
)

func TestHasNextPage(t *testing.T) {
	cases := []struct {
		name string
		link string
		want bool
	}{
		{"empty", "", false},
		{"only last", `<https://gitlab.com/api/v4/groups?page=3>; rel="last"`, false},
		{"has next", `<https://gitlab.com/api/v4/groups?page=2>; rel="next", <https://gitlab.com/api/v4/groups?page=3>; rel="last"`, true},
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
		{"no next", `<https://gitlab.com/api/v4/projects?pagination=keyset&cursor=z>; rel="prev"`, ""},
		{"cursor next", `<https://gitlab.com/api/v4/projects?pagination=keyset&cursor=eyJpZCI6IjQyIn0>; rel="next"`, "eyJpZCI6IjQyIn0"},
		{"param absent in next", `<https://gitlab.com/api/v4/projects?pagination=keyset>; rel="next"`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			if tc.link != "" {
				resp.Header.Set("Link", tc.link)
			}
			if got := NextPageCursor(resp, "cursor"); got != tc.want {
				t.Errorf("NextPageCursor(%q) = %q, want %q", tc.link, got, tc.want)
			}
		})
	}
}

func TestClassifyToken(t *testing.T) {
	cases := map[string]TokenType{
		"glpat-abc":   TokenPAT,
		"glsoat-abc":  TokenServiceAccount,
		"gloas-abc":   TokenOAuth,
		"random-blob": TokenUnknown,
	}
	for raw, want := range cases {
		if got := classifyToken(raw); got != want {
			t.Errorf("classifyToken(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestWithHostNormalization(t *testing.T) {
	cases := map[string]string{
		"https://gitlab.example.com":         "https://gitlab.example.com",
		"https://gitlab.example.com/":        "https://gitlab.example.com",
		"gitlab.example.com":                 "https://gitlab.example.com", // scheme defaulted
		"https://gitlab.example.com/api/v4":  "https://gitlab.example.com", // /api/v4 trimmed
		"https://gitlab.example.com/api/v4/": "https://gitlab.example.com",
	}
	for in, want := range cases {
		c := New(auth.NewSecret("glpat-x")).WithHost(in)
		if c.baseURL != want {
			t.Errorf("WithHost(%q) baseURL = %q, want %q", in, c.baseURL, want)
		}
	}
	// Empty host leaves the default untouched.
	if c := New(auth.NewSecret("glpat-x")).WithHost(""); c.baseURL != defaultBaseURL {
		t.Errorf("WithHost(\"\") baseURL = %q, want %q", c.baseURL, defaultBaseURL)
	}
}

func TestRequestAuthHeaderAndAPIPrefix(t *testing.T) {
	var gotPath, gotPrivate, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotPrivate = r.Header.Get("PRIVATE-TOKEN")
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	// A glpat- token uses the PRIVATE-TOKEN header and the /api/v4 prefix.
	c := New(auth.NewSecret("glpat-secret"))
	c.baseURL = srv.URL
	if _, err := c.Get(context.Background(), "/user", nil, nil); err != nil {
		t.Fatalf("get: %v", err)
	}
	if gotPrivate != "glpat-secret" {
		t.Errorf("PRIVATE-TOKEN = %q, want the raw PAT", gotPrivate)
	}
	if gotAuth != "" {
		t.Errorf("Authorization = %q, want empty for a PAT", gotAuth)
	}
	if !strings.HasPrefix(gotPath, "/api/v4/") {
		t.Errorf("path = %q, want /api/v4 prefix", gotPath)
	}

	// An OAuth token uses Authorization: Bearer instead.
	c2 := New(auth.NewSecret("gloas-secret"))
	c2.baseURL = srv.URL
	if _, err := c2.Get(context.Background(), "/user", nil, nil); err != nil {
		t.Fatalf("get: %v", err)
	}
	if gotAuth != "Bearer gloas-secret" {
		t.Errorf("Authorization = %q, want Bearer for OAuth", gotAuth)
	}
	if gotPrivate != "" {
		t.Errorf("PRIVATE-TOKEN = %q, want empty for OAuth", gotPrivate)
	}
}

func TestGetReturnsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"403 Forbidden"}`))
	}))
	defer srv.Close()

	c := New(auth.NewSecret("glpat-x"))
	c.baseURL = srv.URL
	_, err := c.Get(context.Background(), "/groups", nil, nil)
	if StatusCode(err) != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", StatusCode(err))
	}
	if Message(err) != "403 Forbidden" {
		t.Errorf("Message = %q, want GitLab's body", Message(err))
	}
	if !IsForbidden(err) {
		t.Error("IsForbidden should be true for 403")
	}
}

func TestDecodeErrorMessageFallsBackToError(t *testing.T) {
	// GitLab uses "error" (a string) on some endpoints instead of "message".
	if got := decodeErrorMessage(strings.NewReader(`{"error":"insufficient_scope"}`)); got != "insufficient_scope" {
		t.Errorf("decodeErrorMessage = %q, want insufficient_scope", got)
	}
	if got := decodeErrorMessage(strings.NewReader(`{"message":"404 Not Found"}`)); got != "404 Not Found" {
		t.Errorf("decodeErrorMessage = %q, want 404 Not Found", got)
	}
}
