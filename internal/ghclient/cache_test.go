package ghclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sunnysystems/scopeward/internal/auth"
)

// memCache is a tiny in-memory Cache for testing.
type memCache struct {
	etag, link string
	body       []byte
	hasGet     bool
}

func (m *memCache) Get(string) (string, []byte, string, bool) {
	return m.etag, m.body, m.link, m.hasGet
}
func (m *memCache) Put(_, etag string, body []byte, link string) {
	m.etag, m.body, m.link, m.hasGet = etag, body, link, true
}

func TestConditionalRequest304(t *testing.T) {
	var calls, conditional int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Link", `<u>; rel="next"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			conditional++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"v":1}`))
	}))
	defer srv.Close()

	c := New(auth.NewSecret("ghp_x"))
	c.baseURL = srv.URL
	c.SetCache(&memCache{})

	// First call: 200, caches the body + ETag.
	var out1 struct{ V int }
	if _, err := c.Get(context.Background(), "/x", nil, &out1); err != nil || out1.V != 1 {
		t.Fatalf("first get: v=%d err=%v", out1.V, err)
	}

	// Second call: server sees If-None-Match, returns 304; body served from cache.
	var out2 struct{ V int }
	resp, err := c.Get(context.Background(), "/x", nil, &out2)
	if err != nil || out2.V != 1 {
		t.Fatalf("second get: v=%d err=%v", out2.V, err)
	}
	if conditional != 1 {
		t.Errorf("conditional requests = %d, want 1", conditional)
	}
	if resp.Header.Get("Link") == "" {
		t.Error("Link header not restored on 304 (pagination would break)")
	}
}
