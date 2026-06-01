package cache

import (
	"testing"
)

func TestDiskRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)           // darwin UserCacheDir
	t.Setenv("XDG_CACHE_HOME", tmp) // linux UserCacheDir

	d, err := Open("acme-deadbeef")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	d.Put("https://api/x", "etag-1", []byte(`{"v":1}`), `<u>; rel="next"`)

	if etag, body, link, ok := d.Get("https://api/x"); !ok || etag != "etag-1" || string(body) != `{"v":1}` || link == "" {
		t.Fatalf("get = (%q,%q,%q,%v)", etag, body, link, ok)
	}
	if err := d.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Reopen and confirm persistence.
	d2, err := Open("acme-deadbeef")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if etag, body, _, ok := d2.Get("https://api/x"); !ok || etag != "etag-1" || string(body) != `{"v":1}` {
		t.Errorf("persisted get = (%q,%q,%v)", etag, body, ok)
	}
}
