// Package cache provides a small disk-backed ETag store so repeated audits can
// issue conditional requests: GitHub answers unchanged resources with 304 Not
// Modified, which is fast and does not consume the primary rate limit.
//
// The cache is namespaced per org and per token fingerprint, so a body fetched
// with one token is never replayed for another.
package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

type entry struct {
	ETag string `json:"etag"`
	Link string `json:"link,omitempty"`
	Body []byte `json:"body"` // encoded as base64 by encoding/json
}

// Disk is a file-backed, concurrency-safe ETag cache.
type Disk struct {
	path  string
	mu    sync.Mutex
	items map[string]entry
}

var unsafeName = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// Open loads (or starts) a cache for the given namespace under the user cache
// directory: <cache>/scopeward/<namespace>.json.
func Open(namespace string) (*Disk, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(base, "scopeward")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	d := &Disk{
		path:  filepath.Join(dir, unsafeName.ReplaceAllString(namespace, "_")+".json"),
		items: map[string]entry{},
	}
	if data, err := os.ReadFile(d.path); err == nil {
		_ = json.Unmarshal(data, &d.items) // a corrupt cache is simply ignored
	}
	return d, nil
}

// Get implements ghclient.Cache.
func (d *Disk) Get(key string) (etag string, body []byte, link string, ok bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.items[key]
	return e.ETag, e.Body, e.Link, ok
}

// Put implements ghclient.Cache.
func (d *Disk) Put(key, etag string, body []byte, link string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	stored := make([]byte, len(body))
	copy(stored, body)
	d.items[key] = entry{ETag: etag, Link: link, Body: stored}
}

// Save writes the cache to disk. Call once at the end of a run.
func (d *Disk) Save() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	data, err := json.Marshal(d.items)
	if err != nil {
		return err
	}
	return os.WriteFile(d.path, data, 0o600)
}

// Clear drops all in-memory entries so the run issues full (non-conditional)
// requests and repopulates with fresh ETags. Used by --refresh to guarantee the
// audit reflects current state, never a stale 304. The file is rewritten on Save.
func (d *Disk) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.items = map[string]entry{}
}

// Path returns the cache file location (for diagnostics).
func (d *Disk) Path() string { return d.path }
