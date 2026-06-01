package ghclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

// APIError is a non-2xx response from GitHub, carrying the status code so
// callers can distinguish "forbidden / insufficient scope" (a coverage gap)
// from "not found" or a transport failure.
type APIError struct {
	StatusCode int
	Status     string
	Message    string // GitHub's error message body, if any
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("github %s: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("github %s", e.Status)
}

// IsForbidden reports whether an error is a 403/404 from GitHub — the signals
// that usually mean "the token cannot see this" rather than a real failure.
func IsForbidden(err error) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.StatusCode == http.StatusForbidden || ae.StatusCode == http.StatusNotFound
	}
	return false
}

// StatusCode returns the HTTP status from an APIError, or 0 if err is not one.
func StatusCode(err error) int {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.StatusCode
	}
	return 0
}

// Message returns GitHub's error message body from an APIError, or "" if err is
// not one or carried no message.
func Message(err error) string {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Message
	}
	return ""
}

// Get performs a read-only GET, decoding a 2xx JSON body into out (which may be
// nil to discard). It returns the response (body already closed) so callers can
// read headers such as Link for pagination.
func (c *Client) Get(ctx context.Context, path string, query url.Values, out any) (*http.Response, error) {
	req, err := c.newRequest(ctx, http.MethodGet, path, query)
	if err != nil {
		return nil, err
	}

	// Conditional request: if we cached this URL's ETag, ask GitHub to answer
	// 304 (free, no rate-limit cost) when nothing changed.
	cacheKey := req.URL.String()
	var (
		cachedLink string
		cachedBody []byte
		haveCache  bool
	)
	if c.cache != nil {
		if etag, body, link, ok := c.cache.Get(cacheKey); ok {
			cachedBody, cachedLink, haveCache = body, link, true
			req.Header.Set("If-None-Match", etag)
		}
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("calling GitHub: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified && haveCache {
		if out != nil {
			if err := json.Unmarshal(cachedBody, out); err != nil {
				return resp, fmt.Errorf("decoding cached response: %w", err)
			}
		}
		// Restore the Link header so pagination behaves as on a 200.
		resp.Header.Set("Link", cachedLink)
		return resp, nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, &APIError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Message:    decodeErrorMessage(resp.Body),
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, fmt.Errorf("reading GitHub response: %w", err)
	}
	if c.cache != nil {
		if etag := resp.Header.Get("ETag"); etag != "" {
			c.cache.Put(cacheKey, etag, body, resp.Header.Get("Link"))
		}
	}

	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return resp, fmt.Errorf("decoding GitHub response: %w", err)
		}
	}
	return resp, nil
}

// GetAll fetches every page of a list endpoint into a slice, following the
// Link header's rel="next". It is a free function because Go methods cannot be
// generic.
func GetAll[T any](ctx context.Context, c *Client, path string, query url.Values) ([]T, error) {
	if query == nil {
		query = url.Values{}
	}
	query.Set("per_page", "100")

	var all []T
	page := 1
	for {
		query.Set("page", strconv.Itoa(page))
		var batch []T
		resp, err := c.Get(ctx, path, query, &batch)
		if err != nil {
			return all, err
		}
		all = append(all, batch...)
		if !HasNextPage(resp) {
			return all, nil
		}
		page++
	}
}

var nextLinkRe = regexp.MustCompile(`<[^>]+>;\s*rel="next"`)

// HasNextPage reports whether the response's Link header advertises a next page.
func HasNextPage(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	return nextLinkRe.MatchString(resp.Header.Get("Link"))
}

func decodeErrorMessage(body io.Reader) string {
	var e struct {
		Message string `json:"message"`
	}
	_ = json.NewDecoder(body).Decode(&e)
	return e.Message
}
