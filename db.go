package selfcheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/superfrink/govulnselfcheck/internal/cache"
	"github.com/superfrink/govulnselfcheck/osv"
)

// DefaultDBURL is the public Go vulnerability database.
const DefaultDBURL = "https://vuln.go.dev"

// DefaultUserAgent names the library in requests to the database.
const DefaultUserAgent = "govulnselfcheck"

// Database is where advisories come from. The types are osv's because that is
// where the database's shapes live; these aliases keep the package surface
// spelled the way callers expect.
type (
	// Database is the only external dependency of a check.
	Database = osv.Database
	// Index is the module index.
	Index = osv.Index
	// Ref is one advisory's entry in the module index.
	Ref = osv.Ref
)

// ParseIndex reads an index document.
func ParseIndex(data []byte) (*Index, error) { return osv.ParseIndex(data) }

// HTTPError is a non-success response from the database. NotFound reports the
// common and harmless case of an advisory that has been withdrawn while a
// client is mid-check.
type HTTPError struct {
	URL        string
	StatusCode int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("selfcheck: %s returned %d", e.URL, e.StatusCode)
}

// NotFound reports whether err says the document does not exist. It
// recognises this package's HTTPError and any error type with a
// NotFound() bool method, so a fake database can say the same thing.
func NotFound(err error) bool {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.StatusCode == http.StatusNotFound
	}
	var nf interface{ NotFound() bool }
	if errors.As(err, &nf) {
		return nf.NotFound()
	}
	return false
}

// HTTPDatabase reads the published database over HTTP.
//
// The zero value is not usable; start from HTTPDatabase{}. Fields left empty
// take the defaults named in their comments.
type HTTPDatabase struct {
	Base      string       // default DefaultDBURL
	Client    *http.Client // default: 30s timeout
	UserAgent string       // default DefaultUserAgent

	// IndexTTL and EntryTTL bound reuse of fetched documents within one
	// process. Zero means the default (one hour and 24 hours). A negative
	// value disables caching.
	IndexTTL time.Duration
	EntryTTL time.Duration

	// Backoff computes the wait before retry n (1-based). nil means
	// exponential from 200ms, capped at 5s. Retries applies to 429 and 5xx.
	Backoff func(attempt int) time.Duration
	Retries int // default 3

	initOnce sync.Once
	cache    *cache.Cache
}

func (d *HTTPDatabase) init() {
	d.initOnce.Do(func() {
		if d.cache == nil {
			d.cache = cache.New()
		}
	})
}

func (d *HTTPDatabase) base() string {
	if d.Base == "" {
		return DefaultDBURL
	}
	return strings.TrimSuffix(d.Base, "/")
}

func (d *HTTPDatabase) client() *http.Client {
	if d.Client != nil {
		return d.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (d *HTTPDatabase) userAgent() string {
	if d.UserAgent == "" {
		return DefaultUserAgent
	}
	return d.UserAgent
}

func (d *HTTPDatabase) retries() int {
	if d.Retries > 0 {
		return d.Retries
	}
	return 3
}

func (d *HTTPDatabase) backoff(attempt int) time.Duration {
	if d.Backoff != nil {
		return d.Backoff(attempt)
	}
	const max = 5 * time.Second
	d2 := 200 * time.Millisecond
	for i := 1; i < attempt && d2 < max; i++ {
		d2 *= 2
	}
	if d2 > max {
		d2 = max
	}
	return d2
}

func (d *HTTPDatabase) indexTTL() time.Duration {
	switch {
	case d.IndexTTL < 0:
		return 0
	case d.IndexTTL == 0:
		return time.Hour
	default:
		return d.IndexTTL
	}
}

func (d *HTTPDatabase) entryTTL() time.Duration {
	switch {
	case d.EntryTTL < 0:
		return 0
	case d.EntryTTL == 0:
		return 24 * time.Hour
	default:
		return d.EntryTTL
	}
}

// Index fetches the module index, reusing a cached copy while its TTL holds and
// revalidating with ETag or Last-Modified once it has expired. Concurrent
// calls share one fetch.
func (d *HTTPDatabase) Index(ctx context.Context) (*Index, error) {
	d.init()
	if v, ok := d.cache.Get("index"); ok {
		return v.(*Index), nil
	}
	v, err := d.cache.Do("index", func() (any, error) {
		if v, ok := d.cache.Get("index"); ok {
			return v, nil
		}
		var prev *Index
		if v, ok := d.cache.Get("index-revalidated"); ok {
			prev, _ = v.(*Index)
		}
		ix, err := d.fetchIndex(ctx, prev)
		if err != nil {
			return nil, err
		}
		d.cache.Set("index", ix, d.indexTTL())
		d.cache.Set("index-revalidated", ix, 0)
		return ix, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*Index), nil
}

func (d *HTTPDatabase) fetchIndex(ctx context.Context, prev *Index) (*Index, error) {
	u := d.base() + "/index/modules.json"
	body, header, err := d.get(ctx, u, prev)
	if err != nil {
		return nil, err
	}
	if body == nil { // not modified
		return prev, nil
	}
	ix, err := ParseIndex(body)
	if err != nil {
		return nil, err
	}
	ix.ETag = header.Get("ETag")
	ix.Modified = header.Get("Last-Modified")
	return ix, nil
}

// Entry fetches one advisory. GO IDs are validated before they reach a URL:
// the value in practice comes from a remote index.
func (d *HTTPDatabase) Entry(ctx context.Context, goID string) (*osv.Entry, error) {
	if !osv.ValidateID(goID) {
		return nil, fmt.Errorf("selfcheck: %q is not a Go vulnerability ID", goID)
	}
	d.init()
	key := "entry:" + goID
	if v, ok := d.cache.Get(key); ok {
		return v.(*osv.Entry), nil
	}
	v, err := d.cache.Do(key, func() (any, error) {
		if v, ok := d.cache.Get(key); ok {
			return v, nil
		}
		body, _, err := d.get(ctx, d.base()+"/ID/"+url.PathEscape(goID)+".json", nil)
		if err != nil {
			return nil, err
		}
		var e osv.Entry
		if err := json.Unmarshal(body, &e); err != nil {
			return nil, fmt.Errorf("selfcheck: parsing %s: %w", goID, err)
		}
		d.cache.Set(key, &e, d.entryTTL())
		return &e, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*osv.Entry), nil
}

// maxBody bounds how much of a response is read. The index is a few megabytes;
// anything past this is not the database.
const maxBody = 32 << 20

// get fetches url, retrying 429 and 5xx. When prev is non-nil and carries a
// validator, the request is conditional and a 304 yields (nil, header, nil).
func (d *HTTPDatabase) get(ctx context.Context, rawURL string, prev *Index) ([]byte, http.Header, error) {
	var lastErr error
	for attempt := 1; attempt <= d.retries(); attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("User-Agent", d.userAgent())
		if prev != nil {
			if prev.ETag != "" {
				req.Header.Set("If-None-Match", prev.ETag)
			} else if prev.Modified != "" {
				req.Header.Set("If-Modified-Since", prev.Modified)
			}
		}
		resp, err := d.client().Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			lastErr = err
		} else {
			body, retryable, err := readResponse(resp)
			if err == nil {
				return body, resp.Header, nil
			}
			lastErr = err
			if !retryable {
				return nil, nil, err
			}
		}
		if attempt == d.retries() {
			break
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(d.backoff(attempt)):
		}
	}
	return nil, nil, lastErr
}

// readResponse reads a response body, reporting whether a failure is worth
// retrying. A 304 is NotModified: (nil, false, nil) with no error.
func readResponse(resp *http.Response) (body []byte, retryable bool, err error) {
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return nil, false, nil
	case resp.StatusCode == http.StatusOK:
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		if err != nil {
			return nil, true, err
		}
		return b, false, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, true, &HTTPError{URL: resp.Request.URL.String(), StatusCode: resp.StatusCode}
	default:
		return nil, false, &HTTPError{URL: resp.Request.URL.String(), StatusCode: resp.StatusCode}
	}
}

// compile-time assertion.
var _ Database = (*HTTPDatabase)(nil)
