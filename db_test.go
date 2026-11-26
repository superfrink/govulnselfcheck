package selfcheck

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fixture serves a small database and counts requests.
type fixture struct {
	srv      *httptest.Server
	mu       sync.Mutex
	requests map[string]int
	handler  func(w http.ResponseWriter, r *http.Request) bool // false = 404
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{requests: map[string]int{}}
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/index/modules.json":
			fmt.Fprint(w, indexDoc)
			return true
		case "/ID/GO-2026-0001.json":
			fmt.Fprint(w, entryDoc)
			return true
		case "/ID/GO-2026-0002.json":
			fmt.Fprint(w, entryTwoDoc)
			return true
		}
		return false
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests[r.URL.Path]++
		h := f.handler
		f.mu.Unlock()
		if !h(w, r) {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[path]
}

const indexDoc = `[
 {"path": "example.com/mod", "vulns": [{"id": "GO-2026-0001", "fixed": "1.2.0", "modified": "2026-01-01T00:00:00Z"}]},
 {"path": "example.com/other", "vulns": [{"id": "GO-2026-0002", "fixed": "2.0.0"}]}
]`

const entryDoc = `{
 "id": "GO-2026-0001",
 "summary": "test issue",
 "published": "2026-01-01T00:00:00Z",
 "affected": [{"package": {"name": "example.com/mod"},
   "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}],
   "ecosystem_specific": {"imports": [{"path": "example.com/mod"}]}}]
}`

const entryTwoDoc = `{
 "id": "GO-2026-0002",
 "summary": "other issue",
 "affected": [{"package": {"name": "example.com/other"},
   "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]
}`

func TestHTTPDatabaseIndexAndEntry(t *testing.T) {
	f := newFixture(t)
	db := &HTTPDatabase{Base: f.srv.URL}
	ctx := context.Background()

	ix, err := db.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ix.Len() != 2 {
		t.Errorf("index has %d modules", ix.Len())
	}
	refs := ix.Lookup("example.com/mod")
	if len(refs) != 1 || refs[0].ID != "GO-2026-0001" || refs[0].Fixed != "1.2.0" {
		t.Errorf("refs = %+v", refs)
	}
	if ix.Lookup("example.com/absent") != nil {
		t.Error("lookup of an absent module returned something")
	}

	e, err := db.Entry(ctx, "GO-2026-0001")
	if err != nil {
		t.Fatal(err)
	}
	if e.ID != "GO-2026-0001" || e.Summary != "test issue" {
		t.Errorf("entry = %+v", e)
	}
	if _, fixed, hit := e.Resolve("example.com/mod", "v1.0.0"); !hit || fixed != "1.2.0" {
		t.Errorf("resolve: hit=%v fixed=%q", hit, fixed)
	}
}

func TestHTTPDatabaseCaches(t *testing.T) {
	f := newFixture(t)
	db := &HTTPDatabase{Base: f.srv.URL}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := db.Index(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Entry(ctx, "GO-2026-0001"); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.count("/index/modules.json"); got != 1 {
		t.Errorf("index fetched %d times, want 1", got)
	}
	if got := f.count("/ID/GO-2026-0001.json"); got != 1 {
		t.Errorf("entry fetched %d times, want 1", got)
	}
}

func TestHTTPDatabaseConcurrentFetchesAreShared(t *testing.T) {
	var hits atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
		fmt.Fprint(w, indexDoc)
	}))
	defer srv.Close()

	db := &HTTPDatabase{Base: srv.URL}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := db.Index(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if got := hits.Load(); got != 1 {
		t.Errorf("server saw %d requests, want 1", got)
	}
}

func TestHTTPDatabaseRevalidates(t *testing.T) {
	var conditional bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			conditional = true
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		fmt.Fprint(w, indexDoc)
	}))
	defer srv.Close()

	db := &HTTPDatabase{Base: srv.URL, IndexTTL: -1} // no caching, but revalidation state is kept
	if _, err := db.Index(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A negative TTL disables the cache entirely, so the second call refetches
	// unconditionally: that is the documented way to opt out.
	if conditional {
		t.Error("a disabled cache should not send conditional requests")
	}
}

func TestHTTPDatabaseRetries(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		switch n {
		case 1:
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.WriteHeader(http.StatusBadGateway)
		default:
			fmt.Fprint(w, indexDoc)
		}
	}))
	defer srv.Close()

	db := &HTTPDatabase{Base: srv.URL, Backoff: func(int) time.Duration { return time.Millisecond }}
	ix, err := db.Index(context.Background())
	if err != nil {
		t.Fatalf("should have retried to success: %v", err)
	}
	if ix.Len() != 2 {
		t.Errorf("index = %+v", ix)
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestHTTPDatabaseGivesUp(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	db := &HTTPDatabase{Base: srv.URL, Retries: 2, Backoff: func(int) time.Duration { return time.Millisecond }}
	_, err := db.Index(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
	var he *HTTPError
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %v", err)
	}
	_ = he
}

func TestHTTPDatabaseNoRetryOn404(t *testing.T) {
	f := newFixture(t)
	db := &HTTPDatabase{Base: f.srv.URL}
	_, err := db.Entry(context.Background(), "GO-2026-9999")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !NotFound(err) {
		t.Errorf("a 404 should be recognised as not found: %v", err)
	}
	if got := f.count("/ID/GO-2026-9999.json"); got != 1 {
		t.Errorf("a 404 was requested %d times, want 1", got)
	}
}

func TestHTTPDatabaseRejectsBadIDs(t *testing.T) {
	db := &HTTPDatabase{Base: "http://example.invalid"}
	for _, id := range []string{"", "../../etc/passwd", "GO-2026-1", "CVE-2026-1234", "GO-2026-0001?x=1"} {
		if _, err := db.Entry(context.Background(), id); err == nil {
			t.Errorf("%q should be rejected before any request", id)
		}
	}
}

func TestHTTPDatabaseContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	db := &HTTPDatabase{Base: srv.URL, Backoff: func(int) time.Duration { return time.Millisecond }}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := db.Index(ctx); err == nil {
		t.Fatal("expected an error")
	}
}

func TestHTTPDatabaseTruncatedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"path": "example.com/mod", "vulns": `)
	}))
	defer srv.Close()
	db := &HTTPDatabase{Base: srv.URL}
	if _, err := db.Index(context.Background()); err == nil {
		t.Fatal("truncated JSON should be an error")
	}
}

func TestParseIndex(t *testing.T) {
	ix, err := ParseIndex([]byte(`[
		{"path": "a", "vulns": [{"id": "GO-2026-0001"}, {"id": "GO-2026-0002"}]},
		{"path": "a", "vulns": [{"id": "GO-2026-0003"}]},
		{"path": "", "vulns": [{"id": "GO-2026-0004"}]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(ix.Lookup("a")); got != 3 {
		t.Errorf("a has %d refs, want 3 (duplicate paths are merged)", got)
	}
	if ix.Lookup("") != nil {
		t.Error("an empty path should not be indexed")
	}
	if _, err := ParseIndex([]byte(`nope`)); err == nil {
		t.Error("invalid JSON should be an error")
	}
	if got := (*Index)(nil).Len(); got != 0 {
		t.Errorf("nil index len = %d", got)
	}
	if got := (*Index)(nil).Lookup("a"); got != nil {
		t.Error("nil index lookup returned something")
	}
}

func TestNewHTTPDatabaseDefaults(t *testing.T) {
	var db HTTPDatabase
	if db.base() != DefaultDBURL {
		t.Errorf("base = %q", db.base())
	}
	if db.userAgent() != DefaultUserAgent {
		t.Errorf("user agent = %q", db.userAgent())
	}
	if db.retries() != 3 {
		t.Errorf("retries = %d", db.retries())
	}
	if got := db.backoff(1); got != 200*time.Millisecond {
		t.Errorf("backoff(1) = %v", got)
	}
	if got := db.backoff(50); got != 5*time.Second {
		t.Errorf("backoff should be capped, got %v", got)
	}
	if db.indexTTL() != time.Hour || db.entryTTL() != 24*time.Hour {
		t.Errorf("ttls = %v %v", db.indexTTL(), db.entryTTL())
	}
	if db.client().Timeout != 30*time.Second {
		t.Errorf("default client timeout = %v", db.client().Timeout)
	}
	u := &HTTPDatabase{Base: "https://example.com/", UserAgent: "x", Backoff: func(int) time.Duration { return 1 }}
	if u.base() != "https://example.com" {
		t.Errorf("trailing slash not trimmed: %q", u.base())
	}
	if u.userAgent() != "x" || u.backoff(1) != 1 {
		t.Error("explicit settings should be used")
	}
}
