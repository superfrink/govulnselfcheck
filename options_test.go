package selfcheck

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/superfrink/govulnselfcheck/testdb"
)

func TestOptionValidation(t *testing.T) {
	tests := map[string]Option{
		"nil database":   WithDatabase(nil),
		"nil client":     WithHTTPClient(nil),
		"zero timeout":   WithTimeout(0),
		"negative time":  WithTimeout(-time.Second),
		"zero width":     WithConcurrency(0),
		"negative grace": WithGracePeriod(-time.Second),
		"nil clock":      WithClock(nil),
		"zero interval":  WithInterval(0),
		"jitter > 1":     WithJitter(1.5),
		"jitter < 0":     WithJitter(-0.1),
		"ignore no id":   WithIgnores(Ignore{Module: "m", Reason: "r"}),
		"ignore no why":  WithIgnores(Ignore{ID: "GO-2026-0001", Module: "m"}),
	}
	for name, opt := range tests {
		if _, err := New(opt); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestOptionDefaults(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if c.cfg.timeout != 2*time.Minute || c.cfg.concurrency != 4 || c.cfg.interval != 24*time.Hour {
		t.Errorf("defaults = %+v", c.cfg)
	}
	if _, ok := c.cfg.db.(*HTTPDatabase); !ok {
		t.Errorf("default database = %T", c.cfg.db)
	}
	if c.cfg.logger != nil {
		t.Error("the library should not log unless asked")
	}
}

func TestWithHTTPClientReachesDefaultDatabase(t *testing.T) {
	hc := &http.Client{}
	c, err := New(WithHTTPClient(hc))
	if err != nil {
		t.Fatal(err)
	}
	db := c.cfg.db.(*HTTPDatabase)
	if db.Client != hc {
		t.Error("the client did not reach the default database")
	}

	// A database of another kind is left alone.
	tc, err := New(WithDatabase(testdb.New()), WithHTTPClient(hc))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tc.cfg.db.(*testdb.DB); !ok {
		t.Errorf("database = %T", tc.cfg.db)
	}
}

func TestWithIgnoreFile(t *testing.T) {
	c, err := New(WithIgnoreFile(strings.NewReader("GO-2026-0001 example.com/a - a reason\n")))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.cfg.ignores) != 1 || c.cfg.ignores[0].ID != "GO-2026-0001" {
		t.Errorf("ignores = %+v", c.cfg.ignores)
	}
	if _, err := New(WithIgnoreFile(strings.NewReader("garbage\n"))); err == nil {
		t.Error("a broken ignore file should fail construction, not the check")
	}
}

func TestWithPackagesOverridesScope(t *testing.T) {
	db := testdb.New().Add(testdb.VulnPackages("GO-2026-0001", "example.com/a", []string{"example.com/a/x"}, "0", "1.5.0"))
	c, err := New(WithDatabase(db), WithPackages([]string{"example.com/a"}))
	if err != nil {
		t.Fatal(err)
	}
	s := scopeWith(t, Module{Path: "example.com/a", Version: "v1.0.0"}).WithPackages([]string{"example.com/a/x"})
	res := mustCheck(t, c, s)
	// The option wins: the scope's own list said the package was linked, the
	// option says it is not.
	if res.Findings[0].Status != StatusUnlinked {
		t.Errorf("status = %s", res.Findings[0].Status)
	}
	if res.Scope.Packages[0] != "example.com/a" {
		t.Errorf("scope packages = %v", res.Scope.Packages)
	}
}

func TestWithLoggerDoesNotChangeTheResult(t *testing.T) {
	db := testdb.New().Add(testdb.Vuln("GO-2026-0001", "example.com/a", "0", "1.5.0"))
	quiet, err := New(WithDatabase(db))
	if err != nil {
		t.Fatal(err)
	}
	loud, err := New(WithDatabase(db), WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err != nil {
		t.Fatal(err)
	}
	s := scopeWith(t, Module{Path: "example.com/a", Version: "v1.0.0"})
	if a, b := mustCheck(t, quiet, s), mustCheck(t, loud, s); a.Fingerprint() != b.Fingerprint() {
		t.Error("logging should not change what is found")
	}
}
