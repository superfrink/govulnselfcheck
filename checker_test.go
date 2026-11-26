package selfcheck

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/superfrink/govulnselfcheck/osv"
	"github.com/superfrink/govulnselfcheck/testdb"
)

// The examples use testdb, which lives in its own package: this keeps the
// library's own tests honest about the public surface.
func newChecker(t *testing.T, opts ...Option) *Checker {
	t.Helper()
	c, err := New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func scopeWith(t *testing.T, mods ...Module) Scope {
	t.Helper()
	// FromModules sorts and drops unjudgeable versions the same way a real
	// scope would.
	return FromModules(Module{Path: "example.com/main"}, mods, "go1.26.10")
}

func mustCheck(t *testing.T, c *Checker, s Scope) *Result {
	t.Helper()
	res, err := c.Check(context.Background(), s)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	return res
}

func TestCheckClean(t *testing.T) {
	db := testdb.New().Add(testdb.Vuln("GO-2026-0001", "example.com/mod", "0", "1.2.0"))
	c := newChecker(t, WithDatabase(db))
	res := mustCheck(t, c, scopeWith(t, Module{Path: "example.com/mod", Version: "v1.2.0"}))
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if !res.Clean() {
		t.Error("a clean result should be clean")
	}
	if got := res.DB.IndexModules; got != 1 {
		t.Errorf("index modules = %d", got)
	}
}

func TestCheckFindsAndOrders(t *testing.T) {
	db := testdb.New().Add(
		testdb.Vuln("GO-2026-0002", "example.com/b", "0", "2.0.0"),
		testdb.Vuln("GO-2026-0001", "example.com/a", "0", "1.5.0"),
	)
	c := newChecker(t, WithDatabase(db))
	res := mustCheck(t, c, scopeWith(t,
		Module{Path: "example.com/b", Version: "v1.0.0"},
		Module{Path: "example.com/a", Version: "v1.0.0"},
	))
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if res.Findings[0].Module != "example.com/a" || res.Findings[1].Module != "example.com/b" {
		t.Errorf("findings are not sorted by module: %+v", res.Findings)
	}
	f := res.Findings[0]
	if f.ID != "GO-2026-0001" || f.FixedAt != "1.5.0" || f.Version != "v1.0.0" || f.Status != StatusActionable {
		t.Errorf("finding = %+v", f)
	}
	if res.Findings[1].ID != "GO-2026-0002" {
		t.Errorf("second finding = %+v", res.Findings[1])
	}
	if got := res.Counts()[StatusActionable]; got != 2 {
		t.Errorf("actionable count = %d", got)
	}
	if res.Complete() {
		t.Error("a result with no package list should report that warning")
	}
}

func TestCheckSameAdvisoryTwoModules(t *testing.T) {
	// One entry, two modules: the second block names another module.
	e := testdb.Vuln("GO-2026-0001", "example.com/a", "0", "1.5.0")
	e.Affected = append(e.Affected, osv.Affected{
		Module: "example.com/b",
		Ranges: []osv.Range{{Type: "SEMVER", Events: []osv.Event{{Introduced: "0"}, {Fixed: "3.0.0"}}}},
	})
	db := testdb.New().Add(e)
	c := newChecker(t, WithDatabase(db))
	res := mustCheck(t, c, scopeWith(t,
		Module{Path: "example.com/a", Version: "v1.0.0"},
		Module{Path: "example.com/b", Version: "v2.0.0"},
	))
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if db.EntryCalls("GO-2026-0001") != 1 {
		t.Errorf("the entry was fetched %d times, want 1", db.EntryCalls("GO-2026-0001"))
	}
}

func TestCheckDeduplicates(t *testing.T) {
	// The same advisory listed twice for one module (the index can repeat).
	db := testdb.New().Add(testdb.Vuln("GO-2026-0001", "example.com/a", "0", "1.5.0"))
	c := newChecker(t, WithDatabase(db))
	res := mustCheck(t, c, scopeWith(t,
		Module{Path: "example.com/a", Version: "v1.0.0"},
		Module{Path: "example.com/a", Version: "v1.0.0"},
	))
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func TestCheckStdlib(t *testing.T) {
	db := testdb.New().Add(testdb.Vuln("GO-2026-0100", "stdlib", "0", "1.26.11"))
	c := newChecker(t, WithDatabase(db))
	res := mustCheck(t, c, scopeWith(t))
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	f := res.Findings[0]
	if f.Module != "stdlib" || f.Label() != "Go standard library" {
		t.Errorf("finding = %+v label %q", f, f.Label())
	}
	if f.FixedAt != "1.26.11" {
		t.Errorf("fixed at %q", f.FixedAt)
	}
}

func TestCheckUnlinkedPackage(t *testing.T) {
	db := testdb.New().Add(
		testdb.VulnPackages("GO-2026-0001", "example.com/mod", []string{"example.com/mod/openpgp"}, "0", "1.5.0"),
	)
	c := newChecker(t, WithDatabase(db))

	// Without a package list the finding stands: better a false alarm.
	res := mustCheck(t, c, scopeWith(t, Module{Path: "example.com/mod", Version: "v1.0.0"}))
	if len(res.Actionable()) != 1 {
		t.Fatalf("without a package list the finding should be actionable: %+v", res.Findings)
	}

	// With a package list that does not include the affected package, it is
	// reported separately and not actionable.
	s := scopeWith(t, Module{Path: "example.com/mod", Version: "v1.0.0"}).WithPackages([]string{"example.com/mod"})
	res = mustCheck(t, c, s)
	if len(res.Findings) != 1 || res.Findings[0].Status != StatusUnlinked {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if !res.Clean() {
		t.Error("an unlinked package is not actionable")
	}
	if res.Findings[0].Reason == "" {
		t.Error("a suppressed finding should say why")
	}

	// With the affected package linked, it is actionable again.
	s = scopeWith(t, Module{Path: "example.com/mod", Version: "v1.0.0"}).WithPackages([]string{"example.com/mod/openpgp"})
	res = mustCheck(t, c, s)
	if len(res.Actionable()) != 1 {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func TestCheckReplacedModule(t *testing.T) {
	db := testdb.New().Add(testdb.Vuln("GO-2026-0001", "example.com/new", "0", "2.4.0"))
	c := newChecker(t, WithDatabase(db))
	res := mustCheck(t, c, scopeWith(t, Module{
		Path:     "example.com/new",
		Version:  "v2.3.4",
		Original: &Module{Path: "example.com/old", Version: "v1.0.0"},
	}))
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	f := res.Findings[0]
	if f.Module != "example.com/new" || f.Version != "v2.3.4" {
		t.Errorf("judged the wrong module: %+v", f)
	}
	if f.Replaced != "example.com/old v1.0.0 -> example.com/new v2.3.4" {
		t.Errorf("replaced = %q", f.Replaced)
	}
}

func TestCheckIndexFailureIsAnError(t *testing.T) {
	db := testdb.New().FailIndex(testdb.ErrBoom)
	c := newChecker(t, WithDatabase(db))
	res, err := c.Check(context.Background(), scopeWith(t, Module{Path: "example.com/a", Version: "v1.0.0"}))
	if err == nil {
		t.Fatal("an unreachable index must be an error, not a clean result")
	}
	if res != nil {
		t.Error("a failed check should return no result")
	}
}

func TestCheckEntryFailureIsAWarning(t *testing.T) {
	db := testdb.New().
		Add(testdb.Vuln("GO-2026-0001", "example.com/a", "0", "1.5.0")).
		FailEntry("GO-2026-0001", testdb.ErrBoom)
	c := newChecker(t, WithDatabase(db))
	res := mustCheck(t, c, scopeWith(t, Module{Path: "example.com/a", Version: "v1.0.0"}))
	if len(res.Findings) != 1 {
		t.Fatalf("the index alone says this build is affected: %+v", res.Findings)
	}
	f := res.Findings[0]
	if f.FixedAt != "1.5.0" || !strings.Contains(f.Reason, "index alone") {
		t.Errorf("the fallback should say where it came from: %+v", f)
	}
	if !hasWarningKind(res, WarnEntryMissing) {
		t.Errorf("warnings = %v", res.Warnings)
	}
	if res.Complete() {
		t.Error("a degraded check is not complete")
	}
}

func TestCheckEntryFailureCannotLookClean(t *testing.T) {
	// An unfixed advisory: the index carries no fix to fall back on, so the
	// check cannot say anything about this module. That must be visible, and
	// must not be reported as a finding the caller can act on.
	db := testdb.New().
		Add(testdb.Vuln("GO-2026-0001", "example.com/a", "0", "")).
		FailEntry("GO-2026-0001", testdb.ErrBoom)
	c := newChecker(t, WithDatabase(db))
	res := mustCheck(t, c, scopeWith(t, Module{Path: "example.com/a", Version: "v1.0.0"}))
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v", res.Findings)
	}
	if !hasWarningKind(res, WarnEntryMissing) {
		t.Error("an unchecked module must produce a warning")
	}
	if res.Clean() && res.Complete() {
		t.Error("a result that could not be checked must not look both clean and complete")
	}
}

func TestCheckMissingEntryIsNotAWarning(t *testing.T) {
	// A withdrawn advisory: the index still lists it, the entry is gone. That
	// is normal and needs no warning.
	db := testdb.New().Add(testdb.Vuln("GO-2026-0001", "example.com/a", "0", "1.5.0"))
	db.FailEntry("GO-2026-0001", testdb.ErrNotFound("GO-2026-0001"))
	c := newChecker(t, WithDatabase(db))
	res := mustCheck(t, c, scopeWith(t, Module{Path: "example.com/a", Version: "v1.0.0"}))
	if hasWarningKind(res, WarnEntryMissing) {
		t.Errorf("a withdrawn advisory is not a degraded check: %v", res.Warnings)
	}
}

func TestCheckContextCancelled(t *testing.T) {
	db := testdb.New().Add(testdb.Vuln("GO-2026-0001", "example.com/a", "0", "1.5.0"))
	c := newChecker(t, WithDatabase(db))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Check(ctx, scopeWith(t, Module{Path: "example.com/a", Version: "v1.0.0"})); err == nil {
		t.Fatal("a cancelled context must be an error")
	}
}

func TestCheckTimeout(t *testing.T) {
	slow := &blockingDB{release: make(chan struct{})}
	defer close(slow.release)
	c := newChecker(t, WithDatabase(slow), WithTimeout(20*time.Millisecond))
	start := time.Now()
	if _, err := c.Check(context.Background(), scopeWith(t, Module{Path: "example.com/a", Version: "v1.0.0"})); err == nil {
		t.Fatal("a check that cannot finish must time out")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("took %v", elapsed)
	}
}

func TestCheckNoModules(t *testing.T) {
	c := newChecker(t, WithDatabase(testdb.New()))
	res := mustCheck(t, c, Scope{})
	if len(res.Findings) != 0 || res.Clean() == false {
		t.Fatalf("empty scope = %+v", res)
	}
}

func TestCheckConcurrentSafe(t *testing.T) {
	db := testdb.New().Add(
		testdb.Vuln("GO-2026-0001", "example.com/a", "0", "1.5.0"),
		testdb.Vuln("GO-2026-0002", "example.com/b", "0", "1.5.0"),
	)
	c := newChecker(t, WithDatabase(db), WithConcurrency(2))
	s := scopeWith(t,
		Module{Path: "example.com/a", Version: "v1.0.0"},
		Module{Path: "example.com/b", Version: "v1.0.0"},
	)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := c.Check(context.Background(), s)
			if err != nil {
				t.Error(err)
				return
			}
			if len(res.Findings) != 2 {
				t.Errorf("findings = %+v", res.Findings)
			}
		}()
	}
	wg.Wait()
}

func TestCheckInvalidIndexID(t *testing.T) {
	// A malicious or corrupted index must not be able to steer a fetch.
	c := newChecker(t, WithDatabase(&badIndexDB{}))
	res := mustCheck(t, c, scopeWith(t, Module{Path: "example.com/a", Version: "v1.0.0"}))
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v", res.Findings)
	}
	if !hasWarningKind(res, WarnEntryMissing) {
		t.Errorf("warnings = %v", res.Warnings)
	}
	if res.DB.EntriesFetched != 0 {
		t.Errorf("entries fetched = %d", res.DB.EntriesFetched)
	}
}

func TestCheckFallbackRespectsFixedVersion(t *testing.T) {
	// The index fallback only fires when the version is genuinely before the
	// fix it names.
	db := testdb.New().
		Add(testdb.Vuln("GO-2026-0001", "example.com/a", "0", "1.5.0")).
		FailEntry("GO-2026-0001", testdb.ErrBoom)
	c := newChecker(t, WithDatabase(db))
	res := mustCheck(t, c, scopeWith(t, Module{Path: "example.com/a", Version: "v1.5.0"}))
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v", res.Findings)
	}
	res = mustCheck(t, c, scopeWith(t, Module{Path: "example.com/a", Version: "not-a-version"}))
	if len(res.Findings) != 0 {
		t.Errorf("an unparsable version must not be judged by the fallback: %+v", res.Findings)
	}
}

func hasWarningKind(r *Result, kind WarningKind) bool {
	for _, w := range r.Warnings {
		if w.Kind == kind {
			return true
		}
	}
	return false
}

// blockingDB never answers.
type blockingDB struct{ release chan struct{} }

func (b *blockingDB) Index(ctx context.Context) (*Index, error) {
	select {
	case <-b.release:
		return &Index{Modules: map[string][]Ref{}}, nil
	case <-ctx.Done():
		return nil, errors.Join(ctx.Err())
	}
}

func (b *blockingDB) Entry(ctx context.Context, id string) (*osv.Entry, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// badIndexDB returns an index naming an advisory whose ID is a path segment.
type badIndexDB struct{}

func (badIndexDB) Index(ctx context.Context) (*Index, error) {
	return &Index{Modules: map[string][]Ref{
		"example.com/a": {{ID: "../../evil", Fixed: "1.0.0"}},
	}}, nil
}

func (badIndexDB) Entry(ctx context.Context, id string) (*osv.Entry, error) {
	return nil, errors.New("should never be called")
}
