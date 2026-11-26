package selfcheck

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/superfrink/govulnselfcheck/osv"
	"github.com/superfrink/govulnselfcheck/testdb"
)

func TestEveryChecksImmediately(t *testing.T) {
	db := testdb.New().Add(testdb.Vuln("GO-2026-0001", "example.com/a", "0", "1.5.0"))
	c, err := New(WithDatabase(db), WithInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan *Result, 1)
	go func() {
		_ = c.Every(ctx, scopeWith(t, Module{Path: "example.com/a", Version: "v1.0.0"}), func(r *Result) { got <- r })
	}()

	select {
	case r := <-got:
		if len(r.Actionable()) != 1 {
			t.Errorf("actionable = %d", len(r.Actionable()))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no check ran immediately: a process should not wait an interval to learn its first answer")
	}
}

func TestEveryStopsOnCancel(t *testing.T) {
	db := testdb.New()
	c, err := New(WithDatabase(db), WithInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Every(ctx, scopeWith(t), func(*Result) {}) }()

	// Let the first check run, then stop it.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("cancellation should return nil, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Every did not stop when the context was cancelled")
	}
}

func TestEveryAcceptsDoneContext(t *testing.T) {
	c, err := New(WithDatabase(testdb.New()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Every(ctx, scopeWith(t), nil); err == nil {
		t.Error("a context that is already done should be reported, not ignored")
	}
}

func TestEveryRepeats(t *testing.T) {
	db := testdb.New()
	c, err := New(WithDatabase(db), WithInterval(10*time.Millisecond), WithJitter(0))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	n := 0
	go func() {
		_ = c.Every(ctx, scopeWith(t), func(*Result) {
			mu.Lock()
			n++
			mu.Unlock()
		})
	}()
	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		got := n
		mu.Unlock()
		if got >= 3 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("only %d checks ran", got)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestEverySurvivesADatabaseOutage(t *testing.T) {
	db := testdb.New()
	c, err := New(WithDatabase(db), WithInterval(time.Hour), WithJitter(0))
	if err != nil {
		t.Fatal(err)
	}
	var errs []error
	c.cfg.onError = func(e error) { errs = append(errs, e) }

	// An expired context is a shutdown, not a failure, and must not be
	// reported: otherwise every clean exit looks like an error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.runOnce(ctx, scopeWith(t), func(*Result) { t.Error("handler ran on a cancelled check") })
	if len(errs) != 0 {
		t.Errorf("cancellation reported as an error: %v", errs)
	}
}

func TestEveryReportsUndeliverableOutcome(t *testing.T) {
	failing := &failingDB{err: errors.New("database unavailable")}
	c, err := New(WithDatabase(failing), WithInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var got error
	c.cfg.onError = func(e error) { got = e }

	c.runOnce(context.Background(), scopeWith(t), func(*Result) { t.Error("handler ran without a result") })
	if got == nil {
		t.Fatal("an unreachable database was swallowed: the loop would look healthy while checking nothing")
	}

	// And the loop keeps going: the next run must still happen.
	var calls atomic.Int64
	db := testdb.New()
	c2, err := New(WithDatabase(&flakyDB{db: db, fails: 1}), WithInterval(10*time.Millisecond), WithJitter(0))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = c2.Every(ctx, scopeWith(t), func(*Result) { calls.Add(1) })
	}()
	deadline := time.After(2 * time.Second)
	for {
		if calls.Load() > 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("the loop stopped after one failure")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestEveryRecoversFromHandlerPanic(t *testing.T) {
	c, err := New(WithDatabase(testdb.New()), WithInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var got error
	c.cfg.onError = func(e error) { got = e }

	// A handler that panics must not take the process down, and must not stop
	// the loop.
	c.runOnce(context.Background(), scopeWith(t), func(*Result) { panic("boom") })
	if got == nil {
		t.Fatal("a panicking handler was not reported")
	}
	c.runOnce(context.Background(), scopeWith(t), func(*Result) {})
}

func TestNextIntervalJitter(t *testing.T) {
	c, err := New(WithDatabase(testdb.New()), WithInterval(time.Hour), WithJitter(0.2))
	if err != nil {
		t.Fatal(err)
	}
	lo, hi := time.Hour*8/10, time.Hour*12/10
	for i := 0; i < 500; i++ {
		if d := c.nextInterval(); d < lo || d > hi {
			t.Fatalf("interval %v outside ±20%% of an hour", d)
		}
	}
	noJitter, err := New(WithDatabase(testdb.New()), WithInterval(time.Hour), WithJitter(0))
	if err != nil {
		t.Fatal(err)
	}
	if d := noJitter.nextInterval(); d != time.Hour {
		t.Errorf("without jitter the interval should be exact, got %v", d)
	}
	// A tiny interval with wide jitter must not produce a busy loop.
	tiny, err := New(WithDatabase(testdb.New()), WithInterval(time.Millisecond), WithJitter(1))
	if err != nil {
		t.Fatal(err)
	}
	if d := tiny.nextInterval(); d < time.Second {
		t.Errorf("interval = %v, want at least a second", d)
	}
}

// failingDB always fails its index.
type failingDB struct{ err error }

func (d *failingDB) Index(context.Context) (*Index, error) { return nil, d.err }
func (d *failingDB) Entry(context.Context, string) (*osv.Entry, error) {
	return nil, d.err
}

// flakyDB fails a number of times, then behaves.
type flakyDB struct {
	db    *testdb.DB
	fails int
	mu    sync.Mutex
}

func (d *flakyDB) Index(ctx context.Context) (*Index, error) {
	d.mu.Lock()
	if d.fails > 0 {
		d.fails--
		d.mu.Unlock()
		return nil, errors.New("database unavailable")
	}
	d.mu.Unlock()
	return d.db.Index(ctx)
}

func (d *flakyDB) Entry(ctx context.Context, id string) (*osv.Entry, error) {
	return d.db.Entry(ctx, id)
}
