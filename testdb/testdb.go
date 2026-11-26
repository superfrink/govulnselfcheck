// Package testdb is an in-memory vulnerability database for tests.
//
// It exists so that code using govulnselfcheck can test its own wiring —
// metric names, log lines, alert thresholds — without a network call, a
// fixture file, or a real advisory. Build entries with Vuln, Add them, and pass
// the value to selfcheck.WithDatabase.
//
//	db := testdb.New()
//	db.Add(testdb.Vuln("GO-2026-0001", "example.com/mod", "0", "1.2.0"))
//	c, _ := selfcheck.New(selfcheck.WithDatabase(db))
package testdb

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/superfrink/govulnselfcheck/osv"
)

// DB is an in-memory Database. The zero value is not usable; use New.
type DB struct {
	mu      sync.Mutex
	entries map[string]*osv.Entry
	failIdx error
	failEnt map[string]error
	// counts for assertions about how hard a check leant on the database
	indexCalls int
	entryCalls map[string]int
}

// New returns an empty database.
func New() *DB {
	return &DB{entries: map[string]*osv.Entry{}, entryCalls: map[string]int{}}
}

// Add stores entries, replacing any with the same ID. The index is derived from
// the entries, so there is one source of truth to keep straight.
func (d *DB) Add(entries ...*osv.Entry) *DB {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range entries {
		if e == nil || e.ID == "" {
			continue
		}
		d.entries[e.ID] = e
	}
	return d
}

// FailIndex makes Index return err.
func (d *DB) FailIndex(err error) *DB {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failIdx = err
	return d
}

// FailEntry makes Entry return err for one GO ID. An error of nil clears it.
func (d *DB) FailEntry(id string, err error) *DB {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failEnt == nil {
		d.failEnt = map[string]error{}
	}
	if err == nil {
		delete(d.failEnt, id)
		return d
	}
	d.failEnt[id] = err
	return d
}

// IndexCalls reports how many times Index was called.
func (d *DB) IndexCalls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.indexCalls
}

// EntryCalls reports how many times the entry for id was requested, including
// failures.
func (d *DB) EntryCalls(id string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.entryCalls[id]
}

// Index implements osv.Database.
func (d *DB) Index(ctx context.Context) (*osv.Index, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.indexCalls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.failIdx != nil {
		return nil, d.failIdx
	}
	ix := &osv.Index{Modules: map[string][]osv.Ref{}, ETag: "testdb"}
	for _, e := range d.entries {
		for _, a := range e.Affected {
			path := a.Module
			if path == "" && len(a.Imports) > 0 {
				path = a.Imports[0]
			}
			if path == "" {
				continue
			}
			ix.Modules[path] = append(ix.Modules[path], osv.Ref{
				ID:    e.ID,
				Fixed: firstFix(a.Ranges),
			})
		}
	}
	return ix, nil
}

// Entry implements osv.Database.
func (d *DB) Entry(ctx context.Context, goID string) (*osv.Entry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.entryCalls == nil {
		d.entryCalls = map[string]int{}
	}
	d.entryCalls[goID]++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err, ok := d.failEnt[goID]; ok {
		return nil, err
	}
	e, ok := d.entries[goID]
	if !ok {
		return nil, ErrNotFound(goID)
	}
	return e, nil
}

// NotFoundError is returned for a GO ID that was never added. A check
// recognises it through NotFound below, the same contract a real database's 404
// satisfies.
type NotFoundError struct{ ID string }

func (e *NotFoundError) Error() string { return "testdb: no entry " + e.ID }

// NotFound reports that the advisory does not exist.
func (e *NotFoundError) NotFound() bool { return true }

// ErrNotFound reports an advisory missing from the fake database.
func ErrNotFound(id string) error { return &NotFoundError{ID: id} }

// Len reports how many advisories the database holds.
func (d *DB) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.entries)
}

// Vuln builds an advisory affecting module across [introduced, fixed). An
// introduced of "0" means every release before the fix. An empty fixed means
// the range is still open.
func Vuln(id, module, introduced, fixed string) *osv.Entry {
	events := []osv.Event{{Introduced: introduced}}
	if fixed != "" {
		events[0].Introduced = introduced
		events = append(events, osv.Event{Fixed: fixed})
	}
	return &osv.Entry{
		ID:      id,
		Summary: fmt.Sprintf("%s in %s", id, module),
		Affected: []osv.Affected{{
			Module:  module,
			Imports: []string{module},
			Ranges:  []osv.Range{{Type: "SEMVER", Events: events}},
		}},
	}
}

// VulnPackages is Vuln with an explicit list of affected import paths, for
// exercising package-level filtering.
func VulnPackages(id, module string, imports []string, introduced, fixed string) *osv.Entry {
	e := Vuln(id, module, introduced, fixed)
	e.Affected[0].Imports = imports
	return e
}

// VulnUnfiltered is Vuln with no import paths at all: an advisory that cannot
// be narrowed to a package, so it always applies to the module.
func VulnUnfiltered(id, module, introduced, fixed string) *osv.Entry {
	e := Vuln(id, module, introduced, fixed)
	e.Affected[0].Imports = nil
	return e
}

// ErrBoom is a ready-made failure for tests that need a database that does not
// answer.
var ErrBoom = errors.New("testdb: database unavailable")

func firstFix(ranges []osv.Range) string {
	for _, r := range ranges {
		for _, e := range r.Events {
			if e.Fixed != "" {
				return e.Fixed
			}
		}
	}
	return ""
}
