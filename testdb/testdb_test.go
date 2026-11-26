package testdb

import (
	"context"
	"testing"

	"github.com/superfrink/govulnselfcheck"
	"github.com/superfrink/govulnselfcheck/osv"
)

func TestIndexFromEntries(t *testing.T) {
	db := New().Add(
		Vuln("GO-2026-0001", "example.com/a", "0", "1.2.0"),
		Vuln("GO-2026-0002", "example.com/b", "1.0.0", ""),
	)
	ix, err := db.Index(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ix.Len() != 2 {
		t.Fatalf("len = %d", ix.Len())
	}
	refs := ix.Lookup("example.com/a")
	if len(refs) != 1 || refs[0].ID != "GO-2026-0001" || refs[0].Fixed != "1.2.0" {
		t.Errorf("refs = %+v", refs)
	}
	// An unfixed advisory has no fixed version to offer.
	if got := ix.Lookup("example.com/b")[0].Fixed; got != "" {
		t.Errorf("fixed = %q", got)
	}
}

func TestEntryLookup(t *testing.T) {
	db := New().Add(Vuln("GO-2026-0001", "example.com/a", "0", "1.2.0"))
	e, err := db.Entry(context.Background(), "GO-2026-0001")
	if err != nil {
		t.Fatal(err)
	}
	if e.ID != "GO-2026-0001" {
		t.Errorf("entry = %+v", e)
	}
	_, err = db.Entry(context.Background(), "GO-2026-9999")
	if !selfcheck.NotFound(err) {
		t.Errorf("a missing entry should be not-found, got %v", err)
	}
	if db.EntryCalls("GO-2026-0001") != 1 {
		t.Error("entry calls not counted")
	}
}

func TestFailures(t *testing.T) {
	db := New().Add(Vuln("GO-2026-0001", "example.com/a", "0", "1.2.0"))
	db.FailIndex(ErrBoom)
	if _, err := db.Index(context.Background()); err != ErrBoom {
		t.Errorf("index error = %v", err)
	}
	db.FailIndex(nil)

	db.FailEntry("GO-2026-0001", ErrBoom)
	if _, err := db.Entry(context.Background(), "GO-2026-0001"); err != ErrBoom {
		t.Errorf("entry error = %v", err)
	}
	db.FailEntry("GO-2026-0001", nil)
	if _, err := db.Entry(context.Background(), "GO-2026-0001"); err != nil {
		t.Errorf("entry after clearing the failure = %v", err)
	}
}

func TestContextCancelled(t *testing.T) {
	db := New().Add(Vuln("GO-2026-0001", "example.com/a", "0", "1.2.0"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := db.Index(ctx); err == nil {
		t.Error("Index should honour the context")
	}
	if _, err := db.Entry(ctx, "GO-2026-0001"); err == nil {
		t.Error("Entry should honour the context")
	}
}

func TestVulnBuilders(t *testing.T) {
	e := Vuln("GO-2026-0001", "example.com/a", "1.0.0", "1.2.0")
	if e.ID == "" || e.Summary == "" || len(e.Affected) != 1 {
		t.Fatalf("bad entry: %+v", e)
	}
	if ev := e.Affected[0].Ranges[0].Events; len(ev) != 2 || ev[0].Introduced != "1.0.0" || ev[1].Fixed != "1.2.0" {
		t.Errorf("events = %+v", ev)
	}

	unfixed := Vuln("GO-2026-0002", "example.com/a", "0", "")
	if ev := unfixed.Affected[0].Ranges[0].Events; len(ev) != 1 {
		t.Errorf("an unfixed advisory should have one open event, got %+v", ev)
	}

	pkgs := VulnPackages("GO-2026-0003", "example.com/a", []string{"example.com/a/x"}, "0", "1.0.0")
	if pkgs.Affected[0].Imports[0] != "example.com/a/x" {
		t.Errorf("imports = %v", pkgs.Affected[0].Imports)
	}

	raw := VulnUnfiltered("GO-2026-0004", "example.com/a", "0", "1.0.0")
	if raw.Affected[0].Imports != nil {
		t.Errorf("imports = %v, want none", raw.Affected[0].Imports)
	}
	if _, _, hit := raw.Resolve("example.com/a", "v0.1.0"); !hit {
		t.Error("an unfiltered advisory should still resolve")
	}
}

// The fake must satisfy the interface the library expects: a change to that
// interface that this package does not follow fails to compile here.
func TestImplementsDatabase(t *testing.T) {
	var _ selfcheck.Database = New()
	_ = osv.StdlibModule
}
