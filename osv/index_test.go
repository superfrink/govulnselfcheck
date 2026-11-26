package osv

import "testing"

func TestParseIndex(t *testing.T) {
	ix, err := ParseIndex([]byte(`[
		{"path": "a", "vulns": [{"id": "GO-2026-0001", "fixed": "1.0.0"}]},
		{"path": "a", "vulns": [{"id": "GO-2026-0002"}]},
		{"path": "", "vulns": [{"id": "GO-2026-0003"}]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if ix.Len() != 1 {
		t.Errorf("len = %d, want 1 (duplicate paths merge, empty paths are dropped)", ix.Len())
	}
	refs := ix.Lookup("a")
	if len(refs) != 2 || refs[0].Fixed != "1.0.0" {
		t.Errorf("refs = %+v", refs)
	}
	if ix.Lookup("absent") != nil {
		t.Error("lookup of an absent module returned something")
	}
	if _, err := ParseIndex([]byte(`nope`)); err == nil {
		t.Error("invalid JSON should be an error")
	}
	// An empty document is not an index: the database always writes a JSON
	// array, even for zero modules.
	if _, err := ParseIndex(nil); err == nil {
		t.Error("an empty document should not parse as an index")
	}
	empty, err := ParseIndex([]byte(`[]`))
	if err != nil || empty.Len() != 0 {
		t.Errorf("an empty array should parse to an empty index: %v %d", err, empty.Len())
	}
}

func TestNilIndex(t *testing.T) {
	var ix *Index
	if ix.Len() != 0 {
		t.Errorf("nil len = %d", ix.Len())
	}
	if ix.Lookup("a") != nil {
		t.Error("nil lookup returned something")
	}
	empty := &Index{}
	if empty.Lookup("a") != nil {
		t.Error("a nil map lookup returned something")
	}
}
