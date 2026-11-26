package osv

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAffectedUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		module  string
		imports []string
		ranges  int
		symbols map[string]int
	}{
		{
			name: "current layout: package plus ecosystem_specific imports",
			json: `{
				"package": {"name": "golang.org/x/crypto/openpgp", "ecosystem": "Go"},
				"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.10.0"}]}],
				"ecosystem_specific": {"imports": [{"path": "golang.org/x/crypto/openpgp", "symbols": ["Encrypt"]}]}
			}`,
			module:  "golang.org/x/crypto/openpgp",
			imports: []string{"golang.org/x/crypto/openpgp"},
			ranges:  1,
			symbols: map[string]int{"golang.org/x/crypto/openpgp": 1},
		},
		{
			name:   "older layout: module as a string",
			json:   `{"module": "example.com/mod", "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]}`,
			module: "example.com/mod",
			ranges: 1,
		},
		{
			name:   "older layout: module as an object",
			json:   `{"module": {"path": "example.com/mod", "goos": ["linux"]}, "ranges": []}`,
			module: "example.com/mod",
		},
		{
			name:   "module null falls back to the package name",
			json:   `{"module": null, "package": {"name": "example.com/mod/pkg"}, "ranges": []}`,
			module: "example.com/mod/pkg",
			ranges: 0,
		},
		{
			name: "top level imports are merged and deduplicated",
			json: `{"package": {"name": "example.com/mod"},
				"imports": ["example.com/mod/a", " example.com/mod/b ", ""],
				"ecosystem_specific": {"imports": [{"path": "example.com/mod/a"}, {"path": "example.com/mod/c"}]}}`,
			module:  "example.com/mod",
			imports: []string{"example.com/mod/a", "example.com/mod/b", "example.com/mod/c"},
		},
		{
			name:   "unknown fields are ignored",
			json:   `{"package": {"name": "example.com/mod"}, "database_specific": {"url": "x"}, "ranges": []}`,
			module: "example.com/mod",
			ranges: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a Affected
			if err := json.Unmarshal([]byte(tt.json), &a); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if a.Module != tt.module {
				t.Errorf("module = %q, want %q", a.Module, tt.module)
			}
			if tt.imports != nil {
				if len(a.Imports) != len(tt.imports) {
					t.Fatalf("imports = %v, want %v", a.Imports, tt.imports)
				}
				for i := range tt.imports {
					if a.Imports[i] != tt.imports[i] {
						t.Errorf("imports[%d] = %q, want %q", i, a.Imports[i], tt.imports[i])
					}
				}
			}
			if len(a.Ranges) != tt.ranges {
				t.Errorf("ranges = %d, want %d", len(a.Ranges), tt.ranges)
			}
			for path, n := range tt.symbols {
				if len(a.Symbols[path]) != n {
					t.Errorf("symbols[%q] = %v, want %d", path, a.Symbols[path], n)
				}
			}
		})
	}
}

func TestAffectedUnmarshalErrors(t *testing.T) {
	for _, in := range []string{`[]`, `"x"`, `{"ranges": "nope"}`, `{"module": 42}`, `{`} {
		var a Affected
		if err := json.Unmarshal([]byte(in), &a); err == nil && in != `{"module": 42}` {
			t.Errorf("%s: expected an error", in)
		}
	}
}

// A real entry, trimmed to the fields this library reads, must parse and
// resolve end to end: the adversarial-sounding shapes above are not the only
// thing that has to work.
func TestEntryEndToEnd(t *testing.T) {
	const doc = `{
		"schema_version": "1.3.1",
		"id": "GO-2023-1987",
		"modified": "2023-08-22T19:33:27Z",
		"published": "2023-08-11T17:06:34Z",
		"aliases": ["CVE-2023-39325"],
		"summary": "HTTP/2 rapid reset can cause excessive work in net/http",
		"details": "A malicious HTTP/2 client...",
		"affected": [{
			"package": {"name": "stdlib", "ecosystem": "Go"},
			"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.20.10"}]}],
			"ecosystem_specific": {"imports": [{"path": "net/http", "symbols": ["Server.Serve"]}]}
		}],
		"references": [{"type": "FIX", "url": "https://go.dev/cl/532355"}],
		"credits": [{"name": "someone"}],
		"database_specific": {"url": "https://pkg.go.dev/vuln/GO-2023-1987"}
	}`
	var e Entry
	if err := json.Unmarshal([]byte(doc), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.ID != "GO-2023-1987" || e.Summary == "" || len(e.Affected) != 1 {
		t.Fatalf("bad entry: %+v", e)
	}
	if got := e.Published.Time.UTC().Format(time.RFC3339); got != "2023-08-11T17:06:34Z" {
		t.Errorf("published = %s", got)
	}
	if len(e.References) != 1 || e.References[0].Type != "FIX" {
		t.Errorf("references = %+v", e.References)
	}
	a, fixed, hit := e.Resolve(StdlibModule, "v1.20.9")
	if !hit || fixed != "1.20.10" {
		t.Fatalf("resolve: hit=%v fixed=%q", hit, fixed)
	}
	if !Linked(a.Imports, map[string]bool{"net/http": true}) {
		t.Error("net/http should be linked")
	}
	if Linked(a.Imports, map[string]bool{"net/url": true}) {
		t.Error("net/url is not affected")
	}
}

func TestTime(t *testing.T) {
	tests := []struct {
		in      string
		wantSet bool
		want    string
	}{
		{`"2026-01-02T03:04:05Z"`, true, "2026-01-02T03:04:05Z"},
		{`"2026-01-02T03:04:05.123456789Z"`, true, "2026-01-02T03:04:05Z"},
		{`"2026-01-02"`, true, "2026-01-02T00:00:00Z"},
		{`""`, false, ""},
		{`null`, false, ""},
		{`"not a time"`, false, ""},
		{`123`, false, ""},
	}
	for _, tt := range tests {
		var got Time
		if err := json.Unmarshal([]byte(tt.in), &got); err != nil {
			t.Fatalf("%s: %v", tt.in, err)
		}
		if got.IsZero() == tt.wantSet {
			t.Fatalf("%s: zero = %v, want set = %v", tt.in, got.IsZero(), tt.wantSet)
		}
		if tt.wantSet && got.UTC().Format(time.RFC3339) != tt.want {
			t.Errorf("%s: got %s", tt.in, got.UTC().Format(time.RFC3339))
		}
	}
}

func TestTimeMarshal(t *testing.T) {
	if b, _ := json.Marshal(Time{}); string(b) != "null" {
		t.Errorf("zero time marshalled as %s", b)
	}
	tm := Time{time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)}
	b, err := json.Marshal(tm)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"2026-05-06T07:08:09Z"` {
		t.Errorf("got %s", b)
	}
}

func TestValidateID(t *testing.T) {
	valid := []string{"GO-2026-5932", "GO-2023-1987", "GO-0000-0000"}
	invalid := []string{
		"", "GO-2026-593", "GO-2026-59321", "GO-26-5932", "go-2026-5932",
		"CVE-2026-5932", "GO-2026/5932", "GO-2026-59a2", "../GO-2026-5932",
		"GO-2026-5932?x=1",
	}
	for _, s := range valid {
		if !ValidateID(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range invalid {
		if ValidateID(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}
