package osv

import "testing"

func ev(intro, fixed, last string) Event {
	return Event{Introduced: intro, Fixed: fixed, LastAffected: last}
}

func semverRange(events ...Event) Range {
	return Range{Type: "SEMVER", Events: events}
}

func TestVersionAffected(t *testing.T) {
	tests := []struct {
		name    string
		version string
		ranges  []Range
		want    bool
		fixed   string
	}{
		{
			name:    "before fix",
			version: "v1.0.0",
			ranges:  []Range{semverRange(ev("0", "1.1.0", ""))},
			want:    true,
			fixed:   "1.1.0",
		},
		{
			name:    "at fix",
			version: "v1.1.0",
			ranges:  []Range{semverRange(ev("0", "1.1.0", ""))},
		},
		{
			name:    "after fix",
			version: "v1.2.0",
			ranges:  []Range{semverRange(ev("0", "1.1.0", ""))},
		},
		{
			name:    "before introduced",
			version: "v1.0.0",
			ranges:  []Range{semverRange(ev("1.1.0", "1.2.0", ""))},
		},
		{
			name:    "at introduced",
			version: "v1.1.0",
			ranges:  []Range{semverRange(ev("1.1.0", "1.2.0", ""))},
			want:    true,
			fixed:   "1.2.0",
		},
		{
			name:    "reintroduced after a fix",
			version: "v1.84.0",
			ranges:  []Range{semverRange(ev("0", "1.82.2", ""), ev("1.83.0", "1.85.0", ""))},
			want:    true,
			fixed:   "1.85.0",
		},
		{
			name:    "still fixed between the two windows",
			version: "v1.82.5",
			ranges:  []Range{semverRange(ev("0", "1.82.2", ""), ev("1.83.0", "1.85.0", ""))},
		},
		{
			name:    "open ended trailing introduced",
			version: "v2.0.0",
			ranges:  []Range{semverRange(ev("0", "1.0.0", ""), ev("2.0.0", "", ""))},
			want:    true,
		},
		{
			name:    "trailing introduced, version below it",
			version: "v1.5.0",
			ranges:  []Range{semverRange(ev("0", "1.0.0", ""), ev("2.0.0", "", ""))},
		},
		{
			name:    "bare fixed implies open start",
			version: "v0.1.0",
			ranges:  []Range{semverRange(ev("", "1.0.0", ""))},
			want:    true,
			fixed:   "1.0.0",
		},
		{
			name:    "last_affected closes inclusively",
			version: "v1.2.3",
			ranges:  []Range{semverRange(ev("1.0.0", "", "1.2.3"))},
			want:    true,
		},
		{
			name:    "after last_affected",
			version: "v1.2.4",
			ranges:  []Range{semverRange(ev("1.0.0", "", "1.2.3"))},
		},
		{
			name:    "incompatible suffix judged on its core",
			version: "v2.0.0+incompatible",
			ranges:  []Range{semverRange(ev("0", "2.1.0", ""))},
			want:    true,
			fixed:   "2.1.0",
		},
		{
			name:    "invalid version",
			version: "(devel)",
			ranges:  []Range{semverRange(ev("0", "1.0.0", ""))},
		},
		{
			name:    "non semver range type ignored",
			version: "v1.0.0",
			ranges:  []Range{{Type: "ECOSYSTEM", Events: []Event{ev("0", "1.1.0", "")}}},
		},
		{
			name:    "second range matches",
			version: "v9.0.0",
			ranges: []Range{
				{Type: "GIT", Events: []Event{ev("0", "1.0.0", "")}},
				semverRange(ev("0", "9.0.1", "")),
			},
			want:  true,
			fixed: "9.0.1",
		},
		{
			name:    "no events",
			version: "v1.0.0",
			ranges:  []Range{semverRange()},
		},
		{
			name:    "empty ranges",
			version: "v1.0.0",
		},
		{
			name:    "prerelease below fix",
			version: "v1.26.10-rc1",
			ranges:  []Range{semverRange(ev("0", "1.26.10", ""))},
			want:    true,
			fixed:   "1.26.10",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixed, got := VersionAffected(tt.version, tt.ranges)
			if got != tt.want {
				t.Fatalf("affected = %v, want %v", got, tt.want)
			}
			if fixed != tt.fixed {
				t.Fatalf("fixed = %q, want %q", fixed, tt.fixed)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	// Two blocks cover the same module (one names a package inside it, one
	// names the module). The first block whose range matches decides; when
	// its range no longer matches, the next one is tried.
	entry := &Entry{
		ID: "GO-2026-0001",
		Affected: []Affected{
			{Module: "example.com/other", Ranges: []Range{semverRange(ev("0", "2.0.0", ""))}},
			{Module: "example.com/mod/sub", Ranges: []Range{semverRange(ev("0", "1.2.0", ""))}},
			{Module: "example.com/mod", Ranges: []Range{semverRange(ev("0", "1.5.0", ""))}},
		},
	}
	a, fixed, hit := entry.Resolve("example.com/mod", "v1.1.0")
	if !hit {
		t.Fatal("expected a match")
	}
	if a.Module != "example.com/mod/sub" || fixed != "1.2.0" {
		t.Fatalf("first matching block should win: got module %q fixed %q", a.Module, fixed)
	}
	// Past the first block's fix, the block naming the module decides.
	if _, fixed, hit := entry.Resolve("example.com/mod", "v1.3.0"); !hit || fixed != "1.5.0" {
		t.Fatalf("second block should decide: hit=%v fixed=%q", hit, fixed)
	}
	// Past every fix there is nothing.
	if _, _, hit := entry.Resolve("example.com/mod", "v1.6.0"); hit {
		t.Fatal("matched above every fix")
	}
	// A prefix that is not a path boundary must not match.
	if _, _, hit := entry.Resolve("example.com/mo", "v1.1.0"); hit {
		t.Fatal("prefix without a path boundary matched")
	}
	// A nested module is a different module, even under an affected path:
	// its versions have nothing to do with the parent's.
	if _, _, hit := entry.Resolve("example.com/mod/sub/deeper", "v1.1.0"); hit {
		t.Fatal("a nested module matched its parent's block")
	}
	if _, _, hit := entry.Resolve("example.com/unknown", "v1.0.0"); hit {
		t.Fatal("unrelated module matched")
	}
	// A module with no block of its own is not covered by another's.
	if _, _, hit := entry.Resolve("example.com/oth", "v1.0.0"); hit {
		t.Fatal("sibling prefix matched")
	}
}

func TestCoversModule(t *testing.T) {
	tests := []struct {
		affected, module string
		want             bool
	}{
		{"example.com/a", "example.com/a", true},
		{"example.com/a/pkg", "example.com/a", true},
		{"example.com/ab", "example.com/a", false},
		{"example.com/a", "", false},
		{"", "example.com/a", false},
	}
	for _, tt := range tests {
		if got := CoversModule(tt.affected, tt.module); got != tt.want {
			t.Errorf("CoversModule(%q, %q) = %v, want %v", tt.affected, tt.module, got, tt.want)
		}
	}
}

func TestStdlibVersion(t *testing.T) {
	tests := []struct{ in, want string }{
		{"go1.26.10", "1.26.10"},
		{"go1.26.2 X:strictfipsruntime", "1.26.2"},
		{"go1.22", "1.22"},
		{"devel go1.27-7f2a1c", ""},
		{"devel go1.26.2", ""},
		{"devel +abc123", ""},
		{"", ""},
		{"go", ""},
		{"  go1.26.10  ", "1.26.10"},
		{"1.26.10", "1.26.10"},
	}
	for _, tt := range tests {
		if got := StdlibVersion(tt.in); got != tt.want {
			t.Errorf("StdlibVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLinked(t *testing.T) {
	linked := map[string]bool{
		"example.com/mod":            true,
		"example.com/mod/sub/pkg":    true,
		"example.com/other/nested/x": true,
	}
	tests := []struct {
		name    string
		imports []string
		want    bool
	}{
		{"no imports means unfilterable", nil, true},
		{"exact package", []string{"example.com/mod"}, true},
		{"linked package inside affected package", []string{"example.com/mod/sub"}, true},
		{"not linked", []string{"example.com/mod/absent"}, false},
		{"one of several linked", []string{"example.com/mod/absent", "example.com/mod"}, true},
		{"prefix without boundary", []string{"example.com/mo"}, false},
	}
	for _, tt := range tests {
		if got := Linked(tt.imports, linked); got != tt.want {
			t.Errorf("%s: Linked = %v, want %v", tt.name, got, tt.want)
		}
	}
	if got := Linked([]string{"example.com/mod"}, nil); got {
		t.Error("no linked packages should mean nothing is linked")
	}
}

func TestVPrefixed(t *testing.T) {
	for in, want := range map[string]string{"1.2.3": "v1.2.3", "v1.2.3": "v1.2.3", "": "v"} {
		if got := VPrefixed(in); got != want {
			t.Errorf("VPrefixed(%q) = %q, want %q", in, got, want)
		}
	}
}
