package report

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/superfrink/govulnselfcheck"
	"github.com/superfrink/govulnselfcheck/osv"
)

var update = flag.Bool("update", false, "rewrite golden files")

func fixTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// sample is a result with every status represented, plus a warning, so the
// golden output exercises each section.
func sample() *selfcheck.Result {
	return &selfcheck.Result{
		Target: selfcheck.Target{
			Name:       "fixture-tags",
			Commit:     "4f2a9c1",
			CommitTime: "2026-11-25T21:40:00Z",
			Extra:      map[string]string{"main": "github.com/superfrink/fixture-tags", "platform": "linux/amd64"},
		},
		Scope: selfcheck.Scope{
			Toolchain: "go1.26.11",
			Modules: []selfcheck.Module{
				{Path: "example.com/a", Version: "v1.0.0"},
				{Path: "example.com/b", Version: "v2.1.0", Original: &selfcheck.Module{Path: "example.com/b", Version: "v2.0.0"}},
			},
		},
		Checked: fixTime("2026-11-25T23:05:00Z"),
		DB:      selfcheck.DatabaseInfo{IndexModules: 41209, EntriesFetched: 3},
		Findings: []selfcheck.Finding{
			{
				ID: "GO-2026-0001", Summary: "Panic in Decode", Module: "example.com/a", Version: "v1.0.0",
				FixedAt: "v1.5.0", Published: osv.Time{Time: fixTime("2026-11-01T00:00:00Z")},
				Packages: []string{"example.com/a/x"}, Status: selfcheck.StatusActionable,
			},
			{
				ID: "GO-2026-0002", Summary: "Denial of service", Module: "example.com/b", Version: "v2.1.0",
				Replaced: "v2.0.0 -> v2.1.0", FixedAt: "v2.2.0",
				Status: selfcheck.StatusPending, Reason: "within grace period until 2026-11-08",
			},
			{
				ID: "GO-2026-0003", Summary: "Weak randomness", Module: "example.com/a", Version: "v1.0.0",
				FixedAt: "v1.4.0", Status: selfcheck.StatusIgnored,
				Reason: "accepted: no crypto use in this service", Expires: osv.Time{Time: fixTime("2027-02-01T00:00:00Z")},
			},
			{
				ID: "GO-2026-0004", Summary: "Unused parser bug", Module: "example.com/a", Version: "v1.0.0",
				FixedAt: "v1.2.0", Status: selfcheck.StatusUnlinked,
				Reason: "affected package example.com/a/parser is not linked into this binary",
			},
			{
				ID: "GO-2026-0005", Summary: "Fix-less advisory", Module: "example.com/a", Version: "v1.0.0",
				Status: selfcheck.StatusActionable,
			},
		},
		Warnings: []selfcheck.Warning{
			{Kind: selfcheck.WarnEntryMissing, Module: "example.com/a", ID: "GO-2025-9999", Detail: "using the module index alone"},
		},
	}
}

func TestTextGolden(t *testing.T) {
	got := TextWith(sample(), How("at startup"))
	golden := filepath.Join("testdata", "report.txt")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if got != string(want) {
		t.Errorf("rendering changed.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestTextIsStable(t *testing.T) {
	a, b := Text(sample()), Text(sample())
	if a != b {
		t.Error("the same result rendered differently twice")
	}
	// Reordering the findings must not change the output: the check sorts, and
	// rendering must not depend on the order it happens to receive.
	r := sample()
	r.Findings[0], r.Findings[4] = r.Findings[4], r.Findings[0]
	if Text(r) != a {
		t.Error("rendering depends on the order of findings")
	}
}

func TestTextClean(t *testing.T) {
	r := &selfcheck.Result{Target: selfcheck.Target{Name: "x"}, Checked: fixTime("2026-11-25T23:05:00Z")}
	out := Text(r)
	if !strings.Contains(out, "No actionable vulnerabilities found in x") {
		t.Errorf("clean output = %q", out)
	}
}

func TestTextAll(t *testing.T) {
	full := TextWith(sample(), All())
	// The pending finding is not listed by default but is with All.
	if strings.Contains(Text(sample()), "GO-2026-0002  example.com/b v2.1.0") {
		t.Error("a pending finding was listed without All")
	}
	if !strings.Contains(full, "GO-2026-0002") || !strings.Contains(full, "GO-2026-0004") {
		t.Errorf("All did not list everything:\n%s", full)
	}
}

func TestTextNotCountedSummary(t *testing.T) {
	out := Text(sample())
	if !strings.Contains(out, "-- Not counted (1 pending, 1 ignored, 1 unlinked) --") {
		t.Errorf("missing not-counted header:\n%s", out)
	}
	// Silence about a waived advisory reads as an all-clear, so the reason must
	// be printed.
	if !strings.Contains(out, "accepted: no crypto use in this service") {
		t.Error("ignore reason missing")
	}
	// A clean result with suppressed findings still says so.
	r := &selfcheck.Result{
		Target:  selfcheck.Target{Name: "x"},
		Checked: fixTime("2026-11-25T23:05:00Z"),
		Findings: []selfcheck.Finding{{
			ID: "GO-2026-0003", Module: "example.com/a", Version: "v1.0.0",
			Status: selfcheck.StatusIgnored, Reason: "accepted",
		}},
	}
	out = Text(r)
	if !strings.Contains(out, "No actionable vulnerabilities") || !strings.Contains(out, "1 ignored") {
		t.Errorf("clean-with-ignored output:\n%s", out)
	}
}

func TestTextWarnings(t *testing.T) {
	out := Text(sample())
	if !strings.Contains(out, "-- Incomplete (1) --") || !strings.Contains(out, "GO-2025-9999") {
		t.Errorf("warning section missing:\n%s", out)
	}
	// A clean but incomplete result must not claim more than it checked.
	r := &selfcheck.Result{
		Target:  selfcheck.Target{Name: "x"},
		Checked: fixTime("2026-11-25T23:05:00Z"),
		Warnings: []selfcheck.Warning{{
			Kind: selfcheck.WarnNoToolchain, Detail: "standard library advisories were not checked",
		}},
	}
	if out := Text(r); !strings.Contains(out, "-- Incomplete (1) --") {
		t.Errorf("incomplete clean result hid its warning:\n%s", out)
	}
}

func TestTextNoFixAndReplacement(t *testing.T) {
	out := TextWith(sample(), All())
	if !strings.Contains(out, "no fix published") {
		t.Error("a finding without a fix should say so")
	}
	if !strings.Contains(out, "replaced: v2.0.0 -> v2.1.0") {
		t.Error("a replacement should be visible")
	}
}

func TestSubject(t *testing.T) {
	tests := []struct {
		names []string
		want  string
	}{
		{nil, "x: no actionable Go vulnerabilities"},
		{[]string{"GO-1"}, "x: 1 actionable Go vulnerability"},
		{[]string{"GO-1", "GO-2"}, "x: 2 actionable Go vulnerabilities"},
	}
	for _, tt := range tests {
		r := &selfcheck.Result{Target: selfcheck.Target{Name: "x"}}
		for _, id := range tt.names {
			r.Findings = append(r.Findings, selfcheck.Finding{ID: id, Module: "m", Status: selfcheck.StatusActionable})
		}
		if got := Subject(r); got != tt.want {
			t.Errorf("Subject = %q, want %q", got, tt.want)
		}
	}
}

func TestTextUnknowns(t *testing.T) {
	// A result assembled by hand, or from an old stored document, may be
	// missing the pieces a check normally fills in.
	out := Text(&selfcheck.Result{})
	if !strings.Contains(out, "build") || !strings.Contains(out, "unknown") {
		t.Errorf("unknowns not handled:\n%s", out)
	}
	if Subject(&selfcheck.Result{}) == "" {
		t.Error("empty subject")
	}
}
