package selfcheck

import (
	"testing"

	"github.com/superfrink/govulnselfcheck/osv"
)

func result(findings ...Finding) *Result {
	return &Result{Findings: findings}
}

func find(id, module, version string, s Status) Finding {
	return Finding{ID: id, Module: module, Version: version, Status: s}
}

func TestCounts(t *testing.T) {
	r := result(
		find("GO-2026-0001", "a", "v1", StatusActionable),
		find("GO-2026-0002", "a", "v1", StatusPending),
		find("GO-2026-0003", "b", "v1", StatusUnlinked),
	)
	c := r.Counts()
	if c[StatusActionable] != 1 || c[StatusPending] != 1 || c[StatusUnlinked] != 1 {
		t.Fatalf("counts = %v", c)
	}
	// Every status is present, so a metrics loop never has to check.
	if _, ok := c[StatusIgnored]; !ok {
		t.Error("zero counts should still be present")
	}
	if got := len(result().Counts()); got != 4 {
		t.Errorf("an empty result has %d statuses", got)
	}
}

func TestActionableAndClean(t *testing.T) {
	r := result(find("GO-2026-0001", "a", "v1", StatusPending), find("GO-2026-0002", "b", "v1", StatusUnlinked))
	if !r.Clean() {
		t.Error("pending and unlinked are not actionable")
	}
	if r.Actionable() != nil {
		t.Error("no actionable findings were expected")
	}
	r.Findings = append(r.Findings, find("GO-2026-0003", "c", "v1", StatusActionable))
	if r.Clean() {
		t.Error("an actionable finding is not clean")
	}
	if got := r.Actionable(); len(got) != 1 || got[0].Module != "c" {
		t.Errorf("actionable = %+v", got)
	}
	if !result().Clean() {
		t.Error("an empty result is clean")
	}
}

func TestFingerprintStability(t *testing.T) {
	a := result(
		find("GO-2026-0001", "a", "v1", StatusActionable),
		find("GO-2026-0002", "b", "v1", StatusIgnored),
	)
	b := result(
		find("GO-2026-0002", "b", "v1", StatusIgnored),
		find("GO-2026-0001", "a", "v1", StatusActionable),
	)
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("finding order must not change the fingerprint")
	}
	if a.Fingerprint() == result().Fingerprint() {
		t.Error("an empty result must differ from a result with findings")
	}
	c := result(find("GO-2026-0001", "a", "v1", StatusPending))
	if a.Fingerprint() == c.Fingerprint() {
		t.Error("a status change must change the fingerprint")
	}
	d := result(find("GO-2026-0001", "a", "v2", StatusActionable))
	if a.Fingerprint() == d.Fingerprint() {
		t.Error("a version change must change the fingerprint")
	}
	if len(a.Fingerprint()) != 64 {
		t.Errorf("fingerprint = %q", a.Fingerprint())
	}
}

func TestDiff(t *testing.T) {
	prev := result(
		find("GO-2026-0001", "a", "v1", StatusActionable),
		find("GO-2026-0002", "b", "v1", StatusPending),
		find("GO-2026-0003", "c", "v1", StatusActionable),
	)
	cur := result(
		find("GO-2026-0002", "b", "v1", StatusActionable),
		find("GO-2026-0003", "c", "v1", StatusActionable),
		find("GO-2026-0004", "d", "v1", StatusActionable),
	)
	c := cur.Diff(prev)
	if len(c.Added) != 1 || c.Added[0].ID != "GO-2026-0004" {
		t.Errorf("added = %+v", c.Added)
	}
	if len(c.Cleared) != 1 || c.Cleared[0].ID != "GO-2026-0001" {
		t.Errorf("cleared = %+v", c.Cleared)
	}
	if len(c.Changed) != 1 || c.Changed[0].Finding.ID != "GO-2026-0002" || c.Changed[0].From != StatusPending {
		t.Errorf("changed = %+v", c.Changed)
	}
	if c.Empty() {
		t.Error("a diff with changes is not empty")
	}

	if got := cur.Diff(nil); len(got.Added) != 3 || len(got.Cleared) != 0 {
		t.Errorf("nil previous: %+v", got)
	}
	if got := cur.Diff(cur); !got.Empty() {
		t.Errorf("a result diffed against itself should be empty: %+v", got)
	}
	if !(Changes{}).Empty() {
		t.Error("zero changes should be empty")
	}
}

func TestFindingHelpers(t *testing.T) {
	f := Finding{ID: "GO-2026-0001", Module: osv.StdlibModule, Summary: "x"}
	if got := f.Label(); got != "Go standard library" {
		t.Errorf("label = %q", got)
	}
	if got := (Finding{Module: "example.com/a"}).Label(); got != "example.com/a" {
		t.Errorf("label = %q", got)
	}
	if got := f.Topic(); got != "x" {
		t.Errorf("topic = %q", got)
	}
	if got := (Finding{ID: "GO-2026-0002"}).Topic(); got != "GO-2026-0002" {
		t.Errorf("topic = %q", got)
	}
}

func TestWarningString(t *testing.T) {
	tests := []struct {
		w    Warning
		want string
	}{
		{Warning{Kind: WarnNoToolchain}, "no-toolchain"},
		{Warning{Kind: WarnEntryMissing, ID: "GO-2026-0001"}, "entry-missing GO-2026-0001"},
		{Warning{Kind: WarnUnjudged, Module: "example.com/a"}, "unjudged example.com/a"},
		{Warning{Kind: WarnEntryMissing, ID: "GO-2026-0001", Module: "example.com/a", Detail: "why"}, "entry-missing GO-2026-0001 example.com/a: why"},
	}
	for _, tt := range tests {
		if got := tt.w.String(); got != tt.want {
			t.Errorf("String() = %q, want %q", got, tt.want)
		}
	}
}

func TestFindingsEqual(t *testing.T) {
	a := []Finding{{ID: "1", Module: "m", Packages: []string{"p"}}}
	b := []Finding{{ID: "1", Module: "m", Packages: []string{"p"}}}
	if !findingsEqual(a, b) {
		t.Error("identical findings differ")
	}
	b[0].Packages = []string{"q"}
	if findingsEqual(a, b) {
		t.Error("different packages compare equal")
	}
	if findingsEqual(a, nil) {
		t.Error("different lengths compare equal")
	}
	b = []Finding{{ID: "1", Module: "m", Packages: []string{"p"}, Status: StatusIgnored}}
	if findingsEqual(a, b) {
		t.Error("different statuses compare equal")
	}
	b = []Finding{{ID: "1", Module: "m", Packages: []string{"p"}, Reason: "x"}}
	if findingsEqual(a, b) {
		t.Error("different reasons compare equal")
	}
}

func TestComplete(t *testing.T) {
	if !result().Complete() {
		t.Error("no warnings means complete")
	}
	r := result()
	r.Warnings = []Warning{{Kind: WarnNoPackages}}
	if r.Complete() {
		t.Error("a warning means not complete")
	}
}
