package selfcheck

import (
	"strings"
	"testing"
	"time"

	"github.com/superfrink/govulnselfcheck/osv"
	"github.com/superfrink/govulnselfcheck/testdb"
)

// pub sets an advisory's publication date, which the grace period measures.
func pub(e *osv.Entry, t time.Time) *osv.Entry {
	e.Published = osv.Time{Time: t}
	return e
}

var now = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func checkAt(t *testing.T, c *Checker, s Scope) *Result {
	t.Helper()
	res := mustCheck(t, c, s)
	return res
}

func TestGracePeriod(t *testing.T) {
	day := 24 * time.Hour
	entry := func(published time.Time) *testdb.DB {
		return testdb.New().Add(pub(testdb.Vuln("GO-2026-0001", "example.com/a", "0", "1.5.0"), published))
	}
	s := scopeWith(t, Module{Path: "example.com/a", Version: "v1.0.0"})

	t.Run("inside the window", func(t *testing.T) {
		c := newChecker(t, WithDatabase(entry(now.Add(-2*day))), WithGracePeriod(7*day), WithClock(func() time.Time { return now }))
		res := checkAt(t, c, s)
		if len(res.Findings) != 1 || res.Findings[0].Status != StatusPending {
			t.Fatalf("findings = %+v", res.Findings)
		}
		if !res.Clean() {
			t.Error("a pending finding is not actionable")
		}
		if !strings.Contains(res.Findings[0].Reason, "grace period") {
			t.Errorf("reason = %q", res.Findings[0].Reason)
		}
	})

	t.Run("outside the window", func(t *testing.T) {
		c := newChecker(t, WithDatabase(entry(now.Add(-10*day))), WithGracePeriod(7*day), WithClock(func() time.Time { return now }))
		res := checkAt(t, c, s)
		if len(res.Findings) != 1 || res.Findings[0].Status != StatusActionable {
			t.Fatalf("findings = %+v", res.Findings)
		}
	})

	t.Run("exactly at the boundary", func(t *testing.T) {
		// At published+grace the finding is out of grace: the window is
		// half-open, so an advisory is never pending forever by a rounding
		// the caller cannot see.
		c := newChecker(t, WithDatabase(entry(now.Add(-7*day))), WithGracePeriod(7*day), WithClock(func() time.Time { return now }))
		res := checkAt(t, c, s)
		if res.Findings[0].Status != StatusActionable {
			t.Errorf("status = %s, want actionable at the boundary", res.Findings[0].Status)
		}
	})

	t.Run("no publication date", func(t *testing.T) {
		// An entry with no publication date cannot be aged, so it is not
		// deferred: grace is a courtesy, not a hole.
		db := testdb.New().Add(testdb.Vuln("GO-2026-0001", "example.com/a", "0", "1.5.0"))
		c := newChecker(t, WithDatabase(db), WithGracePeriod(7*day), WithClock(func() time.Time { return now }))
		res := checkAt(t, c, s)
		if res.Findings[0].Status != StatusActionable {
			t.Errorf("status = %s", res.Findings[0].Status)
		}
	})

	t.Run("no grace configured", func(t *testing.T) {
		c := newChecker(t, WithDatabase(entry(now)), WithClock(func() time.Time { return now }))
		res := checkAt(t, c, s)
		if res.Findings[0].Status != StatusActionable {
			t.Errorf("status = %s", res.Findings[0].Status)
		}
	})
}

func TestGraceChangesFingerprint(t *testing.T) {
	// The whole point of including the status in the fingerprint: a caller
	// that was quiet while a finding was pending is told when it becomes
	// actionable, without being told again every day afterwards.
	db := testdb.New().Add(pub(testdb.Vuln("GO-2026-0001", "example.com/a", "0", "1.5.0"), now.Add(-24*time.Hour)))
	s := scopeWith(t, Module{Path: "example.com/a", Version: "v1.0.0"})
	clock := now
	c := newChecker(t, WithDatabase(db), WithGracePeriod(7*24*time.Hour), WithClock(func() time.Time { return clock }))

	early := checkAt(t, c, s)
	if early.Findings[0].Status != StatusPending {
		t.Fatalf("status = %s", early.Findings[0].Status)
	}
	clock = now.Add(8 * 24 * time.Hour)
	late := checkAt(t, c, s)
	if late.Findings[0].Status != StatusActionable {
		t.Fatalf("status = %s", late.Findings[0].Status)
	}
	if early.Fingerprint() == late.Fingerprint() {
		t.Error("leaving the grace period must change the fingerprint")
	}
	// Two checks at the same point in time agree.
	if got, want := checkAt(t, c, s).Fingerprint(), late.Fingerprint(); got != want {
		t.Error("the same state should fingerprint the same")
	}
}

func TestIgnores(t *testing.T) {
	db := testdb.New().Add(testdb.Vuln("GO-2026-0001", "example.com/a", "0", "1.5.0"))
	s := scopeWith(t, Module{Path: "example.com/a", Version: "v1.0.0"})

	t.Run("matching module", func(t *testing.T) {
		c := newChecker(t, WithDatabase(db), WithClock(func() time.Time { return now }),
			WithIgnores(Ignore{ID: "GO-2026-0001", Module: "example.com/a", Reason: "not reachable", Expires: now.Add(24 * time.Hour)}))
		res := checkAt(t, c, s)
		f := res.Findings[0]
		if f.Status != StatusIgnored {
			t.Fatalf("status = %s", f.Status)
		}
		if !strings.Contains(f.Reason, "not reachable") {
			t.Errorf("reason = %q", f.Reason)
		}
		if f.Expires.IsZero() {
			t.Error("an ignored finding should carry its expiry")
		}
		if !res.Clean() {
			t.Error("an ignored finding is not actionable")
		}
	})

	t.Run("wrong module", func(t *testing.T) {
		c := newChecker(t, WithDatabase(db), WithClock(func() time.Time { return now }),
			WithIgnores(Ignore{ID: "GO-2026-0001", Module: "example.com/other", Reason: "x"}))
		if got := checkAt(t, c, s).Findings[0].Status; got != StatusActionable {
			t.Errorf("status = %s", got)
		}
	})

	t.Run("wildcard module", func(t *testing.T) {
		c := newChecker(t, WithDatabase(db), WithClock(func() time.Time { return now }),
			WithIgnores(Ignore{ID: "GO-2026-0001", Module: "*", Reason: "x"}))
		if got := checkAt(t, c, s).Findings[0].Status; got != StatusIgnored {
			t.Errorf("status = %s", got)
		}
	})

	t.Run("expired", func(t *testing.T) {
		c := newChecker(t, WithDatabase(db), WithClock(func() time.Time { return now }),
			WithIgnores(Ignore{ID: "GO-2026-0001", Module: "example.com/a", Reason: "x", Expires: now.Add(-time.Hour)}))
		res := checkAt(t, c, s)
		if got := res.Findings[0].Status; got != StatusActionable {
			t.Errorf("an expired ignore must not apply: status = %s", got)
		}
		if !hasWarningKind(res, WarnIgnoreExpired) {
			t.Errorf("an expired ignore should be reported: %v", res.Warnings)
		}
	})

	t.Run("no reason", func(t *testing.T) {
		if _, err := New(WithIgnores(Ignore{ID: "GO-2026-0001"})); err == nil {
			t.Error("an ignore with no reason should be rejected")
		}
	})
}

func TestStatusPrecedence(t *testing.T) {
	// Unlinked outranks ignored: an ignore exists because a caller has the
	// vulnerable package and accepted it, and saying the package is not linked
	// is the more verifiable statement.
	db := testdb.New().Add(
		pub(testdb.VulnPackages("GO-2026-0001", "example.com/a", []string{"example.com/a/gone"}, "0", "1.5.0"), now.Add(-90*24*time.Hour)),
	)
	c := newChecker(t, WithDatabase(db),
		WithGracePeriod(24*time.Hour),
		WithClock(func() time.Time { return now }),
		WithIgnores(Ignore{ID: "GO-2026-0001", Module: "example.com/a", Reason: "accepted"}))
	s := scopeWith(t, Module{Path: "example.com/a", Version: "v1.0.0"}).WithPackages([]string{"example.com/a"})
	res := checkAt(t, c, s)
	if got := res.Findings[0].Status; got != StatusUnlinked {
		t.Errorf("status = %s, want unlinked", got)
	}
}

func TestParseIgnores(t *testing.T) {
	const doc = `
# GO-ID      module                  expires     reason
GO-2026-5932 golang.org/x/crypto     2027-03-01  only used for signing; dropping in Q2
GO-2026-6859 -                       -           pinned toolchain, upgrade in Q2

GO-2026-1234 example.com/a           *           a reason with * inside
`
	// "*" in the expires column is not a date; that line must fail.
	if _, err := ParseIgnores(strings.NewReader(doc)); err == nil {
		t.Fatal("expected an error for a non-date expiry")
	}

	igs, err := ParseIgnores(strings.NewReader(`
# comment
GO-2026-5932 golang.org/x/crypto 2027-03-01 only used for signing; dropping in Q2
GO-2026-6859 - - pinned toolchain, upgrade in Q2
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(igs) != 2 {
		t.Fatalf("ignores = %+v", igs)
	}
	if igs[0].ID != "GO-2026-5932" || igs[0].Module != "golang.org/x/crypto" ||
		!igs[0].Expires.Equal(time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)) ||
		igs[0].Reason != "only used for signing; dropping in Q2" {
		t.Errorf("first ignore = %+v", igs[0])
	}
	if igs[1].Module != "*" || !igs[1].Expires.IsZero() {
		t.Errorf("second ignore = %+v", igs[1])
	}
}

func TestParseIgnoresErrors(t *testing.T) {
	tests := map[string]string{
		"only an id":            "GO-2026-0001",
		"no reason":             "GO-2026-0001 example.com/a 2027-01-01",
		"bad date":              "GO-2026-0001 example.com/a soon because",
		"wildcard id":           "* example.com/a - everything",
		"two fields and reason": "GO-2026-0001",
	}
	for name, line := range tests {
		if _, err := ParseIgnores(strings.NewReader(line)); err == nil {
			t.Errorf("%s: expected an error", name)
		} else if !strings.Contains(err.Error(), "ignore line 1") && !strings.Contains(err.Error(), "GO-ID") {
			t.Errorf("%s: unhelpful error: %v", name, err)
		}
	}
}
