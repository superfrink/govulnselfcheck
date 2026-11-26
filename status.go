package selfcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/superfrink/govulnselfcheck/osv"
)

// Status says what a caller should do about a finding. The distinction is the
// reason this library returns a list rather than a boolean: "found something"
// is not the same as "found something you can act on".
type Status string

const (
	// StatusActionable: the vulnerable code is in this build, and nothing has
	// been accepted or deferred about it.
	StatusActionable Status = "actionable"
	// StatusPending: the same, but the advisory is younger than the grace
	// period. Usually there is no fix yet on day zero.
	StatusPending Status = "pending"
	// StatusIgnored: matched an ignore entry that has not expired.
	StatusIgnored Status = "ignored"
	// StatusUnlinked: the module version matches, but the affected package is
	// not linked into the build. By far the most common reason a version-based
	// check produces something a call-graph check would not.
	StatusUnlinked Status = "unlinked"
)

// Finding is one advisory that applies to the checked build.
type Finding struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
	// Module is the module as judged: when a replace directive applies, this
	// is the module actually linked, not the one the go.mod asked for.
	Module  string `json:"module"`
	Version string `json:"version"`
	// Replaced describes the substitution, if there was one.
	Replaced string `json:"replaced,omitempty"`
	// FixedAt is the version that clears the advisory. Empty when the advisory
	// names no fix.
	FixedAt   string   `json:"fixed_at,omitempty"`
	Published osv.Time `json:"published"`
	// Packages are the affected import paths from the advisory.
	Packages []string `json:"packages,omitempty"`
	Status   Status   `json:"status"`
	// Reason explains a status other than actionable, in words suitable for a
	// log line.
	Reason string `json:"reason,omitempty"`
	// Expires is the ignore entry's expiry, when Status is StatusIgnored.
	Expires osv.Time `json:"expires"`
}

// Label is the module name as printed in reports; the standard library is not
// a module and reads better spelled out.
func (f Finding) Label() string {
	if f.Module == osv.StdlibModule {
		return "Go standard library"
	}
	return f.Module
}

// Topic is the manufacturer of a finding for a report heading: what is it
// about, not what it is.
func (f Finding) Topic() string {
	if f.Summary != "" {
		return f.Summary
	}
	return f.ID
}

// DatabaseInfo records what the check read, so two results can be compared with
// some confidence that they saw the same data.
type DatabaseInfo struct {
	IndexModules    int    `json:"index_modules"`
	IndexETag       string `json:"index_etag,omitempty"`
	IndexModified   string `json:"index_modified,omitempty"`
	EntriesFetched  int    `json:"entries_fetched"`
	EntriesMissing  int    `json:"entries_missing"`
	DatabaseBlocked string `json:"-"`
}

// Result is one check.
type Result struct {
	Target  Target       `json:"-"`
	Scope   Scope        `json:"-"`
	Checked time.Time    `json:"checked"`
	DB      DatabaseInfo `json:"database"`
	// Findings is every advisory that matched, whatever its status. Order is
	// stable (module, then ID) so reports and fingerprints do not wobble.
	Findings []Finding `json:"findings"`
	// Warnings is where a check says what it could not do. A result with
	// warnings may be incomplete; Clean and Actionable speak only about what
	// was checked.
	Warnings []Warning `json:"warnings,omitempty"`
}

// Counts is the number of findings per status. Keys with no findings are
// present with a zero count, so a metrics loop can iterate without checking
// presence: pending and ignored being zero is information.
func (r *Result) Counts() map[Status]int {
	c := map[Status]int{
		StatusActionable: 0,
		StatusPending:    0,
		StatusIgnored:    0,
		StatusUnlinked:   0,
	}
	for _, f := range r.Findings {
		c[f.Status]++
	}
	return c
}

// Actionable returns the findings a caller should act on, sorted.
func (r *Result) Actionable() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Status == StatusActionable {
			out = append(out, f)
		}
	}
	return out
}

// Clean reports whether nothing actionable was found. It does not report
// whether the check was complete: read Warnings for that.
func (r *Result) Clean() bool {
	for _, f := range r.Findings {
		if f.Status == StatusActionable {
			return false
		}
	}
	return true
}

// Complete reports whether the check ran without warnings.
func (r *Result) Complete() bool { return len(r.Warnings) == 0 }

// Fingerprint identifies the set of findings and their statuses, for dedupe:
// notify when it changes, stay quiet when it does not. Because it includes the
// status, a finding leaving its grace period changes the fingerprint, and an
// advisory that a caller has already been told about is not repeated.
func (r *Result) Fingerprint() string {
	lines := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		lines = append(lines, fmt.Sprintf("%s|%s|%s|%s", f.Status, f.ID, f.Module, f.Version))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// Changes describes how one result differs from another.
type Changes struct {
	// Added are findings the new result has and the old one did not.
	Added []Finding
	// Cleared are findings the old result had and the new one does not. A
	// dependency that was upgraded out of a range shows up here, which is the
	// only evidence a caller gets that a fix landed.
	Cleared []Finding
	// Changed are findings present in both whose status moved, such as a
	// pending finding leaving its grace period.
	Changed []Change
}

// Change is one finding whose status moved.
type Change struct {
	From    Status
	Finding Finding
}

// Empty reports whether nothing changed.
func (c Changes) Empty() bool {
	return len(c.Added) == 0 && len(c.Cleared) == 0 && len(c.Changed) == 0
}

// Diff compares two results. A nil previous result means everything in r is
// new.
func (r *Result) Diff(prev *Result) Changes {
	var c Changes
	if prev == nil {
		c.Added = append([]Finding(nil), r.Findings...)
		return c
	}
	type key struct{ id, module string }
	before := make(map[key]Finding, len(prev.Findings))
	for _, f := range prev.Findings {
		before[key{f.ID, f.Module}] = f
	}
	seen := make(map[key]bool, len(r.Findings))
	for _, f := range r.Findings {
		k := key{f.ID, f.Module}
		seen[k] = true
		old, ok := before[k]
		switch {
		case !ok:
			c.Added = append(c.Added, f)
		case old.Status != f.Status:
			c.Changed = append(c.Changed, Change{From: old.Status, Finding: f})
		}
	}
	for k, f := range before {
		if !seen[k] {
			c.Cleared = append(c.Cleared, f)
		}
	}
	sortFindings(c.Added)
	sortFindings(c.Cleared)
	sort.Slice(c.Changed, func(i, j int) bool {
		if c.Changed[i].Finding.Module != c.Changed[j].Finding.Module {
			return c.Changed[i].Finding.Module < c.Changed[j].Finding.Module
		}
		return c.Changed[i].Finding.ID < c.Changed[j].Finding.ID
	})
	return c
}

// findingsEqual reports whether two finding lists are identical, including
// order.
func findingsEqual(a, b []Finding) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if len(x.Packages) != len(y.Packages) {
			return false
		}
		for k := range x.Packages {
			if x.Packages[k] != y.Packages[k] {
				return false
			}
		}
		x.Packages, y.Packages = nil, nil
		if !findingEqual(x, y) {
			return false
		}
	}
	return true
}

func findingEqual(x, y Finding) bool {
	return x.ID == y.ID &&
		x.Summary == y.Summary &&
		x.Module == y.Module &&
		x.Version == y.Version &&
		x.Replaced == y.Replaced &&
		x.FixedAt == y.FixedAt &&
		x.Published.Equal(y.Published.Time) &&
		x.Status == y.Status &&
		x.Reason == y.Reason &&
		x.Expires.Equal(y.Expires.Time)
}

func sortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Module != fs[j].Module {
			return fs[i].Module < fs[j].Module
		}
		if fs[i].ID != fs[j].ID {
			return fs[i].ID < fs[j].ID
		}
		return fs[i].Version < fs[j].Version
	})
}
