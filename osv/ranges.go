package osv

import (
	"strings"

	"golang.org/x/mod/semver"
)

// Resolve finds the affected block for module at version, and when that
// version is affected returns the block and the version the fix first appears
// in ("" when the advisory names none, or when the range closes with
// last_affected instead of a fix).
//
// Several blocks can name the same module; each range is checked and the first
// match wins.
func (e *Entry) Resolve(module, version string) (Affected, string, bool) {
	for _, a := range e.Affected {
		if !CoversModule(a.Module, module) {
			continue
		}
		if fixed, hit := VersionAffected(version, a.Ranges); hit {
			return a, fixed, true
		}
	}
	return Affected{}, "", false
}

// VersionAffected reports whether version falls inside any SEMVER range, and
// the fix that ends the interval it fell in.
//
// Versions that are not semver (and "+incompatible" strips back to its core,
// which the database's ranges are written against) are judged on that core. A
// range in another versioning system is ignored: the database only expresses
// module versions as SEMVER.
func VersionAffected(version string, ranges []Range) (fixedAt string, affected bool) {
	v := strings.TrimSpace(version)
	if i := strings.Index(v, "+incompatible"); i >= 0 {
		v = v[:i]
	}
	if !semver.IsValid(v) {
		return "", false
	}
	for _, r := range ranges {
		if r.Type != "SEMVER" {
			continue
		}
		if fixed, hit := scanRange(v, r.Events); hit {
			return fixed, true
		}
	}
	return "", false
}

// scanRange walks alternating introduced/fixed events. An interval is
// [introduced, fixed); a bare "fixed" implies an open start; a trailing
// "introduced" is open-ended.
//
// Event versions are written without the "v" prefix that semver requires
// ("1.2.3", and "0" for the beginning of time), so they are normalized.
func scanRange(v string, events []Event) (string, bool) {
	// An event list that closes before it opens still starts at zero: a bare
	// "fixed" means "every release before this one". An empty event list,
	// though, describes nothing.
	pending := len(events) > 0
	intro := ""
	lowerOK := func() bool { return intro == "" || semver.Compare(v, intro) >= 0 }

	for _, e := range events {
		if e.Introduced != "" {
			intro = introVersion(e.Introduced)
			pending = true
		}
		// last_affected closes the interval inclusively, with no fix to name.
		if e.LastAffected != "" {
			if pending && lowerOK() && semver.Compare(v, vPrefixed(e.LastAffected)) <= 0 {
				return "", true
			}
			pending, intro = false, ""
			continue
		}
		if e.Fixed == "" {
			continue
		}
		if pending && lowerOK() && semver.Compare(v, vPrefixed(e.Fixed)) < 0 {
			return e.Fixed, true
		}
		pending, intro = false, ""
	}
	if pending && lowerOK() {
		return "", true
	}
	return "", false
}

func introVersion(s string) string {
	if s == "0" {
		return "v0.0.0"
	}
	return vPrefixed(s)
}

// atOrAfter reports whether v is at or after intro. intro is normalized, so a
// plain comparison is enough; v is already valid semver.
func atOrAfter(v, intro string) bool {
	return semver.Compare(v, intro) >= 0
}

// vPrefixed adds the "v" that semver requires.
func VPrefixed(s string) string {
	if strings.HasPrefix(s, "v") {
		return s
	}
	return "v" + s
}

func vPrefixed(s string) string { return VPrefixed(s) }

// StdlibModule is the module path the database uses for the Go standard
// library. Its versions are bare toolchain versions ("1.26.10"), not
// "v"-prefixed module versions.
const StdlibModule = "stdlib"

// StdlibVersion converts a toolchain version to the form stdlib entries use:
// "go1.26.10" -> "1.26.10". A toolchain string that carries extra words
// ("devel go1.27-abc", "go1.26.2 X:strictfipsruntime") is truncated to its
// first field; a string with no parsable version yields "", which callers must
// treat as "cannot judge", not "clean".
func StdlibVersion(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ' '); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimPrefix(v, "go")
	if v == "" || !semver.IsValid(VPrefixed(v)) {
		return ""
	}
	return v
}

// CoversModule reports whether an affected path names module itself or a
// package inside it.
func CoversModule(affected, module string) bool {
	if module == "" {
		return false
	}
	return affected == module || strings.HasPrefix(affected, module+"/")
}

// Linked reports whether any affected import path is in the set of packages
// the build links. A path in the set that sits under an affected path counts
// too: the advisory names a package, the build links something inside it.
//
// An advisory with no import paths cannot be filtered and is reported: a false
// alarm is better than a missed advisory.
func Linked(imports []string, linked map[string]bool) bool {
	if len(imports) == 0 {
		return true
	}
	for _, imp := range imports {
		if linked[imp] {
			return true
		}
		for p := range linked {
			if strings.HasPrefix(p, imp+"/") {
				return true
			}
		}
	}
	return false
}
