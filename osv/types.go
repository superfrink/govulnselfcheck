// Package osv reads entries from the Go vulnerability database
// (https://vuln.go.dev) and answers one question about them: does this module
// version fall inside the ranges an advisory marks as affected, and if so,
// when does it stop being affected?
//
// The types here only describe what this library uses. The database's full
// schema carries more (credits, database_specific, severity, symbols); unknown
// fields are ignored, so an entry gaining fields cannot break a check.
//
// Two shapes of "affected" exist in the database's history: older entries name
// the module in "module", newer ones name the affected packages in "package"
// and list them under ecosystem_specific.imports. Affected.UnmarshalJSON
// accepts both and flattens them, because package-level filtering needs the
// import paths and the module name has to come from somewhere either way.
package osv

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Entry is one advisory.
type Entry struct {
	ID       string     `json:"id"`
	Summary  string     `json:"summary"`
	Details  string     `json:"details"`
	Affected []Affected `json:"affected"`
	// Aliases and References are kept for callers that report them; nothing
	// in this library reads them.
	Aliases    []string    `json:"aliases"`
	References []Reference `json:"references"`
	Published  Time        `json:"published"`
	Modified   Time        `json:"modified"`
}

// Reference is a link attached to an advisory.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Affected is one affected block: a set of package paths and the version
// ranges of the module they belong to.
type Affected struct {
	// Module is the module path the affected packages belong to. In older
	// entries it is the affected path itself.
	Module string
	// Imports are the affected import paths: the module itself or packages
	// inside it. Empty means the whole module is meant, which cannot be
	// filtered by package.
	Imports []string
	Ranges  []Range
	// Symbols are the affected symbols per import path, when the entry lists
	// them. Unused by the version check; kept for symbol-level work.
	Symbols map[string][]string
}

// Range is a sequence of introduced/fixed events in one versioning system.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is one transition. A "fixed" with no preceding "introduced" means the
// range starts at the beginning; a trailing "introduced" with no following
// "fixed" means it is still open.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// ImportSymbols is the ecosystem_specific.imports shape.
type ImportSymbols struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols"`
}

// UnmarshalJSON accepts the current layout (package + ecosystem_specific.
// imports) and the older one (module as a string or as {"path": ...}).
func (a *Affected) UnmarshalJSON(data []byte) error {
	var raw struct {
		Module  json.RawMessage `json:"module"`
		Package *struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []Range `json:"ranges"`
		// Some entries duplicate the paths at the top level.
		Imports           []string `json:"imports"`
		EcosystemSpecific struct {
			Imports []ImportSymbols `json:"imports"`
		} `json:"ecosystem_specific"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	a.Ranges = raw.Ranges
	a.Module = ""
	if len(raw.Module) > 0 && string(raw.Module) != "null" {
		if raw.Module[0] == '"' {
			if err := json.Unmarshal(raw.Module, &a.Module); err != nil {
				return err
			}
		} else {
			var m struct {
				Path string `json:"path"`
			}
			if err := json.Unmarshal(raw.Module, &m); err != nil {
				return err
			}
			a.Module = m.Path
		}
	}
	if a.Module == "" && raw.Package != nil {
		a.Module = raw.Package.Name
	}

	seen := map[string]bool{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		a.Imports = append(a.Imports, p)
	}
	for _, p := range raw.Imports {
		add(p)
	}
	for _, im := range raw.EcosystemSpecific.Imports {
		add(im.Path)
		if len(im.Symbols) > 0 {
			if a.Symbols == nil {
				a.Symbols = map[string][]string{}
			}
			p := strings.TrimSpace(im.Path)
			a.Symbols[p] = append(a.Symbols[p], im.Symbols...)
		}
	}
	return nil
}

// Time is an OSV timestamp. The database writes RFC 3339, but a malformed or
// absent value must not fail the parse of an otherwise usable entry, so an
// unparseable time becomes the zero value and IsZero reports it.
type Time struct{ time.Time }

// UnmarshalJSON accepts a quoted RFC 3339 string or null.
func (t *Time) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		t.Time = time.Time{}
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		t.Time = time.Time{}
		return nil
	}
	parsed, err := ParseTime(s)
	if err != nil {
		t.Time = time.Time{}
		return nil
	}
	t.Time = parsed
	return nil
}

// MarshalJSON writes RFC 3339, or null when unset.
func (t Time) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(t.UTC().Format(time.RFC3339))
}

// ParseTime parses the timestamp forms seen in the database: RFC 3339 and the
// older date-only "2006-01-02".
func ParseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("osv: cannot parse time %q", s)
}

// ValidateID reports whether s looks like a Go vulnerability ID ("GO-2024-1234"
// is the shape; aliases like CVE-2024-1234 exist but entries live under the GO
// ID). It exists so a value from a remote index is never pasted into a URL
// unchecked.
func ValidateID(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 3 || parts[0] != "GO" {
		return false
	}
	for _, p := range parts[1:] {
		if len(p) != 4 {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}
