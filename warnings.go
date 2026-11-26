package selfcheck

import "fmt"

// WarningKind classifies a way a check fell short. Warnings are part of the
// result, not an aside: a caller that pages on "no findings" needs to know
// when the absence of findings means less than it looks like.
type WarningKind string

const (
	// WarnUnjudged: a module was in the build but cannot be judged, because
	// its version is missing, "(devel)", or a filesystem replacement.
	WarnUnjudged WarningKind = "unjudged"
	// WarnNoToolchain: the toolchain version is unknown, so standard library
	// advisories were not checked.
	WarnNoToolchain WarningKind = "no-toolchain"
	// WarnNoPackages: no linked-package list was supplied, so findings were
	// judged at module level only.
	WarnNoPackages WarningKind = "no-packages"
	// WarnEntryMissing: an advisory's detail could not be fetched, so the
	// judgement used the module index alone. The index carries one fix per
	// advisory, so this can miss a reintroduction.
	WarnEntryMissing WarningKind = "entry-missing"
	// WarnIgnoreExpired: an ignore entry's expiry has passed, so it no longer
	// applies.
	WarnIgnoreExpired WarningKind = "ignore-expired"
)

// Warning is one degradation of a check.
type Warning struct {
	Kind   WarningKind `json:"kind"`
	Module string      `json:"module,omitempty"`
	ID     string      `json:"id,omitempty"`
	Detail string      `json:"detail,omitempty"`
}

func (w Warning) String() string {
	s := string(w.Kind)
	switch {
	case w.ID != "" && w.Module != "":
		s += " " + w.ID + " " + w.Module
	case w.ID != "":
		s += " " + w.ID
	case w.Module != "":
		s += " " + w.Module
	}
	if w.Detail != "" {
		s += ": " + w.Detail
	}
	return s
}

func unjudged(m Module, why string) Warning {
	return Warning{Kind: WarnUnjudged, Module: m.Path, Detail: why}
}

func warnf(kind WarningKind, module, id, format string, args ...any) Warning {
	return Warning{Kind: kind, Module: module, ID: id, Detail: fmt.Sprintf(format, args...)}
}

// Warnings about a missing package list are added when the scope has none, not
// here: see Scope.WithPackages.
