package selfcheck

import (
	"debug/buildinfo"
	"errors"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/superfrink/govulnselfcheck/osv"
)

// Module is one module compiled into a build, as it should be judged: after
// replacements are applied.
type Module struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	// Original is the module the build required, when a replace directive
	// substituted another one. Judging uses Path/Version; Original is for the
	// report, so a finding about a substituted module can say what it replaced.
	Original *Module `json:"original,omitempty"`
	// Dir is set for a filesystem replacement (replace => ../local). Such a
	// module has no version to compare, so it cannot be judged.
}

// String renders a module for reports: "example.com/m v1.2.3", with the
// replacement chain when there is one.
func (m Module) String() string {
	s := m.Path + " " + m.Version
	if m.Original != nil {
		s = m.Original.String() + " -> " + s
	}
	return s
}

// Scope is what a check examines: the compiled-in modules, the toolchain that
// built them, and optionally the packages the build linked.
//
// Warnings collects what could not be represented faithfully while the scope
// was assembled (a module with no version, a missing toolchain). Check adds its
// own warnings to the same list in the Result.
type Scope struct {
	Main      Module   `json:"main"`
	Modules   []Module `json:"modules"`
	Toolchain string   `json:"toolchain"`
	// Packages lists the package paths linked into the binary, typically from
	// `go list -deps` at build time. nil means unknown, which turns
	// package-level filtering off and makes the check module-level only.
	Packages []string  `json:"-"`
	Warnings []Warning `json:"-"`
}

// FromBuildInfo builds a scope from a build's information, applying replace
// directives. It does not read the environment or guess: pass the BuildInfo
// the process already has.
func FromBuildInfo(bi *debug.BuildInfo) (Scope, error) {
	if bi == nil {
		return Scope{}, errors.New("selfcheck: nil build info")
	}
	s := Scope{
		Toolchain: bi.GoVersion,
		Warnings:  []Warning{},
	}
	if s.Toolchain == "" {
		s.Toolchain = runtime.Version()
	}
	if s.Toolchain == "" {
		s.Warnings = append(s.Warnings, Warning{
			Kind:   WarnNoToolchain,
			Detail: "the build records no toolchain version, so the standard library was not checked",
		})
	}

	s.Main = Module{Path: bi.Main.Path, Version: bi.Main.Version}
	if bi.Main.Path == "" {
		s.Warnings = append(s.Warnings, Warning{
			Kind:   WarnUnjudged,
			Detail: "the build records no main module",
		})
	} else if !judgeable(s.Main.Version) {
		s.Warnings = append(s.Warnings, unjudged(s.Main, "the main module has no release version"))
	}

	s.Modules = make([]Module, 0, len(bi.Deps))
	for _, d := range bi.Deps {
		m := Module{Path: d.Path, Version: d.Version}
		if d.Replace != nil {
			m.Original = &Module{Path: d.Path, Version: d.Version}
			m.Path = d.Replace.Path
			m.Version = d.Replace.Version
		}
		if !judgeable(m.Version) {
			why := "the module has no release version"
			if m.Original != nil {
				why = "the module was replaced by one with no version to compare (usually a filesystem replacement)"
			}
			s.Warnings = append(s.Warnings, unjudged(m, why))
			continue
		}
		s.Modules = append(s.Modules, m)
	}
	sortModules(s.Modules)
	return s, nil
}

// Self builds a scope from the running binary's own build information.
func Self() (Scope, error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return Scope{}, errors.New("selfcheck: build information unavailable (binary built with -buildvcs=false is fine; this is usually a stripped or embedded build)")
	}
	return FromBuildInfo(bi)
}

// FromBinary builds a scope from a binary on disk. It works on any Go binary
// of a compatible version, not just the running one, which makes it usable
// from a CLI or an image digger.
func FromBinary(path string) (Scope, error) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return Scope{}, err
	}
	return FromBuildInfo(bi)
}

// FromModules builds a scope without build info, for callers that know their
// modules another way (a lockfile, a manifest). Modules are used as given and
// are not resorted or filtered; a missing version becomes an unjudged warning.
func FromModules(main Module, mods []Module, toolchain string) Scope {
	s := Scope{Toolchain: toolchain, Warnings: []Warning{}}
	s.Main = main
	if toolchain == "" {
		s.Warnings = append(s.Warnings, Warning{
			Kind:   WarnNoToolchain,
			Detail: "no toolchain version, so the standard library was not checked",
		})
	}
	for _, m := range mods {
		if !judgeable(m.Version) {
			s.Warnings = append(s.Warnings, unjudged(m, "the module has no release version"))
			continue
		}
		s.Modules = append(s.Modules, m)
	}
	sortModules(s.Modules)
	return s
}

// WithPackages returns a copy of the scope with the linked-package list set.
// Paths are normalized: trimmed, vendor/ prefixes removed (advisories name the
// real import path), empties dropped, sorted and deduplicated.
func (s Scope) WithPackages(pkgs []string) Scope {
	s.Packages = NormalizePackages(pkgs)
	s.Warnings = removeWarnings(s.Warnings, WarnNoPackages)
	return s
}

// NormalizePackages cleans a `go list -deps` style list into the form advisory
// import paths take.
func NormalizePackages(pkgs []string) []string {
	seen := make(map[string]bool, len(pkgs))
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		p = strings.TrimPrefix(strings.TrimSpace(p), "vendor/")
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// judgeable reports whether a version can be compared against the database.
func judgeable(version string) bool {
	return version != "" && version != "(devel)"
}

func sortModules(mods []Module) {
	sort.Slice(mods, func(i, j int) bool {
		if mods[i].Path != mods[j].Path {
			return mods[i].Path < mods[j].Path
		}
		return mods[i].Version < mods[j].Version
	})
}

func removeWarnings(ws []Warning, kind WarningKind) []Warning {
	out := ws[:0]
	for _, w := range ws {
		if w.Kind != kind {
			out = append(out, w)
		}
	}
	return out
}

// stdlibModule returns the pseudo-module entry for the toolchain, and whether
// the toolchain was usable at all.
func (s Scope) stdlibModule() (Module, bool) {
	v := osv.StdlibVersion(s.Toolchain)
	if v == "" {
		return Module{}, false
	}
	return Module{Path: osv.StdlibModule, Version: osv.VPrefixed(v)}, true
}
