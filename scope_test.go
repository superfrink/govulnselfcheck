package selfcheck

import (
	"os"
	"runtime/debug"
	"strings"
	"testing"
)

func dep(path, version string, replace *debug.Module) *debug.Module {
	return &debug.Module{Path: path, Version: version, Replace: replace}
}

func bi(main debug.Module, goVersion string, deps ...*debug.Module) *debug.BuildInfo {
	return &debug.BuildInfo{Main: main, GoVersion: goVersion, Deps: deps}
}

func findMod(mods []Module, path string) (Module, bool) {
	for _, m := range mods {
		if m.Path == path {
			return m, true
		}
	}
	return Module{}, false
}

func hasWarning(s Scope, kind WarningKind, substr string) bool {
	for _, w := range s.Warnings {
		if w.Kind == kind && strings.Contains(w.String(), substr) {
			return true
		}
	}
	return false
}

func TestFromBuildInfoPlain(t *testing.T) {
	s, err := FromBuildInfo(bi(
		debug.Module{Path: "example.com/main", Version: "(devel)"},
		"go1.26.11",
		dep("example.com/a", "v1.2.3", nil),
		dep("example.com/b", "v0.0.0-20240101120000-abcdef123456", nil),
	))
	if err != nil {
		t.Fatal(err)
	}
	if s.Toolchain != "go1.26.11" {
		t.Errorf("toolchain = %q", s.Toolchain)
	}
	if len(s.Modules) != 2 {
		t.Fatalf("modules = %v", s.Modules)
	}
	if m, ok := findMod(s.Modules, "example.com/a"); !ok || m.Version != "v1.2.3" || m.Original != nil {
		t.Errorf("a = %+v (found %v)", m, ok)
	}
	// The main module of a local build has no release version: a warning, not
	// a finding and not a failure.
	if !hasWarning(s, WarnUnjudged, "example.com/main") {
		t.Errorf("expected an unjudged warning for the main module, got %v", s.Warnings)
	}
}

func TestFromBuildInfoReplace(t *testing.T) {
	t.Run("replaced with another version", func(t *testing.T) {
		s, err := FromBuildInfo(bi(debug.Module{Path: "example.com/main", Version: "v1.0.0"}, "go1.26.11",
			dep("example.com/old", "v1.0.0", &debug.Module{Path: "example.com/new", Version: "v2.3.4"}),
		))
		if err != nil {
			t.Fatal(err)
		}
		m, ok := findMod(s.Modules, "example.com/new")
		if !ok {
			t.Fatalf("replacement missing from modules: %v", s.Modules)
		}
		// Judging uses the replacement: the version that is actually linked is
		// the one an advisory applies to.
		if m.Version != "v2.3.4" {
			t.Errorf("version = %q, want the replacement's", m.Version)
		}
		if m.Original == nil || m.Original.Path != "example.com/old" || m.Original.Version != "v1.0.0" {
			t.Errorf("original = %+v", m.Original)
		}
		if _, found := findMod(s.Modules, "example.com/old"); found {
			t.Error("the replaced module should not be judged as itself")
		}
	})

	t.Run("replaced with a local directory", func(t *testing.T) {
		s, err := FromBuildInfo(bi(debug.Module{Path: "example.com/main", Version: "v1.0.0"}, "go1.26.11",
			dep("example.com/local", "v1.0.0", &debug.Module{Path: "../local", Version: ""}),
		))
		if err != nil {
			t.Fatal(err)
		}
		if _, found := findMod(s.Modules, "../local"); found {
			t.Error("an unversioned replacement must not be judged")
		}
		if !hasWarning(s, WarnUnjudged, "no version to compare") {
			t.Errorf("expected a filesystem-replacement warning, got %v", s.Warnings)
		}
	})

	t.Run("replaced with an unversioned module path", func(t *testing.T) {
		s, err := FromBuildInfo(bi(debug.Module{Path: "example.com/main", Version: "v1.0.0"}, "go1.26.11",
			dep("example.com/x", "v1.0.0", &debug.Module{Path: "example.com/y", Version: ""}),
		))
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Modules) != 0 {
			t.Errorf("modules = %v, want none", s.Modules)
		}
		if !hasWarning(s, WarnUnjudged, "example.com/y") {
			t.Errorf("expected an unjudged warning, got %v", s.Warnings)
		}
	})
}

func TestFromBuildInfoDegraded(t *testing.T) {
	if _, err := FromBuildInfo(nil); err == nil {
		t.Error("nil build info should be an error")
	}

	s, err := FromBuildInfo(bi(debug.Module{Path: "example.com/main", Version: "v1.0.0"}, "",
		dep("example.com/devel", "(devel)", nil),
	))
	if err != nil {
		t.Fatal(err)
	}
	// No GoVersion: falls back to the running toolchain, which exists here.
	if s.Toolchain == "" {
		t.Error("toolchain should fall back to runtime.Version()")
	}
	if !hasWarning(s, WarnUnjudged, "(devel)") && !hasWarning(s, WarnUnjudged, "example.com/devel") {
		t.Errorf("expected an unjudged warning for the (devel) dependency, got %v", s.Warnings)
	}

	s, err = FromBuildInfo(bi(debug.Module{}, "", dep("example.com/a", "v1.0.0", nil)))
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(s, WarnUnjudged, "no main module") {
		t.Errorf("expected a missing-main-module warning, got %v", s.Warnings)
	}
}

func TestFromBuildInfoSorts(t *testing.T) {
	s, err := FromBuildInfo(bi(debug.Module{Path: "m", Version: "v1.0.0"}, "go1.26.11",
		dep("z.example/x", "v1.0.0", nil),
		dep("a.example/x", "v1.0.0", nil),
		dep("a.example/x", "v0.9.0", nil),
		dep("m.example/x", "v1.0.0", nil),
	))
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, m := range s.Modules {
		got = append(got, m.Path+"@"+m.Version)
	}
	want := []string{"a.example/x@v0.9.0", "a.example/x@v1.0.0", "m.example/x@v1.0.0", "z.example/x@v1.0.0"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("modules = %v, want %v", got, want)
	}
}

func TestFromModules(t *testing.T) {
	s := FromModules(
		Module{Path: "example.com/main", Version: "v1.0.0"},
		[]Module{
			{Path: "example.com/b", Version: "v2.0.0"},
			{Path: "example.com/a", Version: "v1.0.0"},
			{Path: "example.com/devel", Version: "(devel)"},
		},
		"go1.26.11",
	)
	if len(s.Modules) != 2 {
		t.Fatalf("modules = %v", s.Modules)
	}
	if s.Modules[0].Path != "example.com/a" {
		t.Error("modules should be sorted")
	}
	if !hasWarning(s, WarnUnjudged, "example.com/devel") {
		t.Errorf("expected an unjudged warning, got %v", s.Warnings)
	}

	s = FromModules(Module{Path: "m"}, nil, "")
	if !hasWarning(s, WarnNoToolchain, "") {
		t.Errorf("expected a toolchain warning, got %v", s.Warnings)
	}
}

func TestNormalizePackages(t *testing.T) {
	got := NormalizePackages([]string{
		" vendor/golang.org/x/net/http2 ",
		"golang.org/x/net/http2",
		"",
		"example.com/m",
		"example.com/m",
	})
	want := []string{"example.com/m", "golang.org/x/net/http2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
	if NormalizePackages([]string{"", "  "}) != nil {
		t.Error("an empty list should normalize to nil, which means unknown")
	}
}

func TestWithPackagesClearsWarning(t *testing.T) {
	s := Scope{Warnings: []Warning{{Kind: WarnNoPackages, Detail: "x"}, {Kind: WarnNoToolchain}}}
	s = s.WithPackages([]string{"example.com/m"})
	for _, w := range s.Warnings {
		if w.Kind == WarnNoPackages {
			t.Fatal("the no-packages warning should be gone")
		}
	}
	if len(s.Packages) != 1 {
		t.Errorf("packages = %v", s.Packages)
	}
}

func TestStdlibModule(t *testing.T) {
	s := Scope{Toolchain: "go1.26.10"}
	m, ok := s.stdlibModule()
	if !ok || m.Path != "stdlib" || m.Version != "v1.26.10" {
		t.Fatalf("stdlib module = %+v ok=%v", m, ok)
	}
	s = Scope{Toolchain: "devel +abc"}
	if _, ok := s.stdlibModule(); ok {
		t.Error("an unparsable toolchain should not produce a stdlib module")
	}
}

func TestModuleString(t *testing.T) {
	m := Module{Path: "example.com/new", Version: "v2.0.0", Original: &Module{Path: "example.com/old", Version: "v1.0.0"}}
	if got, want := m.String(), "example.com/old v1.0.0 -> example.com/new v2.0.0"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := (Module{Path: "example.com/a", Version: "v1.0.0"}).String(); got != "example.com/a v1.0.0" {
		t.Errorf("got %q", got)
	}
}

func TestTargetFromBuildInfo(t *testing.T) {
	b := &debug.BuildInfo{
		Main: debug.Module{Path: "example.com/main"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abc123"},
			{Key: "vcs.time", Value: "2026-11-25T10:00:00Z"},
			{Key: "vcs.modified", Value: "true"},
			{Key: "GOOS", Value: "linux"},
			{Key: "GOARCH", Value: "arm64"},
			{Key: "CGO_ENABLED", Value: "0"},
			{Key: "-buildmode", Value: "exe"},
		},
	}
	tg := TargetFromBuildInfo(b)
	if tg.Commit != "abc123" || tg.CommitTime == "" || !tg.Dirty {
		t.Errorf("target = %+v", tg)
	}
	if tg.Extra["GOARCH"] != "arm64" || tg.Extra["main"] != "example.com/main" {
		t.Errorf("extra = %v", tg.Extra)
	}
	if _, ok := tg.Extra["-buildmode"]; ok {
		t.Error("settings this library does not report should not be copied")
	}
	if got, want := tg.CommitSummary(), "abc123 (2026-11-25T10:00:00Z, modified working tree)"; got != want {
		t.Errorf("commit summary = %q, want %q", got, want)
	}
	if got := tg.Label(); got != "example.com/main" {
		t.Errorf("label = %q", got)
	}

	if got := (Target{Name: "svc"}).Label(); got != "svc" {
		t.Errorf("label = %q", got)
	}
	if got := (Target{}).Label(); got != "build" {
		t.Errorf("label = %q", got)
	}
	if got := (Target{}).CommitSummary(); got != "unknown" {
		t.Errorf("commit summary = %q", got)
	}
	if got := TargetFromBuildInfo(nil); got.Commit != "" || got.Extra != nil {
		t.Errorf("nil build info = %+v", got)
	}
}

func TestSelf(t *testing.T) {
	// The test binary has build information unless it was built with flags
	// that strip it; either outcome must be a usable answer, never a panic.
	s, err := Self()
	if err == nil && s.Toolchain == "" {
		t.Error("a successful Self should know the toolchain")
	}
	if err != nil && !strings.Contains(err.Error(), "selfcheck:") {
		t.Errorf("unexpected error text: %v", err)
	}
	if _, err := FromBinary("/nonexistent/binary"); err == nil {
		t.Error("reading a missing binary should fail")
	}
}

func TestFromBinaryReadsRealBuildInfo(t *testing.T) {
	// The test binary is a Go binary with build information, so this exercises
	// the real debug/buildinfo reader without needing a second build.
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip("no executable path:", err)
	}
	s, err := FromBinary(exe)
	if err != nil {
		t.Skip("no build information in the test binary:", err)
	}
	if s.Toolchain == "" {
		t.Error("a real binary should yield a toolchain version")
	}
	for _, m := range s.Modules {
		if m.Version == "" || m.Version == "(devel)" {
			t.Errorf("an unjudgeable module reached the module list: %+v", m)
		}
	}
}
