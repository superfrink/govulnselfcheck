package selfcheck

import (
	"runtime/debug"
	"strconv"
)

// Target identifies the build a result is about. The zero value is valid: a
// report then says as little as it can instead of guessing.
//
// The library never fills this from the environment. A service passes its own
// name, a CLI passes an empty one, a test passes whatever it likes.
type Target struct {
	Name       string            `json:"name,omitempty"`
	ID         string            `json:"id,omitempty"`
	Commit     string            `json:"commit,omitempty"`
	CommitTime string            `json:"commit_time,omitempty"`
	Dirty      bool              `json:"dirty,omitempty"`
	Extra      map[string]string `json:"extra,omitempty"`
}

// Label is the name used to head a report, falling back to the main module and
// then to a neutral word.
func (t Target) Label() string {
	if t.Name != "" {
		return t.Name
	}
	if t.Extra != nil && t.Extra["main"] != "" {
		return t.Extra["main"]
	}
	return "build"
}

// CommitSummary is a one-line description of the commit, for report headers.
func (t Target) CommitSummary() string {
	if t.Commit == "" {
		return "unknown"
	}
	s := t.Commit
	if t.CommitTime != "" {
		s += " (" + t.CommitTime
		if t.Dirty {
			s += ", modified working tree"
		}
		s += ")"
	}
	return s
}

// TargetFromBuildInfo reads the vcs.* settings that `go build` records, plus
// the platform, into a Target. The name is left for the caller.
func TargetFromBuildInfo(bi *debug.BuildInfo) Target {
	if bi == nil {
		return Target{}
	}
	t := Target{Extra: map[string]string{}}
	if bi.Main.Path != "" {
		t.Extra["main"] = bi.Main.Path
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			t.Commit = s.Value
		case "vcs.time":
			t.CommitTime = s.Value
		case "vcs.modified":
			dirty, _ := strconv.ParseBool(s.Value)
			t.Dirty = dirty
		case "GOOS", "GOARCH", "CGO_ENABLED", "GOAMD64", "GOARM64":
			t.Extra[s.Key] = s.Value
		}
	}
	if len(t.Extra) == 0 {
		t.Extra = nil
	}
	return t
}

// SelfTarget reads the running binary's target. A missing build information
// (stripped binary) yields the zero Target rather than an error: a check can
// still run, it just describes itself less well.
func SelfTarget() Target {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return Target{}
	}
	return TargetFromBuildInfo(bi)
}
