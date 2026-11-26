package osv

import (
	"encoding/json"
	"testing"
)

// The database is a public JSON document this library does not control, and
// millions of builds consume it: the parser must not panic on anything, and
// whatever it does parse must be safe to query.
func FuzzAffectedUnmarshal(f *testing.F) {
	seeds := []string{
		`{"package":{"name":"example.com/m"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]}`,
		`{"module":"example.com/m","ranges":[]}`,
		`{"module":{"path":"example.com/m"}}`,
		`{"imports":["a","a"],"ecosystem_specific":{"imports":[{"path":"b","symbols":["S"]}]}}`,
		`{}`,
		`null`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var a Affected
		if err := json.Unmarshal(data, &a); err != nil {
			return
		}
		// Anything that parsed must be safe to use: no panics, and the
		// answer to "is this version affected" must be stable.
		_ = Linked(a.Imports, map[string]bool{a.Module: true})
		_ = CoversModule(a.Module, "example.com/m")
		fixed, hit := VersionAffected("v1.0.0", a.Ranges)
		if again, hitAgain := VersionAffected("v1.0.0", a.Ranges); hit != hitAgain || fixed != again {
			t.Fatalf("judgement is not deterministic: %q/%v then %q/%v", fixed, hit, again, hitAgain)
		}
	})
}

func FuzzVersionAffected(f *testing.F) {
	f.Add("v1.2.3", "0", "1.2.4", "")
	f.Add("v1.26.10", "", "1.26.10", "")
	f.Add("", "0", "", "")
	f.Add("v2.0.0+incompatible", "1.0.0", "", "1.5.0")
	f.Fuzz(func(t *testing.T, version, intro, fixed, last string) {
		events := []Event{{Introduced: intro, Fixed: fixed, LastAffected: last}}
		_, _ = VersionAffected(version, []Range{{Type: "SEMVER", Events: events}})
		_ = StdlibVersion(version)
		_ = ValidateID(version)
	})
}
