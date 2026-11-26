package report

import (
	"encoding/json"
	"testing"

	"github.com/superfrink/govulnselfcheck"
)

func TestJSONShape(t *testing.T) {
	data, err := JSON(sample())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema", "target", "checked", "toolchain", "database", "findings", "counts", "clean", "complete", "warnings"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
	if doc["schema"].(float64) != SchemaVersion {
		t.Errorf("schema = %v", doc["schema"])
	}
	if doc["clean"].(bool) {
		t.Error("sample has actionable findings but reports clean")
	}
	if doc["complete"].(bool) {
		t.Error("sample has warnings but reports complete")
	}
	counts := doc["counts"].(map[string]any)
	for _, s := range []string{"actionable", "pending", "ignored", "unlinked"} {
		if _, ok := counts[s]; !ok {
			t.Errorf("counts missing %q: a metrics loop reads them without checking presence", s)
		}
	}
	findings := doc["findings"].([]any)
	if len(findings) != 5 {
		t.Errorf("findings = %d", len(findings))
	}
	// Statuses are strings, not numbers, so the document survives a reorder of
	// the Status constants.
	first := findings[0].(map[string]any)
	if _, ok := first["status"].(string); !ok {
		t.Errorf("status = %T", first["status"])
	}
}

func TestJSONEmptyFindingsIsArray(t *testing.T) {
	data, err := JSON(&selfcheck.Result{Target: selfcheck.Target{Name: "x"}})
	if err != nil {
		t.Fatal(err)
	}
	// An empty list must serialise as [], not null: consumers index it.
	if !contains(string(data), `"findings": []`) {
		t.Errorf("findings did not serialise as an empty array:\n%s", data)
	}
}

func TestJSONRoundTripTarget(t *testing.T) {
	r := sample()
	data, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Target selfcheck.Target `json:"target"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Target.Name != "fixture-tags" || doc.Target.Commit != "4f2a9c1" {
		t.Errorf("target = %+v", doc.Target)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
