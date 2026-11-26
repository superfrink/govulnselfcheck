package report

import (
	"encoding/json"

	"github.com/superfrink/govulnselfcheck"
)

// SchemaVersion identifies the JSON shape. It changes only when a field is
// removed or its meaning changes, not when one is added.
const SchemaVersion = 1

// document is the JSON a caller stores or ships elsewhere. Fields are explicit
// rather than an embedded Result so the output does not drift every time the
// library gains an internal field.
type document struct {
	Schema    int                    `json:"schema"`
	Target    selfcheck.Target       `json:"target"`
	Checked   string                 `json:"checked"`
	Toolchain string                 `json:"toolchain"`
	Database  selfcheck.DatabaseInfo `json:"database"`
	Findings  []selfcheck.Finding    `json:"findings"`
	Counts    map[string]int         `json:"counts"`
	Warnings  []selfcheck.Warning    `json:"warnings,omitempty"`
	Clean     bool                   `json:"clean"`
	Complete  bool                   `json:"complete"`
}

// JSON renders a result as a JSON document with a schema version.
func JSON(r *selfcheck.Result) ([]byte, error) {
	counts := map[string]int{}
	for k, v := range r.Counts() {
		counts[string(k)] = v
	}
	doc := document{
		Schema:    SchemaVersion,
		Target:    r.Target,
		Checked:   r.Checked.UTC().Format("2006-01-02T15:04:05Z"),
		Toolchain: r.Scope.Toolchain,
		Database:  r.DB,
		Findings:  r.Findings,
		Counts:    counts,
		Warnings:  r.Warnings,
		Clean:     r.Clean(),
		Complete:  r.Complete(),
	}
	if doc.Findings == nil {
		doc.Findings = []selfcheck.Finding{}
	}
	return json.MarshalIndent(doc, "", "  ")
}
