package osv

import (
	"context"
	"encoding/json"
	"fmt"
)

// Ref is one advisory's entry in the module index.
type Ref struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
	// Fixed is the version the index says this advisory is fixed in. An
	// advisory can be fixed in several versions (one per release branch, and
	// again after a reintroduction), so this is a hint, not an answer.
	Fixed string `json:"fixed"`
}

// Index is the module index: which modules have advisories, and what each
// advisory names as its fix. It is the cheap filter that narrows a build's
// modules down to the few advisories worth fetching in full.
type Index struct {
	Modules map[string][]Ref `json:"-"`
	// ETag and Modified let a client revalidate instead of refetching several
	// megabytes. Both may be empty.
	ETag     string `json:"-"`
	Modified string `json:"-"`
}

// Lookup returns the advisories that name module.
func (ix *Index) Lookup(module string) []Ref {
	if ix == nil || ix.Modules == nil {
		return nil
	}
	return ix.Modules[module]
}

// Len reports how many modules the index covers.
func (ix *Index) Len() int {
	if ix == nil {
		return 0
	}
	return len(ix.Modules)
}

// indexJSON is the on-the-wire shape of /index/modules.json.
type indexJSON []struct {
	Path  string `json:"path"`
	Vulns []Ref  `json:"vulns"`
}

// ParseIndex reads an index document.
func ParseIndex(data []byte) (*Index, error) {
	var raw indexJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("osv: parsing module index: %w", err)
	}
	ix := &Index{Modules: make(map[string][]Ref, len(raw))}
	for _, m := range raw {
		if m.Path == "" {
			continue
		}
		ix.Modules[m.Path] = append(ix.Modules[m.Path], m.Vulns...)
	}
	return ix, nil
}

// Database is where advisories come from: the published database, a local copy
// of it, a cache in front of either, or a fake in a test.
//
// Two methods are enough, and that is the point: judging a build needs no
// knowledge of how bytes arrive.
type Database interface {
	// Index returns the module index.
	Index(ctx context.Context) (*Index, error)
	// Entry returns one advisory in full.
	Entry(ctx context.Context, goID string) (*Entry, error)
}
