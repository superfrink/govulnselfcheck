package selfcheck

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/superfrink/govulnselfcheck/osv"
)

// Checker runs checks against one database with one policy. It is safe for
// concurrent use and keeps whatever caching its Database provides.
type Checker struct {
	cfg config
}

// New builds a checker. It validates its configuration and touches nothing
// else: no network, no files, no environment.
func New(opts ...Option) (*Checker, error) {
	c := defaults()
	for _, o := range opts {
		if o == nil {
			continue
		}
		if err := o(c); err != nil {
			return nil, err
		}
	}
	if c.db == nil {
		c.db = &HTTPDatabase{Client: c.httpClient}
	} else if hd, ok := c.db.(*HTTPDatabase); ok && hd.Client == nil {
		hd.Client = c.httpClient
	}
	return &Checker{cfg: *c}, nil
}

// Check examines a scope and returns what applies to it.
//
// It returns an error only when the check could not complete: the module index
// was unreachable, the context ended, or the database answered with something
// that is not an index. Everything else that goes wrong is a warning on a
// result, because a caller that pages on "no findings" must be able to tell
// "nothing found" from "did not look".
func (c *Checker) Check(ctx context.Context, s Scope) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.timeout)
	defer cancel()

	now := c.cfg.clock()
	res := &Result{Checked: now, Scope: s, Warnings: append([]Warning(nil), s.Warnings...)}
	if c.cfg.packagesSet {
		s.Packages = c.cfg.packages
	}
	res.Scope.Packages = s.Packages

	// What to judge: every module in the scope, plus the toolchain.
	mods := make([]Module, 0, len(s.Modules)+1)
	mods = append(mods, s.Modules...)
	if m, ok := s.stdlibModule(); ok {
		mods = append(mods, m)
	} else if s.Toolchain != "" {
		res.Warnings = append(res.Warnings, warnf(WarnNoToolchain, "", "",
			"toolchain version %q is not comparable to a release, so the standard library was not checked", s.Toolchain))
	}
	if s.Packages == nil {
		res.Warnings = append(res.Warnings, Warning{
			Kind:   WarnNoPackages,
			Detail: "no linked-package list, so findings were judged at module level only",
		})
	}
	if len(mods) == 0 {
		return res, nil
	}

	ix, err := c.cfg.db.Index(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("selfcheck: module index unavailable: %w", err)
	}
	res.DB.IndexModules = ix.Len()
	res.DB.IndexETag = ix.ETag
	res.DB.IndexModified = ix.Modified

	// Which advisories are worth a fetch. The index can list one module many
	// times and one advisory under several modules; the pair (module, advisory)
	// is the unit that gets judged.
	type pair struct {
		module Module
		ref    Ref
	}
	var pairs []pair
	byID := map[string]bool{}
	for _, m := range mods {
		for _, r := range ix.Lookup(m.Path) {
			if !osv.ValidateID(r.ID) {
				res.Warnings = append(res.Warnings, warnf(WarnEntryMissing, m.Path, r.ID,
					"the index names an advisory whose ID is not a Go vulnerability ID; it was not fetched"))
				continue
			}
			pairs = append(pairs, pair{module: m, ref: r})
			byID[r.ID] = true
		}
	}
	if len(pairs) == 0 {
		return res, nil
	}

	entries, failures := c.fetchAll(ctx, byID)
	res.DB.EntriesFetched = len(entries)
	res.DB.EntriesMissing = len(failures)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	linked := linkedSet(s.Packages)
	seen := map[string]bool{}
	for _, p := range pairs {
		f, warn, ok := c.judge(p.module, p.ref, entries, failures, linked)
		warn.each(res)
		if !ok {
			continue
		}
		key := f.ID + "|" + f.Module
		if seen[key] {
			continue
		}
		seen[key] = true
		res.Findings = append(res.Findings, f)
	}

	c.applyPolicy(res, now)
	sortFindings(res.Findings)
	sortWarnings(res.Warnings)
	return res, nil
}

// fetchAll fetches every advisory, bounded and cancellable.
func (c *Checker) fetchAll(ctx context.Context, ids map[string]bool) (map[string]*osv.Entry, map[string]error) {
	entries := make(map[string]*osv.Entry, len(ids))
	failures := make(map[string]error)
	if len(ids) == 0 {
		return entries, failures
	}
	list := make([]string, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	sort.Strings(list)

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, c.cfg.concurrency)
	for _, id := range list {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				failures[id] = ctx.Err()
				mu.Unlock()
				return
			}
			e, err := c.cfg.db.Entry(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures[id] = err
				return
			}
			entries[id] = e
		}(id)
	}
	wg.Wait()
	return entries, failures
}

// judge decides one (module, advisory) pair. It returns the finding when the
// version matches, an optional warning when the judgement had to fall back, and
// whether there is anything to report.
func (c *Checker) judge(m Module, r Ref, entries map[string]*osv.Entry, failures map[string]error, linked map[string]bool) (Finding, warnings, bool) {
	base := Finding{ID: r.ID, Module: m.Path, Version: m.Version}
	if m.Original != nil {
		base.Replaced = m.Original.Path + " " + m.Original.Version + " -> " + m.Path + " " + m.Version
	}

	e, ok := entries[r.ID]
	if !ok {
		err := failures[r.ID]
		if NotFound(err) {
			return Finding{}, nil, false
		}
		// The index alone decides, and the index cannot see a reintroduction:
		// it carries one fix version per advisory. Say so rather than let a
		// degraded check look like a complete one.
		w := warnings{{Kind: WarnEntryMissing, Module: m.Path, ID: r.ID,
			Detail: "advisory detail unavailable, judged from the module index alone"}}
		if r.Fixed == "" {
			return Finding{}, w, false
		}
		if !versionBefore(m.Version, r.Fixed) {
			return Finding{}, w, false
		}
		f := base
		f.Summary = ""
		f.FixedAt = r.Fixed
		f.Status = StatusActionable
		f.Reason = "judged from the module index alone: the advisory entry could not be fetched"
		return f, w, true
	}

	a, fixed, hit := e.Resolve(m.Path, m.Version)
	if !hit {
		return Finding{}, nil, false
	}
	f := base
	f.ID = e.ID
	f.Summary = e.Summary
	f.FixedAt = fixed
	f.Published = e.Published
	f.Packages = a.Imports
	if linked != nil && !osv.Linked(a.Imports, linked) {
		f.Status = StatusUnlinked
		f.Reason = "the affected package is not linked into this build"
		return f, nil, true
	}
	f.Status = StatusActionable
	return f, nil, true
}

// applyPolicy assigns pending and ignored statuses. Precedence is unlinked,
// then ignored, then pending: a waiver exists because a caller has the package
// and accepted it, and a package that is not in the binary makes that waiver
// moot — reporting the verifiable fact is more useful than reporting the
// decision.
func (c *Checker) applyPolicy(res *Result, now time.Time) {
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.Status != StatusActionable {
			continue
		}
		if ig, ok := c.matchIgnore(*f, now, &res.Warnings); ok {
			f.Status = StatusIgnored
			f.Reason = "ignored: " + ig.Reason
			if !ig.Expires.IsZero() {
				f.Expires = osv.Time{Time: ig.Expires}
			}
			continue
		}
		if c.cfg.grace > 0 && !f.Published.IsZero() {
			age := now.Sub(f.Published.Time)
			if age < c.cfg.grace {
				f.Status = StatusPending
				f.Reason = fmt.Sprintf("published %s ago, within the %s grace period",
					round(age), c.cfg.grace)
			}
		}
	}
}

// matchIgnore reports the ignore entry that applies, adding a warning for every
// ignore that has expired: an expired waiver is not a waiver, and a caller
// needs to know that a decision they made has lapsed.
func (c *Checker) matchIgnore(f Finding, now time.Time, warns *[]Warning) (Ignore, bool) {
	var matched Ignore
	found := false
	expired := map[string]bool{}
	for _, ig := range c.cfg.ignores {
		if !ig.matches(f) {
			continue
		}
		if !ig.Expires.IsZero() && !now.Before(ig.Expires) {
			if !expired[ig.ID] {
				expired[ig.ID] = true
				*warns = append(*warns, warnf(WarnIgnoreExpired, f.Module, ig.ID,
					"the ignore expired on %s and no longer applies (%s)", ig.Expires.Format("2006-01-02"), ig.Reason))
			}
			continue
		}
		matched = ig
		found = true
	}
	return matched, found
}

// versionBefore reports whether version is strictly before fixed, comparing the
// semver cores. A version that will not parse is treated as not-before: the
// fallback only fires on evidence.
func versionBefore(version, fixed string) bool {
	_, hit := osv.VersionAffected(version, []osv.Range{{
		Type:   "SEMVER",
		Events: []osv.Event{{Introduced: "0"}, {Fixed: fixed}},
	}})
	return hit
}

func linkedSet(pkgs []string) map[string]bool {
	if len(pkgs) == 0 {
		return nil
	}
	m := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		m[p] = true
	}
	return m
}

// warnings is a small accumulator so judge can return zero or more.
type warnings []Warning

func (w warnings) each(r *Result) {
	r.Warnings = append(r.Warnings, w...)
}

func sortWarnings(ws []Warning) {
	sort.SliceStable(ws, func(i, j int) bool {
		if ws[i].Kind != ws[j].Kind {
			return ws[i].Kind < ws[j].Kind
		}
		if ws[i].Module != ws[j].Module {
			return ws[i].Module < ws[j].Module
		}
		return ws[i].ID < ws[j].ID
	})
}

func round(d time.Duration) time.Duration {
	if d < time.Minute {
		return d.Round(time.Second)
	}
	return d.Round(time.Minute)
}
