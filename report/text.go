// Package report renders a check result for humans and for machines.
//
// Rendering lives outside the check so the same Result can be a log line, a
// JSON document, or an email body without the check knowing which, and so
// there is exactly one implementation of each format.
package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/superfrink/govulnselfcheck"
)

// Options adjust a rendered report.
type Options struct {
	// How says where the result came from: "at startup", "on request", "from
	// the hourly check". It appears in the closing sentence, which otherwise
	// claims more than it knows.
	How string
	// All renders every finding, including those that are not actionable.
	// Without it, only actionable findings are listed and the rest are
	// summarised by count.
	All bool
}

// Option configures a report.
type Option func(*Options)

// How sets the sentence describing what triggered the check.
func How(s string) Option {
	return func(o *Options) {
		if s != "" {
			o.How = s
		}
	}
}

// All includes non-actionable findings in the listing.
func All() Option {
	return func(o *Options) { o.All = true }
}

// Text renders a result as plain text. It is stable: the same result renders
// byte-identically, so it can be diffed, stored, and compared in tests.
func Text(r *selfcheck.Result) string { return TextWith(r) }

// TextWith renders a result with options.
func TextWith(r *selfcheck.Result, opts ...Option) string {
	o := Options{How: "on request"}
	for _, opt := range opts {
		opt(&o)
	}
	var b strings.Builder
	label := r.Target.Label()

	actionable := sorted(r.Actionable())
	shown := sorted(r.Findings)
	if !o.All {
		shown = actionable
	}

	if len(shown) == 0 {
		if len(actionable) == 0 {
			fmt.Fprintf(&b, "No actionable vulnerabilities found in %s (checked %s).\n", label, stamp(r))
		}
	} else {
		fmt.Fprintf(&b, "%s: %d vulnerable module version(s) in this build\n\n", label, len(shown))
		for _, f := range shown {
			fmt.Fprintf(&b, "  %s  %s %s\n", f.ID, f.Label(), f.Version)
			if f.FixedAt != "" {
				fmt.Fprintf(&b, "      fixed in %s\n", f.FixedAt)
			} else {
				b.WriteString("      no fix published\n")
			}
			if f.Summary != "" {
				fmt.Fprintf(&b, "      %s\n", f.Summary)
			}
			if f.Replaced != "" {
				fmt.Fprintf(&b, "      replaced: %s\n", f.Replaced)
			}
			if f.Status != selfcheck.StatusActionable {
				fmt.Fprintf(&b, "      %s: %s\n", f.Status, f.Reason)
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("-- Build --\n\n")
	fmt.Fprintf(&b, "  Target:   %s\n", label)
	if r.Target.ID != "" {
		fmt.Fprintf(&b, "  Revision: %s\n", r.Target.ID)
	}
	fmt.Fprintf(&b, "  Go:       %s\n", orUnknown(r.Scope.Toolchain))
	fmt.Fprintf(&b, "  Commit:   %s\n", r.Target.CommitSummary())
	for _, k := range sortedKeys(r.Target.Extra) {
		if k == "main" {
			fmt.Fprintf(&b, "  Main:     %s\n", r.Target.Extra[k])
			continue
		}
		fmt.Fprintf(&b, "  %-9s %s\n", k+":", r.Target.Extra[k])
	}
	fmt.Fprintf(&b, "  Checked:  %s\n", stamp(r))
	if r.DB.IndexModules > 0 {
		fmt.Fprintf(&b, "  Database: %d modules in the index, %d entries read\n", r.DB.IndexModules, r.DB.EntriesFetched)
	}
	b.WriteString("\n")

	if !o.All {
		if line := notCounted(r); line != "" {
			b.WriteString(line)
		}
	}

	if len(r.Warnings) > 0 {
		fmt.Fprintf(&b, "-- Incomplete (%d) --\n\n", len(r.Warnings))
		b.WriteString("This check did not examine everything it was asked to:\n\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "  %s\n", w)
		}
		b.WriteString("\n")
	}

	how := o.How
	if how == "" {
		how = "on request"
	}
	fmt.Fprintf(&b, "These results come from a version-based check %s, not a call-graph analysis: the vulnerable code may or may not be exercised. See https://pkg.go.dev/vuln/ for details.\n", how)
	return b.String()
}

// Subject is a one-line summary suitable for an email subject or a log line.
func Subject(r *selfcheck.Result) string {
	n := len(r.Actionable())
	label := r.Target.Label()
	switch n {
	case 0:
		return fmt.Sprintf("%s: no actionable Go vulnerabilities", label)
	case 1:
		return fmt.Sprintf("%s: 1 actionable Go vulnerability", label)
	default:
		return fmt.Sprintf("%s: %d actionable Go vulnerabilities", label, n)
	}
}

// notCounted summarises findings that exist but are not actionable, with the
// reason. The list is the proof that the check looked: silence about a pending
// or waived advisory reads as an all-clear.
func notCounted(r *selfcheck.Result) string {
	counts := r.Counts()
	var parts []string
	for _, s := range []selfcheck.Status{selfcheck.StatusPending, selfcheck.StatusIgnored, selfcheck.StatusUnlinked} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "-- Not counted (%s) --\n\n", strings.Join(parts, ", "))
	for _, f := range sorted(r.Findings) {
		if f.Status == selfcheck.StatusActionable {
			continue
		}
		fmt.Fprintf(&b, "  %s  %s  %s\n", f.ID, f.Label(), f.Status)
		if f.Reason != "" {
			fmt.Fprintf(&b, "      %s\n", f.Reason)
		}
	}
	b.WriteString("\n")
	return b.String()
}

// sorted returns the findings in report order. The check already orders them,
// but a result may be hand-assembled or decoded from a stored document, and a
// renderer that depends on the caller's order produces reports that differ for
// no reason.
func sorted(fs []selfcheck.Finding) []selfcheck.Finding {
	out := append([]selfcheck.Finding(nil), fs...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func stamp(r *selfcheck.Result) string {
	if r.Checked.IsZero() {
		return "unknown"
	}
	return r.Checked.UTC().Format("2006-01-02T15:04:05Z")
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
