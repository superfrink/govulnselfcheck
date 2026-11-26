package selfcheck

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"
)

// Ignore is one accepted advisory: a decision, with a reason and usually an end
// date, recorded where it can be reviewed.
//
// An ignore says "this applies to us and we are not fixing it yet". It is not a
// way to silence a check that is wrong: an advisory whose package is not linked
// is StatusUnlinked and needs no ignore.
type Ignore struct {
	// ID is a Go vulnerability ID, e.g. GO-2026-5932.
	ID string
	// Module restricts the ignore to one module. "*" or empty ignores the ID
	// whatever module it arrives through, which is rarely what you want.
	Module string
	// Reason is required: an ignore with no reason is a comment in a blank
	// file, and will be copied onward by people who do not know why.
	Reason string
	// Expires ends the ignore. Zero means it never expires, which is a
	// deliberate statement and worth a sentence in Reason.
	Expires time.Time
}

func (ig Ignore) matches(f Finding) bool {
	if ig.ID != f.ID {
		return false
	}
	return ig.Module == "" || ig.Module == "*" || ig.Module == f.Module
}

// ParseIgnores reads the line-oriented ignore format:
//
//	# GO-ID      module                  expires     reason
//	GO-2026-5932 golang.org/x/crypto     2027-03-01  only used for signing
//	GO-2026-6859 *                       -           pinned toolchain, upgrade in Q2
//
// Fields are separated by whitespace; the reason runs to the end of the line.
// A module of "*" or "-" means any module. An expires of "-" means never.
// Blank lines and lines starting with # are skipped.
func ParseIgnores(r io.Reader) ([]Ignore, error) {
	var out []Ignore
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("selfcheck: ignore line %d: want at least ID and module", lineNo)
		}
		ig := Ignore{ID: fields[0], Module: fields[1]}
		// An absent expires column is only valid when a reason follows
		// immediately; keep the format unambiguous instead of guessing.
		if len(fields) < 3 {
			return nil, fmt.Errorf("selfcheck: ignore line %d: want ID, module, expires and reason", lineNo)
		}
		if ig.Module == "-" {
			ig.Module = "*"
		}
		if fields[2] != "-" {
			exp, err := time.Parse("2006-01-02", fields[2])
			if err != nil {
				return nil, fmt.Errorf("selfcheck: ignore line %d: expires %q is not YYYY-MM-DD (use - for never)", lineNo, fields[2])
			}
			ig.Expires = exp
		}
		ig.Reason = strings.Join(fields[3:], " ")
		if ig.Reason == "" {
			return nil, fmt.Errorf("selfcheck: ignore line %d: an ignore needs a reason", lineNo)
		}
		if ig.ID == "" || ig.ID == "*" {
			return nil, fmt.Errorf("selfcheck: ignore line %d: an ignore needs a specific GO-ID", lineNo)
		}
		out = append(out, ig)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
