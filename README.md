# govulnselfcheck

[![ci](https://github.com/superfrink/govulnselfcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/superfrink/govulnselfcheck/actions/workflows/ci.yml)
[![vulncheck](https://github.com/superfrink/govulnselfcheck/actions/workflows/vulncheck.yml/badge.svg)](https://github.com/superfrink/govulnselfcheck/actions/workflows/vulncheck.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/superfrink/govulnselfcheck.svg)](https://pkg.go.dev/github.com/superfrink/govulnselfcheck)
[![license](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

A Go library that checks a running binary against the [Go vulnerability
database](https://vuln.go.dev): the modules compiled into it, the linked
packages, and the standard library the toolchain carries.

It is a **self** check. The application asks about itself on a schedule and
exports the answer — a log line, a metric, an alert. It is not a build gate, and
it is not [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/govulncheck):
this is a version check with package-level filtering, not a call-graph
analysis. It is cheaper than the real thing and weaker; where they disagree,
`govulncheck` is right.

Requires Go 1.25 or later (`golang.org/x/mod` v0.40, which clears
GO-2026-6179/6180, requires it).

## Install

```sh
go get github.com/superfrink/govulnselfcheck
```

## Use

```go
import (
	"context"
	"log"

	"github.com/superfrink/govulnselfcheck"
)

func check() {
	c, err := selfcheck.New(selfcheck.WithGracePeriod(7 * 24 * time.Hour))
	if err != nil {
		log.Fatal(err)
	}
	scope, err := selfcheck.Self() // build info of this binary
	if err != nil {
		log.Fatal(err)
	}
	r, err := c.Check(context.Background(), scope)
	if err != nil {
		// The check did not run. Do not count this as clean.
		log.Printf("self-check failed: %v", err)
		return
	}
	log.Printf("%s: %d actionable", r.Target.Label(), len(r.Actionable()))
	for _, f := range r.Actionable() {
		log.Printf("%s %s %s (fixed in %s)", f.ID, f.Label(), f.Version, f.FixedAt)
	}
}
```

For a long-running process, `Every` runs the first check immediately and then
on a jittered interval. It never returns for a failure of the database or a
panic in a handler: a check that cannot run must not silence the check.

```go
var vulns = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{Name: "go_vulnerabilities"},
	[]string{"status"},
)

go func() {
	_ = c.Every(ctx, scope, func(r *selfcheck.Result) {
		for status, n := range r.Counts() {
			vulns.WithLabelValues(string(status)).Set(float64(n))
		}
	})
}()
```

`r.Counts()` always has all four statuses, zero included, so the metric does
not need to test for presence.

## Statuses

| Status | Meaning | Counts? |
| --- | --- | --- |
| `actionable` | A published advisory applies to this build. | yes |
| `pending` | It applies, but it is younger than the grace period. | no |
| `ignored` | An ignore in your list accepts it. The `Reason` says why. | no |
| `unlinked` | The affected package is not linked into this binary. | no |

`unlinked` outranks `ignored`: an ignore is a decision about code you have, and
if the code is not there the verifiable answer is the better one. `pending`
becomes `actionable` at the end of its window, which changes
`Result.Fingerprint`, so a dedupe on the fingerprint notifies once, at the
moment it matters.

## Grace and ignores

`WithGracePeriod` leaves new advisories out of the actionable count for a
while, measured from the advisory's **publication** date — editing an entry does
not restart the window.

An ignore file is line-oriented text:

```
# GO-ID       module                expires     reason
GO-2026-5932  golang.org/x/crypto  2027-03-01  only used for signing
GO-2026-6859  *                     -           pinned toolchain, upgrade in Q2
```

```go
f, err := os.Open("vuln-ignores.txt")
if err != nil {
	return err
}
defer f.Close()
c, err := selfcheck.New(selfcheck.WithIgnoreFile(f))
```

A reason is required, and an expired ignore stops applying and is reported as a
warning — a lapsed decision is not a decision.

## Incomplete checks

Anything that narrows a check is a `Warning` on the result, never a silent
pass: an advisory whose entry could not be fetched (judged from the module
index, which carries only one fix per advisory), an unknown toolchain version,
no package list. `Result.Clean` speaks about what was checked;
`Result.Complete` speaks about how much that was. A caller that pages on "no
findings" should look at both.

## Reporting

`report` renders a `Result` as text or JSON, so the same result can be a log
line, a stored document, or an email body:

```go
fmt.Print(report.Text(r))
data, err := report.JSON(r) // schema-versioned, findings as [],
```

## Example CLI

`examples/selfcheck-cli` is working code for the flags a user needs, not a
product. It checks its own process or a binary, prints text or JSON, and
exits 0 clean, 1 findings, 2 check failed.

```sh
go run ./examples/selfcheck-cli -v
go run ./examples/selfcheck-cli -binary ./app -json
go run ./examples/selfcheck-cli -every 12h
```

## Development

```sh
make check        # gofmt, vet, and go test -race -shuffle=on ./...
make cover        # the same tests, plus the coverage floor
```

Tests run under the race detector, always. The cache, the bounded worker pool
and the periodic loop all have concurrency that a plain `go test` never
exercises, so a race there would only be found in production. `-race` needs
cgo, so a C compiler must be installed.

The database is a fake in tests; `testdb` is an in-memory database new tests
can use, and the example CLI is tested against an `httptest` server, including
its exit status contract. Coverage floors and the weekly advisory scan are in
`.github/workflows`.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
