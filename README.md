# govulnselfcheck

[![ci](https://github.com/superfrink/govulnselfcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/superfrink/govulnselfcheck/actions/workflows/ci.yml)
[![vulncheck](https://github.com/superfrink/govulnselfcheck/actions/workflows/vulncheck.yml/badge.svg)](https://github.com/superfrink/govulnselfcheck/actions/workflows/vulncheck.yml)

A Go library that checks a running binary against the Go vulnerability
database: the module versions compiled into it, the linked packages, and the
standard library the toolchain carries.

It is a **self** check. An application asks about itself on a schedule and
exports the answer — a log line, a metric, an alert. It is not a build gate,
and it is not [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/govulncheck):
this is a version check with package-level filtering, not a call-graph
analysis. It is cheaper than the real thing, and weaker; where they disagree,
`govulncheck` is right.

Work in progress. API is not yet frozen.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
