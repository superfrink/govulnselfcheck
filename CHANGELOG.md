# Changelog

Notable changes, newest first. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## v0.1.0

First usable version: the check, the policy, and the reporting.

### Added

- `Checker.Check`: judge a scope against the vulnerability database, with
  bounded parallel fetches, an index cache, and package-level filtering.
- `Scope` from a running binary's build info (`Self`, `FromBuildInfo`), from a
  binary on disk (`FromBinary`), or from an explicit module list
  (`FromModules`), applying `replace` directives before judging.
- Finding statuses `actionable`, `pending`, `ignored` and `unlinked`, with
  `Result.Counts` shaped for a metric loop.
- `WithGracePeriod`, measured from an advisory's publication date, and ignore
  files with required reasons and optional expiry.
- `Result.Fingerprint` and `Result.Diff` for callers that keep their own state
  and only want to hear about changes.
- `Checker.Every`: immediate first check, jittered interval, failures and
  panics recovered rather than fatal.
- `report` package: stable text, schema-versioned JSON.
- `testdb`: an in-memory database for tests.
- CI (gofmt, vet, race, coverage floor, cross-compile), a weekly advisory scan,
  and a keyless release workflow. No release has been made or signed yet.

### Changed

- `golang.org/x/mod` v0.40.0, which clears GO-2026-6179 and GO-2026-6180 and
  requires Go 1.25.
