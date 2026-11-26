// Package selfcheck asks whether a running Go build is affected by published
// vulnerabilities, so the program can say so in its own logs and metrics.
//
// It reads the modules compiled into a binary (from build info), the toolchain
// version, and optionally the list of linked packages, and compares them with
// the Go vulnerability database. The answer is a Result: findings with a
// status, warnings about anything the check could not do, and counts suitable
// for a gauge.
//
//	n, err := selfcheck.New(selfcheck.WithGracePeriod(7 * 24 * time.Hour))
//	if err != nil {
//		return err
//	}
//	scope, err := selfcheck.Self()
//	if err != nil {
//		return err
//	}
//	result, err := n.Check(ctx, scope)
//	if err != nil {
//		return err // the check did not run; do not treat as clean
//	}
//	gauge.Set(float64(len(result.Actionable())))
//
// # What the check is
//
// This is a version check with package-level filtering: if an advisory affects
// a package that is not linked into the binary, the finding is
// StatusUnlinked and does not count. It is not a call-graph analysis. It is
// cheaper than running govulncheck and weaker than it; where the two disagree,
// govulncheck is right.
//
// # What it leaves to the caller
//
// Notification, persistence and scheduling policy are the caller's. The
// library does not send mail, does not read environment variables, does not
// write state, and does not decide whether to run. Every returns a periodic
// loop for programs that want one, and Result.Fingerprint and Result.Diff are
// there for programs that would rather keep their own.
//
// A check returns an error only when it could not complete. Anything that
// merely narrows the check — an advisory whose details could not be fetched, a
// missing toolchain version, no package list — is a warning on an otherwise
// usable Result, because "nothing found" and "did not look" must never be the
// same answer.
package selfcheck
