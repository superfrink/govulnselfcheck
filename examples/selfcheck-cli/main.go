// Command selfcheck-cli is working code for the flags a user needs, not a
// product. It exists to be copied: everything it does is a few lines of the
// library, and the flags are the ones that came up while writing it.
//
// It checks the running process or another binary, prints text or JSON, and
// exits 0 when nothing is actionable, 1 when something is, and 2 when the
// check could not be completed. That third code is the important one: a check
// that failed is not a clean build, and a script that treats them the same
// will report a green build from a database outage.
package main

import (
	"context"
	"debug/buildinfo"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/superfrink/govulnselfcheck"
	"github.com/superfrink/govulnselfcheck/report"
)

// Exit codes, which the workflows in this repository depend on.
const (
	exitClean   = 0
	exitFound   = 1
	exitFailed  = 2
	usageHeader = `selfcheck-cli: check a Go build against the Go vulnerability database.

  selfcheck-cli                 check this process
  selfcheck-cli -binary ./app   check another binary
  selfcheck-cli -every 12h      run periodically

Exit status: 0 nothing actionable, 1 findings, 2 the check failed.
`
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(runContext(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without the process: everything is a parameter, so the exit
// status can be tested.
func run(args []string, stdout, stderr io.Writer) int {
	return runContext(context.Background(), args, stdout, stderr)
}

func runContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("selfcheck-cli", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usageHeader)
		fmt.Fprint(fs.Output(), "\nflags:\n")
		fs.PrintDefaults()
	}

	var (
		binary   = fs.String("binary", "", "check this binary instead of the running process")
		asJSON   = fs.Bool("json", false, "print a JSON result instead of text")
		all      = fs.Bool("all", false, "list findings that are not actionable too")
		verbose  = fs.Bool("v", false, "print warnings: what the check could not do")
		every    = fs.Duration("every", 0, "run periodically with this interval (0: once)")
		grace    = fs.Duration("grace", 0, "how long a new advisory is only pending")
		ignore   = fs.String("ignore", "", "file of accepted advisories")
		packages = fs.String("packages", "", "file of linked package paths, from `go list -deps`")
		dbURL    = fs.String("db", "", "database base URL (default "+selfcheck.DefaultDBURL+")")
		timeout  = fs.Duration("timeout", 2*time.Minute, "timeout for one check")
	)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return exitClean
		}
		return exitFailed
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return exitFailed
	}

	scope, target, err := buildScope(*binary)
	if err != nil {
		fmt.Fprintf(stderr, "selfcheck-cli: %v\n", err)
		return exitFailed
	}
	if *packages != "" {
		pkgs, err := readLines(*packages)
		if err != nil {
			fmt.Fprintf(stderr, "selfcheck-cli: reading packages: %v\n", err)
			return exitFailed
		}
		scope = scope.WithPackages(pkgs)
	}

	opts := []selfcheck.Option{selfcheck.WithTimeout(*timeout)}
	if *grace > 0 {
		opts = append(opts, selfcheck.WithGracePeriod(*grace))
	}
	if *dbURL != "" {
		opts = append(opts, selfcheck.WithDatabase(&selfcheck.HTTPDatabase{Base: *dbURL}))
	}
	if *ignore != "" {
		f, err := os.Open(*ignore)
		if err != nil {
			fmt.Fprintf(stderr, "selfcheck-cli: %v\n", err)
			return exitFailed
		}
		defer f.Close()
		opts = append(opts, selfcheck.WithIgnoreFile(f))
	}

	c, err := selfcheck.New(opts...)
	if err != nil {
		fmt.Fprintf(stderr, "selfcheck-cli: %v\n", err)
		return exitFailed
	}

	how := "self-check"
	if *binary != "" {
		how = "self-check of " + *binary
	}
	emit := func(r *selfcheck.Result) (int, error) {
		r.Target = target
		if *asJSON {
			data, err := report.JSON(r)
			if err != nil {
				return exitFailed, err
			}
			fmt.Fprintf(stdout, "%s\n", data)
		} else {
			var ropts []report.Option
			if *all {
				ropts = append(ropts, report.All())
			}
			if *every > 0 {
				ropts = append(ropts, report.How(how))
			}
			fmt.Fprint(stdout, report.TextWith(r, ropts...))
		}
		if *verbose {
			for _, w := range r.Warnings {
				fmt.Fprintf(stderr, "warning: %s: %s\n", w.Kind, w.Detail)
			}
		}
		return exitCode(r), nil
	}

	if *every <= 0 {
		r, err := c.Check(ctx, scope)
		if err != nil {
			fmt.Fprintf(stderr, "selfcheck-cli: check failed: %v\n", err)
			return exitFailed
		}
		code, err := emit(r)
		if err != nil {
			fmt.Fprintf(stderr, "selfcheck-cli: %v\n", err)
			return exitFailed
		}
		return code
	}

	// A periodic self-check that exits on the first bad result would be a
	// service that stops watching when there is something to watch. The loop
	// logs and carries on; only starting it can fail.
	var lastCode int
	err = c.Every(ctx, scope, func(r *selfcheck.Result) {
		code, err := emit(r)
		if err != nil {
			fmt.Fprintf(stderr, "selfcheck-cli: %v\n", err)
			return
		}
		lastCode = code
	})
	if err != nil {
		fmt.Fprintf(stderr, "selfcheck-cli: %v\n", err)
		return exitFailed
	}
	return lastCode
}

// exitCode is the contract in one place: 0 when nothing is actionable, 1 when
// something is. A failed check never reaches here; it is exit 2 at the caller.
func exitCode(r *selfcheck.Result) int {
	if r.Clean() {
		return exitClean
	}
	return exitFound
}

// buildScope reads the build information of the running process or of a file
// on disk, and returns the target to head a report with.
func buildScope(binary string) (selfcheck.Scope, selfcheck.Target, error) {
	read := debug.ReadBuildInfo
	if binary != "" {
		read = func() (*debug.BuildInfo, bool) {
			bi, err := buildinfo.ReadFile(binary)
			if err != nil {
				return nil, false
			}
			return bi, true
		}
	}
	bi, ok := read()
	if !ok || bi == nil {
		return selfcheck.Scope{}, selfcheck.Target{},
			fmt.Errorf("no build information in %s: build it with module support (not -buildmode=pie or -ldflags=-s -w -buildid=)", label(binary))
	}
	scope, err := selfcheck.FromBuildInfo(bi)
	if err != nil {
		return selfcheck.Scope{}, selfcheck.Target{}, err
	}
	return scope, selfcheck.TargetFromBuildInfo(bi), nil
}

func label(binary string) string {
	if binary == "" {
		return "this process"
	}
	return binary
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}
