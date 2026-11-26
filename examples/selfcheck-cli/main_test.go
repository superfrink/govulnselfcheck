package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/superfrink/govulnselfcheck"
	"github.com/superfrink/govulnselfcheck/osv"
)

// The exit statuses are a contract: the workflows in this repository branch on
// them. These tests exist so that contract cannot change silently.
//
// Every test that runs a check points -db at a local server. A test that reads
// vuln.go.dev is a test that fails when the network does, and passes or fails
// depending on which advisories were published this morning.

// syncBuf is a bytes.Buffer safe to read while the periodic loop writes.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuf) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

// emptyDB serves a database with no advisories, the "everything is fine" case.
func emptyDB(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/index/modules.json") {
			fmt.Fprint(w, `[]`)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// advisoryDB serves a database whose single advisory affects the standard
// library below go1.26, which the toolchain running this test almost certainly
// is. No imports are listed, so the whole module is affected and the finding
// is actionable rather than filtered out.
func advisoryDB(t *testing.T) string {
	t.Helper()
	entry := &osv.Entry{
		ID: "GO-2026-9001",
		Affected: []osv.Affected{{
			Module: osv.StdlibModule,
			Ranges: []osv.Range{{
				Type:   "SEMVER",
				Events: []osv.Event{{Introduced: "0"}, {Fixed: "1.26.0"}},
			}},
		}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/index/modules.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `[{"path":%q,"vulns":[{"id":"GO-2026-9001","fixed":"1.26.0"}]}]`, osv.StdlibModule)
	})
	mux.HandleFunc("/ID/GO-2026-9001.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(entry)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestExitCodeContract(t *testing.T) {
	// The mapping itself, without a database in the way. Only an actionable
	// finding is worth a non-zero exit: pending has a fix on the way, ignored
	// was accepted, and unlinked is not in the build at all.
	if got := exitCode(&selfcheck.Result{}); got != exitClean {
		t.Errorf("clean result: exit = %d, want %d", got, exitClean)
	}
	cases := []struct {
		status selfcheck.Status
		want   int
	}{
		{selfcheck.StatusActionable, exitFound},
		{selfcheck.StatusPending, exitClean},
		{selfcheck.StatusIgnored, exitClean},
		{selfcheck.StatusUnlinked, exitClean},
	}
	for _, c := range cases {
		r := &selfcheck.Result{Findings: []selfcheck.Finding{{ID: "GO-2026-0001", Status: c.status}}}
		if got := exitCode(r); got != c.want {
			t.Errorf("status %s: exit = %d, want %d", c.status, got, c.want)
		}
	}
}

func TestCleanBuild(t *testing.T) {
	code, out, _ := runCLI(t, "-db", emptyDB(t))
	if code != exitClean {
		t.Fatalf("exit = %d, want %d\n%s", code, exitClean, out)
	}
	if out == "" {
		t.Error("no report printed")
	}
}

func TestActionableFinding(t *testing.T) {
	code, out, _ := runCLI(t, "-db", advisoryDB(t))
	if code != exitFound {
		t.Fatalf("exit = %d, want %d (an actionable finding)\n%s", code, exitFound, out)
	}
	if !strings.Contains(out, "GO-2026-9001") {
		t.Errorf("report does not name the advisory:\n%s", out)
	}
}

func TestJSON(t *testing.T) {
	code, out, _ := runCLI(t, "-json", "-db", emptyDB(t))
	if code != exitClean {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if doc["schema"] == nil {
		t.Error("JSON output has no schema version")
	}
}

func TestAll(t *testing.T) {
	// -all includes findings that are not actionable; without it, a pending
	// finding is mentioned only in the summary.
	code, plain, _ := runCLI(t, "-db", emptyDB(t))
	if code != exitClean {
		t.Fatalf("exit = %d, want 0", code)
	}
	code, all, _ := runCLI(t, "-db", emptyDB(t), "-all")
	if code != exitClean {
		t.Fatalf("exit = %d with -all, want 0", code)
	}
	if plain == "" || all == "" {
		t.Error("no report printed")
	}
}

func TestHelp(t *testing.T) {
	for _, arg := range []string{"-h", "-help", "--help"} {
		code, _, errOut := runCLI(t, arg)
		if code != exitClean {
			t.Errorf("%s: exit = %d, want 0", arg, code)
		}
		if !strings.Contains(errOut, "Exit status") {
			t.Errorf("%s: usage does not document the exit status:\n%s", arg, errOut)
		}
	}
}

func TestBadFlag(t *testing.T) {
	code, _, errOut := runCLI(t, "-nope")
	if code != exitFailed {
		t.Errorf("exit = %d, want %d", code, exitFailed)
	}
	if errOut == "" {
		t.Error("no error printed for an unknown flag")
	}
}

func TestUnexpectedArgument(t *testing.T) {
	code, _, errOut := runCLI(t, "extra")
	if code != exitFailed {
		t.Errorf("exit = %d, want %d", code, exitFailed)
	}
	if !strings.Contains(errOut, "unexpected arguments") {
		t.Errorf("stderr = %q", errOut)
	}
}

func TestMissingIgnoreFile(t *testing.T) {
	code, _, errOut := runCLI(t, "-db", emptyDB(t), "-ignore", filepath.Join(t.TempDir(), "absent.txt"))
	if code != exitFailed {
		t.Errorf("exit = %d, want %d", code, exitFailed)
	}
	if !strings.Contains(errOut, "no such file") {
		t.Errorf("stderr = %q", errOut)
	}
}

func TestIgnoreFileAccepted(t *testing.T) {
	// The advisory in advisoryDB accepted for a year: the check still sees it,
	// and the exit status drops to clean because nothing is actionable.
	path := filepath.Join(t.TempDir(), "ignores.txt")
	body := "# accepted\n\nGO-2026-9001 * - pinned toolchain, planned upgrade\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, "-db", advisoryDB(t), "-ignore", path, "-all")
	if code != exitClean {
		t.Fatalf("exit = %d, want 0: an accepted advisory is not actionable\n%s%s", code, out, errOut)
	}
	if !strings.Contains(out, "GO-2026-9001") {
		t.Errorf("-all does not list the accepted finding:\n%s", out)
	}
}

func TestExpiredIgnoreWarning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ignores.txt")
	body := "GO-2026-9001 * 2020-01-01 lapsed decision\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI(t, "-db", advisoryDB(t), "-ignore", path, "-v")
	if code != exitFound {
		t.Fatalf("exit = %d, want %d: an expired ignore stops applying", code, exitFound)
	}
	if !strings.Contains(errOut, "warning") {
		t.Errorf("no warning about the lapsed ignore:\n%s", errOut)
	}
}

func TestGracePeriod(t *testing.T) {
	// An advisory published today, within a long grace period, is pending
	// rather than actionable: the process has not had a chance to upgrade.
	now := time.Now()
	entry := &osv.Entry{
		ID:        "GO-2026-9002",
		Published: osv.Time{Time: now},
		Affected: []osv.Affected{{
			Module: osv.StdlibModule,
			Ranges: []osv.Range{{
				Type:   "SEMVER",
				Events: []osv.Event{{Introduced: "0"}, {Fixed: "1.26.0"}},
			}},
		}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/index/modules.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `[{"path":%q,"vulns":[{"id":"GO-2026-9002","fixed":"1.26.0"}]}]`, osv.StdlibModule)
	})
	mux.HandleFunc("/ID/GO-2026-9002.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(entry)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	code, out, errOut := runCLI(t, "-db", srv.URL, "-grace", "720h", "-all")
	if code != exitClean {
		t.Fatalf("exit = %d, want 0: a finding inside its grace period is not actionable\n%s%s", code, out, errOut)
	}
	if !strings.Contains(out, "pending") {
		t.Errorf("report does not mark the finding pending:\n%s", out)
	}
}

func TestMissingPackagesFile(t *testing.T) {
	code, _, errOut := runCLI(t, "-db", emptyDB(t), "-packages", filepath.Join(t.TempDir(), "absent.txt"))
	if code != exitFailed {
		t.Errorf("exit = %d, want %d", code, exitFailed)
	}
	if !strings.Contains(errOut, "reading packages") {
		t.Errorf("stderr = %q", errOut)
	}
}

func TestPackagesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packages.txt")
	body := "# `go list -deps` output\nfmt\nnet/http\n\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, "-db", emptyDB(t), "-packages", path)
	if code != exitClean {
		t.Fatalf("exit = %d, want 0\n%s%s", code, out, errOut)
	}
	if out == "" {
		t.Error("no report printed")
	}
}

func TestUnreachableDatabase(t *testing.T) {
	// A database that is not there must be exit 2, never a clean report: this
	// is the failure mode where a network outage looks like a healthy build.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	code, _, errOut := runCLI(t, "-db", srv.URL, "-timeout", "3s")
	if code != exitFailed {
		t.Fatalf("exit = %d, want %d (a failed check is not a clean build)", code, exitFailed)
	}
	if !strings.Contains(errOut, "check failed") {
		t.Errorf("stderr = %q", errOut)
	}
}

func TestEveryStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	out := &syncBuf{}
	var errb syncBuf
	done := make(chan int, 1)
	go func() {
		done <- runContext(ctx, []string{"-db", emptyDB(t), "-every", "10ms"}, out, &errb)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for out.Len() == 0 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("the periodic loop printed nothing\n%s", errb.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case code := <-done:
		if code != exitClean {
			t.Errorf("exit = %d after cancel, want 0\n%s", code, errb.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the periodic loop did not stop on cancel")
	}
}
