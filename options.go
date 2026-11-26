package selfcheck

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Option configures a Checker.
type Option func(*config) error

type config struct {
	db          Database
	httpClient  *http.Client
	timeout     time.Duration
	concurrency int
	grace       time.Duration
	ignores     []Ignore
	clock       func() time.Time
	logger      *slog.Logger
	interval    time.Duration
	jitter      float64
	packages    []string
	packagesSet bool
}

func defaults() *config {
	return &config{
		timeout:     2 * time.Minute,
		concurrency: 4,
		clock:       time.Now,
		interval:    24 * time.Hour,
		jitter:      0.2,
	}
}

// WithDatabase sets where advisories come from. The default is HTTPDatabase
// pointed at the public database.
func WithDatabase(db Database) Option {
	return func(c *config) error {
		if db == nil {
			return errors.New("selfcheck: nil database")
		}
		c.db = db
		return nil
	}
}

// WithHTTPClient sets the client used by the default HTTPDatabase. It is
// ignored when WithDatabase supplied a database of another kind.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *config) error {
		if hc == nil {
			return errors.New("selfcheck: nil http client")
		}
		c.httpClient = hc
		return nil
	}
}

// WithTimeout bounds a whole check: the index fetch, every entry fetch and the
// work in between. A context deadline on Check takes precedence when shorter.
func WithTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return errors.New("selfcheck: timeout must be positive")
		}
		c.timeout = d
		return nil
	}
}

// WithConcurrency bounds how many entry fetches are in flight at once. Four is
// the default: enough to hide latency, polite to a public database.
func WithConcurrency(n int) Option {
	return func(c *config) error {
		if n <= 0 {
			return errors.New("selfcheck: concurrency must be positive")
		}
		c.concurrency = n
		return nil
	}
}

// WithGracePeriod defers findings on advisories younger than d: they are
// reported as pending rather than actionable. On day zero there is usually no
// fix, and a check that cries on arrival gets turned off.
//
// The age is measured from the advisory's publication date, never its
// modification date: editing an entry would otherwise restart the window.
func WithGracePeriod(d time.Duration) Option {
	return func(c *config) error {
		if d < 0 {
			return errors.New("selfcheck: grace period cannot be negative")
		}
		c.grace = d
		return nil
	}
}

// WithIgnores adds accepted advisories.
func WithIgnores(ignores ...Ignore) Option {
	return func(c *config) error {
		for _, ig := range ignores {
			if err := validateIgnore(ig); err != nil {
				return err
			}
		}
		c.ignores = append(c.ignores, ignores...)
		return nil
	}
}

// WithIgnoreList replaces the ignore list with the given entries.
func WithIgnoreList(ignores []Ignore) Option { return WithIgnores(ignores...) }

// WithIgnoreFile reads ignores in the line-oriented text format (see
// ParseIgnores). Parsing happens once, when the checker is built.
func WithIgnoreFile(r interface{ Read([]byte) (int, error) }) Option {
	return func(c *config) error {
		igs, err := ParseIgnores(r)
		if err != nil {
			return err
		}
		c.ignores = append(c.ignores, igs...)
		return nil
	}
}

func validateIgnore(ig Ignore) error {
	if strings.TrimSpace(ig.ID) == "" || ig.ID == "*" {
		return errors.New("selfcheck: an ignore needs a specific GO-ID")
	}
	if strings.TrimSpace(ig.Reason) == "" {
		return errors.New("selfcheck: ignore " + ig.ID + " has no reason; an ignore without a reason will be copied onward by people who do not know why")
	}
	return nil
}

// WithPackages overrides the linked-package list on every scope the checker is
// given. The usual path is Scope.WithPackages, which keeps the list with the
// build it describes; this is for callers that read the list from one place.
func WithPackages(pkgs []string) Option {
	return func(c *config) error {
		c.packages = NormalizePackages(pkgs)
		c.packagesSet = true
		return nil
	}
}

// WithClock replaces the source of "now", for testing grace and expiry.
func WithClock(now func() time.Time) Option {
	return func(c *config) error {
		if now == nil {
			return errors.New("selfcheck: nil clock")
		}
		c.clock = now
		return nil
	}
}

// WithLogger turns on the library's own logging, which is off by default: a
// library that logs without being asked is a library that talks over its host.
// Warnings are always in the Result; the logger only mirrors them.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) error {
		c.logger = l
		return nil
	}
}

// WithInterval sets how often Every checks. The default is 24 hours.
func WithInterval(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return errors.New("selfcheck: interval must be positive")
		}
		c.interval = d
		return nil
	}
}

// WithJitter spreads periodic checks by ±f (0.2 means ±20%). Replicas started
// together would otherwise hit the database together.
func WithJitter(f float64) Option {
	return func(c *config) error {
		if f < 0 || f > 1 {
			return errors.New("selfcheck: jitter must be between 0 and 1")
		}
		c.jitter = f
		return nil
	}
}
