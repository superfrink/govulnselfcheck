package selfcheck

import (
	"context"
	"fmt"
	"math/rand"
	"time"
)

// Handler receives each completed check. It is called from the goroutine
// running Every, one result at a time, so it may block without causing
// overlapping checks.
type Handler func(*Result)

// ErrorHandler is called when a check could not be completed at all: the
// database was unreachable, or the context expired mid-check. There is no
// Result in that case, which is why it is a separate callback rather than a
// field on one.
type ErrorHandler func(error)

// WithErrorHandler sets the callback Every uses for checks that could not
// complete, and for panics inside a check or a handler. Without one, such
// failures go to the logger, and are dropped if there is no logger.
func WithErrorHandler(h ErrorHandler) Option {
	return func(c *config) error {
		c.onError = h
		return nil
	}
}

// Every checks immediately and then on a jittered interval, calling h for each
// result, until ctx is cancelled. It returns nil when the context ends and an
// error only if ctx was already done on entry.
//
// A check that cannot complete calls the error handler and does not stop the
// loop: a database outage at three in the morning should not silence the
// process's self-check until the next deploy. A panic in Check or in h is
// recovered and reported the same way, so one bad run does not take the
// application down.
func (c *Checker) Every(ctx context.Context, s Scope, h Handler) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if h == nil {
		h = func(*Result) {}
	}
	for {
		c.runOnce(ctx, s, h)
		d := c.nextInterval()
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

// runOnce performs one check and delivers its outcome. It never panics.
func (c *Checker) runOnce(ctx context.Context, s Scope, h Handler) {
	defer func() {
		if r := recover(); r != nil {
			c.reportError(fmt.Errorf("selfcheck: panic during check: %v", r))
		}
	}()
	res, err := c.Check(ctx, s)
	if err != nil {
		// A cancelled context is a shutdown, not a failure.
		if ctx.Err() == nil {
			c.reportError(err)
		}
		return
	}
	defer func() {
		if r := recover(); r != nil {
			c.reportError(fmt.Errorf("selfcheck: panic in handler: %v", r))
		}
	}()
	h(res)
}

// nextInterval returns the delay before the next check, jittered around the
// configured interval.
func (c *Checker) nextInterval() time.Duration {
	if c.cfg.jitter <= 0 {
		return c.cfg.interval
	}
	spread := time.Duration(float64(c.cfg.interval) * c.cfg.jitter)
	if spread <= 0 {
		return c.cfg.interval
	}
	// Uniform in [-spread, +spread], so jitter 0.2 means ±20%.
	off := time.Duration(rand.Int63n(int64(2*spread)+1)) - spread
	d := c.cfg.interval + off
	if d < time.Second {
		// Never busy-loop, however the options are combined.
		return time.Second
	}
	return d
}

func (c *Checker) reportError(err error) {
	if c.cfg.onError != nil {
		c.cfg.onError(err)
		return
	}
	if c.cfg.logger != nil {
		c.cfg.logger.Error("self-check failed", "err", err)
	}
}
