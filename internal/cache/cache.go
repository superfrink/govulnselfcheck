// Package cache holds the two things a database client needs to be polite:
// short-lived memoisation and collapsing of identical concurrent requests.
//
// It is deliberately small. A vulnerability database is a few megabytes of
// index plus a scattered set of entries; what matters is not fetching them more
// often than necessary, and not having ten replicas' worth of checks arrive at
// once from a single process.
package cache

import (
	"sync"
	"time"
)

// Cache is a TTL map with single-flight.
//
// Two operations: Do runs a function for a key, sharing the result with any
// concurrent call for the same key; Set/Get store a value with a TTL so a
// later, quieter call can reuse it.
type Cache struct {
	mu      sync.Mutex
	entries map[string]item
	flights map[string]*flight
}

type item struct {
	value  any
	expiry time.Time
}

type flight struct {
	done  chan struct{}
	value any
	err   error
}

// New returns an empty cache.
func New() *Cache {
	return &Cache{entries: map[string]item{}, flights: map[string]*flight{}}
}

// Get returns a value that has not expired.
func (c *Cache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	it, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !it.expiry.IsZero() && time.Now().After(it.expiry) {
		delete(c.entries, key)
		return nil, false
	}
	return it.value, true
}

// Set stores a value. A zero ttl stores it without expiry.
func (c *Cache) Set(key string, value any, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]item{}
	}
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	c.entries[key] = item{value: value, expiry: exp}
}

// Delete forgets a key.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Do calls fn for key. Concurrent calls with the same key wait for the first
// one and share its result instead of calling fn again.
//
// fn runs outside the lock, so a slow fetch does not block unrelated keys.
func (c *Cache) Do(key string, fn func() (any, error)) (any, error) {
	c.mu.Lock()
	if c.flights == nil {
		c.flights = map[string]*flight{}
	}
	if f, ok := c.flights[key]; ok {
		c.mu.Unlock()
		<-f.done
		return f.value, f.err
	}
	f := &flight{done: make(chan struct{})}
	c.flights[key] = f
	c.mu.Unlock()

	// A panic in fn must not leave waiters blocked forever, and must not be
	// swallowed silently either: the panic propagates, waiters see an error.
	func() {
		defer func() {
			if r := recover(); r != nil {
				f.err = errPanic{r}
				c.finish(key, f)
				panic(r)
			}
		}()
		f.value, f.err = fn()
		c.finish(key, f)
	}()
	return f.value, f.err
}

func (c *Cache) finish(key string, f *flight) {
	c.mu.Lock()
	delete(c.flights, key)
	c.mu.Unlock()
	close(f.done)
}

type errPanic struct{ v any }

func (e errPanic) Error() string { return "cache: panic in flight" }
