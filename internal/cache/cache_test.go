package cache

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGetSetExpiry(t *testing.T) {
	c := New()
	if _, ok := c.Get("missing"); ok {
		t.Fatal("empty cache returned a value")
	}
	c.Set("a", 1, time.Minute)
	if v, ok := c.Get("a"); !ok || v != 1 {
		t.Fatalf("got %v %v", v, ok)
	}
	c.Set("b", 2, 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	if _, ok := c.Get("b"); ok {
		t.Error("an expired entry should not be returned")
	}
	c.Set("c", 3, 0)
	time.Sleep(5 * time.Millisecond)
	if _, ok := c.Get("c"); !ok {
		t.Error("a zero ttl should not expire")
	}
	c.Delete("a")
	if _, ok := c.Get("a"); ok {
		t.Error("deleted entry returned")
	}
}

func TestDoCollapsesConcurrentCalls(t *testing.T) {
	c := New()
	var calls atomic.Int32
	release := make(chan struct{})
	fn := func() (any, error) {
		calls.Add(1)
		<-release
		return "value", nil
	}
	const n = 20
	var wg sync.WaitGroup
	results := make([]any, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, err := c.Do("key", fn)
			if err != nil {
				t.Error(err)
			}
			results[i] = v
		}(i)
	}
	time.Sleep(50 * time.Millisecond) // let the goroutines pile up on the flight
	close(release)
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Errorf("fn ran %d times, want 1", got)
	}
	for i, v := range results {
		if v != "value" {
			t.Errorf("result %d = %v", i, v)
		}
	}
	// A later call is a new flight.
	if _, err := c.Do("key", func() (any, error) { return "again", nil }); err != nil {
		t.Fatal(err)
	}
}

func TestDoDistinctKeysDoNotBlock(t *testing.T) {
	c := New()
	started := make(chan struct{})
	blocked := make(chan struct{})
	go func() {
		_, _ = c.Do("slow", func() (any, error) {
			close(started)
			<-blocked
			return nil, nil
		})
	}()
	<-started
	done := make(chan struct{})
	go func() {
		_, _ = c.Do("fast", func() (any, error) { return "ok", nil })
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("an unrelated key was blocked by a slow fetch")
	}
	close(blocked)
}

func TestDoPropagatesError(t *testing.T) {
	c := New()
	want := errors.New("boom")
	_, err := c.Do("k", func() (any, error) { return nil, want })
	if !errors.Is(err, want) {
		t.Fatalf("err = %v", err)
	}
	// The failed flight must be forgotten, so a retry runs again.
	if _, err := c.Do("k", func() (any, error) { return "ok", nil }); err != nil {
		t.Fatal(err)
	}
}

func TestDoPanicReleasesWaiters(t *testing.T) {
	c := New()
	release := make(chan struct{})
	go func() {
		defer func() { _ = recover() }()
		_, _ = c.Do("k", func() (any, error) {
			close(release)
			panic("boom")
		})
	}()
	<-release
	done := make(chan struct{})
	go func() {
		// This must not block forever once the panicking flight is finished.
		_, _ = c.Do("k", func() (any, error) { return "ok", nil })
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a panicking flight left a waiter blocked")
	}
}
