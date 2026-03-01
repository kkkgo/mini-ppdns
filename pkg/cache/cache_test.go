package cache

import (
	"testing"
	"time"
)

type testKey uint64

func (k testKey) Sum() uint64 { return uint64(k) }

func TestCache_StoreGet(t *testing.T) {
	c := New[testKey, string](Opts{Size: 1024, CleanerInterval: time.Hour})
	defer c.Close()

	exp := time.Now().Add(time.Minute)
	c.Store(1, "hello", exp)

	v, expTime, ok := c.Get(1)
	if !ok {
		t.Fatal("Get should return true")
	}
	if v != "hello" {
		t.Fatalf("v = %q, want hello", v)
	}
	if !expTime.Equal(exp) {
		t.Fatalf("expiration mismatch")
	}
}

func TestCache_GetMiss(t *testing.T) {
	c := New[testKey, int](Opts{Size: 1024, CleanerInterval: time.Hour})
	defer c.Close()

	_, _, ok := c.Get(1)
	if ok {
		t.Fatal("Get on empty cache should return false")
	}
}

func TestCache_StoreExpired(t *testing.T) {
	c := New[testKey, string](Opts{Size: 1024, CleanerInterval: time.Hour})
	defer c.Close()

	// Store with past expiration should be noop
	c.Store(1, "expired", time.Now().Add(-time.Second))

	_, _, ok := c.Get(1)
	if ok {
		t.Fatal("expired entry should not be stored")
	}
}

func TestCache_GetExpiredEntry(t *testing.T) {
	c := New[testKey, string](Opts{Size: 1024, CleanerInterval: time.Hour})
	defer c.Close()

	// Store with very short TTL
	c.Store(1, "short", time.Now().Add(50*time.Millisecond))
	time.Sleep(100 * time.Millisecond)

	_, _, ok := c.Get(1)
	if ok {
		t.Fatal("expired entry should not be returned by Get")
	}
}

func TestCache_Range(t *testing.T) {
	c := New[testKey, int](Opts{Size: 1024, CleanerInterval: time.Hour})
	defer c.Close()

	exp := time.Now().Add(time.Minute)
	c.Store(1, 10, exp)
	c.Store(2, 20, exp)
	c.Store(3, 30, exp)

	count := 0
	err := c.Range(func(k testKey, v int, expT time.Time) error {
		count++
		return nil
	})
	if err != nil {
		t.Fatalf("Range err: %v", err)
	}
	if count != 3 {
		t.Fatalf("Range count = %d, want 3", count)
	}
}

func TestCache_Len(t *testing.T) {
	c := New[testKey, int](Opts{Size: 1024, CleanerInterval: time.Hour})
	defer c.Close()

	if c.Len() != 0 {
		t.Fatalf("empty len = %d, want 0", c.Len())
	}

	exp := time.Now().Add(time.Minute)
	c.Store(1, 1, exp)
	c.Store(2, 2, exp)

	if c.Len() != 2 {
		t.Fatalf("len = %d, want 2", c.Len())
	}
}

func TestCache_Flush(t *testing.T) {
	c := New[testKey, int](Opts{Size: 1024, CleanerInterval: time.Hour})
	defer c.Close()

	exp := time.Now().Add(time.Minute)
	c.Store(1, 1, exp)
	c.Store(2, 2, exp)
	c.Flush()

	if c.Len() != 0 {
		t.Fatalf("len after flush = %d, want 0", c.Len())
	}
}

func TestCache_Close(t *testing.T) {
	c := New[testKey, int](Opts{Size: 1024, CleanerInterval: time.Millisecond * 50})
	if err := c.Close(); err != nil {
		t.Fatalf("Close err: %v", err)
	}
	// Double close should not panic
	c.Close()
}

func TestCache_DefaultOpts(t *testing.T) {
	// Zero opts should work with defaults
	c := New[testKey, int](Opts{})
	defer c.Close()

	exp := time.Now().Add(time.Minute)
	c.Store(1, 42, exp)
	v, _, ok := c.Get(1)
	if !ok || v != 42 {
		t.Fatalf("Get(1) = %d, %v, want 42, true", v, ok)
	}
}
