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
	c.Range(func(k testKey, v int, expT time.Time) bool {
		count++
		return true
	})
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

func TestCache_EvictExpiredHeap(t *testing.T) {
	c := New[testKey, int](Opts{Size: 1024, CleanerInterval: time.Hour})
	defer c.Close()

	now := time.Now()
	// Mix of past and future expirations, out-of-order insertion to
	// exercise heap ordering rather than insertion order.
	c.Store(1, 1, now.Add(-2*time.Second)) // already expired (will be filtered by Store)
	c.Store(2, 2, now.Add(time.Hour))      // alive
	c.Store(3, 3, now.Add(10*time.Minute)) // alive
	c.Store(4, 4, now.Add(time.Hour*2))    // alive

	// Simulate tick "slightly after now": key 1 wasn't actually stored
	// (past exp), so the alive entries should stay untouched.
	c.evictExpired(now.Add(time.Second))

	for _, k := range []testKey{2, 3, 4} {
		if _, _, ok := c.Get(k); !ok {
			t.Fatalf("alive key %d missing after evict", k)
		}
	}
}

func TestCache_HeapStaleEntryIgnored(t *testing.T) {
	c := New[testKey, int](Opts{Size: 1024, CleanerInterval: time.Hour})
	defer c.Close()

	base := time.Now()
	// Store with short expiration, then immediately refresh with a
	// longer one. The first heap entry is stale; when the janitor
	// later pops it, it must see the refreshed (later) expiration and
	// skip deletion instead of clobbering live data.
	c.Store(1, 100, base.Add(50*time.Millisecond))
	c.Store(1, 200, base.Add(time.Hour))

	// Tick "after the original expiration" — the stale heap entry has
	// key 1, exp=base+50ms; cur exp is base+1h > tick time, so evict
	// must leave the entry alone.
	c.evictExpired(base.Add(time.Second))

	v, _, ok := c.Get(1)
	if !ok || v != 200 {
		t.Fatalf("after stale-heap-entry sweep: got (%d, %v), want (200, true)", v, ok)
	}
}

func TestCache_HeapCompactBoundsStaleGrowth(t *testing.T) {
	// Simulate a workload that refreshes the same key many times with a
	// future TTL — exactly the pathology that used to make expHeap grow
	// without bound (stale entries only drain at the old expiration time).
	// After the janitor's compaction runs, the heap must collapse down to
	// roughly the live map size.
	c := New[testKey, int](Opts{Size: 1024, CleanerInterval: time.Hour})
	defer c.Close()

	exp := time.Now().Add(time.Hour)
	const refreshes = 4096
	for i := 0; i < refreshes; i++ {
		c.Store(1, i, exp)
	}
	if c.Len() != 1 {
		t.Fatalf("map should still have 1 entry, got %d", c.Len())
	}
	c.heapMu.Lock()
	staleLen := len(c.expHeap)
	c.heapMu.Unlock()
	if staleLen < refreshes {
		t.Fatalf("expected heap to hold all stale entries pre-compact, got %d", staleLen)
	}

	c.maybeCompactHeap()

	c.heapMu.Lock()
	compactedLen := len(c.expHeap)
	c.heapMu.Unlock()
	if compactedLen != c.Len() {
		t.Fatalf("heap len after compact = %d, want %d (map size)", compactedLen, c.Len())
	}

	// Post-compact: the live value must still be retrievable with the
	// correct expiration, and a subsequent evictExpired at that expiration
	// must remove the map entry (proving the rebuilt heap keyed on the
	// current expiration, not any stale one).
	v, gotExp, ok := c.Get(1)
	if !ok || v != refreshes-1 || !gotExp.Equal(exp) {
		t.Fatalf("after compact Get = (%d, %v, %v), want (%d, %v, true)",
			v, gotExp, ok, refreshes-1, exp)
	}
	c.evictExpired(exp.Add(time.Second))
	if _, _, ok := c.Get(1); ok {
		t.Fatal("after evictExpired past exp: entry should be gone")
	}
}

// TestCache_StoreEnforcesSizeCap is a regression test for the Store
// implementation switching from concurrent_map.TestAndSet to Set. The
// previous TestAndSet path silently bypassed the per-shard cap that
// concurrent_map.Set enforces (testAndSet has no len() check; set
// random-evicts when full). With many distinct keys inserted into a
// small cache, Len must remain bounded by the configured cap.
//
// The cap is applied per shard (MapShardSize=32), so a Size of 64
// yields a per-shard cap of 2 and a global ceiling of 64. We insert
// 32 * 32 = 1024 distinct keys to make every shard saturate well past
// its cap; if eviction fails, Len() would blow far past 64.
func TestCache_StoreEnforcesSizeCap(t *testing.T) {
	const sizeCap = 64
	c := New[testKey, int](Opts{Size: sizeCap, CleanerInterval: time.Hour})
	defer c.Close()

	exp := time.Now().Add(time.Minute)
	for i := testKey(0); i < 1024; i++ {
		c.Store(i, int(i), exp)
	}

	got := c.Len()
	if got > sizeCap {
		t.Fatalf("Len after 1024 inserts = %d; expected <= sizeCap=%d (cap not enforced)", got, sizeCap)
	}
	// Sanity: cache must be non-empty too — a zero count would mean Set
	// is dropping every store, which would break the cache outright.
	if got == 0 {
		t.Fatal("Len = 0; cache appears to be dropping every Store")
	}
}

func TestCache_EvictExpiredPopsInOrder(t *testing.T) {
	c := New[testKey, int](Opts{Size: 1024, CleanerInterval: time.Hour})
	defer c.Close()

	now := time.Now()
	// Deliberately insert with later expirations first so heap
	// ordering (not insertion order) determines pop sequence.
	c.Store(3, 3, now.Add(3*time.Second))
	c.Store(1, 1, now.Add(1*time.Second))
	c.Store(2, 2, now.Add(2*time.Second))
	c.Store(4, 4, now.Add(time.Hour)) // alive

	// Tick at now+2.5s: keys 1 and 2 must be evicted; 3 and 4 remain.
	c.evictExpired(now.Add(2500 * time.Millisecond))

	for _, k := range []testKey{1, 2} {
		if _, _, ok := c.Get(k); ok {
			t.Fatalf("expired key %d should have been evicted", k)
		}
	}
	for _, k := range []testKey{3, 4} {
		if _, _, ok := c.Get(k); !ok {
			t.Fatalf("live key %d should still be in cache", k)
		}
	}
}
