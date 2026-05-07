package cache

import (
	"container/heap"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kkkgo/mini-ppdns/pkg/concurrent_map"
)

// defaultJanitorTick is how often the background janitor wakes up to
// sweep expired entries when the caller did not specify an interval.
const defaultJanitorTick = 10 * time.Second

// heapCompactRatio controls when the janitor rebuilds expHeap from the live
// map. The heap carries stale entries left over from Store refreshes on an
// already-queued key; lazy eviction at pop time keeps correctness, but under
// sustained high refresh rates (e.g., 1-second fallback TTLs under QPS) the
// stale backlog is bounded by store_rate × TTL, which can reach millions of
// entries before the oldest expirations catch up. Rebuilding when the heap
// exceeds heapCompactRatio × live entries amortizes O(N) work infrequently
// while capping worst-case RSS.
const heapCompactRatio = 4

// heapCompactMin is the absolute size below which compaction never runs —
// tiny heaps are not worth the Range walk.
const heapCompactMin = 1024

type Hashable interface {
	comparable
	Sum() uint64
}

// Key is the interface every cache key must satisfy (equality + a hash
// that shards can bucket on).
type Key interface {
	Hashable
}

// Value is the interface for stored values. Currently unrestricted —
// left as a named type so callers can spot cache-specific constraints if
// we tighten it later.
type Value interface {
	any
}

// Cache is a concurrent TTL-keyed cache on top of concurrent_map.
type Cache[K Key, V Value] struct {
	closed      atomic.Bool
	closeNotify chan struct{}
	m           *concurrent_map.Map[K, *elem[V]]

	// flushMu is the gate that keeps Store's two-step write (shard write +
	// heap push) atomic with respect to Flush/Close. Store holds RLock so
	// many Stores can proceed in parallel; Flush/Close hold the write lock
	// to drain in-flight Stores before clearing or shutting down. Without
	// this, a Store interleaved between Flush's m.Flush() and the heap
	// reset could leave a live map entry with no heap entry — janitor
	// drives eviction off the heap, so that entry would leak forever.
	flushMu sync.RWMutex

	// expHeap is a min-heap keyed by expirationTime so the janitor can
	// process expired entries in O(k log N) (k = expired count) instead
	// of walking the whole map every tick. Stale entries (from Store
	// refreshes on an already-queued key) are filtered out at pop time
	// by re-checking the current expiration under the shard lock.
	heapMu  sync.Mutex
	expHeap expHeap[K]
}

type Opts struct {
	// Size is the soft total capacity. The realized ceiling is slightly
	// below Size because the underlying sharded map rounds down.
	Size int
	// CleanerInterval controls the janitor's tick. Zero uses the default.
	CleanerInterval time.Duration
}

func (opts *Opts) init() {
	if opts.Size == 0 {
		opts.Size = 1024
	}
	if opts.CleanerInterval == 0 {
		opts.CleanerInterval = defaultJanitorTick
	}
}

type elem[V Value] struct {
	v              V
	expirationTime time.Time
}

// New builds a cache and starts its background janitor. Close the cache
// when done to stop the janitor goroutine.
func New[K Key, V Value](opts Opts) *Cache[K, V] {
	opts.init()
	c := &Cache[K, V]{
		closeNotify: make(chan struct{}),
		m:           concurrent_map.NewMapCache[K, *elem[V]](opts.Size),
	}
	go c.janitor(opts.CleanerInterval)
	return c
}

// Close stops the janitor. Subsequent Store calls are silently dropped
// so the map can't grow once nothing is reaping it. Calling Close more
// than once is safe and always returns nil.
func (c *Cache[K, V]) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	// Wait for any Store mid-flight (between TestAndSet and heap.Push) to
	// drain. Without this barrier a Store that already passed the closed
	// check could heap.Push into a heap that nothing reaps, leaving a
	// matching map entry permanently parked. The empty critical section
	// is the barrier itself: acquiring the write lock blocks until every
	// in-flight RLock holder releases, then we let go immediately.
	c.drainInflightStores()
	close(c.closeNotify)
	return nil
}

// drainInflightStores blocks until every Store call that already saw
// closed=false has finished its heap.Push. Acquiring flushMu.Lock waits
// for every outstanding RLock holder; the immediate Unlock is correct
// because Close has already set closed=true, so any Store that wakes
// after we release will hit the closed check and bail. The empty
// critical section is the barrier itself, not a coding mistake.
func (c *Cache[K, V]) drainInflightStores() {
	c.flushMu.Lock()
	//lint:ignore SA2001 empty critical section is the drain barrier
	c.flushMu.Unlock()
}

// Get returns the value for key if present and unexpired. Expired
// entries are removed in-place, unless a concurrent Store refreshed the
// entry between our read and the write-locked recheck — in which case
// we surface the fresher value instead of reporting a miss.
func (c *Cache[K, V]) Get(key K) (v V, expirationTime time.Time, ok bool) {
	ev, found := c.m.Get(key)
	if !found {
		return
	}
	now := time.Now()
	if ev.expirationTime.After(now) {
		return ev.v, ev.expirationTime, true
	}

	// Entry looks expired. Double-check under the shard write lock so a
	// parallel Store isn't clobbered by our eviction. Reuse `now` —
	// widening the TOCTOU window by a few microseconds has no effect on
	// TTL semantics but avoids a second syscall.
	var (
		freshV   V
		freshExp time.Time
		freshOK  bool
	)
	c.m.TestAndSet(key, func(cur *elem[V], present bool) (newV *elem[V], setV, delV bool) {
		if !present {
			return nil, false, false
		}
		if cur.expirationTime.After(now) {
			freshV, freshExp, freshOK = cur.v, cur.expirationTime, true
			return nil, false, false
		}
		return nil, false, true
	})
	if freshOK {
		return freshV, freshExp, true
	}
	return
}

// Store writes key → v with the given expiration. If expirationTime is
// already in the past, the call is a no-op. Stores after Close are
// dropped silently.
func (c *Cache[K, V]) Store(key K, v V, expirationTime time.Time) {
	// flushMu.RLock pairs the shard write and heap push into one atomic
	// segment relative to Flush/Close. Many Stores still proceed in
	// parallel — only Flush/Close take the write lock.
	c.flushMu.RLock()
	defer c.flushMu.RUnlock()
	if c.closed.Load() {
		return
	}
	// Time check inside the lock: a single time.Now() reading also covers
	// the TestAndSet decision, eliminating the pre-lock TOCTOU where wall
	// clock crosses expirationTime between the check and the write. Reject
	// expirationTime == now too: Get treats equal-instant entries as
	// expired (After is strict), so storing one would leak a permanently
	// unreadable entry until the janitor reaps it.
	if !expirationTime.After(time.Now()) {
		return
	}
	// Use Set rather than TestAndSet: the closure variant boxed the entry
	// pointer plus three captured locals (stored, v, expirationTime) into a
	// per-call heap allocation on every Store, and concurrent_map's Set
	// path enforces the per-shard cap that TestAndSet silently bypasses
	// (set() at concurrent_map/map.go:146 random-evicts when full;
	// testAndSet has no len() check). Net effect: the configured cache cap
	// finally takes effect AND each Store no longer pays a closure
	// allocation.
	c.m.Set(key, &elem[V]{v: v, expirationTime: expirationTime})
	// Enqueue for the janitor. A Store that updates an existing key
	// leaves a stale heap entry with the old expiration — handled at
	// pop time by re-checking the current expiration (see evictExpired).
	c.heapMu.Lock()
	heap.Push(&c.expHeap, expEntry[K]{key: key, expirationTime: expirationTime})
	c.heapMu.Unlock()
}

// Range walks every entry, calling f for each. Returning false from f
// stops the walk early. Entries may be visited in any order, and new
// entries stored during the walk may or may not be observed.
func (c *Cache[K, V]) Range(f func(key K, v V, expirationTime time.Time) bool) {
	c.m.Range(func(k K, e *elem[V]) bool {
		return f(k, e.v, e.expirationTime)
	})
}

// Len is the current entry count. Racing with Store/evict is allowed;
// callers treat the result as an estimate.
func (c *Cache[K, V]) Len() int {
	return c.m.Len()
}

// Flush drops every entry.
func (c *Cache[K, V]) Flush() {
	// Hold flushMu.Lock so no Store can interleave between m.Flush and
	// the heap reset. Without it, a Store that wrote its map entry after
	// m.Flush() but pushed onto the heap before this reset would survive
	// the map flush and lose its heap entry — an unreapable ghost.
	c.flushMu.Lock()
	defer c.flushMu.Unlock()
	c.m.Flush()
	c.heapMu.Lock()
	c.expHeap = c.expHeap[:0]
	c.heapMu.Unlock()
}

// janitor runs expired-entry eviction on a ticker until the cache is
// closed.
func (c *Cache[K, V]) janitor(tick time.Duration) {
	if tick <= 0 {
		tick = defaultJanitorTick
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-c.closeNotify:
			return
		case now := <-t.C:
			c.evictExpired(now)
			c.maybeCompactHeap()
		}
	}
}

// maybeCompactHeap rebuilds expHeap from the live map when the stale-entry
// backlog outweighs the live entries. Lazy eviction alone is correct but
// O(store_rate × TTL) in memory when keys are refreshed faster than their
// TTL expires; compaction bounds the heap at roughly live entry count.
//
// Rebuild cost is O(M) where M is the live entry count: Range walks the
// sharded map once, heap.Init uses Floyd's bottom-up heapify (O(M)).
// heapMu is held for the duration — concurrent Store's heap.Push blocks
// briefly but map writes (under the shard lock) proceed unimpeded, so any
// Store races either land in the Range walk (heap has their entry) or push
// onto the rebuilt heap after we unlock (also covered). A stale duplicate
// is tolerated; a missed live entry would silently leak and is not.
func (c *Cache[K, V]) maybeCompactHeap() {
	c.heapMu.Lock()
	defer c.heapMu.Unlock()
	heapLen := len(c.expHeap)
	if heapLen < heapCompactMin {
		return
	}
	live := c.m.Len()
	if heapLen <= live*heapCompactRatio {
		return
	}
	rebuilt := make(expHeap[K], 0, live)
	c.m.Range(func(k K, e *elem[V]) bool {
		rebuilt = append(rebuilt, expEntry[K]{key: k, expirationTime: e.expirationTime})
		return true
	})
	heap.Init(&rebuilt)
	c.expHeap = rebuilt
}

// expiredStackLimit is the largest expired-batch we can drain without a
// heap allocation. The stack-backed slice grows transparently into a heap
// slice past this point — the limit just sets the no-alloc fast-path size.
// 256 covers a steady-state tick on a healthy cache; bursty expirations
// (e.g. a fall-path TTL=1 flood) overflow gracefully without losing the
// fast path on the next tick.
const expiredStackLimit = 256

// evictExpired pops every heap entry whose expiration has passed and
// removes the corresponding map entry — as long as a concurrent Store
// hasn't refreshed the expiration meanwhile (in which case a newer
// heap entry already covers the next eviction deadline and we leave
// the map entry alone).
func (c *Cache[K, V]) evictExpired(now time.Time) {
	// Drain every ready-to-expire heap entry under a single heapMu
	// acquisition. The previous one-pop-per-lock loop paid the lock/unlock
	// cost per expired key — under high refresh rates (e.g. many 1s-TTL
	// fallback entries) that turned into heavy contention with concurrent
	// Store's heap.Push. Collect first, release, then do the per-key
	// TestAndSet work lock-free w.r.t. heapMu.
	//
	// Back the collection slice with a stack array so the common low-
	// expiration tick allocates nothing. Once append exceeds the stack
	// capacity it falls back to heap allocation, which is fine — that
	// only happens on burst ticks where the alloc cost is amortized.
	var stackBuf [expiredStackLimit]expEntry[K]
	expired := stackBuf[:0]
	c.heapMu.Lock()
	for len(c.expHeap) > 0 && !c.expHeap[0].expirationTime.After(now) {
		expired = append(expired, heap.Pop(&c.expHeap).(expEntry[K]))
	}
	c.heapMu.Unlock()

	for _, top := range expired {
		c.m.TestAndSet(top.key, func(cur *elem[V], present bool) (newV *elem[V], setV, delV bool) {
			if !present {
				return nil, false, false
			}
			// The stored expiration may have moved later due to a
			// Store after this heap entry was queued. In that case
			// a newer heap entry already tracks the current deadline
			// — drop this one without touching the map.
			if cur.expirationTime.After(now) {
				return nil, false, false
			}
			return nil, false, true
		})
	}
}

// expEntry is one slot in the expiration min-heap.
type expEntry[K comparable] struct {
	key            K
	expirationTime time.Time
}

// expHeap implements container/heap.Interface, ordering by earliest
// expirationTime first.
type expHeap[K comparable] []expEntry[K]

func (h expHeap[K]) Len() int           { return len(h) }
func (h expHeap[K]) Less(i, j int) bool { return h[i].expirationTime.Before(h[j].expirationTime) }
func (h expHeap[K]) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expHeap[K]) Push(x any)        { *h = append(*h, x.(expEntry[K])) }
func (h *expHeap[K]) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}
