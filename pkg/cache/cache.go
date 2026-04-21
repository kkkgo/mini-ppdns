package cache

import (
	"sync/atomic"
	"time"

	"github.com/kkkgo/mini-ppdns/pkg/concurrent_map"
)

// defaultJanitorTick is how often the background janitor wakes up to
// sweep expired entries when the caller did not specify an interval.
const defaultJanitorTick = 10 * time.Second

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
	opts Opts

	closed      atomic.Bool
	closeNotify chan struct{}
	m           *concurrent_map.Map[K, *elem[V]]
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
	if c.closed.CompareAndSwap(false, true) {
		close(c.closeNotify)
	}
	return nil
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
	if ev.expirationTime.After(time.Now()) {
		return ev.v, ev.expirationTime, true
	}

	// Entry looks expired. Double-check under the shard write lock so a
	// parallel Store isn't clobbered by our eviction.
	var (
		freshV   V
		freshExp time.Time
		freshOK  bool
	)
	c.m.TestAndSet(key, func(cur *elem[V], present bool) (newV *elem[V], setV, delV bool) {
		if !present {
			return nil, false, false
		}
		if cur.expirationTime.After(time.Now()) {
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
	if time.Now().After(expirationTime) {
		return
	}
	// Re-check closed inside the shard write lock so the tiny window between
	// Store's pre-check and Set (during which Close may have stopped the
	// janitor) cannot leave an entry in the map with no reaper.
	c.m.TestAndSet(key, func(_ *elem[V], _ bool) (newV *elem[V], setV, delV bool) {
		if c.closed.Load() {
			return nil, false, false
		}
		return &elem[V]{v: v, expirationTime: expirationTime}, true, false
	})
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
	c.m.Flush()
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
		}
	}
}

// evictExpired walks every shard under its write lock and removes
// entries whose expiration has already passed. Done as a single pass so
// writers are blocked only during the walk of each shard, not through a
// separate collect+delete round.
func (c *Cache[K, V]) evictExpired(now time.Time) {
	_ = c.m.RangeDo(func(k K, e *elem[V]) (newV *elem[V], setV, delV bool, err error) {
		if now.After(e.expirationTime) {
			return nil, false, true, nil
		}
		return nil, false, false, nil
	})
}
