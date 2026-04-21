package concurrent_map

import (
	"sync"
)

// MapShardSize is the number of independent shards. Lower than most
// sharded-map implementations because DNS workloads tend to have moderate
// concurrency — 32 well-spread shards already take lock contention off
// the critical path, and a smaller number keeps Len() / Flush() cheap.
const MapShardSize = 32

// Hashable is the key interface. Implementations Sum() a uint64 that is
// then modded down to pick a shard; if two distinct keys hash to the same
// bucket, equality falls back to the language-level == comparison.
type Hashable interface {
	comparable
	Sum() uint64
}

// TestAndSetFunc reports what should happen to the value for a given key
// after observing its current state. setV and deleteV are mutually
// exclusive; if both are false, the entry is left untouched.
type TestAndSetFunc[K comparable, V any] func(key K, v V, ok bool) (newV V, setV, deleteV bool)

// Map is a concurrent, sharded generic map.
type Map[K Hashable, V any] struct {
	shards [MapShardSize]shard[K, V]
}

// NewMap creates an unbounded concurrent map.
func NewMap[K Hashable, V any]() *Map[K, V] {
	return newMapWithShardCap[K, V](0)
}

// NewMapCache creates a concurrent map with a soft per-shard capacity.
// Because the limit is applied per shard, the realized ceiling is
// MapShardSize * (size / MapShardSize), which rounds slightly below the
// requested size when size is not a multiple of MapShardSize. Passing
// size <= 0 disables the limit (equivalent to NewMap).
func NewMapCache[K Hashable, V any](size int) *Map[K, V] {
	return newMapWithShardCap[K, V](size / MapShardSize)
}

func newMapWithShardCap[K Hashable, V any](perShardMax int) *Map[K, V] {
	m := new(Map[K, V])
	for i := range m.shards {
		m.shards[i] = newShard[K, V](perShardMax)
	}
	return m
}

func (m *Map[K, V]) pickShard(key K) *shard[K, V] {
	return &m.shards[key.Sum()%MapShardSize]
}

// Get returns the value associated with key and whether the key was present.
func (m *Map[K, V]) Get(key K) (V, bool) {
	return m.pickShard(key).get(key)
}

// Set stores v under key, evicting a pseudo-random existing entry if the
// shard is at its capacity cap.
func (m *Map[K, V]) Set(key K, v V) {
	m.pickShard(key).set(key, v)
}

// Del removes key; a no-op if the key is not present.
func (m *Map[K, V]) Del(key K) {
	m.pickShard(key).del(key)
}

// TestAndSet atomically reads the current value for key and applies the
// caller's decision (update, delete, or leave alone) under the shard lock.
func (m *Map[K, V]) TestAndSet(key K, f func(v V, ok bool) (newV V, setV, delV bool)) {
	m.pickShard(key).testAndSet(key, f)
}

// Len returns the total entry count across all shards. The sum is taken
// under each shard's read lock individually; mutations happening during
// the call may be counted inconsistently, which is acceptable for the
// sampling use cases this is designed for.
func (m *Map[K, V]) Len() int {
	total := 0
	for i := range m.shards {
		total += m.shards[i].len()
	}
	return total
}

// Flush drops every entry.
func (m *Map[K, V]) Flush() {
	for i := range m.shards {
		m.shards[i].flush()
	}
}

// Range visits every (key, value) pair exactly once in unspecified order.
// Returning false from f stops the walk.
func (m *Map[K, V]) Range(f func(k K, v V) bool) {
	for i := range m.shards {
		if !m.shards[i].rangeReadOnly(f) {
			return
		}
	}
}

// RangeDo walks every entry and lets f mutate or delete it. Unlike Range,
// each shard is taken under its write lock so f observes a consistent
// view for the entries it visits. If f returns a non-nil error the walk
// aborts immediately.
func (m *Map[K, V]) RangeDo(f func(k K, v V) (newV V, setV, delV bool, err error)) error {
	for i := range m.shards {
		if err := m.shards[i].rangeDo(f); err != nil {
			return err
		}
	}
	return nil
}

// ---- shard ----

type shard[K comparable, V any] struct {
	l   sync.RWMutex
	max int // 0 or negative means unbounded.
	m   map[K]V
}

func newShard[K comparable, V any](max int) shard[K, V] {
	return shard[K, V]{
		max: max,
		m:   make(map[K]V),
	}
}

func (s *shard[K, V]) get(key K) (V, bool) {
	s.l.RLock()
	defer s.l.RUnlock()
	v, ok := s.m[key]
	return v, ok
}

func (s *shard[K, V]) set(key K, v V) {
	s.l.Lock()
	defer s.l.Unlock()
	if s.max > 0 && len(s.m) >= s.max {
		// Random eviction is a deliberate CPU-saving trade-off, not a TODO.
		// An LRU policy would require maintaining a doubly-linked recency
		// list touched on every Get and Set, doubling the per-op write
		// work and holding the shard lock longer. For DNS caching the
		// workload is TTL-dominated — entries expire faster than they
		// would be evicted by LRU pressure — so the hit-rate penalty of
		// randomized eviction is negligible compared with the lock-hold
		// savings. Go's randomized map iteration gives us a jittered
		// victim for free. If a future workload genuinely needs strict
		// recency semantics, swap in concurrent_lru.ShardedLRU.
		for k := range s.m {
			delete(s.m, k)
			break
		}
	}
	s.m[key] = v
}

func (s *shard[K, V]) del(key K) {
	s.l.Lock()
	defer s.l.Unlock()
	delete(s.m, key)
}

func (s *shard[K, V]) testAndSet(key K, f func(v V, ok bool) (newV V, setV, delV bool)) {
	s.l.Lock()
	defer s.l.Unlock()
	v, ok := s.m[key]
	newV, setV, deleteV := f(v, ok)
	switch {
	case setV:
		s.m[key] = newV
	case deleteV && ok:
		delete(s.m, key)
	}
}

func (s *shard[K, V]) len() int {
	s.l.RLock()
	defer s.l.RUnlock()
	return len(s.m)
}

func (s *shard[K, V]) flush() {
	s.l.Lock()
	defer s.l.Unlock()
	s.m = make(map[K]V)
}

func (s *shard[K, V]) rangeReadOnly(f func(k K, v V) bool) bool {
	s.l.RLock()
	defer s.l.RUnlock()
	for k, v := range s.m {
		if !f(k, v) {
			return false
		}
	}
	return true
}

func (s *shard[K, V]) rangeDo(f func(k K, v V) (newV V, setV, delV bool, err error)) error {
	s.l.Lock()
	defer s.l.Unlock()
	for k, v := range s.m {
		newV, setV, deleteV, err := f(k, v)
		if err != nil {
			return err
		}
		switch {
		case setV:
			s.m[k] = newV
		case deleteV:
			delete(s.m, k)
		}
	}
	return nil
}
