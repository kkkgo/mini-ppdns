package concurrent_lru

import (
	"sync"
	"testing"
)

// testKey implements Hashable for testing.
type testKey uint64

func (k testKey) Sum() uint64 { return uint64(k) }

func TestConcurrentLRU_Basic(t *testing.T) {
	l := NewConecurrentLRU[testKey, string](10, nil)
	l.Add(1, "a")
	l.Add(2, "b")

	v, ok := l.Get(1)
	if !ok || v != "a" {
		t.Fatalf("Get(1) = %q, %v, want a, true", v, ok)
	}

	_, ok = l.Get(99)
	if ok {
		t.Fatal("Get(99) should return false")
	}
}

func TestConcurrentLRU_Del(t *testing.T) {
	l := NewConecurrentLRU[testKey, int](10, nil)
	l.Add(1, 100)
	l.Del(1)

	if l.Len() != 0 {
		t.Fatalf("len = %d, want 0", l.Len())
	}
}

func TestConcurrentLRU_Clean(t *testing.T) {
	l := NewConecurrentLRU[testKey, int](10, nil)
	for i := 0; i < 5; i++ {
		l.Add(testKey(i), i)
	}

	removed := l.Clean(func(k testKey, v int) bool {
		return v%2 == 0
	})

	if removed != 3 {
		t.Fatalf("removed = %d, want 3", removed)
	}
	if l.Len() != 2 {
		t.Fatalf("len = %d, want 2", l.Len())
	}
}

func TestConcurrentLRU_Flush(t *testing.T) {
	l := NewConecurrentLRU[testKey, int](10, nil)
	l.Add(1, 1)
	l.Add(2, 2)
	l.Flush()

	if l.Len() != 0 {
		t.Fatalf("len = %d, want 0", l.Len())
	}
}

func TestShardedLRU_Basic(t *testing.T) {
	sl := NewShardedLRU[testKey, string](4, 10, nil)
	sl.Add(1, "one")
	sl.Add(2, "two")
	sl.Add(3, "three")

	v, ok := sl.Get(2)
	if !ok || v != "two" {
		t.Fatalf("Get(2) = %q, %v, want two, true", v, ok)
	}

	if sl.Len() != 3 {
		t.Fatalf("len = %d, want 3", sl.Len())
	}
}

func TestShardedLRU_Del(t *testing.T) {
	sl := NewShardedLRU[testKey, int](4, 10, nil)
	sl.Add(1, 10)
	sl.Add(2, 20)
	sl.Del(1)

	if _, ok := sl.Get(1); ok {
		t.Fatal("key 1 should be deleted")
	}
	if sl.Len() != 1 {
		t.Fatalf("len = %d, want 1", sl.Len())
	}
}

func TestShardedLRU_Clean(t *testing.T) {
	sl := NewShardedLRU[testKey, int](4, 10, nil)
	for i := 0; i < 10; i++ {
		sl.Add(testKey(i), i)
	}

	removed := sl.Clean(func(k testKey, v int) bool {
		return v >= 5
	})

	if removed != 5 {
		t.Fatalf("removed = %d, want 5", removed)
	}
}

func TestShardedLRU_Flush(t *testing.T) {
	sl := NewShardedLRU[testKey, int](4, 10, nil)
	for i := 0; i < 10; i++ {
		sl.Add(testKey(i), i)
	}
	sl.Flush()

	if sl.Len() != 0 {
		t.Fatalf("len = %d, want 0", sl.Len())
	}
}

func TestShardedLRU_LenTracking(t *testing.T) {
	sl := NewShardedLRU[testKey, int](4, 100, nil)

	for i := 0; i < 50; i++ {
		sl.Add(testKey(i), i)
	}
	if sl.Len() != 50 {
		t.Fatalf("len = %d, want 50", sl.Len())
	}

	for i := 0; i < 25; i++ {
		sl.Del(testKey(i))
	}
	if sl.Len() != 25 {
		t.Fatalf("len = %d, want 25", sl.Len())
	}
}

func TestShardedLRU_Concurrent(t *testing.T) {
	sl := NewShardedLRU[testKey, int](8, 100, nil)
	var wg sync.WaitGroup

	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				k := testKey(base*100 + i)
				sl.Add(k, i)
				sl.Get(k)
				if i%3 == 0 {
					sl.Del(k)
				}
			}
		}(g)
	}
	wg.Wait()
}

func BenchmarkShardedLRU_Add(b *testing.B) {
	sl := NewShardedLRU[testKey, int](8, 1024, nil)
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			sl.Add(testKey(i%8192), i)
			i++
		}
	})
}
