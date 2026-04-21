package concurrent_map

import (
	"sync"
	"testing"
)

type testKey uint64

func (k testKey) Sum() uint64 { return uint64(k) }

func TestMap_SetGet(t *testing.T) {
	m := NewMap[testKey, string]()
	m.Set(1, "a")
	m.Set(2, "b")

	v, ok := m.Get(1)
	if !ok || v != "a" {
		t.Fatalf("Get(1) = %q, %v, want a, true", v, ok)
	}

	_, ok = m.Get(99)
	if ok {
		t.Fatal("Get(99) should return false")
	}
}

func TestMap_Del(t *testing.T) {
	m := NewMap[testKey, int]()
	m.Set(1, 10)
	m.Del(1)

	if _, ok := m.Get(1); ok {
		t.Fatal("key 1 should be deleted")
	}
	if m.Len() != 0 {
		t.Fatalf("len = %d, want 0", m.Len())
	}

	// Delete non-existent key should not panic
	m.Del(999)
}

func TestMap_TestAndSet(t *testing.T) {
	m := NewMap[testKey, int]()
	m.Set(1, 10)

	// Update existing
	m.TestAndSet(1, func(v int, ok bool) (int, bool, bool) {
		if !ok || v != 10 {
			t.Fatalf("TestAndSet: v=%d, ok=%v, want 10, true", v, ok)
		}
		return v + 5, true, false
	})

	v, _ := m.Get(1)
	if v != 15 {
		t.Fatalf("after TestAndSet: v=%d, want 15", v)
	}

	// Delete via TestAndSet
	m.TestAndSet(1, func(v int, ok bool) (int, bool, bool) {
		return 0, false, true
	})
	if _, ok := m.Get(1); ok {
		t.Fatal("key should be deleted")
	}

	// TestAndSet on non-existent key - insert
	m.TestAndSet(2, func(v int, ok bool) (int, bool, bool) {
		if ok {
			t.Fatal("should not exist")
		}
		return 42, true, false
	})
	v, _ = m.Get(2)
	if v != 42 {
		t.Fatalf("new key value = %d, want 42", v)
	}
}

func TestMap_Range(t *testing.T) {
	m := NewMap[testKey, int]()
	for i := 0; i < 10; i++ {
		m.Set(testKey(i), i*10)
	}

	count := 0
	m.Range(func(k testKey, v int) bool {
		count++
		return true
	})
	if count != 10 {
		t.Fatalf("Range count = %d, want 10", count)
	}

	// Range with early stop
	count = 0
	m.Range(func(k testKey, v int) bool {
		count++
		return count < 3
	})
	if count != 3 {
		t.Fatalf("Range early stop count = %d, want 3", count)
	}
}

func TestMap_RangeDo(t *testing.T) {
	m := NewMap[testKey, int]()
	for i := 0; i < 5; i++ {
		m.Set(testKey(i), i)
	}

	// Double all values
	err := m.RangeDo(func(k testKey, v int) (int, bool, bool, error) {
		return v * 2, true, false, nil
	})
	if err != nil {
		t.Fatalf("RangeDo err: %v", err)
	}

	for i := 0; i < 5; i++ {
		v, ok := m.Get(testKey(i))
		if !ok || v != i*2 {
			t.Fatalf("Get(%d) = %d, %v, want %d, true", i, v, ok, i*2)
		}
	}
}

func TestMap_Flush(t *testing.T) {
	m := NewMap[testKey, int]()
	for i := 0; i < 10; i++ {
		m.Set(testKey(i), i)
	}
	m.Flush()

	if m.Len() != 0 {
		t.Fatalf("len = %d, want 0", m.Len())
	}
}

func TestMap_Len(t *testing.T) {
	m := NewMap[testKey, int]()
	if m.Len() != 0 {
		t.Fatalf("empty len = %d, want 0", m.Len())
	}

	m.Set(1, 1)
	m.Set(2, 2)
	if m.Len() != 2 {
		t.Fatalf("len = %d, want 2", m.Len())
	}
}

func TestNewMapCache_SizeLimit(t *testing.T) {
	// Each shard max = 1 (64/64), so total max ~ 64
	m := NewMapCache[testKey, int](64)

	for i := 0; i < 200; i++ {
		m.Set(testKey(i), i)
	}

	// Per-shard cap is size/MapShardSize; total cap is bounded accordingly.
	if m.Len() > 200 {
		t.Fatalf("cache should limit size, got len=%d", m.Len())
	}
}

func TestMap_Concurrent(t *testing.T) {
	m := NewMap[testKey, int]()
	var wg sync.WaitGroup

	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				k := testKey(base*100 + i)
				m.Set(k, i)
				m.Get(k)
				if i%3 == 0 {
					m.Del(k)
				}
			}
		}(g)
	}
	wg.Wait()
}

func BenchmarkMap_Set(b *testing.B) {
	m := NewMap[testKey, int]()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			m.Set(testKey(i), i)
			i++
		}
	})
}
