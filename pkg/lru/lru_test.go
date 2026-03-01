package lru

import "testing"

func TestLRU_AddGet(t *testing.T) {
	l := NewLRU[string, int](10, nil)
	l.Add("a", 1)
	l.Add("b", 2)

	v, ok := l.Get("a")
	if !ok || v != 1 {
		t.Fatalf("Get(a) = %d, %v, want 1, true", v, ok)
	}

	_, ok = l.Get("missing")
	if ok {
		t.Fatal("Get(missing) should return false")
	}
}

func TestLRU_Update(t *testing.T) {
	l := NewLRU[string, int](10, nil)
	l.Add("a", 1)
	l.Add("a", 2)

	v, _ := l.Get("a")
	if v != 2 {
		t.Fatalf("updated value = %d, want 2", v)
	}
	if l.Len() != 1 {
		t.Fatalf("len = %d, want 1", l.Len())
	}
}

func TestLRU_Eviction(t *testing.T) {
	var evicted []string
	onEvict := func(key string, v int) {
		evicted = append(evicted, key)
	}

	l := NewLRU[string, int](3, onEvict)
	l.Add("a", 1)
	l.Add("b", 2)
	l.Add("c", 3)
	l.Add("d", 4) // should evict "a"

	if l.Len() != 3 {
		t.Fatalf("len = %d, want 3", l.Len())
	}
	if _, ok := l.Get("a"); ok {
		t.Fatal("a should be evicted")
	}
	if len(evicted) != 1 || evicted[0] != "a" {
		t.Fatalf("evicted = %v, want [a]", evicted)
	}
}

func TestLRU_LRUOrder(t *testing.T) {
	l := NewLRU[string, int](3, nil)
	l.Add("a", 1)
	l.Add("b", 2)
	l.Add("c", 3)

	// Access "a" to make it recently used
	l.Get("a")
	l.Add("d", 4) // should evict "b" (oldest)

	if _, ok := l.Get("b"); ok {
		t.Fatal("b should be evicted")
	}
	if _, ok := l.Get("a"); !ok {
		t.Fatal("a should still exist")
	}
}

func TestLRU_Del(t *testing.T) {
	var evicted []string
	l := NewLRU[string, int](10, func(k string, v int) {
		evicted = append(evicted, k)
	})
	l.Add("a", 1)
	l.Del("a")

	if l.Len() != 0 {
		t.Fatalf("len = %d, want 0", l.Len())
	}
	if _, ok := l.Get("a"); ok {
		t.Fatal("a should be deleted")
	}
	if len(evicted) != 1 || evicted[0] != "a" {
		t.Fatalf("evicted = %v, want [a]", evicted)
	}

	// Delete non-existent key should not panic
	l.Del("nonexistent")
}

func TestLRU_PopOldest(t *testing.T) {
	l := NewLRU[string, int](10, nil)
	l.Add("a", 1)
	l.Add("b", 2)

	k, v, ok := l.PopOldest()
	if !ok || k != "a" || v != 1 {
		t.Fatalf("PopOldest = %s, %d, %v, want a, 1, true", k, v, ok)
	}

	// Pop from empty
	l.PopOldest() // "b"
	_, _, ok = l.PopOldest()
	if ok {
		t.Fatal("PopOldest on empty should return false")
	}
}

func TestLRU_Clean(t *testing.T) {
	l := NewLRU[int, int](10, nil)
	for i := 0; i < 5; i++ {
		l.Add(i, i*10)
	}

	removed := l.Clean(func(k, v int) bool {
		return k%2 == 0 // remove even keys
	})

	if removed != 3 {
		t.Fatalf("removed = %d, want 3", removed)
	}
	if l.Len() != 2 {
		t.Fatalf("len = %d, want 2", l.Len())
	}
}

func TestLRU_Flush(t *testing.T) {
	l := NewLRU[string, int](10, nil)
	l.Add("a", 1)
	l.Add("b", 2)
	l.Flush()

	if l.Len() != 0 {
		t.Fatalf("len = %d, want 0", l.Len())
	}
	if _, ok := l.Get("a"); ok {
		t.Fatal("a should be gone after flush")
	}
}

func TestLRU_PanicOnInvalidSize(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on invalid size")
		}
	}()
	NewLRU[string, int](0, nil)
}

func BenchmarkLRU_Add(b *testing.B) {
	l := NewLRU[int, int](1024, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Add(i%2048, i)
	}
}

func BenchmarkLRU_Get(b *testing.B) {
	l := NewLRU[int, int](1024, nil)
	for i := 0; i < 1024; i++ {
		l.Add(i, i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Get(i % 1024)
	}
}
