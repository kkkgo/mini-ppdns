package pool

import (
	"sync"
	"testing"
)

func TestGetBuf_Size(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantLen int
		wantCap int
	}{
		{"zero", 0, 0, 0},
		{"one", 1, 1, 1},
		{"two", 2, 2, 2},
		{"three", 3, 3, 4},
		{"four", 4, 4, 4},
		{"five", 5, 5, 8},
		{"power_of_2", 16, 16, 16},
		{"just_over", 17, 17, 32},
		{"large", 1024, 1024, 1024},
		{"large_odd", 1025, 1025, 2048},
		{"max_msg_size", 65535, 65535, 65536},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bp := GetBuf(tt.size)
			if len(*bp) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(*bp), tt.wantLen)
			}
			if cap(*bp) != tt.wantCap {
				t.Errorf("cap = %d, want %d", cap(*bp), tt.wantCap)
			}
			ReleaseBuf(bp)
		})
	}
}

func TestGetBuf_Negative(t *testing.T) {
	bp := GetBuf(-1)
	if len(*bp) != 0 {
		t.Errorf("negative size: len = %d, want 0", len(*bp))
	}
}

func TestGetBuf_Oversized(t *testing.T) {
	// Exceeds maxBitLen (1<<17=131072), should directly allocate
	size := 1 << 18
	bp := GetBuf(size)
	if len(*bp) != size {
		t.Errorf("len = %d, want %d", len(*bp), size)
	}
	// Should not panic on release
	ReleaseBuf(bp)
}

func TestReleaseBuf_InvalidCap(t *testing.T) {
	// Non-power-of-2 cap, should not panic
	b := make([]byte, 10, 100)
	ReleaseBuf(&b)
}

func TestReleaseBuf_ZeroCap(t *testing.T) {
	b := make([]byte, 0)
	ReleaseBuf(&b)
}

func TestGetBuf_Reuse(t *testing.T) {
	// Get and release, then get again to verify pool reuse
	bp1 := GetBuf(64)
	// Write pattern to verify identity
	for i := range *bp1 {
		(*bp1)[i] = 0xAB
	}
	ptr1 := &(*bp1)[0]
	ReleaseBuf(bp1)

	// Get same size again, should reuse
	bp2 := GetBuf(64)
	ptr2 := &(*bp2)[0]
	if ptr1 != ptr2 {
		t.Log("buffer was not reused (GC may have cleared pool), this is acceptable")
	}
	// Verify length is correctly set after reuse
	if len(*bp2) != 64 {
		t.Errorf("reused buf len = %d, want 64", len(*bp2))
	}
	ReleaseBuf(bp2)
}

func TestGetBuf_ReleasedBufIsZeroLen(t *testing.T) {
	bp := GetBuf(128)
	if len(*bp) != 128 {
		t.Fatal("unexpected initial len")
	}
	ReleaseBuf(bp)
	// After release, the slice should be zero-length
	if len(*bp) != 0 {
		t.Errorf("released buf len = %d, want 0", len(*bp))
	}
}

func TestGetBuf_Concurrent(t *testing.T) {
	// Verify no race conditions under concurrent access
	var wg sync.WaitGroup
	sizes := []int{0, 1, 64, 255, 512, 1024, 4096, 8192, 65535}

	for _, size := range sizes {
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(s int) {
				defer wg.Done()
				bp := GetBuf(s)
				if len(*bp) != s {
					t.Errorf("concurrent: len = %d, want %d", len(*bp), s)
				}
				// Write to buf to detect data races
				for j := range *bp {
					(*bp)[j] = byte(j)
				}
				ReleaseBuf(bp)
			}(size)
		}
	}
	wg.Wait()
}

func BenchmarkGetBuf_Small(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			bp := GetBuf(64)
			ReleaseBuf(bp)
		}
	})
}

func BenchmarkGetBuf_Medium(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			bp := GetBuf(4096)
			ReleaseBuf(bp)
		}
	})
}

func BenchmarkGetBuf_Large(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			bp := GetBuf(65536)
			ReleaseBuf(bp)
		}
	})
}

// ---- BytesBufPool tests ----

func TestNewBytesBufPool(t *testing.T) {
	p := NewBytesBufPool(64)
	buf := p.Get()
	if buf == nil {
		t.Fatal("Get returned nil")
	}
	if buf.Len() != 0 {
		t.Fatalf("new buf len = %d, want 0", buf.Len())
	}
	p.Release(buf)
}

func TestBytesBufPool_GetRelease(t *testing.T) {
	p := NewBytesBufPool(128)

	buf := p.Get()
	buf.WriteString("hello world")
	if buf.Len() != 11 {
		t.Fatalf("buf len = %d, want 11", buf.Len())
	}

	p.Release(buf)
	if buf.Len() != 0 {
		t.Fatalf("released buf len = %d, want 0", buf.Len())
	}
}

func TestBytesBufPool_Reuse(t *testing.T) {
	p := NewBytesBufPool(32)

	buf1 := p.Get()
	buf1.WriteString("test")
	p.Release(buf1)

	buf2 := p.Get()
	if buf2 == nil {
		t.Fatal("Get after release returned nil")
	}
	if buf2.Len() != 0 {
		t.Fatalf("reused buf should be empty, len = %d", buf2.Len())
	}
	p.Release(buf2)
}

func TestNewBytesBufPool_PanicNegative(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on negative init size")
		}
	}()
	NewBytesBufPool(-1)
}

func TestBytesBufPool_ZeroSize(t *testing.T) {
	p := NewBytesBufPool(0)
	buf := p.Get()
	buf.WriteString("ok")
	if buf.String() != "ok" {
		t.Fatalf("buf = %q, want ok", buf.String())
	}
	p.Release(buf)
}

func BenchmarkBytesBufPool(b *testing.B) {
	p := NewBytesBufPool(256)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := p.Get()
			buf.WriteString("benchmark data")
			p.Release(buf)
		}
	})
}
