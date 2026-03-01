package pool

import (
	"testing"
)

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
	// After release, buf should be reset
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
	// Pool may or may not reuse; just verify it works
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
