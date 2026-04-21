package transport

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/pool"
)

func TestSetDefaultGZ(t *testing.T) {
	t.Run("int_use_source", func(t *testing.T) {
		var v int
		setDefaultGZ(&v, 42, 10)
		if v != 42 {
			t.Fatalf("expected 42, got %d", v)
		}
	})
	t.Run("int_use_default_zero", func(t *testing.T) {
		var v int
		setDefaultGZ(&v, 0, 10)
		if v != 10 {
			t.Fatalf("expected 10, got %d", v)
		}
	})
	t.Run("int_use_default_negative", func(t *testing.T) {
		var v int
		setDefaultGZ(&v, -5, 10)
		if v != 10 {
			t.Fatalf("expected 10, got %d", v)
		}
	})
	t.Run("duration_use_source", func(t *testing.T) {
		var v time.Duration
		setDefaultGZ(&v, 3*time.Second, time.Second)
		if v != 3*time.Second {
			t.Fatalf("expected 3s, got %v", v)
		}
	})
	t.Run("duration_use_default", func(t *testing.T) {
		var v time.Duration
		setDefaultGZ(&v, 0, 5*time.Second)
		if v != 5*time.Second {
			t.Fatalf("expected 5s, got %v", v)
		}
	})
	t.Run("float64_use_source", func(t *testing.T) {
		var v float64
		setDefaultGZ(&v, 3.14, 1.0)
		if v != 3.14 {
			t.Fatalf("expected 3.14, got %f", v)
		}
	})
	t.Run("float64_use_default", func(t *testing.T) {
		var v float64
		setDefaultGZ(&v, 0.0, 2.71)
		if v != 2.71 {
			t.Fatalf("expected 2.71, got %f", v)
		}
	})
}

func TestCopyMsg(t *testing.T) {
	orig := []byte{1, 2, 3, 4, 5}
	bp := copyMsg(orig)
	defer pool.ReleaseBuf(bp)

	if !bytes.Equal(*bp, orig) {
		t.Fatalf("copy mismatch: got %v, want %v", *bp, orig)
	}

	// Modify copy, original should be unchanged.
	(*bp)[0] = 99
	if orig[0] != 1 {
		t.Fatal("modifying copy affected original")
	}
}

func TestCopyMsgWithLenHdr(t *testing.T) {
	t.Run("normal", func(t *testing.T) {
		msg := []byte{0xAA, 0xBB, 0xCC}
		bp, err := copyMsgWithLenHdr(msg)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.ReleaseBuf(bp)

		// First 2 bytes should be big-endian length.
		if (*bp)[0] != 0 || (*bp)[1] != 3 {
			t.Fatalf("length header wrong: got [%x %x], want [00 03]", (*bp)[0], (*bp)[1])
		}
		if !bytes.Equal((*bp)[2:], msg) {
			t.Fatalf("payload mismatch: got %v, want %v", (*bp)[2:], msg)
		}
	})

	t.Run("overflow", func(t *testing.T) {
		// Create a payload larger than dns.MaxMsgSize.
		big := make([]byte, dns.MaxMsgSize+1)
		_, err := copyMsgWithLenHdr(big)
		if !errors.Is(err, ErrPayloadOverFlow) {
			t.Fatalf("expected ErrPayloadOverFlow, got %v", err)
		}
	})

	t.Run("exact_max", func(t *testing.T) {
		// Exactly dns.MaxMsgSize should succeed.
		msg := make([]byte, dns.MaxMsgSize)
		bp, err := copyMsgWithLenHdr(msg)
		if err != nil {
			t.Fatalf("unexpected error for max size: %v", err)
		}
		pool.ReleaseBuf(bp)
	})
}

// mockReader allows controlled Read behavior for testing readMsgUdp.
type mockReader struct {
	reads []mockRead
	idx   int
}

type mockRead struct {
	data []byte
	err  error
}

func (m *mockReader) Read(p []byte) (int, error) {
	if m.idx >= len(m.reads) {
		return 0, io.EOF
	}
	r := m.reads[m.idx]
	m.idx++
	if r.err != nil {
		return 0, r.err
	}
	n := copy(p, r.data)
	return n, nil
}

func TestReadMsgUdp(t *testing.T) {
	t.Run("valid_read", func(t *testing.T) {
		// A valid DNS-sized payload (>= 12 bytes).
		data := make([]byte, 20)
		for i := range data {
			data[i] = byte(i)
		}
		mr := &mockReader{reads: []mockRead{{data: data}}}
		bp, err := readMsgUdp(mr)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.ReleaseBuf(bp)

		if len(*bp) != 20 {
			t.Fatalf("expected len 20, got %d", len(*bp))
		}
		if !bytes.Equal(*bp, data) {
			t.Fatalf("data mismatch")
		}
	})

	t.Run("skip_small_then_valid", func(t *testing.T) {
		// First read is too small (< 12 bytes), second is valid.
		small := make([]byte, 5)
		valid := make([]byte, 15)
		for i := range valid {
			valid[i] = byte(i + 100)
		}
		mr := &mockReader{reads: []mockRead{
			{data: small},
			{data: valid},
		}}
		bp, err := readMsgUdp(mr)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.ReleaseBuf(bp)

		if len(*bp) != 15 {
			t.Fatalf("expected len 15, got %d", len(*bp))
		}
	})

	t.Run("read_error", func(t *testing.T) {
		testErr := errors.New("test read error")
		mr := &mockReader{reads: []mockRead{{err: testErr}}}
		_, err := readMsgUdp(mr)
		if !errors.Is(err, testErr) {
			t.Fatalf("expected test error, got %v", err)
		}
	})

	t.Run("error_after_small_reads", func(t *testing.T) {
		testErr := errors.New("delayed error")
		mr := &mockReader{reads: []mockRead{
			{data: make([]byte, 3)},
			{data: make([]byte, 5)},
			{err: testErr},
		}}
		_, err := readMsgUdp(mr)
		if !errors.Is(err, testErr) {
			t.Fatalf("expected delayed error, got %v", err)
		}
	})

	t.Run("exact_min_size", func(t *testing.T) {
		// Exactly 12 bytes should be accepted.
		data := make([]byte, dnsHeaderLen)
		mr := &mockReader{reads: []mockRead{{data: data}}}
		bp, err := readMsgUdp(mr)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.ReleaseBuf(bp)

		if len(*bp) != dnsHeaderLen {
			t.Fatalf("expected len %d, got %d", dnsHeaderLen, len(*bp))
		}
	})
}

func TestSetNonNilLogger(t *testing.T) {
	t.Run("non_nil", func(t *testing.T) {
		custom := mlog.Nop()
		var l *mlog.Logger
		setNonNilLogger(&l, custom)
		if l != custom {
			t.Fatal("expected custom logger")
		}
	})

	t.Run("nil_uses_nop", func(t *testing.T) {
		var l *mlog.Logger
		setNonNilLogger(&l, nil)
		if l != nopLogger {
			t.Fatal("expected nopLogger")
		}
	})
}

func BenchmarkReadMsgUdp(b *testing.B) {
	data := make([]byte, 512) // typical DNS response size
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mr := &mockReader{reads: []mockRead{{data: data}}}
			bp, err := readMsgUdp(mr)
			if err != nil {
				b.Fatal(err)
			}
			pool.ReleaseBuf(bp)
		}
	})
}

func BenchmarkCopyMsgWithLenHdr(b *testing.B) {
	msg := make([]byte, 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bp, _ := copyMsgWithLenHdr(msg)
		pool.ReleaseBuf(bp)
	}
}
