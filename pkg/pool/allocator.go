package pool

import (
	"bytes"
	"fmt"
	"math/bits"
	"sync"
)

// Two independent pools live in this file:
//
//   • a power-of-two bucketed []byte allocator (GetBuf / ReleaseBuf)
//   • a capped bytes.Buffer pool (BytesBufPool)
//
// Both are safe for concurrent use.

// ---- []byte allocator ----

const (
	// capBits caps the largest bucket to 1<<17 = 128 KiB, which comfortably
	// covers dns.MaxMsgSize (65535) once rounded up to the next power of 2.
	capBits = 17
	// bucketCount leaves one extra entry so the zero-length bucket slot is
	// never addressed; GetBuf/ReleaseBuf reject size <= 0 before indexing.
	bucketCount = capBits + 1
)

var byteBuckets [bucketCount]sync.Pool

// sharedEmpty is returned for GetBuf(0) so the zero-size fast path never
// allocates. Callers are contractually forbidden from appending to it;
// ReleaseBuf ignores zero-cap buffers so no aliasing ever leaks back.
var sharedEmpty = make([]byte, 0)

// GetBuf returns a *[]byte of length `size`. The backing array is rounded
// up to the next power of two within the bucket range; oversize requests
// fall back to a plain allocation so the pools don't grow unbounded.
func GetBuf(size int) *[]byte {
	if size <= 0 {
		b := sharedEmpty
		return &b
	}
	idx := bucketIndexFor(size)
	if idx >= bucketCount {
		b := make([]byte, size)
		return &b
	}
	if bp, ok := byteBuckets[idx].Get().(*[]byte); ok {
		*bp = (*bp)[:size]
		return bp
	}
	b := make([]byte, size, 1<<idx)
	return &b
}

// ReleaseBuf returns a *[]byte previously obtained via GetBuf back to the
// pool. Buffers whose capacity is not a power of two in range are dropped
// on the floor (they didn't come from us; stashing them would corrupt a
// bucket's size invariant).
func ReleaseBuf(b *[]byte) {
	c := cap(*b)
	if c == 0 {
		return
	}
	idx := bucketIndexFor(c)
	if idx >= bucketCount || c != 1<<idx {
		return
	}
	*b = (*b)[:0]
	byteBuckets[idx].Put(b)
}

// bucketIndexFor returns the smallest n such that 1<<n >= v, for v > 0.
// Equivalent to ceil(log2(v)) but branch-free and integer-only.
func bucketIndexFor(v int) int {
	return bits.Len(uint(v - 1))
}

// ---- bytes.Buffer pool ----

// bytesBufRetainCap is the largest Cap() a *bytes.Buffer may have and still
// be eligible for reuse. Anything larger is handed to the GC so a one-off
// jumbo request doesn't pin memory forever.
const bytesBufRetainCap = 64 * 1024

// BytesBufPool wraps a sync.Pool of *bytes.Buffer with a capacity-based
// retention policy. Zero value is unusable; construct with NewBytesBufPool.
type BytesBufPool struct {
	inner sync.Pool
}

// NewBytesBufPool returns a pool whose freshly minted buffers have their
// backing array pre-grown to prealloc bytes. Passing a negative prealloc
// is a programmer error.
func NewBytesBufPool(prealloc int) *BytesBufPool {
	if prealloc < 0 {
		panic(fmt.Sprintf("pool.NewBytesBufPool: prealloc must be >= 0, got %d", prealloc))
	}
	return &BytesBufPool{
		inner: sync.Pool{
			New: func() any {
				b := new(bytes.Buffer)
				if prealloc > 0 {
					b.Grow(prealloc)
				}
				return b
			},
		},
	}
}

// Get returns a reset *bytes.Buffer (length 0, capacity untouched).
func (p *BytesBufPool) Get() *bytes.Buffer {
	return p.inner.Get().(*bytes.Buffer)
}

// Release resets b and returns it to the pool, unless its capacity has
// grown past bytesBufRetainCap — oversized buffers are dropped so a rare
// huge write doesn't poison the pool for the lifetime of the process.
func (p *BytesBufPool) Release(b *bytes.Buffer) {
	if b.Cap() > bytesBufRetainCap {
		return
	}
	b.Reset()
	p.inner.Put(b)
}
