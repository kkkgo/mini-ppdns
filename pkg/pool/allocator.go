package pool

import (
	"math/bits"
	"sync"
)

// Pool manages multiple sync.Pool buckets for []byte buffers.
// Each bucket handles buffers of capacity 1<<n (power of 2).
const maxBitLen = 17 // max capacity 1<<17 = 128KB, enough for dns.MaxMsgSize (65535)

var pools [maxBitLen + 1]sync.Pool

// GetBuf returns a *[]byte with len=size from pool.
// The underlying capacity is rounded up to the next power of 2.
// If size exceeds max pool capacity, directly allocates.
func GetBuf(size int) *[]byte {
	if size <= 0 {
		b := make([]byte, 0)
		return &b
	}
	bit := bits.Len(uint(size - 1)) // ceil log2
	if size == 1 {
		bit = 0
	}
	if bit > maxBitLen {
		b := make([]byte, size)
		return &b
	}
	bp, ok := pools[bit].Get().(*[]byte)
	if !ok {
		b := make([]byte, size, 1<<bit)
		return &b
	}
	*bp = (*bp)[:size]
	return bp
}

// ReleaseBuf returns a *[]byte to the pool.
// Buffers with non-power-of-2 capacity or exceeding max are silently discarded.
func ReleaseBuf(b *[]byte) {
	c := cap(*b)
	if c == 0 {
		return
	}
	bit := bits.Len(uint(c - 1))
	if c == 1 {
		bit = 0
	}
	if bit > maxBitLen || c != 1<<bit {
		return // not a pool buffer, silently discard
	}
	*b = (*b)[:0]
	pools[bit].Put(b)
}
