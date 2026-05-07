package pool

import (
	"encoding/binary"
	"errors"

	"codeberg.org/miekg/dns"
)

// DNS messages can be up to dns.MaxMsgSize (65535 bytes). PackTCPBuffer
// reserves the first two bytes for the TCP length prefix, leaving only
// 65534 bytes for the message itself when packBufferSize is 1<<16; a
// max-size response then forces miekg/dns to reallocate, wasting the
// pooled buffer. Using the next power-of-two (also the largest pool
// bucket) gives every legal message room to pack in place.
const packBufferSize = 1 << 17 // 131072

var errPayloadTooLarge = errors.New("dns payload too large")

// Pack the dns msg m to wire format.
// Callers should release the buf by calling ReleaseBuf after done.
func PackBuffer(m *dns.Msg) (*[]byte, error) {
	packBuf := GetBuf(packBufferSize)
	// Pre-set m.Data so Pack() reuses our buffer if large enough.
	m.Data = (*packBuf)[:cap(*packBuf)]
	if err := m.Pack(); err != nil {
		m.Data = nil
		ReleaseBuf(packBuf)
		return nil, err
	}
	wire := m.Data
	m.Data = nil
	// If dns lib re-allocated (message > buffer), release pool buf.
	if cap(wire) != cap(*packBuf) {
		ReleaseBuf(packBuf)
		b := wire
		return &b, nil
	}
	*packBuf = wire
	return packBuf, nil
}

// Pack the dns msg m to wire format with 2-byte TCP length header.
// Callers should release the buf by calling ReleaseBuf after done.
func PackTCPBuffer(m *dns.Msg) (*[]byte, error) {
	return packTCPBufferSized(m, packBufferSize)
}

// PackTCPBufferSmall is the same as PackTCPBuffer but starts from a
// 4 KiB bucket. Use this for replies that are guaranteed small (TCP
// SERVFAIL synthesis, fixed local errors): every TCP error response
// otherwise burned a 128 KiB pool slot regardless of payload size,
// magnifying pool churn under connection-flood pressure. The fallback
// reallocation path still handles the rare case where Pack needs more
// than the hint, so correctness is unchanged.
func PackTCPBufferSmall(m *dns.Msg) (*[]byte, error) {
	return packTCPBufferSized(m, 4096)
}

func packTCPBufferSized(m *dns.Msg, hint int) (*[]byte, error) {
	packBuf := GetBuf(hint)
	// Reserve first 2 bytes for the TCP length prefix.
	m.Data = (*packBuf)[2:cap(*packBuf)]
	if err := m.Pack(); err != nil {
		m.Data = nil
		ReleaseBuf(packBuf)
		return nil, err
	}
	wire := m.Data
	m.Data = nil

	l := len(wire)
	if l > dns.MaxMsgSize {
		ReleaseBuf(packBuf)
		return nil, errPayloadTooLarge
	}

	// If dns lib re-allocated, release pool buf and build new one.
	if cap(wire) != cap((*packBuf)[2:]) {
		ReleaseBuf(packBuf)
		b := make([]byte, 2+l)
		binary.BigEndian.PutUint16(b, uint16(l))
		copy(b[2:], wire)
		return &b, nil
	}

	*packBuf = (*packBuf)[:2+l]
	binary.BigEndian.PutUint16(*packBuf, uint16(l))
	return packBuf, nil
}
