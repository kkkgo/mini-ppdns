package pool

import (
	"encoding/binary"
	"errors"

	"github.com/miekg/dns"
)

// DNS messages rarely exceed 4KB (UDP) or 64KB (TCP).
// Use 64KB as default pack buffer to cover dns.MaxMsgSize.
const packBufferSize = 1 << 16 // 65536

var errPayloadTooLarge = errors.New("dns payload too large")

// Pack the dns msg m to wire format.
// Callers should release the buf by calling ReleaseBuf after done.
func PackBuffer(m *dns.Msg) (*[]byte, error) {
	packBuf := GetBuf(packBufferSize)
	wire, err := m.PackBuffer(*packBuf)
	if err != nil {
		ReleaseBuf(packBuf)
		return nil, err
	}
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
	packBuf := GetBuf(packBufferSize)
	wire, err := m.PackBuffer((*packBuf)[2:])
	if err != nil {
		ReleaseBuf(packBuf)
		return nil, err
	}

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
