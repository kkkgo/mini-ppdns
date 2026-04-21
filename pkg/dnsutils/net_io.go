package dnsutils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"codeberg.org/miekg/dns"
	"github.com/kkkgo/mini-ppdns/pkg/pool"
)

// DnsHeaderLen is the fixed 12-byte DNS header; anything shorter cannot be
// a valid frame.
const DnsHeaderLen = 12

var ErrPayloadTooSmall = errors.New("payload is too small for a valid dns msg")

// ReadRawMsgFromTCP reads one RFC 1035 length-prefixed frame from c and
// returns the wire bytes (length header stripped). The returned buffer
// comes from pool.GetBuf; the caller owns it and must return it via
// pool.ReleaseBuf when done.
func ReadRawMsgFromTCP(c io.Reader) (*[]byte, error) {
	length, err := readLenHdr(c)
	if err != nil {
		return nil, err
	}
	if length < DnsHeaderLen {
		return nil, ErrPayloadTooSmall
	}

	body := pool.GetBuf(int(length))
	if _, err := io.ReadFull(c, *body); err != nil {
		pool.ReleaseBuf(body)
		return nil, err
	}
	return body, nil
}

// ReadMsgFromTCP is ReadRawMsgFromTCP plus unpacking into a *dns.Msg.
// The second return value is bytes consumed on the wire (body + 2-byte
// length prefix), useful for bandwidth accounting.
func ReadMsgFromTCP(c io.Reader) (*dns.Msg, int, error) {
	raw, err := ReadRawMsgFromTCP(c)
	if err != nil {
		return nil, 0, err
	}
	defer pool.ReleaseBuf(raw)

	m, err := unpackWireMsg(*raw)
	if m != nil {
		// Drop the pool-backed slice reference before returning so the
		// caller-visible *dns.Msg does not alias into a buffer we're
		// about to hand back to the allocator.
		m.Data = nil
	}
	return m, len(*raw) + 2, err
}

// WriteMsgToTCP packs m using pool-backed buffers and writes the framed
// result to c.
func WriteMsgToTCP(c io.Writer, m *dns.Msg) (int, error) {
	frame, err := pool.PackTCPBuffer(m)
	if err != nil {
		return 0, err
	}
	defer pool.ReleaseBuf(frame)
	return c.Write(*frame)
}

// WriteRawMsgToTCP prepends a 2-byte length header to b and writes the
// frame. Rejects empty payloads and payloads exceeding dns.MaxMsgSize —
// both would be invalid on the wire.
func WriteRawMsgToTCP(c io.Writer, b []byte) (int, error) {
	if len(b) == 0 {
		return 0, errors.New("dnsutils: WriteRawMsgToTCP: empty payload")
	}
	if len(b) > dns.MaxMsgSize {
		return 0, fmt.Errorf("dnsutils: WriteRawMsgToTCP: payload length %d exceeds %d", len(b), dns.MaxMsgSize)
	}

	frame := pool.GetBuf(len(b) + 2)
	defer pool.ReleaseBuf(frame)
	binary.BigEndian.PutUint16((*frame)[:2], uint16(len(b)))
	copy((*frame)[2:], b)
	return c.Write(*frame)
}

// WriteMsgToUDP packs m and writes it to c as a single datagram.
func WriteMsgToUDP(c io.Writer, m *dns.Msg) (int, error) {
	pkt, err := pool.PackBuffer(m)
	if err != nil {
		return 0, err
	}
	defer pool.ReleaseBuf(pkt)
	return c.Write(*pkt)
}

// ReadMsgFromUDP reads a single datagram into a pool-backed buffer of
// bufSize bytes (raised to dns.MinMsgSize if smaller) and unpacks it.
func ReadMsgFromUDP(c io.Reader, bufSize int) (*dns.Msg, int, error) {
	if bufSize < dns.MinMsgSize {
		bufSize = dns.MinMsgSize
	}

	buf := pool.GetBuf(bufSize)
	defer pool.ReleaseBuf(buf)
	n, err := c.Read(*buf)
	if err != nil {
		return nil, n, err
	}

	m, err := unpackWireMsg((*buf)[:n])
	if m != nil {
		m.Data = nil
	}
	return m, n, err
}

// readLenHdr pulls the two-byte big-endian length prefix from a TCP frame.
func readLenHdr(r io.Reader) (uint16, error) {
	hdr := pool.GetBuf(2)
	defer pool.ReleaseBuf(hdr)
	if _, err := io.ReadFull(r, *hdr); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(*hdr), nil
}

// unpackWireMsg parses raw wire bytes. On failure the error includes the
// hex dump so callers looking at logs can reproduce the issue.
func unpackWireMsg(raw []byte) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.Data = raw
	if err := m.Unpack(); err != nil {
		return nil, fmt.Errorf("dnsutils: unpack failed for %x: %w", raw, err)
	}
	return m, nil
}
