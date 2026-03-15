package pplog

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// Protocol constants
const (
	MagicByte0 byte = 0x50 // 'P'
	MagicByte1 byte = 0x4C // 'L'
	Version    byte = 0x01

	HeaderSize = 26 // Magic(2) + Version(1) + Level(1) + SeqNum(4) + UUID(16) + PayloadLen(2)

	// Flags
	FlagIPv6 byte = 1 << 0

	// Route values
	RouteCache byte = 0
	RouteLocal byte = 1
	RouteFall  byte = 2

	// Custom Rcode values (above standard DNS range 0-23)
	RcodeTimeout byte = 0xFE
	RcodeNoData  byte = 0xFF

	// Level 5 severity
	SeverityDebug byte = 0
	SeverityInfo  byte = 1
	SeverityWarn  byte = 2
	SeverityError byte = 3
	SeverityFatal byte = 4

	MaxPacketSize = 1400
)

// QueryEntry holds data for a Level 1-4 query log.
type QueryEntry struct {
	ClientIP  netip.Addr
	QType     uint16
	Rcode     byte
	Route     byte
	Duration  uint16 // ms
	QueryName string
	Upstream  string   // Level >= 2
	AnswerRRs []dns.RR // Level >= 3
	ExtraRRs  []dns.RR // Level >= 4
}

// EventEntry holds data for a Level 5 event log.
type EventEntry struct {
	Severity byte
	Message  string
}

// ParseUUID parses a UUID string (with or without hyphens) into 16 bytes.
func ParseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return uuid, fmt.Errorf("invalid UUID length: %d (expected 32 hex chars)", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return uuid, fmt.Errorf("invalid UUID hex: %w", err)
	}
	copy(uuid[:], b)
	return uuid, nil
}

// EncodeHeader writes the 26-byte common header into buf.
// Returns HeaderSize (26).
func EncodeHeader(buf []byte, level byte, seq uint32, uuid [16]byte, payloadLen uint16) int {
	buf[0] = MagicByte0
	buf[1] = MagicByte1
	buf[2] = Version
	buf[3] = level
	binary.BigEndian.PutUint32(buf[4:8], seq)
	copy(buf[8:24], uuid[:])
	binary.BigEndian.PutUint16(buf[24:26], payloadLen)
	return HeaderSize
}

// EncodeQueryEntry encodes a query log entry at the given level into buf (after header).
// Returns the number of bytes written (payload length).
func EncodeQueryEntry(buf []byte, entry *QueryEntry, level int, ts uint32) int {
	off := 0

	// Timestamp (4 bytes)
	binary.BigEndian.PutUint32(buf[off:off+4], ts)
	off += 4

	// Flags (1 byte)
	var flags byte
	isIPv6 := entry.ClientIP.Is6() && !entry.ClientIP.Is4In6()
	if isIPv6 {
		flags |= FlagIPv6
	}
	buf[off] = flags
	off++

	// ClientIP (4 or 16 bytes)
	if isIPv6 {
		ip := entry.ClientIP.As16()
		copy(buf[off:off+16], ip[:])
		off += 16
	} else {
		ip := entry.ClientIP.As4()
		copy(buf[off:off+4], ip[:])
		off += 4
	}

	// QType (2 bytes)
	binary.BigEndian.PutUint16(buf[off:off+2], entry.QType)
	off += 2

	// Rcode (1 byte)
	buf[off] = entry.Rcode
	off++

	// Route (1 byte)
	buf[off] = entry.Route
	off++

	// Duration (2 bytes)
	binary.BigEndian.PutUint16(buf[off:off+2], entry.Duration)
	off += 2

	// NameLen (1 byte) + QueryName
	name := entry.QueryName
	// Strip trailing dot if present
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	nameLen := len(name)
	if nameLen > 255 {
		nameLen = 255
		name = name[:255]
	}
	buf[off] = byte(nameLen)
	off++
	copy(buf[off:off+nameLen], name)
	off += nameLen

	// Level 1 done
	if level < 2 {
		return off
	}

	// Level 2: Upstream address
	upstream := entry.Upstream
	upLen := len(upstream)
	if upLen > 255 {
		upLen = 255
		upstream = upstream[:255]
	}
	buf[off] = byte(upLen)
	off++
	copy(buf[off:off+upLen], upstream)
	off += upLen

	if level < 3 {
		return off
	}

	// Level 3: ANSWER SECTION
	off += encodeRRSection(buf[off:], entry.AnswerRRs)

	if level < 4 {
		return off
	}

	// Level 4: ADDITIONAL SECTION
	off += encodeRRSection(buf[off:], entry.ExtraRRs)

	return off
}

// EncodeEventEntry encodes a Level 5 event log into buf (after header).
// Returns the number of bytes written (payload length).
func EncodeEventEntry(buf []byte, entry *EventEntry, ts uint32) int {
	off := 0

	// Timestamp (4 bytes)
	binary.BigEndian.PutUint32(buf[off:off+4], ts)
	off += 4

	// Severity (1 byte)
	buf[off] = entry.Severity
	off++

	// Message (variable length)
	msgLen := len(entry.Message)
	maxMsg := MaxPacketSize - HeaderSize - 5 // 5 = timestamp(4) + severity(1)
	if msgLen > maxMsg {
		msgLen = maxMsg
	}
	copy(buf[off:off+msgLen], entry.Message[:msgLen])
	off += msgLen

	return off
}

// encodeRRSection encodes a DNS RR section (ANSWER or ADDITIONAL).
// Format: count(1) + per-RR: type(2) + ttl(4) + rdlen(2) + rdata(variable)
func encodeRRSection(buf []byte, rrs []dns.RR) int {
	off := 0

	// Filter out OPT records
	var filtered []dns.RR
	for _, rr := range rrs {
		if rr.Header().Rrtype != dns.TypeOPT {
			filtered = append(filtered, rr)
		}
	}

	count := len(filtered)
	if count > 255 {
		count = 255
	}
	buf[off] = byte(count)
	off++

	for i := 0; i < count; i++ {
		rr := filtered[i]
		hdr := rr.Header()

		// RRType (2 bytes)
		binary.BigEndian.PutUint16(buf[off:off+2], hdr.Rrtype)
		off += 2

		// TTL (4 bytes)
		binary.BigEndian.PutUint32(buf[off:off+4], hdr.Ttl)
		off += 4

		// RData: pack the RR to wire format and extract rdata portion
		rdataBuf := make([]byte, 512)
		rdataOff, err := dns.PackRR(rr, rdataBuf, 0, nil, false)
		if err != nil || rdataOff <= int(hdr.Rdlength) {
			// Fallback: write zero-length rdata
			binary.BigEndian.PutUint16(buf[off:off+2], 0)
			off += 2
			continue
		}

		rdataStart := rdataOff - int(hdr.Rdlength)
		rdLen := int(hdr.Rdlength)

		// Safety check: don't overflow packet
		if off+2+rdLen > len(buf) {
			rdLen = 0
		}

		binary.BigEndian.PutUint16(buf[off:off+2], uint16(rdLen))
		off += 2

		if rdLen > 0 {
			copy(buf[off:off+rdLen], rdataBuf[rdataStart:rdataStart+rdLen])
			off += rdLen
		}
	}

	return off
}
