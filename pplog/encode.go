package pplog

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"codeberg.org/miekg/dns"
)

// Protocol constants
const (
	MagicByte0 byte = 0x50 // 'P'
	MagicByte1 byte = 0x4C // 'L'

	HeaderSize      = 18 // Magic(2) + KeyHint(4) + Nonce(12)
	NonceSize       = 12
	KeyHintSize     = 4
	AEADOverhead    = 16 // Poly1305 tag
	InnerHeaderSize = 7  // SeqNum(4) + Level(1) + PayloadLen(2)

	// MaxInnerPayload is the max payload bytes available inside encrypted packets.
	MaxInnerPayload = MaxPacketSize - HeaderSize - AEADOverhead - InnerHeaderSize

	// Flags
	FlagIPv6 byte = 1 << 0

	// Route values
	RouteCache     byte = 0
	RouteLocal     byte = 1
	RouteFall      byte = 2
	RouteHosts     byte = 3
	RouteForceFall byte = 4
	RouteHookFall  byte = 5

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

// EncodeHeader writes the 18-byte encrypted header into buf.
// Format: Magic(2) + KeyHint(4) + Nonce(12).
func EncodeHeader(buf []byte, keyHint [4]byte, nonce [12]byte) int {
	buf[0] = MagicByte0
	buf[1] = MagicByte1
	copy(buf[2:6], keyHint[:])
	copy(buf[6:18], nonce[:])
	return HeaderSize
}

// EncodeInnerHeader writes the 7-byte inner plaintext header: SeqNum(4) + Level(1) + PayloadLen(2).
func EncodeInnerHeader(buf []byte, seq uint32, level byte, payloadLen uint16) int {
	binary.BigEndian.PutUint32(buf[0:4], seq)
	buf[4] = level
	binary.BigEndian.PutUint16(buf[5:7], payloadLen)
	return InnerHeaderSize
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
	maxMsg := MaxInnerPayload - 5 // 5 = timestamp(4) + severity(1)
	if msgLen > maxMsg {
		msgLen = maxMsg
	}
	copy(buf[off:off+msgLen], entry.Message[:msgLen])
	off += msgLen

	return off
}

// fitPayload re-encodes a query entry with RR trimming to fit within maxSize bytes.
// Only applies to level 3-4 where RR sections can overflow.
// Trimming priority: 1) reduce same-type answer RRs, 2) remove extra RRs,
// 3) remove non-query-type answer RRs, 4) keep at least 1 answer RR.
//
// Uses a single stack-allocated QueryEntry copy and pre-filters OPT records
// to avoid repeated heap allocations.
func fitPayload(buf []byte, entry *QueryEntry, level int, ts uint32, maxSize int) int {
	// First try full encode
	n := EncodeQueryEntry(buf, entry, level, ts)
	if n <= maxSize || level < 3 {
		return n
	}

	// Stack copy — reuse this single struct for all trimming attempts
	trimmed := *entry

	// Pre-filter OPT records once (copies slices to avoid mutating original)
	answers := make([]dns.RR, len(entry.AnswerRRs))
	copy(answers, entry.AnswerRRs)
	answers = filterOPT(answers)

	extras := make([]dns.RR, len(entry.ExtraRRs))
	copy(extras, entry.ExtraRRs)
	extras = filterOPT(extras)

	qtype := entry.QType

	// Separate answer RRs by type match
	var sameType, diffType []dns.RR
	for _, rr := range answers {
		if dns.RRToType(rr) == qtype {
			sameType = append(sameType, rr)
		} else {
			diffType = append(diffType, rr)
		}
	}

	// Strategy 1: Trim same-type answer RRs (keep ~20 max)
	trimLimits := []int{20, 10, 5, 1}
	for _, limit := range trimLimits {
		if len(sameType) > limit {
			trimmed.AnswerRRs = append(sameType[:limit:limit], diffType...)
			trimmed.ExtraRRs = extras
			n = EncodeQueryEntry(buf, &trimmed, level, ts)
			if n <= maxSize {
				return n
			}
		}
	}

	// Strategy 2: Remove ADDITIONAL section entirely
	if level >= 4 {
		trimmed.AnswerRRs = append(sameType[:len(sameType):len(sameType)], diffType...)
		trimmed.ExtraRRs = nil
		n = EncodeQueryEntry(buf, &trimmed, 3, ts)
		if n <= maxSize {
			return n
		}
	}

	// Strategy 3: Remove non-query-type answer RRs
	trimmed.AnswerRRs = sameType
	trimmed.ExtraRRs = nil
	n = EncodeQueryEntry(buf, &trimmed, 3, ts)
	if n <= maxSize {
		return n
	}

	// Strategy 4: Keep only 1 same-type answer RR
	if len(sameType) > 1 {
		trimmed.AnswerRRs = sameType[:1]
		n = EncodeQueryEntry(buf, &trimmed, 3, ts)
		if n <= maxSize {
			return n
		}
	}

	// Final fallback: encode at level 2 (no RR sections at all)
	return EncodeQueryEntry(buf, entry, 2, ts)
}

// filterOPT returns RRs with OPT records removed, reusing the input slice to avoid allocation.
// WARNING: This modifies the input slice in place. Caller must not reuse the original slice.
func filterOPT(rrs []dns.RR) []dns.RR {
	n := 0
	for _, rr := range rrs {
		if dns.RRToType(rr) != dns.TypeOPT {
			rrs[n] = rr
			n++
		}
	}
	return rrs[:n]
}

// encodeRRSection encodes a DNS RR section (ANSWER or ADDITIONAL).
// It filters OPT records before encoding.
// Format: count(1) + per-RR: type(2) + ttl(4) + rdlen(2) + rdata(variable)
func encodeRRSection(buf []byte, rrs []dns.RR) int {
	// Fast path: scan for OPT first; the common case has none, in which case
	// we can pass the slice straight through with zero allocation. Only copy
	// when an OPT actually needs to be filtered out.
	hasOPT := false
	for _, rr := range rrs {
		if dns.RRToType(rr) == dns.TypeOPT {
			hasOPT = true
			break
		}
	}
	if !hasOPT {
		return encodeRRs(buf, rrs)
	}
	filtered := make([]dns.RR, len(rrs))
	copy(filtered, rrs)
	return encodeRRs(buf, filterOPT(filtered))
}

// encodeRRs encodes pre-filtered RRs into buf (no OPT filtering).
// Used by fitPayload which pre-filters RRs to avoid redundant filterOPT calls.
func encodeRRs(buf []byte, rrs []dns.RR) int {
	off := 0

	count := len(rrs)
	if count > 255 {
		count = 255
	}
	buf[off] = byte(count)
	off++

	// Stack-local buffer for hex decode, avoids per-RR heap allocation
	var rdataBuf [512]byte

	written := 0
	for i := 0; i < count; i++ {
		rr := rrs[i]
		hdr := rr.Header()
		rrType := dns.RRToType(rr)

		// Need at least 8 bytes for RRType(2) + TTL(4) + RDataLen(2)
		if off+8 > len(buf) {
			break
		}

		// Extract rdata by converting to RFC3597 (wire format).
		var rdLen int
		var rfc dns.RFC3597
		if err := rfc.ToRFC3597(rr); err == nil && rfc.RFC3597.Data != "" {
			n, decErr := hexDecodeInto(rdataBuf[:], rfc.RFC3597.Data)
			if decErr != nil {
				// RData exceeds our per-RR scratch buffer (or invalid hex):
				// skip this RR rather than write a truncated copy that the
				// receiver would parse as corrupt wire data.
				continue
			}
			rdLen = n
		}

		// Safety check: don't overflow packet
		if off+8+rdLen > len(buf) {
			break
		}

		// RRType (2 bytes)
		binary.BigEndian.PutUint16(buf[off:off+2], rrType)
		off += 2

		// TTL (4 bytes)
		binary.BigEndian.PutUint32(buf[off:off+4], hdr.TTL)
		off += 4

		binary.BigEndian.PutUint16(buf[off:off+2], uint16(rdLen))
		off += 2

		copy(buf[off:off+rdLen], rdataBuf[:rdLen])
		off += rdLen
		written++
	}

	// Update actual count written
	buf[0] = byte(written)

	return off
}

// hexDecodeInto decodes a hex string into the provided buffer, avoiding allocation.
// Returns the number of bytes written and any error. If the decoded length
// exceeds len(dst), it returns an error rather than silently truncating —
// truncation would corrupt the on-the-wire RR.
func hexDecodeInto(dst []byte, s string) (int, error) {
	n := len(s) / 2
	if n > len(dst) {
		return 0, fmt.Errorf("hexDecodeInto: dst too small (need %d, have %d)", n, len(dst))
	}
	for i := 0; i < n; i++ {
		hi := hexNibble(s[i*2])
		lo := hexNibble(s[i*2+1])
		if hi > 15 || lo > 15 {
			return 0, fmt.Errorf("invalid hex")
		}
		dst[i] = hi<<4 | lo
	}
	return n, nil
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 255
	}
}
