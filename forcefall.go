package main

import (
	"fmt"
	"math/bits"
	"net/netip"
	"strings"
)

// forceFallMatcher implements the force_fall matching logic.
// Include rules (without ^) use OR logic: any match triggers force_fall.
// Negate rules (with ^) use AND logic: all negate conditions must be satisfied
// (i.e. client IP must NOT be in ANY negated prefix) for force_fall to trigger.
type forceFallMatcher struct {
	includePrefixes []netip.Prefix // OR logic: any match -> force_fall
	negatePrefixes  []netip.Prefix // AND logic: must NOT match any -> force_fall
}

func (m *forceFallMatcher) Match(addr netip.Addr) bool {
	if len(m.includePrefixes) == 0 && len(m.negatePrefixes) == 0 {
		return false
	}
	// Check include rules (OR): any match -> true
	for _, p := range m.includePrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	// Check negate rules (AND): ALL negate prefixes must NOT contain addr
	if len(m.negatePrefixes) > 0 {
		for _, p := range m.negatePrefixes {
			if p.Contains(addr) {
				return false
			}
		}
		return true
	}
	return false
}

// ipToUint32 converts a 4-byte IPv4 address to uint32.
// Returns 0 and false if addr is not IPv4.
func ipToUint32(addr netip.Addr) (uint32, bool) {
	if !addr.Is4() && !addr.Is4In6() {
		return 0, false
	}
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), true
}

// uint32ToIP converts a uint32 to a netip.Addr (IPv4).
func uint32ToIP(n uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{
		byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
	})
}

// rangeToPrefix converts an IP range [start, end] to the minimal set of CIDR prefixes.
func rangeToPrefix(start, end netip.Addr) []netip.Prefix {
	if !start.Is4() || !end.Is4() {
		return nil
	}
	s, ok1 := ipToUint32(start)
	e, ok2 := ipToUint32(end)
	if !ok1 || !ok2 {
		return nil
	}
	if s > e {
		return nil
	}
	var result []netip.Prefix
	for {
		// Largest aligned block starting at s: 2^trailing_zeros(s).
		alignExp := 32
		if s != 0 {
			alignExp = bits.TrailingZeros32(s)
		}
		// Largest block fitting in remaining span: 2^floor(log2(e-s+1)).
		// uint64 carries the full IPv4 space (e-s+1 == 2^32).
		span := uint64(e) - uint64(s) + 1
		sizeExp := bits.Len64(span) - 1
		exp := alignExp
		if sizeExp < exp {
			exp = sizeExp
		}
		result = append(result, netip.PrefixFrom(uint32ToIP(s), 32-exp))
		next := uint64(s) + (uint64(1) << exp)
		if next > uint64(e) {
			break
		}
		s = uint32(next)
	}
	return result
}

// parseForceFallEntry parses a single force_fall entry string.
// Returns the parsed prefixes, whether it's negated, and any error.
// Supports: single IP, CIDR, IP range (start-end), with optional ^ prefix.
func parseForceFallEntry(s string) (prefixes []netip.Prefix, negated bool, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false, nil
	}
	if strings.HasPrefix(s, "^") {
		negated = true
		s = s[1:]
	}
	if strings.Contains(s, "-") {
		// IP range: start-end
		parts := strings.SplitN(s, "-", 2)
		start, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, negated, fmt.Errorf("invalid range start IP %s: %w", parts[0], err)
		}
		end, err := netip.ParseAddr(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, negated, fmt.Errorf("invalid range end IP %s: %w", parts[1], err)
		}
		prefixes = rangeToPrefix(start, end)
		if len(prefixes) == 0 {
			return nil, negated, fmt.Errorf("invalid IP range %s-%s", parts[0], parts[1])
		}
		return prefixes, negated, nil
	}
	if strings.Contains(s, "/") {
		// CIDR
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, negated, fmt.Errorf("invalid CIDR %s: %w", s, err)
		}
		return []netip.Prefix{prefix}, negated, nil
	}
	// Single IP
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return nil, negated, fmt.Errorf("invalid IP %s: %w", s, err)
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return []netip.Prefix{netip.PrefixFrom(addr, bits)}, negated, nil
}
