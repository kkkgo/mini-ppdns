package dnsutils

import (
	"strconv"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// forEachAnswerRR walks Answer/Authority/Additional sections and calls fn
// for every RR that carries a meaningful TTL. OPT records are skipped
// because their "TTL" bits encode EDNS0 flags, not a cache lifetime.
func forEachAnswerRR(m *dns.Msg, fn func(rr dns.RR)) {
	sections := [...][]dns.RR{m.Answer, m.Ns, m.Extra}
	for _, s := range sections {
		for _, rr := range s {
			if dns.RRToType(rr) == dns.TypeOPT {
				continue
			}
			fn(rr)
		}
	}
}

// GetMinimalTTL returns the smallest TTL across all non-OPT records.
// An empty message yields 0.
func GetMinimalTTL(m *dns.Msg) uint32 {
	var (
		out   uint32
		found bool
	)
	forEachAnswerRR(m, func(rr dns.RR) {
		t := rr.Header().TTL
		if !found || t < out {
			out = t
			found = true
		}
	})
	if !found {
		return 0
	}
	return out
}

// SetTTL overwrites the TTL on every non-OPT record with ttl.
func SetTTL(m *dns.Msg, ttl uint32) {
	forEachAnswerRR(m, func(rr dns.RR) {
		rr.Header().TTL = ttl
	})
}

// ApplyMaximumTTL caps each non-OPT record's TTL at ttl (lower values stay).
func ApplyMaximumTTL(m *dns.Msg, ttl uint32) {
	forEachAnswerRR(m, func(rr dns.RR) {
		if h := rr.Header(); h.TTL > ttl {
			h.TTL = ttl
		}
	})
}

// ApplyMinimalTTL raises each non-OPT record's TTL to at least ttl.
func ApplyMinimalTTL(m *dns.Msg, ttl uint32) {
	forEachAnswerRR(m, func(rr dns.RR) {
		if h := rr.Header(); h.TTL < ttl {
			h.TTL = ttl
		}
	})
}

// SubtractTTL decrements every non-OPT record's TTL by delta. Records
// whose TTL would go to zero or below are clamped to 1, and overflowed
// reports that at least one such clamp happened (i.e. the answer is
// approaching the end of its useful life).
func SubtractTTL(m *dns.Msg, delta uint32) (overflowed bool) {
	forEachAnswerRR(m, func(rr dns.RR) {
		h := rr.Header()
		if h.TTL > delta {
			h.TTL -= delta
			return
		}
		h.TTL = 1
		overflowed = true
	})
	return
}

// QclassToString renders a DNS class code, falling back to a decimal
// literal when the code is not in the standard registry.
func QclassToString(u uint16) string {
	if s, ok := dns.ClassToString[u]; ok {
		return s
	}
	return strconv.Itoa(int(u))
}

// QtypeToString renders a DNS rrtype code, using the upstream library's
// own table (which covers RFC-assigned types plus the meta types).
func QtypeToString(u uint16) string {
	return dnsutil.TypeToString(u)
}
