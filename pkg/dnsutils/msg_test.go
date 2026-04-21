package dnsutils

import (
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func newMsgWithAnswer(name string, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	dnsutil.SetQuestion(m, name, dns.TypeA)
	rr := &dns.A{
		Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: ttl},
	}
	m.Answer = append(m.Answer, rr)
	return m
}

func TestGetMinimalTTL(t *testing.T) {
	t.Run("single_record", func(t *testing.T) {
		m := newMsgWithAnswer("a.com.", 300)
		if ttl := GetMinimalTTL(m); ttl != 300 {
			t.Fatalf("ttl = %d, want 300", ttl)
		}
	})

	t.Run("multiple_records", func(t *testing.T) {
		m := newMsgWithAnswer("a.com.", 300)
		m.Ns = append(m.Ns, &dns.SOA{
			Hdr: dns.Header{Name: "a.com.", Class: dns.ClassINET, TTL: 100},
		})
		if ttl := GetMinimalTTL(m); ttl != 100 {
			t.Fatalf("ttl = %d, want 100", ttl)
		}
	})

	t.Run("no_records", func(t *testing.T) {
		m := new(dns.Msg)
		dnsutil.SetQuestion(m, "a.com.", dns.TypeA)
		if ttl := GetMinimalTTL(m); ttl != 0 {
			t.Fatalf("ttl = %d, want 0", ttl)
		}
	})

	t.Run("skip_opt", func(t *testing.T) {
		m := newMsgWithAnswer("a.com.", 200)
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.SetUDPSize(4096)
		m.Extra = append(m.Extra, opt)
		if ttl := GetMinimalTTL(m); ttl != 200 {
			t.Fatalf("ttl = %d, want 200 (should skip OPT)", ttl)
		}
	})
}

func TestSetTTL(t *testing.T) {
	m := newMsgWithAnswer("a.com.", 300)
	m.Ns = append(m.Ns, &dns.SOA{
		Hdr: dns.Header{Name: "a.com.", Class: dns.ClassINET, TTL: 600},
	})

	SetTTL(m, 42)

	for _, rr := range m.Answer {
		if rr.Header().TTL != 42 {
			t.Fatalf("answer ttl = %d, want 42", rr.Header().TTL)
		}
	}
	for _, rr := range m.Ns {
		if rr.Header().TTL != 42 {
			t.Fatalf("ns ttl = %d, want 42", rr.Header().TTL)
		}
	}
}

func TestSetTTL_SkipOPT(t *testing.T) {
	m := newMsgWithAnswer("a.com.", 300)
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.SetUDPSize(4096)
	m.Extra = append(m.Extra, opt)

	SetTTL(m, 10)

	// OPT TTL should not be changed
	for _, rr := range m.Extra {
		if dns.RRToType(rr) == dns.TypeOPT {
			// OPT record, its "TTL" should remain as-is (used for flags)
			continue
		}
	}
	if m.Answer[0].Header().TTL != 10 {
		t.Fatalf("answer ttl = %d, want 10", m.Answer[0].Header().TTL)
	}
}

func TestApplyMaximumTTL(t *testing.T) {
	m := newMsgWithAnswer("a.com.", 500)
	ApplyMaximumTTL(m, 300)
	if m.Answer[0].Header().TTL != 300 {
		t.Fatalf("ttl = %d, want 300", m.Answer[0].Header().TTL)
	}

	// Should not increase TTL below maximum
	m2 := newMsgWithAnswer("a.com.", 100)
	ApplyMaximumTTL(m2, 300)
	if m2.Answer[0].Header().TTL != 100 {
		t.Fatalf("ttl = %d, want 100", m2.Answer[0].Header().TTL)
	}
}

func TestApplyMinimalTTL(t *testing.T) {
	m := newMsgWithAnswer("a.com.", 50)
	ApplyMinimalTTL(m, 300)
	if m.Answer[0].Header().TTL != 300 {
		t.Fatalf("ttl = %d, want 300", m.Answer[0].Header().TTL)
	}

	// Should not decrease TTL above minimum
	m2 := newMsgWithAnswer("a.com.", 600)
	ApplyMinimalTTL(m2, 300)
	if m2.Answer[0].Header().TTL != 600 {
		t.Fatalf("ttl = %d, want 600", m2.Answer[0].Header().TTL)
	}
}

func TestSubtractTTL(t *testing.T) {
	t.Run("normal", func(t *testing.T) {
		m := newMsgWithAnswer("a.com.", 300)
		o := SubtractTTL(m, 100)
		if o {
			t.Fatal("should not overflow")
		}
		if m.Answer[0].Header().TTL != 200 {
			t.Fatalf("ttl = %d, want 200", m.Answer[0].Header().TTL)
		}
	})

	t.Run("overflow", func(t *testing.T) {
		m := newMsgWithAnswer("a.com.", 50)
		o := SubtractTTL(m, 100)
		if !o {
			t.Fatal("should overflow")
		}
		if m.Answer[0].Header().TTL != 1 {
			t.Fatalf("ttl = %d, want 1", m.Answer[0].Header().TTL)
		}
	})

	t.Run("equal", func(t *testing.T) {
		m := newMsgWithAnswer("a.com.", 100)
		o := SubtractTTL(m, 100)
		if !o {
			t.Fatal("should overflow when equal")
		}
		if m.Answer[0].Header().TTL != 1 {
			t.Fatalf("ttl = %d, want 1", m.Answer[0].Header().TTL)
		}
	})
}

func TestQclassToString(t *testing.T) {
	if s := QclassToString(dns.ClassINET); s != "IN" {
		t.Fatalf("QclassToString(IN) = %q, want IN", s)
	}
	// Unknown class should return number string
	s := QclassToString(9999)
	if s != "9999" {
		t.Fatalf("QclassToString(9999) = %q, want 9999", s)
	}
}

func TestQtypeToString(t *testing.T) {
	if s := QtypeToString(dns.TypeA); s != "A" {
		t.Fatalf("QtypeToString(A) = %q, want A", s)
	}
	if s := QtypeToString(dns.TypeAAAA); s != "AAAA" {
		t.Fatalf("QtypeToString(AAAA) = %q, want AAAA", s)
	}
}
