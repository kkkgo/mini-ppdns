package pool

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/miekg/dns"
)

func TestPackBuffer(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	rr, _ := dns.NewRR("example.com. 3600 IN A 1.2.3.4")
	m.Answer = append(m.Answer, rr)

	buf, err := PackBuffer(m)
	if err != nil {
		t.Fatalf("PackBuffer failed: %v", err)
	}
	defer ReleaseBuf(buf)

	// Verify unpacking produces the same message
	m2 := new(dns.Msg)
	if err := m2.Unpack(*buf); err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}
	if len(m2.Question) == 0 || m2.Question[0].Name != "example.com." {
		t.Error("unpacked question mismatch")
	}
	if len(m2.Answer) != 1 {
		t.Errorf("unpacked answer count = %d, want 1", len(m2.Answer))
	}
}

func TestPackBuffer_EmptyMsg(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("test.com.", dns.TypeAAAA)

	buf, err := PackBuffer(m)
	if err != nil {
		t.Fatalf("PackBuffer failed for empty msg: %v", err)
	}
	defer ReleaseBuf(buf)

	if len(*buf) == 0 {
		t.Error("packed buffer should not be empty")
	}
}

func TestPackTCPBuffer(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	rr, _ := dns.NewRR("example.com. 3600 IN A 1.2.3.4")
	m.Answer = append(m.Answer, rr)

	buf, err := PackTCPBuffer(m)
	if err != nil {
		t.Fatalf("PackTCPBuffer failed: %v", err)
	}
	defer ReleaseBuf(buf)

	// Verify the 2-byte TCP length header
	wire := *buf
	if len(wire) < 2 {
		t.Fatal("TCP buffer too short")
	}
	declaredLen := binary.BigEndian.Uint16(wire[:2])
	actualLen := len(wire) - 2
	if int(declaredLen) != actualLen {
		t.Errorf("TCP length header = %d, actual payload = %d", declaredLen, actualLen)
	}

	// Verify unpacking the payload
	m2 := new(dns.Msg)
	if err := m2.Unpack(wire[2:]); err != nil {
		t.Fatalf("Unpack TCP payload failed: %v", err)
	}
	if len(m2.Question) == 0 || m2.Question[0].Name != "example.com." {
		t.Error("TCP unpacked question mismatch")
	}
}

func TestPackTCPBuffer_LargePayload(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)

	// Add many A records to make a large payload (~4KB)
	for i := 0; i < 200; i++ {
		rr, _ := dns.NewRR("example.com. 3600 IN A 1.2.3.4")
		m.Answer = append(m.Answer, rr)
	}

	buf, err := PackTCPBuffer(m)
	if err != nil {
		t.Fatalf("PackTCPBuffer large payload failed: %v", err)
	}
	defer ReleaseBuf(buf)

	wire := *buf
	declaredLen := binary.BigEndian.Uint16(wire[:2])
	if int(declaredLen) != len(wire)-2 {
		t.Errorf("TCP length mismatch: header=%d, actual=%d", declaredLen, len(wire)-2)
	}

	// Verify unpacking
	m2 := new(dns.Msg)
	if err := m2.Unpack(wire[2:]); err != nil {
		t.Fatalf("Unpack large TCP payload failed: %v", err)
	}
	if len(m2.Answer) != 200 {
		t.Errorf("unpacked answer count = %d, want 200", len(m2.Answer))
	}
}

func TestPackBuffer_ReleaseIsSafe(t *testing.T) {
	// Verify that packing, releasing, then packing again works correctly
	for i := 0; i < 100; i++ {
		m := new(dns.Msg)
		m.SetQuestion("test.com.", dns.TypeA)
		rr, _ := dns.NewRR("test.com. 60 IN A 10.0.0.1")
		m.Answer = append(m.Answer, rr)

		buf, err := PackBuffer(m)
		if err != nil {
			t.Fatalf("iteration %d: PackBuffer failed: %v", i, err)
		}

		m2 := new(dns.Msg)
		if err := m2.Unpack(*buf); err != nil {
			t.Fatalf("iteration %d: Unpack failed: %v", i, err)
		}
		ReleaseBuf(buf)
	}
}

// --- Benchmarks ---

func BenchmarkPool_PackBuffer(b *testing.B) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	for i := 0; i < 10; i++ {
		r, _ := dns.NewRR("example.com. 3600 IN A 1.2.3.4")
		m.Answer = append(m.Answer, r)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf, err := PackBuffer(m)
			if err == nil {
				ReleaseBuf(buf)
			}
		}
	})
}

func BenchmarkPool_PackTCPBuffer(b *testing.B) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)

	payload := make([]byte, 2048)
	rand.Read(payload)
	r := new(dns.TXT)
	r.Hdr = dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}
	r.Txt = []string{string(payload)}
	m.Answer = append(m.Answer, r)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf, err := PackTCPBuffer(m)
			if err == nil {
				ReleaseBuf(buf)
			}
		}
	})
}
