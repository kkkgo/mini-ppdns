package pool

import (
	"crypto/rand"
	"testing"

	"github.com/miekg/dns"
)

func BenchmarkPool_PackBuffer(b *testing.B) {
	// Create a dummy DNS message
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	// Add some dummy records to simulate a real response
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

	// Pre-fill a huge dummy payload to simulate an aggressive TCP transfer
	buf := make([]byte, 2048)
	rand.Read(buf)

	r := new(dns.TXT)
	r.Hdr = dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}
	r.Txt = []string{string(buf)}
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
