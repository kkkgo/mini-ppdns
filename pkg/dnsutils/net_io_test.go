package dnsutils

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"
)

func TestTCPReadWrite(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	rr, _ := dns.NewRR("example.com. 300 IN A 1.2.3.4")
	m.Answer = append(m.Answer, rr)

	// Write to buffer
	var buf bytes.Buffer
	n, err := WriteMsgToTCP(&buf, m)
	if err != nil {
		t.Fatalf("WriteMsgToTCP err: %v", err)
	}
	if n == 0 {
		t.Fatal("WriteMsgToTCP wrote 0 bytes")
	}

	// Read it back
	m2, readN, err := ReadMsgFromTCP(&buf)
	if err != nil {
		t.Fatalf("ReadMsgFromTCP err: %v", err)
	}
	if readN == 0 {
		t.Fatal("ReadMsgFromTCP read 0 bytes")
	}
	if len(m2.Question) == 0 || m2.Question[0].Name != "example.com." {
		t.Fatal("question mismatch")
	}
	if len(m2.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(m2.Answer))
	}
}

func TestTCPReadWriteRaw(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("test.com.", dns.TypeAAAA)
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack err: %v", err)
	}

	var buf bytes.Buffer
	n, err := WriteRawMsgToTCP(&buf, wire)
	if err != nil {
		t.Fatalf("WriteRawMsgToTCP err: %v", err)
	}
	if n != len(wire)+2 {
		t.Fatalf("written = %d, want %d", n, len(wire)+2)
	}

	raw, err := ReadRawMsgFromTCP(&buf)
	if err != nil {
		t.Fatalf("ReadRawMsgFromTCP err: %v", err)
	}
	if !bytes.Equal(*raw, wire) {
		t.Fatal("raw data mismatch")
	}
}

func TestWriteRawMsgToTCP_Empty(t *testing.T) {
	var buf bytes.Buffer
	_, err := WriteRawMsgToTCP(&buf, []byte{})
	if err == nil {
		t.Fatal("empty payload should error")
	}
}

func TestWriteRawMsgToTCP_TooLarge(t *testing.T) {
	var buf bytes.Buffer
	large := make([]byte, dns.MaxMsgSize+1)
	_, err := WriteRawMsgToTCP(&buf, large)
	if err == nil {
		t.Fatal("oversized payload should error")
	}
}

func TestReadRawMsgFromTCP_TooSmall(t *testing.T) {
	// Craft a TCP frame with length <= DnsHeaderLen
	frame := []byte{0, 5, 1, 2, 3, 4, 5}
	_, err := ReadRawMsgFromTCP(bytes.NewReader(frame))
	if err != ErrPayloadTooSmall {
		t.Fatalf("expected ErrPayloadTooSmall, got %v", err)
	}
}

func TestUDPReadWrite(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("udp.com.", dns.TypeMX)

	var buf bytes.Buffer
	n, err := WriteMsgToUDP(&buf, m)
	if err != nil {
		t.Fatalf("WriteMsgToUDP err: %v", err)
	}
	if n == 0 {
		t.Fatal("wrote 0 bytes")
	}

	m2, readN, err := ReadMsgFromUDP(&buf, 512)
	if err != nil {
		t.Fatalf("ReadMsgFromUDP err: %v", err)
	}
	if readN == 0 {
		t.Fatal("read 0 bytes")
	}
	if len(m2.Question) == 0 || m2.Question[0].Name != "udp.com." {
		t.Fatal("question mismatch")
	}
}

func TestReadMsgFromUDP_SmallBufSize(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("test.com.", dns.TypeA)

	var buf bytes.Buffer
	WriteMsgToUDP(&buf, m)

	// bufSize < MinMsgSize should be auto-adjusted
	m2, _, err := ReadMsgFromUDP(&buf, 10)
	if err != nil {
		t.Fatalf("ReadMsgFromUDP err: %v", err)
	}
	if len(m2.Question) == 0 {
		t.Fatal("no questions")
	}
}

func BenchmarkTCP_WriteRead(b *testing.B) {
	m := new(dns.Msg)
	m.SetQuestion("bench.com.", dns.TypeA)
	rr, _ := dns.NewRR("bench.com. 60 IN A 10.0.0.1")
	m.Answer = append(m.Answer, rr)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		WriteMsgToTCP(&buf, m)
		ReadMsgFromTCP(&buf)
	}
}
