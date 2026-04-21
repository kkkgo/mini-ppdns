package pplog

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestParseUUID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		wantHex string
	}{
		{"valid with hyphens", "990c7c49-dbb2-470b-bb05-2f8260281759", false, "990c7c49dbb2470bbb052f8260281759"},
		{"valid without hyphens", "990c7c49dbb2470bbb052f8260281759", false, "990c7c49dbb2470bbb052f8260281759"},
		{"too short", "990c7c49", true, ""},
		{"invalid hex", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uuid, err := ParseUUID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseUUID(%q) err = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err == nil {
				got := ""
				for _, b := range uuid {
					got += sprintf02x(b)
				}
				if got != tt.wantHex {
					t.Errorf("ParseUUID(%q) = %s, want %s", tt.input, got, tt.wantHex)
				}
			}
		})
	}
}

func sprintf02x(b byte) string {
	const hex = "0123456789abcdef"
	return string([]byte{hex[b>>4], hex[b&0x0f]})
}

func TestEncodeHeader(t *testing.T) {
	keyHint := [4]byte{0xAA, 0xBB, 0xCC, 0xDD}
	nonce := [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}

	var buf [HeaderSize]byte
	n := EncodeHeader(buf[:], keyHint, nonce)
	if n != HeaderSize {
		t.Fatalf("EncodeHeader returned %d, want %d", n, HeaderSize)
	}

	if buf[0] != 0x50 || buf[1] != 0x4C {
		t.Errorf("magic = %02x %02x, want 50 4C", buf[0], buf[1])
	}
	for i := 0; i < 4; i++ {
		if buf[2+i] != keyHint[i] {
			t.Errorf("keyHint[%d] = %02x, want %02x", i, buf[2+i], keyHint[i])
		}
	}
	for i := 0; i < 12; i++ {
		if buf[6+i] != nonce[i] {
			t.Errorf("nonce[%d] = %02x, want %02x", i, buf[6+i], nonce[i])
		}
	}
}

func TestEncodeInnerHeader(t *testing.T) {
	var buf [InnerHeaderSize]byte
	n := EncodeInnerHeader(buf[:], 42, 3, 100)
	if n != InnerHeaderSize {
		t.Fatalf("EncodeInnerHeader returned %d, want %d", n, InnerHeaderSize)
	}
	seq := binary.BigEndian.Uint32(buf[0:4])
	if seq != 42 {
		t.Errorf("seq = %d, want 42", seq)
	}
	if buf[4] != 3 {
		t.Errorf("level = %d, want 3", buf[4])
	}
	plen := binary.BigEndian.Uint16(buf[5:7])
	if plen != 100 {
		t.Errorf("payloadLen = %d, want 100", plen)
	}
}

func TestEncodeQueryEntry_Level1_IPv4(t *testing.T) {
	entry := &QueryEntry{
		ClientIP:  netip.MustParseAddr("192.168.1.100"),
		QType:     dns.TypeA,
		Rcode:     0,
		Route:     RouteLocal,
		Duration:  12,
		QueryName: "www.google.com.",
	}

	var buf [512]byte
	n := EncodeQueryEntry(buf[:], entry, 1, 0x67C8A13B)

	off := 0
	ts := binary.BigEndian.Uint32(buf[off : off+4])
	if ts != 0x67C8A13B {
		t.Errorf("timestamp = %08x, want 67C8A13B", ts)
	}
	off += 4

	if buf[off] != 0 {
		t.Errorf("flags = %02x, want 00 (IPv4)", buf[off])
	}
	off++

	if buf[off] != 192 || buf[off+1] != 168 || buf[off+2] != 1 || buf[off+3] != 100 {
		t.Errorf("clientIP = %d.%d.%d.%d, want 192.168.1.100", buf[off], buf[off+1], buf[off+2], buf[off+3])
	}
	off += 4

	qtype := binary.BigEndian.Uint16(buf[off : off+2])
	if qtype != 1 {
		t.Errorf("qtype = %d, want 1", qtype)
	}
	off += 2

	if buf[off] != 0 {
		t.Errorf("rcode = %d, want 0", buf[off])
	}
	off++

	if buf[off] != RouteLocal {
		t.Errorf("route = %d, want %d", buf[off], RouteLocal)
	}
	off++

	dur := binary.BigEndian.Uint16(buf[off : off+2])
	if dur != 12 {
		t.Errorf("duration = %d, want 12", dur)
	}
	off += 2

	nameLen := int(buf[off])
	if nameLen != 14 {
		t.Errorf("nameLen = %d, want 14", nameLen)
	}
	off++

	name := string(buf[off : off+nameLen])
	if name != "www.google.com" {
		t.Errorf("queryName = %q, want %q", name, "www.google.com")
	}
	off += nameLen

	if n != off {
		t.Errorf("encodeQueryEntry returned %d, expected %d", n, off)
	}
}

func TestEncodeQueryEntry_Level1_IPv6(t *testing.T) {
	entry := &QueryEntry{
		ClientIP:  netip.MustParseAddr("2001:db8::1"),
		QType:     dns.TypeAAAA,
		Rcode:     0,
		Route:     RouteCache,
		Duration:  0,
		QueryName: "example.com.",
	}

	var buf [512]byte
	n := EncodeQueryEntry(buf[:], entry, 1, 1000)

	off := 4
	if buf[off]&FlagIPv6 == 0 {
		t.Error("flags bit0 (IPv6) not set")
	}
	off++

	expectedIP := netip.MustParseAddr("2001:db8::1").As16()
	for i := 0; i < 16; i++ {
		if buf[off+i] != expectedIP[i] {
			t.Errorf("clientIP[%d] = %02x, want %02x", i, buf[off+i], expectedIP[i])
		}
	}
	off += 16
	off += 6 // QType(2) + Rcode(1) + Route(1) + Duration(2)

	nameLen := int(buf[off])
	if nameLen != 11 {
		t.Errorf("nameLen = %d, want 11", nameLen)
	}
	off++
	off += nameLen

	if n != off {
		t.Errorf("total = %d, expected %d", n, off)
	}
}

func TestEncodeQueryEntry_Level2(t *testing.T) {
	entry := &QueryEntry{
		ClientIP:  netip.MustParseAddr("10.0.0.1"),
		QType:     dns.TypeA,
		Rcode:     0,
		Route:     RouteLocal,
		Duration:  25,
		QueryName: "test.com.",
		Upstream:  "udp://8.8.8.8:53",
	}

	var buf [512]byte
	n := EncodeQueryEntry(buf[:], entry, 2, 1000)

	level1Len := 4 + 1 + 4 + 2 + 1 + 1 + 2 + 1 + len("test.com")
	expectedLen := level1Len + 1 + len("udp://8.8.8.8:53")
	if n != expectedLen {
		t.Errorf("level2 total = %d, want %d", n, expectedLen)
	}

	upOff := level1Len
	upLen := int(buf[upOff])
	if upLen != 16 {
		t.Errorf("upstreamLen = %d, want 16", upLen)
	}
	upstream := string(buf[upOff+1 : upOff+1+upLen])
	if upstream != "udp://8.8.8.8:53" {
		t.Errorf("upstream = %q, want %q", upstream, "udp://8.8.8.8:53")
	}
}

func TestEncodeQueryEntry_Level3(t *testing.T) {
	aRR, _ := dns.New("example.com. 300 IN A 1.2.3.4")
	entry := &QueryEntry{
		ClientIP:  netip.MustParseAddr("10.0.0.1"),
		QType:     dns.TypeA,
		Rcode:     0,
		Route:     RouteLocal,
		Duration:  10,
		QueryName: "example.com.",
		Upstream:  "udp://1.1.1.1:53",
		AnswerRRs: []dns.RR{aRR},
	}

	var buf [512]byte
	n := EncodeQueryEntry(buf[:], entry, 3, 1000)

	if n < 30 {
		t.Errorf("level3 packet too small: %d bytes", n)
	}

	level1Len := 4 + 1 + 4 + 2 + 1 + 1 + 2 + 1 + len("example.com")
	level2Len := 1 + len("udp://1.1.1.1:53")
	ansOff := level1Len + level2Len

	if buf[ansOff] != 1 {
		t.Errorf("answerCount = %d, want 1", buf[ansOff])
	}
	ansOff++

	rrType := binary.BigEndian.Uint16(buf[ansOff : ansOff+2])
	if rrType != dns.TypeA {
		t.Errorf("rrType = %d, want %d", rrType, dns.TypeA)
	}
	ansOff += 2

	ttl := binary.BigEndian.Uint32(buf[ansOff : ansOff+4])
	if ttl != 300 {
		t.Errorf("ttl = %d, want 300", ttl)
	}
	ansOff += 4

	rdLen := binary.BigEndian.Uint16(buf[ansOff : ansOff+2])
	if rdLen != 4 {
		t.Errorf("rdataLen = %d, want 4", rdLen)
	}
	ansOff += 2

	if buf[ansOff] != 1 || buf[ansOff+1] != 2 || buf[ansOff+2] != 3 || buf[ansOff+3] != 4 {
		t.Errorf("rdata = %d.%d.%d.%d, want 1.2.3.4", buf[ansOff], buf[ansOff+1], buf[ansOff+2], buf[ansOff+3])
	}
	ansOff += 4

	if n != ansOff {
		t.Errorf("total = %d, expected %d", n, ansOff)
	}
}

func TestEncodeEventEntry(t *testing.T) {
	entry := &EventEntry{
		Severity: SeverityInfo,
		Message:  "server started on :53",
	}

	var buf [512]byte
	n := EncodeEventEntry(buf[:], entry, 0x67C8A13B)

	ts := binary.BigEndian.Uint32(buf[0:4])
	if ts != 0x67C8A13B {
		t.Errorf("timestamp = %08x, want 67C8A13B", ts)
	}
	if buf[4] != SeverityInfo {
		t.Errorf("severity = %d, want %d", buf[4], SeverityInfo)
	}
	msg := string(buf[5:n])
	if msg != "server started on :53" {
		t.Errorf("message = %q, want %q", msg, "server started on :53")
	}
	expected := 4 + 1 + len("server started on :53")
	if n != expected {
		t.Errorf("total = %d, want %d", n, expected)
	}
}

func TestReporter_NonBlocking(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	r, err := NewReporter(Config{
		UUID:   "990c7c49-dbb2-470b-bb05-2f8260281759",
		Server: pc.LocalAddr().String(),
		Level:  1,
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	defer r.Close()

	entry := &QueryEntry{
		ClientIP:  netip.MustParseAddr("192.168.1.1"),
		QType:     dns.TypeA,
		Rcode:     0,
		Route:     RouteCache,
		Duration:  0,
		QueryName: "test.com.",
	}

	for i := 0; i < channelSize+100; i++ {
		r.Report(entry)
	}

	if r.Dropped() == 0 {
		t.Log("no drops detected, sender was fast enough")
	}
}

func TestReporter_ReceivesEncryptedPacket(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	uuidStr := "990c7c49-dbb2-470b-bb05-2f8260281759"
	r, err := NewReporter(Config{
		UUID:   uuidStr,
		Server: pc.LocalAddr().String(),
		Level:  1,
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}

	entry := &QueryEntry{
		ClientIP:  netip.MustParseAddr("10.0.0.1"),
		QType:     dns.TypeA,
		Rcode:     0,
		Route:     RouteLocal,
		Duration:  5,
		QueryName: "example.com.",
	}
	r.Report(entry)
	r.Close()

	buf := make([]byte, MaxPacketSize)
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	pkt := buf[:n]

	// Validate header magic
	if pkt[0] != MagicByte0 || pkt[1] != MagicByte1 {
		t.Errorf("magic = %02x%02x, want %02x%02x", pkt[0], pkt[1], MagicByte0, MagicByte1)
	}

	// Verify KeyHint
	uuid, _ := ParseUUID(uuidStr)
	hash := sha256.Sum256(uuid[:])
	for i := 0; i < 4; i++ {
		if pkt[2+i] != hash[i] {
			t.Errorf("keyHint[%d] = %02x, want %02x", i, pkt[2+i], hash[i])
		}
	}

	// Decrypt
	aead, err := chacha20poly1305.New(hash[:])
	if err != nil {
		t.Fatalf("chacha20poly1305.New: %v", err)
	}

	nonce := pkt[6:18]
	ad := pkt[:HeaderSize]
	ciphertext := pkt[HeaderSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		t.Fatalf("AEAD Open: %v", err)
	}

	// Validate inner header
	if len(plaintext) < InnerHeaderSize {
		t.Fatalf("inner plaintext too short: %d", len(plaintext))
	}

	seq := binary.BigEndian.Uint32(plaintext[0:4])
	if seq != 1 {
		t.Errorf("seq = %d, want 1", seq)
	}
	level := plaintext[4]
	if level != 1 {
		t.Errorf("level = %d, want 1", level)
	}
	payloadLen := binary.BigEndian.Uint16(plaintext[5:7])
	if int(payloadLen)+InnerHeaderSize != len(plaintext) {
		t.Errorf("inner header(%d) + payload(%d) = %d, but plaintext is %d bytes",
			InnerHeaderSize, payloadLen, InnerHeaderSize+int(payloadLen), len(plaintext))
	}
}

func TestReporter_DecryptionWithWrongKey(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	r, err := NewReporter(Config{
		UUID:   "990c7c49-dbb2-470b-bb05-2f8260281759",
		Server: pc.LocalAddr().String(),
		Level:  1,
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}

	entry := &QueryEntry{
		ClientIP:  netip.MustParseAddr("10.0.0.1"),
		QType:     dns.TypeA,
		Rcode:     0,
		Route:     RouteLocal,
		Duration:  5,
		QueryName: "example.com.",
	}
	r.Report(entry)
	r.Close()

	buf := make([]byte, MaxPacketSize)
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	pkt := buf[:n]

	// Try to decrypt with wrong UUID
	wrongUUID := [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	wrongHash := sha256.Sum256(wrongUUID[:])
	wrongAEAD, _ := chacha20poly1305.New(wrongHash[:])

	nonce := pkt[6:18]
	ad := pkt[:HeaderSize]
	ciphertext := pkt[HeaderSize:]

	_, err = wrongAEAD.Open(nil, nonce, ciphertext, ad)
	if err == nil {
		t.Error("expected decryption failure with wrong key")
	}
}

func TestFitPayload_Normal(t *testing.T) {
	aRR, _ := dns.New("example.com. 300 IN A 1.2.3.4")
	entry := &QueryEntry{
		ClientIP:  netip.MustParseAddr("10.0.0.1"),
		QType:     dns.TypeA,
		Rcode:     0,
		Route:     RouteLocal,
		Duration:  10,
		QueryName: "example.com.",
		Upstream:  "udp://1.1.1.1:53",
		AnswerRRs: []dns.RR{aRR},
	}

	var buf [MaxPacketSize]byte
	n := fitPayload(buf[:], entry, 3, 1000, MaxInnerPayload)
	if n <= 0 {
		t.Fatal("fitPayload returned 0")
	}
	if n > MaxInnerPayload {
		t.Errorf("fitPayload returned %d, exceeds max %d", n, MaxInnerPayload)
	}
}

func TestFitPayload_ManyRRs(t *testing.T) {
	var answers []dns.RR
	for i := 0; i < 100; i++ {
		rr, _ := dns.New(fmt.Sprintf("example.com. 300 IN A 1.2.3.%d", i%256))
		answers = append(answers, rr)
	}

	entry := &QueryEntry{
		ClientIP:  netip.MustParseAddr("10.0.0.1"),
		QType:     dns.TypeA,
		Rcode:     0,
		Route:     RouteLocal,
		Duration:  10,
		QueryName: "example.com.",
		Upstream:  "udp://1.1.1.1:53",
		AnswerRRs: answers,
	}

	var buf [MaxPacketSize]byte
	n := fitPayload(buf[:], entry, 3, 1000, MaxInnerPayload)
	if n > MaxInnerPayload {
		t.Errorf("fitPayload returned %d, exceeds max %d", n, MaxInnerPayload)
	}
	if n <= 0 {
		t.Fatal("fitPayload returned 0")
	}
}

func TestFitPayload_ManyRRsWithAdditional(t *testing.T) {
	var answers []dns.RR
	for i := 0; i < 100; i++ {
		rr, _ := dns.New(fmt.Sprintf("example.com. 300 IN A 1.2.3.%d", i%256))
		answers = append(answers, rr)
	}
	var extras []dns.RR
	for i := 0; i < 50; i++ {
		rr, _ := dns.New(fmt.Sprintf("ns%d.example.com. 300 IN A 10.0.0.%d", i, i%256))
		extras = append(extras, rr)
	}

	entry := &QueryEntry{
		ClientIP:  netip.MustParseAddr("10.0.0.1"),
		QType:     dns.TypeA,
		Rcode:     0,
		Route:     RouteLocal,
		Duration:  10,
		QueryName: "example.com.",
		Upstream:  "udp://1.1.1.1:53",
		AnswerRRs: answers,
		ExtraRRs:  extras,
	}

	var buf [MaxPacketSize]byte
	n := fitPayload(buf[:], entry, 4, 1000, MaxInnerPayload)
	if n > MaxInnerPayload {
		t.Errorf("fitPayload returned %d, exceeds max %d", n, MaxInnerPayload)
	}
	if n <= 0 {
		t.Fatal("fitPayload returned 0")
	}
}
