package server

import (
	"net"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func TestServeUDP(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to listen udp: %v", err)
	}

	h := &mockHandler{}
	opts := UDPServerOpts{
		MaxConcurrent: 10,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeUDP(conn, h, opts)
	}()

	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)

	// Make a client request
	clientConn, err := net.Dial("udp", conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed to dial udp: %v", err)
	}
	defer clientConn.Close()

	m := new(dns.Msg)
	dnsutil.SetQuestion(m, dnsutil.Fqdn("example.com"), dns.TypeA)
	if err := m.Pack(); err != nil {
		t.Fatalf("failed to pack msg: %v", err)
	}

	if _, err := clientConn.Write(m.Data); err != nil {
		t.Fatalf("failed to write udp: %v", err)
	}

	// Read response
	clientConn.SetReadDeadline(time.Now().Add(time.Second))
	respBuf := make([]byte, dns.MaxMsgSize)
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("failed to read resp udp: %v", err)
	}

	respMsg := new(dns.Msg)
	respMsg.Data = respBuf[:n]
	if err := respMsg.Unpack(); err != nil {
		t.Fatalf("failed to unpack resp msg: %v", err)
	}

	if respMsg.ID != m.ID {
		t.Errorf("expected id %d, got %d", m.ID, respMsg.ID)
	}
	if !h.called.Load() {
		t.Error("handler was not called")
	}

	// Test shutdown
	conn.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("ServeUDP returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("ServeUDP did not return after connection close")
	}
}
