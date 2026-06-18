package server

import (
	"context"
	"net"
	"sync/atomic"
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

// panicThenReplyHandler panics on its first call, then replies normally
// for every subsequent call. Used to verify the UDP server keeps running
// after a per-query handler panic.
type panicThenReplyHandler struct {
	calls       atomic.Int32
	panicked    atomic.Bool
	postPanicOK atomic.Bool
}

func (h *panicThenReplyHandler) Handle(_ context.Context, q *dns.Msg, _ QueryMeta, pack func(*dns.Msg) (*[]byte, error)) *[]byte {
	n := h.calls.Add(1)
	if n == 1 {
		h.panicked.Store(true)
		panic("simulated handler panic")
	}
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, q)
	rr, _ := dns.New(q.Question[0].Header().Name + " 60 IN A 127.0.0.1")
	resp.Answer = []dns.RR{rr}
	b, err := pack(resp)
	if err != nil {
		return nil
	}
	h.postPanicOK.Store(true)
	return b
}

// TestServeUDP_HandlerPanicRecover pins the B3 contract: a panic inside
// Handle drops just that query — sem release + handlerWg.Done both run
// via earlier defers — and the listener keeps accepting subsequent
// queries. Before the recover, an unrecovered panic in the per-query
// goroutine would have crashed the whole process.
func TestServeUDP_HandlerPanicRecover(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	h := &panicThenReplyHandler{}
	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeUDP(conn, h, UDPServerOpts{MaxConcurrent: 4})
	}()

	time.Sleep(50 * time.Millisecond)

	client, err := net.Dial("udp", conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// First query → handler panics → recovered → no reply sent.
	q1 := new(dns.Msg)
	dnsutil.SetQuestion(q1, "panic.example.com.", dns.TypeA)
	if err := q1.Pack(); err != nil {
		t.Fatalf("pack q1: %v", err)
	}
	if _, err := client.Write(q1.Data); err != nil {
		t.Fatalf("write q1: %v", err)
	}
	// Drain any spurious reply (there should be none) before the next query.
	client.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	respBuf := make([]byte, dns.MaxMsgSize)
	if _, err := client.Read(respBuf); err == nil {
		t.Fatal("expected no reply on panicked query, got one")
	}

	// Give the recover defer enough time to run before submitting q2.
	time.Sleep(50 * time.Millisecond)
	if !h.panicked.Load() {
		t.Fatal("first query did not exercise the panic path")
	}

	// Second query → handler answers normally → server is alive.
	q2 := new(dns.Msg)
	dnsutil.SetQuestion(q2, "ok.example.com.", dns.TypeA)
	if err := q2.Pack(); err != nil {
		t.Fatalf("pack q2: %v", err)
	}
	if _, err := client.Write(q2.Data); err != nil {
		t.Fatalf("write q2: %v", err)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	n, err := client.Read(respBuf)
	if err != nil {
		t.Fatalf("read q2 reply (server died?): %v", err)
	}
	resp := new(dns.Msg)
	resp.Data = respBuf[:n]
	if err := resp.Unpack(); err != nil {
		t.Fatalf("unpack q2 reply: %v", err)
	}
	if resp.ID != q2.ID {
		t.Errorf("reply ID = %d, want %d", resp.ID, q2.ID)
	}
	if !h.postPanicOK.Load() {
		t.Error("handler post-panic reply path was not exercised")
	}

	conn.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("ServeUDP returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("ServeUDP did not return after Close")
	}
}
