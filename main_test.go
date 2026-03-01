package main

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/cache"
	"github.com/kkkgo/mini-ppdns/pkg/query_context"
	"github.com/kkkgo/mini-ppdns/pkg/upstream"
	"github.com/miekg/dns"
)

func mockServer(handler func(w dns.ResponseWriter, r *dns.Msg)) (string, *dns.Server, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(handler)}
	go server.ActivateAndServe()
	return pc.LocalAddr().String(), server, nil
}

func TestAAAA_No(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	handler := &miniHandler{
		logger:    logger,
		dnsCache:  cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		allowAAAA: false,
	}

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeAAAA)
	ctx := query_context.NewContext(q)

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil {
		t.Fatal("expected response, got nil")
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected rcode 0, got %d", r.Rcode)
	}
	if len(r.Answer) > 0 {
		t.Fatal("expected no answers for AAAA when allowAAAA is false")
	}
}

func TestForceFall(t *testing.T) {
	// Setup fallback server
	fallAddr, fallSrv, _ := mockServer(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		rr, _ := dns.NewRR("example.com. 3600 IN A 2.2.2.2")
		resp.Answer = append(resp.Answer, rr)
		w.WriteMsg(resp)
	})
	defer fallSrv.Shutdown()

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})
	fallbackFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uFall},
		qtime:     time.Second,
		logger:    logger,
	}

	forcePrefix, _ := netip.ParsePrefix("192.168.1.10/32")

	handler := &miniHandler{
		logger:            logger,
		localForward:      nil, // Will panic if local is called, making test fail if force_fall doesn't work
		cnForward:         fallbackFwd,
		dnsCache:          cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		forceFallPrefixes: []netip.Prefix{forcePrefix},
	}

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	ctx := query_context.NewContext(q)
	ctx.ServerMeta.ClientAddr, _ = netip.ParseAddr("192.168.1.10")

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil || len(r.Answer) == 0 {
		t.Fatal("expected fallback answer")
	}
	if r.Answer[0].(*dns.A).A.String() != "2.2.2.2" {
		t.Fatalf("expected 2.2.2.2 from fallback, got %v", r.Answer[0])
	}
}

func TestLocalFallback(t *testing.T) {
	// Local server returns SERVFAIL
	localAddr, localSrv, _ := mockServer(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Rcode = dns.RcodeServerFailure
		w.WriteMsg(resp)
	})
	defer localSrv.Shutdown()

	// Fallback returns successful A record
	fallAddr, fallSrv, _ := mockServer(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		rr, _ := dns.NewRR("example.com. 3600 IN A 2.2.2.2")
		resp.Answer = append(resp.Answer, rr)
		w.WriteMsg(resp)
	})
	defer fallSrv.Shutdown()

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	localFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uLocal},
		qtime:     time.Second,
		logger:    logger,
	}

	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})
	fallbackFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uFall},
		qtime:     time.Second,
		logger:    logger,
	}

	handler := &miniHandler{
		logger:       logger,
		localForward: localFwd,
		cnForward:    fallbackFwd,
		dnsCache:     cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
	}

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	ctx := query_context.NewContext(q)

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil || len(r.Answer) == 0 {
		t.Fatal("expected fallback answer")
	}
	if r.Answer[0].(*dns.A).A.String() != "2.2.2.2" {
		t.Fatalf("expected 2.2.2.2 from fallback, got %v", r.Answer[0])
	}
	if r.Answer[0].Header().Ttl != 1 {
		t.Fatalf("expected fallback TTL to be overridden to 1, got %d", r.Answer[0].Header().Ttl)
	}
}
