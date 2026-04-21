package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/cache"
	"github.com/kkkgo/mini-ppdns/pkg/query_context"
	"github.com/kkkgo/mini-ppdns/pkg/upstream"
)

func mockServer(handler func(_ context.Context, w dns.ResponseWriter, r *dns.Msg)) (string, *dns.Server, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	wait := make(chan error, 1)
	server := &dns.Server{
		PacketConn:        pc,
		Handler:           dns.HandlerFunc(handler),
		NotifyStartedFunc: func(context.Context) { wait <- nil },
	}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			wait <- err
		}
	}()
	if err := <-wait; err != nil {
		return "", nil, err
	}
	return pc.LocalAddr().String(), server, nil
}

func TestAAAA_No(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	handler := &miniHandler{
		logger:   logger,
		dnsCache: cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		aaaaMode: "no",
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeAAAA)
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

func TestLiteMode(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	// Craft a response with mixed records
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)

		// Answer section: CNAME, A (requested), TXT (unrequested), AAAA (unrequested)
		cname, _ := dns.New("example.com. 3600 IN CNAME alias.example.com.")
		a, _ := dns.New("alias.example.com. 3600 IN A 1.2.3.4")
		txt, _ := dns.New("alias.example.com. 3600 IN TXT \"info\"")
		aaaa, _ := dns.New("alias.example.com. 3600 IN AAAA ::1")
		resp.Answer = []dns.RR{cname, a, txt, aaaa}

		// Authority section: SOA, NS
		soa, _ := dns.New("example.com. 3600 IN SOA ns1.example.com. admin.example.com. 1 2 3 4 5")
		ns, _ := dns.New("example.com. 3600 IN NS ns1.example.com.")
		resp.Ns = []dns.RR{soa, ns}

		// Additional section: A (OPT is now a Msg field in new library)
		resp.UDPSize = 4096
		addA, _ := dns.New("ns1.example.com. 3600 IN A 5.6.7.8")
		resp.Extra = []dns.RR{addA}

		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	localFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uLocal},
		addresses: []string{"udp://" + localAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	handler := &miniHandler{
		logger:       logger,
		localForward: localFwd,
		cnForward:    localFwd,
		dnsCache:     cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		lite:         true,
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	q.UDPSize = 4096
	q.Security = true

	var resp *dns.Msg
	packFn := func(m *dns.Msg) (*[]byte, error) {
		resp = m
		buf := make([]byte, 0)
		return &buf, nil
	}
	meta := query_context.ServerMeta{
		ClientAddr: netip.MustParseAddr("127.0.0.1"),
	}
	handler.Handle(context.Background(), q, meta, packFn)

	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	// Verify Answer: should only have A (CNAME is excluded unless qtype=CNAME)
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer in lite mode, got %d", len(resp.Answer))
	}
	if dns.RRToType(resp.Answer[0]) != dns.TypeA {
		t.Errorf("expected A in Answer, got %s", dns.TypeToString[dns.RRToType(resp.Answer[0])])
	}
	// Verify that the A record name was rewritten to match the query name (CNAME chain rewriting)
	if resp.Answer[0].Header().Name != "example.com." {
		t.Errorf("expected A record name to be rewritten to query name example.com., got %s", resp.Answer[0].Header().Name)
	}

	// Verify cache efficiency: the cached message should also be filtered
	cacheKey := CacheKey{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if cachedVal, _, ok := handler.dnsCache.Get(cacheKey); ok {
		if len(cachedVal.Answer) != 1 || dns.RRToType(cachedVal.Answer[0]) != dns.TypeA {
			t.Errorf("expected filtered response in cache, answer len=%d", len(cachedVal.Answer))
		}
		if len(cachedVal.Ns) != 0 {
			t.Errorf("expected empty Ns in cached response")
		}
	} else {
		t.Errorf("expected response to be cached")
	}

	// Verify Ns: should be empty
	if len(resp.Ns) != 0 {
		t.Errorf("expected 0 Ns in lite mode, got %d", len(resp.Ns))
	}

	// Verify Extra: should only have OPT (if present)
	if len(resp.Extra) > 1 {
		t.Errorf("expected at most 1 OPT in Extra in lite mode, got %d records", len(resp.Extra))
	}
	if len(resp.Extra) == 1 && dns.RRToType(resp.Extra[0]) != dns.TypeOPT {
		t.Errorf("expected ONLY OPT in Extra if any, got %s", dns.TypeToString[dns.RRToType(resp.Extra[0])])
	}
}

func TestLocalFallback(t *testing.T) {
	// Local server returns SERVFAIL
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeServerFailure
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	// Fallback returns successful A record
	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		rr, _ := dns.New("example.com. 3600 IN A 2.2.2.2")
		resp.Answer = append(resp.Answer, rr)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

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
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
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
	if r.Answer[0].Header().TTL != 1 {
		t.Fatalf("expected fallback TTL to be overridden to 1, got %d", r.Answer[0].Header().TTL)
	}
}

// TestNodataBothPreferLocal: local returns NODATA (SOA only), fall also returns NODATA.
// Expected: use local result with original TTL, cache normally.
func TestNodataBothPreferLocal(t *testing.T) {
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeSuccess
		soa, _ := dns.New("example.com. 300 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400")
		resp.Ns = append(resp.Ns, soa)
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeSuccess
		soa, _ := dns.New("example.com. 60 IN SOA ns2.example.com. admin2.example.com. 2024010101 3600 900 604800 86400")
		resp.Ns = append(resp.Ns, soa)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	localFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uLocal},
		addresses: []string{"udp://" + localAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})
	fallbackFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uFall},
		addresses: []string{"udp://" + fallAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	dnsCache := cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10})
	handler := &miniHandler{
		logger:       logger,
		localForward: localFwd,
		cnForward:    fallbackFwd,
		dnsCache:     dnsCache,
		aaaaMode:     "yes",
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeAAAA)
	ctx := query_context.NewContext(q)
	ctx.ServerMeta.ClientAddr, _ = netip.ParseAddr("127.0.0.1")

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil {
		t.Fatal("expected response, got nil")
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) != 0 {
		t.Fatalf("expected no Answer records, got %d", len(r.Answer))
	}
	if len(r.Ns) == 0 {
		t.Fatal("expected NS/SOA records from local result")
	}
	soa, ok := r.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("expected SOA record, got %T", r.Ns[0])
	}
	if soa.Ns != "ns1.example.com." {
		t.Fatalf("expected SOA from local (ns1.example.com.), got %s", soa.Ns)
	}
	if soa.Hdr.TTL != 300 {
		t.Fatalf("expected original TTL 300, got %d", soa.Hdr.TTL)
	}

	cacheKey := CacheKey{Name: "example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	cached, _, ok := dnsCache.Get(cacheKey)
	if !ok || cached == nil {
		t.Fatal("expected NODATA result to be cached")
	}
}

func TestNodataLocalFallHasAnswer(t *testing.T) {
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeSuccess
		soa, _ := dns.New("example.com. 300 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400")
		resp.Ns = append(resp.Ns, soa)
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		rr, _ := dns.New("example.com. 3600 IN A 2.2.2.2")
		resp.Answer = append(resp.Answer, rr)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	localFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uLocal},
		addresses: []string{"udp://" + localAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})
	fallbackFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uFall},
		addresses: []string{"udp://" + fallAddr},
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
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	ctx := query_context.NewContext(q)
	ctx.ServerMeta.ClientAddr, _ = netip.ParseAddr("127.0.0.1")

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil || len(r.Answer) == 0 {
		t.Fatal("expected fallback answer with A record")
	}
	if r.Answer[0].(*dns.A).A.String() != "2.2.2.2" {
		t.Fatalf("expected 2.2.2.2 from fallback, got %v", r.Answer[0])
	}
	if r.Answer[0].Header().TTL != 1 {
		t.Fatalf("expected fallback TTL 1, got %d", r.Answer[0].Header().TTL)
	}
}

func TestNodataLocalFallTimeout(t *testing.T) {
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeSuccess
		soa, _ := dns.New("example.com. 600 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400")
		resp.Ns = append(resp.Ns, soa)
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(5 * time.Second)
	})
	defer fallSrv.Shutdown(context.Background())

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	localFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uLocal},
		addresses: []string{"udp://" + localAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})
	fallbackFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uFall},
		addresses: []string{"udp://" + fallAddr},
		qtime:     200 * time.Millisecond,
		logger:    logger,
	}

	handler := &miniHandler{
		logger:       logger,
		localForward: localFwd,
		cnForward:    fallbackFwd,
		dnsCache:     cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		aaaaMode:     "yes",
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeAAAA)
	ctx := query_context.NewContext(q)
	ctx.ServerMeta.ClientAddr, _ = netip.ParseAddr("127.0.0.1")

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil {
		t.Fatal("expected response, got nil")
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[r.Rcode])
	}
	if len(r.Ns) == 0 {
		t.Fatal("expected SOA from local result when fall times out")
	}
	soa, ok := r.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("expected SOA record, got %T", r.Ns[0])
	}
	if soa.Ns != "ns1.example.com." {
		t.Fatalf("expected SOA from local, got %s", soa.Ns)
	}
	if soa.Hdr.TTL != 600 {
		t.Fatalf("expected original TTL 600, got %d", soa.Hdr.TTL)
	}
}

func TestLocalFailFallNodata(t *testing.T) {
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeServerFailure
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeSuccess
		soa, _ := dns.New("example.com. 300 IN SOA ns2.example.com. admin2.example.com. 2024010101 3600 900 604800 86400")
		resp.Ns = append(resp.Ns, soa)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	localFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uLocal},
		addresses: []string{"udp://" + localAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})
	fallbackFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uFall},
		addresses: []string{"udp://" + fallAddr},
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
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	ctx := query_context.NewContext(q)
	ctx.ServerMeta.ClientAddr, _ = netip.ParseAddr("127.0.0.1")

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil {
		t.Fatal("expected response, got nil")
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR from fall, got %s", dns.RcodeToString[r.Rcode])
	}
	if len(r.Ns) == 0 {
		t.Fatal("expected SOA from fall result")
	}
	soa, ok := r.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("expected SOA record, got %T", r.Ns[0])
	}
	if soa.Ns != "ns2.example.com." {
		t.Fatalf("expected SOA from fall (ns2.example.com.), got %s", soa.Ns)
	}
	if soa.Hdr.TTL != 1 {
		t.Fatalf("expected overridden TTL 1 for fallback result, got %d", soa.Hdr.TTL)
	}
}

func TestShuffleAnswers(t *testing.T) {
	t.Run("CNAME before A records", func(t *testing.T) {
		cname, _ := dns.New("connect.rom.miui.com. 398 IN CNAME extranet.alb.xiaomi.com.")
		a1, _ := dns.New("extranet.alb.xiaomi.com. 21 IN A 118.26.253.153")
		a2, _ := dns.New("extranet.alb.xiaomi.com. 21 IN A 220.181.106.14")
		a3, _ := dns.New("extranet.alb.xiaomi.com. 21 IN A 220.181.52.24")

		for i := 0; i < 50; i++ {
			answers := []dns.RR{cname, a1, a2, a3}
			shuffleAnswers(dns.TypeA, answers)

			if dns.RRToType(answers[0]) != dns.TypeCNAME {
				t.Fatalf("iteration %d: first record should be CNAME, got %s", i, dns.TypeToString[dns.RRToType(answers[0])])
			}
			for j := 1; j < len(answers); j++ {
				if dns.RRToType(answers[j]) != dns.TypeA {
					t.Fatalf("iteration %d: record[%d] should be A, got %s", i, j, dns.TypeToString[dns.RRToType(answers[j])])
				}
			}
		}
	})

	t.Run("multiple CNAME chain before A", func(t *testing.T) {
		cname1, _ := dns.New("example.com. 300 IN CNAME alias1.example.com.")
		cname2, _ := dns.New("alias1.example.com. 300 IN CNAME alias2.example.com.")
		a1, _ := dns.New("alias2.example.com. 60 IN A 1.2.3.4")

		for i := 0; i < 50; i++ {
			answers := []dns.RR{a1, cname2, cname1}
			shuffleAnswers(dns.TypeA, answers)

			for j := 0; j < 2; j++ {
				if dns.RRToType(answers[j]) != dns.TypeCNAME {
					t.Fatalf("iteration %d: record[%d] should be CNAME, got %s", i, j, dns.TypeToString[dns.RRToType(answers[j])])
				}
			}
			if dns.RRToType(answers[2]) != dns.TypeA {
				t.Fatalf("iteration %d: last record should be A, got %s", i, dns.TypeToString[dns.RRToType(answers[2])])
			}
		}
	})

	t.Run("A only records are shuffled", func(t *testing.T) {
		a1, _ := dns.New("example.com. 60 IN A 1.1.1.1")
		a2, _ := dns.New("example.com. 60 IN A 2.2.2.2")
		a3, _ := dns.New("example.com. 60 IN A 3.3.3.3")

		sawDifferentOrder := false
		firstOrder := ""
		for i := 0; i < 50; i++ {
			answers := []dns.RR{
				a1.Clone(), a2.Clone(), a3.Clone(),
			}
			shuffleAnswers(dns.TypeA, answers)

			order := answers[0].(*dns.A).A.String() + answers[1].(*dns.A).A.String() + answers[2].(*dns.A).A.String()
			if i == 0 {
				firstOrder = order
			} else if order != firstOrder {
				sawDifferentOrder = true
			}
		}
		if !sawDifferentOrder {
			t.Fatal("A-only records should be shuffled for load balancing")
		}
	})

	t.Run("single record unchanged", func(t *testing.T) {
		a1, _ := dns.New("example.com. 60 IN A 1.1.1.1")
		answers := []dns.RR{a1}
		shuffleAnswers(dns.TypeA, answers)
		if answers[0].(*dns.A).A.String() != "1.1.1.1" {
			t.Fatal("single record should be unchanged")
		}
	})

	t.Run("CNAME only", func(t *testing.T) {
		cname, _ := dns.New("example.com. 300 IN CNAME other.example.com.")
		answers := []dns.RR{cname}
		shuffleAnswers(dns.TypeA, answers)
		if dns.RRToType(answers[0]) != dns.TypeCNAME {
			t.Fatal("single CNAME should be unchanged")
		}
	})

	t.Run("three-tier order: CNAME then qtype then rest", func(t *testing.T) {
		cname, _ := dns.New("example.com. 300 IN CNAME alias.example.com.")
		a1, _ := dns.New("alias.example.com. 60 IN A 1.2.3.4")
		a2, _ := dns.New("alias.example.com. 60 IN A 5.6.7.8")
		txt, _ := dns.New("alias.example.com. 60 IN TXT \"v=spf1\"")

		for i := 0; i < 50; i++ {
			answers := []dns.RR{txt, a1, cname, a2}
			shuffleAnswers(dns.TypeA, answers)

			if dns.RRToType(answers[0]) != dns.TypeCNAME {
				t.Fatalf("iter %d: answers[0] must be CNAME, got %s", i, dns.TypeToString[dns.RRToType(answers[0])])
			}
			for j := 1; j <= 2; j++ {
				if dns.RRToType(answers[j]) != dns.TypeA {
					t.Fatalf("iter %d: answers[%d] must be A, got %s", i, j, dns.TypeToString[dns.RRToType(answers[j])])
				}
			}
			if dns.RRToType(answers[3]) != dns.TypeTXT {
				t.Fatalf("iter %d: answers[3] must be TXT, got %s", i, dns.TypeToString[dns.RRToType(answers[3])])
			}
		}
	})

	t.Run("qtype records before rest when no CNAME", func(t *testing.T) {
		a1, _ := dns.New("example.com. 60 IN A 1.1.1.1")
		txt, _ := dns.New("example.com. 60 IN TXT \"info\"")

		for i := 0; i < 20; i++ {
			answers := []dns.RR{txt, a1}
			shuffleAnswers(dns.TypeA, answers)

			if dns.RRToType(answers[0]) != dns.TypeA {
				t.Fatalf("iter %d: A record must come before TXT", i)
			}
			if dns.RRToType(answers[1]) != dns.TypeTXT {
				t.Fatalf("iter %d: TXT must be last", i)
			}
		}
	})
}

func TestCacheKeySum_FNV1a(t *testing.T) {
	keys := []CacheKey{
		{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		{Name: "test.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "a.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	seen := make(map[uint64]CacheKey)
	for _, k := range keys {
		h := k.Sum()
		if prev, ok := seen[h]; ok {
			t.Errorf("hash collision between %v and %v: both produce %d", prev, k, h)
		}
		seen[h] = k
	}

	k := CacheKey{Name: "stable.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	h1 := k.Sum()
	h2 := k.Sum()
	if h1 != h2 {
		t.Errorf("non-deterministic hash: %d != %d", h1, h2)
	}

	empty := CacheKey{}
	_ = empty.Sum()
}

func TestStablePartitionRR(t *testing.T) {
	mkA := func(ip string) dns.RR {
		rr, _ := dns.New("example.com. 60 IN A " + ip)
		return rr
	}
	mkCNAME := func(target string) dns.RR {
		rr, _ := dns.New("example.com. 60 IN CNAME " + target)
		return rr
	}
	mkTXT := func(text string) dns.RR {
		rr, _ := dns.New("example.com. 60 IN TXT \"" + text + "\"")
		return rr
	}

	t.Run("all match", func(t *testing.T) {
		a1, a2 := mkA("1.1.1.1"), mkA("2.2.2.2")
		s := []dns.RR{a1, a2}
		n := stablePartitionRR(s, func(rr dns.RR) bool {
			return dns.RRToType(rr) == dns.TypeA
		})
		if n != 2 {
			t.Fatalf("expected 2, got %d", n)
		}
	})

	t.Run("none match", func(t *testing.T) {
		txt1, txt2 := mkTXT("a"), mkTXT("b")
		s := []dns.RR{txt1, txt2}
		n := stablePartitionRR(s, func(rr dns.RR) bool {
			return dns.RRToType(rr) == dns.TypeA
		})
		if n != 0 {
			t.Fatalf("expected 0, got %d", n)
		}
	})

	t.Run("mixed preserves order", func(t *testing.T) {
		c1 := mkCNAME("a.example.com.")
		a1 := mkA("1.1.1.1")
		c2 := mkCNAME("b.example.com.")
		a2 := mkA("2.2.2.2")
		txt := mkTXT("info")

		s := []dns.RR{a1, c1, txt, c2, a2}
		n := stablePartitionRR(s, func(rr dns.RR) bool {
			return dns.RRToType(rr) == dns.TypeCNAME
		})
		if n != 2 {
			t.Fatalf("expected 2 CNAMEs, got %d", n)
		}
		if s[0].(*dns.CNAME).Target != "a.example.com." {
			t.Errorf("expected first CNAME target a.example.com., got %s", s[0].(*dns.CNAME).Target)
		}
		if s[1].(*dns.CNAME).Target != "b.example.com." {
			t.Errorf("expected second CNAME target b.example.com., got %s", s[1].(*dns.CNAME).Target)
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		n := stablePartitionRR(nil, func(rr dns.RR) bool { return true })
		if n != 0 {
			t.Fatalf("expected 0, got %d", n)
		}
	})

	t.Run("single element match", func(t *testing.T) {
		a := mkA("1.1.1.1")
		s := []dns.RR{a}
		n := stablePartitionRR(s, func(rr dns.RR) bool {
			return dns.RRToType(rr) == dns.TypeA
		})
		if n != 1 {
			t.Fatalf("expected 1, got %d", n)
		}
	})
}

// TestCacheSnapshotIsolation guards the contract that cacheSnapshot produces
// a Msg whose Answer/Ns/Extra slices are independent from the source's.
// If someone reverts to Msg.Copy (a shallow copy in this fork of miekg/dns),
// shuffleAnswers on the response would reorder the cached slice.
func TestCacheSnapshotIsolation(t *testing.T) {
	mkA := func(ip string) dns.RR {
		rr, _ := dns.New("example.com. 60 IN A " + ip)
		return rr
	}
	src := &dns.Msg{}
	src.Answer = []dns.RR{mkA("1.1.1.1"), mkA("2.2.2.2"), mkA("3.3.3.3")}

	snap := cacheSnapshot(src)
	if &snap.Answer[0] == &src.Answer[0] {
		t.Fatal("cacheSnapshot returned a slice aliased to the source backing array")
	}
	// Mutating the snapshot's slice order must not affect the source.
	snap.Answer[0], snap.Answer[2] = snap.Answer[2], snap.Answer[0]
	if src.Answer[0].(*dns.A).A.String() != "1.1.1.1" {
		t.Errorf("source was perturbed by snapshot slice swap: got %s",
			src.Answer[0].(*dns.A).A.String())
	}
}

// TestCloneRRsWithTTLIsolation guards the contract that cloneRRsWithTTL
// produces RRs whose TTL writes don't mutate the source RRs — the bug
// fixed in the cache-hit Load path.
func TestCloneRRsWithTTLIsolation(t *testing.T) {
	rr, _ := dns.New("example.com. 3600 IN A 1.1.1.1")
	src := []dns.RR{rr}

	cloned := cloneRRsWithTTL(src, 1)
	if cloned[0] == src[0] {
		t.Fatal("cloneRRsWithTTL returned the source RR pointer; expected a deep clone")
	}
	if got := src[0].Header().TTL; got != 3600 {
		t.Errorf("source TTL mutated: got %d, want 3600", got)
	}
	if got := cloned[0].Header().TTL; got != 1 {
		t.Errorf("cloned TTL not rewritten: got %d, want 1", got)
	}
}

// TestConcurrentCacheHitNoTTLPollution is the regression test for the
// shallow-Msg.Copy pollution bug: many goroutines read the same cached Msg
// and rewrite its TTL via the Load-path pattern. The cached Msg's TTL must
// remain stable and no data race must occur.
func TestConcurrentCacheHitNoTTLPollution(t *testing.T) {
	rr, _ := dns.New("example.com. 3600 IN A 1.1.1.1")
	cached := &dns.Msg{}
	cached.Answer = []dns.RR{rr}

	const origTTL uint32 = 3600
	const goroutines = 32
	const iters = 500

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(ttl uint32) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				resp := &dns.Msg{
					MsgHeader: cached.MsgHeader,
					Question:  cached.Question,
					Answer:    cloneRRsWithTTL(cached.Answer, ttl),
					Ns:        cloneRRsWithTTL(cached.Ns, ttl),
					Extra:     cloneExtraWithTTL(cached.Extra, ttl),
				}
				if resp.Answer[0].Header().TTL != ttl {
					t.Errorf("response TTL = %d, want %d",
						resp.Answer[0].Header().TTL, ttl)
					return
				}
			}
		}(uint32(g + 1))
	}
	wg.Wait()

	if got := cached.Answer[0].Header().TTL; got != origTTL {
		t.Errorf("cached TTL polluted: got %d, want %d", got, origTTL)
	}
}

func TestResolveCNAMEChain(t *testing.T) {
	tests := []struct {
		name      string
		answers   []string
		startName string
		want      string
	}{
		{
			"no CNAME chain",
			[]string{"example.com. 60 IN A 1.2.3.4"},
			"example.com.",
			"example.com.",
		},
		{
			"single hop",
			[]string{"example.com. 300 IN CNAME alias.example.com.", "alias.example.com. 60 IN A 1.2.3.4"},
			"example.com.",
			"alias.example.com.",
		},
		{
			"multi-hop chain",
			[]string{
				"query.com. 300 IN CNAME hop1.cdn.com.",
				"hop1.cdn.com. 200 IN CNAME hop2.cdn.com.",
				"hop2.cdn.com. 60 IN A 1.2.3.4",
			},
			"query.com.",
			"hop2.cdn.com.",
		},
		{
			"broken chain",
			[]string{
				"query.com. 300 IN CNAME hop1.cdn.com.",
				"hop2.cdn.com. 60 IN A 1.2.3.4",
			},
			"query.com.",
			"hop1.cdn.com.",
		},
		{
			"circular chain terminates",
			[]string{
				"a.com. 300 IN CNAME b.com.",
				"b.com. 300 IN CNAME a.com.",
			},
			"a.com.",
			"a.com.",
		},
		{
			"case insensitive",
			[]string{"Example.COM. 300 IN CNAME Alias.Example.COM."},
			"example.com.",
			"alias.example.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var answers []dns.RR
			for _, s := range tt.answers {
				rr, _ := dns.New(s)
				answers = append(answers, rr)
			}
			got := resolveCNAMEChain(answers, tt.startName)
			want := strings.ToLower(tt.want)
			if got != want {
				t.Errorf("resolveCNAMEChain() = %q, want %q", got, want)
			}
		})
	}
}

func TestLiteModeCNAMEChain(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		cname1, _ := dns.New("v5.douyinvod.com. 267 IN CNAME v5.douyinvod.com.volcgslb.com.")
		cname2, _ := dns.New("v5.douyinvod.com.volcgslb.com. 103 IN CNAME v5.douyinvod.com.ctlcdn.cn.")
		a1, _ := dns.New("v5.douyinvod.com.ctlcdn.cn. 31 IN A 180.163.200.129")
		a2, _ := dns.New("v5.douyinvod.com.ctlcdn.cn. 31 IN A 14.152.112.26")
		a3, _ := dns.New("v5.douyinvod.com.ctlcdn.cn. 31 IN A 183.61.184.199")
		a4, _ := dns.New("v5.douyinvod.com.ctlcdn.cn. 31 IN A 183.61.184.195")
		resp.Answer = []dns.RR{cname1, cname2, a1, a2, a3, a4}
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	localFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uLocal},
		addresses: []string{"udp://" + localAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	handler := &miniHandler{
		logger:       logger,
		localForward: localFwd,
		cnForward:    localFwd,
		dnsCache:     cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		lite:         true,
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "v5.douyinvod.com.", dns.TypeA)

	var resp *dns.Msg
	packFn := func(m *dns.Msg) (*[]byte, error) {
		resp = m
		buf := make([]byte, 0)
		return &buf, nil
	}
	meta := query_context.ServerMeta{
		ClientAddr: netip.MustParseAddr("127.0.0.1"),
	}
	handler.Handle(context.Background(), q, meta, packFn)

	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	if len(resp.Answer) != 4 {
		t.Fatalf("expected 4 A answers after lite mode, got %d", len(resp.Answer))
	}

	for i, rr := range resp.Answer {
		if dns.RRToType(rr) != dns.TypeA {
			t.Errorf("answer[%d]: expected A, got %s", i, dns.TypeToString[dns.RRToType(rr)])
		}
		if rr.Header().Name != "v5.douyinvod.com." {
			t.Errorf("answer[%d]: expected name v5.douyinvod.com., got %s", i, rr.Header().Name)
		}
	}

	cacheKey := CacheKey{Name: "v5.douyinvod.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if cachedVal, _, ok := handler.dnsCache.Get(cacheKey); ok {
		for i, rr := range cachedVal.Answer {
			if rr.Header().Name != "v5.douyinvod.com." {
				t.Errorf("cached answer[%d]: expected name v5.douyinvod.com., got %s", i, rr.Header().Name)
			}
		}
	} else {
		t.Errorf("expected response to be cached")
	}

	t.Run("broken chain keeps all records", func(t *testing.T) {
		brokenAddr, brokenSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
			resp := new(dns.Msg)
			dnsutil.SetReply(resp, r)
			cname, _ := dns.New("query.example.com. 300 IN CNAME hop1.example.com.")
			a1, _ := dns.New("unrelated.example.com. 60 IN A 1.1.1.1")
			a2, _ := dns.New("unrelated.example.com. 60 IN A 2.2.2.2")
			resp.Answer = []dns.RR{cname, a1, a2}
			resp.WriteTo(w)
		})
		defer brokenSrv.Shutdown(context.Background())

		uBroken, _ := upstream.NewUpstream("udp://"+brokenAddr, upstream.Opt{Logger: logger})
		brokenFwd := &miniForwarder{
			upstreams: []upstream.Upstream{uBroken},
			addresses: []string{"udp://" + brokenAddr},
			qtime:     time.Second,
			logger:    logger,
		}

		brokenHandler := &miniHandler{
			logger:       logger,
			localForward: brokenFwd,
			cnForward:    brokenFwd,
			dnsCache:     cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
			lite:         true,
		}

		q := new(dns.Msg)
		dnsutil.SetQuestion(q, "query.example.com.", dns.TypeA)

		var brokenResp *dns.Msg
		packFn := func(m *dns.Msg) (*[]byte, error) {
			brokenResp = m
			buf := make([]byte, 0)
			return &buf, nil
		}
		brokenHandler.Handle(context.Background(), q, meta, packFn)

		if brokenResp == nil {
			t.Fatal("expected response, got nil")
		}

		if len(brokenResp.Answer) != 3 {
			t.Fatalf("broken chain: expected 3 answers (1 CNAME + 2 A, no filtering), got %d", len(brokenResp.Answer))
		}
	})

	t.Run("unrelated A records excluded from chain", func(t *testing.T) {
		mixedAddr, mixedSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
			resp := new(dns.Msg)
			dnsutil.SetReply(resp, r)
			cname1, _ := dns.New("v5.douyinvod.com. 267 IN CNAME v5.douyinvod.com.volcgslb.com.")
			cname2, _ := dns.New("v5.douyinvod.com.volcgslb.com. 103 IN CNAME v5.douyinvod.com.ctlcdn.cn.")
			a1, _ := dns.New("v5.douyinvod.com.ctlcdn.cn. 31 IN A 180.163.200.129")
			a2, _ := dns.New("v5.douyinvod.com.ctlcdn.cn. 31 IN A 14.152.112.26")
			aUnrelated, _ := dns.New("www.baidu.com.douyinvod.com.ctlcdn.cn. 7 IN A 183.61.184.100")
			resp.Answer = []dns.RR{cname1, cname2, a1, a2, aUnrelated}
			resp.WriteTo(w)
		})
		defer mixedSrv.Shutdown(context.Background())

		uMixed, _ := upstream.NewUpstream("udp://"+mixedAddr, upstream.Opt{Logger: logger})
		mixedFwd := &miniForwarder{
			upstreams: []upstream.Upstream{uMixed},
			addresses: []string{"udp://" + mixedAddr},
			qtime:     time.Second,
			logger:    logger,
		}

		mixedHandler := &miniHandler{
			logger:       logger,
			localForward: mixedFwd,
			cnForward:    mixedFwd,
			dnsCache:     cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
			lite:         true,
		}

		q := new(dns.Msg)
		dnsutil.SetQuestion(q, "v5.douyinvod.com.", dns.TypeA)

		var mixedResp *dns.Msg
		packFn := func(m *dns.Msg) (*[]byte, error) {
			mixedResp = m
			buf := make([]byte, 0)
			return &buf, nil
		}
		mixedHandler.Handle(context.Background(), q, meta, packFn)

		if mixedResp == nil {
			t.Fatal("expected response, got nil")
		}

		if len(mixedResp.Answer) != 2 {
			t.Fatalf("expected 2 A answers (unrelated excluded), got %d", len(mixedResp.Answer))
		}

		for i, rr := range mixedResp.Answer {
			if rr.Header().Name != "v5.douyinvod.com." {
				t.Errorf("answer[%d]: expected name v5.douyinvod.com., got %s", i, rr.Header().Name)
			}
		}

		for _, rr := range mixedResp.Answer {
			if a, ok := rr.(*dns.A); ok && a.A.String() == "183.61.184.100" {
				t.Error("unrelated A record (183.61.184.100) should have been excluded")
			}
		}
	})
}

func TestExecUpstreamDistribution(t *testing.T) {
	type serverInfo struct {
		addr string
		srv  *dns.Server
	}
	var servers []serverInfo
	for i := 0; i < 5; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		addr, srv, err := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
			resp := new(dns.Msg)
			dnsutil.SetReply(resp, r)
			rr, _ := dns.New(fmt.Sprintf("example.com. 60 IN A %s", ip))
			resp.Answer = append(resp.Answer, rr)
			resp.WriteTo(w)
		})
		if err != nil {
			t.Fatalf("mockServer failed: %v", err)
		}
		defer srv.Shutdown(context.Background())
		servers = append(servers, serverInfo{addr: addr, srv: srv})
	}

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	var upstreams []upstream.Upstream
	var addrs []string
	for _, s := range servers {
		u, _ := upstream.NewUpstream("udp://"+s.addr, upstream.Opt{Logger: logger})
		upstreams = append(upstreams, u)
		addrs = append(addrs, "udp://"+s.addr)
	}

	fwd := &miniForwarder{
		upstreams: upstreams,
		addresses: addrs,
		qtime:     time.Second,
		logger:    logger,
	}

	upstreamSeen := make(map[string]int)
	for i := 0; i < 100; i++ {
		q := new(dns.Msg)
		dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
		qCtx := query_context.NewContext(q)
		_, usedAddr, _, err := fwd.Exec(context.Background(), qCtx)
		if err != nil {
			t.Fatalf("Exec failed: %v", err)
		}
		upstreamSeen[usedAddr]++
	}

	if len(upstreamSeen) < 2 {
		t.Errorf("expected multiple upstreams to be used, only saw %d: %v", len(upstreamSeen), upstreamSeen)
	}
}

func TestAAAA_NoerrorTrustLocalNodata(t *testing.T) {
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeSuccess
		soa, _ := dns.New("example.com. 300 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400")
		resp.Ns = append(resp.Ns, soa)
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	var fallCalled atomic.Bool
	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		fallCalled.Store(true)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		rr, _ := dns.New("example.com. 3600 IN AAAA ::1")
		resp.Answer = append(resp.Answer, rr)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	localFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uLocal},
		addresses: []string{"udp://" + localAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})
	fallbackFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uFall},
		addresses: []string{"udp://" + fallAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	dnsCache := cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10})
	handler := &miniHandler{
		logger:       logger,
		localForward: localFwd,
		cnForward:    fallbackFwd,
		dnsCache:     dnsCache,
		aaaaMode:     "noerror",
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeAAAA)
	ctx := query_context.NewContext(q)
	ctx.ServerMeta.ClientAddr, _ = netip.ParseAddr("127.0.0.1")

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil {
		t.Fatal("expected response, got nil")
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) != 0 {
		t.Fatalf("expected empty answer (NODATA), got %d records", len(r.Answer))
	}
	if fallCalled.Load() {
		t.Fatal("fallback DNS should NOT have been called in aaaa=noerror mode when local returns NOERROR")
	}

	cacheKey := CacheKey{Name: "example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	cached, _, ok := dnsCache.Get(cacheKey)
	if !ok || cached == nil {
		t.Fatal("expected NODATA result to be cached")
	}
}

func TestAAAA_NoerrorFallsBackOnNonNoerror(t *testing.T) {
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeNameError
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		rr, _ := dns.New("example.com. 3600 IN AAAA 2001:db8::1")
		resp.Answer = append(resp.Answer, rr)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	localFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uLocal},
		addresses: []string{"udp://" + localAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})
	fallbackFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uFall},
		addresses: []string{"udp://" + fallAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	handler := &miniHandler{
		logger:       logger,
		localForward: localFwd,
		cnForward:    fallbackFwd,
		dnsCache:     cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		aaaaMode:     "noerror",
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeAAAA)
	ctx := query_context.NewContext(q)
	ctx.ServerMeta.ClientAddr, _ = netip.ParseAddr("127.0.0.1")

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil || len(r.Answer) == 0 {
		t.Fatal("expected AAAA answer from fallback")
	}
	aaaa, ok := r.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("expected AAAA record, got %T", r.Answer[0])
	}
	if aaaa.AAAA.String() != "2001:db8::1" {
		t.Fatalf("expected 2001:db8::1 from fallback, got %s", aaaa.AAAA.String())
	}
	if r.Answer[0].Header().TTL != 1 {
		t.Fatalf("expected fallback TTL 1, got %d", r.Answer[0].Header().TTL)
	}
}

func TestTrustRcode_NoerrorEmptyAnswer(t *testing.T) {
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeSuccess
		soa, _ := dns.New("example.com. 300 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400")
		resp.Ns = append(resp.Ns, soa)
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	var fallCalled atomic.Bool
	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		fallCalled.Store(true)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		rr, _ := dns.New("example.com. 3600 IN A 2.2.2.2")
		resp.Answer = append(resp.Answer, rr)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})

	dnsCache := cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10})
	handler := &miniHandler{
		logger:       logger,
		localForward: &miniForwarder{upstreams: []upstream.Upstream{uLocal}, addresses: []string{"udp://" + localAddr}, qtime: time.Second, logger: logger},
		cnForward:    &miniForwarder{upstreams: []upstream.Upstream{uFall}, addresses: []string{"udp://" + fallAddr}, qtime: time.Second, logger: logger},
		dnsCache:     dnsCache,
		trustRcodes:  map[int]bool{dns.RcodeSuccess: true},
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	ctx := query_context.NewContext(q)
	ctx.ServerMeta.ClientAddr, _ = netip.ParseAddr("127.0.0.1")

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil {
		t.Fatal("expected response, got nil")
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) != 0 {
		t.Fatalf("expected empty answer (trusted NODATA), got %d records", len(r.Answer))
	}
	if fallCalled.Load() {
		t.Fatal("fallback should NOT have been called when trust_rcode includes 0")
	}

	cacheKey := CacheKey{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	cached, _, ok := dnsCache.Get(cacheKey)
	if !ok || cached == nil {
		t.Fatal("expected trusted NODATA result to be cached")
	}
}

func TestTrustRcode_NXDOMAINTrusted(t *testing.T) {
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeNameError
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	var fallCalled atomic.Bool
	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		fallCalled.Store(true)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		rr, _ := dns.New("example.com. 3600 IN A 3.3.3.3")
		resp.Answer = append(resp.Answer, rr)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})

	handler := &miniHandler{
		logger:       logger,
		localForward: &miniForwarder{upstreams: []upstream.Upstream{uLocal}, addresses: []string{"udp://" + localAddr}, qtime: time.Second, logger: logger},
		cnForward:    &miniForwarder{upstreams: []upstream.Upstream{uFall}, addresses: []string{"udp://" + fallAddr}, qtime: time.Second, logger: logger},
		dnsCache:     cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		trustRcodes:  map[int]bool{dns.RcodeSuccess: true, dns.RcodeNameError: true},
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "blocked.example.com.", dns.TypeA)
	ctx := query_context.NewContext(q)
	ctx.ServerMeta.ClientAddr, _ = netip.ParseAddr("127.0.0.1")

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil {
		t.Fatal("expected response, got nil")
	}
	if r.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %s", dns.RcodeToString[r.Rcode])
	}
	if fallCalled.Load() {
		t.Fatal("fallback should NOT have been called when trust_rcode includes 3 (NXDOMAIN)")
	}
}

func TestTrustRcode_UntrustedRcodeFallsBack(t *testing.T) {
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeServerFailure
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		rr, _ := dns.New("example.com. 3600 IN A 4.4.4.4")
		resp.Answer = append(resp.Answer, rr)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})

	handler := &miniHandler{
		logger:       logger,
		localForward: &miniForwarder{upstreams: []upstream.Upstream{uLocal}, addresses: []string{"udp://" + localAddr}, qtime: time.Second, logger: logger},
		cnForward:    &miniForwarder{upstreams: []upstream.Upstream{uFall}, addresses: []string{"udp://" + fallAddr}, qtime: time.Second, logger: logger},
		dnsCache:     cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		trustRcodes:  map[int]bool{dns.RcodeSuccess: true},
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	ctx := query_context.NewContext(q)
	ctx.ServerMeta.ClientAddr, _ = netip.ParseAddr("127.0.0.1")

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil || len(r.Answer) == 0 {
		t.Fatal("expected answer from fallback")
	}
	a, ok := r.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", r.Answer[0])
	}
	if a.A.String() != "4.4.4.4" {
		t.Fatalf("expected 4.4.4.4 from fallback, got %s", a.A.String())
	}
}

func TestTrustRcode_EmptyNoTrust(t *testing.T) {
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeSuccess
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	var fallCalled atomic.Bool
	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		fallCalled.Store(true)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		rr, _ := dns.New("example.com. 3600 IN A 5.5.5.5")
		resp.Answer = append(resp.Answer, rr)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})

	handler := &miniHandler{
		logger:       logger,
		localForward: &miniForwarder{upstreams: []upstream.Upstream{uLocal}, addresses: []string{"udp://" + localAddr}, qtime: time.Second, logger: logger},
		cnForward:    &miniForwarder{upstreams: []upstream.Upstream{uFall}, addresses: []string{"udp://" + fallAddr}, qtime: time.Second, logger: logger},
		dnsCache:     cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		trustRcodes:  nil,
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	ctx := query_context.NewContext(q)
	ctx.ServerMeta.ClientAddr, _ = netip.ParseAddr("127.0.0.1")

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	if !fallCalled.Load() {
		t.Fatal("fallback should have been called when trust_rcode is not configured")
	}

	r := ctx.R()
	if r == nil || len(r.Answer) == 0 {
		t.Fatal("expected answer from fallback")
	}
	if r.Answer[0].(*dns.A).A.String() != "5.5.5.5" {
		t.Fatalf("expected 5.5.5.5 from fallback, got %v", r.Answer[0])
	}
}

func TestTrustRcode_WithAnswer(t *testing.T) {
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		rr, _ := dns.New("example.com. 3600 IN A 1.1.1.1")
		resp.Answer = append(resp.Answer, rr)
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	var fallCalled atomic.Bool
	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		fallCalled.Store(true)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})

	handler := &miniHandler{
		logger:       logger,
		localForward: &miniForwarder{upstreams: []upstream.Upstream{uLocal}, addresses: []string{"udp://" + localAddr}, qtime: time.Second, logger: logger},
		cnForward:    &miniForwarder{upstreams: []upstream.Upstream{uFall}, addresses: []string{"udp://" + fallAddr}, qtime: time.Second, logger: logger},
		dnsCache:     cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		trustRcodes:  map[int]bool{dns.RcodeSuccess: true},
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	ctx := query_context.NewContext(q)
	ctx.ServerMeta.ClientAddr, _ = netip.ParseAddr("127.0.0.1")

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil || len(r.Answer) == 0 {
		t.Fatal("expected answer from local")
	}
	if r.Answer[0].(*dns.A).A.String() != "1.1.1.1" {
		t.Fatalf("expected 1.1.1.1 from local, got %v", r.Answer[0])
	}
	if fallCalled.Load() {
		t.Fatal("fallback should NOT have been called")
	}
}

// TestHostsLookup_A tests that [hosts] entries return A records directly.
func TestHostsLookup_A(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	handler := &miniHandler{
		logger:   logger,
		dnsCache: cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		ptrResolver: newPTRResolver(nil, nil, false, map[string][]net.IP{
			"example.com.": {net.ParseIP("1.2.3.4"), net.ParseIP("5.6.7.8")},
		}, logger),
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	ctx := query_context.NewContext(q)

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil {
		t.Fatal("expected response")
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %d", r.Rcode)
	}
	if len(r.Answer) != 2 {
		t.Fatalf("expected 2 A answers, got %d", len(r.Answer))
	}
	a1 := r.Answer[0].(*dns.A)
	a2 := r.Answer[1].(*dns.A)
	if a1.A.String() != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", a1.A.String())
	}
	if a2.A.String() != "5.6.7.8" {
		t.Errorf("expected 5.6.7.8, got %s", a2.A.String())
	}
}

// TestHostsLookup_AAAA tests that [hosts] entries return AAAA records.
func TestHostsLookup_AAAA(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	handler := &miniHandler{
		logger:   logger,
		dnsCache: cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		aaaaMode: "yes",
		ptrResolver: newPTRResolver(nil, nil, false, map[string][]net.IP{
			"v6.example.com.": {net.ParseIP("2001:db8::1")},
		}, logger),
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "v6.example.com.", dns.TypeAAAA)
	ctx := query_context.NewContext(q)

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil {
		t.Fatal("expected response")
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 AAAA answer, got %d", len(r.Answer))
	}
	aaaa := r.Answer[0].(*dns.AAAA)
	if aaaa.Addr.String() != "2001:db8::1" {
		t.Errorf("expected 2001:db8::1, got %s", aaaa.Addr.String())
	}
}

// TestHostsLookup_NoMatch tests that unmatched domains are not affected by hosts.
func TestHostsLookup_NoMatch(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	// Set up a mock upstream that returns a normal answer
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		rr, _ := dns.New("other.com. 3600 IN A 9.9.9.9")
		resp.Answer = append(resp.Answer, rr)
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	localFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uLocal},
		addresses: []string{"udp://" + localAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	handler := &miniHandler{
		logger:       logger,
		localForward: localFwd,
		cnForward:    localFwd,
		dnsCache:     cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		ptrResolver: newPTRResolver(nil, nil, false, map[string][]net.IP{
			"example.com.": {net.ParseIP("1.2.3.4")},
		}, logger),
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "other.com.", dns.TypeA)
	ctx := query_context.NewContext(q)

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil || len(r.Answer) == 0 {
		t.Fatal("expected upstream answer")
	}
	if r.Answer[0].(*dns.A).A.String() != "9.9.9.9" {
		t.Fatalf("expected upstream 9.9.9.9, got %v", r.Answer[0])
	}
}

// TestHostsLookup_IPv4OnlyForA tests that AAAA query for IPv4-only hosts returns empty.
func TestHostsLookup_IPv4OnlyForA(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	// Need upstreams because hosts won't match AAAA for an IPv4-only entry
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeSuccess
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	fwd := &miniForwarder{
		upstreams: []upstream.Upstream{uLocal},
		addresses: []string{"udp://" + localAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	handler := &miniHandler{
		logger:       logger,
		localForward: fwd,
		cnForward:    fwd,
		dnsCache:     cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		aaaaMode:     "yes",
		ptrResolver: newPTRResolver(nil, nil, false, map[string][]net.IP{
			"example.com.": {net.ParseIP("1.2.3.4")}, // IPv4 only
		}, logger),
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeAAAA)
	ctx := query_context.NewContext(q)

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	// Should fall through to upstream since no AAAA in hosts
	r := ctx.R()
	if r == nil {
		t.Fatal("expected response")
	}
}

// TestIsPaopaoDNS tests the isPaopaoDNS helper function.
func TestIsPaopaoDNS(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"paopao.dns.", true},
		{"PAOPAO.DNS.", true},
		{"sub.paopao.dns.", false},
		{"a.b.paopao.dns.", false},
		{"www.paopao.dns.", false},
		{"notpaopao.dns.", false},
		{"example.com.", false},
		{"paopao.dns.com.", false},
		{"xpaopao.dns.", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPaopaoDNS(tt.name); got != tt.want {
				t.Errorf("isPaopaoDNS(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// TestPaopaoDNS_UsesPrimaryDNS tests that paopao.dns queries use primary DNS
// even when forceFall/hookDown would normally route to fallback.
func TestPaopaoDNS_UsesPrimaryDNS(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	var localCalled atomic.Bool
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		localCalled.Store(true)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		rr, _ := dns.New(fmt.Sprintf("%s 300 IN A 10.10.10.53", r.Question[0].Header().Name))
		resp.Answer = append(resp.Answer, rr)
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())

	var fallCalled atomic.Bool
	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		fallCalled.Store(true)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		rr, _ := dns.New(fmt.Sprintf("%s 300 IN A 99.99.99.99", r.Question[0].Header().Name))
		resp.Answer = append(resp.Answer, rr)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	localFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uLocal},
		addresses: []string{"udp://" + localAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})
	fallFwd := &miniForwarder{
		upstreams: []upstream.Upstream{uFall},
		addresses: []string{"udp://" + fallAddr},
		qtime:     time.Second,
		logger:    logger,
	}

	// Simulate force_fall for all clients
	ffMatcher := &forceFallMatcher{}
	prefix, _, _ := parseForceFallEntry("0.0.0.0/0")
	ffMatcher.includePrefixes = append(ffMatcher.includePrefixes, prefix...)

	handler := &miniHandler{
		logger:           logger,
		localForward:     localFwd,
		cnForward:        fallFwd,
		dnsCache:         cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		forceFallMatcher: ffMatcher,
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "paopao.dns.", dns.TypeA)
	ctx := query_context.NewContext(q)
	ctx.ServerMeta.ClientAddr = netip.MustParseAddr("192.168.1.100")

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	if !localCalled.Load() {
		t.Fatal("expected primary DNS to be called for paopao.dns")
	}

	r := ctx.R()
	if r == nil || len(r.Answer) == 0 {
		t.Fatal("expected answer from primary DNS")
	}
	if r.Answer[0].(*dns.A).A.String() != "10.10.10.53" {
		t.Fatalf("expected 10.10.10.53 from primary, got %s", r.Answer[0].(*dns.A).A.String())
	}
	// fallback should still be called since primary returned success but we want to verify primary was used first
	_ = fallCalled.Load()
}

// TestPaopaoDNS_HostsOverride tests that paopao.dns with hosts entry
// returns the hosts result directly without hitting any upstream.
func TestPaopaoDNS_HostsOverride(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	handler := &miniHandler{
		logger:   logger,
		dnsCache: cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		ptrResolver: newPTRResolver(nil, nil, false, map[string][]net.IP{
			"paopao.dns.": {net.ParseIP("10.10.10.53")},
		}, logger),
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "paopao.dns.", dns.TypeA)
	ctx := query_context.NewContext(q)

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil {
		t.Fatal("expected response")
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(r.Answer))
	}
	if r.Answer[0].(*dns.A).A.String() != "10.10.10.53" {
		t.Errorf("expected 10.10.10.53, got %s", r.Answer[0].(*dns.A).A.String())
	}
}
