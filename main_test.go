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
	matcher := &forceFallMatcher{
		includePrefixes: []netip.Prefix{forcePrefix},
	}

	handler := &miniHandler{
		logger:           logger,
		localForward:     nil, // Will panic if local is called, making test fail if force_fall doesn't work
		cnForward:        fallbackFwd,
		dnsCache:         cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		forceFallMatcher: matcher,
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

func TestForceFallMatcher(t *testing.T) {
	tests := []struct {
		name     string
		include  []string // CIDR prefixes for include
		negate   []string // CIDR prefixes for negate
		clientIP string
		want     bool
	}{
		// No rules → never force_fall
		{"no rules", nil, nil, "192.168.1.1", false},

		// Include-only (OR logic)
		{"include match single", []string{"192.168.1.10/32"}, nil, "192.168.1.10", true},
		{"include no match single", []string{"192.168.1.10/32"}, nil, "192.168.1.11", false},
		{"include match cidr", []string{"192.168.2.0/24"}, nil, "192.168.2.100", true},
		{"include no match cidr", []string{"192.168.2.0/24"}, nil, "192.168.3.1", false},
		{"include OR first", []string{"10.0.0.1/32", "192.168.1.0/24"}, nil, "10.0.0.1", true},
		{"include OR second", []string{"10.0.0.1/32", "192.168.1.0/24"}, nil, "192.168.1.50", true},
		{"include OR none", []string{"10.0.0.1/32", "192.168.1.0/24"}, nil, "172.16.0.1", false},

		// Negate-only (AND logic): force_fall if NOT in any negated prefix
		{"negate not in range", nil, []string{"192.168.1.10/32"}, "192.168.1.11", true},
		{"negate in range", nil, []string{"192.168.1.10/32"}, "192.168.1.10", false},
		{"negate AND all pass", nil, []string{"192.168.1.10/32", "10.0.0.0/8"}, "172.16.0.1", true},
		{"negate AND one fail", nil, []string{"192.168.1.10/32", "10.0.0.0/8"}, "10.0.0.5", false},

		// Mixed: include OR wins first, then negate AND
		{"mixed include match", []string{"10.0.0.1/32"}, []string{"192.168.1.0/24"}, "10.0.0.1", true},
		{"mixed negate pass", []string{"10.0.0.1/32"}, []string{"192.168.1.0/24"}, "172.16.0.1", true},
		{"mixed negate fail", []string{"10.0.0.1/32"}, []string{"192.168.1.0/24"}, "192.168.1.50", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &forceFallMatcher{}
			for _, s := range tt.include {
				p, _ := netip.ParsePrefix(s)
				m.includePrefixes = append(m.includePrefixes, p)
			}
			for _, s := range tt.negate {
				p, _ := netip.ParsePrefix(s)
				m.negatePrefixes = append(m.negatePrefixes, p)
			}
			addr, _ := netip.ParseAddr(tt.clientIP)
			got := m.Match(addr)
			if got != tt.want {
				t.Errorf("Match(%s) = %v, want %v", tt.clientIP, got, tt.want)
			}
		})
	}
}

func TestRangeToPrefix(t *testing.T) {
	tests := []struct {
		name  string
		start string
		end   string
		want  []string // expected CIDR strings
	}{
		{"single IP", "192.168.1.10", "192.168.1.10", []string{"192.168.1.10/32"}},
		{"two IPs", "192.168.1.10", "192.168.1.11", []string{"192.168.1.10/31"}},
		{"three IPs", "192.168.1.123", "192.168.1.125", []string{"192.168.1.123/32", "192.168.1.124/31"}},
		{"full /24", "192.168.1.0", "192.168.1.255", []string{"192.168.1.0/24"}},
		{"partial range", "10.0.0.1", "10.0.0.6", []string{"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, _ := netip.ParseAddr(tt.start)
			end, _ := netip.ParseAddr(tt.end)
			got := rangeToPrefix(start, end)
			if len(got) != len(tt.want) {
				var gotStrs []string
				for _, p := range got {
					gotStrs = append(gotStrs, p.String())
				}
				t.Fatalf("rangeToPrefix(%s, %s) = %v, want %v", tt.start, tt.end, gotStrs, tt.want)
			}
			for i, p := range got {
				if p.String() != tt.want[i] {
					t.Errorf("prefix[%d] = %s, want %s", i, p.String(), tt.want[i])
				}
			}
		})
	}
}

func TestParseForceFallEntry(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantNeg   bool
		wantCount int // number of prefixes
		wantFirst string
		wantErr   bool
	}{
		{"empty", "", false, 0, "", false},
		{"single IP", "192.168.1.10", false, 1, "192.168.1.10/32", false},
		{"CIDR", "192.168.2.0/24", false, 1, "192.168.2.0/24", false},
		{"range", "192.168.1.10-192.168.1.11", false, 1, "192.168.1.10/31", false},
		{"negate single", "^192.168.1.126", true, 1, "192.168.1.126/32", false},
		{"negate cidr", "^192.168.10.0/24", true, 1, "192.168.10.0/24", false},
		{"negate range", "^192.168.1.123-192.168.1.125", true, 2, "192.168.1.123/32", false},
		{"invalid IP", "not.an.ip", false, 0, "", true},
		{"invalid range", "192.168.1.10-bad", false, 0, "", true},
		{"invalid cidr", "192.168.1.0/99", false, 0, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefixes, negated, err := parseForceFallEntry(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseForceFallEntry(%q) err = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if negated != tt.wantNeg {
				t.Errorf("negated = %v, want %v", negated, tt.wantNeg)
			}
			if len(prefixes) != tt.wantCount {
				t.Errorf("len(prefixes) = %d, want %d", len(prefixes), tt.wantCount)
			}
			if tt.wantCount > 0 && prefixes[0].String() != tt.wantFirst {
				t.Errorf("first prefix = %s, want %s", prefixes[0].String(), tt.wantFirst)
			}
		})
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

// TestNodataBothPreferLocal: local returns NODATA (SOA only), fall also returns NODATA.
// Expected: use local result with original TTL, cache normally.
func TestNodataBothPreferLocal(t *testing.T) {
	// Local server returns NODATA with SOA record
	localAddr, localSrv, _ := mockServer(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Rcode = dns.RcodeSuccess
		soa, _ := dns.NewRR("example.com. 300 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400")
		resp.Ns = append(resp.Ns, soa)
		w.WriteMsg(resp)
	})
	defer localSrv.Shutdown()

	// Fallback server also returns NODATA with SOA record
	fallAddr, fallSrv, _ := mockServer(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Rcode = dns.RcodeSuccess
		soa, _ := dns.NewRR("example.com. 60 IN SOA ns2.example.com. admin2.example.com. 2024010101 3600 900 604800 86400")
		resp.Ns = append(resp.Ns, soa)
		w.WriteMsg(resp)
	})
	defer fallSrv.Shutdown()

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
		allowAAAA:    true, // allow AAAA to reach forwarding logic
	}

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeAAAA)
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
	// Should have SOA from local (ns1.example.com), not fall (ns2.example.com)
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
	// TTL should be original (300), not overridden to 1
	if soa.Hdr.Ttl != 300 {
		t.Fatalf("expected original TTL 300, got %d", soa.Hdr.Ttl)
	}

	// Verify it was cached
	cacheKey := CacheKey("example.com._1_28") // class IN=1, type AAAA=28
	cached, _, ok := dnsCache.Get(cacheKey)
	if !ok || cached == nil {
		t.Fatal("expected NODATA result to be cached")
	}
}

// TestNodataLocalFallHasAnswer: local returns NODATA, fall returns actual Answer.
// Expected: use fallback result (existing behavior, TTL=1).
func TestNodataLocalFallHasAnswer(t *testing.T) {
	// Local server returns NODATA
	localAddr, localSrv, _ := mockServer(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Rcode = dns.RcodeSuccess
		soa, _ := dns.NewRR("example.com. 300 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400")
		resp.Ns = append(resp.Ns, soa)
		w.WriteMsg(resp)
	})
	defer localSrv.Shutdown()

	// Fallback server returns actual answer
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
	q.SetQuestion("example.com.", dns.TypeA)
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
	// Fallback answer TTL should be overridden to 1
	if r.Answer[0].Header().Ttl != 1 {
		t.Fatalf("expected fallback TTL 1, got %d", r.Answer[0].Header().Ttl)
	}
}

// TestNodataLocalFallTimeout: local returns NODATA, fall fails/timeout.
// Expected: use local NODATA result with original TTL.
func TestNodataLocalFallTimeout(t *testing.T) {
	// Local server returns NODATA with SOA
	localAddr, localSrv, _ := mockServer(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Rcode = dns.RcodeSuccess
		soa, _ := dns.NewRR("example.com. 600 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400")
		resp.Ns = append(resp.Ns, soa)
		w.WriteMsg(resp)
	})
	defer localSrv.Shutdown()

	// Fallback server with unreachable address (will timeout)
	fallAddr, fallSrv, _ := mockServer(func(w dns.ResponseWriter, r *dns.Msg) {
		// Never respond, causing timeout
		time.Sleep(5 * time.Second)
	})
	defer fallSrv.Shutdown()

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
		qtime:     200 * time.Millisecond, // short timeout to speed up test
		logger:    logger,
	}

	handler := &miniHandler{
		logger:       logger,
		localForward: localFwd,
		cnForward:    fallbackFwd,
		dnsCache:     cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		allowAAAA:    true, // allow AAAA to reach forwarding logic
	}

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeAAAA)
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
	// Should have SOA from local
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
	// TTL should be original (600), not modified
	if soa.Hdr.Ttl != 600 {
		t.Fatalf("expected original TTL 600, got %d", soa.Hdr.Ttl)
	}
}

// TestLocalFailFallNodata: local fails (SERVFAIL), fall returns NODATA.
// Expected: use fall NODATA result with TTL=1 override.
func TestLocalFailFallNodata(t *testing.T) {
	// Local server returns SERVFAIL
	localAddr, localSrv, _ := mockServer(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Rcode = dns.RcodeServerFailure
		w.WriteMsg(resp)
	})
	defer localSrv.Shutdown()

	// Fallback server returns NODATA with SOA
	fallAddr, fallSrv, _ := mockServer(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Rcode = dns.RcodeSuccess
		soa, _ := dns.NewRR("example.com. 300 IN SOA ns2.example.com. admin2.example.com. 2024010101 3600 900 604800 86400")
		resp.Ns = append(resp.Ns, soa)
		w.WriteMsg(resp)
	})
	defer fallSrv.Shutdown()

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
	q.SetQuestion("example.com.", dns.TypeA)
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
	// Should have SOA from fall (ns2.example.com.)
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
	// TTL should be overridden to 1 for fallback results
	if soa.Hdr.Ttl != 1 {
		t.Fatalf("expected overridden TTL 1 for fallback result, got %d", soa.Hdr.Ttl)
	}
}

func TestShuffleAnswers(t *testing.T) {
	t.Run("CNAME before A records", func(t *testing.T) {
		// Simulate connect.rom.miui.com response: 1 CNAME + 3 A records
		cname, _ := dns.NewRR("connect.rom.miui.com. 398 IN CNAME extranet.alb.xiaomi.com.")
		a1, _ := dns.NewRR("extranet.alb.xiaomi.com. 21 IN A 118.26.253.153")
		a2, _ := dns.NewRR("extranet.alb.xiaomi.com. 21 IN A 220.181.106.14")
		a3, _ := dns.NewRR("extranet.alb.xiaomi.com. 21 IN A 220.181.52.24")

		for i := 0; i < 50; i++ {
			answers := []dns.RR{cname, a1, a2, a3}
			shuffleAnswers(dns.TypeA, answers)

			if answers[0].Header().Rrtype != dns.TypeCNAME {
				t.Fatalf("iteration %d: first record should be CNAME, got %s", i, dns.TypeToString[answers[0].Header().Rrtype])
			}
			for j := 1; j < len(answers); j++ {
				if answers[j].Header().Rrtype != dns.TypeA {
					t.Fatalf("iteration %d: record[%d] should be A, got %s", i, j, dns.TypeToString[answers[j].Header().Rrtype])
				}
			}
		}
	})

	t.Run("multiple CNAME chain before A", func(t *testing.T) {
		cname1, _ := dns.NewRR("example.com. 300 IN CNAME alias1.example.com.")
		cname2, _ := dns.NewRR("alias1.example.com. 300 IN CNAME alias2.example.com.")
		a1, _ := dns.NewRR("alias2.example.com. 60 IN A 1.2.3.4")

		for i := 0; i < 50; i++ {
			answers := []dns.RR{a1, cname2, cname1}
			shuffleAnswers(dns.TypeA, answers)

			for j := 0; j < 2; j++ {
				if answers[j].Header().Rrtype != dns.TypeCNAME {
					t.Fatalf("iteration %d: record[%d] should be CNAME, got %s", i, j, dns.TypeToString[answers[j].Header().Rrtype])
				}
			}
			if answers[2].Header().Rrtype != dns.TypeA {
				t.Fatalf("iteration %d: last record should be A, got %s", i, dns.TypeToString[answers[2].Header().Rrtype])
			}
		}
	})

	t.Run("A only records are shuffled", func(t *testing.T) {
		a1, _ := dns.NewRR("example.com. 60 IN A 1.1.1.1")
		a2, _ := dns.NewRR("example.com. 60 IN A 2.2.2.2")
		a3, _ := dns.NewRR("example.com. 60 IN A 3.3.3.3")

		sawDifferentOrder := false
		firstOrder := ""
		for i := 0; i < 50; i++ {
			answers := []dns.RR{
				dns.Copy(a1), dns.Copy(a2), dns.Copy(a3),
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
		a1, _ := dns.NewRR("example.com. 60 IN A 1.1.1.1")
		answers := []dns.RR{a1}
		shuffleAnswers(dns.TypeA, answers)
		if answers[0].(*dns.A).A.String() != "1.1.1.1" {
			t.Fatal("single record should be unchanged")
		}
	})

	t.Run("CNAME only", func(t *testing.T) {
		cname, _ := dns.NewRR("example.com. 300 IN CNAME other.example.com.")
		answers := []dns.RR{cname}
		shuffleAnswers(dns.TypeA, answers)
		if answers[0].Header().Rrtype != dns.TypeCNAME {
			t.Fatal("single CNAME should be unchanged")
		}
	})

	t.Run("three-tier order: CNAME then qtype then rest", func(t *testing.T) {
		// Mixed response: CNAME + A (qtype) + TXT (other)
		cname, _ := dns.NewRR("example.com. 300 IN CNAME alias.example.com.")
		a1, _ := dns.NewRR("alias.example.com. 60 IN A 1.2.3.4")
		a2, _ := dns.NewRR("alias.example.com. 60 IN A 5.6.7.8")
		txt, _ := dns.NewRR("alias.example.com. 60 IN TXT \"v=spf1\"")

		for i := 0; i < 50; i++ {
			answers := []dns.RR{txt, a1, cname, a2}
			shuffleAnswers(dns.TypeA, answers)

			// Position 0: must be CNAME
			if answers[0].Header().Rrtype != dns.TypeCNAME {
				t.Fatalf("iter %d: answers[0] must be CNAME, got %s", i, dns.TypeToString[answers[0].Header().Rrtype])
			}
			// Positions 1-2: must be A (qtype)
			for j := 1; j <= 2; j++ {
				if answers[j].Header().Rrtype != dns.TypeA {
					t.Fatalf("iter %d: answers[%d] must be A, got %s", i, j, dns.TypeToString[answers[j].Header().Rrtype])
				}
			}
			// Position 3: must be TXT (rest)
			if answers[3].Header().Rrtype != dns.TypeTXT {
				t.Fatalf("iter %d: answers[3] must be TXT, got %s", i, dns.TypeToString[answers[3].Header().Rrtype])
			}
		}
	})

	t.Run("qtype records before rest when no CNAME", func(t *testing.T) {
		a1, _ := dns.NewRR("example.com. 60 IN A 1.1.1.1")
		txt, _ := dns.NewRR("example.com. 60 IN TXT \"info\"")

		for i := 0; i < 20; i++ {
			answers := []dns.RR{txt, a1}
			shuffleAnswers(dns.TypeA, answers)

			if answers[0].Header().Rrtype != dns.TypeA {
				t.Fatalf("iter %d: A record must come before TXT", i)
			}
			if answers[1].Header().Rrtype != dns.TypeTXT {
				t.Fatalf("iter %d: TXT must be last", i)
			}
		}
	})
}


func TestCalculateCacheSize(t *testing.T) {
	tests := []struct {
		name     string
		availMem uint64
		wantSize int
	}{
		{"zero (fallback)", 0, maxCacheSize},
		{"large mem 4GB", 4 * 1024 * 1024 * 1024, maxCacheSize},
		{"256MB", 256 * 1024 * 1024, maxCacheSize}, // 104857 → capped to 102400
		{"32MB", 32 * 1024 * 1024, 13107},          // 33554432 / 5 / 512
		{"very small 1MB", 1 * 1024 * 1024, minCacheSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateCacheSize(tt.availMem)
			if got != tt.wantSize {
				t.Errorf("calculateCacheSize(%d) = %d, want %d", tt.availMem, got, tt.wantSize)
			}
		})
	}
}
