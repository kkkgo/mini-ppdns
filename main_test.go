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
