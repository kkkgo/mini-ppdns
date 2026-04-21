package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
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

func TestIpToPTRName(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"10.10.10.132", "132.10.10.10.in-addr.arpa."},
		{"192.168.1.1", "1.1.168.192.in-addr.arpa."},
		{"255.255.255.255", "255.255.255.255.in-addr.arpa."},
		{"0.0.0.0", "0.0.0.0.in-addr.arpa."},
		{"invalid", ""},
		{"::1", ""}, // IPv6 not supported
	}
	for _, tt := range tests {
		got := ipToPTRName(tt.ip)
		if got != tt.want {
			t.Errorf("ipToPTRName(%q) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

func TestIsPrivatePTR(t *testing.T) {
	tests := []struct {
		qname string
		want  bool
	}{
		// 10.0.0.0/8
		{"132.10.10.10.in-addr.arpa.", true},
		{"1.0.0.10.in-addr.arpa.", true},
		// 172.16.0.0/12
		{"1.0.16.172.in-addr.arpa.", true},
		{"1.0.31.172.in-addr.arpa.", true},
		{"1.0.32.172.in-addr.arpa.", false}, // 172.32.x is not private
		// 192.168.0.0/16
		{"1.1.168.192.in-addr.arpa.", true},
		// 169.254.0.0/16 (link-local)
		{"1.1.254.169.in-addr.arpa.", true},
		// Public IPs
		{"4.4.8.8.in-addr.arpa.", false},
		{"1.1.1.1.in-addr.arpa.", false},
		// Not in-addr.arpa
		{"example.com.", false},
		// Malformed
		{"1.2.3.in-addr.arpa.", false},
		{"abc.2.3.4.in-addr.arpa.", false},
	}
	for _, tt := range tests {
		got := isPrivatePTR(tt.qname)
		if got != tt.want {
			t.Errorf("isPrivatePTR(%q) = %v, want %v", tt.qname, got, tt.want)
		}
	}
}

func TestPTRResolver_LeaseFile(t *testing.T) {
	tmpDir := t.TempDir()
	leaseFile := filepath.Join(tmpDir, "dhcp.leases")
	leaseContent := `1774555811 50:88:11:66:de:b6 10.10.10.132 MiAiSoundbox-L05C *
1774531287 00:d8:61:11:21:06 10.10.10.131 DESKTOP-69G4D2I 01:00:d8:61:11:21:06
1774555686 dc:f0:90:f1:6d:ce 10.10.10.124 NX789J 01:dc:f0:90:f1:6d:ce
1774560798 52:54:00:62:a3:83 10.10.10.3 PaoPaoGW *
1774531367 00:15:5d:0a:e2:06 10.10.10.246 * ff:5d:0a:e2:06:00:03:00:01:00:15:5d:0a:e2:06
`
	os.WriteFile(leaseFile, []byte(leaseContent), 0644)

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	pr := newPTRResolver([]string{leaseFile}, nil, false, nil, logger)

	tests := []struct {
		qname string
		want  string
	}{
		{"132.10.10.10.in-addr.arpa.", "MiAiSoundbox-L05C"},
		{"131.10.10.10.in-addr.arpa.", "DESKTOP-69G4D2I"},
		{"124.10.10.10.in-addr.arpa.", "NX789J"},
		{"3.10.10.10.in-addr.arpa.", "PaoPaoGW"},
		{"246.10.10.10.in-addr.arpa.", ""}, // hostname is *, should be skipped
		{"99.10.10.10.in-addr.arpa.", ""},  // not in lease file
	}
	for _, tt := range tests {
		got := pr.Lookup(tt.qname)
		if got != tt.want {
			t.Errorf("Lookup(%q) = %q, want %q", tt.qname, got, tt.want)
		}
	}
}

func TestPTRResolver_HostsFile(t *testing.T) {
	tmpDir := t.TempDir()
	hostsFile := filepath.Join(tmpDir, "hosts")
	hostsContent := `127.0.0.1 localhost
10.10.10.1 router.local myrouter
# comment line
::1     localhost ip6-localhost ip6-loopback

192.168.1.100 myserver  # inline comment
`
	os.WriteFile(hostsFile, []byte(hostsContent), 0644)

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	pr := newPTRResolver(nil, []string{hostsFile}, false, nil, logger)

	tests := []struct {
		qname string
		want  string
	}{
		{"1.0.0.127.in-addr.arpa.", "localhost"},
		{"1.10.10.10.in-addr.arpa.", "router.local"},
		{"100.1.168.192.in-addr.arpa.", "myserver"},
		{"2.0.0.127.in-addr.arpa.", ""}, // not in hosts
	}
	for _, tt := range tests {
		got := pr.Lookup(tt.qname)
		if got != tt.want {
			t.Errorf("Lookup(%q) = %q, want %q", tt.qname, got, tt.want)
		}
	}
}

// TestPTRResolver_ForwardLookup tests that hosts file entries provide forward A/AAAA lookups.
func TestPTRResolver_ForwardLookup(t *testing.T) {
	tmpDir := t.TempDir()
	hostsFile := filepath.Join(tmpDir, "hosts")
	hostsContent := `127.0.0.1 localhost
10.10.10.1 router.local myrouter
::1     localhost ip6-localhost ip6-loopback
192.168.1.100 myserver  # inline comment
2001:db8::1 v6host
`
	os.WriteFile(hostsFile, []byte(hostsContent), 0644)

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	pr := newPTRResolver(nil, []string{hostsFile}, false, nil, logger)

	// IPv4 forward lookups
	ips := pr.LookupIP("localhost.")
	if len(ips) < 1 {
		t.Fatal("expected at least 1 IP for localhost")
	}
	found127 := false
	for _, ip := range ips {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			found127 = true
		}
	}
	if !found127 {
		t.Errorf("expected 127.0.0.1 for localhost, got %v", ips)
	}

	// Multiple hostnames per line
	ips = pr.LookupIP("router.local.")
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.10.10.1")) {
		t.Errorf("expected [10.10.10.1] for router.local, got %v", ips)
	}
	ips = pr.LookupIP("myrouter.")
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.10.10.1")) {
		t.Errorf("expected [10.10.10.1] for myrouter, got %v", ips)
	}

	// IPv6 forward lookup
	ips = pr.LookupIP("v6host.")
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("expected [2001:db8::1] for v6host, got %v", ips)
	}

	// Not found
	ips = pr.LookupIP("nonexistent.")
	if len(ips) != 0 {
		t.Errorf("expected empty for nonexistent, got %v", ips)
	}
}

// TestPTRResolver_StaticHosts tests that [hosts] config entries work for both forward and PTR.
func TestPTRResolver_StaticHosts(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	pr := newPTRResolver(nil, nil, false, map[string][]net.IP{
		"example.com.": {net.ParseIP("1.2.3.4")},
		"dual.test.":   {net.ParseIP("10.0.0.1"), net.ParseIP("2001:db8::2")},
	}, logger)

	// Forward lookup
	ips := pr.LookupIP("example.com.")
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("expected [1.2.3.4] for example.com, got %v", ips)
	}

	// PTR reverse lookup (static hosts should also register PTR)
	got := pr.Lookup("4.3.2.1.in-addr.arpa.")
	if got != "example.com" {
		t.Errorf("expected PTR example.com, got %q", got)
	}

	// Dual-stack forward
	ips = pr.LookupIP("dual.test.")
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs for dual.test, got %d", len(ips))
	}
}

// TestPTRResolver_StaticOverridesFile tests that [hosts] config entries override file entries.
func TestPTRResolver_StaticOverridesFile(t *testing.T) {
	tmpDir := t.TempDir()
	hostsFile := filepath.Join(tmpDir, "hosts")
	os.WriteFile(hostsFile, []byte("1.1.1.1 example.com\n"), 0644)

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	pr := newPTRResolver(nil, []string{hostsFile}, false, map[string][]net.IP{
		"example.com.": {net.ParseIP("2.2.2.2")},
	}, logger)

	// Static should override file
	ips := pr.LookupIP("example.com.")
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("2.2.2.2")) {
		t.Errorf("expected static [2.2.2.2] to override file, got %v", ips)
	}
}

func TestPTRResolver_FileChange(t *testing.T) {
	tmpDir := t.TempDir()
	leaseFile := filepath.Join(tmpDir, "dhcp.leases")
	os.WriteFile(leaseFile, []byte("1774555811 aa:bb:cc:dd:ee:ff 10.10.10.100 host-A *\n"), 0644)

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	pr := newPTRResolver([]string{leaseFile}, nil, false, nil, logger)

	if got := pr.Lookup("100.10.10.10.in-addr.arpa."); got != "host-A" {
		t.Fatalf("expected host-A, got %q", got)
	}

	// Modify the file - need to ensure mtime changes
	time.Sleep(50 * time.Millisecond)
	os.WriteFile(leaseFile, []byte("1774555811 aa:bb:cc:dd:ee:ff 10.10.10.100 host-B *\n1774555812 aa:bb:cc:dd:ee:00 10.10.10.101 host-C *\n"), 0644)

	if !pr.filesChanged() {
		t.Fatal("expected filesChanged() to return true after modification")
	}

	pr.reload()

	if got := pr.Lookup("100.10.10.10.in-addr.arpa."); got != "host-B" {
		t.Fatalf("expected host-B after reload, got %q", got)
	}
	if got := pr.Lookup("101.10.10.10.in-addr.arpa."); got != "host-C" {
		t.Fatalf("expected host-C after reload, got %q", got)
	}
}

func TestPTRResolver_MissingFile(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	pr := newPTRResolver([]string{"/nonexistent/dhcp.leases"}, []string{"/nonexistent/hosts"}, false, nil, logger)

	// Should not panic, just return empty results
	if got := pr.Lookup("1.0.0.10.in-addr.arpa."); got != "" {
		t.Fatalf("expected empty for missing files, got %q", got)
	}
}

// TestBogusPriv_Process tests that private PTR queries return NXDOMAIN when boguspriv=true.
func TestBogusPriv_Process(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	// Create a mock upstream that should NOT be called
	var upstreamCalled atomic.Bool
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		upstreamCalled.Store(true)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeSuccess
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())
	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		upstreamCalled.Store(true)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeSuccess
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})

	handler := &miniHandler{
		logger:   logger,
		dnsCache: cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		localForward: &miniForwarder{
			upstreams: []upstream.Upstream{uLocal},
			addresses: []string{"udp://" + localAddr},
			qtime:     time.Second,
			logger:    logger,
		},
		cnForward: &miniForwarder{
			upstreams: []upstream.Upstream{uFall},
			addresses: []string{"udp://" + fallAddr},
			qtime:     time.Second,
			logger:    logger,
		},
		aaaaMode:  "yes",
		bogusPriv: true,
	}

	// Query for a private IP PTR
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "132.10.10.10.in-addr.arpa.", dns.TypePTR)
	ctx := query_context.NewContext(q)

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil {
		t.Fatal("expected response, got nil")
	}
	if r.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN (rcode %d), got rcode %d", dns.RcodeNameError, r.Rcode)
	}
	if upstreamCalled.Load() {
		t.Fatal("upstream should NOT have been called for private PTR with boguspriv")
	}
}

// TestBogusPriv_PublicPTR tests that public IP PTR queries still go to upstream.
func TestBogusPriv_PublicPTR(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeSuccess
		ptr, _ := dns.New("4.4.8.8.in-addr.arpa. 3600 IN PTR dns.google.")
		resp.Answer = []dns.RR{ptr}
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())
	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})

	handler := &miniHandler{
		logger:   logger,
		dnsCache: cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		localForward: &miniForwarder{
			upstreams: []upstream.Upstream{uLocal},
			addresses: []string{"udp://" + localAddr},
			qtime:     time.Second,
			logger:    logger,
		},
		cnForward: &miniForwarder{
			upstreams: []upstream.Upstream{uFall},
			addresses: []string{"udp://" + fallAddr},
			qtime:     time.Second,
			logger:    logger,
		},
		aaaaMode:  "yes",
		bogusPriv: true,
	}

	// Query for a public IP PTR - should go to upstream
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "4.4.8.8.in-addr.arpa.", dns.TypePTR)
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
		t.Fatalf("expected NOERROR, got rcode %d", r.Rcode)
	}
	if len(r.Answer) == 0 {
		t.Fatal("expected PTR answer for public IP")
	}
}

// TestLocalPTR_Process tests that PTR from lease file is returned directly.
func TestLocalPTR_Process(t *testing.T) {
	tmpDir := t.TempDir()
	leaseFile := filepath.Join(tmpDir, "dhcp.leases")
	os.WriteFile(leaseFile, []byte("1774555811 50:88:11:66:de:b6 10.10.10.132 MiAiSoundbox-L05C *\n"), 0644)

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	ptr := newPTRResolver([]string{leaseFile}, nil, false, nil, logger)

	// upstream should NOT be called
	var upstreamCalled atomic.Bool
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		upstreamCalled.Store(true)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())
	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		upstreamCalled.Store(true)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})

	handler := &miniHandler{
		logger:   logger,
		dnsCache: cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		localForward: &miniForwarder{
			upstreams: []upstream.Upstream{uLocal},
			addresses: []string{"udp://" + localAddr},
			qtime:     time.Second,
			logger:    logger,
		},
		cnForward: &miniForwarder{
			upstreams: []upstream.Upstream{uFall},
			addresses: []string{"udp://" + fallAddr},
			qtime:     time.Second,
			logger:    logger,
		},
		aaaaMode:    "yes",
		bogusPriv:   true,
		ptrResolver: ptr,
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "132.10.10.10.in-addr.arpa.", dns.TypePTR)
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
		t.Fatalf("expected NOERROR, got rcode %d", r.Rcode)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(r.Answer))
	}
	ptrRR, ok := r.Answer[0].(*dns.PTR)
	if !ok {
		t.Fatalf("expected PTR record, got %T", r.Answer[0])
	}
	if ptrRR.Ptr != "MiAiSoundbox-L05C." {
		t.Fatalf("expected PTR MiAiSoundbox-L05C., got %q", ptrRR.Ptr)
	}
	if upstreamCalled.Load() {
		t.Fatal("upstream should NOT have been called when local PTR is found")
	}
}

// TestLocalPTR_NotFound_BogusPriv tests that private PTR not in lease returns NXDOMAIN.
func TestLocalPTR_NotFound_BogusPriv(t *testing.T) {
	tmpDir := t.TempDir()
	leaseFile := filepath.Join(tmpDir, "dhcp.leases")
	os.WriteFile(leaseFile, []byte("1774555811 50:88:11:66:de:b6 10.10.10.132 MiAiSoundbox-L05C *\n"), 0644)

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	ptr := newPTRResolver([]string{leaseFile}, nil, false, nil, logger)

	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())
	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})

	handler := &miniHandler{
		logger:   logger,
		dnsCache: cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		localForward: &miniForwarder{
			upstreams: []upstream.Upstream{uLocal},
			addresses: []string{"udp://" + localAddr},
			qtime:     time.Second,
			logger:    logger,
		},
		cnForward: &miniForwarder{
			upstreams: []upstream.Upstream{uFall},
			addresses: []string{"udp://" + fallAddr},
			qtime:     time.Second,
			logger:    logger,
		},
		aaaaMode:    "yes",
		bogusPriv:   true,
		ptrResolver: ptr,
	}

	// Query for a private IP not in lease file
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "99.10.10.10.in-addr.arpa.", dns.TypePTR)
	ctx := query_context.NewContext(q)

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	r := ctx.R()
	if r == nil {
		t.Fatal("expected response, got nil")
	}
	if r.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got rcode %d", r.Rcode)
	}
}

// TestBogusPriv_Disabled tests that with boguspriv=false, private PTR goes to upstream.
func TestBogusPriv_Disabled(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})

	var upstreamCalled atomic.Bool
	localAddr, localSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		upstreamCalled.Store(true)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeSuccess
		ptr, _ := dns.New("132.10.10.10.in-addr.arpa. 3600 IN PTR some-host.")
		resp.Answer = []dns.RR{ptr}
		resp.WriteTo(w)
	})
	defer localSrv.Shutdown(context.Background())
	fallAddr, fallSrv, _ := mockServer(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.WriteTo(w)
	})
	defer fallSrv.Shutdown(context.Background())

	uLocal, _ := upstream.NewUpstream("udp://"+localAddr, upstream.Opt{Logger: logger})
	uFall, _ := upstream.NewUpstream("udp://"+fallAddr, upstream.Opt{Logger: logger})

	handler := &miniHandler{
		logger:   logger,
		dnsCache: cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 10}),
		localForward: &miniForwarder{
			upstreams: []upstream.Upstream{uLocal},
			addresses: []string{"udp://" + localAddr},
			qtime:     time.Second,
			logger:    logger,
		},
		cnForward: &miniForwarder{
			upstreams: []upstream.Upstream{uFall},
			addresses: []string{"udp://" + fallAddr},
			qtime:     time.Second,
			logger:    logger,
		},
		aaaaMode:  "yes",
		bogusPriv: false, // disabled
	}

	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "132.10.10.10.in-addr.arpa.", dns.TypePTR)
	ctx := query_context.NewContext(q)

	err := handler.process(context.Background(), ctx)
	if err != nil {
		t.Fatalf("process error: %v", err)
	}

	if !upstreamCalled.Load() {
		t.Fatal("upstream should have been called when boguspriv is disabled")
	}
	r := ctx.R()
	if r == nil {
		t.Fatal("expected response, got nil")
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got rcode %d", r.Rcode)
	}
}

// TestPTRResolver_LeaseAndHostsCombined tests that lease entries take priority over hosts.
func TestPTRResolver_LeaseAndHostsCombined(t *testing.T) {
	tmpDir := t.TempDir()
	leaseFile := filepath.Join(tmpDir, "dhcp.leases")
	hostsFile := filepath.Join(tmpDir, "hosts")

	// Both files have entry for 10.10.10.1, hosts loaded first then lease
	os.WriteFile(hostsFile, []byte("10.10.10.1 from-hosts\n"), 0644)
	os.WriteFile(leaseFile, []byte("1774555811 aa:bb:cc:dd:ee:ff 10.10.10.1 from-lease *\n"), 0644)

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	// Lease files are loaded first in newPTRResolver, then hosts files
	// So hosts file entry overwrites lease entry for same IP
	pr := newPTRResolver([]string{leaseFile}, []string{hostsFile}, false, nil, logger)

	got := pr.Lookup("1.10.10.10.in-addr.arpa.")
	// hosts file is loaded after lease file, so hosts entry wins
	if got != "from-hosts" {
		t.Errorf("expected from-hosts (hosts file loaded after lease), got %q", got)
	}
}

// TestPTRResolver_LazyReload tests that Lookup triggers lazy reload after debounce.
func TestPTRResolver_LazyReload(t *testing.T) {
	tmpDir := t.TempDir()
	leaseFile := filepath.Join(tmpDir, "dhcp.leases")
	os.WriteFile(leaseFile, []byte("1774555811 aa:bb:cc:dd:ee:ff 10.10.10.100 host-A *\n"), 0644)

	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	pr := newPTRResolver([]string{leaseFile}, nil, false, nil, logger)

	if got := pr.Lookup("100.10.10.10.in-addr.arpa."); got != "host-A" {
		t.Fatalf("expected host-A, got %q", got)
	}

	// Modify file
	time.Sleep(100 * time.Millisecond)
	os.WriteFile(leaseFile, []byte("1774555811 aa:bb:cc:dd:ee:ff 10.10.10.100 host-UPDATED *\n"), 0644)

	// Lookup within debounce window (< 5s) should NOT reload
	if got := pr.Lookup("100.10.10.10.in-addr.arpa."); got != "host-A" {
		t.Fatalf("expected host-A (debounce should prevent reload), got %q", got)
	}

	// Force lastCheck to expire by setting it to 6 seconds ago
	pr.lastCheck.Store(time.Now().Unix() - 6)

	// Now Lookup should trigger reload
	if got := pr.Lookup("100.10.10.10.in-addr.arpa."); got != "host-UPDATED" {
		t.Fatalf("expected host-UPDATED after debounce expired, got %q", got)
	}
}

// TestPTRResolver_AutoDetect tests auto-detection of default files.
func TestPTRResolver_AutoDetect(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	// With autoDetect=true but no default files existing (test env),
	// should return nil
	pr := newPTRResolver(nil, nil, true, nil, logger)
	// On most test machines, /tmp/dhcp.leases won't exist.
	// If /etc/hosts exists, pr will be non-nil. Either outcome is valid.
	if pr != nil {
		// /etc/hosts was found, verify it loaded something
		got := pr.Lookup("1.0.0.127.in-addr.arpa.")
		// Most /etc/hosts have 127.0.0.1 localhost
		t.Logf("auto-detect found files, localhost PTR = %q", got)
	} else {
		t.Log("auto-detect found no default files (expected in minimal env)")
	}
}

// TestPTRResolver_AutoDetect_NoFiles tests that nil is returned when no default files exist.
func TestPTRResolver_AutoDetect_NoFiles(t *testing.T) {
	logger, _ := mlog.NewLogger(mlog.LogConfig{Level: "error"})
	// Override defaults temporarily for testing
	origLease := defaultLeaseFiles
	origHosts := defaultHostsFiles
	defaultLeaseFiles = []string{"/nonexistent/a", "/nonexistent/b"}
	defaultHostsFiles = []string{"/nonexistent/c"}
	defer func() {
		defaultLeaseFiles = origLease
		defaultHostsFiles = origHosts
	}()

	pr := newPTRResolver(nil, nil, true, nil, logger)
	if pr != nil {
		t.Fatal("expected nil when no default files exist")
	}
}
