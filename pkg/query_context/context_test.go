package query_context

import (
	"sync"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func newTestQuery() *dns.Msg {
	m := new(dns.Msg)
	dnsutil.SetQuestion(m, "example.com.", dns.TypeA)
	return m
}

func TestNewContext(t *testing.T) {
	q := newTestQuery()
	ctx := NewContext(q)

	if ctx.Id() == 0 {
		t.Fatal("id should not be 0")
	}
	if ctx.StartTime().IsZero() {
		t.Fatal("start time should not be zero")
	}
	if ctx.Q() == nil {
		t.Fatal("Q() should not be nil")
	}
	if ctx.QQuestion().Name != "example.com." {
		t.Fatalf("question name = %q, want example.com.", ctx.QQuestion().Name)
	}
}

func TestContext_QOpt(t *testing.T) {
	q := newTestQuery()
	// Set UDPSize so EDNS0 is present
	q.UDPSize = 512
	ctx := NewContext(q)
	opt := ctx.QOpt()
	if opt == nil {
		t.Fatal("QOpt should not be nil")
	}
	if dns.RRToType(opt) != dns.TypeOPT {
		t.Fatal("QOpt should be OPT record")
	}
}

func TestContext_ClientOpt_WithEdns(t *testing.T) {
	q := newTestQuery()
	// Set UDPSize to indicate EDNS0 support
	q.UDPSize = 4096

	ctx := NewContext(q)
	if ctx.ClientOpt() == nil {
		t.Fatal("ClientOpt should not be nil when query has OPT")
	}
	if ctx.RespOpt() == nil {
		t.Fatal("RespOpt should not be nil when client supports EDNS0")
	}
}

func TestContext_ClientOpt_WithoutEdns(t *testing.T) {
	q := newTestQuery()
	// No EDNS0
	ctx := NewContext(q)
	if ctx.ClientOpt() != nil {
		t.Fatal("ClientOpt should be nil when query has no OPT")
	}
}

func TestContext_SetResponse(t *testing.T) {
	q := newTestQuery()
	ctx := NewContext(q)

	if ctx.R() != nil {
		t.Fatal("R() should be nil initially")
	}

	r := new(dns.Msg)
	dnsutil.SetReply(r, q)
	rr, _ := dns.New("example.com. 300 IN A 1.2.3.4")
	r.Answer = append(r.Answer, rr)

	ctx.SetResponse(r)
	if ctx.R() == nil {
		t.Fatal("R() should not be nil after SetResponse")
	}

	// Set nil to clear response
	ctx.SetResponse(nil)
	if ctx.R() != nil {
		t.Fatal("R() should be nil after SetResponse(nil)")
	}
}

func TestContext_UpstreamOpt(t *testing.T) {
	q := newTestQuery()
	ctx := NewContext(q)

	r := new(dns.Msg)
	dnsutil.SetReply(r, q)
	// Indicate EDNS0 via UDPSize
	r.UDPSize = 4096

	ctx.SetResponse(r)
	if ctx.UpstreamOpt() == nil {
		t.Fatal("UpstreamOpt should not be nil when response has EDNS0")
	}

	// No OPT records should be in Extra (new API uses Pseudo/UDPSize fields)
	for _, rr := range ctx.R().Extra {
		if dns.RRToType(rr) == dns.TypeOPT {
			t.Fatal("OPT should not be in Extra with new API")
		}
	}
}

func TestContext_StoreGetDeleteValue(t *testing.T) {
	q := newTestQuery()
	ctx := NewContext(q)

	k := RegKey()

	_, ok := ctx.GetValue(k)
	if ok {
		t.Fatal("value should not exist")
	}

	ctx.StoreValue(k, "hello")
	v, ok := ctx.GetValue(k)
	if !ok || v != "hello" {
		t.Fatalf("GetValue = %v, %v, want hello, true", v, ok)
	}

	ctx.DeleteValue(k)
	_, ok = ctx.GetValue(k)
	if ok {
		t.Fatal("value should be deleted")
	}
}

func TestContext_SetHasDeleteMark(t *testing.T) {
	q := newTestQuery()
	ctx := NewContext(q)

	if ctx.HasMark(1) {
		t.Fatal("mark should not exist")
	}

	ctx.SetMark(1)
	if !ctx.HasMark(1) {
		t.Fatal("mark should exist")
	}

	ctx.DeleteMark(1)
	if ctx.HasMark(1) {
		t.Fatal("mark should be deleted")
	}
}

func TestContext_Copy(t *testing.T) {
	q := newTestQuery()
	ctx := NewContext(q)

	k := RegKey()
	ctx.StoreValue(k, "test")
	ctx.SetMark(42)

	r := new(dns.Msg)
	dnsutil.SetReply(r, q)
	ctx.SetResponse(r)

	copied := ctx.Copy()

	if copied.Id() != ctx.Id() {
		t.Fatal("copied id mismatch")
	}
	if copied.QQuestion().Name != ctx.QQuestion().Name {
		t.Fatal("copied question mismatch")
	}
	if copied.R() == nil {
		t.Fatal("copied response should not be nil")
	}

	// Values should be present in copy
	v, ok := copied.GetValue(k)
	if !ok || v != "test" {
		t.Fatal("copied value mismatch")
	}
	if !copied.HasMark(42) {
		t.Fatal("copied mark should exist")
	}

	// Deep copy: modifying copy should not affect original
	copied.Q().Question[0].Header().Name = "modified.com."
	if ctx.QQuestion().Name == "modified.com." {
		t.Fatal("copy should be deep - modifying copy affected original")
	}
}

func TestContext_CopyTo(t *testing.T) {
	q := newTestQuery()
	ctx := NewContext(q)

	dst := new(Context)
	ctx.CopyTo(dst)

	if dst.Id() != ctx.Id() {
		t.Fatal("CopyTo id mismatch")
	}
	if dst.QQuestion().Name != "example.com." {
		t.Fatal("CopyTo question mismatch")
	}
}

func TestContext_EDNS0_DO_Bit(t *testing.T) {
	q := newTestQuery()
	q.UDPSize = 4096
	q.Security = true // DO bit

	ctx := NewContext(q)
	// RespOpt should have DO bit set
	if ctx.RespOpt() == nil {
		t.Fatal("RespOpt should not be nil")
	}
	if !ctx.RespOpt().Security() {
		t.Fatal("RespOpt DO bit should be set when client sends DO")
	}
}

func TestRegKey_Unique(t *testing.T) {
	k1 := RegKey()
	k2 := RegKey()
	k3 := RegKey()

	if k1 == k2 || k2 == k3 || k1 == k3 {
		t.Fatalf("keys should be unique: %d, %d, %d", k1, k2, k3)
	}
}

func TestRegKey(t *testing.T) {
	k1 := RegKey()
	k2 := RegKey()

	if k1 == 0 || k2 == 0 {
		t.Fatalf("RegKey should not return 0, got k1=%d, k2=%d", k1, k2)
	}
	if k2 <= k1 {
		t.Fatalf("RegKey is not monotonically increasing: k1=%d, k2=%d", k1, k2)
	}

	var wg sync.WaitGroup
	const numGoroutines = 100
	keys := make([]uint32, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			keys[idx] = RegKey()
		}(i)
	}
	wg.Wait()

	seen := make(map[uint32]bool)
	for _, k := range keys {
		if k == 0 {
			t.Errorf("RegKey returned 0 concurrently")
		}
		if seen[k] {
			t.Errorf("RegKey returned duplicate key: %d", k)
		}
		seen[k] = true
	}
}
