package query_context

import (
	"testing"

	"github.com/miekg/dns"
)

func newTestQuery() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
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
	ctx := NewContext(q)
	opt := ctx.QOpt()
	if opt == nil {
		t.Fatal("QOpt should not be nil")
	}
	if opt.Hdr.Rrtype != dns.TypeOPT {
		t.Fatal("QOpt should be OPT record")
	}
}

func TestContext_ClientOpt_WithEdns(t *testing.T) {
	q := newTestQuery()
	// Add client OPT
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	q.Extra = append(q.Extra, opt)

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
	// No OPT in query
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
	r.SetReply(q)
	rr, _ := dns.NewRR("example.com. 300 IN A 1.2.3.4")
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
	r.SetReply(q)
	// Add upstream OPT
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	r.Extra = append(r.Extra, opt)

	ctx.SetResponse(r)
	if ctx.UpstreamOpt() == nil {
		t.Fatal("UpstreamOpt should not be nil when response has OPT")
	}

	// OPT should be removed from response Extra
	for _, rr := range ctx.R().Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			t.Fatal("OPT should be popped from response")
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
	r.SetReply(q)
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
	copied.Q().Question[0].Name = "modified.com."
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
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	opt.SetDo()
	q.Extra = append(q.Extra, opt)

	ctx := NewContext(q)
	// RespOpt should have DO bit set
	if ctx.RespOpt() == nil {
		t.Fatal("RespOpt should not be nil")
	}
	if !ctx.RespOpt().Do() {
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
