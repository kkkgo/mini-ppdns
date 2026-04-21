package query_context

import (
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/kkkgo/mini-ppdns/pkg/server"
)

// ourUDPSize is the UDP payload size we advertise on outgoing queries
// regardless of what the client asked for. 1200 is the value recommended
// by DNS Flag Day 2020 — large enough to hold most realistic answers
// without triggering IP fragmentation over typical MTUs.
const ourUDPSize = 1200

// edns0Size is kept as an alias of ourUDPSize so existing references
// still resolve. New code should use ourUDPSize.
const edns0Size = ourUDPSize

// Question is a plain-value view of the DNS question section. The
// upstream library represents the question as an RR; we copy the three
// fields that callers actually want so they don't have to know that.
type Question struct {
	Name   string
	Qtype  uint16
	Qclass uint16
}

// Context carries one in-flight DNS query from front door to upstream
// and back. Methods are NOT safe for concurrent use; a Context is owned
// by exactly one handling goroutine at a time.
type Context struct {
	id        uint32
	startTime time.Time

	// ServerMeta is caller-facing metadata from the server front end
	// (listener address etc.) and read-only once NewContext returns.
	ServerMeta ServerMeta

	query         *dns.Msg // always non-nil, always has a question
	requesterEDNS *dns.OPT // client's original EDNS0 state, or nil

	resp         *dns.Msg
	respOpt      *dns.OPT // mirrors resolverEDNS presence
	resolverEDNS *dns.OPT // upstream's EDNS0 state, or nil

	// kv / marks are allocated lazily so minimal queries cost zero
	// extra map allocations.
	kv    map[uint32]any
	marks map[uint32]struct{}
}

var contextUid atomic.Uint32

type ServerMeta = server.QueryMeta

// NewContext wraps q into a fresh Context. q must have exactly one
// question; NewContext takes ownership of q (including rewriting its
// UDPSize to our preferred value).
func NewContext(q *dns.Msg) *Context {
	ctx := &Context{
		id:            contextUid.Add(1),
		startTime:     time.Now(),
		query:         q,
		requesterEDNS: extractAndResetOpt(q),
	}
	if ctx.requesterEDNS != nil {
		ctx.respOpt = newOpt()
		// RFC 3225 §3: echo the DO bit into the response.
		if ctx.requesterEDNS.Security() {
			ctx.respOpt.SetSecurity(true)
		}
	}
	return ctx
}

// Id returns a context-local unique id (distinct from the DNS header's
// 16-bit transaction id).
func (ctx *Context) Id() uint32 { return ctx.id }

// StartTime is when NewContext was called.
func (ctx *Context) StartTime() time.Time { return ctx.startTime }

// Q returns the outbound query. Always non-nil with one question and an
// EDNS0 OPT attached. Callers that mutate the message must preserve
// both invariants.
func (ctx *Context) Q() *dns.Msg { return ctx.query }

// QQuestion extracts a value-type view of the first question. If the
// message has no question (malformed input), a zero-value Question is
// returned rather than panicking.
func (ctx *Context) QQuestion() Question {
	if len(ctx.query.Question) == 0 {
		return Question{}
	}
	rr := ctx.query.Question[0]
	h := rr.Header()
	return Question{
		Name:   h.Name,
		Qtype:  dns.RRToType(rr),
		Qclass: h.Class,
	}
}

// QOpt returns the query's OPT record. Always non-nil: NewContext
// guarantees an EDNS0 UDPSize, so the OPT can be reconstructed. If that
// invariant is somehow broken (direct struct construction in a test),
// a safe default is returned instead of panicking.
func (ctx *Context) QOpt() *dns.OPT {
	if opt := buildOptFromMsg(ctx.query); opt != nil {
		return opt
	}
	return newOpt()
}

// ClientOpt returns the OPT the client actually sent (nil if the client
// did not speak EDNS0). Plugins deciding whether to add/forward OPT
// options should branch on this. Read-only.
func (ctx *Context) ClientOpt() *dns.OPT { return ctx.requesterEDNS }

// SetResponse installs m as the response that will be sent to the
// client (nil clears any prior response). Takes ownership of m.
func (ctx *Context) SetResponse(m *dns.Msg) {
	ctx.resp = m
	if m == nil {
		ctx.resolverEDNS = nil
		return
	}
	ctx.resolverEDNS = buildOptFromMsg(m)
}

// R returns the response that will go back to the client (may be nil).
// R does NOT carry EDNS0 — the OPT must be obtained via RespOpt() and
// merged by the writer layer.
func (ctx *Context) R() *dns.Msg { return ctx.resp }

// RespOpt is the OPT that will be written back with R. Non-nil whenever
// the client supports EDNS0 (regardless of whether R itself is set);
// nil otherwise.
func (ctx *Context) RespOpt() *dns.OPT { return ctx.respOpt }

// UpstreamOpt is the OPT the upstream resolver returned (may be nil).
// Read-only; plugins that want to forward options into the response
// must copy from here into RespOpt.
func (ctx *Context) UpstreamOpt() *dns.OPT { return ctx.resolverEDNS }

// Copy returns a deep copy of ctx.
func (ctx *Context) Copy() *Context {
	dst := new(Context)
	ctx.CopyTo(dst)
	return dst
}

// CopyTo deep-copies ctx into d. Values stored via StoreValue are *not*
// deep-copied (only the map keys are).
func (ctx *Context) CopyTo(d *Context) *Context {
	d.id = ctx.id
	d.startTime = ctx.startTime
	d.ServerMeta = ctx.ServerMeta

	d.query = cloneMsg(ctx.query)
	d.requesterEDNS = ctx.requesterEDNS

	if ctx.resp != nil {
		d.resp = ctx.resp.Copy()
	}
	if ctx.respOpt != nil {
		d.respOpt = ctx.respOpt.Clone().(*dns.OPT)
	}
	d.resolverEDNS = ctx.resolverEDNS

	d.kv = copyMap(ctx.kv)
	d.marks = copyMap(ctx.marks)
	return d
}

// StoreValue attaches v to ctx under key k. k MUST come from RegKey.
func (ctx *Context) StoreValue(k uint32, v any) {
	if ctx.kv == nil {
		ctx.kv = make(map[uint32]any)
	}
	ctx.kv[k] = v
}

// GetValue retrieves a value previously set via StoreValue. The second
// result is false if no value was set for k.
func (ctx *Context) GetValue(k uint32) (any, bool) {
	v, ok := ctx.kv[k]
	return v, ok
}

// DeleteValue removes k from ctx.
func (ctx *Context) DeleteValue(k uint32) {
	delete(ctx.kv, k)
}

// SetMark records mark m on ctx.
func (ctx *Context) SetMark(m uint32) {
	if ctx.marks == nil {
		ctx.marks = make(map[uint32]struct{})
	}
	ctx.marks[m] = struct{}{}
}

// HasMark reports whether SetMark was called with m (and not since
// DeleteMark'd).
func (ctx *Context) HasMark(m uint32) bool {
	_, ok := ctx.marks[m]
	return ok
}

// DeleteMark removes mark m.
func (ctx *Context) DeleteMark(m uint32) {
	delete(ctx.marks, m)
}

// cloneMsg deep-copies m. The upstream Msg.Copy does a shallow copy of
// the Question section in the current library version, so we clone the
// question RRs explicitly.
func cloneMsg(m *dns.Msg) *dns.Msg {
	c := m.Copy()
	if len(c.Question) > 0 {
		qs := make([]dns.RR, len(c.Question))
		for i, rr := range c.Question {
			qs[i] = rr.Clone()
		}
		c.Question = qs
	}
	return c
}

func copyMap[K comparable, V any](m map[K]V) map[K]V {
	if m == nil {
		return nil
	}
	out := make(map[K]V, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// extractAndResetOpt snapshots the client's EDNS0 state into an OPT
// record (or returns nil if the client did not speak EDNS0), then
// forces our preferred UDPSize onto m so the outgoing query advertises
// a consistent payload size regardless of what the client asked for.
func extractAndResetOpt(m *dns.Msg) *dns.OPT {
	if m.UDPSize == 0 {
		// Client did not send OPT. Attach ours for the upstream query.
		m.UDPSize = ourUDPSize
		return nil
	}
	saved := newOpt()
	saved.SetUDPSize(m.UDPSize)
	saved.SetSecurity(m.Security)
	m.UDPSize = ourUDPSize
	return saved
}

// buildOptFromMsg synthesizes an OPT record from m's EDNS0 fields, or
// returns nil if the message has no EDNS0 state.
func buildOptFromMsg(m *dns.Msg) *dns.OPT {
	if m.UDPSize == 0 {
		return nil
	}
	opt := newOpt()
	opt.SetUDPSize(m.UDPSize)
	opt.SetSecurity(m.Security)
	return opt
}

// newOpt returns a default OPT record with our advertised UDPSize and
// the root name — the spec-mandated shape.
func newOpt() *dns.OPT {
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.SetUDPSize(ourUDPSize)
	return opt
}

// ---- RegKey ----

var keyCounter atomic.Uint32

// RegKey returns a fresh, process-unique key for use with
// Context.StoreValue / Context.GetValue. Call it at package init or
// similar — never on a hot path, since the counter space is only 2^32.
func RegKey() uint32 {
	n := keyCounter.Add(1)
	if n == 0 {
		panic("query_context: RegKey counter overflowed")
	}
	return n
}
