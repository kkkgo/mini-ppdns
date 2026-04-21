package main

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/cache"
	"github.com/kkkgo/mini-ppdns/pkg/dnsutils"
	"github.com/kkkgo/mini-ppdns/pkg/pool"
	"github.com/kkkgo/mini-ppdns/pkg/query_context"
	"github.com/kkkgo/mini-ppdns/pkg/server"
	"github.com/kkkgo/mini-ppdns/pkg/upstream"
	"github.com/kkkgo/mini-ppdns/pplog"
)

const (
	defaultConcurrentQueries = 3  // number of concurrent upstream queries per request
	maxUpstreams             = 16 // max upstream count for stack-allocated shuffle
	fallbackTTL              = 1  // TTL for fallback DNS responses (short to allow fast switch back to main DNS)
)

type CacheKey struct {
	Name   string
	Qtype  uint16
	Qclass uint16
}

func (k CacheKey) Sum() uint64 {
	// FNV-1a hash
	var hash uint64 = 14695981039346656037
	for i := 0; i < len(k.Name); i++ {
		hash ^= uint64(k.Name[i])
		hash *= 1099511628211
	}
	hash ^= uint64(k.Qtype)
	hash *= 1099511628211
	hash ^= uint64(k.Qclass)
	hash *= 1099511628211
	return hash
}

type miniHandler struct {
	logger *mlog.Logger

	localForward *miniForwarder
	cnForward    *miniForwarder
	dnsCache     *cache.Cache[CacheKey, *dns.Msg]

	forceFallMatcher *forceFallMatcher
	aaaaMode         string // "no", "yes", or "noerror"
	trustRcodes      map[int]bool
	lite             bool
	bogusPriv        bool         // return NXDOMAIN for private PTR not found locally
	ptrResolver      *ptrResolver // nil if no lease/hosts files configured

	pplogReporter *pplog.Reporter
	pplogLevel    int

	hookFailed *atomic.Bool // nil if hook not configured
}

type miniForwarder struct {
	upstreams []upstream.Upstream
	addresses []string
	qtime     time.Duration
	logger    *mlog.Logger
}

func (f *miniForwarder) Exec(ctx context.Context, qCtx *query_context.Context) (*dns.Msg, string, time.Duration, error) {
	if len(f.upstreams) == 0 {
		return nil, "", 0, fmt.Errorf("no upstreams available")
	}

	queryPayload, err := pool.PackBuffer(qCtx.Q())
	if err != nil {
		return nil, "", 0, err
	}
	defer pool.ReleaseBuf(queryPayload)

	type res struct {
		r        *dns.Msg
		err      error
		upstream string
		duration time.Duration
	}

	concurrent := defaultConcurrentQueries
	if len(f.upstreams) < concurrent {
		concurrent = len(f.upstreams)
	}

	resChan := make(chan res, concurrent)
	done := make(chan struct{})
	defer close(done)

	start := time.Now()

	// Pick concurrent distinct upstreams via partial Fisher-Yates shuffle (no heap allocation).
	// Cap n at the stack array size so an oversized upstream list cannot produce out-of-range indices.
	n := len(f.upstreams)
	if n > maxUpstreams {
		// By design: we cap here to keep `indices` stack-allocated and the
		// Exec path allocation-free. Configuring more than maxUpstreams
		// upstreams is outside the intended deployment shape — a DNS
		// forwarder with >16 upstreams is almost always a misconfiguration
		// (load balancing doesn't scale that way on retail hardware). If you
		// truly need more, switch indices to a heap slice.
		n = maxUpstreams
	}
	if concurrent > n {
		concurrent = n
	}
	var indices [maxUpstreams]int
	for i := 0; i < n; i++ {
		indices[i] = i
	}
	for i := 0; i < concurrent; i++ {
		j := i + rand.IntN(n-i)
		indices[i], indices[j] = indices[j], indices[i]
	}
	for c := 0; c < concurrent; c++ {
		idx := indices[c]
		u := f.upstreams[idx]
		addr := ""
		if idx < len(f.addresses) {
			addr = f.addresses[idx]
		}
		qc := func(b *[]byte) *[]byte {
			c := pool.GetBuf(cap(*b))
			*c = (*c)[:len(*b)]
			copy(*c, *b)
			return c
		}(queryPayload)

		go func(up upstream.Upstream, upAddr string) {
			defer pool.ReleaseBuf(qc)
			upstreamCtx, cancel := context.WithTimeout(ctx, f.qtime)
			defer cancel()

			var r *dns.Msg
			respPayload, err := up.ExchangeContext(upstreamCtx, *qc)
			dur := time.Since(start)
			if err == nil {
				r = new(dns.Msg)
				r.Data = *respPayload
				err = r.Unpack()
				// Clear r.Data before releasing the pooled buffer so r does
				// not hold a dangling pointer into a reusable slice.
				r.Data = nil
				pool.ReleaseBuf(respPayload)
				if err != nil {
					r = nil
				}
			}
			select {
			case resChan <- res{r: r, err: err, upstream: upAddr, duration: dur}:
			case <-done:
			}
		}(u, addr)
	}

	var fallbackRes res
	var firstErr error
	for i := 0; i < concurrent; i++ {
		select {
		case r := <-resChan:
			if r.err != nil {
				if firstErr == nil {
					firstErr = r.err
				}
				continue
			}
			if r.r.Rcode == dns.RcodeSuccess {
				return r.r, r.upstream, r.duration, nil
			}
			if fallbackRes.r == nil {
				fallbackRes = r
			}
		case <-ctx.Done():
			return nil, "", time.Since(start), ctx.Err()
		}
	}
	if fallbackRes.r != nil {
		return fallbackRes.r, fallbackRes.upstream, fallbackRes.duration, nil
	}
	return nil, "", time.Since(start), firstErr
}

func (h *miniHandler) Handle(ctx context.Context, q *dns.Msg, meta server.QueryMeta, packMsgPayload func(m *dns.Msg) (*[]byte, error)) *[]byte {
	// Reject malformed queries (no question section) at the boundary so that
	// downstream code can assume a non-empty Question slice.
	if len(q.Question) == 0 {
		r := new(dns.Msg)
		dnsutil.SetReply(r, q)
		r.Rcode = dns.RcodeFormatError
		payload, err := packMsgPayload(r)
		if err != nil {
			h.logger.Warnw("failed to pack FORMERR response", mlog.Err(err))
			return nil
		}
		return payload
	}

	qCtx := query_context.NewContext(q)
	qCtx.ServerMeta = meta

	err := h.process(ctx, qCtx)
	if err != nil {
		h.logger.Debugw("query failed", mlog.Err(err))
		if qCtx.R() == nil {
			r := new(dns.Msg)
			dnsutil.SetReply(r, q)
			r.Rcode = dns.RcodeServerFailure
			qCtx.SetResponse(r)
		}
	} else if qCtx.R() == nil {
		// Empty response
		r := new(dns.Msg)
		dnsutil.SetReply(r, q)
		r.Rcode = dns.RcodeServerFailure
		qCtx.SetResponse(r)
	}
	if qCtx.R() != nil {
		if len(qCtx.R().Answer) > 1 && len(q.Question) > 0 {
			shuffleAnswers(dns.RRToType(q.Question[0]), qCtx.R().Answer)
		}
	}

	payload, err := packMsgPayload(qCtx.R())
	if err != nil {
		h.logger.Warnw("failed to pack response", mlog.Err(err))
		return nil
	}
	return payload
}

func shuffleAnswers(qtype uint16, answers []dns.RR) {
	if len(answers) <= 1 {
		return
	}
	// In-place three-tier partition per RFC 1034 (zero heap allocations):
	//   1. CNAME records (must precede the records they resolve to)
	//   2. Records matching the queried qtype (shuffled for load balancing)
	//   3. Everything else
	cnameEnd := stablePartitionRR(answers, func(rr dns.RR) bool {
		return dns.RRToType(rr) == dns.TypeCNAME
	})
	rest := answers[cnameEnd:]
	qtypeEnd := stablePartitionRR(rest, func(rr dns.RR) bool {
		return dns.RRToType(rr) == qtype
	})
	qtypeSlice := rest[:qtypeEnd]
	rand.Shuffle(len(qtypeSlice), func(i, j int) {
		qtypeSlice[i], qtypeSlice[j] = qtypeSlice[j], qtypeSlice[i]
	})
}

// stablePartitionRR moves elements satisfying pred to the front of s,
// preserving relative order. Returns the count of matching elements.
// Runs in O(n) time with a single scratch allocation, replacing the
// former in-place copy-shift whose worst case (matches clustered at
// the tail) was O(n²).
func stablePartitionRR(s []dns.RR, pred func(dns.RR) bool) int {
	n := len(s)
	if n <= 1 {
		if n == 1 && pred(s[0]) {
			return 1
		}
		return 0
	}
	matches := 0
	for _, rr := range s {
		if pred(rr) {
			matches++
		}
	}
	if matches == 0 || matches == n {
		return matches
	}
	tmp := make([]dns.RR, n)
	hi, lo := 0, matches
	for _, rr := range s {
		if pred(rr) {
			tmp[hi] = rr
			hi++
		} else {
			tmp[lo] = rr
			lo++
		}
	}
	copy(s, tmp)
	return matches
}

// cacheSnapshot prepares a Msg for storage in the DNS cache. Answer/Ns/Extra
// are copied into fresh backing arrays so downstream in-place operations —
// notably shuffleAnswers in Handle — cannot reach back into cached entries.
// RR pointers themselves are shared: RRs are treated as immutable once stored
// (applyLiteMode already finished; fall-path TTL rewrites happen before the
// call reaches here), and the Load path deep-clones via cloneRRsWithTTL
// before the only remaining mutation site (the cache-hit TTL rewrite), so
// the sharing never becomes observable. This replaces the library's
// Msg.Copy, which is explicitly a shallow copy and would let shuffleAnswers
// reorder the cached slice and let Load-side TTL rewrites pollute cached
// RR headers.
func cacheSnapshot(r *dns.Msg) *dns.Msg {
	if r == nil {
		return nil
	}
	snap := &dns.Msg{
		MsgHeader: r.MsgHeader,
		Question:  r.Question,
		Pseudo:    r.Pseudo,
		Data:      r.Data,
	}
	if n := len(r.Answer); n > 0 {
		snap.Answer = append(make([]dns.RR, 0, n), r.Answer...)
	}
	if n := len(r.Ns); n > 0 {
		snap.Ns = append(make([]dns.RR, 0, n), r.Ns...)
	}
	if n := len(r.Extra); n > 0 {
		snap.Extra = append(make([]dns.RR, 0, n), r.Extra...)
	}
	return snap
}

// cloneRRsWithTTL returns a new slice where every RR is a deep clone with
// its TTL field replaced. Used on the cache-hit path so the TTL rewrite
// doesn't leak into the cached Msg that other concurrent hits are reading.
func cloneRRsWithTTL(src []dns.RR, ttl uint32) []dns.RR {
	if len(src) == 0 {
		return nil
	}
	out := make([]dns.RR, len(src))
	for i, rr := range src {
		c := rr.Clone()
		c.Header().TTL = ttl
		out[i] = c
	}
	return out
}

// cloneExtraWithTTL is like cloneRRsWithTTL but preserves the OPT pseudo-
// record's TTL (which encodes EDNS flags, not a cache lifetime).
func cloneExtraWithTTL(src []dns.RR, ttl uint32) []dns.RR {
	if len(src) == 0 {
		return nil
	}
	out := make([]dns.RR, len(src))
	for i, rr := range src {
		c := rr.Clone()
		if dns.RRToType(c) != dns.TypeOPT {
			c.Header().TTL = ttl
		}
		out[i] = c
	}
	return out
}

// pplogReport sends a query log entry if pplog is enabled.
func (h *miniHandler) pplogReport(qCtx *query_context.Context, route byte, rcode byte, durMs uint16, upstream string, resp *dns.Msg) {
	if h.pplogReporter == nil {
		return
	}
	q := qCtx.QQuestion()
	entry := &pplog.QueryEntry{
		ClientIP:  qCtx.ServerMeta.ClientAddr,
		QType:     q.Qtype,
		Rcode:     rcode,
		Route:     route,
		Duration:  durMs,
		QueryName: q.Name,
		Upstream:  upstream,
	}
	if resp != nil && h.pplogLevel >= 3 {
		entry.AnswerRRs = resp.Answer
	}
	if resp != nil && h.pplogLevel >= 4 {
		entry.ExtraRRs = resp.Extra
	}
	h.pplogReporter.Report(entry)
}

// resolveCNAMEChain follows the CNAME chain in answers starting from startName.
// Returns the final resolved name (the last CNAME target, or startName if no chain).
// The returned name is always lower-cased for comparison.
func resolveCNAMEChain(answers []dns.RR, startName string) string {
	current := strings.ToLower(startName)
	for range answers { // max iterations = len(answers), prevents infinite loops
		found := false
		for _, rr := range answers {
			if dns.RRToType(rr) == dns.TypeCNAME &&
				strings.EqualFold(rr.Header().Name, current) {
				current = strings.ToLower(rr.(*dns.CNAME).Target)
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	return current
}

func (h *miniHandler) applyLiteMode(r *dns.Msg, qtype uint16, qname string) {
	if r == nil {
		return
	}

	// If qtype is CNAME, no chain rewriting needed -- just filter normally
	if qtype == dns.TypeCNAME {
		// Keep only CNAME records (matching qtype)
		filteredAns := make([]dns.RR, 0, len(r.Answer))
		for _, rr := range r.Answer {
			if dns.RRToType(rr) == qtype {
				filteredAns = append(filteredAns, rr)
			}
		}
		r.Answer = filteredAns
		r.Ns = nil
		filteredExtra := make([]dns.RR, 0, len(r.Extra))
		for _, rr := range r.Extra {
			if dns.RRToType(rr) == dns.TypeOPT {
				filteredExtra = append(filteredExtra, rr)
			}
		}
		r.Extra = filteredExtra
		return
	}

	// Follow CNAME chain to find the final resolved name
	finalName := resolveCNAMEChain(r.Answer, qname)
	qnameLower := strings.ToLower(qname)

	// Check if chain actually resolved (finalName differs from qname means CNAMEs exist)
	// and that there are matching qtype records at the chain's end
	hasChain := finalName != qnameLower
	if hasChain {
		hasMatchingRecords := false
		for _, rr := range r.Answer {
			if dns.RRToType(rr) == qtype && strings.EqualFold(rr.Header().Name, finalName) {
				hasMatchingRecords = true
				break
			}
		}
		if !hasMatchingRecords {
			// Can't validate the chain end -- fall back to no filtering for compatibility
			return
		}
	}

	filteredAns := make([]dns.RR, 0, len(r.Answer))
	for _, rr := range r.Answer {
		if dns.RRToType(rr) == qtype {
			if hasChain {
				// Only keep records belonging to the CNAME chain's final target
				if !strings.EqualFold(rr.Header().Name, finalName) {
					continue // skip records not in the chain
				}
				rr.Header().Name = qname
			}
			filteredAns = append(filteredAns, rr)
		}
	}
	r.Answer = filteredAns
	r.Ns = nil
	filteredExtra := make([]dns.RR, 0, len(r.Extra))
	for _, rr := range r.Extra {
		if dns.RRToType(rr) == dns.TypeOPT {
			filteredExtra = append(filteredExtra, rr)
		}
	}
	r.Extra = filteredExtra
}

func (h *miniHandler) process(ctx context.Context, qCtx *query_context.Context) error {
	q := qCtx.QQuestion()

	// Reject AAAA, SVCB, HTTPS queries
	if q.Qtype == dns.TypeSVCB || q.Qtype == dns.TypeHTTPS || (h.aaaaMode == "no" && q.Qtype == dns.TypeAAAA) {
		if h.aaaaMode == "no" && q.Qtype == dns.TypeAAAA {
			logQuery(h.logger, &queryLog{
				route:  "block",
				client: qCtx.ServerMeta.ClientAddr,
				qtype:  q.Qtype,
				domain: q.Name,
				rcode:  "BLOCKED",
			})
		}
		r := new(dns.Msg)
		dnsutil.SetReply(r, qCtx.Q())
		r.Rcode = dns.RcodeSuccess
		qCtx.SetResponse(r)
		return nil
	}

	// Forward lookup from hosts files and [hosts] config
	if (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA) && h.ptrResolver != nil {
		if ips := h.ptrResolver.LookupIP(q.Name); len(ips) > 0 {
			r := new(dns.Msg)
			dnsutil.SetReply(r, qCtx.Q())
			r.Rcode = dns.RcodeSuccess
			for _, ip := range ips {
				if q.Qtype == dns.TypeA && ip.To4() != nil {
					addr, _ := netip.AddrFromSlice(ip.To4())
					r.Answer = append(r.Answer, &dns.A{
						Hdr: dns.Header{Name: q.Name, Class: dns.ClassINET, TTL: 300},
						A:   rdata.A{Addr: addr},
					})
				} else if q.Qtype == dns.TypeAAAA && ip.To4() == nil && ip.To16() != nil {
					addr, _ := netip.AddrFromSlice(ip.To16())
					r.Answer = append(r.Answer, &dns.AAAA{
						Hdr:  dns.Header{Name: q.Name, Class: dns.ClassINET, TTL: 300},
						AAAA: rdata.AAAA{Addr: addr},
					})
				}
			}
			if len(r.Answer) > 0 {
				qCtx.SetResponse(r)
				logQuery(h.logger, &queryLog{
					route:  "hosts",
					client: qCtx.ServerMeta.ClientAddr,
					qtype:  q.Qtype,
					domain: q.Name,
					rcode:  "NOERROR",
				})
				h.pplogReport(qCtx, pplog.RouteHosts, byte(dns.RcodeSuccess), 0, "hosts", r)
				return nil
			}
		}
	}

	// Local PTR resolution from lease/hosts files
	if q.Qtype == dns.TypePTR && h.ptrResolver != nil {
		if hostname := h.ptrResolver.Lookup(q.Name); hostname != "" {
			r := new(dns.Msg)
			dnsutil.SetReply(r, qCtx.Q())
			r.Rcode = dns.RcodeSuccess
			ptrRR := &dns.PTR{
				Hdr: dns.Header{
					Name:  q.Name,
					Class: dns.ClassINET,
					TTL:   300,
				},
				PTR: rdata.PTR{Ptr: dnsutil.Fqdn(hostname)},
			}
			r.Answer = []dns.RR{ptrRR}
			qCtx.SetResponse(r)
			logQuery(h.logger, &queryLog{
				route:  "local-ptr",
				client: qCtx.ServerMeta.ClientAddr,
				qtype:  q.Qtype,
				domain: q.Name,
				rcode:  "NOERROR",
				extra:  hostname,
			})
			h.pplogReport(qCtx, pplog.RouteHosts, byte(dns.RcodeSuccess), 0, "local-ptr", r)
			return nil
		}
		// bogus-priv: private PTR not found locally -> NXDOMAIN, don't forward upstream
		if h.bogusPriv && isPrivatePTR(q.Name) {
			r := new(dns.Msg)
			dnsutil.SetReply(r, qCtx.Q())
			r.Rcode = dns.RcodeNameError
			qCtx.SetResponse(r)
			logQuery(h.logger, &queryLog{
				route:  "bogus-priv",
				client: qCtx.ServerMeta.ClientAddr,
				qtype:  q.Qtype,
				domain: q.Name,
				rcode:  "NXDOMAIN",
			})
			h.pplogReport(qCtx, pplog.RouteHosts, byte(dns.RcodeNameError), 0, "bogus-priv", r)
			return nil
		}
	}
	// bogus-priv without ptrResolver: still block private PTR from going upstream
	if q.Qtype == dns.TypePTR && h.bogusPriv && h.ptrResolver == nil && isPrivatePTR(q.Name) {
		r := new(dns.Msg)
		dnsutil.SetReply(r, qCtx.Q())
		r.Rcode = dns.RcodeNameError
		qCtx.SetResponse(r)
		h.logger.Debugw("bogus-priv",
			mlog.Stringer("client", qCtx.ServerMeta.ClientAddr),
			mlog.String("qtype", dns.TypeToString[q.Qtype]),
			mlog.String("domain", q.Name),
			mlog.String("rcode", "NXDOMAIN"))
		h.pplogReport(qCtx, pplog.RouteHosts, byte(dns.RcodeNameError), 0, "bogus-priv", r)
		return nil
	}

	// Determine route for logging
	forceFall := false
	if h.forceFallMatcher != nil {
		forceFall = h.forceFallMatcher.Match(qCtx.ServerMeta.ClientAddr)
	}

	hookDown := false
	if h.hookFailed != nil && h.hookFailed.Load() {
		hookDown = true
		forceFall = true
	}

	// paopao.dns: always use primary DNS unless hosts already handled it
	if forceFall && isPaopaoDNS(q.Name) {
		forceFall = false
		hookDown = false
	}

	// Route label used for the fall-path log line and pplog route byte.
	fallRoute := "fall"
	fallRouteByte := pplog.RouteFall
	if forceFall {
		if hookDown {
			fallRoute = "hook_fall"
			fallRouteByte = pplog.RouteHookFall
		} else {
			fallRoute = "force_fall"
			fallRouteByte = pplog.RouteForceFall
		}
	}

	// 2. Cache
	// DNS names are case-insensitive; normalize so Example.COM and example.com share a cache entry.
	cacheKey := CacheKey{Name: strings.ToLower(q.Name), Qtype: q.Qtype, Qclass: q.Qclass}
	if cachedMsg, expTime, ok := h.dnsCache.Get(cacheKey); ok && cachedMsg != nil {
		// TOCTOU: cache.Get checked expiration, but the entry may have just
		// expired. time.Until can be negative — convert via int64 first so the
		// uint32 cast doesn't wrap to ~136 years.
		secsLeft := int64(time.Until(expTime) / time.Second)
		ttlLeft := uint32(1)
		if secsLeft > 1 {
			ttlLeft = uint32(secsLeft)
		}

		// codeberg.org/miekg/dns Msg.Copy is a shallow copy: RRs are shared
		// by pointer and slice headers point into the same backing arrays.
		// Deep-clone each RR into a fresh slice so the TTL rewrite below and
		// the downstream shuffleAnswers cannot mutate the cached entry (which
		// concurrent hits may be reading). Question/Pseudo/Data are treated
		// as immutable after Store and shared by reference.
		resp := &dns.Msg{
			MsgHeader: cachedMsg.MsgHeader,
			Question:  cachedMsg.Question,
			Pseudo:    cachedMsg.Pseudo,
			Data:      cachedMsg.Data,
			Answer:    cloneRRsWithTTL(cachedMsg.Answer, ttlLeft),
			Ns:        cloneRRsWithTTL(cachedMsg.Ns, ttlLeft),
			Extra:     cloneExtraWithTTL(cachedMsg.Extra, ttlLeft),
		}
		resp.ID = qCtx.Q().ID

		qCtx.SetResponse(resp)
		rcodeLabel := "NOERROR"
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 {
			rcodeLabel = "NODATA"
		} else if resp.Rcode != dns.RcodeSuccess {
			rcodeLabel = dns.RcodeToString[resp.Rcode]
		}
		logQuery(h.logger, &queryLog{
			route:  "cache",
			client: qCtx.ServerMeta.ClientAddr,
			qtype:  q.Qtype,
			domain: q.Name,
			rcode:  rcodeLabel,
		})
		h.pplogReport(qCtx, pplog.RouteCache, byte(resp.Rcode), 0, "", resp)
		return nil
	}

	var r *dns.Msg
	var upstreamUsed string
	var queryDur time.Duration
	var execErr error
	var localNoData *dns.Msg // saved localForward NODATA result

	// 3. Main sequence
	if !forceFall {
		r, upstreamUsed, queryDur, execErr = h.localForward.Exec(ctx, qCtx)
		if upstreamUsed == "" {
			upstreamUsed = "timeout/err"
		}
		if execErr == nil && r != nil {
			if h.lite {
				h.applyLiteMode(r, q.Qtype, q.Name)
			}
			// trust_rcode: if the main DNS rcode is in the trusted set, accept the
			// response directly (even without answer records) and skip fallback.
			if len(h.trustRcodes) > 0 && h.trustRcodes[int(r.Rcode)] {
				qCtx.SetResponse(r)
				ttl := dnsutils.GetMinimalTTL(r)
				if ttl == 0 {
					ttl = 1
				}
				h.dnsCache.Store(cacheKey, cacheSnapshot(r), time.Now().Add(time.Duration(ttl)*time.Second))
				rcodeLabel := dns.RcodeToString[r.Rcode]
				if len(r.Answer) == 0 {
					rcodeLabel += "(trusted)"
				}
				logLocalQuery(h.logger, qCtx.ServerMeta.ClientAddr, upstreamUsed, q.Qtype, q.Name, rcodeLabel, queryDur, nil)
				rcodeByte := byte(r.Rcode)
				if r.Rcode == dns.RcodeSuccess && len(r.Answer) == 0 {
					rcodeByte = pplog.RcodeNoData
				}
				h.pplogReport(qCtx, pplog.RouteLocal, rcodeByte, durToMs(queryDur), upstreamUsed, r)
				return nil
			}
			if r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
				qCtx.SetResponse(r)
				ttl := dnsutils.GetMinimalTTL(r)
				if ttl > 0 {
					h.dnsCache.Store(cacheKey, cacheSnapshot(r), time.Now().Add(time.Duration(ttl)*time.Second))
				}
				logLocalQuery(h.logger, qCtx.ServerMeta.ClientAddr, upstreamUsed, q.Qtype, q.Name, "NOERROR", queryDur, nil)
				h.pplogReport(qCtx, pplog.RouteLocal, byte(r.Rcode), durToMs(queryDur), upstreamUsed, r)
				return nil
			} else if r.Rcode == dns.RcodeSuccess && len(r.Answer) == 0 {
				// aaaa=noerror: trust the NOERROR+empty answer from main DNS directly,
				// skip fallback. Cache with original TTL (or TTL=1 if no NS record TTL).
				if h.aaaaMode == "noerror" && q.Qtype == dns.TypeAAAA {
					qCtx.SetResponse(r)
					ttl := dnsutils.GetMinimalTTL(r)
					if ttl == 0 {
						ttl = 1
					}
					h.dnsCache.Store(cacheKey, cacheSnapshot(r), time.Now().Add(time.Duration(ttl)*time.Second))
					logLocalQuery(h.logger, qCtx.ServerMeta.ClientAddr, upstreamUsed, q.Qtype, q.Name, "NODATA(trusted)", queryDur, nil)
					h.pplogReport(qCtx, pplog.RouteLocal, pplog.RcodeNoData, durToMs(queryDur), upstreamUsed, r)
					return nil
				}
				logLocalQuery(h.logger, qCtx.ServerMeta.ClientAddr, upstreamUsed, q.Qtype, q.Name, "NODATA", queryDur, nil)
				h.pplogReport(qCtx, pplog.RouteLocal, pplog.RcodeNoData, durToMs(queryDur), upstreamUsed, r)
				localNoData = r // save NODATA result for possible later use
			} else {
				logLocalQuery(h.logger, qCtx.ServerMeta.ClientAddr, upstreamUsed, q.Qtype, q.Name, dns.RcodeToString[r.Rcode], queryDur, nil)
				h.pplogReport(qCtx, pplog.RouteLocal, byte(r.Rcode), durToMs(queryDur), upstreamUsed, r)
			}
		} else {
			logLocalQuery(h.logger, qCtx.ServerMeta.ClientAddr, upstreamUsed, q.Qtype, q.Name, "timeout/error", queryDur, execErr)
			h.pplogReport(qCtx, pplog.RouteLocal, pplog.RcodeTimeout, durToMs(queryDur), upstreamUsed, nil)
		}
	}

	// 4. Fallback execution
	rFall, upFall, durFall, errFall := h.cnForward.Exec(ctx, qCtx)
	if upFall == "" {
		upFall = "timeout/err"
	}

	fallIsNoData := rFall != nil && rFall.Rcode == dns.RcodeSuccess && len(rFall.Answer) == 0

	// If both local and fall returned NODATA, prefer localForward result
	// (it may contain useful SOA/CNAME records with original TTL)
	if localNoData != nil && (fallIsNoData || rFall == nil) {
		if h.lite {
			h.applyLiteMode(localNoData, q.Qtype, q.Name)
		}
		qCtx.SetResponse(localNoData)
		ttl := dnsutils.GetMinimalTTL(localNoData)
		if ttl > 0 {
			h.dnsCache.Store(cacheKey, cacheSnapshot(localNoData), time.Now().Add(time.Duration(ttl)*time.Second))
		}
	} else if rFall != nil {
		if h.lite {
			h.applyLiteMode(rFall, q.Qtype, q.Name)
		}
		qCtx.SetResponse(rFall)
		// TTL=1: fallback results are short-lived to allow fast switch back
		// to main DNS once the hook monitor detects recovery.
		for _, ans := range qCtx.R().Answer {
			ans.Header().TTL = fallbackTTL
		}
		for _, ns := range qCtx.R().Ns {
			ns.Header().TTL = fallbackTTL
		}
		for _, ext := range qCtx.R().Extra {
			if dns.RRToType(ext) != dns.TypeOPT {
				ext.Header().TTL = fallbackTTL
			}
		}
		ttl := dnsutils.GetMinimalTTL(qCtx.R())
		if ttl > 0 {
			h.dnsCache.Store(cacheKey, cacheSnapshot(qCtx.R()), time.Now().Add(time.Duration(ttl)*time.Second))
		}
	} else if errFall != nil {
		// Log error
	}

	switch {
	case rFall == nil && errFall != nil:
		// Fallback itself failed (timeout / network error). Do not mask this
		// as NODATA even if local previously returned NODATA — ops needs to
		// see that the fallback upstream is unhealthy.
		logFallQuery(h.logger, fallRoute, qCtx.ServerMeta.ClientAddr, upFall, q.Qtype, q.Name, "timeout/error", durFall, errFall)
	case localNoData != nil && (fallIsNoData || rFall == nil):
		logFallQuery(h.logger, fallRoute, qCtx.ServerMeta.ClientAddr, upFall, q.Qtype, q.Name, "NODATA", durFall, nil)
	default:
		rcodeStr := "NXDOMAIN or timeout"
		if rFall != nil {
			rcodeStr = dns.RcodeToString[rFall.Rcode]
		}
		logFallQuery(h.logger, fallRoute, qCtx.ServerMeta.ClientAddr, upFall, q.Qtype, q.Name, rcodeStr, durFall, nil)
	}
	if rFall != nil {
		rcodeByteFall := byte(rFall.Rcode)
		if fallIsNoData {
			rcodeByteFall = pplog.RcodeNoData
		}
		h.pplogReport(qCtx, fallRouteByte, rcodeByteFall, durToMs(durFall), upFall, rFall)
	} else {
		h.pplogReport(qCtx, fallRouteByte, pplog.RcodeTimeout, durToMs(durFall), upFall, nil)
	}

	return nil
}

// durToMs clamps a duration's millisecond value to uint16 range so
// pplog entries cannot silently truncate on slow queries.
func durToMs(d time.Duration) uint16 {
	ms := d.Milliseconds()
	if ms < 0 {
		return 0
	}
	if ms > 0xFFFF {
		return 0xFFFF
	}
	return uint16(ms)
}

// isPaopaoDNS returns true if the domain is exactly "paopao.dns.".
func isPaopaoDNS(name string) bool {
	return strings.EqualFold(name, "paopao.dns.")
}
