package main

import (
	"context"
	crand "crypto/rand"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/cache"
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

// randPool hands out independently-seeded ChaCha8 generators so upstream
// shuffle and answer shuffle don't contend on math/rand/v2's global source
// lock under high QPS. Each caller Gets a *rand.Rand, uses it lock-free, and
// Puts it back.
var randPool = sync.Pool{
	New: func() any {
		var seed [32]byte
		_, _ = crand.Read(seed[:])
		return rand.New(rand.NewChaCha8(seed))
	},
}

// randPoolWarmup is the number of generators seeded at startup. A cold
// sync.Pool would otherwise force every concurrent request in the first
// burst through crand.Read + ChaCha8 setup on the Get path; pre-filling
// shifts that work off the hot path and keeps the initial flood lock-free.
const randPoolWarmup = 16

func init() {
	for i := 0; i < randPoolWarmup; i++ {
		randPool.Put(randPool.New())
	}
}

func getRand() *rand.Rand  { return randPool.Get().(*rand.Rand) }
func putRand(r *rand.Rand) { randPool.Put(r) }

type CacheKey struct {
	Name   string
	Qtype  uint16
	Qclass uint16
}

func (k CacheKey) Sum() uint64 {
	// FNV-1a body, plus a SplitMix64 finalization. The shard picker in
	// concurrent_map uses `Sum() % 32`, i.e. only the low 5 bits — and
	// FNV-1a's low bits aren't fully avalanched, especially on DNS
	// inputs where Qclass is effectively a constant (IN=1) and shared
	// suffixes (.com.) push the divergence to the front of the hash.
	// The finalization step is two muls and three xor-shifts: it costs
	// ~5 ns once per cache lookup and lifts the bottom bits to good
	// distribution without changing the hash interface.
	var hash uint64 = 14695981039346656037
	for i := 0; i < len(k.Name); i++ {
		hash ^= uint64(k.Name[i])
		hash *= 1099511628211
	}
	hash ^= uint64(k.Qtype)
	hash *= 1099511628211
	hash ^= uint64(k.Qclass)
	hash *= 1099511628211
	hash ^= hash >> 30
	hash *= 0xbf58476d1ce4e5b9
	hash ^= hash >> 27
	hash *= 0x94d049bb133111eb
	hash ^= hash >> 31
	return hash
}

// setReply initializes r as a reply to q. It mirrors dnsutil.SetReply but
// also propagates the EDNS0 advertised UDP size so the wire-format
// response carries an OPT pseudo-record whenever the query did. Per RFC
// 6891 §6.1.1 a server MUST include OPT in responses to queries that
// carried OPT; dnsutil.SetReply only copies the DO/CD/RD bits, leaving
// UDPSize at zero — which suppresses OPT generation in Msg.Pack and can
// trip strict validators or DNSSEC-aware clients on the static-rewrite
// fast paths (AAAA/SVCB/HTTPS block, hosts/local-PTR hits, bogus-priv
// NXDOMAIN, FORMERR, SERVFAIL synthesis).
func setReply(r, q *dns.Msg) {
	dnsutil.SetReply(r, q)
	r.UDPSize = q.UDPSize
}

// lowerASCIIName returns a lower-cased copy of a DNS name, skipping the
// copy entirely when the input is already lowercase. strings.ToLower
// already short-circuits all-lowercase input, so the fast-path here
// mostly saves the scan + branch inside stdlib on the dominant case.
// DNS names only contain ASCII per RFC 1035, so a byte-wise lower is
// correct and avoids the Unicode mapping cost of strings.ToLower.
func lowerASCIIName(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			// Slow path: at least one uppercase byte. Build a lower
			// copy. Using a stack buffer up to 255 (DNS max name
			// length) keeps this allocation-free for all legal
			// domains; overlong inputs fall through to a heap slice.
			var stackBuf [255]byte
			n := len(s)
			if n <= len(stackBuf) {
				copy(stackBuf[:n], s[:i])
				for j := i; j < n; j++ {
					b := s[j]
					if b >= 'A' && b <= 'Z' {
						b += 'a' - 'A'
					}
					stackBuf[j] = b
				}
				return string(stackBuf[:n])
			}
			buf := make([]byte, n)
			copy(buf, s[:i])
			for j := i; j < n; j++ {
				b := s[j]
				if b >= 'A' && b <= 'Z' {
					b += 'a' - 'A'
				}
				buf[j] = b
			}
			return string(buf)
		}
	}
	return s
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
	blockSVCB        bool         // block SVCB/HTTPS queries to prevent DNS split bypass
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

	// execCtx is the cancellation fan-out: once Exec commits to a response we
	// cancel execCtx so pending ExchangeContext calls abort immediately
	// instead of running to their own f.qtime. Derive per-call upstream
	// contexts from it.
	execCtx, cancel := context.WithCancel(ctx)

	// resChan is sized exactly for concurrent sends (one per goroutine) so
	// sends never block a producer — the main loop can leave early while
	// in-flight goroutines finish cleanly.
	resChan := make(chan res, concurrent)
	var wg sync.WaitGroup

	// Cleanup ordering (defers pop LIFO): cancel() first to wake blocked
	// ExchangeContext calls, then wg.Wait() so every goroutine's deferred
	// pool.ReleaseBuf completes before Exec returns. Without the wait, a
	// caller that grabs a buffer from pool.GetBuf right after Exec returns
	// can race the in-flight release and observe a fresh buffer — this was
	// the root cause of the TestMiniForwarderUnpackPanicReleasesBuf flakes.
	defer wg.Wait()
	defer cancel()

	start := time.Now()

	var indices [maxUpstreams]int
	for i := 0; i < n; i++ {
		indices[i] = i
	}
	rng := getRand()
	for i := 0; i < concurrent; i++ {
		j := i + rng.IntN(n-i)
		indices[i], indices[j] = indices[j], indices[i]
	}
	putRand(rng)
	for c := 0; c < concurrent; c++ {
		idx := indices[c]
		u := f.upstreams[idx]
		// upstreams and addresses are appended in lockstep at construction
		// (main.go), so indexing is symmetric — no length divergence to guard.
		addr := f.addresses[idx]
		// Size the per-goroutine copy by len, not cap: queryPayload comes
		// from pool.PackBuffer which returns a 64 KiB-backed slice
		// regardless of message length. Asking for cap returned a 64 KiB
		// pool bucket per concurrent goroutine to hold a ~50-byte query —
		// 192 KiB wasted per request at default concurrency=3. Sizing by
		// len lets pool.GetBuf pick a tight 64- or 128-byte bucket.
		qc := func(b *[]byte) *[]byte {
			n := len(*b)
			c := pool.GetBuf(n)
			*c = (*c)[:n]
			copy(*c, *b)
			return c
		}(queryPayload)

		wg.Add(1)
		go func(up upstream.Upstream, upAddr string) {
			defer wg.Done()
			defer pool.ReleaseBuf(qc)
			// Recover from upstream panics (nil-deref in transport layers,
			// miekg/dns decode edge cases) and funnel them into resChan as a
			// normal error. A single bad response should never crash the
			// resolver process. Select-default guards the pathological case
			// where a late defer panics after the normal send has already
			// filled the channel slot for this goroutine.
			defer func() {
				if rec := recover(); rec != nil {
					if f.logger != nil {
						f.logger.Errorw("upstream exchange panic",
							mlog.String("upstream", upAddr),
							mlog.String("recover", fmt.Sprintf("%v", rec)))
					}
					select {
					case resChan <- res{
						err:      fmt.Errorf("upstream panic: %v", rec),
						upstream: upAddr,
						duration: time.Since(start),
					}:
					default:
					}
				}
			}()
			upstreamCtx, uCancel := context.WithTimeout(execCtx, f.qtime)
			defer uCancel()

			var r *dns.Msg
			respPayload, err := up.ExchangeContext(upstreamCtx, *qc)
			dur := time.Since(start)
			if err == nil {
				// Defer the release so a panic inside r.Unpack (miekg/dns
				// can panic on sufficiently pathological wire data) is caught
				// by the outer recover() without leaking the pooled buffer.
				// Defers run at goroutine exit — after recover — so cleanup
				// is guaranteed on both the success and panic paths.
				defer pool.ReleaseBuf(respPayload)
				r = new(dns.Msg)
				r.Data = *respPayload
				err = r.Unpack()
				// Clear r.Data before the deferred release so r does not hold
				// a dangling pointer into a reusable slice.
				r.Data = nil
				if err != nil {
					r = nil
				}
			}
			// Channel capacity equals goroutine count and each goroutine
			// sends at most once on this path, so the send never blocks.
			resChan <- res{r: r, err: err, upstream: upAddr, duration: dur}
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
		setReply(r, q)
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
			setReply(r, q)
			r.Rcode = dns.RcodeServerFailure
			qCtx.SetResponse(r)
		}
	} else if qCtx.R() == nil {
		// Empty response
		r := new(dns.Msg)
		setReply(r, q)
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
		// Fall back to a synthesized SERVFAIL so the client gets an
		// explicit error code instead of timing out. If even SERVFAIL
		// fails to pack — implausible for a header-only message — there
		// is nothing useful left to send.
		sf := new(dns.Msg)
		setReply(sf, q)
		sf.Rcode = dns.RcodeServerFailure
		sfPayload, sfErr := packMsgPayload(sf)
		if sfErr != nil {
			h.logger.Warnw("failed to pack SERVFAIL fallback", mlog.Err(sfErr))
			return nil
		}
		return sfPayload
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
	rng := getRand()
	rng.Shuffle(len(qtypeSlice), func(i, j int) {
		qtypeSlice[i], qtypeSlice[j] = qtypeSlice[j], qtypeSlice[i]
	})
	putRand(rng)
}

// partitionStackLimit is the largest answer-set size we can partition
// without a heap allocation. DNS responses almost always fit in this
// budget — larger ones fall back to a heap slice.
const partitionStackLimit = 16

// stablePartitionRR moves elements satisfying pred to the front of s,
// preserving relative order. Returns the count of matching elements.
// Runs in O(n) time. For the common case (n ≤ partitionStackLimit) the
// scratch buffer lives on the stack so the partition allocates nothing.
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
	var stackBuf [partitionStackLimit]dns.RR
	var tmp []dns.RR
	if n <= partitionStackLimit {
		tmp = stackBuf[:n]
	} else {
		tmp = make([]dns.RR, n)
	}
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

// cacheSnapshot prepares a Msg for storage in the DNS cache and returns
// the minimum non-OPT TTL across all sections in the same pass — folding
// the GetMinimalTTL scan into the slice copy avoids re-walking Answer/Ns/
// Extra at every Store call site (5 of them in this file). Caller still
// applies the same "0 means no records / use a default" semantics as the
// standalone helper.
//
// Answer/Ns/Extra/Pseudo are copied into fresh backing arrays so downstream
// in-place operations — notably shuffleAnswers in Handle — cannot reach
// back into cached entries. RR pointers themselves are shared: RRs are
// treated as immutable once stored (applyLiteMode already finished;
// fall-path TTL rewrites happen before the call reaches here), and the
// Load path deep-clones via cloneRRsWithTTL before the only remaining
// mutation site (the cache-hit TTL rewrite), so the sharing never becomes
// observable. This replaces the library's Msg.Copy, which is explicitly a
// shallow copy and would let shuffleAnswers reorder the cached slice and
// let Load-side TTL rewrites pollute cached RR headers.
//
// Pseudo (the EDNS0 virtual section) is also detached: the codeberg dns
// fork makes Pseudo a []RR distinct from Extra's OPT, and a shared slice
// would let any future mutation on the response (e.g. EDNS option append)
// race against concurrent cache hits.
//
// Data is intentionally NOT carried over: it points at a pooled wire-format
// buffer that the caller releases after Unpack, and a stale slice header in
// the cached Msg would be a use-after-free waiting to surface. Cached entries
// are re-packed on the Load path anyway.
func cacheSnapshot(r *dns.Msg) (*dns.Msg, uint32) {
	if r == nil {
		return nil, 0
	}
	snap := &dns.Msg{
		MsgHeader: r.MsgHeader,
	}
	var (
		minTTL   uint32
		ttlFound bool
	)
	track := func(rr dns.RR) {
		// Defensive: a malformed upstream response could in principle
		// land a nil entry in a section. Skipping silently keeps the
		// cache write going for the well-formed RRs around it instead
		// of letting a panic tear down the resolve path.
		if rr == nil {
			return
		}
		if dns.RRToType(rr) == dns.TypeOPT {
			return
		}
		t := rr.Header().TTL
		if !ttlFound || t < minTTL {
			minTTL = t
			ttlFound = true
		}
	}
	// Question is intentionally not copied: tryCacheHit always overwrites
	// the response's Question slice with the live query's Question (to echo
	// the client's exact case per RFC 1035 §3.1 and detach from the cached
	// entry). Storing a copy here would be a pure waste.
	if n := len(r.Answer); n > 0 {
		snap.Answer = append(make([]dns.RR, 0, n), r.Answer...)
		for _, rr := range snap.Answer {
			track(rr)
		}
	}
	if n := len(r.Ns); n > 0 {
		snap.Ns = append(make([]dns.RR, 0, n), r.Ns...)
		for _, rr := range snap.Ns {
			track(rr)
		}
	}
	if n := len(r.Extra); n > 0 {
		snap.Extra = append(make([]dns.RR, 0, n), r.Extra...)
		for _, rr := range snap.Extra {
			track(rr)
		}
	}
	if n := len(r.Pseudo); n > 0 {
		snap.Pseudo = append(make([]dns.RR, 0, n), r.Pseudo...)
	}
	return snap, minTTL
}

// cloneRRsWithTTL returns a new slice where every RR is a deep clone with
// its TTL field replaced. Used on the cache-hit path so the TTL rewrite
// doesn't leak into the cached Msg that other concurrent hits are reading.
// nil entries in src are skipped rather than panicking on rr.Clone().
func cloneRRsWithTTL(src []dns.RR, ttl uint32) []dns.RR {
	if len(src) == 0 {
		return nil
	}
	out := make([]dns.RR, 0, len(src))
	for _, rr := range src {
		if rr == nil {
			continue
		}
		c := rr.Clone()
		c.Header().TTL = ttl
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// cloneExtraWithTTL is like cloneRRsWithTTL but preserves the OPT pseudo-
// record's TTL (which encodes EDNS flags, not a cache lifetime). nil
// entries are skipped to keep the function tolerant of malformed cached
// Extra slices — matches cloneRRsWithTTL's contract.
func cloneExtraWithTTL(src []dns.RR, ttl uint32) []dns.RR {
	if len(src) == 0 {
		return nil
	}
	out := make([]dns.RR, 0, len(src))
	for _, rr := range src {
		if rr == nil {
			continue
		}
		c := rr.Clone()
		if dns.RRToType(c) != dns.TypeOPT {
			c.Header().TTL = ttl
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil
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
	current := lowerASCIIName(startName)
	for range answers { // max iterations = len(answers), prevents infinite loops
		found := false
		for _, rr := range answers {
			if dns.RRToType(rr) == dns.TypeCNAME &&
				strings.EqualFold(rr.Header().Name, current) {
				current = lowerASCIIName(rr.(*dns.CNAME).Target)
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

// keepOPTOnly compacts r.Extra in place to keep only the OPT pseudo-record.
// Reuses the source backing array — applyLiteMode runs on a freshly-decoded
// upstream response that nobody else aliases, so shrinking the slice header
// is safe and avoids the per-query allocation of a `make([]dns.RR, 0, len)`
// destination slice.
func keepOPTOnly(s []dns.RR) []dns.RR {
	out := s[:0]
	for _, rr := range s {
		if dns.RRToType(rr) == dns.TypeOPT {
			out = append(out, rr)
		}
	}
	return out
}

func (h *miniHandler) applyLiteMode(r *dns.Msg, qtype uint16, qname string) {
	if r == nil {
		return
	}

	// If qtype is CNAME, no chain rewriting needed -- just filter normally.
	// Filter in place: r.Answer / r.Extra come from a freshly-decoded upstream
	// Msg whose backing arrays nobody else aliases, so shrinking the slice
	// is safe and skips the per-query make() that the previous code paid
	// even when Answer/Extra were already small.
	if qtype == dns.TypeCNAME {
		ans := r.Answer[:0]
		for _, rr := range r.Answer {
			if dns.RRToType(rr) == qtype {
				ans = append(ans, rr)
			}
		}
		r.Answer = ans
		r.Ns = filterSOA(r.Ns)
		r.Extra = keepOPTOnly(r.Extra)
		return
	}

	// Follow CNAME chain to find the final resolved name
	finalName := resolveCNAMEChain(r.Answer, qname)
	qnameLower := lowerASCIIName(qname)

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

	ans := r.Answer[:0]
	for _, rr := range r.Answer {
		if dns.RRToType(rr) == qtype {
			if hasChain {
				// Only keep records belonging to the CNAME chain's final target
				if !strings.EqualFold(rr.Header().Name, finalName) {
					continue // skip records not in the chain
				}
				// Clone before rewriting Name. cacheSnapshot copies only the
				// slice header — RR pointers stay shared with whatever
				// cacheSnapshot is about to store. Mutating rr.Header().Name
				// in place would (a) write through to the upstream-decoded
				// Msg the caller still holds and (b) bake the current query's
				// case into the cached RR, so subsequent cache hits for the
				// same name in different case would echo the first caller's
				// case in the Answer section. cacheSnapshot's contract says
				// RRs are immutable once stored; preserve that here.
				cloned := rr.Clone()
				cloned.Header().Name = qname
				ans = append(ans, cloned)
				continue
			}
			ans = append(ans, rr)
		}
	}
	r.Answer = ans
	r.Ns = filterSOA(r.Ns)
	r.Extra = keepOPTOnly(r.Extra)
}

// filterSOA returns the subset of ns containing only SOA records, in a
// fresh slice so callers can replace ns without aliasing into the
// original (possibly cached) backing array.
//
// Lite mode previously cleared Ns wholesale, which stripped the SOA from
// NXDOMAIN/NODATA responses — clients lose RFC 2308 negative-cache TTLs
// and DNSSEC validators lose authority chain proof. SOA is small and
// non-redundant; keeping just it preserves protocol conformance while
// dropping the rest of the typical "thin response" noise.
func filterSOA(ns []dns.RR) []dns.RR {
	if len(ns) == 0 {
		return nil
	}
	var out []dns.RR
	for _, rr := range ns {
		if dns.RRToType(rr) == dns.TypeSOA {
			if out == nil {
				out = make([]dns.RR, 0, 1)
			}
			out = append(out, rr)
		}
	}
	return out
}

// requestRoute captures the routing decision for a single query:
// whether the main DNS is bypassed in favor of the fallback, and which
// label should appear in the fall-path log line / pplog route byte.
type requestRoute struct {
	forceFall     bool
	fallRoute     string
	fallRouteByte byte
}

func (h *miniHandler) process(ctx context.Context, qCtx *query_context.Context) error {
	if h.tryStaticRewrite(qCtx) {
		return nil
	}
	route := h.resolveRoute(qCtx)
	q := qCtx.QQuestion()
	// DNS names are case-insensitive; normalize so Example.COM and example.com share a cache entry.
	cacheKey := CacheKey{Name: lowerASCIIName(q.Name), Qtype: q.Qtype, Qclass: q.Qclass}
	// forceFall clients must not observe (or pollute) the shared cache: the
	// cache key has no route dimension, so a main-DNS NOERROR cached by a
	// normal client would leak straight through to a force_fall client and
	// silently bypass the fallback routing policy. Skipping tryCacheHit here,
	// and tryCacheStore on the write side inside execFallbackAndFinalize,
	// keeps force_fall queries fully on the fallback path.
	if !route.forceFall && h.tryCacheHit(qCtx, cacheKey) {
		return nil
	}
	localResp, localNoData, handled := h.execLocal(ctx, qCtx, route, cacheKey)
	if handled {
		return nil
	}
	h.execFallbackAndFinalize(ctx, qCtx, route, cacheKey, localResp, localNoData)
	return nil
}

// tryStaticRewrite answers queries that need no upstream dialing: AAAA
// blocks, SVCB/HTTPS rejection, hosts-file lookups, local PTR, and
// bogus-priv. Returns true when the response has been written to qCtx.
func (h *miniHandler) tryStaticRewrite(qCtx *query_context.Context) bool {
	q := qCtx.QQuestion()

	// Reject AAAA, SVCB, HTTPS queries
	if (h.blockSVCB && (q.Qtype == dns.TypeSVCB || q.Qtype == dns.TypeHTTPS)) || (h.aaaaMode == "no" && q.Qtype == dns.TypeAAAA) {
		// Pick a route label so debug logs and pplog telemetry line up with
		// the hosts/local-ptr/bogus-priv paths instead of disappearing
		// silently. SVCB and HTTPS were previously logged nowhere, and the
		// AAAA block had a debug log but no pplog entry.
		var routeLabel, upstreamLabel string
		switch q.Qtype {
		case dns.TypeSVCB:
			routeLabel = "block-svcb"
			upstreamLabel = "block-svcb"
		case dns.TypeHTTPS:
			routeLabel = "block-https"
			upstreamLabel = "block-https"
		default: // AAAA block
			routeLabel = "block"
			upstreamLabel = "block-aaaa"
		}
		logQuery(h.logger, &queryLog{
			route:  routeLabel,
			client: qCtx.ServerMeta.ClientAddr,
			qtype:  q.Qtype,
			domain: q.Name,
			rcode:  "BLOCKED",
		})
		r := new(dns.Msg)
		setReply(r, qCtx.Q())
		r.Rcode = dns.RcodeSuccess
		qCtx.SetResponse(r)
		// Empty NOERROR is reported as RcodeNoData (matches execLocal's
		// NODATA path), routed under RouteHosts since this is a local
		// static decision.
		h.pplogReport(qCtx, pplog.RouteHosts, pplog.RcodeNoData, 0, upstreamLabel, r)
		return true
	}

	// Forward lookup from hosts files and [hosts] config
	if (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA) && h.ptrResolver != nil {
		if ips := h.ptrResolver.LookupIP(q.Name); len(ips) > 0 {
			r := new(dns.Msg)
			setReply(r, qCtx.Q())
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
				return true
			}
		}
	}

	// Local PTR resolution from lease/hosts files
	if q.Qtype == dns.TypePTR && h.ptrResolver != nil {
		if hostname := h.ptrResolver.Lookup(q.Name); hostname != "" {
			r := new(dns.Msg)
			setReply(r, qCtx.Q())
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
			return true
		}
		// bogus-priv: private PTR not found locally -> NXDOMAIN, don't forward upstream
		if h.bogusPriv && isPrivatePTR(q.Name) {
			r := new(dns.Msg)
			setReply(r, qCtx.Q())
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
			return true
		}
	}
	// bogus-priv without ptrResolver: still block private PTR from going upstream
	if q.Qtype == dns.TypePTR && h.bogusPriv && h.ptrResolver == nil && isPrivatePTR(q.Name) {
		r := new(dns.Msg)
		setReply(r, qCtx.Q())
		r.Rcode = dns.RcodeNameError
		qCtx.SetResponse(r)
		h.logger.Debugw("bogus-priv",
			mlog.Stringer("client", qCtx.ServerMeta.ClientAddr),
			mlog.String("qtype", dns.TypeToString[q.Qtype]),
			mlog.String("domain", q.Name),
			mlog.String("rcode", "NXDOMAIN"))
		h.pplogReport(qCtx, pplog.RouteHosts, byte(dns.RcodeNameError), 0, "bogus-priv", r)
		return true
	}
	return false
}

// resolveRoute folds forceFall matcher, hook failure state, and the
// paopao.dns special-case into a requestRoute used by the remaining stages.
func (h *miniHandler) resolveRoute(qCtx *query_context.Context) requestRoute {
	q := qCtx.QQuestion()
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
	return requestRoute{
		forceFall:     forceFall,
		fallRoute:     fallRoute,
		fallRouteByte: fallRouteByte,
	}
}

// tryCacheHit serves a cached response when one is available, deep-cloning
// RRs with the remaining TTL so concurrent hits can't race on shared slices.
// Returns true when the response has been written to qCtx.
func (h *miniHandler) tryCacheHit(qCtx *query_context.Context, cacheKey CacheKey) bool {
	cachedMsg, expTime, ok := h.dnsCache.Get(cacheKey)
	if !ok || cachedMsg == nil {
		return false
	}
	q := qCtx.QQuestion()
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
	// concurrent hits may be reading).
	//
	// Question echoes the client's actual query rather than the cached
	// response's Question. This both (a) preserves the client's case
	// (RFC 1035 §3.1: domain names are case-insensitive but case-
	// preserving — clients that asked "Example.COM." should see
	// "Example.COM." echoed back, not whatever form the upstream used),
	// and (b) structurally prevents any future in-response Question
	// mutation from reaching back into the cached entry. Pseudo's slice
	// header is detached from the cached one (RR pointers stay shared
	// since EDNS option RRs are treated as immutable like the rest);
	// without the detach, two concurrent cache hits would alias the same
	// backing array and a future feature that appends to resp.Pseudo
	// would silently mutate every other in-flight response. Data is
	// intentionally absent on the cached entry (cacheSnapshot drops it),
	// so the response gets re-packed on the way out.
	var pseudo []dns.RR
	if n := len(cachedMsg.Pseudo); n > 0 {
		pseudo = append(make([]dns.RR, 0, n), cachedMsg.Pseudo...)
	}
	resp := &dns.Msg{
		MsgHeader: cachedMsg.MsgHeader,
		Question:  qCtx.Q().Question,
		Pseudo:    pseudo,
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
		// Future-allocated or extended rcodes are absent from the table
		// and would otherwise log as an empty string. Surface the numeric
		// value so ops can identify the unknown code.
		if rcodeLabel == "" {
			rcodeLabel = "RCODE_" + strconv.Itoa(int(resp.Rcode))
		}
	}
	logQuery(h.logger, &queryLog{
		route:  "cache",
		client: qCtx.ServerMeta.ClientAddr,
		qtype:  q.Qtype,
		domain: q.Name,
		rcode:  rcodeLabel,
	})
	// Mirror execLocal's rcode encoding: NOERROR + empty Answer is reported
	// as the synthetic RcodeNoData (0xFF). Without this, the same NODATA
	// response shows up as rcode=0 on cache hits and rcode=0xFF on misses,
	// breaking pplog aggregation.
	rcodeByte := byte(resp.Rcode)
	if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 {
		rcodeByte = pplog.RcodeNoData
	}
	h.pplogReport(qCtx, pplog.RouteCache, rcodeByte, 0, "", resp)
	return true
}

// execLocal runs the main DNS forwarder when the route isn't forced to
// fallback. Returns:
//   - localResp:   any main-DNS response (used as fallback if cnForward fails)
//   - localNoData: the subset of localResp that was NODATA (used for NODATA preference)
//   - handled:     true if the response has already been written to qCtx
//     (trust_rcode path, NOERROR+answer path, or aaaa=noerror+NODATA path)
func (h *miniHandler) execLocal(ctx context.Context, qCtx *query_context.Context, route requestRoute, cacheKey CacheKey) (localResp, localNoData *dns.Msg, handled bool) {
	if route.forceFall {
		return nil, nil, false
	}
	q := qCtx.QQuestion()
	r, upstreamUsed, queryDur, execErr := h.localForward.Exec(ctx, qCtx)
	if upstreamUsed == "" {
		upstreamUsed = "timeout/err"
	}
	if execErr != nil || r == nil {
		logLocalQuery(h.logger, qCtx.ServerMeta.ClientAddr, upstreamUsed, q.Qtype, q.Name, "timeout/error", queryDur, execErr)
		h.pplogReport(qCtx, pplog.RouteLocal, pplog.RcodeTimeout, durToMs(queryDur), upstreamUsed, nil)
		return nil, nil, false
	}
	if h.lite {
		h.applyLiteMode(r, q.Qtype, q.Name)
	}
	// trust_rcode: if the main DNS rcode is in the trusted set, accept the
	// response directly (even without answer records) and skip fallback.
	if len(h.trustRcodes) > 0 && h.trustRcodes[int(r.Rcode)] {
		qCtx.SetResponse(r)
		snap, ttl := cacheSnapshot(r)
		if ttl == 0 {
			ttl = 1
		}
		h.dnsCache.Store(cacheKey, snap, time.Now().Add(time.Duration(ttl)*time.Second))
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
		return nil, nil, true
	}
	if r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
		qCtx.SetResponse(r)
		snap, ttl := cacheSnapshot(r)
		// Mirror the trust_rcode / aaaa=noerror / fallback branches: a
		// TTL of 0 (some CDN/dynamic-DNS upstreams) still gets a 1-second
		// floor so an immediately-retried query doesn't re-traverse the
		// full upstream pipeline. The previous "skip cache when ttl==0"
		// behavior produced inconsistent hit rates depending on which
		// branch served the response.
		if ttl == 0 {
			ttl = 1
		}
		h.dnsCache.Store(cacheKey, snap, time.Now().Add(time.Duration(ttl)*time.Second))
		logLocalQuery(h.logger, qCtx.ServerMeta.ClientAddr, upstreamUsed, q.Qtype, q.Name, "NOERROR", queryDur, nil)
		h.pplogReport(qCtx, pplog.RouteLocal, byte(r.Rcode), durToMs(queryDur), upstreamUsed, r)
		return nil, nil, true
	}
	if r.Rcode == dns.RcodeSuccess && len(r.Answer) == 0 {
		// aaaa=noerror: trust the NOERROR+empty answer from main DNS directly,
		// skip fallback. Cache with original TTL (or TTL=1 if no NS record TTL).
		if h.aaaaMode == "noerror" && q.Qtype == dns.TypeAAAA {
			qCtx.SetResponse(r)
			snap, ttl := cacheSnapshot(r)
			if ttl == 0 {
				ttl = 1
			}
			h.dnsCache.Store(cacheKey, snap, time.Now().Add(time.Duration(ttl)*time.Second))
			logLocalQuery(h.logger, qCtx.ServerMeta.ClientAddr, upstreamUsed, q.Qtype, q.Name, "NODATA(trusted)", queryDur, nil)
			h.pplogReport(qCtx, pplog.RouteLocal, pplog.RcodeNoData, durToMs(queryDur), upstreamUsed, r)
			return nil, nil, true
		}
		logLocalQuery(h.logger, qCtx.ServerMeta.ClientAddr, upstreamUsed, q.Qtype, q.Name, "NODATA", queryDur, nil)
		h.pplogReport(qCtx, pplog.RouteLocal, pplog.RcodeNoData, durToMs(queryDur), upstreamUsed, r)
		// Save NODATA for the NODATA-preference rule + fallback-failure fallback.
		return r, r, false
	}
	// Non-success rcode (NXDOMAIN/REFUSED/etc.) — preserve so a failed fallback
	// doesn't collapse the response to SERVFAIL.
	logLocalQuery(h.logger, qCtx.ServerMeta.ClientAddr, upstreamUsed, q.Qtype, q.Name, dns.RcodeToString[r.Rcode], queryDur, nil)
	h.pplogReport(qCtx, pplog.RouteLocal, byte(r.Rcode), durToMs(queryDur), upstreamUsed, r)
	return r, nil, false
}

// execFallbackAndFinalize runs the fallback forwarder, applies the NODATA
// preference rule (primary NODATA beats fallback NODATA for its original
// TTL), writes a response to qCtx if nothing else has, and emits the
// fall-path log lines + pplog entry.
func (h *miniHandler) execFallbackAndFinalize(ctx context.Context, qCtx *query_context.Context, route requestRoute, cacheKey CacheKey, localResp, localNoData *dns.Msg) {
	q := qCtx.QQuestion()
	rFall, upFall, durFall, errFall := h.cnForward.Exec(ctx, qCtx)
	if upFall == "" {
		upFall = "timeout/err"
	}

	fallIsNoData := rFall != nil && rFall.Rcode == dns.RcodeSuccess && len(rFall.Answer) == 0

	// forceFall queries are isolated from the shared cache on both read
	// (process()) and write sides. Mirror that here: storing a force_fall
	// response under the shared cacheKey would let a normal client picking
	// up the entry within fallbackTTL bypass the main upstream they were
	// supposed to use. The TTL is short (1s) but the leak is real.
	cacheWrites := !route.forceFall

	// If both local and fall returned NODATA, prefer localForward result
	// (it may contain useful SOA/CNAME records with original TTL)
	if localNoData != nil && (fallIsNoData || rFall == nil) {
		if h.lite {
			h.applyLiteMode(localNoData, q.Qtype, q.Name)
		}
		qCtx.SetResponse(localNoData)
		if cacheWrites {
			snap, ttl := cacheSnapshot(localNoData)
			// Match the trust_rcode and aaaa=noerror branches: a NODATA reply
			// without an SOA in Authority has no minimum TTL, but we still
			// want it cached for at least one second so an immediately-retried
			// query doesn't re-traverse the upstream pipeline. Without this
			// floor, NODATA responses missing an SOA silently bypass the cache.
			if ttl == 0 {
				ttl = 1
			}
			h.dnsCache.Store(cacheKey, snap, time.Now().Add(time.Duration(ttl)*time.Second))
		}
	} else if rFall != nil {
		if h.lite {
			h.applyLiteMode(rFall, q.Qtype, q.Name)
		}
		qCtx.SetResponse(rFall)
		// TTL=1: fallback results are short-lived to allow fast switch back
		// to main DNS once the hook monitor detects recovery. Every non-OPT
		// TTL is overwritten below, so the post-rewrite minimum is trivially
		// fallbackTTL — no need for a second GetMinimalTTL pass.
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
		if cacheWrites {
			snap, _ := cacheSnapshot(qCtx.R())
			h.dnsCache.Store(cacheKey, snap, time.Now().Add(time.Duration(fallbackTTL)*time.Second))
		}
	} else if errFall != nil && localResp != nil {
		// Fallback failed entirely (timeout / network error). Surface the
		// main-DNS response that was logged earlier (NXDOMAIN/REFUSED/NODATA)
		// instead of letting Handle() synthesize SERVFAIL — the client
		// deserves the explicit error code the main upstream already gave us.
		if h.lite {
			h.applyLiteMode(localResp, q.Qtype, q.Name)
		}
		qCtx.SetResponse(localResp)
		if cacheWrites {
			snap, ttl := cacheSnapshot(localResp)
			if ttl == 0 {
				ttl = 1
			}
			h.dnsCache.Store(cacheKey, snap, time.Now().Add(time.Duration(ttl)*time.Second))
		}
	}

	switch {
	case localNoData != nil && (fallIsNoData || rFall == nil):
		// Response written to the client is NODATA (from the local resolver).
		// When the fallback also errored, surface both signals in the label so
		// ops still sees the fallback upstream is unhealthy — without logging
		// "timeout/error" for a request the client received as NODATA.
		rcodeLabel := "NODATA"
		if rFall == nil && errFall != nil {
			rcodeLabel = "NODATA(fall-timeout)"
		}
		logFallQuery(h.logger, route.fallRoute, qCtx.ServerMeta.ClientAddr, upFall, q.Qtype, q.Name, rcodeLabel, durFall, errFall)
	case rFall == nil && errFall != nil:
		logFallQuery(h.logger, route.fallRoute, qCtx.ServerMeta.ClientAddr, upFall, q.Qtype, q.Name, "timeout/error", durFall, errFall)
	default:
		rcodeStr := "NXDOMAIN or timeout"
		if rFall != nil {
			// Surface NODATA explicitly so this path's label matches
			// the local-resolver branch (which already says "NODATA").
			// Without this, a fallback NOERROR with empty Answer would
			// log as "NOERROR" while an identical local-resolver result
			// logged as "NODATA" — splitting one observable into two.
			if rFall.Rcode == dns.RcodeSuccess && len(rFall.Answer) == 0 {
				rcodeStr = "NODATA"
			} else {
				rcodeStr = dns.RcodeToString[rFall.Rcode]
				if rcodeStr == "" {
					rcodeStr = "RCODE_" + strconv.Itoa(int(rFall.Rcode))
				}
			}
		}
		logFallQuery(h.logger, route.fallRoute, qCtx.ServerMeta.ClientAddr, upFall, q.Qtype, q.Name, rcodeStr, durFall, nil)
	}
	if rFall != nil {
		rcodeByteFall := byte(rFall.Rcode)
		if fallIsNoData {
			rcodeByteFall = pplog.RcodeNoData
		}
		h.pplogReport(qCtx, route.fallRouteByte, rcodeByteFall, durToMs(durFall), upFall, rFall)
	} else {
		h.pplogReport(qCtx, route.fallRouteByte, pplog.RcodeTimeout, durToMs(durFall), upFall, nil)
	}
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
