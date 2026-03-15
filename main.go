package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/cache"
	"github.com/kkkgo/mini-ppdns/pkg/pool"
	"github.com/kkkgo/mini-ppdns/pkg/query_context"
	"github.com/kkkgo/mini-ppdns/pkg/server"
	"github.com/kkkgo/mini-ppdns/pkg/upstream"
	"github.com/kkkgo/mini-ppdns/pplog"
	"github.com/miekg/dns"
)

var version = "kkkgo/mosdns:mini-ppdns dev"

type ConfigArgs struct {
	DNS       []string
	Fall      []string
	Listen    []string
	ForceFall []string
	QTime     int
	AAAA      string
	Daemon    bool
	Debug     bool

	PPLogUUID   string
	PPLogServer string
	PPLogLevel  int
}

func getPrivateIPs() []string {
	var ips []string
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil {
				if ip.IsPrivate() || ip.IsLoopback() {
					ips = append(ips, ip.String()+":53")
				}
			}
		}
	}
	if len(ips) == 0 {
		ips = append(ips, "127.0.0.1:53")
	}
	return ips
}

func parseINI(filename string, m *ConfigArgs) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	section := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}

		switch section {
		case "dns":
			m.DNS = append(m.DNS, line)
		case "fall":
			m.Fall = append(m.Fall, line)
		case "listen":
			m.Listen = append(m.Listen, line)
		case "force_fall":
			m.ForceFall = append(m.ForceFall, line)
		case "adv":
			kv := strings.SplitN(line, "=", 2)
			if len(kv) == 2 {
				k := strings.TrimSpace(kv[0])
				v := strings.TrimSpace(kv[1])
				if k == "qtime" {
					fmt.Sscanf(v, "%d", &m.QTime)
				} else if k == "aaaa" {
					m.AAAA = v
				}
			}
		case "pplog":
			kv := strings.SplitN(line, "=", 2)
			if len(kv) == 2 {
				k := strings.TrimSpace(kv[0])
				v := strings.TrimSpace(kv[1])
				switch k {
				case "uuid":
					m.PPLogUUID = v
				case "server":
					m.PPLogServer = v
				case "level":
					fmt.Sscanf(v, "%d", &m.PPLogLevel)
				}
			}
		}
	}
	return scanner.Err()
}

type CacheKey string

func (k CacheKey) Sum() uint64 {
	// Basic djb2 hash
	var hash uint64 = 5381
	for i := 0; i < len(k); i++ {
		hash = ((hash << 5) + hash) + uint64(k[i])
	}
	return hash
}

// forceFallMatcher implements the force_fall matching logic.
// Include rules (without ^) use OR logic: any match triggers force_fall.
// Negate rules (with ^) use AND logic: all negate conditions must be satisfied
// (i.e. client IP must NOT be in ANY negated prefix) for force_fall to trigger.
type forceFallMatcher struct {
	includePrefixes []netip.Prefix // OR logic: any match → force_fall
	negatePrefixes  []netip.Prefix // AND logic: must NOT match any → force_fall
}

func (m *forceFallMatcher) Match(addr netip.Addr) bool {
	if len(m.includePrefixes) == 0 && len(m.negatePrefixes) == 0 {
		return false
	}
	// Check include rules (OR): any match → true
	for _, p := range m.includePrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	// Check negate rules (AND): ALL negate prefixes must NOT contain addr
	if len(m.negatePrefixes) > 0 {
		for _, p := range m.negatePrefixes {
			if p.Contains(addr) {
				return false
			}
		}
		return true
	}
	return false
}

// ipToUint32 converts a 4-byte IPv4 address to uint32.
func ipToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// uint32ToIP converts a uint32 to a netip.Addr (IPv4).
func uint32ToIP(n uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{
		byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
	})
}

// rangeToPrefix converts an IP range [start, end] to the minimal set of CIDR prefixes.
func rangeToPrefix(start, end netip.Addr) []netip.Prefix {
	if !start.Is4() || !end.Is4() {
		return nil
	}
	s := ipToUint32(start)
	e := ipToUint32(end)
	if s > e {
		return nil
	}
	var result []netip.Prefix
	for s <= e {
		// Find the largest block (smallest prefix bits) starting at s that fits within [s, e]
		maxBits := 32
		for maxBits > 0 {
			// Check alignment: s must be aligned to 2^(32-maxBits+1)
			mask := uint32(1) << (32 - maxBits + 1)
			if s%mask != 0 {
				break
			}
			// Check that the block end doesn't exceed e
			blockEnd := s + (1 << (32 - maxBits + 1)) - 1
			if blockEnd > e {
				break
			}
			maxBits--
		}
		result = append(result, netip.PrefixFrom(uint32ToIP(s), maxBits))
		blockSize := uint32(1) << (32 - maxBits)
		if s+blockSize-1 == 0xFFFFFFFF {
			break // Prevent overflow for 255.255.255.255
		}
		s += blockSize
	}
	return result
}

// parseForceFallEntry parses a single force_fall entry string.
// Returns the parsed prefixes, whether it's negated, and any error.
// Supports: single IP, CIDR, IP range (start-end), with optional ^ prefix.
func parseForceFallEntry(s string) (prefixes []netip.Prefix, negated bool, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false, nil
	}
	if strings.HasPrefix(s, "^") {
		negated = true
		s = s[1:]
	}
	if strings.Contains(s, "-") {
		// IP range: start-end
		parts := strings.SplitN(s, "-", 2)
		start, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, negated, fmt.Errorf("invalid range start IP %s: %w", parts[0], err)
		}
		end, err := netip.ParseAddr(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, negated, fmt.Errorf("invalid range end IP %s: %w", parts[1], err)
		}
		prefixes = rangeToPrefix(start, end)
		if len(prefixes) == 0 {
			return nil, negated, fmt.Errorf("invalid IP range %s-%s", parts[0], parts[1])
		}
		return prefixes, negated, nil
	}
	if strings.Contains(s, "/") {
		// CIDR
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, negated, fmt.Errorf("invalid CIDR %s: %w", s, err)
		}
		return []netip.Prefix{prefix}, negated, nil
	}
	// Single IP
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return nil, negated, fmt.Errorf("invalid IP %s: %w", s, err)
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return []netip.Prefix{netip.PrefixFrom(addr, bits)}, negated, nil
}

type miniHandler struct {
	logger *mlog.Logger

	localForward *miniForwarder
	cnForward    *miniForwarder
	dnsCache     *cache.Cache[CacheKey, *dns.Msg]

	forceFallMatcher *forceFallMatcher
	allowAAAA        bool

	pplogReporter *pplog.Reporter
	pplogLevel    int
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

	concurrent := 3
	if len(f.upstreams) < concurrent {
		concurrent = len(f.upstreams)
	}

	resChan := make(chan res)
	done := make(chan struct{})
	defer close(done)

	start := time.Now()

	for i := 0; i < concurrent; i++ {
		u := f.upstreams[i%len(f.upstreams)]
		qc := func(b *[]byte) *[]byte {
			c := pool.GetBuf(cap(*b))
			*c = (*c)[:len(*b)]
			copy(*c, *b)
			return c
		}(queryPayload)

		go func(up upstream.Upstream) {
			defer pool.ReleaseBuf(qc)
			upstreamCtx, cancel := context.WithTimeout(ctx, f.qtime)
			defer cancel()

			var r *dns.Msg
			respPayload, err := up.ExchangeContext(upstreamCtx, *qc)
			dur := time.Since(start)
			if err == nil {
				r = new(dns.Msg)
				err = r.Unpack(*respPayload)
				pool.ReleaseBuf(respPayload)
				if err != nil {
					r = nil
				}
			}
			addr := ""
			if len(f.addresses) > 0 {
				addr = f.addresses[i%len(f.addresses)]
			}
			select {
			case resChan <- res{r: r, err: err, upstream: addr, duration: dur}:
			case <-done:
			}
		}(u)
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
	qCtx := query_context.NewContext(q)
	qCtx.ServerMeta = meta

	err := h.process(ctx, qCtx)
	if err != nil {
		h.logger.Debugf("query failed err=%v", err)
		if qCtx.R() == nil {
			r := new(dns.Msg)
			r.SetReply(q)
			r.Rcode = dns.RcodeServerFailure
			qCtx.SetResponse(r)
		}
	} else if qCtx.R() == nil {
		// Empty response
		r := new(dns.Msg)
		r.SetReply(q)
		r.Rcode = dns.RcodeServerFailure
		qCtx.SetResponse(r)
	}

	if qCtx.R() != nil && len(qCtx.R().Answer) > 1 && len(q.Question) > 0 {
		shuffleAnswers(q.Question[0].Qtype, qCtx.R().Answer)
	}

	payload, err := packMsgPayload(qCtx.R())
	if err != nil {
		h.logger.Warnf("failed to pack response err=%v", err)
		return nil
	}
	return payload
}

func shuffleAnswers(qtype uint16, answers []dns.RR) {
	if len(answers) <= 1 {
		return
	}
	// Three-bucket sort per RFC 1034:
	//   1. CNAME records (must precede the records they resolve to)
	//   2. Records matching the queried qtype (shuffled for load balancing)
	//   3. Everything else (shuffled)
	var cnameRecords, qtypeRecords, restRecords []dns.RR
	for _, rr := range answers {
		switch {
		case rr.Header().Rrtype == dns.TypeCNAME:
			cnameRecords = append(cnameRecords, rr)
		case rr.Header().Rrtype == qtype:
			qtypeRecords = append(qtypeRecords, rr)
		default:
			restRecords = append(restRecords, rr)
		}
	}
	rand.Shuffle(len(qtypeRecords), func(i, j int) {
		qtypeRecords[i], qtypeRecords[j] = qtypeRecords[j], qtypeRecords[i]
	})
	rand.Shuffle(len(restRecords), func(i, j int) {
		restRecords[i], restRecords[j] = restRecords[j], restRecords[i]
	})
	pos := copy(answers, cnameRecords)
	pos += copy(answers[pos:], qtypeRecords)
	copy(answers[pos:], restRecords)
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

func (h *miniHandler) process(ctx context.Context, qCtx *query_context.Context) error {
	q := qCtx.QQuestion()

	// Reject AAAA and specific QType
	if q.Qtype == 64 || q.Qtype == 65 || (!h.allowAAAA && q.Qtype == dns.TypeAAAA) {
		if !h.allowAAAA && q.Qtype == dns.TypeAAAA {
			h.logger.Debugf("\033[36m%s\033[0m query \033[36m%s\033[0m \033[36m%s\033[0m aaaa=no,block aaaa record.", qCtx.ServerMeta.ClientAddr.String(), dns.TypeToString[q.Qtype], q.Name)
		}
		r := new(dns.Msg)
		r.SetReply(qCtx.Q())
		r.Rcode = dns.RcodeSuccess
		qCtx.SetResponse(r)
		return nil
	}

	// Determine route for logging
	forceFall := false
	if h.forceFallMatcher != nil {
		forceFall = h.forceFallMatcher.Match(qCtx.ServerMeta.ClientAddr)
	}

	ffStr := ""
	if forceFall {
		ffStr = " \033[35mforce_fall\033[0m"
	}

	// 2. Cache
	cacheKey := CacheKey(q.Name + "_" + fmt.Sprint(q.Qclass) + "_" + fmt.Sprint(q.Qtype))
	if cachedMsg, expTime, ok := h.dnsCache.Get(cacheKey); ok && cachedMsg != nil {
		resp := cachedMsg.Copy()
		resp.Id = qCtx.Q().Id

		if len(resp.Answer) > 0 {
			newAns := make([]dns.RR, len(resp.Answer))
			for i, rr := range resp.Answer {
				newAns[i] = dns.Copy(rr)
			}
			resp.Answer = newAns
		}

		ttlLeft := uint32(time.Until(expTime).Seconds())
		if ttlLeft == 0 {
			ttlLeft = 1
		}
		for _, ans := range resp.Answer {
			ans.Header().Ttl = ttlLeft
		}
		for _, ns := range resp.Ns {
			ns.Header().Ttl = ttlLeft
		}
		for _, ext := range resp.Extra {
			if ext.Header().Rrtype != dns.TypeOPT {
				ext.Header().Ttl = ttlLeft
			}
		}

		qCtx.SetResponse(resp)
		h.logger.Debugf("\033[36m%s\033[0m use \033[33mcache\033[0m query \033[36m%s\033[0m \033[36m%s\033[0m \033[32mNOERROR\033[0m 0ms%s", qCtx.ServerMeta.ClientAddr.String(), dns.TypeToString[q.Qtype], q.Name, ffStr)
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
			if r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
				qCtx.SetResponse(r)
				ttl := getMsgTTL(r)
				if ttl > 0 {
					h.dnsCache.Store(cacheKey, r.Copy(), time.Now().Add(time.Duration(ttl)*time.Second))
				}
				h.logger.Debugf("\033[36m%s\033[0m use \033[33m%s\033[0m local query \033[36m%s\033[0m \033[36m%s\033[0m \033[32mNOERROR\033[0m %v%s", qCtx.ServerMeta.ClientAddr.String(), upstreamUsed, dns.TypeToString[q.Qtype], q.Name, queryDur, ffStr)
				h.pplogReport(qCtx, pplog.RouteLocal, byte(r.Rcode), uint16(queryDur.Milliseconds()), upstreamUsed, r)
				return nil
			} else {
				rcodeStr := dns.RcodeToString[r.Rcode]
				if r.Rcode == dns.RcodeSuccess && len(r.Answer) == 0 {
					rcodeStr = "\033[33mNODATA\033[0m"
					localNoData = r // save NODATA result for possible later use
				} else {
					rcodeStr = "\033[31m" + rcodeStr + "\033[0m"
				}
				h.logger.Debugf("\033[36m%s\033[0m use \033[33m%s\033[0m local query \033[36m%s\033[0m \033[36m%s\033[0m %s %v%s", qCtx.ServerMeta.ClientAddr.String(), upstreamUsed, dns.TypeToString[q.Qtype], q.Name, rcodeStr, queryDur, ffStr)
				rcodeByte := byte(r.Rcode)
				if r.Rcode == dns.RcodeSuccess && len(r.Answer) == 0 {
					rcodeByte = pplog.RcodeNoData
				}
				h.pplogReport(qCtx, pplog.RouteLocal, rcodeByte, uint16(queryDur.Milliseconds()), upstreamUsed, r)
			}
		} else {
			errStr := "timeout/error"
			if execErr != nil {
				errStr = execErr.Error()
			}
			h.logger.Debugf("\033[36m%s\033[0m use \033[33m%s\033[0m local query \033[36m%s\033[0m \033[36m%s\033[0m \033[31m%s\033[0m %v%s", qCtx.ServerMeta.ClientAddr.String(), upstreamUsed, dns.TypeToString[q.Qtype], q.Name, errStr, queryDur, ffStr)
			h.pplogReport(qCtx, pplog.RouteLocal, pplog.RcodeTimeout, uint16(queryDur.Milliseconds()), upstreamUsed, nil)
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
		qCtx.SetResponse(localNoData)
		ttl := getMsgTTL(localNoData)
		if ttl > 0 {
			h.dnsCache.Store(cacheKey, localNoData.Copy(), time.Now().Add(time.Duration(ttl)*time.Second))
		}
	} else if rFall != nil {
		qCtx.SetResponse(rFall)
		for _, ans := range qCtx.R().Answer {
			ans.Header().Ttl = 1
		}
		for _, ns := range qCtx.R().Ns {
			ns.Header().Ttl = 1
		}
		for _, ext := range qCtx.R().Extra {
			if ext.Header().Rrtype != dns.TypeOPT {
				ext.Header().Ttl = 1
			}
		}
		ttl := getMsgTTL(qCtx.R())
		if ttl > 0 {
			h.dnsCache.Store(cacheKey, qCtx.R().Copy(), time.Now().Add(time.Duration(ttl)*time.Second))
		}
	} else if errFall != nil {
		// Log error
	}

	rcodeStr := "\033[31mNXDOMAIN or timeout\033[0m"
	if rFall != nil {
		if rFall.Rcode == dns.RcodeSuccess {
			rcodeStr = "\033[32mNOERROR\033[0m"
		} else {
			rcodeStr = "\033[31m" + dns.RcodeToString[rFall.Rcode] + "\033[0m"
		}
	}
	if errFall != nil && rFall == nil {
		rcodeStr = "\033[31m" + errFall.Error() + "\033[0m"
	}
	if localNoData != nil && (fallIsNoData || rFall == nil) {
		h.logger.Debugf("\033[36m%s\033[0m use \033[33m%s\033[0m fall query \033[36m%s\033[0m \033[36m%s\033[0m \033[33mNODATA\033[0m %v, prefer \033[33mlocal NODATA\033[0m%s", qCtx.ServerMeta.ClientAddr.String(), upFall, dns.TypeToString[q.Qtype], q.Name, durFall, ffStr)
	} else {
		h.logger.Debugf("\033[36m%s\033[0m use \033[33m%s\033[0m fall query \033[36m%s\033[0m \033[36m%s\033[0m %s %v%s", qCtx.ServerMeta.ClientAddr.String(), upFall, dns.TypeToString[q.Qtype], q.Name, rcodeStr, durFall, ffStr)
	}
	if rFall != nil {
		rcodeByteFall := byte(rFall.Rcode)
		if fallIsNoData {
			rcodeByteFall = pplog.RcodeNoData
		}
		h.pplogReport(qCtx, pplog.RouteFall, rcodeByteFall, uint16(durFall.Milliseconds()), upFall, rFall)
	} else {
		h.pplogReport(qCtx, pplog.RouteFall, pplog.RcodeTimeout, uint16(durFall.Milliseconds()), upFall, nil)
	}

	return nil
}

func getMsgTTL(m *dns.Msg) uint32 {
	var ttl uint32 = 0xFFFFFFFF
	for _, a := range m.Answer {
		if a.Header().Ttl < ttl {
			ttl = a.Header().Ttl
		}
	}
	for _, a := range m.Ns {
		if a.Header().Ttl < ttl {
			ttl = a.Header().Ttl
		}
	}
	for _, a := range m.Extra {
		if a.Header().Rrtype != dns.TypeOPT && a.Header().Ttl < ttl {
			ttl = a.Header().Ttl
		}
	}
	if ttl == 0xFFFFFFFF {
		return 0
	}
	return ttl
}

const (
	estimatedEntrySize = 512    // estimated bytes per cache entry
	maxCacheSize       = 102400 // absolute upper limit
	minCacheSize       = 1024   // minimum cache entries
)

// getAvailableMemory reads /proc/meminfo and returns available memory in bytes.
// Returns 0 if /proc/meminfo is not readable (non-Linux).
func getAvailableMemory() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()

	var memAvailable, memFree, buffers, cached uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		val *= 1024 // /proc/meminfo values are in kB
		switch fields[0] {
		case "MemAvailable:":
			memAvailable = val
		case "MemFree:":
			memFree = val
		case "Buffers:":
			buffers = val
		case "Cached:":
			cached = val
		}
	}
	if memAvailable > 0 {
		return memAvailable
	}
	// Fallback for older kernels without MemAvailable
	return memFree + buffers + cached
}

// calculateCacheSize returns the optimal cache size based on available memory.
// The result is capped at maxCacheSize and floored at minCacheSize.
// If availableBytes is 0 (non-Linux or read failure), returns maxCacheSize.
func calculateCacheSize(availableBytes uint64) int {
	if availableBytes == 0 {
		return maxCacheSize
	}
	memBased := int(availableBytes / 5 / estimatedEntrySize) // 20% of available / entry size
	if memBased > maxCacheSize {
		memBased = maxCacheSize
	}
	if memBased < minCacheSize {
		memBased = minCacheSize
	}
	return memBased
}

func main() {
	var (
		dnsStr       = flag.String("dns", "", "Local DNS upstreams (comma separated)")
		fallStr      = flag.String("fall", "", "Fallback DNS upstreams (comma separated)")
		listenStr    = flag.String("listen", "", "Listen addresses (comma separated)")
		forceFallStr = flag.String("force_fall", "", "Force fallback for these client IPs/CIDRs (comma separated)")
		qtimePtr     = flag.Int("qtime", 250, "Delay threshold for failover in ms")
		aaaaPtr      = flag.String("aaaa", "no", "Enable AAAA records (yes/no)")
		daemonPtr    = flag.Bool("d", false, "Run in background as daemon")
		debugPtr     = flag.Bool("debug", false, "Enable debug logging")
		configStr    = flag.String("config", "", "Path to config.ini file")
		versionCmd   = flag.Bool("version", false, "Print out version info and exit")

		pplogServer = flag.String("pplog_server", "", "PPLog UDP server address (e.g. 192.168.1.100:9999)")
		pplogUUID   = flag.String("pplog_uuid", "", "PPLog authentication UUID")
		pplogLevel  = flag.Int("pplog_level", 0, "PPLog detail level (1-5, 0=disabled)")
	)

	flag.Parse()

	if *versionCmd {
		fmt.Println(version)
		os.Exit(0)
	}

	args := ConfigArgs{
		QTime:  *qtimePtr,
		AAAA:   *aaaaPtr,
		Daemon: *daemonPtr,
		Debug:  *debugPtr,
	}

	if *configStr != "" {
		if err := parseINI(*configStr, &args); err != nil {
			fmt.Printf("Error reading config: %v\n", err)
			os.Exit(1)
		}
	}

	if *dnsStr != "" {
		args.DNS = append(args.DNS, strings.Split(*dnsStr, ",")...)
	}
	if *fallStr != "" {
		args.Fall = append(args.Fall, strings.Split(*fallStr, ",")...)
	}
	if *listenStr != "" {
		args.Listen = append(args.Listen, strings.Split(*listenStr, ",")...)
	}
	if *forceFallStr != "" {
		args.ForceFall = append(args.ForceFall, strings.Split(*forceFallStr, ",")...)
	}
	if *pplogServer != "" {
		args.PPLogServer = *pplogServer
	}
	if *pplogUUID != "" {
		args.PPLogUUID = *pplogUUID
	}
	if *pplogLevel > 0 {
		args.PPLogLevel = *pplogLevel
	}

	// Ensure upstreams use udp:// or tcp://
	formatUpstream := func(addr string) string {
		addr = strings.TrimSpace(addr)
		if !strings.Contains(addr, "://") {
			addr = "udp://" + addr
		}
		if !strings.Contains(addr[strings.Index(addr, "://")+3:], ":") {
			addr = addr + ":53" // default port
		}
		return addr
	}

	// Setup logging
	logLevel := "info"
	if args.Debug {
		logLevel = "debug"
	}
	logger, err := mlog.NewLogger(mlog.LogConfig{Level: logLevel, File: ""})
	if err != nil {
		fmt.Println("Failed to init logger:", err)
		os.Exit(1)
	}

	var tryLocalUpstreams []upstream.Upstream
	var tryLocalAddrs []string
	for _, addr := range args.DNS {
		u, err := upstream.NewUpstream(formatUpstream(addr), upstream.Opt{Logger: logger})
		if err == nil {
			tryLocalUpstreams = append(tryLocalUpstreams, u)
			tryLocalAddrs = append(tryLocalAddrs, formatUpstream(addr))
		}
	}

	var tryCNUpstreams []upstream.Upstream
	var tryCNAddrs []string
	for _, addr := range args.Fall {
		u, err := upstream.NewUpstream(formatUpstream(addr), upstream.Opt{Logger: logger})
		if err == nil {
			tryCNUpstreams = append(tryCNUpstreams, u)
			tryCNAddrs = append(tryCNAddrs, formatUpstream(addr))
		}
	}

	if len(tryLocalUpstreams) == 0 {
		fmt.Println("Error: No DNS upstream provided (-dns)")
		os.Exit(1)
	}
	if len(tryCNUpstreams) == 0 {
		fmt.Println("Error: No fallback DNS provided (-fall)")
		os.Exit(1)
	}

	if len(args.Listen) == 0 {
		args.Listen = getPrivateIPs()
	}

	if args.Daemon {
		// Background logic
		execPath, err := os.Executable()
		if err != nil {
			fmt.Printf("Failed to get executable path: %v\n", err)
			os.Exit(1)
		}
		cmdArgs := []string{}
		for _, arg := range os.Args[1:] {
			if arg != "-d" && arg != "-d=true" {
				cmdArgs = append(cmdArgs, arg)
			}
		}
		cmd := exec.Command(execPath, cmdArgs...)
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil
		err = cmd.Start()
		if err != nil {
			fmt.Printf("Failed to start daemon: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Started in background with PID %d\n", cmd.Process.Pid)
		os.Exit(0)
	}

	localFwd := &miniForwarder{
		upstreams: tryLocalUpstreams,
		addresses: tryLocalAddrs,
		qtime:     time.Duration(args.QTime) * time.Millisecond,
		logger:    logger,
	}

	cnFwd := &miniForwarder{
		upstreams: tryCNUpstreams,
		addresses: tryCNAddrs,
		qtime:     time.Duration(args.QTime*10) * time.Millisecond,
		logger:    logger,
	}

	availMem := getAvailableMemory()
	cacheSize := calculateCacheSize(availMem)
	logger.Infof("cache size=\033[36m%d\033[0m (available memory: %d MB)", cacheSize, availMem/1024/1024)
	cachePlug := cache.New[CacheKey, *dns.Msg](cache.Opts{Size: cacheSize})

	// Parse force fall rules
	ffMatcher := &forceFallMatcher{}
	for _, s := range args.ForceFall {
		prefixes, negated, err := parseForceFallEntry(s)
		if err != nil {
			fmt.Printf("Invalid force_fall entry %s: %v\n", s, err)
			os.Exit(1)
		}
		if len(prefixes) == 0 {
			continue
		}
		if negated {
			ffMatcher.negatePrefixes = append(ffMatcher.negatePrefixes, prefixes...)
		} else {
			ffMatcher.includePrefixes = append(ffMatcher.includePrefixes, prefixes...)
		}
	}

	// Initialize pplog reporter if configured
	var pplogReporter *pplog.Reporter
	if args.PPLogServer != "" && args.PPLogUUID != "" && args.PPLogLevel > 0 {
		var err error
		pplogReporter, err = pplog.NewReporter(pplog.Config{
			UUID:   args.PPLogUUID,
			Server: args.PPLogServer,
			Level:  args.PPLogLevel,
		})
		if err != nil {
			logger.Warnf("pplog init failed: %v (log reporting disabled)", err)
		} else {
			logger.Infof("pplog enabled server=\033[36m%s\033[0m level=\033[36m%d\033[0m", args.PPLogServer, args.PPLogLevel)
		}
	}

	handler := &miniHandler{
		logger:           logger,
		localForward:     localFwd,
		cnForward:        cnFwd,
		dnsCache:         cachePlug,
		forceFallMatcher: ffMatcher,
		allowAAAA:        args.AAAA == "yes",
		pplogReporter:    pplogReporter,
		pplogLevel:       args.PPLogLevel,
	}

	// Start servers manually
	var udpConns []net.PacketConn
	var tcpListeners []net.Listener

	for _, addr := range args.Listen {
		addr := addr
		logger.Infof("Starting server addr=\033[36m%s\033[0m", addr)
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			fmt.Printf("\033[31mError: %v\033[0m\n", err)
			continue
		}
		uconn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			fmt.Printf("\033[31mError: %v\033[0m\n", err)
			continue
		}
		udpConns = append(udpConns, uconn)

		tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			fmt.Printf("\033[31mError: %v\033[0m\n", err)
			if uconn != nil {
				uconn.Close()
			}
			continue
		}
		tconn, err := net.ListenTCP("tcp", tcpAddr)
		if err != nil {
			fmt.Printf("\033[31mError: %v\033[0m\n", err)
			if uconn != nil {
				uconn.Close()
			}
			continue
		}
		tcpListeners = append(tcpListeners, tconn)

		// Serve routines
		go server.ServeUDP(uconn, handler, server.UDPServerOpts{Logger: logger})
		go server.ServeTCP(tconn, handler, server.TCPServerOpts{Logger: logger, IdleTimeout: 3 * time.Second})

		// Report server start event
		if pplogReporter != nil {
			pplogReporter.ReportEvent(pplog.SeverityInfo, fmt.Sprintf("server started addr=%s", addr))
		}
	}

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	logger.Infof("signal received signal=%v", sig)

	// Close resources
	for _, uconn := range udpConns {
		uconn.Close()
	}
	for _, tconn := range tcpListeners {
		tconn.Close()
	}
	for _, u := range tryLocalUpstreams {
		u.Close()
	}
	for _, u := range tryCNUpstreams {
		u.Close()
	}
	cachePlug.Close()
	if pplogReporter != nil {
		pplogReporter.ReportEvent(pplog.SeverityInfo, "server shutting down")
		pplogReporter.Close()
	}
	logger.Infof("shutdown complete")
}
