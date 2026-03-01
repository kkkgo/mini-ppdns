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
	"strings"
	"syscall"
	"time"

	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/cache"
	"github.com/kkkgo/mini-ppdns/pkg/pool"
	"github.com/kkkgo/mini-ppdns/pkg/query_context"
	"github.com/kkkgo/mini-ppdns/pkg/server"
	"github.com/kkkgo/mini-ppdns/pkg/upstream"
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

// Implement server.Handler.

type miniHandler struct {
	logger *mlog.Logger

	localForward *miniForwarder
	cnForward    *miniForwarder
	dnsCache     *cache.Cache[CacheKey, *dns.Msg]

	forceFallPrefixes []netip.Prefix
	allowAAAA         bool
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
	rand.Shuffle(len(answers), func(i, j int) {
		answers[i], answers[j] = answers[j], answers[i]
	})

	insertIdx := 0
	for i := 0; i < len(answers); i++ {
		if answers[i].Header().Rrtype == qtype {
			answers[i], answers[insertIdx] = answers[insertIdx], answers[i]
			insertIdx++
		}
	}
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
	if len(h.forceFallPrefixes) > 0 {
		for _, prefix := range h.forceFallPrefixes {
			if prefix.Contains(qCtx.ServerMeta.ClientAddr) {
				forceFall = true
				break
			}
		}
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
		return nil
	}

	var r *dns.Msg
	var upstreamUsed string
	var queryDur time.Duration
	var execErr error

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
				return nil
			} else {
				rcodeStr := dns.RcodeToString[r.Rcode]
				if r.Rcode == dns.RcodeSuccess && len(r.Answer) == 0 {
					rcodeStr = "\033[33mNODATA\033[0m"
				} else {
					rcodeStr = "\033[31m" + rcodeStr + "\033[0m"
				}
				h.logger.Debugf("\033[36m%s\033[0m use \033[33m%s\033[0m local query \033[36m%s\033[0m \033[36m%s\033[0m %s %v%s", qCtx.ServerMeta.ClientAddr.String(), upstreamUsed, dns.TypeToString[q.Qtype], q.Name, rcodeStr, queryDur, ffStr)
			}
		} else {
			errStr := "timeout/error"
			if execErr != nil {
				errStr = execErr.Error()
			}
			h.logger.Debugf("\033[36m%s\033[0m use \033[33m%s\033[0m local query \033[36m%s\033[0m \033[36m%s\033[0m \033[31m%s\033[0m %v%s", qCtx.ServerMeta.ClientAddr.String(), upstreamUsed, dns.TypeToString[q.Qtype], q.Name, errStr, queryDur, ffStr)
		}
	}

	// 4. Fallback execution
	rFall, upFall, durFall, errFall := h.cnForward.Exec(ctx, qCtx)
	if upFall == "" {
		upFall = "timeout/err"
	}

	if rFall != nil {
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
	h.logger.Debugf("\033[36m%s\033[0m use \033[33m%s\033[0m fall query \033[36m%s\033[0m \033[36m%s\033[0m %s %v%s", qCtx.ServerMeta.ClientAddr.String(), upFall, dns.TypeToString[q.Qtype], q.Name, rcodeStr, durFall, ffStr)

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

	cachePlug := cache.New[CacheKey, *dns.Msg](cache.Opts{Size: 102400})

	// Parse force fall prefixes
	var forceFallPrefixes []netip.Prefix
	for _, s := range args.ForceFall {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.ContainsRune(s, '/') {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				fmt.Printf("Invalid force_fall IP %s: %v\n", s, err)
				os.Exit(1)
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			forceFallPrefixes = append(forceFallPrefixes, netip.PrefixFrom(addr, bits))
		} else {
			prefix, err := netip.ParsePrefix(s)
			if err != nil {
				fmt.Printf("Invalid force_fall CIDR %s: %v\n", s, err)
				os.Exit(1)
			}
			forceFallPrefixes = append(forceFallPrefixes, prefix)
		}
	}

	handler := &miniHandler{
		logger:            logger,
		localForward:      localFwd,
		cnForward:         cnFwd,
		dnsCache:          cachePlug,
		forceFallPrefixes: forceFallPrefixes,
		allowAAAA:         args.AAAA == "yes",
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
	logger.Infof("shutdown complete")
}
