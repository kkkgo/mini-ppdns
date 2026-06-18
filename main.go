package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/kkkgo/mini-ppdns/mlog"
	"github.com/kkkgo/mini-ppdns/pkg/cache"
	"github.com/kkkgo/mini-ppdns/pkg/server"
	"github.com/kkkgo/mini-ppdns/pkg/upstream"
	"github.com/kkkgo/mini-ppdns/pplog"
)

var version = "kkkgo/ppdns:mini-ppdns dev"

const shutdownTimeout = 5 * time.Second

func main() {
	initTimezone()
	var (
		dnsStr        = flag.String("dns", "", "Local DNS upstreams (comma separated)")
		fallStr       = flag.String("fall", "", "Fallback DNS upstreams (comma separated)")
		listenStr     = flag.String("listen", "", "Listen addresses (comma separated)")
		forceFallStr  = flag.String("force_fall", "", "Force fallback for these client IPs/CIDRs (comma separated)")
		qtimePtr      = flag.Int("qtime", 250, "Delay threshold for failover in ms")
		aaaaPtr       = flag.String("aaaa", "no", "AAAA record mode (no/yes/noerror)")
		trustRcodeStr = flag.String("trust_rcode", "", "Trust these rcodes from main DNS, skip fallback (comma separated, e.g. 0,3)")
		litePtr       = flag.String("lite", "yes", "Enable lite mode to simplify responses (yes/no)")
		daemonPtr     = flag.Bool("d", false, "Run in background as daemon")
		debugPtr      = flag.Bool("debug", false, "Enable debug logging")
		configStr     = flag.String("config", "", "Path to config.ini file")
		versionCmd    = flag.Bool("version", false, "Print out version info and exit")

		pplogServer = flag.String("pplog_server", "", "PPLog UDP server address (e.g. 192.168.1.100:9999)")
		pplogUUID   = flag.String("pplog_uuid", "", "PPLog authentication UUID")
		pplogLevel  = flag.Int("pplog_level", 0, "PPLog detail level (1-5, 0=disabled)")

		leaseFileStr = flag.String("lease_file", "", "DHCP lease files for PTR resolution (comma separated, e.g. /tmp/dhcp.leases)")
		hostsFileStr = flag.String("hosts_file", "", "Hosts files for PTR resolution (comma separated, e.g. /etc/hosts)")
		bogusPrivPtr = flag.Bool("boguspriv", true, "Return NXDOMAIN for private IP PTR queries not found locally (default true)")
		blockSVCBPtr = flag.Bool("block_svcb", true, "Block SVCB(64)/HTTPS(65) queries to prevent DNS split bypass (default true)")
	)

	flag.Parse()

	if *versionCmd {
		fmt.Println(version)
		os.Exit(0)
	}

	args := ConfigArgs{
		QTime:  *qtimePtr,
		AAAA:   *aaaaPtr,
		Lite:   *litePtr,
		Daemon: *daemonPtr,
		Debug:  *debugPtr,
	}

	preLogger := mlog.Nop()
	if *configStr != "" {
		if err := parseINI(*configStr, &args, preLogger); err != nil {
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
	if *trustRcodeStr != "" {
		args.TrustRcode = nil
		for _, s := range strings.Split(*trustRcodeStr, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if n, err := strconv.Atoi(s); err == nil {
				args.TrustRcode = append(args.TrustRcode, n)
			} else {
				preLogger.Warnw("invalid trust_rcode value, skipping", mlog.String("value", s))
			}
		}
	}
	if *leaseFileStr != "" {
		for _, lf := range strings.Split(*leaseFileStr, ",") {
			lf = strings.TrimSpace(lf)
			if lf != "" {
				args.LeaseFile = append(args.LeaseFile, lf)
			}
		}
	}
	if *hostsFileStr != "" {
		for _, hf := range strings.Split(*hostsFileStr, ",") {
			hf = strings.TrimSpace(hf)
			if hf != "" {
				args.HostsFile = append(args.HostsFile, hf)
			}
		}
	}
	// boguspriv: CLI flag > config file > default (true)
	bogusPrivCLI := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "boguspriv" {
			bogusPrivCLI = true
		}
	})
	if bogusPrivCLI {
		// CLI flag explicitly set, takes highest precedence
		args.BogusPriv = *bogusPrivPtr
	} else if !args.BogusPrivSet {
		// Not set in config file either, use default (true)
		args.BogusPriv = true
	}
	// Otherwise, config file value is already set and takes precedence

	// block_svcb: CLI flag > config file > default (true)
	blockSVCBCLI := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "block_svcb" {
			blockSVCBCLI = true
		}
	})
	if blockSVCBCLI {
		args.BlockSVCB = *blockSVCBPtr
	} else if !args.BlockSVCBSet {
		args.BlockSVCB = true
	}

	// Normalize and validate enum-like config values (case-insensitive).
	args.AAAA = strings.ToLower(strings.TrimSpace(args.AAAA))
	switch args.AAAA {
	case "no", "yes", "noerror":
	default:
		fmt.Printf("invalid aaaa value %q, falling back to \"no\"\n", args.AAAA)
		args.AAAA = "no"
	}
	args.Lite = strings.ToLower(strings.TrimSpace(args.Lite))
	switch args.Lite {
	case "no", "yes":
	default:
		fmt.Printf("invalid lite value %q, falling back to \"yes\"\n", args.Lite)
		args.Lite = "yes"
	}

	formatUpstream := formatUpstreamAddr

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
		formatted := formatUpstream(addr)
		u, err := upstream.NewUpstream(formatted, upstream.Opt{Logger: logger})
		if err != nil {
			logger.Warnw("skipping invalid DNS upstream",
				mlog.String("addr", addr),
				mlog.String("normalized", formatted),
				mlog.Err(err))
			continue
		}
		tryLocalUpstreams = append(tryLocalUpstreams, u)
		tryLocalAddrs = append(tryLocalAddrs, formatted)
	}

	var tryCNUpstreams []upstream.Upstream
	var tryCNAddrs []string
	for _, addr := range args.Fall {
		formatted := formatUpstream(addr)
		u, err := upstream.NewUpstream(formatted, upstream.Opt{Logger: logger})
		if err != nil {
			logger.Warnw("skipping invalid fallback upstream",
				mlog.String("addr", addr),
				mlog.String("normalized", formatted),
				mlog.Err(err))
			continue
		}
		tryCNUpstreams = append(tryCNUpstreams, u)
		tryCNAddrs = append(tryCNAddrs, formatted)
	}

	if len(tryLocalUpstreams) == 0 {
		fmt.Println("Error: No DNS upstream provided (-dns)")
		os.Exit(1)
	}
	if len(tryCNUpstreams) == 0 {
		fmt.Println("Error: No fallback DNS provided (-fall)")
		os.Exit(1)
	}
	// A zero/negative qtime would produce an already-expired context for every
	// upstream query, instantly failing all DNS resolution.
	if args.QTime <= 0 {
		fmt.Printf("Error: qtime must be positive (got %d)\n", args.QTime)
		os.Exit(1)
	}

	if len(args.Listen) == 0 {
		args.Listen = getPrivateIPs()
	} else {
		// Expand wildcard listens (0.0.0.0:port, [::]:port) to private/
		// loopback addresses so we never accidentally serve DNS on public IPs.
		var expanded []string
		seen := make(map[string]bool)
		for _, a := range args.Listen {
			// Bare IPs without :port resolve to port 0 in net.ResolveUDPAddr,
			// silently binding to a random ephemeral port — DNS clients on
			// :53 then see no listener. Default to :53 for any entry the
			// user gave without an explicit port.
			a = ensureListenPort(a)
			for _, e := range expandWildcardListen(a) {
				if !seen[e] {
					seen[e] = true
					expanded = append(expanded, e)
				}
			}
		}
		args.Listen = expanded
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
			if isDaemonFlagArg(arg) {
				continue
			}
			cmdArgs = append(cmdArgs, arg)
		}
		cmd := exec.Command(execPath, cmdArgs...)
		cmd.Stdin = nil
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
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
		qtime:     time.Duration(args.QTime) * 10 * time.Millisecond,
		logger:    logger,
	}

	// Initialize pplog reporter if configured
	var pplogReporter *pplog.Reporter
	if args.PPLogServer != "" && args.PPLogUUID != "" && args.PPLogLevel > 0 {
		var err error
		pplogReporter, err = pplog.NewReporter(pplog.Config{
			UUID:      args.PPLogUUID,
			Server:    args.PPLogServer,
			Level:     args.PPLogLevel,
			HeartBeat: args.PPLogHeartBeat,
		})
		if err != nil {
			logger.Warnw("pplog init failed (log reporting disabled)", mlog.Err(err))
		} else {
			logger.SetReporter(pplogReporter)
			logInfoPPLogEnabled(logger, args.PPLogServer, args.PPLogLevel)
		}
	}

	availMem := getAvailableMemory()
	cacheSize := calculateCacheSize(availMem)
	logInfoAvailableMemory(logger, availMem/1024/1024)
	cachePlug := cache.New[CacheKey, *dns.Msg](cache.Opts{Size: cacheSize})

	// Parse force fall rules
	ffMatcher := &forceFallMatcher{}
	for _, s := range args.ForceFall {
		prefixes, negated, err := parseForceFallEntry(s)
		if err != nil {
			logger.Fatalw("invalid force_fall entry", mlog.String("entry", s), mlog.Err(err))
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

	// Initialize hook monitor if configured
	var hookFailed *atomic.Bool
	var hookCancel context.CancelFunc
	var hookMon *hookMonitor
	if args.Hook != nil && args.Hook.Exec != "" {
		hookFailed = &atomic.Bool{}
		var hookCtx context.Context
		hookCtx, hookCancel = context.WithCancel(context.Background())
		hookMon = &hookMonitor{
			cfg:         args.Hook,
			failed:      hookFailed,
			logger:      logger,
			dnsCache:    cachePlug,
			shutdownCtx: hookCtx,
		}
		go hookMon.run(hookCtx)
		logger.Infow("hook enabled",
			mlog.String("exec", args.Hook.Exec),
			mlog.Int("sleep", args.Hook.SleepTime),
			mlog.Int("retry", args.Hook.RetryTime),
			mlog.Int("count", args.Hook.Count))
	}

	trustRcodes := make(map[int]bool)
	for _, rc := range args.TrustRcode {
		trustRcodes[rc] = true
	}

	// Initialize local resolver (PTR + forward A/AAAA from hosts/lease files and [hosts] config)
	autoDetect := len(args.LeaseFile) == 0 && len(args.HostsFile) == 0
	ptr := newPTRResolver(args.LeaseFile, args.HostsFile, autoDetect, args.Hosts, logger)
	if ptr != nil {
		allHostsFiles := append(ptr.hostsFiles, ptr.autoHostsFiles...)
		logInfoLocalResolver(logger,
			strings.Join(ptr.leaseFiles, ","),
			strings.Join(allHostsFiles, ","),
			len(args.Hosts),
			args.BogusPriv)
	} else if args.BogusPriv {
		logger.Infow("bogus-priv enabled (no lease/hosts files, private PTR returns NXDOMAIN)")
	}

	handler := &miniHandler{
		logger:           logger,
		localForward:     localFwd,
		cnForward:        cnFwd,
		dnsCache:         cachePlug,
		forceFallMatcher: ffMatcher,
		aaaaMode:         args.AAAA,
		trustRcodes:      trustRcodes,
		lite:             args.Lite == "yes",
		bogusPriv:        args.BogusPriv,
		blockSVCB:        args.BlockSVCB,
		ptrResolver:      ptr,
		pplogReporter:    pplogReporter,
		pplogLevel:       args.PPLogLevel,
		hookFailed:       hookFailed,
	}

	// Start servers manually
	var udpConns []net.PacketConn
	var tcpListeners []net.Listener
	var serverWg sync.WaitGroup

	for _, addr := range args.Listen {
		addr := addr
		logInfoListen(logger, addr)
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			logErrorListen(logger, "udp", addr, err)
			continue
		}
		uconn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			logErrorListen(logger, "udp", addr, err)
			continue
		}

		tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			logErrorListen(logger, "tcp", addr, err)
			uconn.Close()
			continue
		}
		tconn, err := net.ListenTCP("tcp", tcpAddr)
		if err != nil {
			logErrorListen(logger, "tcp", addr, err)
			uconn.Close()
			continue
		}
		// Append only after both UDP and TCP are confirmed; otherwise a
		// failed TCP listen would leave the (already closed) UDP conn in
		// the slice and the shutdown path would Close() it a second time.
		udpConns = append(udpConns, uconn)
		tcpListeners = append(tcpListeners, tconn)

		// Serve routines
		serverWg.Add(2)
		go func() {
			defer serverWg.Done()
			server.ServeUDP(uconn, handler, server.UDPServerOpts{Logger: logger})
		}()
		go func() {
			defer serverWg.Done()
			server.ServeTCP(tconn, handler, server.TCPServerOpts{Logger: logger, IdleTimeout: 3 * time.Second})
		}()
	}

	if len(udpConns) == 0 && len(tcpListeners) == 0 {
		logger.Fatalw("failed to listen on any address, exiting")
	}

	// Graceful shutdown
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	logger.Infow("signal received, shutting down", mlog.String("signal", sig.String()), mlog.Duration("timeout", shutdownTimeout))
	// Second signal forces immediate exit so a hung handler can't trap us.
	go func() {
		s := <-sigChan
		logger.Errorw("second signal received, force exit", mlog.String("signal", s.String()))
		os.Exit(1)
	}()

	// Stop hook monitor
	if hookCancel != nil {
		hookCancel()
	}

	// Close listeners to stop accepting new queries
	for _, uconn := range udpConns {
		uconn.Close()
	}
	for _, tconn := range tcpListeners {
		tconn.Close()
	}

	// Wait for in-flight handlers to drain with timeout
	shutdownDone := make(chan struct{})
	go func() {
		serverWg.Wait()
		close(shutdownDone)
	}()
	select {
	case <-shutdownDone:
	case <-time.After(shutdownTimeout):
		logger.Warnw("shutdown timeout reached, forcing exit")
	}

	// Close remaining resources
	for _, u := range tryLocalUpstreams {
		u.Close()
	}
	for _, u := range tryCNUpstreams {
		u.Close()
	}
	cachePlug.Close()
	if pplogReporter != nil {
		pplogReporter.Close()
	}
	// Wait for any hook-spawned command goroutines so we don't log into
	// a closed logger after Close() below. Cap this wait so a wedged
	// exec script cannot indefinitely block shutdown — shutdownCtx was
	// already cancelled above, which should kill any live child process.
	if hookMon != nil {
		hookWait := make(chan struct{})
		go func() {
			hookMon.Wait()
			close(hookWait)
		}()
		select {
		case <-hookWait:
		case <-time.After(shutdownTimeout):
			logger.Warnw("hook shutdown timeout reached, forcing exit")
		}
	}
	logger.Infow("shutdown complete")
	logger.Close()
}

func initTimezone() {
	if _, err := time.LoadLocation("Asia/Shanghai"); err == nil {
		return
	}
	time.Local = time.FixedZone("UTC+8", 8*60*60)
}

// isDaemonFlagArg reports whether arg is any form of the -d boolean flag
// recognized by Go's flag package (-d, --d, -d=<bool>, --d=<bool>). We
// strip every form — not just the "true" variants — so that the forked
// child never inherits a -d anything and cannot recursively fork. Any
// value form that set Daemon=false would never have reached this branch
// anyway, so filtering them too is harmless.
func isDaemonFlagArg(arg string) bool {
	if arg == "-d" || arg == "--d" {
		return true
	}
	return strings.HasPrefix(arg, "-d=") || strings.HasPrefix(arg, "--d=")
}

// formatUpstreamAddr normalizes an upstream DNS string into a URL that
// upstream.NewUpstream accepts: it adds udp:// when no scheme is present and
// fills in the default port 53 when missing. Bare IP literals — including
// unbracketed IPv6 like "::1" — take a fast path because url.Parse cannot
// round-trip udp://::1 (RFC 3986 requires IPv6 hosts to be bracketed).
func formatUpstreamAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if !strings.Contains(addr, "://") && !strings.ContainsRune(addr, '[') {
		if ip, err := netip.ParseAddr(addr); err == nil {
			return "udp://" + net.JoinHostPort(ip.String(), "53")
		}
	}
	if !strings.Contains(addr, "://") {
		addr = "udp://" + addr
	} else {
		// Unbracketed IPv6 literals after the scheme (e.g. "udp://::1",
		// "udp://fe80::1") confuse url.Parse — Host captures the whole
		// "::1" but Hostname() returns garbage like ":" because the parser
		// treats the first colon as the user/port separator. Bracket the
		// host portion up-front so the downstream url.Parse sees a valid
		// RFC 3986 authority. We only bracket when the host parses as a
		// real IPv6 address; plain hostnames with a single colon (host:port)
		// are left untouched.
		addr = bracketIPv6InURL(addr)
	}
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" {
		return addr
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		host := u.Hostname()
		u.Host = net.JoinHostPort(host, "53")
		addr = u.String()
	}
	return addr
}

// bracketIPv6InURL rewrites "scheme://<unbracketed-ipv6>[...]" to
// "scheme://[<ipv6>][...]" when the authority begins with a parseable
// IPv6 literal. Inputs without a scheme, already-bracketed hosts, or hosts
// that are not valid IPv6 addresses are returned unchanged.
func bracketIPv6InURL(addr string) string {
	schemeEnd := strings.Index(addr, "://")
	if schemeEnd < 0 {
		return addr
	}
	head := addr[:schemeEnd+3]
	rest := addr[schemeEnd+3:]
	if rest == "" || rest[0] == '[' {
		return addr
	}
	// Isolate the authority (up to the first path/query/fragment char).
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority := rest[:end]
	suffix := rest[end:]
	// A single colon is host:port; two or more suggest IPv6. Delegate the
	// final decision to netip so we only bracket real IPv6 literals.
	if strings.Count(authority, ":") < 2 {
		return addr
	}
	if ip, err := netip.ParseAddr(authority); err == nil {
		return head + "[" + ip.String() + "]" + suffix
	}
	return addr
}
