package main

import (
	"errors"
	"net/netip"
	"strconv"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/kkkgo/mini-ppdns/mlog"
)

// rootErrMsg walks err.Unwrap() chain to its terminal cause and returns its
// message. Used to strip the "listen udp 1.2.3.4:53: bind: " wrapping from
// net.OpError and surface only "cannot assign requested address".
func rootErrMsg(err error) string {
	if err == nil {
		return ""
	}
	for {
		u := errors.Unwrap(err)
		if u == nil {
			return err.Error()
		}
		err = u
	}
}

// ANSI color escape sequences used for debug query log lines.
// Emitted only when the logger output is a terminal.
const (
	clrReset    = "\x1b[0m"
	clrRoute    = "\x1b[36m"   // cyan
	clrClient   = "\x1b[33m"   // yellow
	clrArrow    = "\x1b[90m"   // gray
	clrUpstream = "\x1b[35m"   // magenta
	clrQtype    = "\x1b[34m"   // blue
	clrDomain   = "\x1b[1;37m" // bold white
	clrDur      = "\x1b[90m"   // gray
	clrErr      = "\x1b[91m"   // bright red
	clrExtra    = "\x1b[96m"   // bright cyan
	clrNoerror  = "\x1b[32m"   // green
	clrNodata   = "\x1b[33m"   // yellow
	clrNxdomain = "\x1b[31m"   // red
	clrServfail = "\x1b[91m"   // bright red
	clrRefused  = "\x1b[95m"   // bright magenta
	clrBlocked  = "\x1b[90m"   // gray
	clrRcodeDef = "\x1b[37m"   // white
)

// rcodeColor returns an ANSI color escape for the given rcode label.
// Matches on the leading alphabetic prefix of the label so variants such
// as "NODATA(trusted)" or "SERVFAIL" map to the right color.
func rcodeColor(rcode string) string {
	switch {
	case hasPrefix(rcode, "NOERROR"):
		return clrNoerror
	case hasPrefix(rcode, "NODATA"):
		return clrNodata
	case hasPrefix(rcode, "NXDOMAIN"):
		return clrNxdomain
	case hasPrefix(rcode, "SERVFAIL"):
		return clrServfail
	case hasPrefix(rcode, "REFUSED"):
		return clrRefused
	case hasPrefix(rcode, "BLOCKED"):
		return clrBlocked
	case hasPrefix(rcode, "timeout"):
		return clrServfail
	}
	return clrRcodeDef
}

// hasPrefix is a local, allocation-free prefix check.
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// queryLog describes a single DNS debug log line. All fields are optional
// except route+client+qtype+domain+rcode; empty values are skipped.
type queryLog struct {
	route    string
	client   netip.Addr
	upstream string // empty to skip upstream segment
	qtype    uint16
	domain   string
	rcode    string
	dur      time.Duration
	hasDur   bool
	err      error
	extra    string // optional trailing info (e.g. PTR target)
}

func appendQueryLog(buf []byte, color bool, q *queryLog) []byte {
	// client
	if color {
		buf = append(buf, clrClient...)
	}
	buf = q.client.AppendTo(buf)
	if color {
		buf = append(buf, clrReset...)
	}
	buf = append(buf, ' ')

	// route
	if color {
		buf = append(buf, clrRoute...)
		buf = append(buf, q.route...)
		buf = append(buf, clrReset...)
	} else {
		buf = append(buf, q.route...)
	}

	// optional upstream segment: " -> <upstream>"
	if q.upstream != "" {
		buf = append(buf, ' ')
		if color {
			buf = append(buf, clrArrow...)
		}
		buf = append(buf, "->"...)
		if color {
			buf = append(buf, clrReset...)
		}
		buf = append(buf, ' ')
		if color {
			buf = append(buf, clrUpstream...)
		}
		buf = append(buf, q.upstream...)
		if color {
			buf = append(buf, clrReset...)
		}
	}

	// qtype
	buf = append(buf, ' ')
	if color {
		buf = append(buf, clrQtype...)
	}
	buf = append(buf, dns.TypeToString[q.qtype]...)
	if color {
		buf = append(buf, clrReset...)
	}

	// domain
	buf = append(buf, ' ')
	if color {
		buf = append(buf, clrDomain...)
	}
	buf = append(buf, q.domain...)
	if color {
		buf = append(buf, clrReset...)
	}

	// rcode
	buf = append(buf, ' ')
	if color {
		buf = append(buf, rcodeColor(q.rcode)...)
		buf = append(buf, q.rcode...)
		buf = append(buf, clrReset...)
	} else {
		buf = append(buf, q.rcode...)
	}

	// duration
	if q.hasDur {
		buf = append(buf, ' ')
		if color {
			buf = append(buf, clrDur...)
		}
		buf = strconv.AppendInt(buf, q.dur.Milliseconds(), 10)
		buf = append(buf, "ms"...)
		if color {
			buf = append(buf, clrReset...)
		}
	}

	// extra (e.g. PTR target)
	if q.extra != "" {
		buf = append(buf, ' ')
		if color {
			buf = append(buf, clrExtra...)
		}
		buf = append(buf, q.extra...)
		if color {
			buf = append(buf, clrReset...)
		}
	}

	// error
	if q.err != nil {
		buf = append(buf, ' ')
		if color {
			buf = append(buf, clrErr...)
		}
		buf = append(buf, q.err.Error()...)
		if color {
			buf = append(buf, clrReset...)
		}
	}
	return buf
}

// logQuery is the common entry point — callers build a queryLog value
// and the helper does the debug-level gating + buffered writes.
func logQuery(l *mlog.Logger, q *queryLog) {
	l.DebugBuild(func(buf []byte, color bool) []byte {
		return appendQueryLog(buf, color, q)
	})
}

// --- Startup / maintenance info lines ---
//
// These use no `=` signs; key ANSI colors highlight the interesting values
// (memory amounts, file paths, addresses, counts). Colors are skipped when
// the output is not a terminal.

const (
	clrValue = "\x1b[1;37m" // bold white — highlighted values
	clrUnit  = "\x1b[32m"   // green — units like "MB"
	clrAddr  = "\x1b[1;35m" // bold magenta — listen addresses
)

func appendHL(buf []byte, color bool, clr, s string) []byte {
	if color {
		buf = append(buf, clr...)
		buf = append(buf, s...)
		buf = append(buf, clrReset...)
	} else {
		buf = append(buf, s...)
	}
	return buf
}

func appendHLInt(buf []byte, color bool, clr string, n int64) []byte {
	if color {
		buf = append(buf, clr...)
	}
	buf = strconv.AppendInt(buf, n, 10)
	if color {
		buf = append(buf, clrReset...)
	}
	return buf
}

// logInfoAvailableMemory → "available memory <MB> MB" (MB + number colored).
func logInfoAvailableMemory(l *mlog.Logger, mb uint64) {
	l.InfoBuild(func(buf []byte, color bool) []byte {
		buf = append(buf, "available memory "...)
		buf = appendHLInt(buf, color, clrValue, int64(mb))
		buf = append(buf, ' ')
		buf = appendHL(buf, color, clrUnit, "MB")
		return buf
	})
}

// logInfoLocalResolver → "local resolver enabled lease_files <...> hosts_files <...> static_hosts <n> boguspriv <bool>"
// Empty string values render as "-" to avoid dangling whitespace.
func logInfoLocalResolver(l *mlog.Logger, leaseFiles, hostsFiles string, staticHosts int, boguspriv bool) {
	if leaseFiles == "" {
		leaseFiles = "-"
	}
	if hostsFiles == "" {
		hostsFiles = "-"
	}
	l.InfoBuild(func(buf []byte, color bool) []byte {
		buf = append(buf, "local resolver enabled lease_files "...)
		buf = appendHL(buf, color, clrValue, leaseFiles)
		buf = append(buf, " hosts_files "...)
		buf = appendHL(buf, color, clrValue, hostsFiles)
		buf = append(buf, " static_hosts "...)
		buf = appendHLInt(buf, color, clrValue, int64(staticHosts))
		buf = append(buf, " boguspriv "...)
		if boguspriv {
			buf = appendHL(buf, color, clrValue, "true")
		} else {
			buf = appendHL(buf, color, clrValue, "false")
		}
		return buf
	})
}

// logErrorListen → "listen <proto>://<addr> err: <root>" with proto+addr and
// root cause highlighted. Used for both resolve and bind failures.
func logErrorListen(l *mlog.Logger, proto, addr string, err error) {
	msg := rootErrMsg(err)
	l.ErrorBuild(func(buf []byte, color bool) []byte {
		buf = append(buf, "listen "...)
		if color {
			buf = append(buf, clrAddr...)
		}
		buf = append(buf, proto...)
		buf = append(buf, "://"...)
		buf = append(buf, addr...)
		if color {
			buf = append(buf, clrReset...)
		}
		buf = append(buf, " err: "...)
		if color {
			buf = append(buf, clrErr...)
		}
		buf = append(buf, msg...)
		if color {
			buf = append(buf, clrReset...)
		}
		return buf
	})
}

// logInfoPPLogEnabled → "pplog enabled server <addr> level <n>" with values highlighted.
func logInfoPPLogEnabled(l *mlog.Logger, server string, level int) {
	l.InfoBuild(func(buf []byte, color bool) []byte {
		buf = append(buf, "pplog enabled server "...)
		buf = appendHL(buf, color, clrAddr, server)
		buf = append(buf, " level "...)
		buf = appendHLInt(buf, color, clrValue, int64(level))
		return buf
	})
}

// logInfoListen → "listen: <addr>" with addr highlighted.
func logInfoListen(l *mlog.Logger, addr string) {
	l.InfoBuild(func(buf []byte, color bool) []byte {
		buf = append(buf, "listen: "...)
		buf = appendHL(buf, color, clrAddr, addr)
		return buf
	})
}

// logDebugPTRLoaded → "[ptr] loaded records ptr <n> fwd <n>" with counts highlighted.
func logDebugPTRLoaded(l *mlog.Logger, ptrCount, fwdCount int) {
	l.DebugBuild(func(buf []byte, color bool) []byte {
		buf = append(buf, "[ptr] loaded records ptr "...)
		buf = appendHLInt(buf, color, clrValue, int64(ptrCount))
		buf = append(buf, " fwd "...)
		buf = appendHLInt(buf, color, clrValue, int64(fwdCount))
		return buf
	})
}

// logLocalQuery logs a main-DNS query result.
func logLocalQuery(l *mlog.Logger, client netip.Addr, upstream string, qtype uint16, domain, rcode string, dur time.Duration, err error) {
	logQuery(l, &queryLog{
		route:    "local",
		client:   client,
		upstream: upstream,
		qtype:    qtype,
		domain:   domain,
		rcode:    rcode,
		dur:      dur,
		hasDur:   true,
		err:      err,
	})
}

// logFallQuery logs a fallback-path query result. route is one of
// "fall", "force_fall", "hook_fall".
func logFallQuery(l *mlog.Logger, route string, client netip.Addr, upstream string, qtype uint16, domain, rcode string, dur time.Duration, err error) {
	logQuery(l, &queryLog{
		route:    route,
		client:   client,
		upstream: upstream,
		qtype:    qtype,
		domain:   domain,
		rcode:    rcode,
		dur:      dur,
		hasDur:   true,
		err:      err,
	})
}
