package main

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// stripAnsi removes ANSI escape sequences so that colored output can be
// compared against a plain expected string.
func stripAnsi(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				i = j + 1
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// containsAnsi returns true if s contains any ANSI escape sequence.
func containsAnsi(s string) bool {
	return strings.Contains(s, "\x1b[")
}

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func TestAppendQueryLog_AllCases(t *testing.T) {
	v4 := mustAddr("192.168.5.105")
	v6 := mustAddr("2001:db8::1")
	boomErr := errors.New("boom")

	tests := []struct {
		name  string
		q     queryLog
		plain string // expected output with colors stripped
	}{
		// ---- local ----
		{
			name: "local NOERROR",
			q: queryLog{
				route: "local", client: v4, upstream: "udp://223.5.5.5:53",
				qtype: dns.TypeA, domain: "qq.com.", rcode: "NOERROR",
				dur: 8 * time.Millisecond, hasDur: true,
			},
			plain: "192.168.5.105 local -> udp://223.5.5.5:53 A qq.com. NOERROR 8ms",
		},
		{
			name: "local NODATA",
			q: queryLog{
				route: "local", client: v4, upstream: "udp://192.168.5.23:53",
				qtype: dns.TypeA, domain: "6.ipw.cn.", rcode: "NODATA",
				dur: 3 * time.Millisecond, hasDur: true,
			},
			plain: "192.168.5.105 local -> udp://192.168.5.23:53 A 6.ipw.cn. NODATA 3ms",
		},
		{
			name: "local NODATA(trusted) AAAA",
			q: queryLog{
				route: "local", client: v4, upstream: "udp://1.1.1.1:53",
				qtype: dns.TypeAAAA, domain: "example.com.", rcode: "NODATA(trusted)",
				dur: 12 * time.Millisecond, hasDur: true,
			},
			plain: "192.168.5.105 local -> udp://1.1.1.1:53 AAAA example.com. NODATA(trusted) 12ms",
		},
		{
			name: "local NXDOMAIN",
			q: queryLog{
				route: "local", client: v4, upstream: "udp://223.5.5.5:53",
				qtype: dns.TypeA, domain: "www.qq.comww.", rcode: "NXDOMAIN",
				dur: 66 * time.Millisecond, hasDur: true,
			},
			plain: "192.168.5.105 local -> udp://223.5.5.5:53 A www.qq.comww. NXDOMAIN 66ms",
		},
		{
			name: "local SERVFAIL trusted",
			q: queryLog{
				route: "local", client: v4, upstream: "udp://8.8.8.8:53",
				qtype: dns.TypeA, domain: "broken.example.", rcode: "SERVFAIL(trusted)",
				dur: 5 * time.Millisecond, hasDur: true,
			},
			plain: "192.168.5.105 local -> udp://8.8.8.8:53 A broken.example. SERVFAIL(trusted) 5ms",
		},
		{
			name: "local timeout with err",
			q: queryLog{
				route: "local", client: v4, upstream: "timeout/err",
				qtype: dns.TypeA, domain: "slow.example.", rcode: "timeout/error",
				dur: 2000 * time.Millisecond, hasDur: true, err: boomErr,
			},
			plain: "192.168.5.105 local -> timeout/err A slow.example. timeout/error 2000ms boom",
		},
		{
			name: "local REFUSED",
			q: queryLog{
				route: "local", client: v4, upstream: "udp://1.1.1.1:53",
				qtype: dns.TypeA, domain: "refused.example.", rcode: "REFUSED",
				dur: 4 * time.Millisecond, hasDur: true,
			},
			plain: "192.168.5.105 local -> udp://1.1.1.1:53 A refused.example. REFUSED 4ms",
		},

		// ---- fall / force_fall / hook_fall ----
		{
			name: "fall NODATA",
			q: queryLog{
				route: "fall", client: v4, upstream: "udp://119.29.29.29:53",
				qtype: dns.TypeA, domain: "6.ipw.cn.", rcode: "NODATA",
				dur: 13 * time.Millisecond, hasDur: true,
			},
			plain: "192.168.5.105 fall -> udp://119.29.29.29:53 A 6.ipw.cn. NODATA 13ms",
		},
		{
			name: "fall NOERROR",
			q: queryLog{
				route: "fall", client: v4, upstream: "udp://119.29.29.29:53",
				qtype: dns.TypeA, domain: "example.com.", rcode: "NOERROR",
				dur: 20 * time.Millisecond, hasDur: true,
			},
			plain: "192.168.5.105 fall -> udp://119.29.29.29:53 A example.com. NOERROR 20ms",
		},
		{
			name: "fall NXDOMAIN",
			q: queryLog{
				route: "fall", client: v4, upstream: "udp://119.29.29.29:53",
				qtype: dns.TypeA, domain: "www.qq.comww.", rcode: "NXDOMAIN",
				dur: 34 * time.Millisecond, hasDur: true,
			},
			plain: "192.168.5.105 fall -> udp://119.29.29.29:53 A www.qq.comww. NXDOMAIN 34ms",
		},
		{
			name: "fall error",
			q: queryLog{
				route: "fall", client: v4, upstream: "timeout/err",
				qtype: dns.TypeA, domain: "x.example.", rcode: "NXDOMAIN or timeout",
				dur: 100 * time.Millisecond, hasDur: true, err: boomErr,
			},
			plain: "192.168.5.105 fall -> timeout/err A x.example. NXDOMAIN or timeout 100ms boom",
		},
		{
			name: "force_fall NOERROR",
			q: queryLog{
				route: "force_fall", client: v4, upstream: "udp://119.29.29.29:53",
				qtype: dns.TypeA, domain: "forced.example.", rcode: "NOERROR",
				dur: 15 * time.Millisecond, hasDur: true,
			},
			plain: "192.168.5.105 force_fall -> udp://119.29.29.29:53 A forced.example. NOERROR 15ms",
		},
		{
			name: "hook_fall NOERROR",
			q: queryLog{
				route: "hook_fall", client: v4, upstream: "udp://119.29.29.29:53",
				qtype: dns.TypeA, domain: "hooked.example.", rcode: "NOERROR",
				dur: 18 * time.Millisecond, hasDur: true,
			},
			plain: "192.168.5.105 hook_fall -> udp://119.29.29.29:53 A hooked.example. NOERROR 18ms",
		},

		// ---- cache ----
		{
			name: "cache NOERROR",
			q: queryLog{
				route: "cache", client: v4, qtype: dns.TypeA,
				domain: "qq.com.", rcode: "NOERROR",
			},
			plain: "192.168.5.105 cache A qq.com. NOERROR",
		},
		{
			name: "cache NODATA",
			q: queryLog{
				route: "cache", client: v4, qtype: dns.TypeAAAA,
				domain: "noipv6.example.", rcode: "NODATA",
			},
			plain: "192.168.5.105 cache AAAA noipv6.example. NODATA",
		},
		{
			name: "cache NXDOMAIN",
			q: queryLog{
				route: "cache", client: v4, qtype: dns.TypeA,
				domain: "nope.example.", rcode: "NXDOMAIN",
			},
			plain: "192.168.5.105 cache A nope.example. NXDOMAIN",
		},

		// ---- hosts / local-ptr / bogus-priv / block ----
		{
			name: "hosts",
			q: queryLog{
				route: "hosts", client: v4, qtype: dns.TypeA,
				domain: "localhost.", rcode: "NOERROR",
			},
			plain: "192.168.5.105 hosts A localhost. NOERROR",
		},
		{
			name: "local-ptr with extra hostname",
			q: queryLog{
				route: "local-ptr", client: v4, qtype: dns.TypePTR,
				domain: "1.1.168.192.in-addr.arpa.", rcode: "NOERROR",
				extra: "router.lan",
			},
			plain: "192.168.5.105 local-ptr PTR 1.1.168.192.in-addr.arpa. NOERROR router.lan",
		},
		{
			name: "bogus-priv",
			q: queryLog{
				route: "bogus-priv", client: v4, qtype: dns.TypePTR,
				domain: "5.5.168.192.in-addr.arpa.", rcode: "NXDOMAIN",
			},
			plain: "192.168.5.105 bogus-priv PTR 5.5.168.192.in-addr.arpa. NXDOMAIN",
		},
		{
			name: "block aaaa",
			q: queryLog{
				route: "block", client: v4, qtype: dns.TypeAAAA,
				domain: "foo.example.", rcode: "BLOCKED",
			},
			plain: "192.168.5.105 block AAAA foo.example. BLOCKED",
		},

		// ---- IPv6 client ----
		{
			name: "local IPv6 client",
			q: queryLog{
				route: "local", client: v6, upstream: "udp://1.1.1.1:53",
				qtype: dns.TypeA, domain: "example.com.", rcode: "NOERROR",
				dur: 7 * time.Millisecond, hasDur: true,
			},
			plain: "2001:db8::1 local -> udp://1.1.1.1:53 A example.com. NOERROR 7ms",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name+"/plain", func(t *testing.T) {
			got := string(appendQueryLog(nil, false, &tc.q))
			if got != tc.plain {
				t.Errorf("plain mismatch\n got: %q\nwant: %q", got, tc.plain)
			}
			if containsAnsi(got) {
				t.Errorf("plain output must not contain ANSI escapes: %q", got)
			}
		})
		t.Run(tc.name+"/color", func(t *testing.T) {
			got := string(appendQueryLog(nil, true, &tc.q))
			if !containsAnsi(got) {
				t.Errorf("color output must contain ANSI escapes: %q", got)
			}
			if stripAnsi(got) != tc.plain {
				t.Errorf("color stripped mismatch\n got: %q\nwant: %q", stripAnsi(got), tc.plain)
			}
			opens := strings.Count(got, "\x1b[") - strings.Count(got, "\x1b[0m")
			closes := strings.Count(got, "\x1b[0m")
			if opens != closes {
				t.Errorf("unbalanced color codes: %d opens vs %d resets in %q", opens, closes, got)
			}
		})
	}
}

func TestAppendQueryLog_RcodeColors(t *testing.T) {
	cases := map[string]string{
		"NOERROR":             clrNoerror,
		"NODATA":              clrNodata,
		"NODATA(trusted)":     clrNodata,
		"NXDOMAIN":            clrNxdomain,
		"SERVFAIL":            clrServfail,
		"REFUSED":             clrRefused,
		"BLOCKED":             clrBlocked,
		"timeout/error":       clrServfail,
		"NXDOMAIN or timeout": clrNxdomain,
		"FORMERR":             clrRcodeDef,
	}
	for rcode, want := range cases {
		got := rcodeColor(rcode)
		if got != want {
			t.Errorf("rcodeColor(%q) = %q, want %q", rcode, got, want)
		}
	}
}

func TestAppendQueryLog_NoExtras(t *testing.T) {
	q := queryLog{
		route:  "hosts",
		client: mustAddr("10.0.0.1"),
		qtype:  dns.TypeA,
		domain: "a.",
		rcode:  "NOERROR",
	}
	got := string(appendQueryLog(nil, false, &q))
	want := "10.0.0.1 hosts A a. NOERROR"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// --- startup / info line helpers ---

// buildNoTs renders what the InfoBuild/DebugBuild closure would emit,
// without the timestamp prefix, so each info helper's body can be asserted
// in isolation.
func runInfoBuild(fn func(buf []byte, color bool) []byte, color bool) string {
	return string(fn(nil, color))
}

func TestInfoLines_Plain(t *testing.T) {
	tests := []struct {
		name  string
		build func(buf []byte, color bool) []byte
		plain string
	}{
		{
			name: "available memory",
			build: func(buf []byte, color bool) []byte {
				buf = append(buf, "available memory "...)
				buf = appendHLInt(buf, color, clrValue, 11942)
				buf = append(buf, ' ')
				buf = appendHL(buf, color, clrUnit, "MB")
				return buf
			},
			plain: "available memory 11942 MB",
		},
		{
			name: "local resolver enabled empty lease",
			build: func(buf []byte, color bool) []byte {
				leaseFiles := "-"
				hostsFiles := "/etc/hosts"
				buf = append(buf, "local resolver enabled lease_files "...)
				buf = appendHL(buf, color, clrValue, leaseFiles)
				buf = append(buf, " hosts_files "...)
				buf = appendHL(buf, color, clrValue, hostsFiles)
				buf = append(buf, " static_hosts "...)
				buf = appendHLInt(buf, color, clrValue, 0)
				buf = append(buf, " boguspriv "...)
				buf = appendHL(buf, color, clrValue, "true")
				return buf
			},
			plain: "local resolver enabled lease_files - hosts_files /etc/hosts static_hosts 0 boguspriv true",
		},
		{
			name: "listen addr",
			build: func(buf []byte, color bool) []byte {
				buf = append(buf, "listen: "...)
				buf = appendHL(buf, color, clrAddr, "127.0.0.1:53")
				return buf
			},
			plain: "listen: 127.0.0.1:53",
		},
		{
			name: "ptr loaded",
			build: func(buf []byte, color bool) []byte {
				buf = append(buf, "[ptr] loaded records ptr "...)
				buf = appendHLInt(buf, color, clrValue, 6)
				buf = append(buf, " fwd "...)
				buf = appendHLInt(buf, color, clrValue, 123)
				return buf
			},
			plain: "[ptr] loaded records ptr 6 fwd 123",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name+"/plain", func(t *testing.T) {
			got := runInfoBuild(tc.build, false)
			if got != tc.plain {
				t.Errorf("plain mismatch\n got: %q\nwant: %q", got, tc.plain)
			}
			if containsAnsi(got) {
				t.Errorf("plain contains ANSI: %q", got)
			}
			if strings.Contains(got, "=") {
				t.Errorf("plain contains '=' sign: %q", got)
			}
		})
		t.Run(tc.name+"/color", func(t *testing.T) {
			got := runInfoBuild(tc.build, true)
			if !containsAnsi(got) {
				t.Errorf("color missing ANSI: %q", got)
			}
			if stripAnsi(got) != tc.plain {
				t.Errorf("color stripped mismatch\n got: %q\nwant: %q", stripAnsi(got), tc.plain)
			}
			opens := strings.Count(got, "\x1b[") - strings.Count(got, "\x1b[0m")
			closes := strings.Count(got, "\x1b[0m")
			if opens != closes {
				t.Errorf("unbalanced color codes: %d vs %d in %q", opens, closes, got)
			}
		})
	}
}
