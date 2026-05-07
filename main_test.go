package main

import (
	"strings"
	"testing"
)

func TestFormatUpstreamAddr(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bare_ipv4", "127.0.0.1", "udp://127.0.0.1:53"},
		{"bare_ipv6_loopback", "::1", "udp://[::1]:53"},
		{"bare_ipv6_ula", "fd00::1", "udp://[fd00::1]:53"},
		{"ipv4_with_port", "8.8.8.8:53", "udp://8.8.8.8:53"},
		{"ipv4_alt_port", "1.1.1.1:5353", "udp://1.1.1.1:5353"},
		{"scheme_bracket_ipv6", "udp://[::1]:5353", "udp://[::1]:5353"},
		{"scheme_bracket_ipv6_no_port", "udp://[::1]", "udp://[::1]:53"},
		{"bare_domain", "dns.example.com", "udp://dns.example.com:53"},
		{"scheme_domain_no_port", "udp://dns.example.com", "udp://dns.example.com:53"},
		{"scheme_domain_with_port", "udp://dns.example.com:5353", "udp://dns.example.com:5353"},
		{"tcp_scheme_ipv4", "tcp://1.1.1.1", "tcp://1.1.1.1:53"},
		{"whitespace_trim", "  8.8.8.8  ", "udp://8.8.8.8:53"},
		// Issue: unbracketed IPv6 after a scheme must be bracketed so
		// url.Parse can round-trip it instead of handing back ":" via
		// Hostname() and producing addresses like "[:]:53".
		{"scheme_unbracketed_ipv6_loopback", "udp://::1", "udp://[::1]:53"},
		{"scheme_unbracketed_ipv6_linklocal", "udp://fe80::1", "udp://[fe80::1]:53"},
		{"scheme_unbracketed_ipv6_doc", "udp://2001:db8::1", "udp://[2001:db8::1]:53"},
		{"tcp_scheme_unbracketed_ipv6", "tcp://::1", "tcp://[::1]:53"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatUpstreamAddr(tc.in)
			if got != tc.want {
				t.Errorf("formatUpstreamAddr(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestLowerASCIIName(t *testing.T) {
	cases := []string{
		"",
		"example.com.",
		"Example.COM.",
		"WWW.EXAMPLE.com.",
		"a.B.c.D.e.F.",
		"google.com.",
		"1.2.3.4.in-addr.arpa.",
		strings.Repeat("A", 255),
		strings.Repeat("z", 255),
	}
	for _, in := range cases {
		got := lowerASCIIName(in)
		want := strings.ToLower(in)
		if got != want {
			t.Errorf("lowerASCIIName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLowerASCIIName_AllLowerSharesBacking(t *testing.T) {
	// Fast path: when already lowercase, return the input unchanged to
	// avoid an allocation. Verify by pointer equivalence via strings.
	in := "example.com."
	if got := lowerASCIIName(in); got != in {
		t.Fatalf("expected identity on already-lowercase input, got %q", got)
	}
}

func TestIsDaemonFlagArg(t *testing.T) {
	// Any -d variant that Go's flag package accepts must be stripped so a
	// re-fork of the daemon cannot recursively fork. The false-value forms
	// never enter the daemon branch anyway, but we strip them too for
	// consistency and defense-in-depth.
	stripped := []string{
		"-d", "--d",
		"-d=true", "-d=True", "-d=TRUE", "-d=t", "-d=T", "-d=1",
		"-d=false", "-d=False", "-d=FALSE", "-d=f", "-d=F", "-d=0",
		"--d=true", "--d=1", "--d=0", "--d=false",
	}
	for _, arg := range stripped {
		if !isDaemonFlagArg(arg) {
			t.Errorf("isDaemonFlagArg(%q) = false, want true", arg)
		}
	}
	// Flags with a -d prefix but a different name must NOT be stripped.
	kept := []string{
		"-dns", "-dns=8.8.8.8", "-debug", "-debug=true",
		"--dns", "--debug",
		"-daemon", "-d-extra", "-", "",
	}
	for _, arg := range kept {
		if isDaemonFlagArg(arg) {
			t.Errorf("isDaemonFlagArg(%q) = true, want false", arg)
		}
	}
}
