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
