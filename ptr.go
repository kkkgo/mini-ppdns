package main

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kkkgo/mini-ppdns/mlog"
)

// ptrResolver maintains an in-memory lookup table built from DHCP lease
// files (e.g. /tmp/dhcp.leases) and hosts files (e.g. /etc/hosts).
// It supports both reverse (PTR) and forward (A/AAAA) lookups.
// File changes are checked lazily on queries with a minimum 5-second
// interval between checks, avoiding unnecessary I/O.
type ptrResolver struct {
	leaseFiles []string
	hostsFiles []string // explicitly configured; watched for hot-reload
	// autoHostsFiles are auto-detected hosts files (e.g. /etc/hosts when no
	// hosts_file is configured). Loaded once at startup; never hot-reloaded.
	autoHostsFiles []string

	mu       sync.RWMutex
	ptrMap   map[string]string   // "132.10.10.10.in-addr.arpa." -> "MiAiSoundbox-L05C"
	fwdMap   map[string][]net.IP // "router.local." -> [10.10.10.1]
	modTimes map[string]time.Time

	// staticFwd/staticPTR hold entries from [hosts] config section.
	// They are never cleared on file reload and always overlay file entries.
	staticFwd map[string][]net.IP // "example.com." -> [1.2.3.4]
	staticPTR map[string]string   // "4.3.2.1.in-addr.arpa." -> "example.com"

	lastCheck atomic.Int64 // unix timestamp of last file check

	logger *mlog.Logger
}

// defaultLeaseFiles are tried when no lease_file is configured.
var defaultLeaseFiles = []string{"/tmp/dhcp.leases", "/tmp/dnsmasq.leases"}

// defaultHostsFiles are tried when no hosts_file is configured.
var defaultHostsFiles = []string{"/etc/hosts"}

// newPTRResolver creates a resolver for local DNS records.
// staticHosts are inline entries from [hosts] config (never cleared on reload).
// If leaseFiles and hostsFiles are both nil (not explicitly configured),
// it auto-detects from default paths.
// Returns nil if no files exist and no static hosts are provided.
func newPTRResolver(leaseFiles, hostsFiles []string, autoDetect bool, staticHosts map[string][]net.IP, logger *mlog.Logger) *ptrResolver {
	var autoHostsFiles []string
	if autoDetect {
		// Auto-detect: only keep files that currently exist.
		// Lease files are dynamic and watched for hot-reload.
		// Default hosts files (e.g. /etc/hosts) are loaded once but not watched.
		for _, f := range defaultLeaseFiles {
			if _, err := os.Stat(f); err == nil {
				leaseFiles = append(leaseFiles, f)
			}
		}
		// Skip auto-detecting default hosts files when [hosts] static entries
		// are explicitly configured — the user's static config is sufficient.
		if len(staticHosts) == 0 {
			for _, f := range defaultHostsFiles {
				if _, err := os.Stat(f); err == nil {
					autoHostsFiles = append(autoHostsFiles, f)
				}
			}
		}
		if len(leaseFiles) == 0 && len(autoHostsFiles) == 0 && len(staticHosts) == 0 {
			return nil // nothing to resolve
		}
	}

	// Build static PTR map from [hosts] entries
	var sFwd map[string][]net.IP
	var sPTR map[string]string
	if len(staticHosts) > 0 {
		sFwd = staticHosts
		sPTR = make(map[string]string, len(staticHosts))
		for domain, ips := range staticHosts {
			for _, ip := range ips {
				ptrName := ipToPTRName(ip.String())
				if ptrName != "" {
					sPTR[ptrName] = strings.TrimSuffix(domain, ".")
				}
			}
		}
	}

	pr := &ptrResolver{
		leaseFiles:     leaseFiles,
		hostsFiles:     hostsFiles,
		autoHostsFiles: autoHostsFiles,
		ptrMap:         make(map[string]string),
		fwdMap:         make(map[string][]net.IP),
		modTimes:       make(map[string]time.Time),
		staticFwd:      sFwd,
		staticPTR:      sPTR,
		logger:         logger,
	}
	pr.reload()
	pr.lastCheck.Store(time.Now().Unix())
	return pr
}

// maybeReload checks file modification times if at least 5 seconds have
// elapsed since the last check. Called on every query.
func (pr *ptrResolver) maybeReload() {
	now := time.Now().Unix()
	last := pr.lastCheck.Load()
	// now < last guards NTP step-backs: a rolled-back clock makes now-last
	// negative, which naively satisfies <5 forever and silently suppresses
	// reloads until wall-clock catches up to last+5. On a rollback we fall
	// through and let the CAS below resync lastCheck to the new epoch.
	if now >= last && now-last < 5 {
		return
	}
	// CAS to avoid concurrent reloads
	if !pr.lastCheck.CompareAndSwap(last, now) {
		return
	}
	if pr.filesChanged() {
		pr.reload()
	}
}

func (pr *ptrResolver) filesChanged() bool {
	allFiles := make([]string, 0, len(pr.leaseFiles)+len(pr.hostsFiles))
	allFiles = append(allFiles, pr.leaseFiles...)
	allFiles = append(allFiles, pr.hostsFiles...)

	// Stat files outside the lock — disk I/O must not block concurrent readers.
	type statResult struct {
		modTime time.Time
		exists  bool
	}
	results := make(map[string]statResult, len(allFiles))
	for _, f := range allFiles {
		info, err := os.Stat(f)
		if err != nil {
			results[f] = statResult{exists: false}
			continue
		}
		results[f] = statResult{modTime: info.ModTime(), exists: true}
	}

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	for _, f := range allFiles {
		res := results[f]
		prev, hadPrev := pr.modTimes[f]
		if !res.exists {
			if hadPrev && !prev.IsZero() {
				return true // file disappeared
			}
			continue
		}
		if !hadPrev || !res.modTime.Equal(prev) {
			return true
		}
	}
	return false
}

func (pr *ptrResolver) reload() {
	newPTR := make(map[string]string)
	newFwd := make(map[string][]net.IP)
	newModTimes := make(map[string]time.Time)

	for _, f := range pr.leaseFiles {
		pr.loadLeaseFile(f, newPTR, newModTimes)
	}
	for _, f := range pr.hostsFiles {
		pr.loadHostsFile(f, newPTR, newFwd, newModTimes)
	}
	// autoHostsFiles are loaded once (no mod-time tracking, not hot-reloaded)
	for _, f := range pr.autoHostsFiles {
		pr.loadHostsFile(f, newPTR, newFwd, nil)
	}

	// Overlay static entries (from [hosts] config) — they always win
	for k, v := range pr.staticPTR {
		newPTR[k] = v
	}
	for k, v := range pr.staticFwd {
		newFwd[k] = v
	}

	pr.mu.Lock()
	pr.ptrMap = newPTR
	pr.fwdMap = newFwd
	pr.modTimes = newModTimes
	pr.mu.Unlock()

	logDebugPTRLoaded(pr.logger, len(newPTR), len(newFwd))
}

// ipToPTRName converts an IPv4 address string to its in-addr.arpa PTR name.
func ipToPTRName(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return ""
	}
	b := addr.As4()
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0])
}

func (pr *ptrResolver) loadLeaseFile(path string, m map[string]string, modTimes map[string]time.Time) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	modTimes[path] = info.ModTime()

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// dnsmasq lease format: timestamp mac ip hostname client-id
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		ip := fields[2]
		hostname := fields[3]
		if hostname == "*" || hostname == "" {
			continue
		}
		ptrName := ipToPTRName(ip)
		if ptrName != "" {
			m[ptrName] = hostname
		}
	}
	if err := scanner.Err(); err != nil {
		pr.logger.Warnw("lease file scan error", mlog.String("path", path), mlog.Err(err))
	}
}

func (pr *ptrResolver) loadHostsFile(path string, ptrMap map[string]string, fwdMap map[string][]net.IP, modTimes map[string]time.Time) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if modTimes != nil {
		modTimes[path] = info.ModTime()
	}

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Remove inline comments
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ipStr := fields[0]
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		// PTR: first hostname is the canonical name (IPv4 only)
		ptrName := ipToPTRName(ipStr)
		if ptrName != "" {
			ptrMap[ptrName] = fields[1]
		}

		// Forward: all hostnames on the line map to this IP
		for _, hostname := range fields[1:] {
			fqdn := strings.ToLower(strings.TrimSuffix(hostname, ".")) + "."
			fwdMap[fqdn] = append(fwdMap[fqdn], ip)
		}
	}
	if err := scanner.Err(); err != nil {
		pr.logger.Warnw("hosts file scan error", mlog.String("path", path), mlog.Err(err))
	}
}

// Lookup returns the hostname for a PTR query name, or "" if not found.
// It lazily checks for file changes (at most once per 5 seconds).
func (pr *ptrResolver) Lookup(ptrName string) string {
	pr.maybeReload()
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return pr.ptrMap[strings.ToLower(ptrName)]
}

// LookupIP returns the IPs for a forward query name, or nil if not found.
// It lazily checks for file changes (at most once per 5 seconds).
func (pr *ptrResolver) LookupIP(name string) []net.IP {
	pr.maybeReload()
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return pr.fwdMap[strings.ToLower(name)]
}

// isPrivatePTR checks if a PTR query name corresponds to a private IP address.
// Covers IPv4 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 and
// IPv6 ULA (fc00::/7) and link-local (fe80::/10).
func isPrivatePTR(qname string) bool {
	qname = strings.ToLower(qname)
	if strings.HasSuffix(qname, ".in-addr.arpa.") {
		trimmed := qname[:len(qname)-len(".in-addr.arpa.")]
		octets, ok := parseIPv4ArpaLabels(trimmed)
		if !ok {
			return false
		}
		addr := netip.AddrFrom4(octets)
		return addr.IsPrivate() || addr.IsLinkLocalUnicast()
	}
	if strings.HasSuffix(qname, ".ip6.arpa.") {
		trimmed := strings.TrimSuffix(qname, ".ip6.arpa.")
		parts := strings.Split(trimmed, ".")
		if len(parts) != 32 {
			return false
		}
		var bytes16 [16]byte
		for i, p := range parts {
			if len(p) != 1 {
				return false
			}
			c := p[0]
			var v byte
			switch {
			case c >= '0' && c <= '9':
				v = c - '0'
			case c >= 'a' && c <= 'f':
				v = c - 'a' + 10
			default:
				return false
			}
			// parts[0] is the lowest nibble; reverse into bytes16.
			byteIdx := 15 - i/2
			if i%2 == 0 {
				bytes16[byteIdx] |= v
			} else {
				bytes16[byteIdx] |= v << 4
			}
		}
		addr := netip.AddrFrom16(bytes16)
		return addr.IsPrivate() || addr.IsLinkLocalUnicast()
	}
	return false
}

// parseIPv4ArpaLabels parses the reversed dotted-octet portion of an
// in-addr.arpa query (e.g. "132.10.10.10") into a big-endian [4]byte.
// It avoids the strings.Split + strconv.Atoi allocations of the former
// implementation by walking the string once in place.
func parseIPv4ArpaLabels(s string) ([4]byte, bool) {
	var out [4]byte
	// Labels appear low-order first; index 3 receives the first label so the
	// final [4]byte ends up in big-endian (wire) order.
	idx := 3
	i := 0
	for {
		if i >= len(s) {
			return out, false
		}
		n := 0
		digits := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			n = n*10 + int(s[i]-'0')
			digits++
			i++
			if digits > 3 || n > 255 {
				return out, false
			}
		}
		if digits == 0 {
			return out, false
		}
		out[idx] = byte(n)
		if idx == 0 {
			if i != len(s) {
				return out, false
			}
			return out, true
		}
		if i >= len(s) || s[i] != '.' {
			return out, false
		}
		i++
		idx--
	}
}
