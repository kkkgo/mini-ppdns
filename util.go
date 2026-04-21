package main

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"
)

func getPrivateIPs() []string {
	return collectPrivateListenAddrs("53", true, true)
}

// collectPrivateListenAddrs walks interface addresses and returns private +
// loopback (and link-local for IPv6) IPs formatted as host:port. v4 / v6 flags
// select which families are included.
func collectPrivateListenAddrs(port string, v4, v6 bool) []string {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		var fb []string
		if v4 {
			fb = append(fb, net.JoinHostPort("127.0.0.1", port))
		}
		if v6 {
			fb = append(fb, net.JoinHostPort("::1", port))
		}
		return fb
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch a := addr.(type) {
			case *net.IPNet:
				ip = a.IP
			case *net.IPAddr:
				ip = a.IP
			}
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				if !v4 {
					continue
				}
				if ip.IsPrivate() || ip.IsLoopback() {
					ips = append(ips, net.JoinHostPort(ip.String(), port))
				}
			} else if ip.To16() != nil {
				if !v6 {
					continue
				}
				if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
					host := ip.String()
					if ip.IsLinkLocalUnicast() {
						host = host + "%" + i.Name
					}
					ips = append(ips, net.JoinHostPort(host, port))
				}
			}
		}
	}
	if len(ips) == 0 {
		if v4 {
			ips = append(ips, net.JoinHostPort("127.0.0.1", port))
		}
		if v6 {
			ips = append(ips, net.JoinHostPort("::1", port))
		}
	}
	return ips
}

// expandWildcardListen rewrites a 0.0.0.0:<port> or [::]:<port> listen entry
// into the set of private/loopback addresses on that port, so a user asking
// for "all interfaces" still skips public addresses. Non-wildcard entries are
// returned unchanged.
func expandWildcardListen(addr string) []string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return []string{addr}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return []string{addr}
	}
	if ip.IsUnspecified() {
		if ip.To4() != nil {
			// 0.0.0.0 → IPv4 private only
			return collectPrivateListenAddrs(port, true, false)
		}
		// :: → IPv4 + IPv6 private
		return collectPrivateListenAddrs(port, true, true)
	}
	return []string{addr}
}

const (
	estimatedEntrySize = 2048   // estimated bytes per cache entry (includes dns.Msg deep copy, map overhead)
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
