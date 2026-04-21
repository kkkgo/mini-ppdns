//go:build linux

package server

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// errCmNoDstAddr is returned when a PKTINFO control message arrives
// without a destination address field. On Linux this should only happen
// if the kernel is denying us PKTINFO (SELinux, seccomp), not on a
// legitimately empty cmsg.
var errCmNoDstAddr = errors.New("control msg does not have dst address")

// getOOBFromCM4 pulls the dst IPv4 out of a parsed PKTINFO control message.
func getOOBFromCM4(oob []byte) (net.IP, error) {
	var cm ipv4.ControlMessage
	if err := cm.Parse(oob); err != nil {
		return nil, err
	}
	if cm.Dst == nil {
		return nil, errCmNoDstAddr
	}
	return cm.Dst, nil
}

// getOOBFromCM6 is the IPv6 twin of getOOBFromCM4.
func getOOBFromCM6(oob []byte) (net.IP, error) {
	var cm ipv6.ControlMessage
	if err := cm.Parse(oob); err != nil {
		return nil, err
	}
	if cm.Dst == nil {
		return nil, errCmNoDstAddr
	}
	return cm.Dst, nil
}

// srcIP2Cm marshals ip into the PKTINFO cmsg bytes needed to make an
// outgoing datagram appear to come from ip. The IPv4 vs IPv6 choice
// follows ip.To4() — an IPv4 literal (even if stored in 16-byte form)
// gets a v4 PKTINFO; anything else is treated as v6.
func srcIP2Cm(ip net.IP) []byte {
	if ip.To4() != nil {
		return (&ipv4.ControlMessage{Src: ip}).Marshal()
	}
	if ip.To16() != nil {
		return (&ipv6.ControlMessage{Src: ip}).Marshal()
	}
	return nil
}

// initOobHandler prepares c to receive and send PKTINFO control data,
// returning the pair of codec functions suitable for plugging into
// ServeUDP. When c is bound to a specific address (not the wildcard)
// PKTINFO is not needed — returns (nil, nil, nil) so the caller knows
// to skip the OOB path entirely.
func initOobHandler(c *net.UDPConn) (getSrcAddrFromOOB, writeSrcAddrToOOB, error) {
	local, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok || !local.IP.IsUnspecified() {
		return nil, nil, nil
	}

	sc, err := c.SyscallConn()
	if err != nil {
		return nil, nil, err
	}

	var (
		reader getSrcAddrFromOOB
		writer writeSrcAddrToOOB
		setErr error
	)
	if err := sc.Control(func(fd uintptr) {
		reader, writer, setErr = configureOOB(c, int(fd))
	}); err != nil {
		return nil, nil, fmt.Errorf("control fd err, %w", err)
	}
	if setErr != nil {
		return nil, nil, fmt.Errorf("failed to set up socket, %w", setErr)
	}
	return reader, writer, nil
}

// configureOOB inspects the socket's address family, enables PKTINFO on
// the matching protocol layer, and returns the reader/writer pair.
// Runs under sc.Control so fd is guaranteed to still be valid.
func configureOOB(c *net.UDPConn, fd int) (getSrcAddrFromOOB, writeSrcAddrToOOB, error) {
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return nil, nil, os.NewSyscallError("failed to get SO_DOMAIN", err)
	}

	switch domain {
	case unix.AF_INET:
		pc := ipv4.NewPacketConn(c)
		if err := pc.SetControlMessage(ipv4.FlagDst, true); err != nil {
			return nil, nil, fmt.Errorf("failed to set ipv4 cmsg flags, %w", err)
		}
		return getOOBFromCM4, srcIP2Cm, nil
	case unix.AF_INET6:
		pc := ipv6.NewPacketConn(c)
		if err := pc.SetControlMessage(ipv6.FlagDst, true); err != nil {
			return nil, nil, fmt.Errorf("failed to set ipv6 cmsg flags, %w", err)
		}
		return getOOBFromCM6, srcIP2Cm, nil
	default:
		return nil, nil, fmt.Errorf("socket protocol %d is not supported", domain)
	}
}
