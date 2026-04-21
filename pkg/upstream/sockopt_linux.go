//go:build linux

package upstream

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

type sockoptSetter func(fd int) error

// buildDialControl returns a net.Dialer.Control callback that applies the
// Linux socket options implied by opts. When no option is requested it
// returns nil so the dialer skips the RawConn.Control round-trip entirely.
func buildDialControl(opts socketOpts) func(network, address string, c syscall.RawConn) error {
	setters := collectSockoptSetters(opts)
	if len(setters) == 0 {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var applyErr error
		ctrlErr := c.Control(func(fd uintptr) {
			sfd := int(fd)
			for _, set := range setters {
				if applyErr = set(sfd); applyErr != nil {
					return
				}
			}
		})
		if ctrlErr != nil {
			return ctrlErr
		}
		return applyErr
	}
}

func collectSockoptSetters(opts socketOpts) []sockoptSetter {
	var out []sockoptSetter
	if mark := opts.so_mark; mark > 0 {
		out = append(out, func(fd int) error {
			if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark); err != nil {
				return fmt.Errorf("setsockopt SO_MARK: %w", err)
			}
			return nil
		})
	}
	if dev := opts.bind_to_device; dev != "" {
		out = append(out, func(fd int) error {
			if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev); err != nil {
				return fmt.Errorf("setsockopt SO_BINDTODEVICE: %w", err)
			}
			return nil
		})
	}
	return out
}
