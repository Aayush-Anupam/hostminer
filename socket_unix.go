//go:build !windows

package hostminer

import "syscall"

// controlSocket sets SO_REUSEADDR on the UDP socket so multiple processes
// (or a restart) can bind to 0.0.0.0:5353 without an "address in use" error.
// This implementation works on Linux, macOS, and other Unix-like systems.
func controlSocket(_ string, _ string, c syscall.RawConn) error {
	var optErr error
	if err := c.Control(func(fd uintptr) {
		optErr = syscall.SetsockoptInt(
			int(fd),
			syscall.SOL_SOCKET,
			syscall.SO_REUSEADDR,
			1,
		)
	}); err != nil {
		return err
	}
	return optErr
}
