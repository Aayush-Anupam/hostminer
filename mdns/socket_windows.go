//go:build windows

package mdns

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// controlSocket sets SO_REUSEADDR on the UDP socket so multiple processes
// (or a restart) can bind to 0.0.0.0:5353 without an "address in use" error.
func controlSocket(_ string, _ string, c syscall.RawConn) error {
	var optErr error
	if err := c.Control(func(fd uintptr) {
		optErr = windows.SetsockoptInt(
			windows.Handle(fd),
			windows.SOL_SOCKET,
			windows.SO_REUSEADDR,
			1,
		)
	}); err != nil {
		return err
	}
	return optErr
}
