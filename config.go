package hostminer

import "time"

const (
	// ProbeTimeout is the default scan duration when Options.Timeout is zero.
	ProbeTimeout = 20 * time.Second

	// resultChBuffer is the capacity of the merged result channel in Probe.
	resultChBuffer = 4096

	// DefaultNetBIOSTimeout is the per-IP NetBIOS scan deadline used when
	// Options.NetBIOSTimeout is zero.
	DefaultNetBIOSTimeout = 2 * time.Second
)
