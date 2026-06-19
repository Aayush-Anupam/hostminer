package hostminer

import "time"

const (
	// ProbeTimeout is the default scan duration when Options.Timeout is zero.
	ProbeTimeout = 20 * time.Second

	// resultChBuffer is the capacity of the merged result channel in Probe.
	resultChBuffer = 4096

	// DefaultNetBIOSTimeout is the total NetBIOS scan deadline used when
	// Options.NetBIOSTimeout is zero.
	DefaultNetBIOSTimeout = 2 * time.Second

	// DefaultNTLMTimeout is the per-host RDP probe deadline used when
	// Options.NTLMTimeout is zero.  1 s is appropriate for LAN scanning where
	// closed ports respond with RST immediately; raise to 3–5 s for internet
	// targets where firewalled ports must time out silently.
	DefaultNTLMTimeout = 1 * time.Second
)
