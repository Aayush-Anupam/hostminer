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

	// DefaultRDNSTimeout is the total PTR-lookup budget used when
	// Options.RDNSTimeout is zero.
	// 30 s accommodates a full /16 (65 534 IPs) at 512 workers with
	// typical LAN DNS RTTs (50–200 ms per lookup).
	DefaultRDNSTimeout = 30 * time.Second

	// DefaultNTLMTimeout is the per-host RDP probe deadline used when
	// Options.NTLMTimeout is zero.
	DefaultNTLMTimeout = 5 * time.Second
)
