// Package proto defines the shared types used by all hostname-resolution
// strategies (mDNS, NetBIOS, …).  Keeping them in a leaf package breaks the
// potential import cycle that would arise if the protocol packages (mdns,
// netbios) imported the root hostminer package and the root package also
// imported them.
package proto

import "context"

// Method identifies a hostname-resolution strategy.
type Method string

const (
	MethodMDNS    Method = "mdns"
	MethodNetBIOS Method = "netbios"
	MethodRDNS    Method = "rdns"
)

// HostResult is a single ip→hostname pair discovered from the network,
// tagged with the protocol that found it.
type HostResult struct {
	IP       string
	Hostname string
	Method   Method
}

// Resolver is the interface implemented by each resolution strategy.
// Implementations are launched in parallel by Probe; each writes discovered
// ip→hostname pairs to results until ctx is cancelled or all targets are done.
type Resolver interface {
	// Name returns a human-readable label used in log messages.
	Name() string
	// Resolve runs resolution and writes results to the shared channel.
	// It must return when ctx is cancelled.
	Resolve(ctx context.Context, targets []string, results chan<- HostResult) error
}
