package hostminer

import "context"

// HostResult is a single ip→hostname pair discovered from the network.
type HostResult struct {
	IP       string
	Hostname string
}

// Method identifies a hostname-resolution strategy.
type Method string

const (
	MethodMDNS Method = "mdns"
	// MethodNetBIOS Method = "netbios"
	// MethodRDNS    Method = "rdns"
)

// DefaultMethods is used when Options.Methods is empty.
var DefaultMethods = []Method{MethodMDNS}

// Resolver is the interface implemented by each hostname-resolution strategy
// (mDNS, NetBIOS, rDNS, …). All resolvers are launched in parallel by Probe;
// each writes discovered ip→hostname pairs to results until ctx is cancelled.
type Resolver interface {
	// Name returns a human-readable label used in log messages.
	Name() string
	// Resolve runs until ctx is cancelled, writing results to the shared channel.
	Resolve(ctx context.Context, targets []string, results chan<- HostResult) error
}
