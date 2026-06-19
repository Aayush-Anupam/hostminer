package hostminer

import "hostminer/internal/proto"

// Re-export shared types so callers that import the root hostminer package do
// not need to know about internal/proto.

// HostResult is a single ip→hostname pair discovered from the network.
type HostResult = proto.HostResult

// Resolver is the interface implemented by each resolution strategy.
type Resolver = proto.Resolver

// Method identifies a hostname-resolution strategy.
type Method = proto.Method

// ResolvedSet is a concurrency-safe set of already-resolved IP addresses.
// It is shared across resolvers during a Probe run so that each resolver can
// skip hosts that another method has already found.  Passing nil is safe.
type ResolvedSet = proto.ResolvedSet

const (
	MethodMDNS    = proto.MethodMDNS
	MethodNetBIOS = proto.MethodNetBIOS
	MethodRDNS    = proto.MethodRDNS
	MethodNTLM    = proto.MethodNTLM
)

// DefaultMethods is used when Options.Methods is empty.
// All four resolution strategies run in parallel; NTLM defers to the UDP
// methods via a computed start delay.
var DefaultMethods = []Method{proto.MethodMDNS, proto.MethodNetBIOS, proto.MethodRDNS, proto.MethodNTLM}
