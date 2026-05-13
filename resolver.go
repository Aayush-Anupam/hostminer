package hostminer

import "hostminer/internal/proto"

// Re-export shared types and constants so callers that import the root
// hostminer package do not need to know about the internal/proto package.

// HostResult is a single ip→hostname pair discovered from the network,
// tagged with the protocol that found it.
type HostResult = proto.HostResult

// Resolver is the interface implemented by each resolution strategy.
type Resolver = proto.Resolver

// Method identifies a hostname-resolution strategy.
type Method = proto.Method

const (
	MethodMDNS    = proto.MethodMDNS
	MethodNetBIOS = proto.MethodNetBIOS
	MethodRDNS    = proto.MethodRDNS
)

// DefaultMethods is used when Options.Methods is empty.
// All supported resolution strategies are run in parallel by default.
var DefaultMethods = []Method{proto.MethodMDNS, proto.MethodNetBIOS, proto.MethodRDNS}
