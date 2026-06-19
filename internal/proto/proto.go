// Package proto defines the shared types used by all hostname-resolution
// strategies.  Keeping them in a leaf package breaks the potential import
// cycle that would arise if the protocol packages (mdns, netbios, …)
// imported the root hostminer package and vice-versa.
package proto

import (
	"context"
	"sync"
)

// Method identifies a hostname-resolution strategy.
type Method string

const (
	MethodMDNS    Method = "mdns"
	MethodNetBIOS Method = "netbios"
	MethodRDNS    Method = "rdns"
	MethodNTLM    Method = "ntlm"
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

// ResolvedSet is a concurrency-safe set of IP addresses that have been
// successfully resolved by any method.  Resolvers receive it at construction
// time and skip IPs already present, avoiding redundant work.
// Passing nil is always safe; all methods become no-ops.
type ResolvedSet struct {
	mu  sync.RWMutex
	ips map[string]struct{}
}

// NewResolvedSet allocates an empty ResolvedSet.
func NewResolvedSet() *ResolvedSet {
	return &ResolvedSet{ips: make(map[string]struct{})}
}

// Add marks ip as resolved.  Safe for concurrent use; nil receiver is a no-op.
func (s *ResolvedSet) Add(ip string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.ips[ip] = struct{}{}
	s.mu.Unlock()
}

// Has reports whether ip has already been resolved.  Safe for concurrent use;
// nil receiver always returns false.
func (s *ResolvedSet) Has(ip string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	_, ok := s.ips[ip]
	s.mu.RUnlock()
	return ok
}
