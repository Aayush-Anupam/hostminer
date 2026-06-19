package hostminer

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"hostminer/internal/logger"
	"hostminer/internal/proto"
	"hostminer/mdns"
	"hostminer/netbios"
	"hostminer/ntlm"
	"hostminer/rdns"
)

// Options controls a single Probe run.
type Options struct {
	CIDR      string
	Interface string
	Timeout   time.Duration
	Methods   []Method

	// Per-method timeout overrides.  A zero value falls back to the defaults
	// described on each constant in config.go.
	NetBIOSTimeout time.Duration
	// RDNSTimeout is the total PTR-lookup budget.  Zero means use Timeout.
	RDNSTimeout time.Duration
	NTLMTimeout time.Duration
}

// Probe discovers hostnames for all IPs in opts.CIDR by running every
// requested [Resolver] in parallel.  It blocks until the timeout expires,
// ctx is cancelled, or every target is resolved.
//
// Resolution is tiered: rDNS, NetBIOS, and mDNS run immediately; NTLM waits
// until the UDP resolvers have had time to respond and only probes hosts they
// did not resolve.
func Probe(ctx context.Context, opts Options) ([]HostResult, error) {
	opts = applyDefaults(opts)

	if opts.CIDR == "" {
		return nil, fmt.Errorf("Options.CIDR is required")
	}

	targets, err := hostsFromCIDR(opts.CIDR)
	if err != nil {
		return nil, fmt.Errorf("expand CIDR %q: %w", opts.CIDR, err)
	}

	resolved := proto.NewResolvedSet()

	resolvers, err := buildResolvers(opts, targets, resolved)
	if err != nil {
		return nil, err
	}
	logger.Infof("Scanning %d hosts in %s with methods %v", len(targets), opts.CIDR, opts.Methods)

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	results := runResolversInParallel(ctx, resolvers, targets)
	return collectResults(ctx, results, targets, resolved), nil
}

func applyDefaults(opts Options) Options {
	if opts.Timeout == 0 {
		opts.Timeout = ProbeTimeout
	}
	if len(opts.Methods) == 0 {
		opts.Methods = DefaultMethods
	}
	if opts.NetBIOSTimeout == 0 {
		opts.NetBIOSTimeout = DefaultNetBIOSTimeout
	}
	if opts.RDNSTimeout == 0 {
		// rDNS shares the global window; a separate 30 s cap would be silently
		// unreachable whenever opts.Timeout < 30 s.
		opts.RDNSTimeout = opts.Timeout
	}
	if opts.NTLMTimeout == 0 {
		opts.NTLMTimeout = DefaultNTLMTimeout
	}
	return opts
}

func buildResolvers(opts Options, targets []string, resolved *proto.ResolvedSet) ([]Resolver, error) {
	var resolvers []Resolver

	var iface *net.Interface
	var bindIP net.IP
	if needsMethod(opts.Methods, MethodMDNS) {
		var err error
		iface, bindIP, err = prepareInterface(opts.Interface, opts.CIDR)
		if err != nil {
			return nil, err
		}
	}

	for _, m := range opts.Methods {
		switch m {
		case MethodMDNS:
			resolvers = append(resolvers, mdns.NewResolver(iface, bindIP, opts.Timeout, len(targets)))
		case MethodNetBIOS:
			resolvers = append(resolvers, netbios.NewResolver(netbios.Options{
				Timeout: opts.NetBIOSTimeout,
			}))
		case MethodRDNS:
			resolvers = append(resolvers, rdns.NewResolver(rdns.Options{
				Timeout: opts.RDNSTimeout,
			}))
		case MethodNTLM:
			delay := ntlmStartDelay(opts, len(targets))
			resolvers = append(resolvers, ntlm.NewResolver(ntlm.Options{
				Timeout: opts.NTLMTimeout,
			}, resolved, delay))
		default:
			logger.Infof("warning: unknown resolution method %q — skipping", m)
		}
	}
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("no valid resolution methods specified")
	}
	return resolvers, nil
}

// ntlmStartDelay computes how long NTLM should wait before opening TCP
// connections.  It estimates the NetBIOS wave-1 duration (using the same
// pacing formula NetBIOS itself uses) and adds a 300 ms buffer, giving the
// UDP resolvers a meaningful head start.  The delay is capped at 25 % of the
// global scan budget so NTLM always gets a useful window.
func ntlmStartDelay(opts Options, targetCount int) time.Duration {
	wave1 := netbios.ComputePacing(opts.NetBIOSTimeout, targetCount) * time.Duration(targetCount)
	delay := wave1 + 300*time.Millisecond
	if delay < 500*time.Millisecond {
		delay = 500 * time.Millisecond
	}
	if cap := time.Duration(float64(opts.Timeout) * 0.25); delay > cap {
		delay = cap
	}
	return delay
}

func needsMethod(methods []Method, m Method) bool {
	for _, x := range methods {
		if x == m {
			return true
		}
	}
	return false
}

func prepareInterface(hint, cidr string) (*net.Interface, net.IP, error) {
	iface, err := ResolveInterface(hint, cidr)
	if err != nil {
		return nil, nil, fmt.Errorf("interface: %w", err)
	}
	if err := ValidateInterfaceForMDNS(iface); err != nil {
		return nil, nil, err
	}
	ip, err := InterfaceIPv4(iface)
	if err != nil {
		return nil, nil, fmt.Errorf("interface IP: %w", err)
	}
	logger.Infof("Using interface %s (index %d, flags %s, MTU %d, IP %s)",
		iface.Name, iface.Index, iface.Flags, iface.MTU, ip)
	return iface, ip, nil
}

func runResolversInParallel(ctx context.Context, resolvers []Resolver, targets []string) <-chan HostResult {
	merged := make(chan HostResult, resultChBuffer)
	var wg sync.WaitGroup
	for _, r := range resolvers {
		r := r
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.Resolve(ctx, targets, merged); err != nil {
				logger.Infof("resolver %s error: %v", r.Name(), err)
			}
		}()
	}
	go func() { wg.Wait(); close(merged) }()
	return merged
}

// collectResults drains the merged channel, deduplicates by IP, feeds each
// new result into resolved (so live resolvers can skip it), and returns a
// slice sorted by IP once ctx is done or all targets are resolved.
func collectResults(ctx context.Context, ch <-chan HostResult, targets []string, resolved *proto.ResolvedSet) []HostResult {
	targetSet := make(map[string]bool, len(targets))
	for _, ip := range targets {
		targetSet[ip] = true
	}

	seen := make(map[string]HostResult, 64)
loop:
	for {
		select {
		case r, ok := <-ch:
			if !ok {
				break loop
			}
			if targetSet[r.IP] {
				if _, already := seen[r.IP]; !already {
					seen[r.IP] = r
					resolved.Add(r.IP)
					logger.Infof("found [%s]: %-18s  %s", r.Method, r.IP, r.Hostname)
					if len(seen) == len(targets) {
						logger.Infof("all %d targets resolved — stopping early", len(targets))
						break loop
					}
				}
			}
		case <-ctx.Done():
			break loop
		}
	}

	results := make([]HostResult, 0, len(seen))
	for _, r := range seen {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].IP < results[j].IP })
	return results
}
