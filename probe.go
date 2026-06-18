package hostminer

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"hostminer/internal/logger"
	"hostminer/mdns"
	"hostminer/netbios"
	"hostminer/ntlm"
	"hostminer/rdns"
)

type Options struct {
	CIDR      string
	Interface string
	Timeout   time.Duration
	Methods   []Method

	// NetBIOS tuning — only used when MethodNetBIOS is included in Methods.
	// Zero value falls back to DefaultNetBIOSTimeout.
	NetBIOSTimeout time.Duration

	// RDNSTimeout is the total PTR-lookup budget when MethodRDNS is active.
	// Zero value falls back to DefaultRDNSTimeout.
	RDNSTimeout time.Duration

	// NTLMTimeout is the per-host RDP probe deadline when MethodNTLM is active.
	// Zero value falls back to DefaultNTLMTimeout.
	NTLMTimeout time.Duration
}

// Probe discovers hostnames for all IPs in opts.CIDR by running every
// requested [Resolver] in parallel. It blocks until the timeout expires,
// ctx is cancelled, or every target is resolved.
func Probe(ctx context.Context, opts Options) ([]HostResult, error) {
	opts = applyDefaults(opts)

	if opts.CIDR == "" {
		return nil, fmt.Errorf("Options.CIDR is required")
	}

	targets, err := hostsFromCIDR(opts.CIDR)
	if err != nil {
		return nil, fmt.Errorf("expand CIDR %q: %w", opts.CIDR, err)
	}

	resolvers, err := buildResolvers(opts, targets)
	if err != nil {
		return nil, err
	}
	logger.Infof("Scanning %d hosts in %s with methods %v", len(targets), opts.CIDR, opts.Methods)

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	results := runResolversInParallel(ctx, resolvers, targets)
	return collectResults(ctx, results, targets), nil
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
		opts.RDNSTimeout = DefaultRDNSTimeout
	}
	if opts.NTLMTimeout == 0 {
		opts.NTLMTimeout = DefaultNTLMTimeout
	}
	return opts
}

// needsMDNS reports whether any of the requested methods require mDNS.
func needsMDNS(methods []Method) bool {
	for _, m := range methods {
		if m == MethodMDNS {
			return true
		}
	}
	return false
}

// buildResolvers instantiates the concrete [Resolver] for each requested method.
// Interface resolution and multicast validation are only performed when mDNS is
// in the method list.
func buildResolvers(opts Options, targets []string) ([]Resolver, error) {
	var resolvers []Resolver

	// Resolve the network interface once, only when mDNS needs it.
	var iface *net.Interface
	var bindIP net.IP

	if needsMDNS(opts.Methods) {
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
			resolvers = append(resolvers, ntlm.NewResolver(ntlm.Options{
				Timeout: opts.NTLMTimeout,
			}))
		default:
			logger.Infof("warning: unknown resolution method %q — skipping", m)
		}
	}
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("no valid resolution methods specified")
	}
	return resolvers, nil
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

// runResolversInParallel launches each resolver in its own goroutine and
// fans all output into a single merged channel that is closed when every
// resolver has finished.
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

// collectResults drains the merged channel, deduplicates by IP, and returns
// a slice sorted by IP once ctx is done or all targets are resolved.
func collectResults(ctx context.Context, ch <-chan HostResult, targets []string) []HostResult {
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
