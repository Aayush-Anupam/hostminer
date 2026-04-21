package hostminer

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"
)

type Options struct {
	CIDR      string
	Interface string
	Timeout   time.Duration
	Methods   []Method
}

// Probe discovers hostnames for all IPs in opts.CIDR by running every
// requested [Resolver] in parallel. It blocks until the timeout expires,
// ctx is cancelled, or every target is resolved.
func Probe(ctx context.Context, opts Options) ([]HostResult, error) {
	opts = applyDefaults(opts)

	if opts.CIDR == "" {
		return nil, fmt.Errorf("Options.CIDR is required")
	}

	iface, bindIP, err := prepareInterface(opts.Interface, opts.CIDR)
	if err != nil {
		return nil, err
	}

	targets, err := hostsFromCIDR(opts.CIDR)
	if err != nil {
		return nil, fmt.Errorf("expand CIDR %q: %w", opts.CIDR, err)
	}
	log.Printf("Scanning %d hosts in %s via interface %s", len(targets), opts.CIDR, iface.Name)

	resolvers, err := buildResolvers(opts.Methods, iface, bindIP, opts.Timeout, len(targets))
	if err != nil {
		return nil, err
	}

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
	return opts
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
	log.Printf("Using interface %s (index %d, flags %s, MTU %d, IP %s)",
		iface.Name, iface.Index, iface.Flags, iface.MTU, ip)
	return iface, ip, nil
}

// buildResolvers instantiates the concrete [Resolver] for each requested method.
func buildResolvers(methods []Method, iface *net.Interface, bindIP net.IP, timeout time.Duration, targetCount int) ([]Resolver, error) {
	var resolvers []Resolver
	for _, m := range methods {
		switch m {
		case MethodMDNS:
			resolvers = append(resolvers, NewMDNSResolver(iface, bindIP, timeout, targetCount))
		default:
			log.Printf("warning: unknown resolution method %q — skipping", m)
		}
	}
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("no valid resolution methods specified")
	}
	return resolvers, nil
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
				log.Printf("resolver %s error: %v", r.Name(), err)
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

	seen := make(map[string]string, 64)
loop:
	for {
		select {
		case r, ok := <-ch:
			if !ok {
				break loop
			}
			if targetSet[r.IP] {
				if _, already := seen[r.IP]; !already {
					seen[r.IP] = r.Hostname
					log.Printf("found: %-18s  %s", r.IP, r.Hostname)
					if len(seen) == len(targets) {
						log.Printf("all %d targets resolved — stopping early", len(targets))
						break loop
					}
				}
			}
		case <-ctx.Done():
			break loop
		}
	}

	results := make([]HostResult, 0, len(seen))
	for ip, hostname := range seen {
		results = append(results, HostResult{IP: ip, Hostname: hostname})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].IP < results[j].IP })
	return results
}
