package mdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"time"

	"github.com/miekg/dns"
)

// Options configures a [Probe] run.
type Options struct {
	// CIDR is the target subnet to scan, e.g. "192.168.1.0/24". Required.
	CIDR string

	// Interface is an optional hint for selecting the network interface.
	// Accepted formats:
	//   - IP address:       "192.168.1.5"   (recommended on Windows)
	//   - Interface name:   "eth0", "en0", "Wi-Fi"
	//   - Empty string:     auto-detect using CIDR-based longest-prefix matching
	Interface string

	// Timeout is how long to listen for mDNS responses.
	// Defaults to ProbeTimeout (20 s) when zero.
	Timeout time.Duration

	// Methods lists the hostname-resolution techniques to apply, in order.
	// Defaults to DefaultMethods ([MethodMDNS]) when nil or empty.
	// Future values: MethodNetBIOS, MethodRDNS.
	Methods []Method
}

// Probe scans the subnet described by opts.CIDR using mDNS/DNS-SD and
// returns all discovered hosts sorted by IP address. It blocks until the
// scan timeout elapses or ctx is cancelled.
//
// Example:
//
//	results, err := mdns.Probe(ctx, mdns.Options{CIDR: "192.168.1.0/24"})
func Probe(ctx context.Context, opts Options) ([]HostResult, error) {
	if opts.CIDR == "" {
		return nil, fmt.Errorf("Options.CIDR is required")
	}
	if opts.Timeout == 0 {
		opts.Timeout = ProbeTimeout
	}
	if len(opts.Methods) == 0 {
		opts.Methods = DefaultMethods
	}

	iface, err := ResolveInterface(opts.Interface, opts.CIDR)
	if err != nil {
		return nil, fmt.Errorf("interface: %w", err)
	}
	if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("interface %s is DOWN — bring it up first", iface.Name)
	}
	if iface.Flags&net.FlagMulticast == 0 {
		return nil, fmt.Errorf("interface %s does not support multicast — mDNS requires multicast", iface.Name)
	}
	log.Printf("Using interface: %s (index %d, flags: %s, MTU: %d)", iface.Name, iface.Index, iface.Flags, iface.MTU)

	ifaceIP, err := InterfaceIPv4(iface)
	if err != nil {
		return nil, fmt.Errorf("resolving interface IP: %w", err)
	}

	d, err := NewDispatcher(iface, ifaceIP)
	if err != nil {
		return nil, fmt.Errorf("dispatcher: %w", err)
	}
	defer d.Close()

	targets, err := hostsFromCIDR(opts.CIDR)
	if err != nil {
		return nil, fmt.Errorf("expand CIDR %q: %w", opts.CIDR, err)
	}
	log.Printf("Scanning %d hosts in %s", len(targets), opts.CIDR)

	targetSet := make(map[string]bool, len(targets))
	for _, ip := range targets {
		targetSet[ip] = true
	}

	// Dispatch over the requested resolution methods.
	// Currently only MethodMDNS is implemented; future methods (NetBIOS, rDNS)
	// will be added as additional cases here without changing the outer API.
	for _, m := range opts.Methods {
		switch m {
		case MethodMDNS:
			// Start DNS-SD global service-type queries (multicast, one packet per type).
			RunQuerySender(d)

			// Send per-IP reverse PTR queries in a paced burst.
			go func() {
				for _, ip := range targets {
					if rev := buildReverseName(ip); rev != "" {
						d.Send(rev, dns.TypePTR)
						time.Sleep(QueryPacing)
					}
				}
				log.Printf("All PTR queries sent")
			}()
		default:
			log.Printf("warning: unknown resolution method %q — skipping", m)
		}
	}

	// Collect results for the full timeout window (or until ctx is done).
	deadline := time.NewTimer(opts.Timeout)
	defer deadline.Stop()

	seen := make(map[string]string, 64)
collect:
	for {
		select {
		case r := <-d.resultCh:
			if targetSet[r.IP] {
				if _, already := seen[r.IP]; !already {
					seen[r.IP] = r.Hostname
					log.Printf("found: %-18s  %s", r.IP, r.Hostname)
				}
			}
		case <-deadline.C:
			break collect
		case <-ctx.Done():
			break collect
		}
	}

	results := make([]HostResult, 0, len(seen))
	for ip, hostname := range seen {
		results = append(results, HostResult{IP: ip, Hostname: hostname})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].IP < results[j].IP })
	return results, nil
}
