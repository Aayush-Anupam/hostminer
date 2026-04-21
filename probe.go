package mdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Options configures a Probe run.
type Options struct {
	// CIDR is the target subnet to scan, e.g. "192.168.1.0/24". Required.
	CIDR string

	// Interface is an optional hint for selecting the network interface.
	// Accepted formats:
	//   - IP address:     "192.168.1.5"  (recommended on Windows)
	//   - Interface name: "eth0", "en0", "Wi-Fi"
	//   - Empty string:   auto-detect via CIDR-based longest-prefix matching
	Interface string

	// Timeout is how long to listen for mDNS responses.
	// Defaults to ProbeTimeout (20s) when zero.
	Timeout time.Duration

	// Methods lists the resolution techniques to apply, in order.
	// Defaults to DefaultMethods when nil or empty.
	Methods []Method
}

// Probe scans the subnet described by opts.CIDR using mDNS/DNS-SD and
// returns all discovered hosts sorted by IP. Blocks until timeout or ctx cancel.
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

	// Compute PTR send pacing dynamically from timeout and target count.
	// 45% of the timeout is budgeted for the PTR sending phase; the rest
	// is reserved for responses to arrive and be collected.
	pacing := computePacing(opts.Timeout, len(targets))
	log.Printf("PTR pacing: %v for %d targets (send budget: %v)",
		pacing, len(targets), time.Duration(float64(opts.Timeout)*ptrSendBudget))

	// phase2Duration for DNS-SD re-query window.
	phase2Duration := time.Duration(float64(opts.Timeout) * dnsSDPhase2Fraction)

	for _, m := range opts.Methods {
		switch m {
		case MethodMDNS:
			// DNS-SD global queries start immediately, concurrently with PTR.
			RunQuerySender(d, phase2Duration)

			// PTR sender: worker pool + global ticker rate limiter.
			go runPTRSender(ctx, d, targets, pacing)

		default:
			log.Printf("warning: unknown resolution method %q — skipping", m)
		}
	}

	// Collect results until timeout or ctx cancel.
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
					if len(seen) == len(targets) {
						log.Printf("all %d targets resolved — stopping early", len(targets))
						break collect
					}
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

// computePacing derives the inter-query delay for the PTR sending phase.
// It targets fitting all queries within ptrSendBudget fraction of the timeout,
// clamped between ptrPacingFloor and ptrPacingCap.
func computePacing(timeout time.Duration, targetCount int) time.Duration {
	if targetCount == 0 {
		return ptrPacingCap
	}
	budget := time.Duration(float64(timeout) * ptrSendBudget)
	pacing := budget / time.Duration(targetCount)
	if pacing < ptrPacingFloor {
		pacing = ptrPacingFloor
	}
	if pacing > ptrPacingCap {
		pacing = ptrPacingCap
	}
	return pacing
}

// runPTRSender distributes all PTR queries across ptrWorkerCount workers.
// A single shared ticker acts as the global rate limiter — every Send()
// call must claim one tick, so the packet rate is globally smooth regardless
// of worker count.
func runPTRSender(ctx context.Context, d *Dispatcher, targets []string, pacing time.Duration) {
	// Feed all IPs into a channel that workers drain.
	ipCh := make(chan string, len(targets))
	for _, ip := range targets {
		ipCh <- ip
	}
	close(ipCh)

	// One global ticker = one Send() slot per tick interval.
	// All workers compete for the same ticks, giving a smooth global rate.
	ticker := time.NewTicker(pacing)
	defer ticker.Stop()

	var wg sync.WaitGroup
	for i := 0; i < ptrWorkerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipCh {
				rev := buildReverseName(ip)
				if rev == "" {
					continue
				}
				// Block until a send slot is available or we are cancelled.
				select {
				case <-ticker.C:
					d.Send(rev, dns.TypePTR)
				case <-d.done:
					return
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	wg.Wait()
	log.Printf("all PTR queries sent")
}
