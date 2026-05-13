// Package rdns implements hostname resolution via reverse DNS (PTR) lookups.
package rdns

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hostminer/internal/logger"
	"hostminer/internal/proto"
)

const (
	ptrMaxAttempts = 3

	// maxWorkers is the upper bound on concurrent PTR goroutines.
	// PTR lookups are cheap goroutines (no persistent FD), so we can afford
	// a high cap. In practice the OS resolver and upstream DNS server are
	// the real bottleneck, not goroutine count.
	maxWorkers = 512

	// defaultTimeout is the total deadline for all PTR lookups.
	// rDNS is I/O-bound and serial within each worker, so this must be
	// large enough for ceil(targets/workers) * perLookupRTT * ptrMaxAttempts.
	// 30 s covers a full /16 (65534 IPs, 512 workers, ~128 rounds) at typical
	// LAN DNS RTTs (50–200 ms).
	defaultTimeout = 30 * time.Second
)

// Options customises the reverse-DNS resolver.
type Options struct {
	// Timeout is the total deadline for all PTR lookups.
	// Defaults to 5 s.
	Timeout time.Duration
}

func (o *Options) withDefaults() Options {
	out := *o
	if out.Timeout <= 0 {
		out.Timeout = defaultTimeout
	}
	return out
}

// Resolver implements [proto.Resolver] using OS reverse-DNS (PTR) lookups.
type Resolver struct {
	opts   Options
	lookup func(ctx context.Context, ip string) ([]string, error)
}

// NewResolver creates a new reverse-DNS Resolver with the given options.
// Pass nil to use [net.DefaultResolver].
func NewResolver(opts Options) *Resolver {
	r := &Resolver{opts: opts.withDefaults()}
	r.lookup = net.DefaultResolver.LookupAddr
	return r
}

func (r *Resolver) Name() string { return string(proto.MethodRDNS) }

// Resolve performs concurrent PTR lookups for every target IP.
// Each IP is retried up to ptrMaxAttempts times. Results are written to
// results as they arrive. Resolve returns when all workers finish or ctx
// is cancelled.
func (r *Resolver) Resolve(ctx context.Context, targets []string, results chan<- proto.HostResult) error {
	if len(targets) == 0 {
		return nil
	}

	// Derive a child context capped to our own timeout so we don't block
	// the overall probe after the PTR budget expires.
	ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()

	ipCh := make(chan string, len(targets))
	for _, ip := range targets {
		ipCh <- ip
	}
	close(ipCh)

	workers := len(targets)
	if workers > maxWorkers {
		workers = maxWorkers
	}

	logger.Infof("[rdns] starting PTR lookups for %d targets (%d workers, timeout %v)",
		len(targets), workers, r.opts.Timeout)

	var found atomic.Int32

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ip, ok := <-ipCh:
					if !ok {
						return
					}
					if name := r.resolvePTR(ctx, ip); name != "" {
						found.Add(1)
						select {
						case results <- proto.HostResult{IP: ip, Hostname: name, Method: proto.MethodRDNS}:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}()
	}
	wg.Wait()
	logger.Infof("[rdns] all %d PTR lookups done (%d resolved)", len(targets), found.Load())
	return nil
}

// resolvePTR tries up to ptrMaxAttempts times to resolve a PTR record for ip.
// It returns immediately on permanent DNS errors (e.g. NXDOMAIN) to avoid
// wasting retries on IPs that simply have no PTR record.
func (r *Resolver) resolvePTR(ctx context.Context, ip string) string {
	for attempt := range ptrMaxAttempts {
		names, err := r.lookup(ctx, ip)
		if err == nil && len(names) > 0 && names[0] != "" {
			return strings.TrimSuffix(names[0], ".")
		}
		if ctx.Err() != nil {
			return ""
		}
		// A permanent DNS error (NXDOMAIN, refused, malformed) will not
		// succeed on retry — bail early to avoid redundant network traffic.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && !dnsErr.Temporary() && !dnsErr.Timeout() {
			logger.Debugf("[rdns] PTR %s: permanent error, skipping retries: %v", ip, err)
			return ""
		}
		logger.Debugf("[rdns] PTR %s attempt %d/%d failed: %v", ip, attempt+1, ptrMaxAttempts, err)
	}
	logger.Debugf("[rdns] PTR %s returned no result", ip)
	return ""
}
