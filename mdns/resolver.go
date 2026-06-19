// Package mdns implements hostname resolution via mDNS/DNS-SD (RFC 6762/6763).
package mdns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"

	"hostminer/internal/logger"
	"hostminer/internal/proto"
)

// Resolver implements [proto.Resolver] using mDNS/DNS-SD.
type Resolver struct {
	iface       *net.Interface
	bindIP      net.IP
	timeout     time.Duration
	targetCount int
}

// NewResolver creates an mDNS Resolver for the given interface and bind IP.
func NewResolver(iface *net.Interface, bindIP net.IP, timeout time.Duration, targetCount int) *Resolver {
	return &Resolver{
		iface:       iface,
		bindIP:      bindIP,
		timeout:     timeout,
		targetCount: targetCount,
	}
}

func (r *Resolver) Name() string { return string(proto.MethodMDNS) }

// Resolve opens the multicast socket, fires PTR and DNS-SD queries, and
// forwards every discovered ip→hostname pair to results until ctx is done.
func (r *Resolver) Resolve(ctx context.Context, targets []string, results chan<- proto.HostResult) error {
	d, err := NewDispatcher(r.iface, r.bindIP)
	if err != nil {
		return fmt.Errorf("mdns dispatcher: %w", err)
	}
	defer d.Close()

	phase2 := time.Duration(float64(r.timeout) * dnsSDPhase2Fraction)
	go runDNSSDSender(d, phase2)

	if r.targetCount <= ptrMaxTargets {
		pacing := computePTRPacing(r.timeout, r.targetCount)
		logger.Infof("[mdns] PTR pacing %v for %d targets", pacing, r.targetCount)
		go runPTRSender(ctx, d, targets, pacing)
	} else {
		logger.Infof("[mdns] PTR queries skipped for %d-host target (limit %d); DNS-SD continues",
			r.targetCount, ptrMaxTargets)
	}

	for {
		select {
		case res := <-d.resultCh:
			results <- res
		case <-d.done:
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

func computePTRPacing(timeout time.Duration, targetCount int) time.Duration {
	if targetCount == 0 {
		return ptrPacingCap
	}
	budget := time.Duration(float64(timeout) * ptrSendBudget)
	pacing := budget / time.Duration(targetCount)
	if pacing < ptrPacingFloor {
		return ptrPacingFloor
	}
	if pacing > ptrPacingCap {
		return ptrPacingCap
	}
	return pacing
}

// runPTRSender sends one reverse-PTR query per tick interval from a single
// goroutine.  A worker pool provides no throughput benefit here because the
// shared Dispatcher socket is the serialisation point; multiple goroutines
// competing for the same ticker would only add scheduling overhead.
func runPTRSender(ctx context.Context, d *Dispatcher, targets []string, pacing time.Duration) {
	ticker := time.NewTicker(pacing)
	defer ticker.Stop()

	for _, ip := range targets {
		rev := buildReverseName(ip)
		if rev == "" {
			continue
		}
		select {
		case <-ticker.C:
			d.Send(rev, dns.TypePTR)
		case <-d.done:
			return
		case <-ctx.Done():
			return
		}
	}
	logger.Infof("[mdns] all PTR queries sent")
}

func runDNSSDSender(d *Dispatcher, phase2Duration time.Duration) {
	queried := make(map[string]bool, len(BaseServiceTypes))
	for _, svc := range BaseServiceTypes {
		select {
		case <-d.done:
			return
		default:
		}
		d.Send(svc, dns.TypePTR)
		queried[svc] = true
		time.Sleep(dnsSDInterQueryDelay)
	}

	phase2End := time.Now().Add(phase2Duration)
	for time.Now().Before(phase2End) {
		select {
		case <-d.done:
			return
		case svc := <-d.globalDnsSdCh:
			if !queried[svc] {
				queried[svc] = true
				d.Send(svc, dns.TypePTR)
				time.Sleep(dnsSDInterQueryDelay)
			}
		case <-time.After(100 * time.Millisecond):
		}
	}
}
