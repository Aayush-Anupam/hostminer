package hostminer

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	ptrWorkerCount = 20

	ptrSendBudget  = 0.45
	ptrPacingFloor = 50 * time.Microsecond
	ptrPacingCap   = 1 * time.Millisecond

	dnsSDInterQueryDelay = 20 * time.Millisecond
	dnsSDPhase2Fraction  = 0.25
)

// MDNSResolver implements [Resolver] using mDNS/DNS-SD (RFC 6762/6763).
type MDNSResolver struct {
	iface       *net.Interface
	bindIP      net.IP
	timeout     time.Duration
	targetCount int
}

// NewMDNSResolver creates an MDNSResolver for the given interface and bind IP.
func NewMDNSResolver(iface *net.Interface, bindIP net.IP, timeout time.Duration, targetCount int) *MDNSResolver {
	return &MDNSResolver{
		iface:       iface,
		bindIP:      bindIP,
		timeout:     timeout,
		targetCount: targetCount,
	}
}

func (r *MDNSResolver) Name() string { return "mdns" }

func (r *MDNSResolver) Resolve(ctx context.Context, targets []string, results chan<- HostResult) error {
	d, err := NewDispatcher(r.iface, r.bindIP)
	if err != nil {
		return fmt.Errorf("mdns dispatcher: %w", err)
	}
	defer d.Close()

	pacing := computePTRPacing(r.timeout, r.targetCount)
	phase2 := time.Duration(float64(r.timeout) * dnsSDPhase2Fraction)

	log.Printf("[mdns] PTR pacing %v for %d targets (send budget %v)",
		pacing, r.targetCount, time.Duration(float64(r.timeout)*ptrSendBudget))

	go runDNSSDSender(d, phase2)
	go runPTRSender(ctx, d, targets, pacing)

	for {
		select {
		case r := <-d.resultCh:
			results <- r
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

func runPTRSender(ctx context.Context, d *Dispatcher, targets []string, pacing time.Duration) {
	ipCh := make(chan string, len(targets))
	for _, ip := range targets {
		ipCh <- ip
	}
	close(ipCh)

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
	log.Printf("[mdns] all PTR queries sent")
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
