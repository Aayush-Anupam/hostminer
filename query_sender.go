package main

import (
	"time"

	"github.com/miekg/dns"
)

// RunQuerySender sends all mDNS queries exactly once, globally.
// It runs in its own goroutine and should be started after the
// dispatcher is ready but before workers begin probing.
//
// Reverse PTR queries are NOT sent here — they are IP-specific
// and are sent individually by each worker in probe().
func RunQuerySender(d *Dispatcher, targets []string) {
	go func() {
		// Phase 1a: send one reverse PTR per target IP.
		// These are the only queries that must be per-IP because
		// the question name encodes the IP itself.
		for _, ip := range targets {
			if rev := buildReverseName(ip); rev != "" {
				d.Send(rev, dns.TypePTR)
				time.Sleep(5 * time.Millisecond) // gentle pacing
			}
		}

		// Phase 1b: send each service type query ONCE globally.
		// mDNS is multicast — every device on the subnet receives
		// this single packet. No need to repeat per IP.
		time.Sleep(300 * time.Millisecond)
		for _, svc := range BaseServiceTypes {
			d.Send(svc, dns.TypePTR)
			time.Sleep(20 * time.Millisecond)
		}

		// Phase 2: re-query any DNS-SD discovered service types.
		// These are fed into d.globalDnsSdCh by the dispatcher
		// when it sees _services._dns-sd._udp.local. PTR replies.
		phase2End := time.Now().Add(3 * time.Second)
		queriedServices := make(map[string]bool)
		for _, svc := range BaseServiceTypes {
			queriedServices[svc] = true
		}

		for time.Now().Before(phase2End) {
			select {
			case svc := <-d.globalDnsSdCh:
				if !queriedServices[svc] {
					queriedServices[svc] = true
					d.Send(svc, dns.TypePTR)
					time.Sleep(20 * time.Millisecond)
				}
			case <-time.After(100 * time.Millisecond):
				// nothing new discovered, keep polling until phase2End
			}
		}
	}()
}
