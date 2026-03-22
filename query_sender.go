package main

import (
	"time"

	"github.com/miekg/dns"
)

// RunQuerySender handles only global multicast DNS-SD service queries.
// Per-IP reverse PTR queries are sent directly by main() after the
// dispatcher is ready, so no reply can arrive before collection starts.
func RunQuerySender(d *Dispatcher) {
	go func() {
		// Phase 1b: send each service type query once globally.
		// mDNS is multicast — one packet reaches every device.
		for _, svc := range BaseServiceTypes {
			d.Send(svc, dns.TypePTR)
			time.Sleep(20 * time.Millisecond)
		}

		// Phase 2: re-query any DNS-SD discovered service types.
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
				// nothing new, keep polling until phase2End
			}
		}
	}()
}
