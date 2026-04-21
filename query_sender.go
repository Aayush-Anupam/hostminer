package mdns

import (
	"time"

	"github.com/miekg/dns"
)

// RunQuerySender fires DNS-SD global service-type queries immediately.
// It runs entirely in its own goroutine and does not block the caller.
// phase2Duration controls how long it listens for newly discovered
// service types and re-queries them.
func RunQuerySender(d *Dispatcher, phase2Duration time.Duration) {
	go func() {
		// Phase 1: send each known service type once globally.
		// mDNS is multicast — one packet reaches every device on the link.
		for _, svc := range BaseServiceTypes {
			select {
			case <-d.done:
				return
			default:
			}
			d.Send(svc, dns.TypePTR)
			time.Sleep(dnsSDInterQueryDelay)
		}

		// Phase 2: re-query any service types discovered dynamically via
		// _services._dns-sd._udp.local. responses, for phase2Duration.
		phase2End := time.Now().Add(phase2Duration)
		queriedServices := make(map[string]bool, len(BaseServiceTypes))
		for _, svc := range BaseServiceTypes {
			queriedServices[svc] = true
		}

		for time.Now().Before(phase2End) {
			select {
			case <-d.done:
				return
			case svc := <-d.globalDnsSdCh:
				if !queriedServices[svc] {
					queriedServices[svc] = true
					d.Send(svc, dns.TypePTR)
					time.Sleep(dnsSDInterQueryDelay)
				}
			case <-time.After(100 * time.Millisecond):
				// nothing new in this window, keep polling
			}
		}
	}()
}
