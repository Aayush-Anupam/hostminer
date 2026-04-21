package hostminer

import (
	"log"

	"github.com/miekg/dns"
)

// readLoop runs in a background goroutine for the lifetime of the Dispatcher.
// It reads raw UDP packets from the socket, parses them as DNS messages, and
// fans the extracted data into the appropriate channels.
func (d *Dispatcher) readLoop() {
	buf := make([]byte, 65536)
	log.Printf("readLoop started — listening for mDNS responses")

	for {
		n, _, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-d.done:
				// clean shutdown — error is expected
			default:
				log.Printf("readLoop: unexpected socket read error: %v", err)
			}
			return
		}

		var msg dns.Msg
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		if !msg.Response {
			continue
		}

		d.dispatchMessage(&msg)
	}
}

// dispatchMessage fans a parsed DNS response into the result and DNS-SD channels.
func (d *Dispatcher) dispatchMessage(msg *dns.Msg) {
	all := append(msg.Answer, msg.Extra...)

	for _, svc := range extractDNSSDServices(all) {
		select {
		case d.globalDnsSdCh <- svc:
		default:
		}
	}

	for ip, hostname := range extractHostResults(all) {
		select {
		case d.resultCh <- HostResult{IP: ip, Hostname: hostname}:
		default:
			d.dropped.Add(1)
		}
	}
}
