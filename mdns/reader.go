package mdns

import (
	"github.com/miekg/dns"

	"hostminer/internal/logger"
	"hostminer/internal/proto"
)

// readLoop runs in a background goroutine for the lifetime of the Dispatcher.
// It reads raw UDP packets from the socket, parses them as DNS messages, and
// fans the extracted data into the appropriate channels.
func (d *Dispatcher) readLoop() {
	buf := make([]byte, 65536)
	logger.Debugf("[mdns] readLoop started")

	for {
		n, _, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-d.done:
				// clean shutdown
			default:
				logger.Infof("[mdns] readLoop: unexpected socket read error: %v", err)
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
		case d.resultCh <- proto.HostResult{IP: ip, Hostname: hostname, Method: proto.MethodMDNS}:
		default:
			d.dropped.Add(1)
		}
	}
}
