package mdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
)

// HostResult is a single ip→hostname pair received from the network.
type HostResult struct {
	IP       string
	Hostname string
}

// Dispatcher owns the single shared UDP socket. It pours all
// incoming mDNS responses into two channels — one for ip→hostname
// results, one for DNS-SD service hints. No per-IP routing,
// no resultMap, no locks.
type Dispatcher struct {
	conn          *net.UDPConn
	dest          *net.UDPAddr
	resultCh      chan HostResult
	globalDnsSdCh chan string
	done          chan struct{}
	closeOnce     sync.Once
}

// NewDispatcher creates a UDP socket bound to bindIP:5353 on the given
// interface. Binding to the interface's own IP (rather than 0.0.0.0) ensures
// that outgoing multicast queries and incoming multicast responses are all
// routed through the intended interface.
func NewDispatcher(iface *net.Interface, bindIP net.IP) (*Dispatcher, error) {
	lc := net.ListenConfig{
		Control: controlSocket,
	}

	bindAddr := fmt.Sprintf("%s:5353", bindIP.String())
	pc, err := lc.ListenPacket(context.Background(), "udp4", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("bind %s: %w", bindAddr, err)
	}
	conn := pc.(*net.UDPConn)
	log.Printf("UDP socket bound to %s", bindAddr)

	p := ipv4.NewPacketConn(conn)
	if err := p.JoinGroup(iface, &net.UDPAddr{IP: net.ParseIP(MdnsAddr)}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("JoinGroup on interface %s (index %d): %w — check that the interface is up and supports multicast", iface.Name, iface.Index, err)
	}
	log.Printf("Joined multicast group %s on interface %s", MdnsAddr, iface.Name)

	dest, _ := net.ResolveUDPAddr("udp4", MdnsAddrStr)

	d := &Dispatcher{
		conn:          conn,
		dest:          dest,
		resultCh:      make(chan HostResult, 1024),
		globalDnsSdCh: make(chan string, 256),
		done:          make(chan struct{}),
	}
	go d.readLoop()
	return d, nil
}

// Close shuts down the dispatcher. It is safe to call multiple times.
func (d *Dispatcher) Close() {
	d.closeOnce.Do(func() {
		close(d.done)
		d.conn.Close()
	})
}

func (d *Dispatcher) readLoop() {
	buf := make([]byte, 65536)
	log.Printf("readLoop started — listening for mDNS responses")
	for {
		n, src, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-d.done:
				// Clean shutdown — Close() was called; suppress the noisy error.
			default:
				log.Printf("readLoop: unexpected socket read error: %v", err)
			}
			return
		}
		_ = src // available for debug: log.Printf("packet from %s", src)

		var msg dns.Msg
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		if !msg.Response {
			continue
		}

		all := append(msg.Answer, msg.Extra...)

		// Forward DNS-SD service hints.
		for _, svc := range extractDNSSDServices(all) {
			select {
			case d.globalDnsSdCh <- svc:
			default:
			}
		}

		// Pour all ip→hostname pairs into the single result channel.
		// No routing, no map lookup, no locks.
		for ip, hostname := range extractAllMatches(all) {
			select {
			case d.resultCh <- HostResult{IP: ip, Hostname: hostname}:
			default:
				// collector is not keeping up — drop rather than block readLoop
			}
		}
	}
}

func (d *Dispatcher) Send(name string, qtype uint16) {
	m := new(dns.Msg)
	m.Id = 0
	m.RecursionDesired = false
	m.Question = []dns.Question{
		{Name: name, Qtype: qtype, Qclass: dns.ClassINET},
	}
	buf, err := m.Pack()
	if err != nil {
		log.Printf("Send: failed to pack DNS query for %s: %v", name, err)
		return
	}
	if _, err := d.conn.WriteToUDP(buf, d.dest); err != nil {
		log.Printf("Send: failed to write UDP packet for %s: %v", name, err)
	}
}

// extractAllMatches scans a DNS record set and returns every
// ip→hostname pair it can determine.
func extractAllMatches(records []dns.RR) map[string]string {
	result := make(map[string]string)

	// Index A records: lowercase hostname → ip
	aRecords := make(map[string]string)
	for _, rr := range records {
		if r, ok := rr.(*dns.A); ok {
			aRecords[strings.ToLower(r.Hdr.Name)] = r.A.String()
		}
	}

	// Pass 1: reverse PTR — ip is encoded in the arpa name itself
	for _, rr := range records {
		if r, ok := rr.(*dns.PTR); ok {
			if strings.HasSuffix(r.Hdr.Name, ".in-addr.arpa.") {
				ip := arpaToIP(r.Hdr.Name)
				if ip != "" {
					result[ip] = strings.TrimSuffix(r.Ptr, ".")
				}
			}
		}
	}

	// Pass 2: A record — ip is the record value
	for name, ip := range aRecords {
		if _, already := result[ip]; !already {
			result[ip] = strings.TrimSuffix(name, ".")
		}
	}

	// Pass 3: SRV whose target has a matching A record in same message
	for _, rr := range records {
		if r, ok := rr.(*dns.SRV); ok {
			target := strings.ToLower(r.Target)
			if ip, exists := aRecords[target]; exists {
				if _, already := result[ip]; !already {
					result[ip] = strings.TrimSuffix(r.Target, ".")
				}
			}
		}
	}

	return result
}

// extractDNSSDServices returns service type strings advertised via
// _services._dns-sd._udp.local. PTR records.
func extractDNSSDServices(records []dns.RR) []string {
	var services []string
	for _, rr := range records {
		ptr, ok := rr.(*dns.PTR)
		if !ok {
			continue
		}
		if ptr.Hdr.Name == "_services._dns-sd._udp.local." {
			svc := ptr.Ptr
			if !strings.HasSuffix(svc, ".") {
				svc += "."
			}
			if strings.Contains(svc, "._tcp.local.") ||
				strings.Contains(svc, "._udp.local.") {
				services = append(services, svc)
			}
		}
	}
	return services
}
