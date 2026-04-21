package mdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"

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
// results, one for DNS-SD service hints.
type Dispatcher struct {
	conn          *net.UDPConn
	dest          *net.UDPAddr
	resultCh      chan HostResult
	globalDnsSdCh chan string
	done          chan struct{}
	closeOnce     sync.Once
	dropped       atomic.Int64
}

// NewDispatcher creates a UDP socket bound to bindIP:5353 on the given
// interface.
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
		resultCh:      make(chan HostResult, resultChBuffer),
		globalDnsSdCh: make(chan string, 256),
		done:          make(chan struct{}),
	}
	go d.readLoop()
	return d, nil
}

// Close shuts down the dispatcher. Safe to call multiple times.
func (d *Dispatcher) Close() {
	d.closeOnce.Do(func() {
		close(d.done)
		d.conn.Close()
		if n := d.dropped.Load(); n > 0 {
			log.Printf("WARNING: dropped %d results due to full resultCh — consider increasing resultChBuffer", n)
		}
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
				// clean shutdown
			default:
				log.Printf("readLoop: unexpected socket read error: %v", err)
			}
			return
		}
		_ = src

		var msg dns.Msg
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		if !msg.Response {
			continue
		}

		all := append(msg.Answer, msg.Extra...)

		for _, svc := range extractDNSSDServices(all) {
			select {
			case d.globalDnsSdCh <- svc:
			default:
			}
		}

		for ip, hostname := range extractAllMatches(all) {
			select {
			case d.resultCh <- HostResult{IP: ip, Hostname: hostname}:
			default:
				d.dropped.Add(1)
			}
		}
	}
}

// Send packs and transmits a single mDNS query onto the multicast group.
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

// extractAllMatches scans a DNS record set and returns every ip→hostname pair.
func extractAllMatches(records []dns.RR) map[string]string {
	result := make(map[string]string)

	// Index A records: lowercase key → IP string, and preserve original casing.
	aRecords := make(map[string]string)     // lowercase name → IP
	aRecordNames := make(map[string]string) // lowercase name → original-case name

	for _, rr := range records {
		if r, ok := rr.(*dns.A); ok {
			lower := strings.ToLower(r.Hdr.Name)
			aRecords[lower] = r.A.String()
			aRecordNames[lower] = r.Hdr.Name
		}
	}

	// Pass 1: reverse PTR — IP is encoded in the arpa name itself.
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

	// Pass 2: A record — IP is the record value, preserve original hostname casing.
	for lower, ip := range aRecords {
		if _, already := result[ip]; !already {
			result[ip] = strings.TrimSuffix(aRecordNames[lower], ".")
		}
	}

	// Pass 3: SRV whose target has a matching A record in the same message.
	for _, rr := range records {
		if r, ok := rr.(*dns.SRV); ok {
			target := strings.ToLower(r.Target)
			if ip, exists := aRecords[target]; exists {
				if _, already := result[ip]; !already {
					result[ip] = strings.TrimSuffix(aRecordNames[target], ".")
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
