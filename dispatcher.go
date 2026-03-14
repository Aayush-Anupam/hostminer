package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/windows"
)

// resultEntry holds the channel a worker listens on for its current IP.
type resultEntry struct {
	ch chan string
}

// Dispatcher owns the single shared UDP socket and routes incoming
// mDNS responses to whichever worker is probing that IP.
type Dispatcher struct {
	conn          *net.UDPConn
	dest          *net.UDPAddr
	mu            sync.RWMutex
	resultMap     map[string]*resultEntry
	globalDnsSdCh chan string // DNS-SD hints, consumed by RunQuerySender
}

func NewDispatcher(iface *net.Interface) (*Dispatcher, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var optErr error
			if err := c.Control(func(fd uintptr) {
				optErr = windows.SetsockoptInt(
					windows.Handle(fd),
					windows.SOL_SOCKET,
					windows.SO_REUSEADDR,
					1,
				)
			}); err != nil {
				return err
			}
			return optErr
		},
	}

	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:5353")
	if err != nil {
		return nil, fmt.Errorf("bind 0.0.0.0:5353: %w", err)
	}
	conn := pc.(*net.UDPConn)

	p := ipv4.NewPacketConn(conn)
	if err := p.JoinGroup(iface, &net.UDPAddr{IP: net.ParseIP(MdnsAddr)}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("JoinGroup: %w", err)
	}

	dest, _ := net.ResolveUDPAddr("udp4", MdnsAddrStr)

	d := &Dispatcher{
		conn:          conn,
		dest:          dest,
		resultMap:     make(map[string]*resultEntry),
		globalDnsSdCh: make(chan string, 256),
	}
	go d.readLoop()
	return d, nil
}

func (d *Dispatcher) readLoop() {
	buf := make([]byte, 65536)
	for {
		n, _, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		var msg dns.Msg
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		if !msg.Response {
			continue
		}

		all := append(msg.Answer, msg.Extra...)

		// Forward any DNS-SD service hints to the global sender.
		for _, svc := range extractDNSSDServices(all) {
			select {
			case d.globalDnsSdCh <- svc:
			default:
			}
		}

		// Extract ip→hostname matches and deliver to the specific
		// worker waiting for that IP. One send, not a broadcast.
		matches := extractAllMatches(all)
		if len(matches) == 0 {
			continue
		}

		d.mu.RLock()
		for ip, hostname := range matches {
			if entry, ok := d.resultMap[ip]; ok {
				select {
				case entry.ch <- hostname:
				default:
				}
			}
		}
		d.mu.RUnlock()
	}
}

func (d *Dispatcher) register(ip string) *resultEntry {
	entry := &resultEntry{
		ch: make(chan string, 8),
	}
	d.mu.Lock()
	d.resultMap[ip] = entry
	d.mu.Unlock()
	return entry
}

func (d *Dispatcher) unregister(ip string) {
	d.mu.Lock()
	delete(d.resultMap, ip)
	d.mu.Unlock()
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
		return
	}
	d.conn.WriteToUDP(buf, d.dest)
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
