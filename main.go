package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/windows"
)

const (
	myInterfaceIP = "192.168.29.165"
	mdnsAddr      = "224.0.0.251"
	mdnsAddrStr   = "224.0.0.251:5353"
	probeTimeout  = 12 * time.Second
)

var serviceTypes = []string{
	"_services._dns-sd._udp.local.",
	"_http._tcp.local.",
	"_https._tcp.local.",
	"_smb._tcp.local.",
	"_wifiMeshAP._tcp.local.",
	"_ipp._tcp.local.",
	"_printer._tcp.local.",
	"_pdl-datastream._tcp.local.",
	"_rdp._tcp.local.",
	"_vnc._tcp.local.",
	"_airplay._tcp.local.",
	"_raop._tcp.local.",
	"_homekit._tcp.local.",
	"_hap._tcp.local.",
}

// -----------------------------------------------------------------
// Dispatcher — one shared socket, fans out DNS messages to waiters
// -----------------------------------------------------------------

type waiter struct {
	ch chan *dns.Msg
}

type Dispatcher struct {
	conn    *net.UDPConn
	dest    *net.UDPAddr
	mu      sync.RWMutex
	waiters map[string][]*waiter // key: targetIP
}

func NewDispatcher(iface *net.Interface) (*Dispatcher, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var optErr error
			c.Control(func(fd uintptr) {
				optErr = windows.SetsockoptInt(
					windows.Handle(fd),
					windows.SOL_SOCKET,
					windows.SO_REUSEADDR,
					1,
				)
			})
			return optErr
		},
	}

	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:5353")
	if err != nil {
		return nil, fmt.Errorf("bind 0.0.0.0:5353: %w", err)
	}
	conn := pc.(*net.UDPConn)

	p := ipv4.NewPacketConn(conn)
	if err := p.JoinGroup(iface, &net.UDPAddr{IP: net.ParseIP(mdnsAddr)}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("JoinGroup: %w", err)
	}

	dest, _ := net.ResolveUDPAddr("udp4", mdnsAddrStr)

	d := &Dispatcher{
		conn:    conn,
		dest:    dest,
		waiters: make(map[string][]*waiter),
	}
	go d.readLoop()
	return d, nil
}

// readLoop reads every incoming mDNS packet and fans it out to ALL
// registered waiters — each goroutine filters for its own IP.
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

		// Copy once, broadcast to all waiters
		msgCopy := msg.Copy()

		d.mu.RLock()
		for _, ws := range d.waiters {
			for _, w := range ws {
				select {
				case w.ch <- msgCopy:
				default: // waiter is busy, skip — it will get the next packet
				}
			}
		}
		d.mu.RUnlock()
	}
}

func (d *Dispatcher) register(ip string) *waiter {
	w := &waiter{ch: make(chan *dns.Msg, 32)}
	d.mu.Lock()
	d.waiters[ip] = append(d.waiters[ip], w)
	d.mu.Unlock()
	return w
}

func (d *Dispatcher) unregister(ip string, w *waiter) {
	d.mu.Lock()
	ws := d.waiters[ip]
	for i, existing := range ws {
		if existing == w {
			d.waiters[ip] = append(ws[:i], ws[i+1:]...)
			break
		}
	}
	if len(d.waiters[ip]) == 0 {
		delete(d.waiters, ip)
	}
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

// -----------------------------------------------------------------
// Per-IP probe — runs in its own goroutine
// -----------------------------------------------------------------

func probe(targetIP string, d *Dispatcher) string {
	w := d.register(targetIP)
	defer d.unregister(targetIP, w)

	deadline := time.NewTimer(probeTimeout)
	defer deadline.Stop()

	found := make(chan string, 1)

	// Query sender goroutine
	go func() {
		// 1. Reverse PTR
		reverseName := buildReverseName(targetIP)
		if reverseName != "" {
			d.Send(reverseName, dns.TypePTR)
		}

		time.Sleep(300 * time.Millisecond)

		// 2. Service type PTR queries
		for _, svc := range serviceTypes {
			d.Send(svc, dns.TypePTR)
			time.Sleep(20 * time.Millisecond)
		}
	}()

	// Response listener
	go func() {
		for msg := range w.ch {
			all := append(msg.Answer, msg.Extra...)
			if hostname := extractHostname(all, targetIP); hostname != "" {
				select {
				case found <- hostname:
				default:
				}
				return
			}
		}
	}()

	select {
	case hostname := <-found:
		return hostname
	case <-deadline.C:
		return ""
	}
}

// -----------------------------------------------------------------
// Main
// -----------------------------------------------------------------

func main() {
	iface, err := findInterfaceByIP(myInterfaceIP)
	if err != nil {
		log.Fatalf("interface not found: %v", err)
	}
	log.Printf("Interface: %s (index %d)", iface.Name, iface.Index)

	d, err := NewDispatcher(iface)
	if err != nil {
		log.Fatalf("dispatcher: %v", err)
	}

	subnet := subnetBase(myInterfaceIP)
	var targets []string
	for i := 1; i <= 254; i++ {
		targets = append(targets, fmt.Sprintf("%s.%d", subnet, i))
	}

	type result struct {
		ip       string
		hostname string
	}

	results := make(chan result, len(targets))
	var wg sync.WaitGroup

	for _, ip := range targets {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			hostname := probe(targetIP, d)
			if hostname != "" {
				results <- result{ip: targetIP, hostname: hostname}
			}
		}(ip)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	fmt.Println("\n=== Results ===")
	for r := range results {
		fmt.Printf("%-18s  %s\n", r.ip, r.hostname)
	}
}

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

func extractHostname(records []dns.RR, targetIP string) string {
	// Pass 1: reverse PTR — most reliable
	for _, rr := range records {
		if r, ok := rr.(*dns.PTR); ok {
			if strings.HasSuffix(r.Hdr.Name, ".in-addr.arpa.") {
				// Verify the arpa name actually matches our target IP
				if arpaMatchesIP(r.Hdr.Name, targetIP) {
					return strings.TrimSuffix(r.Ptr, ".")
				}
			}
		}
	}

	// Pass 2: A record whose IP matches target
	for _, rr := range records {
		if r, ok := rr.(*dns.A); ok {
			if r.A.String() == targetIP {
				return strings.TrimSuffix(r.Hdr.Name, ".")
			}
		}
	}

	// Pass 3: SRV target — only if an A record in the same message
	//         confirms the SRV target resolves to our IP
	aRecords := map[string]string{} // hostname -> IP
	for _, rr := range records {
		if r, ok := rr.(*dns.A); ok {
			aRecords[strings.ToLower(r.Hdr.Name)] = r.A.String()
		}
	}
	for _, rr := range records {
		if r, ok := rr.(*dns.SRV); ok {
			target := strings.ToLower(r.Target)
			if ip, exists := aRecords[target]; exists && ip == targetIP {
				return strings.TrimSuffix(r.Target, ".")
			}
		}
	}

	return ""
}

// arpaMatchesIP checks that e.g. "165.29.168.192.in-addr.arpa." matches "192.168.29.165"
func arpaMatchesIP(arpaName, ip string) bool {
	arpaName = strings.TrimSuffix(arpaName, ".in-addr.arpa.")
	parts := strings.Split(arpaName, ".")
	if len(parts) != 4 {
		return false
	}
	ipParts := strings.Split(ip, ".")
	if len(ipParts) != 4 {
		return false
	}
	// arpa is reversed
	return parts[0] == ipParts[3] &&
		parts[1] == ipParts[2] &&
		parts[2] == ipParts[1] &&
		parts[3] == ipParts[0]
}

func buildReverseName(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa.", parts[3], parts[2], parts[1], parts[0])
}

func findInterfaceByIP(ipStr string) (*net.Interface, error) {
	target := net.ParseIP(ipStr)
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.Equal(target) {
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no interface with IP %s", ipStr)
}

func subnetBase(ip string) string {
	parts := strings.Split(ip, ".")
	return strings.Join(parts[:3], ".")
}
