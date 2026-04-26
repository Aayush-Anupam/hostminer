package mdns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"

	"hostminer/internal/logger"
	"hostminer/internal/proto"
)

// Dispatcher owns the single shared UDP multicast socket for an mDNS scan.
// It exposes Send for outbound queries and carries the channels that the
// reader goroutine writes discovered results into.
type Dispatcher struct {
	conn          *net.UDPConn
	dest          *net.UDPAddr
	resultCh      chan proto.HostResult
	globalDnsSdCh chan string
	done          chan struct{}
	closeOnce     sync.Once
	dropped       atomic.Int64
}

// NewDispatcher creates a UDP socket bound to bindIP:5353 on the given
// interface, joins the mDNS multicast group, and starts the background
// reader goroutine.
func NewDispatcher(iface *net.Interface, bindIP net.IP) (*Dispatcher, error) {
	conn, err := openMulticastSocket(iface, bindIP)
	if err != nil {
		return nil, err
	}

	dest, _ := net.ResolveUDPAddr("udp4", MdnsAddrStr)

	d := &Dispatcher{
		conn:          conn,
		dest:          dest,
		resultCh:      make(chan proto.HostResult, resultChBuffer),
		globalDnsSdCh: make(chan string, 256),
		done:          make(chan struct{}),
	}
	go d.readLoop()
	return d, nil
}

// openMulticastSocket binds a UDP socket to bindIP:5353 and joins the mDNS
// multicast group on iface.
func openMulticastSocket(iface *net.Interface, bindIP net.IP) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: controlSocket}
	bindAddr := fmt.Sprintf("%s:5353", bindIP.String())

	pc, err := lc.ListenPacket(context.Background(), "udp4", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("bind %s: %w", bindAddr, err)
	}
	conn := pc.(*net.UDPConn)
	logger.Infof("UDP socket bound to %s", bindAddr)

	p := ipv4.NewPacketConn(conn)
	group := &net.UDPAddr{IP: net.ParseIP(MdnsAddr)}
	if err := p.JoinGroup(iface, group); err != nil {
		conn.Close()
		return nil, fmt.Errorf("JoinGroup on %s (index %d): %w — check the interface is up and supports multicast",
			iface.Name, iface.Index, err)
	}
	logger.Infof("Joined multicast group %s on interface %s", MdnsAddr, iface.Name)

	return conn, nil
}

// Send packs a single mDNS query and writes it to the multicast group.
func (d *Dispatcher) Send(name string, qtype uint16) {
	msg := &dns.Msg{
		Question: []dns.Question{
			{Name: name, Qtype: qtype, Qclass: dns.ClassINET},
		},
	}
	msg.Id = 0
	msg.RecursionDesired = false

	buf, err := msg.Pack()
	if err != nil {
		logger.Infof("[mdns] Send: pack error for %s: %v", name, err)
		return
	}
	if _, err := d.conn.WriteToUDP(buf, d.dest); err != nil {
		logger.Infof("[mdns] Send: write error for %s: %v", name, err)
	}
}

// Close shuts down the dispatcher. Safe to call multiple times.
func (d *Dispatcher) Close() {
	d.closeOnce.Do(func() {
		close(d.done)
		d.conn.Close()
		if n := d.dropped.Load(); n > 0 {
			logger.Infof("[mdns] WARNING: dropped %d results (resultChBuffer=%d is too small)", n, resultChBuffer)
		}
	})
}
