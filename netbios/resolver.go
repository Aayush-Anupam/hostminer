// Package netbios implements hostname resolution via the NetBIOS Name Service
// (NBNS) Node Status Request (NBSTAT, RFC 1002).
package netbios

import (
	"context"
	"encoding/binary"
	"math/rand"
	"net"
	"sync"
	"time"

	"hostminer/internal/logger"
	"hostminer/internal/proto"
)

const (
	netbiosPort       = 137
	netbiosUDPNetwork = "udp4"
	netbiosBindAddr   = ":0"

	// sendPace is the minimum gap between successive NBSTAT sends.
	// 500 µs ≈ 2 000 packets/s — fast enough to blast 254 hosts in ~130 ms
	// while avoiding local kernel-buffer drops.
	sendPace = 500 * time.Microsecond

	// retransmitAfter is how long to wait before re-sending to hosts that
	// have not yet replied.
	retransmitAfter = 900 * time.Millisecond

	// defaultTimeout is the total wait for any reply after the last send wave.
	defaultTimeout = 2 * time.Second
)

// Options customises the NetBIOS resolver.
type Options struct {
	// Timeout is the total scan deadline for receiving replies.
	// Defaults to 2 s.
	Timeout time.Duration
}

func (o *Options) withDefaults() Options {
	out := *o
	if out.Timeout <= 0 {
		out.Timeout = defaultTimeout
	}
	return out
}

// Resolver implements [proto.Resolver] using NetBIOS NBSTAT queries.
type Resolver struct {
	opts Options
}

// NewResolver creates a new NetBIOS Resolver with the given options.
func NewResolver(opts Options) *Resolver {
	return &Resolver{opts: opts.withDefaults()}
}

func (r *Resolver) Name() string { return string(proto.MethodNetBIOS) }

// Resolve opens a single shared UDP socket, fires NBSTAT queries at all
// targets in rapid succession, then collects responses asynchronously.
// After retransmitAfter it re-sends to every host that has not yet replied,
// then waits until the overall timeout expires.
func (r *Resolver) Resolve(ctx context.Context, targets []string, results chan<- proto.HostResult) error {
	if len(targets) == 0 {
		return nil
	}

	conn, err := net.ListenPacket(netbiosUDPNetwork, netbiosBindAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Assign each target a unique transaction ID so responses can be
	// correlated without inspecting the source IP.
	type entry struct {
		ip   string
		txID uint16
	}
	base := uint16(rand.Uint32())
	byTxID := make(map[uint16]string, len(targets))
	entries := make([]entry, len(targets))
	for i, ip := range targets {
		txID := base + uint16(i)
		entries[i] = entry{ip: ip, txID: txID}
		byTxID[txID] = ip
	}

	// responded tracks IPs that have already replied (protected by mu).
	var mu sync.Mutex
	responded := make(map[string]bool, len(targets))

	// deadline is when we stop reading altogether.
	deadline := time.Now().Add(r.opts.Timeout)
	if err = conn.SetReadDeadline(deadline); err != nil {
		return err
	}

	// sendAll blasts NBSTAT queries to all pending (non-responded) hosts and
	// returns the number of packets actually sent.
	sendAll := func() int {
		sent := 0
		for _, e := range entries {
			select {
			case <-ctx.Done():
				return sent
			default:
			}
			mu.Lock()
			skip := responded[e.ip]
			mu.Unlock()
			if skip {
				continue
			}
			addr := &net.UDPAddr{IP: net.ParseIP(e.ip), Port: netbiosPort}
			if _, werr := conn.WriteTo(buildNBSTATQueryWithTxID(e.txID), addr); werr != nil {
				logger.Debugf("[netbios] write error for %s: %v", e.ip, werr)
				continue
			}
			logger.Debugf("[netbios] NBSTAT sent -> %s", e.ip)
			sent++
			time.Sleep(sendPace)
		}
		return sent
	}

	// Reader goroutine — runs until read deadline or ctx cancellation.
	var readerWg sync.WaitGroup
	readerWg.Add(1)
	go func() {
		defer readerWg.Done()
		buf := make([]byte, 1024)
		for {
			n, src, rerr := conn.ReadFrom(buf)
			if rerr != nil {
				return // deadline or closed
			}
			srcUDP, ok := src.(*net.UDPAddr)
			if !ok || srcUDP.Port != netbiosPort || n < 2 {
				continue
			}
			rxTxID := binary.BigEndian.Uint16(buf[:2])
			mu.Lock()
			ip, known := byTxID[rxTxID]
			if known {
				responded[ip] = true
			}
			mu.Unlock()
			if !known {
				continue
			}
			hostname, parseErr := parseResponse(buf[:n])
			if parseErr != nil {
				logger.Debugf("[netbios] parse error for %s: %v", ip, parseErr)
				continue
			}
			select {
			case results <- proto.HostResult{
				IP:       ip,
				Hostname: hostname,
				Method:   proto.MethodNetBIOS,
			}:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wave 1: send to everyone.
	n1 := sendAll()
	logger.Infof("[netbios] all %d NBSTAT queries sent (wave 1)", n1)

	// Wave 2: after retransmitAfter, re-send to hosts that haven't replied yet.
	select {
	case <-ctx.Done():
		conn.Close()
		readerWg.Wait()
		return ctx.Err()
	case <-time.After(retransmitAfter):
	}
	if n2 := sendAll(); n2 > 0 {
		logger.Infof("[netbios] retransmitted %d NBSTAT queries (wave 2)", n2)
	}

	// Wait for the read deadline to expire (or ctx cancel), then close.
	select {
	case <-ctx.Done():
		conn.Close()
	case <-time.After(time.Until(deadline)):
		conn.Close()
	}
	readerWg.Wait()

	mu.Lock()
	n := len(responded)
	mu.Unlock()
	logger.Infof("[netbios] all %d requests processed (%d responded)", len(targets), n)
	return nil
}
