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

	// sendBudgetFrac is the fraction of the scan timeout allocated to wave-1 sends.
	// The remainder is reserved for receiving replies and the optional wave-2 retransmit.
	sendBudgetFrac = 0.35

	// PacingFloor / PacingCap bound the inter-packet delay.
	// 100 µs → 10 000 pkt/s, safe for gigabit Ethernet.
	// 1 ms  →  1 000 pkt/s, conservative floor for small subnets.
	PacingFloor = 100 * time.Microsecond
	PacingCap   = 1 * time.Millisecond

	// retransmitBuffer is the pause between wave-1 completion and wave-2 start.
	retransmitBuffer = 200 * time.Millisecond

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

// ComputePacing returns the inter-packet delay for NBSTAT wave sends.
// It allocates sendBudgetFrac of the timeout to the send phase, then clamps
// to [PacingFloor, PacingCap].  Exported so the orchestrator can estimate
// wave-1 duration when scheduling dependent resolvers (e.g. NTLM start delay).
func ComputePacing(timeout time.Duration, targetCount int) time.Duration {
	if targetCount == 0 {
		return PacingCap
	}
	budget := time.Duration(float64(timeout) * sendBudgetFrac)
	pacing := budget / time.Duration(targetCount)
	if pacing < PacingFloor {
		return PacingFloor
	}
	if pacing > PacingCap {
		return PacingCap
	}
	return pacing
}

// Resolve opens a single shared UDP socket, fires NBSTAT queries at all
// targets (wave 1), then retransmits to non-responders 200 ms after wave 1
// completes (wave 2).  Replies are collected asynchronously until the overall
// timeout expires or ctx is cancelled.
func (r *Resolver) Resolve(ctx context.Context, targets []string, results chan<- proto.HostResult) error {
	if len(targets) == 0 {
		return nil
	}

	conn, err := net.ListenPacket(netbiosUDPNetwork, netbiosBindAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

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

	var mu sync.Mutex
	responded := make(map[string]bool, len(targets))

	deadline := time.Now().Add(r.opts.Timeout)
	if err = conn.SetReadDeadline(deadline); err != nil {
		return err
	}

	pacing := ComputePacing(r.opts.Timeout, len(targets))

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
			sent++
			time.Sleep(pacing)
		}
		return sent
	}

	var readerWg sync.WaitGroup
	readerWg.Add(1)
	go func() {
		defer readerWg.Done()
		buf := make([]byte, 1024)
		for {
			n, src, rerr := conn.ReadFrom(buf)
			if rerr != nil {
				return
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
			case results <- proto.HostResult{IP: ip, Hostname: hostname, Method: proto.MethodNetBIOS}:
			case <-ctx.Done():
				return
			}
		}
	}()

	n1 := sendAll()
	logger.Infof("[netbios] wave 1: %d queries sent (pacing %v)", n1, pacing)

	// Wave 2 fires retransmitBuffer after wave 1 finishes, not on a fixed clock,
	// so it is always correct regardless of how long wave 1 took.
	select {
	case <-ctx.Done():
		conn.Close()
		readerWg.Wait()
		return ctx.Err()
	case <-time.After(retransmitBuffer):
	}
	if n2 := sendAll(); n2 > 0 {
		logger.Infof("[netbios] wave 2: %d queries retransmitted", n2)
	}

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
	logger.Infof("[netbios] done (%d/%d responded)", n, len(targets))
	return nil
}
