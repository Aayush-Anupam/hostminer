// Package netbios implements hostname resolution via the NetBIOS Name Service
// (NBNS) Node Status Request (NBSTAT, RFC 1002).
package netbios

import (
	"context"
	"net"
	"sync"
	"time"

	"hostminer/internal/logger"
	"hostminer/internal/proto"
)

const (
	defaultWorkers    = 10
	defaultTimeout    = 2 * time.Second
	netbiosPort       = 137
	netbiosUDPNetwork = "udp4"
	netbiosBindAddr   = ":0"
)

// Options customises the NetBIOS resolver.
type Options struct {
	// Workers is the size of the UDP worker pool.
	// Each worker handles one IP at a time.  Defaults to 10.
	Workers int

	// Timeout is the per-IP UDP read deadline.  Defaults to 2 s.
	Timeout time.Duration
}

func (o *Options) withDefaults() Options {
	out := *o
	if out.Workers <= 0 {
		out.Workers = defaultWorkers
	}
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

// Resolve fans the target IPs across a fixed worker pool.
// Each worker sends a single NBSTAT UDP datagram and writes a [proto.HostResult]
// if a hostname is returned.  Returns when all targets are done or ctx is
// cancelled.
func (r *Resolver) Resolve(ctx context.Context, targets []string, results chan<- proto.HostResult) error {
	work := make(chan string, len(targets))
	for _, ip := range targets {
		work <- ip
	}
	close(work)

	var wg sync.WaitGroup
	for i := 0; i < r.opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range work {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if hostname := r.query(ip); hostname != "" {
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
			}
		}()
	}
	wg.Wait()
	logger.Infof("[netbios] all %d requests processed", len(targets))
	return nil
}

// query sends a single NBSTAT datagram to ip:137, waits for a reply,
// and returns the first workstation/file-server name found, or "" on error.
func (r *Resolver) query(ip string) string {
	conn, err := net.ListenPacket(netbiosUDPNetwork, netbiosBindAddr)
	if err != nil {
		logger.Infof("[netbios] listen error for %s: %v", ip, err)
		return ""
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			logger.Debugf("[netbios] close error for %s: %v", ip, closeErr)
		}
	}()

	if err = conn.SetDeadline(time.Now().Add(r.opts.Timeout)); err != nil {
		logger.Infof("[netbios] set deadline error for %s: %v", ip, err)
		return ""
	}

	targetAddr := &net.UDPAddr{IP: net.ParseIP(ip), Port: netbiosPort}
	if _, err = conn.WriteTo(buildNBSTATQuery(), targetAddr); err != nil {
		logger.Infof("[netbios] write error for %s: %v", ip, err)
		return ""
	}
	logger.Debugf("[netbios] NBSTAT sent -> %s", ip)

	buf := make([]byte, 1024)
	for {
		n, src, readErr := conn.ReadFrom(buf)
		if readErr != nil {
			// Deadline exceeded is the normal case for hosts that simply don't
			// speak NetBIOS — suppress it to keep logs clean.
			return ""
		}

		srcUDP, ok := src.(*net.UDPAddr)
		if !ok || !srcUDP.IP.Equal(net.ParseIP(ip)) || srcUDP.Port != netbiosPort {
			// Stale datagram from a previous query; keep reading.
			continue
		}

		hostname, parseErr := parseResponse(buf[:n])
		if parseErr != nil {
			logger.Debugf("[netbios] parse error for %s: %v", ip, parseErr)
			return ""
		}
		return hostname
	}
}
