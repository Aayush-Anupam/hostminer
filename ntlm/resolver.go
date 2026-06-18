// Package ntlm resolves hostnames by probing RDP (port 3389) and extracting
// the computer name from the NTLM Type-2 challenge returned during the
// CredSSP/NLA handshake, with a TLS certificate CN as fallback.
package ntlm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"hostminer/internal/logger"
	"hostminer/internal/proto"
)

const (
	rdpPort        = ":3389"
	ntlmSignature  = "NTLMSSP\x00"
	defaultTimeout = 5 * time.Second
	maxWorkers     = 64
)

// ntlmNegotiateBlob is a minimal NTLM NEGOTIATE_MESSAGE (Type-1).
var ntlmNegotiateBlob = []byte{
	0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
	0x01, 0x00, 0x00, 0x00,
	0xb7, 0x82, 0x08, 0xe2,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x0a, 0x00, 0x63, 0x45, 0x00, 0x00, 0x00, 0x0f,
}

// Options customises the NTLM/RDP resolver.
type Options struct {
	// Timeout is the per-host RDP probe deadline.
	// Defaults to 5 s.
	Timeout time.Duration
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	return o
}

// Resolver implements [proto.Resolver] by probing RDP port 3389 and parsing
// the NTLM Type-2 challenge for the NetBIOS computer name.
type Resolver struct {
	opts Options
	dial func(network, address string) (net.Conn, error)
}

// NewResolver creates a new NTLM/RDP Resolver with the given options.
func NewResolver(opts Options) *Resolver {
	return &Resolver{
		opts: opts.withDefaults(),
		dial: net.Dial,
	}
}

func (r *Resolver) Name() string { return string(proto.MethodNTLM) }

// Resolve probes each target on TCP/3389 concurrently and writes resolved
// hostnames to results. It returns when all workers are done or ctx is
// cancelled.
func (r *Resolver) Resolve(ctx context.Context, targets []string, results chan<- proto.HostResult) error {
	if len(targets) == 0 {
		return nil
	}

	ipCh := make(chan string, len(targets))
	for _, ip := range targets {
		ipCh <- ip
	}
	close(ipCh)

	workers := len(targets)
	if workers > maxWorkers {
		workers = maxWorkers
	}

	logger.Infof("[ntlm] probing %d targets (%d workers, timeout %v)", len(targets), workers, r.opts.Timeout)

	var found atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ip, ok := <-ipCh:
					if !ok {
						return
					}
					name := resolveNTLM(ip, r.dial, r.opts.Timeout)
					if name == "" {
						continue
					}
					found.Add(1)
					select {
					case results <- proto.HostResult{IP: ip, Hostname: name, Method: proto.MethodNTLM}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	logger.Infof("[ntlm] done (%d/%d resolved)", found.Load(), len(targets))
	return nil
}

// resolveNTLM probes ip:3389, performs the RDP/NTLM handshake, and returns
// the best hostname it can extract (NbComputerName > DnsComputerName > TLS CN).
func resolveNTLM(ip string, dial func(network, address string) (net.Conn, error), timeout time.Duration) string {
	result := probeRDP(ip, dial, timeout)
	if result.err != nil {
		logger.Debugf("[ntlm] %s: %v", ip, result.err)
		return ""
	}
	if result.nbComputerName != "" {
		logger.Infof("[ntlm] %s → %s (source: %s)", ip, result.nbComputerName, result.hostnameSource)
		return result.nbComputerName
	}
	if result.dnsComputerName != "" {
		logger.Infof("[ntlm] %s → %s (source: %s)", ip, result.dnsComputerName, result.hostnameSource)
		return result.dnsComputerName
	}
	logger.Debugf("[ntlm] %s: handshake succeeded but no hostname found", ip)
	return ""
}

// rdpInfo holds the data extracted from a single RDP probe.
type rdpInfo struct {
	nbComputerName  string
	dnsComputerName string
	hostnameSource  string
	err             error
}

func probeRDP(ip string, dial func(network, address string) (net.Conn, error), timeout time.Duration) rdpInfo {
	conn, err := dial("tcp", ip+rdpPort)
	if err != nil {
		return rdpInfo{err: err}
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return rdpInfo{err: fmt.Errorf("set deadline: %w", err)}
	}

	negType, selectedProto, err := doX224Handshake(ip, conn)
	if err != nil {
		return rdpInfo{err: err}
	}

	if negType == 0x02 && selectedProto == 0x00000000 {
		return rdpInfo{err: fmt.Errorf("server downgraded to classic RDP (no TLS)")}
	}

	tlsConn, certCN, err := doTLSHandshake(ip, conn, timeout)
	if err != nil {
		return rdpInfo{err: err}
	}

	if negType == 0x03 || selectedProto == 0x00000001 {
		if certCN != "" {
			return rdpInfo{
				nbComputerName: certCN,
				hostnameSource: "TLS certificate (SSL-only or NEG_FAILURE path)",
			}
		}
		return rdpInfo{err: fmt.Errorf("SSL-only / NEG_FAILURE: no cert CN available")}
	}

	return doNTLMExchange(ip, tlsConn, certCN)
}

func doX224Handshake(ip string, conn net.Conn) (negType byte, selectedProto uint32, err error) {
	cookie := []byte("Cookie: mstshash=nmap\r\n")
	rdpNegReq := []byte{0x01, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00}
	x224Fixed := []byte{0xE0, 0x00, 0x00, 0x00, 0x00, 0x00}
	li := byte(len(x224Fixed) + len(cookie) + len(rdpNegReq))
	tpktLen := uint16(4 + 1 + int(li))

	x224CR := []byte{0x03, 0x00, byte(tpktLen >> 8), byte(tpktLen), li}
	x224CR = append(x224CR, x224Fixed...)
	x224CR = append(x224CR, cookie...)
	x224CR = append(x224CR, rdpNegReq...)

	if _, err = conn.Write(x224CR); err != nil {
		return 0, 0, fmt.Errorf("x224 write: %w", err)
	}

	ccBuf := make([]byte, 1024)
	ccN, err := conn.Read(ccBuf)
	if err != nil {
		return 0, 0, fmt.Errorf("x224 cc read: %w", err)
	}
	ccBuf = ccBuf[:ccN]

	if len(ccBuf) >= 19 {
		negType = ccBuf[11]
		selectedProto = binary.LittleEndian.Uint32(ccBuf[15:19])
		logger.Debugf("[ntlm] %s: X.224 neg_type=0x%02x selected_proto=0x%08x", ip, negType, selectedProto)
	}

	return negType, selectedProto, nil
}

func doTLSHandshake(ip string, conn net.Conn, timeout time.Duration) (*tls.Conn, string, error) {
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec
	if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, "", fmt.Errorf("tls set deadline: %w", err)
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, "", fmt.Errorf("tls handshake: %w", err)
	}

	var certCN string
	if certs := tlsConn.ConnectionState().PeerCertificates; len(certs) > 0 {
		cert := certs[0]
		if len(cert.DNSNames) > 0 {
			certCN = cert.DNSNames[0]
		} else if cert.Subject.CommonName != "" {
			certCN = cert.Subject.CommonName
		}
	}
	logger.Debugf("[ntlm] %s: TLS handshake done, cert CN=%q", ip, certCN)

	return tlsConn, certCN, nil
}

func doNTLMExchange(ip string, tlsConn *tls.Conn, certCN string) rdpInfo {
	negoToken := asn1Wrap(0xA0, asn1Wrap(0x04, ntlmNegotiateBlob))
	negoTokensField := asn1Wrap(0xA1, asn1Wrap(0x30, asn1Wrap(0x30, negoToken)))
	versionField := asn1Wrap(0xA0, []byte{0x02, 0x01, 0x02})
	tsRequest := asn1Wrap(0x30, append(versionField, negoTokensField...))

	if _, err := tlsConn.Write(tsRequest); err != nil {
		if certCN != "" {
			return rdpInfo{nbComputerName: certCN, hostnameSource: "TLS certificate (TSRequest write failed)"}
		}
		return rdpInfo{err: fmt.Errorf("tsrequest write: %w", err)}
	}

	msg, err := readNTLMResponse(tlsConn)
	if err != nil {
		if certCN != "" {
			return rdpInfo{nbComputerName: certCN, hostnameSource: "TLS certificate (no NTLM in response)"}
		}
		return rdpInfo{err: err}
	}
	if msg == nil {
		if certCN != "" {
			return rdpInfo{nbComputerName: certCN, hostnameSource: "TLS certificate (NTLMSSP sig not found)"}
		}
		return rdpInfo{err: fmt.Errorf("NTLMSSP signature not found")}
	}

	result, err := parseNTLMType2(msg)
	if err != nil {
		return rdpInfo{err: err}
	}

	if result.nbComputerName != "" || result.dnsComputerName != "" {
		result.hostnameSource = "NTLM Type-2 AvPairs"
	} else if certCN != "" {
		result.nbComputerName = certCN
		result.hostnameSource = "TLS certificate (NTLM AvPairs empty)"
	}

	logger.Debugf("[ntlm] %s: NbComputerName=%q DnsComputerName=%q source=%s",
		ip, result.nbComputerName, result.dnsComputerName, result.hostnameSource)

	return result
}

func readNTLMResponse(tlsConn *tls.Conn) ([]byte, error) {
	sig := []byte(ntlmSignature)
	var fullResp []byte
	tmp := make([]byte, 4096)

	for {
		n, readErr := tlsConn.Read(tmp)
		if n > 0 {
			fullResp = append(fullResp, tmp[:n]...)
			if idx := bytes.Index(fullResp, sig); idx >= 0 {
				return fullResp[idx:], nil
			}
		}
		if readErr != nil {
			return nil, fmt.Errorf("tsresponse read: %w", readErr)
		}
	}
}

func parseNTLMType2(msg []byte) (rdpInfo, error) {
	var result rdpInfo

	if len(msg) < 48 {
		return result, fmt.Errorf("NTLM message too short (%d bytes)", len(msg))
	}
	if msgType := binary.LittleEndian.Uint32(msg[8:12]); msgType != 2 {
		return result, fmt.Errorf("expected NTLM Type-2, got type %d", msgType)
	}

	tiLen := int(binary.LittleEndian.Uint16(msg[40:42]))
	tiOffset := int(binary.LittleEndian.Uint32(msg[44:48]))
	if tiOffset+tiLen > len(msg) {
		return result, fmt.Errorf("TargetInfo out of bounds")
	}
	targetInfo := msg[tiOffset : tiOffset+tiLen]

	for len(targetInfo) >= 4 {
		avID := binary.LittleEndian.Uint16(targetInfo[0:2])
		avLen := int(binary.LittleEndian.Uint16(targetInfo[2:4]))
		if avID == 0x0000 {
			break
		}
		if 4+avLen > len(targetInfo) {
			break
		}
		value := utf16LEToString(targetInfo[4 : 4+avLen])
		switch avID {
		case 0x0001:
			result.nbComputerName = value
		case 0x0003:
			result.dnsComputerName = value
		}
		targetInfo = targetInfo[4+avLen:]
	}

	return result, nil
}

func asn1Wrap(tag byte, value []byte) []byte {
	l := len(value)
	var lenBytes []byte
	switch {
	case l < 0x80:
		lenBytes = []byte{byte(l)}
	case l < 0x100:
		lenBytes = []byte{0x81, byte(l)}
	default:
		lenBytes = []byte{0x82, byte(l >> 8), byte(l)}
	}
	out := []byte{tag}
	out = append(out, lenBytes...)
	return append(out, value...)
}

func utf16LEToString(b []byte) string {
	if len(b)%2 != 0 {
		return string(b)
	}
	runes := make([]rune, len(b)/2)
	for i := range runes {
		runes[i] = rune(binary.LittleEndian.Uint16(b[i*2:]))
	}
	return string(runes)
}
