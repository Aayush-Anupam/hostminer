package hostminer

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"hostminer/internal/logger"
)

// ResolveInterface picks the outbound network interface according to hint:
//   - empty  → auto-select the best match for cidr
//   - IP string → find the interface that owns that address
//   - anything else → look up by interface name
func ResolveInterface(hint, cidr string) (*net.Interface, error) {
	if hint == "" {
		return autoSelectForCIDR(cidr)
	}
	if net.ParseIP(hint) != nil {
		return findInterfaceByIP(hint)
	}
	iface, err := net.InterfaceByName(hint)
	if err != nil {
		return nil, fmt.Errorf("no interface named %q (tip: use an IP address, e.g. --interface 192.168.1.5): %w", hint, err)
	}
	return iface, nil
}

// ValidateInterfaceForMDNS returns an error if iface cannot be used for mDNS
// (must be up and multicast-capable).
func ValidateInterfaceForMDNS(iface *net.Interface) error {
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface %s is DOWN — bring it up first", iface.Name)
	}
	if iface.Flags&net.FlagMulticast == 0 {
		return fmt.Errorf("interface %s does not support multicast — mDNS requires multicast", iface.Name)
	}
	return nil
}

// InterfaceIPv4 returns the first IPv4 address assigned to iface.
func InterfaceIPv4(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("reading addresses for interface %s: %w", iface.Name, err)
	}
	for _, addr := range addrs {
		if ip := addrToIP(addr); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				return ip4, nil
			}
		}
	}
	return nil, fmt.Errorf("interface %s has no IPv4 address", iface.Name)
}

// autoSelectForCIDR picks the interface whose IPv4 address shares the most
// leading bits with the target CIDR, preferring interfaces that are up,
// non-loopback, and multicast-capable.
func autoSelectForCIDR(cidr string) (*net.Interface, error) {
	_, targetNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	targetBase := targetNet.IP.To4()

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	type candidate struct {
		iface net.Interface
		score int
	}
	var candidates []candidate

	for _, iface := range ifaces {
		if !isUsableInterface(iface) {
			continue
		}
		ip4, ok := firstIPv4(iface)
		if !ok {
			continue
		}
		candidates = append(candidates, candidate{
			iface: iface,
			score: commonPrefixBits(ip4, targetBase),
		})
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no suitable interface found — need one that is: up, non-loopback, multicast-capable, with an IPv4 address")
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})
	result := candidates[0].iface
	return &result, nil
}

// findInterfaceByIP returns the interface that owns the given IP address.
func findInterfaceByIP(ipStr string) (*net.Interface, error) {
	target := net.ParseIP(ipStr)
	if target == nil {
		return nil, fmt.Errorf("invalid IP address: %q", ipStr)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing network interfaces: %w", err)
	}

	var available []string
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			logger.Debugf("cannot read addresses for interface %s: %v", iface.Name, err)
			continue
		}
		for _, addr := range addrs {
			ip := addrToIP(addr)
			if ip == nil {
				continue
			}
			available = append(available, fmt.Sprintf("%s(%s)", iface.Name, ip))
			if ip.Equal(target) {
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no interface with IP %s\navailable: %s", ipStr, strings.Join(available, ", "))
}

// isUsableInterface returns true if iface is up, non-loopback, and multicast-capable.
func isUsableInterface(iface net.Interface) bool {
	return iface.Flags&net.FlagUp != 0 &&
		iface.Flags&net.FlagLoopback == 0 &&
		iface.Flags&net.FlagMulticast != 0
}

// firstIPv4 returns the first IPv4 address on iface, and whether one was found.
func firstIPv4(iface net.Interface) (net.IP, bool) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, false
	}
	for _, addr := range addrs {
		if ip := addrToIP(addr); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				return ip4, true
			}
		}
	}
	return nil, false
}

// addrToIP extracts the net.IP from a net.Addr (either *net.IPNet or *net.IPAddr).
func addrToIP(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	return nil
}

// commonPrefixBits counts how many leading bits two IPv4 addresses share.
func commonPrefixBits(a, b net.IP) int {
	count := 0
	for i := 0; i < 4; i++ {
		xor := a[i] ^ b[i]
		if xor == 0 {
			count += 8
			continue
		}
		for bit := 7; bit >= 0; bit-- {
			if xor&(1<<uint(bit)) != 0 {
				return count
			}
			count++
		}
		return count
	}
	return count
}
