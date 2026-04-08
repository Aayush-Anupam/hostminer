package mdns

import (
	"fmt"
	"net"
	"sort"
)

// ResolveInterface resolves a user-supplied hint to a network interface.
// When hint is empty the interface is chosen automatically by comparing each
// candidate's IPv4 address against the target CIDR — the interface whose
// address shares the longest common prefix with the target network wins.
//
// The hint may be:
//   - An IPv4 address ("192.168.1.5") — works identically on all platforms,
//     including Windows where interface names can be GUIDs or long display names.
//   - An interface name ("eth0", "en0", "Wi-Fi") — platform-specific.
//   - An empty string — triggers automatic selection via [AutoSelectInterfaceForCIDR].
func ResolveInterface(hint, cidr string) (*net.Interface, error) {
	if hint == "" {
		return AutoSelectInterfaceForCIDR(cidr)
	}

	// Try as IP address first. This is the most portable approach and works
	// on Windows (where names like "Local Area Connection" are hard to type)
	// as well as Linux and macOS.
	if net.ParseIP(hint) != nil {
		return findInterfaceByIP(hint)
	}

	// Try as interface name (reliable on Linux/macOS; on Windows prefer
	// using the IP address if the name contains spaces or special characters).
	iface, err := net.InterfaceByName(hint)
	if err != nil {
		return nil, fmt.Errorf("no interface named %q (tip: use an IP address instead, e.g. --interface 192.168.1.5): %w", hint, err)
	}
	return iface, nil
}

// AutoSelectInterfaceForCIDR picks the best network interface for reaching the
// given target CIDR by scoring each candidate interface on how many leading
// bits its IPv4 address shares with the target network's base address (longest
// common-prefix match). This means:
//
//   - An interface on 192.168.146.0/24 is preferred for target 192.168.146.0/24.
//   - An interface on 192.168.1.0/24 outscores one on 10.0.0.0/8 for the same target.
//   - If no interface shares any bits (unlikely) the first suitable one is returned.
//
// The candidate must be: up, non-loopback, multicast-capable, with ≥1 IPv4 address.
func AutoSelectInterfaceForCIDR(cidr string) (*net.Interface, error) {
	_, targetNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid target CIDR %q: %w", cidr, err)
	}
	targetBase := targetNet.IP.To4()

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	type candidate struct {
		iface net.Interface
		score int // common leading bits with targetBase
	}
	var candidates []candidate

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagMulticast == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			score := commonPrefixBits(ip4, targetBase)
			candidates = append(candidates, candidate{iface: iface, score: score})
			break // one IPv4 address per interface is enough for scoring
		}
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no suitable network interface found — need one that is: up, non-loopback, multicast-capable, and has an IPv4 address")
	}

	// Stable sort: highest score first; ties preserve enumeration order so the
	// result is deterministic across runs.
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})

	result := candidates[0].iface
	return &result, nil
}

// commonPrefixBits counts the number of leading bits that are identical in
// the two 4-byte IPv4 addresses a and b.
func commonPrefixBits(a, b net.IP) int {
	count := 0
	for i := 0; i < 4; i++ {
		xor := a[i] ^ b[i]
		if xor == 0 {
			count += 8
			continue
		}
		// Count leading zero bits in the differing byte.
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

// InterfaceIPv4 returns the first IPv4 unicast address assigned to iface.
// This is used to bind the UDP socket to a specific interface rather than
// 0.0.0.0, ensuring traffic flows on the intended interface.
func InterfaceIPv4(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("reading addresses for interface %s: %w", iface.Name, err)
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				return ip4, nil
			}
		}
	}
	return nil, fmt.Errorf("interface %s has no IPv4 address", iface.Name)
}
