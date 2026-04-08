package mdns

import (
	"fmt"
	"log"
	"net"
	"strings"
)

// buildReverseName converts "192.168.29.165" →
// "165.29.168.192.in-addr.arpa."
func buildReverseName(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa.",
		parts[3], parts[2], parts[1], parts[0])
}

// arpaToIP converts "165.29.168.192.in-addr.arpa." → "192.168.29.165"
func arpaToIP(arpaName string) string {
	arpaName = strings.TrimSuffix(arpaName, ".in-addr.arpa.")
	parts := strings.Split(arpaName, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.%s",
		parts[3], parts[2], parts[1], parts[0])
}

// findInterfaceByIP returns the network interface that has the
// given IP address assigned to it.
func findInterfaceByIP(ipStr string) (*net.Interface, error) {
	target := net.ParseIP(ipStr)
	if target == nil {
		return nil, fmt.Errorf("invalid IP address: %q", ipStr)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing network interfaces: %w", err)
	}

	// Collect all interface→IP pairs for the error message.
	var available []string
	for _, iface := range ifaces {
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			log.Printf("warning: cannot read addresses for interface %s: %v", iface.Name, addrErr)
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
			available = append(available, fmt.Sprintf("%s(%s)", iface.Name, ip))
			if ip.Equal(target) {
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf(
		"no interface with IP %s\navailable interfaces: %s",
		ipStr, strings.Join(available, ", "),
	)
}

// hostsFromCIDR expands a CIDR block into individual host IPs,
// excluding the network address and broadcast address.
func hostsFromCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// Start from the network base address
	cur := ip.Mask(ipNet.Mask)

	var hosts []string
	for ipNet.Contains(cur) {
		if !isNetworkOrBroadcast(cur, ipNet) {
			hosts = append(hosts, cur.String())
		}
		incrementIP(cur)
	}
	return hosts, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func isNetworkOrBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	broadcast := make(net.IP, len(ipNet.IP))
	for i := range ipNet.IP {
		broadcast[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}
	return ip.Equal(ipNet.IP) || ip.Equal(broadcast)
}
