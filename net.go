package hostminer

import (
	"fmt"
	"net"
	"strings"
)

// buildReverseName converts an IPv4 string like "192.168.29.165" into its
// in-addr.arpa form: "165.29.168.192.in-addr.arpa."
func buildReverseName(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa.",
		parts[3], parts[2], parts[1], parts[0])
}

// arpaToIP is the inverse of buildReverseName: converts
// "165.29.168.192.in-addr.arpa." back to "192.168.29.165".
func arpaToIP(name string) string {
	name = strings.TrimSuffix(name, ".in-addr.arpa.")
	parts := strings.Split(name, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
}

// hostsFromCIDR expands a CIDR block into individual host addresses,
// excluding the network address and broadcast address.
func hostsFromCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

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
