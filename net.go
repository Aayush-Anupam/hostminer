package hostminer

import (
	"net"
)

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
