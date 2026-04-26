package mdns

import (
	"fmt"
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
