package mdns

import "time"

const (
	MdnsAddr     = "224.0.0.251"
	MdnsAddrStr  = "224.0.0.251:5353"
	ProbeTimeout = 20 * time.Second // one global window, 5s is plenty for mDNS
	QueryPacing  = 1 * time.Millisecond
)

// Method identifies a hostname-resolution technique used during a probe.
// Additional methods (NetBIOS, reverse-DNS, etc.) can be added here and
// dispatched inside Probe without changing the public API.
type Method string

const (
	// MethodMDNS resolves hostnames via Multicast DNS (RFC 6762) and DNS-SD (RFC 6763).
	MethodMDNS Method = "mdns"

	// MethodNetBIOS resolves hostnames via NetBIOS Name Service (future).
	// MethodNetBIOS Method = "netbios"

	// MethodRDNS resolves hostnames via unicast reverse-DNS PTR queries (future).
	// MethodRDNS Method = "rdns"
)

// DefaultMethods is the ordered list of resolution techniques used when the
// caller does not specify Methods in Options.
var DefaultMethods = []Method{MethodMDNS}

var BaseServiceTypes = []string{
	"_services._dns-sd._udp.local.",
	"_http._tcp.local.",
	"_https._tcp.local.",
	"_smb._tcp.local.",
	"_wifiMeshAP._tcp.local.",
	"_ipp._tcp.local.",
	"_printer._tcp.local.",
	"_pdl-datastream._tcp.local.",
	"_rdp._tcp.local.",
	"_vnc._tcp.local.",
	"_airplay._tcp.local.",
	"_raop._tcp.local.",
	"_homekit._tcp.local.",
	"_hap._tcp.local.",
}
