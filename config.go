package hostminer

import "time"

const (
	// MdnsAddr is the IPv4 multicast address used by mDNS (RFC 6762).
	MdnsAddr    = "224.0.0.251"
	MdnsAddrStr = "224.0.0.251:5353"

	// ProbeTimeout is the default scan duration when Options.Timeout is zero.
	ProbeTimeout = 20 * time.Second

	// resultChBuffer is the capacity of the shared result channel. Increase
	// this if log warnings report dropped results on large subnets.
	resultChBuffer = 4096
)

// BaseServiceTypes are the DNS-SD service types queried during an mDNS scan.
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
