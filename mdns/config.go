package mdns

import "time"

const (
	// MdnsAddr is the IPv4 multicast address used by mDNS (RFC 6762).
	MdnsAddr    = "224.0.0.251"
	MdnsAddrStr = "224.0.0.251:5353"

	// resultChBuffer is the capacity of the shared result channel. Increase
	// this if log warnings report dropped results on large subnets.
	resultChBuffer = 4096

	// ptrSendBudget is the fraction of the scan timeout spent sending PTR queries.
	ptrSendBudget  = 0.45
	ptrPacingFloor = 50 * time.Microsecond
	ptrPacingCap   = 1 * time.Millisecond

	// ptrMaxTargets is the largest target list for which PTR queries are sent.
	// mDNS is link-local and does not cross routers; sending reverse-PTR queries
	// for IPs outside the local segment produces no responses.  DNS-SD queries
	// are always sent regardless of subnet size.
	ptrMaxTargets = 512

	dnsSDInterQueryDelay = 20 * time.Millisecond
	dnsSDPhase2Fraction  = 0.25
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
