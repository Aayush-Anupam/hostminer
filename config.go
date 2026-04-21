package mdns

import "time"

const (
	MdnsAddr     = "224.0.0.251"
	MdnsAddrStr  = "224.0.0.251:5353"
	ProbeTimeout = 20 * time.Second

	// PTR sender tuning
	ptrWorkerCount = 20
	ptrPacingFloor = 50 * time.Microsecond
	ptrPacingCap   = 1 * time.Millisecond
	ptrSendBudget  = 0.45 // fraction of timeout allocated to PTR sending phase

	// DNS-SD query sender
	dnsSDInterQueryDelay = 20 * time.Millisecond
	dnsSDPhase2Fraction  = 0.25 // fraction of timeout for phase 2 re-query window

	// Result collection
	resultChBuffer = 4096
)

// Method identifies a hostname-resolution technique used during a probe.
type Method string

const (
	MethodMDNS Method = "mdns"
	// MethodNetBIOS Method = "netbios"
	// MethodRDNS    Method = "rdns"
)

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
