package main

import "time"

const (
	MyInterfaceIP = "192.168.146.208"
	MdnsAddr      = "224.0.0.251"
	MdnsAddrStr   = "224.0.0.251:5353"
	ProbeTimeout  = 20 * time.Second // one global window, 5s is plenty for mDNS
	QueryPacing   = 1 * time.Millisecond
)

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
