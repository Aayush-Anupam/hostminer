package main

import "time"

const (
	MyInterfaceIP = "192.168.29.165"
	MdnsAddr      = "224.0.0.251"
	MdnsAddrStr   = "224.0.0.251:5353"
	ProbeTimeout  = 12 * time.Second
	WorkerCount   = 256
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
