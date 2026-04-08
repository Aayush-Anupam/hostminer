// Package mdns implements mDNS (Multicast DNS, RFC 6762) host discovery
// and DNS-SD (DNS Service Discovery, RFC 6763) scanning.
//
// Use [Probe] to scan a subnet for mDNS-enabled hosts:
//
//	results, err := mdns.Probe(ctx, mdns.Options{
//	    CIDR:      "192.168.1.0/24",
//	    Interface: "192.168.1.5", // or empty for auto-detect
//	})
//
// For the command-line tool, see cmd/mdnsprobe.
package mdns
