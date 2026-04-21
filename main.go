// Package hostminer discovers hostnames for every IP in a subnet by running
// multiple resolution strategies (mDNS, NetBIOS, …) in parallel.
//
// Use [Probe] to scan a subnet:
//
//	results, err := hostminer.Probe(ctx, hostminer.Options{
//	    CIDR:      "192.168.1.0/24",
//	    Interface: "192.168.1.5", // or empty for auto-detect
//	})
//
// For the command-line tool, see cmd/hostminer.
package hostminer
