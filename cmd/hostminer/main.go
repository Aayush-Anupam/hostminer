// Command hostminer scans a subnet and discovers hostnames using multiple
// resolution strategies running in parallel.
//
// Resolution is tiered: rDNS, NetBIOS, and mDNS start immediately; NTLM
// waits until the UDP resolvers have had time to respond, then probes only
// the hosts they did not resolve.
//
// Usage:
//
//	hostminer --target <CIDR> [flags]
//
// Examples:
//
//	# Auto-detect interface, all methods, default timeout
//	hostminer --target 192.168.1.0/24
//
//	# Specify interface by IP (recommended on Windows)
//	hostminer --target 192.168.1.0/24 --interface 192.168.1.5
//
//	# Larger subnet with extended timeout
//	hostminer --target 10.0.0.0/16 --timeout 60s
//
//	# UDP methods only (faster, no TCP connections)
//	hostminer --target 192.168.1.0/24 --methods mdns,netbios,rdns
//
//	# NTLM with relaxed per-host timeout (internet / firewalled targets)
//	hostminer --target 10.10.0.0/24 --methods ntlm --ntlm-timeout 3s
//
//	# Verbose output
//	hostminer --target 192.168.1.0/24 -v
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"hostminer"
	"hostminer/internal/logger"
)

func main() {
	target := flag.String("target", "", "Target subnet in CIDR notation (required), e.g. 192.168.1.0/24")
	iface := flag.String("interface", "", "Network interface: IP (192.168.1.5), name (eth0/Wi-Fi), or empty for auto-detect")
	timeout := flag.Duration("timeout", hostminer.ProbeTimeout, "Total scan duration")
	methods := flag.String("methods", "", "Comma-separated methods: mdns,netbios,rdns,ntlm (default: all four)")
	netbiosTimeout := flag.Duration("netbios-timeout", hostminer.DefaultNetBIOSTimeout, "Total NetBIOS scan deadline")
	rdnsTimeout := flag.Duration("rdns-timeout", 0, "Total PTR-lookup budget (0 = use --timeout)")
	ntlmTimeout := flag.Duration("ntlm-timeout", hostminer.DefaultNTLMTimeout, "Per-host RDP probe deadline for NTLM (use 3-5s for internet targets)")
	v := flag.Bool("v", false, "Verbose: info-level logs on stderr")
	vv := flag.Bool("vv", false, "Very verbose: debug-level logs on stderr (implies -v)")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "error: --target is required")
		fmt.Fprintln(os.Stderr)
		flag.Usage()
		os.Exit(1)
	}

	switch {
	case *vv:
		logger.SetLevel(logger.LevelDebug)
	case *v:
		logger.SetLevel(logger.LevelInfo)
	}

	results, err := hostminer.Probe(context.Background(), hostminer.Options{
		CIDR:           *target,
		Interface:      *iface,
		Timeout:        *timeout,
		Methods:        parseMethods(*methods),
		NetBIOSTimeout: *netbiosTimeout,
		RDNSTimeout:    *rdnsTimeout,
		NTLMTimeout:    *ntlmTimeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== hostminer results for %s ===\n", *target)
	for _, r := range results {
		fmt.Printf("%-18s  %-10s  %s\n", r.IP, "["+string(r.Method)+"]", r.Hostname)
	}
	fmt.Printf("\nTotal: %d host(s) found\n", len(results))
}

func parseMethods(raw string) []hostminer.Method {
	if raw == "" {
		return nil
	}
	var out []hostminer.Method
	for _, s := range strings.Split(raw, ",") {
		if m := hostminer.Method(strings.TrimSpace(s)); m != "" {
			out = append(out, m)
		}
	}
	return out
}
