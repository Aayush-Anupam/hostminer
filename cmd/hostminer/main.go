// Command hostminer scans a subnet and discovers hostnames using multiple
// resolution strategies (mDNS, NetBIOS, …) running in parallel.
//
// Usage:
//
//	hostminer --target <CIDR> [--interface <ip|name>] [--timeout <duration>] [--methods <list>] [--verbose]
//
// Examples:
//
//	# Auto-detect interface from the target subnet
//	hostminer --target 192.168.1.0/24
//
//	# Specify interface by IP (recommended on Windows)
//	hostminer --target 192.168.1.0/24 --interface 192.168.1.5
//
//	# Specify interface by name (Linux/macOS)
//	hostminer --target 192.168.1.0/24 --interface eth0
//
//	# Run both mDNS and NetBIOS in parallel
//	hostminer --target 192.168.1.0/24 --methods mdns,netbios
//
//	# NetBIOS only, with custom timeout
//	hostminer --target 192.168.1.0/24 --methods netbios --netbios-timeout 3s
//
//	# Shorter timeout with verbose logging
//	hostminer --target 192.168.1.0/24 --timeout 10s --verbose
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
	timeout := flag.Duration("timeout", hostminer.ProbeTimeout, "How long to scan for responses")
	methods := flag.String("methods", "", "Comma-separated resolution methods: mdns, netbios (default: mdns)")
	netbiosTimeout := flag.Duration("netbios-timeout", hostminer.DefaultNetBIOSTimeout, "Per-scan NetBIOS reply deadline")
	v := flag.Bool("v", false, "Verbose: show info-level logs on stderr")
	vv := flag.Bool("vv", false, "Very verbose: show debug-level logs on stderr (implies -v)")
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
