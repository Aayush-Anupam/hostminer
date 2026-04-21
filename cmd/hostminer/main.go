// Command hostminer scans a subnet and discovers hostnames using multiple
// resolution strategies (mDNS, and more to come) running in parallel.
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
//	# Use specific resolution methods (comma-separated)
//	hostminer --target 192.168.1.0/24 --methods mdns
//
//	# Shorter timeout with verbose logging
//	hostminer --target 192.168.1.0/24 --timeout 10s --verbose
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"hostminer"
)

func main() {
	target := flag.String("target", "", "Target subnet in CIDR notation (required), e.g. 192.168.1.0/24")
	iface := flag.String("interface", "", "Network interface: IP (192.168.1.5), name (eth0/Wi-Fi), or empty for auto-detect")
	timeout := flag.Duration("timeout", hostminer.ProbeTimeout, "How long to scan for responses")
	methods := flag.String("methods", "", "Comma-separated resolution methods (default: mdns)")
	verbose := flag.Bool("verbose", false, "Print verbose diagnostic output to stderr")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "error: --target is required")
		fmt.Fprintln(os.Stderr)
		flag.Usage()
		os.Exit(1)
	}

	if !*verbose {
		log.SetOutput(io.Discard)
	} else {
		log.SetFlags(log.Ltime | log.Lmicroseconds)
	}

	results, err := hostminer.Probe(context.Background(), hostminer.Options{
		CIDR:      *target,
		Interface: *iface,
		Timeout:   *timeout,
		Methods:   parseMethods(*methods),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== hostminer results for %s ===\n", *target)
	for _, r := range results {
		fmt.Printf("%-18s  %s\n", r.IP, r.Hostname)
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
