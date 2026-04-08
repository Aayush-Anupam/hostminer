// Command mdnsprobe scans a subnet for mDNS/DNS-SD enabled hosts.
//
// Usage:
//
//	mdnsprobe --target <CIDR> [--interface <ip|name>] [--timeout <duration>] [--methods <list>] [--verbose]
//
// Examples:
//
//	# Auto-detect interface from target subnet (CIDR-based selection)
//	mdnsprobe --target 192.168.1.0/24
//
//	# Specify interface by IP address (recommended on Windows)
//	mdnsprobe --target 192.168.1.0/24 --interface 192.168.1.5
//
//	# Specify interface by name (Linux/macOS)
//	mdnsprobe --target 192.168.1.0/24 --interface eth0
//
//	# Specify interface by display name (Windows)
//	mdnsprobe --target 192.168.1.0/24 --interface "Wi-Fi"
//
//	# Select resolution methods (comma-separated; currently only "mdns" is supported)
//	mdnsprobe --target 192.168.1.0/24 --methods mdns
//
//	# Shorter timeout and verbose logging
//	mdnsprobe --target 192.168.1.0/24 --timeout 10s --verbose
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	mdns "mdnsprobe"
)

func main() {
	target := flag.String("target", "", "Target subnet in CIDR notation (required), e.g. 192.168.1.0/24")
	iface := flag.String("interface", "", "Network interface: IP (192.168.1.5), name (eth0/Wi-Fi), or empty for auto-detect via CIDR matching")
	timeout := flag.Duration("timeout", 20*time.Second, "How long to listen for mDNS responses")
	methods := flag.String("methods", "", "Comma-separated resolution methods to use (default: mdns). Supported: mdns")
	verbose := flag.Bool("verbose", false, "Print verbose diagnostic log output to stderr")
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

	var resolvedMethods []mdns.Method
	if *methods != "" {
		for _, raw := range strings.Split(*methods, ",") {
			m := mdns.Method(strings.TrimSpace(raw))
			if m != "" {
				resolvedMethods = append(resolvedMethods, m)
			}
		}
	}

	results, err := mdns.Probe(context.Background(), mdns.Options{
		CIDR:      *target,
		Interface: *iface,
		Timeout:   *timeout,
		Methods:   resolvedMethods,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== mDNS Results for %s ===\n", *target)
	for _, r := range results {
		fmt.Printf("%-18s  %s\n", r.IP, r.Hostname)
	}
	fmt.Printf("\nTotal: %d host(s) found\n", len(results))
}
