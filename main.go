package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
)

func main() {
	iface, err := findInterfaceByIP(MyInterfaceIP)
	if err != nil {
		log.Fatalf("interface not found: %v", err)
	}
	log.Printf("Interface: %s (index %d, flags: %s, MTU: %d)", iface.Name, iface.Index, iface.Flags, iface.MTU)
	if iface.Flags&net.FlagUp == 0 {
		log.Fatalf("interface %s is DOWN — bring it up first", iface.Name)
	}
	if iface.Flags&net.FlagMulticast == 0 {
		log.Fatalf("interface %s does not support multicast — mDNS will not work", iface.Name)
	}

	d, err := NewDispatcher(iface)
	if err != nil {
		log.Fatalf("dispatcher: %v", err)
	}

	targets, err := hostsFromCIDR("192.168.146.0/24")
	if err != nil {
		log.Fatalf("CIDR expand: %v", err)
	}
	log.Printf("Scanning %d hosts", len(targets))

	// Build a set for O(1) lookup — only record results for IPs we asked about.
	targetSet := make(map[string]bool, len(targets))
	for _, ip := range targets {
		targetSet[ip] = true
	}

	// Start DNS-SD global queries (runs in its own goroutine).
	RunQuerySender(d)

	// Send all reverse PTR queries in a controlled burst, concurrently
	// with the collector below. readLoop is already running so no
	// reply can arrive before we are ready to collect it.
	go func() {
		for _, ip := range targets {
			if rev := buildReverseName(ip); rev != "" {
				d.Send(rev, dns.TypePTR)
				time.Sleep(QueryPacing)
			}
		}
		log.Printf("All PTR queries sent")
	}()

	// Collect all results for one ProbeTimeout window.
	// Every ip→hostname pair that arrives on resultCh during this
	// window is recorded. No per-IP waiting, no per-IP goroutines.
	deadline := time.NewTimer(ProbeTimeout)
	defer deadline.Stop()

	results := make(map[string]string, 64)

collect:
	for {
		select {
		case r := <-d.resultCh:
			// Only record IPs we actually asked about, skip duplicates.
			if targetSet[r.IP] {
				if _, seen := results[r.IP]; !seen {
					results[r.IP] = r.Hostname
					log.Printf("found: %-18s  %s", r.IP, r.Hostname)
				}
			}
		case <-deadline.C:
			break collect
		}
	}

	fmt.Println("\n=== Results ===")
	for ip, hostname := range results {
		fmt.Printf("%-18s  %s\n", ip, hostname)
	}
	fmt.Printf("\nTotal: %d host(s) found out of %d scanned\n", len(results), len(targets))
}
