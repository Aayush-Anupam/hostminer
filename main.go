package main

import (
	"fmt"
	"log"
	"sync"
)

func main() {
	iface, err := findInterfaceByIP(MyInterfaceIP)
	if err != nil {
		log.Fatalf("interface not found: %v", err)
	}
	log.Printf("Interface: %s (index %d)", iface.Name, iface.Index)

	d, err := NewDispatcher(iface)
	if err != nil {
		log.Fatalf("dispatcher: %v", err)
	}

	targets, err := hostsFromCIDR("192.168.29.0/24")
	if err != nil {
		log.Fatalf("CIDR expand: %v", err)
	}
	log.Printf("Scanning %d hosts", len(targets))

	// Start global query sender before workers so queries are
	// already in flight when workers begin listening.
	RunQuerySender(d, targets)

	ipQueue := make(chan string, len(targets))
	for _, ip := range targets {
		ipQueue <- ip
	}
	close(ipQueue)

	type result struct {
		ip       string
		hostname string
	}
	results := make(chan result, WorkerCount)

	var wg sync.WaitGroup
	for i := 0; i < WorkerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipQueue {
				hostname := probe(ip, d)
				if hostname != "" {
					results <- result{ip: ip, hostname: hostname}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	fmt.Println("\n=== Results ===")
	for r := range results {
		fmt.Printf("%-18s  %s\n", r.ip, r.hostname)
	}
}
