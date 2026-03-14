package main

import (
	"time"
)

// probe registers interest in targetIP and blocks until a hostname
// is received from the dispatcher or the deadline expires.
// It sends no queries itself — all queries are handled globally
// by RunQuerySender. The reverse PTR for this IP was already sent
// by RunQuerySender before workers started.
func probe(targetIP string, d *Dispatcher) string {
	entry := d.register(targetIP)
	defer d.unregister(targetIP)

	deadline := time.NewTimer(ProbeTimeout)
	defer deadline.Stop()

	select {
	case hostname := <-entry.ch:
		return hostname
	case <-deadline.C:
		return ""
	}
}
