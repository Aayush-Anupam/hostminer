package mdns

import (
	"strings"

	"github.com/miekg/dns"
)

// extractHostResults scans a DNS record set and returns every ip→hostname
// pair it can derive from A records, reverse PTR records, and SRV records.
func extractHostResults(records []dns.RR) map[string]string {
	aRecords, aNames := indexARecords(records)
	result := make(map[string]string)

	extractFromReversePTR(records, result)
	extractFromARecords(aRecords, aNames, result)
	extractFromSRVRecords(records, aRecords, aNames, result)

	return result
}

// indexARecords builds two lookup maps from A records:
//   - aRecords: lowercase name → IP string
//   - aNames:   lowercase name → original-case name (to preserve hostname casing)
func indexARecords(records []dns.RR) (aRecords, aNames map[string]string) {
	aRecords = make(map[string]string)
	aNames = make(map[string]string)
	for _, rr := range records {
		if r, ok := rr.(*dns.A); ok {
			lower := strings.ToLower(r.Hdr.Name)
			aRecords[lower] = r.A.String()
			aNames[lower] = r.Hdr.Name
		}
	}
	return
}

// extractFromReversePTR extracts ip→hostname pairs from in-addr.arpa PTR records.
// The IP is encoded directly in the record name so no A record is needed.
func extractFromReversePTR(records []dns.RR, out map[string]string) {
	for _, rr := range records {
		r, ok := rr.(*dns.PTR)
		if !ok || !strings.HasSuffix(r.Hdr.Name, ".in-addr.arpa.") {
			continue
		}
		if ip := arpaToIP(r.Hdr.Name); ip != "" {
			out[ip] = strings.TrimSuffix(r.Ptr, ".")
		}
	}
}

// extractFromARecords maps each A record's IP to its hostname (original casing).
// Skips IPs already resolved by a PTR record.
func extractFromARecords(aRecords, aNames map[string]string, out map[string]string) {
	for lower, ip := range aRecords {
		if _, already := out[ip]; !already {
			out[ip] = strings.TrimSuffix(aNames[lower], ".")
		}
	}
}

// extractFromSRVRecords resolves SRV targets that have a matching A record in
// the same DNS message, associating the A record's IP with the target hostname.
func extractFromSRVRecords(records []dns.RR, aRecords, aNames map[string]string, out map[string]string) {
	for _, rr := range records {
		r, ok := rr.(*dns.SRV)
		if !ok {
			continue
		}
		target := strings.ToLower(r.Target)
		ip, exists := aRecords[target]
		if !exists {
			continue
		}
		if _, already := out[ip]; !already {
			out[ip] = strings.TrimSuffix(aNames[target], ".")
		}
	}
}

// extractDNSSDServices returns service type strings advertised via
// _services._dns-sd._udp.local. PTR records (e.g. "_http._tcp.local.").
func extractDNSSDServices(records []dns.RR) []string {
	var services []string
	for _, rr := range records {
		ptr, ok := rr.(*dns.PTR)
		if !ok || ptr.Hdr.Name != "_services._dns-sd._udp.local." {
			continue
		}
		svc := ptr.Ptr
		if !strings.HasSuffix(svc, ".") {
			svc += "."
		}
		if strings.Contains(svc, "._tcp.local.") || strings.Contains(svc, "._udp.local.") {
			services = append(services, svc)
		}
	}
	return services
}
