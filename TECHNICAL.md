# hostminer — Technical Reference

This document covers the internal design of hostminer: how the four resolvers work, how they coordinate, concurrency models, timeout relationships, and how to extend the system.

---

## Architecture Overview

```
Probe()
  │
  ├─ create ResolvedSet (shared, concurrency-safe)
  │
  ├─ Phase A — starts at t=0 (all parallel)
  │    ├─ rDNS    : PTR lookups via OS resolver   (UDP 53, zero load on targets)
  │    ├─ NetBIOS : NBSTAT queries                (UDP 137, adaptive pacing)
  │    └─ mDNS    : PTR + DNS-SD multicast        (UDP 5353, link-local)
  │
  ├─ Phase B — starts at t=startDelay
  │    └─ NTLM   : RDP/CredSSP probe             (TCP 3389, only unresolved IPs)
  │
  └─ collectResults()
       ├─ deduplicates by IP (first-wins)
       ├─ feeds each new result into ResolvedSet  ← live feedback to NTLM
       └─ exits early when all targets resolved
```

The four resolvers are launched as goroutines by `runResolversInParallel` and all write to a single buffered results channel (capacity 4096). `collectResults` drains that channel and updates the shared `ResolvedSet` as each result arrives.

---

## The ResolvedSet

`proto.ResolvedSet` (`internal/proto/proto.go`) is the coordination primitive shared across all resolvers in a single `Probe` run.

- **Written to** by `collectResults` the moment a result is accepted (first-wins deduplication)
- **Read by** NTLM — before building its work queue after the start delay, and again just before dialing each individual IP

This means: if rDNS resolves `192.168.1.5` at t=200ms and NTLM's start delay is 700ms, NTLM will never open a TCP connection to `192.168.1.5`. The skip is applied twice — once when building the initial pending list, and once per-IP inside the worker loop — to catch hosts resolved during queue processing time.

Passing `nil` for the resolved set is safe everywhere; `Has()` and `Add()` are nil-safe no-ops.

---

## NTLM Start Delay

Computed in `probe.go:ntlmStartDelay()`:

```
wave1_estimate = netbios.ComputePacing(netbiosTimeout, targetCount) × targetCount
delay          = wave1_estimate + 300ms buffer
delay          = max(delay, 500ms)
delay          = min(delay, globalTimeout × 25%)
```

The formula uses NetBIOS's own pacing function so the estimate is accurate regardless of subnet size. The 25% cap ensures NTLM always gets at least 75% of the global budget.

| Subnet | NetBIOS wave 1 | NTLM start delay |
|---|---|---|
| /24 (254 hosts, 20s) | ~254ms | 500ms (floor) |
| /22 (1022 hosts, 30s) | ~1.0s | 1.3s |
| /16 (65534 hosts, 60s) | ~6.6s | 6.9s → capped to 15s (25% of 60s) |

---

## Resolver Deep-Dives

### rDNS (`rdns/`)

- **Concurrency**: `min(len(targets), 128)` goroutines, each doing sequential PTR lookups via the OS resolver
- **Retry**: up to 3 attempts per IP; bails immediately on permanent DNS errors (NXDOMAIN, SERVFAIL) to avoid wasting retries
- **Timeout**: defaults to `opts.Timeout` (global scan window); no longer has a separate independent cap that could exceed the global budget
- **Bottleneck**: the upstream DNS server, not goroutine count. 128 workers saturates a typical LAN resolver without overwhelming it.

The rDNS resolver imposes no load on target hosts — it only talks to the DNS server.

### NetBIOS (`netbios/`)

The most carefully designed resolver. One shared UDP socket eliminates per-host FD cost. Transaction IDs (random base + index) correlate responses without inspecting source IPs.

**Adaptive pacing** (`netbios.ComputePacing`):

```
budget  = timeout × 35%
pacing  = budget / targetCount
pacing  = clamp(pacing, 100µs, 1ms)
```

- `/24` at 2s: budget=700ms, pacing=2.8ms → capped to 1ms → wave 1 in 254ms
- `/16` at 20s: budget=7s, pacing=106µs → above 100µs floor → wave 1 in 7s

**Wave 2** fires `retransmitBuffer` (200ms) after wave 1 *completes*, not on a fixed clock. This is correct for all subnet sizes — previously the fixed 900ms meant wave 2 started while wave 1 was still running on large subnets.

**Why single socket + TxID rather than per-host goroutines**: UDP is connectionless. A shared socket with correlation IDs achieves full parallelism (all hosts get probed in wave 1) without the FD overhead of 65k sockets or the complexity of a worker pool.

### mDNS (`mdns/`)

**PTR sender** uses a single goroutine with a `time.Ticker`. The previous implementation used 20 goroutines all competing for the same ticker — since `time.Ticker` fires to exactly one receiver per interval, this gave zero throughput benefit while adding scheduling overhead. One goroutine is correct.

**Subnet guard**: PTR queries are skipped for targets larger than 512 hosts (`ptrMaxTargets`). mDNS is multicast and link-local — it does not cross routers. Sending 65k reverse-PTR queries for IPs outside the local segment produces no responses and wastes bandwidth. DNS-SD service discovery queries always run regardless of subnet size, since they go to `224.0.0.251` and collect responses from whatever is present on the segment.

**DNS-SD phase 2**: After sending the 14 base service types, the sender listens for newly-discovered service types (e.g. `_my-custom-app._tcp.local.`) reported in `_services._dns-sd._udp.local.` responses, and queries those too. This phase runs for 25% of the scan timeout.

**Dispatcher** (`mdns/dispatcher.go`): Owns the multicast socket and runs a background read loop. Results flow through an internal buffered channel (`resultCh`, capacity 4096). If this channel fills, results are dropped and logged as warnings. The `resultChBuffer` constant controls the size.

### NTLM (`ntlm/`)

**Protocol sequence per host** (5–10 round trips):
1. TCP 3-way handshake
2. X.224 Connection Request → Connection Confirm (TPKT/ISO 8073)
3. RDP Negotiation — server advertises supported protocols (NLA/TLS/ClassicRDP)
4. TLS handshake — certificate CN extracted as fallback hostname
5. CredSSP TSRequest with NTLM NEGOTIATE_MESSAGE (Type-1)
6. Server responds with NTLM CHALLENGE_MESSAGE (Type-2) containing AvPairs

AvPairs are parsed for `MsvAvNbComputerName` (0x0001) and `MsvAvDnsComputerName` (0x0003). NbComputerName is preferred — it is the flat NetBIOS name; DnsComputerName is the FQDN.

**Fallback chain**: NTLM AvPairs → TLS certificate DN/SAN → empty (no result).

**DialContext**: `net.Dialer.DialContext` is used so context cancellation aborts in-progress TCP connects immediately. After the connection is established, `conn.SetDeadline` governs all subsequent I/O — the protocol exchange is not context-aware beyond the connection phase.

**Worker count**: 64. The limit is per-host latency (RTT × 5–10), not concurrency. Adding more workers beyond the RTT-induced limit gives diminishing returns.

**Why 1s default**: On a LAN, a closed port responds with TCP RST in <1ms. A host with RDP open completes the full NTLM exchange in <100ms. The only hosts that consume the full timeout are those behind stateful firewalls that silently drop port 3389. 1s is a reasonable balance; internet-facing scans should use 3–5s.

---

## Timeout Relationships

```
opts.Timeout (global, default 20s)
  │
  ├─ rDNS:    opts.RDNSTimeout    default = opts.Timeout  (shared global window)
  ├─ NetBIOS: opts.NetBIOSTimeout default = 2s            (separate; short by design)
  ├─ mDNS:    opts.Timeout                                (runs for full global window)
  └─ NTLM:    opts.NTLMTimeout    default = 1s (per host) (total window = global - startDelay)
```

Previously `DefaultRDNSTimeout = 30s` was hardcoded, which was silently unreachable when `opts.Timeout < 30s`. Now `RDNSTimeout` defaults to the global timeout, making the relationship explicit.

---

## Concurrency Summary

| Resolver | Goroutines | Socket | Packets/s (LAN) |
|---|---|---|---|
| rDNS | 128 workers | OS DNS (many) | ~128 × DNS RTT |
| NetBIOS | 1 sender + 1 reader | 1 UDP | 1 000–10 000 (adaptive) |
| mDNS | 1 PTR sender + 1 DNS-SD sender + 1 reader | 1 UDP multicast | ~1 000 (1ms cap) |
| NTLM | 64 TCP workers | 1 per active connection | 64 simultaneous SYNs |

Total maximum simultaneous open sockets at t=0: ~130 (128 DNS + 1 NetBIOS + 1 mDNS). NTLM sockets open after `startDelay`.

---

## Adding a New Resolver

1. Create a new package under the repo root, e.g. `wmi/`.

2. Implement `proto.Resolver`:

```go
package wmi

import (
    "context"
    "hostminer/internal/proto"
)

type Resolver struct{ opts Options }

func NewResolver(opts Options) *Resolver { ... }
func (r *Resolver) Name() string         { return string(proto.MethodWMI) }
func (r *Resolver) Resolve(ctx context.Context, targets []string, results chan<- proto.HostResult) error {
    // write to results, return when ctx.Done()
}
```

3. Add `MethodWMI Method = "wmi"` to `internal/proto/proto.go`.

4. Re-export the constant in `resolver.go` and add it to `DefaultMethods` if appropriate.

5. Add a `WMITimeout` field to `Options` in `probe.go`, a case in `buildResolvers`, and a `--wmi-timeout` flag in `cmd/hostminer/main.go`.

If the new resolver is expensive (TCP, heavy protocol), pass the shared `*proto.ResolvedSet` at construction and honour it the same way NTLM does. If it is fast/UDP, it can ignore the resolved set entirely.

---

## Package Layout

```
hostminer/
├── cmd/hostminer/main.go   CLI entry point
├── internal/
│   ├── logger/             Two-level stderr logger (LevelInfo / LevelDebug)
│   └── proto/              Shared types: Method, HostResult, Resolver, ResolvedSet
├── mdns/                   mDNS/DNS-SD resolver
├── netbios/                NetBIOS NBSTAT resolver
├── rdns/                   Reverse-DNS (PTR) resolver
├── ntlm/                   NTLM/RDP resolver
├── config.go               Global timeout constants
├── iface.go                Interface resolution and multicast validation
├── net.go                  CIDR expansion utilities
├── probe.go                Orchestrator: Probe(), buildResolvers(), collectResults()
└── resolver.go             Public re-exports of internal/proto types
```
