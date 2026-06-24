# hostminer — Comprehensive Technical Architecture

This document explains every architectural decision in hostminer, the reasoning behind each choice, how components interact, and the design tradeoffs involved.

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [System Architecture](#system-architecture)
3. [Core Design Principles](#core-design-principles)
4. [Execution Model: Tiered Resolution](#execution-model-tiered-resolution)
5. [The ResolvedSet Coordination](#the-resolvedset-coordination)
6. [Per-Resolver Design Deep-Dives](#per-resolver-design-deep-dives)
7. [Concurrency Model](#concurrency-model)
8. [Timeout Architecture](#timeout-architecture)
9. [Performance Characteristics](#performance-characteristics)
10. [Tradeoffs and Alternatives](#tradeoffs-and-alternatives)
11. [Extension Guide](#extension-guide)

---

## Problem Statement

**What**: Scan a subnet (e.g., 192.168.1.0/24 or 10.0.0.0/16) and resolve hostnames for every IP.

**Why four methods?** Different devices respond to different protocols:
- **Windows (PTR records)**: rDNS works if the IT admin registered DNS PTR records
- **Windows (no PTR)**: NetBIOS works; every Windows machine speaks NBSTAT
- **Devices on LAN**: mDNS/DNS-SD works for Bonjour, Avahi, IoT, printers
- **Hardened Windows**: NTLM/RDP works even when DNS/NetBIOS are disabled

**Why parallel?** Each method has different failure modes and response times. Sending all four simultaneously maximizes the chance of success and finishes faster than running them sequentially.

**The challenge**: Four independent concurrent systems sending packets at different rates, with different timeouts, no awareness of each other's progress, all fighting for a shared timeout budget.

---

## System Architecture

### High-Level Flow

```
User invokes Probe(ctx, opts)
│
├─ Parse CIDR → expand to individual IPs
├─ Create ResolvedSet (empty, shared state)
├─ Create four Resolver instances (with ResolvedSet reference for NTLM)
│
└─ Run orchestration loop:
    │
    ├─ Phase A: Launch rDNS, NetBIOS, mDNS as goroutines (t=0)
    │   ├─ rDNS worker pool starts 128 PTR lookups immediately
    │   ├─ NetBIOS sends wave 1 at adaptive pacing (immediately)
    │   └─ mDNS sends PTR queries at clamped pacing + DNS-SD discovery
    │
    ├─ Phase B: After startDelay (e.g., 700ms), launch NTLM
    │   └─ NTLM filters targets via ResolvedSet, probes only unresolved IPs
    │
    └─ Collect results:
        ├─ Each resolver writes to shared results channel
        ├─ collectResults deduplicates (first IP→hostname wins)
        ├─ Feed each result back into ResolvedSet
        └─ Exit early when all targets resolved OR timeout expires
```

### Packet Flow (Single Host Example)

```
Target: 192.168.1.42

Time    rDNS                NetBIOS           mDNS              NTLM
────────────────────────────────────────────────────────────────────
t=0     PTR query sent      NBSTAT sent       PTR query sent    [waiting]
        (to 8.8.8.8)        (to 192.168.1.42) (multicast)

t=10ms  [waiting]           NBSTAT response   [awaiting]        [waiting]
                            → add to resolved
                            → ResolvedSet.Add()

t=20ms  PTR response        [done with 1.42]  mDNS response     [waiting]
        → add to resolved                      (if present)
        → ResolvedSet.Add()

t=700ms [still working]     [done]            [still listening] Start checking
                                                                 ResolvedSet

        ResolvedSet has {1.42}
        → Skip 1.42
        → Move to next target
```

---

## Core Design Principles

### 1. **Composable, Independent Resolvers**

Each resolver is a standalone `proto.Resolver`:

```go
type Resolver interface {
    Name() string
    Resolve(ctx context.Context, targets []string, results chan<- HostResult) error
}
```

**Why**: 
- Resolvers can be tested in isolation
- New methods can be added without modifying existing ones
- Library users can use individual resolvers directly

**Trade-off**: Resolvers must be launched as goroutines to run in parallel; there is no built-in sequencing between them.

### 2. **Shared ResolvedSet for Cross-Resolver Feedback**

After Phase A resolvers do their work, Phase B (NTLM) knows which IPs are already resolved and skips them.

```
rDNS: resolves 192.168.1.1, .2, .3
  ↓
ResolvedSet updated: {.1, .2, .3}
  ↓
NTLM skips .1, .2, .3 when building work queue
```

**Why**:
- Reduces redundant work (NTLM doesn't open TCP to hosts already found)
- On typical networks, NetBIOS + mDNS resolve 70–90% of hosts; NTLM only probes the remaining 10–30%
- Turns TCP connections (expensive, slow, visible to IDS/IPS) into a targeted last resort

**Trade-off**: Adds a concurrency-safe data structure. The complexity is minimal (a `sync.RWMutex` + `map`).

### 3. **Single-Socket-Per-Protocol Design (NetBIOS, mDNS)**

Rather than opening one socket per target, each protocol uses one shared socket.

**NetBIOS**:
```
1 UDP socket → 254 hosts sent at paced intervals → 1 reader goroutine
```

**mDNS**:
```
1 multicast socket → 1 PTR sender + 1 DNS-SD sender + 1 reader
```

**Why**:
- File descriptor limit: 65k sockets would exceed OS limits (default ~1024 on Linux)
- Correlation via transaction IDs (NetBIOS) or multicast response addresses (mDNS)
- Simpler lifecycle management — one socket to open, one to close

**Trade-off**: The socket is a serialization point. Multiple goroutines cannot write simultaneously without coordination (but in practice, NetBIOS has 1 sender, mDNS has 2 senders on different channels so they don't race).

### 4. **Worker Pools for Stateful Operations (rDNS)**

rDNS uses a worker pool because each worker maintains DNS resolver state:

```
128 workers pulling from a job queue
    ├─ Worker 1: PTR 192.168.1.1, retry on temp error, bail on NXDOMAIN
    ├─ Worker 2: PTR 192.168.1.2, same
    └─ ... 126 more
```

**Why**: DNS is stateful per-worker. The OS resolver maintains connection state for each goroutine's lookups.

**Trade-off**: More goroutines (128 vs. 1), but justified by DNS semantics.

---

## Execution Model: Tiered Resolution

The system runs in two phases that are not strictly sequential — they overlap:

```
t=0                     t=startDelay          t=timeout
│                       │                       │
├─ Phase A ─────────────┼───────────────────────┤
│  rDNS                 │                       │
│  NetBIOS              │                       │
│  mDNS                 │                       │
│                       │                       │
│                       ├─ Phase B ────────────┤
│                       │  NTLM                 │
│                       │                       │
└───────────────────────┴───────────────────────┘

collectResults() drains results from all phases
and feeds them into ResolvedSet continuously.
```

### Why Tiering?

**Latency difference**: Phase A methods are UDP (1–10ms RTT on LAN). Phase B (NTLM) is TCP (50–200ms RTT, plus TLS, plus protocol overhead).

**Probability of success**: On a typical LAN:
- rDNS: succeeds if PTR record exists (~60% of hosts in managed networks)
- NetBIOS: succeeds if Windows (~70% of corporate networks)
- mDNS: succeeds if Bonjour/Avahi (~30% of mixed networks)
- NTLM: succeeds if Windows RDP is reachable (~40%, heavily firewalled)

**By running Phase A first, we resolve most hosts with minimal cost, then use NTLM only for holdouts.**

### Start Delay Calculation

```go
wave1_estimate = netbios.ComputePacing(netbiosTimeout, targetCount) × targetCount
startDelay     = max(wave1_estimate + 300ms, 500ms)
startDelay     = min(startDelay, globalTimeout × 25%)
```

**Worked examples:**

| Subnet | NetBIOS wave 1 | rDNS typical | startDelay | Meaning |
|--------|---|---|---|---|
| /24 (254 hosts, 20s global) | 254ms (adaptive 1ms cap) | 1–2s | 500ms (floor) | rDNS likely done, NetBIOS starting wave 1 |
| /22 (1022 hosts, 30s global) | 1.0s | 3–5s | 1.3s | Stagger NTLM after NetBIOS wave 1 |
| /16 (65534 hosts, 60s global) | 6.6s | 10–20s | 6.9s → capped to 15s | NTLM waits 25% of budget, gets 75% |

**Why 25% cap?** Ensures NTLM always gets at least 75% of the global budget for work. Without the cap, NTLM would wait so long on large subnets that it has almost no time to probe.

---

## The ResolvedSet Coordination

### Data Structure

```go
type ResolvedSet struct {
    mu  sync.RWMutex
    ips map[string]struct{}
}
```

Simple: a read-write-locked map. No fancy version counters or snapshots; just "is this IP in the set?"

### Lifecycle

```
t=0: ResolvedSet created (empty)

As results arrive:
  collectResults() receives HostResult{IP: "192.168.1.1", ...}
    → write lock
    → check if already seen (first-wins deduplication)
    → if new: add to seen map, call resolved.Add("192.168.1.1")
    → unlock

  NTLM worker thread (concurrently):
    → read lock
    → has := resolved.Has("192.168.1.1")
    → unlock
    → if has: skip to next IP in queue
```

### Why Not Wait-Free or Lock-Free?

Go's `sync.Map` exists for high-contention read-heavy workloads. We don't have that:
- Writes happen ~1 per 100ms (one result at a time draining from the channel)
- Reads happen 64 times per 100ms (64 NTLM workers checking before dial)

A `sync.RWMutex` is fine. Contention is minimal because writes are rare and reads are fast.

### Alternative Approaches Considered

**1. Channel-based feedback**: NTLM subscribes to a channel that broadcasts each resolved IP.
- **Pro**: No locking, Go-idiomatic.
- **Con**: NTLM would have to fan out 254 channels; complex.

**2. Callback hooks**: collectResults calls a function on each resolver.
- **Pro**: Type-safe, explicit.
- **Con**: Resolvers must implement the hook; adds complexity to every resolver even if they don't need it.

**Chosen: ResolvedSet**: Simple, used only by NTLM (others ignore it), minimal overhead.

---

## Per-Resolver Design Deep-Dives

### rDNS: Reverse DNS via OS Resolver

#### Design Rationale

**Why use the OS resolver instead of implementing DNS directly?**
- Respects the user's configured DNS servers (from `/etc/resolv.conf`, Windows DNS settings, etc.)
- Works with DNS proxies, local DNS caches, forwarders
- Minimal code; delegates complexity to the OS

**Why 128 workers?**

The bottleneck is the DNS server queue, not goroutine count.

```
Each DNS query:  50ms avg RTT (typical LAN resolver)
Throughput cap:  20 queries/s per RTT = 1000 queries/min at 50ms
Workers:         If you have 128 workers and each spends 50ms on a query,
                 throughput = 128 × (1000 queries/min) / 50ms ≈ 2560 queries/sec

But the DNS server (e.g., a home router's DNS stub) can typically handle
500–2000 queries/sec. So 128 workers = saturating the server without excess.

512 workers (old value): Each worker waiting in the OS resolver queue;
contention increases latency; diminishing returns after ~128.
```

#### Retry Logic

```
for attempt := range 3 {
    names, err := resolver.LookupAddr(ctx, ip)
    
    if err == nil && len(names) > 0:
        return names[0]  // success
    
    if isDNSError(err) && !isTemporary(err):
        return ""  // NXDOMAIN, SERVFAIL, malformed → no retry
    
    // Temporary error (timeout, connection refused): retry
}
```

**Why**: NXDOMAIN means "this IP has no PTR record, ever." Retrying wastes round trips to the same server that already answered definitively. Temporary errors (timeout, packet loss) might recover on retry.

**Trade-off**: Assumes the DNS server is correct. If a PTR record is being added while the scan runs, we might miss it. This is acceptable for a point-in-time scan.

#### Timeout Interaction

rDNS gets a child context with `opts.RDNSTimeout` (previously hardcoded 30s, now defaults to `opts.Timeout`). This caps rDNS work so it doesn't exceed the global budget.

```
Parent context: WithTimeout(ctx, 20s)
├─ rDNS context: WithTimeout(parentCtx, 20s)  [was 30s, now capped by parent]
├─ NetBIOS context: WithTimeout(parentCtx, 2s)
├─ mDNS context: WithTimeout(parentCtx, 20s)
└─ NTLM context: WithTimeout(parentCtx, 1s per host, capped by 20s global)
```

**Why change?** The old 30s default was silently unreachable when global was 20s. Making it explicit and coherent (use global by default) eliminates confusion.

---

### NetBIOS: Single Socket + Adaptive Pacing

#### Why Single Socket?

```
Alternative 1: One goroutine per host
  ├─ 254 hosts on /24 = 254 UDP sockets
  ├─ /16 = 65534 sockets → OS limits (default 1024 FDs)
  └─ Failure

Alternative 2: Connection pooling
  ├─ Overcomplicated; UDP is connectionless
  └─ Rejected

Chosen: 1 socket + 254 transaction IDs
  ├─ Random base txID, then txID = base + hostIndex
  ├─ Correlation via txID in response; no source-IP inspection needed
  └─ Works even if responses arrive out of order
```

#### Adaptive Pacing

```
Problem: Fixed 500µs pacing (2000 pkt/s)
  ├─ /24 (254 hosts): 254 × 500µs = 127ms → wave 1 done quickly ✓
  └─ /16 (65534 hosts): 65534 × 500µs = 32.7s, but timeout is 2s → partial scan ✗

Solution: Adaptive pacing based on subnet size
  pacing = (timeout × 35%) / targetCount
  pacing = clamp(pacing, 100µs floor, 1ms cap)

/24 at 2s: budget = 700ms, pacing = 2.8ms → clamped to 1ms cap → 254ms ✓
/16 at 2s: budget = 700ms, pacing = 10.7µs → below 100µs floor → 6.5s
  ↑ Still exceeds 2s timeout! But at least we send all 65k packets now.

/16 at 60s (recommended): budget = 21s, pacing = 320µs → 21s ✓
```

**Why 35% budget?** Leaves 65% for wave 2 + retransmit + receiving replies. Chosen empirically; could be 40% or 30%, but 35% is a reasonable middle ground.

**Why clamp at 100µs floor?** Below 100µs (~10,000 pkt/s), local kernel buffers start dropping. 100µs is safe for gigabit Ethernet.

**Why clamp at 1ms cap?** Above 1ms (~1,000 pkt/s), provides a hard upper bound on network load for small subnets; prevents unnecessary traffic.

#### Wave 2: Retransmit Non-Responders

```
Wave 1: Send to all 254 hosts
        time = t0 to t0 + 254ms

Wave 2: Wait retransmitBuffer (200ms) after wave 1 completes
        Send to hosts that haven't replied yet
        time = t0 + 254ms + 200ms = t0 + 454ms

Read loop: Continues until timeout (2s) or all responded
```

**Why 200ms, not fixed 900ms?**

Old code: Fixed 900ms from t=0, regardless of how long wave 1 took.

```
/24 at 2s:
  Wave 1 complete at 254ms
  Wave 2 triggered at 900ms (arbitrary)
  Result: 646ms gap between waves; wasteful

/16 at 2s:
  Wave 1 is still sending at 900ms!
  Wave 2 starts overlapping with wave 1
  Result: confusing, out-of-order probe/response pairs
```

New code: Wave 2 fires `wave1_completion + 200ms`, so it's always positioned correctly regardless of subnet size.

---

### mDNS: Multicast Discovery + DNS-SD Service Enumeration

#### Why One Goroutine + Ticker (Not 20 Workers)?

Old design: 20 worker goroutines all blocking on `<-ticker.C`.

```
How Go channels work:
  ├─ Goroutine 1: <-ticker.C (blocked)
  ├─ Goroutine 2: <-ticker.C (blocked)
  ├─ ... 18 more ...
  └─ Goroutine 20: <-ticker.C (blocked)

Tick fires:
  └─ EXACTLY ONE goroutine wakes up; others stay blocked

Result: Effective throughput = 1 packet per tick, same as 1 goroutine!
```

The 20-worker pool was never faster — it was illusion created by code structure.

**Why remove it?**
- Clearer intent (1 goroutine = 1 packet per tick)
- 19 fewer idle goroutines
- No scheduler contention on the shared ticker
- Same throughput, less overhead

---

#### Subnet Guard: Skip PTR for Large Subnets

```go
if targetCount <= ptrMaxTargets {  // 512
    sendPTRQueries()
} else {
    skipPTR()  // DNS-SD still runs
}
```

**Why?**

mDNS is **link-local and multicast**. It does not cross routers. Sending 65k PTR queries for IPs outside the local segment produces no responses.

```
Scenario: Scan 10.0.0.0/16 from a machine on 10.1.2.0/24

Target 10.0.0.1 (not on local /24):
  Query: "Who is 1.0.0.10.in-addr.arpa?"
  Sent to 224.0.0.251 (multicast, local segment only)
  → No device on 10.1.2.0/24 will respond for 10.0.0.1
  → No response; wasted query
```

**Trade-off**: If the user is scanning their own subnet, PTR is skipped. But:
- DNS-SD still runs (service discovery, independent of PTR)
- The alternative (blasting 65k queries into the void) is worse
- Most users don't scan subnets outside their local segment anyway (no routing, no response)

**Why 512 as the threshold?** Roughly a /23 subnet. Larger than a single /24, but not so large that it's obviously cross-segment. Users scanning /22 or smaller might still be local; /23 is the boundary.

---

#### DNS-SD: Service Discovery + Phase 2 Listening

```
Phase 1 (0–75% of timeout):
  Send 14 base service types:
    _http._tcp.local., _https._tcp.local., _smb._tcp.local., ...
  
  Sleep 20ms between sends to space out queries

Phase 2 (75%–100% of timeout):
  Listen for _services._dns-sd._udp.local. responses
  Extract newly-discovered service types (e.g., _my-app._tcp.local.)
  Query those discovered types too
```

**Why?** Devices advertise custom services. Phase 1 only queries hardcoded base types. Phase 2 listens for dynamic discoveries and adapts.

**Trade-off**: Adds complexity, but gains comprehensive service coverage without requiring users to hardcode every possible service type.

---

### NTLM: TCP/RDP Probe with TLS + CredSSP

#### Why TCP (Expensive, Slow)?

rDNS, NetBIOS, mDNS all fail on hardened Windows hosts:
- No PTR record (IT didn't register it)
- NetBIOS disabled (Windows Firewall default on newer systems)
- mDNS not running (not Bonjour, not Avahi)

NTLM works because:
- Windows ships with RDP listener (port 3389) on almost all machines
- The RDP server mandates NTLM negotiation during CredSSP
- The NTLM Type-2 challenge contains the computer name in AvPairs

**Trade-off**: TCP is heavyweight (SYN, ACK, SYN-ACK, TLS negotiation, CredSSP TSRequest, NTLM challenge). For each host, expect:
- ~1ms: TCP handshake + TLS handshake
- ~50ms: Protocol exchange if RDP is open
- ~1000ms: Firewall timeout if port is drop-firewalled (not rejected, dropped)

On a LAN, closed ports respond with RST in <1ms. Only firewalled ports eat the full timeout.

#### Why 1s Default (Not 5s)?

**On LAN:**
- Closed port (RST): <1ms
- Open port (responds): <100ms
- Firewalled port (drop): 1000ms timeout

A /24 subnet is 254 hosts. With 64 workers at 1s timeout:
- Best case (all RST): ceil(254/64) × 1s = 4s total
- Worst case (all firewalled): same, 4s total

At 5s per-host:
- Worst case: 20s total — more than the global timeout

**Trade-off**: 1s assumes most ports are either closed (fast) or open (fast). Only firewalled hosts eat the full timeout. For internet targets where TLS handshakes might take 500ms–1s, users should raise `--ntlm-timeout` to 3–5s.

#### Why DialContext?

```go
hostCtx, cancel := context.WithTimeout(ctx, timeout)
conn, err := dial(hostCtx, "tcp", ip+":3389")
```

**Alternative**: `net.Dial` with no context.

```
If global timeout fires while NTLM is mid-dial:
  ├─ Old: TCP connect keeps trying until per-host deadline
  ├─ New: Context cancel aborts TCP connect immediately
```

**Trade-off**: Requires storing the dial function as a field and accepting `context.Context` parameter in the protocol functions. Small complexity gain for significant responsiveness improvement.

---

### Why These Four? (Alternative Methods)

**WMI (Windows Management Instrumentation)**: Requires credentials, access via RPC on 135/445. Blocked in most firewalls. Skipped.

**SNMP (Simple Network Management Protocol)**: Requires SNMP community strings. Only works on managed infrastructure. Niche use case. Skipped.

**DHCP**: Query the DHCP server's lease table. Requires local access to the DHCP server. Off-band from the subnet scan. Skipped.

**mDNS Multicast (no reverse PTR)**: Send ARP queries instead of PTR. But ARP only works on the local segment and is not suitable for subnets outside the local LAN. Multicast PTR is slightly better (goes to all mDNS devices, not just ARP neighbors).

---

## Concurrency Model

### Goroutine Lifecycle

```
Probe()
  │
  ├─ runResolversInParallel()
  │    │
  │    ├─ Goroutine A (rDNS)
  │    │    ├─ main loop: 128 workers pulling jobs
  │    │    └─ exits when context cancelled or job queue empty
  │    │
  │    ├─ Goroutine B (NetBIOS)
  │    │    ├─ wave 1: send all + reader goroutine (Goroutine B2)
  │    │    ├─ wave 2: retransmit
  │    │    └─ wait until timeout or ctx cancelled
  │    │
  │    ├─ Goroutine C (mDNS)
  │    │    ├─ dispatcher (Goroutine C1)
  │    │    ├─ PTR sender (Goroutine C2)
  │    │    ├─ DNS-SD sender (Goroutine C3)
  │    │    ├─ reader goroutine (Goroutine C4)
  │    │    └─ all exit when dispatcher.Close() called
  │    │
  │    ├─ Goroutine D (NTLM)
  │    │    ├─ main loop: 64 workers pulling jobs
  │    │    └─ exits when context cancelled or job queue empty
  │    │
  │    └─ WaitGroup.Wait() goroutine
  │         └─ closes results channel when all resolvers done
  │
  └─ collectResults()
       ├─ drains results channel
       ├─ updates ResolvedSet
       ├─ exits early if all targets resolved
       └─ returns results
```

### Total Goroutines at Peak

```
rDNS:   128 (workers) + 1 (main) = 129
NetBIOS: 1 (main) + 1 (reader) = 2
mDNS:   1 (PTR) + 1 (DNS-SD) + 1 (reader) + 1 (dispatcher) = 4
NTLM:   64 (workers) + 1 (main) = 65
────────────────────────────────────
Total: 200 goroutines at peak
```

All resolve down over time as work completes or timeouts fire.

### Open File Descriptors at Peak

```
rDNS:   128 × OS DNS sockets (shared with OS resolver, ~128)
        + 1 × context
NetBIOS: 1 × UDP socket
mDNS:   1 × UDP multicast socket
NTLM:   64 × TCP connections (or less if hosts don't respond quickly)
────────────────────────────────────
Total:  ~200 FDs at peak
```

Well under typical OS limits (1024 on Linux, 256 on some macOS defaults, 512 on Windows by default). Configurable on most systems.

### Synchronization Points

```
1. Results channel (buffered, 4096)
   └─ Protects: HostResult message passing
   └─ Serialization: collectResults() reads; resolvers write

2. ResolvedSet.mu (RWMutex)
   └─ Protects: ip → resolved mapping
   └─ Contention: Low (writes ~1 per 100ms, reads ~64 per 100ms)

3. Individual resolver mutexes (NetBIOS, mDNS)
   └─ NetBIOS.responded map: mutex protects the "already replied" set
   └─ mDNS.Dispatcher: none needed; all operations on shared UDP conn
```

No deadlock risks; no complex lock hierarchies. Serialization is at the channel and simple map level.

---

## Timeout Architecture

### Design Philosophy

**Principle**: The global timeout is the law. No resolver should have a larger timeout cap than the global budget.

```
ProbeTimeout (global)
└─ Controls: overall scan duration
└─ Default: 20s

Derived timeouts:
├─ RDNSTimeout
│  ├─ Old: DefaultRDNSTimeout = 30s (could exceed global!)
│  ├─ New: defaults to opts.Timeout (shared global window)
│  └─ Reasoning: PTR lookups shouldn't have a longer leash than the overall scan
│
├─ NetBIOSTimeout
│  ├─ Default: 2s (short; independent per-method knob)
│  └─ Reasoning: NetBIOS is fast UDP; 2s is plenty
│
└─ NTLMTimeout
   ├─ Default: 1s per-host (LAN optimized)
   ├─ Total NTLM window: StartDelay onwards
   └─ Reasoning: TCP is expensive; 1s per host balances coverage vs. duration
```

### Timeout Interaction: /16 Example

```
Global timeout: 60s

applyDefaults():
  ├─ RDNSTimeout = 60s (use global)
  ├─ NetBIOSTimeout = 2s
  ├─ NTLMTimeout = 1s per-host
  └─ Derived NTLM startDelay = min(6.9s, 25% of 60s) = 6.9s

Timeline:
  t=0s     Phase A starts
    ├─ rDNS: 128 workers, 60s window
    ├─ NetBIOS: 65534 hosts at adaptive pacing, waves complete by ~15s
    └─ mDNS: 60s window
  
  t=6.9s   Phase B starts (NTLM)
    └─ NTLM: builds pending list (hosts NOT in ResolvedSet)
  
  t=60s    Global timeout fires
    ├─ All contexts cancelled
    ├─ All goroutines exit
    └─ Remaining probes aborted
```

### Why This Matters

**Scenario 1: rDNS has infinite timeout**
```
Global: 20s
rDNS: 30s
→ rDNS keeps querying 10s after global has fired
→ Resources leak, goroutines hang
```

**Scenario 2: NTLM start delay is too long**
```
Global: 20s
NTLM start delay: 18s
→ NTLM only has 2s to probe 100+ hosts at 1s per-host
→ Only gets through 2 hosts; waste
```

---

## Performance Characteristics

### Throughput by Subnet Size

| Subnet | Hosts | Methods | Typical Duration | Bottleneck |
|--------|-------|---------|---|---|
| /24 | 254 | all 4 | 3–5s | NTLM TCP handshake |
| /22 | 1022 | all 4 | 10–15s | NTLM or rDNS (high latency) |
| /20 | 4094 | all 4 | 30–45s | rDNS (heavy DNS load) |
| /16 | 65534 | all 4 + 60s budget | 45–60s | NTLM (deep TCP queue) |
| /24 | 254 | UDP only (no NTLM) | 2–3s | mDNS multicast time |
| /24 | 254 | NTLM only | 3–4s | TCP + TLS per-host |

### Resource Usage

```
/24 at default settings:
  ├─ Goroutines: ~200 at peak, ~0 after 5s
  ├─ File descriptors: ~150 (mostly rDNS workers + NTLM TCP)
  ├─ Memory: ~10MB (results buffer, goroutine stacks)
  └─ Network: ~1-2 Mbps peak, negligible sustained

/16 at 60s budget:
  ├─ Goroutines: ~200 at peak, ~0 after 60s
  ├─ File descriptors: ~200
  ├─ Memory: ~50MB (large target list, results buffer)
  └─ Network: ~5 Mbps peak (NetBIOS wave 1), then mDNS, then NTLM bursts
```

### Why mDNS PTR Is Skipped for Subnets > 512 Hosts

```
/24 (254 hosts) with mDNS PTR:
  ├─ 254 queries × 20ms pacing = 5s of queries
  ├─ Multicast, so 254 devices hear all 254 queries
  ├─ Expected response rate: 5–30% (depends on mDNS-capable device density)
  └─ Total cost: 5s + response collection time

/16 (65534 hosts):
  ├─ Can't know which IPs are on this LAN vs. remote
  ├─ Off-segment PTR queries produce 0% response rate
  ├─ Would send 65k queries into the void
  └─ Better to skip PTR, keep DNS-SD (service discovery still useful)
```

---

## Tradeoffs and Alternatives

### 1. ResolvedSet: Why Not Channels or Callbacks?

| Approach | Pros | Cons |
|---|---|---|
| **ResolvedSet (chosen)** | Simple, lightweight, only NTLM uses it | Requires sync.RWMutex |
| **Channel broadcast** | Go-idiomatic, no locking | Complex fan-out; requires subscribing |
| **Callback hooks** | Type-safe, explicit | Every resolver must implement; only NTLM needs it |

### 2. Tiered Execution: Why Not Run All Four at Once Without Delay?

**Chosen**: NTLM waits (start delay), checks ResolvedSet.

**Alternative**: Run all four immediately.

| Aspect | Immediate | Delayed (chosen) |
|---|---|---|
| **Throughput** | ~5s for /24 | ~3s for /24 |
| **Network load** | 2000 UDP pkt/s + 64 TCP SYN at t=0 | 2000 UDP pkt/s at t=0, 64 TCP SYN at t=0.7s |
| **IDS visibility** | Obvious scanner signature (UDP + TCP burst) | Less obvious (staggered) |
| **Redundant work** | NTLM probes all 254 | NTLM probes ~50 (if NetBIOS + mDNS cover 80%) |

The delay reduces redundant TCP probes by 70–80% at the cost of ~1s added latency on small subnets. Trade-off is worth it.

### 3. NetBIOS Pacing: Fixed vs. Adaptive

| Approach | Pros | Cons |
|---|---|---|
| **Fixed 500µs (old)** | Simple; worked for /24 | Breaks for /16 (32s+ needed) |
| **Adaptive (chosen)** | Scales to /16; uses budget efficiently | More complex formula |
| **No pacing (unlimited)** | Fastest possible | Network congestion; kernel buffer drops |

Adaptive is necessary for subnets larger than /24.

### 4. Single Goroutine PTR Sender vs. 20 Workers

| Approach | Throughput | Overhead | Clarity |
|---|---|---|---|
| **Single goroutine (chosen)** | 1 pkt/tick (same as 20 workers) | Minimal | Clear intent |
| **20 workers (old)** | 1 pkt/tick (not 20×!) | 20 idle goroutines | Misleading code |

Single goroutine is strictly better.

### 5. NTLM Per-Host Timeout: 1s vs. 5s

| Setting | LAN | Internet | Behavior |
|---|---|---|---|
| **1s (chosen for LAN)** | Closed ports fast, firewalled ports eat 1s | Firewall timeout dominates | /24 in 3–4s |
| **5s** | Slower on LAN (overkill) | Better for firewalled targets | /24 in 15–20s |
| **0.5s** | Fast, but might miss slow responders | Too aggressive for firewalls | /24 in 2s but fewer results |

Default to 1s for LAN (most users). Let users raise `--ntlm-timeout` for internet targets.

---

## Extension Guide

### Adding a New Resolver: Example (Hypothetical WMI)

**Step 1**: Create package `wmi/`

**Step 2**: Implement `proto.Resolver`

```go
package wmi

import (
    "context"
    "hostminer/internal/logger"
    "hostminer/internal/proto"
)

type Options struct {
    Timeout    time.Duration
    Username   string  // WMI requires auth
    Password   string
}

type Resolver struct {
    opts Options
}

func NewResolver(opts Options) *Resolver {
    if opts.Timeout == 0 {
        opts.Timeout = 5 * time.Second
    }
    return &Resolver{opts: opts}
}

func (r *Resolver) Name() string { return "wmi" }

func (r *Resolver) Resolve(ctx context.Context, targets []string, results chan<- proto.HostResult) error {
    // ... WMI protocol implementation ...
}
```

**Step 3**: Add Method constant

```go
// internal/proto/proto.go
const (
    MethodWMI Method = "wmi"
)
```

**Step 4**: Re-export and add to defaults

```go
// resolver.go
const MethodWMI = proto.MethodWMI

// resolver.go var
var DefaultMethods = []Method{..., proto.MethodWMI}
```

**Step 5**: Wire into probe.go

```go
// probe.go
import "hostminer/wmi"

// Options
type Options struct {
    // ... existing fields ...
    WMITimeout time.Duration
    WMIUsername string
    WMIPassword string
}

// applyDefaults
if opts.WMITimeout == 0 {
    opts.WMITimeout = 5 * time.Second
}

// buildResolvers
case MethodWMI:
    resolvers = append(resolvers, wmi.NewResolver(wmi.Options{
        Timeout:  opts.WMITimeout,
        Username: opts.WMIUsername,
        Password: opts.WMIPassword,
    }))
```

**Step 6**: Add CLI flags

```go
// cmd/hostminer/main.go
wmiTimeout := flag.Duration("wmi-timeout", 5*time.Second, "WMI query deadline")
wmiUser := flag.String("wmi-user", "", "WMI username (if required)")
wmiPass := flag.String("wmi-pass", "", "WMI password (if required)")

// Pass to Probe
Results, err := hostminer.Probe(ctx, hostminer.Options{
    // ...
    WMITimeout: *wmiTimeout,
    WMIUsername: *wmiUser,
    WMIPassword: *wmiPass,
})
```

**Step 7** (optional): If WMI is expensive, have it use ResolvedSet

```go
func NewResolver(opts Options, resolved *proto.ResolvedSet) *Resolver {
    return &Resolver{
        opts: opts,
        resolved: resolved,
    }
}

func (r *Resolver) Resolve(ctx context.Context, targets []string, results chan<- proto.HostResult) error {
    var pending []string
    for _, ip := range targets {
        if !r.resolved.Has(ip) {
            pending = append(pending, ip)
        }
    }
    // ... probe only pending ...
}
```

---

## Conclusion: Why This Design?

Every architectural choice in hostminer reflects a tradeoff:

| Choice | Benefit | Cost |
|---|---|---|
| Four independent resolvers | Coverage; different methods catch different hosts | No built-in sequencing |
| Tiered execution (NTLM deferred) | Reduces redundant TCP probes by 70–80% | +~1s latency on small subnets |
| Shared ResolvedSet | NTLM skips already-resolved hosts | Concurrency primitive needed |
| Adaptive NetBIOS pacing | Works from /24 to /16 | Formula complexity |
| Single socket + TxID (NetBIOS/mDNS) | Avoids FD exhaustion | Correlation complexity |
| Worker pools (rDNS) | Saturates DNS server efficiently | More goroutines than single-threaded |
| Context-aware NTLM dial | Quick cancellation when global timeout fires | Slightly more code complexity |

The design prioritizes **correctness** (all the right tradeoffs) over **simplicity** (only one method). For most users, four methods running in parallel discovers nearly all hosts quickly. For advanced users, the library API allows using individual resolvers or implementing custom orchestration.
