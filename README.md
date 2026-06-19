# hostminer

Hostminer discovers hostnames for every IP in a subnet by running four complementary resolution strategies in parallel: reverse DNS, NetBIOS, mDNS/DNS-SD, and NTLM/RDP.

It works as both a CLI tool and an importable Go library.

---

## Install

```bash
go install hostminer/cmd/hostminer@latest
```

Or build from source:

```bash
git clone <repo>
cd hostminer
go build ./cmd/hostminer
```

---

## CLI Usage

```
hostminer --target <CIDR> [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--target` | *(required)* | Subnet in CIDR notation, e.g. `192.168.1.0/24` |
| `--interface` | auto-detect | Network interface: IP address, name (`eth0`), or empty for auto |
| `--timeout` | `20s` | Total scan duration |
| `--methods` | all four | Comma-separated: `mdns,netbios,rdns,ntlm` |
| `--netbios-timeout` | `2s` | Total NetBIOS scan deadline |
| `--rdns-timeout` | `0` | Total PTR-lookup budget (`0` = use `--timeout`) |
| `--ntlm-timeout` | `1s` | Per-host RDP probe deadline (use `3–5s` for internet targets) |
| `-v` | off | Info-level logs on stderr |
| `-vv` | off | Debug-level logs on stderr |

### Examples

```bash
# Scan a /24 with auto-detected interface
hostminer --target 192.168.1.0/24

# Specify interface by IP (recommended on Windows)
hostminer --target 192.168.1.0/24 --interface 192.168.1.5

# Larger subnet — extend the timeout
hostminer --target 10.0.0.0/16 --timeout 60s

# UDP-only scan (no TCP connections opened)
hostminer --target 192.168.1.0/24 --methods mdns,netbios,rdns

# NTLM only, relaxed per-host timeout for firewalled/internet targets
hostminer --target 10.10.0.0/24 --methods ntlm --ntlm-timeout 3s

# Verbose output to see what each resolver is doing
hostminer --target 192.168.1.0/24 -v
```

### Output

```
=== hostminer results for 192.168.1.0/24 ===
192.168.1.1        [rdns]      router.home
192.168.1.10       [netbios]   DESKTOP-ABC123
192.168.1.20       [mdns]      macbook.local
192.168.1.35       [ntlm]      WIN-XYZ789

Total: 4 host(s) found
```

---

## Library Usage

```go
import "hostminer"

results, err := hostminer.Probe(context.Background(), hostminer.Options{
    CIDR:    "192.168.1.0/24",
    Timeout: 30 * time.Second,
})
for _, r := range results {
    fmt.Printf("%s\t%s\t%s\n", r.IP, r.Method, r.Hostname)
}
```

Individual resolvers can also be used directly:

```go
import (
    "hostminer/netbios"
    "hostminer/rdns"
    "hostminer/ntlm"
    "hostminer/internal/proto"
)

r := netbios.NewResolver(netbios.Options{Timeout: 2 * time.Second})
ch := make(chan proto.HostResult, 256)
r.Resolve(ctx, []string{"192.168.1.10", "192.168.1.20"}, ch)
```

When using NTLM directly, pass `nil` for the resolved set and `0` for the start delay to disable cross-resolver coordination:

```go
r := ntlm.NewResolver(ntlm.Options{Timeout: 1 * time.Second}, nil, 0)
```

---

## Resolution Methods

| Method | Protocol | Port | Best for |
|---|---|---|---|
| `rdns` | DNS PTR | UDP 53 | IT-managed networks with PTR records |
| `netbios` | NBSTAT | UDP 137 | Windows-heavy environments |
| `mdns` | mDNS/DNS-SD | UDP 5353 | IoT, Apple, Linux/Avahi devices |
| `ntlm` | RDP/CredSSP | TCP 3389 | Windows hosts when DNS/NetBIOS fail |

---

## Subnet Size Guidelines

| Subnet | Hosts | Recommended `--timeout` |
|---|---|---|
| /24 | 254 | `20s` (default) |
| /22 | 1022 | `30s` |
| /20 | 4094 | `45s` |
| /16 | 65534 | `60s` |

For subnets larger than /23, mDNS PTR queries are automatically skipped (they are link-local and produce no responses for off-segment IPs). DNS-SD service discovery always runs regardless of subnet size.

---

## Requirements

- Go 1.21+
- For mDNS: a network interface with multicast support
- For NetBIOS: UDP port 137 must not be blocked outbound
- For NTLM: TCP port 3389 must be reachable on target hosts
