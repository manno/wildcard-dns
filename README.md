# wildcard-dns

A self-hosted wildcard DNS server that resolves hostnames with embedded IP addresses back to those IPs. Inspired by [xip.io](http://xip.io) and [sslip.io](https://sslip.io).

## What it does

Query a hostname that contains an IP address, and the server returns that IP:

```
10-0-0-1.example.com        → 10.0.0.1   (IPv4, dash-separated)
10.0.0.1.example.com        → 10.0.0.1   (IPv4, dot-separated)
2001-db8--1.example.com     → 2001:db8::1 (IPv6, dash-separated, :: → --)
```

This is useful for local development when you need a real DNS name resolving to a private or dynamic IP — for example, to obtain a TLS certificate or satisfy browser same-origin rules.

## Prerequisites

- Go 1.15+
- `sudo` / root (to bind to port 53)
- A domain with its NS records delegated to this server

## Setup

Copy `.envrc.template` to `.envrc` and fill in your values:

```sh
cp .envrc.template .envrc
```

| Variable | Description | Example |
|---|---|---|
| `IP` | This server's public IP | `203.0.113.5` |
| `WILD_DOMAIN` | Apex domain (trailing dot required) | `example.com.` |
| `WILD_NS1` / `NS2` / `NS3` | Nameserver FQDNs (trailing dot required) | `ns1.example.com.` |
| `WILD_NS1_IP` / `NS2_IP` / `NS3_IP` | IPs for nameserver A records | `203.0.113.5` |
| `WILD_ALLOW_PUBLIC_IPS` | `true` to resolve public internet IPs; omit or set `false` to restrict to private/loopback only (prevents DNS amplification) | _(unset)_ |

## Build & Run

```sh
# Build
make

# Run (loads .envrc, then runs with sudo)
make run

# Optional: redirect DNS traffic via iptables (e.g. intercept queries to 8.8.8.8)
make iptables
```

## DNS record support

| Type | Behaviour |
|---|---|
| A | Extracted from hostname, or custom via `Customizations` |
| AAAA | Extracted from hostname (dash-separated IPv6), or custom |
| CNAME | Custom only (via `Customizations`) |
| MX | Custom (via `Customizations`), or self-referential fallback |
| NS | Returns configured nameservers; delegates for `_acme-challenge.*` |
| SOA | Hard-coded, MNAME derived from query name |
| TXT | Custom (via `Customizations`), or returns querier's source IP |
| ANY | Returns `NOTIMPL` (RFC 8482) |

## ACME DNS-01 challenges

`_acme-challenge.*` queries are delegated via NS records rather than answered directly, so Let's Encrypt (and other ACME CAs) can complete DNS-01 validation against subdomains.

## Customizations

Hardcoded responses for specific FQDNs are set at startup in `xip.Customizations` (a `map[string]DomainCustomization`). By default, the apex domain resolves to `127.0.0.1` and each nameserver FQDN resolves to its configured IP. To add custom records, modify `xip/xip.go`.

## Architecture

```
main.go          UDP listener on :53, per-goroutine query dispatch
└── xip/xip.go   All DNS logic; entry point: QueryResponse(rawBytes, srcIP)
```

`QueryResponse` parses the raw DNS query using `golang.org/x/net/dns/dnsmessage`, calls `processQuestion`, then serialises the response with `dnsmessage.Builder`. Because the Builder requires the header before answers, responses are built as slices of deferred `func(*Builder) error` closures, applied after all processing is done.

## License

See [LICENSE](LICENSE).
