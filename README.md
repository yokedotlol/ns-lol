# ns.lol 🌐

Fast, API-first DNS toolkit. Every lookup you'd reach for `dig` for, content-negotiated and rate-friendly.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/runs%20on-Cloudflare%20Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com)

## Quick start

```bash
# API — full DNS report
curl -s https://ns.lol/example.com | jq

# API — single record type
curl -s https://ns.lol/example.com/mx | jq

# CLI — install
brew install yokedotlol/tap/ns
# or
curl -sSL https://ns.lol/install.sh | bash

# CLI — full lookup
ns example.com

# CLI — propagation check
ns example.com propagation
```

Same URL, content-negotiated: `curl` gets JSON, browsers get an interactive report with map and tabs.

---

## CLI

The `ns` CLI hits the ns.lol API — same data, formatted for your terminal.

### Install

```bash
# Homebrew
brew install yokedotlol/tap/ns

# curl | bash
curl -sSL https://ns.lol/install.sh | bash

# Go
go install github.com/yokedotlol/ns-lol/cli@latest
```

### Usage

```bash
# Full DNS lookup (all record types)
ns example.com

# Specific record type
ns example.com -t mx

# Global propagation check
ns example.com propagation

# Zone health check
ns example.com health

# Email DNS audit (MX, SPF, DKIM, DMARC, MTA-STS, BIMI)
ns example.com email

# Security analysis (DNSSEC, dangling records, CAA)
ns example.com security

# Side-by-side comparison
ns compare example.com cloudflare.com

# JSON output
ns --json example.com

# Pipe domains from stdin
echo -e "google.com\ngithub.com" | ns
```

---

## API

No accounts, no API keys, no tracking. CORS-enabled for browser use.

### Endpoints

| Endpoint | Description |
|---|---|
| `GET /:domain` | Full DNS report — all common record types in parallel |
| `GET /:domain/:type` | Single record type (`a`, `aaaa`, `mx`, `txt`, `ns`, `soa`, `srv`, `caa`, `https`, `ds`, `ptr`, `dnskey`, `naptr`, `tlsa`, `sshfp`, `loc`, `hinfo`) |
| `GET /:domain/:number` | Numeric QTYPE (1–65535) |
| `GET /:domain/any` | Simulated ANY query (RFC 8482 deprecated real ANY) |
| `GET /:domain/trace` | Authority chain walk — root → TLD → authoritative NS → answer |
| `GET /:domain/propagation` | Global propagation across 15 resolvers in 4 regions (always live, never cached) |
| `GET /:domain/health` | Zone health report with letter grade (A–F) |
| `GET /:domain/email` | Email DNS audit — MX, SPF, DKIM, DMARC, MTA-STS, BIMI, DANE/TLSA |
| `GET /:domain/security` | Security analysis — dangling records, DNSSEC, wildcard, CDN/WAF, CAA |
| `GET /:ip` | Reverse DNS (PTR) for IPv4 and IPv6 |
| `POST /batch` | Batch lookup — up to 20 domains in one request |
| `GET /api/docs` | Machine-readable API documentation |

### Content negotiation

| Accept header | Response format |
|---|---|
| `application/json` | JSON (default for curl/httpie/wget) |
| `application/dns-json` | JSON (RFC 8484 alias) |
| `text/plain` | dig-style plain text |
| `text/html` | Interactive SPA with map, tabs, copy-to-clipboard |

### Query parameters

| Param | Description |
|---|---|
| `?explain=true` | Add plain-English explanations to every record and signal |
| `?force=true` | Bypass cache, force fresh lookup |
| `?type=MX` | Record type for propagation checks (default: A) |
| `?expected=1.2.3.4` | Expected value for propagation — resolvers flagged as matching or divergent |

### Examples

```bash
# Reverse DNS
curl -s https://ns.lol/8.8.8.8 | jq

# Propagation with expected value
curl -s "https://ns.lol/example.com/propagation?type=A&expected=93.184.216.34" | jq

# Zone health with explanations
curl -s "https://ns.lol/example.com/health?explain=true" | jq

# Authority trace
curl -s https://ns.lol/example.com/trace | jq

# dig-style output
curl -sH "Accept: text/plain" https://ns.lol/example.com

# Batch lookup
curl -s -X POST https://ns.lol/batch \
  -H 'Content-Type: application/json' \
  -d '{"domains":["google.com","github.com","cloudflare.com"]}' | jq
```

### Rate limiting

120 requests/hour per IP. Homepage, `/health`, and `/api/docs` are not limited.

Response headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.

---

## Infrastructure

- **Edge**: Cloudflare Workers (global)
- **Probes**: Fly.io in SJC (US-West) + AMS (EU) for real UDP propagation queries
- **Resolvers**: 15 public DNS resolvers across 4 regions (NA, EU, APAC, Oceania), queried in parallel from nearest probe
- **DNS method**: RFC 8484 wireformat DoH for lookups; real UDP via probes for propagation

## Self-hosting

```bash
git clone https://github.com/yokedotlol/ns-lol
cd ns-lol
bun install
# Set up wrangler.toml with your Cloudflare account
wrangler dev     # local development
wrangler deploy  # deploy to your account
```

Propagation checks require a Fly.io probe (`PROBE_URL` + `PROBE_KEY`). Without it, propagation falls back to DoH-only queries.

## Family

| Tool | What it does |
|---|---|
| **[yoke.lol](https://yoke.lol)** | Domain intelligence dashboard |
| **[ns.lol](https://ns.lol)** | DNS toolkit ← you are here |
| **[certs.lol](https://certs.lol)** | TLS/certificate analysis |
| **[xhttp.lol](https://xhttp.lol)** | HTTP header analysis |
| **[vrfy.lol](https://vrfy.lol)** | Email validation |

## License

[MIT](LICENSE)
