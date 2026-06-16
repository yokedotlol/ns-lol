# ns.lol — Current State

> Volatile snapshot of the project. Updated after significant sessions.

**Last updated:** 2026-06-16

## Codebase

| Metric | Value |
|--------|-------|
| Total lines | ~8,559 (source + tests + probe) |
| Source files | 11 TypeScript (`src/`) + 1 Node.js (`probe/server.js`) |
| Test files | 7 (144 tests, all passing) |
| TODOs/FIXMEs | 0 |

## Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/handler.ts` | 1,890 | Request routing, all endpoint functions |
| `src/spa.ts` | 1,218 | Full SPA renderer (HTML/CSS/JS + world map SVG) |
| `src/health.ts` | 594 | Zone health checks (DNSSEC, NS, SOA, delegation) |
| `src/security.ts` | 574 | DNS security checks (dangling CNAME/NS, CDN, NXDOMAIN hijacking) |
| `src/worker.ts` | 418 | Worker entry point, content negotiation, CORS, rate limit wiring |
| `src/email.ts` | 376 | Email DNS audit (MX, SPF, DKIM, DMARC, MTA-STS, BIMI) |
| `src/dns-wire.ts` | 294 | RFC 1035 DNS wireformat encoder/decoder |
| `src/usage.ts` | 284 | Usage dashboard handler |
| `src/dns.ts` | 175 | DoH resolution, resolver list, record type maps |
| `src/status.ts` | ~40 | Public status page |
| `src/rate-limiter.ts` | 56 | Durable Object rate limiter (120/hr token bucket) |
| `probe/server.js` | 444 | Fly probe: raw UDP DNS queries to 15 resolvers |

## Test Files

| File | Tests | Coverage |
|------|-------|----------|
| `handler.test.ts` | 44 | Request routing, endpoints, error handling |
| `dns-wire.test.ts` | 26 | Wire format encode/decode |
| `security.test.ts` | 21 | Security analysis |
| `health.test.ts` | 15 | Zone health checks |
| `email.test.ts` | 14 | Email DNS audit |
| `dns.test.ts` | 13 | DoH resolution |
| `rate-limiter.test.ts` | 11 | Rate limiting |

## Resolvers

### DoH Resolvers (`src/dns.ts` — `DOH_RESOLVERS`)
14 unique entries:
Cloudflare, Google, Quad9, Quad9 Unfiltered, OpenDNS, NextDNS, DNS.SB, IIJ, AdGuard, Control D, Mullvad, Wikimedia, CleanBrowsing, CIRA Shield

### UDP Resolvers (`probe/server.js` — `RESOLVERS`)
15 resolvers:
Google, Cloudflare, Quad9, OpenDNS, Quad9 Secondary, Control D, CleanBrowsing, CIRA Shield, dns0.eu, Mullvad, AdGuard, Verisign, NextDNS, DNS.SB, Wikimedia

## Infrastructure

| Resource | Details |
|----------|---------|
| Domain | ns.lol |
| CF Zone ID | `de03a3feedef8f14f0670d6ab5ff57da` |
| GitHub | yokedotlol/ns-lol |
| KV namespace | `CACHE` (id: `3c8fefc09b494e2ba1e5b3cc9d70a744`) |
| Durable Object | `RateLimiterDO` (per-IP rate limiting) |
| Fly app | `ns-lol-probe` (SJC, shared-cpu-1x:256MB, auto-stop) |
| CI | Two workflows: `deploy.yml` (CF Worker), `fly-probe.yml` (Fly probe) |
| CLI | Go binary v0.1.0 via GoReleaser + Homebrew tap (`yokedotlol/tap/ns`) |

## Deployment Status

- ✅ CF Worker deployed and serving traffic
- ✅ Fly probe deployed (single SJC machine, auto-stop)
- ✅ CI/CD fully configured (both workflows passing)
- ✅ Propagation working via UDP probe (source: `udp`)
- ✅ Design aligned with .lol family (canonical tokens, standardized footer, word-based toggle)
- ✅ 7 test files, 144 tests passing
- ✅ CLI v0.1.0 released via GoReleaser + Homebrew
- ⚠️ ~80% propagation rate (3/15 resolvers may time out — varies by resolver)

## What Doesn't Exist Yet

- No MCP server (P4 — yoke's MCP already covers domain intelligence)
- No CHANGELOG / version tracking
