# ns.lol — Current State

> Volatile snapshot of the project. Updated after significant sessions.

**Last updated:** 2026-06-16

## Codebase

| Metric | Value |
|--------|-------|
| Total lines | ~4,229 |
| Source files | 9 TypeScript (`src/`) + 1 Node.js (`probe/server.js`) |
| Test files | 0 |
| TODOs/FIXMEs | 0 |

## Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/handler.ts` | 1,117 | Request routing, all endpoint functions |
| `src/spa.ts` | 963 | Full SPA renderer (HTML/CSS/JS + world map SVG) |
| `src/health.ts` | 594 | Zone health checks (DNSSEC, NS, SOA, delegation) |
| `src/security.ts` | 470 | DNS security checks (dangling CNAME/NS, CDN, NXDOMAIN hijacking) |
| `src/email.ts` | 376 | Email DNS audit (MX, SPF, DKIM, DMARC, MTA-STS, BIMI) |
| `src/dns-wire.ts` | 294 | RFC 1035 DNS wireformat encoder/decoder |
| `src/worker.ts` | 184 | Worker entry point, content negotiation, CORS, rate limit wiring |
| `src/dns.ts` | 175 | DoH resolution, resolver list, record type maps |
| `src/rate-limiter.ts` | 56 | Durable Object rate limiter (120/hr token bucket) |
| `probe/server.js` | ~310 | Fly probe: raw UDP DNS queries to 15 resolvers |

## Resolvers

### DoH Resolvers (`src/dns.ts` — `DOH_RESOLVERS`)
14 entries (13 unique — IIJ is duplicated):
Cloudflare, Google, Quad9, OpenDNS, NextDNS, DNS.SB, IIJ (×2), AdGuard, Control D, Mullvad, Wikimedia, CleanBrowsing, CIRA Shield

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

## Deployment Status

- ✅ CF Worker deployed and serving traffic
- ✅ Fly probe deployed (single SJC machine, auto-stop)
- ✅ CI/CD fully configured (both workflows passing)
- ✅ Propagation working via UDP probe (source: `udp`)
- ✅ Design aligned with .lol family (June 15-16: canonical tokens, standardized footer, word-based toggle)
- ⚠️ ~80% propagation rate (3/15 resolvers may time out — varies by resolver)

## What Doesn't Exist Yet

- No tests (unit or integration)
- No CLI
- No MCP server
- No CHANGELOG
- No version tracking
