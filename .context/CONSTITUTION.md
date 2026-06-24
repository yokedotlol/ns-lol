# ns.lol — Project Constitution

> Stable identity, architecture, and red lines. Changes here are rare and require discussion.

## What ns.lol Is

Fast, API-first DNS toolkit at [ns.lol](https://ns.lol). Users enter a domain → get comprehensive DNS analysis: records, propagation, zone health, email DNS audit, security checks. Part of the .lol family alongside [certs.lol](https://certs.lol) (TLS) and [yoke.lol](https://yoke.lol) (full domain intelligence).

## Architecture

| Layer | Technology | Location |
|-------|-----------|----------|
| Worker | Cloudflare Workers (TypeScript, zero-framework) | `src/` |
| SPA | Inline HTML/CSS/JS generated in `src/spa.ts` | `src/spa.ts` |
| Probe | Node.js HTTP server on Fly.io (raw UDP DNS queries) | `probe/` |

### How It Works

1. **CF Worker** receives all requests. Content negotiation routes to JSON (curl/API), dig-style plain text (`Accept: text/plain`), or SPA (browsers).
2. **DoH queries** (RFC 8484 wireformat) handle single lookups, full reports, health, email, and security checks. All go through `queryDoH()` → `buildDNSQuery()` → `parseDNSResponse()`.
3. **Fly probe** handles propagation checks. The Worker calls the probe first (real UDP to 15 public resolvers); falls back to DoH if the probe is unreachable. The probe sends raw UDP packets via `dgram` to geographically distributed public DNS resolvers — geographic diversity comes from the resolvers, not from where the probe runs.
4. **SPA** is a single function `renderSPA()` that returns complete HTML with embedded JSON data. No build step, no framework, no external JS dependencies. Blue/cyan terminal aesthetic, Inter + JetBrains Mono fonts, dark-mode-first.

### Storage

- **KV `CACHE`** — all DNS result caching. Domain reports (1h TTL), health/security checks (6h TTL). Propagation is never cached.
- **Durable Object `RateLimiterDO`** — per-IP rate limiting (120 requests/hour). Token bucket with time-based refill.

### Endpoints

| Endpoint | Function | Source |
|----------|----------|--------|
| `GET /:domain` | Full DNS report (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, HTTPS, DS) | `fullReport()` |
| `GET /:domain/:type` | Single record type lookup | `singleLookup()` |
| `GET /:domain/:number` | Custom numeric QTYPE (1-65535) | `numericLookup()` |
| `GET /:domain/any` | Simulated ANY query (RFC 8482 workaround) | `anyQuery()` |
| `GET /:domain/trace` | Authority chain walk (TLD → NS → A → SOA → DNSSEC) | `authorityTrace()` |
| `GET /:domain/propagation` | Multi-resolver propagation check with world map | `propagationCheck()` |
| `GET /:domain/health` | Zone health audit (DNSSEC, NS, SOA, delegation, lame detection) | `runHealthCheck()` |
| `GET /:domain/email` | Email DNS audit (MX, SPF, DKIM, DMARC, MTA-STS, BIMI, TLSRPT) | `runEmailCheck()` |
| `GET /:domain/security` | DNS security (dangling CNAME/NS, takeover risk, NXDOMAIN hijacking) | `runSecurityCheck()` |
| `GET /:ip` | Reverse DNS (PTR) lookup for IPv4/IPv6 | `reverseLookup()` |
| `POST /batch` | Batch lookup (up to 20 domains) | `batchCheck()` |
| `GET /api/docs` | API documentation | `apiDocs()` |

Query parameters: `?explain=true` (human explanations + fix suggestions), `?force=true` (bypass cache), `?expected=<value>` (propagation target match), `?type=<type>` (propagation record type).

### SPA Tabs

6 tabs in the browser UI: **Records**, **Propagation** (world map + resolver grid), **Trace**, **Health**, **Email**, **Security**. Each tab lazy-loads via client-side fetch when clicked.

## Content Negotiation

The Worker serves three output formats based on `Accept` header and User-Agent:

- **JSON** — `Accept: application/json`, or CLI user agents (curl, httpie, wget)
- **dig-style plain text** — `Accept: text/plain` (formatted via `formatDig()`)
- **HTML SPA** — browsers (`Accept: text/html`)

## Cost Awareness

ns.lol targets $5/mo total (CF Workers Paid plan). The Fly probe runs on free tier with auto-stop.

### Per-Request Budget
- **Uncached lookup:** 1 KV write (cache result), 1 DO read-write (rate limit)
- **Cached lookup:** 1 KV read (cache hit), 1 DO read-write (rate limit)
- **Propagation:** 1 DO read-write only (never cached, never writes to KV)

### Fly Probe Cost
- Single `shared-cpu-1x:256MB` machine in SJC with auto-stop
- Free tier covers 3 shared-cpu machines; should cost $0/mo
- Even running 24/7 would be ~$1.94/mo

## Red Lines

- **No accounts, no signup.** API-first, open access, rate-limited only.
- **POST-only where PII is involved.** Batch endpoint uses POST. Domain names in GET URLs are public data and fine.
- **No framework, no build tool beyond tsc.** The SPA is a TypeScript template literal, not a React/Vue/Svelte app.
- **No external JS dependencies in the SPA.** Everything is inline in `spa.ts`.
- **No `--no-verify` on commits.** Pre-commit hooks exist for a reason.
- **Secrets never in code or wrangler.toml.** `PROBE_KEY` is set via `wrangler secret put`.
- **Probe auth is required.** All probe endpoints (except `/health`) require `?key=<AUTH_SECRET>`.

## Module Boundaries

- **DNS resolution:** `src/dns.ts` (DoH queries, resolver list), `src/dns-wire.ts` (RFC 1035 encoder/decoder)
- **Request handler:** `src/handler.ts` (routing, all endpoint functions)
- **Health checks:** `src/health.ts` (DNSSEC, NS, SOA, delegation, lame detection, response consistency)
- **Email audit:** `src/email.ts` (MX, SPF, DKIM, DMARC, MTA-STS, BIMI, null MX)
- **Security checks:** `src/security.ts` (dangling CNAME/NS, CDN detection, NXDOMAIN hijacking, wildcard, CNAME chain)
- **Rate limiter:** `src/rate-limiter.ts` (Durable Object, token bucket)
- **SPA renderer:** `src/spa.ts` (full HTML/CSS/JS generation, world map SVG)
- **Worker entry:** `src/worker.ts` (content negotiation, CORS, routing)
- **Fly probe:** `probe/server.js` (Node.js, raw UDP DNS via `dgram`)

## .context/ Maintenance Protocol

These files are maintained by AI agents **with human approval**:

- **CONSTITUTION.md** — Changes are rare. Always discuss before editing.
- **DECISIONS.md** — Append-only. Entries are never edited or removed.
- **INVARIANTS.md** — Adding or removing an invariant requires explicit human approval.
- **STATE.md** — Can be updated more freely; agent proposes changes, human confirms.
- **GOTCHAS.md** — Append when a new lesson is learned. Pair every "don't" with a "do."
