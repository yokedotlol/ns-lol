# ns.lol — Invariants

> Things that must ALWAYS be true. Adding or removing an invariant requires explicit human approval.
> Each invariant includes a verification method where possible.

## Propagation

- [ ] **UDP probe first, DoH fallback.** `propagationCheck()` always tries the Fly probe first. DoH is the fallback, not the default.
  - _Verify:_ In `src/handler.ts`, `propagationCheck()` must check `env.PROBE_URL && env.PROBE_KEY` before falling back to `queryAllResolvers()`.

- [ ] **`_source` field always present in propagation responses.** Every propagation response includes `_source: 'udp' | 'doh'` so callers know which path was used.
  - _Verify:_ `grep '_source' src/handler.ts` — must appear in the propagation result construction.

- [ ] **Propagation is never cached.** The `propagation` action is explicitly excluded from KV cache reads and writes.
  - _Verify:_ `src/handler.ts` — cache read and write blocks must both check `action !== 'propagation'`.

- [ ] **Propagation measures availability, not uniformity.** `propagation_pct` = percentage of resolvers that responded (not timed out/errored), regardless of whether they agree. `consistency_pct` measures answer agreement separately.
  - _Verify:_ Check the `propagation_pct` formula in `propagationCheck()`.

## DNS Resolution

- [ ] **All DoH queries use wireformat (RFC 8484).** Every resolver is queried via POST with `Content-Type: application/dns-message`. No JSON API (`?type=A&name=...`) anywhere.
  - _Verify:_ `queryDoH()` in `src/dns.ts` must use `buildDNSQuery()` and POST, not URL params.

- [ ] **Single lookups use Cloudflare.** `querySingle()` always uses `DOH_RESOLVERS[0]` (Cloudflare) for consistency and speed.
  - _Verify:_ Check `querySingle()` in `src/dns.ts`.

- [ ] **EDNS0 with DO flag is always set.** The wireformat query builder includes an OPT pseudo-RR with DO=1 to request DNSSEC data.
  - _Verify:_ `buildDNSQuery()` in `src/dns-wire.ts` must include the OPT record with DO=1 (0x80, 0x00 in flags).

## Response Format

- [ ] **All responses include `_meta`.** Full reports, health, email, and security responses all include a `_meta` object with cross-links to related tools.
  - _Verify:_ `grep -n '_meta' src/handler.ts src/health.ts src/email.ts src/security.ts` — every return object must have `_meta`.

- [ ] **`ttl_human` is computed for all record arrays.** Every place records are returned, each record includes `ttl_human` via `humanTTL(rec.TTL)`.
  - _Verify:_ Search for `ttl_human` in `src/handler.ts` — must appear in every records mapping.

- [ ] **Grades use letter scale: A, B, C, D, F.** Health, email, and security checks all use the same grading formula based on pass/warn/fail counts.
  - _Verify:_ Check grade computation in `src/health.ts`, `src/email.ts`, `src/security.ts`.

## Rate Limiting

- [ ] **Rate limiter is Durable Object, not D1.** `RateLimiterDO` uses in-memory state with DO storage, never D1.
  - _Verify:_ `src/rate-limiter.ts` uses `this.state.storage`, not D1.

- [ ] **120 requests per hour per IP.** Token bucket with `MAX_TOKENS = 120`, `REFILL_INTERVAL = 3600`.
  - _Verify:_ Constants in `src/rate-limiter.ts`.

- [ ] **Rate limit headers on all responses.** `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` are set on every DNS response.
  - _Verify:_ `rateLimitHeaders` in `src/worker.ts` is spread into every response.

## SPA

- [ ] **SPA is inline in `spa.ts`.** No external JS files, no framework, no build step. `renderSPA()` returns a complete HTML document.
  - _Verify:_ `src/spa.ts` must not import any npm packages.

- [ ] **World map uses Natural Earth 110m land outlines.** SVG path data in `spa.ts`, not hand-drawn or placeholder geometry.
  - _Verify:_ The SVG path in `spa.ts` should contain detailed land outline data (thousands of coordinate points).

- [ ] **Dark mode only.** CSS variables define a single dark theme. No light mode toggle.
  - _Verify:_ `:root` in `spa.ts` must have `--bg:#0a0e17` (dark background).

## Resolver Lists

- [ ] **Probe and DoH resolver lists should stay in sync.** `RESOLVERS` in `probe/server.js` and `DOH_RESOLVERS` in `src/dns.ts` represent the same set of public resolvers (with protocol-appropriate endpoints).
  - _Verify:_ Compare resolver names/locations between the two files. Same resolvers, different access methods (UDP IP vs DoH URL).

## Build & Deploy

- [ ] **CI deploys Worker and probe independently.** `.github/workflows/deploy.yml` handles CF Worker; `.github/workflows/fly-probe.yml` handles the Fly probe.
  - _Verify:_ Both workflow files exist and have separate triggers.

- [ ] **Probe deploy uses `--ha=false`.** To prevent Fly from creating duplicate machines for HA.
  - _Verify:_ `grep 'ha=false' .github/workflows/fly-probe.yml`.

- [ ] **`wrangler.toml` includes `PROBE_URL` as a var, `PROBE_KEY` as a secret.** URL is public (just the endpoint), key is secret.
  - _Verify:_ `PROBE_URL` appears in `[vars]` in `wrangler.toml`; `PROBE_KEY` is never in the file.

## Probe

- [ ] **Probe auth on all endpoints except `/health`.** The `AUTH_SECRET` env var is checked for `/propagation`, `/resolve`, `/authoritative`.
  - _Verify:_ Auth check in `probe/server.js` must exclude only `/health`.

- [ ] **Single Fly machine with auto-stop.** `fly.toml` must have `auto_stop_machines = 'stop'` and `min_machines_running = 0`.
  - _Verify:_ Check `probe/fly.toml`.
