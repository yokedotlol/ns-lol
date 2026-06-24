# ns.lol — Patterns

> Operational guide: "do X this way." Distinct from GOTCHAS ("don't do X").

## All DNS Queries Are DoH Wireformat

DNS resolution uses RFC 8484 wireformat over HTTPS, NOT JSON-based DoH. The `buildDNSQuery()` function in `src/dns-wire.ts` constructs raw DNS packets, sends them as binary POST to resolver `/dns-query` endpoints, and `parseDNSResponse()` decodes the binary response.

This gives full control over the DNS wire protocol — arbitrary QTYPEs, EDNS0, DNSSEC flags — without being limited by what a JSON API exposes.

## Probe First, DoH Fallback

For propagation checks, the Worker calls the Fly probe first (raw UDP to 15 resolvers). If the probe is unreachable (auto-stopped, network issue), the Worker falls back to DoH queries directly. The fallback produces results tagged `source: "doh"` instead of `source: "udp"`.

Propagation results are **never cached** — they represent point-in-time state.

## World Map SVG Is Inline

The propagation world map is a Natural Earth-derived SVG embedded directly in `src/spa.ts`. No external map library, no tile server, no Leaflet. Resolver locations are hardcoded coordinates rendered as colored dots on the inline SVG.

## Resolver Lists Are Separate

DoH resolvers (`src/dns.ts` — `DOH_RESOLVERS`) and UDP resolvers (`probe/server.js` — `RESOLVERS`) are maintained independently. They overlap but aren't identical. When adding a resolver, add it to both if applicable.

**Known issue:** IIJ appears twice in the DoH resolver list (duplicate entry).

## Three Content Formats

Unlike certs (JSON + HTML), ns.lol serves three formats:
- **JSON** — `Accept: application/json` or CLI user agents
- **dig-style plain text** — `Accept: text/plain` (via `formatDig()`)
- **HTML SPA** — browsers

The dig-style output mimics traditional `dig` command output for terminal users who want familiar formatting without JSON parsing.

## Rate Limiter Is a Durable Object

Per-IP rate limiting uses a CF Durable Object with token bucket algorithm and time-based refill. 120 requests/hour per IP (2× certs' limit — DNS lookups are lighter weight).

## Lazy-Loading Tabs

The SPA has 6 tabs: Records, Propagation, Trace, Health, Email, Security. Only Records loads on initial page render. Other tabs lazy-load via client-side fetch when clicked — this avoids the cost of running all checks upfront.

## Click-to-Copy on Data Values

All DNS records, IPs, nameservers, and other data values use the `.data-val` class with click-to-copy behavior. Hover → accent color, click → clipboard + "copied" toast.
