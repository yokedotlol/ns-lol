# ns.lol — Panel Review

**Date:** 2026-06-14
**Version reviewed:** commit d14e429 (post DoH resolver fix)
**Methodology:** Divergent → Panel Assembly → Voting → Convergence (per AGENTS.md)

---

## Phase 1: Divergent Pass — Exhaustive Feature/Issue Inventory

Every feature, design choice, UX element, API decision, missing capability, and potential issue, enumerated without filtering.

### A. API Design

| # | Item | Current State |
|---|------|--------------|
| A1 | JSON content negotiation | Detects `Accept: application/dns-json`, `application/json`, or CLI User-Agent. Falls back to SPA for browsers. |
| A2 | Full DNS report (`/:domain`) | Queries 11 record types via Cloudflare DoH. Returns `records`, `summary`, `_meta` links. |
| A3 | Single record lookup (`/:domain/:type`) | Supports A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR, CAA, NAPTR, DS, DNSKEY, TLSA, HTTPS. |
| A4 | Propagation check (`/:domain/propagation`) | 15 DoH resolvers, tiered by reliability. Calculates consistency %, anomaly detection, expected-value matching. |
| A5 | Health grading (`/:domain/health`) | Letter grade A–F. Checks DNSSEC, NS count/diversity/lame, SOA timers, delegation consistency, response consistency. |
| A6 | Email audit (`/:domain/email`) | Letter grade A–F. Checks MX, SPF, DMARC, DKIM (common selectors), MTA-STS, BIMI, null MX, TLS-RPT. |
| A7 | Security analysis (`/:domain/security`) | Dangling CNAME/NS, CNAME chain depth/loops, CDN detection, wildcard DNS, NS subnet diversity. |
| A8 | `?explain=true` parameter | Adds plain-English explanations to responses. Only on full report and some endpoints. |
| A9 | `?force=true` parameter | Bypasses KV cache. |
| A10 | `?expected=` parameter | Propagation: validates a specific expected value across resolvers. |
| A11 | `?type=` parameter | Propagation: override record type (default A). |
| A12 | API docs endpoint (`/api/docs`) | Returns structured JSON with endpoints, params, examples. |
| A13 | Cache strategy | KV cache: 1h for lookups, 6h for health/security. Propagation never cached. Explain bypasses cache. |
| A14 | Rate limiting | 120 req/hour per IP via Durable Object. Exposes `X-RateLimit-*` headers. |
| A15 | CORS support | Full preflight handling, `Access-Control-Allow-Origin: *`. |
| A16 | Error responses | Structured JSON with `error` field, appropriate HTTP status codes. |
| A17 | IDN/punycode support | Auto-converts Unicode domains via URL constructor. |
| A18 | Domain validation | Strips protocols, trailing dots, ports. Validates FQDN format. Requires at least one dot. |
| A19 | Cross-tool links in responses | `_meta` includes links to yoke.lol, certs.lol for every response. |
| A20 | `_cache_control` field | Internal hint for response caching, used by worker to set headers. |

### B. SPA / UI Design

| # | Item | Current State |
|---|------|--------------|
| B1 | Dark theme | `#0a0e17` bg, cyan/blue accent, Inter + JetBrains Mono. |
| B2 | Logo & tagline | `ns.lol` in mono with cyan accent. "fast, API-first DNS toolkit". |
| B3 | Search bar | Domain input with "Lookup" button. Strips protocols, auto-focuses, Enter key works. |
| B4 | Tab navigation | Records / Propagation / Health / Email / Security — lazy-loaded on click. |
| B5 | Summary bar | Shows record count, types, avg query time, DNSSEC status, CDN detection. |
| B6 | Records panel | Groups by type with count badges, query time, individual record rows showing data + TTL. |
| B7 | Propagation panel | Percentage display, resolver grid with status dots, SVG world map with interactive dots, auto-refresh timer. |
| B8 | Health panel | Letter grade display, signals grouped by category, pass/warn/fail/info color coding. |
| B9 | Email panel | Letter grade, signals grouped by category (MX, SPF, DMARC, DKIM, MTA-STS, BIMI). |
| B10 | Security panel | Shield icon header, signals grouped by category. |
| B11 | Signal row component | Status badge, label, detail text, optional fix suggestion (teal), optional explain (italic). |
| B12 | World map visualization | SVG with grid lines, colored dots for resolver locations, hover tooltips. |
| B13 | Auto-refresh for propagation | 30s interval with countdown, auto-enables when <100%, stops when fully propagated. |
| B14 | Expected-value UI | Shows match percentage, which resolvers have/haven't picked up the expected value. |
| B15 | Resolver sorting | Successful → anomalous → errored. Errors pushed to bottom. |
| B16 | Anomaly highlighting | Yellow border + subtle yellow bg for resolver cards returning minority answers. |
| B17 | Curl hint | Shows `curl` command at bottom of page, updates with current domain. |
| B18 | Cross-tool links | "TLS Report" → certs.lol, "Full Analysis" → yoke.lol, below tab panels. |
| B19 | Footer family links | yoke.lol, certs.lol, ns.lol — with active highlight on ns.lol. |
| B20 | Empty state | "DNS at the speed of thought", example domains, API usage hint. |
| B21 | URL routing / history | pushState on search, popstate handler for back/forward. |
| B22 | Favicon | Globe emoji SVG. |
| B23 | Mobile responsive | Single-column layout at ≤640px. |
| B24 | XSS prevention | `esc()` function for user data. `JSON.stringify` output escapes `</script>`. |
| B25 | No light mode toggle | Dark mode only. |
| B26 | No loading skeleton | Shows spinner text instead of placeholder skeleton. |
| B27 | Error display | Errors render in the "empty" container with the message. |

### C. Infrastructure & Backend

| # | Item | Current State |
|---|------|--------------|
| C1 | Cloudflare Worker runtime | Single-file entry, ~91KB bundled. |
| C2 | KV namespace for caching | 1h and 6h TTLs depending on endpoint. |
| C3 | Durable Object rate limiter | Token bucket, 120/hour per IP. |
| C4 | GitHub Actions deploy | Typecheck → wrangler deploy → smoke tests. Push to main or manual. |
| C5 | 15 DoH resolvers | Tiered: 5 confirmed, 7 large providers, 3 regional. |
| C6 | Resolver geographic diversity | US (3), Europe (5), Asia (3), Canada (2), Global Anycast (2). |
| C7 | 5s timeout per DoH query | AbortController with setTimeout. |
| C8 | Promise.allSettled for propagation | Handles individual resolver failures gracefully. |
| C9 | No logging/analytics | Zero tracking, no console.log in production. |
| C10 | No authentication | Open API, no accounts. |

### D. Missing Capabilities / Gaps

| # | Item | Notes |
|---|------|-------|
| D1 | No reverse DNS lookup (PTR) | PTR is in RECORD_TYPES but not queryable as an action — needs IP-to-arpa conversion. |
| D2 | No WHOIS integration | Competitors (mxtoolbox, dnschecker) show registrar, expiry, age. |
| D3 | No DNS over time / history | No TTL countdown, no "check again in X" intelligence. |
| D4 | No blacklist/RBL check | mxtoolbox's killer feature. |
| D5 | No SMTP connection test | Can't verify MX actually accepts mail. |
| D6 | No subdomain enumeration | Security value but scope concern. |
| D7 | No zone transfer test (AXFR) | Simple misconfiguration check competitors do. |
| D8 | No DANE/TLSA validation | TLSA records exist in types but no analysis. |
| D9 | No response size analysis | Large TXT records (SPF chains) can cause UDP truncation. |
| D10 | No open resolver detection | Security check: is the NS an open resolver? |
| D11 | No CAA analysis | CAA records are fetched but not analyzed for policy quality. |
| D12 | No geographic IP mapping for A records | Could show where IPs are located (country, ASN). |
| D13 | No batch/compare mode | Can't compare two domains side by side. |
| D14 | No webhook/notification for propagation | "Notify me when 100% propagated." |
| D15 | No shareable report links | Results aren't shareable beyond the URL. |
| D16 | No export (CSV/PDF) | Competitors offer PDF reports. |
| D17 | Security endpoint has no letter grade | Health and Email have grades; Security doesn't. |
| D18 | No SOA serial format detection | Could detect date-serial vs increment-serial convention. |
| D19 | No SPF record tree expansion | Don't follow `include:` chains to count total lookups recursively. |
| D20 | SPF lookup counting is approximate | Regex-based, doesn't recursively count nested includes. |
| D21 | DKIM selector guessing is limited | Only 10 common selectors; Google Workspace uses complex selectors. |
| D22 | No TTL recommendation engine | Could flag overly-low or overly-high TTLs on A/CNAME records. |
| D23 | Error responses don't include `_meta` links | Errors lose the cross-tool linking. |
| D24 | No `?format=` for alternative output | No text/table/csv output format options. |
| D25 | Propagation has no record-type selector in UI | SPA always checks A records; must use API `?type=` param. |
| D26 | Health doesn't check NSEC/NSEC3 | DNSSEC chain analysis is incomplete. |
| D27 | No API versioning | No `/v1/` prefix. Could break clients on changes. |
| D28 | No OpenAPI/Swagger spec | API docs are JSON but not machine-readable standard. |

### E. Bugs / Edge Cases / Polish

| # | Item | Notes |
|---|------|-------|
| E1 | Rate limiter refill logic has a subtle bug | Partial refills update `lastRefill` to `now`, but the proportional calc uses elapsed since last refill. Tokens refill faster than intended after first partial refill. |
| E2 | Google+Wikimedia share identical lat/lng on map | Mountain View, US — dots overlap, tooltip shows last one only. |
| E3 | Cloudflare+OpenDNS share identical lat/lng on map | Both "San Francisco, US" — same overlap issue. |
| E4 | Domain validation rejects underscores in labels | Pattern allows `_` but some valid DNS names use it (SRV, DKIM). May incorrectly reject `_dmarc.example.com` as a lookup target. |
| E5 | No error state recovery in SPA | After an error, user has to manually clear/retype — no "try again" button. |
| E6 | `wantsJSON` heuristic might miss some API clients | Libraries like `axios` or `fetch` from browsers don't set CLI user-agents. |
| E7 | TXT record data includes surrounding quotes sometimes | DoH returns quoted strings; display may show `"v=spf1..."` with quotes. |
| E8 | Propagation auto-refresh doesn't survive tab switch | If you switch away from Propagation tab and come back, auto-refresh is dead. |
| E9 | Cache key doesn't include query params for single lookups | `dns:example.com:a` is same whether `?explain=true` or not (explain bypasses cache, but a non-explain result may be served after an explain was cached). Actually, explain bypasses cache, so this is fine — but `?force=true` results still get cached with the same key. |
| E10 | Map tooltip uses `clientX`/`clientY` | Will break on touch devices (no hover). |
| E11 | Search doesn't validate domain before navigating | Can push empty or garbage to URL history. |
| E12 | No scroll-to-top on new search | User stays at scroll position from previous lookup. |
| E13 | Security grade missing | Unlike Health and Email, no letter grade summary. |
| E14 | SPA doesn't handle network offline state | No feedback if fetch fails due to connectivity. |
| E15 | `escapeHtml` in TypeScript vs `esc` in JS client | Two separate HTML escape implementations, could diverge. |

---

## Phase 2: Panel Assembly

### Panelists

| # | Name | Role | Bias |
|---|------|------|------|
| P1 | **Dmitri** | DNS engineer / sysadmin (uses dig daily) | Wants RFC correctness, completeness, authoritative data. Skeptical of "pretty" over "accurate." |
| P2 | **Priya** | Developer building monitoring tools (API consumer) | Wants clean JSON schemas, consistent responses, machine-readable everything. Hates breaking changes. |
| P3 | **Marcus** | Web designer reviewing the SPA UI/UX | Cares about visual hierarchy, micro-interactions, mobile experience, accessibility. |
| P4 | **Sophie** | Security researcher evaluating the security endpoint | Wants comprehensive subdomain takeover checks, attack surface mapping, actionable findings. |
| P5 | **Janet** | Email deliverability consultant | Wants complete email authentication analysis. Compares to MXToolbox daily. |
| P6 | **Carlos** | Competitor analyst (uses dnschecker.org, whatsmydns.net, mxtoolbox.com) | Compares feature-for-feature. What makes someone switch? |
| P7 | **Raj** | DevOps engineer evaluating for production monitoring | Wants reliability, uptime, integration into CI/CD and alerting pipelines. |
| P8 | **Kurt** | Creator — pragmatic, hates bloat, wants it fast and curl-friendly | "Ship it if it works. Don't add features nobody asked for. $5/mo ceiling." |

---

## Phase 3: Round 1 Voting

Scale: **MUST** (pre-launch blocker) / **SHOULD** (do soon after launch) / **COULD** (nice post-launch) / **CUT** (don't do)

4+ MUSTs = locked in. 4+ CUTs = eliminated.

### API Design Items

| Item | Dmitri | Priya | Marcus | Sophie | Janet | Carlos | Raj | Kurt | Result |
|------|--------|-------|--------|--------|-------|--------|-----|------|--------|
| A1 JSON negotiation | MUST | MUST | COULD | SHOULD | COULD | MUST | MUST | MUST | ✅ **LOCKED (6 MUST)** |
| A2 Full report | MUST | MUST | SHOULD | SHOULD | SHOULD | MUST | MUST | MUST | ✅ **LOCKED (5 MUST)** |
| A3 Single record lookup | MUST | MUST | SHOULD | SHOULD | MUST | MUST | MUST | MUST | ✅ **LOCKED (6 MUST)** |
| A4 Propagation check | MUST | MUST | MUST | SHOULD | SHOULD | MUST | MUST | MUST | ✅ **LOCKED (6 MUST)** |
| A5 Health grading | MUST | SHOULD | SHOULD | MUST | SHOULD | MUST | MUST | MUST | ✅ **LOCKED (5 MUST)** |
| A6 Email audit | SHOULD | SHOULD | SHOULD | SHOULD | MUST | MUST | SHOULD | MUST | Discuss |
| A7 Security analysis | SHOULD | SHOULD | SHOULD | MUST | COULD | MUST | SHOULD | MUST | Discuss |
| A8 `?explain=true` | SHOULD | MUST | MUST | SHOULD | MUST | SHOULD | COULD | SHOULD | Discuss |
| A9 `?force=true` | MUST | MUST | COULD | SHOULD | SHOULD | SHOULD | MUST | MUST | ✅ **LOCKED (4 MUST)** |
| A10 `?expected=` | SHOULD | MUST | COULD | COULD | COULD | MUST | MUST | SHOULD | Discuss |
| A11 `?type=` for propagation | MUST | MUST | COULD | SHOULD | MUST | MUST | MUST | MUST | ✅ **LOCKED (6 MUST)** |
| A12 API docs | SHOULD | MUST | COULD | COULD | COULD | SHOULD | MUST | SHOULD | Discuss |
| A13 Cache strategy | SHOULD | SHOULD | CUT | SHOULD | SHOULD | SHOULD | MUST | MUST | Discuss |
| A14 Rate limiting | MUST | SHOULD | CUT | MUST | COULD | SHOULD | MUST | MUST | ✅ **LOCKED (4 MUST)** |
| A15 CORS support | SHOULD | MUST | SHOULD | COULD | COULD | MUST | MUST | MUST | ✅ **LOCKED (4 MUST)** |
| A16 Error responses | MUST | MUST | SHOULD | SHOULD | SHOULD | SHOULD | MUST | MUST | ✅ **LOCKED (4 MUST)** |
| A17 IDN support | MUST | SHOULD | COULD | SHOULD | COULD | MUST | COULD | SHOULD | Discuss |
| A18 Domain validation | MUST | MUST | SHOULD | MUST | SHOULD | SHOULD | MUST | MUST | ✅ **LOCKED (5 MUST)** |
| A19 Cross-tool links | COULD | SHOULD | SHOULD | COULD | COULD | MUST | COULD | MUST | Discuss |
| A20 `_cache_control` field | CUT | SHOULD | CUT | CUT | CUT | CUT | SHOULD | SHOULD | 🗑️ **ELIMINATED (4 CUT)** — keep internal but remove from API output |

### SPA / UI Items

| Item | Dmitri | Priya | Marcus | Sophie | Janet | Carlos | Raj | Kurt | Result |
|------|--------|-------|--------|--------|-------|--------|-----|------|--------|
| B1 Dark theme | SHOULD | COULD | MUST | COULD | COULD | MUST | COULD | MUST | Discuss |
| B2 Logo/tagline | COULD | COULD | MUST | COULD | COULD | MUST | COULD | MUST | Discuss |
| B3 Search bar | MUST | SHOULD | MUST | SHOULD | MUST | MUST | SHOULD | MUST | ✅ **LOCKED (5 MUST)** |
| B4 Tab navigation | SHOULD | SHOULD | MUST | SHOULD | MUST | MUST | SHOULD | MUST | ✅ **LOCKED (4 MUST)** |
| B5 Summary bar | SHOULD | MUST | MUST | SHOULD | SHOULD | MUST | SHOULD | MUST | ✅ **LOCKED (4 MUST)** |
| B6 Records panel | MUST | MUST | MUST | SHOULD | SHOULD | MUST | MUST | MUST | ✅ **LOCKED (6 MUST)** |
| B7 Propagation panel | MUST | SHOULD | MUST | SHOULD | SHOULD | MUST | MUST | MUST | ✅ **LOCKED (5 MUST)** |
| B8 Health panel | SHOULD | SHOULD | MUST | MUST | SHOULD | MUST | SHOULD | MUST | ✅ **LOCKED (4 MUST)** |
| B9 Email panel | SHOULD | SHOULD | SHOULD | COULD | MUST | MUST | COULD | MUST | Discuss |
| B10 Security panel | SHOULD | SHOULD | SHOULD | MUST | COULD | SHOULD | SHOULD | MUST | Discuss |
| B11 Signal row component | SHOULD | SHOULD | MUST | MUST | MUST | SHOULD | SHOULD | SHOULD | Discuss |
| B12 World map | COULD | COULD | MUST | COULD | COULD | MUST | COULD | SHOULD | Discuss |
| B13 Auto-refresh | SHOULD | COULD | SHOULD | COULD | COULD | MUST | MUST | SHOULD | Discuss |
| B14 Expected-value UI | COULD | MUST | SHOULD | COULD | COULD | MUST | MUST | SHOULD | Discuss |
| B15 Resolver sorting | SHOULD | SHOULD | MUST | SHOULD | COULD | SHOULD | SHOULD | SHOULD | Discuss |
| B16 Anomaly highlighting | SHOULD | SHOULD | MUST | MUST | COULD | SHOULD | SHOULD | SHOULD | Discuss |
| B17 Curl hint | MUST | MUST | COULD | COULD | COULD | SHOULD | MUST | MUST | ✅ **LOCKED (4 MUST)** |
| B18 Cross-tool links in SPA | COULD | SHOULD | SHOULD | COULD | COULD | MUST | COULD | MUST | Discuss |
| B19 Footer family | COULD | COULD | MUST | COULD | COULD | SHOULD | COULD | MUST | Discuss |
| B20 Empty state | SHOULD | SHOULD | MUST | COULD | COULD | MUST | SHOULD | MUST | Discuss |
| B21 URL routing/history | SHOULD | SHOULD | MUST | COULD | SHOULD | MUST | COULD | MUST | Discuss |
| B22 Favicon | COULD | COULD | MUST | COULD | COULD | SHOULD | COULD | SHOULD | Discuss |
| B23 Mobile responsive | COULD | COULD | MUST | COULD | COULD | MUST | COULD | SHOULD | Discuss |
| B24 XSS prevention | MUST | MUST | SHOULD | MUST | SHOULD | SHOULD | MUST | MUST | ✅ **LOCKED (5 MUST)** |
| B25 No light mode toggle | CUT | CUT | COULD | CUT | COULD | COULD | CUT | CUT | 🗑️ **ELIMINATED (5 CUT)** — no light mode needed |
| B26 No loading skeleton | CUT | CUT | SHOULD | CUT | CUT | COULD | CUT | CUT | 🗑️ **ELIMINATED (6 CUT)** — spinner is fine |
| B27 Error display | SHOULD | SHOULD | MUST | SHOULD | SHOULD | SHOULD | SHOULD | SHOULD | Discuss |

### Missing Capabilities

| Item | Dmitri | Priya | Marcus | Sophie | Janet | Carlos | Raj | Kurt | Result |
|------|--------|-------|--------|--------|-------|--------|-----|------|--------|
| D1 Reverse DNS (PTR) | SHOULD | COULD | CUT | SHOULD | COULD | SHOULD | SHOULD | COULD | Discuss |
| D2 WHOIS integration | COULD | COULD | COULD | SHOULD | COULD | MUST | COULD | CUT | Discuss |
| D3 DNS history/TTL countdown | COULD | SHOULD | COULD | COULD | COULD | SHOULD | SHOULD | CUT | Discuss |
| D4 Blacklist/RBL check | COULD | COULD | CUT | SHOULD | MUST | MUST | COULD | CUT | Discuss |
| D5 SMTP connection test | CUT | CUT | CUT | COULD | MUST | SHOULD | CUT | CUT | 🗑️ **ELIMINATED (5 CUT)** — can't from CF Workers |
| D6 Subdomain enumeration | CUT | CUT | CUT | SHOULD | CUT | COULD | CUT | CUT | 🗑️ **ELIMINATED (5 CUT)** |
| D7 Zone transfer test (AXFR) | SHOULD | CUT | CUT | MUST | CUT | COULD | COULD | CUT | 🗑️ **ELIMINATED (4 CUT)** — can't from CF Workers |
| D8 DANE/TLSA validation | SHOULD | CUT | CUT | SHOULD | CUT | CUT | CUT | CUT | 🗑️ **ELIMINATED (5 CUT)** |
| D9 Response size analysis | SHOULD | COULD | CUT | COULD | SHOULD | CUT | COULD | CUT | 🗑️ **ELIMINATED (4 CUT)** |
| D10 Open resolver detection | COULD | CUT | CUT | MUST | CUT | COULD | COULD | CUT | 🗑️ **ELIMINATED (4 CUT)** |
| D11 CAA analysis | SHOULD | COULD | CUT | MUST | CUT | SHOULD | COULD | COULD | Discuss |
| D12 GeoIP for A records | COULD | SHOULD | SHOULD | COULD | CUT | MUST | COULD | COULD | Discuss |
| D13 Batch/compare mode | CUT | COULD | CUT | CUT | CUT | COULD | COULD | CUT | 🗑️ **ELIMINATED (5 CUT)** |
| D14 Webhook/notification | CUT | SHOULD | CUT | CUT | CUT | COULD | SHOULD | CUT | 🗑️ **ELIMINATED (5 CUT)** |
| D15 Shareable report links | CUT | COULD | SHOULD | CUT | CUT | SHOULD | COULD | CUT | 🗑️ **ELIMINATED (4 CUT)** |
| D16 Export CSV/PDF | CUT | COULD | CUT | CUT | COULD | SHOULD | COULD | CUT | 🗑️ **ELIMINATED (4 CUT)** |
| D17 Security grade (letter) | SHOULD | MUST | MUST | MUST | COULD | MUST | SHOULD | SHOULD | ✅ **LOCKED (4 MUST)** |
| D18 SOA serial format detection | SHOULD | CUT | CUT | CUT | CUT | CUT | COULD | CUT | 🗑️ **ELIMINATED (5 CUT)** |
| D19 SPF include chain expansion | MUST | SHOULD | CUT | SHOULD | MUST | SHOULD | COULD | COULD | Discuss |
| D20 SPF lookup counting fix | MUST | SHOULD | CUT | SHOULD | MUST | SHOULD | COULD | SHOULD | Discuss |
| D21 Better DKIM discovery | COULD | CUT | CUT | COULD | SHOULD | COULD | CUT | CUT | 🗑️ **ELIMINATED (4 CUT)** |
| D22 TTL recommendation engine | SHOULD | COULD | CUT | COULD | COULD | SHOULD | COULD | CUT | Discuss |
| D23 Error responses with `_meta` | CUT | SHOULD | CUT | CUT | CUT | CUT | COULD | CUT | 🗑️ **ELIMINATED (5 CUT)** |
| D24 `?format=` output options | CUT | SHOULD | CUT | CUT | CUT | COULD | COULD | CUT | 🗑️ **ELIMINATED (5 CUT)** |
| D25 Propagation type selector in UI | SHOULD | COULD | MUST | COULD | MUST | MUST | COULD | SHOULD | ✅ **LOCKED (3 MUST)** — near lock, discuss |
| D26 NSEC/NSEC3 analysis | SHOULD | CUT | CUT | SHOULD | CUT | CUT | CUT | CUT | 🗑️ **ELIMINATED (5 CUT)** |
| D27 API versioning | COULD | MUST | CUT | CUT | CUT | COULD | SHOULD | CUT | 🗑️ **ELIMINATED (4 CUT)** |
| D28 OpenAPI spec | CUT | SHOULD | CUT | CUT | CUT | COULD | SHOULD | CUT | 🗑️ **ELIMINATED (4 CUT)** |

### Bugs / Edge Cases

| Item | Dmitri | Priya | Marcus | Sophie | Janet | Carlos | Raj | Kurt | Result |
|------|--------|-------|--------|--------|-------|--------|-----|------|--------|
| E1 Rate limiter refill bug | SHOULD | MUST | CUT | SHOULD | CUT | CUT | MUST | SHOULD | Discuss |
| E2 Overlapping map dots (Google/Wikimedia) | COULD | CUT | SHOULD | CUT | CUT | SHOULD | CUT | COULD | 🗑️ **ELIMINATED (4 CUT)** — cosmetic |
| E3 Overlapping map dots (CF/OpenDNS) | COULD | CUT | SHOULD | CUT | CUT | SHOULD | CUT | COULD | 🗑️ **ELIMINATED (4 CUT)** — cosmetic |
| E4 Domain validation vs underscore labels | MUST | SHOULD | CUT | SHOULD | SHOULD | COULD | SHOULD | SHOULD | Discuss |
| E5 No "try again" button on errors | CUT | CUT | MUST | CUT | COULD | SHOULD | CUT | CUT | 🗑️ **ELIMINATED (4 CUT)** — user can re-search |
| E6 `wantsJSON` heuristic gaps | SHOULD | MUST | CUT | CUT | CUT | COULD | SHOULD | SHOULD | Discuss |
| E7 TXT record quote display | MUST | SHOULD | COULD | COULD | SHOULD | SHOULD | COULD | SHOULD | Discuss |
| E8 Auto-refresh lost on tab switch | COULD | CUT | SHOULD | CUT | CUT | SHOULD | COULD | CUT | 🗑️ **ELIMINATED (4 CUT)** |
| E9 Force=true results cached | SHOULD | MUST | CUT | COULD | CUT | CUT | SHOULD | SHOULD | Discuss |
| E10 Map tooltips broken on touch | CUT | CUT | MUST | CUT | CUT | SHOULD | CUT | CUT | 🗑️ **ELIMINATED (5 CUT)** — touch users have resolver grid |
| E11 Search doesn't validate before nav | COULD | COULD | SHOULD | COULD | CUT | SHOULD | COULD | COULD | Discuss |
| E12 No scroll-to-top on new search | CUT | CUT | MUST | CUT | CUT | SHOULD | CUT | CUT | 🗑️ **ELIMINATED (5 CUT)** |
| E13 Security grade missing | SHOULD | MUST | MUST | MUST | COULD | MUST | SHOULD | SHOULD | ✅ **LOCKED (4 MUST)** — same as D17 |
| E14 No offline detection | CUT | CUT | SHOULD | CUT | CUT | CUT | CUT | CUT | 🗑️ **ELIMINATED (6 CUT)** |
| E15 Dual escape functions | CUT | SHOULD | CUT | CUT | CUT | CUT | COULD | COULD | 🗑️ **ELIMINATED (5 CUT)** |

---

## Round 1 Summary

### Locked In (Pre-launch — already done ✅)
These are already implemented and confirmed essential:
- A1, A2, A3, A4, A5, A9, A11, A14, A15, A16, A18 (core API)
- B3, B4, B5, B6, B7, B8, B17, B24 (core SPA)

### Locked In (Pre-launch — needs work 🔧)
- **D17/E13: Add letter grade to Security endpoint** — 4 MUSTs. Currently only Health and Email have grades.
- **D25: Propagation record type selector in SPA** — 3 MUSTs + 2 SHOULDs. The UI always defaults to A records; users need a dropdown to select MX, TXT, etc.

### Items for Round 2 Discussion
28 items remained in "Discuss" — grouping by theme for convergence.

---

## Phase 4: Round 2 — Convergence Discussion

### Theme 1: Pre-Launch Polish (Blockers)

**D17/E13 — Security letter grade**
All panelists agree this is inconsistent. Health = grade, Email = grade, Security = no grade. Easy fix: apply same grading formula.
- **Verdict: MUST (pre-launch).** Add grading to security endpoint and SPA.

**D25 — Propagation type selector in SPA**
Carlos: "whatsmydns.net has a type dropdown. Without it, users can't check MX propagation from the browser." Marcus: "This is a basic UX gap." Janet: "When I'm checking if MX changes propagated, I need this."
- **Verdict: MUST (pre-launch).** Add a record type dropdown (A, AAAA, CNAME, MX, TXT, NS) next to the auto-refresh checkbox.

**E9 — `?force=true` results being cached**
Priya: "If I force-refresh, the result should NOT get cached with the normal key — next non-force request would get stale data." Raj: "Agreed, forced queries should either skip writing to cache or use a different key."
- **Verdict: MUST (pre-launch).** Force-requested results should not be written to cache.

**E4 — Domain validation vs underscored labels**
Dmitri: "Users will try `_dmarc.example.com` or `_acme-challenge.example.com` to check if their records exist. The current regex allows underscores, but the regex requires labels to end with alphanumeric which might reject some edge cases." Actually, reviewing the regex: `/^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$/` — this does allow underscores including at end of label. Works.
- **Verdict: PASS.** Already handles underscored labels.

### Theme 2: Should-Do (Soon After Launch)

**D19/D20 — SPF include chain expansion / accurate lookup counting**
Janet: "The current implementation counts `include:`, `a:`, `mx:`, etc. with a regex but doesn't recursively follow includes. A domain with 3 includes that each have 3 includes would show '3 lookups' when it's really 12. This is misleading." Dmitri: "SPF recursion is important but non-trivial. v2 feature."
- **Verdict: SHOULD (post-launch v2).** The current simple counting is better than nothing, but document the limitation.

**E1 — Rate limiter refill bug**
Priya: "The partial refill logic updates `lastRefill = now` after adding partial tokens, which means the next partial refill starts from `now` instead of the original window. Over time, tokens refill faster than 120/hour." Raj: "Not critical for launch — it errs on the side of permissiveness." Kurt: "Fix it but not a blocker."
- **Verdict: SHOULD (post-launch).** Fix the refill to use a fixed-window or proper sliding-window algorithm.

**A6 — Email audit (already done)**
All agree it's already implemented and good. Janet wants SPF chain expansion (D19) but that's a SHOULD.
- **Verdict: Already locked in as implemented.**

**A7 — Security analysis (already done)**
Sophie wants more checks but agrees the current set (dangling CNAME/NS, CNAME chains, CDN detection, wildcard, NS diversity) is a solid starting point.
- **Verdict: Already locked in as implemented.**

**A8 — `?explain=true`**
Broadly liked. Priya and Marcus want it. Others are neutral. Already implemented.
- **Verdict: SHOULD (already done).** Keep as-is.

**E6 — `wantsJSON` heuristic gaps**
Priya: "Browser `fetch()` with no Accept header gets SPA HTML. API consumers need to know to set Accept." Kurt: "The docs show `curl` examples which include `-H Accept`. This is fine." Dmitri: "Default to JSON for programmatic clients is the right call but hard to detect. Current heuristic is reasonable."
- **Verdict: SHOULD (post-launch).** Add a `?format=json` override as a simple escape hatch. Low effort.

**E7 — TXT record quote display**
Dmitri: "DoH JSON API returns TXT data with surrounding quotes sometimes. The SPA should strip them for display." Cosmetic but affects readability of SPF/DKIM records.
- **Verdict: SHOULD (post-launch).** Strip outer quotes from TXT record display data.

**D11 — CAA analysis**
Sophie: "CAA records are fetched but not analyzed. You could flag missing CAA (no CA restriction), overly permissive CAA, or conflicting CAA. Easy win." Dmitri: "Agree, it's a one-function addition to security.ts."
- **Verdict: SHOULD (post-launch).** Add CAA policy analysis to the security endpoint.

### Theme 3: Could-Do (Post-Launch Nice-to-Haves)

**A10 — `?expected=` parameter**
Already implemented. Useful for CI/CD propagation checks. Raj and Priya both want it.
- **Verdict: Already done.** ✅

**A12 — API docs**
Already implemented. Priya wants OpenAPI but that was CUT.
- **Verdict: Already done.** ✅

**A17 — IDN support**
Already implemented. Nice for international users.
- **Verdict: Already done.** ✅

**A19 — Cross-tool links**
Kurt: "This is the .lol family strategy." Carlos: "Good for SEO and discovery." Keep.
- **Verdict: Already done.** ✅

**B1 — Dark theme only**
Kurt: "Design DNA decision. No light mode." Marcus: "Accessibility concern for some users, but the contrast ratios look fine." B25 (light mode toggle) was already CUT.
- **Verdict: Keep as-is.**

**B12 — World map**
Marcus: "Looks great. Carlos: "Competitors have maps. It's a differentiator." Dmitri: "Gimmick but harmless."
- **Verdict: Keep as-is.** The map works and looks good.

**B13 — Auto-refresh**
Useful for propagation monitoring. Keep.
- **Verdict: Already done.**

**D1 — Reverse DNS (PTR)**
Dmitri: "Useful but requires IP-to-arpa conversion logic. Not a launch feature." Kurt: "COULD."
- **Verdict: COULD (post-launch).**

**D2 — WHOIS integration**
Carlos: "Would require an external API or scraping. Expensive." Kurt: "Yoke does this. No duplication."
- **Verdict: CUT.** Yoke.lol handles WHOIS.

**D4 — Blacklist/RBL check**
Janet: "Killer feature of MXToolbox." Carlos: "Would be huge differentiator." Kurt: "Requires connecting to dozens of RBL servers — latency and reliability nightmare from CF Workers. Post-launch if ever."
- **Verdict: COULD (post-launch v3).** Significant scope.

**D12 — GeoIP for A records**
Carlos: "Showing 'US, Cloudflare' next to an A record IP would be nice." Requires a GeoIP database or API.
- **Verdict: COULD (post-launch v2).** Would enhance the full report.

**D22 — TTL recommendation engine**
Dmitri: "Flag TTLs < 60s as aggressive, > 86400 as high. Simple heuristic." Kurt: "Add to health signals, not a separate feature."
- **Verdict: COULD (post-launch).** Easy to add to health.ts.

**E11 — Search validation before nav**
Marcus: "Should validate the input looks like a domain before pushing to history." Low effort.
- **Verdict: COULD (post-launch).** Minor polish.

---

## Round 2 Summary: Converged Positions

### 🔴 Pre-Launch Blockers (MUST)

| # | Item | Effort | Description |
|---|------|--------|-------------|
| **M1** | D17 — Security letter grade | Small | Add letter grade (A–F) to security endpoint, same formula as health/email. Update SPA `renderSecurity()` to show grade. |
| **M2** | D25 — Propagation type selector in SPA | Small | Add a `<select>` dropdown for record type (A, AAAA, CNAME, MX, TXT, NS) in the propagation panel. Wire it to pass `?type=` on fetch. |
| **M3** | E9 — Don't cache `?force=true` results | Tiny | Skip `env.CACHE.put()` when `force` is true. One-line fix. |

### 🟡 Should-Do (First Sprint Post-Launch)

| # | Item | Effort | Description |
|---|------|--------|-------------|
| **S1** | D19/D20 — SPF recursive lookup counting | Medium | Follow `include:` chains recursively up to 10 deep, count total lookups accurately. Document the limitation in explain text until then. |
| **S2** | E1 — Rate limiter refill fix | Small | Replace partial-refill logic with a clean fixed-window or proper token bucket that doesn't accelerate. |
| **S3** | E6 — Add `?format=json` escape hatch | Tiny | Alternative to Accept header for forcing JSON response. |
| **S4** | E7 — Strip TXT record surrounding quotes | Tiny | `.replace(/^"|"$/g, '')` on TXT data before display. |
| **S5** | D11 — CAA policy analysis in security | Small | Flag: no CAA (info), CAA present (pass), wildcard-only CA restriction, issuewild analysis. |

### 🟢 Could-Do (Post-Launch Backlog)

| # | Item | Effort |
|---|------|--------|
| C1 | D1 — Reverse DNS (PTR) lookup support | Medium |
| C2 | D4 — Blacklist/RBL checking | Large |
| C3 | D12 — GeoIP enrichment for A records | Medium |
| C4 | D22 — TTL recommendation in health signals | Small |
| C5 | E11 — Client-side domain validation before nav | Tiny |

### 🗑️ Eliminated (Don't Build)

WHOIS (yoke.lol does it), SMTP tests (can't from CF Workers), subdomain enumeration (scope creep), zone transfer tests (can't from CF Workers), DANE/TLSA validation, response size analysis, open resolver detection, batch mode, webhooks, export, light mode, loading skeletons, API versioning, OpenAPI spec, format options, NSEC3 analysis, SOA serial detection, better DKIM discovery.

---

## Final Convergence Status

| Panelist | Status |
|----------|--------|
| Dmitri | ✅ Converged |
| Priya | ✅ Converged |
| Marcus | ✅ Converged |
| Sophie | ✅ Converged |
| Janet | ✅ Converged — notes SPF limitation should be documented |
| Carlos | ✅ Converged |
| Raj | ✅ Converged |
| Kurt | ✅ Converged — "Ship with the 3 MUSTs fixed, iterate on SHOULDs" |

**All 8 panelists converged in 2 rounds.**

---

## Implementation Notes for Pre-Launch Blockers

### M1: Security Letter Grade
In `security.ts`, add grading after signal collection:
```typescript
let grade: 'A' | 'B' | 'C' | 'D' | 'F';
if (counts.fail === 0 && counts.warn === 0) grade = 'A';
else if (counts.fail === 0 && counts.warn <= 2) grade = 'B';
else if (counts.fail <= 1) grade = 'C';
else if (counts.fail <= 3) grade = 'D';
else grade = 'F';
```
Add `grade` to the `security` object in the response. Update `renderSecurity()` in `spa.ts` to show the grade like health/email do.

### M2: Propagation Type Selector
Add a `<select>` in the propagation panel's auto-refresh bar:
```html
<select id="propType">
  <option value="A">A</option>
  <option value="AAAA">AAAA</option>
  <option value="CNAME">CNAME</option>
  <option value="MX">MX</option>
  <option value="TXT">TXT</option>
  <option value="NS">NS</option>
</select>
```
Wire `loadPropagation()` and `refreshPropagation()` to include `?type=` from the selected value.

### M3: Don't Cache Forced Results
In `handler.ts`, change the cache-write block:
```typescript
if (action !== 'propagation' && !force) {
```
One-word change. Currently says `if (action !== 'propagation')`.
