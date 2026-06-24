# ns.lol — Gotchas

> Lessons learned the hard way. Every "don't" is paired with a "do."
> Append new entries when a mistake is discovered. Never remove entries.

---

### Chinese DNS resolvers block UDP from US IPs

**What happened:** Tencent DNSPod (119.29.29.29) and AliDNS (223.5.5.5) consistently timed out when the Fly probe (in SJC) sent UDP queries. This caused 80% propagation instead of 100%.

**Don't:** Include resolvers that are known to block queries from US data centers.
**Do:** Replaced Chinese resolvers with Verisign (64.6.64.6), DNS.SB (185.222.222.222), and Wikimedia (76.223.122.150). Validate any new resolver actually responds from the probe's region before adding it to the list.

---

### dns0.eu is Cloudflare-proxied — unreachable from CF Workers via DoH

**What happened:** dns0.eu's DoH endpoint is behind Cloudflare. CF Workers can't fetch from another CF-proxied origin (loops). DoH queries to dns0.eu returned errors.

**Don't:** Add CF-proxied DoH resolvers to `DOH_RESOLVERS` in `src/dns.ts`.
**Do:** The UDP probe in `probe/server.js` can reach dns0.eu (193.110.81.0) via raw UDP since that bypasses CF. Replaced dns0.eu with CleanBrowsing in the DoH resolver list. When adding new DoH resolvers, check if they're behind Cloudflare first: `curl -sI <resolver-url> | grep cf-ray`.

---

### Egress proxy blocks *.fly.dev from sandbox

**What happened:** Could not curl the Fly probe directly from the development sandbox to verify it was working. All `*.fly.dev` requests are blocked by the egress proxy.

**Don't:** Try to verify the probe by curling it from the sandbox.
**Do:** Verify via the Fly Machines API (`api.machines.dev`), CI smoke tests, or by hitting the CF Worker propagation endpoint (which calls the probe internally).

---

### Probe was initially deployed via Machines API (base64 env hack)

**What happened:** The Depot builder was stuck during the first `flyctl deploy`, so the probe was deployed by injecting `server.js` as a base64-encoded environment variable via the Machines API, then decoded at runtime. This was a workaround, not the production path.

**Don't:** Deploy via the Machines API with env-var injection as a standard practice.
**Do:** Use `flyctl deploy --remote-only` via CI (`.github/workflows/fly-probe.yml`). The Dockerfile builds normally in CI.

---

### `--ha=false` needed to prevent duplicate Fly machines

**What happened:** `flyctl deploy` defaults to creating 2 machines for HA. Without `--ha=false`, CI created a second machine alongside the one deployed via the Machines API, resulting in duplicates.

**Don't:** Run `flyctl deploy` without `--ha=false` for the probe.
**Do:** The CI workflow includes `--ha=false`. If you ever deploy manually: `flyctl deploy --remote-only --ha=false` from the `probe/` directory.

---

### DoH wireformat vs JSON API mismatch

**What happened:** Early implementation used Cloudflare's JSON DNS API (`?type=A&name=...`) for some resolvers and wireformat for others. Not all resolvers support the JSON API (it's a CF/Google extension, not standardized). This caused silent failures for resolvers that only support the standard wireformat endpoint.

**Don't:** Mix JSON API and wireformat DoH. Don't assume resolvers support `application/dns-json`.
**Do:** All DoH queries go through `buildDNSQuery()` → `queryDoH()` using `application/dns-message` POST (RFC 8484). This is the universal standard — every compliant DoH resolver supports it.

---

### NXDOMAIN wildcard detection overlaps with hijacking detection

**What happened:** Both `checkWildcard()` and `checkNXDOMAINHijacking()` in `src/security.ts` query random non-existent subdomains. When a wildcard is present, both fire, creating redundant and potentially contradictory signals.

**Don't:** Treat wildcard responses as NXDOMAIN hijacking.
**Do:** `checkNXDOMAINHijacking()` checks for known ISP hijacking IPs first. If the response doesn't match known hijack patterns, it reports "likely wildcard DNS, not hijacking" as info-level. The wildcard check handles the primary wildcard reporting.

---

### Seven regional probe machines = $35/mo for no reason

**What happened:** Initial probe deployment created 7 Fly machines across global regions (sjc, iad, lhr, fra, nrt, sin, syd) at $5/mo each. The architecture doesn't need per-region probes — geographic diversity comes from querying geographically distributed *resolvers*, not from running in multiple locations.

**Don't:** Deploy multiple probe machines thinking geographic diversity comes from probe location.
**Do:** One machine in SJC queries 15 globally distributed resolvers via UDP. Same result, $0/mo (free tier) instead of $35/mo.

---

### IIJ resolver duplicated in DoH list

**What happened:** `DOH_RESOLVERS` in `src/dns.ts` has IIJ (Tokyo) listed twice, occupying two slots. This means IIJ is double-weighted in DoH-fallback propagation checks, and only 13 unique resolvers are actually queried.

**Don't:** Copy-paste resolver entries without checking for duplicates.
**Do:** Before adding a resolver, `grep` for its URL/IP in the list. The duplicate should be replaced with a different resolver.
