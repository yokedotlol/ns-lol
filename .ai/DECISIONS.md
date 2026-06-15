# ns.lol — Decision Log

> Append-only record of significant decisions. Never edit or remove entries.
> Include `Rejected:` to prevent re-exploring dead ends, `Directive:` to guide future work.

---

### 2026-06-14 — Single probe machine, not per-region

**What changed:** Replaced initial 7-region Fly deployment with a single machine in SJC.
**Why:** Geographic diversity comes from querying geographically distributed *resolvers*, not from where the probe runs. One machine querying 15 global resolvers via UDP gives the same propagation insight as 7 machines querying local resolvers — at $0/mo instead of $35/mo.
**Rejected:** Per-region probes (7 machines × $5/mo). The per-region model would also need per-region auth, health checks, and failover logic.
**Directive:** Never deploy multiple probe machines for geographic diversity. Add diversity by adding resolvers to the list, not machines to Fly.

---

### 2026-06-14 — Natural Earth SVG for world map

**What changed:** Replaced hand-drawn SVG continent outlines with Natural Earth 110m land outlines.
**Why:** The hand-drawn map looked amateur. Natural Earth provides free, public domain vector data at multiple resolutions.
**Rejected:** Using a map library (Leaflet, Mapbox) → too heavy for an inline SPA, adds external dependencies.
**Directive:** World map is SVG path data embedded in `spa.ts`. If the map needs updating, regenerate from Natural Earth shapefiles, don't hand-edit the paths.

---

### 2026-06-14 — Wireformat DoH for all resolvers

**What changed:** Standardized all DoH queries to use RFC 8484 wireformat (POST with `application/dns-message`).
**Why:** The JSON DNS API (`?type=A&name=...`) is a Cloudflare/Google extension, not universally supported. Wireformat is the actual RFC standard.
**Rejected:** Mixed mode (JSON for CF/Google, wireformat for others) → inconsistent behavior, harder to debug.
**Directive:** All DoH goes through `buildDNSQuery()` + `queryDoH()` with wireformat POST. Do not add JSON API fallback.

---

### 2026-06-14 — No budget-based scoring (unlike Yoke)

**What changed:** ns.lol uses simple letter grades (A-F) for health, email, and security based on pass/warn/fail signal counts.
**Why:** DNS analysis is binary — records exist or they don't, configuration is correct or it isn't. The deductive scoring model (start at 100, subtract) that Yoke uses makes sense for holistic domain analysis but is overkill for DNS-focused checks.
**Rejected:** Deductive scoring model → would require signal weights, absent penalties, axis normalization. Unnecessary complexity for the problem space.
**Directive:** Keep simple grading. If scoring becomes more nuanced in the future, consider adopting Yoke's model, but don't prematurely add it.

---

### 2026-06-14 — Inline SPA over framework

**What changed:** SPA is a single `renderSPA()` function in `src/spa.ts` that returns complete HTML with embedded JSON data.
**Why:** Zero external dependencies, no build step beyond `tsc`, fastest possible TTFB (HTML is pre-rendered server-side with data). Aligns with .lol family convention of minimal infrastructure.
**Rejected:** React/Vue/Svelte SPA → adds build toolchain, node_modules, hydration overhead, potential CSP issues. Also rejected: separate static files → requires asset hosting and cache invalidation.
**Directive:** SPA stays inline. If it grows past ~2000 lines, consider splitting into template functions within the same file, but don't extract to a framework.

---

### 2026-06-15 — Chinese resolvers replaced

**What changed:** Removed Tencent DNSPod and AliDNS from the probe resolver list. Replaced with Verisign, DNS.SB, and Wikimedia.
**Why:** Both consistently timed out from SJC — they block or deprioritize UDP queries from US data centers.
**Rejected:** Adding retries or longer timeouts for Chinese resolvers → still unreliable, slows down the entire propagation check.
**Directive:** Only add resolvers that reliably respond from the probe's region (SJC). Test any new resolver with a manual UDP query before committing.
