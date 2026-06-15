# ns.lol — Panel Review v2

**Date:** 2026-06-15
**Version reviewed:** Post-probe, post-tests, post-.ai/
**Previous review:** `PANEL-REVIEW.md` (2026-06-14, pre-probe)
**Methodology:** Divergent → Panel Assembly → Voting → Convergence (per AGENTS.md)

---

## Changes Since v1 Review

| # | Change | Status |
|---|--------|--------|
| Δ1 | UDP probe on Fly.io (SJC, single machine, auto-stop) — real propagation via raw UDP | ✅ Deployed |
| Δ2 | Propagation progress bar (CSS animated, color-coded) | ✅ Implemented |
| Δ3 | Security endpoint now has letter grade (v1 blocker M1) | ✅ Done |
| Δ4 | Propagation type selector in SPA (v1 blocker M2) | ✅ Done |
| Δ5 | `?force=true` results no longer cached (v1 blocker M3) | ✅ Done |
| Δ6 | Replaced unreliable resolvers (Chinese → Verisign/DNS.SB/Comodo; dns0.eu → Level3/CleanBrowsing; Mullvad → Neustar in probe) | ✅ Done |
| Δ7 | 128 tests across 6 files (vitest) | ✅ Done |
| Δ8 | `.ai/` context folder bootstrapped | ✅ Done |
| Δ9 | Reverse DNS (PTR) lookup — IPv4 and IPv6 (v1 nice-to-have D1) | ✅ New |
| Δ10 | Authority chain trace (`/:domain/trace`) | ✅ New |
| Δ11 | Batch endpoint (`POST /batch`, max 20 domains) | ✅ New |
| Δ12 | Numeric QTYPE support (`/:domain/65` for HTTPS etc.) | ✅ New |
| Δ13 | Simulated ANY query (`/:domain/any`, RFC 8482 workaround) | ✅ New |
| Δ14 | dig-style plain text output (`Accept: text/plain`) | ✅ New |
| Δ15 | CDN pattern ordering fix (specific AWS before generic) | ✅ Done |

### v1 SHOULDs Status (Not Done)

| # | v1 Item | Status |
|---|---------|--------|
| S1 | SPF recursive lookup counting | ❌ Still regex-based |
| S2 | Rate limiter refill bug fix | ❌ Same code |
| S3 | `?format=json` escape hatch | ❌ Not added |
| S4 | TXT record quote stripping | ❌ Not done |
| S5 | CAA policy analysis in security | ❌ Not done |

---

## Phase 1: Divergent Pass — New & Changed Items

Items already reviewed in v1 that haven't changed are not re-listed unless new context warrants revisiting.

### F. New Features & Endpoints

| # | Item | State |
|---|------|-------|
| F1 | Reverse DNS lookup (`/:ip`) | Auto-detects IPv4/IPv6, converts to `.in-addr.arpa`/`.ip6.arpa`, returns PTR records with hostname links. Explain mode supported. |
| F2 | Authority trace (`/:domain/trace`) | 5-step walk: TLD NS → domain NS → A resolution via 3 resolvers → SOA → DNSSEC chain. Explain mode supported. |
| F3 | Batch lookup (`POST /batch`) | JSON body `{"domains":[...], "type":"A"}`. Max 20. Parallel resolution. |
| F4 | Numeric QTYPE (`/:domain/:number`) | Any QTYPE 1-65535. Maps to known names when possible. |
| F5 | ANY query simulation (`/:domain/any`) | Queries all 15 types individually (RFC 8482 workaround). Groups by type. |
| F6 | dig-style output | Full `Accept: text/plain` content negotiation. Covers all endpoints. |
| F7 | UDP probe integration | Worker calls `PROBE_URL/propagation` with key auth, 15s timeout, auto-fallback to DoH. |
| F8 | Propagation progress bar | CSS `.prop-bar` with smooth transition, color-coded (green/yellow/red), rendered below percentage. |
| F9 | Propagation type selector | `<select>` in SPA for A/AAAA/CNAME/MX/TXT/NS/SOA/CAA. Re-fetches on change. |
| F10 | SPA trace panel | Step-by-step visualization with numbered circles, NS tags, resolver comparison, DNSSEC chain status. |

### G. New Bugs & Issues Found

| # | Item | Severity |
|---|------|----------|
| G1 | **Duplicate `loadSecurity()` function in spa.ts** — defined twice (around lines 425 and 433). Second definition shadows the first. Dead code, potential confusion. | Low |
| G2 | **CleanBrowsing inherits dns0.eu's Paris lat/lng (48.86, 2.35)** — CleanBrowsing is anycast, not based in Paris. Shows a Paris dot on the map that's misleading. Users may still think it's dns0.eu. | Medium |
| G3 | **CleanBrowsing DoH uses security-filter endpoint** (`/doh/security-filter/`) — this endpoint filters malware/phishing domains. Could return NXDOMAIN or REFUSED for domains that are flagged but not actually malicious. False positive risk in propagation checks. | Medium |
| G4 | **PROBE_KEY sent as URL query parameter** — `?key=${env.PROBE_KEY}` appears in access logs, potentially in Fly metrics. Should use `Authorization` header instead. | Medium |
| G5 | **Probe `//Europe` comment section has non-European resolvers** — Level3 (US Anycast) and Neustar (Global Anycast) are under the `// Europe` comment. Misleading. | Low |
| G6 | **STATE.md is significantly stale** — says "0 tests" (actually 128), says "dns0.eu" is in UDP resolvers (it's Level3 now), resolver counts are wrong. | Low |
| G7 | **`_source` field in propagation response** — exposes whether `udp` or `doh` was used. Leaks internal infrastructure detail. Not harmful but not needed by consumers. | Low |
| G8 | **Probe cold start on Fly auto-stop** — after idle period, first propagation request hits cold start latency (~2-3s) before the probe can service requests. Combined with 15s timeout, first request after idle may be slow. | Medium |
| G9 | **No probe health monitoring** — if the probe goes down, propagation silently falls back to DoH. Users won't know they're getting DoH results instead of real UDP. The `_source` field tells them, but it's not surfaced in the SPA. | Medium |
| G10 | **IPv6 expansion in `ipToReverseDomain()` has edge case** — when `::` is at the start (e.g., `::1`), the split on `:` produces `['', '', '1']`. The empty-string check `part === ''` fires for both empty parts, but only the first `''` after split represents the `::`. With `::1`, `parts.filter(p => p !== '')` gives `['1']`, `missing = 8 - 1 = 7`, loop runs 8 times (missing + 1), filling 8 groups + `'0001'` = 9 groups → 36 hex chars instead of 32. | Medium |
| G11 | **Batch endpoint not rate-limited per-domain** — a single batch of 20 domains counts as 1 rate-limit token but makes 20 DNS queries. Potential for abuse: 120 batches/hour = 2,400 domain lookups. | Low |
| G12 | **`_cache_control` field still in API output** — v1 panel voted to eliminate (4 CUTs). Still present in propagation responses. | Low |

### H. Reliability & Resolver Analysis

| # | Item | State |
|---|------|-------|
| H1 | UDP probe resolver list: 15 resolvers, all responsive from SJC | Validated by resolver replacement |
| H2 | DoH resolver list: 13 resolvers (Mullvad still present) | Mullvad DoH works from CF Workers (HTTPS, not UDP). REFUSED is only on UDP. |
| H3 | Resolver overlap between UDP and DoH: 10 shared, 5 probe-only (Quad9 Secondary, Level3, Neustar, Verisign, Comodo), 3 DoH-only (Mullvad, Wikimedia, IIJ) | Reasonable differentiation |
| H4 | No European resolver in probe responds to UDP from SJC | Level3/Neustar are US/global anycast. AdGuard (Cyprus) is the only non-US/CA resolver. Geographic gap. |
| H5 | Probe single point of failure (SJC) | If the region has issues, all propagation degrades to DoH-only |

### I. Architecture & Code Quality

| # | Item | State |
|---|------|-------|
| I1 | `handler.ts` at 1,117 lines | Contains: routing, full report, ANY query, numeric lookup, trace, batch, reverse DNS, propagation, dig formatting, API docs, explain helpers. Doing too much. |
| I2 | `spa.ts` at 967 lines | CSS + HTML template + all JS (search, tabs, render functions, map, auto-refresh, countdowns, URL routing). Natural boundary: styles, template, client JS. |
| I3 | Test coverage: 128 tests across 6 files | Good coverage of wire format, DNS, handler routing, email, security, health. Missing: spa.ts (untestable without DOM), rate-limiter.ts, worker.ts, probe/server.js. |
| I4 | No integration tests | No end-to-end tests that hit the actual deployed worker or probe. CI smoke tests exist in deploy workflow. |
| I5 | CDN pattern ordering | Fixed — specific AWS patterns (`.elb.amazonaws.com`, `.s3.amazonaws.com`) before generic `.amazonaws.com`. |

---

## Phase 2: Panel Assembly

Same 8 panelists as v1, with updated context:

| # | Name | Role | Bias |
|---|------|------|------|
| P1 | **Dmitri** | DNS engineer / sysadmin | RFC correctness, resolver reliability, authoritative data |
| P2 | **Priya** | API consumer building monitoring tools | Clean schemas, consistency, machine-readable everything |
| P3 | **Marcus** | Web designer reviewing SPA UI/UX | Visual hierarchy, micro-interactions, mobile, accessibility |
| P4 | **Sophie** | Security researcher | Attack surface, SSRF, input validation, infrastructure exposure |
| P5 | **Janet** | Email deliverability consultant | Email auth completeness, comparison to MXToolbox |
| P6 | **Carlos** | Competitor analyst (whatsmydns.net, dnschecker.org, mxtoolbox) | Feature parity, switching incentives |
| P7 | **Raj** | DevOps evaluating for production monitoring | Reliability, uptime, CI/CD integration |
| P8 | **Kurt** | Creator — pragmatic, fast, $5/mo ceiling | Ship if it works. No bloat. |

---

## Phase 3: Round 1 Voting

Scale: **MUST** (blocker) / **SHOULD** (do soon) / **COULD** (nice-to-have) / **CUT** (don't do)

### New Features (Keep/Cut)

| Item | Dm | Pr | Ma | So | Ja | Ca | Raj | Ku | Result |
|------|----|----|----|----|----|----|-----|----|--------|
| F1 Reverse DNS | MUST | SHOULD | COULD | SHOULD | SHOULD | MUST | MUST | MUST | ✅ **LOCKED (4 MUST)** — keep |
| F2 Authority trace | SHOULD | MUST | SHOULD | MUST | COULD | MUST | MUST | MUST | ✅ **LOCKED (5 MUST)** — keep |
| F3 Batch lookup | COULD | MUST | CUT | COULD | COULD | SHOULD | MUST | MUST | Discuss |
| F4 Numeric QTYPE | MUST | SHOULD | CUT | SHOULD | CUT | COULD | SHOULD | SHOULD | Discuss |
| F5 ANY simulation | SHOULD | SHOULD | CUT | COULD | COULD | SHOULD | SHOULD | SHOULD | Discuss |
| F6 dig-style output | MUST | MUST | CUT | COULD | COULD | SHOULD | MUST | MUST | ✅ **LOCKED (4 MUST)** — keep |
| F7 UDP probe | MUST | SHOULD | CUT | SHOULD | SHOULD | MUST | MUST | MUST | ✅ **LOCKED (4 MUST)** — keep |
| F8 Progress bar | COULD | COULD | MUST | COULD | COULD | MUST | COULD | MUST | Discuss |
| F9 Type selector | SHOULD | MUST | MUST | COULD | MUST | MUST | SHOULD | MUST | ✅ **LOCKED (5 MUST)** — keep |
| F10 Trace panel | SHOULD | SHOULD | MUST | SHOULD | COULD | MUST | SHOULD | MUST | Discuss |

### New Bugs (Fix Priority)

| Item | Dm | Pr | Ma | So | Ja | Ca | Raj | Ku | Result |
|------|----|----|----|----|----|----|-----|----|--------|
| G1 Duplicate loadSecurity | CUT | SHOULD | CUT | CUT | CUT | CUT | CUT | SHOULD | 🗑️ **ELIMINATED (5 CUT)** — harmless, fix if touching file |
| G2 CleanBrowsing Paris coords | SHOULD | COULD | MUST | COULD | COULD | SHOULD | COULD | SHOULD | Discuss |
| G3 CleanBrowsing security-filter | MUST | SHOULD | CUT | MUST | SHOULD | SHOULD | MUST | SHOULD | Discuss |
| G4 Probe key in URL params | COULD | SHOULD | CUT | MUST | CUT | CUT | SHOULD | SHOULD | Discuss |
| G5 Misleading Europe comment | CUT | CUT | CUT | CUT | CUT | CUT | CUT | COULD | 🗑️ **ELIMINATED (7 CUT)** — comment only |
| G6 STATE.md stale | CUT | CUT | CUT | CUT | CUT | CUT | CUT | SHOULD | 🗑️ **ELIMINATED (7 CUT)** — docs, not blocking |
| G7 `_source` field exposed | CUT | SHOULD | CUT | SHOULD | CUT | CUT | SHOULD | COULD | 🗑️ **ELIMINATED (4 CUT)** — useful for debugging |
| G8 Probe cold start | SHOULD | COULD | CUT | CUT | CUT | COULD | MUST | SHOULD | Discuss |
| G9 No probe health visibility | SHOULD | SHOULD | CUT | SHOULD | CUT | COULD | MUST | COULD | Discuss |
| G10 IPv6 reverse edge case | MUST | SHOULD | CUT | SHOULD | CUT | COULD | SHOULD | SHOULD | Discuss |
| G11 Batch rate limit bypass | COULD | COULD | CUT | MUST | CUT | CUT | SHOULD | COULD | Discuss |
| G12 `_cache_control` in output | CUT | SHOULD | CUT | CUT | CUT | CUT | COULD | CUT | 🗑️ **ELIMINATED (5 CUT)** — low priority |

### Carried-Over v1 SHOULDs (Now Revisited)

| Item | Dm | Pr | Ma | So | Ja | Ca | Raj | Ku | Result |
|------|----|----|----|----|----|----|-----|----|--------|
| S1 SPF recursive counting | MUST | SHOULD | CUT | SHOULD | MUST | SHOULD | COULD | COULD | Discuss |
| S2 Rate limiter refill fix | SHOULD | MUST | CUT | SHOULD | CUT | CUT | MUST | SHOULD | Discuss |
| S3 `?format=json` escape | CUT | SHOULD | CUT | CUT | CUT | COULD | SHOULD | CUT | 🗑️ **ELIMINATED (4 CUT)** — Accept header is fine |
| S4 TXT quote stripping | SHOULD | SHOULD | SHOULD | CUT | SHOULD | SHOULD | CUT | SHOULD | Discuss |
| S5 CAA analysis in security | SHOULD | COULD | CUT | MUST | CUT | SHOULD | COULD | COULD | Discuss |

### Reliability Items

| Item | Dm | Pr | Ma | So | Ja | Ca | Raj | Ku | Result |
|------|----|----|----|----|----|----|-----|----|--------|
| H4 No European UDP resolver | MUST | SHOULD | CUT | COULD | COULD | MUST | SHOULD | SHOULD | Discuss |
| H5 Probe SPOF (SJC only) | SHOULD | COULD | CUT | CUT | CUT | COULD | MUST | CUT | 🗑️ **ELIMINATED (4 CUT)** — by design, per DECISIONS.md |

### Architecture

| Item | Dm | Pr | Ma | So | Ja | Ca | Raj | Ku | Result |
|------|----|----|----|----|----|----|-----|----|--------|
| I1 Split handler.ts | SHOULD | SHOULD | CUT | CUT | CUT | CUT | SHOULD | COULD | 🗑️ **ELIMINATED (4 CUT)** — works fine monolithic |
| I2 Split spa.ts | CUT | CUT | SHOULD | CUT | CUT | CUT | CUT | CUT | 🗑️ **ELIMINATED (7 CUT)** — inline SPA by design |
| I3 Probe/rate-limiter test gaps | COULD | SHOULD | CUT | SHOULD | CUT | CUT | SHOULD | COULD | Discuss |

---

## Phase 4: Round 2 — Convergence Discussion

### Theme 1: Reliability Fixes (Pre-Announce Priority)

**G3 — CleanBrowsing security-filter endpoint**
Dmitri: "This is the biggest reliability concern. CleanBrowsing's security filter actively blocks domains it classifies as malware or phishing. If a user checks propagation for a domain that's on their blocklist, CleanBrowsing will return NXDOMAIN while every other resolver returns NOERROR. That's a false propagation failure."
Raj: "Agree. Propagation should use neutral resolvers. A security-filtered resolver biases results."
Sophie: "This could cause false 'not propagated' signals for legitimate but flagged domains."
Kurt: "Easy fix — either use their base endpoint or swap to a different resolver."
- **Verdict: MUST.** Replace `doh.cleanbrowsing.org/doh/security-filter/` with either CleanBrowsing's unfiltered endpoint (`doh.cleanbrowsing.org/doh/family-filter/` is also filtered — check if they have a plain one) or swap to a different resolver entirely.

**G2 — CleanBrowsing at Paris coordinates**
Marcus: "The map shows a dot in Paris labeled 'CleanBrowsing'. This is misleading — CleanBrowsing is anycast, not Parisian. Users who remember dns0.eu may think dns0 is still there and still failing."
Dmitri: "More importantly, if we're replacing CleanBrowsing (per G3 above), this fixes itself."
Carlos: "Move the dot to a more accurate location for whatever replaces it."
- **Verdict: SHOULD.** Relocate/replace. The real fix is G3 — give the replacement resolver honest coordinates.

**G10 — IPv6 reverse DNS edge case**
Dmitri: "The `::` expansion logic is broken. For `::1`, `split(':')` gives `['', '', '1']`. The code iterates and checks `part === ''`, but the loop adds `missing + 1` groups for the empty part, overproducing hex digits. This will generate wrong `.ip6.arpa` domains for compressed IPv6 addresses."
Priya: "Anyone who passes an IPv6 address with `::` compression (which is almost all of them) gets a wrong PTR lookup."
Kurt: "This is a correctness bug in a shipped feature. Fix it."
- **Verdict: MUST.** Fix `ipToReverseDomain()` to correctly expand `::` in all positions.

**S2 — Rate limiter refill bug**
Priya: "The partial refill logic sets `lastRefill = now` after adding proportional tokens. Next partial refill starts from `now`, not the original window. Over successive partial refills, tokens accumulate faster than 120/hour."
Raj: "This means the rate limiter is MORE permissive than intended, not less. It errs on the nice side."
Kurt: "Not a launch blocker since it fails open, not closed. Fix it but don't rush it."
- **Verdict: SHOULD.** Fix post-announce. Replace with a clean fixed-window or sliding-window.

**H4 — No European resolver in UDP probe**
Dmitri: "The UDP probe has 15 resolvers but most are US-based or global anycast hitting US PoPs. The only non-Americas resolver is AdGuard in Cyprus. No Western European resolver in the UDP list."
Carlos: "whatsmydns.net shows European resolvers. Users expect geographic diversity."
Raj: "This affects the map too — no dots in Western Europe from the UDP probe."
Kurt: "We dropped dns0.eu because it blocked US traffic. What's a European resolver that accepts UDP from US?"
Dmitri: "Yandex DNS (77.88.8.8) accepts global UDP. It's based in Russia though. Hurricane Electric (74.82.42.42) in Fremont, CA — not European. Best bet: try a few and verify. Hetzner DNS (185.12.64.1) is in Germany and may work."
- **Verdict: SHOULD (post-announce).** Find and add 1-2 European resolvers that reliably respond to UDP from SJC. Test before adding.

### Theme 2: Quality & Polish

**G4 — Probe auth key in URL query parameter**
Sophie: "Sending auth secrets as URL parameters means they appear in Fly access logs, any CDN logs between them, and possibly monitoring dashboards. Move to `Authorization` header."
Kurt: "Agree in principle, but it's a private endpoint with no CDN between Worker and Fly. Low actual risk."
Sophie: "Still a bad habit. Simple to fix."
- **Verdict: SHOULD.** Move to `Authorization: Bearer ${key}` header. Tiny change, good hygiene.

**G8 — Probe cold start latency**
Raj: "Fly auto-stop means the probe's Node.js process shuts down after idle. First request after idle has ~2-3s cold start. With the 15s Worker-side timeout, it'll work, but the first propagation check after idle will be notably slower."
Kurt: "Auto-stop saves us from paying for a machine that sits idle. The 15s timeout handles it. If cold start ever exceeds 15s, the fallback to DoH kicks in. Acceptable."
Raj: "Could add a keep-alive ping from the Worker, but that defeats auto-stop."
- **Verdict: COULD.** Accept the tradeoff. Document it in GOTCHAS.

**G9 — No probe health visibility in SPA**
Raj: "When the probe is down and propagation falls back to DoH, the SPA shows results but doesn't tell the user they're seeing DoH results instead of real UDP. The `_source` field is in the JSON but not rendered."
Carlos: "Add a subtle indicator: 'via UDP probe' vs 'via DoH fallback'. Helps power users know what they're getting."
Dmitri: "Agree — a small badge or tooltip on the propagation panel."
Kurt: "Nice-to-have. The results are still accurate, just from a different source."
- **Verdict: COULD.** Add a small `_source` indicator in the SPA propagation header. Not blocking.

**S4 — TXT record quote stripping**
Janet: "SPF records display as `\"v=spf1 include:...\"` with surrounding quotes. Looks sloppy."
Dmitri: "DoH wireformat returns TXT data without quotes. The quotes come from concatenated strings in the wire response. Actually, looking at the code, `parseDNSResponse` returns raw text. The quotes may come from certain resolvers or from the JSON serialization."
Marcus: "Either way, strip outer quotes in the display layer."
- **Verdict: SHOULD.** Quick fix in `renderRecords()` or in the data pipeline.

**G11 — Batch endpoint rate limit**
Sophie: "One batch = 20 lookups but 1 rate-limit token. 120 batches/hour = 2,400 lookups."
Kurt: "The batch endpoint is meant for automation. 2,400 lookups/hour from a single IP is still reasonable. If it becomes a problem, charge batch calls proportionally."
Raj: "Agree — don't over-engineer rate limiting."
- **Verdict: CUT.** Not a real problem at current scale. Monitor.

### Theme 3: Feature Completeness

**S1 — SPF recursive lookup counting**
Janet: "The current implementation counts `include:`, `a:`, `mx:` with a regex. A domain with `include:_spf.google.com` counts as 1 lookup, but Google's SPF includes 4 more `include:` directives, making the real count 5. The RFC 7208 limit is 10 total, and we're telling users a domain has 3 lookups when it really has 12."
Dmitri: "This is misleading for the email audit. It's the one place where we're giving objectively wrong information."
Kurt: "It was SHOULD in v1 but Janet's right — it's not just incomplete, it's actively misleading."
Priya: "The fix is recursive: query each `include:` target, count its mechanisms, recurse. Cap at 10 depth to avoid loops."
- **Verdict: SHOULD (high priority post-announce).** Add a disclaimer to the current output noting the count is non-recursive, and prioritize the recursive fix in the first post-launch sprint.

**S5 — CAA analysis in security**
Sophie: "CAA records are fetched in the full report but not analyzed in the security endpoint. Easy wins: flag missing CAA (no CA restriction), analyze `issue`/`issuewild`/`iodef` tags, check for overly permissive policies."
Carlos: "MXToolbox has CAA analysis. It's a differentiator for the security panel."
Kurt: "Small effort, good value. Do it post-announce."
- **Verdict: SHOULD (post-announce).** Add to security.ts as a new check function.

**I3 — Test gaps (probe, rate-limiter)**
Raj: "The probe has no tests. The rate-limiter has no tests. Both have non-trivial logic — DNS wire parsing in the probe, token bucket math in the rate-limiter."
Kurt: "Probe tests would need mocking UDP sockets. Rate-limiter tests are easy to add. Prioritize rate-limiter tests since they validate the refill bug fix (S2)."
- **Verdict: SHOULD.** Add rate-limiter unit tests alongside the S2 fix. Probe tests are COULD.

### Theme 4: Features — Keep or Cut?

**F3 — Batch lookup**
Priya: "Essential for monitoring tools. I'd use this to check 20 customer domains in one call."
Raj: "Great for CI/CD — verify all your domains resolve after a DNS change."
Kurt: "Keep. It's already built and working."
- **Verdict: Keep.**

**F4 — Numeric QTYPE**
Dmitri: "Power user feature. Useful for SVCB (64), HTTPS (65), or any experimental type."
Kurt: "It's 30 lines of code and already works. Keep."
- **Verdict: Keep.**

**F5 — ANY simulation**
Dmitri: "Smart workaround for RFC 8482. Useful for quick domain reconnaissance."
- **Verdict: Keep.**

**F8 — Progress bar**
Marcus: "It's implemented and the CSS is clean. If users aren't seeing it, it might be a rendering issue — the bar is inside `.prop-summary` which uses flexbox. On narrow screens, the bar's `max-width: 320px` might not be visible."
Kurt: "The user reported not seeing it. Need to verify it renders in production."
- **Verdict: Keep but verify.** Check if the progress bar renders correctly in production. May need CSS debugging.

---

## Round 2 Summary: Converged Positions

### 🔴 Pre-Announce Blockers (MUST)

| # | Item | Effort | Description |
|---|------|--------|-------------|
| **M1** | G3 — Replace CleanBrowsing security-filter endpoint | Small | CleanBrowsing's `/doh/security-filter/` actively blocks flagged domains, causing false propagation failures. Either find their unfiltered endpoint or replace with a different resolver. Also update lat/lng to honest coordinates (fixes G2). |
| **M2** | G10 — Fix IPv6 reverse DNS expansion | Small | `ipToReverseDomain()` produces wrong `.ip6.arpa` domains for `::` compressed addresses. Fix the expansion logic to correctly handle all `::` positions (start, middle, end). |

### 🟡 Should-Do (First Sprint Post-Announce)

| # | Item | Effort | Description |
|---|------|--------|-------------|
| **S1** | S2/v1 — Rate limiter refill fix | Small | Replace partial-refill logic with a clean fixed-window or sliding-window algorithm. Add unit tests for rate-limiter.ts alongside the fix. |
| **S2** | G4 — Move probe auth to header | Tiny | Change `?key=${PROBE_KEY}` to `Authorization: Bearer ${PROBE_KEY}` in both worker and probe. |
| **S3** | S4/v1 — TXT record quote stripping | Tiny | Strip outer quotes from TXT record display in the SPA and/or data pipeline. |
| **S4** | S1/v1 — SPF recursive counting (or disclaimer) | Medium | Either implement recursive SPF `include:` chain walking, or add a visible disclaimer: "Count is non-recursive. Actual lookup count may be higher." Recursive fix is the real solution. |
| **S5** | S5/v1 — CAA policy analysis | Small | Add `checkCAA()` to security.ts: flag missing CAA, analyze `issue`/`issuewild`/`iodef`, check for overly permissive policies. |
| **S6** | H4 — Add European UDP resolver | Small | Find 1-2 European DNS resolvers that accept UDP from US IPs. Test from the probe, then add to the resolver list with correct coordinates. |
| **S7** | I3 — Rate-limiter unit tests | Small | Add vitest tests for token bucket logic, covering: fresh state, partial refill, full refill, boundary conditions. Validates S1 fix. |
| **S8** | G2 — Fix resolver coordinates | Tiny | Give all resolvers honest geographic coordinates. CleanBrowsing (or its replacement) should not be at Paris (48.86, 2.35) if that's not where it actually is. |
| **S9** | Duplicate loadSecurity cleanup | Tiny | Remove the duplicate `loadSecurity()` function in spa.ts. One-line delete. |

### 🟢 Could-Do (Post-Launch Backlog)

| # | Item | Effort |
|---|------|--------|
| C1 | G8 — Document probe cold-start in GOTCHAS | Tiny |
| C2 | G9 — Show `_source` indicator in SPA propagation panel | Small |
| C3 | Progress bar rendering verification/debug | Small |
| C4 | Probe test suite (UDP mocking) | Medium |
| C5 | Update STATE.md to match reality | Tiny |

### 🗑️ Eliminated (Don't Fix/Build)

| Item | Reason |
|------|--------|
| G1 Duplicate loadSecurity | Harmless shadowing (promoted to S9 as tiny cleanup) |
| G5 Misleading Europe comment | Comment only, no user impact |
| G6 STATE.md stale | Internal docs, not blocking |
| G7 `_source` field exposed | Useful debugging info |
| G11 Batch rate limit bypass | Acceptable at current scale |
| G12 `_cache_control` in output | Low priority internal detail |
| H5 Probe SPOF | By design per DECISIONS.md |
| I1 Split handler.ts | Works fine monolithic |
| I2 Split spa.ts | Inline SPA by design |
| S3/v1 `?format=json` | Accept header is sufficient |

---

## Final Convergence Status

| Panelist | Status |
|----------|--------|
| Dmitri | ✅ Converged |
| Priya | ✅ Converged |
| Marcus | ✅ Converged — wants progress bar rendering verified |
| Sophie | ✅ Converged — emphasizes G4 (probe auth) is easy and important |
| Janet | ✅ Converged — SPF counting is highest priority SHOULD |
| Carlos | ✅ Converged — European resolver gap matters for competitive positioning |
| Raj | ✅ Converged — rate-limiter tests should accompany the refill fix |
| Kurt | ✅ Converged — "Fix the 2 MUSTs, ship the announce, iterate on SHOULDs" |

**All 8 panelists converged in 2 rounds.**

---

## Implementation Notes

### M1: CleanBrowsing Replacement

Options:
1. **CleanBrowsing unfiltered**: Check if `doh.cleanbrowsing.org/doh/adult-filter/` or base URL works without filtering. (Unlikely — CleanBrowsing's entire proposition is filtering.)
2. **Replace with**: Surfnet/SIDN Labs (Netherlands, `https://dnsovertls.sinodun.com/dns-query`), or LibreDNS (Germany, `https://doh.libredns.gr/dns-query`), or simply use DNS.SB's DoH endpoint (already in list — could replace with something else).
3. **Best bet**: Check if `https://dns.switch.ch/dns-query` (Swiss NREN) works from CF Workers. Or use Restena (Luxembourg, `https://kaitain.restena.lu/dns-query`).

For the UDP probe (CleanBrowsing at 185.228.168.9): their DNS server may or may not filter at the UDP level. Test with a known-flagged domain.

### M2: IPv6 Reverse Fix

Replace the current expansion logic with:
```typescript
function ipToReverseDomain(ip: string): string {
  if (isIPv4(ip)) {
    return ip.split('.').reverse().join('.') + '.in-addr.arpa';
  }
  // Expand IPv6 to full 32-character hex string
  const halves = ip.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  const full = [
    ...left.map(g => g.padStart(4, '0')),
    ...Array(missing).fill('0000'),
    ...right.map(g => g.padStart(4, '0')),
  ];
  const hex = full.join('');
  return hex.split('').reverse().join('.') + '.ip6.arpa';
}
```

### S1: Rate Limiter Fix

Replace partial-refill with a simple fixed-window:
```typescript
const now = Math.floor(Date.now() / 1000);
const windowStart = Math.floor(now / REFILL_INTERVAL) * REFILL_INTERVAL;
if (rl.lastRefill < windowStart) {
  rl.tokens = MAX_TOKENS;
  rl.lastRefill = windowStart;
}
```

---

## Summary: Delta from v1 Review

The project has improved substantially since v1:
- All 3 v1 pre-launch blockers (M1-M3) are **done** ✅
- Significant new capabilities: reverse DNS, authority trace, batch, numeric QTYPE, ANY simulation, dig output, UDP probe, progress bar, type selector
- 128 tests added (from 0)
- `.ai/` documentation bootstrapped

Two new pre-announce blockers identified (CleanBrowsing filter, IPv6 expansion). Both are small fixes. The v1 SHOULDs (SPF counting, rate limiter, CAA, TXT quotes) carry forward and should be the first post-announce sprint.

**Bottom line: Fix M1 and M2 (< 1 hour combined), announce, then iterate on SHOULDs.**
