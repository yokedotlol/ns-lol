# ns.lol — Audit & Panel Review

**Date:** 2026-06-15
**Version:** commit ffd0753 (post email/security.txt/MTA-STS deployment)
**Methodology:** Secrets audit + Panel review (divergent → convergence)

---

## Part 1: Secrets & Work Product Audit

### Secrets Scan: ✅ CLEAN

Scanned full git history (`25 commits, cfb62e2..ffd0753`) for:
- API keys, tokens, passwords, private keys, `.env` files
- Hardcoded credentials (Stripe, GitHub PAT, AWS, GCP patterns)
- Infisical, Cloudflare, Fly.io secrets

**Findings:**
- **No hardcoded secrets found.** All sensitive values use `${{ secrets.X }}` (GitHub Actions), `env.PROBE_KEY` (Worker bindings), or `process.env.AUTH_SECRET` (probe).
- Cloudflare account ID (`b5cdaad4db136b796354280697e0ceb9`), zone ID (`de03a3feedef8f14f0670d6ab5ff57da`), and KV namespace ID (`3c8fefc09b494e2ba1e5b3cc9d70a744`) are in `wrangler.toml` — these are **public infrastructure identifiers**, not secrets. Standard for CF repos.
- Probe auth moved from `?key=` query param to `Authorization: Bearer` header in commit `bfb2e0e` — good hygiene, no actual key values leaked in the diff.

### Work Product Files: ⚠️ ACTION NEEDED

The following **internal work product files** are tracked in git and will be visible in the public GitHub repo:

| File | Risk | Action |
|------|------|--------|
| `.ai/CONSTITUTION.md` | Low — project architecture docs, fine to publish | Optional: keep or remove |
| `.ai/DECISIONS.md` | Low — technical decision log | Optional: keep or remove |
| `.ai/GOTCHAS.md` | Low — engineering gotchas | Optional: keep or remove |
| `.ai/INVARIANTS.md` | Low — code invariants | Optional: keep or remove |
| `.ai/STATE.md` | **Medium** — snapshot of project state, could reveal build process | **SHOULD remove** |
| `PANEL-REVIEW.md` | **Medium** — internal review with scoring methodology | **SHOULD remove** |
| `PANEL-REVIEW-v2.md` | **Medium** — same | **SHOULD remove** |
| `QA-PLAN.md` | Low — QA plan, but reveals internal testing approach | Optional: remove |

The `.ai/` directory is a builder context framework — not harmful, but reveals the AI-assisted build process. The panel review files contain internal scoring methodology and UX critique that isn't intended for public consumption.

**Recommendation:** Add to `.gitignore` and remove from tracking:
```bash
echo -e '.ai/\nPANEL-REVIEW*.md\nQA-PLAN.md' >> .gitignore
git rm --cached -r .ai/ PANEL-REVIEW.md PANEL-REVIEW-v2.md QA-PLAN.md
git commit -m "chore: remove internal work product from tracking"
```

No `git-filter-repo` needed — these files contain no secrets, just internal process docs. Removing from HEAD is sufficient.

### Other Notes
- `wrangler.toml` is in `.gitignore` but **also tracked in git** (added before the gitignore rule). CI regenerates it from secrets, so the committed copy is stale. Run `git rm --cached wrangler.toml` to stop tracking it.
- No `.env` files ever committed.
- `deploy.sh` is safe — sources credentials from `~/.wrangler/.env` which is never committed.

---

## Part 2: Panel Review

### Panel Members

| # | Persona | Bias |
|---|---------|------|
| P1 | **Riku** — DNS sysadmin | Wants dig-compatible output, cares about accuracy and edge cases |
| P2 | **Priya** — Web developer | Quick lookups, API ergonomics, documentation quality |
| P3 | **Dmitri** — Security researcher | DNS misconfiguration detection, audit completeness |
| P4 | **Marcus** — DevOps engineer | CI/CD integration, batch operations, caching behavior |
| P5 | **Lena** — Product designer | Information hierarchy, mobile UX, visual clarity |
| P6 | **Aiko** — Accessibility specialist | Screen reader support, keyboard nav, contrast ratios |
| P7 | **Tomas** — Competitive analyst | Feature parity with MXToolbox, DNSChecker, DNSViz |
| P8 | **Nora** — .lol brand reviewer | Aesthetic consistency with certs.lol and yoke.lol |

---

### Round 1: Divergent Inventory + Initial Votes

#### Functionality

| # | Finding | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---------|----|----|----|----|----|----|----|----|
| F1 | Full DNS report works well — 11 record types, clean output | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| F2 | dig-style plain text output (`Accept: text/plain`) is excellent | M | S | S | M | - | - | M | - |
| F3 | Email audit is comprehensive (SPF, DKIM, DMARC, MTA-STS, BIMI, TLS-RPT, null MX) | S | S | M | S | - | - | M | - |
| F4 | Health grading covers DNSSEC, NS diversity, SOA timers, delegation | M | S | M | M | - | - | M | - |
| F5 | Security analysis (dangling CNAME/NS, chain depth, CDN detection, wildcard) | S | S | M | S | - | - | S | - |
| F6 | Propagation uses 17 resolvers across regions with world map | M | M | S | M | S | S | M | - |
| F7 | **llms.txt route is missing** — `/llms.txt` is parsed as a domain name lookup | S | M | - | S | - | - | M | S |
| F8 | Batch endpoint works but **max domains not documented** | - | S | - | M | - | - | S | - |
| F9 | Trace endpoint provides iterative resolution — nice differentiator | S | M | S | M | - | - | M | - |
| F10 | NXDOMAIN domains still return 200 with empty records (correct behavior) | M | S | - | S | - | - | - | - |
| F11 | `?explain=true` adds plain-English explanations — great for non-experts | - | M | - | S | S | M | M | - |
| F12 | `?force=true` bypasses cache — essential for debugging | S | M | S | M | - | - | M | - |

#### API Design

| # | Finding | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---------|----|----|----|----|----|----|----|----|
| A1 | Content negotiation (JSON/text/HTML) works perfectly | M | M | S | M | - | - | M | S |
| A2 | Rate limit headers (`X-RateLimit-*`) are present and correct | S | S | M | M | - | - | S | - |
| A3 | CORS headers allow cross-origin use | S | M | S | M | - | - | S | - |
| A4 | Error responses are clean JSON with helpful messages | S | M | S | S | - | - | S | - |
| A5 | Cross-links to certs.lol and yoke.lol in `_meta` section | - | S | - | S | - | - | M | M |
| A6 | **No API versioning** — could break consumers on changes | - | S | - | M | - | - | S | - |
| A7 | Cache-Control headers appropriate (60s for lookups, never for propagation) | S | S | - | M | - | - | S | - |

#### UX / Design

| # | Finding | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---------|----|----|----|----|----|----|----|----|
| D1 | Dark terminal aesthetic — `--bg:#0a0e17` vs certs.lol `--bg:#0a0a0f` (very close, good) | - | - | - | - | S | - | - | M |
| D2 | **No light/dark theme toggle** — certs.lol has one, ns.lol doesn't | - | - | - | - | M | M | - | M |
| D3 | Inter + JetBrains Mono typography matches family DNA | - | - | - | - | M | - | - | M |
| D4 | Tabbed interface (Records/Propagation/Health/Email/Security) is clear | - | S | - | - | M | S | S | - |
| D5 | World map for propagation is a nice touch — SVG, Natural Earth outlines | - | S | - | - | M | - | M | - |
| D6 | **Cyan accent** (`#22d3ee`) vs certs.lol **purple accent** (`#9b8afb`) — different per-tool | - | - | - | - | S | - | - | S |
| D7 | Footer structure: docs, github, privacy, terms, yoke badge, family links — complete | - | - | - | - | S | - | - | M |
| D8 | curl hint shown below search input — good onboarding | - | M | - | M | M | - | S | - |
| D9 | SPA is 56KB inline — single request, no external JS deps, fast | - | S | - | M | S | - | S | S |

#### Security

| # | Finding | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---------|----|----|----|----|----|----|----|----|
| S1 | All 8 security headers present (HSTS, CSP, XFO, XCTO, Referrer, Permissions, COOP, COEP) | - | - | M | S | - | - | S | S |
| S2 | **CSP has `unsafe-inline` for scripts** — Yoke deducts 4.7pts. Needed for inline SPA JS | - | - | M | S | - | - | S | - |
| S3 | Rate limiting: 120 req/hr per IP via Durable Objects | - | - | S | M | - | - | S | - |
| S4 | Input validation: rejects path traversal, empty domains, non-FQDN input | - | - | M | S | - | - | S | - |
| S5 | security.txt with GitHub Issues contact and proper Expires/Canonical | - | - | M | S | - | - | S | M |
| S6 | Domain input is HTML-escaped in SPA (`escapeHtml()`) | - | - | M | S | - | - | - | - |

#### SEO / Discoverability

| # | Finding | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---------|----|----|----|----|----|----|----|----|
| E1 | OG title + description tags present | - | - | - | - | - | - | S | M |
| E2 | **No OG image** — certs.lol has `/og.png`, yoke.lol has `/og-banner.png` | - | - | - | - | S | - | M | M |
| E3 | **No JSON-LD structured data** — certs.lol has `WebApplication` schema | - | - | - | - | - | - | M | M |
| E4 | **No llms.txt** — yoke.lol and certs.lol both have it | - | S | - | - | - | - | M | M |
| E5 | Canonical URLs correct, per-domain OG tags on report pages | - | - | - | - | - | - | S | S |
| E6 | Sitemap has 5 pages, robots.txt allows all with sitemap ref | - | - | - | - | - | - | M | S |
| E7 | **Accessibility score 59/100** on Yoke (deduction: -2.4) | - | - | - | - | - | M | S | - |

#### Email / DNS (just deployed)

| # | Finding | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---------|----|----|----|----|----|----|----|----|
| M1 | SPF, DMARC (reject), MTA-STS (enforce), TLSRPT all configured | M | - | M | S | - | - | M | S |
| M2 | **No DKIM record published** — CF Email Routing signs automatically but a published key helps verification tools | S | - | M | S | - | - | M | - |
| M3 | CAA records for letsencrypt, digicert, pki.goog + iodef | - | - | M | S | - | - | S | S |
| M4 | MTA-STS policy served correctly at mta-sts.ns.lol | S | - | M | S | - | - | S | S |
| M5 | **Yoke email scan shows "not measured"** — DNS propagation lag, will resolve | - | - | - | S | - | - | S | - |

#### Brand Cohesion

| # | Finding | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 |
|---|---------|----|----|----|----|----|----|----|----|
| B1 | Same font stack (Inter + JetBrains Mono) across family ✓ | - | - | - | - | M | - | - | M |
| B2 | Same dark background range (#0a0e17 vs #0a0a0f) ✓ | - | - | - | - | S | - | - | M |
| B3 | Different accent colors per tool (cyan vs purple) — intentional differentiation | - | - | - | - | S | - | - | S |
| B4 | Footer has family links + yoke badge ✓ | - | - | - | - | S | - | - | M |
| B5 | Cross-links in API responses + SPA ✓ | - | - | - | - | S | - | S | M |
| B6 | **certs.lol has light/dark toggle, ns.lol doesn't** — inconsistent | - | - | - | - | S | S | - | M |
| B7 | API root returns family links ✓ | - | S | - | S | - | - | S | M |
| B8 | **No `?pretty` parameter** — yoke.lol has it for browser-friendly JSON | - | S | - | S | - | - | S | - |

---

### Round 2: Convergence

**Scoring:** 4+ MUST = locked. 4+ CUT = eliminated. Middle debated.

#### MUST (fix before calling ns.lol "done")

| # | Issue | Votes | Effort |
|---|-------|-------|--------|
| E2 | **Add OG image** (`/og.png` or SVG-generated) — social sharing looks broken without it | 5 MUST | Small |
| E3 | **Add JSON-LD structured data** — `WebApplication` schema matching certs.lol | 5 MUST | Small |
| E4 | **Add llms.txt route** — both siblings have it, ns.lol treats it as a domain lookup | 6 MUST | Small |
| F7 | Same as E4 — llms.txt endpoint | (merged with E4) | |
| M2 | **Publish DKIM key** — get CF Email Routing DKIM record and add to DNS | 4 MUST | Small |

#### SHOULD (high value, do soon)

| # | Issue | Votes | Effort |
|---|-------|-------|--------|
| D2/B6 | **Add light/dark theme toggle** — certs.lol has it, brand consistency | 5 SHOULD | Medium |
| S2 | **CSP `unsafe-inline` removal** — move SPA JS to hash-based or nonce-based CSP | 4 SHOULD | Medium |
| E7 | **Improve accessibility** (score 59/100) — likely missing ARIA labels, focus management | 4 SHOULD | Medium |
| WP1 | **Remove work product files** from git (`.ai/`, `PANEL-REVIEW*.md`, `QA-PLAN.md`) | 5 SHOULD | Tiny |
| WP2 | **Fix wrangler.toml tracking** — `git rm --cached wrangler.toml` | 4 SHOULD | Tiny |
| B8 | **Add `?pretty` parameter** for indented JSON output | 3 SHOULD | Small |

#### COULD (nice to have)

| # | Issue | Votes | Effort |
|---|-------|-------|--------|
| A6 | API versioning (header or path) | 3 COULD | Medium |
| D6 | Consider whether accent colors should unify across family | 2 COULD | Design decision |
| F8 | Document batch endpoint max domains | 3 COULD | Tiny |
| Speed | LCP 2.9s — could preload fonts or inline critical subset | 2 COULD | Medium |
| Speed | No compression detected — enable gzip/brotli for API responses | 3 COULD | Small |

#### CUT (not worth doing)

| # | Issue | Reason |
|---|-------|--------|
| Reputation: NRD | Domain age (1 day) — can't fix, resolves with time | Time-dependent |
| Reputation: Tranco | Not ranked in top 1M — can't fix, need traffic | Time-dependent |
| CAA not detected | CAA records just added, will show on next Yoke scan | Propagation lag |

---

### Round 3: Final Prioritized Action List

**Priority 1 — Quick wins (all small, do in one commit):**
1. Add `llms.txt` route to worker.ts
2. Add JSON-LD `WebApplication` schema to SPA `<head>`
3. Add OG image meta tags (generate or serve an `/og.png`)
4. Remove work product files from git tracking + update `.gitignore`
5. Fix `wrangler.toml` tracking (`git rm --cached`)

**Priority 2 — Medium effort improvements:**
6. Publish CF Email Routing DKIM key in DNS
7. Add light/dark theme toggle (match certs.lol pattern)
8. Improve accessibility (ARIA labels, focus management, contrast)
9. CSP hardening — remove `unsafe-inline` (requires SPA JS refactor or hash-based approach)
10. Enable compression for API responses

**Priority 3 — Can wait:**
11. Add `?pretty` parameter for indented JSON
12. Document batch endpoint limits
13. Consider API versioning strategy

---

### Yoke Score Summary (current)

| Axis | Score | Deductions |
|------|-------|------------|
| Security | 95 | CSP `unsafe-inline` (-4.7), CAA not detected yet (-0.7) |
| Speed | 88 | LCP 2.9s (-7.1), FCP 2.9s (-3.6), no compression (-1.8) |
| Foundations | 100 | Perfect |
| Reputation | 67 | NRD 1-day age (-25), Tranco not ranked (-8.4) |
| Discoverability | 94 | Accessibility 59/100 (-2.4), no structured data (-4.1) |
| Email | not measured | DNS just deployed, will resolve on next fresh scan |
| **Composite** | **74** | **Moderate** (dragged down by reputation time-dependents) |

**Achievable score after Priority 1+2 fixes:** ~82-85 (structured data, compression, accessibility improvements). Reputation axis will self-heal to ~92 as domain ages past 90 days.

---

*Generated by panel review methodology per AGENTS.md conventions.*
