# ns.lol QA Test Plan

## Deployment Prerequisite
Need Cloudflare API token. Deploy command:
```bash
cd ~/workspace/ns-lol && bash deploy.sh
```

---

## 1. API Smoke Tests (curl)

### 1.1 Home page (JSON)
```bash
curl -s https://ns.lol/ | jq
```
**Expected:** Service info with endpoints list and `.lol` family links.

### 1.2 Health check
```bash
curl -s https://ns.lol/health | jq
```
**Expected:** `{"status": "ok", "service": "ns.lol"}`

### 1.3 Full report
```bash
curl -s https://ns.lol/google.com | jq
```
**Expected:** JSON with `domain`, `summary` (total_records, record_types, avg_query_time_ms, dnssec), `records` (A, AAAA, MX, NS, TXT at minimum), and `_meta` with links to propagation/health/email/security/certs.lol/yoke.lol.

### 1.4 Single record type
```bash
curl -s https://ns.lol/google.com/mx | jq
```
**Expected:** Just MX records with `ttl_human` fields.

### 1.5 Propagation check
```bash
curl -s https://ns.lol/google.com/propagation | jq
```
**Expected:** 20 resolver results with `anomaly` flag, `propagation` summary with percentage/status/distinct_answers, TTL info.

### 1.6 Propagation with expected value
```bash
curl -s "https://ns.lol/google.com/propagation?expected=142.250.9.139" | jq .expected_match
```
**Expected:** `expected_match` object with matches/mismatches/resolvers.

### 1.7 Health check
```bash
curl -s https://ns.lol/google.com/health | jq
```
**Expected:** Grade A-F, signals with categories (DNSSEC, Nameservers, SOA, etc.), `_meta` links.

### 1.8 Health with explain
```bash
curl -s "https://ns.lol/google.com/health?explain=true" | jq '.signals[0]'
```
**Expected:** Signals include `explain` field with human-readable descriptions.

### 1.9 Email audit
```bash
curl -s https://ns.lol/google.com/email | jq
```
**Expected:** Grade, signals for MX, SPF, DMARC, DKIM, MTA-STS, BIMI.

### 1.10 Security check
```bash
curl -s https://ns.lol/google.com/security | jq
```
**Expected:** Security summary with pass/warn/fail/info counts, signals for dangling CNAME, NS diversity, wildcard, CDN.

### 1.11 API docs
```bash
curl -s https://ns.lol/api/docs | jq
```
**Expected:** Endpoint list, parameters, examples.

### 1.12 Force bypass cache
```bash
curl -s "https://ns.lol/google.com?force=true" | jq .summary
```
**Expected:** Fresh results (no `_cached` flag).

---

## 2. Edge Cases

### 2.1 Invalid domain
```bash
curl -s https://ns.lol/notadomain | jq
```
**Expected:** Error "Please provide a fully qualified domain name"

### 2.2 NXDOMAIN
```bash
curl -s https://ns.lol/thisdoesnotexist12345.com | jq
```
**Expected:** Full report with empty records, summary showing 0.

### 2.3 URL pasted as input
```bash
curl -s https://ns.lol/https://google.com/search?q=test | jq
```
**Expected:** Strips protocol, treats as `google.com`.

### 2.4 Domain with trailing dot
```bash
curl -s https://ns.lol/google.com. | jq
```
**Expected:** Resolves as `google.com` (trailing dot stripped).

### 2.5 Underscore domain (DMARC lookup)
```bash
curl -s https://ns.lol/_dmarc.google.com/txt | jq
```
**Expected:** TXT record with DMARC policy.

### 2.6 IDN / Punycode domain
```bash
curl -s https://ns.lol/xn--n3h.com | jq
```
**Expected:** Valid response (even if no records).

### 2.7 Invalid record type
```bash
curl -s https://ns.lol/google.com/invalid | jq
```
**Expected:** Error "Unknown action: invalid. Use a record type..."

### 2.8 All record types
```bash
for t in a aaaa cname mx txt ns soa srv caa https ds; do
  echo "=== $t ==="
  curl -s "https://ns.lol/google.com/$t" | jq .records | head -5
done
```
**Expected:** Each type returns correctly.

---

## 3. Content Negotiation

### 3.1 Browser gets SPA
```bash
curl -s https://ns.lol/google.com -H "Accept: text/html" | head -5
```
**Expected:** HTML starting with `<!DOCTYPE html>`.

### 3.2 curl gets JSON (default)
```bash
curl -s https://ns.lol/google.com -H "User-Agent: curl/8.0" | head -3
```
**Expected:** JSON.

### 3.3 application/dns-json works
```bash
curl -s https://ns.lol/google.com -H "Accept: application/dns-json" | python3 -m json.tool | head -5
```
**Expected:** Valid JSON.

---

## 4. Rate Limiting

### 4.1 Rate limit headers present
```bash
curl -sI https://ns.lol/google.com -H "Accept: application/json" | grep -i x-ratelimit
```
**Expected:** X-RateLimit-Limit: 120, X-RateLimit-Remaining: <number>, X-RateLimit-Reset: <timestamp>.

### 4.2 Rate limit enforcement (stress test — be careful)
```bash
# Don't actually run all 120 at once during QA
for i in $(seq 1 5); do
  curl -s https://ns.lol/example.com -o /dev/null -w "%{http_code}\n"
done
```
**Expected:** All return 200 (well within limit).

---

## 5. SPA / Browser Tests

### 5.1 Landing page
Open `https://ns.lol` in browser.
- **Check:** Logo "ns.lol" with cyan accent
- **Check:** "fast, API-first DNS toolkit" tagline
- **Check:** Search box with placeholder "example.com"
- **Check:** Example domain links (cloudflare.com, google.com, github.com, example.com)
- **Check:** Curl hint hidden on landing page
- **Check:** Footer with yoke.lol, certs.lol, ns.lol links

### 5.2 Domain lookup
Type `cloudflare.com` in search box and press Enter.
- **Check:** URL changes to `ns.lol/cloudflare.com`
- **Check:** Summary bar appears (Records count, Types, Avg Query, DNSSEC status, CDN if detected)
- **Check:** Tabs appear: Records, Propagation, Health, Email, Security
- **Check:** Records tab active by default showing A, AAAA, NS, MX, TXT groups
- **Check:** Each record shows data, TTL with human-readable format
- **Check:** Curl hint shows at bottom

### 5.3 Tab switching
- Click Propagation tab
  - **Check:** Map renders with resolver dots
  - **Check:** Percentage display (likely 100% for established domains)
  - **Check:** Resolver grid with name, location, query time, value
  - **Check:** Auto-refresh checkbox (unchecked if 100%)
- Click Health tab
  - **Check:** Grade letter (A/B/C/D/F) with color
  - **Check:** Signals grouped by category (DNSSEC, Nameservers, SOA, etc.)
  - **Check:** Pass/warn/fail/info colored badges
  - **Check:** Fix suggestions on failing signals (teal 💡 text)
- Click Email tab
  - **Check:** Grade with color
  - **Check:** Signals for MX, SPF, DMARC, DKIM
  - **Check:** "Email DNS Audit" subtitle
- Click Security tab
  - **Check:** "Security Analysis" with pass/warn/fail/info summary
  - **Check:** Signals grouped by category
  - **Check:** Fix suggestions visible on warn/fail items

### 5.4 Cross-tool links
Below the tab panels:
- **Check:** "🔒 TLS Report" links to `certs.lol/cloudflare.com`
- **Check:** "📊 Full Analysis" links to `yoke.lol/cloudflare.com`

### 5.5 New search
Type a new domain and search.
- **Check:** All tab content resets (not stale from previous domain)
- **Check:** Lazy-loaded tabs reload fresh data

### 5.6 Direct URL
Navigate to `https://ns.lol/github.com` directly.
- **Check:** Domain pre-filled in search box
- **Check:** Results load immediately

### 5.7 Browser back/forward
Search for `google.com`, then `github.com`, then press back.
- **Check:** Returns to google.com results

### 5.8 Mobile responsive
Resize to 640px width (or use phone).
- **Check:** Logo scales down
- **Check:** Record rows stack vertically
- **Check:** Propagation grid goes to single column
- **Check:** Tabs scrollable horizontally if needed

### 5.9 Auto-refresh (propagation)
For a domain with recent DNS changes (hard to test), or verify the UI elements:
- **Check:** Auto-refresh checkbox is visible
- **Check:** Countdown timer shows "refreshing in Xs"
- **Check:** Unchecking stops the countdown
- **Check:** Timer actually refreshes the propagation data

---

## 6. Specific Domains to Test

| Domain | Why |
|--------|-----|
| `google.com` | Large, well-configured — lots of records, DNSSEC |
| `cloudflare.com` | CDN detection should fire, good email config |
| `github.com` | CDN (Fastly), good baseline |
| `example.com` | Minimal records — tests empty states |
| `ns.lol` | Our own domain — meta test |
| `certs.lol` | Our sibling — known config |
| `yoke.lol` | Our sibling — known config |
| `microsoft.com` | Complex setup with many TXT records |
| `nmu.edu` | Likely some issues to surface in health/email |
| `amazon.com` | CDN detection |

---

## 7. Caching

### 7.1 Cache works
```bash
# First request
time curl -s https://ns.lol/example.com -o /dev/null
# Second request (should be faster)  
time curl -s https://ns.lol/example.com -o /dev/null
```
**Expected:** Second request faster. Response includes `_cached: true`.

### 7.2 Propagation not cached
```bash
curl -s https://ns.lol/example.com/propagation | jq ._cached
```
**Expected:** null (propagation never cached).

### 7.3 Force bypasses cache
```bash
curl -s "https://ns.lol/example.com?force=true" | jq ._cached
```
**Expected:** null.

---

## 8. CORS

### 8.1 Preflight works
```bash
curl -s -X OPTIONS https://ns.lol/google.com -H "Origin: https://example.com" -H "Access-Control-Request-Method: GET" -I | grep -i access-control
```
**Expected:** CORS headers present.

### 8.2 Response has CORS
```bash
curl -sI https://ns.lol/google.com -H "Accept: application/json" | grep -i access-control
```
**Expected:** `Access-Control-Allow-Origin: *`

---

## Deploy Checklist
- [ ] Cloudflare API token obtained and set
- [ ] `bash deploy.sh` succeeds
- [ ] `/health` returns ok
- [ ] Full report for google.com returns records
- [ ] SPA loads in browser
- [ ] All 5 tabs render data
- [ ] Rate limit headers present
- [ ] CORS headers present
- [ ] Cross-tool links work (certs.lol, yoke.lol)
- [ ] Mobile view looks good
