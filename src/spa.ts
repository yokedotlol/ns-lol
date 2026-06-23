// SPA renderer — full terminal-aesthetic UI for browser clients
// Blue/cyan palette, dark-mode-first, Inter + JetBrains Mono

export function renderSPA(data: any, path: string, domain?: string, nonce?: string, rl?: { remaining: number; limit: number }): string {
  const jsonData = JSON.stringify(data || {}).replace(/<\//g, '<\\/');
  const currentDomain = domain || '';
  const nonceAttr = nonce ? ` nonce="${nonce}"` : '';

  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${currentDomain ? `DNS Report for ${escapeHtml(currentDomain)} — ns.lol` : 'ns.lol — Fast, API-first DNS Toolkit'}</title>
<meta name="description" content="${currentDomain ? `Complete DNS report for ${escapeHtml(currentDomain)}: records, propagation, zone health, email, security.` : 'Instant DNS lookups, propagation, zone health, email audit, security analysis. No accounts, no tracking.'}">
<meta property="og:title" content="${currentDomain ? `DNS Report for ${escapeHtml(currentDomain)} — ns.lol` : 'ns.lol — Fast, API-first DNS Toolkit'}">
<meta property="og:description" content="${currentDomain ? `Complete DNS report for ${escapeHtml(currentDomain)}: records, propagation, zone health, email, security.` : 'Instant DNS lookups, propagation, zone health, email audit, security analysis. No accounts, no tracking.'}">
<meta property="og:type" content="website">
<meta property="og:url" content="${currentDomain ? `https://ns.lol/${escapeHtml(currentDomain)}` : 'https://ns.lol/'}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${currentDomain ? `DNS Report for ${escapeHtml(currentDomain)} — ns.lol` : 'ns.lol — Fast, API-first DNS Toolkit'}">
<meta name="twitter:description" content="${currentDomain ? `Complete DNS report for ${escapeHtml(currentDomain)}: records, propagation, zone health, email, security.` : 'Instant DNS lookups, propagation, zone health, email audit, security analysis. No accounts, no tracking.'}">
<meta property="og:image" content="https://ns.lol/og.png">
<meta name="twitter:image" content="https://ns.lol/og.png">
<link rel="canonical" href="${currentDomain ? `https://ns.lol/${escapeHtml(currentDomain)}` : 'https://ns.lol/'}">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "WebApplication",
  "name": "ns.lol",
  "url": "https://ns.lol",
  "description": "Fast, API-first DNS toolkit. Instant lookups, propagation monitoring, zone health, email DNS auditing, and security analysis.",
  "applicationCategory": "DeveloperApplication",
  "operatingSystem": "Any",
  "offers": { "@type": "Offer", "price": "0" },
  "author": { "@type": "Organization", "name": "Yoke", "url": "https://yoke.lol" }
}
</script>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
:root{
  --font-mono:'JetBrains Mono',ui-monospace,'Cascadia Code','Source Code Pro',Menlo,Consolas,monospace;
  --font-sans:'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  --radius:8px;--radius-sm:6px;
}
:root,[data-theme="dark"]{
  color-scheme:dark;
  --bg:#0a0a12;--surface:#15151f;--surface-raised:#1e1e2a;--surface-hover:#26263a;--border:#2a2a3a;--border-muted:#1e1e2a;
  --text:#e0e0ea;--text-secondary:#a8a8b8;--muted:#7a7a8e;--dim:#55556a;--faint:#3a3a4a;
  --accent:#22d3ee;--accent-fg:#0a0a12;--accent-dim:rgba(34,211,238,0.08);--accent-subtle:rgba(34,211,238,0.08);
  --ok:#3fb950;--ok-subtle:rgba(63,185,80,0.08);--warn:#e5a820;--warn-subtle:rgba(229,168,32,0.08);--err:#f85149;--err-subtle:rgba(248,81,73,0.08);
  --info:#6ea8fe;--purple:#bc8cff;
  --teal:#14b8a6;--blue:#3b82f6;--orange:#f97316;
}
[data-theme="light"]{
  color-scheme:light;
  --bg:#fafafe;--surface:#f0f0f5;--surface-raised:#e8e8ef;--surface-hover:#dddde6;--border:#d0d0dc;--border-muted:#e0e0ea;
  --text:#1a1a2e;--text-secondary:#4a4a60;--muted:#6a6a80;--dim:#9090a4;--faint:#b8b8c8;
  --accent:#0891b2;--accent-fg:#ffffff;--accent-dim:rgba(8,145,178,0.06);--accent-subtle:rgba(8,145,178,0.06);
  --ok:#16a34a;--ok-subtle:rgba(22,163,74,0.06);--warn:#b58900;--warn-subtle:rgba(181,137,0,0.06);--err:#dc2626;--err-subtle:rgba(220,38,38,0.06);
  --info:#2563eb;--purple:#8250df;
  --teal:#0d9488;--blue:#2563eb;--orange:#ea580c;
}
html{background:var(--bg)}
body{background:var(--bg);color:var(--text);font-family:var(--font-sans);-webkit-font-smoothing:antialiased;line-height:1.6;transition:background .25s,color .25s}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.page{max-width:960px;margin:0 auto;padding:24px 16px}
/* Header */
.hdr{padding:2rem 0 0;display:flex;align-items:baseline;gap:16px}
.logo{font-size:1.5rem;font-weight:800;letter-spacing:-0.04em;text-decoration:none;color:var(--text)}
.logo span{color:var(--accent)}
.tag{font-size:11px;color:var(--dim);font-family:var(--font-mono)}
/* Terminal input */
.input-wrap{margin-top:2rem;border-bottom:2px solid var(--accent);padding-bottom:10px;font-family:var(--font-mono);font-size:14px;display:flex;align-items:center;transition:border-color .25s;outline:none}
.input-wrap form{display:contents}
.prompt-dollar{color:var(--accent);font-weight:600;margin-right:4px}
.prompt-cmd{color:var(--text);margin-right:2px}
.prompt-dim{color:var(--dim)}
.di{background:none;border:none;color:var(--text);font-family:var(--font-mono);font-size:14px;outline:none;flex:1;min-width:80px;caret-color:var(--accent)}
.di::placeholder{color:var(--faint)}
.cur{display:inline-block;width:7px;height:14px;background:var(--accent);animation:b 1.1s step-end infinite;vertical-align:text-bottom;margin-left:1px}
@keyframes b{0%,100%{opacity:.7}50%{opacity:0}}
.type-select{background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:2px 6px;font-family:var(--font-mono);font-size:12px;margin-left:8px;cursor:pointer;outline:none}
.type-select:focus{border-color:var(--accent)}
/* Tabs */
.tabs{display:flex;gap:2px;margin:32px 0 16px;border-bottom:1px solid var(--border);overflow-x:auto;-webkit-overflow-scrolling:touch}
.tab{padding:10px 16px;color:var(--muted);font-size:0.85rem;font-weight:500;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;transition:color .2s,border-color .2s}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
/* Panels */
.panel{display:none}.panel.active{display:block}
/* Records table */
.record-group{margin-bottom:20px}
.record-type{font-family:var(--font-mono);font-weight:600;font-size:0.95rem;color:var(--accent);margin-bottom:8px;display:flex;align-items:center;gap:8px}
.record-type .count{font-size:0.75rem;background:var(--surface-raised);color:var(--muted);padding:1px 8px;border-radius:10px}
.record-row{display:grid;grid-template-columns:1fr auto auto;gap:12px;padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:6px;margin-bottom:4px;font-family:var(--font-mono);font-size:0.82rem;align-items:center;word-break:break-all}
.record-row .data{color:var(--text)}
.record-row .ttl{color:var(--dim);font-size:0.75rem;white-space:nowrap}
.record-row .name{color:var(--muted);font-size:0.75rem}
/* Propagation */
.prop-summary{display:flex;gap:16px;align-items:center;margin-bottom:20px;flex-wrap:wrap}
.prop-pct{font-family:var(--font-mono);font-size:2.2rem;font-weight:700}
.prop-pct.full{color:var(--ok)}.prop-pct.partial{color:var(--warn)}.prop-pct.low{color:var(--err)}
.prop-bar-wrap{width:100%;max-width:320px;height:10px;background:var(--surface-raised);border-radius:5px;overflow:hidden;margin-top:6px}
.prop-bar{height:100%;border-radius:5px;transition:width 0.6s ease}
.prop-bar.full{background:var(--ok)}.prop-bar.partial{background:var(--warn)}.prop-bar.low{background:var(--err)}
.prop-status{font-size:0.85rem;color:var(--muted)}
.prop-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:8px}
.resolver-card{padding:10px 14px;background:var(--surface);border:1px solid var(--border);border-radius:6px;display:flex;justify-content:space-between;align-items:center;gap:8px}
.resolver-name{font-weight:500;font-size:0.85rem}
.resolver-loc{color:var(--muted);font-size:0.75rem}
.resolver-val{font-family:var(--font-mono);font-size:0.78rem;color:var(--accent);text-align:right;word-break:break-all;max-width:55%}
.resolver-err{color:var(--err)}
.resolver-time{font-size:0.7rem;color:var(--dim);margin-top:2px}
.ttl-countdown{color:var(--warn);font-family:var(--font-mono);font-size:0.7rem}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.dot-pass{background:var(--ok)}.dot-warn{background:var(--warn)}.dot-fail{background:var(--err)}.dot-info{background:var(--blue)}
/* Map */
.map-wrap{position:relative;width:100%;max-width:800px;margin:20px auto;aspect-ratio:2/1;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
.map-svg{width:100%;height:100%}
.map-dot{cursor:pointer;transition:r .15s}
.map-dot:hover{r:6}
.map-tooltip{position:absolute;background:var(--surface-raised);border:1px solid var(--border);border-radius:6px;padding:8px 12px;font-size:0.78rem;pointer-events:none;opacity:0;transition:opacity .15s;z-index:10;white-space:nowrap}
/* Health signals */
.signal-row{display:flex;gap:12px;padding:10px 14px;background:var(--surface);border:1px solid var(--border);border-radius:6px;margin-bottom:6px;align-items:flex-start}
.signal-status{font-size:0.8rem;font-weight:600;white-space:nowrap;min-width:48px;text-align:center;padding:2px 0;border-radius:4px}
.signal-status.pass{color:var(--ok)}.signal-status.warn{color:var(--warn)}.signal-status.fail{color:var(--err)}.signal-status.info{color:var(--blue)}
.signal-body{flex:1;min-width:0}
.signal-label{font-weight:500;font-size:0.85rem}
.signal-detail{color:var(--muted);font-size:0.8rem;margin-top:2px;word-break:break-word}
.signal-explain{color:var(--dim);font-size:0.75rem;margin-top:4px;font-style:italic}
.signal-fix{color:var(--teal);font-size:0.78rem;margin-top:4px}

.prop-controls{margin-bottom:16px;display:flex;align-items:center;gap:12px}
.prop-type-label{font-size:0.82rem;color:var(--muted);display:flex;align-items:center;gap:6px}
.prop-type-select{background:var(--surface);color:var(--fg);border:1px solid var(--border);border-radius:4px;padding:4px 8px;font-size:0.82rem;font-family:var(--font-mono)}
.anomaly{border-color:var(--warn) !important;background:rgba(234,179,8,0.05) !important}
.summary-bar{display:flex;gap:16px;margin-bottom:16px;flex-wrap:wrap;padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);font-size:0.82rem}
.summary-item{display:flex;flex-direction:column;gap:2px}
.summary-label{color:var(--muted);font-size:0.72rem;text-transform:uppercase;letter-spacing:0.5px}
.summary-value{font-family:var(--font-mono);font-weight:600;color:var(--accent)}
.cross-links{display:flex;gap:8px;margin-top:16px;flex-wrap:wrap}
.cross-link{padding:6px 14px;background:var(--surface);border:1px solid var(--border);border-radius:6px;font-family:var(--font-mono);font-size:0.78rem;color:var(--muted);transition:all .2s}
.cross-link:hover{color:var(--accent);border-color:var(--accent);text-decoration:none}
.hook{margin-top:2.25rem;padding:14px 0;border-top:1px solid var(--border);border-bottom:1px solid var(--border);display:flex;align-items:baseline;gap:10px;font-family:var(--font-mono);font-size:12px}
.hook .ar{color:var(--accent);font-size:14px}
.hook .q{color:var(--muted)}
.hook a{color:var(--accent);text-decoration:none;font-weight:500}
.hook a:hover{text-decoration:underline}
.grade{font-family:var(--font-mono);font-size:3rem;font-weight:700;margin-right:12px}
.grade-a{color:var(--ok)}.grade-b{color:var(--teal)}.grade-c{color:var(--warn)}.grade-d{color:var(--orange)}.grade-f{color:var(--err)}
/* Curl hint */
.curl-hint{margin-top:24px;padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);font-family:var(--font-mono);font-size:0.8rem;color:var(--muted);overflow-x:auto}
.curl-hint code{color:var(--accent)}
.copy-btn{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:6px 12px;color:var(--muted);font-family:var(--font-mono);font-size:0.78rem;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:4px}
.copy-btn:hover{color:var(--accent);border-color:var(--accent)}
.copy-btn.copied{color:var(--ok);border-color:var(--ok)}
.family-header{display:flex;gap:12px;justify-content:center;margin-top:8px}
.family-header a{font-family:var(--font-mono);font-size:0.75rem;color:var(--dim);transition:color .2s}
.family-header a:hover{color:var(--accent);text-decoration:none}
.family-header a.current{color:var(--accent)}
/* Footer */
.footer{text-align:center;padding:2rem 0 3rem;margin-top:2rem;font-size:10px;color:var(--faint);font-family:var(--font-mono);display:flex;flex-direction:column;align-items:center;gap:10px}
.footer a{color:var(--dim);text-decoration:none;transition:color .2s}
.footer a:hover{color:var(--muted);text-decoration:none}
.footer-links{display:flex;justify-content:center;gap:16px;flex-wrap:wrap}
.footer-links a{color:var(--dim);text-decoration:none}
.footer-links a:hover{color:var(--muted)}
.footer-family{display:flex;justify-content:center;gap:16px}
.footer-family a{color:var(--faint);text-decoration:none;transition:color .2s}
.footer-family a:hover{color:var(--accent)}
.yoke-badge{display:inline-block}
.yoke-badge img{vertical-align:middle;opacity:0.6;transition:opacity .2s}
.yoke-badge:hover img{opacity:1}
.footer-tagline{font-size:10px;color:var(--faint);margin-bottom:2px}
.footer-tagline a{color:var(--dim);text-decoration:none;transition:color .2s}
.footer-tagline a:hover{color:var(--accent)}
/* Loading */
.loading{text-align:center;padding:40px;color:var(--muted)}
.spinner{display:inline-block;width:20px;height:20px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite;margin-right:8px;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
/* Loading progress bar */
.load-progress{margin:16px auto 0;max-width:320px}
.load-progress-label{font-size:0.8rem;color:var(--muted);margin-bottom:6px;text-align:center}
.load-progress-bar{width:100%;height:6px;background:var(--surface-raised);border-radius:3px;overflow:hidden}
.load-progress-fill{height:100%;width:0%;background:var(--accent);border-radius:3px;transition:width 0.3s linear}
/* Rate limit pill */
.rl-pill{position:fixed;bottom:16px;right:16px;background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:6px 14px;font-family:var(--font-mono);font-size:11px;color:var(--dim);z-index:100;display:none;cursor:pointer;opacity:0.7;transition:opacity 0.3s,color 0.3s,border-color 0.3s}
.rl-pill.visible{display:block}
.rl-pill.warn{color:var(--warn);border-color:var(--warn);opacity:1}
.rl-pill.danger{color:var(--err);border-color:var(--err);opacity:1}
.rl-detail{display:none;position:fixed;bottom:48px;right:16px;background:var(--surface-raised);border:1px solid var(--border);border-radius:var(--radius);padding:10px 14px;min-width:220px;font-family:var(--font-mono);font-size:12px;color:var(--text);z-index:101;box-shadow:0 8px 24px rgba(0,0,0,0.6)}
.rl-detail.visible{display:block}
.rl-detail .rl-title{font-weight:600;margin-bottom:4px}
.rl-bar{height:4px;border-radius:2px;background:var(--border);margin-bottom:8px;overflow:hidden}
.rl-bar-fill{height:100%;border-radius:2px;transition:width 0.3s}
.rl-detail .rl-info{color:var(--dim);font-size:11px}
/* Empty state */
.empty{text-align:center;padding:60px 20px;color:var(--muted)}
.empty h2{color:var(--text);font-size:1.2rem;margin-bottom:8px}
.empty p{max-width:480px;margin:0 auto;line-height:1.8}
.empty code{color:var(--accent);background:var(--surface);padding:2px 6px;border-radius:4px;font-family:var(--font-mono);font-size:0.85rem}
.examples{display:flex;gap:8px;justify-content:center;margin-top:20px;flex-wrap:wrap}
.examples a{padding:6px 14px;background:var(--surface);border:1px solid var(--border);border-radius:6px;font-family:var(--font-mono);font-size:0.82rem;color:var(--accent);transition:background .2s}
.examples a:hover{background:var(--surface-raised);text-decoration:none}
/* Responsive */
@media(max-width:640px){
  .hdr{flex-direction:column;gap:4px;padding-top:2rem}
  .input-wrap{font-size:13px;margin-top:1.5rem}.di{font-size:13px}
  .record-row{grid-template-columns:1fr;gap:4px}
  .prop-grid{grid-template-columns:1fr}
  .hook{font-size:11px;flex-wrap:wrap}
  .footer-links,.footer-family{flex-direction:row;gap:16px}
}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);border:0}
.skip-nav{position:absolute;left:-9999px;top:0;z-index:200;padding:8px 16px;background:var(--accent);color:var(--accent-fg,#fff);font-family:var(--font-mono);font-size:12px;text-decoration:none;border-radius:0 0 6px 0}
.skip-nav:focus{left:0}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.input-wrap :focus-visible,.input-wrap:focus-visible{outline:none}
.theme-toggle{position:fixed;top:16px;right:16px;z-index:100;display:flex;border-radius:var(--radius-sm);overflow:hidden;border:1px solid var(--border);background:var(--surface);font-family:var(--font-mono);font-size:11px}
.theme-opt{padding:5px 10px;cursor:pointer;border:none;background:none;color:var(--dim);transition:all .15s;white-space:nowrap}
.theme-opt.active{background:var(--accent);color:var(--accent-fg);font-weight:600}
.theme-opt:not(.active):hover{color:var(--text)}
</style>
</head>
<body>
<a href="#main" class="skip-nav">Skip to content</a>
<div class="theme-toggle" role="radiogroup" aria-label="Theme">
  <button class="theme-opt active" role="radio" aria-checked="true" data-theme="dark">Dark</button>
  <button class="theme-opt" role="radio" aria-checked="false" data-theme="light">Light</button>
</div>
<div class="page">
  <header class="hdr">
    <a class="logo" href="/" aria-label="ns.lol home">ns<span>.lol</span></a>
    <div class="tag">fast, API-first DNS toolkit</div>
  </header>

  <nav class="input-wrap" aria-label="DNS lookup">
    <form id="searchForm" role="search" style="display:contents">
    <span class="prompt-dollar" aria-hidden="true">$</span>
    <span class="prompt-cmd" aria-hidden="true">ns</span>
    <span class="prompt-dim" aria-hidden="true">&nbsp;▸&nbsp;</span>
    <label for="domainInput" class="sr-only">Domain or IP address</label>
    <input class="di" id="domainInput" type="text" value="${escapeHtml(currentDomain)}" placeholder="example.com" spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off" inputmode="url" autofocus>

    <select class="type-select" id="typeSelect" aria-label="Record type">
      <option value="">all</option>
      <optgroup label="Common">
      <option value="A">A</option>
      <option value="AAAA">AAAA</option>
      <option value="CNAME">CNAME</option>
      <option value="MX">MX</option>
      <option value="TXT">TXT</option>
      <option value="NS">NS</option>
      <option value="SOA">SOA</option>
      <option value="SRV">SRV</option>
      <option value="CAA">CAA</option>
      <option value="PTR">PTR</option>
      </optgroup>
      <optgroup label="Modern">
      <option value="HTTPS">HTTPS</option>
      <option value="SVCB">SVCB</option>
      <option value="DNAME">DNAME</option>
      <option value="URI">URI</option>
      <option value="NAPTR">NAPTR</option>
      </optgroup>
      <optgroup label="Security">
      <option value="TLSA">TLSA</option>
      <option value="SSHFP">SSHFP</option>
      <option value="CERT">CERT</option>
      <option value="OPENPGPKEY">OPENPGPKEY</option>
      <option value="SMIMEA">SMIMEA</option>
      <option value="IPSECKEY">IPSECKEY</option>
      </optgroup>
      <optgroup label="DNSSEC">
      <option value="DS">DS</option>
      <option value="DNSKEY">DNSKEY</option>
      <option value="RRSIG">RRSIG</option>
      <option value="NSEC">NSEC</option>
      <option value="NSEC3">NSEC3</option>
      <option value="NSEC3PARAM">NSEC3PARAM</option>
      <option value="CDNSKEY">CDNSKEY</option>
      <option value="CDS">CDS</option>
      </optgroup>
      <optgroup label="Other">
      <option value="LOC">LOC</option>
      <option value="HINFO">HINFO</option>
      <option value="RP">RP</option>
      <option value="AFSDB">AFSDB</option>
      <option value="KX">KX</option>
      <option value="SPF">SPF</option>
      <option value="HIP">HIP</option>
      <option value="CSYNC">CSYNC</option>
      <option value="ZONEMD">ZONEMD</option>
      </optgroup>
    </select>
    <span class="cur" aria-hidden="true"></span>
    </form>
  </nav>

  <main id="main" role="main">
  <div id="content">
    ${currentDomain ? '<div class="loading"><span class="spinner"></span> Querying resolvers...</div>' : renderEmpty()}
  </div>

  <div id="curlHint" class="curl-hint" style="display:${currentDomain ? 'block' : 'none'}">
    <code>curl -s https://ns.lol/${escapeHtml(currentDomain)}</code>
    <button class="copy-btn" id="copyBtn" style="margin-left:12px" title="Copy shareable link">📋 Copy Link</button>
  </div>
  </main>

  <footer class="footer">
    <div class="footer-links"><a href="/cli">cli</a><a href="/docs">docs</a><a href="https://github.com/yokedotlol/ns-lol">github</a><a href="/about">about</a><a href="/privacy">privacy</a><a href="/terms">terms</a></div>
    <div class="footer-tagline">Part of the <a href="https://yoke.lol/tools">.lol tools</a></div>
    <div class="footer-family"><a href="https://yoke.lol">yoke</a><a href="https://certs.lol">certs</a><a href="https://xhttp.lol">xhttp</a><a href="https://vrfy.lol">vrfy</a></div>
    <a href="https://yoke.lol/ns.lol" class="yoke-badge"><img src="https://yoke.lol/badge/ns.lol.svg" alt="Yoke score for ns.lol" height="20"></a>
  </footer>
</div>

<div class="rl-pill" id="rlPill"${rl ? ` data-remaining="${rl.remaining}" data-limit="${rl.limit}"` : ''}></div>
<div class="rl-detail" id="rlDetail">
  <div class="rl-title" id="rlTitle">API usage</div>
  <div class="rl-bar"><div class="rl-bar-fill" id="rlBarFill"></div></div>
  <div class="rl-info" id="rlInfo"></div>
</div>

<div class="map-tooltip" id="mapTooltip"></div>

<script${nonceAttr}>
const INITIAL_DATA = ${jsonData};
const INITIAL_PATH = ${JSON.stringify(path)};
const INITIAL_DOMAIN = ${JSON.stringify(currentDomain)};

// Yoke CTA hooks — random question linking to sibling tools
const YOKE_HOOKS = [
  ["what's {d}'s TLS grade?", "check on certs.lol \\u2192", "https://certs.lol/{d}"],
  ["what's {d}'s overall score?", "see on yoke.lol \\u2192", "https://yoke.lol/{d}"],
  ["has {d} been breached?", "check on yoke.lol \\u2192", "https://yoke.lol/{d}"],
  ["how fast is {d}?", "see on yoke.lol \\u2192", "https://yoke.lol/{d}"],
  ["is {d}'s email spoofable?", "check on yoke.lol \\u2192", "https://yoke.lol/{d}"],
  ["what tech stack does {d} run?", "see on yoke.lol \\u2192", "https://yoke.lol/{d}"],
];

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

// State
let currentData = INITIAL_DATA;
let activeTab = 'records';

// Theme toggle
const toggleBtns = $$('.theme-opt');
function setTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  toggleBtns.forEach(b => {
    const isActive = b.dataset.theme === t;
    b.classList.toggle('active', isActive);
    b.setAttribute('aria-checked', isActive ? 'true' : 'false');
  });
  localStorage.setItem('ns-theme', t);
}
const savedTheme = localStorage.getItem('ns-theme');
if (savedTheme) { setTheme(savedTheme); }
toggleBtns.forEach(b => b.addEventListener('click', () => setTheme(b.dataset.theme)));

// Rate limit pill
let rlExpanded = false;
function updateRateLimit(resp) {
  const pill = $('#rlPill');
  const detail = $('#rlDetail');
  if (!pill || !detail) return;
  const remaining = resp.headers.get('X-RateLimit-Remaining');
  const limit = resp.headers.get('X-RateLimit-Limit');
  const reset = resp.headers.get('X-RateLimit-Reset');
  if (remaining === null || limit === null) return;
  const r = parseInt(remaining, 10);
  const l = parseInt(limit, 10);
  const pct = r / l;
  const used = l - r;

  // Pill text
  if (r <= 0 && reset) {
    const secsLeft = Math.max(0, parseInt(reset, 10) - Math.floor(Date.now() / 1000));
    pill.textContent = 'Resets in ' + Math.ceil(secsLeft / 60) + 'm';
  } else {
    pill.textContent = r + '/' + l;
  }
  pill.classList.add('visible');
  pill.classList.remove('warn', 'danger');
  if (pct <= 0.10) pill.classList.add('danger');
  else if (pct <= 0.25) pill.classList.add('warn');

  // Detail panel
  const color = pct <= 0.10 ? 'var(--err)' : pct <= 0.25 ? 'var(--warn)' : 'var(--dim)';
  $('#rlTitle').textContent = r <= 0 ? 'Rate limit reached' : pct <= 0.25 ? 'Running low' : 'API usage';
  $('#rlTitle').style.color = color;
  $('#rlBarFill').style.width = Math.min((used / l) * 100, 100) + '%';
  $('#rlBarFill').style.background = color;
  let info = used + ' of ' + l + ' lookups used this hour';
  if (r <= 0 && reset) {
    const secsLeft = Math.max(0, parseInt(reset, 10) - Math.floor(Date.now() / 1000));
    info += '\\nResets in ' + Math.ceil(secsLeft / 60) + ' min';
  } else {
    info += '\\nRolling 1-hour window';
  }
  $('#rlInfo').textContent = info;
}

$('#rlPill').addEventListener('click', () => {
  rlExpanded = !rlExpanded;
  $('#rlDetail').classList.toggle('visible', rlExpanded);
});
$('#rlPill').addEventListener('mouseenter', () => {
  rlExpanded = true;
  $('#rlDetail').classList.add('visible');
});
$('#rlPill').addEventListener('mouseleave', () => {
  rlExpanded = false;
  $('#rlDetail').classList.remove('visible');
});

// Boot
if (INITIAL_DOMAIN && Object.keys(INITIAL_DATA).length > 0) {
  renderResults(INITIAL_DATA);
}
// Init rate limit pill from server-rendered data attributes
(function() {
  const pill = $('#rlPill');
  if (!pill) return;
  const r = pill.getAttribute('data-remaining');
  const l = pill.getAttribute('data-limit');
  if (r !== null && l !== null) {
    const remaining = parseInt(r, 10);
    const limit = parseInt(l, 10);
    const pct = remaining / limit;
    const used = limit - remaining;
    pill.textContent = remaining <= 0 ? 'Rate limited' : remaining + '/' + limit;
    pill.classList.add('visible');
    pill.classList.remove('warn', 'danger');
    if (remaining <= 0) pill.classList.add('danger');
    else if (pct <= 0.1) pill.classList.add('danger');
    else if (pct <= 0.25) pill.classList.add('warn');
    const detail = $('#rlDetail');
    const title = $('#rlTitle');
    const barFill = $('#rlBarFill');
    const info = $('#rlInfo');
    if (detail && title && barFill && info) {
      title.textContent = remaining <= 0 ? 'Rate limit reached' : pct <= 0.25 ? 'Running low' : 'API usage';
      title.style.color = remaining <= 0 ? 'var(--err)' : pct <= 0.25 ? 'var(--warn)' : 'var(--dim)';
      barFill.style.width = Math.min((used / limit) * 100, 100) + '%';
      barFill.style.background = remaining <= 0 ? 'var(--err)' : pct <= 0.25 ? 'var(--warn)' : 'var(--dim)';
      info.textContent = used + ' of ' + limit + ' lookups used this hour';
    }
  }
})();
if (INITIAL_DOMAIN && !Object.keys(INITIAL_DATA).length) {
  fetchDomain(INITIAL_DOMAIN);
}

// Search
$('#searchForm').addEventListener('submit', (e) => {
  e.preventDefault();
  doSearch();
});

$('#domainInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); doSearch(); }
});

const copyBtnEl = $('#copyBtn');
if (copyBtnEl) copyBtnEl.addEventListener('click', copyLink);

function doSearch() {
  const val = $('#domainInput').value.trim().toLowerCase().replace(/^https?:\\/\\//, '').replace(/\\/.*$/, '');
  if (!val) return;
  const typeSelect = $('#typeSelect');
  const type = typeSelect ? typeSelect.value : '';
  const path = type ? '/' + val + '/' + type.toLowerCase() : '/' + val;
  history.pushState(null, '', path);
  document.title = val + ' — ns.lol';
  fetchDomain(val, type);
}

async function fetchDomain(domain, type) {
  $('#content').innerHTML = '<div class="loading"><span class="spinner"></span> Querying resolvers...</div>';
  $('#curlHint').style.display = 'block';
  const endpoint = type ? '/' + domain + '/' + type.toLowerCase() : '/' + domain;
  $('#curlHint').querySelector('code').textContent = 'curl -s https://ns.lol' + endpoint;

  try {
    const resp = await fetch(endpoint, { headers: { 'Accept': 'application/dns-json' } });
    updateRateLimit(resp);
    const data = await resp.json();
    currentData = data;
    renderResults(data);
  } catch (err) {
    $('#content').innerHTML = '<div class="empty"><h2>Error</h2><p>' + err.message + '</p></div>';
  }
}

function renderReverse(data) {
  let html = '<div class="summary-bar">';
  html += '<div class="summary-item"><div class="summary-label">IP</div><div class="summary-value">' + esc(data.ip) + '</div></div>';
  html += '<div class="summary-item"><div class="summary-label">Type</div><div class="summary-value">' + esc(data.type) + '</div></div>';
  html += '<div class="summary-item"><div class="summary-label">PTR Domain</div><div class="summary-value" style="font-size:0.75rem">' + esc(data.reverse_domain) + '</div></div>';
  html += '<div class="summary-item"><div class="summary-label">Status</div><div class="summary-value" style="color:' + (data.hostnames.length > 0 ? 'var(--ok)' : 'var(--err)') + '">' + (data.hostnames.length > 0 ? 'Found' : 'No rDNS') + '</div></div>';
  html += '</div>';

  if (data.hostnames.length > 0) {
    html += '<div class="record-section"><h3>Hostnames</h3><table class="record-table"><thead><tr><th>Hostname</th><th>TTL</th><th></th></tr></thead><tbody>';
    for (const rec of (data.ptr_records || [])) {
      const hostname = rec.data.replace(/\\.$/, '');
      html += '<tr><td>' + esc(hostname) + '</td><td>' + (rec.TTL || '') + '</td>';
      html += '<td><a href="/' + esc(hostname) + '" style="color:var(--accent);text-decoration:none">Lookup →</a></td></tr>';
    }
    html += '</tbody></table></div>';
  } else {
    html += '<div class="empty"><p>No reverse DNS (PTR) record found for this IP.</p><p style="color:var(--dim)">This IP has no rDNS configured. This can cause email delivery issues.</p></div>';
  }

  if (data._explain) {
    html += '<div class="explain-box"><strong>What is this?</strong><br>' + esc(data._explain.what) + '<br><br><strong>How?</strong><br>' + esc(data._explain.how) + '<br><br><strong>Result:</strong><br>' + esc(data._explain.why) + '</div>';
  }

  $('#content').innerHTML = html;
}

function renderResults(data) {
  if (data.error) {
    $('#content').innerHTML = '<div class="empty"><h2>Error</h2><p>' + esc(data.error) + '</p></div>';
    return;
  }

  // Reverse DNS result
  if (data.ip) {
    renderReverse(data);
    return;
  }

  // Summary bar
  let html = '';
  if (data.summary) {
    const s = data.summary;
    html += '<div class="summary-bar">';
    html += '<div class="summary-item"><div class="summary-label">Records</div><div class="summary-value">' + s.total_records + '</div></div>';
    html += '<div class="summary-item"><div class="summary-label">Types</div><div class="summary-value">' + s.record_types + '</div></div>';
    html += '<div class="summary-item"><div class="summary-label">Avg Query</div><div class="summary-value">' + s.avg_query_time_ms + 'ms</div></div>';
    html += '<div class="summary-item"><div class="summary-label">DNSSEC</div><div class="summary-value" style="color:' + (s.dnssec === 'authenticated' ? 'var(--ok)' : s.dnssec === 'signed' ? 'var(--warn)' : 'var(--dim)') + '">' + s.dnssec + '</div></div>';
    if (s.cdn) html += '<div class="summary-item"><div class="summary-label">CDN</div><div class="summary-value">' + esc(s.cdn) + '</div></div>';
    html += '</div>';
  }

  // Tabs
  html += '<div class="tabs" id="tabs" role="tablist">';
  html += tab('records', 'Records');
  html += tab('propagation', 'Propagation');
  html += tab('trace', 'Trace');
  html += tab('health', 'Health');
  html += tab('email', 'Email');
  html += tab('security', 'Security');
  html += '</div>';

  // Records panel
  html += '<div class="panel active" id="panel-records">';
  if (data.records) {
    html += renderRecords(data.records);
  } else {
    html += '<div class="loading"><span class="spinner"></span> Loading...</div>';
  }
  html += '</div>';

  // Propagation panel (lazy load)
  html += '<div class="panel" id="panel-propagation"><div class="loading"><span class="spinner"></span> Checking 15 resolvers across 4 regions...<div class="load-progress"><div class="load-progress-bar"><div class="load-progress-fill" id="propProgress"></div></div></div></div></div>';

  // Trace panel (lazy load)
  html += '<div class="panel" id="panel-trace"><div class="loading"><span class="spinner"></span> Tracing authority chain...</div></div>';

  // Health panel (lazy load)
  html += '<div class="panel" id="panel-health"><div class="loading"><span class="spinner"></span> Running health check...</div></div>';

  // Email panel (lazy load)
  html += '<div class="panel" id="panel-email"><div class="loading"><span class="spinner"></span> Checking email DNS...</div></div>';

  // Security panel (lazy load)
  html += '<div class="panel" id="panel-security"><div class="loading"><span class="spinner"></span> Running security checks...</div></div>';

  // Cross-tool links
  const domain = data.domain || INITIAL_DOMAIN;
  html += '<div class="cross-links">';
  html += '<a class="cross-link" href="https://certs.lol/' + domain + '" target="_blank">🔒 TLS Report</a>';
  html += '<a class="cross-link" href="https://xhttp.lol/' + domain + '" target="_blank">🔍 HTTP Headers</a>';
  html += '<a class="cross-link" href="https://yoke.lol/' + domain + '" target="_blank">📊 Full Analysis</a>';
  html += '</div>';

  // Yoke CTA hook
  if (domain) {
    const picked = YOKE_HOOKS[Math.floor(Math.random() * YOKE_HOOKS.length)];
    const q = picked[0].replace('{d}', domain);
    const url = picked[2].replace('{d}', encodeURIComponent(domain));
    html += '<div class="hook"><span class="ar">→</span><span class="q">' + esc(q) + '</span> <a href="' + url + '" target="_blank">' + picked[1] + '</a></div>';
  }

  $('#content').innerHTML = html;

  // Tab clicks
  $$('.tab').forEach((t) => {
    t.addEventListener('click', () => switchTab(t.dataset.tab));
    t.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); switchTab(t.dataset.tab); }
    });
  });

  activeTab = 'records';
}

function tab(id, label) {
  return '<div class="tab' + (id === 'records' ? ' active' : '') + '" data-tab="' + id + '" role="tab" tabindex="0" aria-selected="' + (id === 'records' ? 'true' : 'false') + '">' + label + '</div>';
}

function switchTab(tabId) {
  activeTab = tabId;
  $$('.tab').forEach((t) => {
    const isActive = t.dataset.tab === tabId;
    t.classList.toggle('active', isActive);
    t.setAttribute('aria-selected', isActive ? 'true' : 'false');
  });
  $$('.panel').forEach((p) => p.classList.toggle('active', p.id === 'panel-' + tabId));

  const domain = currentData.domain || INITIAL_DOMAIN;
  const panel = $('#panel-' + tabId);
  if (panel.dataset.loaded) return;

  if (tabId === 'propagation') {
    panel.dataset.loaded = '1';
    loadPropagation(domain, panel);
  } else if (tabId === 'trace') {
    panel.dataset.loaded = '1';
    loadTrace(domain, panel);
  } else if (tabId === 'health') {
    panel.dataset.loaded = '1';
    loadHealth(domain, panel);
  } else if (tabId === 'email') {
    panel.dataset.loaded = '1';
    loadEmail(domain, panel);
  } else if (tabId === 'security') {
    panel.dataset.loaded = '1';
    loadSecurity(domain, panel);
  }
}

async function loadPropagation(domain, panel) {
  try {
    const propType = (panel.dataset.propType || 'A').toUpperCase();
    // Animate progress bar while waiting (fills to 90% over ~5s, eases)
    const fill = $('#propProgress');
    let progress = 0;
    const progressInterval = fill ? setInterval(() => {
      progress = Math.min(progress + (90 - progress) * 0.08, 90);
      fill.style.width = progress + '%';
    }, 100) : null;
    const resp = await fetch('/' + domain + '/propagation?type=' + propType, { headers: { 'Accept': 'application/dns-json' } });
    updateRateLimit(resp);
    const data = await resp.json();
    if (progressInterval) clearInterval(progressInterval);
    if (fill) { fill.style.width = '100%'; }
    panel.innerHTML = renderPropagationControls(propType) + renderPropagation(data);
    // Wire up type selector
    const sel = $('#propTypeSelect');
    if (sel) {
      sel.addEventListener('change', () => {
        panel.dataset.propType = sel.value;
        panel.dataset.loaded = '';
        panel.innerHTML = '<div class="loading"><span class="spinner"></span> Checking ' + sel.value + ' propagation...<div class="load-progress"><div class="load-progress-bar"><div class="load-progress-fill" id="propProgress"></div></div></div></div>';
        loadPropagation(domain, panel);
      });
    }
    renderMap(data.results || []);
    startTTLCountdowns();
  } catch (err) {
    panel.innerHTML = '<div class="empty"><p>Failed to load propagation data</p></div>';
  }
}

async function loadHealth(domain, panel) {
  try {
    const resp = await fetch('/' + domain + '/health', { headers: { 'Accept': 'application/dns-json' } });
    updateRateLimit(resp);
    const data = await resp.json();
    panel.innerHTML = renderHealth(data);
  } catch (err) {
    panel.innerHTML = '<div class="empty"><p>Failed to load health data</p></div>';
  }
}

async function loadEmail(domain, panel) {
  try {
    const resp = await fetch('/' + domain + '/email', { headers: { 'Accept': 'application/dns-json' } });
    updateRateLimit(resp);
    const data = await resp.json();
    panel.innerHTML = renderEmail(data);
  } catch (err) {
    panel.innerHTML = '<div class="empty"><p>Failed to load email data</p></div>';
  }
}

async function loadSecurity(domain, panel) {
  try {
    const resp = await fetch('/' + domain + '/security', { headers: { 'Accept': 'application/dns-json' } });
    updateRateLimit(resp);
    const data = await resp.json();
    panel.innerHTML = renderSecurity(data);
  } catch (err) {
    panel.innerHTML = '<div class="empty"><p>Failed to load security data</p></div>';
  }
}

async function loadTrace(domain, panel) {
  try {
    const resp = await fetch('/' + domain + '/trace', { headers: { 'Accept': 'application/dns-json' } });
    updateRateLimit(resp);
    const data = await resp.json();
    panel.innerHTML = renderTrace(data);
  } catch (err) {
    panel.innerHTML = '<div class="empty"><p>Failed to load trace data</p></div>';
  }
}

function renderTrace(data) {
  if (!data.steps || data.steps.length === 0) {
    return '<div class="empty"><p>No trace data available</p></div>';
  }

  let html = '<div style="display:flex;align-items:center;margin-bottom:20px;gap:12px">';
  html += '<div style="font-size:1.2rem">🔍</div>';
  html += '<div><div style="font-weight:600">Authority Chain Trace</div>';
  html += '<div style="font-size:0.78rem;color:var(--dim)">' + data.trace.steps + ' steps &middot; ' + data.trace.total_time_ms + 'ms total</div>';
  html += '</div></div>';

  for (const step of data.steps) {
    html += '<div class="signal-row" style="flex-direction:column;gap:8px">';
    html += '<div style="display:flex;gap:12px;align-items:center">';
    html += '<div style="background:var(--surface-raised);border:1px solid var(--border);border-radius:50%;width:28px;height:28px;display:flex;align-items:center;justify-content:center;font-family:var(--font-mono);font-size:0.75rem;font-weight:600;color:var(--accent);flex-shrink:0">' + step.step + '</div>';
    html += '<div style="flex:1">';
    html += '<div style="font-weight:500;font-size:0.85rem">' + esc(step.label) + '</div>';
    html += '<div style="color:var(--muted);font-size:0.78rem;font-family:var(--font-mono)">' + esc(step.query || '') + '</div>';
    html += '</div>';
    if (step.query_time_ms) html += '<div style="color:var(--dim);font-size:0.72rem">' + step.query_time_ms + 'ms</div>';
    html += '</div>';

    if (step.error) {
      html += '<div style="color:var(--err);font-size:0.82rem;margin-left:40px">Error: ' + esc(step.error) + '</div>';
    }

    if (step.nameservers && step.nameservers.length > 0) {
      html += '<div style="margin-left:40px;display:flex;flex-wrap:wrap;gap:4px">';
      for (const ns of step.nameservers) {
        html += '<span style="background:var(--surface-raised);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);font-size:0.75rem;color:var(--teal)">' + esc(ns) + '</span>';
      }
      html += '</div>';
    }

    if (step.ns_ips && step.ns_ips.length > 0) {
      html += '<div style="margin-left:40px;font-size:0.75rem;color:var(--dim)">';
      html += step.ns_ips.map(function(n) { return esc(n.ns) + ' → ' + esc(n.ip); }).join(', ');
      html += '</div>';
    }

    if (step.resolver_results) {
      html += '<div style="margin-left:40px;display:grid;gap:4px">';
      for (const rr of step.resolver_results) {
        if (rr.error) {
          html += '<div style="font-size:0.78rem;color:var(--err)">' + esc(rr.resolver) + ': ' + esc(rr.error) + '</div>';
        } else {
          const ips = (rr.records || []).map(function(r) { return esc(r.data); }).join(', ');
          html += '<div style="font-size:0.78rem"><span style="color:var(--muted)">' + esc(rr.resolver) + ':</span> ';
          html += '<span style="color:var(--accent);font-family:var(--font-mono)">' + ips + '</span>';
          html += ' <span style="color:var(--dim)">' + (rr.aa ? '[AA]' : '') + (rr.ad ? ' [AD]' : '') + ' ' + rr.rcode + ' ' + rr.query_time_ms + 'ms</span>';
          html += '</div>';
        }
      }
      html += '</div>';
    }

    if (step.primary_ns) {
      html += '<div style="margin-left:40px;font-size:0.78rem">';
      html += '<span style="color:var(--muted)">Primary NS:</span> <span style="color:var(--accent);font-family:var(--font-mono)">' + esc(step.primary_ns) + '</span>';
      if (step.serial) html += ' &middot; <span style="color:var(--muted)">Serial:</span> <span style="font-family:var(--font-mono)">' + step.serial + '</span>';
      html += '</div>';
    }

    if (step.ds_records !== undefined) {
      const chainColor = step.chain_intact ? 'var(--ok)' : 'var(--err)';
      html += '<div style="margin-left:40px;font-size:0.78rem">';
      html += '<span style="color:var(--muted)">DS:</span> ' + step.ds_records + ' record(s) &middot; ';
      html += '<span style="color:var(--muted)">DNSKEY:</span> ' + step.dnskey_records + ' record(s) &middot; ';
      html += '<span style="color:' + chainColor + '">' + (step.chain_intact ? '✓ Chain intact' : '✗ Chain broken') + '</span>';
      html += '</div>';
    }

    if (step.explain) {
      html += '<div style="margin-left:40px;font-size:0.75rem;color:var(--dim);font-style:italic">' + esc(step.explain) + '</div>';
    }

    html += '</div>';
  }

  return html;
}

function renderRecords(records) {
  if (!records || Object.keys(records).length === 0) {
    return '<div class="empty"><p>No DNS records found</p></div>';
  }
  let html = '';
  const order = ['A','AAAA','CNAME','MX','TXT','NS','SOA','SRV','CAA','HTTPS','DS'];
  for (const type of order) {
    const data = records[type];
    if (!data || data.records.length === 0) continue;
    html += '<div class="record-group">';
    html += '<div class="record-type">' + type + '<span class="count">' + data.records.length + '</span>';
    if (data.query_time_ms) html += '<span class="count">' + data.query_time_ms + 'ms</span>';
    html += '</div>';
    for (const r of data.records) {
      html += '<div class="record-row">';
      // Strip outer quotes from TXT records (wire format artifact)
      const displayData = type === 'TXT' ? r.data.replace(/^"|"$/g, '') : r.data;
      html += '<div class="data">' + esc(displayData) + '</div>';
      html += '<div class="ttl">TTL ' + r.TTL + (r.ttl_human ? ' (' + r.ttl_human + ')' : '') + '</div>';
      html += '</div>';
    }
    html += '</div>';
  }
  return html;
}

function renderPropagationControls(currentType) {
  const types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA'];
  let html = '<div class="prop-controls">';
  html += '<label class="prop-type-label">Record type: ';
  html += '<select id="propTypeSelect" class="prop-type-select">';
  for (const t of types) {
    html += '<option value="' + t + '"' + (t === currentType ? ' selected' : '') + '>' + t + '</option>';
  }
  html += '</select></label></div>';
  return html;
}

function renderPropagation(data) {
  if (!data.propagation) return '<div class="empty"><p>No propagation data</p></div>';
  const p = data.propagation;
  const pctClass = p.percentage >= 100 ? 'full' : p.percentage >= 50 ? 'partial' : 'low';

  let html = '';

  html += '<div class="prop-summary">';
  html += '<div class="prop-pct ' + pctClass + '">' + p.percentage + '%</div>';
  html += '<div style="flex:1;min-width:200px"><div class="prop-status">' + p.status.replace('_',' ') + '</div>';
  html += '<div class="prop-bar-wrap"><div class="prop-bar ' + pctClass + '" style="width:' + p.percentage + '%"></div></div>';
  const responded = p.resolvers_responded || (p.resolvers_queried - (p.resolvers_errored || 0));
  const errored = p.resolvers_errored || 0;
  html += '<div style="color:var(--dim);font-size:0.78rem;margin-top:4px">' + responded + '/' + p.resolvers_queried + ' resolvers responded';
  if (p.distinct_answers > 1) {
    html += ' &middot; ' + p.distinct_answers + ' distinct answer(s)';
    if (typeof p.consistency === 'number' && p.consistency < 100) {
      html += ' &middot; <span style="color:var(--accent)">' + p.consistency + '% consistent</span>';
    }
  }
  if (errored > 0) html += ' &middot; <span style="color:var(--warn)">' + errored + ' failed</span>';
  if (p.ttl) html += ' &middot; TTL ' + p.ttl.min_human + '–' + p.ttl.max_human;
  html += '</div></div>';
  html += '</div>';

  // Expected value match (if present)
  if (data.expected_match) {
    const em = data.expected_match;
    const emClass = em.percentage === 100 ? 'pass' : em.percentage > 50 ? 'warn' : 'fail';
    html += '<div class="signal-row" style="margin-bottom:16px">';
    html += '<div class="signal-status ' + emClass + '">' + em.percentage + '%</div>';
    html += '<div class="signal-body">';
    html += '<div class="signal-label">Expected: ' + esc(em.expected) + '</div>';
    html += '<div class="signal-detail">' + em.matches + '/' + (em.matches + em.mismatches) + ' resolvers returning expected value</div>';
    if (em.resolvers_mismatching.length > 0) {
      html += '<div class="signal-explain">Not yet: ' + em.resolvers_mismatching.join(', ') + '</div>';
    }
    html += '</div></div>';
  }

  // Map
  html += '<div class="map-wrap"><svg class="map-svg" id="propMap" viewBox="0 0 800 400"></svg></div>';

  // Resolver grid — sort: successful first, then anomalies, then errors
  const sortedResults = [...(data.results || [])].sort((a, b) => {
    if (a.error && !b.error) return 1;
    if (!a.error && b.error) return -1;
    if (a.anomaly && !b.anomaly) return 1;
    if (!a.anomaly && b.anomaly) return -1;
    return 0;
  });
  html += '<div class="prop-grid">';
  for (const r of sortedResults) {
    const val = r.error ? '<span class="resolver-err">' + esc(r.error) + '</span>' :
      r.records.length === 0 ? '<span style="color:var(--dim)">No records</span>' :
      r.records.map(rec => esc(rec.data)).join('<br>');
    const anomalyClass = r.anomaly ? ' anomaly' : '';
    html += '<div class="resolver-card' + anomalyClass + '">';
    html += '<div><div class="resolver-name"><span class="dot ' + (r.error ? 'dot-fail' : r.anomaly ? 'dot-warn' : r.rcode === 'NOERROR' ? 'dot-pass' : 'dot-warn') + '"></span>' + esc(r.resolver) + '</div>';
    html += '<div class="resolver-loc">' + esc(r.location) + '</div>';
    html += '<div class="resolver-time">' + r.query_time_ms + 'ms';
    if (r.records && r.records[0] && r.records[0].TTL) {
      html += ' &middot; TTL ' + (r.records[0].ttl_human || r.records[0].TTL);
      html += ' &middot; <span class="ttl-countdown" data-ttl-remaining="' + r.records[0].TTL + '">' + (r.records[0].ttl_human || r.records[0].TTL + 's') + '</span> left';
    }
    html += '</div></div>';
    html += '<div class="resolver-val">' + val + '</div>';
    html += '</div>';
  }
  html += '</div>';

  return html;
}

function renderMap(results) {
  const svg = $('#propMap');
  if (!svg) return;

  // Natural Earth 110m land outlines — Douglas-Peucker simplified, equirectangular projection 800x400
  // Source: Natural Earth (public domain). 57 polygons, ~2.7KB.
  const WORLD_LAND = 'M268,378L253,378L268,378ZM46,377L36,375L46,377ZM300,373L280,379L300,373ZM248,358L233,359L248,358ZM270,343L254,351L265,364L227,376L271,385L337,379L320,374L385,358L521,346L553,351L555,357L562,357L574,353L590,349L617,349L632,346L648,347L664,349L676,348L693,348L706,349L726,351L749,354L769,357L779,361L764,369L765,373L757,377L761,382L800,388L800,400L0,400L0,388L25,387L55,389L76,390L59,384L51,380L65,380L67,376L51,374L63,372L75,370L248,358L270,343ZM249,320L239,321L249,320ZM270,314L265,316L270,314ZM556,311L553,308L556,311ZM723,291L730,294L723,291ZM785,291L777,304L771,303L774,298L785,291ZM788,280L793,284L789,293L788,280ZM771,249L765,245L771,249ZM511,230L507,246L501,257L497,249L499,236L511,230ZM719,231L725,242L741,262L734,278L726,287L716,285L707,276L706,273L700,275L691,270L675,274L664,277L657,274L654,263L652,256L655,249L665,244L674,237L678,233L685,233L690,228L697,226L702,231L711,239L715,233L715,227L719,231ZM642,215L657,219L647,218L635,213L642,215ZM698,203L702,205L717,207L728,214L735,224L725,218L718,218L707,214L697,208L690,202L698,203ZM678,197L669,199L673,210L668,208L665,212L664,204L668,197L678,197ZM686,198L683,198L686,198ZM635,213L626,206L622,201L619,196L617,195L621,192L628,197L632,205L635,213ZM662,196L659,203L658,209L649,208L642,197L655,189L660,185L662,196ZM681,181L677,187L675,181L681,181ZM581,186L577,182L581,186ZM676,177L672,178L676,177ZM663,179L666,175L663,179ZM671,174L671,177L671,174ZM679,173L677,178L676,172L679,173ZM671,171L667,170L671,171ZM670,159L672,162L676,169L676,172L669,170L666,166L670,159ZM254,160L252,160L254,160ZM229,160L226,160L229,160ZM239,156L247,157L239,160L237,156L239,156ZM645,159L643,156L645,159ZM54,158L54,155L54,158ZM223,149L231,153L225,156L222,151L216,149L215,149L223,149ZM228,147L226,145L228,147ZM669,149L668,146L669,149ZM227,141L225,141L227,141ZM699,124L695,127L699,124ZM477,121L473,123L477,121ZM453,121L455,122L453,121ZM435,115L428,116L435,115ZM421,108L419,113L421,108ZM713,118L705,123L700,124L694,125L692,130L689,128L694,121L704,117L711,112L715,111L713,118ZM421,106L419,106L421,106ZM720,102L718,107L711,108L715,101L720,102ZM259,97L257,89L263,97L259,97ZM263,91L260,90L263,91ZM126,92L115,89L126,92ZM275,87L276,89L282,93L276,96L268,94L271,88L276,85ZM105,80L109,84L105,80ZM719,87L716,94L716,87L715,82L719,87ZM385,84L378,85L382,79L387,79L385,84ZM428,76L425,77L428,76ZM60,73L58,72L60,73ZM393,70L396,72L404,83L394,87L388,89L391,86L390,82L392,79L389,78L393,70ZM32,67L29,67L32,67ZM224,62L221,62L224,62ZM218,61L215,62L218,61ZM18,58L25,59L18,58ZM211,54L222,58L209,60L211,54ZM368,52L350,53L361,52L368,52ZM231,51L229,49L231,51ZM11,52L22,53L8,56L0,54L0,47L11,52ZM187,46L178,46L187,46ZM800,43L798,43L800,43ZM3,43L0,43L3,43ZM199,46L210,45L219,46L219,51L207,55L196,60L191,65L193,71L211,77L218,82L226,78L229,73L226,69L227,65L240,63L246,69L261,71L268,77L276,84L263,89L251,90L248,91L252,91L260,98L264,96L260,101L251,102L244,103L238,108L233,114L231,115L231,118L232,121L219,130L221,137L222,140L217,141L215,135L208,132L195,135L185,137L184,145L183,149L186,157L198,157L200,153L206,152L204,160L202,165L215,165L215,173L217,179L228,179L233,176L241,172L241,177L244,175L249,177L260,176L265,179L272,186L285,187L287,192L287,200L296,202L308,207L318,211L322,220L314,229L312,241L307,251L293,255L292,260L285,271L278,278L271,276L273,278L272,285L261,286L259,291L255,294L253,300L250,303L250,307L246,313L243,320L233,316L232,308L236,304L235,298L238,295L236,293L236,285L241,275L243,257L244,248L241,239L229,231L222,216L222,199L228,193L228,187L224,180L219,183L215,181L210,178L206,172L197,169L189,164L180,163L167,157L164,149L160,145L154,138L149,133L145,133L150,138L153,144L156,147L153,147L148,141L146,138L142,133L137,127L131,123L127,117L124,110L124,99L123,93L128,93L128,93L118,87L110,79L103,73L93,70L84,67L74,65L67,67L58,72L55,72L62,65L48,75L39,78L40,76L51,69L40,68L33,66L34,59L39,59L33,57L26,54L41,53L37,51L29,48L40,44L55,42L67,43L91,46L105,46L112,44L124,44L131,45L142,47L153,49L158,50L158,48L168,49L178,49L186,49L191,47L185,44L186,42L194,41L199,46ZM146,38L160,41L163,38L172,43L168,47L152,48L139,45L150,44L137,43L142,42L135,39L146,38ZM168,37L162,37L168,37ZM230,38L220,37L230,38ZM208,37L221,38L242,42L252,46L256,59L248,58L234,56L227,57L232,55L239,51L237,49L226,45L220,45L207,44L200,42L201,38L208,37ZM177,36L185,39L177,41L177,36ZM719,37L712,37L719,37ZM193,38L187,38L198,36L193,38ZM132,41L120,40L125,36L139,35L143,37L136,39L132,41ZM735,33L725,33L735,33ZM192,33L185,34L192,33ZM722,32L705,33L714,31L722,32ZM181,30L175,33L175,30L181,30ZM160,31L163,33L148,35L152,33L142,33L160,31ZM528,43L522,36L536,31L547,29L537,33L524,39L528,43ZM190,29L204,32L222,33L208,35L194,34L186,30L190,29ZM142,28L127,31L142,28ZM638,29L654,33L645,35L652,37L657,36L686,38L686,40L694,40L710,41L735,40L753,43L758,46L769,46L779,45L790,45L800,47L800,56L794,56L788,63L776,66L760,70L763,75L752,82L749,87L747,77L752,71L764,64L758,63L743,67L745,69L733,67L709,73L704,79L715,82L712,86L708,96L695,105L686,111L685,114L688,121L681,124L680,118L678,113L673,112L665,114L672,117L665,121L668,126L671,130L670,137L664,143L658,149L649,152L644,153L637,154L636,160L641,164L643,170L639,178L634,181L628,173L622,173L621,176L625,185L630,194L626,194L622,188L619,177L613,189L609,164L606,154L601,152L593,152L587,157L578,164L578,169L575,179L569,177L564,165L562,157L554,151L544,144L531,143L524,140L519,141L514,138L511,133L507,133L510,139L512,143L514,142L517,146L525,141L528,147L531,150L528,156L522,160L514,164L508,169L500,172L496,169L494,162L489,155L487,150L483,146L481,141L477,138L473,137L472,134L476,141L481,151L483,158L487,162L492,168L497,176L504,176L512,174L514,176L511,182L506,191L498,198L491,205L488,210L488,218L490,226L490,234L484,239L478,244L479,251L474,256L472,263L461,274L453,275L445,276L442,277L441,274L437,264L433,258L432,250L427,244L426,237L428,230L431,225L429,219L427,214L425,209L419,203L421,195L419,190L413,190L407,186L399,188L393,189L387,189L380,190L376,186L371,183L368,178L365,175L363,171L362,165L364,160L362,153L364,147L369,141L375,136L379,131L383,125L389,121L397,121L400,120L410,118L417,118L421,117L424,121L425,127L434,128L435,130L442,132L445,131L448,127L455,129L463,131L468,130L473,131L477,127L480,119L472,120L466,120L462,119L460,116L461,110L472,107L478,107L485,109L492,108L492,105L484,102L482,100L487,95L480,96L478,99L475,101L468,97L464,99L462,105L460,110L458,110L453,110L451,113L452,117L446,114L443,111L442,106L435,103L432,100L428,101L433,107L441,110L438,110L436,116L434,112L427,107L423,102L418,103L407,104L401,109L398,116L392,119L384,118L380,115L381,109L379,105L388,103L396,104L398,98L390,93L396,92L396,89L403,89L411,82L419,77L423,74L424,79L433,80L441,79L447,77L447,74L454,72L452,70L457,68L462,67L465,67L458,66L451,67L447,65L449,58L455,56L447,56L444,59L438,64L440,65L437,69L435,75L429,77L426,72L419,70L412,68L411,62L419,59L433,50L447,44L458,42L470,43L477,46L492,49L489,53L476,52L478,54L483,55L494,52L498,53L497,48L512,49L528,43L534,48L549,45L552,40L561,38L562,44L559,53L565,49L565,43L567,40L573,39L579,37L583,36L600,32L624,30L632,27L638,29ZM509,108L510,112L516,118L520,114L518,109L519,106L514,104L514,100L518,95L508,98L506,103L509,108ZM192,28L186,28L192,28ZM155,27L148,27L155,27ZM455,27L446,27L455,27ZM156,25L150,26L156,25ZM187,27L181,26L187,27ZM178,26L166,26L178,26ZM755,219L752,217L755,219ZM750,216L748,215L750,216ZM746,215L730,213L737,209L746,215ZM683,208L680,208L683,208ZM690,207L684,208L690,207ZM740,210L736,207L740,210ZM634,25L613,19L623,23L634,25ZM207,23L194,26L187,23L195,19L207,23ZM248,15L258,17L245,21L221,31L205,30L211,28L204,26L210,25L212,22L206,21L197,19L207,17L215,17L224,15L248,15ZM340,14L354,16L365,18L357,25L359,29L356,31L355,35L351,37L350,39L351,41L344,46L332,49L327,50L315,54L310,56L305,61L305,64L298,65L289,61L284,55L281,51L286,47L284,45L279,45L279,43L278,39L270,34L259,31L245,30L248,28L237,27L254,24L249,22L266,18L282,18L293,18L296,18L304,15L322,14L340,14Z';

  let svgContent = '<rect width="800" height="400" fill="var(--surface)" rx="0"/>';

  // Subtle grid
  for (let x = 0; x < 800; x += 100) {
    svgContent += '<line x1="' + x + '" y1="0" x2="' + x + '" y2="400" stroke="var(--border)" stroke-width="0.3" opacity="0.3"/>';
  }
  for (let y = 0; y < 400; y += 100) {
    svgContent += '<line x1="0" y1="' + y + '" x2="800" y2="' + y + '" stroke="var(--border)" stroke-width="0.3" opacity="0.3"/>';
  }

  // Draw land masses (single compound path for efficiency)
  svgContent += '<path d="' + WORLD_LAND + '" fill="var(--surface-raised)" stroke="var(--border)" stroke-width="0.5" opacity="0.7"/>';

  // Plot resolver dots with glow effect
  for (const r of results) {
    const x = ((r.lng + 180) / 360) * 800;
    const y = ((90 - r.lat) / 180) * 400;
    const color = r.error ? 'var(--err)' : r.rcode === 'NOERROR' ? 'var(--ok)' : 'var(--warn)';

    // Glow
    svgContent += '<circle cx="' + x + '" cy="' + y + '" r="10" fill="' + color + '" opacity="0.15"/>';
    // Dot
    svgContent += '<circle class="map-dot" cx="' + x + '" cy="' + y + '" r="4.5" fill="' + color + '" stroke="' + color + '" stroke-width="1" opacity="0.9"' +
      ' data-name="' + esc(r.resolver) + '"' +
      ' data-loc="' + esc(r.location) + '"' +
      ' data-val="' + esc(r.records?.map(rec => rec.data).join(', ') || r.error || 'no records') + '"' +
      ' data-time="' + r.query_time_ms + 'ms"/>';
  }

  svg.innerHTML = svgContent;

  // Tooltips
  const tooltip = $('#mapTooltip');
  svg.querySelectorAll('.map-dot').forEach((dot) => {
    dot.addEventListener('mouseenter', (e) => {
      const d = e.target.dataset;
      tooltip.innerHTML = '<strong>' + d.name + '</strong><br>' + d.loc + '<br><span style="color:var(--accent)">' + d.val + '</span><br><span style="color:var(--dim)">' + d.time + '</span>';
      tooltip.style.opacity = '1';
    });
    dot.addEventListener('mousemove', (e) => {
      tooltip.style.left = (e.clientX + 12) + 'px';
      tooltip.style.top = (e.clientY - 10) + 'px';
    });
    dot.addEventListener('mouseleave', () => {
      tooltip.style.opacity = '0';
    });
  });
}

function renderHealth(data) {
  if (!data.health) return '<div class="empty"><p>No health data</p></div>';
  const h = data.health;
  const gradeClass = 'grade-' + h.grade.toLowerCase();

  let html = '<div style="display:flex;align-items:center;margin-bottom:20px">';
  html += '<div class="grade ' + gradeClass + '">' + h.grade + '</div>';
  html += '<div><div style="font-size:0.85rem;color:var(--muted)">' + h.signals_checked + ' checks</div>';
  html += '<div style="font-size:0.78rem;color:var(--dim)">';
  if (h.pass) html += '<span style="color:var(--ok)">' + h.pass + ' pass</span> ';
  if (h.warn) html += '<span style="color:var(--warn)">' + h.warn + ' warn</span> ';
  if (h.fail) html += '<span style="color:var(--err)">' + h.fail + ' fail</span> ';
  if (h.info) html += '<span style="color:var(--blue)">' + h.info + ' info</span>';
  html += '</div></div></div>';

  // Signals grouped by category
  const grouped = {};
  for (const s of (data.signals || [])) {
    if (!grouped[s.category]) grouped[s.category] = [];
    grouped[s.category].push(s);
  }

  for (const [cat, sigs] of Object.entries(grouped)) {
    html += '<div style="margin-bottom:16px"><div style="font-weight:600;font-size:0.85rem;color:var(--accent);margin-bottom:6px">' + esc(cat) + '</div>';
    for (const s of sigs) {
      html += signalRow(s);
    }
    html += '</div>';
  }
  return html;
}

function renderEmail(data) {
  if (!data.email) return '<div class="empty"><p>No email data</p></div>';
  const e = data.email;
  const gradeClass = 'grade-' + e.grade.toLowerCase();

  let html = '<div style="display:flex;align-items:center;margin-bottom:20px">';
  html += '<div class="grade ' + gradeClass + '">' + e.grade + '</div>';
  html += '<div><div style="font-size:0.85rem;color:var(--muted)">Email DNS Audit</div>';
  html += '<div style="font-size:0.78rem;color:var(--dim)">';
  if (e.pass) html += '<span style="color:var(--ok)">' + e.pass + ' pass</span> ';
  if (e.warn) html += '<span style="color:var(--warn)">' + e.warn + ' warn</span> ';
  if (e.fail) html += '<span style="color:var(--err)">' + e.fail + ' fail</span> ';
  if (e.info) html += '<span style="color:var(--blue)">' + e.info + ' info</span>';
  html += '</div></div></div>';

  const grouped = {};
  for (const s of (data.signals || [])) {
    if (!grouped[s.category]) grouped[s.category] = [];
    grouped[s.category].push(s);
  }

  for (const [cat, sigs] of Object.entries(grouped)) {
    html += '<div style="margin-bottom:16px"><div style="font-weight:600;font-size:0.85rem;color:var(--accent);margin-bottom:6px">' + esc(cat) + '</div>';
    for (const s of sigs) {
      html += signalRow(s);
    }
    html += '</div>';
  }
  return html;
}

function signalRow(s) {
  let html = '<div class="signal-row">';
  html += '<div class="signal-status ' + s.status + '">' + s.status.toUpperCase() + '</div>';
  html += '<div class="signal-body">';
  html += '<div class="signal-label">' + esc(s.label) + '</div>';
  html += '<div class="signal-detail">' + esc(s.detail) + '</div>';
  if (s.fix) html += '<div class="signal-fix">💡 ' + esc(s.fix) + '</div>';
  if (s.explain) html += '<div class="signal-explain">' + esc(s.explain) + '</div>';
  html += '</div></div>';
  return html;
}

function renderSecurity(data) {
  if (!data.security) return '<div class="empty"><p>No security data</p></div>';
  const sec = data.security;

  const gradeClass = 'grade-' + sec.grade.toLowerCase();
  let html = '<div style="display:flex;align-items:center;margin-bottom:20px">';
  html += '<div class="grade ' + gradeClass + '">' + sec.grade + '</div>';
  html += '<div><div style="font-size:0.85rem;color:var(--muted)">Security Analysis</div>';
  html += '<div style="font-size:0.78rem;color:var(--dim)">';
  if (sec.pass) html += '<span style="color:var(--ok)">' + sec.pass + ' pass</span> ';
  if (sec.warn) html += '<span style="color:var(--warn)">' + sec.warn + ' warn</span> ';
  if (sec.fail) html += '<span style="color:var(--err)">' + sec.fail + ' fail</span> ';
  if (sec.info) html += '<span style="color:var(--blue)">' + sec.info + ' info</span>';
  html += '</div></div></div>';

  const grouped = {};
  for (const s of (data.signals || [])) {
    if (!grouped[s.category]) grouped[s.category] = [];
    grouped[s.category].push(s);
  }

  for (const [cat, sigs] of Object.entries(grouped)) {
    html += '<div style="margin-bottom:16px"><div style="font-weight:600;font-size:0.85rem;color:var(--accent);margin-bottom:6px">' + esc(cat) + '</div>';
    for (const s of sigs) {
      html += signalRow(s);
    }
    html += '</div>';
  }
  return html;
}

function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Auto-refresh for propagation
// Copy link to clipboard
function copyLink() {
  navigator.clipboard.writeText(window.location.href).then(() => {
    const btn = document.querySelector('.copy-btn');
    if (btn) {
      btn.textContent = '✓ Copied!';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.innerHTML = '📋 Copy Link';
        btn.classList.remove('copied');
      }, 2000);
    }
  });
}

// TTL countdown timers
let ttlCountdownTimer = null;

function startTTLCountdowns() {
  stopTTLCountdowns();
  ttlCountdownTimer = setInterval(() => {
    const els = document.querySelectorAll('[data-ttl-remaining]');
    els.forEach((el) => {
      let remaining = parseInt(el.getAttribute('data-ttl-remaining'), 10);
      if (remaining > 0) {
        remaining--;
        el.setAttribute('data-ttl-remaining', String(remaining));
        const m = Math.floor(remaining / 60);
        const s = remaining % 60;
        el.textContent = remaining > 3600
          ? Math.floor(remaining / 3600) + 'h ' + Math.floor((remaining % 3600) / 60) + 'm'
          : remaining > 60
            ? m + 'm ' + s + 's'
            : remaining + 's';
        if (remaining <= 30) el.style.color = 'var(--err)';
        else if (remaining <= 120) el.style.color = 'var(--warn)';
      } else {
        el.textContent = 'expired';
        el.style.color = 'var(--err)';
      }
    });
  }, 1000);
}

function stopTTLCountdowns() {
  if (ttlCountdownTimer) {
    clearInterval(ttlCountdownTimer);
    ttlCountdownTimer = null;
  }
}

// URL handling
window.addEventListener('popstate', () => {
  const path = location.pathname.slice(1);
  if (path) {
    $('#domainInput').value = path;
    fetchDomain(path);
  }
});
</script>
</body>
</html>`;
}

function renderEmpty(): string {
  return `<div class="empty" style="margin-top:3rem;text-align:center">
    <p style="color:var(--dim);font-family:var(--font-mono);font-size:12px"><code>curl -s https://ns.lol/example.com</code></p>
    <div class="examples">
      <a href="/cloudflare.com">cloudflare.com</a>
      <a href="/google.com">google.com</a>
      <a href="/github.com">github.com</a>
    </div>
  </div>`;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
