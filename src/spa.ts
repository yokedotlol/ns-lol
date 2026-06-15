// SPA renderer — full terminal-aesthetic UI for browser clients
// Blue/cyan palette, dark-mode-first, Inter + JetBrains Mono

export function renderSPA(data: any, path: string, domain?: string): string {
  const jsonData = JSON.stringify(data || {}).replace(/<\//g, '<\\/');
  const currentDomain = domain || '';

  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${currentDomain ? `${currentDomain} — ns.lol` : 'ns.lol — DNS Toolkit'}</title>
<meta name="description" content="Fast, API-first DNS toolkit. Record lookups, propagation checks, zone health, email DNS audit.">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌐</text></svg>">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0a0e17;--surface:#111827;--surface2:#1a2332;--border:#1e293b;
  --text:#e2e8f0;--muted:#64748b;--dim:#475569;
  --cyan:#22d3ee;--blue:#3b82f6;--teal:#14b8a6;
  --green:#22c55e;--yellow:#eab308;--red:#ef4444;--orange:#f97316;
  --mono:'JetBrains Mono',monospace;--sans:'Inter',system-ui,sans-serif;
  --radius:8px;
}
html,body{background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.6;min-height:100vh}
a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline}
.container{max-width:960px;margin:0 auto;padding:24px 16px}
/* Header */
.header{text-align:center;padding:48px 0 32px}
.logo{font-family:var(--mono);font-size:2.5rem;font-weight:700;letter-spacing:-1px}
.logo span{color:var(--cyan)}
.tagline{color:var(--muted);margin-top:4px;font-size:0.9rem}
/* Search */
.search-wrap{max-width:600px;margin:24px auto 0;position:relative}
.search-input{width:100%;padding:14px 20px;padding-right:120px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-family:var(--mono);font-size:1rem;outline:none;transition:border-color .2s}
.search-input:focus{border-color:var(--cyan)}
.search-input::placeholder{color:var(--dim)}
.search-btn{position:absolute;right:4px;top:4px;bottom:4px;padding:0 20px;background:var(--cyan);color:var(--bg);border:none;border-radius:6px;font-family:var(--mono);font-weight:600;font-size:0.85rem;cursor:pointer;transition:opacity .2s}
.search-btn:hover{opacity:.85}
.search-btn:disabled{opacity:.5;cursor:not-allowed}
/* Tabs */
.tabs{display:flex;gap:2px;margin:32px 0 16px;border-bottom:1px solid var(--border);overflow-x:auto;-webkit-overflow-scrolling:touch}
.tab{padding:10px 16px;color:var(--muted);font-size:0.85rem;font-weight:500;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;transition:color .2s,border-color .2s}
.tab:hover{color:var(--text)}
.tab.active{color:var(--cyan);border-bottom-color:var(--cyan)}
/* Panels */
.panel{display:none}.panel.active{display:block}
/* Records table */
.record-group{margin-bottom:20px}
.record-type{font-family:var(--mono);font-weight:600;font-size:0.95rem;color:var(--cyan);margin-bottom:8px;display:flex;align-items:center;gap:8px}
.record-type .count{font-size:0.75rem;background:var(--surface2);color:var(--muted);padding:1px 8px;border-radius:10px}
.record-row{display:grid;grid-template-columns:1fr auto auto;gap:12px;padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:6px;margin-bottom:4px;font-family:var(--mono);font-size:0.82rem;align-items:center;word-break:break-all}
.record-row .data{color:var(--text)}
.record-row .ttl{color:var(--dim);font-size:0.75rem;white-space:nowrap}
.record-row .name{color:var(--muted);font-size:0.75rem}
/* Propagation */
.prop-summary{display:flex;gap:16px;align-items:center;margin-bottom:20px;flex-wrap:wrap}
.prop-pct{font-family:var(--mono);font-size:2.2rem;font-weight:700}
.prop-pct.full{color:var(--green)}.prop-pct.partial{color:var(--yellow)}.prop-pct.low{color:var(--red)}
.prop-status{font-size:0.85rem;color:var(--muted)}
.prop-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:8px}
.resolver-card{padding:10px 14px;background:var(--surface);border:1px solid var(--border);border-radius:6px;display:flex;justify-content:space-between;align-items:center;gap:8px}
.resolver-name{font-weight:500;font-size:0.85rem}
.resolver-loc{color:var(--muted);font-size:0.75rem}
.resolver-val{font-family:var(--mono);font-size:0.78rem;color:var(--cyan);text-align:right;word-break:break-all;max-width:55%}
.resolver-err{color:var(--red)}
.resolver-time{font-size:0.7rem;color:var(--dim);margin-top:2px}
.ttl-countdown{color:var(--yellow);font-family:var(--mono);font-size:0.7rem}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.dot-pass{background:var(--green)}.dot-warn{background:var(--yellow)}.dot-fail{background:var(--red)}.dot-info{background:var(--blue)}
/* Map */
.map-wrap{position:relative;width:100%;max-width:800px;margin:20px auto;aspect-ratio:2/1;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
.map-svg{width:100%;height:100%}
.map-dot{cursor:pointer;transition:r .15s}
.map-dot:hover{r:6}
.map-tooltip{position:absolute;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:8px 12px;font-size:0.78rem;pointer-events:none;opacity:0;transition:opacity .15s;z-index:10;white-space:nowrap}
/* Health signals */
.signal-row{display:flex;gap:12px;padding:10px 14px;background:var(--surface);border:1px solid var(--border);border-radius:6px;margin-bottom:6px;align-items:flex-start}
.signal-status{font-size:0.8rem;font-weight:600;white-space:nowrap;min-width:48px;text-align:center;padding:2px 0;border-radius:4px}
.signal-status.pass{color:var(--green)}.signal-status.warn{color:var(--yellow)}.signal-status.fail{color:var(--red)}.signal-status.info{color:var(--blue)}
.signal-body{flex:1;min-width:0}
.signal-label{font-weight:500;font-size:0.85rem}
.signal-detail{color:var(--muted);font-size:0.8rem;margin-top:2px;word-break:break-word}
.signal-explain{color:var(--dim);font-size:0.75rem;margin-top:4px;font-style:italic}
.signal-fix{color:var(--teal);font-size:0.78rem;margin-top:4px}
.auto-refresh{display:flex;align-items:center;gap:8px;margin-bottom:16px;font-size:0.82rem;color:var(--muted)}
.auto-refresh label{cursor:pointer;display:flex;align-items:center;gap:6px}
.auto-refresh input[type=checkbox]{accent-color:var(--cyan)}
.prop-controls{margin-bottom:16px;display:flex;align-items:center;gap:12px}
.prop-type-label{font-size:0.82rem;color:var(--muted);display:flex;align-items:center;gap:6px}
.prop-type-select{background:var(--surface);color:var(--fg);border:1px solid var(--border);border-radius:4px;padding:4px 8px;font-size:0.82rem;font-family:var(--mono)}
.anomaly{border-color:var(--yellow) !important;background:rgba(234,179,8,0.05) !important}
.summary-bar{display:flex;gap:16px;margin-bottom:16px;flex-wrap:wrap;padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);font-size:0.82rem}
.summary-item{display:flex;flex-direction:column;gap:2px}
.summary-label{color:var(--muted);font-size:0.72rem;text-transform:uppercase;letter-spacing:0.5px}
.summary-value{font-family:var(--mono);font-weight:600;color:var(--cyan)}
.cross-links{display:flex;gap:8px;margin-top:16px;flex-wrap:wrap}
.cross-link{padding:6px 14px;background:var(--surface);border:1px solid var(--border);border-radius:6px;font-family:var(--mono);font-size:0.78rem;color:var(--muted);transition:all .2s}
.cross-link:hover{color:var(--cyan);border-color:var(--cyan);text-decoration:none}
.grade{font-family:var(--mono);font-size:3rem;font-weight:700;margin-right:12px}
.grade-a{color:var(--green)}.grade-b{color:var(--teal)}.grade-c{color:var(--yellow)}.grade-d{color:var(--orange)}.grade-f{color:var(--red)}
/* Curl hint */
.curl-hint{margin-top:24px;padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);font-family:var(--mono);font-size:0.8rem;color:var(--muted);overflow-x:auto}
.curl-hint code{color:var(--cyan)}
.copy-btn{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:6px 12px;color:var(--muted);font-family:var(--mono);font-size:0.78rem;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:4px}
.copy-btn:hover{color:var(--cyan);border-color:var(--cyan)}
.copy-btn.copied{color:var(--green);border-color:var(--green)}
.family-header{display:flex;gap:12px;justify-content:center;margin-top:8px}
.family-header a{font-family:var(--mono);font-size:0.75rem;color:var(--dim);transition:color .2s}
.family-header a:hover{color:var(--cyan);text-decoration:none}
.family-header a.current{color:var(--cyan)}
/* Footer */
.footer{text-align:center;padding:48px 0 24px;color:var(--dim);font-size:0.78rem}
.footer a{color:var(--muted)}
.family{display:flex;gap:16px;justify-content:center;margin-bottom:12px;flex-wrap:wrap}
.family a{padding:4px 10px;border:1px solid var(--border);border-radius:4px;font-family:var(--mono);font-size:0.78rem;color:var(--muted);transition:color .2s,border-color .2s}
.family a:hover{color:var(--cyan);border-color:var(--cyan);text-decoration:none}
/* Loading */
.loading{text-align:center;padding:40px;color:var(--muted)}
.spinner{display:inline-block;width:20px;height:20px;border:2px solid var(--border);border-top-color:var(--cyan);border-radius:50%;animation:spin .6s linear infinite;margin-right:8px;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
/* Empty state */
.empty{text-align:center;padding:60px 20px;color:var(--muted)}
.empty h2{color:var(--text);font-size:1.2rem;margin-bottom:8px}
.empty p{max-width:480px;margin:0 auto;line-height:1.8}
.empty code{color:var(--cyan);background:var(--surface);padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:0.85rem}
.examples{display:flex;gap:8px;justify-content:center;margin-top:20px;flex-wrap:wrap}
.examples a{padding:6px 14px;background:var(--surface);border:1px solid var(--border);border-radius:6px;font-family:var(--mono);font-size:0.82rem;color:var(--cyan);transition:background .2s}
.examples a:hover{background:var(--surface2);text-decoration:none}
/* Responsive */
@media(max-width:640px){
  .header{padding:32px 0 20px}.logo{font-size:1.8rem}
  .record-row{grid-template-columns:1fr;gap:4px}
  .prop-grid{grid-template-columns:1fr}
}
</style>
</head>
<body>
<div class="container">
  <header class="header">
    <div class="logo"><span>ns</span>.lol</div>
    <div class="tagline">fast, API-first DNS toolkit</div>
    <div class="family-header">
      <a href="https://yoke.lol">yoke.lol</a>
      <span style="color:var(--border)">·</span>
      <a href="https://certs.lol">certs.lol</a>
      <span style="color:var(--border)">·</span>
      <a href="https://ns.lol" class="current">ns.lol</a>
    </div>
    <div class="search-wrap">
      <input type="text" class="search-input" id="domainInput" placeholder="example.com or 1.2.3.4" value="${escapeHtml(currentDomain)}" autocomplete="off" spellcheck="false" autofocus>
      <button class="search-btn" id="searchBtn" onclick="doSearch()">Lookup</button>
    </div>
  </header>

  <div id="content">
    ${currentDomain ? '<div class="loading"><span class="spinner"></span> Querying resolvers...</div>' : renderEmpty()}
  </div>

  <div id="curlHint" class="curl-hint" style="display:${currentDomain ? 'block' : 'none'}">
    <code>curl -s https://ns.lol/${escapeHtml(currentDomain)} | jq</code>
    <button class="copy-btn" onclick="copyLink()" style="margin-left:12px" title="Copy shareable link">📋 Copy Link</button>
  </div>

  <footer class="footer">
    <div class="family">
      <a href="https://yoke.lol">yoke.lol</a>
      <a href="https://certs.lol">certs.lol</a>
      <a href="https://ns.lol" class="active" style="color:var(--cyan);border-color:var(--cyan)">ns.lol</a>
    </div>
    <div>API-first DNS toolkit &middot; No accounts &middot; No tracking</div>
  </footer>
</div>

<div class="map-tooltip" id="mapTooltip"></div>

<script>
const INITIAL_DATA = ${jsonData};
const INITIAL_PATH = ${JSON.stringify(path)};
const INITIAL_DOMAIN = ${JSON.stringify(currentDomain)};

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

// State
let currentData = INITIAL_DATA;
let activeTab = 'records';

// Boot
if (INITIAL_DOMAIN && Object.keys(INITIAL_DATA).length > 0) {
  renderResults(INITIAL_DATA);
} else if (INITIAL_DOMAIN) {
  fetchDomain(INITIAL_DOMAIN);
}

// Search
$('#domainInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') doSearch();
});

function doSearch() {
  const val = $('#domainInput').value.trim().toLowerCase().replace(/^https?:\\/\\//, '').replace(/\\/.*$/, '');
  if (!val) return;
  history.pushState(null, '', '/' + val);
  document.title = val + ' — ns.lol';
  fetchDomain(val);
}

async function fetchDomain(domain) {
  $('#content').innerHTML = '<div class="loading"><span class="spinner"></span> Querying resolvers...</div>';
  $('#curlHint').style.display = 'block';
  $('#curlHint').querySelector('code').textContent = 'curl -s https://ns.lol/' + domain + ' | jq';

  try {
    const resp = await fetch('/' + domain, { headers: { 'Accept': 'application/dns-json' } });
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
  html += '<div class="summary-item"><div class="summary-label">Status</div><div class="summary-value" style="color:' + (data.hostnames.length > 0 ? 'var(--green)' : 'var(--red)') + '">' + (data.hostnames.length > 0 ? 'Found' : 'No rDNS') + '</div></div>';
  html += '</div>';

  if (data.hostnames.length > 0) {
    html += '<div class="record-section"><h3>Hostnames</h3><table class="record-table"><thead><tr><th>Hostname</th><th>TTL</th><th></th></tr></thead><tbody>';
    for (const rec of (data.ptr_records || [])) {
      const hostname = rec.data.replace(/\\.$/, '');
      html += '<tr><td>' + esc(hostname) + '</td><td>' + (rec.TTL || '') + '</td>';
      html += '<td><a href="/' + esc(hostname) + '" style="color:var(--cyan);text-decoration:none">Lookup →</a></td></tr>';
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
    html += '<div class="summary-item"><div class="summary-label">DNSSEC</div><div class="summary-value" style="color:' + (s.dnssec === 'authenticated' ? 'var(--green)' : s.dnssec === 'signed' ? 'var(--yellow)' : 'var(--dim)') + '">' + s.dnssec + '</div></div>';
    if (s.cdn) html += '<div class="summary-item"><div class="summary-label">CDN</div><div class="summary-value">' + esc(s.cdn) + '</div></div>';
    html += '</div>';
  }

  // Tabs
  html += '<div class="tabs" id="tabs">';
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
  html += '<div class="panel" id="panel-propagation"><div class="loading"><span class="spinner"></span> Checking propagation...</div></div>';

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
  html += '<a class="cross-link" href="https://yoke.lol/' + domain + '" target="_blank">📊 Full Analysis</a>';
  html += '</div>';

  $('#content').innerHTML = html;

  // Tab clicks
  $$('.tab').forEach((t) => {
    t.addEventListener('click', () => switchTab(t.dataset.tab));
  });

  activeTab = 'records';
}

function tab(id, label) {
  return '<div class="tab' + (id === 'records' ? ' active' : '') + '" data-tab="' + id + '">' + label + '</div>';
}

function switchTab(tabId) {
  activeTab = tabId;
  $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === tabId));
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
    const resp = await fetch('/' + domain + '/propagation?type=' + propType, { headers: { 'Accept': 'application/dns-json' } });
    const data = await resp.json();
    panel.innerHTML = renderPropagationControls(propType) + renderPropagation(data);
    // Wire up type selector
    const sel = $('#propTypeSelect');
    if (sel) {
      sel.addEventListener('change', () => {
        panel.dataset.propType = sel.value;
        panel.dataset.loaded = '';
        stopAutoRefresh();
        panel.innerHTML = '<div class="loading"><span class="spinner"></span> Checking ' + sel.value + ' propagation...</div>';
        loadPropagation(domain, panel);
      });
    }
    renderMap(data.results || []);
    startTTLCountdowns();
    // Start auto-refresh if not fully propagated
    const cb = $('#autoRefresh');
    if (cb) {
      cb.addEventListener('change', () => {
        if (cb.checked) startAutoRefresh();
        else stopAutoRefresh();
      });
      if (cb.checked && data.propagation && data.propagation.percentage < 100) {
        startAutoRefresh();
      }
    }
  } catch (err) {
    panel.innerHTML = '<div class="empty"><p>Failed to load propagation data</p></div>';
  }
}

async function loadHealth(domain, panel) {
  try {
    const resp = await fetch('/' + domain + '/health', { headers: { 'Accept': 'application/dns-json' } });
    const data = await resp.json();
    panel.innerHTML = renderHealth(data);
  } catch (err) {
    panel.innerHTML = '<div class="empty"><p>Failed to load health data</p></div>';
  }
}

async function loadEmail(domain, panel) {
  try {
    const resp = await fetch('/' + domain + '/email', { headers: { 'Accept': 'application/dns-json' } });
    const data = await resp.json();
    panel.innerHTML = renderEmail(data);
  } catch (err) {
    panel.innerHTML = '<div class="empty"><p>Failed to load email data</p></div>';
  }
}

async function loadSecurity(domain, panel) {
  try {
    const resp = await fetch('/' + domain + '/security', { headers: { 'Accept': 'application/dns-json' } });
    const data = await resp.json();
    panel.innerHTML = renderSecurity(data);
  } catch (err) {
    panel.innerHTML = '<div class="empty"><p>Failed to load security data</p></div>';
  }
}

async function loadSecurity(domain, panel) {
  try {
    const resp = await fetch('/' + domain + '/security', { headers: { 'Accept': 'application/dns-json' } });
    const data = await resp.json();
    panel.innerHTML = renderSecurity(data);
  } catch (err) {
    panel.innerHTML = '<div class="empty"><p>Failed to load security data</p></div>';
  }
}

async function loadTrace(domain, panel) {
  try {
    const resp = await fetch('/' + domain + '/trace', { headers: { 'Accept': 'application/dns-json' } });
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
    html += '<div style="background:var(--surface2);border:1px solid var(--border);border-radius:50%;width:28px;height:28px;display:flex;align-items:center;justify-content:center;font-family:var(--mono);font-size:0.75rem;font-weight:600;color:var(--cyan);flex-shrink:0">' + step.step + '</div>';
    html += '<div style="flex:1">';
    html += '<div style="font-weight:500;font-size:0.85rem">' + esc(step.label) + '</div>';
    html += '<div style="color:var(--muted);font-size:0.78rem;font-family:var(--mono)">' + esc(step.query || '') + '</div>';
    html += '</div>';
    if (step.query_time_ms) html += '<div style="color:var(--dim);font-size:0.72rem">' + step.query_time_ms + 'ms</div>';
    html += '</div>';

    if (step.error) {
      html += '<div style="color:var(--red);font-size:0.82rem;margin-left:40px">Error: ' + esc(step.error) + '</div>';
    }

    if (step.nameservers && step.nameservers.length > 0) {
      html += '<div style="margin-left:40px;display:flex;flex-wrap:wrap;gap:4px">';
      for (const ns of step.nameservers) {
        html += '<span style="background:var(--surface2);padding:2px 8px;border-radius:4px;font-family:var(--mono);font-size:0.75rem;color:var(--teal)">' + esc(ns) + '</span>';
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
          html += '<div style="font-size:0.78rem;color:var(--red)">' + esc(rr.resolver) + ': ' + esc(rr.error) + '</div>';
        } else {
          const ips = (rr.records || []).map(function(r) { return esc(r.data); }).join(', ');
          html += '<div style="font-size:0.78rem"><span style="color:var(--muted)">' + esc(rr.resolver) + ':</span> ';
          html += '<span style="color:var(--cyan);font-family:var(--mono)">' + ips + '</span>';
          html += ' <span style="color:var(--dim)">' + (rr.aa ? '[AA]' : '') + (rr.ad ? ' [AD]' : '') + ' ' + rr.rcode + ' ' + rr.query_time_ms + 'ms</span>';
          html += '</div>';
        }
      }
      html += '</div>';
    }

    if (step.primary_ns) {
      html += '<div style="margin-left:40px;font-size:0.78rem">';
      html += '<span style="color:var(--muted)">Primary NS:</span> <span style="color:var(--cyan);font-family:var(--mono)">' + esc(step.primary_ns) + '</span>';
      if (step.serial) html += ' &middot; <span style="color:var(--muted)">Serial:</span> <span style="font-family:var(--mono)">' + step.serial + '</span>';
      html += '</div>';
    }

    if (step.ds_records !== undefined) {
      const chainColor = step.chain_intact ? 'var(--green)' : 'var(--red)';
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
      html += '<div class="data">' + esc(r.data) + '</div>';
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

  // Auto-refresh control
  html += '<div class="auto-refresh">';
  html += '<label><input type="checkbox" id="autoRefresh" ' + (p.percentage < 100 ? 'checked' : '') + '> Auto-refresh every 30s</label>';
  if (p.percentage < 100) html += '<span id="refreshCountdown" style="color:var(--dim)"></span>';
  html += '</div>';

  html += '<div class="prop-summary">';
  html += '<div class="prop-pct ' + pctClass + '">' + p.percentage + '%</div>';
  html += '<div><div class="prop-status">' + p.status.replace('_',' ') + '</div>';
  const responded = p.resolvers_responded || (p.resolvers_queried - (p.resolvers_errored || 0));
  const errored = p.resolvers_errored || 0;
  html += '<div style="color:var(--dim);font-size:0.78rem">' + responded + '/' + p.resolvers_queried + ' resolvers responded';
  if (p.distinct_answers > 1) {
    html += ' &middot; ' + p.distinct_answers + ' distinct answer(s)';
    if (typeof p.consistency === 'number' && p.consistency < 100) {
      html += ' &middot; <span style="color:var(--cyan)">' + p.consistency + '% consistent</span>';
    }
  }
  if (errored > 0) html += ' &middot; <span style="color:var(--yellow)">' + errored + ' failed</span>';
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

  // Continent outlines (simplified equirectangular projection, 800x400)
  const continents = [
    'M111,89L122,78L133,67L156,56L178,49L200,56L222,67L256,89L278,93L244,102L222,129L211,133L184,144L167,156L178,167L211,178L222,182L216,167L200,156L189,144L178,133L167,129L144,129L133,122L122,107L111,89Z',
    'M222,178L233,189L256,200L278,211L289,200L300,211L322,222L318,233L311,249L300,251L293,262L278,273L271,284L256,293L249,311L233,318L244,300L240,278L244,244L233,233L227,211L222,200L222,178Z',
    'M378,120L389,120L400,116L411,104L407,96L389,93L378,84L389,78L411,80L422,78L433,80L444,78L462,76L467,67L462,56L456,44L440,49L422,62L411,67L400,71L389,78L378,84L378,120Z',
    'M367,133L378,120L400,116L422,118L433,127L456,133L471,133L478,140L489,173L511,173L511,196L493,204L489,222L478,244L467,262L456,276L440,278L433,267L427,244L422,211L411,189L389,189L378,178L360,169L362,156L367,133Z',
    'M467,67L489,56L511,56L533,44L556,40L578,44L600,56L622,78L644,100L667,111L678,122L689,122L700,122L711,111L722,100L711,89L700,78L711,67L733,67L756,62L778,56L800,56L800,67L778,78L756,89L733,93L711,100L700,111L689,129L678,133L667,151L644,156L633,178L622,196L611,182L578,178L567,167L556,151L544,144L533,144L511,144L500,167L489,173L478,140L471,133L456,133L462,111L462,76L467,67Z',
    'M656,233L667,229L689,227L700,233L707,240L722,233L733,249L740,262L729,276L711,278L693,271L678,267L656,256L651,249L656,233Z',
  ];

  let svgContent = '<rect width="800" height="400" fill="var(--surface)" rx="0"/>';

  // Subtle grid
  for (let x = 0; x < 800; x += 100) {
    svgContent += '<line x1="' + x + '" y1="0" x2="' + x + '" y2="400" stroke="var(--border)" stroke-width="0.3" opacity="0.4"/>';
  }
  for (let y = 0; y < 400; y += 100) {
    svgContent += '<line x1="0" y1="' + y + '" x2="800" y2="' + y + '" stroke="var(--border)" stroke-width="0.3" opacity="0.4"/>';
  }

  // Draw continents
  for (const path of continents) {
    svgContent += '<path d="' + path + '" fill="var(--surface2)" stroke="var(--border)" stroke-width="0.8" opacity="0.6"/>';
  }

  // Plot resolver dots with glow effect
  for (const r of results) {
    const x = ((r.lng + 180) / 360) * 800;
    const y = ((90 - r.lat) / 180) * 400;
    const color = r.error ? 'var(--red)' : r.rcode === 'NOERROR' ? 'var(--green)' : 'var(--yellow)';

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
      tooltip.innerHTML = '<strong>' + d.name + '</strong><br>' + d.loc + '<br><span style="color:var(--cyan)">' + d.val + '</span><br><span style="color:var(--dim)">' + d.time + '</span>';
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
  if (h.pass) html += '<span style="color:var(--green)">' + h.pass + ' pass</span> ';
  if (h.warn) html += '<span style="color:var(--yellow)">' + h.warn + ' warn</span> ';
  if (h.fail) html += '<span style="color:var(--red)">' + h.fail + ' fail</span> ';
  if (h.info) html += '<span style="color:var(--blue)">' + h.info + ' info</span>';
  html += '</div></div></div>';

  // Signals grouped by category
  const grouped = {};
  for (const s of (data.signals || [])) {
    if (!grouped[s.category]) grouped[s.category] = [];
    grouped[s.category].push(s);
  }

  for (const [cat, sigs] of Object.entries(grouped)) {
    html += '<div style="margin-bottom:16px"><div style="font-weight:600;font-size:0.85rem;color:var(--cyan);margin-bottom:6px">' + esc(cat) + '</div>';
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
  if (e.pass) html += '<span style="color:var(--green)">' + e.pass + ' pass</span> ';
  if (e.warn) html += '<span style="color:var(--yellow)">' + e.warn + ' warn</span> ';
  if (e.fail) html += '<span style="color:var(--red)">' + e.fail + ' fail</span> ';
  if (e.info) html += '<span style="color:var(--blue)">' + e.info + ' info</span>';
  html += '</div></div></div>';

  const grouped = {};
  for (const s of (data.signals || [])) {
    if (!grouped[s.category]) grouped[s.category] = [];
    grouped[s.category].push(s);
  }

  for (const [cat, sigs] of Object.entries(grouped)) {
    html += '<div style="margin-bottom:16px"><div style="font-weight:600;font-size:0.85rem;color:var(--cyan);margin-bottom:6px">' + esc(cat) + '</div>';
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
  if (sec.pass) html += '<span style="color:var(--green)">' + sec.pass + ' pass</span> ';
  if (sec.warn) html += '<span style="color:var(--yellow)">' + sec.warn + ' warn</span> ';
  if (sec.fail) html += '<span style="color:var(--red)">' + sec.fail + ' fail</span> ';
  if (sec.info) html += '<span style="color:var(--blue)">' + sec.info + ' info</span>';
  html += '</div></div></div>';

  const grouped = {};
  for (const s of (data.signals || [])) {
    if (!grouped[s.category]) grouped[s.category] = [];
    grouped[s.category].push(s);
  }

  for (const [cat, sigs] of Object.entries(grouped)) {
    html += '<div style="margin-bottom:16px"><div style="font-weight:600;font-size:0.85rem;color:var(--cyan);margin-bottom:6px">' + esc(cat) + '</div>';
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
let autoRefreshTimer = null;
let autoRefreshCountdown = 30;

function startAutoRefresh() {
  stopAutoRefresh();
  const domain = currentData.domain || INITIAL_DOMAIN;
  if (!domain) return;

  autoRefreshCountdown = 30;
  updateCountdown();

  autoRefreshTimer = setInterval(() => {
    autoRefreshCountdown--;
    updateCountdown();
    if (autoRefreshCountdown <= 0) {
      autoRefreshCountdown = 30;
      refreshPropagation(domain);
    }
  }, 1000);
}

function stopAutoRefresh() {
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }
}

function updateCountdown() {
  const el = $('#refreshCountdown');
  if (el) el.textContent = 'refreshing in ' + autoRefreshCountdown + 's';
}

async function refreshPropagation(domain) {
  const panel = $('#panel-propagation');
  if (!panel || activeTab !== 'propagation') { stopAutoRefresh(); return; }
  try {
    const propType = (panel.dataset.propType || 'A').toUpperCase();
    const resp = await fetch('/' + domain + '/propagation?type=' + propType + '&force=true', { headers: { 'Accept': 'application/dns-json' } });
    const data = await resp.json();
    panel.innerHTML = renderPropagationControls(propType) + renderPropagation(data);
    // Re-wire type selector
    const sel = $('#propTypeSelect');
    if (sel) {
      sel.addEventListener('change', () => {
        panel.dataset.propType = sel.value;
        panel.dataset.loaded = '';
        stopAutoRefresh();
        panel.innerHTML = '<div class="loading"><span class="spinner"></span> Checking ' + sel.value + ' propagation...</div>';
        loadPropagation(domain, panel);
      });
    }
    renderMap(data.results || []);
    startTTLCountdowns();
    // Re-attach auto-refresh checkbox handler
    const cb = $('#autoRefresh');
    if (cb) {
      cb.addEventListener('change', () => {
        if (cb.checked) startAutoRefresh();
        else stopAutoRefresh();
      });
    }
    // Stop auto-refresh if fully propagated
    if (data.propagation && data.propagation.percentage >= 100) {
      stopAutoRefresh();
    }
  } catch { }
}

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
        if (remaining <= 30) el.style.color = 'var(--red)';
        else if (remaining <= 120) el.style.color = 'var(--yellow)';
      } else {
        el.textContent = 'expired';
        el.style.color = 'var(--red)';
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
  return `<div class="empty">
    <h2>DNS at the speed of thought</h2>
    <p>Enter a domain above or use the API directly:</p>
    <p style="margin-top:12px"><code>curl -s https://ns.lol/example.com | jq</code></p>
    <p style="margin-top:8px;font-size:0.82rem"><code>/domain</code> full report &middot; <code>/domain/a</code> specific type &middot; <code>/domain/propagation</code> multi-resolver &middot; <code>/domain/health</code> zone health &middot; <code>/domain/email</code> email audit &middot; <code>/domain/security</code> security checks</p>
    <div class="examples">
      <a href="/cloudflare.com">cloudflare.com</a>
      <a href="/google.com">google.com</a>
      <a href="/github.com">github.com</a>
      <a href="/example.com">example.com</a>
    </div>
  </div>`;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
