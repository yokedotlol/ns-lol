// SPA renderer — full terminal-aesthetic UI for browser clients
// Blue/cyan palette, dark-mode-first, Inter + JetBrains Mono

export function renderSPA(data: any, path: string, domain?: string): string {
  const jsonData = JSON.stringify(data || {});
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
.grade{font-family:var(--mono);font-size:3rem;font-weight:700;margin-right:12px}
.grade-a{color:var(--green)}.grade-b{color:var(--teal)}.grade-c{color:var(--yellow)}.grade-d{color:var(--orange)}.grade-f{color:var(--red)}
/* Curl hint */
.curl-hint{margin-top:24px;padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);font-family:var(--mono);font-size:0.8rem;color:var(--muted);overflow-x:auto}
.curl-hint code{color:var(--cyan)}
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
    <div class="search-wrap">
      <input type="text" class="search-input" id="domainInput" placeholder="example.com" value="${escapeHtml(currentDomain)}" autocomplete="off" spellcheck="false" autofocus>
      <button class="search-btn" id="searchBtn" onclick="doSearch()">Lookup</button>
    </div>
  </header>

  <div id="content">
    ${currentDomain ? '<div class="loading"><span class="spinner"></span> Querying resolvers...</div>' : renderEmpty()}
  </div>

  <div id="curlHint" class="curl-hint" style="display:${currentDomain ? 'block' : 'none'}">
    <code>curl -s https://ns.lol/${escapeHtml(currentDomain)} | jq</code>
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

function renderResults(data) {
  if (data.error) {
    $('#content').innerHTML = '<div class="empty"><h2>Error</h2><p>' + esc(data.error) + '</p></div>';
    return;
  }

  // Full report with tabs
  let html = '<div class="tabs" id="tabs">';
  html += tab('records', 'Records');
  html += tab('propagation', 'Propagation');
  html += tab('health', 'Health');
  html += tab('email', 'Email');
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

  // Health panel (lazy load)
  html += '<div class="panel" id="panel-health"><div class="loading"><span class="spinner"></span> Running health check...</div></div>';

  // Email panel (lazy load)
  html += '<div class="panel" id="panel-email"><div class="loading"><span class="spinner"></span> Checking email DNS...</div></div>';

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
  } else if (tabId === 'health') {
    panel.dataset.loaded = '1';
    loadHealth(domain, panel);
  } else if (tabId === 'email') {
    panel.dataset.loaded = '1';
    loadEmail(domain, panel);
  }
}

async function loadPropagation(domain, panel) {
  try {
    const resp = await fetch('/' + domain + '/propagation', { headers: { 'Accept': 'application/dns-json' } });
    const data = await resp.json();
    panel.innerHTML = renderPropagation(data);
    renderMap(data.results || []);
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

function renderRecords(records) {
  if (!records || Object.keys(records).length === 0) {
    return '<div class="empty"><p>No DNS records found</p></div>';
  }
  let html = '';
  const order = ['A','AAAA','CNAME','MX','TXT','NS','SOA','CAA','HTTPS'];
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
      html += '<div class="ttl">TTL ' + r.TTL + '</div>';
      html += '</div>';
    }
    html += '</div>';
  }
  return html;
}

function renderPropagation(data) {
  if (!data.propagation) return '<div class="empty"><p>No propagation data</p></div>';
  const p = data.propagation;
  const pctClass = p.percentage >= 100 ? 'full' : p.percentage >= 50 ? 'partial' : 'low';

  let html = '<div class="prop-summary">';
  html += '<div class="prop-pct ' + pctClass + '">' + p.percentage + '%</div>';
  html += '<div><div class="prop-status">' + p.status.replace('_',' ') + '</div>';
  html += '<div style="color:var(--dim);font-size:0.78rem">' + p.resolvers_queried + ' resolvers queried &middot; ' + p.distinct_answers + ' distinct answer(s)</div></div>';
  html += '</div>';

  // Map placeholder
  html += '<div class="map-wrap"><svg class="map-svg" id="propMap" viewBox="0 0 800 400"></svg></div>';

  // Resolver grid
  html += '<div class="prop-grid">';
  for (const r of (data.results || [])) {
    const val = r.error ? '<span class="resolver-err">' + esc(r.error) + '</span>' :
      r.records.length === 0 ? '<span style="color:var(--dim)">No records</span>' :
      r.records.map(rec => esc(rec.data)).join('<br>');
    html += '<div class="resolver-card">';
    html += '<div><div class="resolver-name"><span class="dot ' + (r.error ? 'dot-fail' : r.rcode === 'NOERROR' ? 'dot-pass' : 'dot-warn') + '"></span>' + esc(r.resolver) + '</div>';
    html += '<div class="resolver-loc">' + esc(r.location) + '</div>';
    html += '<div class="resolver-time">' + r.query_time_ms + 'ms</div></div>';
    html += '<div class="resolver-val">' + val + '</div>';
    html += '</div>';
  }
  html += '</div>';
  return html;
}

function renderMap(results) {
  const svg = $('#propMap');
  if (!svg) return;

  // Simple world map outline (Mercator-ish projection)
  // Just dots on a dark background — no complicated paths needed
  let svgContent = '<rect width="800" height="400" fill="var(--surface)" rx="0"/>';

  // Grid lines
  for (let x = 0; x < 800; x += 80) {
    svgContent += '<line x1="' + x + '" y1="0" x2="' + x + '" y2="400" stroke="var(--border)" stroke-width="0.5"/>';
  }
  for (let y = 0; y < 400; y += 80) {
    svgContent += '<line x1="0" y1="' + y + '" x2="800" y2="' + y + '" stroke="var(--border)" stroke-width="0.5"/>';
  }

  // Plot resolver dots
  for (const r of results) {
    const x = ((r.lng + 180) / 360) * 800;
    const y = ((90 - r.lat) / 180) * 400;
    const color = r.error ? 'var(--red)' : r.rcode === 'NOERROR' ? 'var(--green)' : 'var(--yellow)';

    svgContent += '<circle class="map-dot" cx="' + x + '" cy="' + y + '" r="4.5" fill="' + color + '" stroke="' + color + '" stroke-width="1" opacity="0.85"' +
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
  if (s.explain) html += '<div class="signal-explain">' + esc(s.explain) + '</div>';
  html += '</div></div>';
  return html;
}

function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
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
    <p style="margin-top:8px;font-size:0.82rem"><code>/domain</code> full report &middot; <code>/domain/a</code> specific type &middot; <code>/domain/propagation</code> multi-resolver &middot; <code>/domain/health</code> zone health &middot; <code>/domain/email</code> email audit</p>
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
