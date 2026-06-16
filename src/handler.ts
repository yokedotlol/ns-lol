// Request handler — routes paths to DNS operations

import { Env } from './worker';
import { queryAllResolvers, querySingle, queryDoH, getRecordTypeNumber, RECORD_TYPES, DOH_RESOLVERS, rcodeName, ResolverResult } from './dns';
import { runHealthCheck } from './health';
import { runEmailCheck } from './email';
import { runSecurityCheck, detectCDNFromRecords } from './security';

// Supported DNS record types for single lookups
const RECORD_TYPE_SLUGS = new Set(
  Object.keys(RECORD_TYPES).map((t) => t.toLowerCase())
);

// Validate domain name (supports IDN via punycode)
// Check if input is an IP address (v4 or v6)
function isIPv4(s: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split('.').every(o => parseInt(o) <= 255);
}

function isIPv6(s: string): boolean {
  // Simplified: contains colons, valid hex groups
  return /^[0-9a-f:]+$/i.test(s) && s.includes(':');
}

// Convert IP to reverse DNS domain
export function ipToReverseDomain(ip: string): string {
  if (isIPv4(ip)) {
    return ip.split('.').reverse().join('.') + '.in-addr.arpa';
  }
  // IPv6: expand :: to full 8 groups, pad each to 4 hex chars, reverse nibbles
  let groups: string[];
  if (ip.includes('::')) {
    const [left, right] = ip.split('::');
    const leftGroups = left ? left.split(':') : [];
    const rightGroups = right ? right.split(':') : [];
    const missing = 8 - leftGroups.length - rightGroups.length;
    groups = [...leftGroups, ...Array(missing).fill('0000'), ...rightGroups];
  } else {
    groups = ip.split(':');
  }
  const hex = groups.map(g => g.padStart(4, '0')).join('');
  return hex.split('').reverse().join('.') + '.ip6.arpa';
}

function validateDomain(input: string): string {
  let domain = input.replace(/\.$/, '').toLowerCase();
  // Strip protocol if pasted URL
  domain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');

  // Convert Unicode IDN to punycode (e.g. 例え.jp → xn--r8jz45g.jp)
  if (/[^\x00-\x7F]/.test(domain)) {
    try {
      // Use URL constructor to leverage built-in IDN/punycode handling
      const url = new URL(`http://${domain}`);
      domain = url.hostname;
    } catch {
      throw Object.assign(new Error('Invalid domain name'), { status: 400 });
    }
  }

  if (domain.length < 1 || domain.length > 253) {
    throw Object.assign(new Error('Invalid domain name'), { status: 400 });
  }
  // Allow punycode (xn--) and normal labels
  if (!/^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$/.test(domain)) {
    throw Object.assign(new Error('Invalid domain name'), { status: 400 });
  }
  if (!domain.includes('.')) {
    throw Object.assign(new Error('Please provide a fully qualified domain name (e.g. example.com)'), { status: 400 });
  }
  return domain;
}

// Format TTL as human-readable
export function humanTTL(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) {
    const h = Math.floor(seconds / 3600);
    const m = Math.round((seconds % 3600) / 60);
    return m > 0 ? `${h}h ${m}m` : `${h}h`;
  }
  const d = Math.floor(seconds / 86400);
  const h = Math.round((seconds % 86400) / 3600);
  return h > 0 ? `${d}d ${h}h` : `${d}d`;
}

export async function handleDNSRequest(url: URL, request: Request, env: Env): Promise<any> {
  const parts = url.pathname.slice(1).split('/').filter(Boolean);

  if (parts.length === 0) {
    throw Object.assign(new Error('No domain specified'), { status: 400 });
  }

  // Special routes
  if (parts[0] === 'api' && parts[1] === 'docs') {
    return apiDocs();
  }

  // Batch endpoint
  if (parts[0] === 'batch' && request.method === 'POST') {
    return batchCheck(request, env);
  }

  const rawInput = parts[0].replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '').toLowerCase();

  // Reverse DNS lookup — detect IP addresses
  if (isIPv4(rawInput) || isIPv6(rawInput)) {
    return reverseLookup(rawInput, url.searchParams.get('explain') === 'true');
  }

  const domain = validateDomain(parts[0]);
  const action = parts[1]?.toLowerCase();
  const explain = url.searchParams.get('explain') === 'true';
  const expected = url.searchParams.get('expected') || null;
  const force = url.searchParams.get('force') === 'true';

  // Check cache unless forced — explain bypasses cache too since it adds data
  if (!force && !explain && action !== 'propagation') {
    const cacheKey = `dns:${domain}:${action || 'full'}`;
    const cached = await env.CACHE.get(cacheKey, 'json');
    if (cached) {
      return { ...(cached as object), _cached: true, _cache_control: 'public, max-age=60' };
    }
  }

  let result: any;

  if (!action) {
    result = await fullReport(domain, explain);
  } else if (action === 'propagation') {
    result = await propagationCheck(domain, url, expected, explain, env);
  } else if (action === 'health') {
    result = await runHealthCheck(domain, env, explain);
  } else if (action === 'email') {
    result = await runEmailCheck(domain, explain);
  } else if (action === 'security') {
    result = await runSecurityCheck(domain, explain);
  } else if (action === 'any') {
    result = await anyQuery(domain, explain);
  } else if (action === 'trace') {
    result = await authorityTrace(domain, explain);
  } else if (RECORD_TYPE_SLUGS.has(action)) {
    result = await singleLookup(domain, action.toUpperCase(), explain);
  } else if (/^\d+$/.test(action)) {
    // Custom QTYPE — accept numeric record type (e.g., /example.com/65 for HTTPS)
    const typeNum = parseInt(action, 10);
    if (typeNum < 1 || typeNum > 65535) {
      throw Object.assign(new Error('Invalid record type number (1-65535)'), { status: 400 });
    }
    result = await numericLookup(domain, typeNum, explain);
  } else {
    throw Object.assign(
      new Error(`Unknown action: ${action}. Use a record type (a, aaaa, mx, ...), a numeric type (1-65535), or: propagation, health, email, security, any, trace`),
      { status: 400 }
    );
  }

  // Cache result (skip if forced refresh or explain mode — don't pollute cache)
  if (action !== 'propagation' && !force && !explain) {
    const cacheKey = `dns:${domain}:${action || 'full'}`;
    const ttl = action === 'health' || action === 'security' ? 21600 : 3600;
    await env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: ttl });
  }

  return result;
}

// ── Full Report ──────────────────────────────────────────────────────

async function fullReport(domain: string, explain: boolean): Promise<any> {
  const types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'CAA', 'HTTPS', 'DS'];
  const queries = types.map(async (type) => {
    try {
      const typeNum = getRecordTypeNumber(type);
      const result = await querySingle(domain, typeNum);
      return { type, records: result.records, rcode: result.rcode, ad: result.ad, query_time_ms: result.query_time_ms };
    } catch {
      return { type, records: [], rcode: 'ERROR', ad: false, query_time_ms: 0 };
    }
  });

  const results = await Promise.all(queries);
  const records: Record<string, any> = {};
  let dnssecAuthenticated = false;

  for (const r of results) {
    if (r.ad) dnssecAuthenticated = true;
    if (r.records.length > 0) {
      records[r.type] = {
        records: r.records.map((rec) => ({
          ...rec,
          ttl_human: humanTTL(rec.TTL),
        })),
        rcode: r.rcode,
        query_time_ms: r.query_time_ms,
      };
    }
  }

  // CDN detection from CNAME records
  const cnameRecords = results.find((r) => r.type === 'CNAME')?.records || [];
  const cdn = detectCDNFromRecords(cnameRecords);

  // Quick stats
  const totalRecords = Object.values(records).reduce((sum: number, r: any) => sum + r.records.length, 0);
  const avgQueryTime = results.length > 0
    ? Math.round(results.reduce((s, r) => s + r.query_time_ms, 0) / results.length)
    : 0;

  const report: any = {
    domain,
    query_time: new Date().toISOString(),
    resolver: 'Cloudflare',
    summary: {
      total_records: totalRecords,
      record_types: Object.keys(records).length,
      avg_query_time_ms: avgQueryTime,
      dnssec: dnssecAuthenticated ? 'authenticated' : results.find((r) => r.type === 'DS')?.records.length ? 'signed' : 'unsigned',
      ...(cdn && { cdn }),
    },
    records,
    _meta: {
      propagation: `https://ns.lol/${domain}/propagation`,
      health: `https://ns.lol/${domain}/health`,
      email: `https://ns.lol/${domain}/email`,
      security: `https://ns.lol/${domain}/security`,
      any: `https://ns.lol/${domain}/any`,
      trace: `https://ns.lol/${domain}/trace`,
      tls_report: `https://certs.lol/${domain}`,
      full_report: `https://yoke.lol/${domain}`,
    },
  };

  if (explain) {
    report._explain = explainRecords(records);
  }

  return report;
}

// ── ANY Query Simulation ──────────────────────────────────────────────

async function anyQuery(domain: string, explain: boolean): Promise<any> {
  const types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'CAA', 'HTTPS', 'DS', 'PTR', 'DNSKEY', 'NAPTR', 'TLSA'];
  const start = performance.now();
  const queries = types.map(async (type) => {
    try {
      const typeNum = getRecordTypeNumber(type);
      const result = await querySingle(domain, typeNum);
      return { type, records: result.records, rcode: result.rcode, ad: result.ad, query_time_ms: result.query_time_ms };
    } catch {
      return { type, records: [], rcode: 'ERROR', ad: false, query_time_ms: 0 };
    }
  });

  const results = await Promise.all(queries);
  const elapsed = Math.round(performance.now() - start);

  // Flatten all records
  const allRecords: any[] = [];
  let dnssecAuthenticated = false;

  for (const r of results) {
    if (r.ad) dnssecAuthenticated = true;
    for (const rec of r.records) {
      allRecords.push({
        ...rec,
        ttl_human: humanTTL(rec.TTL),
      });
    }
  }

  // Group by type
  const grouped: Record<string, any[]> = {};
  for (const rec of allRecords) {
    if (!grouped[rec.type]) grouped[rec.type] = [];
    grouped[rec.type].push(rec);
  }

  return {
    domain,
    query_time: new Date().toISOString(),
    type: 'ANY',
    note: 'Simulated ANY query — individual queries for each record type (RFC 8482 deprecated real ANY queries)',
    total_records: allRecords.length,
    types_found: Object.keys(grouped),
    dnssec_authenticated: dnssecAuthenticated,
    records: grouped,
    query_time_ms: elapsed,
    _meta: {
      full_report: `https://yoke.lol/${domain}`,
      tls_report: `https://certs.lol/${domain}`,
      full_analysis: `https://yoke.lol/${domain}`,
    },
    ...(explain && {
      _explain: {
        what: 'This simulates a DNS ANY query by querying all common record types individually.',
        why: 'RFC 8482 deprecated ANY queries — most resolvers now return minimal or empty responses to ANY. This gives you what ANY used to provide.',
        types_queried: types.join(', '),
      },
    }),
  };
}

// ── Custom Numeric QTYPE ──────────────────────────────────────────────

async function numericLookup(domain: string, typeNum: number, explain: boolean): Promise<any> {
  // Check if we have a name for this type
  const knownName = Object.entries(RECORD_TYPES).find(([, v]) => v === typeNum)?.[0];
  const typeName = knownName || `TYPE${typeNum}`;

  const result = await querySingle(domain, typeNum);

  const report: any = {
    domain,
    type: typeName,
    type_number: typeNum,
    query_time: new Date().toISOString(),
    resolver: result.resolver,
    rcode: result.rcode,
    records: result.records.map((r) => ({
      ...r,
      ttl_human: humanTTL(r.TTL),
    })),
    dnssec_authenticated: result.ad,
    query_time_ms: result.query_time_ms,
    _meta: {
      full_report: `https://yoke.lol/${domain}`,
      propagation: `https://ns.lol/${domain}/propagation?type=${typeName}`,
    },
  };

  if (explain) {
    report._explain = knownName
      ? explainType(knownName, result.records)
      : `Queried custom record type ${typeNum}. ${result.records.length} record(s) returned.`;
  }

  return report;
}

// ── Authority Chain Walk / Trace ──────────────────────────────────────

async function authorityTrace(domain: string, explain: boolean): Promise<any> {
  const start = performance.now();
  const steps: any[] = [];

  // Step 1: Query root servers for the TLD
  const labels = domain.split('.');
  const tld = labels[labels.length - 1];

  try {
    // Query a root hint (via Cloudflare, asking for NS of TLD)
    const rootResult = await querySingle(tld, getRecordTypeNumber('NS'));
    steps.push({
      step: 1,
      label: 'TLD NS Lookup',
      query: `${tld} NS`,
      nameservers: rootResult.records.filter(r => r.type === 'NS').map(r => r.data.replace(/\.$/, '')),
      rcode: rootResult.rcode,
      query_time_ms: rootResult.query_time_ms,
      ...(explain && { explain: `Found the nameservers responsible for the .${tld} TLD.` }),
    });
  } catch (err: any) {
    steps.push({ step: 1, label: 'TLD NS Lookup', query: `${tld} NS`, error: err.message });
  }

  // Step 2: Query NS for the domain itself
  try {
    const nsResult = await querySingle(domain, getRecordTypeNumber('NS'));
    const nameservers = nsResult.records.filter(r => r.type === 'NS').map(r => r.data.replace(/\.$/, ''));
    steps.push({
      step: 2,
      label: 'Domain NS Lookup',
      query: `${domain} NS`,
      nameservers,
      rcode: nsResult.rcode,
      aa: nsResult.aa,
      query_time_ms: nsResult.query_time_ms,
      ...(explain && { explain: `These are the authoritative nameservers for ${domain}.` }),
    });

    // Step 3: Query each authoritative NS directly for A records
    if (nameservers.length > 0) {
      // Resolve NS hostnames to IPs first
      const nsIPs: { ns: string; ip: string }[] = [];
      await Promise.all(
        nameservers.slice(0, 4).map(async (ns) => {
          try {
            const aResult = await querySingle(ns, getRecordTypeNumber('A'));
            for (const r of aResult.records) {
              if (r.type === 'A') nsIPs.push({ ns, ip: r.data });
            }
          } catch { /* skip */ }
        })
      );

      // Query authoritative NS directly via DoH (we can only use DoH from Workers,
      // so we'll query the domain via our regular resolvers and compare AA flags)
      const authResults: any[] = [];
      const resolverSubset = DOH_RESOLVERS.slice(0, 3);
      await Promise.all(
        resolverSubset.map(async (resolver) => {
          try {
            const result = await queryDoH(resolver.url, domain, getRecordTypeNumber('A'));
            authResults.push({
              resolver: resolver.name,
              records: result.answers.map(r => ({ ...r, ttl_human: humanTTL(r.TTL) })),
              rcode: rcodeName(result.rcode),
              aa: result.flags.aa,
              ad: result.flags.ad,
              query_time_ms: result.query_time_ms,
            });
          } catch (err: any) {
            authResults.push({ resolver: resolver.name, error: err.message });
          }
        })
      );

      steps.push({
        step: 3,
        label: 'A Record Resolution',
        query: `${domain} A`,
        authoritative_ns: nameservers,
        ns_ips: nsIPs,
        resolver_results: authResults,
        ...(explain && { explain: `Queried multiple resolvers for the final A record of ${domain}. The AA (Authoritative Answer) flag shows whether the response came directly from an authoritative server.` }),
      });
    }
  } catch (err: any) {
    steps.push({ step: 2, label: 'Domain NS Lookup', query: `${domain} NS`, error: err.message });
  }

  // Step 4: SOA check (authoritative info)
  try {
    const soaResult = await querySingle(domain, getRecordTypeNumber('SOA'));
    if (soaResult.records.length > 0) {
      const soaData = soaResult.records[0].data;
      const soaParts = soaData.split(/\s+/);
      steps.push({
        step: 4,
        label: 'SOA Record',
        query: `${domain} SOA`,
        primary_ns: soaParts[0]?.replace(/\.$/, ''),
        admin_email: soaParts[1]?.replace(/\.$/, '').replace('.', '@', ),
        serial: parseInt(soaParts[2], 10),
        rcode: soaResult.rcode,
        query_time_ms: soaResult.query_time_ms,
        ...(explain && { explain: `The SOA record identifies the primary nameserver and zone serial number.` }),
      });
    }
  } catch { /* non-critical */ }

  // Step 5: DNSSEC chain
  try {
    const dsResult = await querySingle(domain, getRecordTypeNumber('DS'));
    const dnskeyResult = await querySingle(domain, getRecordTypeNumber('DNSKEY'));

    if (dsResult.records.length > 0 || dnskeyResult.records.length > 0) {
      steps.push({
        step: 5,
        label: 'DNSSEC Chain',
        ds_records: dsResult.records.length,
        dnskey_records: dnskeyResult.records.length,
        chain_intact: dsResult.records.length > 0 && dnskeyResult.records.length > 0,
        ...(explain && {
          explain: dsResult.records.length > 0 && dnskeyResult.records.length > 0
            ? 'DNSSEC chain is intact: DS at parent links to DNSKEY at zone.'
            : dsResult.records.length > 0
              ? 'DS record exists at parent but no DNSKEY in zone — broken chain.'
              : 'DNSKEY exists but no DS at parent — zone is signed but parent hasn\'t published the trust anchor.',
        }),
      });
    }
  } catch { /* non-critical */ }

  const elapsed = Math.round(performance.now() - start);

  return {
    domain,
    query_time: new Date().toISOString(),
    trace: {
      steps: steps.length,
      total_time_ms: elapsed,
    },
    steps,
    _meta: {
      full_report: `https://yoke.lol/${domain}`,
      health: `https://ns.lol/${domain}/health`,
      tls_report: `https://certs.lol/${domain}`,
      full_analysis: `https://yoke.lol/${domain}`,
    },
    ...(explain && {
      _explain: {
        what: `Authority chain walk for ${domain} — traces the delegation path from TLD to authoritative nameservers to final answer.`,
        why: 'This reveals the full DNS delegation chain, helping diagnose issues like lame delegation, DNSSEC breaks, or misconfigured nameservers.',
      },
    }),
  };
}

// ── Batch Checking ────────────────────────────────────────────────────

async function batchCheck(request: Request, env: Env): Promise<any> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    throw Object.assign(new Error('Invalid JSON body'), { status: 400 });
  }

  const domains = body.domains;
  if (!Array.isArray(domains) || domains.length === 0) {
    throw Object.assign(new Error('Provide a "domains" array in the request body'), { status: 400 });
  }
  if (domains.length > 20) {
    throw Object.assign(new Error('Maximum 20 domains per batch request'), { status: 400 });
  }

  const type = (body.type || 'A').toUpperCase();
  const typeNum = getRecordTypeNumber(type);

  const results = await Promise.all(
    domains.map(async (d: string) => {
      try {
        const domain = validateDomain(d);
        const result = await querySingle(domain, typeNum);
        return {
          domain,
          type,
          rcode: result.rcode,
          records: result.records.map((r) => ({
            ...r,
            ttl_human: humanTTL(r.TTL),
          })),
          query_time_ms: result.query_time_ms,
        };
      } catch (err: any) {
        return {
          domain: d,
          type,
          error: err.message || 'Lookup failed',
        };
      }
    })
  );

  return {
    query_time: new Date().toISOString(),
    type,
    count: results.length,
    results,
  };
}

// ── Reverse DNS ───────────────────────────────────────────────────────

async function reverseLookup(ip: string, explain: boolean): Promise<any> {
  const ptrDomain = ipToReverseDomain(ip);
  const typeNum = getRecordTypeNumber('PTR');
  const start = performance.now();

  try {
    const result = await querySingle(ptrDomain, typeNum);
    const elapsed = Math.round(performance.now() - start);

    const hostnames = result.records
      .filter((r: any) => r.type === 'PTR')
      .map((r: any) => r.data.replace(/\.$/, ''));

    return {
      ip,
      type: isIPv4(ip) ? 'IPv4' : 'IPv6',
      reverse_domain: ptrDomain,
      hostnames,
      ptr_records: result.records.map((r: any) => ({
        ...r,
        ttl_human: humanTTL(r.TTL),
      })),
      rcode: result.rcode,
      query_time_ms: elapsed,
      ...(explain && {
        _explain: {
          what: `Reverse DNS (PTR) lookup converts an IP address to its associated hostname(s).`,
          how: `The IP ${ip} is converted to ${ptrDomain} and queried for PTR records.`,
          why: hostnames.length > 0
            ? `This IP resolves to: ${hostnames.join(', ')}. Reverse DNS is used for email authentication (SPF), logging, and security investigations.`
            : `No PTR record found. This means the IP has no reverse DNS configured. This can cause email delivery issues and may indicate a cloud/hosting IP without proper rDNS setup.`,
        },
      }),
      _meta: {
        full_report: `https://yoke.lol/${hostnames[0] || ip}`,
        tls_report: hostnames[0] ? `https://certs.lol/${hostnames[0]}` : undefined,
      },
    };
  } catch (err: any) {
    return {
      ip,
      type: isIPv4(ip) ? 'IPv4' : 'IPv6',
      reverse_domain: ptrDomain,
      hostnames: [],
      ptr_records: [],
      rcode: 'ERROR',
      error: err.message || 'Reverse lookup failed',
    };
  }
}

// ── Single Lookup ─────────────────────────────────────────────────────

async function singleLookup(domain: string, type: string, explain: boolean): Promise<any> {
  const typeNum = getRecordTypeNumber(type);
  const result = await querySingle(domain, typeNum);

  const report: any = {
    domain,
    type,
    query_time: new Date().toISOString(),
    resolver: result.resolver,
    rcode: result.rcode,
    records: result.records.map((r) => ({
      ...r,
      ttl_human: humanTTL(r.TTL),
    })),
    dnssec_authenticated: result.ad,
    query_time_ms: result.query_time_ms,
    _meta: {
      full_report: `https://yoke.lol/${domain}`,
      propagation: `https://ns.lol/${domain}/propagation?type=${type}`,
    },
  };

  if (explain) {
    report._explain = explainType(type, result.records);
  }

  return report;
}

// ── Propagation Check ─────────────────────────────────────────────────

async function propagationCheck(
  domain: string,
  url: URL,
  expected: string | null,
  explain: boolean,
  env: Env
): Promise<any> {
  const type = (url.searchParams.get('type') || 'A').toUpperCase();
  const typeNum = getRecordTypeNumber(type);

  // Try Fly probes (real UDP queries), fall back to DoH
  // Two probes: NA (sjc) and EU (ams), called in parallel
  let results: ResolverResult[];
  let source: 'udp' | 'doh' = 'doh';

  if (env.PROBE_URL && env.PROBE_KEY) {
    try {
      const probeUrl = `${env.PROBE_URL}/propagation?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`;
      const probeHeaders = { 'Authorization': `Bearer ${env.PROBE_KEY}` };

      // Call both regions in parallel — fly-prefer-region routes to the right machine
      const [naResp, euResp] = await Promise.all([
        fetch(probeUrl, {
          signal: AbortSignal.timeout(15000),
          headers: { ...probeHeaders, 'fly-prefer-region': 'sjc' },
        }).catch(() => null),
        fetch(probeUrl, {
          signal: AbortSignal.timeout(15000),
          headers: { ...probeHeaders, 'fly-prefer-region': 'ams' },
        }).catch(() => null),
      ]);

      const mapResults = (probeData: any): ResolverResult[] =>
        (probeData.results || []).map((r: any) => ({
          resolver: r.resolver,
          location: r.location,
          lat: r.lat,
          lng: r.lng,
          records: (r.records || []).map((rec: any) => ({
            type: rec.type,
            name: rec.name || domain,
            TTL: rec.TTL || 0,
            data: rec.data,
          })),
          rcode: r.rcode,
          aa: r.aa || false,
          ad: r.ad || false,
          query_time_ms: r.query_time_ms || 0,
          ...(r.error && { error: r.error }),
        }));

      const allResults: ResolverResult[] = [];
      let gotProbeData = false;

      for (const resp of [naResp, euResp]) {
        if (resp?.ok) {
          const data = await resp.json() as any;
          allResults.push(...mapResults(data));
          gotProbeData = true;
        }
      }

      if (gotProbeData) {
        results = allResults;
        source = 'udp';
      } else {
        results = await queryAllResolvers(domain, typeNum);
      }
    } catch {
      // Probes unreachable — fall back to DoH
      results = await queryAllResolvers(domain, typeNum);
    }
  } else {
    results = await queryAllResolvers(domain, typeNum);
  }

  // Analyze consistency
  const valueMap = new Map<string, string[]>();
  let errors = 0;

  for (const r of results) {
    if (r.error || r.rcode !== 'NOERROR') {
      errors++;
      continue;
    }
    const vals = r.records.map((rec) => rec.data).sort().join(',');
    const key = vals || '(empty)';
    if (!valueMap.has(key)) valueMap.set(key, []);
    valueMap.get(key)!.push(r.resolver);
  }

  const totalResponded = results.length - errors;
  // Propagation percentage: measures resolution availability, not answer uniformity.
  const propagation_pct = results.length > 0
    ? Math.round((totalResponded / (totalResponded + errors)) * 100)
    : 0;

  // Consistency: what % of responding resolvers agree on the same answer
  const consistentResolvers = Math.max(...Array.from(valueMap.values()).map((v) => v.length), 0);
  const consistency_pct = totalResponded > 0 ? Math.round((consistentResolvers / totalResponded) * 100) : 0;

  let status: 'complete' | 'partial' | 'not_started' = 'complete';
  if (propagation_pct < 50) status = 'not_started';
  else if (propagation_pct < 100) status = 'partial';

  // Determine majority answer for anomaly detection
  let majorityAnswer = '';
  let majorityCount = 0;
  for (const [val, resolvers] of valueMap) {
    if (resolvers.length > majorityCount) {
      majorityCount = resolvers.length;
      majorityAnswer = val;
    }
  }

  // Annotate each result with anomaly flag
  const annotatedResults = results.map((r) => {
    if (r.error) return { ...r, anomaly: false };
    const vals = r.records.map((rec) => rec.data).sort().join(',');
    const key = vals || '(empty)';
    return {
      ...r,
      anomaly: key !== majorityAnswer && !r.error,
      records: r.records.map((rec) => ({
        ...rec,
        ttl_human: humanTTL(rec.TTL),
      })),
    };
  });

  // Collect min/max TTL for countdown info
  const ttls = results.flatMap((r) => r.records.map((rec) => rec.TTL)).filter((t) => t > 0);
  const ttlInfo = ttls.length > 0
    ? {
        min: Math.min(...ttls),
        max: Math.max(...ttls),
        min_human: humanTTL(Math.min(...ttls)),
        max_human: humanTTL(Math.max(...ttls)),
      }
    : null;

  // Check expected value
  let expected_match: any = undefined;
  if (expected) {
    expected_match = {
      expected,
      matches: 0,
      mismatches: 0,
      resolvers_matching: [] as string[],
      resolvers_mismatching: [] as string[],
    };
    for (const r of results) {
      if (r.error) continue;
      const vals = r.records.map((rec) => rec.data);
      if (vals.includes(expected)) {
        expected_match.matches++;
        expected_match.resolvers_matching.push(r.resolver);
      } else {
        expected_match.mismatches++;
        expected_match.resolvers_mismatching.push(r.resolver);
      }
    }
    expected_match.percentage = totalResponded > 0
      ? Math.round((expected_match.matches / totalResponded) * 100) : 0;
  }

  // Distinct answers detail
  const distinctAnswers = Array.from(valueMap.entries()).map(([val, resolvers]) => ({
    value: val === '(empty)' ? null : val.split(','),
    resolvers,
    count: resolvers.length,
    is_majority: val === majorityAnswer,
  }));

  const report: any = {
    domain,
    type,
    query_time: new Date().toISOString(),
    propagation: {
      status,
      percentage: propagation_pct,
      consistency: consistency_pct,
      resolvers_queried: results.length,
      resolvers_responded: totalResponded,
      resolvers_errored: errors,
      distinct_answers: valueMap.size,
      ...(ttlInfo && { ttl: ttlInfo }),
    },
    ...(expected_match && { expected_match }),
    distinct_answers: distinctAnswers,
    results: annotatedResults,
    _cache_control: 'no-cache',
    _source: source,
  };

  if (explain) {
    report._explain = {
      summary: propagation_pct === 100
        ? `${type} records for ${domain} are resolving successfully across all ${totalResponded} resolvers checked.`
        : `${type} records for ${domain} show ${propagation_pct}% propagation — ${errors} resolver(s) failed to respond.`,
      ...(valueMap.size > 1 && {
        consistency_note: `${valueMap.size} distinct answers seen across ${totalResponded} resolvers (${consistency_pct}% consistent). Multiple answers are normal for CDN/anycast domains like those behind Cloudflare, Fastly, or Akamai — different locations intentionally return different IPs.`,
      }),
      ...(ttlInfo && {
        ttl_note: `Current TTLs range from ${ttlInfo.min_human} to ${ttlInfo.max_human}. Full propagation typically completes within the maximum TTL window.`,
      }),
      tip: expected
        ? expected_match?.matches === totalResponded
          ? 'Your expected value is live everywhere.'
          : `Your expected value (${expected}) is not live on all resolvers yet. This usually resolves within the TTL window.`
        : 'Add ?expected=1.2.3.4 to track when a specific value goes live.',
    };
  }

  return report;
}

// ── dig-style output ──────────────────────────────────────────────────

export function formatDig(data: any): string {
  const lines: string[] = [];
  const domain = data.domain || data.ip || 'unknown';

  lines.push(`; <<>> ns.lol DiG-style output <<>> ${domain}`);
  lines.push(`;; Query time: ${new Date().toISOString()}`);
  lines.push('');

  // Reverse DNS
  if (data.ip) {
    lines.push(';; QUESTION SECTION:');
    lines.push(`;; ${data.reverse_domain}\tIN\tPTR`);
    lines.push('');
    lines.push(';; ANSWER SECTION:');
    for (const r of (data.ptr_records || [])) {
      lines.push(`${padRight(r.name || data.reverse_domain, 32)}\t${r.TTL}\tIN\t${r.type}\t${r.data}`);
    }
    if ((data.ptr_records || []).length === 0) {
      lines.push(';; (no PTR records found)');
    }
    lines.push('');
    lines.push(`;; RCODE: ${data.rcode || 'NOERROR'}`);
    lines.push(`;; Query time: ${data.query_time_ms || 0} msec`);
    return lines.join('\n') + '\n';
  }

  // Batch results
  if (data.results && data.count !== undefined) {
    lines.push(`;; BATCH QUERY: ${data.count} domain(s), type ${data.type}`);
    lines.push('');
    for (const r of data.results) {
      if (r.error) {
        lines.push(`; ${r.domain}: ERROR - ${r.error}`);
      } else {
        lines.push(`;; ${r.domain}`);
        for (const rec of (r.records || [])) {
          lines.push(`${padRight(rec.name || r.domain, 32)}\t${rec.TTL}\tIN\t${rec.type}\t${rec.data}`);
        }
        if ((r.records || []).length === 0) {
          lines.push(`;; RCODE: ${r.rcode}`);
        }
      }
      lines.push('');
    }
    return lines.join('\n') + '\n';
  }

  // ANY query
  if (data.type === 'ANY') {
    lines.push(`;; Simulated ANY query (RFC 8482)`);
    lines.push(`;; ${data.total_records} record(s) across ${data.types_found?.length || 0} type(s)`);
    lines.push('');
    lines.push(';; ANSWER SECTION:');
    for (const [type, recs] of Object.entries(data.records || {})) {
      for (const rec of (recs as any[])) {
        lines.push(`${padRight(rec.name || domain, 32)}\t${rec.TTL}\tIN\t${rec.type || type}\t${rec.data}`);
      }
    }
    lines.push('');
    lines.push(`;; DNSSEC: ${data.dnssec_authenticated ? 'validated' : 'not validated'}`);
    lines.push(`;; Query time: ${data.query_time_ms || 0} msec`);
    return lines.join('\n') + '\n';
  }

  // Trace output
  if (data.steps) {
    lines.push(`;; Authority chain trace for ${domain}`);
    lines.push(`;; ${data.trace.steps} steps, ${data.trace.total_time_ms}ms total`);
    lines.push('');
    for (const step of data.steps) {
      lines.push(`; Step ${step.step}: ${step.label}`);
      if (step.nameservers) {
        for (const ns of step.nameservers) {
          lines.push(`;\t${ns}`);
        }
      }
      if (step.resolver_results) {
        for (const rr of step.resolver_results) {
          if (rr.error) {
            lines.push(`;\t${rr.resolver}: ERROR - ${rr.error}`);
          } else {
            for (const rec of (rr.records || [])) {
              lines.push(`${padRight(rec.name || domain, 32)}\t${rec.TTL}\tIN\t${rec.type}\t${rec.data}`);
            }
          }
        }
      }
      if (step.primary_ns) {
        lines.push(`;\tPrimary NS: ${step.primary_ns}`);
        lines.push(`;\tSerial: ${step.serial}`);
      }
      if (step.ds_records !== undefined) {
        lines.push(`;\tDS: ${step.ds_records} record(s), DNSKEY: ${step.dnskey_records} record(s)`);
        lines.push(`;\tChain intact: ${step.chain_intact ? 'yes' : 'no'}`);
      }
      lines.push('');
    }
    return lines.join('\n') + '\n';
  }

  // Propagation
  if (data.propagation) {
    const p = data.propagation;
    lines.push(`;; PROPAGATION CHECK: ${domain} ${data.type}`);
    lines.push(`;; ${p.percentage}% propagated, ${p.consistency}% consistent`);
    lines.push(`;; ${p.resolvers_responded}/${p.resolvers_queried} responded, ${p.distinct_answers} distinct answer(s)`);
    lines.push('');
    for (const r of (data.results || [])) {
      if (r.error) {
        lines.push(`; ${padRight(r.resolver, 16)} ERROR: ${r.error}`);
      } else {
        const vals = r.records.map((rec: any) => rec.data).join(', ') || '(empty)';
        const flag = r.anomaly ? ' [ANOMALY]' : '';
        lines.push(`; ${padRight(r.resolver, 16)} ${padRight(r.rcode, 10)} ${vals}${flag}  (${r.query_time_ms}ms)`);
      }
    }
    lines.push('');
    return lines.join('\n') + '\n';
  }

  // Health / Email / Security signals
  if (data.health || data.email || data.security) {
    const section = data.health || data.email || data.security;
    const label = data.health ? 'HEALTH' : data.email ? 'EMAIL' : 'SECURITY';
    lines.push(`;; ${label} REPORT: ${domain}`);
    lines.push(`;; Grade: ${section.grade} (${section.pass} pass, ${section.warn} warn, ${section.fail} fail, ${section.info} info)`);
    lines.push('');
    for (const s of (data.signals || [])) {
      const icon = s.status === 'pass' ? '✓' : s.status === 'fail' ? '✗' : s.status === 'warn' ? '!' : 'i';
      lines.push(`; [${icon}] ${s.label}: ${s.detail}`);
      if (s.fix) lines.push(`;     Fix: ${s.fix}`);
    }
    lines.push('');
    return lines.join('\n') + '\n';
  }

  // Single lookup or full report
  if (data.records) {
    // Single type result (has domain + type + records array)
    if (Array.isArray(data.records)) {
      lines.push(';; QUESTION SECTION:');
      lines.push(`;; ${domain}\tIN\t${data.type}`);
      lines.push('');
      lines.push(';; ANSWER SECTION:');
      for (const r of data.records) {
        lines.push(`${padRight(r.name || domain, 32)}\t${r.TTL}\tIN\t${r.type}\t${r.data}`);
      }
      if (data.records.length === 0) {
        lines.push(`;; RCODE: ${data.rcode || 'NOERROR'} (no records)`);
      }
      lines.push('');
      lines.push(`;; RCODE: ${data.rcode || 'NOERROR'}`);
      lines.push(`;; DNSSEC: ${data.dnssec_authenticated ? 'AD flag set' : 'not validated'}`);
      lines.push(`;; Resolver: ${data.resolver || 'Cloudflare'}`);
      lines.push(`;; Query time: ${data.query_time_ms || 0} msec`);
    } else {
      // Full report (records is an object keyed by type)
      lines.push(';; ANSWER SECTION:');
      const typeOrder = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'CAA', 'HTTPS', 'DS'];
      for (const type of typeOrder) {
        const group = data.records[type];
        if (!group || !group.records) continue;
        for (const r of group.records) {
          lines.push(`${padRight(r.name || domain, 32)}\t${r.TTL}\tIN\t${r.type || type}\t${r.data}`);
        }
      }
      lines.push('');
      if (data.summary) {
        lines.push(`;; ${data.summary.total_records} record(s), ${data.summary.record_types} type(s)`);
        lines.push(`;; DNSSEC: ${data.summary.dnssec}`);
        if (data.summary.cdn) lines.push(`;; CDN: ${data.summary.cdn}`);
        lines.push(`;; Avg query time: ${data.summary.avg_query_time_ms} msec`);
      }
    }
  }

  lines.push('');
  return lines.join('\n') + '\n';
}

function padRight(s: string, len: number): string {
  return s.length >= len ? s : s + ' '.repeat(len - s.length);
}

// ── API Docs ──────────────────────────────────────────────────────────

function apiDocs(): any {
  return {
    name: 'ns.lol',
    version: '0.3.0',
    description: 'Fast, API-first DNS toolkit. No accounts, no tracking, no API keys.',
    base_url: 'https://ns.lol',
    endpoints: {
      'GET /:domain': {
        description: 'Full DNS report — queries all common record types (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, HTTPS, DS) in parallel.',
        example: 'curl -s https://ns.lol/example.com | jq',
        response: {
          domain: 'string — the queried domain',
          records: 'object — keyed by record type, each with records[], rcode, query_time_ms',
          stats: '{ total_records, types_found, avg_query_time_ms, dnssec }',
          _meta: 'object — links to propagation, health, email, security, trace, TLS report, full analysis',
        },
      },
      'GET /:domain/:type': {
        description: 'Single record type lookup. Accepts standard type names or numeric QTYPEs (1-65535).',
        types: 'a, aaaa, cname, mx, txt, ns, soa, srv, caa, https, ds, ptr, dnskey, naptr, tlsa, sshfp, loc, hinfo',
        example: 'curl -s https://ns.lol/example.com/mx | jq',
        numeric_example: 'curl -s https://ns.lol/example.com/65 | jq  # HTTPS record (type 65)',
        response: {
          domain: 'string',
          type: 'string — record type name',
          records: 'array — [{ type, name, TTL, ttl_human, data }]',
          rcode: 'string — NOERROR, NXDOMAIN, SERVFAIL, etc.',
          query_time_ms: 'number',
        },
      },
      'GET /:domain/any': {
        description: 'Simulated ANY query — queries all common types in parallel. RFC 8482 deprecated real ANY queries; this is the modern equivalent.',
        example: 'curl -s https://ns.lol/example.com/any | jq',
      },
      'GET /:domain/trace': {
        description: 'Authority chain walk — traces delegation from root to TLD to authoritative NS to final answer. Shows each hop with the nameserver, answer, and timing.',
        example: 'curl -s https://ns.lol/example.com/trace | jq',
        response: {
          domain: 'string',
          hops: 'array — [{ server, server_ip, records, rcode, aa, query_time_ms }]',
          final_answer: 'object — the authoritative result',
        },
      },
      'GET /:ip': {
        description: 'Reverse DNS (PTR) lookup for IPv4 or IPv6 addresses. Returns hostnames and the in-addr.arpa/ip6.arpa domain.',
        example: 'curl -s https://ns.lol/8.8.8.8 | jq',
        ipv6_example: 'curl -s https://ns.lol/2606:4700:4700::1111 | jq',
        response: {
          ip: 'string',
          type: 'string — ipv4 or ipv6',
          reverse_domain: 'string — the .arpa PTR domain',
          hostnames: 'array of strings',
        },
      },
      'GET /:domain/propagation': {
        description: 'Global DNS propagation check across 17 resolvers in 2 regions (US + EU). Real UDP queries via dedicated probe servers.',
        params: {
          type: 'Record type to check (default: A). Examples: A, AAAA, MX, CNAME, TXT, NS',
          expected: 'Expected value — each resolver is marked as matching or divergent',
        },
        example: 'curl -s "https://ns.lol/example.com/propagation?type=MX" | jq',
        response: {
          propagation: '{ status, percentage, total, responding, values, expected }',
          results: 'array — per-resolver: { resolver, location, lat, lng, records, rcode, query_time_ms }',
        },
        notes: 'Never cached — always live. Probes in US-West (SJC) and EU (AMS) queried in parallel.',
      },
      'GET /:domain/health': {
        description: 'Zone health report with letter grade (A-F). Checks DNSSEC, NS diversity, SOA values, delegation consistency.',
        example: 'curl -s https://ns.lol/example.com/health | jq',
        response: {
          health: '{ grade, signals_checked, pass, warn, fail, info }',
          signals: 'array — [{ id, category, label, status, detail, fix?, explain? }]',
        },
      },
      'GET /:domain/email': {
        description: 'Email DNS audit — MX, SPF, DKIM (common selectors), DMARC, MTA-STS, BIMI, DANE/TLSA. Returns a letter grade.',
        example: 'curl -s https://ns.lol/example.com/email | jq',
        response: {
          email: '{ grade, signals_checked, pass, warn, fail, info }',
          signals: 'array — [{ id, category, label, status, detail, fix?, explain? }]',
        },
      },
      'GET /:domain/security': {
        description: 'Security analysis — dangling CNAME/NS, NXDOMAIN hijacking, wildcard, CDN/WAF detection, NS diversity, CAA policy.',
        example: 'curl -s https://ns.lol/example.com/security | jq',
        response: {
          security: '{ grade, signals_checked, pass, warn, fail, info }',
          signals: 'array — [{ id, category, label, status, detail, fix?, explain? }]',
        },
      },
      'POST /batch': {
        description: 'Batch lookup — query multiple domains in one request. Max 20 domains.',
        content_type: 'application/json',
        body: '{ "domains": ["google.com", "github.com"], "type": "A" }',
        example: `curl -s -X POST https://ns.lol/batch -H 'Content-Type: application/json' -d '{"domains":["google.com","github.com"]}' | jq`,
        response: {
          results: 'array — one result object per domain',
          count: 'number — domains processed',
        },
      },
      'GET /api/docs': {
        description: 'This documentation endpoint.',
      },
      'GET /health': {
        description: 'Service health check (not rate-limited).',
        response: '{ status: "ok", service: "ns.lol" }',
      },
    },
    query_parameters: {
      explain: { type: 'boolean', description: 'Add plain-English explanations to every record and signal. Bypasses cache.', example: '?explain=true' },
      force: { type: 'boolean', description: 'Bypass cache and force a fresh lookup. Results are not re-cached.', example: '?force=true' },
      expected: { type: 'string', description: 'Expected DNS value for propagation — resolvers flagged as matching or divergent.', example: '?expected=93.184.216.34' },
      type: { type: 'string', description: 'Record type for propagation checks (default: A).', example: '?type=MX' },
    },
    content_negotiation: {
      'Accept: application/json': 'JSON response (default for curl, httpie, wget)',
      'Accept: application/dns-json': 'Alias for JSON (RFC 8484 media type)',
      'Accept: text/plain': 'dig-style plain text output',
      'Accept: text/html': 'Interactive SPA with map, tabs, copy-to-clipboard (default for browsers)',
    },
    rate_limiting: {
      limit: '120 requests per hour per IP',
      scope: 'Per-IP via Cloudflare Durable Objects',
      headers: {
        'X-RateLimit-Limit': 'Max requests per window (120)',
        'X-RateLimit-Remaining': 'Requests remaining in current window',
        'X-RateLimit-Reset': 'Unix timestamp when the window resets',
      },
      exceeded: {
        status: 429,
        body: '{ "error": "Rate limit exceeded", "retry_after": <seconds> }',
        header: 'Retry-After: <seconds>',
      },
      not_limited: 'Homepage (/), /health, and /api/docs are not rate-limited.',
    },
    caching: {
      default_ttl: '1 hour (record lookups, full reports)',
      health_security_ttl: '6 hours (health and security checks)',
      propagation: 'Never cached — always live',
      bypass: '?force=true or ?explain=true',
    },
    infrastructure: {
      worker: 'Cloudflare Workers (global edge)',
      probes: 'Fly.io — SJC (US-West) + AMS (EU) for real UDP propagation queries',
      resolvers: '17 public DNS resolvers — 10 NA + 7 EU, queried in parallel from nearest probe',
      dns_method: 'RFC 8484 wireformat DoH for lookups; real UDP via probes for propagation',
    },
    cors: {
      allowed_origins: '*',
      allowed_methods: 'GET, POST, OPTIONS',
    },
    family: {
      'ns.lol': 'DNS toolkit (you are here)',
      'certs.lol': 'TLS/SSL certificate scanner — https://certs.lol',
      'yoke.lol': 'Full domain intelligence dashboard — https://yoke.lol',
    },
    examples: [
      '# Full DNS report',
      'curl -s https://ns.lol/example.com | jq',
      '',
      '# Single record type',
      'curl -s https://ns.lol/example.com/mx | jq',
      '',
      '# Custom QTYPE (numeric)',
      'curl -s https://ns.lol/example.com/65 | jq',
      '',
      '# Reverse DNS',
      'curl -s https://ns.lol/8.8.8.8 | jq',
      '',
      '# Propagation check with expected value',
      'curl -s "https://ns.lol/example.com/propagation?type=A&expected=93.184.216.34" | jq',
      '',
      '# Zone health with explanations',
      'curl -s "https://ns.lol/example.com/health?explain=true" | jq',
      '',
      '# Email DNS audit',
      'curl -s https://ns.lol/example.com/email | jq',
      '',
      '# Security analysis',
      'curl -s https://ns.lol/example.com/security | jq',
      '',
      '# Authority trace',
      'curl -s https://ns.lol/example.com/trace | jq',
      '',
      '# dig-style output',
      'curl -sH "Accept: text/plain" https://ns.lol/example.com',
      '',
      '# Batch lookup (max 20 domains)',
      `curl -s -X POST https://ns.lol/batch -H 'Content-Type: application/json' \\`,
      `  -d '{"domains":["google.com","github.com","cloudflare.com"],"type":"A"}' | jq`,
      '',
      '# Check your rate limit',
      'curl -si https://ns.lol/example.com 2>&1 | grep X-RateLimit',
    ],
  };
}

// ── Explain helpers ───────────────────────────────────────────────────

function explainRecords(records: Record<string, any>): Record<string, string> {
  const explanations: Record<string, string> = {};
  for (const [type, data] of Object.entries(records)) {
    if (data.records?.length > 0) {
      explanations[type] = explainType(type, data.records);
    }
  }
  return explanations;
}

function explainType(type: string, records: any[]): string {
  if (records.length === 0) return `No ${type} records found.`;
  switch (type) {
    case 'A':
      return `Points to ${records.length} IPv4 address(es): ${records.map((r: any) => r.data).join(', ')}`;
    case 'AAAA':
      return `Points to ${records.length} IPv6 address(es): ${records.map((r: any) => r.data).join(', ')}`;
    case 'CNAME':
      return `Aliased to ${records[0].data}`;
    case 'MX':
      return `Mail handled by: ${records.map((r: any) => r.data).join(', ')}`;
    case 'TXT':
      return `${records.length} TXT record(s) — often used for SPF, DKIM, domain verification`;
    case 'NS':
      return `Nameservers: ${records.map((r: any) => r.data).join(', ')}`;
    case 'SOA':
      return `Start of Authority: ${records[0].data}`;
    case 'CAA':
      return `Certificate Authority Authorization: only ${records.map((r: any) => r.data).join(', ')} can issue certs`;
    case 'HTTPS':
      return `HTTPS service binding record — used for ECH, ALPN hints, and IP fallback`;
    case 'SRV':
      return `Service records: ${records.map((r: any) => r.data).join(', ')}`;
    case 'DS':
      return `DNSSEC Delegation Signer — links parent zone to this zone's DNSSEC keys`;
    case 'PTR':
      return `Reverse DNS: ${records.map((r: any) => r.data).join(', ')}`;
    default:
      return `${records.length} ${type} record(s) found`;
  }
}


// ── Static Pages ─────────────────────────────────────────────────────

function baseCSS(): string {
  return `*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e17;color:#e2e8f0;font-family:'Inter',system-ui,sans-serif;-webkit-font-smoothing:antialiased;line-height:1.6}
.page{max-width:640px;margin:0 auto;padding:3rem 1.5rem}
h1{font-size:1.5rem;font-weight:800;margin-bottom:0.5rem;letter-spacing:-0.03em}
h2{font-size:1rem;font-weight:700;margin-top:2rem;margin-bottom:0.5rem;color:#22d3ee}
h3{font-size:0.875rem;font-weight:600;margin-top:1.5rem;margin-bottom:0.25rem}
p{margin-bottom:1rem;color:#94a3b8;font-size:0.875rem}
ul{margin:0.5rem 0 1rem 1.5rem;color:#94a3b8;font-size:0.875rem}
li{margin-bottom:0.25rem}
a{color:#22d3ee;text-decoration:none}a:hover{text-decoration:underline}
pre{background:#111827;border:1px solid #1e293b;border-radius:6px;padding:12px 16px;overflow-x:auto;margin:0.75rem 0;font-size:13px}
code{font-family:'JetBrains Mono',monospace;color:#22d3ee}
.muted{color:#64748b;font-style:italic}
.footer-link{margin-top:3rem;padding-top:1rem;border-top:1px solid #1e293b;font-size:12px}`;
}

function metaTags(title: string, description: string, path: string = '/'): string {
  const url = `https://ns.lol${path}`;
  return `<meta name="description" content="${description}">
<meta property="og:title" content="${title}">
<meta property="og:description" content="${description}">
<meta property="og:type" content="website">
<meta property="og:url" content="${url}">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="${title}">
<meta name="twitter:description" content="${description}">
<link rel="canonical" href="${url}">`;
}

export function privacyPage(): string {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy — ns.lol</title>
${metaTags('Privacy Policy — ns.lol', 'ns.lol privacy policy. We collect nothing.', '/privacy')}
<style>${baseCSS()}</style></head><body>
<div class="page">
<h1>Privacy Policy</h1>
<p class="muted">Last updated: June 2026</p>

<h2>What we collect</h2>
<p>Nothing. ns.lol has no accounts, no cookies, no analytics, no tracking pixels, and no third-party scripts.</p>

<h2>Server logs</h2>
<p>Cloudflare processes requests as our CDN and compute provider. Their standard edge logs (IP, URL, timestamp) are subject to <a href="https://www.cloudflare.com/privacypolicy/">Cloudflare's privacy policy</a>. We do not access, store, or process these logs.</p>

<h2>Rate limiting</h2>
<p>We store an IP-derived counter in a Cloudflare Durable Object for rate limiting. These counters expire automatically and contain no personally identifiable information beyond a hashed IP key.</p>

<h2>DNS query data</h2>
<p>DNS lookup results are cached in Cloudflare KV for 1–6 hours to improve performance. Cached data contains only publicly observable DNS records — no private information. Propagation results are never cached.</p>

<h2>Contact</h2>
<p>Questions? <a href="mailto:hello@ns.lol">hello@ns.lol</a></p>

<div class="footer-link"><a href="/">← back to ns.lol</a></div>
</div></body></html>`;
}

export function termsPage(): string {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Terms — ns.lol</title>
${metaTags('Terms of Service — ns.lol', 'ns.lol terms of service.', '/terms')}
<style>${baseCSS()}</style></head><body>
<div class="page">
<h1>Terms of Service</h1>
<p class="muted">Last updated: June 2026</p>

<h2>What this is</h2>
<p>ns.lol is a free DNS toolkit. It queries publicly-observable DNS records and reports what it finds.</p>

<h2>Use it reasonably</h2>
<p>Rate limits are enforced at 120 requests per hour per IP. Results are cached for 1–6 hours depending on the endpoint. These limits keep hosting costs near zero so ns.lol can stay free.</p>
<p>For a full domain report including DNS, TLS, performance, and more, see <a href="https://yoke.lol">yoke.lol</a>. Automated scanning at scale without coordination is not welcome — talk to us first.</p>

<h2>No warranty</h2>
<p>This tool is provided as-is. DNS results reflect what we observe at query time and may not represent the complete state of any domain. Do not use ns.lol as your sole basis for DNS or security decisions.</p>

<h2>DNS queries</h2>
<p>ns.lol performs standard DNS lookups — the same queries any resolver or dig command makes. We do not attempt zone transfers, exploit vulnerabilities, or probe beyond normal DNS resolution.</p>

<h2>Changes</h2>
<p>We may update these terms. Continued use constitutes acceptance.</p>

<h2>Contact</h2>
<p><a href="mailto:hello@ns.lol">hello@ns.lol</a></p>

<div class="footer-link"><a href="/">← back to ns.lol</a></div>
</div></body></html>`;
}

export function docsPage(): string {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>API Docs — ns.lol</title>
${metaTags('API Documentation — ns.lol', 'Complete API reference for ns.lol — fast, API-first DNS toolkit.', '/docs')}
<style>${baseCSS()}
.endpoint{margin:1.5rem 0;padding:16px;background:#111827;border:1px solid #1e293b;border-radius:8px}
.endpoint-header{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
.method{font-family:'JetBrains Mono',monospace;font-size:0.75rem;font-weight:700;padding:2px 8px;border-radius:4px;background:#22d3ee20;color:#22d3ee}
.method.post{background:#f9731620;color:#f97316}
.endpoint-path{font-family:'JetBrains Mono',monospace;font-size:0.9rem;font-weight:600;color:#e2e8f0}
.endpoint-desc{color:#94a3b8;font-size:0.82rem;margin-top:6px}
.endpoint pre{font-size:12px;margin-top:8px}
.param-table{width:100%;border-collapse:collapse;margin:0.75rem 0;font-size:0.82rem}
.param-table th{text-align:left;color:#64748b;font-weight:500;padding:6px 10px;border-bottom:1px solid #1e293b}
.param-table td{padding:6px 10px;border-bottom:1px solid #1e293b10;color:#94a3b8}
.param-table code{font-size:0.78rem}
.section{margin-top:2.5rem}
.badge{display:inline-block;font-family:'JetBrains Mono',monospace;font-size:0.7rem;padding:2px 8px;border-radius:4px;margin-left:6px}
.badge-green{background:#22c55e20;color:#22c55e}
.badge-yellow{background:#eab30820;color:#eab308}
.badge-red{background:#ef444420;color:#ef4444}
.toc{list-style:none;padding:0;margin:1rem 0}
.toc li{margin-bottom:4px}
.toc a{font-size:0.85rem;color:#64748b}.toc a:hover{color:#22d3ee}
.header-row{display:flex;align-items:center;gap:12px;margin-bottom:4px}
</style></head><body>
<div class="page" style="max-width:800px">
<h1>ns.lol API</h1>
<p>Fast, API-first DNS toolkit. No accounts, no API keys, no tracking.</p>
<p style="font-size:0.82rem;color:#64748b">Base URL: <code>https://ns.lol</code> · JSON endpoint: <a href="/api/docs">/api/docs</a></p>

<h2>Quick Start</h2>
<pre><code>curl -s https://ns.lol/example.com | jq</code></pre>

<nav>
<h2>Contents</h2>
<ul class="toc">
<li><a href="#endpoints">Endpoints</a></li>
<li><a href="#params">Query Parameters</a></li>
<li><a href="#content-neg">Content Negotiation</a></li>
<li><a href="#rate-limits">Rate Limiting</a></li>
<li><a href="#caching">Caching</a></li>
<li><a href="#examples">Examples</a></li>
</ul>
</nav>

<div class="section" id="endpoints">
<h2>Endpoints</h2>

<div class="endpoint">
<div class="endpoint-header"><span class="method">GET</span><span class="endpoint-path">/:domain</span></div>
<div class="endpoint-desc">Full DNS report — queries A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, HTTPS, DS in parallel.</div>
<pre><code>curl -s https://ns.lol/example.com | jq</code></pre>
</div>

<div class="endpoint">
<div class="endpoint-header"><span class="method">GET</span><span class="endpoint-path">/:domain/:type</span></div>
<div class="endpoint-desc">Single record type lookup. Types: <code>a</code> <code>aaaa</code> <code>cname</code> <code>mx</code> <code>txt</code> <code>ns</code> <code>soa</code> <code>srv</code> <code>caa</code> <code>https</code> <code>ds</code> <code>ptr</code> <code>dnskey</code> <code>naptr</code> <code>tlsa</code> <code>sshfp</code> <code>loc</code> <code>hinfo</code></div>
<pre><code>curl -s https://ns.lol/example.com/mx | jq</code></pre>
</div>

<div class="endpoint">
<div class="endpoint-header"><span class="method">GET</span><span class="endpoint-path">/:domain/:number</span></div>
<div class="endpoint-desc">Custom QTYPE — pass a numeric record type (1–65535).</div>
<pre><code>curl -s https://ns.lol/example.com/65 | jq  # HTTPS record</code></pre>
</div>

<div class="endpoint">
<div class="endpoint-header"><span class="method">GET</span><span class="endpoint-path">/:domain/any</span></div>
<div class="endpoint-desc">Simulated ANY query — queries all common types in parallel. RFC 8482 deprecated real ANY; this is the modern equivalent.</div>
<pre><code>curl -s https://ns.lol/example.com/any | jq</code></pre>
</div>

<div class="endpoint">
<div class="endpoint-header"><span class="method">GET</span><span class="endpoint-path">/:domain/trace</span></div>
<div class="endpoint-desc">Authority chain walk — traces delegation from root → TLD → authoritative NS → final answer. Shows each hop with nameserver, answer, and timing.</div>
<pre><code>curl -s https://ns.lol/example.com/trace | jq</code></pre>
</div>

<div class="endpoint">
<div class="endpoint-header"><span class="method">GET</span><span class="endpoint-path">/:ip</span></div>
<div class="endpoint-desc">Reverse DNS (PTR) lookup for IPv4 or IPv6 addresses.</div>
<pre><code>curl -s https://ns.lol/8.8.8.8 | jq
curl -s https://ns.lol/2606:4700:4700::1111 | jq</code></pre>
</div>

<div class="endpoint">
<div class="endpoint-header"><span class="method">GET</span><span class="endpoint-path">/:domain/propagation</span></div>
<div class="endpoint-desc">Global DNS propagation check across 17 resolvers in 2 regions (US + EU). Real UDP queries via dedicated Fly.io probes — not DoH approximations.</div>
<pre><code>curl -s "https://ns.lol/example.com/propagation?type=MX" | jq</code></pre>
<table class="param-table"><tr><th>Param</th><th>Description</th></tr>
<tr><td><code>?type=</code></td><td>Record type to check (default: A)</td></tr>
<tr><td><code>?expected=</code></td><td>Expected value — resolvers flagged as matching or divergent</td></tr></table>
</div>

<div class="endpoint">
<div class="endpoint-header"><span class="method">GET</span><span class="endpoint-path">/:domain/health</span></div>
<div class="endpoint-desc">Zone health report with letter grade (A–F). Checks DNSSEC, NS diversity, SOA values, delegation consistency.</div>
<pre><code>curl -s https://ns.lol/example.com/health | jq</code></pre>
</div>

<div class="endpoint">
<div class="endpoint-header"><span class="method">GET</span><span class="endpoint-path">/:domain/email</span></div>
<div class="endpoint-desc">Email DNS audit — MX, SPF, DKIM (common selectors), DMARC, MTA-STS, BIMI, DANE/TLSA. Returns a letter grade.</div>
<pre><code>curl -s https://ns.lol/example.com/email | jq</code></pre>
</div>

<div class="endpoint">
<div class="endpoint-header"><span class="method">GET</span><span class="endpoint-path">/:domain/security</span></div>
<div class="endpoint-desc">Security analysis — dangling CNAME/NS, NXDOMAIN hijacking, wildcard, CDN/WAF detection, NS diversity, CAA policy.</div>
<pre><code>curl -s https://ns.lol/example.com/security | jq</code></pre>
</div>

<div class="endpoint">
<div class="endpoint-header"><span class="method post">POST</span><span class="endpoint-path">/batch</span></div>
<div class="endpoint-desc">Batch lookup — query up to 20 domains in one request.</div>
<pre><code>curl -s -X POST https://ns.lol/batch \\
  -H 'Content-Type: application/json' \\
  -d '{"domains":["google.com","github.com"],"type":"A"}' | jq</code></pre>
</div>

<div class="endpoint">
<div class="endpoint-header"><span class="method">GET</span><span class="endpoint-path">/api/docs</span></div>
<div class="endpoint-desc">Machine-readable API documentation (this page in JSON).</div>
<pre><code>curl -s https://ns.lol/api/docs | jq</code></pre>
</div>
</div>

<div class="section" id="params">
<h2>Query Parameters</h2>
<table class="param-table">
<tr><th>Parameter</th><th>Type</th><th>Description</th></tr>
<tr><td><code>?explain=true</code></td><td>boolean</td><td>Add plain-English explanations to every record and signal. Bypasses cache.</td></tr>
<tr><td><code>?force=true</code></td><td>boolean</td><td>Bypass cache and force a fresh lookup.</td></tr>
<tr><td><code>?expected=</code></td><td>string</td><td>Expected DNS value for propagation — resolvers flagged as matching or divergent.</td></tr>
<tr><td><code>?type=</code></td><td>string</td><td>Record type for propagation checks (default: A).</td></tr>
</table>
</div>

<div class="section" id="content-neg">
<h2>Content Negotiation</h2>
<table class="param-table">
<tr><th>Accept Header</th><th>Response</th></tr>
<tr><td><code>application/json</code></td><td>JSON (default for curl, httpie, wget)</td></tr>
<tr><td><code>application/dns-json</code></td><td>Alias for JSON (RFC 8484)</td></tr>
<tr><td><code>text/plain</code></td><td>dig-style plain text output</td></tr>
<tr><td><code>text/html</code></td><td>Interactive SPA (default for browsers)</td></tr>
</table>
</div>

<div class="section" id="rate-limits">
<h2>Rate Limiting</h2>
<p><strong>120 requests per hour per IP</strong>, enforced via Cloudflare Durable Objects.</p>
<p>Every response includes rate limit headers:</p>
<table class="param-table">
<tr><th>Header</th><th>Description</th></tr>
<tr><td><code>X-RateLimit-Limit</code></td><td>Max requests per window (120)</td></tr>
<tr><td><code>X-RateLimit-Remaining</code></td><td>Requests remaining</td></tr>
<tr><td><code>X-RateLimit-Reset</code></td><td>Unix timestamp when window resets</td></tr>
</table>
<p>When exceeded, returns <code>429</code> with <code>Retry-After</code> header.</p>
<p>Not rate-limited: <code>/</code>, <code>/health</code>, <code>/docs</code>, <code>/api/docs</code>, <code>/privacy</code>, <code>/terms</code>.</p>
</div>

<div class="section" id="caching">
<h2>Caching</h2>
<table class="param-table">
<tr><th>Endpoint</th><th>Cache TTL</th></tr>
<tr><td>Record lookups, full reports</td><td>1 hour</td></tr>
<tr><td>Health, security checks</td><td>6 hours</td></tr>
<tr><td>Propagation</td><td>Never — always live</td></tr>
</table>
<p>Bypass with <code>?force=true</code> or <code>?explain=true</code>.</p>
</div>

<div class="section" id="examples">
<h2>Examples</h2>
<pre><code># Full DNS report
curl -s https://ns.lol/example.com | jq

# Single record type
curl -s https://ns.lol/example.com/mx | jq

# Reverse DNS
curl -s https://ns.lol/8.8.8.8 | jq

# Propagation with expected value
curl -s "https://ns.lol/example.com/propagation?expected=93.184.216.34" | jq

# Zone health with explanations
curl -s "https://ns.lol/example.com/health?explain=true" | jq

# Email DNS audit
curl -s https://ns.lol/example.com/email | jq

# Security analysis
curl -s https://ns.lol/example.com/security | jq

# Authority trace
curl -s https://ns.lol/example.com/trace | jq

# dig-style output
curl -sH "Accept: text/plain" https://ns.lol/example.com

# Batch lookup
curl -s -X POST https://ns.lol/batch \\
  -H 'Content-Type: application/json' \\
  -d '{"domains":["google.com","github.com"]}' | jq

# Check rate limit headers
curl -si https://ns.lol/example.com 2>&1 | grep X-RateLimit</code></pre>
</div>

<div class="section">
<h2>Infrastructure</h2>
<ul>
<li><strong>Worker:</strong> Cloudflare Workers (global edge)</li>
<li><strong>Probes:</strong> Fly.io machines in SJC (US-West) + AMS (EU) for real UDP propagation queries</li>
<li><strong>Resolvers:</strong> 17 public DNS resolvers — 10 NA + 7 EU, queried in parallel</li>
<li><strong>DNS method:</strong> RFC 8484 wireformat DoH for lookups; real UDP via probes for propagation</li>
<li><strong>CORS:</strong> Full support — all origins, GET/POST/OPTIONS</li>
</ul>
</div>

<div class="section">
<h2>Family</h2>
<ul>
<li><a href="https://ns.lol">ns.lol</a> — DNS toolkit (you are here)</li>
<li><a href="https://certs.lol">certs.lol</a> — TLS/SSL certificate scanner</li>
<li><a href="https://yoke.lol">yoke.lol</a> — Full domain intelligence dashboard</li>
</ul>
</div>

<div class="footer-link"><a href="/">← back to ns.lol</a></div>
</div></body></html>`;
}

export const INSTALL_SCRIPT = `#!/usr/bin/env bash
# Install ns CLI — curl -sSL https://ns.lol/install.sh | bash
set -euo pipefail

REPO="yokedotlol/ns-lol"

echo "Installing ns..."

# Detect OS/arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "error: unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# Get latest release tag
LATEST=$(curl -sfL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
if [ -z "$LATEST" ]; then
  echo "error: could not determine latest release" >&2; exit 1
fi

echo "  Version: $LATEST ($OS/$ARCH)"

# Build download URL
EXT="tar.gz"
[ "$OS" = "windows" ] && EXT="zip"
URL="https://github.com/$REPO/releases/download/$LATEST/ns_\${OS}_\${ARCH}.\${EXT}"

# Pick install dir
if [ -w /usr/local/bin ]; then
  INSTALL_DIR="/usr/local/bin"
elif [ -d "$HOME/.local/bin" ]; then
  INSTALL_DIR="$HOME/.local/bin"
else
  mkdir -p "$HOME/.local/bin"
  INSTALL_DIR="$HOME/.local/bin"
fi

# Download and extract
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "  Downloading from GitHub Releases..."
curl -sfL -o "$TMP/ns.$EXT" "$URL" || {
  echo "error: download failed — $URL" >&2; exit 1
}

if [ "$EXT" = "tar.gz" ]; then
  tar -xzf "$TMP/ns.$EXT" -C "$TMP"
else
  unzip -q "$TMP/ns.$EXT" -d "$TMP"
fi

# Install binary
cp "$TMP/ns" "$INSTALL_DIR/ns"
chmod +x "$INSTALL_DIR/ns"

echo "  ✓ Installed to $INSTALL_DIR/ns"

# Verify
if "$INSTALL_DIR/ns" version &>/dev/null; then
  echo "  $($INSTALL_DIR/ns version)"
fi

# Check PATH
if ! echo "$PATH" | tr ':' '\\n' | grep -qx "$INSTALL_DIR"; then
  echo ""
  echo "  Add to your PATH:"
  echo "    export PATH=\\"$INSTALL_DIR:\\$PATH\\""
fi

echo ""
echo "  Try it: ns example.com"
`;

export function cliPage(): string {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CLI — ns.lol</title>
${metaTags('CLI', 'ns CLI — fast, local DNS lookup. Same engine as ns.lol. No middleman. No rate limits.', '/cli')}
<style>${baseCSS()}
.badge{display:inline-block;background:#111827;border:1px solid #1e293b;border-radius:4px;padding:2px 8px;font-size:12px;color:#22d3ee;margin-right:6px}
table{border-collapse:collapse;width:100%;margin:0.75rem 0;font-size:13px}
th{text-align:left;padding:6px 12px;border-bottom:2px solid #1e293b;color:#22d3ee;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:0.05em}
td{padding:6px 12px;border-bottom:1px solid #111827;color:#94a3b8;vertical-align:top}
td code{color:#22d3ee;font-size:12px}
td:first-child{color:#e2e8f0;white-space:nowrap}
</style></head><body>
<div class="page">
<h1>ns CLI</h1>
<p>Run locally without us. No middleman. No rate limits. Same engine as ns.lol.</p>
<p><span class="badge">MIT</span><span class="badge">Go</span><span class="badge">17 resolvers</span></p>

<h2>Install</h2>
<pre><code># Homebrew
brew install yokedotlol/tap/ns

# Or one-liner
curl -sSL https://ns.lol/install.sh | bash

# Or download from GitHub Releases
curl -sL https://github.com/yokedotlol/ns-lol/releases/latest/download/ns_darwin_arm64.tar.gz | tar xz
sudo mv ns /usr/local/bin/</code></pre>

<h2>Quick Start</h2>
<pre><code># Full DNS lookup
ns stripe.com

# JSON output (default when piped)
ns stripe.com | jq

# Specific record type
ns stripe.com -t MX

# Propagation check across 17 global resolvers
ns stripe.com propagation
ns stripe.com -p

# DNS health audit
ns stripe.com health

# Email security (SPF/DKIM/DMARC)
ns stripe.com email

# DNSSEC &amp; security
ns stripe.com security

# Side-by-side comparison
ns compare stripe.com shopify.com</code></pre>

<h2>Three Modes</h2>
<table>
<tr><th>Mode</th><th>When</th><th>Use</th></tr>
<tr><td>Pretty</td><td>TTY (default)</td><td>Human-readable, colored output</td></tr>
<tr><td>JSON</td><td>Piped / <code>--json</code></td><td>Machine-readable, matches ns.lol API</td></tr>
<tr><td>Quiet</td><td><code>--quiet</code></td><td>Exit code only — for scripts</td></tr>
</table>

<h2>Commands</h2>
<table>
<tr><td><code>ns &lt;domain&gt;</code></td><td>Full DNS lookup (all record types)</td></tr>
<tr><td><code>ns &lt;domain&gt; -t &lt;type&gt;</code></td><td>Query specific record type (A, AAAA, MX, NS, TXT, etc.)</td></tr>
<tr><td><code>ns &lt;domain&gt; propagation</code></td><td>Check propagation across global resolvers</td></tr>
<tr><td><code>ns &lt;domain&gt; health</code></td><td>DNS health audit</td></tr>
<tr><td><code>ns &lt;domain&gt; email</code></td><td>Email security audit (SPF/DKIM/DMARC)</td></tr>
<tr><td><code>ns &lt;domain&gt; security</code></td><td>DNSSEC &amp; security check</td></tr>
<tr><td><code>ns compare &lt;a&gt; &lt;b&gt;</code></td><td>Side-by-side DNS comparison</td></tr>
<tr><td><code>ns version</code></td><td>Print version info</td></tr>
</table>

<h2>Options</h2>
<table>
<tr><td><code>-j, --json</code></td><td>JSON output (default when piped)</td></tr>
<tr><td><code>-q, --quiet</code></td><td>Exit code only</td></tr>
<tr><td><code>--no-color</code></td><td>Disable ANSI colors</td></tr>
<tr><td><code>-t, --type &lt;TYPE&gt;</code></td><td>Record type (A, AAAA, MX, NS, TXT, etc.)</td></tr>
<tr><td><code>-p</code></td><td>Shortcut for propagation</td></tr>
<tr><td><code>--timeout &lt;dur&gt;</code></td><td>Request timeout (default 30s)</td></tr>
</table>

<h2>Pipe Support</h2>
<pre><code># Read domains from stdin
echo "example.com" | ns

# Batch from a file
cat domains.txt | ns</code></pre>

<h2>Exit Codes</h2>
<table>
<tr><td><code>0</code></td><td>Lookup succeeded</td></tr>
<tr><td><code>1</code></td><td>Lookup succeeded, issues found</td></tr>
<tr><td><code>2</code></td><td>Usage error or request failed</td></tr>
</table>

<div class="footer-link"><a href="/">← back to ns.lol</a> · <a href="https://github.com/yokedotlol/ns-lol">github</a></div>
</div></body></html>`;
}

export function sitemapXml(): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://ns.lol/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>
  <url><loc>https://ns.lol/cli</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>
  <url><loc>https://ns.lol/docs</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>
  <url><loc>https://ns.lol/api/docs</loc><changefreq>monthly</changefreq><priority>0.7</priority></url>
  <url><loc>https://ns.lol/privacy</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
  <url><loc>https://ns.lol/terms</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
</urlset>`;
}
