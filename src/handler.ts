// Request handler — routes paths to DNS operations

import { Env } from './worker';
import { queryAllResolvers, querySingle, queryDoH, getRecordTypeNumber, RECORD_TYPES, DOH_RESOLVERS, rcodeName } from './dns';
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
function ipToReverseDomain(ip: string): string {
  if (isIPv4(ip)) {
    return ip.split('.').reverse().join('.') + '.in-addr.arpa';
  }
  // IPv6: expand to full 32 hex chars, reverse each nibble
  const parts = ip.split(':');
  const full: string[] = [];
  for (const part of parts) {
    if (part === '') {
      // :: expansion
      const missing = 8 - parts.filter(p => p !== '').length;
      for (let i = 0; i < missing + 1; i++) full.push('0000');
    } else {
      full.push(part.padStart(4, '0'));
    }
  }
  const hex = full.join('');
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
    result = await propagationCheck(domain, url, expected, explain);
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
      full_report: `https://ns.lol/${domain}`,
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
      full_report: `https://ns.lol/${domain}`,
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
      full_report: `https://ns.lol/${domain}`,
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
      full_report: `https://ns.lol/${domain}`,
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
  explain: boolean
): Promise<any> {
  const type = (url.searchParams.get('type') || 'A').toUpperCase();
  const typeNum = getRecordTypeNumber(type);

  const results = await queryAllResolvers(domain, typeNum);

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
    version: '0.2.0',
    description: 'Fast, API-first DNS toolkit',
    endpoints: [
      { path: '/:domain', method: 'GET', description: 'Full DNS report — all common record types' },
      { path: '/:domain/:type', method: 'GET', description: 'Single record type lookup (a, aaaa, mx, txt, ns, soa, caa, srv, https, ds, cname, ptr)' },
      { path: '/:domain/:number', method: 'GET', description: 'Custom QTYPE — pass numeric record type (1-65535, e.g. /example.com/65 for HTTPS)' },
      { path: '/:domain/any', method: 'GET', description: 'Simulated ANY query — queries all common types (RFC 8482 deprecated real ANY)' },
      { path: '/:domain/trace', method: 'GET', description: 'Authority chain walk — trace delegation from TLD NS → authoritative NS → answer' },
      { path: '/:ip', method: 'GET', description: 'Reverse DNS (PTR) lookup — pass an IPv4 or IPv6 address' },
      { path: '/:domain/propagation', method: 'GET', description: 'Global propagation check across 15 resolvers', params: ['?type=A', '?expected=1.2.3.4'] },
      { path: '/:domain/health', method: 'GET', description: 'Zone health report with grade (DNSSEC, NS, SOA, delegation)' },
      { path: '/:domain/email', method: 'GET', description: 'Email DNS audit (MX, SPF, DKIM, DMARC, MTA-STS)' },
      { path: '/:domain/security', method: 'GET', description: 'Security checks (dangling CNAME/NS, wildcard, CDN, NS diversity)' },
      { path: '/batch', method: 'POST', description: 'Batch lookup — POST {"domains":["a.com","b.com"], "type":"A"} (max 20)' },
    ],
    parameters: [
      { name: 'explain', type: 'boolean', description: 'Add plain-English explanations (?explain=true)' },
      { name: 'force', type: 'boolean', description: 'Bypass cache (?force=true)' },
      { name: 'expected', type: 'string', description: 'Expected value for propagation validation (?expected=1.2.3.4)' },
      { name: 'type', type: 'string', description: 'Record type for propagation (?type=MX)' },
    ],
    content_negotiation: [
      { accept: 'application/json', description: 'JSON response (default for curl/httpie)' },
      { accept: 'text/plain', description: 'dig-style plain text output' },
      { accept: 'text/html', description: 'Interactive SPA (default for browsers)' },
    ],
    examples: [
      'curl -s https://ns.lol/example.com | jq',
      'curl -s https://ns.lol/example.com/mx | jq',
      'curl -s https://ns.lol/example.com/65',
      'curl -s https://ns.lol/example.com/any | jq',
      'curl -s https://ns.lol/example.com/trace | jq',
      'curl -s https://ns.lol/example.com/propagation | jq',
      'curl -s https://ns.lol/example.com/health?explain=true | jq',
      'curl -s https://ns.lol/example.com/email | jq',
      'curl -s https://ns.lol/example.com/security | jq',
      'curl -sH "Accept: text/plain" https://ns.lol/example.com',
      'curl -s -X POST https://ns.lol/batch -d \'{"domains":["google.com","github.com"]}\'',
    ],
    rate_limit: '120 requests/hour per IP',
    family: {
      dns: 'https://ns.lol',
      tls: 'https://certs.lol',
      domains: 'https://yoke.lol',
    },
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
