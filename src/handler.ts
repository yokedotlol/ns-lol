// Request handler — routes paths to DNS operations

import { Env } from './worker';
import { queryAllResolvers, querySingle, getRecordTypeNumber, RECORD_TYPES, DOH_RESOLVERS } from './dns';
import { runHealthCheck } from './health';
import { runEmailCheck } from './email';
import { runSecurityCheck, detectCDNFromRecords } from './security';

// Supported DNS record types for single lookups
const RECORD_TYPE_SLUGS = new Set(
  Object.keys(RECORD_TYPES).map((t) => t.toLowerCase())
);

// Validate domain name (supports IDN via punycode)
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
function humanTTL(seconds: number): string {
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

export async function handleDNSRequest(url: URL, env: Env): Promise<any> {
  const parts = url.pathname.slice(1).split('/').filter(Boolean);

  if (parts.length === 0) {
    throw Object.assign(new Error('No domain specified'), { status: 400 });
  }

  // Special routes
  if (parts[0] === 'api' && parts[1] === 'docs') {
    return apiDocs();
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
  } else if (RECORD_TYPE_SLUGS.has(action)) {
    result = await singleLookup(domain, action.toUpperCase(), explain);
  } else {
    throw Object.assign(
      new Error(`Unknown action: ${action}. Use a record type (a, aaaa, mx, ...) or: propagation, health, email, security`),
      { status: 400 }
    );
  }

  // Cache result
  if (action !== 'propagation') {
    const cacheKey = `dns:${domain}:${action || 'full'}`;
    const ttl = action === 'health' || action === 'security' ? 21600 : 3600;
    await env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: ttl });
  }

  return result;
}

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
      tls_report: `https://certs.lol/${domain}`,
      full_report: `https://yoke.lol/${domain}`,
    },
  };

  if (explain) {
    report._explain = explainRecords(records);
  }

  return report;
}

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
  const consistentResolvers = Math.max(...Array.from(valueMap.values()).map((v) => v.length), 0);
  const propagation_pct = totalResponded > 0 ? Math.round((consistentResolvers / totalResponded) * 100) : 0;

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
        ? `${type} records for ${domain} have fully propagated across all ${totalResponded} resolvers checked.`
        : `${type} records for ${domain} show ${propagation_pct}% propagation. ${valueMap.size} distinct answer(s) seen across ${totalResponded} resolvers.`,
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

function apiDocs(): any {
  return {
    name: 'ns.lol',
    version: '0.1.0',
    description: 'Fast, API-first DNS toolkit',
    endpoints: [
      { path: '/:domain', method: 'GET', description: 'Full DNS report — all common record types' },
      { path: '/:domain/:type', method: 'GET', description: 'Single record type lookup (a, aaaa, mx, txt, ns, soa, caa, srv, https, ds, cname, ptr)' },
      { path: '/:domain/propagation', method: 'GET', description: 'Global propagation check across 15 resolvers', params: ['?type=A', '?expected=1.2.3.4'] },
      { path: '/:domain/health', method: 'GET', description: 'Zone health report with grade (DNSSEC, NS, SOA, delegation)' },
      { path: '/:domain/email', method: 'GET', description: 'Email DNS audit (MX, SPF, DKIM, DMARC, MTA-STS)' },
      { path: '/:domain/security', method: 'GET', description: 'Security checks (dangling CNAME/NS, wildcard, CDN, NS diversity)' },
    ],
    parameters: [
      { name: 'explain', type: 'boolean', description: 'Add plain-English explanations (?explain=true)' },
      { name: 'force', type: 'boolean', description: 'Bypass cache (?force=true)' },
      { name: 'expected', type: 'string', description: 'Expected value for propagation validation (?expected=1.2.3.4)' },
      { name: 'type', type: 'string', description: 'Record type for propagation (?type=MX)' },
    ],
    examples: [
      'curl -s https://ns.lol/example.com | jq',
      'curl -s https://ns.lol/example.com/mx | jq',
      'curl -s https://ns.lol/example.com/propagation | jq',
      'curl -s https://ns.lol/example.com/health?explain=true | jq',
      'curl -s https://ns.lol/example.com/email | jq',
      'curl -s https://ns.lol/example.com/security | jq',
    ],
    rate_limit: '120 requests/hour per IP',
    family: {
      dns: 'https://ns.lol',
      tls: 'https://certs.lol',
      domains: 'https://yoke.lol',
    },
  };
}

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
