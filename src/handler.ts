// Request handler — routes paths to DNS operations

import { Env } from './worker';
import { queryAllResolvers, querySingle, getRecordTypeNumber, RECORD_TYPES } from './dns';
import { runHealthCheck } from './health';
import { runEmailCheck } from './email';

// Supported DNS record types for single lookups
const RECORD_TYPE_SLUGS = new Set(
  Object.keys(RECORD_TYPES).map((t) => t.toLowerCase())
);

// Validate domain name
function validateDomain(input: string): string {
  // Strip trailing dot
  let domain = input.replace(/\.$/, '').toLowerCase();
  // Basic validation
  if (domain.length < 1 || domain.length > 253) {
    throw Object.assign(new Error('Invalid domain name'), { status: 400 });
  }
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(domain)) {
    throw Object.assign(new Error('Invalid domain name'), { status: 400 });
  }
  if (!domain.includes('.')) {
    throw Object.assign(new Error('Please provide a fully qualified domain name'), { status: 400 });
  }
  return domain;
}

export async function handleDNSRequest(url: URL, env: Env): Promise<any> {
  const parts = url.pathname.slice(1).split('/').filter(Boolean);

  if (parts.length === 0) {
    throw Object.assign(new Error('No domain specified'), { status: 400 });
  }

  const domain = validateDomain(parts[0]);
  const action = parts[1]?.toLowerCase();
  const explain = url.searchParams.get('explain') === 'true';
  const expected = url.searchParams.get('expected') || null;
  const force = url.searchParams.get('force') === 'true';

  // Check cache unless forced
  if (!force && action !== 'propagation') {
    const cacheKey = `dns:${domain}:${action || 'full'}`;
    const cached = await env.CACHE.get(cacheKey, 'json');
    if (cached) {
      return { ...(cached as object), _cached: true, _cache_control: 'public, max-age=60' };
    }
  }

  let result: any;

  if (!action) {
    // Full DNS report — query all common types via primary resolver
    result = await fullReport(domain, explain);
  } else if (action === 'propagation') {
    // Propagation check — query all resolvers
    result = await propagationCheck(domain, url, expected, explain);
  } else if (action === 'health') {
    // Health report
    result = await runHealthCheck(domain, env, explain);
  } else if (action === 'email') {
    // Email DNS audit
    result = await runEmailCheck(domain, explain);
  } else if (RECORD_TYPE_SLUGS.has(action)) {
    // Single record type lookup
    result = await singleLookup(domain, action.toUpperCase(), explain);
  } else {
    throw Object.assign(new Error(`Unknown action: ${action}. Use a record type (a, aaaa, mx, ...) or: propagation, health, email`), { status: 400 });
  }

  // Cache result
  if (action !== 'propagation') {
    const cacheKey = `dns:${domain}:${action || 'full'}`;
    const ttl = action === 'health' ? 21600 : 3600; // 6h for health, 1h for lookups
    await env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: ttl });
  }

  return result;
}

async function fullReport(domain: string, explain: boolean): Promise<any> {
  const types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'HTTPS'];
  const queries = types.map(async (type) => {
    try {
      const typeNum = getRecordTypeNumber(type);
      const result = await querySingle(domain, typeNum);
      return { type, records: result.records, rcode: result.rcode, query_time_ms: result.query_time_ms };
    } catch {
      return { type, records: [], rcode: 'ERROR', query_time_ms: 0 };
    }
  });

  const results = await Promise.all(queries);
  const records: Record<string, any> = {};

  for (const r of results) {
    if (r.records.length > 0 || r.rcode !== 'NOERROR') {
      records[r.type] = {
        records: r.records,
        rcode: r.rcode,
        query_time_ms: r.query_time_ms,
      };
    }
  }

  const report: any = {
    domain,
    query_time: new Date().toISOString(),
    resolver: 'Cloudflare',
    records,
    _meta: {
      full_report: `https://yoke.lol/${domain}`,
      tls_report: `https://certs.lol/${domain}`,
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
    records: result.records,
    dnssec_authenticated: result.ad,
    query_time_ms: result.query_time_ms,
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

  // Check expected value
  let expected_match: any = undefined;
  if (expected) {
    expected_match = {
      expected: expected,
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
  }

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
    },
    expected_match,
    results,
    _cache_control: 'no-cache',
  };

  if (explain) {
    report._explain = {
      summary: propagation_pct === 100
        ? `${type} records for ${domain} have fully propagated across all ${totalResponded} resolvers checked.`
        : `${type} records for ${domain} show ${propagation_pct}% propagation. ${valueMap.size} distinct answer(s) seen across ${totalResponded} resolvers.`,
      tip: expected
        ? expected_match?.matches === totalResponded
          ? 'Your expected value is live everywhere.'
          : `Your expected value (${expected}) is not live on all resolvers yet. This usually resolves within the TTL window.`
        : 'Add ?expected=1.2.3.4 to track when a specific value goes live.',
    };
  }

  return report;
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
    default:
      return `${records.length} ${type} record(s) found`;
  }
}
