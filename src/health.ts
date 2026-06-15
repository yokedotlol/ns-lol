// Zone health analysis
// Checks DNSSEC, NS diversity, SOA configuration, delegation consistency

import { Env } from './worker';
import { querySingle, queryDoH, getRecordTypeNumber, DOH_RESOLVERS, rcodeName } from './dns';

interface HealthSignal {
  id: string;
  category: string;
  label: string;
  status: 'pass' | 'warn' | 'fail' | 'info';
  detail: string;
  explain?: string;
  fix?: string;
}

export async function runHealthCheck(domain: string, env: Env, explain: boolean): Promise<any> {
  const signals: HealthSignal[] = [];
  const start = performance.now();

  // Run all checks in parallel
  await Promise.all([
    checkDNSSEC(domain, signals, explain),
    checkNameservers(domain, signals, explain),
    checkSOA(domain, signals, explain),
    checkDelegation(domain, signals, explain),
    checkResponseConsistency(domain, signals, explain),
  ]);

  const elapsed = Math.round(performance.now() - start);

  // Compute summary
  const counts = { pass: 0, warn: 0, fail: 0, info: 0 };
  for (const s of signals) counts[s.status]++;

  let grade: 'A' | 'B' | 'C' | 'D' | 'F';
  if (counts.fail === 0 && counts.warn === 0) grade = 'A';
  else if (counts.fail === 0 && counts.warn <= 2) grade = 'B';
  else if (counts.fail <= 1) grade = 'C';
  else if (counts.fail <= 3) grade = 'D';
  else grade = 'F';

  return {
    domain,
    query_time: new Date().toISOString(),
    health: {
      grade,
      signals_checked: signals.length,
      ...counts,
    },
    signals,
    analysis_time_ms: elapsed,
    _meta: {
      full_report: `https://yoke.lol/${domain}`,
      tls_report: `https://certs.lol/${domain}`,
    },
  };
}

async function checkDNSSEC(domain: string, signals: HealthSignal[], explain: boolean) {
  try {
    // Check for DS records at parent
    const dsResult = await querySingle(domain, getRecordTypeNumber('DS'));
    const hasDS = dsResult.records.length > 0;

    // Check for DNSKEY at zone
    const dnskeyResult = await querySingle(domain, getRecordTypeNumber('DNSKEY'));
    const hasDNSKEY = dnskeyResult.records.length > 0;

    // Check AD flag on A query
    const aResult = await querySingle(domain, getRecordTypeNumber('A'));

    if (hasDS && hasDNSKEY && aResult.ad) {
      signals.push({
        id: 'dnssec_valid',
        category: 'DNSSEC',
        label: 'DNSSEC validation',
        status: 'pass',
        detail: 'DNSSEC is enabled and validating (AD flag set)',
        ...(explain && { explain: 'DS records at parent, DNSKEY in zone, and resolver confirms authentication.' }),
      });
    } else if (hasDS && hasDNSKEY) {
      signals.push({
        id: 'dnssec_partial',
        category: 'DNSSEC',
        label: 'DNSSEC validation',
        status: 'warn',
        detail: 'DNSSEC records present but AD flag not set — possible validation issue',
        fix: 'Check for expired signatures or key mismatch. Verify with `delv` or DNSViz.',
        ...(explain && { explain: 'DS and DNSKEY exist but the resolver did not set the Authenticated Data flag. This could indicate a signature issue.' }),
      });
    } else if (hasDS && !hasDNSKEY) {
      signals.push({
        id: 'dnssec_broken',
        category: 'DNSSEC',
        label: 'DNSSEC delegation',
        status: 'fail',
        detail: 'DS record at parent but no DNSKEY in zone — DNSSEC is broken',
        fix: 'Either publish DNSKEY records in your zone, or remove the DS record at your registrar. Validating resolvers will SERVFAIL until this is fixed.',
        ...(explain && { explain: 'The parent zone has a DS record pointing to this zone, but the zone does not publish a DNSKEY. Validating resolvers will return SERVFAIL.' }),
      });
    } else {
      signals.push({
        id: 'dnssec_absent',
        category: 'DNSSEC',
        label: 'DNSSEC',
        status: 'info',
        detail: 'DNSSEC is not enabled',
        ...(explain && { explain: 'No DS record at parent. DNSSEC would protect against cache poisoning and man-in-the-middle attacks.' }),
      });
    }

    // Check algorithm strength if DNSKEY present
    if (hasDNSKEY) {
      const keyData = dnskeyResult.records.map((r) => r.data);
      const hasECDSA = keyData.some((d) => d.includes(' 13 ') || d.includes(' 14 '));
      const hasEdDSA = keyData.some((d) => d.includes(' 15 ') || d.includes(' 16 '));
      const hasRSA = keyData.some((d) => d.includes(' 8 ') || d.includes(' 10 '));

      if (hasEdDSA) {
        signals.push({ id: 'dnssec_algo', category: 'DNSSEC', label: 'Algorithm', status: 'pass', detail: 'Using EdDSA (modern, fast)' });
      } else if (hasECDSA) {
        signals.push({ id: 'dnssec_algo', category: 'DNSSEC', label: 'Algorithm', status: 'pass', detail: 'Using ECDSA (P-256/P-384)' });
      } else if (hasRSA) {
        signals.push({ id: 'dnssec_algo', category: 'DNSSEC', label: 'Algorithm', status: 'warn', detail: 'Using RSA — consider upgrading to ECDSA for smaller signatures' });
      }
    }
  } catch (err: any) {
    signals.push({
      id: 'dnssec_error',
      category: 'DNSSEC',
      label: 'DNSSEC check',
      status: 'warn',
      detail: `Could not check DNSSEC: ${err.message}`,
    });
  }
}

async function checkNameservers(domain: string, signals: HealthSignal[], explain: boolean) {
  try {
    const nsResult = await querySingle(domain, getRecordTypeNumber('NS'));
    const nameservers = nsResult.records.map((r) => r.data.replace(/\.$/, ''));

    if (nameservers.length === 0) {
      signals.push({
        id: 'ns_missing',
        category: 'Nameservers',
        label: 'NS records',
        status: 'fail',
        detail: 'No NS records found',
      });
      return;
    }

    // Count
    if (nameservers.length >= 3) {
      signals.push({ id: 'ns_count', category: 'Nameservers', label: 'NS count', status: 'pass', detail: `${nameservers.length} nameservers (good redundancy)` });
    } else if (nameservers.length === 2) {
      signals.push({ id: 'ns_count', category: 'Nameservers', label: 'NS count', status: 'pass', detail: '2 nameservers (minimum for redundancy)' });
    } else {
      signals.push({ id: 'ns_count', category: 'Nameservers', label: 'NS count', status: 'fail', detail: 'Only 1 nameserver — no redundancy', fix: 'Add at least one more nameserver for redundancy. Most registrars provide a free secondary NS.' });
    }

    // Provider diversity — check if all NS share same suffix
    const suffixes = new Set(nameservers.map((ns) => ns.split('.').slice(-2).join('.')));
    if (suffixes.size === 1 && nameservers.length > 1) {
      signals.push({
        id: 'ns_diversity',
        category: 'Nameservers',
        label: 'Provider diversity',
        status: 'info',
        detail: `All nameservers under ${[...suffixes][0]} — single-provider dependency`,
        ...(explain && { explain: 'If the DNS provider has an outage, all nameservers go down together. Some operators add a secondary DNS provider.' }),
      });
    } else if (suffixes.size > 1) {
      signals.push({ id: 'ns_diversity', category: 'Nameservers', label: 'Provider diversity', status: 'pass', detail: `${suffixes.size} distinct NS domains — good diversity` });
    }

    // Check if all nameservers resolve (quick — just A records)
    const nsResolutions = await Promise.all(
      nameservers.slice(0, 4).map(async (ns) => {
        try {
          const result = await querySingle(ns, getRecordTypeNumber('A'));
          return { ns, resolves: result.records.length > 0 };
        } catch {
          return { ns, resolves: false };
        }
      })
    );

    const unresolvable = nsResolutions.filter((r) => !r.resolves);
    if (unresolvable.length > 0) {
      signals.push({
        id: 'ns_lame',
        category: 'Nameservers',
        label: 'Lame delegation',
        status: 'fail',
        detail: `${unresolvable.length} nameserver(s) don't resolve: ${unresolvable.map((r) => r.ns).join(', ')}`,
        ...(explain && { explain: 'A lame delegation means a listed nameserver cannot be reached, reducing redundancy and sometimes causing slow lookups.' }),
      });
    }
  } catch (err: any) {
    signals.push({ id: 'ns_error', category: 'Nameservers', label: 'NS check', status: 'warn', detail: `Could not check nameservers: ${err.message}` });
  }
}

async function checkSOA(domain: string, signals: HealthSignal[], explain: boolean) {
  try {
    const soaResult = await querySingle(domain, getRecordTypeNumber('SOA'));
    if (soaResult.records.length === 0) {
      signals.push({ id: 'soa_missing', category: 'SOA', label: 'SOA record', status: 'fail', detail: 'No SOA record found' });
      return;
    }

    const soaData = soaResult.records[0].data;
    // SOA format: mname rname serial refresh retry expire minimum
    const parts = soaData.split(/\s+/);
    if (parts.length >= 7) {
      const serial = parseInt(parts[2], 10);
      const refresh = parseInt(parts[3], 10);
      const retry = parseInt(parts[4], 10);
      const expire = parseInt(parts[5], 10);
      const minimum = parseInt(parts[6], 10);

      signals.push({ id: 'soa_present', category: 'SOA', label: 'SOA record', status: 'pass', detail: `Serial: ${serial}, Primary: ${parts[0]}` });

      // Check refresh interval
      if (refresh < 300) {
        signals.push({ id: 'soa_refresh', category: 'SOA', label: 'Refresh interval', status: 'warn', detail: `Refresh ${refresh}s is very low — high secondary polling load` });
      } else if (refresh > 86400) {
        signals.push({ id: 'soa_refresh', category: 'SOA', label: 'Refresh interval', status: 'warn', detail: `Refresh ${refresh}s (${Math.round(refresh / 3600)}h) is very high — secondaries may serve stale data` });
      }

      // Check expire
      if (expire < 604800) {
        signals.push({
          id: 'soa_expire',
          category: 'SOA',
          label: 'Expire value',
          status: 'info',
          detail: `Expire ${expire}s (${Math.round(expire / 86400)}d) — RFC 1912 recommends 2-4 weeks`,
          ...(explain && { explain: 'If secondaries cannot reach the primary for this long, they stop serving the zone.' }),
        });
      }

      // Negative cache TTL
      if (minimum > 3600) {
        signals.push({ id: 'soa_ncache', category: 'SOA', label: 'Negative cache TTL', status: 'warn', detail: `Negative TTL ${minimum}s (${Math.round(minimum / 3600)}h) — NXDOMAIN cached longer than needed` });
      }
    }
  } catch (err: any) {
    signals.push({ id: 'soa_error', category: 'SOA', label: 'SOA check', status: 'warn', detail: `Could not check SOA: ${err.message}` });
  }
}

async function checkDelegation(domain: string, signals: HealthSignal[], explain: boolean) {
  try {
    // Query NS from two different resolvers and compare
    const typeNum = getRecordTypeNumber('NS');
    const [cf, google] = await Promise.all([
      queryDoH(DOH_RESOLVERS[0].url, domain, typeNum),
      queryDoH(DOH_RESOLVERS[1].url, domain, typeNum),
    ]);

    const cfNS = new Set(cf.answers.map((r) => r.data.replace(/\.$/, '').toLowerCase()));
    const googleNS = new Set(google.answers.map((r) => r.data.replace(/\.$/, '').toLowerCase()));

    if (cfNS.size === 0 && googleNS.size === 0) return; // Already caught by NS check

    const symmetric = cfNS.size === googleNS.size && [...cfNS].every((ns) => googleNS.has(ns));
    if (symmetric) {
      signals.push({ id: 'delegation_consistent', category: 'Delegation', label: 'Delegation consistency', status: 'pass', detail: 'NS records consistent across Cloudflare and Google' });
    } else {
      signals.push({
        id: 'delegation_mismatch',
        category: 'Delegation',
        label: 'Delegation consistency',
        status: 'warn',
        detail: `NS mismatch between resolvers: CF sees ${[...cfNS].join(', ')} — Google sees ${[...googleNS].join(', ')}`,
        ...(explain && { explain: 'Different resolvers seeing different NS records usually means a recent change is still propagating, or there is a configuration issue.' }),
      });
    }
  } catch {
    // Non-critical
  }
}

async function checkResponseConsistency(domain: string, signals: HealthSignal[], explain: boolean) {
  try {
    // Check if A records are consistent across a few resolvers
    const typeNum = getRecordTypeNumber('A');
    const resolverSubset = DOH_RESOLVERS.slice(0, 5);
    const results = await Promise.allSettled(
      resolverSubset.map((r) => queryDoH(r.url, domain, typeNum))
    );

    const answers = results
      .filter((r): r is PromiseFulfilledResult<any> => r.status === 'fulfilled')
      .map((r) => r.value.answers.map((a: any) => a.data).sort().join(','));

    const unique = new Set(answers);
    if (unique.size === 1 && answers.length > 1) {
      signals.push({
        id: 'response_consistent',
        category: 'Response',
        label: 'A record consistency',
        status: 'pass',
        detail: `Same A records across ${answers.length} resolvers`,
      });
    } else if (unique.size > 1) {
      signals.push({
        id: 'response_inconsistent',
        category: 'Response',
        label: 'A record consistency',
        status: 'info',
        detail: `${unique.size} distinct A record sets across ${answers.length} resolvers — may indicate GeoDNS or load balancing`,
        ...(explain && { explain: 'Different A records from different resolvers is normal for CDNs and GeoDNS setups, but unexpected for simple sites.' }),
      });
    }

    // Response time analysis
    const times = results
      .filter((r): r is PromiseFulfilledResult<any> => r.status === 'fulfilled')
      .map((r) => r.value.query_time_ms);

    if (times.length > 0) {
      const avg = Math.round(times.reduce((a, b) => a + b, 0) / times.length);
      const max = Math.max(...times);
      if (max > 1000) {
        signals.push({ id: 'response_slow', category: 'Response', label: 'Response time', status: 'warn', detail: `Slow DNS: avg ${avg}ms, max ${max}ms` });
      } else if (avg > 500) {
        signals.push({ id: 'response_moderate', category: 'Response', label: 'Response time', status: 'info', detail: `Moderate DNS latency: avg ${avg}ms` });
      }
    }
  } catch {
    // Non-critical
  }
}
