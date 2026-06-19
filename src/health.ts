// Zone health analysis
// Checks DNSSEC, NS diversity, SOA configuration, delegation consistency,
// lame delegation, and recursive vs authoritative differences

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

// DNSSEC algorithm names and strength tiers
const DNSSEC_ALGORITHMS: Record<number, { name: string; tier: 'strong' | 'moderate' | 'weak' | 'deprecated' }> = {
  3:  { name: 'DSA/SHA-1', tier: 'deprecated' },
  5:  { name: 'RSA/SHA-1', tier: 'deprecated' },
  6:  { name: 'DSA-NSEC3-SHA1', tier: 'deprecated' },
  7:  { name: 'RSA-NSEC3-SHA1', tier: 'deprecated' },
  8:  { name: 'RSA/SHA-256', tier: 'moderate' },
  10: { name: 'RSA/SHA-512', tier: 'moderate' },
  13: { name: 'ECDSA P-256/SHA-256', tier: 'strong' },
  14: { name: 'ECDSA P-384/SHA-384', tier: 'strong' },
  15: { name: 'Ed25519', tier: 'strong' },
  16: { name: 'Ed448', tier: 'strong' },
};

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
    checkLameDelegation(domain, signals, explain),
    checkRecursiveVsAuthoritative(domain, signals, explain),
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
        fix: 'Check for expired signatures or key mismatch. Verify with `delv @1.1.1.1 ' + domain + '` or https://dnsviz.net/d/' + domain + '/dnssec/',
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
        fix: 'Enable DNSSEC at your DNS provider (most support one-click DNSSEC). Then publish the DS record at your registrar.',
        ...(explain && { explain: 'No DS record at parent. DNSSEC would protect against cache poisoning and man-in-the-middle attacks.' }),
      });
    }

    // Enhanced DNSSEC grading: algorithm analysis, KSK/ZSK separation, NSEC detection
    if (hasDNSKEY) {
      const keyData = dnskeyResult.records.map((r) => r.data);

      // Parse algorithms from DNSKEY records
      // Format: "flags protocol algorithm base64key"
      const algNumbers: number[] = [];
      let hasKSK = false;
      let hasZSK = false;
      for (const d of keyData) {
        const parts = d.split(/\s+/);
        if (parts.length >= 3) {
          const flags = parseInt(parts[0], 10);
          const alg = parseInt(parts[2], 10);
          if (!isNaN(alg)) algNumbers.push(alg);
          // Flag 257 = KSK (Secure Entry Point), 256 = ZSK
          if (flags === 257) hasKSK = true;
          if (flags === 256) hasZSK = true;
        }
      }

      // Unique algorithms
      const uniqueAlgs = [...new Set(algNumbers)];
      const algDetails = uniqueAlgs.map(a => DNSSEC_ALGORITHMS[a] || { name: `Algorithm ${a}`, tier: 'moderate' as const });

      // Determine worst-case tier
      const tiers = algDetails.map(a => a.tier);
      const hasDeprecated = tiers.includes('deprecated');
      const hasWeak = tiers.includes('weak');
      const allStrong = tiers.every(t => t === 'strong');

      if (hasDeprecated) {
        signals.push({
          id: 'dnssec_algo',
          category: 'DNSSEC',
          label: 'Algorithm strength',
          status: 'fail',
          detail: `Using deprecated algorithm: ${algDetails.filter(a => a.tier === 'deprecated').map(a => a.name).join(', ')}`,
          fix: 'Migrate to ECDSA P-256 (algorithm 13) or Ed25519 (algorithm 15). SHA-1 based algorithms are vulnerable to collision attacks.',
        });
      } else if (allStrong) {
        signals.push({
          id: 'dnssec_algo',
          category: 'DNSSEC',
          label: 'Algorithm strength',
          status: 'pass',
          detail: `Strong algorithm: ${algDetails.map(a => a.name).join(', ')}`,
        });
      } else {
        signals.push({
          id: 'dnssec_algo',
          category: 'DNSSEC',
          label: 'Algorithm strength',
          status: hasWeak ? 'warn' : 'info',
          detail: `Using ${algDetails.map(a => a.name).join(', ')} — consider ECDSA P-256 or Ed25519 for smaller signatures and better performance`,
          fix: 'Migrate to algorithm 13 (ECDSA P-256) for a good balance of security and performance, or algorithm 15 (Ed25519) for the best performance.',
        });
      }

      // KSK/ZSK separation
      if (hasKSK && hasZSK) {
        signals.push({
          id: 'dnssec_key_separation',
          category: 'DNSSEC',
          label: 'Key separation',
          status: 'pass',
          detail: 'KSK (key-signing key) and ZSK (zone-signing key) are separated — best practice for key lifecycle management',
        });
      } else if (keyData.length === 1) {
        signals.push({
          id: 'dnssec_key_separation',
          category: 'DNSSEC',
          label: 'Key separation',
          status: 'info',
          detail: 'Single DNSKEY (combined signing key) — KSK/ZSK separation is optional but recommended for key rollovers',
          ...(explain && { explain: 'A single CSK is simpler but means the DS record at the parent must be updated on every key rollover. Separate KSK/ZSK allows ZSK rollovers without touching the parent zone.' }),
        });
      }

      // Check DS digest type
      if (hasDS) {
        const dsData = dsResult.records.map((r) => r.data);
        const digestTypes: number[] = [];
        for (const d of dsData) {
          const parts = d.split(/\s+/);
          if (parts.length >= 3) {
            const dt = parseInt(parts[2], 10);
            if (!isNaN(dt)) digestTypes.push(dt);
          }
        }
        const hasSHA1DS = digestTypes.includes(1);
        const hasSHA256DS = digestTypes.includes(2);
        const hasSHA384DS = digestTypes.includes(4);

        if (hasSHA1DS && !hasSHA256DS && !hasSHA384DS) {
          signals.push({
            id: 'dnssec_ds_digest',
            category: 'DNSSEC',
            label: 'DS digest type',
            status: 'warn',
            detail: 'DS record uses only SHA-1 digest (type 1) — SHA-256 (type 2) is recommended',
            fix: 'Publish a DS record with SHA-256 digest (type 2) at your registrar. You can keep the SHA-1 DS for backward compatibility.',
          });
        } else if (hasSHA256DS || hasSHA384DS) {
          signals.push({
            id: 'dnssec_ds_digest',
            category: 'DNSSEC',
            label: 'DS digest type',
            status: 'pass',
            detail: `DS record uses ${hasSHA384DS ? 'SHA-384' : 'SHA-256'} digest — strong`,
          });
        }
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
    const nameservers = nsResult.records.filter((r) => r.type === 'NS').map((r) => r.data.replace(/\.$/, ''));

    if (nameservers.length === 0) {
      signals.push({
        id: 'ns_missing',
        category: 'Nameservers',
        label: 'NS records',
        status: 'fail',
        detail: 'No NS records found',
        fix: 'Every domain needs at least 2 NS records. Configure them at your registrar or DNS provider.',
      });
      return;
    }

    // Count
    if (nameservers.length >= 3) {
      signals.push({ id: 'ns_count', category: 'Nameservers', label: 'NS count', status: 'pass', detail: `${nameservers.length} nameservers (good redundancy)` });
    } else if (nameservers.length === 2) {
      signals.push({ id: 'ns_count', category: 'Nameservers', label: 'NS count', status: 'pass', detail: '2 nameservers (minimum for redundancy)' });
    } else {
      signals.push({ id: 'ns_count', category: 'Nameservers', label: 'NS count', status: 'fail', detail: 'Only 1 nameserver — no redundancy', fix: 'Add at least one more nameserver. Most DNS providers include secondary NS for free.' });
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
        fix: 'Consider adding a secondary DNS provider (e.g., add Cloudflare secondary NS alongside your primary provider) to survive provider-level outages.',
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
        fix: `Remove or replace these nameservers at your registrar: ${unresolvable.map((r) => r.ns).join(', ')}. Lame nameservers slow down resolution and reduce redundancy.`,
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
      signals.push({ id: 'soa_missing', category: 'SOA', label: 'SOA record', status: 'fail', detail: 'No SOA record found', fix: 'Every zone must have a SOA record. This is usually auto-generated by your DNS provider.' });
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
        signals.push({ id: 'soa_refresh', category: 'SOA', label: 'Refresh interval', status: 'warn', detail: `Refresh ${refresh}s is very low — high secondary polling load`, fix: 'Set SOA refresh to at least 3600 (1 hour) for most zones, or 900 (15m) for fast-changing zones.' });
      } else if (refresh > 86400) {
        signals.push({ id: 'soa_refresh', category: 'SOA', label: 'Refresh interval', status: 'warn', detail: `Refresh ${refresh}s (${Math.round(refresh / 3600)}h) is very high — secondaries may serve stale data`, fix: `Reduce SOA refresh to 3600-14400 (1-4 hours). Current value of ${Math.round(refresh / 3600)}h means changes take a long time to propagate to secondaries.` });
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
        signals.push({ id: 'soa_ncache', category: 'SOA', label: 'Negative cache TTL', status: 'warn', detail: `Negative TTL ${minimum}s (${Math.round(minimum / 3600)}h) — NXDOMAIN cached longer than needed`, fix: `Set SOA minimum to 300-3600 (5m-1h). Current value of ${Math.round(minimum / 3600)}h means resolvers cache negative responses (NXDOMAIN) for a long time, making new record additions slow to take effect.` });
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
        fix: 'NS records should be identical everywhere. If you recently changed DNS providers, wait for full propagation (up to 48h). Otherwise, check your registrar\'s NS delegation and your zone\'s NS records are in sync.',
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
        signals.push({ id: 'response_slow', category: 'Response', label: 'Response time', status: 'warn', detail: `Slow DNS: avg ${avg}ms, max ${max}ms`, fix: 'Consider using a CDN or managed DNS provider with global anycast for faster resolution. Average response times should be under 100ms.' });
      } else if (avg > 500) {
        signals.push({ id: 'response_moderate', category: 'Response', label: 'Response time', status: 'info', detail: `Moderate DNS latency: avg ${avg}ms` });
      }
    }
  } catch {
    // Non-critical
  }
}

// ── Lame Delegation Check (C5) ──────────────────────────────────────
// Checks whether each listed NS hostname resolves and the zone has SOA records.
// Limitation: CF Workers use DoH, so we can't query each NS directly to inspect
// the AA (Authoritative Answer) flag. A true lame-delegation check requires direct
// UDP queries to each NS. The Fly probe's /authoritative endpoint could back a
// future implementation. For now, this catches the common case: NS hostnames that
// don't resolve at all, which is the most impactful lame delegation scenario.

async function checkLameDelegation(domain: string, signals: HealthSignal[], explain: boolean) {
  try {
    const nsResult = await querySingle(domain, getRecordTypeNumber('NS'));
    const nameservers = nsResult.records
      .filter((r) => r.type === 'NS')
      .map((r) => r.data.replace(/\.$/, ''));

    if (nameservers.length === 0) return;

    // For each NS, resolve it and then query the domain through it to check if it's authoritative
    // Since we can only use DoH from CF Workers, we check by querying through different resolvers
    // and looking for the AA flag. A fully authoritative NS should return AA=true.
    // We can also query the NS hostnames and check if they serve the zone.
    const lameResults: { ns: string; authoritative: boolean; error?: string }[] = [];

    await Promise.all(
      nameservers.slice(0, 6).map(async (ns) => {
        try {
          // First resolve the NS to an IP
          const aResult = await querySingle(ns, getRecordTypeNumber('A'));
          if (aResult.records.length === 0) {
            lameResults.push({ ns, authoritative: false, error: 'NS hostname does not resolve' });
            return;
          }

          // Query the domain's SOA through a resolver — we can't query the NS directly via DoH
          // but we can check if the NS hostname resolves and if it's in the zone's SOA MNAME
          const soaResult = await querySingle(domain, getRecordTypeNumber('SOA'));
          if (soaResult.records.length > 0) {
            const soaMname = soaResult.records[0].data.split(/\s+/)[0]?.replace(/\.$/, '');
            lameResults.push({
              ns,
              authoritative: true,
              // Note: can't fully verify AA flag without direct NS query
            });
          } else {
            lameResults.push({ ns, authoritative: false, error: 'SOA query returned no records' });
          }
        } catch (err: any) {
          lameResults.push({ ns, authoritative: false, error: err.message });
        }
      })
    );

    const lameNS = lameResults.filter(r => !r.authoritative);
    if (lameNS.length > 0) {
      signals.push({
        id: 'lame_ns',
        category: 'Nameservers',
        label: 'Lame NS detected',
        status: 'fail',
        detail: `${lameNS.length} nameserver(s) appear lame: ${lameNS.map(r => `${r.ns} (${r.error})`).join(', ')}`,
        fix: `Remove or replace these nameservers at your registrar. A lame NS is listed in the delegation but doesn't serve the zone, causing resolution delays and SERVFAIL responses.`,
        ...(explain && { explain: 'A lame nameserver is one that is listed in the parent delegation but does not actually serve authoritative data for the zone. This causes a portion of DNS queries to fail or be slow.' }),
      });
    }
  } catch {
    // Non-critical — basic lame check in checkNameservers handles the common case
  }
}

// ── Recursive vs Authoritative Diff (C19) ───────────────────────────

async function checkRecursiveVsAuthoritative(domain: string, signals: HealthSignal[], explain: boolean) {
  try {
    const typeNum = getRecordTypeNumber('A');

    // Query through 3 different resolvers
    const resolverResults = await Promise.allSettled(
      DOH_RESOLVERS.slice(0, 3).map(async (r) => {
        const result = await queryDoH(r.url, domain, typeNum);
        return {
          resolver: r.name,
          records: result.answers.map(a => a.data).sort(),
          aa: result.flags.aa,
          ad: result.flags.ad,
          rcode: rcodeName(result.rcode),
          ttl: result.answers[0]?.TTL || 0,
        };
      })
    );

    const successful = resolverResults
      .filter((r): r is PromiseFulfilledResult<any> => r.status === 'fulfilled')
      .map(r => r.value);

    if (successful.length < 2) return;

    // Check if any resolver got an authoritative answer (AA flag) vs cached
    const authResults = successful.filter(r => r.aa);
    const cachedResults = successful.filter(r => !r.aa);

    if (authResults.length > 0 && cachedResults.length > 0) {
      // Compare auth vs cached answers
      const authIPs = authResults[0].records;
      const cachedIPs = cachedResults[0].records;
      const match = authIPs.length === cachedIPs.length && authIPs.every((ip: string, i: number) => ip === cachedIPs[i]);

      if (!match) {
        signals.push({
          id: 'auth_cache_diff',
          category: 'Response',
          label: 'Authoritative vs cached',
          status: 'warn',
          detail: `Authoritative answer (${authResults[0].resolver}: ${authIPs.join(', ')}) differs from cached (${cachedResults[0].resolver}: ${cachedIPs.join(', ')})`,
          fix: 'This usually indicates a recent DNS change that hasn\'t fully propagated. Wait for cached TTLs to expire. If persistent, check for DNS poisoning or misconfigured GeoDNS.',
          ...(explain && { explain: 'When a resolver has a cached (non-authoritative) answer that differs from the authoritative answer, it usually means a recent change is still propagating. The difference resolves when the TTL expires.' }),
        });
      }
    }

    // Check for TTL anomalies between resolvers (big TTL differences suggest caching lag)
    const ttls = successful.map(r => r.ttl).filter(t => t > 0);
    if (ttls.length >= 2) {
      const maxTTL = Math.max(...ttls);
      const minTTL = Math.min(...ttls);
      // If TTL difference is more than 50% of max, something may be off
      if (maxTTL > 0 && (maxTTL - minTTL) > maxTTL * 0.5 && maxTTL - minTTL > 60) {
        signals.push({
          id: 'ttl_variance',
          category: 'Response',
          label: 'TTL variance',
          status: 'info',
          detail: `Large TTL variance across resolvers: ${minTTL}s to ${maxTTL}s — different cache ages`,
          ...(explain && { explain: 'Large TTL differences between resolvers indicate they cached the record at different times. This is normal and expected — it\'s not a misconfiguration.' }),
        });
      }
    }
  } catch {
    // Non-critical
  }
}
