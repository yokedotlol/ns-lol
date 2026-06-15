// Security checks — dangling CNAME, dangling NS, CNAME chain analysis, CDN detection,
// NXDOMAIN hijacking, NS diversity

import { querySingle, getRecordTypeNumber } from './dns';

interface SecuritySignal {
  id: string;
  category: string;
  label: string;
  status: 'pass' | 'warn' | 'fail' | 'info';
  detail: string;
  fix?: string;
  explain?: string;
}

// Known CDN/hosting CNAME patterns
const CDN_PATTERNS: [RegExp, string][] = [
  [/\.cloudflare\.net$/i, 'Cloudflare'],
  [/\.cloudfront\.net$/i, 'Amazon CloudFront'],
  [/\.fastly\.net$/i, 'Fastly'],
  [/\.akamaiedge\.net$/i, 'Akamai'],
  [/\.akamai\.net$/i, 'Akamai'],
  [/\.edgekey\.net$/i, 'Akamai'],
  [/\.azurewebsites\.net$/i, 'Azure App Service'],
  [/\.azure-api\.net$/i, 'Azure API Management'],
  [/\.azureedge\.net$/i, 'Azure CDN'],
  [/\.trafficmanager\.net$/i, 'Azure Traffic Manager'],
  [/\.netlify\.app$/i, 'Netlify'],
  [/\.vercel\.app$/i, 'Vercel'],
  [/\.vercel-dns\.com$/i, 'Vercel'],
  [/\.github\.io$/i, 'GitHub Pages'],
  [/\.herokuapp\.com$/i, 'Heroku'],
  [/\.herokudns\.com$/i, 'Heroku'],
  [/\.wpengine\.com$/i, 'WP Engine'],
  [/\.pantheonsite\.io$/i, 'Pantheon'],
  [/\.squarespace\.com$/i, 'Squarespace'],
  [/\.shopify\.com$/i, 'Shopify'],
  [/\.myshopify\.com$/i, 'Shopify'],
  [/\.zendesk\.com$/i, 'Zendesk'],
  [/\.ghost\.io$/i, 'Ghost'],
  [/\.fly\.dev$/i, 'Fly.io'],
  [/\.render\.com$/i, 'Render'],
  [/\.railway\.app$/i, 'Railway'],
  [/\.pages\.dev$/i, 'Cloudflare Pages'],
  [/\.workers\.dev$/i, 'Cloudflare Workers'],
  [/\.googleusercontent\.com$/i, 'Google Cloud'],
  [/\.appspot\.com$/i, 'Google App Engine'],
  [/\.firebaseapp\.com$/i, 'Firebase'],
  [/\.amazonaws\.com$/i, 'AWS'],
  [/\.elb\.amazonaws\.com$/i, 'AWS ELB'],
  [/\.s3\.amazonaws\.com$/i, 'AWS S3'],
  [/\.s3-website.*\.amazonaws\.com$/i, 'AWS S3 Website'],
  [/\.dualstack\./i, 'AWS (dualstack)'],
  [/\.cdn\.cloudflare\.net$/i, 'Cloudflare CDN'],
  [/\.incapdns\.net$/i, 'Imperva/Incapsula'],
  [/\.sucuri\.net$/i, 'Sucuri'],
  [/\.stackpathdns\.com$/i, 'StackPath'],
  [/\.edgecastcdn\.net$/i, 'Edgecast/Verizon'],
];

// Known services that indicate dangling CNAME risk if target doesn't resolve
const TAKEOVER_CANDIDATES: [RegExp, string][] = [
  [/\.s3\.amazonaws\.com$/i, 'AWS S3'],
  [/\.s3-website.*\.amazonaws\.com$/i, 'AWS S3 Website'],
  [/\.herokuapp\.com$/i, 'Heroku'],
  [/\.herokudns\.com$/i, 'Heroku'],
  [/\.github\.io$/i, 'GitHub Pages'],
  [/\.pantheonsite\.io$/i, 'Pantheon'],
  [/\.ghost\.io$/i, 'Ghost'],
  [/\.myshopify\.com$/i, 'Shopify'],
  [/\.zendesk\.com$/i, 'Zendesk'],
  [/\.readme\.io$/i, 'ReadMe'],
  [/\.surge\.sh$/i, 'Surge.sh'],
  [/\.bitbucket\.io$/i, 'Bitbucket'],
  [/\.ghost\.org$/i, 'Ghost'],
  [/\.helpjuice\.com$/i, 'HelpJuice'],
  [/\.helpscoutdocs\.com$/i, 'HelpScout'],
  [/\.freshdesk\.com$/i, 'Freshdesk'],
  [/\.wordpress\.com$/i, 'WordPress.com'],
  [/\.tumblr\.com$/i, 'Tumblr'],
  [/\.cargocollective\.com$/i, 'Cargo'],
  [/\.uservoice\.com$/i, 'UserVoice'],
  [/\.azurewebsites\.net$/i, 'Azure'],
  [/\.cloudapp\.net$/i, 'Azure'],
  [/\.trafficmanager\.net$/i, 'Azure Traffic Manager'],
];

export async function runSecurityCheck(domain: string, explain: boolean): Promise<any> {
  const signals: SecuritySignal[] = [];
  const start = performance.now();

  await Promise.all([
    checkDanglingCNAME(domain, signals, explain),
    checkDanglingNS(domain, signals, explain),
    checkCNAMEChain(domain, signals, explain),
    detectCDN(domain, signals, explain),
    checkWildcard(domain, signals, explain),
    checkNSdiversity(domain, signals, explain),
    checkNXDOMAINHijacking(domain, signals, explain),
  ]);

  const elapsed = Math.round(performance.now() - start);

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
    security: {
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

async function checkDanglingCNAME(domain: string, signals: SecuritySignal[], explain: boolean) {
  try {
    const cnameResult = await querySingle(domain, getRecordTypeNumber('CNAME'));
    if (cnameResult.records.length === 0) return;

    const target = cnameResult.records[0].data.replace(/\.$/, '');

    // Check if target resolves
    const targetA = await querySingle(target, getRecordTypeNumber('A'));
    const targetAAAA = await querySingle(target, getRecordTypeNumber('AAAA'));

    if (targetA.records.length === 0 && targetAAAA.records.length === 0) {
      // Check if it's a known takeover-susceptible service
      const service = TAKEOVER_CANDIDATES.find(([re]) => re.test(target));

      if (service) {
        signals.push({
          id: 'dangling_cname_takeover',
          category: 'Subdomain Takeover',
          label: 'Dangling CNAME — takeover risk',
          status: 'fail',
          detail: `CNAME points to ${target} (${service[1]}) which does not resolve. This may be vulnerable to subdomain takeover.`,
          fix: `Remove the CNAME record for ${domain} pointing to ${target}, or reconfigure it to point to an active resource on ${service[1]}. An attacker could claim "${target}" on ${service[1]} and serve content on your domain.`,
          ...(explain && { explain: `A dangling CNAME to a service like ${service[1]} means an attacker could claim that resource name and serve content on your domain.` }),
        });
      } else {
        signals.push({
          id: 'dangling_cname',
          category: 'Subdomain Takeover',
          label: 'Dangling CNAME',
          status: 'warn',
          detail: `CNAME points to ${target} which does not resolve`,
          fix: `Remove or update the CNAME record pointing to ${target} — the target no longer exists. In your DNS zone, delete the CNAME for ${domain} or update it to a live target.`,
        });
      }
    } else {
      signals.push({
        id: 'cname_valid',
        category: 'CNAME',
        label: 'CNAME target',
        status: 'pass',
        detail: `CNAME to ${target} resolves correctly`,
      });
    }
  } catch {
    // No CNAME is fine
  }
}

async function checkDanglingNS(domain: string, signals: SecuritySignal[], explain: boolean) {
  try {
    const nsResult = await querySingle(domain, getRecordTypeNumber('NS'));
    if (nsResult.records.length === 0) return;

    const nameservers = nsResult.records.filter((r) => r.type === "NS").map((r) => r.data.replace(/\.$/, ''));
    const danglingNS: string[] = [];

    const checks = nameservers.map(async (ns) => {
      try {
        const aResult = await querySingle(ns, getRecordTypeNumber('A'));
        if (aResult.records.length === 0) {
          const aaaaResult = await querySingle(ns, getRecordTypeNumber('AAAA'));
          if (aaaaResult.records.length === 0) {
            danglingNS.push(ns);
          }
        }
      } catch {
        danglingNS.push(ns);
      }
    });

    await Promise.all(checks);

    if (danglingNS.length > 0) {
      signals.push({
        id: 'dangling_ns',
        category: 'Nameserver Security',
        label: 'Dangling NS — domain takeover risk',
        status: 'fail',
        detail: `${danglingNS.length} nameserver(s) do not resolve: ${danglingNS.join(', ')}. This is a critical domain takeover risk.`,
        fix: `Remove or replace these NS records at your registrar immediately: ${danglingNS.join(', ')}. If the nameserver domain is available for registration, an attacker could register it and take full control of your DNS.`,
        ...(explain && { explain: 'If an attacker registers the dangling nameserver hostname, they can serve arbitrary DNS responses for your domain — including redirecting all traffic.' }),
      });
    } else {
      signals.push({
        id: 'ns_all_resolve',
        category: 'Nameserver Security',
        label: 'NS records',
        status: 'pass',
        detail: 'All nameservers resolve correctly',
      });
    }
  } catch {
    // Non-critical
  }
}

async function checkCNAMEChain(domain: string, signals: SecuritySignal[], explain: boolean) {
  try {
    let current = domain;
    const chain: string[] = [domain];
    let depth = 0;
    const maxDepth = 10;

    while (depth < maxDepth) {
      const result = await querySingle(current, getRecordTypeNumber('CNAME'));
      if (result.records.length === 0) break;
      const target = result.records[0].data.replace(/\.$/, '');
      if (chain.includes(target)) {
        signals.push({
          id: 'cname_loop',
          category: 'CNAME',
          label: 'CNAME loop detected',
          status: 'fail',
          detail: `Circular CNAME chain: ${chain.join(' → ')} → ${target}`,
          fix: `Break the circular CNAME reference. Change one of the CNAME records to point to an A/AAAA record instead: ${chain.join(' → ')} → ${target}`,
        });
        return;
      }
      chain.push(target);
      current = target;
      depth++;
    }

    if (chain.length > 3) {
      signals.push({
        id: 'cname_deep',
        category: 'CNAME',
        label: 'Deep CNAME chain',
        status: 'warn',
        detail: `${chain.length - 1} CNAME hops: ${chain.join(' → ')}. Each hop adds DNS latency.`,
        fix: `Point ${domain} directly to the final target (${chain[chain.length - 1]}) to eliminate ${chain.length - 2} unnecessary CNAME hops and reduce DNS latency by ~${(chain.length - 2) * 20}ms.`,
        ...(explain && { explain: 'Each CNAME hop requires an additional DNS lookup, adding ~5-50ms of latency per hop.' }),
      });
    } else if (chain.length > 1) {
      signals.push({
        id: 'cname_chain',
        category: 'CNAME',
        label: 'CNAME chain',
        status: 'info',
        detail: `${chain.length - 1} hop(s): ${chain.join(' → ')}`,
      });
    }
  } catch {
    // Non-critical
  }
}

export function detectCDNFromRecords(records: any[]): string | null {
  for (const r of records) {
    const data = r.data?.replace(/\.$/, '') || '';
    for (const [pattern, name] of CDN_PATTERNS) {
      if (pattern.test(data)) return name;
    }
  }
  return null;
}

async function detectCDN(domain: string, signals: SecuritySignal[], explain: boolean) {
  try {
    const cnameResult = await querySingle(domain, getRecordTypeNumber('CNAME'));
    const cdn = detectCDNFromRecords(cnameResult.records);

    if (cdn) {
      signals.push({
        id: 'cdn_detected',
        category: 'Infrastructure',
        label: 'CDN/Hosting',
        status: 'info',
        detail: `Detected: ${cdn} (via CNAME)`,
      });
      return;
    }

    // Check A records for known CDN IP ranges (simplified)
    const aResult = await querySingle(domain, getRecordTypeNumber('A'));
    // Cloudflare IP ranges (simplified check)
    const cfRanges = ['104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.', '104.23.', '104.24.', '104.25.', '104.26.', '104.27.', '172.67.', '173.245.'];
    for (const r of aResult.records) {
      if (cfRanges.some((prefix) => r.data.startsWith(prefix))) {
        signals.push({
          id: 'cdn_detected',
          category: 'Infrastructure',
          label: 'CDN/Hosting',
          status: 'info',
          detail: 'Detected: Cloudflare (via IP range)',
        });
        return;
      }
    }
  } catch {
    // Non-critical
  }
}

async function checkWildcard(domain: string, signals: SecuritySignal[], explain: boolean) {
  try {
    // Query a random subdomain to check for wildcards
    const random = `_nslol-wildcard-test-${Date.now()}.${domain}`;
    const result = await querySingle(random, getRecordTypeNumber('A'));

    if (result.records.length > 0 && result.rcode === 'NOERROR') {
      signals.push({
        id: 'wildcard_detected',
        category: 'DNS Configuration',
        label: 'Wildcard DNS',
        status: 'info',
        detail: `Wildcard *.${domain} is configured — all subdomains resolve to ${result.records.map((r) => r.data).join(', ')}`,
        ...(explain && { explain: 'Wildcard DNS means any subdomain will resolve, even if not explicitly configured. This is normal for some setups (CDNs, catch-all services) but can mask subdomain takeover vulnerabilities.' }),
      });
    }
  } catch {
    // Non-critical
  }
}

async function checkNSdiversity(domain: string, signals: SecuritySignal[], explain: boolean) {
  try {
    const nsResult = await querySingle(domain, getRecordTypeNumber('NS'));
    if (nsResult.records.length < 2) return;

    const nameservers = nsResult.records.filter((r) => r.type === "NS").map((r) => r.data.replace(/\.$/, ''));

    // Resolve all NS to IPs and check /24 subnet diversity
    const ips: { ns: string; ip: string }[] = [];
    await Promise.all(
      nameservers.map(async (ns) => {
        try {
          const result = await querySingle(ns, getRecordTypeNumber('A'));
          for (const r of result.records) {
            ips.push({ ns, ip: r.data });
          }
        } catch { }
      })
    );

    if (ips.length < 2) return;

    // Check subnet diversity (/24)
    const subnets = new Set(ips.map((i) => i.ip.split('.').slice(0, 3).join('.')));
    if (subnets.size === 1) {
      signals.push({
        id: 'ns_same_subnet',
        category: 'Nameserver Security',
        label: 'NS subnet diversity',
        status: 'warn',
        detail: `All nameserver IPs are in the same /24 subnet (${[...subnets][0]}.0/24). A single network issue could take all nameservers offline.`,
        fix: 'Use nameservers in different networks. Options: add a secondary DNS provider (Cloudflare, AWS Route 53, or Google Cloud DNS offer free secondary), or use nameservers with IPs in different /24 subnets.',
        ...(explain && { explain: 'Best practice is to have nameservers in different networks (ideally different providers) to survive localized outages.' }),
      });
    } else {
      signals.push({
        id: 'ns_diverse_subnets',
        category: 'Nameserver Security',
        label: 'NS network diversity',
        status: 'pass',
        detail: `Nameserver IPs span ${subnets.size} distinct /24 subnets`,
      });
    }
  } catch {
    // Non-critical
  }
}

// ── NXDOMAIN Hijacking Detection (C13) ──────────────────────────────

async function checkNXDOMAINHijacking(domain: string, signals: SecuritySignal[], explain: boolean) {
  try {
    // Query a known-nonexistent random subdomain
    const randomHex = Math.random().toString(16).slice(2, 10);
    const testDomain = `_nslol-nx-${randomHex}.${domain}`;

    const result = await querySingle(testDomain, getRecordTypeNumber('A'));

    // If we get NXDOMAIN, that's correct — no hijacking
    if (result.rcode === 'NXDOMAIN') {
      signals.push({
        id: 'nxdomain_clean',
        category: 'DNS Integrity',
        label: 'NXDOMAIN handling',
        status: 'pass',
        detail: 'Non-existent subdomains correctly return NXDOMAIN',
      });
      return;
    }

    // If we get records back for a non-existent subdomain, check if it's wildcarding or ISP hijacking
    if (result.rcode === 'NOERROR' && result.records.length > 0) {
      // Check if the domain has a wildcard record — already detected by checkWildcard
      // If the response IPs look like known ISP hijacking/ad servers, flag it
      const ips = result.records.filter(r => r.type === 'A').map(r => r.data);

      // Known ISP NXDOMAIN hijacking IP ranges (partial list)
      const knownHijackIPs = [
        '67.215.65.',   // OpenDNS Guide
        '156.154.175.', // Neustar/UltraDNS
        '92.242.140.',  // British Telecom
        '198.105.244.', // CenturyLink
        '23.209.',      // Akamai (sometimes used for ISP redirect)
      ];

      const isHijacked = ips.some(ip =>
        knownHijackIPs.some(prefix => ip.startsWith(prefix))
      );

      if (isHijacked) {
        signals.push({
          id: 'nxdomain_hijacked',
          category: 'DNS Integrity',
          label: 'NXDOMAIN hijacking',
          status: 'warn',
          detail: `Resolver is hijacking NXDOMAIN responses — non-existent subdomain returned ${ips.join(', ')} instead of NXDOMAIN`,
          fix: 'This is usually caused by the ISP or resolver intercepting NXDOMAIN responses to show ads or search pages. Switch to a clean resolver like 1.1.1.1, 8.8.8.8, or 9.9.9.9.',
          ...(explain && { explain: 'Some ISPs and resolvers intercept NXDOMAIN (non-existent domain) responses and redirect them to their own servers to show search suggestions or ads. This breaks applications that rely on NXDOMAIN and is considered a privacy concern.' }),
        });
      } else {
        // This is likely a wildcard DNS record (*.domain.com), not hijacking
        // The wildcard check handles this case — don't double-report
        // Only flag if it looks suspicious (not matching wildcard IPs)
        signals.push({
          id: 'nxdomain_wildcard',
          category: 'DNS Integrity',
          label: 'NXDOMAIN override',
          status: 'info',
          detail: `Non-existent subdomains return records (${ips.join(', ')}) — likely wildcard DNS, not hijacking`,
        });
      }
    }
  } catch {
    // Non-critical — query failure doesn't indicate an issue
  }
}
