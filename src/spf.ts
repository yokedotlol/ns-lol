// Deep SPF analysis — recursive lookup budget tracking, term explanations,
// include tree resolution, IP range expansion, and issue detection.

import { querySingle, queryDoH, getRecordTypeNumber, DOH_RESOLVERS } from './dns';

// ── Types ────────────────────────────────────────────────────────────

export interface SPFTerm {
  raw: string;
  qualifier: '+' | '-' | '~' | '?';
  mechanism: string;
  argument: string;
  explanation: string;
  lookups: number;             // DNS lookups this term consumes
  ip_count?: number;           // authorized IP count (for ip4/ip6)
  cidr?: string;               // CIDR notation
}

export interface SPFNode {
  domain: string;
  record: string;
  terms: SPFTerm[];
  lookups: number;             // total lookups at this node (direct only)
  includes: SPFNode[];         // recursive include children
  error?: string;
}

export interface SPFIssue {
  severity: 'error' | 'warn' | 'info';
  code: string;
  message: string;
}

export interface SPFAnalysis {
  domain: string;
  has_spf: boolean;
  record?: string;
  lookups_used: number;
  lookups_max: number;
  tree: SPFNode | null;
  issues: SPFIssue[];
  authorized_ip4_count: number;
  authorized_ip6_count: number;
  ip4_ranges: string[];
  ip6_ranges: string[];
  analysis_time_ms: number;
}

// ── Constants ────────────────────────────────────────────────────────

const MAX_LOOKUPS = 10;
const MAX_DEPTH = 10;      // prevent infinite loops
const MAX_VOID_LOOKUPS = 2; // RFC 7208 §4.6.4

// Well-known SPF include domains → provider names
const KNOWN_PROVIDERS: Record<string, string> = {
  '_spf.google.com': 'Google Workspace',
  '_netblocks.google.com': 'Google',
  '_netblocks2.google.com': 'Google',
  '_netblocks3.google.com': 'Google',
  'spf.protection.outlook.com': 'Microsoft 365',
  'spf.messagelabs.com': 'Broadcom/Symantec Email',
  'amazonses.com': 'Amazon SES',
  '_spf.salesforce.com': 'Salesforce',
  'sendgrid.net': 'SendGrid',
  'spf.mandrillapp.com': 'Mailchimp/Mandrill',
  'mail.zendesk.com': 'Zendesk',
  'servers.mcsv.net': 'Mailchimp',
  'mktomail.com': 'Marketo',
  'spf.mtasv.net': 'Postmark',
  '_spf.mx.cloudflare.net': 'Cloudflare Email Routing',
  'spf.messagingengine.com': 'Fastmail',
  '_spf.protonmail.ch': 'Proton Mail',
  'secureserver.net': 'GoDaddy',
  '_spf.firebasemail.com': 'Firebase',
  'spf1.hubspot.com': 'HubSpot',
  'mailgun.org': 'Mailgun',
  'email.freshdesk.com': 'Freshdesk',
  'helpscoutemail.com': 'Help Scout',
  'aspmx.pardot.com': 'Pardot/Salesforce',
  'stspg-customer.com': 'StatusPage',
  'zoho.com': 'Zoho Mail',
  '_spf.intuit.com': 'Intuit',
};

function getProviderName(domain: string): string | null {
  const lower = domain.toLowerCase();
  for (const [pattern, name] of Object.entries(KNOWN_PROVIDERS)) {
    if (lower === pattern || lower.endsWith('.' + pattern)) return name;
  }
  return null;
}

// ── Main entry point ─────────────────────────────────────────────────

export async function runSPFAnalysis(domain: string): Promise<SPFAnalysis> {
  const start = performance.now();
  const issues: SPFIssue[] = [];
  const visited = new Set<string>();
  const allIp4: string[] = [];
  const allIp6: string[] = [];

  // Fetch the root SPF record
  let spfRecords: string[] = [];
  try {
    const result = await querySingle(domain, getRecordTypeNumber('TXT'));
    spfRecords = result.records
      .filter(r => r.data.replace(/^"/, '').startsWith('v=spf1'))
      .map(r => r.data.replace(/^"|"$/g, ''));
  } catch (err: any) {
    return {
      domain,
      has_spf: false,
      lookups_used: 0,
      lookups_max: MAX_LOOKUPS,
      tree: null,
      issues: [{ severity: 'error', code: 'spf_dns_error', message: `DNS query failed: ${err.message}` }],
      authorized_ip4_count: 0,
      authorized_ip6_count: 0,
      ip4_ranges: [],
      ip6_ranges: [],
      analysis_time_ms: Math.round(performance.now() - start),
    };
  }

  if (spfRecords.length === 0) {
    return {
      domain,
      has_spf: false,
      lookups_used: 0,
      lookups_max: MAX_LOOKUPS,
      tree: null,
      issues: [{ severity: 'error', code: 'spf_missing', message: 'No SPF record found for this domain' }],
      authorized_ip4_count: 0,
      authorized_ip6_count: 0,
      ip4_ranges: [],
      ip6_ranges: [],
      analysis_time_ms: Math.round(performance.now() - start),
    };
  }

  if (spfRecords.length > 1) {
    issues.push({
      severity: 'error',
      code: 'spf_multiple',
      message: `${spfRecords.length} SPF records found — RFC 7208 allows only one. Receivers may pick either unpredictably.`,
    });
  }

  const tree = await resolveNode(domain, spfRecords[0], visited, issues, allIp4, allIp6, 0);

  // Count total lookups recursively
  const totalLookups = countLookups(tree);

  if (totalLookups > MAX_LOOKUPS) {
    issues.push({
      severity: 'error',
      code: 'spf_too_many_lookups',
      message: `${totalLookups} DNS lookups used — exceeds the RFC 7208 limit of 10. SPF evaluation will permerror and receivers may reject your mail.`,
    });
  } else if (totalLookups > 7) {
    issues.push({
      severity: 'warn',
      code: 'spf_near_limit',
      message: `${totalLookups}/10 DNS lookups used — approaching the limit. Adding another include: or service could push you over.`,
    });
  }

  // Check for void lookups
  const voidCount = countVoidLookups(tree);
  if (voidCount > MAX_VOID_LOOKUPS) {
    issues.push({
      severity: 'warn',
      code: 'spf_void_lookups',
      message: `${voidCount} void lookups (mechanisms that resolve to nothing). RFC 7208 §4.6.4 limits these to ${MAX_VOID_LOOKUPS}.`,
    });
  }

  const ip4Count = allIp4.reduce((sum, cidr) => sum + cidrSize(cidr, 4), 0);
  const ip6Count = allIp6.reduce((sum, cidr) => sum + cidrSize(cidr, 6), 0);

  return {
    domain,
    has_spf: true,
    record: spfRecords[0],
    lookups_used: totalLookups,
    lookups_max: MAX_LOOKUPS,
    tree,
    issues,
    authorized_ip4_count: ip4Count,
    authorized_ip6_count: ip6Count,
    ip4_ranges: [...new Set(allIp4)],
    ip6_ranges: [...new Set(allIp6)],
    analysis_time_ms: Math.round(performance.now() - start),
  };
}

// ── Recursive resolver ───────────────────────────────────────────────

async function resolveNode(
  domain: string,
  record: string,
  visited: Set<string>,
  issues: SPFIssue[],
  allIp4: string[],
  allIp6: string[],
  depth: number
): Promise<SPFNode> {
  if (depth > MAX_DEPTH) {
    return { domain, record, terms: [], lookups: 0, includes: [], error: 'Maximum include depth exceeded' };
  }

  const key = domain.toLowerCase();
  if (visited.has(key)) {
    issues.push({ severity: 'warn', code: 'spf_loop', message: `Circular include detected: ${domain}` });
    return { domain, record, terms: [], lookups: 0, includes: [], error: 'Circular include' };
  }
  visited.add(key);

  const rawTerms = record.replace(/^v=spf1\s*/, '').trim().split(/\s+/).filter(Boolean);
  const terms: SPFTerm[] = [];
  const includes: SPFNode[] = [];
  let directLookups = 0;

  for (const raw of rawTerms) {
    const term = parseTerm(raw, domain);
    terms.push(term);
    directLookups += term.lookups;

    // Collect IP ranges
    if (term.mechanism === 'ip4' && term.cidr) allIp4.push(term.cidr);
    if (term.mechanism === 'ip6' && term.cidr) allIp6.push(term.cidr);

    // Check for issues
    if (term.mechanism === 'all' && term.qualifier === '+') {
      issues.push({
        severity: 'error',
        code: 'spf_plus_all',
        message: `+all allows ANY server to send email as ${domain}. This effectively disables SPF.`,
      });
    }
    if (term.mechanism === 'all' && term.qualifier === '?') {
      issues.push({
        severity: 'warn',
        code: 'spf_neutral_all',
        message: `?all is neutral — SPF provides no opinion on unauthorized senders. Consider ~all or -all.`,
      });
    }
    if (term.mechanism === 'ptr') {
      issues.push({
        severity: 'warn',
        code: 'spf_ptr_deprecated',
        message: `"ptr" mechanism is deprecated (RFC 7208 §5.5) — it's slow, unreliable, and should be replaced with ip4:/ip6: or include:.`,
      });
    }

    // Recursively resolve includes
    if (term.mechanism === 'include' && term.argument) {
      try {
        const childResult = await querySingle(term.argument, getRecordTypeNumber('TXT'));
        const childSpf = childResult.records
          .filter(r => r.data.replace(/^"/, '').startsWith('v=spf1'))
          .map(r => r.data.replace(/^"|"$/g, ''));

        if (childSpf.length > 0) {
          const childNode = await resolveNode(term.argument, childSpf[0], visited, issues, allIp4, allIp6, depth + 1);
          includes.push(childNode);
        } else {
          includes.push({
            domain: term.argument,
            record: '(no SPF record)',
            terms: [],
            lookups: 0,
            includes: [],
            error: 'No SPF record found',
          });
          // This is a void lookup — count it but note it
        }
      } catch (err: any) {
        includes.push({
          domain: term.argument,
          record: '(DNS error)',
          terms: [],
          lookups: 0,
          includes: [],
          error: err.message,
        });
      }
    }

    // Resolve redirect
    if (term.mechanism === 'redirect' && term.argument) {
      try {
        const redirectResult = await querySingle(term.argument, getRecordTypeNumber('TXT'));
        const redirectSpf = redirectResult.records
          .filter(r => r.data.replace(/^"/, '').startsWith('v=spf1'))
          .map(r => r.data.replace(/^"|"$/g, ''));

        if (redirectSpf.length > 0) {
          const redirectNode = await resolveNode(term.argument, redirectSpf[0], visited, issues, allIp4, allIp6, depth + 1);
          includes.push(redirectNode);
        }
      } catch (err: any) {
        issues.push({ severity: 'error', code: 'spf_redirect_error', message: `redirect=${term.argument} failed: ${err.message}` });
      }
    }

    // Resolve a: and mx: mechanisms to find their IPs
    if (term.mechanism === 'a') {
      const target = term.argument || domain;
      try {
        const aResult = await querySingle(target, getRecordTypeNumber('A'));
        for (const r of aResult.records) {
          if (r.type === 'A') allIp4.push(r.data + '/32');
        }
        const aaaaResult = await querySingle(target, getRecordTypeNumber('AAAA'));
        for (const r of aaaaResult.records) {
          if (r.type === 'AAAA') allIp6.push(r.data + '/128');
        }
      } catch { /* non-critical */ }
    }

    if (term.mechanism === 'mx') {
      const target = term.argument || domain;
      try {
        const mxResult = await querySingle(target, getRecordTypeNumber('MX'));
        for (const r of mxResult.records) {
          const host = r.data.split(/\s+/).pop()?.replace(/\.$/, '');
          if (host) {
            try {
              const aResult = await querySingle(host, getRecordTypeNumber('A'));
              for (const ar of aResult.records) {
                if (ar.type === 'A') allIp4.push(ar.data + '/32');
              }
            } catch { /* skip */ }
          }
        }
      } catch { /* non-critical */ }
    }
  }

  return { domain, record, terms, lookups: directLookups, includes };
}

// ── Term parser ──────────────────────────────────────────────────────

function parseTerm(raw: string, contextDomain: string): SPFTerm {
  // Handle redirect= and exp= modifiers
  if (raw.startsWith('redirect=')) {
    const arg = raw.slice(9);
    return {
      raw,
      qualifier: '+',
      mechanism: 'redirect',
      argument: arg,
      explanation: `Redirect SPF evaluation to ${arg}'s policy — this domain's own mechanisms are ignored if redirect is reached`,
      lookups: 1,
    };
  }
  if (raw.startsWith('exp=')) {
    return {
      raw,
      qualifier: '+',
      mechanism: 'exp',
      argument: raw.slice(4),
      explanation: 'Custom explanation string for SPF failures (exp= modifier)',
      lookups: 0,
    };
  }

  // Parse qualifier
  let qualifier: '+' | '-' | '~' | '?' = '+';
  let rest = raw;
  if (/^[+\-~?]/.test(rest)) {
    qualifier = rest[0] as any;
    rest = rest.slice(1);
  }

  // Parse mechanism:argument
  const colonIdx = rest.indexOf(':');
  const slashIdx = rest.indexOf('/');
  let mechanism: string;
  let argument = '';
  let cidrSuffix = '';

  if (colonIdx > 0) {
    mechanism = rest.slice(0, colonIdx).toLowerCase();
    const afterColon = rest.slice(colonIdx + 1);
    // Separate CIDR suffix if present
    const cidx = afterColon.indexOf('/');
    if (cidx > 0) {
      argument = afterColon.slice(0, cidx);
      cidrSuffix = afterColon.slice(cidx);
    } else {
      argument = afterColon;
    }
  } else if (slashIdx > 0) {
    mechanism = rest.slice(0, slashIdx).toLowerCase();
    cidrSuffix = rest.slice(slashIdx);
  } else {
    mechanism = rest.toLowerCase();
  }

  const qualWord = qualifier === '+' ? 'Pass' : qualifier === '-' ? 'Fail' : qualifier === '~' ? 'Soft fail' : 'Neutral';

  let explanation = '';
  let lookups = 0;
  let ip_count: number | undefined;
  let cidr: string | undefined;

  switch (mechanism) {
    case 'all':
      lookups = 0;
      if (qualifier === '+') explanation = '⚠️ Allow ALL senders — anyone can send email as this domain (dangerous)';
      else if (qualifier === '-') explanation = 'Hard fail all other senders — unauthorized mail should be rejected';
      else if (qualifier === '~') explanation = 'Soft fail all other senders — unauthorized mail may land in spam';
      else explanation = 'Neutral — no opinion on unauthorized senders';
      break;

    case 'include': {
      lookups = 1;
      const provider = getProviderName(argument);
      if (provider) {
        explanation = `Evaluate ${provider}'s SPF record (${argument}) — ${qualWord.toLowerCase()} if it passes`;
      } else {
        explanation = `Evaluate ${argument}'s SPF record — ${qualWord.toLowerCase()} if it passes`;
      }
      break;
    }

    case 'a':
      lookups = 1;
      if (argument) {
        explanation = `${qualWord} if the sender IP matches ${argument}'s A/AAAA records${cidrSuffix ? ` (${cidrSuffix} CIDR)` : ''}`;
      } else {
        explanation = `${qualWord} if the sender IP matches ${contextDomain}'s own A/AAAA records${cidrSuffix ? ` (${cidrSuffix} CIDR)` : ''}`;
      }
      break;

    case 'mx':
      lookups = 1;
      if (argument) {
        explanation = `${qualWord} if the sender IP matches ${argument}'s mail server IPs${cidrSuffix ? ` (${cidrSuffix} CIDR)` : ''}`;
      } else {
        explanation = `${qualWord} if the sender IP matches ${contextDomain}'s mail server IPs${cidrSuffix ? ` (${cidrSuffix} CIDR)` : ''}`;
      }
      break;

    case 'ip4': {
      lookups = 0;
      cidr = argument + (cidrSuffix || (/\//.test(argument) ? '' : '/32'));
      ip_count = cidrSize(cidr, 4);
      explanation = `${qualWord} emails from ${ip_count.toLocaleString()} IPv4 address${ip_count !== 1 ? 'es' : ''} in ${cidr}`;
      break;
    }

    case 'ip6': {
      lookups = 0;
      cidr = argument + (cidrSuffix || (/\//.test(argument) ? '' : '/128'));
      ip_count = cidrSize(cidr, 6);
      const label = ip_count > 1e15 ? `~2^${Math.round(Math.log2(ip_count))}` : ip_count.toLocaleString();
      explanation = `${qualWord} emails from ${label} IPv6 address${ip_count !== 1 ? 'es' : ''} in ${cidr}`;
      break;
    }

    case 'ptr':
      lookups = 1;
      explanation = `⚠️ Deprecated: ${qualWord} if sender's reverse DNS matches ${argument || contextDomain} (slow, unreliable — use ip4:/ip6: instead)`;
      break;

    case 'exists':
      lookups = 1;
      explanation = `${qualWord} if a DNS A record exists for ${argument} (macro-expanded pattern)`;
      break;

    default:
      explanation = `Unknown mechanism: ${raw}`;
  }

  return { raw, qualifier, mechanism, argument, explanation, lookups, ip_count, cidr };
}

// ── Helpers ──────────────────────────────────────────────────────────

function countLookups(node: SPFNode): number {
  let total = node.lookups;
  for (const child of node.includes) {
    total += countLookups(child);
  }
  return total;
}

function countVoidLookups(node: SPFNode): number {
  let count = 0;
  for (const child of node.includes) {
    if (child.error && !child.error.includes('Circular')) count++;
    count += countVoidLookups(child);
  }
  return count;
}

function cidrSize(cidr: string, version: 4 | 6): number {
  const parts = cidr.split('/');
  const prefix = parseInt(parts[1], 10);
  if (isNaN(prefix)) return 1;
  const maxBits = version === 4 ? 32 : 128;
  const hostBits = maxBits - prefix;
  if (hostBits <= 0) return 1;
  if (hostBits > 53) return Math.pow(2, hostBits); // approximate for huge ranges
  return Math.pow(2, hostBits);
}
