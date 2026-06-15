// Email DNS audit — MX, SPF, DKIM, DMARC

import { querySingle, getRecordTypeNumber } from './dns';

interface EmailSignal {
  id: string;
  category: string;
  label: string;
  status: 'pass' | 'warn' | 'fail' | 'info';
  detail: string;
  explain?: string;
  fix?: string;
}

export async function runEmailCheck(domain: string, explain: boolean): Promise<any> {
  const signals: EmailSignal[] = [];
  const start = performance.now();

  await Promise.all([
    checkMX(domain, signals, explain),
    checkSPF(domain, signals, explain),
    checkDMARC(domain, signals, explain),
    checkDKIM(domain, signals, explain),
    checkMTA_STS(domain, signals, explain),
    checkBIMI(domain, signals, explain),
    checkNullMX(domain, signals),
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
    email: {
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

async function checkMX(domain: string, signals: EmailSignal[], explain: boolean) {
  try {
    const result = await querySingle(domain, getRecordTypeNumber('MX'));
    if (result.records.length === 0) {
      signals.push({
        id: 'mx_missing',
        category: 'MX',
        label: 'MX records',
        status: 'info',
        detail: 'No MX records — domain may not receive email',
        ...(explain && { explain: 'Without MX records, email delivery falls back to A/AAAA records. If you don\'t want email, set a null MX (RFC 7505).' }),
      });
      return;
    }

    // Parse priorities
    const mxRecords = result.records.map((r) => {
      const parts = r.data.split(/\s+/);
      return {
        priority: parseInt(parts[0], 10) || 0,
        host: (parts[1] || parts[0]).replace(/\.$/, ''),
      };
    }).sort((a, b) => a.priority - b.priority);

    signals.push({
      id: 'mx_present',
      category: 'MX',
      label: 'MX records',
      status: 'pass',
      detail: `${mxRecords.length} MX record(s): ${mxRecords.map((m) => `${m.priority} ${m.host}`).join(', ')}`,
    });

    // Check redundancy
    if (mxRecords.length === 1) {
      signals.push({
        id: 'mx_redundancy',
        category: 'MX',
        label: 'MX redundancy',
        status: 'info',
        detail: 'Single MX — no backup mail server',
      });
    }

    // Check for IP literals (bad practice)
    const ipLiterals = mxRecords.filter((m) => /^\d+\.\d+\.\d+\.\d+$/.test(m.host));
    if (ipLiterals.length > 0) {
      signals.push({
        id: 'mx_ip_literal',
        category: 'MX',
        label: 'MX IP literal',
        status: 'fail',
        detail: `MX points to IP address(es) — violates RFC 5321: ${ipLiterals.map((m) => m.host).join(', ')}`,
      });
    }
  } catch (err: any) {
    signals.push({ id: 'mx_error', category: 'MX', label: 'MX check', status: 'warn', detail: `MX check failed: ${err.message}` });
  }
}

async function checkSPF(domain: string, signals: EmailSignal[], explain: boolean) {
  try {
    const result = await querySingle(domain, getRecordTypeNumber('TXT'));
    const spfRecords = result.records.filter((r) =>
      r.data.replace(/^"/, '').startsWith('v=spf1')
    );

    if (spfRecords.length === 0) {
      signals.push({
        id: 'spf_missing',
        category: 'SPF',
        label: 'SPF record',
        status: 'fail',
        detail: 'No SPF record found',
        ...(explain && { explain: 'SPF (Sender Policy Framework) tells receiving servers which IPs are allowed to send mail for your domain. Without it, spoofed emails are harder to detect.' }),
      });
      return;
    }

    if (spfRecords.length > 1) {
      signals.push({
        id: 'spf_multiple',
        category: 'SPF',
        label: 'SPF duplicates',
        status: 'fail',
        detail: `${spfRecords.length} SPF records found — RFC 7208 allows only one`,
        ...(explain && { explain: 'Multiple SPF records cause unpredictable behavior. Merge them into a single record.' }),
      });
    }

    const spf = spfRecords[0].data.replace(/^"|"$/g, '');
    signals.push({ id: 'spf_present', category: 'SPF', label: 'SPF record', status: 'pass', detail: spf });

    // Check for +all (wide open)
    if (/\+all\s*$/.test(spf)) {
      signals.push({
        id: 'spf_permissive',
        category: 'SPF',
        label: 'SPF policy',
        status: 'fail',
        detail: 'SPF uses +all — allows anyone to send as this domain',
      });
    } else if (/~all\s*$/.test(spf)) {
      signals.push({
        id: 'spf_softfail',
        category: 'SPF',
        label: 'SPF policy',
        status: 'warn',
        detail: 'SPF uses ~all (softfail) — consider -all for strict enforcement',
        ...(explain && { explain: 'Softfail (~all) marks unauthorized senders as suspicious but doesn\'t reject them. Hard fail (-all) is stronger.' }),
      });
    } else if (/-all\s*$/.test(spf)) {
      signals.push({ id: 'spf_strict', category: 'SPF', label: 'SPF policy', status: 'pass', detail: 'SPF uses -all (strict)' });
    }

    // Count lookups (max 10 per RFC)
    const lookupMechanisms = (spf.match(/\b(include|a|mx|ptr|exists|redirect)[:=]/gi) || []).length;
    if (lookupMechanisms > 10) {
      signals.push({ id: 'spf_lookups', category: 'SPF', label: 'SPF lookup count', status: 'fail', detail: `${lookupMechanisms} DNS lookups — exceeds RFC 7208 limit of 10` });
    } else if (lookupMechanisms > 7) {
      signals.push({ id: 'spf_lookups', category: 'SPF', label: 'SPF lookup count', status: 'warn', detail: `${lookupMechanisms}/10 DNS lookups used — approaching limit` });
    }
  } catch (err: any) {
    signals.push({ id: 'spf_error', category: 'SPF', label: 'SPF check', status: 'warn', detail: `SPF check failed: ${err.message}` });
  }
}

async function checkDMARC(domain: string, signals: EmailSignal[], explain: boolean) {
  try {
    const dmarcDomain = `_dmarc.${domain}`;
    const result = await querySingle(dmarcDomain, getRecordTypeNumber('TXT'));
    const dmarcRecords = result.records.filter((r) =>
      r.data.replace(/^"/, '').startsWith('v=DMARC1')
    );

    if (dmarcRecords.length === 0) {
      signals.push({
        id: 'dmarc_missing',
        category: 'DMARC',
        label: 'DMARC record',
        status: 'fail',
        detail: 'No DMARC record found',
        ...(explain && { explain: 'DMARC tells receivers what to do when SPF and DKIM both fail. Without it, spoofed emails may be delivered.' }),
      });
      return;
    }

    const dmarc = dmarcRecords[0].data.replace(/^"|"$/g, '');
    signals.push({ id: 'dmarc_present', category: 'DMARC', label: 'DMARC record', status: 'pass', detail: dmarc });

    // Parse policy
    const policyMatch = dmarc.match(/;\s*p=(\w+)/);
    const policy = policyMatch?.[1]?.toLowerCase();

    if (policy === 'none') {
      signals.push({
        id: 'dmarc_policy',
        category: 'DMARC',
        label: 'DMARC policy',
        status: 'warn',
        detail: 'DMARC policy is "none" — monitoring only, no enforcement',
        ...(explain && { explain: '"none" is fine for initial deployment to collect reports, but should be upgraded to "quarantine" or "reject" once you\'re confident in SPF/DKIM setup.' }),
      });
    } else if (policy === 'quarantine') {
      signals.push({ id: 'dmarc_policy', category: 'DMARC', label: 'DMARC policy', status: 'pass', detail: 'DMARC policy: quarantine (suspicious mail goes to spam)' });
    } else if (policy === 'reject') {
      signals.push({ id: 'dmarc_policy', category: 'DMARC', label: 'DMARC policy', status: 'pass', detail: 'DMARC policy: reject (spoofed mail is dropped)' });
    }

    // Check for rua (aggregate reports)
    if (!dmarc.includes('rua=')) {
      signals.push({
        id: 'dmarc_rua',
        category: 'DMARC',
        label: 'DMARC reporting',
        status: 'info',
        detail: 'No rua= tag — DMARC aggregate reports not being collected',
      });
    }
  } catch (err: any) {
    signals.push({ id: 'dmarc_error', category: 'DMARC', label: 'DMARC check', status: 'warn', detail: `DMARC check failed: ${err.message}` });
  }
}

async function checkDKIM(domain: string, signals: EmailSignal[], explain: boolean) {
  // Try common DKIM selector prefixes
  const selectors = ['default', 'google', 'k1', 'selector1', 'selector2', 'dkim', 's1', 's2', 'mail', 'smtp'];
  const found: string[] = [];

  const checks = selectors.map(async (sel) => {
    try {
      const dkimDomain = `${sel}._domainkey.${domain}`;
      const result = await querySingle(dkimDomain, getRecordTypeNumber('TXT'));
      const dkimRecords = result.records.filter((r) => r.data.includes('v=DKIM1') || r.data.includes('k=rsa') || r.data.includes('k=ed25519'));
      if (dkimRecords.length > 0) found.push(sel);
      // Also check CNAME (common for hosted services)
      if (dkimRecords.length === 0) {
        const cnameResult = await querySingle(dkimDomain, getRecordTypeNumber('CNAME'));
        if (cnameResult.records.length > 0) found.push(`${sel} (CNAME)`);
      }
    } catch {
      // Ignore
    }
  });

  await Promise.all(checks);

  if (found.length > 0) {
    signals.push({
      id: 'dkim_found',
      category: 'DKIM',
      label: 'DKIM selectors',
      status: 'pass',
      detail: `Found DKIM at selector(s): ${found.join(', ')}`,
    });
  } else {
    signals.push({
      id: 'dkim_none',
      category: 'DKIM',
      label: 'DKIM selectors',
      status: 'info',
      detail: 'No DKIM records found at common selectors (may use non-standard selector)',
      ...(explain && { explain: 'DKIM selectors are not discoverable — we check common ones (google, default, k1, selector1/2). Your provider may use a different selector.' }),
    });
  }
}

async function checkMTA_STS(domain: string, signals: EmailSignal[], explain: boolean) {
  try {
    const stsRecord = `_mta-sts.${domain}`;
    const result = await querySingle(stsRecord, getRecordTypeNumber('TXT'));
    const stsRecords = result.records.filter((r) => r.data.includes('v=STSv1'));

    if (stsRecords.length > 0) {
      signals.push({
        id: 'mta_sts_present',
        category: 'MTA-STS',
        label: 'MTA-STS',
        status: 'pass',
        detail: 'MTA-STS enabled — enforces TLS for inbound mail',
        ...(explain && { explain: 'MTA-STS (RFC 8461) tells sending servers to require TLS when delivering mail to your domain, preventing downgrade attacks.' }),
      });
    } else {
      signals.push({
        id: 'mta_sts_missing',
        category: 'MTA-STS',
        label: 'MTA-STS',
        status: 'info',
        detail: 'No MTA-STS record — inbound mail TLS not enforced',
      });
    }
  } catch {
    // Non-critical
  }

  // Check TLSRPT
  try {
    const tlsrpt = `_smtp._tls.${domain}`;
    const result = await querySingle(tlsrpt, getRecordTypeNumber('TXT'));
    const rptRecords = result.records.filter((r) => r.data.includes('v=TLSRPTv1'));
    if (rptRecords.length > 0) {
      signals.push({ id: 'tlsrpt_present', category: 'MTA-STS', label: 'TLS-RPT', status: 'pass', detail: 'TLS reporting enabled' });
    }
  } catch {
    // Non-critical
  }
}

async function checkBIMI(domain: string, signals: EmailSignal[], explain: boolean) {
  try {
    const bimiDomain = `default._bimi.${domain}`;
    const result = await querySingle(bimiDomain, getRecordTypeNumber('TXT'));
    const bimiRecords = result.records.filter((r) => r.data.includes('v=BIMI1'));

    if (bimiRecords.length > 0) {
      signals.push({
        id: 'bimi_present',
        category: 'BIMI',
        label: 'BIMI',
        status: 'pass',
        detail: 'BIMI record found — brand logo can appear in supporting email clients',
      });
    }
    // Don't warn if missing — BIMI is optional and advanced
  } catch {
    // Non-critical
  }
}

async function checkNullMX(domain: string, signals: EmailSignal[]) {
  try {
    const result = await querySingle(domain, getRecordTypeNumber('MX'));
    const nullMx = result.records.some((r) => {
      const parts = r.data.split(/\s+/);
      return parts[0] === '0' && (parts[1] === '.' || parts[1] === '');
    });

    if (nullMx) {
      signals.push({
        id: 'null_mx',
        category: 'MX',
        label: 'Null MX',
        status: 'info',
        detail: 'Null MX (RFC 7505) — domain explicitly does not accept email',
      });
    }
  } catch {
    // Ignore
  }
}
