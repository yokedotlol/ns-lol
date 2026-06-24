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
        fix: 'Add a TXT record: v=spf1 -all (if you don\'t send email from this domain) or v=spf1 include:_spf.google.com ~all (for Google Workspace). Adjust the include: for your email provider.',
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
        fix: 'Merge all SPF records into a single TXT record. Multiple SPF records cause unpredictable behavior. Combine all include: and ip4:/ip6: mechanisms into one record starting with v=spf1.',
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
        fix: 'Change +all to -all (hard fail) or ~all (soft fail). +all means any server in the world can send email claiming to be from your domain.',
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

    // Count lookups (max 10 per RFC) — counts direct mechanisms only, not recursive includes
    const lookupMechanisms = (spf.match(/\b(include|a|mx|ptr|exists|redirect)[:=]/gi) || []).length;
    if (lookupMechanisms > 10) {
      signals.push({ id: 'spf_lookups', category: 'SPF', label: 'SPF lookup count', status: 'fail', detail: `${lookupMechanisms} DNS lookups — exceeds RFC 7208 limit of 10 (direct mechanisms only; nested includes may add more)`, fix: `Run a deep SPF analysis at https://ns.lol/${domain}/spf to see the full recursive lookup tree.` });
    } else if (lookupMechanisms > 7) {
      signals.push({ id: 'spf_lookups', category: 'SPF', label: 'SPF lookup count', status: 'warn', detail: `${lookupMechanisms}/10 DNS lookups used — approaching limit (direct mechanisms only; nested includes may add more)`, fix: `Run a deep SPF analysis at https://ns.lol/${domain}/spf to see the full recursive lookup tree.` });
    } else {
      signals.push({ id: 'spf_lookups', category: 'SPF', label: 'SPF lookup count', status: 'pass', detail: `${lookupMechanisms}/10 direct DNS lookups (deep analysis at /${domain}/spf for recursive count)` });
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
        fix: 'Add a TXT record at _dmarc.' + domain + ': v=DMARC1; p=none; rua=mailto:dmarc@' + domain + ' (start with p=none to monitor, then move to p=quarantine or p=reject).',
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
        ...(explain && { explain: 'p=none tells receivers to deliver mail even when SPF and DKIM both fail. It\'s fine for initial deployment to collect reports and identify legitimate senders, but should be upgraded to p=quarantine (spam folder) or p=reject (drop) once you\'re confident all legitimate mail passes SPF/DKIM.' }),
      });
    } else if (policy === 'quarantine') {
      signals.push({
        id: 'dmarc_policy',
        category: 'DMARC',
        label: 'DMARC policy',
        status: 'pass',
        detail: 'DMARC policy: quarantine — mail failing both SPF and DKIM alignment is sent to spam',
        ...(explain && { explain: 'p=quarantine tells receivers to put suspicious mail (failing SPF/DKIM alignment) into the spam folder rather than delivering it to the inbox. This is strong protection while allowing recipients to review false positives.' }),
      });
    } else if (policy === 'reject') {
      signals.push({
        id: 'dmarc_policy',
        category: 'DMARC',
        label: 'DMARC policy',
        status: 'pass',
        detail: 'DMARC policy: reject — mail failing both SPF and DKIM alignment is dropped',
        ...(explain && { explain: 'p=reject is the strongest DMARC policy. It tells receivers to silently drop mail that fails both SPF and DKIM alignment. This is the gold standard but requires confidence that all legitimate mail sources are properly configured.' }),
      });
    }

    // Check for rua (aggregate reports)
    if (!dmarc.includes('rua=')) {
      signals.push({
        id: 'dmarc_rua',
        category: 'DMARC',
        label: 'DMARC reporting',
        status: 'info',
        detail: 'No rua= tag — DMARC aggregate reports not being collected',
        fix: 'Add rua=mailto:dmarc@' + domain + ' to your DMARC record to receive aggregate reports. Free services like Report URI or Postmark DMARC can visualize these reports.',
      });
    }
  } catch (err: any) {
    signals.push({ id: 'dmarc_error', category: 'DMARC', label: 'DMARC check', status: 'warn', detail: `DMARC check failed: ${err.message}` });
  }
}

async function checkDKIM(domain: string, signals: EmailSignal[], explain: boolean) {
  // Try common DKIM selector prefixes
  const selectors = [
    'default', 'google', 'k1', 'selector1', 'selector2', 'dkim', 's1', 's2', 'mail', 'smtp',
    // Provider-specific selectors
    'resend', 'mandrill', 'sendgrid', 'smtpapi', 'amazonses', 'fm1', 'fm2', 'fm3',
    'protonmail', 'protonmail2', 'protonmail3', 'cm', 'mxvault', 'zoho', 'mailjet',
  ];
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
