// Tests for email DNS audit (MX, SPF, DKIM, DMARC, etc.)

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runEmailCheck } from '../email';

// Mock DNS queries
vi.mock('../dns', async () => {
  const actual = await vi.importActual('../dns') as any;
  return {
    ...actual,
    querySingle: vi.fn(),
  };
});

import { querySingle } from '../dns';
const mockQuerySingle = querySingle as ReturnType<typeof vi.fn>;

// Helper to make a resolver result
function resolverResult(records: any[], rcode = 'NOERROR') {
  return {
    resolver: 'Cloudflare',
    location: 'San Francisco, US',
    lat: 37.77, lng: -122.42,
    records, rcode,
    aa: false, ad: false,
    query_time_ms: 10,
  };
}

describe('runEmailCheck', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default: return empty results for all queries
    mockQuerySingle.mockResolvedValue(resolverResult([]));
  });

  it('returns a graded email report', async () => {
    const result = await runEmailCheck('example.com', false);
    expect(result.domain).toBe('example.com');
    expect(result.email).toBeDefined();
    expect(result.email.grade).toMatch(/^[A-F]$/);
    expect(result.signals).toBeDefined();
    expect(Array.isArray(result.signals)).toBe(true);
  });

  it('detects missing MX as info (not fail)', async () => {
    const result = await runEmailCheck('example.com', false);
    const mxSignal = result.signals.find((s: any) => s.id === 'mx_missing');
    expect(mxSignal).toBeDefined();
    expect(mxSignal.status).toBe('info');
  });

  it('detects present MX records', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      // MX query (type 15)
      if (type === 15 && !domain.startsWith('_')) {
        return resolverResult([
          { type: 'MX', name: 'example.com', TTL: 3600, data: '10 mail.example.com.' },
          { type: 'MX', name: 'example.com', TTL: 3600, data: '20 mail2.example.com.' },
        ]);
      }
      return resolverResult([]);
    });

    const result = await runEmailCheck('example.com', false);
    const mxPresent = result.signals.find((s: any) => s.id === 'mx_present');
    expect(mxPresent).toBeDefined();
    expect(mxPresent.status).toBe('pass');
    expect(mxPresent.detail).toContain('2 MX record(s)');
  });

  it('detects missing SPF as fail', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      // Return TXT without SPF
      if (type === 16 && !domain.startsWith('_')) {
        return resolverResult([
          { type: 'TXT', name: 'example.com', TTL: 3600, data: '"google-site-verification=abc"' },
        ]);
      }
      return resolverResult([]);
    });

    const result = await runEmailCheck('example.com', false);
    const spfMissing = result.signals.find((s: any) => s.id === 'spf_missing');
    expect(spfMissing).toBeDefined();
    expect(spfMissing.status).toBe('fail');
  });

  it('detects valid SPF with -all', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (type === 16 && !domain.startsWith('_')) {
        return resolverResult([
          { type: 'TXT', name: 'example.com', TTL: 3600, data: '"v=spf1 include:_spf.google.com -all"' },
        ]);
      }
      return resolverResult([]);
    });

    const result = await runEmailCheck('example.com', false);
    const spfPresent = result.signals.find((s: any) => s.id === 'spf_present');
    const spfStrict = result.signals.find((s: any) => s.id === 'spf_strict');
    expect(spfPresent).toBeDefined();
    expect(spfPresent.status).toBe('pass');
    expect(spfStrict).toBeDefined();
    expect(spfStrict.status).toBe('pass');
  });

  it('warns on SPF ~all (softfail)', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (type === 16 && !domain.startsWith('_')) {
        return resolverResult([
          { type: 'TXT', name: 'example.com', TTL: 3600, data: '"v=spf1 include:_spf.google.com ~all"' },
        ]);
      }
      return resolverResult([]);
    });

    const result = await runEmailCheck('example.com', false);
    const spfSoft = result.signals.find((s: any) => s.id === 'spf_softfail');
    expect(spfSoft).toBeDefined();
    expect(spfSoft.status).toBe('warn');
  });

  it('fails on SPF +all (open relay)', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (type === 16 && !domain.startsWith('_')) {
        return resolverResult([
          { type: 'TXT', name: 'example.com', TTL: 3600, data: '"v=spf1 +all"' },
        ]);
      }
      return resolverResult([]);
    });

    const result = await runEmailCheck('example.com', false);
    const spfPermissive = result.signals.find((s: any) => s.id === 'spf_permissive');
    expect(spfPermissive).toBeDefined();
    expect(spfPermissive.status).toBe('fail');
  });

  it('fails on multiple SPF records', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (type === 16 && !domain.startsWith('_')) {
        return resolverResult([
          { type: 'TXT', name: 'example.com', TTL: 3600, data: '"v=spf1 include:a.com -all"' },
          { type: 'TXT', name: 'example.com', TTL: 3600, data: '"v=spf1 include:b.com -all"' },
        ]);
      }
      return resolverResult([]);
    });

    const result = await runEmailCheck('example.com', false);
    const spfMultiple = result.signals.find((s: any) => s.id === 'spf_multiple');
    expect(spfMultiple).toBeDefined();
    expect(spfMultiple.status).toBe('fail');
  });

  it('detects missing DMARC as fail', async () => {
    const result = await runEmailCheck('example.com', false);
    const dmarcMissing = result.signals.find((s: any) => s.id === 'dmarc_missing');
    expect(dmarcMissing).toBeDefined();
    expect(dmarcMissing.status).toBe('fail');
  });

  it('detects DMARC with p=none as warn', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (domain === '_dmarc.example.com' && type === 16) {
        return resolverResult([
          { type: 'TXT', name: '_dmarc.example.com', TTL: 3600, data: '"v=DMARC1; p=none; rua=mailto:d@example.com"' },
        ]);
      }
      return resolverResult([]);
    });

    const result = await runEmailCheck('example.com', false);
    const dmarcPresent = result.signals.find((s: any) => s.id === 'dmarc_present');
    const dmarcPolicy = result.signals.find((s: any) => s.id === 'dmarc_policy');
    expect(dmarcPresent).toBeDefined();
    expect(dmarcPresent.status).toBe('pass');
    expect(dmarcPolicy).toBeDefined();
    expect(dmarcPolicy.status).toBe('warn');
  });

  it('passes DMARC with p=reject', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (domain === '_dmarc.example.com' && type === 16) {
        return resolverResult([
          { type: 'TXT', name: '_dmarc.example.com', TTL: 3600, data: '"v=DMARC1; p=reject; rua=mailto:d@example.com"' },
        ]);
      }
      return resolverResult([]);
    });

    const result = await runEmailCheck('example.com', false);
    const dmarcPolicy = result.signals.find((s: any) => s.id === 'dmarc_policy');
    expect(dmarcPolicy).toBeDefined();
    expect(dmarcPolicy.status).toBe('pass');
    expect(dmarcPolicy.detail).toContain('reject');
  });

  it('includes explain data when requested', async () => {
    const result = await runEmailCheck('example.com', true);
    const signalsWithExplain = result.signals.filter((s: any) => s.explain);
    // At least SPF and DMARC should include explain text
    expect(signalsWithExplain.length).toBeGreaterThan(0);
  });

  it('calculates grade based on signal counts', async () => {
    // All pass → A
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (type === 15 && !domain.startsWith('_')) {
        return resolverResult([{ type: 'MX', name: domain, TTL: 3600, data: '10 mail.example.com.' }]);
      }
      if (type === 16 && !domain.startsWith('_')) {
        return resolverResult([{ type: 'TXT', name: domain, TTL: 3600, data: '"v=spf1 -all"' }]);
      }
      if (domain === '_dmarc.example.com' && type === 16) {
        return resolverResult([{ type: 'TXT', name: domain, TTL: 3600, data: '"v=DMARC1; p=reject; rua=mailto:d@example.com"' }]);
      }
      if (domain === '_mta-sts.example.com' && type === 16) {
        return resolverResult([{ type: 'TXT', name: domain, TTL: 3600, data: '"v=STSv1; id=20240101"' }]);
      }
      return resolverResult([]);
    });

    const result = await runEmailCheck('example.com', false);
    // With good MX, SPF strict, DMARC reject — should be A or B
    expect(['A', 'B']).toContain(result.email.grade);
  });

  it('detects null MX (RFC 7505)', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (type === 15 && !domain.startsWith('_')) {
        return resolverResult([{ type: 'MX', name: domain, TTL: 3600, data: '0 .' }]);
      }
      return resolverResult([]);
    });

    const result = await runEmailCheck('example.com', false);
    const nullMx = result.signals.find((s: any) => s.id === 'null_mx');
    expect(nullMx).toBeDefined();
    expect(nullMx.status).toBe('info');
  });
});
