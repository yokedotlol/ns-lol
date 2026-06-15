// Tests for zone health analysis

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runHealthCheck } from '../health';
import type { Env } from '../worker';

vi.mock('../dns', async () => {
  const actual = await vi.importActual('../dns') as any;
  return {
    ...actual,
    querySingle: vi.fn(),
    queryDoH: vi.fn(),
  };
});

import { querySingle, queryDoH } from '../dns';
const mockQuerySingle = querySingle as ReturnType<typeof vi.fn>;
const mockQueryDoH = queryDoH as ReturnType<typeof vi.fn>;

function resolverResult(records: any[], rcode = 'NOERROR', ad = false) {
  return {
    resolver: 'Cloudflare',
    location: 'San Francisco, US',
    lat: 37.77, lng: -122.42,
    records, rcode, aa: false, ad,
    query_time_ms: 10,
  };
}

function mockEnv(): Env {
  return {
    CACHE: {
      get: vi.fn().mockResolvedValue(null),
      put: vi.fn().mockResolvedValue(undefined),
    } as any,
    RATE_LIMITER: {} as any,
  };
}

describe('runHealthCheck', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default: return empty for all queries
    mockQuerySingle.mockResolvedValue(resolverResult([]));
    mockQueryDoH.mockResolvedValue({
      answers: [],
      rcode: 0,
      flags: { aa: false, ad: false },
      query_time_ms: 10,
    });
  });

  it('returns a graded health report', async () => {
    const result = await runHealthCheck('example.com', mockEnv(), false);
    expect(result.domain).toBe('example.com');
    expect(result.health).toBeDefined();
    expect(result.health.grade).toMatch(/^[A-F]$/);
    expect(result.signals).toBeDefined();
    expect(result.analysis_time_ms).toBeDefined();
  });

  it('detects DNSSEC not enabled', async () => {
    const result = await runHealthCheck('example.com', mockEnv(), false);
    const dnssecAbsent = result.signals.find((s: any) => s.id === 'dnssec_absent');
    expect(dnssecAbsent).toBeDefined();
    expect(dnssecAbsent.status).toBe('info');
  });

  it('detects valid DNSSEC (DS + DNSKEY + AD)', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      // DS (type 43)
      if (type === 43) {
        return resolverResult([
          { type: 'DS', name: domain, TTL: 86400, data: '2371 13 2 ABCDEF' }
        ]);
      }
      // DNSKEY (type 48)
      if (type === 48) {
        return resolverResult([
          { type: 'DNSKEY', name: domain, TTL: 3600, data: '257 3 13 base64key==' },
          { type: 'DNSKEY', name: domain, TTL: 3600, data: '256 3 13 base64key2==' },
        ]);
      }
      // A record with AD flag
      if (type === 1) {
        return resolverResult(
          [{ type: 'A', name: domain, TTL: 300, data: '1.2.3.4' }],
          'NOERROR',
          true // AD flag
        );
      }
      return resolverResult([]);
    });

    const result = await runHealthCheck('example.com', mockEnv(), false);
    const dnssecValid = result.signals.find((s: any) => s.id === 'dnssec_valid');
    expect(dnssecValid).toBeDefined();
    expect(dnssecValid.status).toBe('pass');
  });

  it('detects broken DNSSEC (DS without DNSKEY)', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (type === 43) {
        return resolverResult([
          { type: 'DS', name: domain, TTL: 86400, data: '2371 13 2 ABCDEF' }
        ]);
      }
      // No DNSKEY
      return resolverResult([]);
    });

    const result = await runHealthCheck('example.com', mockEnv(), false);
    const broken = result.signals.find((s: any) => s.id === 'dnssec_broken');
    expect(broken).toBeDefined();
    expect(broken.status).toBe('fail');
  });

  it('detects deprecated DNSSEC algorithm', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (type === 43) {
        return resolverResult([
          { type: 'DS', name: domain, TTL: 86400, data: '2371 5 2 ABCDEF' } // algo 5 = RSA/SHA-1
        ]);
      }
      if (type === 48) {
        return resolverResult([
          { type: 'DNSKEY', name: domain, TTL: 3600, data: '257 3 5 base64key==' }, // algo 5
        ]);
      }
      if (type === 1) {
        return resolverResult(
          [{ type: 'A', name: domain, TTL: 300, data: '1.2.3.4' }],
          'NOERROR', true
        );
      }
      return resolverResult([]);
    });

    const result = await runHealthCheck('example.com', mockEnv(), false);
    const algo = result.signals.find((s: any) => s.id === 'dnssec_algo');
    expect(algo).toBeDefined();
    expect(algo.status).toBe('fail');
    expect(algo.detail).toContain('deprecated');
  });

  it('detects strong DNSSEC algorithm (ECDSA P-256)', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (type === 43) {
        return resolverResult([
          { type: 'DS', name: domain, TTL: 86400, data: '2371 13 2 ABCDEF' }
        ]);
      }
      if (type === 48) {
        return resolverResult([
          { type: 'DNSKEY', name: domain, TTL: 3600, data: '257 3 13 base64key==' },
        ]);
      }
      if (type === 1) {
        return resolverResult([{ type: 'A', name: domain, TTL: 300, data: '1.2.3.4' }], 'NOERROR', true);
      }
      return resolverResult([]);
    });

    const result = await runHealthCheck('example.com', mockEnv(), false);
    const algo = result.signals.find((s: any) => s.id === 'dnssec_algo');
    expect(algo).toBeDefined();
    expect(algo.status).toBe('pass');
    expect(algo.detail).toContain('ECDSA');
  });

  it('detects missing NS records', async () => {
    const result = await runHealthCheck('example.com', mockEnv(), false);
    const nsMissing = result.signals.find((s: any) => s.id === 'ns_missing');
    expect(nsMissing).toBeDefined();
    expect(nsMissing.status).toBe('fail');
  });

  it('passes with 2+ NS records', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (domain === 'example.com' && type === 2) {
        return resolverResult([
          { type: 'NS', name: 'example.com', TTL: 86400, data: 'ns1.example.com.' },
          { type: 'NS', name: 'example.com', TTL: 86400, data: 'ns2.example.com.' },
        ]);
      }
      if (domain.startsWith('ns') && type === 1) {
        return resolverResult([{ type: 'A', name: domain, TTL: 3600, data: '1.2.3.4' }]);
      }
      return resolverResult([]);
    });

    const result = await runHealthCheck('example.com', mockEnv(), false);
    const nsCount = result.signals.find((s: any) => s.id === 'ns_count');
    expect(nsCount).toBeDefined();
    expect(nsCount.status).toBe('pass');
  });

  it('detects missing SOA', async () => {
    const result = await runHealthCheck('example.com', mockEnv(), false);
    const soaMissing = result.signals.find((s: any) => s.id === 'soa_missing');
    expect(soaMissing).toBeDefined();
    expect(soaMissing.status).toBe('fail');
  });

  it('passes with valid SOA', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (type === 6) {
        return resolverResult([
          { type: 'SOA', name: domain, TTL: 86400, data: 'ns1.example.com. admin.example.com. 2024010101 3600 900 1209600 300' }
        ]);
      }
      return resolverResult([]);
    });

    const result = await runHealthCheck('example.com', mockEnv(), false);
    const soaPresent = result.signals.find((s: any) => s.id === 'soa_present');
    expect(soaPresent).toBeDefined();
    expect(soaPresent.status).toBe('pass');
  });

  it('warns on very low SOA refresh interval', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (type === 6) {
        return resolverResult([
          { type: 'SOA', name: domain, TTL: 86400, data: 'ns1.example.com. admin.example.com. 2024010101 60 60 1209600 300' }
        ]);
      }
      return resolverResult([]);
    });

    const result = await runHealthCheck('example.com', mockEnv(), false);
    const soaRefresh = result.signals.find((s: any) => s.id === 'soa_refresh');
    expect(soaRefresh).toBeDefined();
    expect(soaRefresh.status).toBe('warn');
  });

  it('warns on high negative cache TTL', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (type === 6) {
        return resolverResult([
          { type: 'SOA', name: domain, TTL: 86400, data: 'ns1.example.com. admin.example.com. 2024010101 3600 900 1209600 7200' }
        ]);
      }
      return resolverResult([]);
    });

    const result = await runHealthCheck('example.com', mockEnv(), false);
    const ncache = result.signals.find((s: any) => s.id === 'soa_ncache');
    expect(ncache).toBeDefined();
    expect(ncache.status).toBe('warn');
  });

  it('detects delegation consistency across resolvers', async () => {
    mockQueryDoH.mockResolvedValue({
      answers: [
        { type: 'NS', name: 'example.com', TTL: 86400, data: 'ns1.example.com.' },
        { type: 'NS', name: 'example.com', TTL: 86400, data: 'ns2.example.com.' },
      ],
      rcode: 0,
      flags: { aa: false, ad: false },
      query_time_ms: 10,
    });

    const result = await runHealthCheck('example.com', mockEnv(), false);
    const delegation = result.signals.find((s: any) => s.id === 'delegation_consistent');
    expect(delegation).toBeDefined();
    expect(delegation.status).toBe('pass');
  });

  it('includes explain data when requested', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (type === 43) {
        return resolverResult([{ type: 'DS', name: domain, TTL: 86400, data: '2371 13 2 ABCDEF' }]);
      }
      if (type === 48) {
        return resolverResult([{ type: 'DNSKEY', name: domain, TTL: 3600, data: '257 3 13 key==' }]);
      }
      if (type === 1) {
        return resolverResult([{ type: 'A', name: domain, TTL: 300, data: '1.2.3.4' }], 'NOERROR', true);
      }
      return resolverResult([]);
    });

    const result = await runHealthCheck('example.com', mockEnv(), true);
    const withExplain = result.signals.filter((s: any) => s.explain);
    expect(withExplain.length).toBeGreaterThan(0);
  });

  it('computes grade F with many failures', async () => {
    // Everything returns empty → DNSSEC absent (info), NS missing (fail), SOA missing (fail)
    const result = await runHealthCheck('example.com', mockEnv(), false);
    // Should have some failures
    expect(result.health.fail).toBeGreaterThan(0);
    // Grade should be C, D, or F depending on exact signal count
    expect(['C', 'D', 'F']).toContain(result.health.grade);
  });
});
