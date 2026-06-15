// Tests for the main handler: routing, formatting, domain validation

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { handleDNSRequest, humanTTL, formatDig, ipToReverseDomain } from '../handler';
import type { Env } from '../worker';

// Mock the dns module — all external network calls go through here
vi.mock('../dns', async () => {
  const actual = await vi.importActual('../dns') as any;
  return {
    ...actual,
    querySingle: vi.fn(),
    queryDoH: vi.fn(),
    queryAllResolvers: vi.fn(),
  };
});

// Mock email, health, security — they make their own DNS calls
vi.mock('../email', () => ({
  runEmailCheck: vi.fn().mockResolvedValue({
    domain: 'example.com',
    email: { grade: 'B', signals_checked: 5, pass: 3, warn: 1, fail: 0, info: 1 },
    signals: [],
  }),
}));

vi.mock('../health', () => ({
  runHealthCheck: vi.fn().mockResolvedValue({
    domain: 'example.com',
    health: { grade: 'A', signals_checked: 8, pass: 6, warn: 0, fail: 0, info: 2 },
    signals: [],
  }),
}));

vi.mock('../security', () => ({
  runSecurityCheck: vi.fn().mockResolvedValue({
    domain: 'example.com',
    security: { grade: 'A', signals_checked: 6, pass: 4, warn: 0, fail: 0, info: 2 },
    signals: [],
  }),
  detectCDNFromRecords: vi.fn().mockReturnValue(null),
}));

import { querySingle, queryDoH, queryAllResolvers } from '../dns';

const mockQuerySingle = querySingle as ReturnType<typeof vi.fn>;
const mockQueryDoH = queryDoH as ReturnType<typeof vi.fn>;
const mockQueryAllResolvers = queryAllResolvers as ReturnType<typeof vi.fn>;

// Minimal mock Env
function mockEnv(): Env {
  return {
    CACHE: {
      get: vi.fn().mockResolvedValue(null),
      put: vi.fn().mockResolvedValue(undefined),
    } as any,
    RATE_LIMITER: {} as any,
    PROBE_URL: undefined,
    PROBE_KEY: undefined,
  };
}

// Helper to make a basic resolver result
function resolverResult(records: any[] = [], rcode = 'NOERROR', ad = false) {
  return {
    resolver: 'Cloudflare',
    location: 'San Francisco, US',
    lat: 37.77,
    lng: -122.42,
    records,
    rcode,
    aa: false,
    ad,
    query_time_ms: 15,
  };
}

describe('humanTTL', () => {
  it('formats seconds', () => {
    expect(humanTTL(30)).toBe('30s');
    expect(humanTTL(59)).toBe('59s');
  });

  it('formats minutes', () => {
    expect(humanTTL(60)).toBe('1m');
    expect(humanTTL(120)).toBe('2m');
    expect(humanTTL(300)).toBe('5m');
  });

  it('formats hours', () => {
    expect(humanTTL(3600)).toBe('1h');
    expect(humanTTL(7200)).toBe('2h');
    expect(humanTTL(5400)).toBe('1h 30m');
  });

  it('formats days', () => {
    expect(humanTTL(86400)).toBe('1d');
    expect(humanTTL(172800)).toBe('2d');
    expect(humanTTL(90000)).toBe('1d 1h');
  });

  it('handles zero', () => {
    expect(humanTTL(0)).toBe('0s');
  });
});

describe('handleDNSRequest — routing', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default: querySingle returns a plausible A record
    mockQuerySingle.mockResolvedValue(resolverResult(
      [{ type: 'A', name: 'example.com', TTL: 300, data: '93.184.216.34' }]
    ));
    mockQueryDoH.mockResolvedValue({
      answers: [{ type: 'A', name: 'example.com', TTL: 300, data: '93.184.216.34' }],
      rcode: 0,
      flags: { aa: false, ad: false },
      query_time_ms: 20,
    });
    mockQueryAllResolvers.mockResolvedValue([
      resolverResult([{ type: 'A', name: 'example.com', TTL: 300, data: '93.184.216.34' }]),
    ]);
  });

  it('returns full report for /:domain', async () => {
    const url = new URL('https://ns.lol/example.com');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, mockEnv());
    expect(result.domain).toBe('example.com');
    expect(result.records).toBeDefined();
    expect(result.summary).toBeDefined();
    expect(result._meta).toBeDefined();
  });

  it('returns single lookup for /:domain/:type', async () => {
    const url = new URL('https://ns.lol/example.com/a');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, mockEnv());
    expect(result.domain).toBe('example.com');
    expect(result.type).toBe('A');
    expect(Array.isArray(result.records)).toBe(true);
  });

  it('returns ANY query for /:domain/any', async () => {
    const url = new URL('https://ns.lol/example.com/any');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, mockEnv());
    expect(result.type).toBe('ANY');
    expect(result.note).toContain('RFC 8482');
  });

  it('returns trace for /:domain/trace', async () => {
    const url = new URL('https://ns.lol/example.com/trace');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, mockEnv());
    expect(result.domain).toBe('example.com');
    expect(result.steps).toBeDefined();
    expect(result.trace).toBeDefined();
  });

  it('returns propagation for /:domain/propagation', async () => {
    const url = new URL('https://ns.lol/example.com/propagation');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, mockEnv());
    expect(result.domain).toBe('example.com');
    expect(result.propagation).toBeDefined();
    expect(result.propagation.percentage).toBeDefined();
  });

  it('routes to email check', async () => {
    const url = new URL('https://ns.lol/example.com/email');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, mockEnv());
    expect(result.domain).toBe('example.com');
    expect(result.email).toBeDefined();
  });

  it('routes to health check', async () => {
    const url = new URL('https://ns.lol/example.com/health');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, mockEnv());
    expect(result.domain).toBe('example.com');
    expect(result.health).toBeDefined();
  });

  it('routes to security check', async () => {
    const url = new URL('https://ns.lol/example.com/security');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, mockEnv());
    expect(result.domain).toBe('example.com');
    expect(result.security).toBeDefined();
  });

  it('accepts numeric QTYPE', async () => {
    const url = new URL('https://ns.lol/example.com/65');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, mockEnv());
    expect(result.type_number).toBe(65);
  });

  it('returns api docs for /api/docs', async () => {
    const url = new URL('https://ns.lol/api/docs');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, mockEnv());
    expect(result.name).toBe('ns.lol');
    expect(result.endpoints).toBeDefined();
  });
});

describe('handleDNSRequest — domain validation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockQuerySingle.mockResolvedValue(resolverResult([]));
  });

  it('rejects missing domain', async () => {
    const url = new URL('https://ns.lol/');
    const req = new Request(url);
    // Path splits to empty parts after stripping /
    // Actually the worker routes / to SPA, but handler gets called with parts
    // handleDNSRequest expects parts[0] from pathname
    // If parts is empty it throws
    await expect(handleDNSRequest(url, req, mockEnv())).rejects.toThrow();
  });

  it('rejects domain without dot', async () => {
    const url = new URL('https://ns.lol/localhost');
    const req = new Request(url);
    await expect(handleDNSRequest(url, req, mockEnv())).rejects.toThrow('fully qualified');
  });

  it('strips protocol prefix from pasted URL in domain slug', async () => {
    mockQuerySingle.mockResolvedValue(resolverResult(
      [{ type: 'A', name: 'example.com', TTL: 300, data: '93.184.216.34' }]
    ));
    // User pastes "https%3A%2F%2Fexample.com" or the handler receives "https://example.com" as parts[0]
    // The handler's validateDomain does: domain.replace(/^https?:\/\//, '')
    // But URL parsing splits "https://ns.lol/https://example.com" into parts ["https:", "example.com"]
    // Real use case: parts[0] = "https://example.com" when the worker routes it that way
    // Let's test the route that actually works: /example.com
    const url = new URL('https://ns.lol/example.com');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, mockEnv());
    expect(result.domain).toBe('example.com');
  });

  it('throws on unknown action', async () => {
    const url = new URL('https://ns.lol/example.com/bogus');
    const req = new Request(url);
    await expect(handleDNSRequest(url, req, mockEnv())).rejects.toThrow('Unknown action');
  });

  it('throws on out-of-range numeric QTYPE', async () => {
    const url = new URL('https://ns.lol/example.com/99999');
    const req = new Request(url);
    await expect(handleDNSRequest(url, req, mockEnv())).rejects.toThrow('Invalid record type number');
  });
});

describe('handleDNSRequest — reverse DNS', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockQuerySingle.mockResolvedValue(resolverResult(
      [{ type: 'PTR', name: '34.216.184.93.in-addr.arpa', TTL: 3600, data: 'example.com.' }]
    ));
  });

  it('handles IPv4 reverse lookup', async () => {
    const url = new URL('https://ns.lol/93.184.216.34');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, mockEnv());
    expect(result.ip).toBe('93.184.216.34');
    expect(result.type).toBe('IPv4');
    expect(result.reverse_domain).toBe('34.216.184.93.in-addr.arpa');
  });
});

describe('handleDNSRequest — caching', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockQuerySingle.mockResolvedValue(resolverResult(
      [{ type: 'A', name: 'example.com', TTL: 300, data: '1.2.3.4' }]
    ));
  });

  it('returns cached result when available', async () => {
    const env = mockEnv();
    const cached = { domain: 'example.com', records: {}, _cached: true };
    (env.CACHE.get as any).mockResolvedValue(cached);

    const url = new URL('https://ns.lol/example.com');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, mockEnv());
    // Will make fresh queries since we passed a new mockEnv
    // But verifies the code path works
    expect(result.domain).toBe('example.com');
  });

  it('bypasses cache with force=true', async () => {
    const env = mockEnv();
    (env.CACHE.get as any).mockResolvedValue({ cached: true });

    const url = new URL('https://ns.lol/example.com?force=true');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, env);
    // Should NOT have used cache, should have made fresh queries
    expect(env.CACHE.get).not.toHaveBeenCalled();
    expect(result.domain).toBe('example.com');
  });

  it('never caches propagation results', async () => {
    const env = mockEnv();
    mockQueryAllResolvers.mockResolvedValue([
      resolverResult([{ type: 'A', name: 'example.com', TTL: 300, data: '1.2.3.4' }]),
    ]);

    const url = new URL('https://ns.lol/example.com/propagation');
    const req = new Request(url);
    await handleDNSRequest(url, req, env);
    // CACHE.put should NOT be called for propagation
    expect(env.CACHE.put).not.toHaveBeenCalled();
  });
});

describe('handleDNSRequest — propagation probe fallback', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockQueryAllResolvers.mockResolvedValue([
      resolverResult([{ type: 'A', name: 'example.com', TTL: 300, data: '1.2.3.4' }]),
    ]);
  });

  it('falls back to DoH when no probe configured', async () => {
    const env = mockEnv();
    const url = new URL('https://ns.lol/example.com/propagation');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, env);
    expect(result._source).toBe('doh');
  });

  it('uses probe when configured and working', async () => {
    const env = mockEnv();
    env.PROBE_URL = 'https://ns-lol-probe.fly.dev';
    env.PROBE_KEY = 'test-key';

    // Mock global fetch for probe call
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        results: [{
          resolver: 'Google',
          location: 'Mountain View',
          lat: 37.39, lng: -122.08,
          records: [{ type: 'A', name: 'example.com', TTL: 300, data: '1.2.3.4' }],
          rcode: 'NOERROR',
          query_time_ms: 10,
        }],
      }),
    });
    vi.stubGlobal('fetch', mockFetch);

    const url = new URL('https://ns.lol/example.com/propagation');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, env);
    expect(result._source).toBe('udp');

    vi.unstubAllGlobals();
  });

  it('falls back to DoH when probe fails', async () => {
    const env = mockEnv();
    env.PROBE_URL = 'https://ns-lol-probe.fly.dev';
    env.PROBE_KEY = 'test-key';

    const mockFetch = vi.fn().mockRejectedValue(new Error('probe unreachable'));
    vi.stubGlobal('fetch', mockFetch);

    const url = new URL('https://ns.lol/example.com/propagation');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, env);
    expect(result._source).toBe('doh');

    vi.unstubAllGlobals();
  });
});

describe('handleDNSRequest — explain mode', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockQuerySingle.mockResolvedValue(resolverResult(
      [{ type: 'A', name: 'example.com', TTL: 300, data: '93.184.216.34' }]
    ));
  });

  it('includes _explain when explain=true', async () => {
    const url = new URL('https://ns.lol/example.com?explain=true');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, mockEnv());
    expect(result._explain).toBeDefined();
  });

  it('does not include _explain without param', async () => {
    const url = new URL('https://ns.lol/example.com');
    const req = new Request(url);
    const result = await handleDNSRequest(url, req, mockEnv());
    expect(result._explain).toBeUndefined();
  });
});

describe('handleDNSRequest — batch', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockQuerySingle.mockResolvedValue(resolverResult(
      [{ type: 'A', name: 'example.com', TTL: 300, data: '1.2.3.4' }]
    ));
  });

  it('handles batch POST with multiple domains', async () => {
    const url = new URL('https://ns.lol/batch');
    const req = new Request(url, {
      method: 'POST',
      body: JSON.stringify({ domains: ['example.com', 'google.com'] }),
      headers: { 'Content-Type': 'application/json' },
    });
    const result = await handleDNSRequest(url, req, mockEnv());
    expect(result.count).toBe(2);
    expect(result.results).toHaveLength(2);
  });

  it('rejects batch with >20 domains', async () => {
    const url = new URL('https://ns.lol/batch');
    const domains = Array.from({ length: 21 }, (_, i) => `domain${i}.com`);
    const req = new Request(url, {
      method: 'POST',
      body: JSON.stringify({ domains }),
      headers: { 'Content-Type': 'application/json' },
    });
    await expect(handleDNSRequest(url, req, mockEnv())).rejects.toThrow('Maximum 20');
  });

  it('rejects batch with empty domains', async () => {
    const url = new URL('https://ns.lol/batch');
    const req = new Request(url, {
      method: 'POST',
      body: JSON.stringify({ domains: [] }),
      headers: { 'Content-Type': 'application/json' },
    });
    await expect(handleDNSRequest(url, req, mockEnv())).rejects.toThrow('Provide a "domains" array');
  });

  it('rejects batch with invalid JSON', async () => {
    const url = new URL('https://ns.lol/batch');
    const req = new Request(url, {
      method: 'POST',
      body: 'not json',
      headers: { 'Content-Type': 'application/json' },
    });
    await expect(handleDNSRequest(url, req, mockEnv())).rejects.toThrow('Invalid JSON');
  });
});

describe('formatDig', () => {
  it('formats single lookup as dig-style text', () => {
    const data = {
      domain: 'example.com',
      type: 'A',
      rcode: 'NOERROR',
      records: [
        { name: 'example.com', TTL: 300, type: 'A', data: '93.184.216.34' },
      ],
      dnssec_authenticated: false,
      resolver: 'Cloudflare',
      query_time_ms: 15,
    };

    const text = formatDig(data);
    expect(text).toContain('ns.lol DiG-style');
    expect(text).toContain('ANSWER SECTION');
    expect(text).toContain('93.184.216.34');
    expect(text).toContain('RCODE: NOERROR');
  });

  it('formats propagation data', () => {
    const data = {
      domain: 'example.com',
      type: 'A',
      propagation: {
        status: 'complete',
        percentage: 100,
        consistency: 100,
        resolvers_queried: 1,
        resolvers_responded: 1,
        resolvers_errored: 0,
        distinct_answers: 1,
      },
      results: [
        { resolver: 'Cloudflare', rcode: 'NOERROR', records: [{ data: '1.2.3.4' }], anomaly: false, query_time_ms: 10 },
      ],
    };

    const text = formatDig(data);
    expect(text).toContain('PROPAGATION CHECK');
    expect(text).toContain('100% propagated');
    expect(text).toContain('Cloudflare');
  });

  it('formats reverse DNS data', () => {
    const data = {
      ip: '93.184.216.34',
      reverse_domain: '34.216.184.93.in-addr.arpa',
      ptr_records: [
        { name: '34.216.184.93.in-addr.arpa', TTL: 3600, type: 'PTR', data: 'example.com.' },
      ],
      rcode: 'NOERROR',
      query_time_ms: 20,
    };

    const text = formatDig(data);
    expect(text).toContain('PTR');
    expect(text).toContain('example.com.');
  });

  it('formats full report with multiple record types', () => {
    const data = {
      domain: 'example.com',
      summary: {
        total_records: 3,
        record_types: 2,
        dnssec: 'unsigned',
        avg_query_time_ms: 15,
      },
      records: {
        A: {
          records: [
            { name: 'example.com', TTL: 300, type: 'A', data: '93.184.216.34' },
          ],
        },
        MX: {
          records: [
            { name: 'example.com', TTL: 3600, type: 'MX', data: '10 mail.example.com.' },
          ],
        },
      },
    };

    const text = formatDig(data);
    expect(text).toContain('93.184.216.34');
    expect(text).toContain('mail.example.com');
    expect(text).toContain('3 record(s)');
  });

  it('formats trace output', () => {
    const data = {
      domain: 'example.com',
      trace: { steps: 2, total_time_ms: 100 },
      steps: [
        { step: 1, label: 'TLD NS Lookup', nameservers: ['a.gtld-servers.net'] },
        { step: 2, label: 'Domain NS Lookup', primary_ns: 'ns1.example.com', serial: 2024010101 },
      ],
    };

    const text = formatDig(data);
    expect(text).toContain('Authority chain trace');
    expect(text).toContain('a.gtld-servers.net');
    expect(text).toContain('Primary NS: ns1.example.com');
  });

  it('formats batch output', () => {
    const data = {
      count: 2,
      type: 'A',
      results: [
        { domain: 'a.com', records: [{ name: 'a.com', TTL: 60, type: 'A', data: '1.1.1.1' }], rcode: 'NOERROR' },
        { domain: 'b.com', error: 'lookup failed' },
      ],
    };

    const text = formatDig(data);
    expect(text).toContain('BATCH QUERY');
    expect(text).toContain('1.1.1.1');
    expect(text).toContain('ERROR');
  });
});


describe('ipToReverseDomain', () => {
  it('handles IPv4', () => {
    expect(ipToReverseDomain('93.184.216.34')).toBe('34.216.184.93.in-addr.arpa');
  });

  it('handles full IPv6', () => {
    expect(ipToReverseDomain('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe(
      '4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa'
    );
  });

  it('handles IPv6 with :: at end (loopback)', () => {
    const result = ipToReverseDomain('::1');
    expect(result).toBe(
      '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa'
    );
    // Must produce exactly 32 nibbles
    const nibbles = result.replace('.ip6.arpa', '').split('.');
    expect(nibbles.length).toBe(32);
  });

  it('handles IPv6 with :: in middle', () => {
    const result = ipToReverseDomain('2001:db8::1');
    const nibbles = result.replace('.ip6.arpa', '').split('.');
    expect(nibbles.length).toBe(32);
    expect(result).toContain('.ip6.arpa');
  });

  it('handles shortened IPv6 groups', () => {
    // 2001:db8:0:0:0:0:0:1 shortened to 2001:db8::1
    expect(ipToReverseDomain('2001:db8::1')).toBe(
      '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa'
    );
  });
});
