// Tests for deep SPF analysis

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runSPFAnalysis } from '../spf';

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

describe('runSPFAnalysis', () => {
  beforeEach(() => {
    mockQuerySingle.mockReset();
  });

  it('returns has_spf: false when no SPF record', async () => {
    mockQuerySingle.mockResolvedValue(resolverResult([
      { type: 'TXT', name: 'example.com', TTL: 300, data: '"google-site-verification=abc123"' },
    ]));
    const result = await runSPFAnalysis('example.com');
    expect(result.has_spf).toBe(false);
    expect(result.issues[0].code).toBe('spf_missing');
  });

  it('detects multiple SPF records', async () => {
    mockQuerySingle.mockResolvedValue(resolverResult([
      { type: 'TXT', name: 'example.com', TTL: 300, data: '"v=spf1 -all"' },
      { type: 'TXT', name: 'example.com', TTL: 300, data: '"v=spf1 include:_spf.google.com -all"' },
    ]));
    const result = await runSPFAnalysis('example.com');
    expect(result.has_spf).toBe(true);
    expect(result.issues.some(i => i.code === 'spf_multiple')).toBe(true);
  });

  it('counts lookups for simple record', async () => {
    mockQuerySingle.mockImplementation(async (domain: string) => {
      if (domain === 'example.com') {
        return resolverResult([
          { type: 'TXT', name: 'example.com', TTL: 300, data: '"v=spf1 ip4:192.168.1.0/24 -all"' },
        ]);
      }
      return resolverResult([]);
    });
    const result = await runSPFAnalysis('example.com');
    expect(result.has_spf).toBe(true);
    expect(result.lookups_used).toBe(0); // ip4 and -all don't cost lookups
    expect(result.authorized_ip4_count).toBe(256); // /24 = 256 IPs
    expect(result.ip4_ranges).toContain('192.168.1.0/24');
  });

  it('counts lookups for includes', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (domain === 'example.com') {
        return resolverResult([
          { type: 'TXT', name: 'example.com', TTL: 300, data: '"v=spf1 include:_spf.google.com include:sendgrid.net -all"' },
        ]);
      }
      if (domain === '_spf.google.com') {
        return resolverResult([
          { type: 'TXT', name: '_spf.google.com', TTL: 300, data: '"v=spf1 ip4:74.125.0.0/16 -all"' },
        ]);
      }
      if (domain === 'sendgrid.net') {
        return resolverResult([
          { type: 'TXT', name: 'sendgrid.net', TTL: 300, data: '"v=spf1 ip4:167.89.0.0/17 -all"' },
        ]);
      }
      return resolverResult([]);
    });
    const result = await runSPFAnalysis('example.com');
    expect(result.has_spf).toBe(true);
    expect(result.lookups_used).toBe(2); // 2 includes = 2 lookups
    expect(result.tree!.includes.length).toBe(2);
  });

  it('detects +all as dangerous', async () => {
    mockQuerySingle.mockResolvedValue(resolverResult([
      { type: 'TXT', name: 'example.com', TTL: 300, data: '"v=spf1 +all"' },
    ]));
    const result = await runSPFAnalysis('example.com');
    expect(result.issues.some(i => i.code === 'spf_plus_all')).toBe(true);
  });

  it('detects deprecated ptr mechanism', async () => {
    mockQuerySingle.mockResolvedValue(resolverResult([
      { type: 'TXT', name: 'example.com', TTL: 300, data: '"v=spf1 ptr -all"' },
    ]));
    const result = await runSPFAnalysis('example.com');
    expect(result.issues.some(i => i.code === 'spf_ptr_deprecated')).toBe(true);
  });

  it('handles DNS errors gracefully', async () => {
    mockQuerySingle.mockRejectedValue(new Error('timeout'));
    const result = await runSPFAnalysis('example.com');
    expect(result.has_spf).toBe(false);
    expect(result.issues[0].code).toBe('spf_dns_error');
  });

  it('generates term explanations', async () => {
    mockQuerySingle.mockImplementation(async (domain: string) => {
      if (domain === 'example.com') {
        return resolverResult([
          { type: 'TXT', name: 'example.com', TTL: 300, data: '"v=spf1 a mx ip4:10.0.0.0/8 ~all"' },
        ]);
      }
      return resolverResult([]);
    });
    const result = await runSPFAnalysis('example.com');
    expect(result.tree!.terms.length).toBe(4); // a, mx, ip4, ~all
    expect(result.tree!.terms[0].mechanism).toBe('a');
    expect(result.tree!.terms[0].lookups).toBe(1);
    expect(result.tree!.terms[1].mechanism).toBe('mx');
    expect(result.tree!.terms[1].lookups).toBe(1);
    expect(result.tree!.terms[2].mechanism).toBe('ip4');
    expect(result.tree!.terms[2].lookups).toBe(0);
    expect(result.tree!.terms[3].mechanism).toBe('all');
    expect(result.tree!.terms[3].qualifier).toBe('~');
  });
});
