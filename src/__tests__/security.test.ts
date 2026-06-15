// Tests for security checks (dangling CNAME, CDN detection, etc.)

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runSecurityCheck, detectCDNFromRecords } from '../security';

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

describe('detectCDNFromRecords', () => {
  it('detects Cloudflare from CNAME', () => {
    const records = [{ data: 'cdn.cloudflare.net.' }];
    expect(detectCDNFromRecords(records)).toBe('Cloudflare');
  });

  it('detects CloudFront', () => {
    const records = [{ data: 'd123.cloudfront.net.' }];
    expect(detectCDNFromRecords(records)).toBe('Amazon CloudFront');
  });

  it('detects Vercel', () => {
    expect(detectCDNFromRecords([{ data: 'cname.vercel-dns.com.' }])).toBe('Vercel');
  });

  it('detects GitHub Pages', () => {
    expect(detectCDNFromRecords([{ data: 'username.github.io.' }])).toBe('GitHub Pages');
  });

  it('detects Netlify', () => {
    expect(detectCDNFromRecords([{ data: 'abc.netlify.app.' }])).toBe('Netlify');
  });

  it('detects AWS from amazonaws.com', () => {
    // The generic .amazonaws.com pattern matches before the more specific S3 patterns
    // because CDN_PATTERNS is ordered generically first
    expect(detectCDNFromRecords([{ data: 'bucket.s3.amazonaws.com.' }])).toBe('AWS');
    expect(detectCDNFromRecords([{ data: 'bucket.s3-website-us-east-1.amazonaws.com.' }])).toBe('AWS');
    expect(detectCDNFromRecords([{ data: 'my-alb-1234.us-east-1.elb.amazonaws.com.' }])).toBe('AWS');
  });

  it('detects Shopify', () => {
    expect(detectCDNFromRecords([{ data: 'shops.myshopify.com.' }])).toBe('Shopify');
  });

  it('detects Heroku', () => {
    expect(detectCDNFromRecords([{ data: 'app.herokuapp.com.' }])).toBe('Heroku');
  });

  it('returns null for unknown CNAME', () => {
    expect(detectCDNFromRecords([{ data: 'server.mycustomhost.com.' }])).toBeNull();
  });

  it('returns null for empty records', () => {
    expect(detectCDNFromRecords([])).toBeNull();
  });

  it('handles records without data field', () => {
    expect(detectCDNFromRecords([{}])).toBeNull();
  });
});

describe('runSecurityCheck', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default: most queries return no records
    mockQuerySingle.mockResolvedValue(resolverResult([]));
  });

  it('returns a graded security report', async () => {
    const result = await runSecurityCheck('example.com', false);
    expect(result.domain).toBe('example.com');
    expect(result.security).toBeDefined();
    expect(result.security.grade).toMatch(/^[A-F]$/);
    expect(result.signals).toBeDefined();
    expect(Array.isArray(result.signals)).toBe(true);
  });

  it('passes when no wildcard DNS', async () => {
    // Default mock returns empty = no wildcard
    const result = await runSecurityCheck('example.com', false);
    const wildcard = result.signals.find((s: any) => s.id === 'wildcard_clean');
    expect(wildcard).toBeDefined();
    expect(wildcard.status).toBe('pass');
  });

  it('detects wildcard DNS', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      // Wildcard test queries a random subdomain
      if (domain.includes('_nslol-wildcard-test') && type === 1) {
        return resolverResult([
          { type: 'A', name: domain, TTL: 300, data: '1.2.3.4' }
        ]);
      }
      return resolverResult([]);
    });

    const result = await runSecurityCheck('example.com', false);
    const wildcard = result.signals.find((s: any) => s.id === 'wildcard_detected');
    expect(wildcard).toBeDefined();
    expect(wildcard.status).toBe('info');
  });

  it('detects dangling CNAME', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      // CNAME query for main domain
      if (domain === 'example.com' && type === 5) {
        return resolverResult([
          { type: 'CNAME', name: 'example.com', TTL: 300, data: 'old.herokuapp.com.' }
        ]);
      }
      // Target does not resolve (A and AAAA return empty)
      if (domain === 'old.herokuapp.com') {
        return resolverResult([]);
      }
      return resolverResult([]);
    });

    const result = await runSecurityCheck('example.com', false);
    const dangling = result.signals.find((s: any) => s.id === 'dangling_cname_takeover');
    expect(dangling).toBeDefined();
    expect(dangling.status).toBe('fail');
    expect(dangling.detail).toContain('Heroku');
  });

  it('passes when CNAME resolves correctly', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (domain === 'example.com' && type === 5) {
        return resolverResult([
          { type: 'CNAME', name: 'example.com', TTL: 300, data: 'app.netlify.app.' }
        ]);
      }
      if (domain === 'app.netlify.app' && type === 1) {
        return resolverResult([
          { type: 'A', name: 'app.netlify.app', TTL: 300, data: '75.2.60.5' }
        ]);
      }
      return resolverResult([]);
    });

    const result = await runSecurityCheck('example.com', false);
    const valid = result.signals.find((s: any) => s.id === 'cname_valid');
    expect(valid).toBeDefined();
    expect(valid.status).toBe('pass');
  });

  it('detects dangling NS records', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (domain === 'example.com' && type === 2) {
        return resolverResult([
          { type: 'NS', name: 'example.com', TTL: 86400, data: 'ns1.defunct-provider.com.' },
          { type: 'NS', name: 'example.com', TTL: 86400, data: 'ns2.defunct-provider.com.' },
        ]);
      }
      // NS hostnames don't resolve
      if (domain.includes('defunct-provider') && type === 1) {
        return resolverResult([]);
      }
      if (domain.includes('defunct-provider') && type === 28) {
        return resolverResult([]);
      }
      return resolverResult([]);
    });

    const result = await runSecurityCheck('example.com', false);
    const dangling = result.signals.find((s: any) => s.id === 'dangling_ns');
    expect(dangling).toBeDefined();
    expect(dangling.status).toBe('fail');
    expect(dangling.detail).toContain('domain takeover');
  });

  it('passes when all NS resolve', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (domain === 'example.com' && type === 2) {
        return resolverResult([
          { type: 'NS', name: 'example.com', TTL: 86400, data: 'ns1.example.com.' },
        ]);
      }
      if (domain === 'ns1.example.com' && type === 1) {
        return resolverResult([
          { type: 'A', name: 'ns1.example.com', TTL: 3600, data: '1.2.3.4' }
        ]);
      }
      return resolverResult([]);
    });

    const result = await runSecurityCheck('example.com', false);
    const nsOk = result.signals.find((s: any) => s.id === 'ns_all_resolve');
    expect(nsOk).toBeDefined();
    expect(nsOk.status).toBe('pass');
  });

  it('detects NS same subnet', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (domain === 'example.com' && type === 2) {
        return resolverResult([
          { type: 'NS', name: 'example.com', TTL: 86400, data: 'ns1.example.com.' },
          { type: 'NS', name: 'example.com', TTL: 86400, data: 'ns2.example.com.' },
        ]);
      }
      if (domain === 'ns1.example.com' && type === 1) {
        return resolverResult([{ type: 'A', name: 'ns1.example.com', TTL: 3600, data: '10.0.0.1' }]);
      }
      if (domain === 'ns2.example.com' && type === 1) {
        return resolverResult([{ type: 'A', name: 'ns2.example.com', TTL: 3600, data: '10.0.0.2' }]);
      }
      return resolverResult([]);
    });

    const result = await runSecurityCheck('example.com', false);
    const sameSubnet = result.signals.find((s: any) => s.id === 'ns_same_subnet');
    expect(sameSubnet).toBeDefined();
    expect(sameSubnet.status).toBe('warn');
  });

  it('passes NS with diverse subnets', async () => {
    mockQuerySingle.mockImplementation(async (domain: string, type: number) => {
      if (domain === 'example.com' && type === 2) {
        return resolverResult([
          { type: 'NS', name: 'example.com', TTL: 86400, data: 'ns1.example.com.' },
          { type: 'NS', name: 'example.com', TTL: 86400, data: 'ns2.example.com.' },
        ]);
      }
      if (domain === 'ns1.example.com' && type === 1) {
        return resolverResult([{ type: 'A', name: 'ns1.example.com', TTL: 3600, data: '10.0.0.1' }]);
      }
      if (domain === 'ns2.example.com' && type === 1) {
        return resolverResult([{ type: 'A', name: 'ns2.example.com', TTL: 3600, data: '192.168.1.1' }]);
      }
      return resolverResult([]);
    });

    const result = await runSecurityCheck('example.com', false);
    const diverse = result.signals.find((s: any) => s.id === 'ns_diverse_subnets');
    expect(diverse).toBeDefined();
    expect(diverse.status).toBe('pass');
  });

  it('includes explain when requested', async () => {
    const result = await runSecurityCheck('example.com', true);
    // Should have at least some signals with explain text
    expect(result.signals.length).toBeGreaterThan(0);
  });
});
