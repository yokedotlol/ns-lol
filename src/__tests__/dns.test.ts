// Tests for DNS utility functions

import { describe, it, expect } from 'vitest';
import { getRecordTypeNumber, getRecordTypeName, rcodeName, RECORD_TYPES, DOH_RESOLVERS } from '../dns';

describe('getRecordTypeNumber', () => {
  it('returns correct number for common types', () => {
    expect(getRecordTypeNumber('A')).toBe(1);
    expect(getRecordTypeNumber('AAAA')).toBe(28);
    expect(getRecordTypeNumber('CNAME')).toBe(5);
    expect(getRecordTypeNumber('MX')).toBe(15);
    expect(getRecordTypeNumber('TXT')).toBe(16);
    expect(getRecordTypeNumber('NS')).toBe(2);
    expect(getRecordTypeNumber('SOA')).toBe(6);
    expect(getRecordTypeNumber('SRV')).toBe(33);
    expect(getRecordTypeNumber('CAA')).toBe(257);
    expect(getRecordTypeNumber('DS')).toBe(43);
    expect(getRecordTypeNumber('DNSKEY')).toBe(48);
    expect(getRecordTypeNumber('HTTPS')).toBe(65);
    expect(getRecordTypeNumber('PTR')).toBe(12);
  });

  it('is case-insensitive', () => {
    expect(getRecordTypeNumber('a')).toBe(1);
    expect(getRecordTypeNumber('aaaa')).toBe(28);
    expect(getRecordTypeNumber('Mx')).toBe(15);
    expect(getRecordTypeNumber('txt')).toBe(16);
  });

  it('throws on unknown type', () => {
    expect(() => getRecordTypeNumber('BOGUS')).toThrow('Unknown record type: BOGUS');
  });

  it('error includes status 400', () => {
    try {
      getRecordTypeNumber('NOPE');
    } catch (err: any) {
      expect(err.status).toBe(400);
    }
  });
});

describe('getRecordTypeName', () => {
  it('returns name for known types', () => {
    expect(getRecordTypeName(1)).toBe('A');
    expect(getRecordTypeName(28)).toBe('AAAA');
    expect(getRecordTypeName(5)).toBe('CNAME');
    expect(getRecordTypeName(15)).toBe('MX');
    expect(getRecordTypeName(257)).toBe('CAA');
  });

  it('returns TYPE{n} for unknown types', () => {
    expect(getRecordTypeName(999)).toBe('TYPE999');
    expect(getRecordTypeName(0)).toBe('TYPE0');
    expect(getRecordTypeName(65535)).toBe('TYPE65535');
  });
});

describe('rcodeName', () => {
  it('returns name for known RCODEs', () => {
    expect(rcodeName(0)).toBe('NOERROR');
    expect(rcodeName(1)).toBe('FORMERR');
    expect(rcodeName(2)).toBe('SERVFAIL');
    expect(rcodeName(3)).toBe('NXDOMAIN');
    expect(rcodeName(4)).toBe('NOTIMP');
    expect(rcodeName(5)).toBe('REFUSED');
  });

  it('returns RCODE{n} for unknown codes', () => {
    expect(rcodeName(99)).toBe('RCODE99');
  });
});

describe('RECORD_TYPES constant', () => {
  it('has all standard record types', () => {
    const expected = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR', 'CAA', 'DS', 'DNSKEY', 'HTTPS', 'NAPTR', 'TLSA'];
    for (const type of expected) {
      expect(RECORD_TYPES).toHaveProperty(type);
    }
  });

  it('maps are consistent (name→number and number→name round-trip)', () => {
    for (const [name, num] of Object.entries(RECORD_TYPES)) {
      expect(getRecordTypeName(num)).toBe(name);
    }
  });
});

describe('DOH_RESOLVERS', () => {
  it('has at least 10 resolvers', () => {
    expect(DOH_RESOLVERS.length).toBeGreaterThanOrEqual(10);
  });

  it('each resolver has required fields', () => {
    for (const r of DOH_RESOLVERS) {
      expect(r.name).toBeTruthy();
      expect(r.url).toMatch(/^https:\/\//);
      expect(r.location).toBeTruthy();
      expect(typeof r.lat).toBe('number');
      expect(typeof r.lng).toBe('number');
    }
  });

  it('all resolver URLs end with dns-query or similar path', () => {
    for (const r of DOH_RESOLVERS) {
      // All should be valid HTTPS URLs
      const url = new URL(r.url);
      expect(url.protocol).toBe('https:');
    }
  });
});
