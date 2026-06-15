// Tests for DNS wire format encoding/decoding (RFC 1035 / RFC 8484)

import { describe, it, expect } from 'vitest';
import { buildDNSQuery, parseDNSResponse } from '../dns-wire';

describe('buildDNSQuery', () => {
  it('builds a valid DNS query for an A record', () => {
    const buf = buildDNSQuery('example.com', 1); // A record
    expect(buf).toBeInstanceOf(Uint8Array);
    // Min: 12 header + name + 4 question + OPT RR
    expect(buf.length).toBeGreaterThan(12);

    const view = new DataView(buf.buffer);
    // QDCOUNT = 1
    expect(view.getUint16(4)).toBe(1);
    // ANCOUNT = 0
    expect(view.getUint16(6)).toBe(0);
    // NSCOUNT = 0
    expect(view.getUint16(8)).toBe(0);
    // RD flag should be set (0x0100)
    expect(view.getUint16(2) & 0x0100).toBe(0x0100);
  });

  it('builds query without RD flag when rd=false', () => {
    const buf = buildDNSQuery('example.com', 1, false);
    const view = new DataView(buf.buffer);
    expect(view.getUint16(2) & 0x0100).toBe(0);
  });

  it('includes EDNS0 OPT RR with DO flag by default', () => {
    const buf = buildDNSQuery('example.com', 1, true, true);
    const view = new DataView(buf.buffer);
    // ARCOUNT = 1 (OPT RR)
    expect(view.getUint16(10)).toBe(1);
  });

  it('excludes OPT RR when doFlag=false', () => {
    const buf = buildDNSQuery('example.com', 1, true, false);
    const view = new DataView(buf.buffer);
    // ARCOUNT = 0
    expect(view.getUint16(10)).toBe(0);
  });

  it('encodes domain name labels correctly', () => {
    const buf = buildDNSQuery('example.com', 1, true, false);
    // After 12-byte header: label "example" = 0x07 + 7 bytes, "com" = 0x03 + 3 bytes, 0x00 root
    expect(buf[12]).toBe(7); // "example" length
    expect(String.fromCharCode(...buf.slice(13, 20))).toBe('example');
    expect(buf[20]).toBe(3); // "com" length
    expect(String.fromCharCode(...buf.slice(21, 24))).toBe('com');
    expect(buf[24]).toBe(0); // root label
  });

  it('strips trailing dot from domain', () => {
    const withDot = buildDNSQuery('example.com.', 1, true, false);
    const withoutDot = buildDNSQuery('example.com', 1, true, false);
    // Name encoding should be identical (skip the first 2 bytes which contain random ID)
    expect(withDot.slice(2)).toEqual(withoutDot.slice(2));
  });

  it('encodes AAAA record type (28)', () => {
    const buf = buildDNSQuery('example.com', 28, true, false);
    // QTYPE is 2 bytes after the name section
    const nameEnd = 12 + 7 + 1 + 3 + 1 + 1; // header + "example" + "com" + root
    const view = new DataView(buf.buffer);
    expect(view.getUint16(nameEnd)).toBe(28);
  });

  it('encodes various record types', () => {
    const types = [1, 2, 5, 6, 15, 16, 28, 33, 43, 48, 65, 257];
    for (const type of types) {
      const buf = buildDNSQuery('test.example.com', type, true, false);
      expect(buf.length).toBeGreaterThan(12);
      const view = new DataView(buf.buffer);
      expect(view.getUint16(4)).toBe(1); // QDCOUNT
    }
  });

  it('handles single-label with TLD correctly', () => {
    const buf = buildDNSQuery('a.b', 1, true, false);
    expect(buf[12]).toBe(1); // "a" length
    expect(buf[13]).toBe(0x61); // 'a'
    expect(buf[14]).toBe(1); // "b" length
    expect(buf[15]).toBe(0x62); // 'b'
    expect(buf[16]).toBe(0); // root
  });

  it('throws on label longer than 63 characters', () => {
    const longLabel = 'a'.repeat(64) + '.com';
    expect(() => buildDNSQuery(longLabel, 1)).toThrow('Label too long');
  });

  it('handles subdomain correctly', () => {
    const buf = buildDNSQuery('sub.example.com', 1, true, false);
    expect(buf[12]).toBe(3); // "sub" length
    expect(String.fromCharCode(...buf.slice(13, 16))).toBe('sub');
  });
});

describe('parseDNSResponse', () => {
  // Helper to build a minimal DNS response buffer
  function buildResponse(opts: {
    rcode?: number;
    aa?: boolean;
    ad?: boolean;
    qdcount?: number;
    answers?: { name: string; type: number; ttl: number; rdata: Uint8Array }[];
  }): Uint8Array {
    const rcode = opts.rcode ?? 0;
    const aa = opts.aa ?? false;
    const ad = opts.ad ?? false;
    const qdcount = opts.qdcount ?? 1;
    const answers = opts.answers ?? [];

    const parts: number[] = [];
    // Header: ID(2), Flags(2), QDCOUNT(2), ANCOUNT(2), NSCOUNT(2), ARCOUNT(2)
    parts.push(0x00, 0x01); // ID
    let flags = 0x8000; // QR=1
    if (aa) flags |= 0x0400;
    if (ad) flags |= 0x0020;
    flags |= (rcode & 0x0f);
    parts.push((flags >> 8) & 0xff, flags & 0xff);
    parts.push(0, qdcount); // QDCOUNT
    parts.push(0, answers.length); // ANCOUNT
    parts.push(0, 0); // NSCOUNT
    parts.push(0, 0); // ARCOUNT

    // Question section (minimal: encode "example.com" type A class IN)
    if (qdcount > 0) {
      // example.com
      parts.push(7);
      for (const c of 'example') parts.push(c.charCodeAt(0));
      parts.push(3);
      for (const c of 'com') parts.push(c.charCodeAt(0));
      parts.push(0); // root
      parts.push(0, 1); // QTYPE A
      parts.push(0, 1); // QCLASS IN
    }

    // Answers
    for (const ans of answers) {
      // Encode name
      const labels = ans.name.replace(/\.$/, '').split('.');
      for (const label of labels) {
        parts.push(label.length);
        for (const c of label) parts.push(c.charCodeAt(0));
      }
      parts.push(0);
      // TYPE
      parts.push((ans.type >> 8) & 0xff, ans.type & 0xff);
      // CLASS IN
      parts.push(0, 1);
      // TTL
      parts.push((ans.ttl >> 24) & 0xff, (ans.ttl >> 16) & 0xff, (ans.ttl >> 8) & 0xff, ans.ttl & 0xff);
      // RDLENGTH
      parts.push((ans.rdata.length >> 8) & 0xff, ans.rdata.length & 0xff);
      // RDATA
      for (const b of ans.rdata) parts.push(b);
    }

    return new Uint8Array(parts);
  }

  it('parses a simple A record response', () => {
    const resp = buildResponse({
      answers: [{
        name: 'example.com',
        type: 1, // A
        ttl: 300,
        rdata: new Uint8Array([93, 184, 216, 34]) // 93.184.216.34
      }]
    });

    const result = parseDNSResponse(resp, 42);
    expect(result.rcode).toBe(0);
    expect(result.answers).toHaveLength(1);
    expect(result.answers[0].type).toBe('A');
    expect(result.answers[0].data).toBe('93.184.216.34');
    expect(result.answers[0].TTL).toBe(300);
    expect(result.answers[0].name).toBe('example.com');
    expect(result.query_time_ms).toBe(42);
  });

  it('parses NXDOMAIN response (rcode=3)', () => {
    const resp = buildResponse({ rcode: 3 });
    const result = parseDNSResponse(resp, 10);
    expect(result.rcode).toBe(3);
    expect(result.answers).toHaveLength(0);
  });

  it('detects authoritative answer flag', () => {
    const resp = buildResponse({ aa: true });
    const result = parseDNSResponse(resp, 0);
    expect(result.flags.aa).toBe(true);
    expect(result.flags.ad).toBe(false);
  });

  it('detects authenticated data flag', () => {
    const resp = buildResponse({ ad: true });
    const result = parseDNSResponse(resp, 0);
    expect(result.flags.ad).toBe(true);
  });

  it('parses multiple A records', () => {
    const resp = buildResponse({
      answers: [
        { name: 'example.com', type: 1, ttl: 60, rdata: new Uint8Array([1, 2, 3, 4]) },
        { name: 'example.com', type: 1, ttl: 60, rdata: new Uint8Array([5, 6, 7, 8]) },
      ]
    });

    const result = parseDNSResponse(resp, 5);
    expect(result.answers).toHaveLength(2);
    expect(result.answers[0].data).toBe('1.2.3.4');
    expect(result.answers[1].data).toBe('5.6.7.8');
  });

  it('parses TXT record', () => {
    // TXT RDATA: length-prefixed character strings
    const txtValue = 'v=spf1 include:_spf.google.com ~all';
    const rdata = new Uint8Array(1 + txtValue.length);
    rdata[0] = txtValue.length;
    for (let i = 0; i < txtValue.length; i++) {
      rdata[1 + i] = txtValue.charCodeAt(i);
    }

    const resp = buildResponse({
      answers: [{ name: 'example.com', type: 16, ttl: 3600, rdata }]
    });

    const result = parseDNSResponse(resp, 0);
    expect(result.answers).toHaveLength(1);
    expect(result.answers[0].type).toBe('TXT');
    expect(result.answers[0].data).toBe(`"${txtValue}"`);
  });

  it('parses CAA record', () => {
    // CAA: flags(1) + tag_len(1) + tag + value
    const tag = 'issue';
    const value = 'letsencrypt.org';
    const rdata = new Uint8Array(2 + tag.length + value.length);
    rdata[0] = 0; // flags
    rdata[1] = tag.length;
    for (let i = 0; i < tag.length; i++) rdata[2 + i] = tag.charCodeAt(i);
    for (let i = 0; i < value.length; i++) rdata[2 + tag.length + i] = value.charCodeAt(i);

    const resp = buildResponse({
      answers: [{ name: 'example.com', type: 257, ttl: 86400, rdata }]
    });

    const result = parseDNSResponse(resp, 0);
    expect(result.answers).toHaveLength(1);
    expect(result.answers[0].type).toBe('CAA');
    expect(result.answers[0].data).toBe('0 issue "letsencrypt.org"');
  });

  it('parses DS record', () => {
    // DS: key_tag(2) + algorithm(1) + digest_type(1) + digest(variable)
    const rdata = new Uint8Array([
      0x0A, 0x1B, // key tag = 2587
      0x0D,       // algorithm 13
      0x02,       // digest type 2 (SHA-256)
      0xAB, 0xCD, 0xEF, 0x01 // truncated digest
    ]);

    const resp = buildResponse({
      answers: [{ name: 'example.com', type: 43, ttl: 86400, rdata }]
    });

    const result = parseDNSResponse(resp, 0);
    expect(result.answers).toHaveLength(1);
    expect(result.answers[0].type).toBe('DS');
    expect(result.answers[0].data).toContain('2587 13 2');
  });

  it('skips RRSIG records (type 46)', () => {
    const resp = buildResponse({
      answers: [
        { name: 'example.com', type: 1, ttl: 300, rdata: new Uint8Array([1, 2, 3, 4]) },
        { name: 'example.com', type: 46, ttl: 300, rdata: new Uint8Array([0, 0, 0, 0]) }, // RRSIG
      ]
    });

    const result = parseDNSResponse(resp, 0);
    // RRSIG should be filtered out
    expect(result.answers).toHaveLength(1);
    expect(result.answers[0].type).toBe('A');
  });

  it('throws on response shorter than 12 bytes', () => {
    const short = new Uint8Array(6);
    expect(() => parseDNSResponse(short, 0)).toThrow('Response too short');
  });

  it('handles response with zero answers', () => {
    const resp = buildResponse({ answers: [] });
    const result = parseDNSResponse(resp, 15);
    expect(result.answers).toHaveLength(0);
    expect(result.rcode).toBe(0);
    expect(result.query_time_ms).toBe(15);
  });

  it('handles all RCODE values', () => {
    for (const rcode of [0, 1, 2, 3, 4, 5]) {
      const resp = buildResponse({ rcode });
      const result = parseDNSResponse(resp, 0);
      expect(result.rcode).toBe(rcode);
    }
  });

  it('preserves query time in milliseconds', () => {
    const resp = buildResponse({});
    const result = parseDNSResponse(resp, 123.456);
    expect(result.query_time_ms).toBe(123);
  });

  it('parses DNSKEY record', () => {
    // DNSKEY: flags(2) + protocol(1) + algorithm(1) + public_key
    const key = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
    const rdata = new Uint8Array(4 + key.length);
    rdata[0] = 0x01; rdata[1] = 0x01; // flags = 257 (KSK)
    rdata[2] = 3; // protocol
    rdata[3] = 13; // algorithm ECDSAP256
    rdata.set(key, 4);

    const resp = buildResponse({
      answers: [{ name: 'example.com', type: 48, ttl: 3600, rdata }]
    });

    const result = parseDNSResponse(resp, 0);
    expect(result.answers).toHaveLength(1);
    expect(result.answers[0].type).toBe('DNSKEY');
    expect(result.answers[0].data).toContain('257 3 13');
  });

  it('hex-encodes unknown record types', () => {
    const rdata = new Uint8Array([0xAA, 0xBB, 0xCC]);
    const resp = buildResponse({
      answers: [{ name: 'example.com', type: 999, ttl: 60, rdata }]
    });

    const result = parseDNSResponse(resp, 0);
    expect(result.answers[0].type).toBe('TYPE999');
    expect(result.answers[0].data).toBe('aa bb cc');
  });
});
