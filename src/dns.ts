// DNS resolution via DoH (DNS-over-HTTPS)
// Uses wireformat (RFC 8484) by default — works with ALL DoH resolvers.
// JSON API fallback for resolvers that support it (Cloudflare, Google).

import { buildDNSQuery, parseDNSResponse } from './dns-wire';

export interface DNSRecord {
  type: string;
  name: string;
  TTL: number;
  data: string;
}

export interface ResolverResult {
  resolver: string;
  location: string;
  lat: number;
  lng: number;
  records: DNSRecord[];
  rcode: string;
  tc?: boolean; // truncation flag
  aa: boolean;
  ad: boolean; // DNSSEC authenticated
  query_time_ms: number;
  error?: string;
}

// DoH-capable public resolvers with approximate geographic locations
// All resolvers use wireformat DoH (RFC 8484) via POST to /dns-query.
// This is the standard — every compliant DoH resolver supports it.
export const DOH_RESOLVERS: { name: string; url: string; location: string; lat: number; lng: number }[] = [
  { name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query', location: 'San Francisco, US', lat: 37.77, lng: -122.42 },
  { name: 'Google', url: 'https://dns.google/dns-query', location: 'Mountain View, US', lat: 37.39, lng: -122.08 },
  { name: 'Quad9', url: 'https://dns.quad9.net/dns-query', location: 'Zurich, CH', lat: 47.37, lng: 8.54 },
  { name: 'OpenDNS', url: 'https://doh.opendns.com/dns-query', location: 'San Francisco, US', lat: 37.77, lng: -122.42 },
  { name: 'NextDNS', url: 'https://dns.nextdns.io/dns-query', location: 'Global (Anycast)', lat: 40.71, lng: -74.01 },
  { name: 'DNS.SB', url: 'https://doh.dns.sb/dns-query', location: 'Global (Anycast)', lat: 1.35, lng: 103.82 },
  { name: 'IIJ', url: 'https://public.dns.iij.jp/dns-query', location: 'Tokyo, JP', lat: 35.68, lng: 139.69 },
  { name: 'AdGuard', url: 'https://dns.adguard-dns.com/dns-query', location: 'Cyprus', lat: 35.17, lng: 33.36 },
  { name: 'Control D', url: 'https://freedns.controld.com/p0', location: 'Toronto, CA', lat: 43.65, lng: -79.38 },
  { name: 'Mullvad', url: 'https://dns.mullvad.net/dns-query', location: 'Stockholm, SE', lat: 59.33, lng: 18.07 },
  { name: 'Wikimedia', url: 'https://wikimedia-dns.org/dns-query', location: 'Global (Anycast)', lat: 37.39, lng: -122.08 },
  { name: 'Quad9 Unfiltered', url: 'https://dns10.quad9.net/dns-query', location: 'Zurich, CH', lat: 47.37, lng: 8.54 },
  { name: 'CIRA Shield', url: 'https://private.canadianshield.cira.ca/dns-query', location: 'Ottawa, CA', lat: 45.42, lng: -75.70 },
];

// DNS record type numbers — comprehensive IANA registry coverage (55 types)
export const RECORD_TYPES: Record<string, number> = {
  // Core / widely used
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33,
  // Security & policy
  CAA: 257, TLSA: 52, SSHFP: 44, CERT: 37, IPSECKEY: 45, OPENPGPKEY: 61, SMIMEA: 53,
  // DNSSEC
  DS: 43, DNSKEY: 48, RRSIG: 46, NSEC: 47, NSEC3: 50, NSEC3PARAM: 51,
  CDNSKEY: 60, CDS: 59, DLV: 32769, TA: 32768,
  // Service discovery & modern
  HTTPS: 65, SVCB: 64, NAPTR: 35, URI: 256,
  // Informational & legacy
  HINFO: 13, RP: 17, LOC: 29, AFSDB: 18, KX: 36, DNAME: 39, APL: 42,
  SPF: 99, NXT: 30, SIG: 24, KEY: 25,
  // Extended
  HIP: 55, CSYNC: 62, ZONEMD: 63, EUI48: 108, EUI64: 109,
  DHCID: 49, TKEY: 249, TSIG: 250,
  // Transfer & meta (named for completeness — may not return data via DoH)
  OPT: 41, AXFR: 252, IXFR: 251,
  // Newer / experimental
  WALLET: 262, NINFO: 56, RKEY: 57, TALINK: 58, AMTRELAY: 260, AVC: 258,
};

const RECORD_TYPE_NAMES: Record<number, string> = Object.fromEntries(
  Object.entries(RECORD_TYPES).map(([k, v]) => [v, k])
);

export function getRecordTypeNumber(type: string): number {
  const num = RECORD_TYPES[type.toUpperCase()];
  if (!num) throw Object.assign(new Error(`Unknown record type: ${type}`), { status: 400 });
  return num;
}

export function getRecordTypeName(num: number): string {
  return RECORD_TYPE_NAMES[num] || `TYPE${num}`;
}

export async function queryDoH(
  resolverUrl: string,
  domain: string,
  type: number,
  timeout = 5000
): Promise<{ answers: any[]; rcode: number; flags: { aa: boolean; ad: boolean }; query_time_ms: number }> {
  const start = performance.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    // Build wireformat DNS query (RFC 8484)
    const queryMsg = buildDNSQuery(domain, type);

    const resp = await fetch(resolverUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message',
      },
      body: queryMsg,
      signal: controller.signal,
    });
    const elapsed = performance.now() - start;

    if (!resp.ok) {
      throw new Error(`DoH returned ${resp.status}`);
    }

    const respBuf = new Uint8Array(await resp.arrayBuffer());
    return parseDNSResponse(respBuf, elapsed, type);
  } finally {
    clearTimeout(timer);
  }
}

const RCODE_NAMES: Record<number, string> = {
  0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
  4: 'NOTIMP', 5: 'REFUSED', 6: 'YXDOMAIN', 7: 'YXRRSET',
  8: 'NXRRSET', 9: 'NOTAUTH',
};

export function rcodeName(code: number): string {
  return RCODE_NAMES[code] || `RCODE${code}`;
}

export async function queryAllResolvers(
  domain: string,
  type: number,
  resolvers = DOH_RESOLVERS
): Promise<ResolverResult[]> {
  const results = await Promise.allSettled(
    resolvers.map(async (r) => {
      try {
        const result = await queryDoH(r.url, domain, type);
        return {
          resolver: r.name,
          location: r.location,
          lat: r.lat,
          lng: r.lng,
          records: result.answers,
          rcode: rcodeName(result.rcode),
          aa: result.flags.aa,
          ad: result.flags.ad,
          query_time_ms: result.query_time_ms,
        } as ResolverResult;
      } catch (err: any) {
        return {
          resolver: r.name,
          location: r.location,
          lat: r.lat,
          lng: r.lng,
          records: [],
          rcode: 'ERROR',
          aa: false,
          ad: false,
          query_time_ms: 0,
          error: err.message,
        } as ResolverResult;
      }
    })
  );

  return results
    .filter((r): r is PromiseFulfilledResult<ResolverResult> => r.status === 'fulfilled')
    .map((r) => r.value);
}

// Query a single resolver (default: Cloudflare for speed)
export async function querySingle(
  domain: string,
  type: number
): Promise<ResolverResult> {
  const r = DOH_RESOLVERS[0]; // Cloudflare
  const result = await queryDoH(r.url, domain, type);
  return {
    resolver: r.name,
    location: r.location,
    lat: r.lat,
    lng: r.lng,
    records: result.answers,
    rcode: rcodeName(result.rcode),
    aa: result.flags.aa,
    ad: result.flags.ad,
    query_time_ms: result.query_time_ms,
  };
}
