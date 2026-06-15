// DNS resolution via DoH (DNS-over-HTTPS)
// Queries multiple public resolvers for propagation, single resolver for lookups

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
  aa: boolean;
  ad: boolean; // DNSSEC authenticated
  query_time_ms: number;
  error?: string;
}

// DoH-capable public resolvers with approximate geographic locations
// Each resolver uses the JSON API (Accept: application/dns-json).
// Google uses /resolve (not /dns-query) for its JSON API.
// Resolvers behind Cloudflare are excluded — CF Workers can't reliably
// fetch CF-proxied origins (521/530 errors).
export const DOH_RESOLVERS: { name: string; url: string; location: string; lat: number; lng: number }[] = [
  // Tier 1: Confirmed working from CF Workers
  { name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query', location: 'San Francisco, US', lat: 37.77, lng: -122.42 },
  { name: 'Google', url: 'https://dns.google/resolve', location: 'Mountain View, US', lat: 37.39, lng: -122.08 },
  { name: 'NextDNS', url: 'https://dns.nextdns.io/dns-query', location: 'Global (Anycast)', lat: 40.71, lng: -74.01 },
  { name: 'DNS.SB', url: 'https://doh.dns.sb/dns-query', location: 'Global (Anycast)', lat: 1.35, lng: 103.82 },
  { name: 'Tencent', url: 'https://doh.pub/dns-query', location: 'Shenzhen, CN', lat: 22.54, lng: 114.06 },
  // Tier 2: Large providers on own infrastructure (high confidence)
  { name: 'Quad9', url: 'https://dns.quad9.net/dns-query', location: 'Zurich, CH', lat: 47.37, lng: 8.54 },
  { name: 'OpenDNS', url: 'https://doh.opendns.com/dns-query', location: 'San Francisco, US', lat: 37.77, lng: -122.42 },
  { name: 'AliDNS', url: 'https://dns.alidns.com/dns-query', location: 'Hangzhou, CN', lat: 30.27, lng: 120.15 },
  { name: 'AdGuard', url: 'https://dns.adguard-dns.com/dns-query', location: 'Cyprus', lat: 35.17, lng: 33.36 },
  { name: 'Control D', url: 'https://freedns.controld.com/p0', location: 'Toronto, CA', lat: 43.65, lng: -79.38 },
  { name: 'Mullvad', url: 'https://dns.mullvad.net/dns-query', location: 'Stockholm, SE', lat: 59.33, lng: 18.07 },
  { name: 'Wikimedia', url: 'https://wikimedia-dns.org/dns-query', location: 'Global (Anycast)', lat: 37.39, lng: -122.08 },
  // Tier 3: Smaller/regional providers (may fail from CF Workers)
  { name: 'dns0.eu', url: 'https://dns0.eu/dns-query', location: 'Paris, FR', lat: 48.86, lng: 2.35 },
  { name: 'CIRA Shield', url: 'https://private.canadianshield.cira.ca/dns-query', location: 'Ottawa, CA', lat: 45.42, lng: -75.70 },
  { name: 'IIJ', url: 'https://public.dns.iij.jp/dns-query', location: 'Tokyo, JP', lat: 35.68, lng: 139.69 },
];

// DNS record type numbers
export const RECORD_TYPES: Record<string, number> = {
  A: 1, AAAA: 28, CNAME: 5, MX: 15, TXT: 16, NS: 2,
  SOA: 6, SRV: 33, PTR: 12, CAA: 257, NAPTR: 35, DS: 43,
  DNSKEY: 48, TLSA: 52, HTTPS: 65,
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
  const params = new URLSearchParams({
    name: domain,
    type: String(type),
    do: '1', // request DNSSEC
  });

  const start = performance.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const resp = await fetch(`${resolverUrl}?${params}`, {
      headers: { Accept: 'application/dns-json' },
      signal: controller.signal,
    });
    const elapsed = performance.now() - start;

    if (!resp.ok) {
      throw new Error(`DoH returned ${resp.status}`);
    }

    const data = await resp.json() as any;

    return {
      answers: (data.Answer || []).map((a: any) => ({
        type: getRecordTypeName(a.type),
        name: a.name?.replace(/\.$/, '') || domain,
        TTL: a.TTL || 0,
        data: a.data || '',
      })),
      rcode: data.Status || 0,
      flags: {
        aa: !!data.AA,
        ad: !!data.AD,
      },
      query_time_ms: Math.round(elapsed),
    };
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
