// ns.lol DNS Probe — single Fly.io machine that queries geo-distributed resolvers via UDP
// CF Workers can't do UDP, so this probe fills that gap.
// Returns results from public resolvers around the world for propagation checking.

const dgram = require('dgram');
const http = require('http');

const AUTH_SECRET = process.env.AUTH_SECRET || '';

// Global public DNS resolvers with known geographic locations
// These are the resolvers we query FROM this single probe — the geographic
// diversity comes from the resolvers themselves, not from where we run.
// All resolvers — probe selects its subset based on FLY_REGION
const ALL_RESOLVERS = [
  // North America
  { ip: '8.8.8.8',         name: 'Google',             location: 'Mountain View, US',  lat: 37.39, lng: -122.08, region: 'na' },
  { ip: '1.1.1.1',         name: 'Cloudflare',         location: 'San Francisco, US',  lat: 37.77, lng: -122.42, region: 'na' },
  { ip: '208.67.222.222',  name: 'OpenDNS',            location: 'San Francisco, US',  lat: 37.77, lng: -122.42, region: 'na' },
  { ip: '76.76.2.0',       name: 'Control D',          location: 'Toronto, CA',        lat: 43.65, lng: -79.38,  region: 'na' },
  { ip: '185.228.168.9',   name: 'CleanBrowsing',      location: 'Global (Anycast)',   lat: 37.77, lng: -122.42, region: 'na' },
  { ip: '149.112.121.10',  name: 'CIRA Shield',        location: 'Ottawa, CA',         lat: 45.42, lng: -75.70,  region: 'na' },
  { ip: '4.2.2.1',         name: 'Level3',             location: 'Denver, US',         lat: 39.74, lng: -104.99, region: 'na' },
  { ip: '156.154.70.5',    name: 'Neustar',            location: 'Sterling, US',       lat: 39.01, lng: -77.43,  region: 'na' },
  { ip: '64.6.64.6',       name: 'Verisign',           location: 'Reston, US',         lat: 38.96, lng: -77.34,  region: 'na' },
  { ip: '8.26.56.26',      name: 'Comodo Secure',      location: 'Clifton, US',        lat: 40.86, lng: -74.16,  region: 'na' },
  // Europe / Global (better from EU probe)
  { ip: '9.9.9.9',         name: 'Quad9',              location: 'Zurich, CH',         lat: 47.37, lng: 8.54,    region: 'eu' },
  { ip: '149.112.112.112', name: 'Quad9 Secondary',    location: 'Global (Anycast)',   lat: 40.71, lng: -74.01,  region: 'eu' },
  { ip: '94.140.14.14',    name: 'AdGuard',            location: 'Cyprus',             lat: 35.17, lng: 33.36,   region: 'eu' },
  { ip: '84.200.69.80',    name: 'dns.watch',          location: 'Nuremberg, DE',      lat: 49.45, lng: 11.08,   region: 'eu' },
  { ip: '77.88.8.8',       name: 'Yandex DNS',         location: 'Moscow, RU',         lat: 55.76, lng: 37.62,   region: 'eu' },
  { ip: '45.90.28.0',      name: 'NextDNS',            location: 'Global (Anycast)',   lat: 40.71, lng: -74.01,  region: 'eu' },
  { ip: '185.222.222.222', name: 'DNS.SB',             location: 'Global (Anycast)',   lat: 1.35,  lng: 103.82,  region: 'eu' },
];

// EU Fly regions (ams, cdg, fra, lhr, mad, waw, etc.)
const EU_FLY_REGIONS = new Set(['ams', 'cdg', 'fra', 'lhr', 'mad', 'waw', 'arn', 'otp', 'hel']);
const flyRegion = process.env.FLY_REGION || 'sjc';
const isEU = EU_FLY_REGIONS.has(flyRegion);
const RESOLVERS = ALL_RESOLVERS.filter(r => r.region === (isEU ? 'eu' : 'na'));

// DNS record type codes
const QTYPES = {
  A: 1, AAAA: 28, CNAME: 5, MX: 15, TXT: 16, NS: 2,
  SOA: 6, SRV: 33, PTR: 12, CAA: 257, DS: 43, DNSKEY: 48, HTTPS: 65,
};
const QTYPE_NAMES = Object.fromEntries(Object.entries(QTYPES).map(([k, v]) => [v, k]));

// Build a DNS query packet (RFC 1035 + EDNS0 RFC 6891)
function buildQuery(domain, qtype) {
  const id = (Math.random() * 0xFFFF) | 0;
  // Header: ID, flags (RD=1), QDCOUNT=1, ARCOUNT=1 (for OPT)
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2); // standard query, RD=1
  header.writeUInt16BE(1, 4);      // QDCOUNT
  header.writeUInt16BE(0, 6);      // ANCOUNT
  header.writeUInt16BE(0, 8);      // NSCOUNT
  header.writeUInt16BE(1, 10);     // ARCOUNT (OPT record)

  // QNAME
  const labels = domain.split('.');
  const parts = [];
  for (const label of labels) {
    const buf = Buffer.alloc(1 + label.length);
    buf.writeUInt8(label.length, 0);
    buf.write(label, 1, 'ascii');
    parts.push(buf);
  }
  parts.push(Buffer.from([0])); // root label

  // QTYPE + QCLASS
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(qtype, 0);
  tail.writeUInt16BE(1, 2); // IN class

  // EDNS0 OPT record (RFC 6891): request 4096-byte UDP payloads
  // NAME=root(0), TYPE=OPT(41), CLASS=UDP payload size(4096), TTL=0, RDLENGTH=0
  const opt = Buffer.alloc(11);
  opt.writeUInt8(0, 0);           // NAME: root
  opt.writeUInt16BE(41, 1);       // TYPE: OPT
  opt.writeUInt16BE(4096, 3);     // CLASS: UDP payload size
  opt.writeUInt32BE(0, 5);        // TTL: extended RCODE + flags
  opt.writeUInt16BE(0, 9);        // RDLENGTH: no options

  return { id, packet: Buffer.concat([header, ...parts, tail, opt]) };
}

// Parse a DNS response packet
function parseResponse(buf, queryId) {
  if (buf.length < 12) throw new Error('Response too short');

  const id = buf.readUInt16BE(0);
  if (id !== queryId) throw new Error('ID mismatch');

  const flags = buf.readUInt16BE(2);
  const rcode = flags & 0x0F;
  const tc = !!(flags & 0x0200);
  const aa = !!(flags & 0x0400);
  const ad = !!(flags & 0x0020);
  const qdcount = buf.readUInt16BE(4);
  const ancount = buf.readUInt16BE(6);

  let offset = 12;

  // Skip questions
  for (let i = 0; i < qdcount; i++) {
    offset = skipName(buf, offset);
    offset += 4; // QTYPE + QCLASS
  }

  // Parse answers
  const answers = [];
  for (let i = 0; i < ancount; i++) {
    const { name, newOffset } = readName(buf, offset);
    offset = newOffset;
    const type = buf.readUInt16BE(offset);
    offset += 4; // TYPE + CLASS
    const ttl = buf.readUInt32BE(offset);
    offset += 4;
    const rdlength = buf.readUInt16BE(offset);
    offset += 2;
    const rdata = parseRData(buf, offset, rdlength, type);
    offset += rdlength;
    answers.push({
      name,
      type: QTYPE_NAMES[type] || `TYPE${type}`,
      TTL: ttl,
      data: rdata,
    });
  }

  return { rcode: rcodeStr(rcode), tc, aa, ad, answers };
}

function rcodeStr(code) {
  const names = ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED'];
  return names[code] || `RCODE${code}`;
}

// Read a DNS name (with compression pointer support)
function readName(buf, offset) {
  const labels = [];
  let jumped = false;
  let savedOffset = 0;

  while (true) {
    if (offset >= buf.length) break;
    const len = buf[offset];
    if (len === 0) { offset++; break; }
    if ((len & 0xC0) === 0xC0) {
      if (!jumped) savedOffset = offset + 2;
      jumped = true;
      offset = ((len & 0x3F) << 8) | buf[offset + 1];
      continue;
    }
    offset++;
    labels.push(buf.subarray(offset, offset + len).toString('ascii'));
    offset += len;
  }

  return { name: labels.join('.'), newOffset: jumped ? savedOffset : offset };
}

function skipName(buf, offset) {
  while (true) {
    if (offset >= buf.length) return offset;
    const len = buf[offset];
    if (len === 0) return offset + 1;
    if ((len & 0xC0) === 0xC0) return offset + 2;
    offset += 1 + len;
  }
}

// Parse RDATA based on record type
function parseRData(buf, offset, length, type) {
  try {
    switch (type) {
      case 1: // A
        return `${buf[offset]}.${buf[offset+1]}.${buf[offset+2]}.${buf[offset+3]}`;
      case 28: { // AAAA
        const parts = [];
        for (let i = 0; i < 16; i += 2) {
          parts.push(buf.readUInt16BE(offset + i).toString(16));
        }
        return parts.join(':').replace(/(^|:)0(:0)*(:|$)/, '$1::$3').replace(/^::/, '::');
      }
      case 5: // CNAME
      case 2: // NS
      case 12: // PTR
        return readName(buf, offset).name;
      case 15: { // MX
        const pref = buf.readUInt16BE(offset);
        const mx = readName(buf, offset + 2).name;
        return `${pref} ${mx}`;
      }
      case 16: { // TXT
        const txts = [];
        let pos = offset;
        const end = offset + length;
        while (pos < end) {
          const slen = buf[pos++];
          txts.push(buf.subarray(pos, pos + slen).toString('utf8'));
          pos += slen;
        }
        return txts.join('');
      }
      case 6: { // SOA
        const { name: mname, newOffset: o1 } = readName(buf, offset);
        const { name: rname, newOffset: o2 } = readName(buf, o1);
        const serial = buf.readUInt32BE(o2);
        const refresh = buf.readUInt32BE(o2 + 4);
        const retry = buf.readUInt32BE(o2 + 8);
        const expire = buf.readUInt32BE(o2 + 12);
        const minimum = buf.readUInt32BE(o2 + 16);
        return `${mname} ${rname} ${serial} ${refresh} ${retry} ${expire} ${minimum}`;
      }
      default:
        return buf.subarray(offset, offset + length).toString('hex');
    }
  } catch {
    return buf.subarray(offset, offset + length).toString('hex');
  }
}

// Send a TCP DNS query (RFC 1035 §4.2.2: 2-byte length prefix)
function queryResolverTCP(ip, domain, qtype, timeout = 5000) {
  const net = require('net');
  return new Promise((resolve) => {
    const { id, packet } = buildQuery(domain, qtype);
    // TCP DNS: prepend 2-byte message length
    const lenBuf = Buffer.alloc(2);
    lenBuf.writeUInt16BE(packet.length, 0);
    const tcpPacket = Buffer.concat([lenBuf, packet]);

    const socket = new net.Socket();
    const start = performance.now();
    let done = false;
    let buf = Buffer.alloc(0);

    const finish = (result) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };

    const timer = setTimeout(() => finish(null), timeout);

    socket.connect(53, ip, () => {
      socket.write(tcpPacket);
    });

    socket.on('data', (chunk) => {
      if (done) return;
      buf = Buffer.concat([buf, chunk]);
      // Need at least 2 bytes for length prefix
      if (buf.length < 2) return;
      const msgLen = buf.readUInt16BE(0);
      // Wait until we have the full message
      if (buf.length < 2 + msgLen) return;
      try {
        const msg = buf.subarray(2, 2 + msgLen);
        const parsed = parseResponse(msg, id);
        const elapsed = Math.round(performance.now() - start);
        finish({ answers: parsed.answers, rcode: parsed.rcode, aa: parsed.aa, ad: parsed.ad, elapsed });
      } catch {
        finish(null);
      }
    });

    socket.on('end', () => finish(null));
    socket.on('error', () => finish(null));
  });
}

// Send a UDP DNS query to a specific resolver, with TCP fallback on truncation
function queryResolver(resolver, domain, qtype, timeout = 5000) {
  return new Promise((resolve) => {
    const { id, packet } = buildQuery(domain, qtype);
    const socket = dgram.createSocket('udp4');
    const start = performance.now();
    let done = false;

    const timer = setTimeout(() => {
      if (!done) {
        done = true;
        socket.close();
        resolve({
          resolver: resolver.name,
          ip: resolver.ip,
          location: resolver.location,
          lat: resolver.lat,
          lng: resolver.lng,
          records: [],
          rcode: 'TIMEOUT',
          aa: false,
          ad: false,
          query_time_ms: timeout,
          error: 'Query timed out',
        });
      }
    }, timeout);

    socket.on('message', async (msg) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.close();
      try {
        const parsed = parseResponse(msg, id);

        // TC bit set = response truncated, retry over TCP
        if (parsed.tc) {
          const remaining = timeout - Math.round(performance.now() - start);
          if (remaining > 500) {
            const tcp = await queryResolverTCP(resolver.ip, domain, qtype, remaining);
            if (tcp) {
              resolve({
                resolver: resolver.name,
                ip: resolver.ip,
                location: resolver.location,
                lat: resolver.lat,
                lng: resolver.lng,
                records: tcp.answers,
                rcode: tcp.rcode,
                tc: false,
                aa: tcp.aa,
                ad: tcp.ad,
                query_time_ms: Math.round(performance.now() - start),
              });
              return;
            }
          }
        }

        resolve({
          resolver: resolver.name,
          ip: resolver.ip,
          location: resolver.location,
          lat: resolver.lat,
          lng: resolver.lng,
          records: parsed.answers,
          rcode: parsed.rcode,
          tc: parsed.tc,
          aa: parsed.aa,
          ad: parsed.ad,
          query_time_ms: Math.round(performance.now() - start),
        });
      } catch (err) {
        resolve({
          resolver: resolver.name,
          ip: resolver.ip,
          location: resolver.location,
          lat: resolver.lat,
          lng: resolver.lng,
          records: [],
          rcode: 'ERROR',
          aa: false,
          ad: false,
          query_time_ms: Math.round(performance.now() - start),
          error: err.message,
        });
      }
    });

    socket.on('error', (err) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      const elapsed = Math.round(performance.now() - start);
      socket.close();
      resolve({
        resolver: resolver.name,
        ip: resolver.ip,
        location: resolver.location,
        lat: resolver.lat,
        lng: resolver.lng,
        records: [],
        rcode: 'ERROR',
        aa: false,
        ad: false,
        query_time_ms: elapsed,
        error: err.message,
      });
    });

    socket.send(packet, 0, packet.length, 53, resolver.ip);
  });
}

// Query a specific nameserver directly (for authoritative checks)
function queryNameserver(nameserver, domain, qtype, timeout = 5000) {
  return new Promise((resolve) => {
    const dns = require('dns');
    dns.resolve4(nameserver, (err, addresses) => {
      if (err || !addresses.length) {
        resolve({
          nameserver,
          records: [],
          rcode: 'RESOLVE_FAILED',
          error: `Could not resolve nameserver: ${err ? err.message : 'no addresses'}`,
          query_time_ms: 0,
        });
        return;
      }
      const ip = addresses[0];
      const { id, packet } = buildQuery(domain, qtype);
      const socket = dgram.createSocket('udp4');
      const start = performance.now();
      let done = false;

      const timer = setTimeout(() => {
        if (!done) { done = true; socket.close(); resolve({ nameserver, ip, records: [], rcode: 'TIMEOUT', query_time_ms: timeout, error: 'Timed out' }); }
      }, timeout);

      socket.on('message', async (msg) => {
        if (done) return; done = true; clearTimeout(timer);
        socket.close();
        try {
          const parsed = parseResponse(msg, id);
          // TC bit set = truncated, retry over TCP
          if (parsed.tc) {
            const remaining = timeout - Math.round(performance.now() - start);
            if (remaining > 500) {
              const tcp = await queryResolverTCP(ip, domain, qtype, remaining);
              if (tcp) {
                resolve({ nameserver, ip, records: tcp.answers, rcode: tcp.rcode, tc: false, aa: tcp.aa, ad: tcp.ad, query_time_ms: Math.round(performance.now() - start) });
                return;
              }
            }
          }
          resolve({ nameserver, ip, records: parsed.answers, rcode: parsed.rcode, tc: parsed.tc, aa: parsed.aa, ad: parsed.ad, query_time_ms: Math.round(performance.now() - start) });
        } catch (e) {
          resolve({ nameserver, ip, records: [], rcode: 'ERROR', query_time_ms: Math.round(performance.now() - start), error: e.message });
        }
      });

      socket.on('error', (e) => {
        if (done) return; done = true; clearTimeout(timer);
        socket.close();
        resolve({ nameserver, ip, records: [], rcode: 'ERROR', query_time_ms: Math.round(performance.now() - start), error: e.message });
      });

      socket.send(packet, 0, packet.length, 53, ip);
    });
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  // Auth check (skip for health)
  const authHeader = req.headers['authorization'] || '';
  const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  if (url.pathname !== '/health' && AUTH_SECRET && bearerToken !== AUTH_SECRET) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }

  // Health
  if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', region: flyRegion, role: isEU ? 'eu' : 'na', resolvers: RESOLVERS.length, total: ALL_RESOLVERS.length }));
    return;
  }

  // List available resolvers
  if (url.pathname === '/resolvers') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ resolvers: RESOLVERS.map(r => ({ name: r.name, ip: r.ip, location: r.location, lat: r.lat, lng: r.lng })) }));
    return;
  }

  // Propagation check: query ALL resolvers in parallel
  if (url.pathname === '/propagation') {
    const name = url.searchParams.get('name');
    const type = (url.searchParams.get('type') || 'A').toUpperCase();
    const qtype = QTYPES[type];

    if (!name) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Missing name parameter' })); return; }
    if (!qtype) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: `Unknown type: ${type}` })); return; }

    const start = performance.now();
    const results = await Promise.all(RESOLVERS.map(r => queryResolver(r, name, qtype)));
    const elapsed = Math.round(performance.now() - start);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ name, type, total_time_ms: elapsed, results }));
    return;
  }

  // Single resolve: query ONE resolver
  if (url.pathname === '/resolve') {
    const name = url.searchParams.get('name');
    const type = (url.searchParams.get('type') || 'A').toUpperCase();
    const resolver = url.searchParams.get('resolver') || '8.8.8.8';
    const qtype = QTYPES[type];

    if (!name) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Missing name parameter' })); return; }
    if (!qtype) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: `Unknown type: ${type}` })); return; }

    const r = RESOLVERS.find(r => r.ip === resolver || r.name.toLowerCase() === resolver.toLowerCase()) || { ip: resolver, name: resolver, location: 'Custom', lat: 0, lng: 0 };
    const result = await queryResolver(r, name, qtype);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
    return;
  }

  // Query authoritative nameserver directly
  if (url.pathname === '/authoritative') {
    const name = url.searchParams.get('name');
    const type = (url.searchParams.get('type') || 'A').toUpperCase();
    const ns = url.searchParams.get('ns');
    const qtype = QTYPES[type];

    if (!name || !ns) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Missing name or ns parameter' })); return; }
    if (!qtype) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: `Unknown type: ${type}` })); return; }

    const result = await queryNameserver(ns, name, qtype);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    error: 'Not found',
    endpoints: {
      propagation: '/propagation?name=example.com&type=A',
      resolve: '/resolve?name=example.com&type=A&resolver=8.8.8.8',
      authoritative: '/authoritative?name=example.com&type=A&ns=ns1.example.com',
      resolvers: '/resolvers',
      health: '/health',
    },
  }));
});

server.listen(8080, () => {
  console.log(`DNS probe listening on :8080 in region ${process.env.FLY_REGION || 'unknown'}`);
});
