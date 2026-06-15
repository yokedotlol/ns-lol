// ns.lol DNS Probe — single Fly.io machine that queries geo-distributed resolvers via UDP
// CF Workers can't do UDP, so this probe fills that gap.
// Returns results from public resolvers around the world for propagation checking.

const dgram = require('dgram');
const http = require('http');

const AUTH_SECRET = process.env.AUTH_SECRET || '';

// Global public DNS resolvers with known geographic locations
// These are the resolvers we query FROM this single probe — the geographic
// diversity comes from the resolvers themselves, not from where we run.
const RESOLVERS = [
  // North America
  { ip: '8.8.8.8',         name: 'Google',           location: 'Mountain View, US',  lat: 37.39, lng: -122.08 },
  { ip: '1.1.1.1',         name: 'Cloudflare',       location: 'San Francisco, US',  lat: 37.77, lng: -122.42 },
  { ip: '9.9.9.9',         name: 'Quad9',            location: 'Zurich, CH',         lat: 47.37, lng: 8.54 },
  { ip: '208.67.222.222',  name: 'OpenDNS',          location: 'San Francisco, US',  lat: 37.77, lng: -122.42 },
  { ip: '149.112.112.112', name: 'Quad9 Secondary',  location: 'Global (Anycast)',   lat: 40.71, lng: -74.01 },
  { ip: '76.76.2.0',       name: 'Control D',        location: 'Toronto, CA',        lat: 43.65, lng: -79.38 },
  { ip: '185.228.168.9',   name: 'CleanBrowsing',    location: 'Global (Anycast)',   lat: 48.86, lng: 2.35 },
  { ip: '149.112.121.10',  name: 'CIRA Shield',      location: 'Ottawa, CA',         lat: 45.42, lng: -75.70 },
  // Europe
  { ip: '4.2.2.1',         name: 'Level3',           location: 'US (Anycast)',       lat: 38.00, lng: -97.00 },
  { ip: '194.242.2.2',     name: 'Mullvad',          location: 'Stockholm, SE',      lat: 59.33, lng: 18.07 },
  { ip: '94.140.14.14',    name: 'AdGuard',          location: 'Cyprus',             lat: 35.17, lng: 33.36 },
  // Americas / Global
  { ip: '64.6.64.6',       name: 'Verisign',         location: 'Reston, US',         lat: 38.96, lng: -77.34 },
  { ip: '45.90.28.0',      name: 'NextDNS',          location: 'Global (Anycast)',   lat: 40.71, lng: -74.01 },
  // Asia-Pacific
  { ip: '185.222.222.222', name: 'DNS.SB',           location: 'Global (Anycast)',   lat: 1.35,  lng: 103.82 },
  { ip: '8.26.56.26',      name: 'Comodo Secure',    location: 'Clifton, US',        lat: 40.86, lng: -74.16 },
];

// DNS record type codes
const QTYPES = {
  A: 1, AAAA: 28, CNAME: 5, MX: 15, TXT: 16, NS: 2,
  SOA: 6, SRV: 33, PTR: 12, CAA: 257, DS: 43, DNSKEY: 48, HTTPS: 65,
};
const QTYPE_NAMES = Object.fromEntries(Object.entries(QTYPES).map(([k, v]) => [v, k]));

// Build a DNS query packet (RFC 1035)
function buildQuery(domain, qtype) {
  const id = (Math.random() * 0xFFFF) | 0;
  // Header: ID, flags (RD=1), QDCOUNT=1
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2); // standard query, RD=1
  header.writeUInt16BE(1, 4);      // QDCOUNT

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

  return { id, packet: Buffer.concat([header, ...parts, tail]) };
}

// Parse a DNS response packet
function parseResponse(buf, queryId) {
  if (buf.length < 12) throw new Error('Response too short');

  const id = buf.readUInt16BE(0);
  if (id !== queryId) throw new Error('ID mismatch');

  const flags = buf.readUInt16BE(2);
  const rcode = flags & 0x0F;
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

  return { rcode: rcodeStr(rcode), aa, ad, answers };
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

// Send a UDP DNS query to a specific resolver
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

    socket.on('message', (msg) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      const elapsed = Math.round(performance.now() - start);
      socket.close();
      try {
        const parsed = parseResponse(msg, id);
        resolve({
          resolver: resolver.name,
          ip: resolver.ip,
          location: resolver.location,
          lat: resolver.lat,
          lng: resolver.lng,
          records: parsed.answers,
          rcode: parsed.rcode,
          aa: parsed.aa,
          ad: parsed.ad,
          query_time_ms: elapsed,
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
          query_time_ms: elapsed,
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

      socket.on('message', (msg) => {
        if (done) return; done = true; clearTimeout(timer);
        const elapsed = Math.round(performance.now() - start);
        socket.close();
        try {
          const parsed = parseResponse(msg, id);
          resolve({ nameserver, ip, records: parsed.answers, rcode: parsed.rcode, aa: parsed.aa, ad: parsed.ad, query_time_ms: elapsed });
        } catch (e) {
          resolve({ nameserver, ip, records: [], rcode: 'ERROR', query_time_ms: elapsed, error: e.message });
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
  if (url.pathname !== '/health' && AUTH_SECRET && url.searchParams.get('key') !== AUTH_SECRET) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }

  // Health
  if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', region: process.env.FLY_REGION || 'unknown', resolvers: RESOLVERS.length }));
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
