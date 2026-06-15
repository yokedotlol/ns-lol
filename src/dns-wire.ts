// DNS wireformat (RFC 1035 / RFC 8484) encoder/decoder
// Enables DoH queries to ALL resolvers, not just those supporting JSON API

import { getRecordTypeName } from './dns';

// Build a DNS query message (binary)
export function buildDNSQuery(domain: string, type: number, rd = true, doFlag = true): Uint8Array {
  const id = (Math.random() * 0xffff) | 0;

  // Encode domain name as labels
  const labels = domain.replace(/\.$/, '').split('.');
  const nameBytes: number[] = [];
  for (const label of labels) {
    if (label.length > 63) throw new Error('Label too long');
    nameBytes.push(label.length);
    for (let i = 0; i < label.length; i++) {
      nameBytes.push(label.charCodeAt(i));
    }
  }
  nameBytes.push(0); // root label

  // Question: name + QTYPE(2) + QCLASS(2)
  const questionLen = nameBytes.length + 4;

  // OPT RR for EDNS0 (if DO flag requested)
  // NAME=0x00, TYPE=OPT(41), UDP_SIZE=4096, EXT_RCODE=0, VERSION=0, DO=1, Z=0, RDLENGTH=0
  const optRR = doFlag ? new Uint8Array([
    0x00,                   // NAME (root)
    0x00, 0x29,             // TYPE = OPT (41)
    0x10, 0x00,             // CLASS = UDP payload size (4096)
    0x00,                   // extended RCODE
    0x00,                   // EDNS version
    0x80, 0x00,             // flags: DO=1
    0x00, 0x00,             // RDLENGTH = 0
  ]) : new Uint8Array(0);

  const arcount = doFlag ? 1 : 0;
  const totalLen = 12 + questionLen + optRR.length;
  const buf = new Uint8Array(totalLen);
  const view = new DataView(buf.buffer);

  // Header
  view.setUint16(0, id);
  view.setUint16(2, rd ? 0x0100 : 0x0000); // RD flag
  view.setUint16(4, 1);       // QDCOUNT
  view.setUint16(6, 0);       // ANCOUNT
  view.setUint16(8, 0);       // NSCOUNT
  view.setUint16(10, arcount); // ARCOUNT

  // Question
  let offset = 12;
  for (const b of nameBytes) {
    buf[offset++] = b;
  }
  view.setUint16(offset, type); offset += 2;
  view.setUint16(offset, 1);   offset += 2; // QCLASS = IN

  // OPT pseudo-RR
  if (optRR.length > 0) {
    buf.set(optRR, offset);
  }

  return buf;
}

// Decode a domain name from a DNS message, handling compression pointers
function decodeName(buf: Uint8Array, offset: number, maxJumps = 10): { name: string; newOffset: number } {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const labels: string[] = [];
  let jumped = false;
  let readOffset = offset;
  let jumps = 0;

  while (true) {
    if (readOffset >= buf.length) throw new Error('Name decode out of bounds');
    const len = buf[readOffset];

    if (len === 0) {
      if (!jumped) offset = readOffset + 1;
      break;
    }

    if ((len & 0xc0) === 0xc0) {
      // Compression pointer
      if (++jumps > maxJumps) throw new Error('Too many compression jumps');
      const ptr = view.getUint16(readOffset) & 0x3fff;
      if (!jumped) offset = readOffset + 2;
      readOffset = ptr;
      jumped = true;
      continue;
    }

    readOffset++;
    const label = new TextDecoder().decode(buf.slice(readOffset, readOffset + len));
    labels.push(label);
    readOffset += len;
  }

  return { name: labels.join('.'), newOffset: jumped ? offset : readOffset + 1 };
}

// Format IPv4 address from 4 bytes
function formatA(rdata: Uint8Array): string {
  return `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
}

// Format IPv6 address from 16 bytes
function formatAAAA(rdata: Uint8Array): string {
  const groups: string[] = [];
  const view = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  for (let i = 0; i < 16; i += 2) {
    groups.push(view.getUint16(i).toString(16));
  }
  // Compress consecutive zero groups
  const full = groups.join(':');
  return full.replace(/(^|:)0(:0)+(:|$)/, '::').replace(/^0::/, '::').replace(/::0$/, '::');
}

// Format MX record: "priority hostname"
function formatMX(rdata: Uint8Array, buf: Uint8Array, rdataOffset: number): string {
  const view = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  const preference = view.getUint16(0);
  const { name } = decodeName(buf, rdataOffset + 2);
  return `${preference} ${name}.`;
}

// Format SOA record
function formatSOA(buf: Uint8Array, rdataOffset: number): string {
  const { name: mname, newOffset: off1 } = decodeName(buf, rdataOffset);
  const { name: rname, newOffset: off2 } = decodeName(buf, off1);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const serial = view.getUint32(off2);
  const refresh = view.getUint32(off2 + 4);
  const retry = view.getUint32(off2 + 8);
  const expire = view.getUint32(off2 + 12);
  const minimum = view.getUint32(off2 + 16);
  return `${mname}. ${rname}. ${serial} ${refresh} ${retry} ${expire} ${minimum}`;
}

// Format SRV record
function formatSRV(rdata: Uint8Array, buf: Uint8Array, rdataOffset: number): string {
  const view = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  const priority = view.getUint16(0);
  const weight = view.getUint16(2);
  const port = view.getUint16(4);
  const { name } = decodeName(buf, rdataOffset + 6);
  return `${priority} ${weight} ${port} ${name}.`;
}

// Format CAA record
function formatCAA(rdata: Uint8Array): string {
  const flags = rdata[0];
  const tagLen = rdata[1];
  const tag = new TextDecoder().decode(rdata.slice(2, 2 + tagLen));
  const value = new TextDecoder().decode(rdata.slice(2 + tagLen));
  return `${flags} ${tag} "${value}"`;
}

// Format TXT record (concatenate character strings)
function formatTXT(rdata: Uint8Array): string {
  const parts: string[] = [];
  let pos = 0;
  while (pos < rdata.length) {
    const len = rdata[pos++];
    if (pos + len > rdata.length) break;
    parts.push(new TextDecoder().decode(rdata.slice(pos, pos + len)));
    pos += len;
  }
  return `"${parts.join('')}"`;
}

// Format DS record
function formatDS(rdata: Uint8Array): string {
  const view = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  const keyTag = view.getUint16(0);
  const algorithm = rdata[2];
  const digestType = rdata[3];
  const digest = Array.from(rdata.slice(4)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return `${keyTag} ${algorithm} ${digestType} ${digest}`;
}

// Format DNSKEY record
function formatDNSKEY(rdata: Uint8Array): string {
  const view = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  const flags = view.getUint16(0);
  const protocol = rdata[2];
  const algorithm = rdata[3];
  // Base64 encode the public key
  const keyBytes = rdata.slice(4);
  const keyB64 = btoa(String.fromCharCode(...keyBytes));
  return `${flags} ${protocol} ${algorithm} ${keyB64}`;
}

// Format RDATA based on record type
function formatRData(type: number, rdata: Uint8Array, fullMsg: Uint8Array, rdataOffset: number): string {
  try {
    switch (type) {
      case 1:   return formatA(rdata);                           // A
      case 28:  return formatAAAA(rdata);                        // AAAA
      case 2:                                                    // NS
      case 5:                                                    // CNAME
      case 12:                                                   // PTR
        return decodeName(fullMsg, rdataOffset).name + '.';
      case 15:  return formatMX(rdata, fullMsg, rdataOffset);    // MX
      case 16:  return formatTXT(rdata);                         // TXT
      case 6:   return formatSOA(fullMsg, rdataOffset);          // SOA
      case 33:  return formatSRV(rdata, fullMsg, rdataOffset);   // SRV
      case 257: return formatCAA(rdata);                         // CAA
      case 43:  return formatDS(rdata);                          // DS
      case 48:  return formatDNSKEY(rdata);                      // DNSKEY
      default:
        // Hex-encode unknown types
        return Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join(' ');
    }
  } catch {
    return Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join(' ');
  }
}

export interface WireAnswer {
  type: string;
  name: string;
  TTL: number;
  data: string;
}

export interface WireResponse {
  answers: WireAnswer[];
  rcode: number;
  flags: { aa: boolean; ad: boolean };
  query_time_ms: number;
}

// Parse a DNS response message
export function parseDNSResponse(buf: Uint8Array, elapsed: number): WireResponse {
  if (buf.length < 12) throw new Error('Response too short');

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);

  const flags = view.getUint16(2);
  const rcode = flags & 0x0f;
  const aa = !!(flags & 0x0400);
  const ad = !!(flags & 0x0020);

  const qdcount = view.getUint16(4);
  const ancount = view.getUint16(6);

  // Skip questions
  let offset = 12;
  for (let i = 0; i < qdcount; i++) {
    const { newOffset } = decodeName(buf, offset);
    offset = newOffset + 4; // skip QTYPE + QCLASS
  }

  // Parse answers
  const answers: WireAnswer[] = [];
  for (let i = 0; i < ancount; i++) {
    if (offset >= buf.length) break;

    const { name, newOffset } = decodeName(buf, offset);
    offset = newOffset;

    if (offset + 10 > buf.length) break;

    const rrType = view.getUint16(offset); offset += 2;
    /* rrClass */ offset += 2;
    const ttl = view.getUint32(offset); offset += 4;
    const rdlength = view.getUint16(offset); offset += 2;

    if (offset + rdlength > buf.length) break;

    const rdata = buf.slice(offset, offset + rdlength);
    const rdataStr = formatRData(rrType, rdata, buf, offset);

    // Skip RRSIG (type 46) and OPT (type 41) — they're metadata, not user records
    if (rrType !== 46 && rrType !== 41) {
      answers.push({
        type: getRecordTypeName(rrType),
        name: name.replace(/\.$/, ''),
        TTL: ttl,
        data: rdataStr,
      });
    }

    offset += rdlength;
  }

  return {
    answers,
    rcode,
    flags: { aa, ad },
    query_time_ms: Math.round(elapsed),
  };
}
