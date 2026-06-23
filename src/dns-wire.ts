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

// Format NAPTR record
function formatNAPTR(rdata: Uint8Array, buf: Uint8Array, rdataOffset: number): string {
  const view = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  const order = view.getUint16(0);
  const preference = view.getUint16(2);
  let pos = 4;
  // Three character strings: flags, service, regexp
  const strings: string[] = [];
  for (let i = 0; i < 3; i++) {
    const len = rdata[pos++];
    strings.push(new TextDecoder().decode(rdata.slice(pos, pos + len)));
    pos += len;
  }
  const { name: replacement } = decodeName(buf, rdataOffset + pos);
  return `${order} ${preference} "${strings[0]}" "${strings[1]}" "${strings[2]}" ${replacement}.`;
}

// Format TLSA record
function formatTLSA(rdata: Uint8Array): string {
  const usage = rdata[0];
  const selector = rdata[1];
  const matchingType = rdata[2];
  const certData = Array.from(rdata.slice(3)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return `${usage} ${selector} ${matchingType} ${certData}`;
}

// Format SSHFP record
function formatSSHFP(rdata: Uint8Array): string {
  const algorithm = rdata[0];
  const fpType = rdata[1];
  const fingerprint = Array.from(rdata.slice(2)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return `${algorithm} ${fpType} ${fingerprint}`;
}

// Format HINFO record
function formatHINFO(rdata: Uint8Array): string {
  let pos = 0;
  const cpuLen = rdata[pos++];
  const cpu = new TextDecoder().decode(rdata.slice(pos, pos + cpuLen));
  pos += cpuLen;
  const osLen = rdata[pos++];
  const os = new TextDecoder().decode(rdata.slice(pos, pos + osLen));
  return `"${cpu}" "${os}"`;
}

// Format LOC record (RFC 1876)
function formatLOC(rdata: Uint8Array): string {
  const view = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  const version = rdata[0];
  if (version !== 0) return Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join(' ');
  const size = rdata[1];
  const horizPre = rdata[2];
  const vertPre = rdata[3];
  const latitude = view.getUint32(4);
  const longitude = view.getUint32(8);
  const altitude = view.getUint32(12);
  // Convert from 1/1000 arc-second offset from equator/prime meridian
  const latRef = 2147483648; // 2^31
  const latDeg = (latitude - latRef) / 3600000;
  const lonDeg = (longitude - latRef) / 3600000;
  const altM = (altitude - 10000000) / 100;
  const ns = latDeg >= 0 ? 'N' : 'S';
  const ew = lonDeg >= 0 ? 'E' : 'W';
  return `${Math.abs(latDeg).toFixed(4)} ${ns} ${Math.abs(lonDeg).toFixed(4)} ${ew} ${altM.toFixed(2)}m`;
}

// Format RP record (RFC 1183)
function formatRP(rdata: Uint8Array, buf: Uint8Array, rdataOffset: number): string {
  const { name: mbox, newOffset } = decodeName(buf, rdataOffset);
  const { name: txtDname } = decodeName(buf, newOffset);
  return `${mbox}. ${txtDname}.`;
}

// Format SVCB/HTTPS record (RFC 9460)
function formatSVCB(rdata: Uint8Array, buf: Uint8Array, rdataOffset: number): string {
  const view = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  const priority = view.getUint16(0);
  const { name: target, newOffset } = decodeName(buf, rdataOffset + 2);
  const targetStr = target || '.';
  if (priority === 0) return `${priority} ${targetStr}.`; // AliasMode
  // ServiceMode — parse SvcParams
  const params: string[] = [];
  let pos = newOffset - rdataOffset;
  while (pos + 4 <= rdata.length) {
    const key = view.getUint16(pos); pos += 2;
    const valLen = view.getUint16(pos); pos += 2;
    if (pos + valLen > rdata.length) break;
    const valBytes = rdata.slice(pos, pos + valLen);
    pos += valLen;
    switch (key) {
      case 1: // alpn
        { const alpns: string[] = []; let ap = 0;
          while (ap < valBytes.length) { const al = valBytes[ap++]; alpns.push(new TextDecoder().decode(valBytes.slice(ap, ap + al))); ap += al; }
          params.push(`alpn="${alpns.join(',')}"`); }
        break;
      case 2: // no-default-alpn
        params.push('no-default-alpn'); break;
      case 3: // port
        params.push(`port=${new DataView(valBytes.buffer, valBytes.byteOffset, valBytes.byteLength).getUint16(0)}`); break;
      case 4: // ipv4hint
        { const ips: string[] = [];
          for (let i = 0; i < valBytes.length; i += 4) ips.push(`${valBytes[i]}.${valBytes[i+1]}.${valBytes[i+2]}.${valBytes[i+3]}`);
          params.push(`ipv4hint=${ips.join(',')}`); }
        break;
      case 5: // ech
        params.push(`ech=${btoa(String.fromCharCode(...valBytes))}`); break;
      case 6: // ipv6hint
        { const v6s: string[] = [];
          const dv = new DataView(valBytes.buffer, valBytes.byteOffset, valBytes.byteLength);
          for (let i = 0; i < valBytes.length; i += 16) {
            const g: string[] = []; for (let j = 0; j < 16; j += 2) g.push(dv.getUint16(i + j).toString(16));
            v6s.push(g.join(':'));
          }
          params.push(`ipv6hint=${v6s.join(',')}`); }
        break;
      default:
        params.push(`key${key}=${Array.from(valBytes).map(b => b.toString(16).padStart(2, '0')).join('')}`);
    }
  }
  return `${priority} ${targetStr}. ${params.join(' ')}`;
}

// Format RRSIG record (RFC 4034)
function formatRRSIG(rdata: Uint8Array, buf: Uint8Array, rdataOffset: number): string {
  const view = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  const typeCovered = getRecordTypeName(view.getUint16(0));
  const algorithm = rdata[2];
  const labels = rdata[3];
  const origTTL = view.getUint32(4);
  const expiration = view.getUint32(8);
  const inception = view.getUint32(12);
  const keyTag = view.getUint16(16);
  const { name: signerName, newOffset } = decodeName(buf, rdataOffset + 18);
  const sigBytes = rdata.slice(newOffset - rdataOffset);
  const sigB64 = btoa(String.fromCharCode(...sigBytes));
  return `${typeCovered} ${algorithm} ${labels} ${origTTL} ${expiration} ${inception} ${keyTag} ${signerName}. ${sigB64}`;
}

// Format NSEC record (RFC 4034)
function formatNSEC(rdata: Uint8Array, buf: Uint8Array, rdataOffset: number): string {
  const { name: nextDomain, newOffset } = decodeName(buf, rdataOffset);
  const bitmapOffset = newOffset - rdataOffset;
  const types = parseTypeBitmap(rdata.slice(bitmapOffset));
  return `${nextDomain}. ${types.join(' ')}`;
}

// Format NSEC3 record (RFC 5155)
function formatNSEC3(rdata: Uint8Array): string {
  const hashAlg = rdata[0];
  const flags = rdata[1];
  const iterations = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength).getUint16(2);
  const saltLen = rdata[4];
  const salt = saltLen > 0 ? Array.from(rdata.slice(5, 5 + saltLen)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase() : '-';
  let pos = 5 + saltLen;
  const hashLen = rdata[pos++];
  const hash = base32hexEncode(rdata.slice(pos, pos + hashLen));
  pos += hashLen;
  const types = parseTypeBitmap(rdata.slice(pos));
  return `${hashAlg} ${flags} ${iterations} ${salt} ${hash} ${types.join(' ')}`;
}

// Format NSEC3PARAM record (RFC 5155)
function formatNSEC3PARAM(rdata: Uint8Array): string {
  const hashAlg = rdata[0];
  const flags = rdata[1];
  const iterations = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength).getUint16(2);
  const saltLen = rdata[4];
  const salt = saltLen > 0 ? Array.from(rdata.slice(5, 5 + saltLen)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase() : '-';
  return `${hashAlg} ${flags} ${iterations} ${salt}`;
}

// Format URI record (RFC 7553)
function formatURI(rdata: Uint8Array): string {
  const view = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  const priority = view.getUint16(0);
  const weight = view.getUint16(2);
  const target = new TextDecoder().decode(rdata.slice(4));
  return `${priority} ${weight} "${target}"`;
}

// Format DNAME record (RFC 6672) — same as CNAME, just a name
// (handled by the NS/CNAME/PTR/DNAME case below)

// Format CDS record — same as DS
// Format CDNSKEY record — same as DNSKEY

// Format AFSDB record (RFC 1183)
function formatAFSDB(rdata: Uint8Array, buf: Uint8Array, rdataOffset: number): string {
  const view = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  const subtype = view.getUint16(0);
  const { name } = decodeName(buf, rdataOffset + 2);
  return `${subtype} ${name}.`;
}

// Format KX record (RFC 2230)
function formatKX(rdata: Uint8Array, buf: Uint8Array, rdataOffset: number): string {
  const view = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  const preference = view.getUint16(0);
  const { name } = decodeName(buf, rdataOffset + 2);
  return `${preference} ${name}.`;
}

// Format CERT record (RFC 4398)
function formatCERT(rdata: Uint8Array): string {
  const view = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  const certType = view.getUint16(0);
  const keyTag = view.getUint16(2);
  const algorithm = rdata[4];
  const certData = btoa(String.fromCharCode(...rdata.slice(5)));
  return `${certType} ${keyTag} ${algorithm} ${certData}`;
}

// Helper: parse NSEC/NSEC3 type bitmaps
function parseTypeBitmap(bitmap: Uint8Array): string[] {
  const types: string[] = [];
  let pos = 0;
  while (pos + 2 <= bitmap.length) {
    const window = bitmap[pos++];
    const bitmapLen = bitmap[pos++];
    if (pos + bitmapLen > bitmap.length) break;
    for (let i = 0; i < bitmapLen; i++) {
      const byte = bitmap[pos + i];
      for (let bit = 0; bit < 8; bit++) {
        if (byte & (0x80 >> bit)) {
          const typeNum = window * 256 + i * 8 + bit;
          types.push(getRecordTypeName(typeNum));
        }
      }
    }
    pos += bitmapLen;
  }
  return types;
}

// Helper: base32hex encoding (RFC 4648) for NSEC3 hashes
function base32hexEncode(data: Uint8Array): string {
  const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
  let result = '';
  let bits = 0;
  let value = 0;
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += alphabet[(value >> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    result += alphabet[(value << (5 - bits)) & 0x1f];
  }
  return result;
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
      case 39:                                                   // DNAME
        return decodeName(fullMsg, rdataOffset).name + '.';
      case 15:  return formatMX(rdata, fullMsg, rdataOffset);    // MX
      case 16:  return formatTXT(rdata);                         // TXT
      case 99:  return formatTXT(rdata);                         // SPF (same wire format as TXT)
      case 6:   return formatSOA(fullMsg, rdataOffset);          // SOA
      case 33:  return formatSRV(rdata, fullMsg, rdataOffset);   // SRV
      case 257: return formatCAA(rdata);                         // CAA
      case 43:  return formatDS(rdata);                          // DS
      case 59:  return formatDS(rdata);                          // CDS (same format as DS)
      case 48:  return formatDNSKEY(rdata);                      // DNSKEY
      case 60:  return formatDNSKEY(rdata);                      // CDNSKEY (same format as DNSKEY)
      case 35:  return formatNAPTR(rdata, fullMsg, rdataOffset); // NAPTR
      case 52:  return formatTLSA(rdata);                        // TLSA
      case 53:  return formatTLSA(rdata);                        // SMIMEA (same format as TLSA)
      case 44:  return formatSSHFP(rdata);                       // SSHFP
      case 13:  return formatHINFO(rdata);                       // HINFO
      case 29:  return formatLOC(rdata);                         // LOC
      case 17:  return formatRP(rdata, fullMsg, rdataOffset);    // RP
      case 64:  return formatSVCB(rdata, fullMsg, rdataOffset);  // SVCB
      case 65:  return formatSVCB(rdata, fullMsg, rdataOffset);  // HTTPS (same wire format as SVCB)
      case 46:  return formatRRSIG(rdata, fullMsg, rdataOffset); // RRSIG
      case 47:  return formatNSEC(rdata, fullMsg, rdataOffset);  // NSEC
      case 50:  return formatNSEC3(rdata);                       // NSEC3
      case 51:  return formatNSEC3PARAM(rdata);                  // NSEC3PARAM
      case 256: return formatURI(rdata);                         // URI
      case 18:  return formatAFSDB(rdata, fullMsg, rdataOffset); // AFSDB
      case 36:  return formatKX(rdata, fullMsg, rdataOffset);    // KX
      case 37:  return formatCERT(rdata);                        // CERT
      case 25:  return formatDNSKEY(rdata);                      // KEY (legacy, same wire format)
      case 24:  return formatRRSIG(rdata, fullMsg, rdataOffset); // SIG (legacy, same wire format)
      case 32769: return formatDS(rdata);                        // DLV (same format as DS)
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
export function parseDNSResponse(buf: Uint8Array, elapsed: number, requestedType?: number): WireResponse {
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

    // Skip OPT (type 41) always — it's an EDNS pseudo-RR, not a real record.
    // Skip RRSIG (type 46) unless it was explicitly requested — otherwise it clutters results.
    if (rrType === 41 || (rrType === 46 && requestedType !== 46)) {
      offset += rdlength;
      continue;
    }

    answers.push({
      type: getRecordTypeName(rrType),
      name: name.replace(/\.$/, ''),
      TTL: ttl,
      data: rdataStr,
    });

    offset += rdlength;
  }

  return {
    answers,
    rcode,
    flags: { aa, ad },
    query_time_ms: Math.round(elapsed),
  };
}
