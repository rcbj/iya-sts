'use strict';
//
// File: krb5_keytab.js
//
// ---------------------------------------------------------------------------
// THE MIT KEYTAB FILE FORMAT, VERSION 0x502 — A WRITER AND A READER (2026-09-12).
//
// A keytab is how a real Kerberos service holds its long-term key: the service
// never types a password, it reads a file of (principal, kvno, enctype, key)
// entries and tries the one a ticket names. `/admin/kerberos/principals` and
// `POST /admin-api/kerberos/principals/{create-service,rotate-service}` mint a
// RANDOM key for a service principal and hand it over in this format, once,
// so that a real acceptor — Apache's mod_auth_gssapi, a Java service, `kinit
// -k` — can accept tickets this KDC issues for that principal.
//
// **THIS REPOSITORY HAD NO KEYTAB CODE AT ALL**, reader or writer, before this
// file: the acceptor in `krb5_service.js` keys itself from a PASSWORD and a
// salt (`krb5.servicePassword`, `krb5.serviceSalt`), which is what a mock needs
// and not what a deployment hands a service. So there was nothing to reuse and
// nothing to round-trip against, and the in-process test carries an
// INDEPENDENT reader of its own for exactly that reason — a writer checked only
// by the reader beside it is an implementation agreeing with itself.
//
// THE FORMAT, as MIT's `src/lib/krb5/keytab/kt_file.c` writes it and as
// Heimdal and Java's `KeyTab` read it. Everything is BIG-ENDIAN in version
// 0x502 (0x501 was host order and is not written by anything current):
//
//     uint16  0x0502
//     then, repeated to end of file:
//       int32   size of the entry that follows (a NEGATIVE size is a hole —
//               a deleted entry — whose |size| bytes are skipped)
//       uint16  number of name components
//       data    realm              (uint16 length, then the bytes)
//       data    component * count  (uint16 length, then the bytes)
//       uint32  name type          (KRB5_NT_PRINCIPAL = 1, what ktadd writes)
//       uint32  timestamp          (seconds since the epoch)
//       uint8   kvno, modulo 256
//       uint16  enctype
//       data    key                (uint16 length, then the key bytes)
//       uint32  kvno               (OPTIONAL: present when the entry has four
//                                   more bytes, and then it wins over the
//                                   8-bit one — which is how a kvno above 255
//                                   survives)
//
// **A LIBRARY (rule 3).** It registers no route, holds no state and requires
// only the logger — so its position in the require order is not a position,
// and it can never join a cycle. It is NOT reachable from `krb5_kdc.js`,
// `krb5_service.js` or `spnego.js`, which is what keeps the parent project's
// COPY set unchanged (see `kerberos/CLAUDE.md`).
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');

const KEYTAB_VERSION = 0x0502;

// KRB5_NT_PRINCIPAL. `ktadd` writes it for a service principal as well as a
// user, so it is what an MIT-reading acceptor expects to find; a reader
// matches on the name components and the realm, not on this number.
const NAME_TYPE_PRINCIPAL = 1;

// The largest counted string the format can carry.
const MAX_DATA = 0xffff;

function asBytes(value) {
  if (value instanceof Uint8Array) {
    return value;
  }
  return Buffer.from(String(value == null ? '' : value), 'utf8');
}

// One counted string: a 16-bit length, then the bytes.
function counted(value) {
  const bytes = asBytes(value);
  if (bytes.length > MAX_DATA) {
    throw new Error('krb5_keytab: a field of ' + bytes.length + ' bytes does ' +
                    'not fit a keytab\'s 16-bit length');
  }
  const out = Buffer.alloc(2 + bytes.length);
  out.writeUInt16BE(bytes.length, 0);
  Buffer.from(bytes).copy(out, 2);
  return out;
}

// ---------------------------------------------------------------------------
// WRITE. `entries` is a list of
//   { realm, components: ['HTTP', 'web.example.com'], nameType, timestamp,
//     kvno, etype, key: Uint8Array }
// and the answer is a Buffer holding the whole file. An entry that cannot be
// encoded THROWS rather than being dropped: a keytab missing one enctype reads
// perfectly and then refuses exactly the tickets that were issued under it.
// ---------------------------------------------------------------------------
function writeKeytab(entries) {
  log.debug('Entering writeKeytab(). entries=' + (entries || []).length);
  const parts = [];
  const header = Buffer.alloc(2);
  header.writeUInt16BE(KEYTAB_VERSION, 0);
  parts.push(header);
  (entries || []).forEach(function (entry, index) {
    const components = (entry.components || []).map(String);
    if (!components.length || components.some(function (c) { return !c; })) {
      throw new Error('krb5_keytab: entry ' + index + ' names no principal');
    }
    const key = asBytes(entry.key);
    if (!key.length) {
      throw new Error('krb5_keytab: entry ' + index + ' carries no key');
    }
    const kvno = Number(entry.kvno);
    if (!Number.isInteger(kvno) || kvno < 0 || kvno > 0xffffffff) {
      throw new Error('krb5_keytab: entry ' + index + ' has kvno ' + entry.kvno);
    }
    const stamp = entry.timestamp instanceof Date
      ? Math.floor(entry.timestamp.getTime() / 1000)
      : Math.floor(Number(entry.timestamp || Date.now() / 1000));
    const fixed = Buffer.alloc(2);
    fixed.writeUInt16BE(components.length, 0);
    const body = [fixed, counted(entry.realm)];
    components.forEach(function (c) { body.push(counted(c)); });
    const middle = Buffer.alloc(4 + 4 + 1 + 2);
    middle.writeUInt32BE((entry.nameType == null ? NAME_TYPE_PRINCIPAL
                                                 : Number(entry.nameType)) >>> 0, 0);
    middle.writeUInt32BE(stamp >>> 0, 4);
    middle.writeUInt8(kvno & 0xff, 8);
    middle.writeUInt16BE(Number(entry.etype) & 0xffff, 9);
    body.push(middle, counted(key));
    // The 32-bit kvno is always written. MIT writes it whenever the kvno does
    // not fit in the byte and readers take it whenever it is there, so writing
    // it always is what makes kvno 256 and kvno 0 two different keys.
    const wide = Buffer.alloc(4);
    wide.writeUInt32BE(kvno >>> 0, 0);
    body.push(wide);
    const bytes = Buffer.concat(body);
    const size = Buffer.alloc(4);
    size.writeInt32BE(bytes.length, 0);
    parts.push(size, bytes);
  });
  const out = Buffer.concat(parts);
  log.debug('Leaving writeKeytab(). ' + out.length + ' bytes.');
  return out;
}

// ---------------------------------------------------------------------------
// READ. The inverse, and it REFUSES what it cannot read rather than returning
// the entries before the damage: a keytab that parses half-way is a service
// that holds some of its keys, which fails later and names a ticket.
// ---------------------------------------------------------------------------
function readKeytab(bytes) {
  log.debug('Entering readKeytab().');
  const buf = Buffer.from(asBytes(bytes));
  if (buf.length < 2 || buf.readUInt16BE(0) !== KEYTAB_VERSION) {
    log.debug('Leaving readKeytab(). Not a version 0x502 keytab.');
    throw new Error('krb5_keytab: not a version 0x502 keytab');
  }
  const entries = [];
  let at = 2;
  function need(n) {
    if (at + n > buf.length) {
      throw new Error('krb5_keytab: truncated at byte ' + at);
    }
  }
  function data(end) {
    need(2);
    const len = buf.readUInt16BE(at);
    at += 2;
    if (at + len > end) {
      throw new Error('krb5_keytab: a field runs past its entry at byte ' + at);
    }
    const out = buf.subarray(at, at + len);
    at += len;
    return out;
  }
  while (at < buf.length) {
    need(4);
    const size = buf.readInt32BE(at);
    at += 4;
    if (size < 0) {
      need(-size);
      at += -size;
      continue;
    }
    need(size);
    const end = at + size;
    const count = buf.readUInt16BE(at);
    at += 2;
    const realm = data(end).toString('utf8');
    const components = [];
    for (let i = 0; i < count; i++) {
      components.push(data(end).toString('utf8'));
    }
    if (at + 11 > end) {
      throw new Error('krb5_keytab: an entry ends before its key');
    }
    const nameType = buf.readUInt32BE(at);
    const timestamp = buf.readUInt32BE(at + 4);
    let kvno = buf.readUInt8(at + 8);
    const etype = buf.readUInt16BE(at + 9);
    at += 11;
    const key = Uint8Array.from(data(end));
    if (end - at >= 4) {
      kvno = buf.readUInt32BE(at);
    }
    at = end;
    entries.push({ realm: realm, components: components, nameType: nameType,
                   timestamp: timestamp, kvno: kvno, etype: etype, key: key });
  }
  log.debug('Leaving readKeytab(). ' + entries.length + ' entr' +
            (entries.length === 1 ? 'y' : 'ies') + '.');
  return entries;
}

module.exports = {
  KEYTAB_VERSION: KEYTAB_VERSION,
  NAME_TYPE_PRINCIPAL: NAME_TYPE_PRINCIPAL,
  writeKeytab: writeKeytab,
  readKeytab: readKeytab
};
