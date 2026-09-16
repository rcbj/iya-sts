'use strict';
//
// File: krb5_keytab.ts
//
// ---------------------------------------------------------------------------
// THE MIT KEYTAB FILE FORMAT, VERSION 0x502 — A WRITER AND A READER
// (2026-09-12).
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
// file: the acceptor in `krb5_service.js` keyed itself from a PASSWORD and a
// salt (`krb5.servicePassword`, `krb5.serviceSalt`), which is what a mock needs
// and not what a deployment hands a service. It still does, unless a key has
// been stored for its SPN. So there was nothing to reuse and
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

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `Krb5Keytab` takes the logger through its constructor, the two
// counted-string helpers and the reader's two cursor steps are private static
// methods, and the module still exports `KEYTAB_VERSION`,
// `NAME_TYPE_PRINCIPAL`, `writeKeytab` and `readKeytab` from a TRANSITIONAL
// instance for `krb5_person_keys.ts` and the tests. It goes when the
// composition root exists; `Krb5Keytab` is exported beside it for that root.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');

interface Krb5KeytabDeps {
  log: { debug(message: string): void };
}

// One entry as the writer takes it and the reader answers it. The writer
// accepts a Date or a number of seconds for `timestamp`, and a string for
// `key` (as UTF-8); the reader answers numbers and bytes.
interface KeytabEntry {
  realm?: unknown;
  components?: unknown[];
  nameType?: number | null;
  timestamp?: Date | number | null;
  kvno?: number | string;
  etype?: number | string;
  key?: Uint8Array | string | null;
}

interface ReadEntry {
  realm: string;
  components: string[];
  nameType: number;
  timestamp: number;
  kvno: number;
  etype: number;
  key: Uint8Array;
}

// The reader's position in the file, shared by its two steps.
interface Cursor {
  at: number;
}

class Krb5Keytab {
  static readonly KEYTAB_VERSION = 0x0502;

  // KRB5_NT_PRINCIPAL. `ktadd` writes it for a service principal as well as a
  // user, so it is what an MIT-reading acceptor expects to find; a reader
  // matches on the name components and the realm, not on this number.
  static readonly NAME_TYPE_PRINCIPAL = 1;

  // The largest counted string the format can carry.
  static readonly MAX_DATA = 0xffff;

  constructor(private readonly deps: Krb5KeytabDeps) {
    deps.log.debug("Entering Krb5Keytab.constructor().");
    deps.log.debug("Leaving Krb5Keytab.constructor().");
  }

  private asBytes(value: unknown): Uint8Array {
    const { log } = this.deps;
    log.debug("Entering Krb5Keytab.asBytes().");
    if (value instanceof Uint8Array) {
      log.debug("Leaving Krb5Keytab.asBytes().");
      return value;
    }
    log.debug("Leaving Krb5Keytab.asBytes().");
    return Buffer.from(String(value == null ? '' : value), 'utf8');
  }

  // One counted string: a 16-bit length, then the bytes.
  private counted(value: unknown): Buffer {
    const { log } = this.deps;
    log.debug("Entering Krb5Keytab.counted().");
    const bytes = this.asBytes(value);
    if (bytes.length > Krb5Keytab.MAX_DATA) {
      log.debug("Leaving Krb5Keytab.counted(). Too long.");
      throw new Error('krb5_keytab: a field of ' + bytes.length + ' bytes ' +
                      'does not fit a keytab\'s 16-bit length');
    }
    const out = Buffer.alloc(2 + bytes.length);
    out.writeUInt16BE(bytes.length, 0);
    Buffer.from(bytes).copy(out, 2);
    log.debug("Leaving Krb5Keytab.counted().");
    return out;
  }

  // -------------------------------------------------------------------------
  // WRITE. `entries` is a list of
  //   { realm, components: ['HTTP', 'web.example.com'], nameType, timestamp,
  //     kvno, etype, key: Uint8Array }
  // and the answer is a Buffer holding the whole file. An entry that cannot be
  // encoded THROWS rather than being dropped: a keytab missing one enctype
  // reads perfectly and then refuses exactly the tickets that were issued
  // under it.
  // -------------------------------------------------------------------------
  writeKeytab(entries: KeytabEntry[] | null | undefined): Buffer {
    const self = this;
    const { log } = this.deps;
    log.debug('Entering Krb5Keytab.writeKeytab(). entries=' +
              (entries || []).length);
    const parts: Buffer[] = [];
    const header = Buffer.alloc(2);
    header.writeUInt16BE(Krb5Keytab.KEYTAB_VERSION, 0);
    parts.push(header);
    (entries || []).forEach(function (entry, index) {
      const components = (entry.components || []).map(String);
      if (!components.length || components.some(function (c) {
        return !c;
      })) {
        log.debug('Leaving Krb5Keytab.writeKeytab(). No principal.');
        throw new Error('krb5_keytab: entry ' + index + ' names no principal');
      }
      const key = self.asBytes(entry.key);
      if (!key.length) {
        log.debug('Leaving Krb5Keytab.writeKeytab(). No key.');
        throw new Error('krb5_keytab: entry ' + index + ' carries no key');
      }
      const kvno = Number(entry.kvno);
      if (!Number.isInteger(kvno) || kvno < 0 || kvno > 0xffffffff) {
        log.debug('Leaving Krb5Keytab.writeKeytab(). Bad kvno.');
        throw new Error('krb5_keytab: entry ' + index + ' has kvno ' +
                        entry.kvno);
      }
      const stamp = entry.timestamp instanceof Date
        ? Math.floor(entry.timestamp.getTime() / 1000)
        : Math.floor(Number(entry.timestamp || Date.now() / 1000));
      const fixed = Buffer.alloc(2);
      fixed.writeUInt16BE(components.length, 0);
      const body: Buffer[] = [fixed, self.counted(entry.realm)];
      components.forEach(function (c) {
        body.push(self.counted(c));
      });
      const middle = Buffer.alloc(4 + 4 + 1 + 2);
      middle.writeUInt32BE((entry.nameType == null
        ? Krb5Keytab.NAME_TYPE_PRINCIPAL
        : Number(entry.nameType)) >>> 0, 0);
      middle.writeUInt32BE(stamp >>> 0, 4);
      middle.writeUInt8(kvno & 0xff, 8);
      middle.writeUInt16BE(Number(entry.etype) & 0xffff, 9);
      body.push(middle, self.counted(key));
      // The 32-bit kvno is always written. MIT writes it whenever the kvno
      // does not fit in the byte and readers take it whenever it is there, so
      // writing it always is what makes kvno 256 and kvno 0 two different
      // keys.
      const wide = Buffer.alloc(4);
      wide.writeUInt32BE(kvno >>> 0, 0);
      body.push(wide);
      const bytes = Buffer.concat(body);
      const size = Buffer.alloc(4);
      size.writeInt32BE(bytes.length, 0);
      parts.push(size, bytes);
    });
    const out = Buffer.concat(parts);
    log.debug('Leaving Krb5Keytab.writeKeytab(). ' + out.length + ' bytes.');
    return out;
  }

  // The reader's bounds check: `n` more bytes must be in the file.
  private need(buf: Buffer, cursor: Cursor, n: number): void {
    const { log } = this.deps;
    log.debug("Entering Krb5Keytab.need().");
    if (cursor.at + n > buf.length) {
      log.debug("Leaving Krb5Keytab.need(). Truncated.");
      throw new Error('krb5_keytab: truncated at byte ' + cursor.at);
    }
    log.debug("Leaving Krb5Keytab.need().");
  }

  // One counted string, which must end inside its entry (`end`).
  private data(buf: Buffer, cursor: Cursor, end: number): Buffer {
    const { log } = this.deps;
    log.debug("Entering Krb5Keytab.data().");
    this.need(buf, cursor, 2);
    const len = buf.readUInt16BE(cursor.at);
    cursor.at += 2;
    if (cursor.at + len > end) {
      log.debug("Leaving Krb5Keytab.data(). Past its entry.");
      throw new Error('krb5_keytab: a field runs past its entry at byte ' +
                      cursor.at);
    }
    const out = buf.subarray(cursor.at, cursor.at + len);
    cursor.at += len;
    log.debug("Leaving Krb5Keytab.data().");
    return out;
  }

  // -------------------------------------------------------------------------
  // READ. The inverse, and it REFUSES what it cannot read rather than
  // returning the entries before the damage: a keytab that parses half-way is
  // a service that holds some of its keys, which fails later and names a
  // ticket.
  // -------------------------------------------------------------------------
  readKeytab(bytes: Uint8Array | string): ReadEntry[] {
    const { log } = this.deps;
    log.debug('Entering Krb5Keytab.readKeytab().');
    const buf = Buffer.from(this.asBytes(bytes));
    if (buf.length < 2 || buf.readUInt16BE(0) !== Krb5Keytab.KEYTAB_VERSION) {
      log.debug('Leaving Krb5Keytab.readKeytab(). Not a version 0x502 ' +
                'keytab.');
      throw new Error('krb5_keytab: not a version 0x502 keytab');
    }
    const entries: ReadEntry[] = [];
    const cursor: Cursor = { at: 2 };
    while (cursor.at < buf.length) {
      this.need(buf, cursor, 4);
      const size = buf.readInt32BE(cursor.at);
      cursor.at += 4;
      if (size < 0) {
        this.need(buf, cursor, -size);
        cursor.at += -size;
        continue;
      }
      this.need(buf, cursor, size);
      const end = cursor.at + size;
      const count = buf.readUInt16BE(cursor.at);
      cursor.at += 2;
      const realm = this.data(buf, cursor, end).toString('utf8');
      const components: string[] = [];
      for (let i = 0; i < count; i++) {
        components.push(this.data(buf, cursor, end).toString('utf8'));
      }
      if (cursor.at + 11 > end) {
        log.debug('Leaving Krb5Keytab.readKeytab(). Entry ends early.');
        throw new Error('krb5_keytab: an entry ends before its key');
      }
      const nameType = buf.readUInt32BE(cursor.at);
      const timestamp = buf.readUInt32BE(cursor.at + 4);
      let kvno = buf.readUInt8(cursor.at + 8);
      const etype = buf.readUInt16BE(cursor.at + 9);
      cursor.at += 11;
      const key = Uint8Array.from(this.data(buf, cursor, end));
      if (end - cursor.at >= 4) {
        kvno = buf.readUInt32BE(cursor.at);
      }
      cursor.at = end;
      entries.push({ realm: realm, components: components,
                     nameType: nameType, timestamp: timestamp, kvno: kvno,
                     etype: etype, key: key });
    }
    log.debug('Leaving Krb5Keytab.readKeytab(). ' + entries.length +
              ' entr' + (entries.length === 1 ? 'y' : 'ies') + '.');
    return entries;
  }
}

// THE TRANSITIONAL INSTANCE — see the header. Built from the real logger, as
// the composition root will build one.
const keytab = new Krb5Keytab({ log: helpers.log });

export = {
  Krb5Keytab: Krb5Keytab,
  KEYTAB_VERSION: Krb5Keytab.KEYTAB_VERSION,
  NAME_TYPE_PRINCIPAL: Krb5Keytab.NAME_TYPE_PRINCIPAL,
  writeKeytab: keytab.writeKeytab.bind(keytab) as Krb5Keytab['writeKeytab'],
  readKeytab: keytab.readKeytab.bind(keytab) as Krb5Keytab['readKeytab']
};
