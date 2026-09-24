'use strict';
//
// File: oidfed_store.ts
//
// ===========================================================================
// THE OPENID FEDERATION REGISTER, IN THE DIRECTORY (#132, #133, 2026-09-23).
//
// Everything a realm KNOWS as a federation entity is an entry under
// `ou=oidfed` in its own directory tree (`ldap/ldap_server.js`): one class,
// `stsOidfedEntry`, whose `stsOidfedKind` says what the entry is and whose
// `stsOidfedData` holds its record as one JSON value.
//
//   kind           cn                what it records
//   ------------   ---------------   ----------------------------------------
//   keys           keys              the Federation Entity Key table
//                                    (`stsOidfedKeys`, one row per value,
//                                    private keys sealed; federation_keys.ts)
//   subordinate    sub-<digest>      an entity this realm vouches for: its
//                                    keys, and the metadata, policy and
//                                    constraints its statement carries
//   anchor         ta-<digest>       a Trust Anchor this realm trusts, with
//                                    its keys pinned
//   mark-type      mt-<digest>       a Trust Mark type this realm issues
//   issued-mark    im-<digest>       a Trust Mark this realm issued, and
//                                    whether it was revoked
//   held-mark      hm-<digest>       a Trust Mark issued TO this realm, which
//                                    its Entity Configuration carries
//   mark-policy    mp-<digest>       as a Trust Anchor: who may issue marks of
//                                    a type, and who owns it (3.1.2's
//                                    trust_mark_issuers, trust_mark_owners)
//   events         ev-<digest>       a subordinate's event history (#137),
//                                    one JSON event per `stsOidfedEvent`
//                                    value — kept after the subordinate is
//                                    gone (subordinate_events.ts)
//   suspension     su-<digest>       a subordinate suspended (#137): no
//                                    Subordinate Statement is issued about
//                                    it until it is reinstated
//   collection     collection        the realm's Entity Collection (#136),
//                                    as its last crawl found it
//                                    (entity_collection.ts)
//
// An `events` or `suspension` entry is keyed by the subordinate's KEY rather
// than always its Entity Identifier: a registered subordinate's key IS its
// Entity Identifier, but a realm of this service beneath the default realm
// is keyed `realm:<id>`, because its identifier depends on the host a
// request arrived on and a background job has no request
// (`subordinate_events.ts`).
//
// **WHY THE DIRECTORY AND NOT A STORE OF ITS OWN.** It is the one store every
// backend persists and every node of a cluster shares (the change log), and
// these are REGISTERS — what this realm vouches for and trusts — which is
// what the directory is for here (`ou=applications`, `ou=federations`). A
// realm's register lives in the realm's own tree, so realms are separated
// the way their applications are.
//
// The `<digest>` is SHA-256 of the entity identifier (or type, or JWT) in
// hex, cut to 32 characters: an Entity Identifier is a URL, which is a poor
// RDN value, and the digest makes the name of an entry a function of what it
// is about — a second write about the same entity replaces the first.
//
// A LIBRARY OF STATIC METHODS: it holds nothing in memory, so there is
// nothing for the composition root to build. It reaches the directory
// through `credentials.oidfedStore()`, which answers empty where no directory
// is loaded. Every call is AMBIENT-REALM: the caller has entered the realm.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import credentials = require('../common/credentials');

type Json = any;

const log = helpers.log;

const KINDS = Object.freeze({
  KEYS: 'keys',
  SUBORDINATE: 'subordinate',
  ANCHOR: 'anchor',
  MARK_TYPE: 'mark-type',
  ISSUED_MARK: 'issued-mark',
  HELD_MARK: 'held-mark',
  MARK_POLICY: 'mark-policy',
  EVENTS: 'events',
  SUSPENSION: 'suspension',
  COLLECTION: 'collection'
});

const PREFIX: Record<string, string> = {
  'subordinate': 'sub-', 'anchor': 'ta-', 'mark-type': 'mt-',
  'issued-mark': 'im-', 'held-mark': 'hm-', 'mark-policy': 'mp-',
  'events': 'ev-', 'suspension': 'su-'
};

interface Entry {
  cn: string;
  kind: string;
  entityId: string;
  data: Json;
  createdAt: number;
  updatedAt: number;
}

class OidfedStore {
  static readonly KINDS = KINDS;

  // The digest an entry is named by.
  static digest(value: string): string {
    log.debug("Entering OidfedStore.digest().");
    const out = nodeCrypto.createHash('sha256').update(String(value), 'utf8')
      .digest('hex').slice(0, 32);
    log.debug("Leaving OidfedStore.digest().");
    return out;
  }

  // The `cn` of the entry of `kind` about `key`.
  static cnOf(kind: string, key: string): string {
    log.debug("Entering OidfedStore.cnOf(). " + kind);
    log.debug("Leaving OidfedStore.cnOf().");
    if (kind === KINDS.KEYS || kind === KINDS.COLLECTION) {
      return kind;
    }
    return (PREFIX[kind] || 'x-') + OidfedStore.digest(key);
  }

  // A generalized time ("20260923120000Z" or with a fraction) as epoch ms;
  // 0 when there is none.
  static timeOf(values: Json): number {
    log.debug("Entering OidfedStore.timeOf().");
    const raw = String((Array.isArray(values) ? values[0] : values) || '');
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(raw);
    const out = m ? Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]),
                             Number(m[4]), Number(m[5]), Number(m[6])) : 0;
    log.debug("Leaving OidfedStore.timeOf().");
    return out;
  }

  private static read(stored: Json): Entry | null {
    log.debug("Entering OidfedStore.read().");
    const a = stored.attributes || {};
    const first = function (name: string): string {
      log.debug("Entering first(). " + name);
      log.debug("Leaving first().");
      return String((a[name] || [])[0] || '');
    };
    let data: Json = null;
    try {
      data = JSON.parse(first('stsoidfeddata') || 'null');
    } catch (e: any) {
      log.debug("Caught in OidfedStore.read(): " + ((e && e.message) || e));
      data = null;
    }
    const cn = (/^cn=([^,]+),/i.exec(String(stored.dn)) || [])[1] || '';
    log.debug("Leaving OidfedStore.read().");
    return { cn: cn, kind: first('stsoidfedkind'),
             entityId: first('stsoidfedentityid'), data: data,
             createdAt: OidfedStore.timeOf(a.createtimestamp),
             updatedAt: OidfedStore.timeOf(a.modifytimestamp) };
  }

  // Every entry of `kind` in the ambient realm, oldest first.
  static entries(kind: string): Entry[] {
    log.debug("Entering OidfedStore.entries(). " + kind);
    const all = credentials.oidfedStore('listOidfedEntries', []) || [];
    const out: Entry[] = [];
    all.forEach(function (stored: Json): void {
      const entry = OidfedStore.read(stored);
      if (entry && entry.kind === kind && kind !== KINDS.KEYS) {
        out.push(entry);
      }
    });
    out.sort(function (a: Entry, b: Entry): number {
      return a.createdAt - b.createdAt || (a.cn < b.cn ? -1 : 1);
    });
    log.debug("Leaving OidfedStore.entries(). " + out.length);
    return out;
  }

  // The entry of `kind` about `key`, or null.
  static get(kind: string, key: string): Entry | null {
    log.debug("Entering OidfedStore.get(). " + kind);
    const cn = OidfedStore.cnOf(kind, key);
    const hit = OidfedStore.entries(kind).filter(function (e: Entry) {
      return e.cn.toLowerCase() === cn.toLowerCase();
    })[0] || null;
    log.debug("Leaving OidfedStore.get(). " + !!hit);
    return hit;
  }

  // Write the entry of `kind` about `key` — created, or replaced whole.
  static put(kind: string, key: string, entityId: string,
             data: Json): boolean {
    log.debug("Entering OidfedStore.put(). " + kind);
    const cn = OidfedStore.cnOf(kind, key);
    const attributes: Json = {
      objectClass: ['top', 'stsOidfedEntry'],
      cn: cn,
      stsOidfedKind: kind,
      stsOidfedData: JSON.stringify(data)
    };
    if (entityId) {
      attributes.stsOidfedEntityId = entityId;
    }
    const ok = !!credentials.oidfedStore('writeOidfedEntry', [cn, attributes]);
    log.debug("Leaving OidfedStore.put(). " + ok);
    return ok;
  }

  static remove(kind: string, key: string): boolean {
    log.debug("Entering OidfedStore.remove(). " + kind);
    const ok = !!credentials.oidfedStore('deleteOidfedEntry',
                                         [OidfedStore.cnOf(kind, key)]);
    log.debug("Leaving OidfedStore.remove(). " + ok);
    return ok;
  }

  // -------------------------------------------------------------------------
  // THE KEY TABLE: the rows of the realm's one `keys` entry, each a JSON
  // value of `stsOidfedKeys` — one row per value, so the directory's own
  // redaction of a key table's private keys (`withheldKeyTableValues()`)
  // applies to it row by row, as it does to a federation relationship's.
  // -------------------------------------------------------------------------
  static keyRows(): Json[] {
    log.debug("Entering OidfedStore.keyRows().");
    const all = credentials.oidfedStore('listOidfedEntries', []) || [];
    const entry = all.filter(function (stored: Json): boolean {
      return String(((stored.attributes || {}).stsoidfedkind || [])[0]) ===
             KINDS.KEYS;
    })[0];
    const rows: Json[] = [];
    ((entry && entry.attributes.stsoidfedkeys) || []).forEach(function (v) {
      try {
        rows.push(JSON.parse(String(v)));
      } catch (e: any) {
        log.debug("Caught in OidfedStore.keyRows(): " +
                  ((e && e.message) || e));
      }
    });
    log.debug("Leaving OidfedStore.keyRows(). " + rows.length);
    return rows;
  }

  // -------------------------------------------------------------------------
  // AN EVENT LOG (#137): the values of the `events` entry about `key`, each
  // one JSON event as `subordinate_events.ts` wrote it. A value is appended
  // and never replaced, and `stsOidfedEvent` is merged BY VALUE when two
  // nodes write one entry (`persistence/directory_merge.js`, MULTI), so two
  // events recorded at once on two nodes are both kept.
  // -------------------------------------------------------------------------
  private static rawEntry(cn: string): Json {
    log.debug("Entering OidfedStore.rawEntry(). " + cn);
    const all = credentials.oidfedStore('listOidfedEntries', []) || [];
    const hit = all.filter(function (stored: Json): boolean {
      const got = (/^cn=([^,]+),/i.exec(String(stored.dn)) || [])[1] || '';
      return got.toLowerCase() === cn.toLowerCase();
    })[0] || null;
    log.debug("Leaving OidfedStore.rawEntry(). " + !!hit);
    return hit;
  }

  static eventValues(key: string): string[] {
    log.debug("Entering OidfedStore.eventValues().");
    const stored = OidfedStore.rawEntry(OidfedStore.cnOf(KINDS.EVENTS, key));
    const out = ((stored && stored.attributes.stsoidfedevent) || [])
      .map(String);
    log.debug("Leaving OidfedStore.eventValues(). " + out.length);
    return out;
  }

  static appendEvent(key: string, entityId: string, value: string): boolean {
    log.debug("Entering OidfedStore.appendEvent().");
    const values = OidfedStore.eventValues(key);
    if (values.indexOf(value) < 0) {
      values.push(value);
    }
    const cn = OidfedStore.cnOf(KINDS.EVENTS, key);
    const attributes: Json = {
      objectClass: ['top', 'stsOidfedEntry'],
      cn: cn,
      stsOidfedKind: KINDS.EVENTS,
      stsOidfedData: JSON.stringify({ key: key }),
      stsOidfedEvent: values
    };
    if (entityId) {
      attributes.stsOidfedEntityId = entityId;
    }
    const ok = !!credentials.oidfedStore('writeOidfedEntry', [cn, attributes]);
    log.debug("Leaving OidfedStore.appendEvent(). " + ok);
    return ok;
  }

  static writeKeyRows(rows: Json[]): boolean {
    log.debug("Entering OidfedStore.writeKeyRows(). " + rows.length);
    const attributes: Json = {
      objectClass: ['top', 'stsOidfedEntry'],
      cn: 'keys',
      stsOidfedKind: KINDS.KEYS,
      stsOidfedData: JSON.stringify({ rows: rows.length })
    };
    if (rows.length) {
      attributes.stsOidfedKeys = rows.map(function (row: Json): string {
        return JSON.stringify(row);
      });
    }
    const ok = !!credentials.oidfedStore('writeOidfedEntry',
                                         ['keys', attributes]);
    log.debug("Leaving OidfedStore.writeKeyRows(). " + ok);
    return ok;
  }
}

export = OidfedStore;
