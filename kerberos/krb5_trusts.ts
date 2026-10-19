// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: krb5_trusts.ts
//
// ===========================================================================
// KERBEROS TRUSTS AS FACTS: ONE DIRECTORY ENTRY PER PARTNER (#430 Phase 1,
// 2026-10-19).
//
// A cross-realm trust is not a flag. It is a SHARED KEY held by two KDCs —
// `krbtgt/B@A`, which A seals a referral in and B opens it with — and until
// this file the only one this service had was a development fixture built
// from four process-wide settings (`krb5.trustedRealm`, `krb5.trustPassword`,
// `krb5.trustedDomainSid`, `krb5.trustedKrbtgtPassword`), held by the default
// trust realm alone. Those four are retired with no shim (REPLACED_SETTINGS
// in common/config.js), and the trust is now a RECORD:
//
//   * **ONE ENTRY PER PARTNER under `ou=kerberosTrusts` in the realm's own
//     subtree** (`cn=<partner Kerberos realm>`), modelled on Active
//     Directory's trustedDomain object ([MS-ADTS] 6.1.6.7): `trustPartner`,
//     `flatName`, `securityIdentifier`, `trustDirection`, `trustAttributes`
//     and `trustType` are written beside the record so an `ldapsearch` reads
//     what an AD administrator expects. They are a MIRROR: the record itself
//     is `stsKrb5TrustData`, one JSON value, and the keys are
//     `stsKrb5TrustKeys`, sealed where keys persist and withheld from every
//     directory read (SECRET_ATTRIBUTES in ldap/ldap_server.js). Per realm,
//     persisted and replicated like every other entry there.
//   * **THE KEYS HELD, NOT A DIRECTION, ARE THE TRUTH.** The INCOMING key is
//     `krbtgt/<us>@<partner>` — this realm accepts the partner's tickets —
//     and the OUTGOING key is `krbtgt/<partner>@<us>` — this realm refers its
//     own people to the partner. `trustDirection` is derived from which are
//     held ([MS-ADTS] 6.1.6.7.12: 1 inbound, 2 outbound, 3 both), so the two
//     can never disagree. kerberos/CLAUDE.md (*DELEGATION ACROSS A TRUST*)
//     says why INBOUND reads as "the incoming key is held".
//   * **A KEY IS A SHARED PASSWORD OR A GENERATED KEY.** A password is kept
//     (sealed) and turned into keys by `krb5_principals.js`'s `longTermKey()`
//     when first used — RFC 3961 string-to-key with RFC 4120 section 4's
//     default salt for `krbtgt/B@A`, `AkrbtgtB` — which is what lets a
//     partner KDC that is not this one compute the same key with nothing but
//     the password. A generated key is random-to-key per enctype, shown once
//     by the act that made it and never again.
//   * **THE TYPE** is `external` (the partner's KDC is somewhere else) or
//     `trust-realm` (the partner is another trust realm in this process,
//     answering on the same port 88 for its own Kerberos realm). `pair()`
//     writes both records of a trust-realm pair in one act, mirrored.
//
// **TRUST REALMS MAY TRUST EACH OTHER'S KERBEROS NOW** (rcbj's decision 1 on
// #430), which reverses the rule kerberos/CLAUDE.md recorded on 2026-09-15 —
// but only through an explicit record on each side. Nothing is implied by two
// realms living in one process.
//
// WHAT THIS FILE DOES NOT DO: issue anything. It answers the KDC four
// questions — which partner a host's DNS suffix is routed to (`routeHost()`),
// the inter-realm principal for a `krbtgt/X@R` lookup (`trustPrincipal()`),
// whether a cross-realm path is acceptable (`pathProblem()`), and how
// `transited` is written and read (`encodeTransited()`, `decodeTransited()`).
// The KDC (`krb5_kdc.js`) and the principal database (`krb5_principals.js`)
// reach it LAZILY, so the parent project's in-process Kerberos jobs, which
// copy the closure of those two files, load it only when a cross-realm name
// is asked about — and owe a COPY line for it, compiled (kerberos/CLAUDE.md).
//
// THE DIRECTORY SLOT (rule 3e). `setDirectory()` is filled by
// `ldap/ldap_server.js` with three functions over `ou=kerberosTrusts`. A
// require from here to the directory would drag every `/admin/ldap/*` page
// ahead of the KDC's routes (the directory is a JavaScript route module at
// 21, the KDC at 15), and the directory's own require of this file closes
// the other way round; and the parent's closure would gain the whole
// directory for a feature its jobs do not drive. **WITHOUT A DIRECTORY** —
// an in-process test that never loads it, or the parent's jobs — the records
// live in a per-realm map of this process (`realms.map()`), seeded the same
// way on first read, so the development trust with PARTNER.COM still exists
// there.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import mode = require('../common/mode');
import errorCodes = require('../common/error_codes');
import stsCrypto = require('../common/crypto');
import cacheRegistry = require('../common/cache_registry');
import InstanceSlot = require('../common/instance_slot');
import kcrypto = require('./krb5_crypto');

// A stored record, a directory row, a view: JSON this file wrote.
type Json = any;

const log = helpers.log;

// The three functions `ldap/ldap_server.js` installs through setDirectory().
interface DirectoryHooks {
  listKerberosTrustEntries(): Json[];
  writeKerberosTrustEntry(cn: string, attributes: Json): boolean;
  deleteKerberosTrustEntry(cn: string): boolean;
}

interface Krb5TrustsDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  mode: typeof mode;
  errorCodes: typeof errorCodes;
  stsCrypto: typeof stsCrypto;
  kcrypto: Json;
  // LAZILY, both: the keystore (the seal), and the principal database (which
  // Kerberos realm a trust realm answers as). The principal database
  // requires THIS file lazily, so a require at load would be a cycle.
  keystore: () => Json;
  principals: () => Json;
}

// A refusal: the code it is recorded under and the sentence the caller sees.
interface Problem {
  code: string;
  message: string;
}

// ---------------------------------------------------------------------------
// THE ATTRIBUTES, AS NAMED BITS ([MS-ADTS] 6.1.6.7.9 `trustAttributes`).
// A closed set: a name not here is refused, and the console's checkboxes
// (Phase 4) are drawn from it. What each one changes is in
// kerberos/CLAUDE.md's table; two are honoured by this file now —
// `non-transitive` (`pathProblem()`) — and the rest are recorded for the
// phases that act on them (SID filtering, ok-as-delegate across a trust).
// ---------------------------------------------------------------------------
const ATTRIBUTE_BITS: Record<string, number> = {
  'non-transitive': 0x00000001,
  'quarantined': 0x00000004,
  'forest-transitive': 0x00000008,
  'cross-organization': 0x00000010,
  'within-forest': 0x00000020,
  'treat-as-external': 0x00000040,
  'no-tgt-delegation': 0x00000200,
  'enable-tgt-delegation': 0x00000800
};

// Pairs that cannot both be set, each with the reason a reader is given.
const CONTRADICTIONS: Array<[string, string, string]> = [
  ['no-tgt-delegation', 'enable-tgt-delegation',
   'a trust cannot both forbid and enable TGT delegation'],
  ['non-transitive', 'forest-transitive',
   'a forest trust is transitive by definition']
];

// SID filtering is ON by default (rcbj's decision 4 on #430): a record that
// names no attributes is quarantined.
const DEFAULT_ATTRIBUTES = ['quarantined'];

const TYPES = ['external', 'trust-realm'];

// The enctypes a trust key is made for when none are named: AES only. A
// trust that still holds an RC4 key is the configuration a hardened domain
// controller refuses, and the referral's enctype is negotiated against the
// TRUST, not the service asked for.
const DEFAULT_ENCTYPES = [18, 17];

// [MS-ADTS] 6.1.6.7.15 trustType: 2 an Active Directory domain (a PAC with
// a domain SID), 3 a non-Windows Kerberos realm.
const TRUST_TYPE_UPLEVEL = 2;
const TRUST_TYPE_MIT = 3;

// A trust password shorter than this is refused: it is the only secret
// between two KDCs, and a guessable one is every ticket the partner accepts.
const MIN_PASSWORD_LENGTH = 16;

// The most records one realm may hold. A bound on the register, and so on
// the cache below; a realm that trusts more partners than this is not a
// shape this service is built for.
const MAX_RECORDS = 256;

// What `keystore.seal()` counts the keys under, for `/admin/encryption`.
const SEAL_LABEL = 'kerberos-trust-keys';

// ---------------------------------------------------------------------------
// THE DEVELOPMENT FIXTURE: THE TRUST WITH PARTNER.COM, AS A RECORD.
//
// What the four retired settings built, now one record seeded into the
// DEFAULT realm's register in development mode only (`mode.seedsDemoData()`),
// with the same password and SID the settings shipped with. Its partner's own
// database — `krbtgt/PARTNER.COM@PARTNER.COM`, carol and `HTTP/app.partner.com`
// — stays a fixture of the default realm's KDC (`krb5_principals.js`, which
// owns the realm's name and SID, `DEV_PARTNER_REALM` and
// `DEV_PARTNER_DOMAIN_SID`), and in development that KDC answers as that realm
// too, so a referral can be walked without a second KDC. A seed, not a
// setting: deleting the record ends the trust, and nothing puts it back while
// the register's container exists.
// ---------------------------------------------------------------------------
const DEV_TRUST_PASSWORD = 'inter-realm-trust-password';

// A Kerberos realm name, as this service accepts one: the domain style RFC
// 4120 section 6.1 describes, which is every realm a krb5.conf names.
const REALM_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$/;
const SUFFIX_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/;
const NETBIOS_PATTERN = /^[A-Za-z0-9][A-Za-z0-9-]{0,14}$/;
const DOMAIN_SID_PATTERN = /^S-1-5-21-\d{1,10}-\d{1,10}-\d{1,10}$/;

// The bound on the inter-realm principals held built, per realm.
const MAX_CACHED_PRINCIPALS = 2 * MAX_RECORDS;

/**
 * The Kerberos trust register: one record per partner realm, under
 * `ou=kerberosTrusts`, and the four questions the KDC asks of it.
 */
class Krb5Trusts {
  /**
   * The attribute names and their [MS-ADTS] bits.
   */
  static readonly ATTRIBUTE_BITS = ATTRIBUTE_BITS;
  /**
   * The two kinds of partner.
   */
  static readonly TYPES = TYPES;
  /**
   * The keystore label the keys are sealed under.
   */
  static readonly SEAL_LABEL = SEAL_LABEL;
  /**
   * The shortest trust password accepted.
   */
  static readonly MIN_PASSWORD_LENGTH = MIN_PASSWORD_LENGTH;

  private directory: DirectoryHooks | null = null;
  // Records, per realm, when there is no directory: cn → { attributes }, and
  // the key '' once the realm has been seeded (the container's stand-in).
  private readonly memory = realms.map();
  // The inter-realm principals built from the records, per realm: key
  // `<direction>|krbtgt/X@R` → { stamp, principal }.
  private readonly built = realms.map();
  // Records that would not open, said once per realm and partner.
  private readonly unreadableLogged = new Set<string>();
  private readonly counter: Json;

  /**
   * Builds the register with no directory installed.
   *
   * @param deps - the logger, settings, realms, mode, error codes, crypto and
   *   the lazily-reached keystore and principal database
   */
  constructor(private readonly deps: Krb5TrustsDeps) {
    deps.log.debug("Entering Krb5Trusts.constructor().");
    const self = this;
    this.counter = cacheRegistry.register({
      name: 'krb5.trust-keys',
      title: 'Kerberos inter-realm trust keys',
      description: 'The inter-realm krbtgt principals built from this ' +
        'realm\'s trust records (ou=kerberosTrusts), each with the keys ' +
        'derived from its shared password or opened from its seal, held ' +
        'for every referral after the first.',
      owner: 'kerberos/krb5_trusts.ts',
      scope: 'realm',
      maxEntries: function (): number {
        return MAX_CACHED_PRINCIPALS;
      },
      bound: 'Enforced: at most ' + MAX_CACHED_PRINCIPALS + ' per realm ' +
        '(two keys for each of at most ' + MAX_RECORDS + ' records); the ' +
        'oldest is dropped and built again at its next use.',
      lifetime: function (): string {
        return 'No expiry: replaced the moment its record changes (the ' +
          'record\'s bytes are compared at every use), and dropped with ' +
          'the record; never persisted.';
      },
      entries: function (): Json[] {
        return cacheRegistry.realmRows(
          realms.list().map(function (r: Json): string {
            return r.id;
          }),
          function (id: string): Map<string, Json> {
            return self.built.realmMap(id);
          },
          function (value: Json, key: string): Json {
            return { key: key, validUntil: null,
                     basis: 'replaced when its record changes' };
          });
      }
    });
    deps.log.debug("Leaving Krb5Trusts.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the service's own modules
   */
  static defaultDeps(): Krb5TrustsDeps {
    log.debug("Entering Krb5Trusts.defaultDeps().");
    log.debug("Leaving Krb5Trusts.defaultDeps().");
    return {
      log: log, config: config, realms: realms, mode: mode,
      errorCodes: errorCodes, stsCrypto: stsCrypto, kcrypto: kcrypto,
      keystore: function (): Json {
        return require('../common/keystore');
      },
      principals: function (): Json {
        return require('./krb5_principals');
      }
    };
  }

  // =========================================================================
  // THE DIRECTORY SLOT.
  // =========================================================================
  /**
   * Installs the three directory functions the records are kept through;
   * filled by `ldap/ldap_server.js`. Validated whole: a filler that installs
   * a reader and no writer would leave a register that lists and cannot act.
   *
   * @param hooks - the directory's functions, or null to remove them
   * @returns whether they were installed
   */
  setDirectory(hooks: DirectoryHooks | null | undefined): boolean {
    const { log, errorCodes } = this.deps;
    log.debug('Entering Krb5Trusts.setDirectory().');
    if (!hooks) {
      this.directory = null;
      log.debug('Leaving Krb5Trusts.setDirectory(). Removed.');
      return true;
    }
    const needed = ['listKerberosTrustEntries', 'writeKerberosTrustEntry',
                    'deleteKerberosTrustEntry'];
    const missing = needed.filter(function (name: string): boolean {
      return typeof (hooks as Json)[name] !== 'function';
    });
    if (missing.length) {
      log.error(errorCodes.tag('STS-KRB-0225') + 'krb5: the Kerberos trust ' +
                'register was given a directory without ' +
                missing.join(', ') + ', so it was refused whole; the ' +
                'records stay in this process\'s memory.');
      log.debug('Leaving Krb5Trusts.setDirectory(). Refused.');
      return false;
    }
    this.directory = hooks;
    log.debug('Leaving Krb5Trusts.setDirectory(). Installed.');
    return true;
  }

  /**
   * Returns the installed directory functions, so a test can put back what
   * was there.
   *
   * @returns the hooks, or null
   */
  directoryInstalled(): DirectoryHooks | null {
    this.deps.log.debug("Entering Krb5Trusts.directoryInstalled().");
    this.deps.log.debug("Leaving Krb5Trusts.directoryInstalled().");
    return this.directory;
  }

  // =========================================================================
  // SEALING: `keystore.seal()` where keys outlive the process, and the value
  // as written where they do not — development's key-encryption key is made
  // at every start, so a sealed value would not open after a restart
  // (`oauth-oidc/claims_providers.ts` argues the same). Either way the
  // attribute is withheld from every directory read in product mode.
  // =========================================================================
  private seal(plain: string): string | null {
    const { log, keystore } = this.deps;
    log.debug("Entering Krb5Trusts.seal().");
    const ks = keystore();
    if (!ks.persists()) {
      log.debug("Leaving Krb5Trusts.seal(). Keys do not persist.");
      return plain;
    }
    const sealed = ks.seal(plain, SEAL_LABEL);
    log.debug("Leaving Krb5Trusts.seal(). " + (sealed ? 'Sealed.' :
                                                        'No key.'));
    return sealed || null;
  }

  private open(stored: string): string | null {
    const { log, keystore, stsCrypto } = this.deps;
    log.debug("Entering Krb5Trusts.open().");
    const text = String(stored || '');
    if (!stsCrypto.isEncryptedWithKek(text)) {
      log.debug("Leaving Krb5Trusts.open(). Not sealed.");
      return text;
    }
    const opened = keystore().open(text, SEAL_LABEL);
    log.debug("Leaving Krb5Trusts.open(). " + (opened !== null &&
                                              opened !== undefined ?
                                              'Opened.' : 'Unopenable.'));
    return opened === null || opened === undefined ? null : String(opened);
  }

  // =========================================================================
  // THE STORE: the directory where there is one, this process's memory where
  // there is not. Both answer the ambient realm.
  // =========================================================================
  private isDefaultRealm(): boolean {
    this.deps.log.debug("Entering Krb5Trusts.isDefaultRealm().");
    this.deps.log.debug("Leaving Krb5Trusts.isDefaultRealm().");
    return this.deps.realms.currentId() === this.deps.realms.DEFAULT_ID;
  }

  private rawEntries(): Json[] {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.rawEntries().");
    if (this.directory) {
      const rows = this.directory.listKerberosTrustEntries() || [];
      log.debug("Leaving Krb5Trusts.rawEntries(). " + rows.length +
                " from the directory.");
      return rows;
    }
    // WITHOUT A DIRECTORY: seeded on the first read in a realm, as the
    // directory's seed() does when it builds the realm's tree.
    if (!this.memory.has('')) {
      this.memory.set('', true);
      const self = this;
      this.seedEntries().forEach(function (entry: Json): void {
        self.memory.set(entry.cn, { attributes: entry.attributes });
      });
    }
    const out: Json[] = [];
    this.memory.forEach(function (value: Json, key: string): void {
      if (key !== '') {
        out.push({ dn: 'cn=' + key, attributes: value.attributes });
      }
    });
    log.debug("Leaving Krb5Trusts.rawEntries(). " + out.length +
              " from memory.");
    return out;
  }

  private writeEntry(cn: string, attributes: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.writeEntry(). cn=" + cn);
    if (this.directory) {
      const ok = this.directory.writeKerberosTrustEntry(cn, attributes);
      log.debug("Leaving Krb5Trusts.writeEntry(). " + (ok ? 'Written.' :
                                                      'Refused.'));
      return !!ok;
    }
    this.rawEntries();
    this.memory.set(cn, { attributes: attributes });
    log.debug("Leaving Krb5Trusts.writeEntry(). In memory.");
    return true;
  }

  private deleteEntry(cn: string): boolean {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.deleteEntry(). cn=" + cn);
    if (this.directory) {
      const ok = this.directory.deleteKerberosTrustEntry(cn);
      log.debug("Leaving Krb5Trusts.deleteEntry().");
      return !!ok;
    }
    this.rawEntries();
    const had = this.memory.has(cn);
    this.memory.delete(cn);
    log.debug("Leaving Krb5Trusts.deleteEntry().");
    return had;
  }

  // =========================================================================
  // THE ENTRY: the record as JSON, the keys sealed, and the trustedDomain
  // mirror an `ldapsearch` reads.
  // =========================================================================
  private attributeMask(names: string[]): number {
    this.deps.log.debug("Entering Krb5Trusts.attributeMask().");
    let mask = 0;
    (names || []).forEach(function (name: string): void {
      mask |= ATTRIBUTE_BITS[name] || 0;
    });
    this.deps.log.debug("Leaving Krb5Trusts.attributeMask().");
    return mask >>> 0;
  }

  private directionOf(record: Json): number {
    this.deps.log.debug("Entering Krb5Trusts.directionOf().");
    this.deps.log.debug("Leaving Krb5Trusts.directionOf().");
    return (record.incoming ? 1 : 0) | (record.outgoing ? 2 : 0);
  }

  private entryFor(record: Json, secrets: Json): Json | null {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.entryFor(). partner=" +
              record.partnerRealm);
    const sealed = this.seal(JSON.stringify(secrets));
    if (sealed === null) {
      log.debug("Leaving Krb5Trusts.entryFor(). Not sealed.");
      return null;
    }
    const attributes: Json = {
      objectClass: ['top', 'stsKrb5Trust'],
      cn: record.partnerRealm,
      trustPartner: record.partnerRealm.toLowerCase(),
      flatName: record.netbiosName,
      trustDirection: String(this.directionOf(record)),
      trustAttributes: String(this.attributeMask(record.attributes)),
      trustType: String(record.partnerSid ? TRUST_TYPE_UPLEVEL :
                                            TRUST_TYPE_MIT),
      stsKrb5TrustData: JSON.stringify(record),
      stsKrb5TrustKeys: sealed
    };
    if (record.partnerSid) {
      attributes.securityIdentifier = record.partnerSid;
    }
    log.debug("Leaving Krb5Trusts.entryFor().");
    return attributes;
  }

  private firstValue(attributes: Json, name: string): string {
    this.deps.log.debug("Entering Krb5Trusts.firstValue().");
    const found = attributes[name] !== undefined ? attributes[name] :
                  attributes[name.toLowerCase()];
    this.deps.log.debug("Leaving Krb5Trusts.firstValue().");
    return Array.isArray(found) ? String(found[0] === undefined ? '' :
                                         found[0])
                                : (found === undefined || found === null ?
                                   '' : String(found));
  }

  // The record and its opened secrets, or null for an entry that is not one
  // (said once per realm and partner, STS-KRB-0224). `stamp` is a digest of
  // the two stored values, so a cached principal is rebuilt the moment
  // either changes — by this file or by an ldapmodify.
  private readEntry(stored: Json): Json | null {
    const { log, errorCodes, stsCrypto, realms } = this.deps;
    log.debug("Entering Krb5Trusts.readEntry().");
    const attributes = (stored && stored.attributes) || {};
    const data = this.firstValue(attributes, 'stsKrb5TrustData');
    const keys = this.firstValue(attributes, 'stsKrb5TrustKeys');
    let record: Json = null;
    let secrets: Json = null;
    let why = '';
    try {
      record = JSON.parse(data);
    } catch (e: any) {
      log.debug("Caught in Krb5Trusts.readEntry(): " +
                ((e && e.message) || e));
      why = 'its stsKrb5TrustData is not JSON';
    }
    if (!why && (!record || !record.partnerRealm)) {
      why = 'its stsKrb5TrustData names no partner realm';
    }
    if (!why) {
      const opened = this.open(keys);
      if (opened === null) {
        why = 'its keys are sealed under a key-encryption key this ' +
              'process does not hold';
      } else {
        try {
          secrets = JSON.parse(opened || '{}');
        } catch (e: any) {
          log.debug("Caught in Krb5Trusts.readEntry(): " +
                    ((e && e.message) || e));
          why = 'its stsKrb5TrustKeys do not open to JSON';
        }
      }
    }
    if (why) {
      const name = realms.currentId() + '|' + String(stored && stored.dn);
      if (!this.unreadableLogged.has(name)) {
        this.unreadableLogged.add(name);
        log.warn(errorCodes.tag('STS-KRB-0224') + 'krb5: the trust record ' +
                 String(stored && stored.dn) + ' in realm "' +
                 realms.currentId() + '" was not used: ' + why + '. No ' +
                 'referral is made through it and no ticket is accepted ' +
                 'from it until it is written again.');
      }
      log.debug("Leaving Krb5Trusts.readEntry(). Unreadable.");
      return null;
    }
    log.debug("Leaving Krb5Trusts.readEntry().");
    return { record: record, secrets: secrets || {},
             stamp: stsCrypto.digest('sha256', data + '\u0000' + keys)
               .toString('hex') };
  }

  private allRead(): Json[] {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.allRead().");
    const self = this;
    const out = this.rawEntries().map(function (stored: Json): Json {
      return self.readEntry(stored);
    }).filter(Boolean);
    log.debug("Leaving Krb5Trusts.allRead(). " + out.length + ".");
    return out;
  }

  private readOne(partner: string): Json | null {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.readOne(). partner=" + partner);
    const wanted = String(partner || '');
    const found = this.allRead().filter(function (one: Json): boolean {
      return one.record.partnerRealm === wanted;
    })[0] || null;
    log.debug("Leaving Krb5Trusts.readOne(). " + (found ? 'Held.' :
                                                         'None.'));
    return found;
  }

  // =========================================================================
  // THE PUBLIC VIEW: the record with its keys described, never carried.
  // =========================================================================
  private keyView(side: Json): Json {
    this.deps.log.debug("Entering Krb5Trusts.keyView().");
    this.deps.log.debug("Leaving Krb5Trusts.keyView().");
    return side ? { held: true, kvno: side.kvno, source: side.source,
                    setAt: side.setAt || null } : { held: false };
  }

  private viewOf(read: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.viewOf().");
    const r = read.record;
    const ourRealm = this.ourKerberosRealm();
    const view = {
      partnerRealm: r.partnerRealm,
      netbiosName: r.netbiosName,
      partnerSid: r.partnerSid || '',
      type: r.type,
      partnerTrustRealm: r.partnerTrustRealm || '',
      direction: ['none', 'inbound', 'outbound', 'bidirectional']
        [this.directionOf(r)],
      trustDirection: this.directionOf(r),
      trustAttributes: this.attributeMask(r.attributes),
      attributes: (r.attributes || []).slice(),
      suffixes: (r.suffixes || []).slice(),
      enctypes: (r.enctypes || []).slice(),
      incoming: Object.assign(this.keyView(r.incoming), {
        principal: 'krbtgt/' + ourRealm + '@' + r.partnerRealm }),
      outgoing: Object.assign(this.keyView(r.outgoing), {
        principal: 'krbtgt/' + r.partnerRealm + '@' + ourRealm }),
      enabled: r.enabled !== false,
      createdAt: r.createdAt || null,
      updatedAt: r.updatedAt || null
    };
    log.debug("Leaving Krb5Trusts.viewOf().");
    return view;
  }

  /**
   * Lists the ambient realm's trust records, keys described and never
   * carried, sorted by partner realm.
   *
   * @returns the records' public views
   */
  list(): Json[] {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.list().");
    const self = this;
    const out = this.allRead().map(function (read: Json): Json {
      return self.viewOf(read);
    });
    out.sort(function (a: Json, b: Json): number {
      return a.partnerRealm < b.partnerRealm ? -1 :
             (a.partnerRealm > b.partnerRealm ? 1 : 0);
    });
    log.debug("Leaving Krb5Trusts.list(). " + out.length + ".");
    return out;
  }

  /**
   * Returns one trust record of the ambient realm.
   *
   * @param partner - the partner Kerberos realm, exactly
   * @returns its public view, or null
   */
  get(partner: string): Json | null {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.get(). partner=" + partner);
    const read = this.readOne(partner);
    log.debug("Leaving Krb5Trusts.get().");
    return read ? this.viewOf(read) : null;
  }

  // =========================================================================
  // THE KERBEROS REALM A TRUST REALM ANSWERS AS, and its domain SID — asked
  // of the principal database, which owns the answer.
  // =========================================================================
  private kerberosNameOf(realmId: string): string {
    this.deps.log.debug("Entering Krb5Trusts.kerberosNameOf(). " + realmId);
    const p = this.deps.principals();
    const name = p.enabledIn(realmId) ? String(p.nameOf(realmId) || '') : '';
    this.deps.log.debug("Leaving Krb5Trusts.kerberosNameOf(). " + name);
    return name;
  }

  private ourKerberosRealm(): string {
    this.deps.log.debug("Entering Krb5Trusts.ourKerberosRealm().");
    const name = this.kerberosNameOf(this.deps.realms.currentId());
    this.deps.log.debug("Leaving Krb5Trusts.ourKerberosRealm().");
    return name;
  }

  // =========================================================================
  // VALIDATION. Every refusal names what was wrong and carries its own code;
  // a record is written only when nothing was refused.
  // =========================================================================
  private normaliseList(value: unknown): string[] {
    this.deps.log.debug("Entering Krb5Trusts.normaliseList().");
    const list = Array.isArray(value) ? value :
      (value === undefined || value === null || value === '' ? [] :
       String(value).split(','));
    this.deps.log.debug("Leaving Krb5Trusts.normaliseList().");
    return list.map(function (one: unknown): string {
      return String(one).trim();
    }).filter(function (one: string): boolean {
      return one !== '';
    });
  }

  // One key side of the input: null (not held), `{ password }`,
  // `{ generate: true }`, or `{ keys: { <etype>: <base64> } }` (what pair()
  // hands the partner). Answers { side, secret } or a problem.
  private keySide(input: Json, label: string, enctypes: number[],
                  existing: Json, existingSecret: Json): Json {
    const { log, kcrypto } = this.deps;
    log.debug("Entering Krb5Trusts.keySide(). " + label);
    if (input === undefined) {
      log.debug("Leaving Krb5Trusts.keySide(). Kept.");
      return { side: existing || null, secret: existingSecret || null };
    }
    if (input === null || input === false) {
      log.debug("Leaving Krb5Trusts.keySide(). Not held.");
      return { side: null, secret: null };
    }
    const kvno = input.kvno === undefined ? 1 : Number(input.kvno);
    if (!Number.isInteger(kvno) || kvno < 0 || kvno > 0x7fffffff) {
      log.debug("Leaving Krb5Trusts.keySide(). Bad kvno.");
      return { problem: { code: 'STS-KRB-0222', message: 'the ' + label +
        ' key\'s kvno must be a whole number from 0 to 2147483647' } };
    }
    const setAt = new Date().toISOString();
    if (typeof input.password === 'string') {
      if (input.password.length < MIN_PASSWORD_LENGTH) {
        log.debug("Leaving Krb5Trusts.keySide(). Short password.");
        return { problem: { code: 'STS-KRB-0222', message: 'the ' + label +
          ' trust password must be at least ' + MIN_PASSWORD_LENGTH +
          ' characters: it is the only secret between the two KDCs' } };
      }
      log.debug("Leaving Krb5Trusts.keySide(). A password.");
      return { side: { kvno: kvno, source: 'password', setAt: setAt },
               secret: { password: input.password } };
    }
    if (input.generate === true) {
      const keys: Record<string, string> = {};
      enctypes.forEach(function (etype: number): void {
        const profile = kcrypto.etypeById(etype);
        keys[String(etype)] = Buffer.from(
          kcrypto.randomBytes(profile.keyBytes)).toString('base64');
      });
      log.debug("Leaving Krb5Trusts.keySide(). Generated.");
      return { side: { kvno: kvno, source: 'generated', setAt: setAt },
               secret: { keys: keys }, shown: keys };
    }
    if (input.keys && typeof input.keys === 'object') {
      const keys: Record<string, string> = {};
      let wrong = '';
      enctypes.forEach(function (etype: number): void {
        const value = input.keys[String(etype)];
        const bytes = typeof value === 'string' ?
          Buffer.from(value, 'base64') : null;
        const profile = kcrypto.etypeById(etype);
        if (!bytes || bytes.length !== profile.keyBytes) {
          wrong = wrong || kcrypto.etypeName(etype);
          return;
        }
        keys[String(etype)] = bytes.toString('base64');
      });
      if (wrong) {
        log.debug("Leaving Krb5Trusts.keySide(). A key is wrong.");
        return { problem: { code: 'STS-KRB-0222', message: 'the ' + label +
          ' keys hold no key of the right length for ' + wrong } };
      }
      log.debug("Leaving Krb5Trusts.keySide(). Keys given.");
      return { side: { kvno: kvno, source: 'generated', setAt: setAt },
               secret: { keys: keys } };
    }
    log.debug("Leaving Krb5Trusts.keySide(). No source.");
    return { problem: { code: 'STS-KRB-0222', message: 'the ' + label +
      ' key needs a source: { password }, { generate: true }, or null for ' +
      'a key this realm does not hold' } };
  }

  /**
   * Checks a record as it would be written, against the ambient realm.
   *
   * @param input - the fields: partnerRealm, netbiosName, partnerSid, type,
   *   partnerTrustRealm, attributes, suffixes, enctypes, incoming, outgoing,
   *   enabled
   * @param existing - the record being replaced, with its secrets, or null
   *   for a new one
   * @returns `{ ok, record, secrets, shown, errors }`
   */
  validate(input: Json, existing?: Json): Json {
    const { log, realms, mode, kcrypto } = this.deps;
    log.debug("Entering Krb5Trusts.validate().");
    const errors: Problem[] = [];
    const given = input || {};
    const before = existing ? existing.record : null;
    const pick = function (name: string): unknown {
      return given[name] !== undefined ? given[name] :
             (before ? before[name] : undefined);
    };
    const ourRealm = this.ourKerberosRealm();
    const partnerRealm = String(pick('partnerRealm') || '').trim();
    if (!partnerRealm || partnerRealm.length > 255 ||
        !REALM_PATTERN.test(partnerRealm)) {
      errors.push({ code: 'STS-KRB-0213', message: 'partnerRealm must be ' +
        'a Kerberos realm name in the domain style (letters, digits, ' +
        'hyphens and dots), such as PARTNER.EXAMPLE' });
    } else if (ourRealm && partnerRealm.toUpperCase() ===
                           ourRealm.toUpperCase()) {
      errors.push({ code: 'STS-KRB-0214', message: 'partnerRealm ' +
        partnerRealm + ' is this realm\'s own Kerberos realm; a realm ' +
        'needs no trust with itself' });
    }
    if (!ourRealm) {
      errors.push({ code: 'STS-KRB-0214', message: 'realm "' +
        realms.currentId() + '" has no Kerberos realm of its own ' +
        '(krb5.realm and krb5.enabled), so it can hold no trust' });
    }
    const type = String(pick('type') || 'external');
    if (TYPES.indexOf(type) === -1) {
      errors.push({ code: 'STS-KRB-0216', message: 'type must be one of ' +
        TYPES.join(', ') });
    }
    let partnerTrustRealm = '';
    if (type === 'trust-realm') {
      partnerTrustRealm = String(pick('partnerTrustRealm') || '').trim();
      const answers = partnerTrustRealm ?
        this.kerberosNameOf(partnerTrustRealm) : '';
      if (!partnerTrustRealm || !realms.get(partnerTrustRealm)) {
        errors.push({ code: 'STS-KRB-0216', message: 'a trust-realm ' +
          'partner names the trust realm in this process it is ' +
          '(partnerTrustRealm), and "' + partnerTrustRealm + '" is none' });
      } else if (partnerTrustRealm === realms.currentId()) {
        errors.push({ code: 'STS-KRB-0216', message: 'partnerTrustRealm ' +
          'is this realm itself' });
      } else if (answers !== partnerRealm) {
        errors.push({ code: 'STS-KRB-0216', message: 'trust realm "' +
          partnerTrustRealm + '" answers ' + (answers ? 'as Kerberos ' +
          'realm ' + answers : 'as no Kerberos realm (its Kerberos is ' +
          'off)') + ', not ' + partnerRealm });
      }
    }
    const netbiosName = String(pick('netbiosName') ||
      partnerRealm.split('.')[0].toUpperCase().slice(0, 15)).trim();
    if (netbiosName && !NETBIOS_PATTERN.test(netbiosName)) {
      errors.push({ code: 'STS-KRB-0218', message: 'netbiosName must be ' +
        'one to fifteen letters, digits and hyphens' });
    }
    let partnerSid = String(pick('partnerSid') || '').trim();
    if (!partnerSid && type === 'trust-realm' && partnerTrustRealm &&
        realms.get(partnerTrustRealm)) {
      partnerSid = String(realms.run(realms.get(partnerTrustRealm),
        function (): unknown {
          return config.value('krb5.domainSid');
        }) || '');
    }
    if (partnerSid && !DOMAIN_SID_PATTERN.test(partnerSid)) {
      errors.push({ code: 'STS-KRB-0218', message: 'partnerSid must be a ' +
        'domain SID, S-1-5-21- and three numbers' });
    }
    const attributes = this.normaliseList(pick('attributes') === undefined ?
      DEFAULT_ATTRIBUTES : pick('attributes')).map(function (one: string):
      string {
      return one.toLowerCase();
    });
    attributes.forEach(function (name: string): void {
      if (!Object.prototype.hasOwnProperty.call(ATTRIBUTE_BITS, name)) {
        errors.push({ code: 'STS-KRB-0217', message: 'attribute "' + name +
          '" is not one of ' + Object.keys(ATTRIBUTE_BITS).join(', ') });
      }
    });
    CONTRADICTIONS.forEach(function (pair: [string, string, string]): void {
      if (attributes.indexOf(pair[0]) !== -1 &&
          attributes.indexOf(pair[1]) !== -1) {
        errors.push({ code: 'STS-KRB-0217', message: pair[0] + ' and ' +
          pair[1] + ' cannot both be set: ' + pair[2] });
      }
    });
    const ownDomain = ourRealm.toLowerCase();
    const suffixes = this.normaliseList(pick('suffixes') === undefined ?
      [partnerRealm.toLowerCase()] : pick('suffixes'))
      .map(function (one: string): string {
        return one.toLowerCase().replace(/^\.+/, '');
      });
    suffixes.forEach(function (suffix: string): void {
      if (!SUFFIX_PATTERN.test(suffix) || suffix.length > 253) {
        errors.push({ code: 'STS-KRB-0219', message: 'suffix "' + suffix +
          '" is not a DNS name' });
      } else if (suffix === ownDomain) {
        errors.push({ code: 'STS-KRB-0219', message: 'suffix "' + suffix +
          '" is this realm\'s own domain: routing it to a partner would ' +
          'refer every service of this realm away' });
      }
    });
    const enctypes = (Array.isArray(pick('enctypes')) ?
      pick('enctypes') as unknown[] :
      this.normaliseList(pick('enctypes') === undefined ?
                         DEFAULT_ENCTYPES.map(String) : pick('enctypes')))
      .map(function (one: unknown): number {
        return Number(one);
      });
    if (!enctypes.length) {
      errors.push({ code: 'STS-KRB-0220', message: 'enctypes names none; ' +
        'a trust key is made for at least one' });
    }
    enctypes.forEach(function (etype: number): void {
      if (!Number.isInteger(etype) || !kcrypto.isSupportedEtype(etype)) {
        errors.push({ code: 'STS-KRB-0220', message: 'enctype ' + etype +
          ' is not one this KDC implements' });
      } else if (!mode.allowsValue('krb5.enctypes', [String(etype)])) {
        errors.push({ code: 'STS-KRB-0220', message: kcrypto
          .etypeName(etype) + ' is not used in product mode (RFC 8429 ' +
          'deprecates it)' });
      }
    });
    const before2 = existing || { record: {}, secrets: {} };
    const incoming = this.keySide(given.incoming, 'incoming', enctypes,
                                  before2.record.incoming,
                                  before2.secrets.incoming);
    const outgoing = this.keySide(given.outgoing, 'outgoing', enctypes,
                                  before2.record.outgoing,
                                  before2.secrets.outgoing);
    [incoming, outgoing].forEach(function (one: Json): void {
      if (one.problem) {
        errors.push(one.problem);
      }
    });
    if (!incoming.problem && !outgoing.problem && !incoming.side &&
        !outgoing.side) {
      errors.push({ code: 'STS-KRB-0221', message: 'a trust holds at ' +
        'least one key: incoming (krbtgt/' + (ourRealm || '<us>') + '@' +
        (partnerRealm || '<partner>') + ', accepting the partner\'s ' +
        'tickets) or outgoing (krbtgt/' + (partnerRealm || '<partner>') +
        '@' + (ourRealm || '<us>') + ', referring to the partner)' });
    }
    // A changed enctype list cannot keep GENERATED keys made for the old one.
    [['incoming', incoming], ['outgoing', outgoing]].forEach(
      function (pair: Json[]): void {
        const side = pair[1];
        if (side.secret && side.secret.keys && given[pair[0]] === undefined) {
          const missing = enctypes.filter(function (etype: number): boolean {
            return !side.secret.keys[String(etype)];
          });
          if (missing.length) {
            errors.push({ code: 'STS-KRB-0220', message: 'the ' + pair[0] +
              ' key was generated without ' + missing.map(function (e:
                number): string {
                return kcrypto.etypeName(e);
              }).join(', ') + '; give it a new key with the new enctypes' });
          }
        }
      });
    const enabledValue = pick('enabled');
    const enabled = enabledValue === undefined ? true :
      !(enabledValue === false || String(enabledValue) === 'false');
    if (errors.length) {
      log.debug("Leaving Krb5Trusts.validate(). " + errors.length +
                " refusal(s).");
      return { ok: false, errors: errors };
    }
    const now = new Date().toISOString();
    const record = {
      v: 1,
      partnerRealm: partnerRealm,
      netbiosName: netbiosName,
      partnerSid: partnerSid,
      type: type,
      partnerTrustRealm: partnerTrustRealm,
      attributes: attributes.filter(function (one: string, i: number,
                                               all: string[]): boolean {
        return all.indexOf(one) === i;
      }),
      suffixes: suffixes.filter(function (one: string, i: number,
                                         all: string[]): boolean {
        return all.indexOf(one) === i;
      }),
      enctypes: enctypes.filter(function (one: number, i: number,
                                         all: number[]): boolean {
        return all.indexOf(one) === i;
      }),
      incoming: incoming.side,
      outgoing: outgoing.side,
      enabled: enabled,
      createdAt: before && before.createdAt ? before.createdAt : now,
      updatedAt: now
    };
    const shown: Json = {};
    if (incoming.shown) {
      shown.incoming = incoming.shown;
    }
    if (outgoing.shown) {
      shown.outgoing = outgoing.shown;
    }
    log.debug("Leaving Krb5Trusts.validate(). Acceptable.");
    return { ok: true, record: record,
             secrets: { incoming: incoming.secret, outgoing: outgoing.secret },
             shown: Object.keys(shown).length ? shown : null };
  }

  // =========================================================================
  // WRITING. Each act answers `{ ok, trust, errors }`; a generated key is in
  // `shown` once, and never again.
  // =========================================================================
  private store(checked: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.store().");
    const attributes = this.entryFor(checked.record, checked.secrets);
    if (!attributes) {
      log.debug("Leaving Krb5Trusts.store(). Could not seal.");
      return { ok: false, errors: [{ code: 'STS-KRB-0223', message: 'the ' +
        'trust keys could not be sealed (no key-encryption key), so the ' +
        'record was not written' }] };
    }
    if (!this.writeEntry(checked.record.partnerRealm, attributes)) {
      log.debug("Leaving Krb5Trusts.store(). The directory refused.");
      return { ok: false, errors: [{ code: 'STS-KRB-0223', message: 'the ' +
        'directory did not write the record (it may be full)' }] };
    }
    log.debug("Leaving Krb5Trusts.store().");
    return { ok: true, trust: this.get(checked.record.partnerRealm),
             shown: checked.shown || null };
  }

  /**
   * Adds a trust record to the ambient realm.
   *
   * @param input - the record's fields (see `validate()`)
   * @returns `{ ok, trust, shown, errors }`
   */
  add(input: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.add().");
    const partner = String((input || {}).partnerRealm || '').trim();
    if (partner && this.readOne(partner)) {
      log.debug("Leaving Krb5Trusts.add(). Already held.");
      return { ok: false, errors: [{ code: 'STS-KRB-0215', message: 'this ' +
        'realm already holds a trust with ' + partner + '; update it ' +
        'instead' }] };
    }
    if (this.rawEntries().length >= MAX_RECORDS) {
      log.debug("Leaving Krb5Trusts.add(). Full.");
      return { ok: false, errors: [{ code: 'STS-KRB-0215', message: 'this ' +
        'realm already holds ' + MAX_RECORDS + ' trusts, the most it ' +
        'may' }] };
    }
    const checked = this.validate(input, null);
    if (!checked.ok) {
      log.debug("Leaving Krb5Trusts.add(). Refused.");
      return checked;
    }
    const out = this.store(checked);
    log.debug("Leaving Krb5Trusts.add().");
    return out;
  }

  /**
   * Changes a trust record of the ambient realm; a field not given keeps its
   * value, and a key side not given keeps its key.
   *
   * @param partner - the partner Kerberos realm
   * @param changes - the fields to change (see `validate()`); `partnerRealm`
   *   cannot change
   * @returns `{ ok, trust, shown, errors }`
   */
  update(partner: string, changes: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.update(). partner=" + partner);
    const existing = this.readOne(partner);
    if (!existing) {
      log.debug("Leaving Krb5Trusts.update(). Not held.");
      return { ok: false, errors: [{ code: 'STS-KRB-0215', message: 'this ' +
        'realm holds no trust with ' + partner }] };
    }
    const asked = Object.assign({}, changes || {});
    if (asked.partnerRealm !== undefined &&
        String(asked.partnerRealm) !== existing.record.partnerRealm) {
      log.debug("Leaving Krb5Trusts.update(). A rename.");
      return { ok: false, errors: [{ code: 'STS-KRB-0213', message: 'a ' +
        'trust\'s partner realm cannot change: every key is salted with ' +
        'it. Remove the trust and add another.' }] };
    }
    const checked = this.validate(asked, existing);
    if (!checked.ok) {
      log.debug("Leaving Krb5Trusts.update(). Refused.");
      return checked;
    }
    const out = this.store(checked);
    log.debug("Leaving Krb5Trusts.update().");
    return out;
  }

  /**
   * Turns a trust record on or off. A disabled trust refers nobody and
   * accepts no ticket; its keys are kept.
   *
   * @param partner - the partner Kerberos realm
   * @param enabled - whether it is on
   * @returns `{ ok, trust, errors }`
   */
  setEnabled(partner: string, enabled: boolean): Json {
    this.deps.log.debug("Entering Krb5Trusts.setEnabled(). partner=" +
                        partner + " enabled=" + enabled);
    const out = this.update(partner, { enabled: !!enabled });
    this.deps.log.debug("Leaving Krb5Trusts.setEnabled().");
    return out;
  }

  /**
   * Removes a trust record from the ambient realm, keys and all.
   *
   * @param partner - the partner Kerberos realm
   * @returns `{ ok, errors }`
   */
  remove(partner: string): Json {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.remove(). partner=" + partner);
    if (!this.readOne(partner) || !this.deleteEntry(String(partner))) {
      log.debug("Leaving Krb5Trusts.remove(). Not held.");
      return { ok: false, errors: [{ code: 'STS-KRB-0215', message: 'this ' +
        'realm holds no trust with ' + partner }] };
    }
    log.debug("Leaving Krb5Trusts.remove().");
    return { ok: true };
  }

  /**
   * Writes both records of a trust between the ambient realm and another
   * trust realm in this process, mirrored: this realm's outgoing key is the
   * other's incoming key and the other way round, from one shared password
   * or one generated key set. Nothing is written unless both are acceptable.
   *
   * @param otherRealmId - the other trust realm's id
   * @param input - `direction` (`both`, `outgoing` or `incoming`, from this
   *   realm's side), `password` or `generate: true`, and the shared fields
   *   (attributes, enctypes, kvno); `suffixes` and `partnerSuffixes` for each
   *   side
   * @returns `{ ok, here, there, shown, errors }`
   */
  pair(otherRealmId: string, input: Json): Json {
    const { log, realms } = this.deps;
    log.debug("Entering Krb5Trusts.pair(). other=" + otherRealmId);
    const given = input || {};
    const other = realms.get(String(otherRealmId || ''));
    const hereId = realms.currentId();
    const here = realms.get(hereId);
    const ourName = this.ourKerberosRealm();
    const theirName = other ? this.kerberosNameOf(other.id) : '';
    if (!other || other.id === hereId || !theirName) {
      log.debug("Leaving Krb5Trusts.pair(). No such partner.");
      return { ok: false, errors: [{ code: 'STS-KRB-0216', message: 'pair ' +
        'names another trust realm in this process whose Kerberos is on, ' +
        'and "' + otherRealmId + '" is not one' }] };
    }
    const direction = String(given.direction || 'both');
    if (['both', 'outgoing', 'incoming'].indexOf(direction) === -1) {
      log.debug("Leaving Krb5Trusts.pair(). Bad direction.");
      return { ok: false, errors: [{ code: 'STS-KRB-0221', message:
        'direction must be both, outgoing or incoming' }] };
    }
    const enctypes = given.enctypes === undefined ? DEFAULT_ENCTYPES :
      this.normaliseList(given.enctypes).map(Number);
    // ONE SOURCE FOR BOTH SIDES OF EACH KEY: a generated key is made once
    // and handed to both records as given keys.
    const sourceFor = function (self: Krb5Trusts): Json {
      if (typeof given.password === 'string') {
        return { password: given.password, kvno: given.kvno };
      }
      const made = self.keySide({ generate: true, kvno: given.kvno },
                                'shared', enctypes, null, null);
      return made.problem ? { generate: 'refused' } :
        { keys: made.secret.keys, kvno: given.kvno };
    };
    const outKey = direction !== 'incoming' ? sourceFor(this) : null;
    const inKey = direction !== 'outgoing' ? sourceFor(this) : null;
    const shared = {
      attributes: given.attributes, enctypes: enctypes, enabled: true,
      type: 'trust-realm'
    };
    const mine = Object.assign({}, shared, {
      partnerRealm: theirName, partnerTrustRealm: other.id,
      suffixes: given.suffixes, outgoing: outKey, incoming: inKey
    });
    const theirs = Object.assign({}, shared, {
      partnerRealm: ourName, partnerTrustRealm: hereId,
      suffixes: given.partnerSuffixes, outgoing: inKey, incoming: outKey
    });
    const self = this;
    const checkedHere = this.readOne(theirName) ?
      { ok: false, errors: [{ code: 'STS-KRB-0215', message: 'this realm ' +
        'already holds a trust with ' + theirName }] } :
      this.validate(mine, null);
    const checkedThere = realms.run(other, function (): Json {
      return self.readOne(ourName) ?
        { ok: false, errors: [{ code: 'STS-KRB-0215', message: 'realm "' +
          other.id + '" already holds a trust with ' + ourName }] } :
        self.validate(theirs, null);
    });
    if (!checkedHere.ok || !checkedThere.ok) {
      log.debug("Leaving Krb5Trusts.pair(). Refused.");
      return { ok: false, errors: (checkedHere.errors || [])
        .concat(checkedThere.errors || []) };
    }
    const wroteHere = this.store(checkedHere);
    if (!wroteHere.ok) {
      log.debug("Leaving Krb5Trusts.pair(). This side was not written.");
      return wroteHere;
    }
    const wroteThere = realms.run(other, function (): Json {
      return self.store(checkedThere);
    });
    if (!wroteThere.ok) {
      // Taken back, so the two realms are never left half-paired.
      this.deleteEntry(theirName);
      log.debug("Leaving Krb5Trusts.pair(). The other side was not " +
                "written.");
      return wroteThere;
    }
    const shown: Json = {};
    if (outKey && outKey.keys) {
      shown.outgoing = outKey.keys;
    }
    if (inKey && inKey.keys) {
      shown.incoming = inKey.keys;
    }
    log.debug("Leaving Krb5Trusts.pair(). " + (here ? here.id : hereId) +
              " <-> " + other.id);
    return { ok: true, here: wroteHere.trust, there: wroteThere.trust,
             shown: Object.keys(shown).length ? shown : null };
  }

  /**
   * The entries the directory's seed() writes into a realm's new tree: the
   * development trust with PARTNER.COM in the DEFAULT realm while it seeds
   * demonstration data, and nothing anywhere else.
   *
   * @returns `[{ cn, attributes }]`
   */
  seedEntries(): Json[] {
    const { log, mode } = this.deps;
    log.debug("Entering Krb5Trusts.seedEntries().");
    if (!this.isDefaultRealm() || !mode.seedsDemoData()) {
      log.debug("Leaving Krb5Trusts.seedEntries(). None here.");
      return [];
    }
    const now = new Date().toISOString();
    const p = this.deps.principals();
    const record = {
      v: 1, partnerRealm: p.DEV_PARTNER_REALM, netbiosName: 'PARTNER',
      partnerSid: p.DEV_PARTNER_DOMAIN_SID, type: 'external',
      partnerTrustRealm: '',
      attributes: DEFAULT_ATTRIBUTES.slice(),
      suffixes: [p.DEV_PARTNER_DOMAIN],
      enctypes: DEFAULT_ENCTYPES.slice(),
      incoming: null,
      outgoing: { kvno: 1, source: 'password', setAt: now },
      enabled: true, createdAt: now, updatedAt: now
    };
    const attributes = this.entryFor(record, {
      incoming: null, outgoing: { password: DEV_TRUST_PASSWORD } });
    log.debug("Leaving Krb5Trusts.seedEntries().");
    return attributes ? [{ cn: p.DEV_PARTNER_REALM,
                           attributes: attributes }] : [];
  }

  // =========================================================================
  // THE KDC'S QUESTIONS.
  // =========================================================================
  /**
   * Which partner a service host belongs to: the enabled record holding an
   * OUTGOING key whose routed suffix matches the host most specifically —
   * the next hop, which for a transitive trust may not be the service's own
   * realm. The ambient realm's own domain wins over a suffix no longer than
   * it.
   *
   * @param host - the host name, any case
   * @param ownDomain - the ambient realm's own DNS domain
   * @returns `{ partner, suffix }`, or null when no record routes it
   */
  routeHost(host: string, ownDomain: string): Json | null {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.routeHost(). host=" + host);
    const name = String(host || '').toLowerCase();
    const matches = function (suffix: string): boolean {
      return !!suffix && (name === suffix || name.endsWith('.' + suffix));
    };
    let best: Json = null;
    this.allRead().forEach(function (read: Json): void {
      const r = read.record;
      if (r.enabled === false || !r.outgoing) {
        return;
      }
      (r.suffixes || []).forEach(function (suffix: string): void {
        if (matches(suffix) &&
            (!best || suffix.length > best.suffix.length)) {
          best = { partner: r.partnerRealm, suffix: suffix };
        }
      });
    });
    const own = String(ownDomain || '').toLowerCase();
    if (best && matches(own) && own.length >= best.suffix.length) {
      log.debug("Leaving Krb5Trusts.routeHost(). This realm's own.");
      return null;
    }
    log.debug("Leaving Krb5Trusts.routeHost(). " +
              (best ? best.partner : 'none'));
    return best;
  }

  /**
   * Why a `krbtgt/X@R` name has no inter-realm principal here although a
   * record names it, for the refusal's sentence; '' when no record names it.
   *
   * @param nameComponents - `['krbtgt', X]`
   * @param realm - R, the realm the name is looked up in
   * @param ourRealm - the ambient KDC's Kerberos realm
   * @returns the sentence, or ''
   */
  unavailableReason(nameComponents: string[], realm: string,
                    ourRealm: string): string {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.unavailableReason().");
    const which = this.sideOf(nameComponents, realm, ourRealm);
    const read = which ? this.readOne(which.partner) : null;
    if (!read) {
      log.debug("Leaving Krb5Trusts.unavailableReason(). No record.");
      return '';
    }
    if (read.record.enabled === false) {
      log.debug("Leaving Krb5Trusts.unavailableReason(). Disabled.");
      return 'the trust with ' + which.partner + ' is disabled';
    }
    if (!read.record[which.direction]) {
      log.debug("Leaving Krb5Trusts.unavailableReason(). No such key.");
      return 'the trust with ' + which.partner + ' holds no ' +
             which.direction + ' key (' + (which.direction === 'incoming' ?
             'this realm does not accept that realm\'s tickets' :
             'this realm does not refer to that realm') + ')';
    }
    log.debug("Leaving Krb5Trusts.unavailableReason().");
    return '';
  }

  // Which record and which of its two keys a `krbtgt/X@R` name is, or null:
  // OUTGOING when R is ours (`krbtgt/PARTNER@US`), INCOMING when X is ours
  // (`krbtgt/US@PARTNER`). A HOT PATH — asked of every krbtgt lookup the KDC
  // makes, its own TGT included — so no Entering/Leaving pair here, which
  // would drown the log.
  private sideOf(nameComponents: string[], realm: string,
                 ourRealm: string): Json | null {
    if (!Array.isArray(nameComponents) || nameComponents.length !== 2 ||
        String(nameComponents[0]) !== 'krbtgt') {
      return null;
    }
    const x = String(nameComponents[1]);
    const r = String(realm || '');
    if (!x || !r || x === r) {
      return null;
    }
    if (r === ourRealm) {
      return { partner: x, direction: 'outgoing' };
    }
    if (x === ourRealm) {
      return { partner: r, direction: 'incoming' };
    }
    return null;
  }

  /**
   * The inter-realm principal a `krbtgt/X@R` lookup names, built from the
   * ambient realm's record: its kvno, its enctypes, and its key — a password
   * the principal database derives from with the default salt, or generated
   * keys already in its cache. Null when no enabled record holds that key.
   *
   * @param nameComponents - `['krbtgt', X]`
   * @param realm - R, the realm the name is looked up in
   * @param ourRealm - the ambient KDC's Kerberos realm
   * @returns the principal, or null
   */
  // A HOT PATH: every krbtgt lookup the KDC makes reaches it, its own TGT's
  // included, so it logs only when it BUILDS a principal — an
  // Entering/Leaving pair on every ticket would drown the log.
  trustPrincipal(nameComponents: string[], realm: string,
                 ourRealm: string): Json | null {
    const { log } = this.deps;
    const which = this.sideOf(nameComponents, realm, ourRealm);
    if (!which) {
      return null;
    }
    const read = this.readOne(which.partner);
    const side = read ? read.record[which.direction] : null;
    const secret = read ? (read.secrets || {})[which.direction] : null;
    if (!read || read.record.enabled === false || !side || !secret) {
      return null;
    }
    const cacheKey = which.direction + '|krbtgt/' + nameComponents[1] + '@' +
                     realm;
    const held = this.built.get(cacheKey);
    if (held && held.stamp === read.stamp) {
      this.counter.hit();
      return held.principal;
    }
    this.counter.miss();
    const principal: Json = {
      name: ['krbtgt', String(nameComponents[1])],
      type: 2,
      realm: String(realm),
      password: typeof secret.password === 'string' ? secret.password : null,
      // RFC 4120 section 4's default salt: the realm, then the name
      // components, with no separators — `AkrbtgtB` for krbtgt/B@A. What a
      // partner KDC derives from the same password.
      salt: String(realm) + 'krbtgt' + String(nameComponents[1]),
      etypes: (read.record.enctypes || []).slice(),
      kvno: side.kvno,
      requiresPreAuth: true,
      revoked: false,
      passwordExpired: false,
      directoryKeys: false,
      autoCreated: false,
      description: 'the inter-realm trust key with ' + which.partner +
        ' (' + which.direction + '), from this realm\'s trust record',
      // [MS-SAMR]'s INTERDOMAIN_TRUST_ACCOUNT: what an inter-realm account
      // is in a domain. Nothing builds a PAC for this principal; it is here
      // for the readers that list principals.
      pac: { rid: 0, groups: [], userAccountControl: 0x00000040,
             extraSids: [] },
      trustKey: { partner: which.partner, direction: which.direction,
                  attributes: (read.record.attributes || []).slice(),
                  type: read.record.type }
    };
    // The generated keys, kept where `longTermKey()` reads them back after
    // the principal's own cache was cleared to make room.
    const material = new Map<number, Uint8Array>();
    Object.keys(secret.keys || {}).forEach(function (etype: string): void {
      material.set(Number(etype), new Uint8Array(
        Buffer.from(String(secret.keys[etype]), 'base64')));
    });
    Object.defineProperty(principal, 'trustKeyMaterial', {
      value: material, enumerable: false, writable: false,
      configurable: false
    });
    Object.defineProperty(principal, 'keys', {
      value: new Map(material), enumerable: false, writable: true,
      configurable: true
    });
    if (!held) {
      // The bound, oldest first: a Map iterates in insertion order.
      let evicted = 0;
      while (this.built.size >= MAX_CACHED_PRINCIPALS) {
        const oldest = this.built.keys().next().value;
        this.built.delete(oldest);
        evicted += 1;
      }
      if (evicted) {
        this.counter.evicted(evicted);
      }
    }
    this.built.set(cacheKey, { stamp: read.stamp, principal: principal });
    log.debug("krb5: built the inter-realm principal " + cacheKey +
              " from its trust record, kvno " + side.kvno + ".");
    return principal;
  }

  /**
   * The ambient realm's record for a partner, opened, for the KDC's checks;
   * null when none is held.
   *
   * @param partner - the partner Kerberos realm
   * @returns the record (no secrets), or null
   */
  recordFor(partner: string): Json | null {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.recordFor(). partner=" + partner);
    const read = this.readOne(partner);
    log.debug("Leaving Krb5Trusts.recordFor().");
    return read ? JSON.parse(JSON.stringify(read.record)) : null;
  }

  // Whether a Kerberos realm name is inside a record's namespace: the
  // partner itself, or a realm whose domain form falls under one of its
  // routed suffixes.
  private inNamespace(record: Json, realmName: string): boolean {
    this.deps.log.debug("Entering Krb5Trusts.inNamespace().");
    const domain = String(realmName || '').toLowerCase();
    const inside = realmName === record.partnerRealm ||
      (record.suffixes || []).some(function (suffix: string): boolean {
        return domain === suffix || domain.endsWith('.' + suffix);
      });
    this.deps.log.debug("Leaving Krb5Trusts.inNamespace().");
    return inside;
  }

  /**
   * THE TRANSITED-POLICY CHECK (RFC 4120 sections 2.7 and 3.3.3.2), asked
   * by the KDC before it issues anything from a cross-realm TGT, and before
   * it refers anybody onward. The path is the client's realm, the realms in
   * `transited`, and the realm that issued the presented ticket; this realm
   * accepts it only through an ENABLED record holding an INCOMING key from
   * that issuer, and:
   *
   *   * a NON-TRANSITIVE record accepts the partner's own people only — the
   *     client's realm is the issuer and nothing was transited;
   *   * a transitive one accepts every realm on the path that is inside the
   *     record's namespace (the partner, or under one of its routed
   *     suffixes), and none that is this realm (a loop);
   *   * an elided-hierarchy entry (`,,`) is refused: a record names
   *     partners, not a hierarchy;
   *   * referring ONWARD needs a transitive record too — a non-transitive
   *     trust is not a way through — and the crossings so far, plus the one
   *     being made, may not pass `krb5.maxReferralHops`.
   *
   * @param path - `{ crealm, issuer, transited, onward, ourRealm }`, with
   *   `transited` as `decodeTransited()` answers it
   * @returns null when acceptable, or `{ code, message }`
   */
  pathProblem(path: Json): Problem | null {
    const { log, config } = this.deps;
    log.debug("Entering Krb5Trusts.pathProblem().");
    const crealm = String(path.crealm || '');
    const issuer = String(path.issuer || '');
    const ourRealm = String(path.ourRealm || '');
    const decoded = path.transited || { realms: [], elided: false };
    const listed: string[] = (decoded.realms || []).slice();
    const crossings = issuer && issuer !== ourRealm ?
      listed.length + 1 : 0;
    if (path.onward) {
      const max = Number(config.value('krb5.maxReferralHops'));
      if (crossings + 1 > max) {
        log.debug("Leaving Krb5Trusts.pathProblem(). Too many hops.");
        return { code: 'STS-KRB-0226', message: 'a referral from here ' +
          'would be crossing ' + (crossings + 1) + ' of a path whose ' +
          'limit is ' + max + ' (krb5.maxReferralHops)' };
      }
    }
    if (!crossings) {
      log.debug("Leaving Krb5Trusts.pathProblem(). Not cross-realm.");
      return null;
    }
    if (decoded.elided) {
      log.debug("Leaving Krb5Trusts.pathProblem(). Elided.");
      return { code: 'STS-KRB-0228', message: 'the ticket\'s transited ' +
        'path elides realms between two (",,"), and this KDC accepts only ' +
        'a path it can check realm by realm' };
    }
    const read = this.readOne(issuer);
    const record = read ? read.record : null;
    if (!record || record.enabled === false || !record.incoming) {
      log.debug("Leaving Krb5Trusts.pathProblem(). No incoming trust.");
      return { code: 'STS-KRB-0228', message: 'this realm holds no enabled ' +
        'trust accepting tickets from ' + issuer };
    }
    const transitive = (record.attributes || [])
      .indexOf('non-transitive') === -1;
    if (!transitive && (crealm !== issuer || listed.length)) {
      log.debug("Leaving Krb5Trusts.pathProblem(). Non-transitive.");
      return { code: 'STS-KRB-0227', message: 'the trust with ' + issuer +
        ' is non-transitive, so it accepts ' + issuer + '\'s own people ' +
        'only, and this ticket is for ' + crealm +
        (listed.length ? ' through ' + listed.join(', ') : '') };
    }
    if (path.onward && !transitive) {
      log.debug("Leaving Krb5Trusts.pathProblem(). Not a way through.");
      return { code: 'STS-KRB-0227', message: 'the trust with ' + issuer +
        ' is non-transitive, so its people are not referred onward from ' +
        'here' };
    }
    const self = this;
    const outside = [crealm].concat(listed).filter(function (name: string):
      boolean {
      return name === ourRealm || !self.inNamespace(record, name);
    });
    if (outside.length) {
      log.debug("Leaving Krb5Trusts.pathProblem(). Outside the namespace.");
      return { code: 'STS-KRB-0228', message: 'the path names ' +
        outside.join(', ') + ', outside what the trust with ' + issuer +
        ' routes (' + [issuer].concat(record.suffixes || []).join(', ') +
        ')' + (outside.indexOf(ourRealm) !== -1 ? ', and a path back ' +
          'through this realm is a loop' : '') };
    }
    log.debug("Leaving Krb5Trusts.pathProblem(). Acceptable.");
    return null;
  }

  // =========================================================================
  // `transited`, DOMAIN-X500-COMPRESS (RFC 4120 section 3.3.3.2).
  // =========================================================================
  /**
   * Encodes realm names as a DOMAIN-X500-COMPRESS `transited` value: comma
   * separated, a domain-style name that extends the one before it written as
   * its new labels followed by a dot, and `,` and `\` escaped.
   *
   * @param list - the realm names, in the order they were transited
   * @returns the contents' bytes
   */
  static encodeTransited(list: string[]): Uint8Array {
    log.debug("Entering Krb5Trusts.encodeTransited().");
    const escape = function (text: string): string {
      return text.replace(/\\/g, '\\\\').replace(/,/g, '\\,');
    };
    const parts: string[] = [];
    let previous = '';
    (list || []).forEach(function (name: string): void {
      const full = String(name);
      if (previous && full.length > previous.length + 1 &&
          full.endsWith('.' + previous) && previous.indexOf('/') !== 0 &&
          full.indexOf('/') !== 0) {
        parts.push(escape(full.slice(0, full.length - previous.length)));
      } else {
        parts.push(escape(full));
      }
      previous = full;
    });
    log.debug("Leaving Krb5Trusts.encodeTransited().");
    return new Uint8Array(Buffer.from(parts.join(','), 'utf8'));
  }

  /**
   * Decodes a DOMAIN-X500-COMPRESS `transited` value: a name ending in `.`
   * is prefixed to the name before it, one starting with `/` is appended to
   * it, an empty first or last element stands for the client's or the
   * server's realm, and an empty one between two names elides the hierarchy
   * between them.
   *
   * @param contents - the contents' bytes
   * @param crealm - the client's realm
   * @param srealm - the server's realm
   * @returns `{ realms, elided }`
   */
  static decodeTransited(contents: Uint8Array | null, crealm: string,
                         srealm: string): Json {
    log.debug("Entering Krb5Trusts.decodeTransited().");
    const text = Buffer.from(contents || new Uint8Array(0)).toString('utf8');
    if (!text) {
      log.debug("Leaving Krb5Trusts.decodeTransited(). Empty.");
      return { realms: [], elided: false };
    }
    const raw: string[] = [];
    let current = '';
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (c === '\\' && i + 1 < text.length) {
        current += text[i + 1];
        i += 1;
      } else if (c === ',') {
        raw.push(current);
        current = '';
      } else {
        current += c;
      }
    }
    raw.push(current);
    const out: string[] = [];
    let elided = false;
    let previous = '';
    raw.forEach(function (part: string, index: number): void {
      if (part === '') {
        if (index === 0) {
          previous = crealm;
          out.push(crealm);
        } else if (index === raw.length - 1) {
          out.push(srealm);
        } else {
          elided = true;
        }
        return;
      }
      let full = part;
      if (part.endsWith('.') && previous) {
        full = part + previous;
      } else if (part.indexOf('/') === 0 && previous) {
        full = previous + part;
      }
      out.push(full);
      previous = full;
    });
    log.debug("Leaving Krb5Trusts.decodeTransited(). " + out.length + ".");
    return { realms: out, elided: elided };
  }
}

const slot = new InstanceSlot<Krb5Trusts>(
  'kerberos/krb5_trusts',
  () => new Krb5Trusts(Krb5Trusts.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

/**
 * The Kerberos trust register (#430): a record per partner realm under
 * `ou=kerberosTrusts`, and the routing, inter-realm principals and path
 * checks the KDC asks of it. The exports forward to the instance the
 * composition root installs.
 *
 * @namespace
 */
export = {
  Krb5Trusts: Krb5Trusts,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: Krb5Trusts): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  ATTRIBUTE_BITS: Krb5Trusts.ATTRIBUTE_BITS,
  TYPES: Krb5Trusts.TYPES,
  SEAL_LABEL: Krb5Trusts.SEAL_LABEL,
  MIN_PASSWORD_LENGTH: Krb5Trusts.MIN_PASSWORD_LENGTH,
  encodeTransited: Krb5Trusts.encodeTransited,
  decodeTransited: Krb5Trusts.decodeTransited,
  setDirectory: slot.forward('setDirectory'),
  directoryInstalled: slot.forward('directoryInstalled'),
  list: slot.forward('list'),
  get: slot.forward('get'),
  validate: slot.forward('validate'),
  add: slot.forward('add'),
  update: slot.forward('update'),
  setEnabled: slot.forward('setEnabled'),
  remove: slot.forward('remove'),
  pair: slot.forward('pair'),
  seedEntries: slot.forward('seedEntries'),
  routeHost: slot.forward('routeHost'),
  unavailableReason: slot.forward('unavailableReason'),
  trustPrincipal: slot.forward('trustPrincipal'),
  recordFor: slot.forward('recordFor'),
  pathProblem: slot.forward('pathProblem')
};
