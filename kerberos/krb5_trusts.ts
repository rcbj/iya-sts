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
// The vendored PAC codec (#430 Phase 2), for SID filtering: it requires only
// the rest of the codec, which is already in the parent project's closure.
import kpac = require('./krb5_pac');

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
  kpac: Json;
  // LAZILY, both: the keystore (the seal), and the principal database (which
  // Kerberos realm a trust realm answers as). The principal database
  // requires THIS file lazily, so a require at load would be a cycle.
  keystore: () => Json;
  principals: () => Json;
  // LAZILY too: the audit log, which every filtered ticket writes a row to
  // (rcbj, 2026-10-19). Already in the parent's COPY closure through
  // krb5_kdc.js; lazy so a register built in a test never reaches it at load.
  audit: () => Json;
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
  // [MS-ADTS] 6.1.6.7.9 TAPT: with treat-as-external on a forest trust, the
  // PrivilegedIdentityManagement boundary of [MS-PAC] 4.1.2.2 (#430's SID
  // filtering, R14).
  'pim-trust': 0x00000400,
  'enable-tgt-delegation': 0x00000800
};

// Pairs that cannot both be set, each with the reason a reader is given.
const CONTRADICTIONS: Array<[string, string, string]> = [
  ['no-tgt-delegation', 'enable-tgt-delegation',
   'a trust cannot both forbid and enable TGT delegation'],
  ['non-transitive', 'forest-transitive',
   'a forest trust is transitive by definition'],
  ['within-forest', 'forest-transitive',
   'a trust within the forest is not a cross-forest trust'],
  ['within-forest', 'cross-organization',
   'a trust within the forest is to the same organization']
];

// Attributes evaluated only beside another ([MS-ADTS] 6.1.6.7.9): each is
// refused without what it needs, so a record never says something it does
// not do.
const REQUIRES: Array<[string, string, string]> = [
  ['treat-as-external', 'forest-transitive',
   'TREAT_AS_EXTERNAL is evaluated only on a cross-forest trust'],
  ['pim-trust', 'forest-transitive',
   'PIM_TRUST is evaluated only on a cross-forest trust'],
  ['pim-trust', 'treat-as-external',
   'PIM_TRUST takes effect only with TREAT_AS_EXTERNAL']
];

// What a trust does with the claims of a PAC arriving across it ([MS-ADTS]
// 3.1.1.11.2.11): `drop-all`, the specification's answer when the trust
// has no transformation policy, or `allow-all`, [MS-CTA]'s rule that issues
// every input claim. The rest of [MS-CTA]'s rule language is not
// implemented (kerberos/CLAUDE.md, R19).
const CLAIMS_TRANSFORMATIONS = ['drop-all', 'allow-all'];

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
      kpac: kpac,
      keystore: function (): Json {
        return require('../common/keystore');
      },
      principals: function (): Json {
        return require('./krb5_principals');
      },
      audit: function (): Json {
        return require('../common/audit');
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

  // The previous incoming version a rotation keeps, while its grace lasts:
  // its kvno, when it was retired and until when it is accepted. Null when
  // none is kept or its grace has passed.
  private previousView(record: Json): Json | null {
    this.deps.log.debug("Entering Krb5Trusts.previousView().");
    const prev = record && record.previousIncoming;
    const until = prev ? this.graceEnds(prev) : 0;
    this.deps.log.debug("Leaving Krb5Trusts.previousView().");
    return prev && until > Date.now()
      ? { kvno: prev.kvno, source: prev.source, retiredAt: prev.retiredAt,
          acceptedUntil: new Date(until).toISOString() }
      : null;
  }

  /**
   * How long a retired incoming trust key is still accepted, in seconds:
   * `krb5.trustKeyGraceSeconds`, or — at its default, zero — the ticket
   * lifetime plus the clock skew, the longest a ticket issued under the
   * old key an instant before the rotation can still be presented. Read at
   * every check, so a change applies to a key already retired.
   *
   * @returns the grace in seconds
   */
  graceSeconds(): number {
    const { log, config } = this.deps;
    log.debug("Entering Krb5Trusts.graceSeconds().");
    const set = Number(config.value('krb5.trustKeyGraceSeconds'));
    const out = set > 0 ? set :
      Number(config.value('krb5.ticketLifetimeSeconds')) +
      Number(config.value('krb5.clockSkew'));
    log.debug("Leaving Krb5Trusts.graceSeconds(). " + out);
    return out;
  }

  // When a retired version's grace ends, in milliseconds since the epoch.
  private graceEnds(prev: Json): number {
    this.deps.log.debug("Entering Krb5Trusts.graceEnds().");
    const at = Date.parse(String(prev && prev.retiredAt || ''));
    this.deps.log.debug("Leaving Krb5Trusts.graceEnds().");
    return Number.isNaN(at) ? 0 : at + this.graceSeconds() * 1000;
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
      forestTrustInfo: r.forestTrustInfo || null,
      claimsTransformation: r.claimsTransformation || 'drop-all',
      boundary: this.boundaryOf(r),
      incoming: Object.assign(this.keyView(r.incoming), {
        principal: 'krbtgt/' + ourRealm + '@' + r.partnerRealm,
        previous: this.previousView(r) }),
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
    REQUIRES.forEach(function (pair: [string, string, string]): void {
      if (attributes.indexOf(pair[0]) !== -1 &&
          attributes.indexOf(pair[1]) === -1) {
        errors.push({ code: 'STS-KRB-0217', message: pair[0] + ' needs ' +
          pair[1] + ': ' + pair[2] });
      }
    });
    // THE FOREST TRUST INFORMATION ([MS-ADTS] 6.1.6.9.3, #430's SID
    // filtering R12): the trusted forest's domains, each a domain SID with
    // its DNS and NetBIOS names and whether SID matching is enabled
    // (LSA_SID_DISABLED_ADMIN off), and its top-level names. Only a
    // cross-forest trust has one.
    const ftGiven = pick('forestTrustInfo');
    let forestTrustInfo: Json = null;
    if (ftGiven !== undefined && ftGiven !== null && ftGiven !== '') {
      const ft = typeof ftGiven === 'string' ? (function (): Json {
        try {
          return JSON.parse(ftGiven as string);
        } catch (e: any) {
          log.debug("Caught in Krb5Trusts.validate(): " +
                    ((e && e.message) || e));
          return { invalid: true };
        }
      })() : ftGiven as Json;
      const domains = Array.isArray(ft && ft.domains) ? ft.domains : null;
      const names = Array.isArray(ft && ft.topLevelNames) ?
        ft.topLevelNames : [];
      if (!ft || ft.invalid || !domains) {
        errors.push({ code: 'STS-KRB-0237', message: 'forestTrustInfo is ' +
          '{ domains: [{ sid, dnsName, netbiosName, sidEnabled }], ' +
          'topLevelNames: [{ name, enabled }] }' });
      } else if (attributes.indexOf('forest-transitive') === -1) {
        errors.push({ code: 'STS-KRB-0237', message: 'forestTrustInfo ' +
          'belongs to a cross-forest trust (forest-transitive)' });
      } else {
        const badDomain = domains.filter(function (d: Json): boolean {
          return !d || !DOMAIN_SID_PATTERN.test(String(d.sid || '')) ||
            (d.dnsName && !SUFFIX_PATTERN.test(String(d.dnsName)
              .toLowerCase())) ||
            (d.netbiosName && !NETBIOS_PATTERN.test(String(d.netbiosName)));
        });
        const badName = names.filter(function (n: Json): boolean {
          return !n || !SUFFIX_PATTERN.test(String(n.name || '')
            .toLowerCase());
        });
        if (badDomain.length || badName.length) {
          errors.push({ code: 'STS-KRB-0237', message: 'forestTrustInfo ' +
            'holds ' + (badDomain.length ? badDomain.length + ' domain(s) ' +
            'without a domain SID, a DNS name or a NetBIOS name' : '') +
            (badDomain.length && badName.length ? ' and ' : '') +
            (badName.length ? badName.length + ' top-level name(s) that ' +
              'are not DNS names' : '') });
        } else {
          forestTrustInfo = {
            domains: domains.map(function (d: Json): Json {
              return { sid: String(d.sid),
                       dnsName: String(d.dnsName || '').toLowerCase(),
                       netbiosName: String(d.netbiosName || ''),
                       sidEnabled: d.sidEnabled !== false };
            }),
            topLevelNames: names.map(function (n: Json): Json {
              return { name: String(n.name).toLowerCase(),
                       enabled: n.enabled !== false };
            })
          };
        }
      }
    }
    // THE CLAIMS POLICY ([MS-ADTS] 3.1.1.11.2.11, R19).
    const claimsTransformation = String(pick('claimsTransformation') ||
                                        'drop-all');
    if (CLAIMS_TRANSFORMATIONS.indexOf(claimsTransformation) === -1) {
      errors.push({ code: 'STS-KRB-0238', message: 'claimsTransformation ' +
        'is one of ' + CLAIMS_TRANSFORMATIONS.join(', ') + '; the rest of ' +
        '[MS-CTA]\'s rule language is not implemented here' });
    }
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
    // THE PREVIOUS INCOMING KEY a rotation keeps for its grace (#430 Phase
    // 4): carried through any other write while this realm still holds an
    // incoming key, and dropped with it. rotateKey() is what sets it.
    const keepPrevious = !!(incoming.side && before && before.previousIncoming &&
                            before2.secrets.previousIncoming);
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
      forestTrustInfo: forestTrustInfo,
      claimsTransformation: claimsTransformation,
      previousIncoming: keepPrevious ? before.previousIncoming : null,
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
             secrets: { incoming: incoming.secret, outgoing: outgoing.secret,
                        previousIncoming: keepPrevious ?
                          before2.secrets.previousIncoming : null },
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

  // =========================================================================
  // ROTATION, MIRRORING AND WHAT THE CONSOLE SHOWS (#430 Phase 4).
  // =========================================================================
  /**
   * Replaces a trust's keys at the next kvno. The incoming version it
   * replaces is KEPT and still opens tickets for `graceSeconds()` — the
   * partner goes on sealing with it until its own side changes — while
   * nothing new is issued under it; the outgoing key is used from the next
   * referral. One previous incoming version is kept: a second rotation
   * within the grace ends the first one's.
   *
   * With `mirror` and a trust-realm partner, the partner realm's record is
   * rotated in the same act with the same keys the other way round, so the
   * two realms never disagree; without it, the partner's administrator
   * gives their side the same password (or the keys shown once).
   *
   * @param partner - the partner Kerberos realm
   * @param input - `password` or `generate: true`; `side` (`both` — the
   *   default — `incoming` or `outgoing`, of the sides held); `mirror`
   * @returns `{ ok, trust, there, shown, errors }`
   */
  rotateKey(partner: string, input: Json): Json {
    const { log, realms } = this.deps;
    log.debug("Entering Krb5Trusts.rotateKey(). partner=" + partner);
    const given = input || {};
    const existing = this.readOne(partner);
    if (!existing) {
      log.debug("Leaving Krb5Trusts.rotateKey(). Not held.");
      return { ok: false, errors: [{ code: 'STS-KRB-0215', message: 'this ' +
        'realm holds no trust with ' + partner }] };
    }
    const r = existing.record;
    const side = String(given.side || 'both');
    if (['both', 'incoming', 'outgoing'].indexOf(side) === -1) {
      log.debug("Leaving Krb5Trusts.rotateKey(). Bad side.");
      return { ok: false, errors: [{ code: 'STS-KRB-0241', message: 'side ' +
        'is both, incoming or outgoing' }] };
    }
    const sides = ['incoming', 'outgoing'].filter(function (one: string):
      boolean {
      return (side === 'both' || side === one) && !!r[one];
    });
    if (!sides.length) {
      log.debug("Leaving Krb5Trusts.rotateKey(). No such key.");
      return { ok: false, errors: [{ code: 'STS-KRB-0241', message: 'the ' +
        'trust with ' + partner + ' holds no ' + (side === 'both' ? '' :
        side + ' ') + 'key to rotate' }] };
    }
    if (typeof given.password !== 'string' && given.generate !== true) {
      log.debug("Leaving Krb5Trusts.rotateKey(). No source.");
      return { ok: false, errors: [{ code: 'STS-KRB-0241', message: 'a ' +
        'rotation needs the new key\'s source: password, or generate' }] };
    }
    const mirror = given.mirror === true || String(given.mirror) === 'true';
    const other = mirror ? realms.get(String(r.partnerTrustRealm || '')) :
      null;
    if (mirror && (r.type !== 'trust-realm' || !other)) {
      log.debug("Leaving Krb5Trusts.rotateKey(). Nothing to mirror.");
      return { ok: false, errors: [{ code: 'STS-KRB-0241', message: 'only ' +
        'a trust with another trust realm of this service can be rotated ' +
        'on both sides at once (mirror)' }] };
    }
    // ONE KEY PER SIDE, made once: a generated key goes to both records as
    // given keys, so the mirror holds exactly what this realm holds.
    const enctypes = (r.enctypes || []).slice();
    const self = this;
    const sourceFor = function (current: Json): Json {
      const kvno = (Number(current.kvno) || 0) + 1;
      if (typeof given.password === 'string') {
        return { password: given.password, kvno: kvno };
      }
      const made = self.keySide({ generate: true }, 'rotated', enctypes, null,
                                null);
      return { keys: made.secret.keys, kvno: kvno };
    };
    const asked: Json = {};
    sides.forEach(function (one: string): void {
      asked[one] = sourceFor(r[one]);
    });
    const checked = this.validate(asked, existing);
    if (!checked.ok) {
      log.debug("Leaving Krb5Trusts.rotateKey(). Refused.");
      return checked;
    }
    if (asked.incoming) {
      this.retire(checked, r.incoming, existing.secrets.incoming);
    }
    let mirrored: Json = null;
    if (mirror && other) {
      const hereName = this.ourKerberosRealm();
      const there = realms.run(other, function (): Json {
        const theirs = self.readOne(hereName);
        if (!theirs) {
          return { ok: false, errors: [{ code: 'STS-KRB-0241', message:
            'realm "' + other.id + '" holds no trust with ' + hereName +
            ' to rotate; pair the two first' }] };
        }
        const swapped: Json = {};
        if (asked.outgoing && theirs.record.incoming) {
          swapped.incoming = Object.assign({}, asked.outgoing);
        }
        if (asked.incoming && theirs.record.outgoing) {
          swapped.outgoing = Object.assign({}, asked.incoming);
        }
        const out = self.validate(swapped, theirs);
        if (out.ok && swapped.incoming) {
          self.retire(out, theirs.record.incoming, theirs.secrets.incoming);
        }
        return out;
      });
      if (!there.ok) {
        log.debug("Leaving Krb5Trusts.rotateKey(). The mirror refused.");
        return there;
      }
      mirrored = there;
    }
    const wrote = this.store(checked);
    if (!wrote.ok) {
      log.debug("Leaving Krb5Trusts.rotateKey(). Not written.");
      return wrote;
    }
    let thereTrust: Json = null;
    if (mirrored) {
      const wroteThere = realms.run(other, function (): Json {
        return self.store(mirrored);
      });
      if (!wroteThere.ok) {
        log.debug("Leaving Krb5Trusts.rotateKey(). The mirror was not " +
                  "written.");
        return { ok: false, trust: wrote.trust, errors: [{ code:
          'STS-KRB-0241', message: 'this realm\'s side was rotated and ' +
          'realm "' + other.id + '"\'s was not: ' + ((wroteThere.errors ||
          [])[0] || {}).message + '. Rotate it there with the same ' +
          'password.' }] };
      }
      thereTrust = wroteThere.trust;
    }
    const shown: Json = {};
    sides.forEach(function (one: string): void {
      if (asked[one].keys) {
        shown[one] = asked[one].keys;
      }
    });
    log.debug("Leaving Krb5Trusts.rotateKey(). " + sides.join(', ') +
              (thereTrust ? ', mirrored' : ''));
    return { ok: true, trust: wrote.trust, there: thereTrust,
             rotated: sides,
             shown: Object.keys(shown).length ? shown : null };
  }

  // Moves the incoming version a checked write replaces into the previous
  // slot, retired now.
  private retire(checked: Json, side: Json, secret: Json): void {
    this.deps.log.debug("Entering Krb5Trusts.retire().");
    if (side && secret) {
      checked.record.previousIncoming = {
        kvno: side.kvno, source: side.source, setAt: side.setAt || null,
        retiredAt: new Date().toISOString()
      };
      checked.secrets.previousIncoming = secret;
    }
    this.deps.log.debug("Leaving Krb5Trusts.retire().");
  }

  /**
   * The key of a RETIRED incoming version of an inter-realm principal,
   * while its grace lasts: what `ticketKeyFor()` in the KDC opens a ticket
   * sealed under the previous kvno with.
   *
   * @param principal - the inter-realm principal (`trustPrincipal()`)
   * @param etype - the ticket's enctype
   * @param kvno - the ticket's kvno
   * @returns `{ key, kvno, expiresAt }`, or null when that version is not
   *   kept or its grace has passed
   */
  async previousKey(principal: Json, etype: number,
                    kvno: number): Promise<Json | null> {
    const { log, kcrypto } = this.deps;
    log.debug("Entering Krb5Trusts.previousKey(). kvno=" + kvno);
    const which = principal && principal.trustKey;
    if (!which || which.direction !== 'incoming') {
      log.debug("Leaving Krb5Trusts.previousKey(). Not an incoming key.");
      return null;
    }
    const read = this.readOne(which.partner);
    const prev = read ? read.record.previousIncoming : null;
    const secret = read ? (read.secrets || {}).previousIncoming : null;
    const until = prev ? this.graceEnds(prev) : 0;
    if (!prev || !secret || Number(prev.kvno) !== Number(kvno) ||
        until <= Date.now()) {
      log.debug("Leaving Krb5Trusts.previousKey(). Not kept.");
      return null;
    }
    let key: Uint8Array | null = null;
    if (typeof secret.password === 'string') {
      key = await kcrypto.etypeById(etype).stringToKey(secret.password,
        new Uint8Array(Buffer.from(String(principal.salt), 'utf8')), null);
    } else if (secret.keys && secret.keys[String(etype)]) {
      key = new Uint8Array(Buffer.from(String(secret.keys[String(etype)]),
                                       'base64'));
    }
    log.debug("Leaving Krb5Trusts.previousKey(). " + (key ? 'Kept.' :
                                                       'No such enctype.'));
    return key ? { key: key, kvno: Number(prev.kvno), expiresAt: until } :
      null;
  }

  /**
   * Writes the matching record of a trust with another trust realm of this
   * service ON THAT REALM, in one act: the partner's record for this realm,
   * its incoming key this realm's outgoing and the other way round, the
   * same attributes and enctypes. Where the partner already holds a record
   * for this realm, its KEYS are made to match and nothing else is changed.
   *
   * @param partner - the partner Kerberos realm of a `trust-realm` record
   * @returns `{ ok, here, there, created, errors }`
   */
  mirror(partner: string): Json {
    const { log, realms } = this.deps;
    log.debug("Entering Krb5Trusts.mirror(). partner=" + partner);
    const existing = this.readOne(partner);
    if (!existing) {
      log.debug("Leaving Krb5Trusts.mirror(). Not held.");
      return { ok: false, errors: [{ code: 'STS-KRB-0215', message: 'this ' +
        'realm holds no trust with ' + partner }] };
    }
    const r = existing.record;
    const other = r.type === 'trust-realm' ?
      realms.get(String(r.partnerTrustRealm || '')) : null;
    if (!other) {
      log.debug("Leaving Krb5Trusts.mirror(). Not a trust realm.");
      return { ok: false, errors: [{ code: 'STS-KRB-0241', message: 'only ' +
        'a trust with another trust realm of this service can be paired ' +
        'from here; an external partner\'s administrator writes their ' +
        'side' }] };
    }
    const hereId = realms.currentId();
    const hereName = this.ourKerberosRealm();
    const asGiven = function (side: Json, secret: Json): Json {
      if (!side || !secret) {
        return null;
      }
      return typeof secret.password === 'string'
        ? { password: secret.password, kvno: side.kvno }
        : { keys: secret.keys, kvno: side.kvno };
    };
    const theirIncoming = asGiven(r.outgoing, existing.secrets.outgoing);
    const theirOutgoing = asGiven(r.incoming, existing.secrets.incoming);
    const self = this;
    const there = realms.run(other, function (): Json {
      const theirs = self.readOne(hereName);
      if (theirs) {
        const checked = self.validate({ incoming: theirIncoming,
                                        outgoing: theirOutgoing }, theirs);
        return checked.ok ? Object.assign(self.store(checked),
                                          { created: false }) : checked;
      }
      const checked = self.validate({
        partnerRealm: hereName, type: 'trust-realm',
        partnerTrustRealm: hereId,
        attributes: (r.attributes || []).slice(),
        enctypes: (r.enctypes || []).slice(),
        claimsTransformation: r.claimsTransformation,
        incoming: theirIncoming, outgoing: theirOutgoing,
        enabled: r.enabled !== false
      }, null);
      return checked.ok ? Object.assign(self.store(checked),
                                        { created: true }) : checked;
    });
    if (!there.ok) {
      log.debug("Leaving Krb5Trusts.mirror(). Refused there.");
      return there;
    }
    log.debug("Leaving Krb5Trusts.mirror(). " + (there.created ? 'Created' :
                                                'Matched') + " in " +
              other.id);
    return { ok: true, here: this.viewOf(existing), there: there.trust,
             created: !!there.created, otherRealm: other.id };
  }

  /**
   * What the console's health column says of one record, as findings:
   * `{ kind, level, text }`, `level` one of `ok`, `warn` and `bad`. `kind`
   * names the finding for a translated sentence; `text` is the English.
   *
   * @param view - a record's public view (`list()`, `get()`)
   * @returns the findings
   */
  health(view: Json): Json[] {
    const { log, realms, mode, config } = this.deps;
    log.debug("Entering Krb5Trusts.health(). " + (view && view.partnerRealm));
    const out: Json[] = [];
    const v = view || {};
    if (v.enabled === false) {
      out.push({ kind: 'disabled', level: 'bad', text: 'Disabled: it ' +
        'refers nobody and accepts nothing; its keys are kept.' });
    }
    const quarantined = (v.attributes || []).indexOf('quarantined') !== -1;
    if (!quarantined) {
      const refused = mode.requiresSidFilteringOnTrusts() &&
        !!config.value('krb5.requireSidFilteringInProduct');
      out.push(refused
        ? { kind: 'unfilteredRefused', level: 'bad', text: 'Not ' +
            'quarantined, and this realm is in product mode with ' +
            'krb5.requireSidFilteringInProduct on: the trust is not used ' +
            '(STS-KRB-0229).' }
        : { kind: 'unfiltered', level: 'warn', text: 'Not quarantined: ' +
            'SIDs of domains other than the partner\'s cross it as its ' +
            'boundary allows, and product mode will not use it while ' +
            'krb5.requireSidFilteringInProduct is on.' });
    }
    out.push(v.incoming && v.incoming.held
      ? { kind: 'incomingHeld', level: 'ok',
          params: { kvno: String(v.incoming.kvno) },
          text: 'Incoming key held ' +
          '(kvno ' + v.incoming.kvno + '): the partner\'s tickets are ' +
          'accepted.' }
      : { kind: 'incomingMissing', level: 'warn', text: 'No incoming key: ' +
          'no ticket from the partner is accepted (outbound only).' });
    if (!(v.outgoing && v.outgoing.held)) {
      out.push({ kind: 'outgoingMissing', level: 'warn', text: 'No ' +
        'outgoing key: nobody is referred to the partner (inbound only).' });
    }
    out.push((v.suffixes || []).length
      ? { kind: 'routed', level: 'ok',
          params: { suffixes: v.suffixes.join(', ') }, text: 'Routes ' +
          v.suffixes.join(', ') + '.' }
      : { kind: 'unrouted', level: 'warn', text: 'Routes no DNS suffix: ' +
          'a service name is never referred to the partner, only a realm ' +
          'named outright.' });
    if (v.type === 'trust-realm' && v.partnerTrustRealm) {
      const other = realms.get(String(v.partnerTrustRealm));
      const self = this;
      const ours = this.ourKerberosRealm();
      const theirs = other ? realms.run(other, function (): Json {
        return self.readOne(ours);
      }) : null;
      out.push(theirs
        ? { kind: 'paired', level: 'ok',
            params: { realm: String(v.partnerTrustRealm) },
            text: 'Trust realm "' +
            v.partnerTrustRealm + '" holds the matching record.' }
        : { kind: 'unpaired', level: 'warn',
            params: { realm: String(v.partnerTrustRealm) },
            text: 'Trust realm "' +
            v.partnerTrustRealm + '" holds no record for this realm: ' +
            'Pair writes it.' });
    }
    log.debug("Leaving Krb5Trusts.health(). " + out.length);
    return out;
  }

  /**
   * What an application's Kerberos delegation attributes mean across this
   * realm's trusts, for the console's *Across trusts* panel and `GET
   * /admin-api/applications?application=`: each foreign front end its
   * resource-based delegation accepts, each foreign target its classic
   * delegation names, each realm it may impersonate users of, and how its
   * unconstrained delegation meets the trusts' TGT-delegation bits.
   *
   * @param attributes - the application's attributes (arrays of strings)
   * @returns the panel
   */
  applicationAcross(attributes: Json): Json {
    const { log, config, realms } = this.deps;
    log.debug("Entering Krb5Trusts.applicationAcross().");
    const self = this;
    const ours = this.ourKerberosRealm();
    const values = function (name: string): string[] {
      const v = (attributes || {})[name];
      return (Array.isArray(v) ? v : (v === undefined || v === null ||
              v === '' ? [] : [v])).map(String);
    };
    const realmOf = function (value: string): string {
      const at = value.lastIndexOf('@');
      return at > 0 ? value.slice(at + 1) : '';
    };
    const trustState = function (realmName: string, needs: string): Json {
      // The trust a ticket from (or a referral to) `realmName` crosses:
      // the record for that realm, or the transitive one routing it.
      const direct = self.readOne(realmName);
      const hop = needs === 'incoming' ? '' : self.nextHopForRealm(realmName);
      const via = direct || (hop ? self.readOne(hop) : null) ||
        self.allRead().filter(function (read: Json): boolean {
          return (read.record.attributes || []).indexOf('non-transitive') ===
            -1 && self.inNamespace(read.record, realmName);
        })[0] || null;
      const problems: Json[] = [];
      if (!via) {
        problems.push({ kind: 'missing', params: { realm: realmName },
                        text: 'this realm holds no trust ' +
          'reaching ' + realmName });
      } else {
        const r = via.record;
        if (r.enabled === false) {
          problems.push({ kind: 'disabled',
                          params: { partner: r.partnerRealm },
                          text: 'the trust with ' +
            r.partnerRealm + ' is disabled' });
        }
        if (!r[needs]) {
          problems.push({ kind: needs === 'incoming' ? 'notAccepting' :
                          'notReferring',
            params: { partner: r.partnerRealm },
            text: 'the trust with ' + r.partnerRealm + ' holds no ' + needs +
                  ' key' });
        }
        if (!self.honoured(r)) {
          problems.push({ kind: 'unfilteredProduct',
                          params: { partner: r.partnerRealm },
                          text: 'the trust with ' +
            r.partnerRealm + ' is not quarantined, and product mode does ' +
            'not use it while krb5.requireSidFilteringInProduct is on' });
        }
      }
      return { realm: realmName, via: via ? via.record.partnerRealm : '',
               path: via ? (via.record.partnerRealm === realmName ?
                 [realmName] : [via.record.partnerRealm, realmName]) : [],
               ok: !problems.length, problems: problems };
    };
    const classicHere = !!config.value('krb5.crossRealmClassicDelegation');
    const classicThere = function (realmName: string): Json {
      const read = self.readOne(realmName);
      const other = read && read.record.type === 'trust-realm'
        ? realms.get(String(read.record.partnerTrustRealm || '')) : null;
      if (!other) {
        return null;
      }
      return !!realms.run(other, function (): unknown {
        return config.value('krb5.crossRealmClassicDelegation');
      });
    };
    const frontEnds = values('appAllowedToActOnBehalfOf')
      .filter(function (one: string): boolean {
        const realm = realmOf(one);
        return !!realm && realm !== ours;
      }).map(function (one: string): Json {
        return Object.assign({ actor: one },
                             trustState(realmOf(one), 'incoming'));
      });
    const targets = values('appAllowedToDelegateTo')
      .filter(function (one: string): boolean {
        const realm = realmOf(one);
        return !!realm && realm !== ours;
      }).map(function (one: string): Json {
        const realm = realmOf(one);
        const there = classicThere(realm);
        const state = trustState(realm, 'outgoing');
        const refused: Json[] = [];
        if (!classicHere) {
          refused.push({ kind: 'classicOffHere', text: 'classic ' +
            'delegation across realms is off in this realm ' +
            '(krb5.crossRealmClassicDelegation)' });
        }
        if (there === false) {
          refused.push({ kind: 'classicOffThere', params: { realm: realm },
                         text: 'classic ' +
            'delegation across realms is off in ' + realm });
        }
        return Object.assign({ target: one, classicRefused:
                                 refused.length > 0,
                               classicProblems: refused }, state);
      });
    const selfRealms = values('krb5S4uSelfRealm').map(function (one: string):
      Json {
      return Object.assign({ accepted: self.acceptsRealm(one) },
                           trustState(one, 'incoming'));
    });
    const unconstrained = values('krb5TrustedForDelegation')
      .some(function (one: string): boolean {
        return one === 'true' || one === 'TRUE';
      });
    const tgtTrusts = this.list().map(function (view: Json): Json {
      return { partner: view.partnerRealm,
               allowed: self.tgtDelegationAllowed(view.partnerRealm),
               attributes: view.attributes };
    });
    const foreign = values('krb5ForeignTgtDelegation')[0] || 'inherit';
    log.debug("Leaving Krb5Trusts.applicationAcross().");
    return {
      realm: ours,
      frontEnds: frontEnds,
      targets: targets,
      selfRealms: selfRealms,
      tgtDelegation: {
        unconstrained: unconstrained,
        foreignTgtDelegation: foreign,
        trusts: tgtTrusts.map(function (one: Json): Json {
          return Object.assign({}, one, {
            delivered: unconstrained && one.allowed && foreign !== 'deny'
          });
        })
      },
      choices: {
        krb5S4uSelfRealm: this.list().filter(function (view: Json): boolean {
          return !!view.incoming.held;
        }).map(function (view: Json): string {
          return view.partnerRealm;
        }),
        krb5ForeignTgtDelegation: ['inherit', 'deny']
      }
    };
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
  // A TRUST WITHOUT SID FILTERING IS NOT HONOURED IN PRODUCT (#430, rcbj's
  // decision 4): `quarantined` is on by default, and a record with it off is
  // used only where the mode does not ask for it
  // (`mode.requiresSidFilteringOnTrusts()`) or the realm turned
  // krb5.requireSidFilteringInProduct off. Asked at every use, not at the
  // write, so a realm switched to product stops using such a record at once.
  // =========================================================================
  /**
   * Says whether a trust record is honoured: SID filtering on, or not
   * required here.
   *
   * @param record - the record
   * @returns true when it may be used
   */
  honoured(record: Json): boolean {
    const { log, mode, config } = this.deps;
    log.debug("Entering Krb5Trusts.honoured().");
    const filtered = (record && record.attributes || [])
      .indexOf('quarantined') !== -1;
    const out = filtered || !mode.requiresSidFilteringOnTrusts() ||
      !config.value('krb5.requireSidFilteringInProduct');
    log.debug("Leaving Krb5Trusts.honoured(). " + out);
    return out;
  }

  // A record that may be used at all: enabled and honoured.
  private usable(record: Json): boolean {
    this.deps.log.debug("Entering Krb5Trusts.usable().");
    this.deps.log.debug("Leaving Krb5Trusts.usable().");
    return !!record && record.enabled !== false && this.honoured(record);
  }

  /**
   * Says whether this realm's trusts accept tickets from a Kerberos realm:
   * an enabled, honoured record holding an incoming key from it, or a
   * transitive one whose namespace routes it. What krb5S4uSelfRealm may
   * name (#430 Phase 3).
   *
   * @param realmName - the Kerberos realm
   * @returns true when accepted
   */
  acceptsRealm(realmName: string): boolean {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.acceptsRealm(). " + realmName);
    const self = this;
    const name = String(realmName || '');
    const out = !!name && this.allRead().some(function (read: Json): boolean {
      const r = read.record;
      if (!self.usable(r) || !r.incoming) {
        return false;
      }
      return r.partnerRealm === name ||
        ((r.attributes || []).indexOf('non-transitive') === -1 &&
         self.inNamespace(r, name));
    });
    log.debug("Leaving Krb5Trusts.acceptsRealm(). " + out);
    return out;
  }

  /**
   * The partner a request for a Kerberos REALM is referred to — S4U2Self
   * naming a user of another realm ([MS-SFU] 3.1.5.1.1.2): the enabled,
   * honoured record with an outgoing key for that realm, else a transitive
   * one whose namespace routes it, the most specific suffix winning.
   *
   * @param realmName - the realm the request is for
   * @returns the partner realm, or ''
   */
  nextHopForRealm(realmName: string): string {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.nextHopForRealm(). " + realmName);
    const self = this;
    const name = String(realmName || '');
    const domain = name.toLowerCase();
    let best = '';
    let bestLength = -1;
    this.allRead().forEach(function (read: Json): void {
      const r = read.record;
      if (!self.usable(r) || !r.outgoing) {
        return;
      }
      if (r.partnerRealm === name) {
        best = r.partnerRealm;
        bestLength = Number.MAX_SAFE_INTEGER;
        return;
      }
      if ((r.attributes || []).indexOf('non-transitive') !== -1) {
        return;
      }
      (r.suffixes || []).forEach(function (suffix: string): void {
        if ((domain === suffix || domain.endsWith('.' + suffix)) &&
            suffix.length > bestLength) {
          best = r.partnerRealm;
          bestLength = suffix.length;
        }
      });
    });
    log.debug("Leaving Krb5Trusts.nextHopForRealm(). " + (best || 'none'));
    return best;
  }

  /**
   * The facts the issuance policy reads of the trust a question arrived
   * across (#430 Phase 3): `{ partner, type, direction, attributes,
   * enabled }`, or null when this realm holds no record for the partner.
   *
   * @param partner - the partner Kerberos realm
   * @returns the facts, or null
   */
  policyFacts(partner: string): Json | null {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.policyFacts(). " + partner);
    const read = this.readOne(partner);
    if (!read) {
      log.debug("Leaving Krb5Trusts.policyFacts(). None.");
      return null;
    }
    const view = this.viewOf(read);
    log.debug("Leaving Krb5Trusts.policyFacts().");
    return { partner: view.partnerRealm, type: view.type,
             direction: view.direction, attributes: view.attributes,
             enabled: this.usable(read.record) };
  }

  /**
   * Whether a referral across the trust with a partner may carry
   * ok-as-delegate: [MS-KILE] 3.3.5.7.5's EnableConditions (within-forest,
   * enable-tgt-delegation) and none of its DisableConditions on the trust
   * (no-tgt-delegation, quarantined). The source ticket's own flag is the
   * caller's half.
   *
   * @param partner - the partner Kerberos realm
   * @returns true when the trust's attributes allow it
   */
  tgtDelegationAllowed(partner: string): boolean {
    const { log } = this.deps;
    log.debug("Entering Krb5Trusts.tgtDelegationAllowed(). " + partner);
    const read = this.readOne(partner);
    const a: string[] = read ? (read.record.attributes || []) : [];
    const out = !!read &&
      (a.indexOf('within-forest') !== -1 ||
       a.indexOf('enable-tgt-delegation') !== -1) &&
      a.indexOf('no-tgt-delegation') === -1 &&
      a.indexOf('quarantined') === -1;
    log.debug("Leaving Krb5Trusts.tgtDelegationAllowed(). " + out);
    return out;
  }

  // =========================================================================
  // SID FILTERING ON ARRIVAL, ALL OF IT (#430 Phase 2; [MS-PAC] 4.1.2.2,
  // [MS-ADTS] 6.1.6.7 and 6.1.6.9.3, [MS-ADTS] 3.1.1.11.2.11, [MS-KILE]
  // 3.3.5.7.5). kerberos/CLAUDE.md, *SID FILTERING: THE RULES*, is the
  // numbered table; each `R<n>` below is a row of it, and
  // tests/kerberos_cross_realm_delegation.js tests each row by its number.
  //
  // The TRUST BOUNDARY a record is ([MS-PAC] 4.1.2.2's first table) comes
  // from its attribute bits ([MS-ADTS] 6.1.6.7.9): see boundaryOf(). Each SID
  // a PAC asserts is classed by the pattern table — AlwaysFilter,
  // NeverFilter, EDC, ForestSpecific, a domain SID — and the class and the
  // boundary decide whether it crosses.
  // =========================================================================
  /**
   * The [MS-PAC] 4.1.2.2 trust boundary a record is.
   *
   * @param record - the trust record
   * @returns `WithinForest`, `QuarantinedWithinForest`, `CrossForest`,
   *   `External`, `QuarantinedExternal` or `PrivilegedIdentityManagement`
   */
  boundaryOf(record: Json): string {
    this.deps.log.debug("Entering Krb5Trusts.boundaryOf().");
    const a: string[] = (record && record.attributes) || [];
    const has = function (name: string): boolean {
      return a.indexOf(name) !== -1;
    };
    let out = has('quarantined') ? 'QuarantinedExternal' : 'External';
    if (has('within-forest')) {
      out = has('quarantined') ? 'QuarantinedWithinForest' : 'WithinForest';
    } else if (has('forest-transitive')) {
      // R13, R14: TREAT_AS_EXTERNAL relaxes a cross-forest trust to an
      // external one, and with PIM_TRUST beside it, to PIM.
      out = has('treat-as-external')
        ? (has('pim-trust') ? 'PrivilegedIdentityManagement' : 'External')
        : 'CrossForest';
    }
    this.deps.log.debug("Leaving Krb5Trusts.boundaryOf(). " + out);
    return out;
  }

  // [MS-PAC] 4.1.2.2's SID pattern table, as a class: `always` (R1, R4,
  // R23), `never` (R2), `edc` (R3), `forest` (ForestSpecific: a domain SID
  // with R below 1000, R5 to R7), `account` (a domain SID with R of 1000 or
  // more), with the SID's domain part for the last two. A HOT PATH — once
  // per SID per crossing PAC — so no Entering/Leaving pair here.
  private sidClass(text: string): Json {
    const parts = String(text || '').split('-');
    if (parts.length < 3 || parts[0] !== 'S' || parts[1] !== '1' ||
        !parts.slice(2).every(function (one: string): boolean {
          return /^\d+$/.test(one);
        })) {
      return { kind: 'always', why: 'invalid' };
    }
    const authority = Number(parts[2]);
    const subs = parts.slice(3).map(Number);
    if (authority === 0 || authority === 1 || authority === 2 ||
        authority === 3 || (authority >= 6 && authority <= 9)) {
      return { kind: 'always', why: 'well-known' };
    }
    if (authority === 4 || authority === 10) {
      return { kind: 'never' };
    }
    // UNCERTAIN (kerberos/CLAUDE.md, R2): S-1-18 (the authentication
    // authority asserted identities, [MS-DTYP] 2.4.2.4) is in no row of the
    // table, which predates it; it says how an identity was established and
    // is kept.
    if (authority === 18) {
      return { kind: 'never' };
    }
    if (authority !== 5) {
      return { kind: 'always', why: 'unlisted authority' };
    }
    if (!subs.length) {
      return { kind: 'always', why: 'NT Authority' };
    }
    const first = subs[0];
    if (first === 9 && subs.length === 1) {
      return { kind: 'edc' };
    }
    if (first === 15 && subs.length === 1) {
      return { kind: 'never' };
    }
    if (first === 21) {
      if (subs.length === 5 && subs[1] === 0 && subs[2] === 0 &&
          subs[3] === 0 && (subs[4] === 496 || subs[4] === 497)) {
        return { kind: 'never' };
      }
      if (subs.length !== 5) {
        // R4: S-1-5-21, partially formed, a domain itself, or too many RIDs.
        return { kind: 'always', why: 'not a principal of a domain' };
      }
      const domain = 'S-1-5-21-' + subs.slice(1, 4).join('-');
      return { kind: subs[4] < 1000 ? 'forest' : 'account', domain: domain,
               rid: subs[4] };
    }
    if (first === 1000) {
      return { kind: 'never' };
    }
    if (first > 1000) {
      return { kind: 'never' };
    }
    return { kind: 'always', why: 'reserved' };
  }

  /**
   * Filters a PAC that arrived through the trust with a partner: every row
   * of kerberos/CLAUDE.md's *SID FILTERING: THE RULES*.
   *
   * A PAC it changed writes ONE AUDIT ROW, `krb5.trust.sid-filtered`
   * (rcbj, 2026-10-19): the per-event record is the audit log, so the trust,
   * the principal and the SIDs removed or added are there, and the service
   * log has a debug line at most.
   *
   * @param pacBytes - the PAC
   * @param partner - the partner the ticket arrived from
   * @param localSid - this realm's own domain SID
   * @param principal - who the ticket is for, `name@REALM`, for the audit
   *   row; the PAC's own logon name and domain when not given
   * @returns `{ bytes, removed, refused, boundary, sids }` — `refused` a
   *   sentence when the PAC may not cross at all (R8, R17), else ''; `sids`
   *   every SID the PAC carries once filtered (the user's, its groups', its
   *   extra SIDs and resource groups), which is what a role may be granted to
   *   across a trust (`common/roles.js`)
   */
  sidFilter(pacBytes: Uint8Array, partner: string,
            localSid: string, principal?: string): Json {
    const { log, kpac } = this.deps;
    log.debug("Entering Krb5Trusts.sidFilter(). " + partner);
    const self = this;
    const read = this.readOne(partner);
    const record = read ? read.record : { attributes: ['quarantined'] };
    const boundary = this.boundaryOf(record);
    const partnerSid = String(record.partnerSid || '');
    // THIS REALM'S FOREST (R9): its own domain and the domains it trusts
    // WITHIN the forest.
    const localForest = [String(localSid || '')].concat(this.allRead()
      .filter(function (one: Json): boolean {
        return (one.record.attributes || []).indexOf('within-forest') !== -1 &&
               !!one.record.partnerSid;
      }).map(function (one: Json): string {
        return String(one.record.partnerSid);
      })).filter(Boolean);
    // THE TRUSTED FOREST'S DOMAINS (R12): the forest trust information's
    // domains whose SID matching is not disabled ([MS-ADTS] 6.1.6.9.3.1,
    // LSA_SID_DISABLED_ADMIN and _CONFLICT), else the partner's own domain.
    const ftDomains = ((record.forestTrustInfo || {}).domains || [])
      .filter(function (one: Json): boolean {
        return one.sidEnabled !== false;
      }).map(function (one: Json): string {
        return String(one.sid);
      });
    const trustedForestDomains = ftDomains.length ? ftDomains :
      (partnerSid ? [partnerSid] : []);
    const pac = kpac.parsePac(pacBytes);
    const buffer = kpac.bufferOfType(pac, kpac.TYPE.LOGON_INFO);
    const info = buffer ? buffer.parsed : null;
    if (!info) {
      log.debug("Leaving Krb5Trusts.sidFilter(). No logon information.");
      return { bytes: pacBytes, removed: [], refused: '',
               boundary: boundary };
    }
    const sidText = function (sid: Json): string {
      return sid ? String(sid.text || sid) : '';
    };
    const logonDomain = sidText(info.logonDomainId);
    // EVERY SID THE PAC CARRIES once filtered: the user's and its groups'
    // (LogonDomainId-RID, which no rule filters), the extra SIDs and the
    // resource groups that were kept.
    const carriedSids = function (extra: Json[], resources: Json[],
                                  resourceDomainSid: string): string[] {
      const out: string[] = [];
      const add = function (one: string): void {
        if (one && out.indexOf(one) === -1) {
          out.push(one);
        }
      };
      if (logonDomain) {
        add(logonDomain + '-' + info.userId);
        add(logonDomain + '-' + info.primaryGroupId);
        (info.groups || []).forEach(function (g: Json): void {
          add(logonDomain + '-' + g.relativeId);
        });
      }
      (extra || []).forEach(function (one: Json): void {
        add(sidText(one.sid));
      });
      if (resourceDomainSid) {
        (resources || []).forEach(function (g: Json): void {
          add(resourceDomainSid + '-' + g.relativeId);
        });
      }
      return out;
    };
    // R8: across a CrossForest or External boundary, a PAC whose logon
    // domain is in this realm's forest is invalid authorization data.
    if ((boundary === 'CrossForest' || boundary === 'External' ||
         boundary === 'QuarantinedExternal') &&
        localForest.indexOf(logonDomain) !== -1) {
      log.debug("Leaving Krb5Trusts.sidFilter(). R8.");
      return { bytes: pacBytes, removed: [], boundary: boundary,
               refused: 'R8: the PAC\'s logon domain ' + logonDomain +
                 ' is in this realm\'s forest, and it arrived across the ' +
                 boundary + ' trust with ' + partner +
                 ' ([MS-PAC] 4.1.2.2, DomainSpecific)' };
    }
    // R17: a quarantined boundary passes only its trusted domain's
    // principals; a USER of another domain cannot have their own SID
    // filtered without the PAC naming nobody, so the PAC does not cross.
    // UNCERTAIN: the specification filters SIDs and says nothing of the
    // user's own.
    if ((boundary === 'QuarantinedExternal' ||
         boundary === 'QuarantinedWithinForest') && partnerSid &&
        logonDomain !== partnerSid) {
      log.debug("Leaving Krb5Trusts.sidFilter(). R17.");
      return { bytes: pacBytes, removed: [], boundary: boundary,
               refused: 'R17: the user\'s domain ' + logonDomain + ' is not ' +
                 'the trusted domain ' + partnerSid + ' of the quarantined ' +
                 'trust with ' + partner };
    }
    if (boundary === 'CrossForest' && logonDomain &&
        trustedForestDomains.indexOf(logonDomain) === -1) {
      log.debug("Leaving Krb5Trusts.sidFilter(). R17 (forest).");
      return { bytes: pacBytes, removed: [], boundary: boundary,
               refused: 'R17: the user\'s domain ' + logonDomain + ' is not ' +
                 'among the trusted forest\'s domains (forest trust ' +
                 'information) of the trust with ' + partner };
    }
    // ONE SID: kept or not, at this boundary. R1-R16.
    const keeps = function (text: string): boolean {
      const c = self.sidClass(text);
      if (c.kind === 'always') {
        return false;                                         // R1, R4, R23
      }
      if (c.kind === 'never') {
        return true;                                          // R2
      }
      if (c.kind === 'edc') {                                 // R3, R11, R14
        return boundary === 'WithinForest' ||
               boundary === 'QuarantinedWithinForest';
      }
      if (c.domain === localSid && c.kind === 'forest') {
        return false;                                         // R6
      }
      if (c.kind === 'forest' && c.domain !== logonDomain) {
        return false;                                         // R7
      }
      if (c.kind === 'forest' && boundary !== 'WithinForest' &&
          boundary !== 'PrivilegedIdentityManagement' &&
          c.domain !== partnerSid &&
          !(boundary === 'CrossForest' &&
            trustedForestDomains.indexOf(c.domain) !== -1)) {
        return false;                                         // R5
      }
      if (localForest.indexOf(c.domain) !== -1 &&             // R9, R14
          (boundary === 'CrossForest' || boundary === 'External' ||
           boundary === 'QuarantinedExternal')) {
        return false;
      }
      if (boundary === 'QuarantinedExternal' ||               // R10, R11
          boundary === 'QuarantinedWithinForest') {
        return c.domain === partnerSid;
      }
      if (boundary === 'CrossForest') {                       // R12
        return trustedForestDomains.indexOf(c.domain) !== -1;
      }
      return true;                                            // R13, R15
    };
    const removed: string[] = [];
    let keptSids = (info.extraSids || []).filter(function (one: Json):
      boolean {
      const text = sidText(one.sid);
      const kept = keeps(text);
      if (!kept) {
        removed.push(text);
      }
      return kept;
    }).map(function (one: Json): Json {
      return { sid: one.sid, attributes: one.attributes };
    });
    // R24: CROSS_ORGANIZATION adds OTHER_ORGANIZATION ([MS-KILE] 3.3.5.7.5).
    const added: string[] = [];
    if ((record.attributes || []).indexOf('cross-organization') !== -1 &&
        !keptSids.some(function (one: Json): boolean {
          return sidText(one.sid) === 'S-1-5-1000';
        })) {
      keptSids = keptSids.concat([{ sid: 'S-1-5-1000',
                                    attributes: 0x00000007 }]);
      added.push('S-1-5-1000');
    }
    // R16: each resource group is the SID ResourceGroupDomainSid-RID, and
    // crosses as that SID would.
    const resourceDomain = sidText(info.resourceGroupDomainSid);
    const keptResources = (info.resourceGroups || []).filter(function (g:
      Json): boolean {
      const text = resourceDomain + '-' + g.relativeId;
      const kept = !!resourceDomain && keeps(text);
      if (!kept) {
        removed.push(text);
      }
      return kept;
    });
    // R18, R19: device information, and claims ([MS-ADTS] 3.1.1.11.2.11 —
    // an incoming direction with no transformation policy carries none).
    const claimsPolicy = String(record.claimsTransformation || 'drop-all');
    const droppedBuffers: number[] = [];
    pac.buffers.forEach(function (b: Json): void {
      if (b.type === kpac.TYPE.DEVICE_INFO) {
        droppedBuffers.push(b.type);
      }
      if ((b.type === kpac.TYPE.CLIENT_CLAIMS ||
           b.type === kpac.TYPE.DEVICE_CLAIMS) &&
          claimsPolicy !== 'allow-all') {
        droppedBuffers.push(b.type);
      }
    });
    const sids = carriedSids(keptSids, keptResources, resourceDomain);
    if (!removed.length && !added.length && !droppedBuffers.length) {
      log.debug("Leaving Krb5Trusts.sidFilter(). Nothing to change.");
      return { bytes: pacBytes, removed: [], refused: '',
               boundary: boundary, sids: sids };
    }
    const time = function (ft: Json): Json {
      return !ft ? null : (ft.never ? 'never' : (ft.unset ? null : ft.date));
    };
    const extraFlag = kpac.USER_FLAG_EXTRA_SIDS;
    const resourceFlag = kpac.USER_FLAG_RESOURCE_GROUPS;
    const logonBytes = kpac.encodeLogonInfo({
      logonTime: time(info.logonTime), logoffTime: time(info.logoffTime),
      kickOffTime: time(info.kickOffTime),
      passwordLastSet: time(info.passwordLastSet),
      passwordCanChange: time(info.passwordCanChange),
      passwordMustChange: time(info.passwordMustChange),
      effectiveName: info.effectiveName, fullName: info.fullName,
      logonScript: info.logonScript, profilePath: info.profilePath,
      homeDirectory: info.homeDirectory,
      homeDirectoryDrive: info.homeDirectoryDrive,
      logonCount: info.logonCount, badPasswordCount: info.badPasswordCount,
      userId: info.userId, primaryGroupId: info.primaryGroupId,
      groups: (info.groups || []).map(function (g: Json): Json {
        return { relativeId: g.relativeId, attributes: g.attributes };
      }),
      userFlags: (info.userFlags & ~(extraFlag | resourceFlag)) |
        (keptSids.length ? extraFlag : 0) |
        (keptResources.length ? resourceFlag : 0),
      userSessionKey: info.userSessionKey,
      logonServer: info.logonServer, logonDomainName: info.logonDomainName,
      logonDomainId: info.logonDomainId,
      userAccountControl: info.userAccountControl,
      subAuthStatus: info.subAuthStatus,
      lastSuccessfulILogon: time(info.lastSuccessfulILogon),
      lastFailedILogon: time(info.lastFailedILogon),
      failedILogonCount: info.failedILogonCount,
      extraSids: keptSids,
      resourceGroupDomainSid: keptResources.length ?
        info.resourceGroupDomainSid : null,
      resourceGroups: keptResources.map(function (g: Json): Json {
        return { relativeId: g.relativeId, attributes: g.attributes };
      })
    });
    const entries = pac.buffers.filter(function (b: Json): boolean {
      return !!b.bytes && droppedBuffers.indexOf(b.type) === -1;
    }).map(function (b: Json): Json {
      return { type: b.type, bytes: b.type === kpac.TYPE.LOGON_INFO ?
        logonBytes : b.bytes };
    });
    const bytes = kpac.assemblePac(entries).bytes;
    this.recordFiltered(partner, boundary, principal ||
      (String(info.effectiveName || '') +
       (info.logonDomainName ? '@' + String(info.logonDomainName) : '')),
      removed, added, droppedBuffers);
    log.debug("Leaving Krb5Trusts.sidFilter(). " + removed.length +
              " removed.");
    return { bytes: bytes, removed: removed, added: added,
             droppedBuffers: droppedBuffers, refused: '',
             boundary: boundary, sids: sids };
  }

  // THE AUDIT ROW FOR A FILTERED TICKET (rcbj, 2026-10-19): it was an info
  // line per ticket in the service log, which is the per-event record this
  // service keeps in the audit log instead (`common/audit.js`; the
  // no-per-event-failure-logs rule). The trust, the principal and the SIDs —
  // identifiers a PAC carries in the clear to every service it reaches — and
  // never a key. Recording never fails the ticket: audit.audit() swallows.
  private recordFiltered(partner: string, boundary: string,
                         principal: string, removed: string[],
                         added: string[], dropped: number[]): void {
    const { log, realms } = this.deps;
    log.debug("Entering Krb5Trusts.recordFiltered(). " + partner);
    let auditLog: Json = null;
    try {
      auditLog = this.deps.audit();
    } catch (e) {
      log.debug("Caught in Krb5Trusts.recordFiltered(): " +
                ((e && e.message) || e));
      auditLog = null;
    }
    if (!auditLog || typeof auditLog.audit !== 'function') {
      log.debug("Leaving Krb5Trusts.recordFiltered(). No audit log.");
      return;
    }
    auditLog.audit({
      action: 'krb5.trust.sid-filtered', protocol: 'Kerberos',
      channel: 'kerberos', actor: principal, target: partner,
      summary: 'SID filtering on a ticket for ' + (principal || '?') +
               ' that crossed the trust with ' + partner + ' (' + boundary +
               ' boundary)' +
               (removed.length ? ': removed ' + removed.join(', ') : '') +
               (added.length ? '; added ' + added.join(', ') : '') +
               (dropped.length ? '; dropped PAC buffer(s) of type ' +
                 dropped.join(', ') : '') + '.',
      detail: { trust: partner, trustRealm: realms.currentId(),
                boundary: boundary, principal: principal,
                removed: removed.join(' '), added: added.join(' '),
                droppedBuffers: dropped.join(' ') }
    });
    log.debug("Leaving Krb5Trusts.recordFiltered().");
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
    const self = this;
    this.allRead().forEach(function (read: Json): void {
      const r = read.record;
      if (!self.usable(r) || !r.outgoing) {
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
    if (!this.honoured(read.record)) {
      log.debug("Leaving Krb5Trusts.unavailableReason(). Not honoured.");
      return 'the trust with ' + which.partner + ' has SID filtering off ' +
             '(quarantined is not set), which product mode does not honour ' +
             'while krb5.requireSidFilteringInProduct is on';
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
    if (!read || !this.usable(read.record) || !side || !secret) {
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
    if (!record || !this.usable(record) || !record.incoming) {
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
  pathProblem: slot.forward('pathProblem'),
  honoured: slot.forward('honoured'),
  acceptsRealm: slot.forward('acceptsRealm'),
  nextHopForRealm: slot.forward('nextHopForRealm'),
  policyFacts: slot.forward('policyFacts'),
  tgtDelegationAllowed: slot.forward('tgtDelegationAllowed'),
  sidFilter: slot.forward('sidFilter'),
  boundaryOf: slot.forward('boundaryOf'),
  rotateKey: slot.forward('rotateKey'),
  previousKey: slot.forward('previousKey'),
  graceSeconds: slot.forward('graceSeconds'),
  mirror: slot.forward('mirror'),
  health: slot.forward('health'),
  applicationAcross: slot.forward('applicationAcross'),
  CONTRADICTIONS: CONTRADICTIONS,
  REQUIRES: REQUIRES,
  DEFAULT_ATTRIBUTES: DEFAULT_ATTRIBUTES,
  DEFAULT_ENCTYPES: DEFAULT_ENCTYPES,
  CLAIMS_TRANSFORMATIONS: CLAIMS_TRANSFORMATIONS
};
