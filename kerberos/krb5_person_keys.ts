'use strict';
//
// File: krb5_person_keys.ts
//
// ===========================================================================
// STORED KERBEROS LONG-TERM KEYS: A DIRECTORY PERSON'S, AND A SERVICE
// PRINCIPAL'S (2026-09-12).
//
// A PRODUCT-MODE KDC AUTHENTICATED NOBODY UNTIL THIS FILE, and the reason was
// structural rather than an omission. Development keys every user from ONE
// shared password (`krb5.userPassword`) and creates accounts on demand; product
// mode turns both off, and what it has instead is a person's REAL password —
// stored as a scrypt hash on their directory entry by `common/credentials.ts`.
// A Kerberos key is RFC 3961's string-to-key over the PLAINTEXT and a salt, and
// no key can be derived from a hash. So there were no keys, and there was no
// account a person could use.
//
// THE DESIGN IS ONE SENTENCE: **DERIVE THE KEYS AT THE MOMENTS A PLAINTEXT
// PASSWORD IS IN HAND, AND STORE THEM ON THE PERSON'S OWN ENTRY.** There are
// exactly two such moments and `credentials.js` reports both through its
// password observer (rule 3e, argued there):
//
//   * the password is SET — the console, `/admin-api`, the portal's form, an
//     activation link, the product-mode bootstrap. The keys REPLACE any held
//     and the kvno moves up by one, so an AS-REQ with the old password fails
//     pre-authentication.
//   * the password is VERIFIED — the sign-in screen, an LDAP bind, SCIM Basic,
//     a WS-Trust UsernameToken, SSF Basic, the password grant. This is the
//     UPGRADE PATH for everybody who had a password before this file existed:
//     their first sign-in anywhere derives their keys. It derives only when the
//     keys are missing, cover fewer enctypes than `krb5.enctypes`, or were made
//     from a password the entry no longer holds.
//
// ---------------------------------------------------------------------------
// THE WINDOW, SAID RATHER THAN DISCOVERED.
//
// `setPassword()` and `verify()` are synchronous and RFC 3961 string-to-key is
// not — it is PBKDF2 through Web Crypto, 4096 iterations for the SHA-1 AES
// profiles and 32768 for RFC 8009's — so the derivation is kicked off AFTER the
// act and runs on its own. **A PASSWORD SET NOW HAS NO KEYS FOR A FEW TENS OF
// MILLISECONDS**, and in that window the KDC refuses the person with "sign in
// once" rather than accepting anything. The window can never be the dangerous
// way round: the keys carry a STAMP of the password hash they were derived
// beside, and the KDC refuses keys whose stamp is not the entry's current hash
// — so a key made from an OLD password is never used after the password
// changes, however the change arrived. An LDAP modify of `userPassword`
// included, which never passes through the observer at all and is caught by the
// stamp at the next AS-REQ and repaired at the next sign-in.
//
// A derivation that FAILS is logged and audited (`STS-KRB-0107`) and changes
// nothing about the act it observed: a sign-in is never delayed and never
// refused because a key could not be made.
//
// The plaintext is held by the closure of that one derivation and nowhere
// else, and is dropped when it settles. A JavaScript string cannot be wiped —
// `common/keystore.js` says the same thing about a decrypted signing key — so
// the claim is about the window, not about memory.
//
// ---------------------------------------------------------------------------
// WHERE THE KEYS LIVE, AND WHY TWO ATTRIBUTES RATHER THAN ONE PER ENCTYPE.
//
// On a person: `stsKrb5Keys` and `stsKrb5KeyInfo`. On a service principal's
// application entry under `ou=applications`: `krb5ServiceKeys` and
// `krb5ServiceKeyInfo`. The first of each pair is ONE value — a JSON document
// carrying the NAME, the REALM, the KVNO, the password STAMP and every
// enctype's key — SEALED as a whole under the key-encryption key wherever that
// key outlives the process (`keystore.persists()`, which is
// `writeTotpRecord()`'s rule and for its reason: development's key is
// ephemeral, and a directory attribute sealed under it is permanent garbage
// after a restart).
//
// **ONE SEALED VALUE IS THE SECURITY OF THE STORAGE.** The authentication tag
// covers the name and the stamp beside the keys, so a sealed value copied onto
// somebody else's entry names the wrong person, and one copied back after a
// password change carries the wrong stamp — both are refused by the reader.
// One value per enctype could have been spliced. In product mode a CLEAR value
// is refused outright, so an `ldapmodify` cannot plant a key it chose.
//
// The second of each pair is PUBLIC — the kvno, the enctypes, when, and how —
// so every page listing principals can say what is held without opening a key.
//
// ---------------------------------------------------------------------------
// WHICH TRUST REALM: THE AMBIENT ONE, SINCE 2026-09-15.
//
// This read *the KDC answers in no trust realm, so this file reads and writes
// the DEFAULT trust realm's directory* — pinned there by `ldap_server.js`'s
// slot — and *a password set or verified inside another trust realm derives
// NOTHING*. Both halves are gone: a trust realm whose Kerberos is on has a
// Kerberos realm and a principal database of its own, so a person in THAT
// realm's directory is a principal of THAT realm's KDC, and their keys belong
// on their own entry in their own realm.
//
// So every function here works in the AMBIENT realm — the realm a password was
// set in, or the realm the KDC entered for the request it is answering — and
// `principals.REALM` answers for that realm. What decides whether keys are
// derived at all is no longer "is this the default realm" but
// `principals.enabledIn()`: a realm with no KDC has nothing to hold keys for,
// which is the same sentence the old rule made about every realm but one.
//
// ---------------------------------------------------------------------------
// SERVICE PRINCIPALS, AND THE ONE TIME A KEY LEAVES THIS SERVICE.
//
// A service does not type a password. An operator creates one at
// `/admin/kerberos/principals` (or `POST /admin-api/kerberos/principals/
// create-service`), this file makes a RANDOM key per enctype, stores it sealed
// on the application entry for `<spn>@<realm>`, and hands back an MIT keytab
// (`krb5_keytab.ts`) — ONCE, as the answer to that request. Nothing reads a
// key back out afterwards; a service that has lost its keytab is ROTATED, which
// adds one to the kvno and hands over a new keytab carrying the previous kvno
// too, and tickets issued under the old key go on being accepted until they
// could have expired (PREVIOUS KEY VERSIONS, below) and are then refused
// KRB_AP_ERR_BADKEYVER. The KDC and
// this service's own acceptor prefer a stored key over one built from
// `krb5.servicePassword`, so the acceptor's SPN can be given a real keytab too.
//
// ---------------------------------------------------------------------------
// WHAT IT REQUIRES, AND WHAT IT MUST NOT BE REQUIRED BY.
//
// A LIBRARY (rule 3): it registers no route. It requires the principal
// database, the codec, the keytab writer and eight `common/` libraries —
// none of which requires it back. Two slots point INTO it and two OUT of it:
//
//   * `credentials.setPasswordObserver()` and `principals.setKeySource()` are
//     filled HERE, at require time. See each for its rule-3e argument.
//   * `setDirectory()` is filled by `ldap/ldap_server.js`, for the reason every
//     directory slot in this service is.
//
// **IT IS REACHABLE FROM NONE OF `krb5_kdc.js`, `krb5_service.js` AND
// `spnego.js`**, which is what leaves the parent project's `tests/Dockerfile`
// COPY set exactly as it was: the principal database reaches it only through a
// slot, and the modules that require it are `ldap/ldap_server.js` and the two
// `admin-core/` halves.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape:
//
//   * **`Krb5PersonKeys` TAKES EVERY MODULE IT USES THROUGH ITS CONSTRUCTOR**
//     (`Krb5PersonKeysDeps`): the logger, the settings, the realm registry,
//     the key store, the credential store, the application registry, the
//     audit log, the error codes, the Kerberos codec and principal database
//     (both locked, JavaScript, and required as they were), the keytab writer
//     and node's `crypto`. The principal database is typed by what this file
//     reads of it, because several of those members are getters its
//     `module.exports` gains after the object literal.
//   * **THE DIRECTORY SLOT IS STATE OF THE INSTANCE**; the in-flight
//     derivations stay a module-level `Map`, declared as it was.
//   * **THE TWO SLOTS THIS FILE FILLS** are filled by `installSlots()`, which
//     `Krb5PersonKeys.wire()` calls when the instance is installed (#50, R2):
//     the composition root builds the instance, and a process without the
//     root builds a default, and wires it, at load, where the original filled
//     them. The module still exports every old name, as a FACADE forwarding
//     to that one instance; `Krb5PersonKeys` is exported beside them for that
//     root.
//   * **THE CODEC REQUIRES ARE EXTENSIONLESS NOW** (`./krb5_crypto`), which
//     resolves to the same files.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import keystore = require('../common/keystore');
import credentials = require('../common/credentials');
import applications = require('../common/applications');
import audit = require('../common/audit');
import errorCodes = require('../common/error_codes');
import kcrypto = require('./krb5_crypto');
import prim = require('./krb5_primitives');
import principals = require('./krb5_principals');
import keytab = require('./krb5_keytab');
// FAST, OTP PRE-AUTHENTICATION AND AUTHENTICATION INDICATORS (#173). Built
// here and handed to the KDC INSIDE the key source, so `krb5_kdc.js` reaches
// it through the slot it already reads and gains no require (see
// `installSlots()`).
import Krb5Fast = require('./krb5_fast');

// A stored record, an info value, a directory row: JSON this file wrote.
type Json = any;

// The six hooks `ldap/ldap_server.js` installs through `setDirectory()`.
interface DirectoryHooks {
  readPerson(name: string): Json;
  writePerson(name: string, keys: string | null,
              info: string | null): boolean;
  personKeyInfos(): Json[];
  readService(identifier: string): Json;
  writeService(identifier: string, keys: string | null,
               info: string | null): boolean;
  serviceKeyInfos(): Json[];
}

// What this file reads of the (locked, JavaScript) principal database.
interface PrincipalDatabase {
  readonly REALM: string;
  readonly KDC_ETYPES: number[];
  readonly seedsDemoPrincipals: boolean;
  readonly KVNO: number;
  // Whether this realm's krbtgt is derived from krb5.krbtgtPassword (#169).
  readonly krbtgtFromPassword: boolean;
  userSalt(realm: string, name: string): string;
  enabledIn(realmId: string): boolean;
  kerberosRealmOf(realmId?: string): Json;
  find(name: string[], realm?: string): Json;
  longTermKey(principal: Json, etype: number): Promise<Uint8Array>;
  setKeySource?(source: {
    personKeys(name: string): Json;
    serviceKeys(spn: string): Json;
    krbtgtKeys?(): Json;
    personDisabled?(name: string): boolean;
    personSecondFactor?(name: string): Json;
    fast?: Krb5Fast;
  }): unknown;
}

// What this file reads of the credential store.
interface CredentialStore {
  setPasswordObserver?(fn: (name: string, password: string,
                            info?: Json) => void): unknown;
  secondFactorDemand?(name: string): Json;
}

// What `openRecord()` answers.
interface Opened {
  ok: boolean;
  record?: Json;
  why?: string;
}

// Who asked for an act, for the audit row.
interface ActContext {
  actor?: unknown;
  via?: unknown;
}

interface Krb5PersonKeysDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  keystore: typeof keystore;
  credentials: CredentialStore;
  applications: typeof applications;
  audit: typeof audit;
  errorCodes: typeof errorCodes;
  kcrypto: Json;
  prim: Json;
  principals: PrincipalDatabase;
  keytab: typeof keytab;
  nodeCrypto: typeof nodeCrypto;
  fast: Krb5Fast;
  // LAZILY, each (#169): the claim a cluster's first krbtgt key is made
  // under, and the store it is made against. Both load after this module in
  // the composition root, and neither is wanted by a process with no store.
  claims: () => Json;
  persistence: () => Json;
}

// What `keystore.seal()` counts these under, for `/admin/encryption`.
const SEAL_LABEL = 'kerberos-keys';

const PERSON_KEYS_ATTRIBUTE = 'stsKrb5Keys';
const PERSON_INFO_ATTRIBUTE = 'stsKrb5KeyInfo';
const SERVICE_KEYS_ATTRIBUTE = 'krb5ServiceKeys';
const SERVICE_INFO_ATTRIBUTE = 'krb5ServiceKeyInfo';

// The two that are never drawn anywhere, ciphertext included. `ldap_server.js`
// withholds them from the directory dump and from an LDAP search, and
// `applications.js` from every application view.
const WITHHELD_ATTRIBUTES = [PERSON_KEYS_ATTRIBUTE, SERVICE_KEYS_ATTRIBUTE];

// The record format, so that a value written by a later shape is refused by
// name rather than read wrongly.
const RECORD_VERSION = 1;

// ---------------------------------------------------------------------------
// THE DERIVATION's queues — see `observePassword()`.
//
// KEYED BY REALM AND NAME SINCE 2026-09-15. It was the name alone, which was
// one queue per person while there was one KDC; with a KDC per trust realm the
// same username exists in several realms as several people, and a derivation
// for one would serialise behind — and be waited on by — another realm's.
// ---------------------------------------------------------------------------
const inFlight: Map<string, Promise<unknown>> = new Map();

// THE KRBTGT CREATIONS IN FLIGHT, per trust realm (#169) — see
// `ensureKrbtgtKey()`. Bounded by the realms, like the queue above.
const krbtgtInFlight: Map<string, Promise<Json>> = new Map();

// The realms whose unreadable krbtgt record has been reported, so a KDC asking
// on every request says it ONCE per process (bounded by the realms).
const krbtgtUnreadableSaid: Set<string> = new Set();

// How long a node holds the right to make a realm's first krbtgt key.
const KRBTGT_CREATE_CLAIM_MS = 60000;

class Krb5PersonKeys {
  static readonly SEAL_LABEL = SEAL_LABEL;
  static readonly PERSON_KEYS_ATTRIBUTE = PERSON_KEYS_ATTRIBUTE;
  static readonly PERSON_INFO_ATTRIBUTE = PERSON_INFO_ATTRIBUTE;
  static readonly SERVICE_KEYS_ATTRIBUTE = SERVICE_KEYS_ATTRIBUTE;
  static readonly SERVICE_INFO_ATTRIBUTE = SERVICE_INFO_ATTRIBUTE;
  static readonly ATTRIBUTES = [PERSON_KEYS_ATTRIBUTE, PERSON_INFO_ATTRIBUTE];
  static readonly WITHHELD_ATTRIBUTES = WITHHELD_ATTRIBUTES;
  static readonly RECORD_VERSION = RECORD_VERSION;

  private directory: DirectoryHooks | null = null;

  constructor(private readonly deps: Krb5PersonKeysDeps) {
    deps.log.debug("Entering Krb5PersonKeys.constructor().");
    deps.log.debug("Leaving Krb5PersonKeys.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  static defaultDeps(): Krb5PersonKeysDeps {
    helpers.log.debug("Entering Krb5PersonKeys.defaultDeps().");
    helpers.log.debug("Leaving Krb5PersonKeys.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      realms: realms,
      keystore: keystore,
      credentials: credentials as CredentialStore,
      applications: applications,
      audit: audit,
      errorCodes: errorCodes,
      kcrypto: kcrypto,
      prim: prim,
      principals: principals as unknown as PrincipalDatabase,
      keytab: keytab,
      nodeCrypto: nodeCrypto,
      fast: new Krb5Fast(Krb5Fast.defaultDeps()),
      claims: function (): Json {
        return require('../cluster/cluster_claims');
      },
      persistence: function (): Json {
        return require('../persistence/persistence');
      }
    };
  }

  // What loading this module did with its instance before #50's R2, now
  // done by the slot for whichever instance is installed: its two slot fills.
  static wire(instance: Krb5PersonKeys): void {
    helpers.log.debug("Entering Krb5PersonKeys.wire().");
    instance.installSlots();
    helpers.log.debug("Leaving Krb5PersonKeys.wire().");
  }

  setDirectory(hooks: DirectoryHooks | null): boolean {
    const { log, errorCodes } = this.deps;
    log.debug('Entering Krb5PersonKeys.setDirectory().');
    if (hooks === null) {
      // CLEARED, which only a test does: `tests/CLAUDE.md`'s rule is that a
      // slot somebody stubbed is put back to what was there, and in a process
      // that never loaded the directory what was there is nothing.
      this.directory = null;
      log.debug('Leaving Krb5PersonKeys.setDirectory(). Cleared.');
      return true;
    }
    const needed = ['readPerson', 'writePerson', 'personKeyInfos',
                    'readService', 'writeService', 'serviceKeyInfos'];
    const missing = needed.filter(function (name) {
      return !hooks || typeof hooks[name] !== 'function';
    });
    if (missing.length) {
      // WHOLE, for `admin.js`'s `setLogoutReader()` reason: a register that
      // could read people and not write them would derive keys it could never
      // store, on every sign-in, for ever.
      log.error(errorCodes.tag('STS-KRB-0110') +
                'krb5-keys: setDirectory() was given something without ' +
                missing.join(', ') + ', so it was refused whole. No person ' +
                'will get Kerberos keys and no service principal can be ' +
                'stored.');
      log.debug('Leaving Krb5PersonKeys.setDirectory(). Refused.');
      return false;
    }
    this.directory = hooks;
    log.debug('Leaving Krb5PersonKeys.setDirectory(). Installed.');
    return true;
  }

  installed(): boolean {
    const { log } = this.deps;
    log.debug("Entering Krb5PersonKeys.installed().");
    log.debug("Leaving Krb5PersonKeys.installed().");
    return !!this.directory;
  }

  // What is installed, so a test that stubs the slot can put back exactly
  // that.
  currentDirectory(): DirectoryHooks | null {
    const { log } = this.deps;
    log.debug("Entering Krb5PersonKeys.currentDirectory().");
    log.debug("Leaving Krb5PersonKeys.currentDirectory().");
    return this.directory;
  }

  // Whether the AMBIENT trust realm's KDC is a product one — decided when that
  // realm's principal database was built, which is the only mode its KDC
  // answers in.
  productKdc(): boolean {
    const { log, principals } = this.deps;
    log.debug("Entering Krb5PersonKeys.productKdc().");
    log.debug("Leaving Krb5PersonKeys.productKdc().");
    return !principals.seedsDemoPrincipals;
  }

  personKeysEnabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering Krb5PersonKeys.personKeysEnabled().");
    log.debug("Leaving Krb5PersonKeys.personKeysEnabled().");
    return config.value('krb5.personKeys') !== false;
  }

  // A short, one-way fingerprint of the STORED password hash. It is what binds
  // a set of keys to the password they were derived beside: the hash changes
  // on every password set (scrypt salts it), so a stamp that no longer matches
  // is a key made from a password the person no longer has. Not a secret — it
  // is a digest of a digest — but it is only ever TRUSTED from inside the
  // seal.
  stampOf(storedHash: unknown): string {
    const { log, nodeCrypto } = this.deps;
    log.debug("Entering Krb5PersonKeys.stampOf().");
    log.debug("Leaving Krb5PersonKeys.stampOf().");
    return nodeCrypto.createHash('sha256').update(String(storedHash || ''))
      .digest('hex').slice(0, 32);
  }

  private saltFor(name: string): string {
    const { log, principals } = this.deps;
    log.debug("Entering Krb5PersonKeys.saltFor().");
    log.debug("Leaving Krb5PersonKeys.saltFor().");
    return principals.userSalt(principals.REALM, name);
  }

  // A principal name this file will key: one component, printable, and
  // nothing that `ldap_server.js`'s lookup would read as a DN or a DID.
  private personNameProblem(name: unknown): string {
    const { log } = this.deps;
    log.debug("Entering Krb5PersonKeys.personNameProblem().");
    const text = String(name == null ? '' : name);
    if (!text) {
      log.debug("Leaving Krb5PersonKeys.personNameProblem().");
      return 'no name';
    }
    if (text.length > 255 || /[\s\/@=,\\\x00-\x1f]/.test(text)) {
      log.debug("Leaving Krb5PersonKeys.personNameProblem().");
      return 'not a single-component principal name';
    }
    log.debug("Leaving Krb5PersonKeys.personNameProblem().");
    return '';
  }

  private isSealedValue(value: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering Krb5PersonKeys.isSealedValue().");
    log.debug("Leaving Krb5PersonKeys.isSealedValue().");
    return String(value || '').indexOf('$aesgcm$') === 0;
  }

  // Seal a record for storage, or say it could not be.
  private sealRecord(record: Json): { value: string; sealed: boolean } | null {
    const { log, keystore } = this.deps;
    log.debug("Entering Krb5PersonKeys.sealRecord().");
    const plaintext = JSON.stringify(record);
    if (!keystore.persists()) {
      log.debug("Leaving Krb5PersonKeys.sealRecord().");
      return { value: plaintext, sealed: false };
    }
    const value = keystore.seal(plaintext, SEAL_LABEL);
    log.debug("Leaving Krb5PersonKeys.sealRecord().");
    return value ? { value: value, sealed: true } : null;
  }

  // Open a stored value: `{ ok, record }` or `{ ok: false, why }`.
  private openRecord(value: unknown): Opened {
    const { log, keystore } = this.deps;
    log.debug("Entering Krb5PersonKeys.openRecord().");
    const text = String(value || '');
    let plaintext = '';
    if (this.isSealedValue(text)) {
      plaintext = keystore.open(text, SEAL_LABEL) || '';
      if (!plaintext) {
        log.debug("Leaving Krb5PersonKeys.openRecord().");
        return { ok: false,
                 why: 'sealed under a different key-encryption key' };
      }
    } else if (keystore.persists()) {
      log.debug("Leaving Krb5PersonKeys.openRecord().");
      // A CLEAR VALUE WHERE A SEALED ONE IS REQUIRED. This service never
      // writes one while keys persist, so it came from somewhere else — an
      // `ldapmodify` — and a key somebody chose is exactly what the seal
      // exists to refuse.
      return { ok: false, why: 'stored in the clear, which this service ' +
                               'never writes while its key-encryption key ' +
                               'persists' };
    } else {
      plaintext = text;
    }
    try {
      const record = JSON.parse(plaintext);
      if (!record || record.v !== RECORD_VERSION ||
          typeof record.keys !== 'object') {
        log.debug("Leaving Krb5PersonKeys.openRecord().");
        return { ok: false, why: 'not a record this service wrote' };
      }
      log.debug("Leaving Krb5PersonKeys.openRecord().");
      return { ok: true, record: record };
    } catch (e) {
      log.debug("Caught in Krb5PersonKeys.openRecord(): " +
                ((e && e.message) || e));
      log.debug("Leaving Krb5PersonKeys.openRecord().");
      // Not JSON: reported as unreadable rather than thrown, because the
      // caller is the KDC answering a request.
      return { ok: false, why: 'not JSON' };
    }
  }

  private parseInfo(value: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering Krb5PersonKeys.parseInfo().");
    try {
      log.debug("Leaving Krb5PersonKeys.parseInfo().");
      return value ? JSON.parse(String(value)) : null;
    } catch (e) {
      log.debug("Caught in Krb5PersonKeys.parseInfo(): " +
                ((e && e.message) || e));
      log.debug("Leaving Krb5PersonKeys.parseInfo().");
      // A public info value nothing can read describes nothing; the KEYS are
      // judged from the seal, never from this.
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // STRING-TO-KEY, the one path every derivation here takes. `s2kparams` is
  // null for everything this file stores — the enctype's own default
  // iteration count, which is what `krb5_principals.js`'s `longTermKey()` uses
  // and what a client applies when PA-ETYPE-INFO2 carries none — and is a
  // parameter only so that the RFC 3962 Appendix B vectors can be run through
  // this same function.
  // -------------------------------------------------------------------------
  async deriveKey(etype: number, password: unknown, salt: unknown,
                  s2kparams?: unknown): Promise<Uint8Array> {
    const { log, kcrypto, prim } = this.deps;
    log.debug("Entering Krb5PersonKeys.deriveKey().");
    const profile = kcrypto.etypeById(etype);
    log.debug("Leaving Krb5PersonKeys.deriveKey().");
    return profile.stringToKey(String(password), prim.utf8(String(salt)),
                               s2kparams || null);
  }

  // -------------------------------------------------------------------------
  // PREVIOUS KEY VERSIONS (2026-09-12).
  //
  // A password change and a rotation both move the kvno up by one, and until
  // this section they threw the old key away in the same write — so a ticket
  // issued an instant earlier, still well inside its lifetime, was refused
  // KRB_AP_ERR_BADKEYVER at its very next use. A real KDC keeps the previous
  // kvno in its database and a service keeps it in its keytab until those
  // tickets have expired; this is that, bounded twice —
  // `krb5.retainedKeyVersions` says how many, `krb5.retainedKeyTtlS` how long
  // each.
  //
  // **THEY LIVE INSIDE THE SAME SEALED VALUE, AS `previous`, AND NOT IN A
  // COMPANION ATTRIBUTE.** Three reasons, and the first is the one that
  // decides:
  //
  //   * ONE AUTHENTICATION TAG. The seal already binds the keys to a name and
  //     a password stamp; a companion attribute would be a second sealed value
  //     that could be copied, kept or restored independently of the first — an
  //     old version planted back beside a new current key, or a current key
  //     written while its previous versions are left on another entry. Inside
  //     the record they are replaced, pruned and cleared in the one write that
  //     replaces the current key, and a drop, a clear and a delete cannot miss
  //     them.
  //   * ONE WRITE. A password change retires the old current key and stores
  //     the new one atomically; two attributes would have a moment holding the
  //     new key and no previous version, or the reverse.
  //   * NO SCHEMA CHANGE. `stsKrb5Keys` and `krb5ServiceKeys` are already
  //     withheld everywhere, sealed, and on the schema rows a sighting
  //     preserves; a third and fourth attribute would have to be added to all
  //     of that and would be the one a future change forgot. `RECORD_VERSION`
  //     stays 1: `previous` is optional, a record without it has none, and an
  //     older reader ignores it.
  //
  // **A PREVIOUS VERSION IS NEVER A WAY IN.** It is handed to the KDC for ONE
  // purpose — decrypting a ticket already sealed under it — and
  // pre-authentication reads the current keys only (`krb5_principals.js`'s
  // `directoryUser()` puts those, and only those, in the key cache). An old
  // password cannot sign in.
  //
  // **THE BOUNDS ARE APPLIED ON READ AS WELL AS ON WRITE.** A version's expiry
  // is the EARLIER of the one stamped when it was retired and its retirement
  // plus the lifetime in force NOW, so shortening the setting ends windows at
  // once and lengthening it never resurrects one; the count is re-applied too.
  // What is past either bound is never used and never listed, and the next
  // write of that key removes it from storage.
  // -------------------------------------------------------------------------
  retainedVersionsLimit(): number {
    const { log, config } = this.deps;
    log.debug("Entering Krb5PersonKeys.retainedVersionsLimit().");
    const n = Number(config.value('krb5.retainedKeyVersions'));
    log.debug("Leaving Krb5PersonKeys.retainedVersionsLimit().");
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
  }

  // Seconds a retired version is kept. Zero in the setting means the longest
  // a ticket issued under it can still be presented — see the settings row.
  retainedTtlSeconds(): number {
    const { log, config } = this.deps;
    log.debug("Entering Krb5PersonKeys.retainedTtlSeconds().");
    const configured = Number(config.value('krb5.retainedKeyTtlS'));
    if (Number.isFinite(configured) && configured > 0) {
      log.debug("Leaving Krb5PersonKeys.retainedTtlSeconds().");
      return configured;
    }
    log.debug("Leaving Krb5PersonKeys.retainedTtlSeconds().");
    return Number(config.value('krb5.ticketLifetimeSeconds')) +
           Number(config.value('krb5.clockSkew'));
  }

  // When one retired version stops being usable, in epoch milliseconds; 0 for
  // an entry that says nothing readable about when it was retired. `ttlS` is
  // the lifetime to apply, where it is not `retainedTtlSeconds()` — the
  // krbtgt's (#169, `krbtgtTtlSeconds()`) — and is threaded through every
  // helper below for that one caller.
  private retainedUntilMs(entry: Json, ttlS?: number): number {
    const { log } = this.deps;
    log.debug("Entering Krb5PersonKeys.retainedUntilMs().");
    const retired = Date.parse(String((entry || {}).retiredAt || ''));
    if (!Number.isFinite(retired)) {
      log.debug("Leaving Krb5PersonKeys.retainedUntilMs().");
      return 0;
    }
    const byNow = retired + (ttlS === undefined ? this.retainedTtlSeconds()
                                                : ttlS) * 1000;
    const stamped = Date.parse(String(entry.expiresAt || ''));
    log.debug("Leaving Krb5PersonKeys.retainedUntilMs().");
    return Number.isFinite(stamped) ? Math.min(stamped, byNow) : byNow;
  }

  // The entries of a `previous` list (sealed, with keys) or a `retained` list
  // (public, without) that are inside both bounds at `nowMs`: newest first, at
  // most the limit.
  private withinBounds(list: unknown, nowMs: number, ttlS?: number): Json[] {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering Krb5PersonKeys.withinBounds().");
    const limit = this.retainedVersionsLimit();
    if (!limit || !Array.isArray(list)) {
      log.debug("Leaving Krb5PersonKeys.withinBounds().");
      return [];
    }
    log.debug("Leaving Krb5PersonKeys.withinBounds().");
    return list.filter(function (entry) {
      return entry && Number.isFinite(Number(entry.kvno)) &&
             self.retainedUntilMs(entry, ttlS) > nowMs;
    }).sort(function (a, b) {
      return Number(b.kvno) - Number(a.kvno);
    }).slice(0, limit);
  }

  // What `previous` becomes when `outgoing` — the record being replaced —
  // stops being current at `nowMs`. An outgoing record at the SAME kvno as the
  // one replacing it is not retired (the same password adding enctypes is the
  // same version), so only the pruning happens.
  private retire(outgoing: Json, newKvno: number, nowMs: number,
                 ttlS?: number): Json[] {
    const { log } = this.deps;
    log.debug("Entering Krb5PersonKeys.retire().");
    const kept = this.withinBounds(outgoing && outgoing.previous, nowMs, ttlS);
    if (!outgoing || Number(outgoing.kvno) === Number(newKvno) ||
        !this.retainedVersionsLimit()) {
      log.debug("Leaving Krb5PersonKeys.retire().");
      return kept;
    }
    const entry = {
      kvno: Number(outgoing.kvno),
      salt: outgoing.salt || '',
      createdAt: outgoing.derivedAt || outgoing.createdAt || '',
      retiredAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(nowMs + (ttlS === undefined
        ? this.retainedTtlSeconds() : ttlS) * 1000).toISOString(),
      keys: outgoing.keys
    };
    log.debug("Leaving Krb5PersonKeys.retire().");
    return this.withinBounds([entry].concat(kept.filter(function (one) {
      return Number(one.kvno) !== entry.kvno;
    })), nowMs, ttlS);
  }

  // The public half of a sealed `previous` list, for the info attribute:
  // kvno, enctypes and the two dates, never a key.
  private retainedInfo(previous: unknown, nowMs: number,
                       ttlS?: number): Json[] {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering Krb5PersonKeys.retainedInfo().");
    log.debug("Leaving Krb5PersonKeys.retainedInfo().");
    return this.withinBounds(previous, nowMs, ttlS).map(function (entry) {
      return {
        kvno: Number(entry.kvno),
        etypes: Object.keys(entry.keys || {}).map(Number)
          .filter(Number.isFinite),
        retiredAt: entry.retiredAt,
        expiresAt: new Date(self.retainedUntilMs(entry, ttlS)).toISOString()
      };
    });
  }

  // The public `retained` list of an info attribute, as a page lists it:
  // inside both bounds NOW, with the expiry the bounds give now.
  private retainedRows(infoRetained: unknown, nowMs: number,
                       ttlS?: number): Json[] {
    const self = this;
    const { log, kcrypto } = this.deps;
    log.debug("Entering Krb5PersonKeys.retainedRows().");
    log.debug("Leaving Krb5PersonKeys.retainedRows().");
    return this.withinBounds(infoRetained, nowMs, ttlS).map(function (entry) {
      return {
        kvno: Number(entry.kvno),
        etypes: (Array.isArray(entry.etypes) ? entry.etypes : []).map(
            function (etype) {
          return { etype: Number(etype),
                   name: kcrypto.etypeName(Number(etype)) };
        }),
        retiredAt: String(entry.retiredAt || ''),
        expiresAt: new Date(self.retainedUntilMs(entry, ttlS)).toISOString()
      };
    });
  }

  // `{ "18": "<base64>" }` into the `[[etype, bytes]]` pairs the KDC takes, in
  // this KDC's own enctype order and only for enctypes it offers.
  private keyPairs(keys: Json): Array<[number, Uint8Array]> {
    const { log, principals } = this.deps;
    log.debug("Entering Krb5PersonKeys.keyPairs().");
    log.debug("Leaving Krb5PersonKeys.keyPairs().");
    return principals.KDC_ETYPES.filter(function (etype) {
      return keys && typeof keys[etype] === 'string';
    }).map(function (etype): [number, Uint8Array] {
      return [etype, Uint8Array.from(Buffer.from(keys[etype], 'base64'))];
    });
  }

  // The retained versions of a record as the KDC's key source hands them
  // over.
  private retainedForKdc(record: Json, nowMs: number, ttlS?: number): Json[] {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering Krb5PersonKeys.retainedForKdc().");
    log.debug("Leaving Krb5PersonKeys.retainedForKdc().");
    return this.withinBounds(record.previous, nowMs, ttlS).map(
        function (entry) {
      return { kvno: Number(entry.kvno),
               expiresAt: self.retainedUntilMs(entry, ttlS),
               keys: self.keyPairs(entry.keys) };
    }).filter(function (entry) {
      return entry.keys.length > 0;
    });
  }

  // -------------------------------------------------------------------------
  // THE KDC'S KEY SOURCE — the two functions `principals.setKeySource()`
  // takes. Synchronous, because the principal lookup is: a directory read and
  // a seal opened, no derivation.
  // -------------------------------------------------------------------------
  personKeys(name: string): Json {
    const { log, principals } = this.deps;
    const directory = this.directory;
    log.debug('Entering Krb5PersonKeys.personKeys(). name=' + name);
    if (!directory) {
      log.debug('Leaving Krb5PersonKeys.personKeys(). No directory.');
      return { state: 'no-source' };
    }
    if (!this.personKeysEnabled()) {
      log.debug('Leaving Krb5PersonKeys.personKeys(). Switched off.');
      return { state: 'off' };
    }
    if (this.personNameProblem(name)) {
      log.debug('Leaving Krb5PersonKeys.personKeys(). Not a usable name.');
      return { state: 'unknown' };
    }
    const current = directory.readPerson(name);
    if (!current) {
      log.debug('Leaving Krb5PersonKeys.personKeys(). Nobody by that name.');
      return { state: 'unknown' };
    }
    if (!current.keys) {
      log.debug('Leaving Krb5PersonKeys.personKeys(). No keys yet.');
      return { state: 'none' };
    }
    const opened = this.openRecord(current.keys);
    if (!opened.ok) {
      log.debug('Leaving Krb5PersonKeys.personKeys(). Unreadable: ' +
                opened.why);
      return { state: 'unreadable', detail: opened.why };
    }
    const record = opened.record;
    if (record.name !== name || record.realm !== principals.REALM) {
      // Exact, as Kerberos names are: the salt carries the name as it was, and
      // a key for `Alice` is not a key for `alice`.
      log.debug('Leaving Krb5PersonKeys.personKeys(). Bound to ' +
                record.name + '@' + record.realm + '.');
      return { state: 'unknown', detail: 'the stored keys are bound to ' +
                                         'another name' };
    }
    if (!current.passwordHash ||
        record.stamp !== this.stampOf(current.passwordHash)) {
      log.debug('Leaving Krb5PersonKeys.personKeys(). Derived from an older ' +
                'password.');
      return { state: 'stale' };
    }
    const keys = this.keyPairs(record.keys);
    if (!keys.length) {
      log.debug('Leaving Krb5PersonKeys.personKeys(). No key for any enctype ' +
                'this KDC offers.');
      return { state: 'none' };
    }
    // THE PREVIOUS VERSIONS RIDE BESIDE THE CURRENT KEYS AND NEVER AMONG THEM:
    // `krb5_principals.js` keeps them apart, so pre-authentication can only
    // ever be checked against `keys`.
    const retained = this.retainedForKdc(record, Date.now());
    log.debug('Leaving Krb5PersonKeys.personKeys(). kvno ' + record.kvno +
              ', ' + keys.length + ' key(s), ' + retained.length +
              ' previous version(s).');
    return { state: 'ok', kvno: record.kvno, salt: record.salt, keys: keys,
             retained: retained };
  }

  // A DISABLED ACCOUNT (2026-09-17): `pwdAccountLockedTime` on the person's
  // entry, which the KDC refuses with KDC_ERR_CLIENT_REVOKED (18) in EVERY
  // mode — so it is asked whether or not this directory holds the person's
  // keys, and before a development-mode KDC would create the principal.
  personDisabled(name: string): boolean {
    const { log } = this.deps;
    const directory = this.directory;
    log.debug('Entering Krb5PersonKeys.personDisabled(). name=' + name);
    if (!directory || this.personNameProblem(name)) {
      log.debug('Leaving Krb5PersonKeys.personDisabled(). Nothing to ask.');
      return false;
    }
    const current = directory.readPerson(name);
    log.debug('Leaving Krb5PersonKeys.personDisabled(). ' +
              !!(current && current.disabled));
    return !!(current && current.disabled);
  }

  // -------------------------------------------------------------------------
  // DOES THIS PERSON HOLD, OR OWE, A SECOND FACTOR? (#173, 2026-09-22). Asked
  // by the KDC after pre-authentication verified, for a person-shaped name in
  // its own realm, in BOTH modes — what the answer REFUSES is
  // `mode.issuesTicketsOnPasswordAlone()`'s, at the KDC. The answer is
  // `common/credentials.ts`'s `secondFactorDemand()`, the one the five
  // password-only doors of #101 ask, so the two cannot come to disagree about
  // who is a two-factor account: `{ person, totp, key, holds, required,
  // byUser, needed }`. Nobody by that name, or no directory, answers
  // `needed: false`.
  // -------------------------------------------------------------------------
  personSecondFactor(name: string): Json {
    const { log, credentials } = this.deps;
    log.debug('Entering Krb5PersonKeys.personSecondFactor(). name=' + name);
    const none = { person: false, totp: false, key: false, holds: false,
                   required: false, byUser: false, needed: false };
    if (!this.directory || this.personNameProblem(name) ||
        typeof credentials.secondFactorDemand !== 'function') {
      log.debug('Leaving Krb5PersonKeys.personSecondFactor(). Nothing to ' +
                'ask.');
      return none;
    }
    const answer = credentials.secondFactorDemand(name) || none;
    log.debug('Leaving Krb5PersonKeys.personSecondFactor(). needed=' +
              !!answer.needed);
    return answer;
  }

  // What the KDC does about pre-authentication in the AMBIENT realm, for the
  // console and the management API (rule 7). See `Krb5Fast.policy()`.
  preauthPolicy(): Json {
    const { log, fast } = this.deps;
    log.debug('Entering Krb5PersonKeys.preauthPolicy().');
    log.debug('Leaving Krb5PersonKeys.preauthPolicy().');
    return fast.policy();
  }

  serviceKeys(spn: string): Json {
    const { log, principals } = this.deps;
    const directory = this.directory;
    log.debug("Entering Krb5PersonKeys.serviceKeys().");
    if (!directory) {
      log.debug("Leaving Krb5PersonKeys.serviceKeys().");
      return null;
    }
    log.debug('Entering Krb5PersonKeys.serviceKeys(). spn=' + spn);
    const current = directory.readService(String(spn) + '@' +
                                          principals.REALM);
    if (!current || !current.keys) {
      log.debug('Leaving Krb5PersonKeys.serviceKeys(). None stored.');
      return null;
    }
    const opened = this.openRecord(current.keys);
    if (!opened.ok || opened.record.spn !== String(spn) ||
        opened.record.realm !== principals.REALM) {
      // Treated as NO stored key — the configured account, if there is one,
      // answers as it did before — and said at warn, because an operator made
      // this key and it has stopped working.
      log.warn('krb5-keys: the stored key for ' + spn + ' cannot be used (' +
               (opened.ok ? 'it is bound to another principal'
                          : opened.why) +
               '). Rotate it at /admin/kerberos/principals.');
      log.debug('Leaving Krb5PersonKeys.serviceKeys(). Unusable.');
      return null;
    }
    const record = opened.record;
    const keys = this.keyPairs(record.keys);
    log.debug('Leaving Krb5PersonKeys.serviceKeys(). kvno ' + record.kvno +
              '.');
    return keys.length
      ? { kvno: record.kvno, keys: keys,
          retained: this.retainedForKdc(record, Date.now()) }
      : null;
  }

  // -------------------------------------------------------------------------
  // THE DERIVATION, which the password observer starts.
  //
  // ONE AT A TIME PER PERSON, chained: two sign-ins racing would otherwise
  // derive twice and write last-wins, and a set racing a verify of the
  // PREVIOUS password could write keys for the old one after the new one's.
  // The chain makes them sequential and the re-read before the write — is the
  // hash still the one this derivation started beside? — makes a superseded
  // one abandon itself. The queues are `inFlight`, above the class.
  // -------------------------------------------------------------------------
  private inFlightKey(name: string): string {
    const { log, realms } = this.deps;
    log.debug("Entering Krb5PersonKeys.inFlightKey().");
    log.debug("Leaving Krb5PersonKeys.inFlightKey().");
    return realms.currentId() + '|' + String(name);
  }

  observePassword(name: string, password: string, info?: Json): void {
    const self = this;
    const { log, principals, realms, errorCodes, audit } = this.deps;
    log.debug('Entering Krb5PersonKeys.observePassword(). name=' + name);
    const event = (info && info.event) || 'verified';
    if (!this.productKdc() || !this.directory || !this.personKeysEnabled() ||
        this.personNameProblem(name) ||
        !principals.enabledIn(realms.currentId())) {
      // Nothing to do, and deliberately said at debug: this is called on every
      // verified sign-in in the service.
      log.debug('Leaving Krb5PersonKeys.observePassword(). Not deriving (' +
                (!this.productKdc() ? 'development KDC'
                  : !this.directory ? 'no directory'
                  : !this.personKeysEnabled() ? 'krb5.personKeys is off'
                  : this.personNameProblem(name) ? 'not a principal name'
                  : 'this trust realm has no KDC') + ').');
      return;
    }
    const queue = this.inFlightKey(name);
    const previous = inFlight.get(queue) || Promise.resolve();
    const next = previous.then(function () {
      return self.derive(name, password, event,
                         (info && typeof info.hash === 'string' &&
                          info.hash) || null);
    }).catch(function (e) {
      log.error(errorCodes.tag('STS-KRB-0107') + 'krb5-keys: deriving the ' +
                'Kerberos keys for ' + name + ' failed: ' +
                (e.stack || e.message));
      audit.failure('STS-KRB-0107', {
        action: 'service.failure', protocol: 'Kerberos', channel: 'internal',
        target: name + '@' + principals.REALM, outcome: 'error',
        summary: 'Kerberos keys could not be derived for ' + name + ' after ' +
                 'a password was ' + event + '; the ' + event + ' itself ' +
                 'was unaffected'
      });
    });
    inFlight.set(queue, next);
    next.then(function () {
      if (inFlight.get(queue) === next) {
        inFlight.delete(queue);
      }
    });
    log.debug('Leaving Krb5PersonKeys.observePassword(). A derivation is ' +
              'queued.');
  }

  // Every derivation now running, settled — in EVERY realm, which is what a
  // caller of this wants: a test, or a console action that clears keys and
  // must not race a derivation writing them back, cares that nothing is still
  // in flight rather than that one realm's queue is empty.
  idle(): Promise<unknown[]> {
    const { log } = this.deps;
    log.debug("Entering Krb5PersonKeys.idle().");
    log.debug("Leaving Krb5PersonKeys.idle().");
    return Promise.all(Array.from(inFlight.values()));
  }

  private async derive(name: string, password: string,
                       event: string, hash: string | null): Promise<Json> {
    const { log, principals, config, errorCodes, audit,
            kcrypto } = this.deps;
    const directory = this.directory;
    log.debug('Entering Krb5PersonKeys.derive(). name=' + name + ' event=' +
              event);
    const current = directory.readPerson(name);
    if (!current || !current.passwordHash) {
      log.info('krb5-keys: ' + name + ' has no entry or no stored password, ' +
               'so no Kerberos keys were derived.');
      log.debug('Leaving Krb5PersonKeys.derive(). Nothing to key.');
      return { derived: false, why: 'no-password' };
    }
    // BOUND TO THE HASH THE PASSWORD WAS CHECKED AGAINST, not to the one on
    // the entry now. This derivation may have waited behind another in the
    // queue, and a password SET in the meantime — here or, through the change
    // log, on another node — leaves the entry holding a hash `password` does
    // not produce. Stamping that hash on these keys wrote the OLD password's
    // keys as the NEW one's, and the KDC then refused the new password's
    // keytab (sts_kerberos_keytab on the cluster stack, 2026-09-24). The
    // superseded check below catches a change DURING the derivation; this
    // catches one BEFORE it started.
    if (hash && current.passwordHash !== hash) {
      log.info('krb5-keys: the password for ' + name + ' changed before its ' +
               'queued derivation started, so none was made from it; the ' +
               'newer password\'s derivation writes its own.');
      log.debug('Leaving Krb5PersonKeys.derive(). Superseded before it ran.');
      return { derived: false, why: 'superseded' };
    }
    const stamp = this.stampOf(current.passwordHash);
    const wanted = principals.KDC_ETYPES.slice();
    const opened: Opened = current.keys ? this.openRecord(current.keys)
                                        : { ok: false };
    const record = opened.ok ? opened.record : null;
    const info = this.parseInfo(current.info);
    // CURRENT means the record holds exactly the enctypes wanted: every one
    // of them, and none besides. The second half is #182's (2026-09-23): a
    // realm that became product holds an rc4-hmac key derived while it was
    // development, which `KDC_ETYPES` no longer lists, and the next verified
    // sign-in re-derives without it — the same password, so the same kvno —
    // rather than leave an RC4 key sealed on the entry. (It is never handed
    // to the KDC meanwhile: `keyPairs()` reads only the enctypes offered.)
    if (event !== 'set' && record && record.name === name &&
        record.stamp === stamp &&
        wanted.every(function (etype) {
          return typeof record.keys[etype] === 'string';
        }) &&
        Object.keys(record.keys || {}).every(function (etype) {
          return wanted.indexOf(Number(etype)) >= 0;
        })) {
      log.debug('Leaving Krb5PersonKeys.derive(). The keys are already ' +
                'current.');
      return { derived: false, why: 'current' };
    }
    // THE KVNO. The same password adding enctypes keeps its version — those
    // keys did not change. A different password is a new key and a new
    // version, and a first key starts at `krb5.kvno`.
    let kvno: number;
    if (record && record.stamp === stamp) {
      kvno = Number(record.kvno);
    } else if (record || (info && info.kvno)) {
      kvno = Number((record || info).kvno) + 1;
    } else {
      kvno = Number(config.value('krb5.kvno'));
    }
    const salt = this.saltFor(name);
    const keys: Record<string, string> = {};
    for (const etype of wanted) {
      const key = await this.deriveKey(etype, password, salt, null);
      keys[etype] = Buffer.from(key).toString('base64');
    }
    // SUPERSEDED? A newer password landed while this one was being derived.
    const again = directory.readPerson(name);
    if (!again || again.passwordHash !== current.passwordHash) {
      log.info('krb5-keys: the password for ' + name + ' changed while its ' +
               'Kerberos keys were being derived, so these were thrown away; ' +
               'the newer password\'s derivation writes its own.');
      log.debug('Leaving Krb5PersonKeys.derive(). Superseded.');
      return { derived: false, why: 'superseded' };
    }
    const nowMs = Date.now();
    const derivedAt = new Date(nowMs).toISOString();
    // THE OUTGOING RECORD IS THE ONE ON THE ENTRY NOW, not the one read before
    // the derivation: an operator's "drop previous versions" may have landed
    // in between, and retiring from the older read would put back what they
    // dropped. `again` is read and this write is made with no await between
    // them.
    const againOpened: Opened = again.keys ? this.openRecord(again.keys)
                                           : { ok: false };
    const outgoing = againOpened.ok && againOpened.record.name === name
      ? againOpened.record : null;
    const previous = this.retire(outgoing, kvno, nowMs);
    const sealed = this.sealRecord({ v: RECORD_VERSION, name: name,
                                     realm: principals.REALM, kvno: kvno,
                                     salt: salt, stamp: stamp,
                                     derivedAt: derivedAt, keys: keys,
                                     previous: previous });
    if (!sealed) {
      log.error(errorCodes.tag('STS-KRB-0108') + 'krb5-keys: the Kerberos ' +
                'keys for ' + name + ' could not be sealed, so they were NOT ' +
                'stored. Storing them in the clear would put a ' +
                'password-equivalent key in every directory dump.');
      audit.failure('STS-KRB-0108', {
        action: 'service.failure', protocol: 'Kerberos', channel: 'internal',
        target: name + '@' + principals.REALM, outcome: 'error',
        summary: 'Kerberos keys for ' + name + ' could not be sealed and ' +
                 'were not stored'
      });
      log.debug('Leaving Krb5PersonKeys.derive(). Not sealed.');
      return { derived: false, why: 'seal' };
    }
    const infoValue = JSON.stringify({
      kvno: kvno, etypes: wanted, derivedAt: derivedAt,
      sealed: sealed.sealed, event: event, stamp: stamp,
      retained: this.retainedInfo(previous, nowMs)
    });
    if (!directory.writePerson(name, sealed.value, infoValue)) {
      log.error(errorCodes.tag('STS-KRB-0109') + 'krb5-keys: the Kerberos ' +
                'keys for ' + name + ' could not be written to their entry.');
      audit.failure('STS-KRB-0109', {
        action: 'service.failure', protocol: 'Kerberos', channel: 'internal',
        target: name + '@' + principals.REALM, outcome: 'error',
        summary: 'Kerberos keys for ' + name + ' could not be written to ' +
                 'the directory'
      });
      log.debug('Leaving Krb5PersonKeys.derive(). Not written.');
      return { derived: false, why: 'write' };
    }
    audit.audit({
      action: 'krb5.keys.derived', actor: name, protocol: 'Kerberos',
      channel: 'internal', target: name + '@' + principals.REALM,
      summary: 'Kerberos keys for ' + name + ' were derived from the ' +
               'password just ' +
               (event === 'set' ? 'set' : 'verified') + ' (kvno ' + kvno +
               ', ' + wanted.map(kcrypto.etypeName).join(', ') + ')',
      // No key, no salt beyond what ETYPE-INFO2 publishes anyway, no
      // password.
      detail: { kvno: kvno, etypes: wanted, event: event,
                sealed: sealed.sealed,
                retainedKvnos: previous.map(function (one) {
                  return one.kvno;
                }) }
    });
    log.info('krb5-keys: ' + name + '@' + principals.REALM + ' now has ' +
             'Kerberos keys at ' +
             'kvno ' + kvno + ' (' + (sealed.sealed ? 'sealed' : 'clear, ' +
             'development key ' +
             'store') + '), derived from the password just ' + event +
             (previous.length ?
              '; keeping previous kvno ' + previous.map(function (one) {
                return one.kvno;
              }).join(', ') + ' for tickets already issued under it' : '') +
             '.');
    log.debug('Leaving Krb5PersonKeys.derive(). kvno ' + kvno + '.');
    return { derived: true, kvno: kvno };
  }

  // -------------------------------------------------------------------------
  // SERVICE PRINCIPALS.
  // -------------------------------------------------------------------------

  // `HTTP/web.example.com` or `HTTP/web.example.com@EXAMPLE.COM`, refused
  // otherwise with a sentence. The realm, when given, must be this KDC's: a
  // key stored for another realm's principal is a key nothing here would ask
  // for.
  normaliseSpn(raw: unknown): Json {
    const { log, principals } = this.deps;
    log.debug('Entering Krb5PersonKeys.normaliseSpn().');
    let text = String(raw == null ? '' : raw).trim();
    const at = text.lastIndexOf('@');
    if (at >= 0) {
      const realm = text.slice(at + 1);
      if (realm !== principals.REALM) {
        log.debug('Leaving Krb5PersonKeys.normaliseSpn(). Foreign realm.');
        return { ok: false, error: '"' + text + '" names the realm ' + realm +
                 ', and this KDC is ' + principals.REALM + '.' };
      }
      text = text.slice(0, at);
    }
    const components = text.split('/');
    if (components.length < 2 || components.some(function (c) {
      return !c || /[\s@\\\x00-\x1f]/.test(c);
    }) || text.length > 255) {
      log.debug('Leaving Krb5PersonKeys.normaliseSpn(). Not a service ' +
                'principal name.');
      return { ok: false, error: '"' + text + '" is not a service principal ' +
               'name: one is two or more non-empty components separated by ' +
               '"/", like HTTP/web.example.com, with no spaces and no "@" ' +
               'inside it.' };
    }
    if (components[0].toLowerCase() === 'krbtgt') {
      log.debug('Leaving Krb5PersonKeys.normaliseSpn(). krbtgt.');
      return { ok: false, error: 'krbtgt is the ticket-granting key every ' +
               'TGT in the realm is sealed under: it is not a service ' +
               'principal an operator creates, and has a rotation of its own ' +
               '(rotate-krbtgt and rotate-krbtgt-invalidate).' };
    }
    log.debug('Leaving Krb5PersonKeys.normaliseSpn().');
    return { ok: true, components: components, spn: text,
             identifier: text + '@' + principals.REALM };
  }

  private refusal(code: string, message: string): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Krb5PersonKeys.refusal().");
    log.debug("Leaving Krb5PersonKeys.refusal().");
    return errorCodes.mark({ ok: false, errors: [message] }, code);
  }

  // -------------------------------------------------------------------------
  // NO KDC IN THIS TRUST REALM, NO KEYS IN IT (2026-09-15).
  //
  // Every act below writes key material for a principal of the AMBIENT
  // realm's KDC, and a realm whose `krb5.enabled` is off has no such KDC: no
  // Kerberos realm name, no principal database, no etypes. Without this guard
  // those acts did not refuse — they SUCCEEDED emptily, which is worse than
  // either: the SPN was stored as `HTTP/web.acme.test@` (the realm name is the
  // empty string), the key list was built from an empty etype list, and the
  // caller was handed a keytab with no entries and told it was created.
  // `observePassword()` has asked the same question since the split; these
  // six had been left with the register's older assumption that there was
  // always exactly one KDC.
  // -------------------------------------------------------------------------
  private noKdcHere(): Json {
    const { log, principals } = this.deps;
    log.debug("Entering Krb5PersonKeys.noKdcHere().");
    const state = principals.kerberosRealmOf();
    if (state.enabled && state.active) {
      log.debug("Leaving Krb5PersonKeys.noKdcHere(). This realm has a KDC.");
      return null;
    }
    log.debug("Leaving Krb5PersonKeys.noKdcHere(). No KDC here.");
    return this.refusal('STS-KRB-0128', 'Trust realm "' + state.trustRealm +
      '" has no KDC, so there is nothing here to hold a Kerberos key for: ' +
      (state.reason || 'krb5.enabled is off for it') + '. Give the realm a ' +
      'krb5.realm of its own and turn krb5.enabled on, and its principals ' +
      'become the people and applications in its own directory.');
  }

  // Random keys, sealed, written, and the keytab that carries them. The one
  // function a create and a rotate share, so that they cannot disagree about
  // what a stored service key is.
  //
  // `outgoing` is the opened record a ROTATE replaces (null for a create): its
  // key becomes a previous version, and **THE KEYTAB CARRIES EVERY VERSION
  // STILL KEPT**, current first — what MIT's `ktadd` without `-k` leaves in a
  // keytab, and what a service needs so that a ticket issued under the old
  // kvno a moment before the rotation is still accepted once the new keytab is
  // installed.
  private mintServiceKeys(spn: Json, kvno: number, act: string,
                          context: ActContext | null | undefined,
                          outgoing?: Json): Json {
    const self = this;
    const { log, principals, kcrypto, keytab, errorCodes, audit } = this.deps;
    const directory = this.directory;
    log.debug('Entering Krb5PersonKeys.mintServiceKeys(). spn=' + spn.spn +
              ' kvno=' + kvno);
    const etypes = principals.KDC_ETYPES.slice();
    const now = new Date();
    const keys: Record<string, string> = {};
    const entries = [];
    etypes.forEach(function (etype) {
      const key = kcrypto.randomBytes(kcrypto.etypeById(etype).keyBytes);
      keys[etype] = Buffer.from(key).toString('base64');
      entries.push({ realm: principals.REALM, components: spn.components,
                     nameType: keytab.NAME_TYPE_PRINCIPAL, timestamp: now,
                     kvno: kvno, etype: etype, key: key });
    });
    const kept = this.retire(outgoing || null, kvno, now.getTime());
    kept.forEach(function (version) {
      const made = Date.parse(String(version.createdAt || ''));
      self.keyPairs(version.keys).forEach(function (pair) {
        entries.push({ realm: principals.REALM, components: spn.components,
                       nameType: keytab.NAME_TYPE_PRINCIPAL,
                       timestamp: Number.isFinite(made) ? new Date(made)
                                                        : now,
                       kvno: Number(version.kvno), etype: pair[0],
                       key: pair[1] });
      });
    });
    const previous = this.parseInfo((directory.readService(spn.identifier) ||
                                     {}).info);
    const sealed = this.sealRecord({ v: RECORD_VERSION, spn: spn.spn,
                                     realm: principals.REALM,
                                     kvno: kvno,
                                     createdAt: now.toISOString(),
                                     keys: keys,
                                     previous: kept });
    if (!sealed) {
      log.error(errorCodes.tag('STS-KRB-0108') + 'krb5-keys: the key for ' +
                spn.spn + ' could not be sealed, so nothing was stored.');
      log.debug('Leaving Krb5PersonKeys.mintServiceKeys(). Not sealed.');
      return this.refusal('STS-ADMIN-0607', 'The new key for ' + spn.spn +
                          ' could not be encrypted under the key-encryption ' +
                          'key, so nothing was stored and no keytab was ' +
                          'made.');
    }
    const info = { kvno: kvno, etypes: etypes, sealed: sealed.sealed,
                   createdAt: previous && previous.createdAt
                     ? previous.createdAt : now.toISOString(),
                   rotatedAt: act === 'rotated' ? now.toISOString() : '',
                   retained: this.retainedInfo(kept, now.getTime()) };
    if (!directory.writeService(spn.identifier, sealed.value,
                                JSON.stringify(info))) {
      log.debug('Leaving Krb5PersonKeys.mintServiceKeys(). Not written.');
      return this.refusal('STS-ADMIN-0607', 'The key for ' + spn.spn +
                          ' could not be written to its application entry, ' +
                          'so no keytab was made.');
    }
    const bytes = keytab.writeKeytab(entries);
    audit.audit({
      action: 'admin.krb5.service.' + act,
      actor: String((context || {}).actor || ''),
      protocol: 'Kerberos', channel: 'internal', target: spn.identifier,
      summary: 'The Kerberos service principal ' + spn.identifier + ' was ' +
               act +
               ' with a random key (kvno ' + kvno + ') through the ' +
               String((context || {}).via || 'console'),
      detail: { kvno: kvno, etypes: etypes,
                via: String((context || {}).via || 'console'),
                retainedKvnos: kept.map(function (one) {
                  return one.kvno;
                }) }
    });
    log.info('krb5-keys: ' + spn.identifier + ' ' + act + ' at kvno ' + kvno +
             (kept.length ? ', keeping previous kvno ' +
               kept.map(function (one) {
                 return one.kvno;
               }).join(', ') : '') +
             '; its keytab was handed to the caller and is not kept.');
    log.debug('Leaving Krb5PersonKeys.mintServiceKeys().');
    const retained = this.retainedRows(this.retainedInfo(kept,
                                                         now.getTime()),
                                       now.getTime());
    log.debug("Leaving Krb5PersonKeys.mintServiceKeys().");
    return {
      ok: true, act: act, spn: spn.spn, principal: spn.identifier,
      kvno: kvno, etypes: etypes, sealed: sealed.sealed, retained: retained,
      keytabKvnos: [kvno].concat(kept.map(function (one) {
        return Number(one.kvno);
      })),
      keytabFilename: spn.spn.replace(/[^A-Za-z0-9.-]+/g, '_') + '.kvno' +
                      kvno + '.keytab',
      keytab: bytes.toString('base64'),
      message: 'The Kerberos service principal ' + spn.identifier + ' was ' +
               act +
               ' at kvno ' + kvno + '. Its keytab is in this answer and is ' +
               'not kept: it cannot be downloaded again, only replaced by ' +
               'rotating.' +
               (kept.length
                 ? ' The keytab also carries the previous kvno ' +
                   kept.map(function (one) {
                     return one.kvno;
                   }).join(', ') + ', which this KDC and its acceptor still ' +
                   'accept for tickets already issued under it until ' +
                   retained.map(function (one) {
                     return one.expiresAt;
                   }).join(', ') +
                   ' (krb5.retainedKeyTtlS).'
                 : '')
    };
  }

  createServicePrincipal(raw: unknown, context?: ActContext): Json {
    const { log, applications, config } = this.deps;
    const directory = this.directory;
    log.debug('Entering Krb5PersonKeys.createServicePrincipal().');
    const noKdc = this.noKdcHere();
    if (noKdc) {
      log.debug('Leaving Krb5PersonKeys.createServicePrincipal(). No KDC in ' +
                'this trust realm.');
      return noKdc;
    }
    const spn = this.normaliseSpn(raw);
    if (!spn.ok) {
      log.debug('Leaving Krb5PersonKeys.createServicePrincipal(). Not an ' +
                'SPN.');
      return this.refusal('STS-ADMIN-0603', spn.error);
    }
    if (!directory) {
      log.debug('Leaving Krb5PersonKeys.createServicePrincipal(). No ' +
                'directory.');
      return this.refusal('STS-ADMIN-0609', 'There is no directory in this ' +
                          'process, so there is nowhere to store a service ' +
                          'principal\'s key.');
    }
    const existing = directory.readService(spn.identifier);
    if (existing && existing.keys) {
      log.debug('Leaving Krb5PersonKeys.createServicePrincipal(). Already ' +
                'keyed.');
      return this.refusal('STS-ADMIN-0604', spn.identifier + ' already ' +
                          'holds a stored key. Rotate it to get a new ' +
                          'keytab; creating it again would silently strand ' +
                          'every service holding the current one.');
    }
    if (!existing) {
      // THE APPLICATION ENTRY, in the AMBIENT trust realm since 2026-09-15 —
      // the realm whose KDC will issue tickets for this SPN, which is the
      // realm this request is in. Created through the registry's own door, so
      // it is the same entry a ticket for this SPN would have made.
      const created: Json = applications.createApplication({
        identifier: spn.identifier, kind: 'kerberos-service',
        protocols: ['krb5'],
        fields: { krb5ServicePrincipalName: spn.identifier },
        actor: String((context || {}).actor || '')
      });
      if (!created.ok || !directory.readService(spn.identifier)) {
        log.debug('Leaving Krb5PersonKeys.createServicePrincipal(). No ' +
                  'application entry.');
        return this.refusal('STS-ADMIN-0606',
                            'No application entry could be made for ' +
                            spn.identifier + ': ' +
                            ((created.errors || []).join(' ') ||
                             'the directory did not hold it afterwards') +
                            '.');
      }
    }
    const result = this.mintServiceKeys(spn,
                                        Number(config.value('krb5.kvno')),
                                        'created', context);
    log.debug('Leaving Krb5PersonKeys.createServicePrincipal().');
    return result;
  }

  rotateServicePrincipal(raw: unknown, context?: ActContext): Json {
    const { log, config } = this.deps;
    const directory = this.directory;
    log.debug('Entering Krb5PersonKeys.rotateServicePrincipal().');
    const noKdc = this.noKdcHere();
    if (noKdc) {
      log.debug('Leaving Krb5PersonKeys.rotateServicePrincipal(). No KDC in ' +
                'this trust realm.');
      return noKdc;
    }
    const spn = this.normaliseSpn(raw);
    if (!spn.ok) {
      log.debug('Leaving Krb5PersonKeys.rotateServicePrincipal(). Not an ' +
                'SPN.');
      return this.refusal('STS-ADMIN-0603', spn.error);
    }
    if (!directory) {
      log.debug('Leaving Krb5PersonKeys.rotateServicePrincipal(). No ' +
                'directory.');
      return this.refusal('STS-ADMIN-0609', 'There is no directory in this ' +
                          'process.');
    }
    const existing = directory.readService(spn.identifier);
    if (!existing || !existing.keys) {
      log.debug('Leaving Krb5PersonKeys.rotateServicePrincipal(). Nothing ' +
                'stored.');
      return this.refusal('STS-ADMIN-0605', spn.identifier + ' holds no ' +
                          'stored key to rotate. Create it first.');
    }
    const opened = this.openRecord(existing.keys);
    const info = this.parseInfo(existing.info);
    const was = opened.ok
      ? Number(opened.record.kvno)
      : Number((info && info.kvno) || config.value('krb5.kvno'));
    // A record this process cannot open is rotated with nothing retained: a
    // key that cannot be read is no key a ticket could be opened with.
    const outgoing = opened.ok && opened.record.spn === spn.spn
      ? opened.record : null;
    const result = this.mintServiceKeys(spn, was + 1, 'rotated', context,
                                        outgoing);
    log.debug('Leaving Krb5PersonKeys.rotateServicePrincipal().');
    return result;
  }

  deleteServicePrincipal(raw: unknown, context?: ActContext): Json {
    const { log, audit } = this.deps;
    const directory = this.directory;
    log.debug('Entering Krb5PersonKeys.deleteServicePrincipal().');
    const noKdc = this.noKdcHere();
    if (noKdc) {
      log.debug('Leaving Krb5PersonKeys.deleteServicePrincipal(). No KDC in ' +
                'this trust realm.');
      return noKdc;
    }
    const spn = this.normaliseSpn(raw);
    if (!spn.ok) {
      log.debug('Leaving Krb5PersonKeys.deleteServicePrincipal(). Not an ' +
                'SPN.');
      return this.refusal('STS-ADMIN-0603', spn.error);
    }
    if (!directory) {
      log.debug('Leaving Krb5PersonKeys.deleteServicePrincipal(). No ' +
                'directory.');
      return this.refusal('STS-ADMIN-0609', 'There is no directory in this ' +
                          'process.');
    }
    const existing = directory.readService(spn.identifier);
    if (!existing || !existing.keys) {
      log.debug('Leaving Krb5PersonKeys.deleteServicePrincipal(). Nothing ' +
                'stored.');
      return this.refusal('STS-ADMIN-0605', spn.identifier + ' holds no ' +
                          'stored key.');
    }
    const info = this.parseInfo(existing.info);
    if (!directory.writeService(spn.identifier, null, null)) {
      log.debug('Leaving Krb5PersonKeys.deleteServicePrincipal(). Not ' +
                'written.');
      return this.refusal('STS-ADMIN-0607', 'The stored key for ' +
                          spn.identifier + ' could not be removed from its ' +
                          'application entry.');
    }
    audit.audit({
      action: 'admin.krb5.service.deleted',
      actor: String((context || {}).actor || ''),
      protocol: 'Kerberos', channel: 'internal', target: spn.identifier,
      summary: 'The stored key for the Kerberos service principal ' +
               spn.identifier +
               ' was deleted through the ' +
               String((context || {}).via || 'console'),
      detail: { kvno: info ? info.kvno : null,
                via: String((context || {}).via || 'console') }
    });
    log.debug('Leaving Krb5PersonKeys.deleteServicePrincipal().');
    return { ok: true, spn: spn.spn, principal: spn.identifier,
             message: 'The stored key for ' + spn.identifier + ' is gone. ' +
                      'The application entry stays, as every entry this ' +
                      'registry records does; a ticket for that SPN is now ' +
                      'keyed as it was before a key was stored — from ' +
                      'krb5.servicePassword if it is the acceptor\'s own ' +
                      'name, and not at all in product mode otherwise.' };
  }

  clearPersonKeys(name: unknown, context?: ActContext): Json {
    const { log, audit, principals } = this.deps;
    const directory = this.directory;
    log.debug('Entering Krb5PersonKeys.clearPersonKeys(). name=' + name);
    const noKdc = this.noKdcHere();
    if (noKdc) {
      log.debug('Leaving Krb5PersonKeys.clearPersonKeys(). No KDC in this ' +
                'trust realm.');
      return noKdc;
    }
    const who = String(name == null ? '' : name).trim();
    if (!directory) {
      log.debug('Leaving Krb5PersonKeys.clearPersonKeys(). No directory.');
      return this.refusal('STS-ADMIN-0609', 'There is no directory in this ' +
                          'process.');
    }
    if (!who || this.personNameProblem(who)) {
      log.debug('Leaving Krb5PersonKeys.clearPersonKeys(). No usable name.');
      return this.refusal('STS-ADMIN-0608', 'Name the person whose Kerberos ' +
                          'keys to clear, as `username`.');
    }
    const current = directory.readPerson(who);
    if (!current) {
      log.debug('Leaving Krb5PersonKeys.clearPersonKeys(). Nobody by that ' +
                'name.');
      return this.refusal('STS-ADMIN-0608', 'There is nobody called "' + who +
                          '" in this trust realm\'s directory, which is the ' +
                          'one its KDC reads.');
    }
    if (!current.keys && !current.info) {
      log.debug('Leaving Krb5PersonKeys.clearPersonKeys(). Nothing held.');
      return { ok: true, cleared: false, username: who,
               message: who + ' holds no Kerberos keys, so there was ' +
                        'nothing to clear.' };
    }
    if (!directory.writePerson(who, null, null)) {
      log.debug('Leaving Krb5PersonKeys.clearPersonKeys(). Not written.');
      return this.refusal('STS-ADMIN-0607', 'The Kerberos keys on ' + who +
                          '\'s entry could not be removed.');
    }
    audit.audit({
      action: 'admin.krb5.keys.cleared',
      actor: String((context || {}).actor || ''),
      protocol: 'Kerberos', channel: 'internal',
      target: who + '@' + principals.REALM,
      summary: 'The Kerberos keys of ' + who + ' were cleared through the ' +
               String((context || {}).via || 'console'),
      detail: { via: String((context || {}).via || 'console') }
    });
    log.debug('Leaving Krb5PersonKeys.clearPersonKeys(). Cleared.');
    return { ok: true, cleared: true, username: who,
             message: 'The Kerberos keys of ' + who + ' are cleared, ' +
                      'previous versions included. Their next AS-REQ is ' +
                      'refused with "sign in once"; their next verified ' +
                      'sign-in derives new keys at the next kvno.' };
  }

  // -------------------------------------------------------------------------
  // DROP THE PREVIOUS VERSIONS NOW — an operator ending the window early,
  // which is what somebody does after a compromise: the old password or the
  // old keytab is in the wrong hands, and a ticket issued under it must stop
  // being accepted before its lifetime is out.
  //
  // It REWRITES the record with `previous` empty and the current key
  // untouched, so the person still signs in and the service keeps its current
  // keytab. Somebody holding nothing to drop is answered `dropped: 0` rather
  // than refused, for `clearPersonKeys()`'s reason. A record this process
  // cannot OPEN is refused: rewriting it would mean writing a current key it
  // cannot read.
  //
  // `write(keysValue, infoValue)` is the one thing a person and a service
  // differ in beyond how they are located, so both go through this.
  // -------------------------------------------------------------------------
  private dropPrevious(kind: string, label: string, current: Json,
                       context: ActContext | null | undefined,
                       write: (keysValue: string,
                               infoValue: string) => boolean,
                       ttlS?: number): Json {
    const { log, audit } = this.deps;
    log.debug('Entering Krb5PersonKeys.dropPrevious(). ' + kind + '=' +
              label);
    if (!current || !current.keys) {
      log.debug('Leaving Krb5PersonKeys.dropPrevious(). No stored key.');
      return this.refusal('STS-ADMIN-0605', label + ' holds no stored ' +
                          'Kerberos key, so there are no previous versions ' +
                          'to drop.');
    }
    const opened = this.openRecord(current.keys);
    if (!opened.ok) {
      log.debug('Leaving Krb5PersonKeys.dropPrevious(). Unreadable.');
      return this.refusal('STS-ADMIN-0607', 'The stored Kerberos key for ' +
                          label + ' cannot be opened on this service (' +
                          opened.why + '), so its previous versions cannot ' +
                          'be dropped without rewriting a key it cannot ' +
                          'read. Clear or rotate it instead.');
    }
    const nowMs = Date.now();
    const stored = Array.isArray(opened.record.previous) ?
                   opened.record.previous : [];
    const live = this.withinBounds(stored, nowMs, ttlS);
    if (!stored.length) {
      log.debug('Leaving Krb5PersonKeys.dropPrevious(). Nothing kept.');
      return { ok: true, dropped: 0, kvnos: [], principal: label,
               message: label + ' keeps no previous key version, so there ' +
                        'was nothing to drop.' };
    }
    const sealed = this.sealRecord(Object.assign({}, opened.record,
                                                 { previous: [] }));
    const info = Object.assign({}, this.parseInfo(current.info) || {},
                               { retained: [] });
    if (!sealed || !write(sealed.value, JSON.stringify(info))) {
      log.debug('Leaving Krb5PersonKeys.dropPrevious(). Not written.');
      return this.refusal('STS-ADMIN-0607', 'The previous Kerberos key ' +
                          'versions of ' + label + ' could not be removed ' +
                          'from its entry.');
    }
    const kvnos = live.map(function (one) {
      return Number(one.kvno);
    });
    audit.audit({
      action: 'admin.krb5.previous.dropped',
      actor: String((context || {}).actor || ''),
      protocol: 'Kerberos', channel: 'internal', target: label,
      summary: 'The previous Kerberos key versions of ' + label + ' (' +
               (kvnos.length ? 'kvno ' + kvnos.join(', ') : 'none still in ' +
                   'their window') +
               ') were dropped through the ' +
               String((context || {}).via || 'console'),
      detail: { kind: kind, kvnos: kvnos,
                via: String((context || {}).via || 'console') }
    });
    log.info('krb5-keys: dropped the previous key versions of ' + label +
             ' (' + (kvnos.join(', ') || 'only expired ones were left') +
             '); a ticket under any of them is now refused ' +
             'KRB_AP_ERR_BADKEYVER.');
    log.debug('Leaving Krb5PersonKeys.dropPrevious(). ' + kvnos.length +
              ' dropped.');
    return { ok: true, dropped: kvnos.length, kvnos: kvnos, principal: label,
             currentKvno: Number(opened.record.kvno),
             message: kvnos.length
               ? 'Dropped previous kvno ' + kvnos.join(', ') + ' of ' +
                 label + '. ' +
                 'A ticket issued ' +
                 'under ' + (kvnos.length === 1 ? 'it' : 'any of ' +
                     'them') +
                 ' is now refused KRB_AP_ERR_BADKEYVER; kvno ' +
                 opened.record.kvno +
                 ' is untouched.'
               : label + ' kept only previous versions already past their ' +
                 'window; they are removed from storage now.' };
  }

  dropPreviousPersonKeys(name: unknown, context?: ActContext): Json {
    const { log, principals } = this.deps;
    const directory = this.directory;
    log.debug('Entering Krb5PersonKeys.dropPreviousPersonKeys(). name=' +
              name);
    const noKdc = this.noKdcHere();
    if (noKdc) {
      log.debug('Leaving Krb5PersonKeys.dropPreviousPersonKeys(). No KDC in ' +
                'this trust realm.');
      return noKdc;
    }
    const who = String(name == null ? '' : name).trim();
    if (!directory) {
      log.debug('Leaving Krb5PersonKeys.dropPreviousPersonKeys(). No ' +
                'directory.');
      return this.refusal('STS-ADMIN-0609', 'There is no directory in this ' +
                          'process.');
    }
    if (!who || this.personNameProblem(who)) {
      log.debug('Leaving Krb5PersonKeys.dropPreviousPersonKeys(). No usable ' +
                'name.');
      return this.refusal('STS-ADMIN-0608', 'Name the person whose previous ' +
                          'Kerberos key versions to drop, as `username`.');
    }
    const current = directory.readPerson(who);
    if (!current) {
      log.debug('Leaving Krb5PersonKeys.dropPreviousPersonKeys(). Nobody by ' +
                'that name.');
      return this.refusal('STS-ADMIN-0608', 'There is nobody called "' + who +
                          '" in this trust realm\'s directory, which is the ' +
                          'one its KDC reads.');
    }
    const result = this.dropPrevious('person', who + '@' + principals.REALM,
      current, context,
      function (keysValue, infoValue) {
        return directory.writePerson(who, keysValue, infoValue);
      });
    if (result.ok) {
      result.username = who;
    }
    log.debug('Leaving Krb5PersonKeys.dropPreviousPersonKeys(). ok=' +
              result.ok);
    return result;
  }

  dropPreviousServiceKeys(raw: unknown, context?: ActContext): Json {
    const { log } = this.deps;
    const directory = this.directory;
    log.debug('Entering Krb5PersonKeys.dropPreviousServiceKeys().');
    const noKdc = this.noKdcHere();
    if (noKdc) {
      log.debug('Leaving Krb5PersonKeys.dropPreviousServiceKeys(). No KDC in ' +
                'this trust realm.');
      return noKdc;
    }
    // THIS REALM'S KRBTGT IS ACCEPTED HERE TOO (#169): its previous versions
    // are dropped exactly as a service's are, which is how an operator ends a
    // rotation's window early without also invalidating the current key.
    if (this.isOwnKrbtgt(raw)) {
      log.debug('Leaving Krb5PersonKeys.dropPreviousServiceKeys(). krbtgt.');
      return this.dropPreviousKrbtgtKeys(context);
    }
    const spn = this.normaliseSpn(raw);
    if (!spn.ok) {
      log.debug('Leaving Krb5PersonKeys.dropPreviousServiceKeys(). Not an ' +
                'SPN.');
      return this.refusal('STS-ADMIN-0603', spn.error);
    }
    if (!directory) {
      log.debug('Leaving Krb5PersonKeys.dropPreviousServiceKeys(). No ' +
                'directory.');
      return this.refusal('STS-ADMIN-0609', 'There is no directory in this ' +
                          'process.');
    }
    const result = this.dropPrevious('service', spn.identifier,
      directory.readService(spn.identifier), context,
      function (keysValue, infoValue) {
        return directory.writeService(spn.identifier, keysValue, infoValue);
      });
    if (result.ok) {
      result.spn = spn.spn;
    }
    log.debug('Leaving Krb5PersonKeys.dropPreviousServiceKeys(). ok=' +
              result.ok);
    return result;
  }

  // =========================================================================
  // THE KRBTGT KEY (#169, 2026-09-23).
  //
  // Until this section a realm's krbtgt key was derived at startup from
  // `krb5.krbtgtPassword` at the fixed `krb5.kvno`, was never rotated and
  // kept no previous version — so one leaked krbtgt key let whoever held it
  // forge ticket-granting tickets (a "golden ticket") for as long as the
  // service ran with that setting. It is now a STORED key like a service
  // principal's, on the application entry `krbtgt/<REALM>@<REALM>` under
  // `ou=applications` (every identity maps to an entry), in the same sealed
  // `krb5ServiceKeys` / `krb5ServiceKeyInfo` pair, with `previous` inside the
  // seal. What differs from a service principal is decided here:
  //
  //   * **RANDOM, AND IN PRODUCT FROM THE START.** RFC 3961 random-to-key for
  //     every enctype the KDC offers — no password, which is a weaker key
  //     than the KDC can make and one Active Directory never lets an
  //     operator choose. Product makes it at the realm's first KDC use
  //     (`krbtgtKeys()` below, or `ensureKrbtgtKey()` at startup, which a
  //     cluster makes under a claim so exactly one node's key wins).
  //     Development keeps the password-derived key the fixtures publish
  //     until somebody rotates by hand.
  //   * **NO KEYTAB, EVER.** Nothing reads the key back out: not a view,
  //     not the audit log, not an LDAP search (the attribute is withheld),
  //     and no rotation answers with one — the one party that needs the key
  //     is this KDC.
  //   * **ITS WINDOW IS A TGT'S, RENEWALS INCLUDED** (`krbtgtTtlSeconds()`):
  //     every TGT is sealed under it, so a kept version lives the longer of
  //     the ticket and renew lifetimes plus the skew — the sign-out
  //     horizon's bound (#111) — unless `krb5.retainedKeyTtlS` names a
  //     number.
  //   * **"ROTATE AND INVALIDATE" KEEPS NOTHING** — Active Directory's double
  //     reset in one act: every TGT in the realm is refused
  //     KRB_AP_ERR_BADKEYVER at its next TGS-REQ. It is also the one act
  //     that may replace a record this process cannot OPEN
  //     (`STS-KRB-0161`), because it carries nothing of it forward; every
  //     other path refuses such a record and never rewrites it.
  //
  // WHEN a rotation happens is `krb5_krbtgt_rotation.ts`'s; this is what one
  // IS. Synchronous where the KDC asks (a directory read and a seal opened),
  // asynchronous only where a development rotation derives the key it
  // replaces from the password.
  // =========================================================================
  krbtgtIdentifier(): string {
    const { log, principals } = this.deps;
    log.debug("Entering Krb5PersonKeys.krbtgtIdentifier().");
    log.debug("Leaving Krb5PersonKeys.krbtgtIdentifier().");
    return 'krbtgt/' + principals.REALM + '@' + principals.REALM;
  }

  // Is `raw` this realm's own krbtgt, as an SPN or a full principal name?
  private isOwnKrbtgt(raw: unknown): boolean {
    const { log, principals } = this.deps;
    log.debug("Entering Krb5PersonKeys.isOwnKrbtgt().");
    const text = String(raw == null ? '' : raw).trim();
    log.debug("Leaving Krb5PersonKeys.isOwnKrbtgt().");
    return text === 'krbtgt/' + principals.REALM ||
           text === this.krbtgtIdentifier();
  }

  // Seconds a retired krbtgt version is kept: `krb5.retainedKeyTtlS` when it
  // names a number, and otherwise the longest a TGT sealed under it can
  // still be presented — its lifetime or, renewed, its renew-till — plus the
  // clock skew the KDC allows. A renewal re-seals under the CURRENT key, so
  // the ticket lifetime alone would do for a TGT renewed on time; the renew
  // bound is the one that cannot be wrong, and is the sign-out horizon's.
  krbtgtTtlSeconds(): number {
    const { log, config } = this.deps;
    log.debug("Entering Krb5PersonKeys.krbtgtTtlSeconds().");
    const configured = Number(config.value('krb5.retainedKeyTtlS'));
    if (Number.isFinite(configured) && configured > 0) {
      log.debug("Leaving Krb5PersonKeys.krbtgtTtlSeconds(). Configured.");
      return configured;
    }
    log.debug("Leaving Krb5PersonKeys.krbtgtTtlSeconds().");
    return Math.max(Number(config.value('krb5.ticketLifetimeSeconds')) || 0,
                    Number(config.value('krb5.renewLifetimeSeconds')) || 0) +
           (Number(config.value('krb5.clockSkew')) || 0);
  }

  // The entry and what is on it: `{ entry, record, info, unreadable, why }`.
  // A record is only answered when it opens AND names this realm's krbtgt —
  // a value copied from another realm's entry is refused like an unreadable
  // one.
  private readKrbtgt(): Json {
    const { log, principals } = this.deps;
    log.debug("Entering Krb5PersonKeys.readKrbtgt().");
    const directory = this.directory;
    const entry = directory ? directory.readService(this.krbtgtIdentifier())
                            : null;
    const info = entry ? this.parseInfo(entry.info) : null;
    if (!entry || !entry.keys) {
      log.debug("Leaving Krb5PersonKeys.readKrbtgt(). None stored.");
      return { entry: entry, record: null, info: info, unreadable: false };
    }
    const opened = this.openRecord(entry.keys);
    const spn = 'krbtgt/' + principals.REALM;
    if (!opened.ok || opened.record.spn !== spn ||
        opened.record.realm !== principals.REALM) {
      log.debug("Leaving Krb5PersonKeys.readKrbtgt(). Unreadable.");
      return { entry: entry, record: null, info: info, unreadable: true,
               why: opened.ok ? 'it is bound to another principal'
                              : opened.why };
    }
    log.debug("Leaving Krb5PersonKeys.readKrbtgt(). kvno " +
              opened.record.kvno + ".");
    return { entry: entry, record: opened.record, info: info,
             unreadable: false };
  }

  // Is the persistence store one several processes share (postgres)? Then a
  // first krbtgt key is made under a claim, never on a KDC's request path.
  private sharedStore(): boolean {
    const { log, persistence } = this.deps;
    log.debug("Entering Krb5PersonKeys.sharedStore().");
    try {
      const store = persistence();
      log.debug("Leaving Krb5PersonKeys.sharedStore().");
      return !!(store && typeof store.clusterStore === 'function' &&
                store.clusterStore());
    } catch (e) {
      log.debug("Caught in Krb5PersonKeys.sharedStore(): " +
                ((e && e.message) || e));
      log.debug("Leaving Krb5PersonKeys.sharedStore(). No store.");
      // No persistence module in this process: nothing is shared.
      return false;
    }
  }

  // -------------------------------------------------------------------------
  // THE KDC'S KEY SOURCE FOR THIS REALM'S KRBTGT — `serviceKeys()`'s shape,
  // `{ kvno, keys, retained }`, or null. Null in development until a
  // rotation by hand stored a key (the principal database then derives the
  // krbtgt from its password, as it always did). In product a realm with none
  // yet is given one HERE when this process is the only writer of its store;
  // behind a shared store the creation is `ensureKrbtgtKey()`'s, under a
  // claim, and this answers null until it lands — the KDC refuses in the
  // meantime rather than make a key another node might be making too.
  // -------------------------------------------------------------------------
  krbtgtKeys(): Json {
    const { log, principals, realms, errorCodes } = this.deps;
    log.debug("Entering Krb5PersonKeys.krbtgtKeys().");
    if (!this.directory) {
      log.debug("Leaving Krb5PersonKeys.krbtgtKeys(). No directory.");
      return null;
    }
    const got = this.readKrbtgt();
    if (got.record) {
      const keys = this.keyPairs(got.record.keys);
      log.debug("Leaving Krb5PersonKeys.krbtgtKeys(). kvno " +
                got.record.kvno + ".");
      return keys.length
        ? { kvno: Number(got.record.kvno), keys: keys,
            retained: this.retainedForKdc(got.record, Date.now(),
                                          this.krbtgtTtlSeconds()) }
        : null;
    }
    if (got.unreadable) {
      const realmId = realms.currentId();
      if (!krbtgtUnreadableSaid.has(realmId)) {
        krbtgtUnreadableSaid.add(realmId);
        log.error(errorCodes.tag('STS-KRB-0161') + 'krb5-keys: the stored ' +
                  'krbtgt key of ' + principals.REALM + ' cannot be used (' +
                  got.why + '). It is NOT rewritten; the KDC issues no ' +
                  'ticket-granting ticket until "Rotate and invalidate" at ' +
                  '/admin/kerberos/principals replaces it. Said once per ' +
                  'process.');
      }
      log.debug("Leaving Krb5PersonKeys.krbtgtKeys(). Unreadable.");
      return null;
    }
    if (principals.krbtgtFromPassword) {
      log.debug("Leaving Krb5PersonKeys.krbtgtKeys(). Development: derived " +
                "from the password.");
      return null;
    }
    if (this.sharedStore()) {
      // The promise is the claim's business; a failure is logged there.
      this.ensureKrbtgtKey().catch(function (e: Json): void {
        log.debug("Caught in a callback in Krb5PersonKeys.krbtgtKeys(): " +
                  ((e && e.message) || e));
      });
      log.debug("Leaving Krb5PersonKeys.krbtgtKeys(). Being made under a " +
                "claim.");
      return null;
    }
    const made = this.createKrbtgtKey({ via: 'first use' });
    log.debug("Leaving Krb5PersonKeys.krbtgtKeys(). " +
              (made.ok ? 'Made.' : 'Not made.'));
    return made.ok ? this.krbtgtKeys() : null;
  }

  // -------------------------------------------------------------------------
  // THE FIRST KEY: at `krb5.kvno`, nothing kept. Refuses (and changes
  // nothing) where a key, readable or not, is already stored — a creation
  // never replaces anything.
  // -------------------------------------------------------------------------
  createKrbtgtKey(context?: ActContext): Json {
    const { log, config } = this.deps;
    log.debug("Entering Krb5PersonKeys.createKrbtgtKey().");
    const noKdc = this.noKdcHere();
    if (noKdc) {
      log.debug("Leaving Krb5PersonKeys.createKrbtgtKey(). No KDC here.");
      return noKdc;
    }
    if (!this.directory) {
      log.debug("Leaving Krb5PersonKeys.createKrbtgtKey(). No directory.");
      return this.refusal('STS-ADMIN-0609', 'There is no directory in this ' +
                          'process, so there is nowhere to keep a krbtgt key.');
    }
    const got = this.readKrbtgt();
    if (got.record || got.unreadable) {
      log.debug("Leaving Krb5PersonKeys.createKrbtgtKey(). One is there.");
      return { ok: true, existing: true,
               kvno: got.record ? Number(got.record.kvno) : null };
    }
    const result = this.writeKrbtgt(Number(config.value('krb5.kvno')), [],
                                    'created', context, got.info, false);
    log.debug("Leaving Krb5PersonKeys.createKrbtgtKey().");
    return result;
  }

  // -------------------------------------------------------------------------
  // THE FIRST KEY, ONCE FOR THE CLUSTER. The node that wins the claim
  // catches up with the store, makes the key if it is still absent, and
  // gives the claim back only once the write has committed — so a node that
  // loses reads the winner's key rather than making a second one
  // (`credentials.bootstrapOnce()`'s shape). Without a shared store it is
  // `createKrbtgtKey()`. One in flight per realm. Never rejects.
  // -------------------------------------------------------------------------
  ensureKrbtgtKey(realmId?: string): Promise<Json> {
    const self = this;
    const { log, realms, principals, claims, persistence,
            errorCodes } = this.deps;
    const id = realmId === undefined ? realms.currentId() : String(realmId);
    log.debug("Entering Krb5PersonKeys.ensureKrbtgtKey(). realm=" + id);
    const held = krbtgtInFlight.get(id);
    if (held) {
      log.debug("Leaving Krb5PersonKeys.ensureKrbtgtKey(). In flight.");
      return held;
    }
    const realm = realms.get(id);
    if (!realm) {
      log.debug("Leaving Krb5PersonKeys.ensureKrbtgtKey(). No such realm.");
      return Promise.resolve({ ok: false, why: 'no such realm' });
    }
    const work = Promise.resolve(realms.run(realm, async function ():
        Promise<Json> {
      if (!principals.enabledIn(id) || principals.krbtgtFromPassword ||
          !self.directory) {
        return { ok: true, made: false, why: 'not a product KDC with a ' +
                                             'directory' };
      }
      const before = self.readKrbtgt();
      if (before.record || before.unreadable) {
        return { ok: true, made: false, existing: true };
      }
      if (!self.sharedStore()) {
        return self.createKrbtgtKey({ via: 'startup' });
      }
      const store = persistence();
      const claimed = await claims().claim({ scope: 'krb5.krbtgt-create',
        value: principals.REALM, ttlMs: KRBTGT_CREATE_CLAIM_MS, realm: id });
      if (!claimed.ok && claimed.reason === 'used') {
        await Promise.resolve(typeof store.syncNow === 'function'
          ? store.syncNow() : null).catch(function (e: Json): void {
          log.debug("Caught in a callback in " +
                    "Krb5PersonKeys.ensureKrbtgtKey(): " +
                    ((e && e.message) || e));
        });
        const after = self.readKrbtgt();
        if (!after.record) {
          log.warn(errorCodes.tag('STS-KRB-0162') + 'krb5-keys: another ' +
                   'node is making the krbtgt key of ' + principals.REALM +
                   ' and it has not reached this one yet; its KDC refuses ' +
                   'until it does.');
        }
        return { ok: !!after.record, made: false, lost: true };
      }
      if (!claimed.ok) {
        log.error(errorCodes.tag('STS-KRB-0163') + 'krb5-keys: the krbtgt ' +
                  'key of ' + principals.REALM + ' was NOT made: the store ' +
                  'could not be asked whether another node is making it (' +
                  (claimed.why || claimed.reason) + ').');
        return { ok: false, made: false, why: 'the store could not be asked' };
      }
      await Promise.resolve(typeof store.syncNow === 'function'
        ? store.syncNow() : null).catch(function (e: Json): void {
        log.debug("Caught in a callback in Krb5PersonKeys.ensureKrbtgtKey(): " +
                  ((e && e.message) || e));
      });
      const made = self.createKrbtgtKey({ via: 'startup' });
      await Promise.resolve(typeof store.flush === 'function'
        ? store.flush() : null).catch(function (e: Json): void {
        log.debug("Caught in a callback in Krb5PersonKeys.ensureKrbtgtKey(): " +
                  ((e && e.message) || e));
      });
      await Promise.resolve(claims().release(claimed.handle))
        .catch(function (e: Json): void {
          log.debug("Caught in a callback in " +
                    "Krb5PersonKeys.ensureKrbtgtKey(): " +
                    ((e && e.message) || e));
        });
      return made;
    })).catch(function (e: Json): Json {
      log.error(errorCodes.tag('STS-KRB-0160') + 'krb5-keys: making the ' +
                'krbtgt key of trust realm "' + id + '" failed: ' +
                ((e && e.message) || e));
      return { ok: false, made: false, why: String((e && e.message) || e) };
    }).then(function (answer: Json): Json {
      krbtgtInFlight.delete(id);
      return answer;
    });
    krbtgtInFlight.set(id, work);
    log.debug("Leaving Krb5PersonKeys.ensureKrbtgtKey(). Started.");
    return work;
  }

  // -------------------------------------------------------------------------
  // A ROTATION. `invalidate` keeps nothing — AD's double reset in one act.
  // Otherwise the key it replaces is kept for `krbtgtTtlSeconds()`: the
  // stored one, or in development the key derived from the password, so a
  // TGT sealed under the published key an instant before still opens.
  // -------------------------------------------------------------------------
  async rotateKrbtgt(options?: Json): Promise<Json> {
    const { log, principals } = this.deps;
    const o = options || {};
    const invalidate = !!o.invalidate;
    log.debug("Entering Krb5PersonKeys.rotateKrbtgt(). invalidate=" +
              invalidate);
    const noKdc = this.noKdcHere();
    if (noKdc) {
      log.debug("Leaving Krb5PersonKeys.rotateKrbtgt(). No KDC here.");
      return noKdc;
    }
    if (!this.directory) {
      log.debug("Leaving Krb5PersonKeys.rotateKrbtgt(). No directory.");
      return this.refusal('STS-ADMIN-0609', 'There is no directory in this ' +
                          'process, so there is nowhere to keep a krbtgt key.');
    }
    const got = this.readKrbtgt();
    if (got.unreadable && !invalidate) {
      log.debug("Leaving Krb5PersonKeys.rotateKrbtgt(). Unreadable.");
      return this.refusal('STS-KRB-0161', 'The stored krbtgt key of ' +
        principals.REALM + ' cannot be opened on this service (' + got.why +
        '), so it cannot be rotated without dropping a key it cannot read. ' +
        '"Rotate and invalidate" replaces it and keeps nothing.');
    }
    let outgoing: Json = got.record;
    if (!outgoing && !got.unreadable && !invalidate &&
        principals.krbtgtFromPassword) {
      // DEVELOPMENT'S FIRST ROTATION: the key it replaces is the one derived
      // from the password, at the configured kvno — kept, so the TGTs a
      // reader was decrypting with the published password still open.
      const configured = principals.find(['krbtgt', principals.REALM],
                                         principals.REALM);
      if (configured && !configured.directoryKeys) {
        const keys: Record<string, string> = {};
        const etypes = principals.KDC_ETYPES.slice();
        for (let i = 0; i < etypes.length; i++) {
          keys[etypes[i]] = Buffer.from(
            await principals.longTermKey(configured, etypes[i]))
            .toString('base64');
        }
        outgoing = { kvno: Number(configured.kvno), keys: keys,
                     createdAt: '' };
      }
    }
    const base = outgoing ? Number(outgoing.kvno)
      : got.info && Number.isFinite(Number(got.info.kvno))
        ? Number(got.info.kvno)
        : principals.krbtgtFromPassword ? Number(principals.KVNO) : null;
    const kvno = base === null ? Number(this.deps.config.value('krb5.kvno'))
                               : base + 1;
    const nowMs = Number(o.nowMs) || Date.now();
    const kept = invalidate ? []
      : this.retire(outgoing, kvno, nowMs, this.krbtgtTtlSeconds());
    const result = this.writeKrbtgt(kvno, kept,
                                    invalidate ? 'invalidated' : 'rotated',
                                    o.context, got.info, invalidate,
                                    outgoing ? Number(outgoing.kvno) : base,
                                    String(o.reason || 'requested'), nowMs);
    log.debug("Leaving Krb5PersonKeys.rotateKrbtgt(). ok=" + result.ok);
    return result;
  }

  // The one write every krbtgt act makes: random keys for every enctype
  // offered, `kept` as the previous versions, sealed, on the entry — made if
  // it is not there. The audit row names kvnos and enctypes, never a key.
  private writeKrbtgt(kvno: number, kept: Json[], act: string,
                      context: ActContext | null | undefined, priorInfo: Json,
                      invalidated: boolean, previousKvno?: number | null,
                      reason?: string, atMs?: number): Json {
    const { log, principals, kcrypto, applications, audit,
            errorCodes } = this.deps;
    const directory = this.directory;
    const identifier = this.krbtgtIdentifier();
    log.debug("Entering Krb5PersonKeys.writeKrbtgt(). " + act + " kvno " +
              kvno);
    const ttlS = this.krbtgtTtlSeconds();
    const now = new Date(atMs || Date.now());
    const etypes = principals.KDC_ETYPES.slice();
    const keys: Record<string, string> = {};
    etypes.forEach(function (etype) {
      keys[etype] = Buffer.from(kcrypto.randomBytes(
        kcrypto.etypeById(etype).keyBytes)).toString('base64');
    });
    if (!directory.readService(identifier)) {
      // THE ENTRY, through the registry's own door: `krbtgt/<REALM>@<REALM>`
      // is the KDC's own principal, a service principal by kind.
      const created: Json = applications.createApplication({
        identifier: identifier, kind: 'kerberos-service',
        protocols: ['krb5'],
        fields: { krb5ServicePrincipalName: identifier },
        actor: String((context || {}).actor || '')
      });
      if (!created.ok || !directory.readService(identifier)) {
        log.error(errorCodes.tag('STS-KRB-0160') + 'krb5-keys: no entry ' +
                  'could be made for ' + identifier + ': ' +
                  ((created.errors || []).join(' ') || 'the directory did ' +
                   'not hold it afterwards') + '.');
        log.debug("Leaving Krb5PersonKeys.writeKrbtgt(). No entry.");
        return this.refusal('STS-KRB-0160', 'No directory entry could be ' +
                            'made for ' + identifier + ', so no krbtgt key ' +
                            'was stored.');
      }
    }
    const sealed = this.sealRecord({ v: RECORD_VERSION,
                                     spn: 'krbtgt/' + principals.REALM,
                                     realm: principals.REALM, kvno: kvno,
                                     createdAt: now.toISOString(),
                                     keys: keys, previous: kept });
    const prior = priorInfo || {};
    const info = {
      kvno: kvno, etypes: etypes, sealed: !!(sealed && sealed.sealed),
      krbtgt: true,
      createdAt: prior.createdAt || now.toISOString(),
      keyCreatedAt: now.toISOString(),
      rotatedAt: act === 'created' ? String(prior.rotatedAt || '')
                                   : now.toISOString(),
      invalidatedAt: invalidated ? now.toISOString()
                                 : String(prior.invalidatedAt || ''),
      retained: this.retainedInfo(kept, now.getTime(), ttlS)
    };
    if (!sealed || !directory.writeService(identifier, sealed.value,
                                           JSON.stringify(info))) {
      log.error(errorCodes.tag('STS-KRB-0160') + 'krb5-keys: the krbtgt key ' +
                'of ' + principals.REALM + ' could not be ' +
                (sealed ? 'written' : 'sealed') + '; nothing changed.');
      log.debug("Leaving Krb5PersonKeys.writeKrbtgt(). Not stored.");
      return this.refusal('STS-KRB-0160', 'The new krbtgt key of ' +
                          principals.REALM + ' could not be ' +
                          (sealed ? 'written to its directory entry'
                                  : 'encrypted under the key-encryption key') +
                          ', so nothing changed.');
    }
    krbtgtUnreadableSaid.delete(this.deps.realms.currentId());
    const retainedKvnos = kept.map(function (one) {
      return Number(one.kvno);
    });
    const via = String((context || {}).via || 'scheduler');
    const manual = !!(context && context.actor) || /console|api/.test(via);
    audit.audit({
      action: (manual ? 'admin.' : '') + 'krb5.krbtgt.' + act,
      actor: String((context || {}).actor || ''),
      protocol: 'Kerberos', channel: 'internal', target: identifier,
      summary: 'The krbtgt key of ' + principals.REALM + ' was ' + act +
               ' (kvno ' + kvno + (retainedKvnos.length
                 ? ', keeping kvno ' + retainedKvnos.join(', ') : '') +
               ') through the ' + via,
      detail: { kvno: kvno, previousKvno: previousKvno === undefined
                  ? null : previousKvno,
                etypes: etypes, retainedKvnos: retainedKvnos,
                invalidated: invalidated, reason: String(reason || ''),
                via: via }
    });
    log.info('krb5-keys: the krbtgt key of ' + principals.REALM + ' was ' +
             act + ' at kvno ' + kvno +
             (retainedKvnos.length
               ? '; kvno ' + retainedKvnos.join(', ') + ' is kept for the ' +
                 'TGTs already sealed under it'
               : invalidated ? '; NOTHING is kept, so every TGT issued ' +
                 'before now is refused KRB_AP_ERR_BADKEYVER' : '') + '.');
    const retained = this.retainedRows(info.retained, now.getTime(), ttlS);
    log.debug("Leaving Krb5PersonKeys.writeKrbtgt().");
    return {
      ok: true, act: act, principal: identifier, kvno: kvno,
      previousKvno: previousKvno === undefined ? null : previousKvno,
      etypes: etypes, sealed: info.sealed, retained: retained,
      invalidated: invalidated,
      message: 'The krbtgt key of ' + principals.REALM + ' was ' + act +
               ' at kvno ' + kvno + '. ' +
               (retained.length
                 ? 'TGTs sealed under kvno ' + retained.map(function (one) {
                   return one.kvno;
                 }).join(', ') + ' are still accepted until ' +
                   retained.map(function (one) {
                     return one.expiresAt;
                   }).join(', ') + '.'
                 : invalidated
                   ? 'Nothing was kept: every TGT issued before now is ' +
                     'refused, and everybody runs a fresh AS exchange.'
                   : '') +
               ' No key is shown, here or anywhere.'
    };
  }

  // The public state of this realm's krbtgt, for the console, the API and
  // the rotation job: where the key comes from, its kvno, when it was made
  // and last rotated, and the versions kept. The record is opened only to
  // tell a readable one from an unreadable one; nothing of it is answered.
  krbtgtState(): Json {
    const { log, principals, kcrypto } = this.deps;
    log.debug("Entering Krb5PersonKeys.krbtgtState().");
    const kerberos = principals.kerberosRealmOf();
    const ttlS = this.krbtgtTtlSeconds();
    const got = this.directory && kerberos.enabled && kerberos.active
      ? this.readKrbtgt() : { record: null, info: null, unreadable: false };
    const info = got.info || {};
    const nowMs = Date.now();
    const source = got.record ? 'stored'
      : got.unreadable ? 'unreadable'
      : principals.krbtgtFromPassword ? 'password' : 'none';
    const retained = got.record
      ? this.retainedRows(info.retained, nowMs, ttlS) : [];
    const etypes = got.record ? (info.etypes || []).map(Number)
      : source === 'password' ? principals.KDC_ETYPES.slice() : [];
    const openUntil = retained.reduce(function (most: string, one: Json) {
      return one.expiresAt > most ? one.expiresAt : most;
    }, '');
    log.debug("Leaving Krb5PersonKeys.krbtgtState(). " + source);
    return {
      principal: kerberos.enabled && kerberos.active
        ? this.krbtgtIdentifier() : '',
      source: source,
      kvno: got.record ? Number(got.record.kvno)
        : source === 'password' ? Number(principals.KVNO) : null,
      etypes: etypes.map(function (etype: number) {
        return { etype: etype, name: kcrypto.etypeName(etype) };
      }),
      sealed: got.record ? !!info.sealed : false,
      createdAt: got.record ? String(info.createdAt || '') : '',
      keyCreatedAt: got.record ? String(info.keyCreatedAt ||
                                        info.createdAt || '') : '',
      rotatedAt: got.record ? String(info.rotatedAt || '') : '',
      invalidatedAt: got.record ? String(info.invalidatedAt || '') : '',
      retained: retained,
      windowOpenUntil: openUntil,
      retainedTtlSeconds: ttlS,
      why: got.unreadable ? String(got.why || '') : ''
    };
  }

  // "Drop previous versions" for the krbtgt: the rotation's window ended now,
  // the current key untouched.
  dropPreviousKrbtgtKeys(context?: ActContext): Json {
    const { log } = this.deps;
    const directory = this.directory;
    const identifier = this.krbtgtIdentifier();
    log.debug("Entering Krb5PersonKeys.dropPreviousKrbtgtKeys().");
    const noKdc = this.noKdcHere();
    if (noKdc) {
      log.debug("Leaving Krb5PersonKeys.dropPreviousKrbtgtKeys(). No KDC.");
      return noKdc;
    }
    if (!directory) {
      log.debug("Leaving Krb5PersonKeys.dropPreviousKrbtgtKeys(). No " +
                "directory.");
      return this.refusal('STS-ADMIN-0609', 'There is no directory in this ' +
                          'process.');
    }
    const result = this.dropPrevious('krbtgt', identifier,
      directory.readService(identifier), context,
      function (keysValue, infoValue) {
        return directory.writeService(identifier, keysValue, infoValue);
      }, this.krbtgtTtlSeconds());
    if (result.ok) {
      result.spn = identifier.replace(/@[^@]*$/, '');
    }
    log.debug("Leaving Krb5PersonKeys.dropPreviousKrbtgtKeys(). ok=" +
              result.ok);
    return result;
  }

  // -------------------------------------------------------------------------
  // WHETHER A KEYTAB CAN BE MADE FOR `name` AT ALL, asked before anything is
  // derived — and by the console's reset BEFORE it changes the person's
  // password, so an administrator is never left having reset a password for a
  // keytab that was then refused. A refusal, or null.
  // -------------------------------------------------------------------------
  personKeytabRefusal(name: unknown): Json {
    const { log } = this.deps;
    const directory = this.directory;
    log.debug('Entering Krb5PersonKeys.personKeytabRefusal(). name=' + name);
    const noKdc = this.noKdcHere();
    if (noKdc) {
      log.debug('Leaving Krb5PersonKeys.personKeytabRefusal(). No KDC in ' +
                'this trust realm.');
      return noKdc;
    }
    const who = String(name == null ? '' : name).trim();
    if (!directory) {
      log.debug('Leaving Krb5PersonKeys.personKeytabRefusal(). No ' +
                'directory.');
      return this.refusal('STS-KRB-0130', 'There is no directory in this ' +
                          'process, so there is nobody to make a keytab for.');
    }
    if (!who || this.personNameProblem(who)) {
      log.debug('Leaving Krb5PersonKeys.personKeytabRefusal(). No usable ' +
                'name.');
      return this.refusal('STS-KRB-0130', 'Name the person whose keytab to ' +
                          'make, as `username`: a single-component name, ' +
                          'which is what a Kerberos user principal is.');
    }
    if (!directory.readPerson(who)) {
      log.debug('Leaving Krb5PersonKeys.personKeytabRefusal(). Nobody by ' +
                'that name.');
      return this.refusal('STS-KRB-0130', 'There is nobody called "' + who +
                          '" in this trust realm\'s directory, which is the ' +
                          'one its KDC reads.');
    }
    if (this.personDisabled(who)) {
      log.debug('Leaving Krb5PersonKeys.personKeytabRefusal(). Disabled.');
      return this.refusal('STS-KRB-0134', who + '\'s account is disabled, ' +
                          'and the KDC refuses a disabled account ' +
                          'KDC_ERR_CLIENT_REVOKED whatever key it presents, ' +
                          'so a keytab for it would be a file that cannot ' +
                          'sign in. Enable the account first.');
    }
    if (this.productKdc() && !this.personKeysEnabled()) {
      log.debug('Leaving Krb5PersonKeys.personKeytabRefusal(). Switched ' +
                'off.');
      return this.refusal('STS-KRB-0131', 'krb5.personKeys is off, so this ' +
                          'KDC authenticates no person with keys of their ' +
                          'own and a keytab would sign nobody in.');
    }
    log.debug('Leaving Krb5PersonKeys.personKeytabRefusal(). None.');
    return null;
  }

  // -------------------------------------------------------------------------
  // A PERSON'S KEYTAB (#59, 2026-09-22) — FROM A PASSWORD IN HAND, AND FROM
  // NOTHING ELSE.
  //
  // A keytab is how a client that cannot type a password — a batch job, a
  // cron entry, `kinit -k` on a server — authenticates as a person, and it is
  // exactly as good as that person's password: whoever holds it can get a TGT
  // as them. So the rule this file has kept since it was written holds here
  // too: **A STORED KEY IS NEVER READ BACK OUT.** The keytab is DERIVED, at
  // the moment of asking, from a password the caller has in hand:
  //
  //   * the PORTAL: the person's own current password, typed on the form and
  //     verified by `credentials.verify()` before this is called — which is
  //     also the re-authentication a password-equivalent export needs (a
  //     browser left signed in is not enough);
  //   * the CONSOLE and `/admin-api`: a password an administrator has just SET
  //     for the person (typed, or generated) — so the act is a password
  //     reset, the kvno moves up by one, and the person's old password stops
  //     working. An administrator never learns a password they did not
  //     choose.
  //
  // **THE DERIVED KEY IS COMPARED WITH THE ONE THE KDC HOLDS**, in constant
  // time, before anything is handed over, and a mismatch is a refusal. The
  // stored key is opened for that comparison and for nothing else. What it
  // buys: a keytab that would not work is never handed out — a password
  // written behind the observer, a stale record, a derivation that failed —
  // and the kvno and salt in the keytab are the KDC's own, rather than a guess
  // about them.
  //
  // **ONLY THE CURRENT kvno.** A client keytab is read by `kinit -k`, which
  // needs the key a new AS-REQ is checked against and nothing else; the
  // previous versions this file keeps exist to open tickets ALREADY issued,
  // and a keytab carrying them would be more password-equivalent material for
  // no use.
  //
  // **DEVELOPMENT MODE.** A development KDC does not key a person from their
  // password at all: every user shares `krb5.userPassword` (a service or
  // computer fixture has a literal one of its own, `krb5_principals.js`,
  // which no directory person is). A keytab
  // from the password the caller typed would not open a single AS-REP there,
  // so a development keytab is derived from the password THAT KDC uses for
  // the principal — which the service publishes on `/krb5/principals` anyway
  // — and the answer says so. The typed password is then not what the keytab
  // is made from, and nothing pretends otherwise.
  // -------------------------------------------------------------------------
  async personKeytab(name: unknown, password: unknown,
                     context?: ActContext): Promise<Json> {
    const { log, principals, kcrypto, keytab, audit, nodeCrypto,
            realms } = this.deps;
    log.debug('Entering Krb5PersonKeys.personKeytab(). name=' + name);
    const refused = this.personKeytabRefusal(name);
    if (refused) {
      log.debug('Leaving Krb5PersonKeys.personKeytab(). Refused before ' +
                'anything was derived.');
      return refused;
    }
    const who = String(name).trim();
    const via = String((context || {}).via || 'console');
    let made: Json;
    if (this.productKdc()) {
      made = await this.productPersonKeys(who, password);
    } else {
      made = await this.developmentPersonKeys(who);
    }
    if (!made.ok) {
      log.debug('Leaving Krb5PersonKeys.personKeytab(). Refused: ' +
                (made.errors || []).join(' '));
      return made;
    }
    const now = new Date();
    const entries = made.keys.map(function (pair: [number, Uint8Array]) {
      return { realm: principals.REALM, components: [who],
               nameType: keytab.NAME_TYPE_PRINCIPAL, timestamp: now,
               kvno: made.kvno, etype: pair[0], key: pair[1] };
    });
    const bytes = keytab.writeKeytab(entries);
    const etypes = made.keys.map(function (pair: [number, Uint8Array]) {
      return pair[0];
    });
    const principal = who + '@' + principals.REALM;
    audit.audit({
      action: 'krb5.keytab.person',
      actor: String((context || {}).actor || who),
      protocol: 'Kerberos', channel: 'internal', target: principal,
      summary: 'A keytab for ' + principal + ' (kvno ' + made.kvno + ', ' +
               etypes.map(kcrypto.etypeName).join(', ') + ') was made from ' +
               (made.source === 'password'
                 ? 'a password in hand'
                 : 'the development KDC\'s password for the principal') +
               ' through the ' + via,
      // The kvno, the enctypes and where it came from. Never a key, a salt
      // beyond what ETYPE-INFO2 publishes, the keytab or the password.
      detail: { kvno: made.kvno, etypes: etypes, source: made.source,
                via: via, fingerprint: nodeCrypto.createHash('sha256')
                  .update(bytes).digest('hex').slice(0, 16) }
    });
    log.info('krb5-keys: a keytab for ' + principal + ' at kvno ' +
             made.kvno + ' was made through the ' + via + ' and handed to ' +
             'the caller; it is not kept.');
    log.debug('Leaving Krb5PersonKeys.personKeytab(). kvno ' + made.kvno +
              '.');
    return {
      ok: true, username: who, principal: principal,
      realm: principals.REALM, trustRealm: realms.currentId(),
      kvno: made.kvno, etypes: etypes, keytabKvnos: [made.kvno],
      source: made.source,
      keytabFilename: who.replace(/[^A-Za-z0-9.-]+/g, '_') + '.kvno' +
                      made.kvno + '.keytab',
      keytab: bytes.toString('base64'),
      message: 'A keytab for ' + principal + ' at kvno ' + made.kvno +
               ' is in this answer and is not kept: this service cannot ' +
               'show it again. ' +
               (made.source === 'password'
                 ? 'It holds the keys derived from the password, and stops ' +
                   'working when that password changes.'
                 : 'This is a DEVELOPMENT KDC, which keys this principal ' +
                   'from the password on its principal record (krb5.userPassword ' +
                   'for every user) ' +
                   'rather than the person\'s, so that is what the keytab ' +
                   'was derived from.') +
               ' kinit -k -t ' +
               who.replace(/[^A-Za-z0-9.-]+/g, '_') + '.kvno' + made.kvno +
               '.keytab ' + principal + ' uses it.'
    };
  }

  // The keys a PRODUCT KDC holds for a person, re-derived from `password` and
  // checked against them. `{ ok, kvno, keys, source }` or a refusal.
  private async productPersonKeys(who: string, password: unknown):
      Promise<Json> {
    const self = this;
    const { log, principals, nodeCrypto } = this.deps;
    const directory = this.directory;
    log.debug('Entering Krb5PersonKeys.productPersonKeys(). name=' + who);
    if (typeof password !== 'string' || !password) {
      log.debug('Leaving Krb5PersonKeys.productPersonKeys(). No password.');
      return this.refusal('STS-KRB-0132', 'A keytab is derived from the ' +
                          'person\'s password, and none was given.');
    }
    // The password was just SET or VERIFIED, and either queued a derivation
    // (`observePassword()`); settle it so that the record read below is the
    // one this password produced.
    await this.idle();
    const current = directory.readPerson(who);
    const opened: Opened = current && current.keys
      ? this.openRecord(current.keys) : { ok: false, why: 'none' };
    if (!opened.ok || opened.record.name !== who ||
        opened.record.realm !== principals.REALM || !current.passwordHash ||
        opened.record.stamp !== this.stampOf(current.passwordHash)) {
      log.debug('Leaving Krb5PersonKeys.productPersonKeys(). No current ' +
                'keys (' + (opened.ok ? 'stale or bound elsewhere'
                                      : opened.why) + ').');
      return this.refusal('STS-KRB-0131', who + ' holds no Kerberos keys ' +
                          'for the password on their entry' +
                          (opened.ok || opened.why === 'none' ? ''
                            : ' (' + opened.why + ')') +
                          ', so the KDC would refuse any keytab. Their keys ' +
                          'are derived when a password is set or verified ' +
                          'here; a password written behind this service (an ' +
                          'ldapmodify) derives none until then.');
    }
    const record = opened.record;
    const pairs = this.keyPairs(record.keys);
    if (!pairs.length) {
      log.debug('Leaving Krb5PersonKeys.productPersonKeys(). No key for an ' +
                'enctype this KDC offers.');
      return this.refusal('STS-KRB-0131', who + '\'s stored keys cover no ' +
                          'enctype in krb5.enctypes; their next verified ' +
                          'sign-in derives the ones it lists.');
    }
    const keys: Array<[number, Uint8Array]> = [];
    for (const pair of pairs) {
      const derived = await self.deriveKey(pair[0], password, record.salt,
                                           null);
      const a = Buffer.from(derived);
      const b = Buffer.from(pair[1]);
      if (a.length !== b.length || !nodeCrypto.timingSafeEqual(a, b)) {
        log.debug('Leaving Krb5PersonKeys.productPersonKeys(). The password ' +
                  'does not give the stored key.');
        return this.refusal('STS-KRB-0132', 'That password does not give ' +
                            'the Kerberos key the KDC holds for ' + who +
                            ', so no keytab was made.');
      }
      keys.push([pair[0], Uint8Array.from(a)]);
    }
    log.debug('Leaving Krb5PersonKeys.productPersonKeys(). kvno ' +
              record.kvno + '.');
    return { ok: true, kvno: Number(record.kvno), keys: keys,
             source: 'password' };
  }

  // The keys a DEVELOPMENT KDC uses for a person: the principal it answers
  // with — created on first sight, as its AS exchange would — and that
  // principal's own password and salt.
  private async developmentPersonKeys(who: string): Promise<Json> {
    const { log, principals } = this.deps;
    log.debug('Entering Krb5PersonKeys.developmentPersonKeys(). name=' + who);
    const db = principals as unknown as Json;
    const found = db.lookupUser([who]);
    const principal = found && found.principal;
    if (!principal) {
      log.debug('Leaving Krb5PersonKeys.developmentPersonKeys(). No ' +
                'principal.');
      return this.refusal('STS-KRB-0133', 'The development KDC has no ' +
                          'principal ' + who + '@' + principals.REALM +
                          ' and will not make one (' +
                          'a name krb5.unknownUsers keeps unknown), so a ' +
                          'keytab would name nobody it knows.');
    }
    const keys: Array<[number, Uint8Array]> = [];
    for (const etype of db.supportedEtypes(principal)) {
      keys.push([etype, Uint8Array.from(await db.longTermKey(principal,
                                                             etype))]);
    }
    if (!keys.length) {
      log.debug('Leaving Krb5PersonKeys.developmentPersonKeys(). No ' +
                'enctype.');
      return this.refusal('STS-KRB-0133', who + '@' + principals.REALM +
                          ' supports no enctype this KDC offers.');
    }
    log.debug('Leaving Krb5PersonKeys.developmentPersonKeys(). kvno ' +
              principal.kvno + '.');
    return { ok: true, kvno: Number(principal.kvno), keys: keys,
             source: 'development' };
  }

  // What one person's Kerberos account IS, for their page on the console and
  // their own in the portal: the principal, whether this realm has a KDC,
  // which kind, and the PUBLIC half of their keys. Nothing is opened.
  personKerberosState(name: unknown): Json {
    const { log, principals, kcrypto } = this.deps;
    const directory = this.directory;
    log.debug('Entering Krb5PersonKeys.personKerberosState(). name=' + name);
    const who = String(name == null ? '' : name).trim();
    const state = principals.kerberosRealmOf();
    const kdc = !!(state.enabled && state.active);
    const out: Json = {
      kdc: kdc, realm: kdc ? principals.REALM : '',
      trustRealm: state.trustRealm,
      reason: kdc ? '' : (state.reason || 'krb5.enabled is off for it'),
      productKdc: kdc ? this.productKdc() : null,
      personKeys: this.personKeysEnabled(),
      principal: kdc && who ? who + '@' + principals.REALM : '',
      nameUsable: !!who && !this.personNameProblem(who),
      person: false, disabled: false, keys: null
    };
    if (!directory || !out.nameUsable) {
      log.debug('Leaving Krb5PersonKeys.personKerberosState(). No directory ' +
                'or no usable name.');
      return out;
    }
    const current = directory.readPerson(who);
    out.person = !!current;
    out.disabled = !!(current && current.disabled);
    const info = current ? this.parseInfo(current.info) : null;
    if (kdc && info) {
      out.keys = {
        kvno: info.kvno == null ? null : Number(info.kvno),
        etypes: (info.etypes || []).map(function (etype) {
          return { etype: Number(etype),
                   name: kcrypto.etypeName(Number(etype)) };
        }),
        derivedAt: info.derivedAt || '', derivedOn: info.event || '',
        sealed: !!info.sealed,
        current: !!current.passwordHash &&
                 info.stamp === this.stampOf(current.passwordHash),
        retained: this.retainedRows(info.retained, Date.now())
      };
    }
    log.debug('Leaving Krb5PersonKeys.personKerberosState().');
    return out;
  }

  // -------------------------------------------------------------------------
  // WHAT IS HELD, WITHOUT A KEY IN IT — for `/admin/kerberos/principals` and
  // its operation. Built from the PUBLIC info attributes only; nothing is
  // opened.
  // -------------------------------------------------------------------------
  listPeople(): Json[] {
    const self = this;
    const { log, principals, kcrypto } = this.deps;
    log.debug('Entering Krb5PersonKeys.listPeople().');
    if (!this.directory) {
      log.debug('Leaving Krb5PersonKeys.listPeople(). No directory.');
      return [];
    }
    const nowMs = Date.now();
    const rows = this.directory.personKeyInfos().map(function (one) {
      const info = self.parseInfo(one.info) || {};
      return {
        // THE PREVIOUS VERSIONS STILL ACCEPTED for tickets issued under them —
        // kvno, enctypes and expiry, from the public info — inside both bounds
        // as they stand NOW, so a shortened lifetime shows at once.
        retained: self.retainedRows(info.retained, nowMs),
        username: one.username,
        principal: one.username + '@' + principals.REALM,
        kvno: info.kvno == null ? null : Number(info.kvno),
        etypes: (info.etypes || []).map(function (etype) {
          return { etype: Number(etype),
                   name: kcrypto.etypeName(Number(etype)) };
        }),
        derivedAt: info.derivedAt || '',
        derivedOn: info.event || '',
        sealed: !!info.sealed,
        // Whether the keys match the password the entry holds NOW. From the
        // public stamp, which is a hint for this page and nothing more — the
        // KDC judges the stamp inside the seal.
        current: !!one.passwordHash &&
                 info.stamp === self.stampOf(one.passwordHash)
      };
    });
    rows.sort(function (a, b) {
      return a.username.localeCompare(b.username);
    });
    log.debug('Leaving Krb5PersonKeys.listPeople(). ' + rows.length +
              ' person(s).');
    return rows;
  }

  listServices(): Json[] {
    const self = this;
    const { log, kcrypto } = this.deps;
    log.debug('Entering Krb5PersonKeys.listServices().');
    if (!this.directory) {
      log.debug('Leaving Krb5PersonKeys.listServices(). No directory.');
      return [];
    }
    const nowMs = Date.now();
    // THE KRBTGT'S ENTRY IS NOT A SERVICE PRINCIPAL ROW (#169): it has its
    // own block (`krbtgtState()`) and no control on the service table applies
    // to it — rotating it there would hand its key out as a keytab.
    const rows = this.directory.serviceKeyInfos().filter(function (one) {
      return !/^krbtgt\//i.test(String(one.identifier));
    }).map(function (one) {
      const info = self.parseInfo(one.info) || {};
      const principal = String(one.identifier);
      return {
        retained: self.retainedRows(info.retained, nowMs),
        principal: principal,
        spn: principal.replace(/@[^@]*$/, ''),
        kvno: info.kvno == null ? null : Number(info.kvno),
        etypes: (info.etypes || []).map(function (etype) {
          return { etype: Number(etype),
                   name: kcrypto.etypeName(Number(etype)) };
        }),
        createdAt: info.createdAt || '',
        rotatedAt: info.rotatedAt || '',
        sealed: !!info.sealed,
        held: !!one.hasKeys
      };
    });
    rows.sort(function (a, b) {
      return a.principal.localeCompare(b.principal);
    });
    log.debug('Leaving Krb5PersonKeys.listServices(). ' + rows.length +
              ' service principal(s).');
    return rows;
  }

  // Replace the value of a withheld attribute for display. `ldap_server.js`
  // calls it with the LOWER-CASED names the store uses.
  withheldValues(attribute: unknown, values: unknown[]): unknown[] {
    const { log } = this.deps;
    log.debug("Entering Krb5PersonKeys.withheldValues().");
    const lower = String(attribute || '').toLowerCase();
    if (!WITHHELD_ATTRIBUTES.some(function (one) {
      return one.toLowerCase() === lower;
    })) {
      log.debug("Leaving Krb5PersonKeys.withheldValues().");
      return values;
    }
    log.debug("Leaving Krb5PersonKeys.withheldValues().");
    return (values || []).map(function (value) {
      return '(withheld: Kerberos key material, ' +
             String(value || '').length + ' characters, never shown)';
    });
  }

  // -------------------------------------------------------------------------
  // THE TWO SLOTS THIS FILE FILLS — called by `wire()` when the instance is
  // installed; standalone, that is at require time, where the original filled
  // them.
  // -------------------------------------------------------------------------
  installSlots(): void {
    const { log, credentials, principals } = this.deps;
    log.debug("Entering Krb5PersonKeys.installSlots().");
    if (typeof credentials.setPasswordObserver === 'function') {
      credentials.setPasswordObserver(this.observePassword.bind(this));
    } else {
      log.warn('krb5-keys: common/credentials.ts offers no ' +
               'setPasswordObserver(), so no person will get Kerberos keys ' +
               'from a password. That is the older credential store and is ' +
               'not an error.');
    }
    if (typeof principals.setKeySource === 'function') {
      // THE FAST PROVIDER RIDES IN THE KEY SOURCE (#173). It is not a key,
      // but it needs the same two things the key source is the KDC's only
      // door to — the directory's people (their second factors) and the
      // credential store (their authenticator codes) — and a second slot
      // would be rule 3e's "a slot by analogy". One object, validated whole
      // by `setKeySource()` as before; the two new members are optional
      // there, so a source without them (the parent project's jobs have
      // none) leaves the KDC exactly as it was.
      principals.setKeySource({ personKeys: this.personKeys.bind(this),
                                serviceKeys: this.serviceKeys.bind(this),
                                // #169: this realm's random krbtgt key.
                                krbtgtKeys: this.krbtgtKeys.bind(this),
                                personDisabled:
                                  this.personDisabled.bind(this),
                                personSecondFactor:
                                  this.personSecondFactor.bind(this),
                                fast: this.deps.fast });
    } else {
      log.warn('krb5-keys: kerberos/krb5_principals.js offers no ' +
               'setKeySource(), so stored Kerberos keys are never read. That ' +
               'is the older principal database and is not an error.');
    }
    log.debug("Leaving Krb5PersonKeys.installSlots().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<Krb5PersonKeys>(
  'kerberos/krb5_person_keys',
  () => new Krb5PersonKeys(Krb5PersonKeys.defaultDeps()),
  Krb5PersonKeys.wire,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  Krb5PersonKeys: Krb5PersonKeys,
  installInstance: (instance: Krb5PersonKeys): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  SEAL_LABEL: Krb5PersonKeys.SEAL_LABEL,
  PERSON_KEYS_ATTRIBUTE: Krb5PersonKeys.PERSON_KEYS_ATTRIBUTE,
  PERSON_INFO_ATTRIBUTE: Krb5PersonKeys.PERSON_INFO_ATTRIBUTE,
  SERVICE_KEYS_ATTRIBUTE: Krb5PersonKeys.SERVICE_KEYS_ATTRIBUTE,
  SERVICE_INFO_ATTRIBUTE: Krb5PersonKeys.SERVICE_INFO_ATTRIBUTE,
  ATTRIBUTES: Krb5PersonKeys.ATTRIBUTES,
  WITHHELD_ATTRIBUTES: Krb5PersonKeys.WITHHELD_ATTRIBUTES,
  setDirectory: slot.forward('setDirectory'),
  installed: slot.forward('installed'),
  currentDirectory: slot.forward('currentDirectory'),
  productKdc: slot.forward('productKdc'),
  personKeysEnabled: slot.forward('personKeysEnabled'),
  stampOf: slot.forward('stampOf'),
  deriveKey: slot.forward('deriveKey'),
  personKeys: slot.forward('personKeys'),
  personDisabled: slot.forward('personDisabled'),
  personSecondFactor: slot.forward('personSecondFactor'),
  preauthPolicy: slot.forward('preauthPolicy'),
  serviceKeys: slot.forward('serviceKeys'),
  observePassword: slot.forward('observePassword'),
  idle: slot.forward('idle'),
  normaliseSpn: slot.forward('normaliseSpn'),
  createServicePrincipal: slot.forward('createServicePrincipal'),
  rotateServicePrincipal: slot.forward('rotateServicePrincipal'),
  deleteServicePrincipal: slot.forward('deleteServicePrincipal'),
  clearPersonKeys: slot.forward('clearPersonKeys'),
  dropPreviousPersonKeys: slot.forward('dropPreviousPersonKeys'),
  dropPreviousServiceKeys: slot.forward('dropPreviousServiceKeys'),
  personKeytabRefusal: slot.forward('personKeytabRefusal'),
  personKeytab: slot.forward('personKeytab'),
  personKerberosState: slot.forward('personKerberosState'),
  retainedVersionsLimit: slot.forward('retainedVersionsLimit'),
  retainedTtlSeconds: slot.forward('retainedTtlSeconds'),
  listPeople: slot.forward('listPeople'),
  listServices: slot.forward('listServices'),
  withheldValues: slot.forward('withheldValues'),
  // THE KRBTGT KEY (#169).
  krbtgtIdentifier: slot.forward('krbtgtIdentifier'),
  krbtgtTtlSeconds: slot.forward('krbtgtTtlSeconds'),
  krbtgtKeys: slot.forward('krbtgtKeys'),
  krbtgtState: slot.forward('krbtgtState'),
  createKrbtgtKey: slot.forward('createKrbtgtKey'),
  ensureKrbtgtKey: slot.forward('ensureKrbtgtKey'),
  rotateKrbtgt: slot.forward('rotateKrbtgt'),
  dropPreviousKrbtgtKeys: slot.forward('dropPreviousKrbtgtKeys')
};
