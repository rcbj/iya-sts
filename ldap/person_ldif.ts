// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ldap/person_ldif.ts
//
// ===========================================================================
// A PERSON AS AN LDIF FILE, OUT AND BACK IN (rcbj, 2026-11-14).
//
// "Add import / export functionality to the Directory->Users->User page. Use
// the same pattern that Directory->Applications->Application exposes." That
// pattern is #546's (`common/applications.js`, *AN APPLICATION AS AN LDIF
// FILE*), and each of its four decisions is a rule here, read for a person:
//
//   1. RFC 2849 content records, one per person, through the codec
//      `persistence/persistence_ldif.js` holds — one reading of LDIF in this
//      service, not three.
//   2. CREDENTIAL MATERIAL IS LEFT OUT UNLESS ASKED FOR, and when asked for it
//      goes out UNENCRYPTED: the password's stored hash as stored, and a value
//      sealed under this process's key-encryption key (the authenticator
//      app's secret, a legacy recovery-code set) is OPENED, because a file
//      sealed under that key opens nowhere else. A sealed value that will not
//      open refuses the whole export (STS-LDAP-0215) rather than writing
//      ciphertext beside clear values.
//   3. AN IMPORT NEVER OVERWRITES. The file names its own username (its DN's
//      `uid=` and its `uid`), and one already here is refused by name
//      (STS-LDAP-0218). So an import from a person's page cannot touch the
//      person the page is about.
//   4. DECLARED ATTRIBUTES ONLY, BOTH WAYS. A person's declared attributes are
//      the ones a CREATE takes — `ldap_server.js`'s `personAttributesFrom()`
//      answers that from the credential catalogue (`vc_claims.ts`) and the
//      person editor's universe, the realm's custom attributes among it
//      (#396) — so an export writes exactly what `createUser()` will accept
//      back. What this service RECORDED about the person (sign-in methods,
//      federation sightings, consents, certificate sightings, the console's
//      bootstrap marks, delegation and account flags, pending links) is not
//      exported, and an import carrying it is refused by name
//      (STS-LDAP-0219), so a copy starts with no history it did not have.
//
// WHAT IS A CREDENTIAL HERE: what the entry holds that SIGNS THE PERSON IN —
// the password's hash (`userPassword`), the authenticator app
// (`stsTotpCredential`), the passkeys (`stsWebauthnCredential` and the two user
// handles a discoverable credential finds the person by), the recovery codes
// (`stsBackupCodes`), the app passwords (`stsAppPassword`), stored client
// certificates (`userCertificate;binary`), HOBA keys and the CIBA user code's
// hash. The credentials a subsystem MINTS are never exported and refused on
// import: the Kerberos keys (derived from the password in the clear, which a
// hash cannot give back — the imported person has none until their password is
// set again), the RFC 7523 / 7522 key pairs and enrolled certificates (each
// certified under THIS realm's authority), ACME and SCEP enrolment secrets,
// the person's published DIDs and self-issued subjects, and every pending
// link's hash. No session, token or audit row is ever on an entry.
//
// GROUP MEMBERSHIPS ARE NOT EXPORTED. #546 exports no relationships (an
// application's owners are not in its file), and a person's memberships are
// on the GROUP entries, not theirs: a group of the same name in another realm
// is a different group, and joining it is an administrator's act there.
//
// THE `entryUUID` IS NOT CARRIED, AND ONE IN A FILE IS REFUSED. It is the
// person's `sub` (`urn:uuid:<entryUUID>`), NO-USER-MODIFICATION in every mode
// (RFC 4530), and `createUser()` mints a new one. A file that could choose it
// could make the imported entry the subject of somebody else's tokens — the
// identity theft `ALWAYS_PROTECTED_OPERATIONAL` refuses at the socket.
//
// A HASH CANNOT BE HELD TO THE PASSWORD POLICY, and that is #546's rule for an
// application's client secret read for a person: the credential in the file
// is written as it is stored. Only a value this service writes is taken — a
// `$scrypt$` or `$argon2id$` string (`crypto.isHashedSecret()`); a clear
// password is refused (STS-LDAP-0220): set it with `set-password` after the
// import, where the policy applies. The hash names its own cost, so it
// verifies as it did, and product mode's upgrade on sign-in rewrites one
// weaker than the policy at the next verified sign-in.
//
// THE DN: the export writes the entry's own DN; the import reads only its
// SHAPE — `uid=<name>,ou=users,…` — and creates the person under the realm it
// is imported INTO. So a file moves a person between realms as they stand.
//
// THE STORE'S HALF IS `ldap_server.js`'s: the entry is read through
// `locateEntry()`, the person created through `createUser()` (the one create,
// so the attribute policy, the DN rules and one-entry-per-person are its
// checks), and the credentials written through `writeImportedCredentials()`.
// That module is JavaScript and registers its routes when required (rule 1),
// and `admin-core/admin_actions.ts` loads this file at 18, before it — so it
// is read out of `require.cache` at request time, never required at load:
// `admin-core/certificate_views.ts`'s arrangement, and no slot.
//
// A LIBRARY (rule 3): it registers no route.
// ===========================================================================

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import stsCrypto = require('../common/crypto');
import keystore = require('../common/keystore');
import realms = require('../common/realms');
import audit = require('../common/audit');
import InstanceSlot = require('../common/instance_slot');

// One credential attribute: its LDIF spelling, what kind of credential it is
// (the answer's `credentials` and the CAEP signal name it), and whether it
// holds one value.
interface CredentialRow {
  name: string;
  kind: string;
  single: boolean;
}

// THE CREDENTIALS AN EXPORT MAY CARRY AND AN IMPORT MAY WRITE, by the
// directory's lower-cased name.
const CREDENTIALS: Record<string, CredentialRow> = {
  userpassword: { name: 'userPassword', kind: 'password', single: true },
  ststotpcredential: { name: 'stsTotpCredential', kind: 'totp',
                       single: true },
  stswebauthncredential: { name: 'stsWebauthnCredential', kind: 'passkey',
                           single: false },
  stswebauthnuserhandle: { name: 'stsWebauthnUserHandle', kind: 'passkey',
                           single: true },
  stswebauthnpqcuserhandle: { name: 'stsWebauthnPqcUserHandle',
                              kind: 'passkey', single: true },
  stsbackupcodes: { name: 'stsBackupCodes', kind: 'recovery-codes',
                    single: true },
  stsapppassword: { name: 'stsAppPassword', kind: 'app-passwords',
                    single: true },
  'usercertificate;binary': { name: 'userCertificate;binary',
                              kind: 'certificate', single: false },
  usercertificate: { name: 'userCertificate;binary', kind: 'certificate',
                     single: false },
  hobapublickey: { name: 'hobaPublicKey', kind: 'hoba', single: false },
  stscibausercode: { name: 'stsCibaUserCode', kind: 'ciba-user-code',
                     single: true }
};

// What an import reads past without a word: the entry's structure, which the
// create writes for itself in the realm it is imported into.
const STRUCTURAL = ['objectclass', 'entrydn', 'createtimestamp',
                    'modifytimestamp'];

// What names the person, written by the create from the DN.
const NAMING = 'uid';

// The DN's shape: `uid=<name>,ou=users,…`.
interface LdapDirectory {
  locateEntry(key: string): { dn?: string; stored?: any };
  isPersonEntry(stored: any): boolean;
  createUser(name: string, options: Record<string, unknown>): any;
  writeImportedCredentials(dn: string,
                           values: Record<string, string[]>): boolean;
  webauthnUserHandleHolder(handle: string): { owner: string } | null;
  certificateHolders(sha256: string): Array<{ dn: string }>;
}

interface PersonLdifDeps {
  log: { debug(message: string): void; warn(message: string): void };
  errorCodes: typeof errorCodes;
  // The store, found at request time (see the header).
  directory: () => LdapDirectory | null;
  // The attribute's name in the spelling a create takes, or '' when a create
  // takes no such attribute.
  creatable: (name: string) => string;
  codec: () => { toLdif(rows: unknown[], header: string[]): string;
                 fromLdif(text: string, log: unknown): any[] };
  isHashedSecret: (value: string) => boolean;
  isRecoveryHash: (value: string) => boolean;
  certificateDerOf: (value: string) => Buffer | null;
  sha256Hex: (der: Buffer) => string;
  seal: (text: string, label: string) => string;
  open: (text: string, label: string) => string;
  sealsHere: () => boolean;
  realmId: () => string;
  audit: (row: Record<string, unknown>) => void;
}

// The seal labels `common/credentials.ts` writes the two sealed records
// under; a value sealed under any other label does not open as one.
const TOTP_LABEL = 'totp-secret';
const RECOVERY_LABEL = 'recovery-codes';

/**
 * A person's directory entry as an RFC 2849 LDIF file, and a person created
 * from one.
 */
class PersonLdif {
  static readonly CREDENTIALS = CREDENTIALS;
  static readonly STRUCTURAL = STRUCTURAL;

  /**
   * Builds the export and import over the given dependencies.
   *
   * @param deps - the modules it reads, from `PersonLdif.defaultDeps()`
   */
  constructor(private readonly deps: PersonLdifDeps) {
    deps.log.debug("Entering PersonLdif.constructor().");
    deps.log.debug("Leaving PersonLdif.constructor().");
  }

  /**
   * Returns the real modules the library depends on.
   *
   * @returns the dependencies
   */
  static defaultDeps(): PersonLdifDeps {
    helpers.log.debug("Entering PersonLdif.defaultDeps().");
    helpers.log.debug("Leaving PersonLdif.defaultDeps().");
    return {
      log: helpers.log,
      errorCodes: errorCodes,
      directory: function directory() {
        helpers.log.debug("Entering directory().");
        // Out of the require cache, never required: `ldap_server.js`
        // registers its routes when required (rule 1).
        const key = Object.keys(require.cache).filter(function (one) {
          return /[\\/]ldap[\\/]ldap_server\.js$/.test(one);
        })[0];
        const loaded = key && require.cache[key]
          ? require.cache[key].exports : null;
        helpers.log.debug("Leaving directory().");
        return loaded && typeof loaded.createUser === 'function'
          ? loaded : null;
      },
      creatable: function creatable(name) {
        helpers.log.debug("Entering creatable().");
        // Both lists `personAttributesFrom()` asks, required when asked:
        // the editor reads the attribute policy, which reads the directory.
        const vcClaims = require('../oid4vc/vc_claims');
        const personEditor = require('./person_editor');
        const checked = personEditor.checkCreateValues(name, []);
        const row = vcClaims.personField(name);
        helpers.log.debug("Leaving creatable().");
        return checked && checked.name ? String(checked.name)
          : (row ? String(row.ldap) : '');
      },
      codec: function codec() {
        helpers.log.debug("Entering codec().");
        helpers.log.debug("Leaving codec().");
        return require('../persistence/persistence_ldif');
      },
      isHashedSecret: function isHashedSecret(value) {
        helpers.log.debug("Entering isHashedSecret().");
        helpers.log.debug("Leaving isHashedSecret().");
        return !!stsCrypto.isHashedSecret(value);
      },
      isRecoveryHash: function isRecoveryHash(value) {
        helpers.log.debug("Entering isRecoveryHash().");
        helpers.log.debug("Leaving isRecoveryHash().");
        return !!require('../common/backup_codes').isHash(value);
      },
      certificateDerOf: function certificateDerOf(value) {
        helpers.log.debug("Entering certificateDerOf().");
        helpers.log.debug("Leaving certificateDerOf().");
        return require('../persistence/directory_codec')
          .certificateDerOf(value);
      },
      sha256Hex: function sha256Hex(der) {
        helpers.log.debug("Entering sha256Hex().");
        helpers.log.debug("Leaving sha256Hex().");
        return String(stsCrypto.digest('sha256', der, 'hex'));
      },
      seal: function seal(text, label) {
        helpers.log.debug("Entering seal().");
        helpers.log.debug("Leaving seal().");
        // Under the CELL's key where there is one, as `credentials.ts` seals
        // a person's secrets (#98).
        return keystore.seal(text, label, 'cell') || '';
      },
      open: function open(text, label) {
        helpers.log.debug("Entering open().");
        helpers.log.debug("Leaving open().");
        return keystore.open(text, label) || '';
      },
      sealsHere: function sealsHere() {
        helpers.log.debug("Entering sealsHere().");
        helpers.log.debug("Leaving sealsHere().");
        return !!keystore.persists();
      },
      realmId: function realmId() {
        helpers.log.debug("Entering realmId().");
        helpers.log.debug("Leaving realmId().");
        return String(realms.currentId() || 'default');
      },
      audit: function auditRow(row) {
        helpers.log.debug("Entering auditRow().");
        audit.audit(row);
        helpers.log.debug("Leaving auditRow().");
      }
    };
  }

  // A refusal, coded.
  private refused(code: string, message: string) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PersonLdif.refused(). " + code);
    log.debug("Leaving PersonLdif.refused().");
    return errorCodes.mark({ ok: false, errors: [message] }, code);
  }

  // A stored credential's values as the file carries them: the two sealed
  // records opened, everything else as stored. null where a sealed one will
  // not open.
  private openedValues(lower: string, values: string[], who: string) {
    const { log, open } = this.deps;
    log.debug("Entering PersonLdif.openedValues(). " + lower);
    if (lower !== 'ststotpcredential' && lower !== 'stsbackupcodes') {
      log.debug("Leaving PersonLdif.openedValues(). As stored.");
      return values;
    }
    const out: string[] = [];
    for (const value of values) {
      let record: any = null;
      try {
        record = JSON.parse(value);
      } catch (e) {
        log.debug("Caught in PersonLdif.openedValues(): " +
                  ((e && e.message) || e));
        // Not a record this service wrote: carried as it is, and an import
        // refuses it by name.
        record = null;
      }
      if (!record || !record.sealed) {
        out.push(value);
        continue;
      }
      const member = lower === 'ststotpcredential' ? 'secret' : 'vault';
      const label = lower === 'ststotpcredential' ? TOTP_LABEL
                                                  : RECOVERY_LABEL;
      const opened = open(String(record[member] || ''), label);
      if (!opened) {
        log.warn(errorCodes.tag('STS-LDAP-0215') + 'ldap: the ' +
                 CREDENTIALS[lower].name + ' on "' + who + '" will not ' +
                 'open under this process\'s key-encryption key, so it ' +
                 'cannot be exported in the clear.');
        log.debug("Leaving PersonLdif.openedValues(). Will not open.");
        return null;
      }
      record[member] = opened;
      record.sealed = false;
      out.push(JSON.stringify(record));
    }
    log.debug("Leaving PersonLdif.openedValues().");
    return out;
  }

  /**
   * Writes one person's entry as an RFC 2849 LDIF document: the attributes a
   * create takes, and their credentials, UNENCRYPTED, when asked.
   *
   * @param key - the person, as `/admin-api/users` names them
   * @param options - `credentials` (true to include credential material),
   *   `actor`
   * @returns `{ ok, ldif, fileName, username, attributes, credentials,
   *   leftOut }`, or a marked refusal
   */
  exportPerson(key: string, options?: { credentials?: boolean;
                                        actor?: string }) {
    const { log, directory, creatable, codec, realmId } = this.deps;
    const opts = options || {};
    const who = String(key || '').trim();
    log.debug("Entering PersonLdif.exportPerson(). " + who);
    const ldap = directory();
    const located = who && ldap ? ldap.locateEntry(who) : null;
    const stored = located && located.stored;
    if (!stored || !ldap.isPersonEntry(stored)) {
      log.debug("Leaving PersonLdif.exportPerson(). Nobody.");
      return this.refused('STS-LDAP-0214', 'Nobody called "' + who +
                          '" is in this realm\'s directory, so there is ' +
                          'nothing to export.');
    }
    const attrs = stored.attributes || {};
    const username = String([].concat(attrs.uid || [])[0] || who);
    const withCredentials = opts.credentials === true;
    const out: Record<string, string[]> = {
      objectClass: [].concat(attrs.objectclass || []).map(String),
      uid: [username]
    };
    const leftOut: string[] = [];
    const exportedKinds: string[] = [];
    let refused = false;
    Object.keys(attrs).sort().forEach((lower) => {
      if (refused || lower === 'objectclass' || lower === NAMING) {
        return;
      }
      const values = [].concat(attrs[lower] || []).map(String)
        .filter(function (one) { return one !== ''; });
      if (!values.length) {
        return;
      }
      const credential = CREDENTIALS[lower];
      if (credential) {
        if (!withCredentials) {
          if (leftOut.indexOf(credential.name) < 0) {
            leftOut.push(credential.name);
          }
          return;
        }
        const opened = this.openedValues(lower, values, username);
        if (!opened) {
          refused = true;
          return;
        }
        out[credential.name] = (out[credential.name] || []).concat(opened);
        if (exportedKinds.indexOf(credential.kind) < 0) {
          exportedKinds.push(credential.kind);
        }
        return;
      }
      const name = creatable(lower);
      if (name) {
        out[name] = values;
      }
    });
    if (refused) {
      log.debug("Leaving PersonLdif.exportPerson(). A credential will not " +
                "open.");
      return this.refused('STS-LDAP-0215', 'A credential on "' + username +
                          '" is sealed under a key-encryption key this ' +
                          'process does not hold, so it cannot be written ' +
                          'in the clear. Nothing was exported. Export ' +
                          'without credential material, or have the person ' +
                          'enrol it again.');
    }
    const header = [
      'One person of this identity service, exported ' +
        new Date().toISOString() + ' from the "' + realmId() + '" realm.',
      'The attributes a create takes only: nothing this service recorded ' +
        'about them, no group membership, no entryUUID.',
      withCredentials
        ? 'CREDENTIAL MATERIAL IS INCLUDED, UNENCRYPTED (the password as ' +
          'its stored hash). Keep this file as you would keep the secrets ' +
          'in it.'
        : 'No credential material: ' +
          (leftOut.length ? leftOut.join(', ') : 'they held none') + '.',
      'Kerberos keys, signing key pairs and enrolment secrets are never ' +
        'exported.',
      'Import it on Directory > Users > (a person) > Import / export, or ' +
        'POST /admin-api/users/import-ldif, in any realm.'
    ];
    const ldif = codec().toLdif([{ dn: String(stored.dn), attributes: out }],
                                header);
    this.deps.audit({
      action: 'user.export', category: 'directory',
      actor: opts.actor || '', protocol: 'console', channel: 'internal',
      target: username,
      summary: 'Person "' + username + '" was exported to LDIF' +
               (withCredentials
                 ? ', WITH their credential material in the clear'
                 : ', without credential material'),
      // The NAMES only, never a value: these are personal data and
      // credentials.
      detail: { username: username, credentials: withCredentials,
                attributes: Object.keys(out).join(', '),
                leftOut: leftOut.join(', ') }
    });
    log.debug("Leaving PersonLdif.exportPerson(). " +
              Object.keys(out).length + " attribute(s).");
    return { ok: true, ldif: ldif, username: username,
             fileName: username.replace(/[^A-Za-z0-9._-]+/g, '_') + '.ldif',
             attributes: Object.keys(out), credentials: withCredentials,
             credentialKinds: exportedKinds, leftOut: leftOut };
  }

  // The one record of a document, or a refusal.
  private recordOf(text: unknown) {
    const { log, codec } = this.deps;
    log.debug("Entering PersonLdif.recordOf().");
    let records: any[] = [];
    try {
      records = codec().fromLdif(String(text == null ? '' : text), log);
    } catch (e) {
      log.debug("Caught in PersonLdif.recordOf(): " +
                ((e && e.message) || e));
      // Not LDIF this codec reads: answered as a file of no records.
      records = [];
    }
    log.debug("Leaving PersonLdif.recordOf(). " + records.length);
    return records;
  }

  /**
   * The username an LDIF document names (its one record's `uid`), or '' when
   * it is not one person's record. What a create claims across nodes before
   * it runs.
   *
   * @param text - the LDIF document
   * @returns the username, or ''
   */
  usernameOf(text: unknown): string {
    const { log } = this.deps;
    log.debug("Entering PersonLdif.usernameOf().");
    const records = this.recordOf(text);
    const attrs = records.length === 1 ? (records[0].attributes || {}) : {};
    const name = String([].concat(attrs.uid || [])[0] || '').trim();
    log.debug("Leaving PersonLdif.usernameOf().");
    return name;
  }

  // Each credential value checked and put in its stored form, or a refusal.
  // Nothing is written here.
  private storedCredentials(given: Record<string, string[]>,
                            ldap: LdapDirectory) {
    const { log, isHashedSecret, isRecoveryHash, certificateDerOf,
            sha256Hex, seal, sealsHere } = this.deps;
    log.debug("Entering PersonLdif.storedCredentials().");
    const out: Record<string, string[]> = {};
    const problems: string[] = [];
    const parsed = function (value: string) {
      try {
        const one = JSON.parse(value);
        return one && typeof one === 'object' && !Array.isArray(one)
          ? one : null;
      } catch (e) {
        log.debug("Caught in parsed(): " + ((e && e.message) || e));
        // Not JSON: refused below, by the attribute's name.
        return null;
      }
    };
    Object.keys(given).forEach(function (lower) {
      const row = CREDENTIALS[lower];
      const values = given[lower];
      if (row.single && values.length > 1) {
        problems.push(row.name + ' holds one value, and the file gives ' +
                      values.length + '.');
        return;
      }
      if (lower === 'userpassword' || lower === 'stscibausercode') {
        if (!isHashedSecret(values[0])) {
          problems.push(row.name + ' is not a hash this service writes. ' +
                        'An import takes a password only as its stored ' +
                        'hash; set a clear one with set-password after ' +
                        'the import, where the password policy applies.');
          return;
        }
        out[lower] = values;
        return;
      }
      if (lower === 'ststotpcredential') {
        const record = parsed(values[0]);
        if (!record || record.sealed || typeof record.secret !== 'string' ||
            !record.secret) {
          problems.push(row.name + ' is not an authenticator record with ' +
                        'its secret in the clear, as an export writes it.');
          return;
        }
        if (sealsHere()) {
          const sealed = seal(record.secret, TOTP_LABEL);
          if (!sealed) {
            problems.push(row.name + '\'s secret could not be sealed under ' +
                          'this process\'s key-encryption key.');
            return;
          }
          record.secret = sealed;
          record.sealed = true;
        } else {
          record.sealed = false;
        }
        out[lower] = [JSON.stringify(record)];
        return;
      }
      if (lower === 'stsbackupcodes') {
        const record = parsed(values[0]);
        let codes: any = null;
        try {
          codes = record && !record.sealed
            ? JSON.parse(String(record.vault || '')) : null;
        } catch (e) {
          log.debug("Caught in storedCredentials(): " +
                    ((e && e.message) || e));
          // Not the list an export writes: refused below.
          codes = null;
        }
        if (!Array.isArray(codes)) {
          problems.push(row.name + ' is not a recovery-code record with ' +
                        'its codes in the clear, as an export writes it.');
          return;
        }
        // A LEGACY SET (codes, not hashes) is sealed wherever the key
        // persists, as `writeBackupCodesRecord()` keeps it (#70).
        const legacy = codes.some(function (one) {
          return one && one.hash && !isRecoveryHash(String(one.hash));
        });
        if (legacy && sealsHere()) {
          const sealed = seal(String(record.vault), RECOVERY_LABEL);
          if (!sealed) {
            problems.push(row.name + ' could not be sealed under this ' +
                          'process\'s key-encryption key.');
            return;
          }
          record.vault = sealed;
          record.sealed = true;
        } else {
          record.sealed = false;
        }
        out[lower] = [JSON.stringify(record)];
        return;
      }
      if (lower === 'stswebauthncredential' || lower === 'stsapppassword') {
        const bad = values.filter(function (one) {
          return !parsed(one);
        });
        if (bad.length) {
          problems.push(row.name + ' holds a value that is not the JSON ' +
                        'record this service writes.');
          return;
        }
        out[lower] = values;
        return;
      }
      if (lower === 'stswebauthnuserhandle' ||
          lower === 'stswebauthnpqcuserhandle') {
        const holder = ldap.webauthnUserHandleHolder(values[0]);
        if (holder) {
          problems.push(row.name + ' is already the user handle of "' +
                        holder.owner + '" in this realm, and a passkey ' +
                        'finds one person by it.');
          return;
        }
        out[lower] = values;
        return;
      }
      if (row.kind === 'certificate') {
        const kept: string[] = [];
        for (const value of values) {
          const der = certificateDerOf(value);
          if (!der) {
            problems.push(row.name + ' holds a value that is not one ' +
                          'certificate.');
            return;
          }
          const elsewhere = ldap.certificateHolders(sha256Hex(der)) || [];
          if (elsewhere.length) {
            problems.push('A certificate in ' + row.name + ' is already ' +
                          'stored on ' + elsewhere.map(function (one) {
                            return String(one.dn);
                          }).join(', ') + '. Stored on two entries it ' +
                          'signs nobody in.');
            return;
          }
          kept.push(der.toString('base64'));
        }
        out['usercertificate;binary'] =
          (out['usercertificate;binary'] || []).concat(kept);
        return;
      }
      out[lower] = values;
    });
    if (out.stswebauthnpqcuserhandle && !out.stswebauthnuserhandle) {
      problems.push('stsWebauthnPqcUserHandle is written only beside ' +
                    'stsWebauthnUserHandle.');
    }
    log.debug("Leaving PersonLdif.storedCredentials(). " + problems.length +
              " problem(s).");
    return { values: out, problems: problems };
  }

  /**
   * Creates a person from an LDIF document holding one record, through the
   * same create the console and `/admin-api/users/create` use, and writes the
   * credentials it carries. Never overwrites.
   *
   * @param text - the LDIF document
   * @param options - `actor`
   * @returns `{ ok, username, dn, attributes, credentials,
   *   credentialKinds, kerberosKeys }` or a marked refusal
   */
  importPerson(text: unknown, options?: { actor?: string }) {
    const { log, directory } = this.deps;
    const opts = options || {};
    log.debug("Entering PersonLdif.importPerson().");
    const ldap = directory();
    if (!ldap) {
      log.debug("Leaving PersonLdif.importPerson(). No directory.");
      return this.refused('STS-ADMIN-0501', 'No LDAP directory is loaded in ' +
                          'this process, so there is nowhere to put a ' +
                          'person.');
    }
    const records = this.recordOf(text);
    if (records.length !== 1) {
      log.debug("Leaving PersonLdif.importPerson(). " + records.length +
                " record(s).");
      return this.refused('STS-LDAP-0216', 'An import reads LDIF holding ' +
                          'exactly one person\'s record, as an export ' +
                          'writes it; this holds ' + records.length + '.');
    }
    const record = records[0];
    const rdns = String(record.dn || '').split(',').map(function (part) {
      return part.trim();
    });
    const attrs = record.attributes || {};
    const uids = [].concat(attrs.uid || []).map(String);
    const username = String(uids[0] || '').trim();
    const second = String(rdns[1] || '').toLowerCase();
    if (second === 'ou=applications') {
      log.debug("Leaving PersonLdif.importPerson(). An application.");
      return this.refused('STS-LDAP-0217', 'That record is an application ' +
                          'entry (' + String(record.dn) + '). Import it on ' +
                          'Directory > Applications > (an application) > ' +
                          'Import / export, or POST ' +
                          '/admin-api/applications/import-ldif.');
    }
    if (rdns.length < 2 || !/^uid=/i.test(rdns[0]) ||
        second !== 'ou=users' || !username || uids.length !== 1 ||
        rdns[0].slice(4).trim().toLowerCase() !== username.toLowerCase()) {
      log.debug("Leaving PersonLdif.importPerson(). Not a person entry.");
      return this.refused('STS-LDAP-0217', 'That record is not a person\'s ' +
                          'entry: its DN must be uid=<name>,ou=users,… and ' +
                          'it must carry that name as its one uid. It names ' +
                          '"' + String(record.dn || '') + '".');
    }
    const clash = ldap.locateEntry(username);
    if (clash && clash.stored) {
      log.debug("Leaving PersonLdif.importPerson(). Already here.");
      return this.refused('STS-LDAP-0218', 'There is already a person ' +
                          'called "' + username + '" in this realm, at ' +
                          String(clash.stored.dn) + ', and an import never ' +
                          'overwrites. Delete them, or change the file\'s ' +
                          'uid and its DN, and import again.');
    }
    // Every attribute sorted into what the create takes, what is written
    // after it, what is read past, and what is refused.
    const declared: Record<string, string[]> = {};
    const credentials: Record<string, string[]> = {};
    const notImportable: string[] = [];
    Object.keys(attrs).forEach((lower) => {
      if (STRUCTURAL.indexOf(lower) >= 0 || lower === NAMING) {
        return;
      }
      const values = [].concat(attrs[lower] || []).map(String);
      if (CREDENTIALS[lower]) {
        credentials[lower] = (credentials[lower] || []).concat(values);
        return;
      }
      const name = this.deps.creatable(lower);
      if (name) {
        declared[name] = values;
        return;
      }
      notImportable.push(lower);
    });
    if (notImportable.length) {
      log.debug("Leaving PersonLdif.importPerson(). Not importable.");
      return this.refused('STS-LDAP-0219', 'The record carries what no ' +
                          'import may write: ' + notImportable.join(', ') +
                          '. An import takes the attributes a create takes ' +
                          'and the credentials an export writes. What this ' +
                          'service records about a person, the entryUUID ' +
                          '(their subject, which a create mints), and the ' +
                          'Kerberos keys, key pairs and enrolment secrets ' +
                          'its subsystems mint are refused. Remove them, or ' +
                          'export the person again.');
    }
    const checked = this.storedCredentials(credentials, ldap);
    if (checked.problems.length) {
      log.debug("Leaving PersonLdif.importPerson(). Credentials refused.");
      return errorCodes.mark({ ok: false, errors: checked.problems },
                             'STS-LDAP-0220');
    }
    const created = ldap.createUser(username, {
      origin: 'console', channel: 'console', invent: false,
      attributes: declared, actor: opts.actor || '',
      note: 'imported from an LDIF file on the admin console or the ' +
            'management API'
    });
    if (!created || created.ok === false) {
      log.debug("Leaving PersonLdif.importPerson(). The create refused it.");
      // The create's own code and sentences, and nothing else of its
      // answer: an import's refusal is `{ ok, errors }`.
      return errorCodes.mark({ ok: false,
                               errors: (created && created.errors) || [] },
                             errorCodes.codeOf(created) || 'STS-LDAP-0219');
    }
    const kinds: string[] = [];
    const names = Object.keys(checked.values);
    if (names.length) {
      let written = false;
      try {
        written = ldap.writeImportedCredentials(created.dn, checked.values);
      } catch (e) {
        log.debug("Caught in PersonLdif.importPerson(): " +
                  ((e && e.message) || e));
        written = false;
      }
      if (!written) {
        log.debug("Leaving PersonLdif.importPerson(). Credentials not " +
                  "written.");
        return this.refused('STS-LDAP-0221', '"' + username + '" was ' +
                            'created, but the credentials in the file ' +
                            'could not be written. Set them again from ' +
                            'their page.');
      }
      names.forEach(function (lower) {
        const kind = CREDENTIALS[lower].kind;
        if (kinds.indexOf(kind) < 0) {
          kinds.push(kind);
        }
      });
    }
    this.deps.audit({
      action: 'user.import', category: 'directory',
      actor: opts.actor || '', protocol: 'console', channel: 'internal',
      target: username,
      summary: 'Person "' + username + '" was imported from LDIF' +
               (kinds.length ? ', with credential material' : ''),
      // The NAMES only, as the export's row.
      detail: { username: username, dn: String(created.dn),
                attributes: Object.keys(declared).join(', '),
                credentials: names.map(function (lower) {
                  return CREDENTIALS[lower].name;
                }).join(', ') }
    });
    log.debug("Leaving PersonLdif.importPerson(). Imported.");
    return { ok: true, username: username, dn: String(created.dn),
             attributes: Object.keys(declared),
             credentials: names.map(function (lower) {
               return CREDENTIALS[lower].name;
             }),
             credentialKinds: kinds,
             // A hash gives back no password, so no Kerberos key is derived
             // until the password is set again.
             kerberosKeys: false };
  }
}

const slot = new InstanceSlot<PersonLdif>(
  'ldap/person_ldif',
  () => new PersonLdif(PersonLdif.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * A person exported to, and imported from, an LDIF file.
 *
 * @namespace
 */
export = {
  PersonLdif: PersonLdif,
  CREDENTIALS: CREDENTIALS,
  installInstance: (instance: PersonLdif): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  exportPerson: slot.forward('exportPerson'),
  importPerson: slot.forward('importPerson'),
  usernameOf: slot.forward('usernameOf')
};
