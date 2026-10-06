// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: service_accounts.ts
//
// ---------------------------------------------------------------------------
// A SERVICE ACCOUNT IS A PERSON ENTRY WITH A FLAG (#221, 2026-10-06).
//
// rcbj's first decision on #221 (2026-10-05): "A service account is a regular
// user (person) entry with a flag that says 'this is a service account'. It
// is not an application." So everything a person entry already is — a
// password, app passwords, Kerberos keys, a `sub`, groups, roles, RISC's
// account lifecycle, CAEP under the person's `iss_sub` — a service account
// is too, unchanged. What the flag adds is a POLICY (the third kind on
// Directory → Policies, `common/service_account_policy.ts`) and, where the
// realm turns it on, a password that ROTATES and is PUSHED to a secrets
// manager (`cluster`'s `service-accounts.rotate` job,
// `common/service_account_rotation.ts`).
//
// ---------------------------------------------------------------------------
// THE ATTRIBUTES, all on the person's own entry, carried by the AUXILIARY
// class `stsServiceAccount`:
//
//   stsServiceAccount            TRUE. The flag. Its absence is a person.
//   stsServiceAccountOwner       the DN of the person or group answerable for
//                                the account (required while the policy's
//                                `requireOwner` is on — rcbj: "the owner may
//                                be a person or a group").
//   stsSecretDestination         the DN of the APPLICATION ENTRY the rotated
//                                password is pushed to (rcbj: "Each push
//                                destination is an application entry in the
//                                realm"), and
//   stsSecretName                the secret's name or path there.
//   stsPasswordRotatedAt         when the password was last rotated.
//   stsPreviousPassword          the previous password's scrypt hash, for the
//                                overlap window (a SECRET attribute: withheld
//                                from every read, as `userPassword` is), and
//   stsPreviousPasswordExpires   when it stops being accepted (ms).
//   stsRotationFailures          consecutive failed rotations,
//   stsRotationLastError         the code of the last failure, and
//   stsRotationLastAttempt       when the job last tried (ms).
//
// The rotation state is on the ENTRY, not in a process, because any node may
// run the job next (#49) and the count of failures has to survive it moving.
//
// ---------------------------------------------------------------------------
// ONE PREDICATE, `isServiceAccount(entry)`, AND EVERY DOOR ASKS IT (rcbj's
// design: "No door reads the attribute directly"). A door holding a NAME
// rather than an entry asks `isServiceAccountName()`, which reads the entry
// and asks the same predicate.
//
// WHERE THE FLAG IS SET: the console's *Service account* box on
// `/admin/users/new` and a person's page, `POST /admin-api/users/
// set-service-account` (rule 7), and an LDAP modify by a holder of Admin
// Write — never by the person themselves, since no `sts*` attribute is in
// `ldap.selfWritableAttributes` and the directory refuses these names there
// whatever that setting says. SCIM does NOT carry it (rcbj, 2026-10-05).
//
// IT IS A LIBRARY (rule 3) AND A LEAF: `helpers`, `error_codes`, the instance
// slot, the directory through a slot `ldap/ldap_server.js` fills, and LAZILY
// the policy (a leaf) and the destination register.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');

const { log } = helpers;

/**
 * The auxiliary object class that carries a service account's attributes.
 */
const OBJECT_CLASS = 'stsServiceAccount';

/**
 * Every attribute this module writes on a person, in the order the schema
 * lists them.
 */
const ATTRIBUTES = ['stsServiceAccount', 'stsServiceAccountOwner',
                    'stsSecretDestination', 'stsSecretName',
                    'stsPasswordRotatedAt', 'stsPreviousPassword',
                    'stsPreviousPasswordExpires', 'stsRotationFailures',
                    'stsRotationLastError', 'stsRotationLastAttempt'];

/**
 * The attributes no directory read hands out: the previous password's hash.
 */
const SECRET_ATTRIBUTES = ['stsPreviousPassword'];

/**
 * The longest secret name or path accepted.
 */
const MAX_SECRET_NAME = 512;

/**
 * The directory schema a service account adds to a person entry.
 */
const SCHEMA = {
  objectClasses: [
    { name: OBJECT_CLASS,
      what: 'AUXILIARY. This service\'s class for a SERVICE ACCOUNT: a ' +
            'person entry used by a program, governed by the realm\'s ' +
            'service-account policy (ou=serviceAccountPolicies) (#221).' }
  ],
  personAttributes: [
    { name: 'stsServiceAccount',
      what: 'TRUE on a service account. Absent: an ordinary person. Asked ' +
            'through common/service_accounts.ts\'s isServiceAccount(), ' +
            'never read directly.' },
    { name: 'stsServiceAccountOwner',
      what: 'The DN of the person or group answerable for the account.' },
    { name: 'stsSecretDestination',
      what: 'The DN of the application entry (a push destination) a rotated ' +
            'password is written to.' },
    { name: 'stsSecretName',
      what: 'The name or path of the secret at that destination. It must ' +
            'already exist: a push never creates one.' },
    { name: 'stsPasswordRotatedAt',
      what: 'When the password was last rotated (GeneralizedTime).' },
    { name: 'stsPreviousPassword',
      what: 'The previous password\'s scrypt hash, accepted until ' +
            'stsPreviousPasswordExpires. Withheld from every read.' },
    { name: 'stsPreviousPasswordExpires',
      what: 'When the previous password stops being accepted (ms since the ' +
            'epoch).' },
    { name: 'stsRotationFailures',
      what: 'Consecutive failed rotations, reset by a success.' },
    { name: 'stsRotationLastError',
      what: 'The error code of the last failed rotation.' },
    { name: 'stsRotationLastAttempt',
      what: 'When the rotation job last tried this account (ms).' }
  ]
};

interface DirectoryHooks {
  readServiceAccount?(key: string): {
    found: boolean; person: boolean; dn: string; username: string;
    values: Record<string, string>;
  } | null;
  writeServiceAccount?(key: string,
                       changes: Record<string, string | null>): boolean;
  serviceAccountNames?(): string[];
  resolveOwner?(value: string): { kind: string; dn: string; name: string };
  [hook: string]: unknown;
}

/**
 * What a service account is, read off its entry.
 */
interface ServiceAccountFacts {
  username: string;
  dn: string;
  serviceAccount: boolean;
  owner: string;
  ownerKind: string;
  ownerName: string;
  destination: string;
  secretName: string;
  rotatedAt: string;
  previousPasswordExpires: number;
  rotation: { failures: number; lastError: string; lastAttempt: number };
}

interface Refusal {
  ok: false;
  errors: string[];
}

interface ServiceAccountsDeps {
  log: typeof helpers.log;
  errorCodes: {
    mark<T>(target: T, code: string): T;
    tag(code: string): string;
  };
  // The policy's `requireOwner`, asked lazily.
  requiresOwner(): boolean;
  // A destination by its DN, asked lazily: `{ found, usable, problems }`;
  // `found: null` where the register is not loaded in this process.
  destination(dn: string): { found: boolean | null; name?: string;
                             problems?: string[] };
}

// The first value of an attribute on any of the three shapes an entry is
// handed around in here: a stored entry (`attributes`, lower-cased keys,
// arrays), an `entryObject()` (`attributes`, spelt keys) or a flat object.
function firstOf(entry: any, name: string): string {
  log.debug("Entering firstOf(). " + name);
  const bag = entry && typeof entry === 'object'
    ? (entry.attributes && typeof entry.attributes === 'object'
      ? entry.attributes : entry)
    : {};
  let found = bag[name];
  if (found === undefined) {
    found = bag[name.toLowerCase()];
  }
  if (found === undefined) {
    const wanted = name.toLowerCase();
    const key = Object.keys(bag).filter(function (one) {
      return one.toLowerCase() === wanted;
    })[0];
    found = key === undefined ? undefined : bag[key];
  }
  const value = Array.isArray(found) ? found[0] : found;
  log.debug("Leaving firstOf().");
  return value === undefined || value === null ? '' : String(value);
}

/**
 * Service accounts (#221): person entries flagged `stsServiceAccount`, their
 * owner, the destination their rotated password is pushed to, and the state of
 * that rotation. `isServiceAccount()` is the one predicate every door asks.
 */
class ServiceAccounts {
  /**
   * The auxiliary object class.
   */
  static readonly OBJECT_CLASS = OBJECT_CLASS;
  /**
   * Every attribute this module writes.
   */
  static readonly ATTRIBUTES = ATTRIBUTES;
  /**
   * The attributes withheld from every read.
   */
  static readonly SECRET_ATTRIBUTES = SECRET_ATTRIBUTES;
  /**
   * The schema a service account adds to a person entry.
   */
  static readonly SCHEMA = SCHEMA;

  private directory: DirectoryHooks | null = null;

  /**
   * Builds the register with no directory installed.
   *
   * @param deps - the logger, error codes, and lazy reads of the policy and
   *   the destination register
   */
  constructor(private readonly deps: ServiceAccountsDeps) {
    deps.log.debug("Entering ServiceAccounts.constructor().");
    deps.log.debug("Leaving ServiceAccounts.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the service's own modules, with the policy and the destination
   *   register reached lazily
   */
  static defaultDeps(): ServiceAccountsDeps {
    log.debug("Entering ServiceAccounts.defaultDeps().");
    log.debug("Leaving ServiceAccounts.defaultDeps().");
    return {
      log: log,
      errorCodes: errorCodes,
      requiresOwner: function () {
        log.debug("Entering ServiceAccounts requiresOwner().");
        const policy = require('./service_account_policy');
        const out = !!policy.requiresOwner();
        log.debug("Leaving ServiceAccounts requiresOwner().");
        return out;
      },
      destination: function (dn) {
        log.debug("Entering ServiceAccounts destination().");
        let destinations = null;
        try {
          // LAZY, and absent in a process that never loaded the register:
          // then nothing can be said about the DN, which `set()` refuses.
          destinations = require('./secret_destinations');
        } catch (e) {
          log.debug("Caught in ServiceAccounts destination(): " +
                    ((e && e.message) || e));
          destinations = null;
        }
        if (!destinations || typeof destinations.get !== 'function') {
          log.debug("Leaving ServiceAccounts destination(). No register.");
          return { found: null };
        }
        const row = destinations.get(dn);
        log.debug("Leaving ServiceAccounts destination(). " + !!row);
        return row ? { found: true, name: row.name,
                       problems: row.problems || [] }
          : { found: false };
      }
    };
  }

  // -------------------------------------------------------------------------
  // THE PREDICATE.
  // -------------------------------------------------------------------------
  /**
   * Says whether an entry is a service account: `stsServiceAccount` TRUE.
   *
   * Accepts a stored entry, an `entryObject()` or a flat attribute map. The one
   * question every door asks; no door reads the attribute itself.
   *
   * @param entry - the entry
   * @returns true for a service account
   */
  static isServiceAccount(entry: unknown): boolean {
    log.debug("Entering ServiceAccounts.isServiceAccount().");
    const out = firstOf(entry, 'stsServiceAccount').toUpperCase() === 'TRUE';
    log.debug("Leaving ServiceAccounts.isServiceAccount(). " + out);
    return out;
  }

  /**
   * Installs the directory hooks; filled by the directory.
   *
   * @param hooks - the directory's hooks, or null to remove them
   */
  setDirectory(hooks: DirectoryHooks | null | undefined): void {
    const { log } = this.deps;
    log.debug("Entering ServiceAccounts.setDirectory().");
    this.directory = hooks || null;
    log.debug("Leaving ServiceAccounts.setDirectory(). " +
              (this.directory ? 'Installed.' : 'Removed.'));
  }

  /**
   * Returns the installed directory hooks, so a test can put back what was
   * there.
   *
   * @returns the hooks, or null
   */
  directoryInstalled(): DirectoryHooks | null {
    const { log } = this.deps;
    log.debug("Entering ServiceAccounts.directoryInstalled().");
    log.debug("Leaving ServiceAccounts.directoryInstalled().");
    return this.directory;
  }

  private read(username: unknown) {
    const { log } = this.deps;
    log.debug("Entering ServiceAccounts.read().");
    const name = String(username == null ? '' : username).trim();
    if (!name || !this.directory ||
        typeof this.directory.readServiceAccount !== 'function') {
      log.debug("Leaving ServiceAccounts.read(). No store or no name.");
      return null;
    }
    let found = null;
    try {
      found = this.directory.readServiceAccount(name);
    } catch (e) {
      log.debug("Caught in ServiceAccounts.read(): " +
                ((e && e.message) || e));
      found = null;
    }
    log.debug("Leaving ServiceAccounts.read(). " + !!(found && found.found));
    return found && found.found ? found : null;
  }

  /**
   * Says whether the named entry is a service account.
   *
   * @param username - any key the directory locates an entry by
   * @returns false where there is no such entry, or no directory
   */
  isServiceAccountName(username: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering ServiceAccounts.isServiceAccountName().");
    const found = this.read(username);
    const out = !!found && found.person &&
                ServiceAccounts.isServiceAccount(found.values);
    log.debug("Leaving ServiceAccounts.isServiceAccountName(). " + out);
    return out;
  }

  /**
   * Reads what a service account is: its owner, destination and rotation
   * state.
   *
   * @param username - any key the directory locates an entry by
   * @returns the facts, or null where the entry is not a service account
   */
  of(username: unknown): ServiceAccountFacts | null {
    const { log } = this.deps;
    log.debug("Entering ServiceAccounts.of().");
    const found = this.read(username);
    if (!found || !found.person ||
        !ServiceAccounts.isServiceAccount(found.values)) {
      log.debug("Leaving ServiceAccounts.of(). Not a service account.");
      return null;
    }
    const value = function (name: string): string {
      return firstOf(found.values, name);
    };
    const owner = value('stsServiceAccountOwner');
    let ownerKind = '';
    let ownerName = '';
    if (owner && this.directory &&
        typeof this.directory.resolveOwner === 'function') {
      const resolved = this.directory.resolveOwner(owner);
      ownerKind = resolved.kind;
      ownerName = resolved.name;
    }
    const out: ServiceAccountFacts = {
      username: found.username,
      dn: found.dn,
      serviceAccount: true,
      owner: owner,
      ownerKind: ownerKind,
      ownerName: ownerName,
      destination: value('stsSecretDestination'),
      secretName: value('stsSecretName'),
      rotatedAt: value('stsPasswordRotatedAt'),
      previousPasswordExpires: Number(value('stsPreviousPasswordExpires')) ||
                               0,
      rotation: {
        failures: Number(value('stsRotationFailures')) || 0,
        lastError: value('stsRotationLastError'),
        lastAttempt: Number(value('stsRotationLastAttempt')) || 0
      }
    };
    log.debug("Leaving ServiceAccounts.of().");
    return out;
  }

  /**
   * Lists every service account in the ambient realm.
   *
   * @returns their facts, in name order
   */
  list(): ServiceAccountFacts[] {
    const { log } = this.deps;
    log.debug("Entering ServiceAccounts.list().");
    if (!this.directory ||
        typeof this.directory.serviceAccountNames !== 'function') {
      log.debug("Leaving ServiceAccounts.list(). No store.");
      return [];
    }
    const out = this.directory.serviceAccountNames().slice().sort()
      .map((name) => this.of(name))
      .filter(function (one) {
        return !!one;
      });
    log.debug("Leaving ServiceAccounts.list(). " + out.length);
    return out;
  }

  /**
   * Returns the names of every service account in the ambient realm, read
   * without building each one's facts — for a people list's tag and filter.
   *
   * @returns the usernames
   */
  names(): string[] {
    const { log } = this.deps;
    log.debug("Entering ServiceAccounts.names().");
    const out = this.directory &&
                typeof this.directory.serviceAccountNames === 'function'
      ? this.directory.serviceAccountNames() : [];
    log.debug("Leaving ServiceAccounts.names(). " + out.length);
    return out;
  }

  /**
   * Says whether a secret at a destination is one a service account's
   * rotation writes — what `secret_destinations.testPush()` asks before it
   * writes a canary, so a test can never overwrite a live password.
   *
   * @param destination - the destination's DN
   * @param secretName - the secret's name or path
   * @returns true when a service account in this realm names that pair
   */
  secretNameInUse(destination: string, secretName: string): boolean {
    const { log } = this.deps;
    log.debug("Entering ServiceAccounts.secretNameInUse().");
    const dn = String(destination || '').replace(/\s*,\s*/g, ',')
      .toLowerCase();
    const name = String(secretName || '');
    const out = this.list().some(function (one) {
      return one.secretName === name &&
             one.destination.replace(/\s*,\s*/g, ',').toLowerCase() === dn;
    });
    log.debug("Leaving ServiceAccounts.secretNameInUse(). " + out);
    return out;
  }

  // -------------------------------------------------------------------------
  // SETTING THE FLAG.
  // -------------------------------------------------------------------------
  private refusal(code: string, message: string): Refusal {
    const { log, errorCodes } = this.deps;
    log.debug("Entering ServiceAccounts.refusal(). " + code);
    log.debug("Leaving ServiceAccounts.refusal().");
    return errorCodes.mark({ ok: false, errors: [message] }, code);
  }

  private truthy(value: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering ServiceAccounts.truthy().");
    log.debug("Leaving ServiceAccounts.truthy().");
    return value === true || ['true', 'on', '1', 'yes'].indexOf(
      String(value == null ? '' : value).trim().toLowerCase()) >= 0;
  }

  /**
   * Checks what would make an entry a service account, without writing: the
   * owner (a person or a group in this realm, never `selfDn`; required while
   * the policy's `requireOwner` is on), and the destination with the
   * secret's name, both or neither. Asked by `set()`, and by the console's
   * and the API's create BEFORE the person exists, so a refused account is
   * never left behind as an ordinary person.
   *
   * @param given - `owner`, `destination`, `secretName`
   * @param selfDn - the account's own DN, or '' for one not created yet
   * @returns `{ ok: true, owner, destination, secretName }`, or a refusal
   */
  check(given: Record<string, any>, selfDn?: string) {
    const { log } = this.deps;
    log.debug("Entering ServiceAccounts.check().");
    const body = given || {};
    // THE OWNER: a person or a group in this realm, never the account itself.
    const ownerGiven = String(body.owner == null ? '' : body.owner).trim();
    let owner = { kind: '', dn: '', name: '' };
    if (ownerGiven) {
      owner = this.directory &&
              typeof this.directory.resolveOwner === 'function'
        ? this.directory.resolveOwner(ownerGiven) : owner;
      if (owner.kind !== 'person' && owner.kind !== 'group') {
        log.debug("Leaving ServiceAccounts.check(). The owner names nobody.");
        return this.refusal('STS-SVCACCT-0024', '"' +
          ownerGiven.slice(0, 128) + '" is neither a person nor a group in ' +
          'this realm, so it cannot own a service account.');
      }
      if (owner.dn.toLowerCase() === String(selfDn || '').toLowerCase()) {
        log.debug("Leaving ServiceAccounts.check(). The account owns itself.");
        return this.refusal('STS-SVCACCT-0025', 'A service account cannot ' +
          'own itself: the owner is who answers for it.');
      }
    } else if (this.deps.requiresOwner()) {
      log.debug("Leaving ServiceAccounts.check(). No owner.");
      return this.refusal('STS-SVCACCT-0023', 'This realm\'s ' +
        'service-account policy requires an owner — a person or a group ' +
        'answerable for the account. Name one in `owner`.');
    }
    // THE DESTINATION AND THE SECRET'S NAME, both or neither.
    const destination = String(body.destination == null ? ''
                                 : body.destination).trim();
    const secretName = String(body.secretName == null ? ''
                                : body.secretName).trim();
    if (!!destination !== !!secretName) {
      log.debug("Leaving ServiceAccounts.check(). Half a destination.");
      return this.refusal('STS-SVCACCT-0026', 'A push destination and the ' +
        'secret\'s name there go together: name both, or neither.');
    }
    if (secretName && (secretName.length > MAX_SECRET_NAME ||
                       /[\u0000-\u001f\u007f\s]/.test(secretName))) {
      log.debug("Leaving ServiceAccounts.check(). An unusable secret name.");
      return this.refusal('STS-SVCACCT-0028', 'The secret\'s name must be ' +
        'at most ' + MAX_SECRET_NAME + ' characters with no spaces or ' +
        'control characters.');
    }
    if (destination) {
      const row = this.deps.destination(destination);
      if (row.found !== true) {
        log.debug("Leaving ServiceAccounts.check(). Not a destination.");
        return this.refusal('STS-SVCACCT-0029', row.found === null
          ? 'The push destination register is not loaded in this process, ' +
            'so "' + destination.slice(0, 128) + '" cannot be checked.'
          : '"' + destination.slice(0, 128) + '" is not a push destination ' +
            'in this realm. A destination is an application entry ' +
            'registered under Directory → Secret destinations.');
      }
    }
    log.debug("Leaving ServiceAccounts.check(). Allowed.");
    return { ok: true as const, owner: owner, destination: destination,
             secretName: secretName };
  }

  /**
   * Makes a person a service account, changes one, or makes one a person
   * again.
   *
   * `serviceAccount` false clears every attribute this module writes, the
   * previous password and the rotation state included. Otherwise `owner` (a
   * DN, username or group name — required while the policy's `requireOwner`
   * is on), and `destination` (an application entry's DN) with `secretName`,
   * both or neither.
   *
   * @param username - the person
   * @param given - `serviceAccount`, `owner`, `destination`, `secretName`
   * @returns `{ ok: true, account, changed }`, or a refusal with a code
   */
  set(username: unknown, given: Record<string, any>) {
    const { log } = this.deps;
    log.debug("Entering ServiceAccounts.set().");
    const body = given || {};
    const found = this.read(username);
    if (!this.directory ||
        typeof this.directory.writeServiceAccount !== 'function') {
      log.debug("Leaving ServiceAccounts.set(). No store.");
      return this.refusal('STS-SVCACCT-0020', 'There is no directory in ' +
        'this process to keep a service account in.');
    }
    if (!found) {
      log.debug("Leaving ServiceAccounts.set(). Nobody by that name.");
      return this.refusal('STS-SVCACCT-0021', 'There is nobody called "' +
        String(username || '').slice(0, 64) + '" in this realm\'s ' +
        'directory.');
    }
    if (!found.person) {
      log.debug("Leaving ServiceAccounts.set(). Not a person.");
      return this.refusal('STS-SVCACCT-0022', found.dn + ' is not a ' +
        'person entry. A service account is a person entry with a flag; an ' +
        'application is already a non-human identity of its own kind.');
    }
    const was = ServiceAccounts.isServiceAccount(found.values);
    if (!this.truthy(body.serviceAccount)) {
      const changes: Record<string, string | null> = {};
      ATTRIBUTES.forEach(function (name) {
        changes[name] = null;
      });
      if (!this.directory.writeServiceAccount(found.dn, changes)) {
        log.debug("Leaving ServiceAccounts.set(). The clear was not written.");
        return this.refusal('STS-SVCACCT-0027', 'The directory would not ' +
          'write ' + found.dn + '.');
      }
      log.info('service_accounts: ' + found.username + ' is ' +
               (was ? 'no longer' : 'still not') + ' a service account.');
      log.debug("Leaving ServiceAccounts.set(). Cleared.");
      return { ok: true, account: null, changed: was,
               username: found.username };
    }
    const checked = this.check(body, found.dn);
    if (checked.ok !== true) {
      log.debug("Leaving ServiceAccounts.set(). Refused by the checks.");
      return checked;
    }
    const owner = checked.owner;
    const destination = checked.destination;
    const secretName = checked.secretName;
    const changes: Record<string, string | null> = {
      stsServiceAccount: 'TRUE',
      stsServiceAccountOwner: owner.dn || null,
      stsSecretDestination: destination || null,
      stsSecretName: secretName || null
    };
    if (!this.directory.writeServiceAccount(found.dn, changes)) {
      log.debug("Leaving ServiceAccounts.set(). Not written.");
      return this.refusal('STS-SVCACCT-0027', 'The directory would not ' +
        'write ' + found.dn + '.');
    }
    log.info('service_accounts: ' + found.username + ' is ' +
             (was ? 'still' : 'now') + ' a service account, owned by ' +
             (owner.dn || 'nobody') + (destination ? ', pushing to ' +
             destination : '') + '.');
    log.debug("Leaving ServiceAccounts.set(). Written.");
    return { ok: true, account: this.of(found.dn), changed: !was,
             username: found.username };
  }

  // -------------------------------------------------------------------------
  // THE ROTATION'S STATE (P4). Written through the same hook as the flag, so
  // there is one writer of these attributes.
  // -------------------------------------------------------------------------
  private writeState(username: unknown,
                     changes: Record<string, string | null>): boolean {
    const { log } = this.deps;
    log.debug("Entering ServiceAccounts.writeState().");
    const found = this.read(username);
    if (!found || !this.directory ||
        typeof this.directory.writeServiceAccount !== 'function' ||
        !ServiceAccounts.isServiceAccount(found.values)) {
      log.debug("Leaving ServiceAccounts.writeState(). Not a service " +
                "account.");
      return false;
    }
    const out = !!this.directory.writeServiceAccount(found.dn, changes);
    log.debug("Leaving ServiceAccounts.writeState(). " + out);
    return out;
  }

  /**
   * Returns the previous password's hash while it is still accepted.
   *
   * @param username - the account
   * @param nowMs - the time to compare with; now when omitted
   * @returns the hash and its expiry, or null outside the window
   */
  previousPassword(username: unknown, nowMs?: number):
      { hash: string; expires: number } | null {
    const { log } = this.deps;
    log.debug("Entering ServiceAccounts.previousPassword().");
    const found = this.read(username);
    if (!found || !ServiceAccounts.isServiceAccount(found.values)) {
      log.debug("Leaving ServiceAccounts.previousPassword(). Not one.");
      return null;
    }
    const hash = firstOf(found.values, 'stsPreviousPassword');
    const expires = Number(firstOf(found.values,
                                   'stsPreviousPasswordExpires')) || 0;
    // THE EXPIRY IS ASKED HERE, AT THE READ (correctness, not housekeeping —
    // the root CLAUDE.md's rule): a hash the clean-up job has not reached yet
    // is never accepted after its time.
    const live = !!hash && expires > (nowMs === undefined ? Date.now()
                                                          : nowMs);
    log.debug("Leaving ServiceAccounts.previousPassword(). " + live);
    return live ? { hash: hash, expires: expires } : null;
  }

  /**
   * Records a rotation that was committed: the previous hash kept until
   * `expires`, the time, and the failure count reset.
   *
   * @param username - the account
   * @param previousHash - the hash the rotation replaced ('' for none)
   * @param expires - when it stops being accepted (ms)
   * @param rotatedAt - GeneralizedTime of the rotation
   * @returns whether it was written
   */
  recordRotated(username: unknown, previousHash: string, expires: number,
                rotatedAt: string): boolean {
    const { log } = this.deps;
    log.debug("Entering ServiceAccounts.recordRotated().");
    const keep = !!previousHash && expires > Date.now();
    const out = this.writeState(username, {
      stsPasswordRotatedAt: rotatedAt,
      stsPreviousPassword: keep ? previousHash : null,
      stsPreviousPasswordExpires: keep ? String(expires) : null,
      stsRotationFailures: null,
      stsRotationLastError: null,
      stsRotationLastAttempt: String(Date.now())
    });
    log.debug("Leaving ServiceAccounts.recordRotated(). " + out);
    return out;
  }

  /**
   * Records a rotation that failed and changed nothing.
   *
   * @param username - the account
   * @param code - the failure's error code
   * @returns the consecutive failures now, or -1 where nothing was written
   */
  recordFailure(username: unknown, code: string): number {
    const { log } = this.deps;
    log.debug("Entering ServiceAccounts.recordFailure(). " + code);
    const facts = this.of(username);
    if (!facts) {
      log.debug("Leaving ServiceAccounts.recordFailure(). Not one.");
      return -1;
    }
    const failures = facts.rotation.failures + 1;
    const written = this.writeState(username, {
      stsRotationFailures: String(failures),
      stsRotationLastError: String(code || ''),
      stsRotationLastAttempt: String(Date.now())
    });
    log.debug("Leaving ServiceAccounts.recordFailure(). " + failures);
    return written ? failures : -1;
  }

  /**
   * Clears a previous password whose window has closed — the clean-up job's
   * one write.
   *
   * @param username - the account
   * @param nowMs - the time to compare with; now when omitted
   * @returns true when a hash was cleared
   */
  clearExpiredPrevious(username: unknown, nowMs?: number): boolean {
    const { log } = this.deps;
    log.debug("Entering ServiceAccounts.clearExpiredPrevious().");
    const found = this.read(username);
    if (!found || !ServiceAccounts.isServiceAccount(found.values)) {
      log.debug("Leaving ServiceAccounts.clearExpiredPrevious(). Not one.");
      return false;
    }
    const hash = firstOf(found.values, 'stsPreviousPassword');
    const expires = Number(firstOf(found.values,
                                   'stsPreviousPasswordExpires')) || 0;
    const now = nowMs === undefined ? Date.now() : nowMs;
    if (!hash && !expires) {
      log.debug("Leaving ServiceAccounts.clearExpiredPrevious(). None held.");
      return false;
    }
    if (hash && expires > now) {
      log.debug("Leaving ServiceAccounts.clearExpiredPrevious(). Still live.");
      return false;
    }
    const out = this.writeState(username, { stsPreviousPassword: null,
                                            stsPreviousPasswordExpires: null });
    log.debug("Leaving ServiceAccounts.clearExpiredPrevious(). " + out);
    return out;
  }
}

const slot = new InstanceSlot<ServiceAccounts>(
  'common/service_accounts',
  () => new ServiceAccounts(ServiceAccounts.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

/**
 * Service accounts (#221): person entries flagged `stsServiceAccount`. The
 * exports forward to the instance the composition root installs;
 * `isServiceAccount()` is static and needs none.
 *
 * @namespace
 */
export = {
  ServiceAccounts: ServiceAccounts,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: ServiceAccounts): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  OBJECT_CLASS: ServiceAccounts.OBJECT_CLASS,
  ATTRIBUTES: ServiceAccounts.ATTRIBUTES,
  SECRET_ATTRIBUTES: ServiceAccounts.SECRET_ATTRIBUTES,
  SCHEMA: ServiceAccounts.SCHEMA,
  isServiceAccount: ServiceAccounts.isServiceAccount,
  setDirectory: slot.forward('setDirectory'),
  directoryInstalled: slot.forward('directoryInstalled'),
  isServiceAccountName: slot.forward('isServiceAccountName'),
  of: slot.forward('of'),
  list: slot.forward('list'),
  names: slot.forward('names'),
  secretNameInUse: slot.forward('secretNameInUse'),
  check: slot.forward('check'),
  set: slot.forward('set'),
  previousPassword: slot.forward('previousPassword'),
  recordRotated: slot.forward('recordRotated'),
  recordFailure: slot.forward('recordFailure'),
  clearExpiredPrevious: slot.forward('clearExpiredPrevious')
};
