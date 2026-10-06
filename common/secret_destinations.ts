// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: secret_destinations.ts
//
// ---------------------------------------------------------------------------
// THE SECRET PUSH DESTINATIONS (#221 P3, 2026-10-06): WHERE A SERVICE
// ACCOUNT'S ROTATED PASSWORD IS WRITTEN.
//
// rcbj's design on #221: a service account's password is rotated
// automatically, and each new password is PUSHED to a secrets manager before
// its hash is committed (decisions 3 and 5). Destinations are named and
// registered per realm, each with its own write credential sealed under the
// key-encryption key (decision 6), and — the answer to open question 3 —
// **each destination is an APPLICATION ENTRY in the realm, holding its
// credential**, so the rule that every credential sits on a user or an
// application entry keeps no exception. A service account's
// `stsSecretDestination` names that entry (P1), and its `stsSecretName` the
// secret.
//
// **SO THIS REGISTER IS NOT A STORE.** It is the realm's application entries
// declared for the `secret-destination` family (`common/applications.js`'s
// PROTOCOLS row and its ten `secretDest*` attributes), read through
// `applications.list()` — one copy of every fact, and the entry's own page,
// LDAP and `/admin-api/applications` reach the same attributes. What this
// module adds is the MEANING: whether a destination is usable and why not,
// the add / change / remove / test-push acts the register page and
// `/admin-api/secret-destinations` share (rule 7), and `push()`, which P4's
// rotation calls.
//
// **THE WRITE CREDENTIAL IS WRITE-ONLY.** It is sealed on the way in
// (`SEALED_FIELDS`), withheld from every view on the way out
// (`WITHHELD_FIELDS`, a sentence in its place), masked in every directory
// read (`SECRET_ATTRIBUTES`), refused by `reveal-secret`, never quoted in an
// audit row or a log line, and opened by `applications
// .secretDestinationCredentialOf()` for the one push that uses it. Nothing
// this module answers carries it: a row says `credentialSet` and nothing
// more.
//
// **THE CONTRACT P4 CODES AGAINST** — the names are fixed:
//
//   list()      the ambient realm's destinations: { id (the entry's DN),
//               name, provider, payload, usable, problems, ... }
//   get(id)     one of those (by DN, or by the entry's identifier), or null
//   push(id, secretName, { username, password, realm, rotatedAt })
//               -> Promise<{ ok, version?, error?, code? }>, NEVER throws
//   testPush(id, testSecretName)
//               a canary version, written only to a TEST secret: refused
//               for a name a service account's rotation writes, where
//               `common/service_accounts` can say so (it is asked for
//               `secretNameInUse(destinationId, secretName)`)
//   isDestination(entry)
//
// A library: it registers no route (the API is
// `mgmt-api/secret_destinations_api.ts`, the page `admin-ui/
// web_secret_destinations.ts`). It requires `applications`, `secrets`,
// `mode`, `audit`, `crypto`, `realms` and `error_codes`, none of which
// requires it, so it closes no cycle and moves no route.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import applications = require('./applications');
import secrets = require('./secrets');
import mode = require('./mode');
import audit = require('./audit');
import realms = require('./realms');
import errorCodes = require('./error_codes');
// The canary's random password: every random value comes from crypto.js.
import stsCrypto = require('./crypto');

type Json = Record<string, any>;

const log = helpers.log;

/**
 * The declared family a destination's application entry carries.
 */
const FAMILY = 'secret-destination';

/**
 * The page's path, which the API's `mirrors` names.
 */
const PAGE = '/admin/secret-destinations';

// The attributes a definition is made of, by the member name the console and
// the API take them under. The credential is apart: it is written, never
// read back.
const MEMBERS: Array<[string, string]> = [
  ['provider', 'secretDestProvider'],
  ['payload', 'secretDestPayload'],
  ['region', 'secretDestRegion'],
  ['project', 'secretDestProject'],
  ['endpoint', 'secretDestEndpoint'],
  ['mount', 'secretDestMount'],
  ['field', 'secretDestField'],
  ['directory', 'secretDestDirectory'],
  ['caCertificates', 'secretDestCaCertificates']
];
const CREDENTIAL_ATTRIBUTE = 'secretDestCredential';

// What each provider's write credential is, for a refusal and for the page.
const CREDENTIAL_SHAPES: Record<string, { members: string[]; what: string }>
  = {
    aws: { members: ['accessKeyId', 'secretAccessKey'],
           what: 'JSON {"accessKeyId", "secretAccessKey"[, ' +
                 '"sessionToken"]} of an IAM identity allowed ' +
                 'secretsmanager:PutSecretValue on the named secrets' },
    gcp: { members: ['client_email', 'private_key'],
           what: 'a service account key file\'s JSON, for an account ' +
                 'granted secretmanager.versions.add on the named secrets' },
    azure: { members: ['tenantId', 'clientId', 'clientSecret'],
             what: 'JSON {"tenantId", "clientId", "clientSecret"} of an ' +
                   'application allowed to list and set secrets' },
    vault: { members: [],
             what: 'a token whose policy allows read on <mount>/metadata/' +
                   '<name> and create, update on <mount>/data/<name>' },
    file: { members: [], what: 'none' }
  };

// The secret names a canary is written to are anybody's; the service
// accounts' own are not (testPush()). The most PEM a destination's CA may
// hold.
const MAX_CA_TEXT = 65536;

/**
 * A push's answer: `ok`, and the store's `version`, or why not and its code.
 */
interface PushResult {
  ok: boolean;
  version?: string;
  error?: string;
  code?: string;
}

/**
 * One destination as `list()` and `get()` answer it. Never the credential.
 */
interface DestinationRow {
  id: string;
  identifier: string;
  name: string;
  provider: string;
  payload: 'password' | 'json';
  usable: boolean;
  problems: string[];
  location: Json;
  credentialSet: boolean;
  credentialShape: string;
}

interface SecretDestinationsDeps {
  log: typeof helpers.log;
  applications: typeof applications;
  secrets: typeof secrets;
  mode: typeof mode;
  audit: typeof audit;
  realms: typeof realms;
  errorCodes: typeof errorCodes;
  randomToken: (bits: number) => string;
  // The service accounts' module (P1), asked whether a secret name is one a
  // rotation writes. Loaded lazily and optional: until it says, a test push
  // trusts the name it is given, as the page says.
  loadServiceAccounts: () => Json | null;
}

/**
 * The secret push destinations of a realm: its application entries declared
 * for `secret-destination`, what makes each usable, the acts on them, and the
 * push a service account's rotation calls (#221).
 */
class SecretDestinations {
  /**
   * Builds the register from its dependencies.
   *
   * @param deps - from `SecretDestinations.defaultDeps()`, or a test's
   */
  constructor(private readonly deps: SecretDestinationsDeps) {
    deps.log.debug("Entering SecretDestinations.constructor().");
    deps.log.debug("Leaving SecretDestinations.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): SecretDestinationsDeps {
    log.debug("Entering SecretDestinations.defaultDeps().");
    log.debug("Leaving SecretDestinations.defaultDeps().");
    return {
      log: log, applications: applications, secrets: secrets, mode: mode,
      audit: audit, realms: realms, errorCodes: errorCodes,
      randomToken: function (bits: number): string {
        return stsCrypto.randomToken(bits);
      },
      loadServiceAccounts: function (): Json | null {
        try {
          return require('./service_accounts');
        } catch (e: any) {
          log.debug("Caught in SecretDestinations.loadServiceAccounts(): " +
                    ((e && e.message) || e));
          // Not built yet (#221 P1 lands beside this): no name is known to
          // be a service account's, and testPush() says so.
          return null;
        }
      }
    };
  }

  /**
   * Says whether an application entry, record or view is a secret push
   * destination: declared for the `secret-destination` family.
   *
   * @param entry - an application view or record (`fields`), or raw entry
   *   attributes
   * @returns true for a destination
   */
  isDestination(entry: unknown): boolean {
    const { log, applications } = this.deps;
    log.debug("Entering SecretDestinations.isDestination().");
    const e: Json = (entry && typeof entry === 'object') ? entry as Json : {};
    const record = e.fields ? e : { fields: e.attributes || e };
    const declared = applications.declaredFamiliesOf(record as any);
    log.debug("Leaving SecretDestinations.isDestination().");
    return declared.indexOf(FAMILY) >= 0;
  }

  // One value of a view's fields, as text.
  private one(fields: Json, attribute: string): string {
    const { log } = this.deps;
    log.debug("Entering SecretDestinations.one(). " + attribute);
    const value = fields[attribute];
    log.debug("Leaving SecretDestinations.one().");
    return String((Array.isArray(value) ? value[0] : value) || '').trim();
  }

  // What stops a destination from being pushed to, as sentences: the same
  // rules `secrets.pushSecret()` refuses by, said before anybody pushes.
  private problemsOf(location: Json, credentialSet: boolean): string[] {
    const { log, secrets, mode } = this.deps;
    log.debug("Entering SecretDestinations.problemsOf().");
    const out: string[] = [];
    const provider = location.provider;
    if (secrets.DESTINATION_PROVIDERS.indexOf(provider) < 0) {
      out.push(provider ? '"' + provider + '" is not a provider; it is one ' +
                          'of ' + secrets.DESTINATION_PROVIDERS.join(', ') +
                          '.'
                        : 'No provider is set.');
    }
    if (location.payload &&
        secrets.DESTINATION_PAYLOADS.indexOf(location.payload) < 0) {
      out.push('"' + location.payload + '" is not a payload; it is one of ' +
               secrets.DESTINATION_PAYLOADS.join(', ') + '.');
    }
    if (provider === 'aws' && !location.region) {
      out.push('An AWS destination needs its region.');
    }
    if ((provider === 'azure' || provider === 'vault') &&
        !/^https:\/\/[^\s\/?#]+/i.test(location.endpoint || '')) {
      out.push((provider === 'azure' ? 'An Azure Key Vault destination ' +
                                       'needs its vault URL'
                                     : 'A Vault destination needs its ' +
                                       'address') +
               ', https only.');
    }
    if (provider === 'file') {
      if (!mode.acceptsFileSecretDestinations()) {
        out.push('A file is a destination in development mode only.');
      }
      if (!location.directory || location.directory.charAt(0) !== '/') {
        out.push('A file destination needs an absolute directory.');
      }
    }
    if (provider && provider !== 'file' && !credentialSet) {
      out.push('No write credential is set.');
    }
    log.debug("Leaving SecretDestinations.problemsOf(). " + out.length);
    return out;
  }

  // One application view as a destination row.
  private rowOf(view: Json): DestinationRow {
    const { log } = this.deps;
    log.debug("Entering SecretDestinations.rowOf().");
    const fields = view.fields || {};
    const location: Json = {};
    MEMBERS.forEach((pair) => {
      location[pair[0]] = this.one(fields, pair[1]);
    });
    location.payload = location.payload || 'password';
    // THE VIEW CARRIES THE WITHHELD SENTENCE, so its presence is the fact
    // that a credential is set — and nothing else about it is known here.
    const credentialSet = !!this.one(fields, CREDENTIAL_ATTRIBUTE);
    const problems = this.problemsOf(location, credentialSet);
    const shape = CREDENTIAL_SHAPES[location.provider];
    log.debug("Leaving SecretDestinations.rowOf().");
    return {
      id: String(view.dn || view.identifier || ''),
      identifier: String(view.identifier || ''),
      name: String(view.name || view.identifier || ''),
      provider: location.provider,
      payload: location.payload === 'json' ? 'json' : 'password',
      usable: problems.length === 0,
      problems: problems,
      location: location,
      credentialSet: credentialSet,
      credentialShape: shape ? shape.what : ''
    };
  }

  /**
   * Lists the ambient realm's secret push destinations, each with whether it
   * is usable and why not. Never a credential.
   *
   * @returns the destinations
   */
  list(): DestinationRow[] {
    const { log, applications } = this.deps;
    log.debug("Entering SecretDestinations.list().");
    const out = applications.list().filter((view: Json) => {
      return this.isDestination(view);
    }).map((view: Json) => this.rowOf(view));
    log.debug("Leaving SecretDestinations.list(). " + out.length + ".");
    return out;
  }

  /**
   * Returns one destination of the ambient realm, by its entry's DN or its
   * application identifier.
   *
   * @param id - the DN (the `id` `list()` answers) or the identifier
   * @returns the destination, or null
   */
  get(id: string): DestinationRow | null {
    const { log } = this.deps;
    log.debug("Entering SecretDestinations.get().");
    const wanted = String(id || '').trim();
    if (!wanted) {
      log.debug("Leaving SecretDestinations.get(). No id.");
      return null;
    }
    const lower = wanted.toLowerCase();
    const found = this.list().filter(function (row) {
      return row.id.toLowerCase() === lower || row.identifier === wanted;
    })[0] || null;
    log.debug("Leaving SecretDestinations.get(). " + (found ? 'Found.'
                                                           : 'None.'));
    return found;
  }

  // A coded failure in push()'s shape, audited.
  private failed(row: DestinationRow | null, id: string, secretName: string,
                 why: string, code: string, test: boolean): PushResult {
    const { log, audit } = this.deps;
    log.debug("Entering SecretDestinations.failed(). " + code);
    audit.audit({ action: test ? 'secret-destination.test-push'
                               : 'secret-destination.push',
                  category: 'admin', protocol: 'secrets',
                  channel: 'internal', errorCode: code,
                  target: row ? row.id : id,
                  summary: (test ? 'A test push' : 'A push') + ' of "' +
                           secretName + '" to ' +
                           (row ? row.name : '"' + id + '"') + ' failed',
                  detail: { destination: row ? row.id : id,
                            secretName: secretName } });
    log.debug("Leaving SecretDestinations.failed().");
    return { ok: false, error: why, code: code };
  }

  // The push itself: the destination, its opened credential, the store.
  private async write(id: string, secretName: string, value: Json,
                      test: boolean): Promise<PushResult> {
    const { log, applications, secrets, audit, errorCodes } = this.deps;
    log.debug("Entering SecretDestinations.write().");
    const row = this.get(id);
    const name = String(secretName || '').trim();
    if (!row) {
      log.debug("Leaving SecretDestinations.write(). No such destination.");
      return this.failed(null, String(id || ''), name, 'There is no secret ' +
        'destination "' + id + '" in this realm.', 'STS-SECDEST-0009', test);
    }
    if (!row.usable) {
      log.debug("Leaving SecretDestinations.write(). Not usable.");
      return this.failed(row, row.id, name, 'Secret destination ' + row.name +
        ' is not usable: ' + row.problems.join(' '),
        row.problems.some(function (p) { return /development mode/.test(p); })
          ? 'STS-SECDEST-0006' : 'STS-SECDEST-0002', test);
    }
    let answer: Json;
    try {
      answer = await secrets.pushSecret(Object.assign({}, row.location, {
        provider: row.provider, payload: row.payload, label: row.name,
        secretName: name,
        value: { username: String(value.username || ''),
                 password: String(value.password || ''),
                 realm: String(value.realm || ''),
                 rotatedAt: String(value.rotatedAt || '') },
        // OPENED HERE, for this call, and held by nothing after it.
        credential: row.provider === 'file' ? ''
          : applications.secretDestinationCredentialOf(row.identifier)
      }));
    } catch (e: any) {
      const code = errorCodes.codeOf(e) || 'STS-SECDEST-0015';
      log.debug("Caught in SecretDestinations.write(): " + code);
      log.debug("Leaving SecretDestinations.write(). Refused.");
      return this.failed(row, row.id, name, String((e && e.message) || e),
                         code, test);
    }
    const version = String((answer && answer.version) || '');
    audit.audit({ action: test ? 'secret-destination.test-push'
                               : 'secret-destination.push',
                  category: 'admin', protocol: 'secrets',
                  channel: 'internal', target: row.id,
                  summary: (test ? 'A test version' : 'A new version') +
                           ' of "' + name + '" was pushed to ' + row.name +
                           ' (' + row.provider + ')',
                  detail: { destination: row.id, secretName: name,
                            provider: row.provider, version: version } });
    log.debug("Leaving SecretDestinations.write(). Pushed.");
    return { ok: true, version: version };
  }

  /**
   * Pushes a new version of a service account's secret to a destination: the
   * write a rotation commits a password after (#221 decision 5). Never
   * throws, never creates a secret, never logs or returns the password.
   *
   * @param id - the destination's DN, or its identifier
   * @param secretName - the secret's name or path at the destination
   * @param value - `username`, `password`, `realm` and `rotatedAt`
   * @returns `{ ok: true, version }`, or `{ ok: false, error, code }`
   */
  async push(id: string, secretName: string, value: Json): Promise<PushResult> {
    const { log } = this.deps;
    log.debug("Entering SecretDestinations.push().");
    let out: PushResult;
    try {
      out = await this.write(id, secretName, value || {}, false);
    } catch (e: any) {
      // write() answers rather than throws; this is the promise's guarantee
      // that a rotation is never thrown at, whatever a store's SDK did.
      log.error(errorCodes.tag('STS-SECDEST-0015') + 'secret destinations: ' +
                'a push failed unexpectedly: ' + ((e && e.message) || e));
      out = { ok: false, error: 'The push failed unexpectedly.',
              code: 'STS-SECDEST-0015' };
    }
    log.debug("Leaving SecretDestinations.push(). ok=" + out.ok);
    return out;
  }

  // Whether a secret name is one a service account's rotation writes, where
  // the service accounts' module can say; false where it cannot.
  private serviceAccountSecret(row: DestinationRow, name: string): boolean {
    const { log, loadServiceAccounts } = this.deps;
    log.debug("Entering SecretDestinations.serviceAccountSecret().");
    const accounts = loadServiceAccounts();
    if (!accounts || typeof accounts.secretNameInUse !== 'function') {
      log.debug("Leaving SecretDestinations.serviceAccountSecret(). " +
                "Nobody to ask.");
      return false;
    }
    let inUse = false;
    try {
      inUse = !!accounts.secretNameInUse(row.id, name);
    } catch (e: any) {
      // Asked and not answered: refuse rather than write a canary over a
      // secret that may be a service account's.
      log.debug("Caught in SecretDestinations.serviceAccountSecret(): " +
                ((e && e.message) || e));
      inUse = true;
    }
    log.debug("Leaving SecretDestinations.serviceAccountSecret(). " + inUse);
    return inUse;
  }

  /**
   * Writes a CANARY version — a random password nobody uses — to a test
   * secret at a destination, to prove the credential, the address and the
   * secret before a rotation depends on them. Refused for a secret a service
   * account's rotation writes.
   *
   * @param id - the destination's DN, or its identifier
   * @param testSecretName - a secret kept for the test
   * @returns push()'s answer
   */
  async testPush(id: string, testSecretName: string): Promise<PushResult> {
    const { log, realms, randomToken } = this.deps;
    log.debug("Entering SecretDestinations.testPush().");
    const name = String(testSecretName || '').trim();
    const row = this.get(id);
    if (row && name && this.serviceAccountSecret(row, name)) {
      log.debug("Leaving SecretDestinations.testPush(). A service account's.");
      return this.failed(row, row.id, name, '"' + name + '" is the secret a ' +
        'service account\'s rotation writes at ' + row.name + '. A test push ' +
        'writes a canary, and only to a secret kept for testing.',
        'STS-SECDEST-0010', true);
    }
    let out: PushResult;
    try {
      out = await this.write(id, name, {
        username: 'sts-test-push', password: randomToken(256),
        realm: realms.currentId() || 'default',
        rotatedAt: new Date().toISOString() }, true);
    } catch (e: any) {
      log.error(errorCodes.tag('STS-SECDEST-0015') + 'secret destinations: ' +
                'a test push failed unexpectedly: ' + ((e && e.message) || e));
      out = { ok: false, error: 'The test push failed unexpectedly.',
              code: 'STS-SECDEST-0015' };
    }
    log.debug("Leaving SecretDestinations.testPush(). ok=" + out.ok);
    return out;
  }

  // ---------------------------------------------------------------------
  // THE REGISTER'S ACTS, for the page and the API alike (rule 7).
  // ---------------------------------------------------------------------

  // A coded refusal in the shape every act answers.
  private refusal(code: string, errors: string[]): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering SecretDestinations.refusal(). " + code);
    log.debug("Leaving SecretDestinations.refusal().");
    return errorCodes.mark({ ok: false, errors: errors }, code);
  }

  // Whether a credential is the shape its provider takes. Said by member,
  // never by value.
  private credentialProblem(provider: string, credential: string): string {
    const { log } = this.deps;
    log.debug("Entering SecretDestinations.credentialProblem().");
    const shape = CREDENTIAL_SHAPES[provider];
    if (!shape || !shape.members.length) {
      log.debug("Leaving SecretDestinations.credentialProblem(). Free form.");
      return provider === 'vault' && /\s/.test(credential)
        ? 'A Vault token is one word.' : '';
    }
    let parsed: Json | null = null;
    try {
      parsed = JSON.parse(credential);
    } catch (e: any) {
      log.debug("Caught in SecretDestinations.credentialProblem(): " +
                ((e && e.message) || e));
      parsed = null;
    }
    const missing = (!parsed || typeof parsed !== 'object' ||
                     Array.isArray(parsed))
      ? shape.members
      : shape.members.filter(function (m) { return !(parsed as Json)[m]; });
    log.debug("Leaving SecretDestinations.credentialProblem(). " +
              missing.length);
    return missing.length
      ? 'A ' + provider + ' write credential is ' + shape.what + '; this ' +
        'one lacks ' + missing.join(', ') + '.'
      : '';
  }

  // The definition an act would leave, checked whole before anything is
  // written: the location members, then the credential.
  private definitionProblems(location: Json, credential: string,
                             credentialSet: boolean): string[] {
    const { log } = this.deps;
    log.debug("Entering SecretDestinations.definitionProblems().");
    const out = this.problemsOf(location, credentialSet || !!credential)
      .filter(function (p) { return p !== 'No write credential is set.'; });
    if (location.provider && location.provider !== 'file' && !credential &&
        !credentialSet) {
      out.push('A ' + location.provider + ' destination needs its write ' +
               'credential: ' + CREDENTIAL_SHAPES[location.provider].what +
               '.');
    }
    if (credential) {
      const bad = this.credentialProblem(location.provider, credential);
      if (bad) {
        out.push(bad);
      }
    }
    const ca = String(location.caCertificates || '');
    if (ca && (ca.length > MAX_CA_TEXT ||
               !/-----BEGIN CERTIFICATE-----/.test(ca))) {
      out.push('The CA certificates are PEM certificates, at most ' +
               MAX_CA_TEXT + ' characters.');
    }
    log.debug("Leaving SecretDestinations.definitionProblems(). " +
              out.length);
    return out;
  }

  // The members an act was given, over what the destination holds.
  private locationFrom(given: Json, before: DestinationRow | null): Json {
    const { log } = this.deps;
    log.debug("Entering SecretDestinations.locationFrom().");
    const out: Json = {};
    MEMBERS.forEach(function (pair) {
      const key = pair[0];
      out[key] = given[key] !== undefined
        ? String(given[key] == null ? '' : given[key]).trim()
        : (before ? String(before.location[key] || '') : '');
    });
    out.payload = out.payload || 'password';
    log.debug("Leaving SecretDestinations.locationFrom().");
    return out;
  }

  // Writes the definition onto the entry, one attribute at a time through
  // the registry's own door, the credential last (sealed there).
  private writeDefinition(identifier: string, location: Json,
                          before: DestinationRow | null, credential: string,
                          actor: string): string[] {
    const { log, applications, errorCodes } = this.deps;
    log.debug("Entering SecretDestinations.writeDefinition().");
    const errors: string[] = [];
    MEMBERS.forEach(function (pair) {
      const value = String(location[pair[0]] || '');
      const was = before ? String(before.location[pair[0]] || '') : '';
      if (errors.length || value === was) {
        return;
      }
      const result: Json = applications.updateApplication(identifier, {
        attribute: pair[1], mode: 'set', value: value, actor: actor });
      if (!result.ok) {
        errors.push.apply(errors, result.errors || []);
        log.debug("A write of " + pair[1] + " was refused: " +
                  errorCodes.codeOf(result));
      }
    });
    if (!errors.length && credential) {
      const result: Json = applications.updateApplication(identifier, {
        attribute: CREDENTIAL_ATTRIBUTE, mode: 'set', value: credential,
        actor: actor });
      if (!result.ok) {
        errors.push.apply(errors, result.errors || []);
      }
    }
    log.debug("Leaving SecretDestinations.writeDefinition(). " +
              errors.length);
    return errors;
  }

  /**
   * Performs one act on the register, for the console and the API:
   * `add-destination`, `update-destination`, `remove-destination` and
   * `test-push`.
   *
   * @param body - `action` and its members
   * @param context - `actor` and `via`
   * @returns `{ ok, message, ... }` or a coded refusal
   */
  async act(body: Json, context?: Json): Promise<Json> {
    const { log, applications, mode, errorCodes } = this.deps;
    const given = body || {};
    const ctx = context || {};
    const actor = String(ctx.actor || '');
    const action = String(given.action || '');
    log.debug("Entering SecretDestinations.act(). " + action);

    if (action === 'add-destination') {
      const identifier = String(given.identifier || '').trim();
      const location = this.locationFrom(given, null);
      const credential = String(given.credential || '');
      const problems = (identifier ? [] : ['An identifier is required: the ' +
        'name the destination\'s application entry is filed under.'])
        .concat(this.definitionProblems(location, credential, false));
      if (problems.length) {
        log.debug("Leaving SecretDestinations.act(). Refused.");
        return this.refusal(location.provider === 'file' &&
                            !mode.acceptsFileSecretDestinations()
                              ? 'STS-SECDEST-0006' : 'STS-SECDEST-0011',
                            problems);
      }
      const fields: Json = {};
      MEMBERS.forEach(function (pair) {
        if (location[pair[0]]) {
          fields[pair[1]] = location[pair[0]];
        }
      });
      if (credential) {
        fields[CREDENTIAL_ATTRIBUTE] = credential;
      }
      const created: Json = applications.createApplication({
        identifier: identifier,
        name: String(given.name || '').trim() || identifier,
        protocols: [FAMILY], fields: fields, actor: actor });
      if (!created.ok) {
        log.debug("Leaving SecretDestinations.act(). Not created.");
        return this.refusal(errorCodes.codeOf(created) || 'STS-SECDEST-0011',
                            created.errors || []);
      }
      const row = this.get(identifier);
      log.debug("Leaving SecretDestinations.act(). Added.");
      return { ok: true, destination: row,
               message: 'Secret destination ' + identifier + ' is added' +
                        (row && !row.usable ? ', and is not usable yet: ' +
                                              row.problems.join(' ')
                                            : '.') };
    }

    const id = String(given.id || '').trim();
    const before = id ? this.get(id) : null;
    if (['update-destination', 'remove-destination',
         'test-push'].indexOf(action) < 0) {
      log.debug("Leaving SecretDestinations.act(). Unknown action.");
      return this.refusal('STS-SECDEST-0012', ['Unknown action "' + action +
        '". The four are: add-destination, update-destination, ' +
        'remove-destination, test-push.']);
    }
    if (!before) {
      log.debug("Leaving SecretDestinations.act(). No such destination.");
      return this.refusal('STS-SECDEST-0009', ['There is no secret ' +
        'destination "' + id + '" in this realm.']);
    }

    if (action === 'update-destination') {
      const location = this.locationFrom(given, before);
      const credential = String(given.credential || '');
      const problems = this.definitionProblems(location, credential,
                                               before.credentialSet);
      if (problems.length) {
        log.debug("Leaving SecretDestinations.act(). Refused.");
        return this.refusal(location.provider === 'file' &&
                            !mode.acceptsFileSecretDestinations()
                              ? 'STS-SECDEST-0006' : 'STS-SECDEST-0011',
                            problems);
      }
      const errors = this.writeDefinition(before.identifier, location, before,
                                          credential, actor);
      if (errors.length) {
        log.debug("Leaving SecretDestinations.act(). A write was refused.");
        return this.refusal('STS-SECDEST-0011', errors);
      }
      if (given.name !== undefined && String(given.name).trim() &&
          String(given.name).trim() !== before.name) {
        applications.updateApplication(before.identifier, {
          attribute: 'appName', mode: 'set',
          value: String(given.name).trim(), actor: actor });
      }
      const row = this.get(before.identifier);
      log.debug("Leaving SecretDestinations.act(). Changed.");
      return { ok: true, destination: row,
               message: 'Secret destination ' + before.name + ' is changed' +
                        (credential ? ', with a new write credential' : '') +
                        (row && !row.usable ? '. It is not usable: ' +
                                              row.problems.join(' ')
                                            : '.') };
    }

    if (action === 'remove-destination') {
      const gone: Json = applications.deleteApplication(before.identifier,
                                                        { actor: actor });
      if (!gone.ok) {
        log.debug("Leaving SecretDestinations.act(). Not removed.");
        return this.refusal(errorCodes.codeOf(gone) || 'STS-SECDEST-0011',
                            gone.errors || []);
      }
      log.debug("Leaving SecretDestinations.act(). Removed.");
      return { ok: true, message: 'Secret destination ' + before.name +
               ' is removed, with its write credential. A service account ' +
               'that named it has nowhere to push until it names another.' };
    }

    // test-push
    const tested = await this.testPush(before.id,
                                       String(given.secretName || ''));
    if (!tested.ok) {
      log.debug("Leaving SecretDestinations.act(). The test push failed.");
      return this.refusal(tested.code || 'STS-SECDEST-0015',
                          [String(tested.error || '')]);
    }
    log.debug("Leaving SecretDestinations.act(). Tested.");
    return { ok: true, version: tested.version,
             message: 'A canary version of "' + String(given.secretName) +
                      '" was written to ' + before.name + ' (version ' +
                      (tested.version || 'not given') + '). Nothing a ' +
                      'service account reads was touched.' };
  }

  /**
   * Returns the view the register page is drawn from and
   * `GET /admin-api/secret-destinations` answers. Never a credential.
   *
   * @returns the view
   */
  view(): Json {
    const { log, secrets, mode } = this.deps;
    log.debug("Entering SecretDestinations.view().");
    const out = {
      destinations: this.list(),
      providers: secrets.DESTINATION_PROVIDERS.filter(function (one) {
        return one !== 'file' || mode.acceptsFileSecretDestinations();
      }),
      payloads: secrets.DESTINATION_PAYLOADS.slice(),
      credentialShapes: Object.keys(CREDENTIAL_SHAPES).reduce(
        function (acc: Json, key) {
          acc[key] = CREDENTIAL_SHAPES[key].what;
          return acc;
        }, {}),
      fileAllowed: mode.acceptsFileSecretDestinations(),
      family: FAMILY
    };
    log.debug("Leaving SecretDestinations.view().");
    return out;
  }
}

const slot = new InstanceSlot<SecretDestinations>(
  'common/secret_destinations',
  () => new SecretDestinations(SecretDestinations.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

/**
 * The secret push destinations (#221 P3): a realm's application entries
 * declared for `secret-destination`, and the push a service account's
 * rotation calls. The exports forward to the instance the composition root
 * installs.
 *
 * @namespace
 */
export = {
  SecretDestinations: SecretDestinations,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: SecretDestinations): void =>
    slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  FAMILY: FAMILY,
  PAGE: PAGE,
  CREDENTIAL_ATTRIBUTE: CREDENTIAL_ATTRIBUTE,
  isDestination: slot.forward('isDestination'),
  list: slot.forward('list'),
  get: slot.forward('get'),
  push: slot.forward('push'),
  testPush: slot.forward('testPush'),
  act: slot.forward('act'),
  view: slot.forward('view')
};
