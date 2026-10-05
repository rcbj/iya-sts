// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: secrets_admin.ts
//
// ===========================================================================
// MONITORING > SECRET STORE: ONE CONSOLE PAGE, `/admin/secrets` (2026-09-12).
//
// **WHERE THIS SERVICE'S PRIMORDIAL SECRETS COME FROM, WHETHER IT ACTUALLY
// GOT THEM, AND WHAT THE STORE AT THE OTHER END IS DOING.**
//
// There are two of them and there is no third: the **key-encryption key**,
// which everything this service seals is sealed under, and the **database
// password**. Both are read from outside — this service never generates
// either and never writes either down — so they are the one part of its
// configuration whose correctness depends on a system nobody here controls.
//
// ---------------------------------------------------------------------------
// WHY IT IS IN MONITORING, AND WHY IT IS NOT A SECOND `/admin/encryption`.
//
// `admin-ui/CLAUDE.md`'s filing rule is that a page goes where the QUESTION it
// answers goes, and three pages in this console touch this subject:
//
//   * **`/admin/config`**, under Server configuration, holds the `keys.*` and
//     `persistence.databasePassword*` settings. It says what this service is
//     CONFIGURED to do and reads identically on a service that started a
//     second ago.
//   * **`/admin/encryption`**, in Monitoring, says what is SEALED and with
//     what — and mentions the key-encryption key in one paragraph, because
//     the key is a fact about the sealing there rather than the subject.
//   * **This page** says what is at the other end of that one paragraph: the
//     file's mode and mtime, or the store's seal state, its version, its
//     leader, the certificate this service authenticates with and when it
//     expires, what the policy actually grants, and every version of the
//     secret the store has kept. None of that is configuration and none of it
//     is this service's; it moves while a reader watches, and it can be
//     BROKEN while every settings row is right.
//
// That is the same argument `/admin/database` is filed under Monitoring on
// against `/admin/persistence` under Server configuration, made a second time
// for a second thing somebody else is running rather than cited.
//
// ---------------------------------------------------------------------------
// THE PAGE HOLDS NO PROBE, NO SDK AND NO CREDENTIAL.
//
// `common/secrets.js` owns the providers, the client and the login; this
// module asks it for `storeReport()` and draws what comes back. That is
// `/admin/database`'s separation and it is load-bearing for the same reason
// one layer down: this file must never `require('node-vault')` or an AWS SDK,
// because the module that does is the one on the path this service STARTS on,
// and the login a probe makes must be the same login a startup read makes or
// the page is right about something nobody is running.
//
// **AND THERE IS NO CONTROL ON IT AND THERE MUST NEVER BE ONE.** No reveal, no
// rotate, no test-read button. A reveal is the end of the key. A rotate is a
// deployment act — every signing key, every certificate authority and, in
// product mode, every minted row is sealed under this key, so replacing it
// without re-sealing what it opens destroys all of it, which is why
// `openbao/seed.js` writes the key ONCE and never replaces it. And a
// test-read would be this console causing the one thing the whole design
// avoids: the key in this process's memory because somebody opened a page.
//
// ---------------------------------------------------------------------------
// A PROBE THAT FAILED IS A ROW AND NOT AN ABSENCE — AND HERE HALF OF THEM ARE
// SUPPOSED TO FAIL.
//
// The identity this service holds in a secret store is deliberately allowed to
// read two paths and do nothing else. So `sys/mounts` refused with 403 is the
// policy WORKING, and a page that hid the refusal would be hiding the evidence
// for the claim `openbao/read-only.hcl` makes. Every probe is drawn with what
// it was asking, what came back, and — where the answer is a status code this
// service can interpret — a sentence saying which of the ordinary causes it is.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, for a module that has a route (rule 1): `SecretsAdmin` takes
// the console shell, the error codes, the settings, the secret reader, the
// keystore, the mode and the logger through its constructor, and its
// `registerRoutes(app)` holds the page's one route. `SECRET_NOTES` stays a
// module-level table. The module exports `registerRoutes(app)`, which
// `common/protocol_stack.ts` calls at 18d, where requiring this module used to
// register the route (#50, R1) — requiring it registers nothing. It also
// exports `secretsView` and `secretNotes`, for `mgmt-api/admin_api.ts` and
// `tests/secret_store_report.js`.
//
// R2 (#50): the composition root builds the instance and installs it; this
// module builds none of its own, and its exports are FACADES that forward to
// that instance, for the JavaScript callers. A process without the root
// builds a default instance at load, as loading this module always did.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import admin = require('./admin');
import helpers = require('../common/helpers');
// The error codes (common/error_codes.js), a leaf: requiring it moves nothing.
import errorCodes = require('../common/error_codes');
import config = require('../common/config');
import secrets = require('../common/secrets');
import keystore = require('../common/keystore');
import mode = require('../common/mode');
import InstanceSlot = require('../common/instance_slot');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import SecretsPage = require('./web_secrets');

type Req = any;
type Res = any;
type Json = any;

interface SecretsAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  errorCodes: typeof errorCodes;
  // Not read by any method today; passed so the require above is kept (an
  // import nothing uses is dropped by the compiler).
  config: typeof config;
  secrets: typeof secrets;
  keystore: typeof keystore;
  mode: typeof mode;
}

// ---------------------------------------------------------------------------
// WHAT EACH SECRET IS FOR, IN ONE SENTENCE, AND WHAT BREAKS WITHOUT IT.
//
// **THE PAGE'S ONE PIECE OF WRITTEN-DOWN KNOWLEDGE**, and worth being honest
// about that the way `encryption_admin.ts` is about its own. `secrets.js`
// knows where a secret comes from and cannot know what it protects; a reader
// arriving at this page because something will not start needs the second
// sentence more than the first.
//
// It is keyed by the descriptor ids `secrets.js` exports, and
// `tests/secret_store_report.js` checks the two lists against each other in
// both directions — a secret with no row here is drawn with no explanation,
// and a row for a secret that no longer exists is prose about nothing.
// ---------------------------------------------------------------------------
/**
 * What the page says about each secret, keyed by the descriptor ids
 * `common/secrets.js` exports.
 */
const SECRET_NOTES = {
  'kek': {
    heading: 'The key-encryption key',
    what: 'The key that wraps every data encryption key (#391) — and so ' +
          'protects every signing key, certificate authority, issued key ' +
          'pair, authenticator secret and recovery code, and, in product ' +
          'mode on a postgres store, every row this service mints. Read ' +
          'into this process from a file or a secret store, or kept in ' +
          'a key management service (Vault Transit, AWS KMS, Cloud KMS or ' +
          'Azure Key Vault), which then wraps each data key itself and ' +
          'never hands the key over.',
    without: 'In PRODUCT mode this service does not start without it, and ' +
             'that is deliberate: generating a replacement would stop every ' +
             'token, assertion and signed document it has ever issued from ' +
             'verifying, silently, at somebody else’s relying party. In ' +
             'DEVELOPMENT mode &mdash; the default &mdash; nothing is ' +
             'persisted, so it is never asked for at all, which is why a ' +
             'perfectly broken configuration can sit here looking fine.',
    rotating: 'Rotated by RE-WRAPPING the data keys, not by re-encrypting ' +
              'the store: put the new key in <code>keys.kek*</code> and the ' +
              'old one in <code>keys.previousKek*</code>, and start. A key ' +
              'rotated inside its key management service needs neither. ' +
              'Never ' +
              'replace it without the previous one beside it: everything ' +
              'wrapped under it would be unreadable, which is why ' +
              '<code>openbao/seed.js</code> refuses to overwrite one.'
  },
  'database-password': {
    heading: 'The database password',
    what: 'The password this service dials PostgreSQL with. It is optional ' +
          'and unconfigured by default, in which case the password is where ' +
          'it has always been — in <code>persistence.databaseUrl</code>, ' +
          'in clear text.',
    without: 'Nothing, until <code>persistence.mode</code> is ' +
             '<code>postgres</code>. Then this service cannot open its ' +
             'store, and <code>persistence.start()</code> is the one place ' +
             'in this repository where a failure to open something stops the ' +
             'process.',
    rotating: 'Rotating it is ordinary: change it in the store and in ' +
              'PostgreSQL, and restart. Nothing this service has written ' +
              'depends on its value.'
  },
  // THE CELLS' TWO (#98). Neither is asked for without `cells.id`.
  'global-database-password': {
    heading: 'The global database password',
    what: 'The password this cell dials the GLOBAL tier with &mdash; the ' +
          'one writable database every cell shares for realms, settings, ' +
          'applications, policies, signing keys and the routing index, and ' +
          'its replica in this cell ' +
          '(<code>persistence.globalDatabaseUrl</code>, ' +
          '<code>persistence.globalDatabaseReadUrl</code>).',
    without: 'Nothing in single-cell mode. A cell (<code>cells.id</code> ' +
             'set) cannot open the global tier without it where the URL ' +
             'carries none, and a cell with no global tier does not start.',
    rotating: 'Ordinary: change it in the store and in PostgreSQL, then ' +
              'restart every cell. Nothing written depends on its value.'
  },
  'cell-kek': {
    heading: 'This cell\'s key-encryption key',
    what: 'The AES-256 key the rows RESIDENT in this cell are sealed under ' +
          '&mdash; a person\'s credentials, devices, sessions and everything ' +
          'else minted about the people homed here. It lives only in this ' +
          'cell\'s region, so another jurisdiction holding a copy of the ' +
          'database still cannot read them. It must not be the service ' +
          'key-encryption key, and is refused if it is.',
    without: 'In PRODUCT mode a cell does not start without it, and there ' +
             'is no fallback to the service key: that would put the ' +
             'people of every jurisdiction under one key. In development ' +
             'mode, and in single-cell mode, it is never asked for.',
    rotating: 'Written once and never replaced, for the same reason as the ' +
              'service key: this service has no re-sealing pass. A person ' +
              're-homed to another cell is sealed again under THAT cell\'s ' +
              'key as they move.'
  },
  'previous-kek': {
    heading: 'The previous key-encryption key',
    what: 'Read only while the key-encryption key is being ROTATED (#391): ' +
          'the old key, beside the new one in <code>keys.kek*</code>. A data ' +
          'encryption key that unwraps only under the old key is re-wrapped ' +
          'under the new one at start and written back. It may be a key ' +
          'read into this process or a key in a key management service.',
    without: '<code>none</code>, the default, is the ordinary state. A ' +
             'start with a new key and no previous key, over data keys ' +
             'wrapped under the old one, does not start (STS-KEYS-0091).',
    rotating: 'Set it back to <code>none</code> once every node has started ' +
              'with the new key: by then nothing is wrapped under the old ' +
              'one.'
  },
  // THE MAIL CHANNEL'S FOUR (#63). Each is optional and unconfigured by
  // default; each is read when `common/mail.ts` builds the transport that
  // needs it, never at startup except in product mode's check that the
  // configured transport can be built.
  'mail-smtp-password': {
    heading: 'The SMTP relay password',
    what: 'The SMTP AUTH password (or XOAUTH2 credential) the SMTP mail ' +
          'transport logs in to its relay with, when ' +
          '<code>mail.smtpAuth</code> asks for one.',
    without: 'The SMTP transport cannot log in. In PRODUCT mode a service ' +
             'configured to send through it does not start ' +
             '(STS-MAIL-0002); otherwise each message is a failed attempt ' +
             'and, in the end, a dead letter on Monitoring &rarr; Mail.',
    rotating: 'Change it in the store and at the relay. It is read again ' +
              'the next time the transport is built — after any Mail ' +
              'setting changes, or a restart.'
  },
  'mail-dkim-key': {
    heading: 'The DKIM private key',
    what: 'The private key of <code>mail.dkimSelector</code>, which ' +
          '<code>common/crypto.js</code> signs every message the SMTP ' +
          'transport sends with (RFC 6376 / RFC 8463).',
    without: 'Nothing, until <code>mail.dkimDomain</code> is set. Then the ' +
             'SMTP transport cannot be built, because a message that should ' +
             'carry a signature and does not fails DMARC at the receiver.',
    rotating: 'Publish the new public key under a NEW selector, point ' +
              '<code>mail.dkimSelector</code> and this secret at it, and ' +
              'withdraw the old record only after mail signed with it has ' +
              'been delivered.'
  },
  'mail-acs-connection-string': {
    heading: 'The Azure Communication Services connection string',
    what: 'The endpoint and access key the <code>acs</code> mail transport ' +
          'authenticates with, when <code>mail.acsAuth</code> is ' +
          '<code>connection-string</code>. A managed identity needs no ' +
          'secret at all and is the default.',
    without: 'The <code>acs</code> transport cannot be built with ' +
             'connection-string authentication.',
    rotating: 'Regenerate the resource\u2019s secondary key, store the ' +
              'string built from it, and regenerate the primary once the ' +
              'transport has been rebuilt.'
  },
  'mail-gmail-key': {
    heading: 'The Gmail API service account key',
    what: 'The JSON key of the service account the <code>gmail</code> ' +
          'mail transport signs its token requests with, impersonating ' +
          '<code>mail.gmailSender</code> by domain-wide delegation of the ' +
          'gmail.send scope.',
    without: 'The <code>gmail</code> transport cannot be built.',
    rotating: 'Create a second key for the service account, store it, and ' +
              'delete the first once the transport has been rebuilt.'
  }
};


/**
 * Monitoring → Secret store: where the key-encryption key and the database
 * password come from, whether this process read them, and what the store at the
 * other end is doing. No secret value appears on it.
 */
class SecretsAdmin {
  /**
   * See the module's `SECRET_NOTES`.
   */
  static readonly SECRET_NOTES = SECRET_NOTES;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the console, the secret reader, the keystore and the mode
   */
  constructor(private readonly deps: SecretsAdminDeps) {
    deps.log.debug("Entering SecretsAdmin.constructor().");
    deps.log.debug("Leaving SecretsAdmin.constructor().");
  }

  // What the composition root passes: the real modules, as the load-time
  // instance was built from before R2 (#50).
  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): SecretsAdminDeps {
    helpers.log.debug("Entering SecretsAdmin.defaultDeps().");
    helpers.log.debug("Leaving SecretsAdmin.defaultDeps().");
    return {
      log: helpers.log,
      admin: admin,
      errorCodes: errorCodes,
      config: config,
      secrets: secrets,
      keystore: keystore,
      mode: mode
    };
  }

  // ===========================================================================
  // THE MODEL. One object, rendered twice — HTML and `?format=json` — which is
  // `respond()`'s contract and why `/admin-api/secrets` cannot disagree with
  // the page (rule 7).
  //
  // **THE STORE HALF COMES FROM `secrets.js` AND THE CONTEXT HALF IS ASSEMBLED
  // HERE**, which is the one place this page adds anything: whether the mode
  // makes the key-encryption key REQUIRED, and whether this process is actually
  // persisting keys. `secrets.js` cannot answer the second: `keystore.js`
  // requires it (and `helpers.js` requires `keystore.js`), so a require back
  // would close a cycle (rule 2).
  // ===========================================================================
  /**
   * Builds the page's model, the one object behind the page, its `?format=json`
   * and `/admin-api/secrets` (rule 7): the store half from `common/secrets.js`,
   * and whether the mode requires the key-encryption key and whether this
   * process persists keys.
   *
   * @returns a promise of the model
   */
  secretsJson(): Promise<Json> {
    const { log, secrets, keystore, mode } = this.deps;
    log.debug('Entering SecretsAdmin.secretsJson().');
    log.debug("Leaving SecretsAdmin.secretsJson().");
    return secrets.storeReport().then(function (report: Json) {
      const keys = keystore.report();
      const out = Object.assign({}, report);
      out.mode = mode.current();
      out.productMode = mode.isProduct();
      // **WHETHER THE KEY IS BEING USED, WHICH IS NOT WHETHER IT IS
      // CONFIGURED.** `keys.source` decides it and product mode forces it; a
      // service that is not persisting signing keys never asks for the key at
      // all, and that is the state in which every row on this page can be
      // wrong without anything failing.
      out.persistingKeys = !!keys.persisting;
      out.keySource = keys.source;
      out.kekHeld = !!keys.kekRead;
      out.notes = SECRET_NOTES;
      log.debug('Leaving SecretsAdmin.secretsJson(). ' + out.stores.length +
                ' store(s), ' + out.failed.length + ' probe(s) unavailable.');
      return out;
    });
  }

  // ===========================================================================
  // THE PAGE.
  // ===========================================================================
  private renderSecrets(req: Req, res: Res): void {
    const { log, admin, errorCodes } = this.deps;
    const self = this;
    log.debug('Entering SecretsAdmin.renderSecrets().');
    self.secretsJson().then(function (json) {
      admin.respond(req, res, json, 'Secret store', '/admin/secrets',
                    self.body(json));
      log.debug('Leaving SecretsAdmin.renderSecrets().');
    }).catch(function (e) {
      log.error(errorCodes.tag('STS-ADMIN-0599') + 'secrets_admin: the ' +
                                                   'page threw: ' +
                (e && e.stack ? e.stack : e));
      errorCodes.mark(res, 'STS-ADMIN-0599');
      admin.respond(req, res,
                    { ok: false, error: String(e && e.message || e) },
                    'Secret store', '/admin/secrets',
                    admin.warn('This page could not be drawn: ' +
                               admin.esc(String(e && e.message || e)),
                               'It threw'));
    });
    log.debug("Leaving SecretsAdmin.renderSecrets().");
  }

  // DRAWN BY `web_secrets.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  private body(json: Json): string {
    const { log } = this.deps;
    log.debug("Entering SecretsAdmin.body().");
    const drawn = SecretsPage.render(JSON.parse(JSON.stringify(json)));
    log.debug("Leaving SecretsAdmin.body().");
    return drawn;
  }

  // For `tests/secret_store_report.js`, which checks these against the
  // descriptors `secrets.js` exports in both directions. A secret with no
  // note is drawn with no explanation; a note for a secret that no longer
  // exists is prose about nothing. Neither is an error anywhere else.
  /**
   * Answers the notes table, for the test that checks it against the secret
   * descriptors in both directions.
   *
   * @returns the notes
   */
  secretNotes(): typeof SECRET_NOTES {
    const { log } = this.deps;
    log.debug("Entering SecretsAdmin.secretNotes().");
    log.debug("Leaving SecretsAdmin.secretNotes().");
    return Object.assign({}, SECRET_NOTES);
  }

  /**
   * Registers `GET /admin/secrets`.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: { get: Function }): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SecretsAdmin.registerRoutes().");
    log.debug("Leaving SecretsAdmin.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<SecretsAdmin>(
  'admin-ui/secrets_admin',
  () => new SecretsAdmin(SecretsAdmin.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

helpers.log.info('The secret store report is at /admin/secrets: where the ' +
                 'key-encryption key and the database password come from, ' +
                 'whether this process read them, and what the store at the ' +
                 'other end is doing. No secret value appears on it and it ' +
                 'has no control.');

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * Monitoring → Secret store, `/admin/secrets`: where this service's two
 * primordial secrets come from, whether it got them, and what the store at the
 * other end is doing. It has no control.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  SecretsAdmin: SecretsAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: SecretsAdmin): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  // For `mgmt-api/admin_api.ts`. Rule 7 — one function behind the page and
  // the operation, so the two cannot report a different state of the same
  // store.
  secretsView: slot.forward('secretsJson'),
  // For `tests/secret_store_report.js` — see `SecretsAdmin.secretNotes()`.
  secretNotes: slot.forward('secretNotes')
};
