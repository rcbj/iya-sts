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
const SECRET_NOTES = {
  'kek': {
    heading: 'The key-encryption key',
    what: 'The AES-256 key every signing key, every certificate authority, ' +
          'every assertion key pair this service issues, every authenticator ' +
          'secret and every recovery code is sealed under — and, in product ' +
          'mode on a postgres store, every row this service mints.',
    without: 'In PRODUCT mode this service does not start without it, and ' +
             'that is deliberate: generating a replacement would stop every ' +
             'token, assertion and signed document it has ever issued from ' +
             'verifying, silently, at somebody else’s relying party. In ' +
             'DEVELOPMENT mode &mdash; the default &mdash; nothing is ' +
             'persisted, so it is never asked for at all, which is why a ' +
             'perfectly broken configuration can sit here looking fine.',
    rotating: 'It is written ONCE and never replaced. Everything sealed ' +
              'under it would be unreadable, and this service has no ' +
              're-sealing pass — which is why there is no rotate ' +
              'control on this page and why <code>openbao/seed.js</code> ' +
              'refuses to overwrite one.'
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

// ---------------------------------------------------------------------------
// RENDERING A VALUE THIS PAGE HAS NEVER HEARD OF.
//
// Every probe's `data` is somebody else's shape — a `sys/health` body, a
// `DescribeSecret` reply, a stat — so this is the only thing that decides how
// an arbitrary one is drawn, exactly as `database_admin.ts`'s `cell()` is for
// PostgreSQL. The cases are each a real shape that arrives here:
//
//   * **`null` is not `false` and not an empty string.** A null `expires` is
//     a secret that does not expire; a false one would be a lie about a
//     field nobody set.
//   * **A boolean is a state and not a quality**, so it is drawn in words and
//     never in green: `sealed: true` is bad and `renewable: true` is good,
//     and a renderer that coloured them would be guessing.
//   * **An ISO timestamp gets a relative reading beside it**, because
//     "2026-03-01T09:12:44Z" and "six months ago" are answers to two
//     different questions and the second is the one somebody reading a
//     monitoring page is asking.
// ---------------------------------------------------------------------------
const ISO_LIKE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;

class SecretsAdmin {
  static readonly SECRET_NOTES = SECRET_NOTES;

  constructor(private readonly deps: SecretsAdminDeps) {
    deps.log.debug("Entering SecretsAdmin.constructor().");
    deps.log.debug("Leaving SecretsAdmin.constructor().");
  }

  // What the composition root passes: the real modules, as the load-time
  // instance was built from before R2 (#50).
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

  private ago(iso: Json): string {
    const { log } = this.deps;
    log.debug("Entering SecretsAdmin.ago().");
    const then = Date.parse(iso);
    if (!then) {
      log.debug("Leaving SecretsAdmin.ago().");
      return '';
    }
    const seconds = Math.round((Date.now() - then) / 1000);
    const future = seconds < 0;
    const n = Math.abs(seconds);
    let said;
    if (n < 90) {
      said = n + 's';
    } else if (n < 5400) {
      said = Math.round(n / 60) + ' min';
    } else if (n < 172800) {
      said = Math.round(n / 3600) + ' hours';
    } else {
      said = Math.round(n / 86400) + ' days';
    }
    log.debug("Leaving SecretsAdmin.ago().");
    return future ? ('in ' + said) : (said + ' ago');
  }

  private cell(value: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering SecretsAdmin.cell().");
    if (value === null || value === undefined) {
      log.debug("Leaving SecretsAdmin.cell().");
      return '<span class="muted">&mdash;</span>';
    }
    if (typeof value === 'boolean') {
      log.debug("Leaving SecretsAdmin.cell().");
      return value ? 'yes' : 'no';
    }
    if (Array.isArray(value)) {
      if (!value.length) {
        log.debug("Leaving SecretsAdmin.cell().");
        return '<span class="muted">none</span>';
      }
      if (value.every(function (one) {
        return one === null || typeof one !== 'object';
      })) {
        log.debug("Leaving SecretsAdmin.cell().");
        return value.map(function (one) {
          return '<code>' + admin.esc(String(one)) + '</code>';
        }).join(' ');
      }
      log.debug("Leaving SecretsAdmin.cell().");
      return '<div class="wide">' + value.map(function (one) {
        return self.objectTable(one);
      }).join('') + '</div>';
    }
    if (typeof value === 'object') {
      log.debug("Leaving SecretsAdmin.cell().");
      return self.objectTable(value);
    }
    const text = String(value);
    if (ISO_LIKE.test(text)) {
      const relative = self.ago(text);
      log.debug("Leaving SecretsAdmin.cell().");
      return admin.esc(text.replace('T', ' ').replace(/\.\d+/, '')) +
             (relative ? ' <span class="muted">(' + admin.esc(relative) +
                         ')</span>' : '');
    }
    // A certificate fingerprint, a mounted path or an ARN runs past the width
    // of the page; `clipped()` is the console's own control for that and opens
    // out on a click, so nothing is lost.
    //
    // **A VALUE WITH SPACES IN IT IS PROSE AND IS GIVEN TWICE THE ROOM.** Some
    // of what a probe answers is a SENTENCE — `capabilities` ends with a
    // verdict this service composed — and clipping a sentence at the width that
    // suits a fingerprint hides the half that says what to do about it, behind
    // a control whose label is "click the value to select it all, then copy".
    // An identifier is the thing worth folding; a sentence is the thing worth
    // reading.
    const limit = text.indexOf(' ') >= 0 ? 160 : 80;
    if (text.length > limit) {
      log.debug("Leaving SecretsAdmin.cell().");
      return admin.clipped(text, limit);
    }
    log.debug("Leaving SecretsAdmin.cell().");
    return admin.esc(text);
  }

  // A nested object, drawn as its own little table. The recursion is what lets
  // this page draw a `replication` block or a `rotationRules` block without
  // naming a single member of either — which is the same reason
  // `/admin/database` asks for every column rather than the ones it knows.
  private objectTable(value: Json): string {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SecretsAdmin.objectTable().");
    if (value === null || typeof value !== 'object') {
      log.debug("Leaving SecretsAdmin.objectTable().");
      return self.cell(value);
    }
    const keys = Object.keys(value);
    if (!keys.length) {
      log.debug("Leaving SecretsAdmin.objectTable().");
      return '<span class="muted">empty</span>';
    }
    log.debug("Leaving SecretsAdmin.objectTable().");
    return '<table class="grid"><tbody>' +
      keys.map(function (key) {
        return '<tr><th>' + self.label(key) + '</th><td>' +
               self.cell(value[key]) + '</td></tr>';
      }).join('') +
      '</tbody></table>';
  }

  // A member name as a person reads it. The raw name goes in a `title`, because
  // `cas_required` is what somebody searching OpenBao's documentation will type
  // and a page that only showed "cas required" would have cost them the string
  // they need.
  private label(name: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering SecretsAdmin.label().");
    const text = String(name)
      .replace(/_/g, ' ')
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2');
    log.debug("Leaving SecretsAdmin.label().");
    return '<span title="' + admin.esc(String(name)) + '">' +
           admin.esc(text) + '</span>';
  }

  // ---------------------------------------------------------------------------
  // WHY A PROBE DID NOT ANSWER.
  //
  // `database_admin.ts` tells 42P01 from 42501 because "an older server" and
  // "this role may not" are completely different things to do about. The same
  // is true here and the codes are HTTP ones: **403 is the policy working**,
  // which is the single most misread row on this page, and a missing file is
  // the ordinary state of a development-mode service that has never needed a
  // key.
  // ---------------------------------------------------------------------------
  private whyNot(probe: Json): string {
    const { log } = this.deps;
    log.debug("Entering SecretsAdmin.whyNot().");
    if (probe.status === 403) {
      log.debug("Leaving SecretsAdmin.whyNot().");
      return 'The store refused it. For the paths this service is NOT ' +
             'supposed ' +
             'to reach that is the read-only policy <strong>working</strong> ' +
             'and not a fault — the identity it holds is bound to two read ' +
             'paths and nothing else.';
    }
    if (probe.status === 404) {
      log.debug("Leaving SecretsAdmin.whyNot().");
      return 'No such path in the store. For a KV version 2 secret that ' +
             'usually means the engine is mounted somewhere else, or the ' +
             'secret has not been written yet.';
    }
    if (probe.status === 400) {
      log.debug("Leaving SecretsAdmin.whyNot().");
      return 'The store rejected the request itself. A KV version 1 engine ' +
             'answers this to a version 2 path, which is the usual cause.';
    }
    if (/ENOENT/.test(probe.error || '')) {
      log.debug("Leaving SecretsAdmin.whyNot().");
      return 'There is no such file. On a DEVELOPMENT-mode service that is ' +
             'ordinary: nothing is persisted, so the key-encryption key is ' +
             'never read and the file it names need not exist. In product ' +
             'mode this is a service that would not start.';
    }
    if (/EACCES/.test(probe.error || '')) {
      log.debug("Leaving SecretsAdmin.whyNot().");
      return 'The file is there and this process may not read it. Check the ' +
             'ownership of the mount rather than the path.';
    }
    if (/did not answer within/.test(probe.error || '')) {
      log.debug("Leaving SecretsAdmin.whyNot().");
      return 'The store did not answer inside ' +
             '<code>keys.storeProbeTimeoutMs</code>. That bounds one probe ' +
             'and not the page, so the others below were still asked.';
    }
    if (/Cannot find module|needs the /.test(probe.error || '')) {
      log.debug("Leaving SecretsAdmin.whyNot().");
      return 'The SDK for this provider is not installed. It is deliberately ' +
             'not a dependency of this service — it is a mock first, and ' +
             'five cloud SDKs nobody uses would be carried by every install ' +
             '— so the message above names the package to install.';
    }
    log.debug("Leaving SecretsAdmin.whyNot().");
    return '';
  }

  private probeRows(probes: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering SecretsAdmin.probeRows().");
    log.debug("Leaving SecretsAdmin.probeRows().");
    return probes.map(function (probe) {
      return '<h4>' + admin.esc(probe.id) +
        ' <span class="muted">' + (probe.ok ? '' : 'unavailable, ') +
        probe.tookMs + 'ms</span></h4>' +
        '<p class="muted">' + admin.esc(probe.what) + '</p>' +
        (probe.ok
          ? self.objectTable(probe.data)
          : admin.warn('<p><code>' +
                       admin.esc(String(probe.status || '') +
                                 (probe.status ? ' ' : '')) +
                       admin.esc(probe.error) + '</code></p>' +
                       (self.whyNot(probe)
                         ? '<p>' + self.whyNot(probe) + '</p>' : ''),
                       'It did not answer'));
    }).join('');
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

  private body(json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug('Entering SecretsAdmin.body().');

    const configured = json.secrets.filter(function (one) {
      return one.configured;
    });
    const read = json.secrets.filter(function (one) {
      return one.lastRead && one.lastRead.ok;
    });
    const tiles = '<div class="tiles">' +
      admin.tile(String(configured.length) + '/' + String(json.secrets.length),
                 'secrets from a store') +
      admin.tile(String(json.stores.length), 'stores') +
      admin.tile(String(read.length), 'read this start') +
      admin.tile(json.productMode ? 'product' : 'development', 'mode') +
      admin.tile(json.persistingKeys ? 'durable' : 'ephemeral',
                 'signing keys') +
      admin.tile(String(json.failed.length), 'probes unavailable') +
      '</div>';

    const what = admin.note(
      '<p>This page is <strong>where this service’s two primordial ' +
      'secrets come from, whether it actually got them, and what the store ' +
      'at the other end is doing</strong>. It reads them and never writes ' +
      'one: the key-encryption key is generated by nobody here, and neither ' +
      'is the database password.</p><p><strong>Three pages touch this ' +
      'subject and they answer three questions.</strong> <a ' +
      'href="/admin/config">Configuration</a>, under Server configuration, ' +
      'holds the <code>keys.*</code> settings and says what this service is ' +
      '<em>set up</em> to do. <a href="/admin/encryption">Encryption</a> ' +
      'says what is <em>sealed</em> and with what. This one says what is at ' +
      'the other end of that: a file’s mode and mtime, or a store’s seal ' +
      'state, its version, its leader, the certificate this service proves ' +
      'itself with and when that expires, what its policy actually grants, ' +
      'and every version of the secret the store has kept. <strong>All of ' +
      'that can be broken while every settings row is ' +
      'right.</strong></p><p><strong>No secret value appears here and there ' +
      'is no control on this page.</strong> No reveal, no rotate, no ' +
      'test-read. A reveal is the end of the key. A rotate would destroy ' +
      'everything sealed under it, because this service has no re-sealing ' +
      'pass — which is exactly why the key is written once. And a test-read ' +
      'would be this console causing the one thing the whole design avoids: ' +
      'the key in this process’s memory because somebody opened a page. ' +
      'Every probe below reads METADATA — a stat, a <code>sys</code> ' +
      'endpoint, a version history, a <code>DescribeSecret</code> — and not ' +
      'one of them fetches a stored value.</p>',
      'What this page is, and the three controls it deliberately has not got');

    const refusals = admin.warn(
      '<p><strong>Half the probes on this page are supposed to fail, and a ' +
      '403 is usually the good news.</strong> The identity this service ' +
      'holds in a secret store is bound to two read paths and nothing else — ' +
      'it cannot write its own key, cannot rotate it out from under the data ' +
      'sealed with it, and cannot plant one of its own — so a refusal ' +
      'against anything else is the policy working. A page that hid those ' +
      'refusals would be hiding the evidence for the claim.</p><p>Each probe ' +
      'is run, timed and caught <strong>separately</strong>, bounded by ' +
      '<code>keys.storeProbeTimeoutMs</code> at ' +
      admin.esc(String(json.timeoutMs)) + 'ms, and they run in parallel: a ' +
      'store that is entirely unreachable costs that bound once rather than ' +
      'once per question asked of it.</p>',
      'Why a failed probe here is not the same as a failed probe anywhere ' +
      'else');

    // **THE STATE THAT MAKES EVERY ROW BELOW MEANINGLESS, SAID FIRST.** A
    // development-mode service on a memory store never reads the
    // key-encryption key, so the configuration can be wrong in every particular
    // and nothing will say so until the day somebody sets `global.mode` to
    // product. That is the one thing a reader of this page can most easily come
    // away not knowing.
    const unused = (!json.persistingKeys && !json.productMode)
      ? admin.warn(
          '<p>This service is in <strong>development</strong> mode and is ' +
          'not persisting signing keys, so <strong>it has never asked for ' +
          'the key-encryption key</strong>. Everything below about that ' +
          'secret describes what <em>would</em> happen, and the ordinary ' +
          '<em>unavailable</em> rows on this page are this service correctly ' +
          'not needing something.</p><p>Signing keys are generated on every ' +
          'start and held in memory here, which is what makes this service ' +
          'disposable. <code>global.mode=product</code>, or ' +
          '<code>keys.source=persisted</code>, is what makes the key real — ' +
          'and in product mode a key that cannot be read is a service that ' +
          'does not start.</p>',
          'Nothing here is load-bearing on this service, yet')
      : '';

    log.debug("Leaving SecretsAdmin.body().");
    return tiles + what + refusals + unused +
           json.secrets.map(function (row) {
             return self.secretBlock(row, json);
           }).join('') +
           self.storesBlock(json);
  }

  // ---------------------------------------------------------------------------
  // ONE SECRET: what it is, where it is configured to come from, whether this
  // process has actually read it, and the probes that are about the SECRET
  // rather than about the store holding it.
  // ---------------------------------------------------------------------------
  private secretBlock(row: Json, json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug('Entering SecretsAdmin.secretBlock(). secret=' + row.secret);
    const notes = json.notes[row.secret] || { heading: row.secret, what: '',
                                              without: '', rotating: '' };
    if (!row.configured) {
      log.debug('Leaving SecretsAdmin.secretBlock(). Not configured.');
      return '<h3>' + admin.esc(notes.heading) + '</h3>' +
        admin.note(
          '<p>' + notes.what + '</p>' +
          '<p><strong>No provider is configured</strong>, so this service ' +
          'does not read it from a store. <code>' +
          admin.esc(row.settings.provider) + '</code> selects one.</p>' +
          '<p>' + notes.without + '</p>',
          'Not read from a secret store');
    }

    const last = row.lastRead;
    const read = last
      ? (last.ok
          ? admin.note('<p>Read <strong>successfully</strong> at ' +
                       admin.esc(String(last.at).replace('T', ' ')
                         .replace(/\.\d+Z$/, 'Z')) +
                       ' <span class="muted">(' + admin.esc(self.ago(last.at)) +
                       ')</span>, in ' + admin.esc(String(last.tookMs)) +
                       'ms, from <code>' + admin.esc(last.provider) +
                       '</code>.</p><p class="muted">This process holds the ' +
                       'value in memory and nothing wrote it to disk. It is ' +
                       'not on this page, in the JSON behind it, or in any ' +
                       'log line this service has ever emitted.</p>',
                       'This process has read it')
          : admin.warn('<p>The last read <strong>failed</strong> at ' +
                       admin.esc(String(last.at).replace('T', ' ')
                         .replace(/\.\d+Z$/, 'Z')) + ': <code>' +
                       admin.esc(last.error) + '</code></p>',
                       'The last read of this secret failed'))
      : admin.note('<p><strong>This process has not read it.</strong> ' +
                   'That is ' +
                   'not by itself a fault: a secret is read when something ' +
                   'needs it, and in development mode on a memory store ' +
                   'nothing does. It does mean nothing below has been ' +
                   'proved by use.</p>',
                   'Not read in this process');

    const where = '<table class="grid"><tbody>' +
      '<tr><th>Provider</th><td><code>' + admin.esc(row.provider) +
        '</code> &mdash; ' + admin.esc(row.label) + '</td>' +
        '<td class="why">Set by <code>' + admin.esc(row.settings.provider) +
        '</code>.</td></tr>' +
      // **`field` AND `shared` ARE SKIPPED HERE AND NOT BECAUSE THEY ARE
      // UNINTERESTING**: both have a row of their own below with the sentence
      // that makes them mean something, and a provider's `describe()` carries
      // them too. Drawn from both places they appeared twice in one table, once
      // with an explanation and once without.
      Object.keys(row.where || {}).filter(function (key) {
        return ['field', 'shared'].indexOf(key) < 0 &&
               row.where[key] !== null && row.where[key] !== undefined;
      }).map(function (key) {
        return '<tr><th>' + self.label(key) + '</th><td>' +
               self.cell(row.where[key]) + '</td><td class="why"></td></tr>';
      }).join('') +
      (row.field
        ? '<tr><th>Field</th><td><code>' + admin.esc(row.field) +
          '</code></td>' +
          '<td class="why">Which member is taken when what is stored is a ' +
          'JSON object. A stored value that is not JSON is taken whole. Set ' +
          'by <code>' + admin.esc(row.settings.field) + '</code>.</td></tr>'
        : '') +
      '<tr><th>Location of its own</th><td>' + (row.shared ? 'no' : 'yes') +
        '</td><td class="why">' +
        (row.shared
          ? 'This secret names no location, so it is read from ' +
            '<strong>wherever the key-encryption key is</strong> and the ' +
            'field above is what tells the two apart inside one value. That ' +
            'is the arrangement a deployment with one mounted file or one ' +
            'cloud secret is already in. If what is there turns out NOT to ' +
            'be a JSON object, reading this secret is REFUSED rather than ' +
            'handing that key to a database.'
          : 'It names its own location in <code>' +
            admin.esc(row.settings.location) + '</code>.') +
        '</td></tr>' +
      '</tbody></table>';

    log.debug('Leaving SecretsAdmin.secretBlock().');
    return '<h3>' + admin.esc(notes.heading) + '</h3>' +
      admin.note('<p>' + notes.what + '</p>' +
                 '<p><strong>Without it:</strong> ' + notes.without + '</p>' +
                 '<p><strong>Rotating it:</strong> ' + notes.rotating + '</p>',
                 'What it is, and what happens without it') +
      where + read +
      (row.probes.length
        ? '<h4 class="muted">What the store says about this secret</h4>' +
          self.probeRows(row.probes)
        : '');
  }

  // ---------------------------------------------------------------------------
  // THE STORES. One block per store rather than per secret, because two secrets
  // in one Vault must not make this page ask it twice whether it is sealed —
  // and because a reader looking at *is the store up* is not asking about
  // either secret.
  // ---------------------------------------------------------------------------
  private storesBlock(json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering SecretsAdmin.storesBlock().");
    if (!json.stores.length) {
      log.debug("Leaving SecretsAdmin.storesBlock().");
      return '<h3>The stores</h3>' +
        admin.note('Neither secret is read from a store, so there is none to ' +
                   'report on.');
    }
    log.debug("Leaving SecretsAdmin.storesBlock().");
    return '<h3>The stores</h3>' +
      admin.note('<p>One block per store and not per secret: two secrets ' +
                 'kept ' +
                 'in one place share everything below, and asking the same ' +
                 'store twice whether it is sealed would be this page ' +
                 'inventing a disagreement it then has to draw.</p>') +
      json.stores.map(function (store) {
        return '<h4>' + admin.esc(store.label) + ' <span class="muted">' +
          admin.esc(store.where) + '</span></h4>' +
          '<p class="muted">Holds: ' +
          store.secrets.map(function (one) {
            return '<code>' + admin.esc(one) + '</code>';
          }).join(', ') + '</p>' +
          (store.probes.length
            ? self.probeRows(store.probes)
            : admin.note('This provider publishes nothing about the store ' +
                         'itself beyond what is already on the secret above ' +
                         '&mdash; a cloud secret manager is an endpoint and ' +
                         'an access policy, and everything it will say is ' +
                         'said about the secret.'));
      }).join('');
  }

  // For `tests/secret_store_report.js`, which checks these against the
  // descriptors `secrets.js` exports in both directions. A secret with no
  // note is drawn with no explanation; a note for a secret that no longer
  // exists is prose about nothing. Neither is an error anywhere else.
  secretNotes(): typeof SECRET_NOTES {
    const { log } = this.deps;
    log.debug("Entering SecretsAdmin.secretNotes().");
    log.debug("Leaving SecretsAdmin.secretNotes().");
    return Object.assign({}, SECRET_NOTES);
  }

  registerRoutes(app: { get: Function }): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SecretsAdmin.registerRoutes().");
    app.get('/admin/secrets', function (req, res) {
      log.debug('Entering GET /admin/secrets.');
      self.renderSecrets(req, res);
      log.debug('Leaving GET /admin/secrets.');
    });
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

export = {
  registerRoutes: slot.forward('registerRoutes'),
  SecretsAdmin: SecretsAdmin,
  installInstance: (instance: SecretsAdmin): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  // For `mgmt-api/admin_api.ts`. Rule 7 — one function behind the page and
  // the operation, so the two cannot report a different state of the same
  // store.
  secretsView: slot.forward('secretsJson'),
  // For `tests/secret_store_report.js` — see `SecretsAdmin.secretNotes()`.
  secretNotes: slot.forward('secretNotes')
};
