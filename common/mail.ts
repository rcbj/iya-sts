'use strict';
//
// File: mail.ts
//
// ===========================================================================
// THE MAIL CHANNEL (#63, 2026-09-22): the one way this service tells a person
// something at an address, and the one outbound connection it makes to a
// mail relay or a provider.
//
// Until this file the service had NO mail channel, and said so in a dozen
// places — a reset link and an activation link were shown to an
// administrator to pass on by hand, and a person could not start recovery
// themselves. This is the send side: one interface, `send()`, a PERSISTED
// OUTBOX, and five transports (`common/mail_transports.ts`, which nothing
// else requires). What is SENT — reset links, verification links, security
// notices — is `common/mail_uses.ts`, which calls this and nothing below it.
//
// A LIBRARY (rule 3): it registers no route. It requires `common/`
// libraries and `cluster/cluster_claims.js`, none of which requires it back;
// the directory reaches it through a SLOT (`setDirectory()`, filled by
// `ldap/ldap_server.js`), for the portal's reason — this module is loaded long
// before the directory, and a require the other way would load the JavaScript
// directory module and its routes out of order (rule 1, rule 3e).
//
// ---------------------------------------------------------------------------
// EIGHT THINGS ARE WORTH KNOWING BEFORE READING FURTHER.
//
// **1. ONE TRANSPORT FOR THE SERVICE, WHICH A REALM MAY OVERRIDE** (rcbj's
// decision on #63). Every `mail.*` setting is an ordinary realm-overridable
// row, read in the ambient realm, so a realm that sets `mail.transport` sends
// through its own and every other realm through the default realm's. A built
// transport is cached per realm by a FINGERPRINT of the settings it was built
// from, so a changed setting rebuilds it on the next send — and a secret is
// read again then.
//
// **2. `default` IS THE MODE'S, AND CAPTURE NEVER REACHES PRODUCT** (rcbj:
// capture unless configured). Development's `default` is the capture
// transport, which keeps the message and its body on Monitoring → Mail and
// sends nothing; a configured `smtp`, `ses`, `acs` or `gmail` sends in
// development too. Product's `default` is `off`. `capture` is refused on
// write and at start in product (`common/mode.js`, `capturesMail()`).
// Product also refuses to START when a configured transport cannot be built
// (`startupProblem()`, STS-MAIL-0002), because a service that cannot send the
// reset link it just promised is worse than one that says so at boot.
//
// **3. EVERY MESSAGE IS A ROW, AND THE ROW IS THE RETRY** — back-channel
// logout's arrangement (`oauth-oidc/backchannel_logout.ts`, rule 3aq), and
// for its reason. `mail.outbox`, per realm, persisted and shared exactly
// where this service persists what it mints, sealed at rest under the
// key-encryption key there. A scheduler job, `mail.deliver` (a CLUSTER job,
// #49), sweeps what is due on the leader; the process that queued a message
// attempts it at once, so the job is the safety net and not the delay. Retries
// back off, a final failure is a DEAD LETTER an administrator can retry, and
// nothing is pending for ever. **There is no timer of this module's own**
// (`tests/no_periodic_timers.js`): a retry waits for the sweep.
//
// **4. EXACTLY ONE PROCESS SENDS EACH ATTEMPT.** A claim with a lease on
// (realm, message, generation, attempt), whose claim time is the row's fence
// — back-channel logout's point 4 unchanged. What cannot be excluded is that
// two processes both handed the message to the relay when one died between
// the hand-over and recording it; the Message-ID is the same in both, which
// is what a receiver deduplicates on.
//
// **5. A RECIPIENT IS A DIRECTORY ENTRY, NEVER AN ADDRESS FROM A REQUEST.**
// `send()` takes a USERNAME, and the address is the `mail` attribute of that
// person's entry in the ambient realm; administrators are the realm's Admin
// Write roster. There is no parameter anywhere that takes an address.
//
// **6. A LINK IS BUILT ON THIS SERVICE'S PINNED ORIGIN, NEVER THE REQUEST'S.**
// A caller hands a PATH; `linkBase()` puts `global.publicBaseUrl` (and the
// realm's prefix) in front of it. With that setting empty, development builds
// the listener's configured address and product refuses to mail a link at
// all (STS-MAIL-0015) — `baseUrlOf(req)` reads the Host header, and a Host
// header choosing where a password reset link points is the classic
// poisoned-reset attack.
//
// **7. A CEILING PER RECIPIENT AND PER CATEGORY, AND ONE MESSAGE PER ACT.**
// Counted from the shared outbox, so the ceiling is the cluster's: a storm of
// risk events or an attacker pressing "forgot password" cannot turn this
// service into a mail cannon. A message that names what it is about (a
// `dedupKey`) is queued once per `mail.dedupWindowS`, however many doors
// reported the same act. A person may decline the `notification` category;
// `security` and `account` cannot be declined (`common/mail_templates.ts`).
//
// **8. THE AUDIT ROW AND THE LOG LINE NAME THE RECIPIENT, NEVER THE BODY.** A
// sent message keeps no body either: only who, which template, when and what
// became of it. A dead letter keeps its body for the retry, a captured one
// because the body is all it is for, and neither leaves this module except
// to the monitor page's detail view of a captured message in development.
// ===========================================================================

import nodeCrypto = require('crypto');
import os = require('os');
import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import config = require('./config');
import realms = require('./realms');
import mode = require('./mode');
import errorCodes = require('./error_codes');
import audit = require('./audit');
import cacheRegistry = require('./cache_registry');
import clusterClaims = require('../cluster/cluster_claims');
import MailTemplates = require('./mail_templates');
import mailTransports = require('./mail_transports');

type Json = any;

// The states a message passes through: `pending` until it is `sent`,
// `captured` (the capture transport's final state) or `dead` (a final
// failure, until an administrator retries it).
const STATES = ['pending', 'sent', 'captured', 'dead'];

// The transports `mail.transport` may name besides `default` and `off`.
const TRANSPORTS = ['capture', 'smtp', 'ses', 'acs', 'gmail'];

// The claim scope an attempt is spent under.
const ATTEMPT_SCOPE = 'mail.attempt';

// The scheduler job (#49).
const DELIVER_JOB = 'mail.deliver';

// The settings a transport is built from — its fingerprint (header point 1).
const TRANSPORT_KEYS = [
  'mail.transport', 'mail.from', 'mail.smtpPreset', 'mail.smtpHost',
  'mail.smtpPort', 'mail.smtpTls', 'mail.smtpCaFile', 'mail.smtpServerName',
  'mail.smtpAuth', 'mail.smtpUser', 'mail.smtpPasswordProvider',
  'mail.smtpPasswordRef', 'mail.smtpPasswordField',
  'mail.smtpClientCertFile', 'mail.smtpClientKeyFile', 'mail.dkimDomain',
  'mail.dkimSelector', 'mail.dkimAlgorithm', 'mail.dkimKeyProvider',
  'mail.dkimKeyRef', 'mail.dkimKeyField', 'mail.sesRegion',
  'mail.sesConfigurationSet', 'mail.acsEndpoint', 'mail.acsAuth',
  'mail.acsConnectionStringProvider', 'mail.acsConnectionStringRef',
  'mail.acsConnectionStringField', 'mail.gmailSender',
  'mail.gmailKeyProvider', 'mail.gmailKeyRef', 'mail.gmailKeyField',
  'mail.timeoutMs'
];

// The known relays `mail.smtpPreset` names.
const PRESETS = {
  'google-workspace-relay': function (): Json {
    return { host: 'smtp-relay.gmail.com', port: 587, tls: 'starttls' };
  },
  'aws-ses-smtp': function (region: string): Json {
    return { host: 'email-smtp.' + (region || 'us-east-1') +
                   '.amazonaws.com', port: 587, tls: 'starttls' };
  }
};

interface Message {
  id: string;
  realm: string;
  username: string;
  to: string;
  category: string;
  template: string;
  lang: string;
  dedup: string;
  subject: string;
  text: string;
  html: string;
  from: string;
  fromName: string;
  messageId: string;
  via: string;
  actor: string;
  state: string;
  transport: string;
  generation: number;
  attempts: number;
  inFlight: number;
  fenceAt: number;
  holder: string;
  errorCode: string;
  why: string;
  providerId: string;
  queuedAt: number;
  nextAttemptAt: number;
  lastAttemptAt: number;
  finishedAt: number;
  updatedAt: number;
}

interface SendRequest {
  // A person in the ambient realm, by username…
  username?: string;
  // …or the realm's Admin Write roster, each member with an address.
  toAdministrators?: boolean;
  template: string;
  values?: Json;
  // name → a PATH on this service (header point 6).
  links?: Json;
  // What the message is about, for suppression (header point 7).
  dedupKey?: string;
  via?: string;
  actor?: string;
}

interface Directory {
  personEntry: (username: string) => Json;
  personByMail: (address: string) => string;
  writeMailFlag: (username: string, name: string, value: unknown) => boolean;
  personExists?: (username: string) => boolean;
}

interface MailDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  mode: typeof mode;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  claims: typeof clusterClaims;
  transports: Json;
  now: () => number;
  // The realm's Admin Write roster: usernames. Lazy, because the roster is
  // the console's (admin-ui/admin_rbac.ts) and this module is below it.
  administrators: () => string[];
  scheduler: () => Json;
}

// WHICH OF TWO COPIES OF A ROW IS NEWER — back-channel logout's total order:
// (generation, the attempt the row is at, its fence, final over pending, the
// last update). Ties keep the STORED copy.
function rankOf(row: Json): number[] {
  helpers.log.debug("Entering rankOf().");
  const r = row || {};
  const at = Math.max(Number(r.attempts) || 0, Number(r.inFlight) || 0);
  helpers.log.debug("Leaving rankOf().");
  return [Number(r.generation) || 0, at, Number(r.fenceAt) || 0,
          r.state === 'pending' ? 0 : 1, Number(r.updatedAt) || 0];
}

function compareRows(a: Json, b: Json): number {
  helpers.log.debug("Entering compareRows().");
  const x = rankOf(a);
  const y = rankOf(b);
  for (let i = 0; i < x.length; i++) {
    if (x[i] !== y[i]) {
      helpers.log.debug("Leaving compareRows().");
      return x[i] < y[i] ? -1 : 1;
    }
  }
  helpers.log.debug("Leaving compareRows(). Equal.");
  return 0;
}

// THE OUTBOX — per realm at its declaration, persisted, tombstoned (a random
// id is never legitimately written again once retention removed it) and
// merged by rank (header points 3 and 4).
const outbox = realms.map({
  persist: 'mail.outbox',
  tombstone: true,
  mergeRow: function (mine: Json, theirs: Json): Json {
    helpers.log.debug("Entering mergeRow().");
    helpers.log.debug("Leaving mergeRow().");
    return compareRows(mine, theirs) > 0 ? mine : theirs;
  }
});

// A REALM'S OWN WORDING of a message, keyed `<template>:<language>` — the
// subject, the text part and the HTML part, checked when saved.
const templates = realms.map({ persist: 'mail.templates' });

// WHAT A PERSON DECLINED, keyed by username: `{ declined: [category], at }`.
// Only an optional category may be in it.
const preferences = realms.map({ persist: 'mail.preferences' });

// Described to `/admin/caches` (rule 3ap) as the durable queue it is.
cacheRegistry.register({
  name: 'mail.outbox',
  title: 'Mail outbox',
  description: 'One row per message this service sends: its recipient, its ' +
    'state, its attempts, when it is next due — and its body while it is ' +
    'pending, dead or captured, never once it is sent. The durable queue ' +
    'the mail.deliver job sweeps.',
  owner: 'common/mail.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  hitMeaning: 'a message suppressed as a duplicate of one already queued ' +
    'for the same act in mail.dedupWindowS',
  settings: ['mail.retentionS', 'mail.maxRows', 'mail.deliverS'],
  maxEntries: function (): number {
    return Number(config.value('mail.maxRows'));
  },
  bound: 'Enforced: mail.maxRows per realm, the oldest FINISHED message ' +
    'dropped first; a pending one is never dropped to make room.',
  lifetime: function (): string {
    return 'Until mail.retentionS after it was queued, the oldest finished ' +
      'first past mail.maxRows per realm.';
  },
  entries: function (): unknown[] {
    const keepS = Number(config.value('mail.retentionS'));
    return cacheRegistry.realmMapRows(realms, outbox,
      function (row: Json, key: unknown): object {
        return { key: String(key) + ' (' + String((row && row.state) || '?') +
                      ')',
                 validUntil: Number(row && row.queuedAt) + keepS * 1000,
                 basis: 'time' };
      });
  }
});

// This process's name on a row it is sending, for the console.
const HOLDER = os.hostname() + ':' + process.pid;

// THE DIRECTORY (header point 5), filled by `ldap/ldap_server.js`.
let directory: Directory | null = null;

// Per realm, what this process did since its last summary line.
const tallies = new Map<string, Json>();
const lastSummaryAt = new Map<string, number>();

// Attempts in flight in this process.
let inFlightHere = 0;

class Mail {
  static readonly STATES = STATES;
  static readonly TRANSPORTS = TRANSPORTS;
  static readonly ATTEMPT_SCOPE = ATTEMPT_SCOPE;
  static readonly DELIVER_JOB = DELIVER_JOB;

  // BUILT TRANSPORTS, per realm, by fingerprint — a socket pool is held by
  // one process and shared by none (root CLAUDE.md, "One front process"), so
  // this is this INSTANCE's and NOT a realm store: every process builds its
  // own from the same settings, and an instance built with other transports
  // (a test's) never answers with another's.
  private readonly built = new Map<string, Json>();

  // The last build failure per realm, for the console.
  private readonly buildProblems = new Map<string, Json>();

  constructor(private readonly deps: MailDeps) {
    deps.log.debug("Entering Mail.constructor().");
    deps.log.debug("Leaving Mail.constructor().");
  }

  static defaultDeps(): MailDeps {
    helpers.log.debug("Entering Mail.defaultDeps().");
    helpers.log.debug("Leaving Mail.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      realms: realms,
      mode: mode,
      errorCodes: errorCodes,
      audit: audit,
      claims: clusterClaims,
      transports: new mailTransports.MailTransports(
        mailTransports.MailTransports.defaultDeps()),
      now: function (): number {
        return Date.now();
      },
      administrators: function (): string[] {
        const rbac = require('../admin-ui/admin_rbac');
        const roster = rbac.rosterFor('write');
        return ((roster && roster.members) || []).filter(function (m: Json) {
          return m && m.present && m.username;
        }).map(function (m: Json) {
          return String(m.username);
        });
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      }
    };
  }

  private setting(key: string): any {
    const { log, config } = this.deps;
    log.debug("Entering Mail.setting(). " + key);
    log.debug("Leaving Mail.setting().");
    return config.value(key);
  }

  // -------------------------------------------------------------------------
  // WHICH TRANSPORT, in the ambient realm (header points 1 and 2):
  // `capture`, `smtp`, `ses`, `acs`, `gmail` or `off`.
  // -------------------------------------------------------------------------
  effectiveTransport(): string {
    const { log, mode } = this.deps;
    log.debug("Entering Mail.effectiveTransport().");
    const named = String(this.setting('mail.transport') || 'default');
    let out = named;
    if (named === 'default') {
      out = mode.capturesMail() ? 'capture' : 'off';
    }
    log.debug("Leaving Mail.effectiveTransport(). " + out);
    return out;
  }

  // Is there a transport to send through, in the ambient realm? A caller
  // offering something that mails (a "forgot password" link) asks this.
  available(): boolean {
    const { log, mode } = this.deps;
    log.debug("Entering Mail.available().");
    const t = this.effectiveTransport();
    const ok = t !== 'off' && !(t === 'capture' && !mode.capturesMail());
    log.debug("Leaving Mail.available(). " + ok);
    return ok;
  }

  // The settings a transport is built from, resolved: presets applied, the
  // From address defaulted.
  transportConfig(): Json {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering Mail.transportConfig().");
    const cfg: Json = { setting: String(this.setting('mail.transport')) };
    TRANSPORT_KEYS.forEach(function (key) {
      cfg[key.replace(/^mail\./, '')] = self.setting(key);
    });
    cfg.transport = this.effectiveTransport();
    cfg.from = this.fromAddress();
    const preset = PRESETS[String(cfg.smtpPreset || 'custom')];
    if (preset && !cfg.smtpHost) {
      const p = preset(String(cfg.sesRegion || ''));
      cfg.smtpHost = p.host;
      cfg.smtpPort = p.port;
      cfg.smtpTls = p.tls;
    }
    cfg.realm = realms.currentId();
    log.debug("Leaving Mail.transportConfig().");
    return cfg;
  }

  fingerprint(cfg: Json): string {
    const { log } = this.deps;
    log.debug("Entering Mail.fingerprint().");
    const digest = nodeCrypto.createHash('sha256')
      .update(JSON.stringify(TRANSPORT_KEYS.map(function (key) {
        return cfg[key.replace(/^mail\./, '')];
      }).concat([cfg.transport, cfg.smtpHost, cfg.smtpPort])))
      .digest('base64url');
    log.debug("Leaving Mail.fingerprint().");
    return digest;
  }

  // -------------------------------------------------------------------------
  // THE TRANSPORT FOR THE AMBIENT REALM, built (and its secrets read) the
  // first time and again whenever its settings change. Rejects with a coded
  // error; the failure is kept for the console.
  // -------------------------------------------------------------------------
  async transport(): Promise<Json> {
    const { log, realms, mode, transports } = this.deps;
    log.debug("Entering Mail.transport().");
    const cfg = this.transportConfig();
    const realmId = realms.currentId();
    if (cfg.transport === 'capture' && !mode.capturesMail()) {
      log.debug("Leaving Mail.transport(). Capture in product.");
      throw mailTransports.sendError('mail.transport is "capture", which ' +
        'product mode refuses: a captured message puts its body on the ' +
        'console', 'STS-MAIL-0003', false);
    }
    const print = this.fingerprint(cfg);
    const held = this.built.get(realmId);
    if (held && held.print === print) {
      log.debug("Leaving Mail.transport(). Cached.");
      return held.transport;
    }
    try {
      const made = await transports.build(cfg);
      if (held && held.transport && typeof held.transport.close ===
          'function') {
        held.transport.close();
      }
      this.built.set(realmId, { print: print, transport: made });
      this.buildProblems.delete(realmId);
      log.debug("Leaving Mail.transport(). Built " + made.name + ".");
      return made;
    } catch (e) {
      log.debug("Caught in Mail.transport(): " + ((e && e.message) || e));
      this.buildProblems.set(realmId, { at: Date.now(),
        code: errorCodes.codeOf(e) || 'STS-MAIL-0004',
        why: String((e && e.message) || e) });
      if (!errorCodes.codeOf(e)) {
        errorCodes.mark(e, 'STS-MAIL-0004');
      }
      log.debug("Leaving Mail.transport(). Not built.");
      throw e;
    }
  }

  // The last reason the ambient realm's transport could not be built, or
  // null.
  buildProblem(): Json {
    const { log, realms } = this.deps;
    log.debug("Entering Mail.buildProblem().");
    log.debug("Leaving Mail.buildProblem().");
    return this.buildProblems.get(realms.currentId()) || null;
  }

  // The From address: the setting, or `no-reply@` the realm's DNS domain.
  fromAddress(): string {
    const { log, realms } = this.deps;
    log.debug("Entering Mail.fromAddress().");
    const set = String(this.setting('mail.from') || '').trim();
    const out = set || 'no-reply@' +
      String(realms.domainOf(realms.current()) || 'localhost');
    log.debug("Leaving Mail.fromAddress(). " + out);
    return out;
  }

  // -------------------------------------------------------------------------
  // WHERE A MAILED LINK POINTS (header point 6): `global.publicBaseUrl` and
  // the realm's prefix; in development with that empty, the listener's
  // configured address; in product with it empty, '' — nothing is mailed.
  // -------------------------------------------------------------------------
  linkBase(): string {
    const { log, config, realms, mode } = this.deps;
    log.debug("Entering Mail.linkBase().");
    const pinned = String(config.value('global.publicBaseUrl') || '').trim()
      .replace(/\/+$/, '');
    if (pinned) {
      log.debug("Leaving Mail.linkBase(). Pinned.");
      return pinned + realms.currentPrefix();
    }
    if (!mode.mailsLinksFromListenerAddress()) {
      log.debug("Leaving Mail.linkBase(). Product, unpinned.");
      return '';
    }
    const bound = String(config.value('global.host') || '')
      .replace(/^\[|\]$/g, '');
    const host = (!bound || bound === '0.0.0.0' || bound === '::')
      ? 'localhost' : (bound.indexOf(':') >= 0 ? '[' + bound + ']' : bound);
    const base = (config.value('global.https') ? 'https' : 'http') + '://' +
      host + ':' + Number(config.value('global.port')) +
      realms.currentPrefix();
    log.debug("Leaving Mail.linkBase(). The listener's: " + base);
    return base;
  }

  // -------------------------------------------------------------------------
  // THE DIRECTORY, through its slot.
  // -------------------------------------------------------------------------
  directory(): Directory | null {
    const { log } = this.deps;
    log.debug("Entering Mail.directory().");
    log.debug("Leaving Mail.directory().");
    return directory;
  }

  // A person as the mail channel sees them: their address, whether it is
  // verified, the language they prefer. `null` when there is no entry.
  recipient(username: string): Json {
    const { log } = this.deps;
    log.debug("Entering Mail.recipient(). " + username);
    const entry = directory && username
      ? directory.personEntry(String(username)) : null;
    if (!entry) {
      log.debug("Leaving Mail.recipient(). No entry.");
      return null;
    }
    const attrs = entry.attributes || {};
    const first = function (name: string): string {
      log.debug("Entering first().");
      const values = attrs[name.toLowerCase()] || [];
      log.debug("Leaving first().");
      return values.length ? String(values[0]) : '';
    };
    const address = first('mail').trim();
    const verified = first('stsMailVerified').trim();
    log.debug("Leaving Mail.recipient().");
    return {
      username: String(username),
      address: address,
      verified: !!address && verified.toLowerCase() === address.toLowerCase(),
      language: first('preferredLanguage'),
      name: first('displayName') || first('cn') || String(username)
    };
  }

  // -------------------------------------------------------------------------
  // PREFERENCES (header point 7): only an optional category may be declined.
  // -------------------------------------------------------------------------
  declined(username: string): string[] {
    const { log, realms } = this.deps;
    log.debug("Entering Mail.declined(). " + username);
    const held = preferences.realmMap(realms.currentId()).get(
      String(username || ''));
    log.debug("Leaving Mail.declined().");
    return ((held && held.declined) || []).slice();
  }

  setDeclined(username: string, category: string, decline: boolean,
              actor?: string): Json {
    const { log, realms, audit, errorCodes, now } = this.deps;
    log.debug("Entering Mail.setDeclined(). " + username + " " + category +
              " " + decline);
    const cat = MailTemplates.category(String(category || ''));
    if (!cat || !cat.optional) {
      log.debug("Leaving Mail.setDeclined(). Not optional.");
      return errorCodes.mark({ ok: false, errors: [(cat ? cat.label +
        ' cannot be declined: ' + (cat.id === 'security'
          ? 'a person is always told what happened to their account.'
          : 'a link is only sent when somebody asked for it.')
        : 'There is no category "' + String(category || '') + '".')] },
        'STS-MAIL-0034');
    }
    const store = preferences.realmMap(realms.currentId());
    const name = String(username || '');
    const held = store.get(name) || { declined: [] };
    const set = (held.declined || []).filter(function (one: string) {
      return one !== cat.id;
    });
    if (decline) {
      set.push(cat.id);
    }
    store.set(name, { declined: set, at: now() });
    audit.audit({ action: 'mail.preferences', actor: actor || name,
      target: name, protocol: 'Mail', channel: 'http',
      summary: name + (decline ? ' declined ' : ' accepted ') + cat.label,
      detail: { category: cat.id, declined: String(!!decline) } });
    log.debug("Leaving Mail.setDeclined().");
    return { ok: true, declined: set,
             message: (decline ? 'You will not be sent ' : 'You will be ' +
                       'sent ') + cat.label.toLowerCase() + '.' };
  }

  // -------------------------------------------------------------------------
  // A REALM'S TEMPLATES
  // -------------------------------------------------------------------------
  templateFor(id: string, languages: string[]): Json {
    const { log, realms } = this.deps;
    log.debug("Entering Mail.templateFor(). " + id);
    const spec = MailTemplates.builtIn(id);
    if (!spec) {
      log.debug("Leaving Mail.templateFor(). Unknown.");
      return null;
    }
    const own = templates.realmMap(realms.currentId());
    for (let i = 0; i < languages.length; i++) {
      const held = own.get(id + ':' + languages[i]);
      if (held) {
        log.debug("Leaving Mail.templateFor(). The realm's, " + languages[i]);
        return { spec: spec, parts: held, lang: languages[i], own: true };
      }
      if (languages[i] === 'en') {
        log.debug("Leaving Mail.templateFor(). Built-in.");
        return { spec: spec, parts: spec, lang: 'en', own: false };
      }
    }
    log.debug("Leaving Mail.templateFor(). Built-in.");
    return { spec: spec, parts: spec, lang: 'en', own: false };
  }

  // Every message, with the languages this realm has its own wording in.
  listTemplates(): Json[] {
    const { log, realms } = this.deps;
    log.debug("Entering Mail.listTemplates().");
    const own = templates.realmMap(realms.currentId());
    const out = MailTemplates.BUILT_IN.map(function (spec) {
      const langs: string[] = [];
      own.forEach(function (row: Json, key: string) {
        const at = String(key).indexOf(':');
        if (row && String(key).slice(0, at) === spec.id) {
          langs.push(String(key).slice(at + 1));
        }
      });
      return { id: spec.id, title: spec.title, category: spec.category,
               values: MailTemplates.COMMON.concat(spec.values),
               links: spec.links, languages: langs.sort() };
    });
    log.debug("Leaving Mail.listTemplates().");
    return out;
  }

  // One message in one language: the realm's wording if it has one, else
  // the built-in (English).
  templateView(id: string, lang: string): Json {
    const { log, realms } = this.deps;
    log.debug("Entering Mail.templateView(). " + id + " " + lang);
    const spec = MailTemplates.builtIn(String(id || ''));
    if (!spec) {
      log.debug("Leaving Mail.templateView(). Unknown.");
      return null;
    }
    const tag = String(lang || 'en').toLowerCase();
    const held = templates.realmMap(realms.currentId()).get(spec.id + ':' +
                                                             tag);
    log.debug("Leaving Mail.templateView().");
    return { id: spec.id, title: spec.title, category: spec.category,
             lang: tag, own: !!held,
             values: MailTemplates.COMMON.concat(spec.values),
             links: spec.links,
             subject: held ? held.subject : spec.subject,
             text: held ? held.text : spec.text,
             html: held ? held.html : spec.html };
  }

  saveTemplate(id: string, lang: string, parts: Json, actor?: string): Json {
    const { log, realms, audit, errorCodes, now } = this.deps;
    log.debug("Entering Mail.saveTemplate(). " + id + " " + lang);
    const spec = MailTemplates.builtIn(String(id || ''));
    const tag = String(lang || '').trim().toLowerCase();
    if (!spec) {
      log.debug("Leaving Mail.saveTemplate(). Unknown.");
      return errorCodes.mark({ ok: false, errors: ['There is no message "' +
        String(id || '') + '".'] }, 'STS-MAIL-0017');
    }
    if (!/^[a-z]{1,8}(-[a-z0-9]{1,8})*$/.test(tag)) {
      log.debug("Leaving Mail.saveTemplate(). Bad language.");
      return errorCodes.mark({ ok: false, errors: ['"' + String(lang || '') +
        '" is not a BCP 47 language tag.'] }, 'STS-MAIL-0016');
    }
    const problem = MailTemplates.problem(spec, parts);
    if (problem) {
      log.debug("Leaving Mail.saveTemplate(). " + problem);
      return errorCodes.mark({ ok: false, errors: ['The ' + spec.id + ' (' +
        tag + ') template was not saved: ' + problem + '.'] },
        'STS-MAIL-0016');
    }
    templates.realmMap(realms.currentId()).set(spec.id + ':' + tag, {
      subject: String(parts.subject), text: String(parts.text),
      html: String(parts.html), savedAt: now(), savedBy: actor || '' });
    audit.audit({ action: 'mail.template', actor: actor || '',
      target: spec.id + ':' + tag, protocol: 'Mail', channel: 'http',
      summary: 'the ' + spec.id + ' message was reworded in ' + tag });
    log.debug("Leaving Mail.saveTemplate().");
    return { ok: true, message: 'The ' + spec.id + ' message in ' + tag +
             ' is this realm\'s own wording now.' };
  }

  resetTemplate(id: string, lang: string, actor?: string): Json {
    const { log, realms, audit, errorCodes } = this.deps;
    log.debug("Entering Mail.resetTemplate(). " + id + " " + lang);
    const spec = MailTemplates.builtIn(String(id || ''));
    const tag = String(lang || '').trim().toLowerCase();
    const store = templates.realmMap(realms.currentId());
    if (!spec || !store.get(spec.id + ':' + tag)) {
      log.debug("Leaving Mail.resetTemplate(). Nothing to reset.");
      return errorCodes.mark({ ok: false, errors: ['This realm has no ' +
        'wording of its own for "' + String(id || '') + '" in "' + tag +
        '".'] }, 'STS-MAIL-0017');
    }
    store.delete(spec.id + ':' + tag);
    audit.audit({ action: 'mail.template', actor: actor || '',
      target: spec.id + ':' + tag, protocol: 'Mail', channel: 'http',
      summary: 'the ' + spec.id + ' message in ' + tag + ' was put back to ' +
               'the built-in wording' });
    log.debug("Leaving Mail.resetTemplate().");
    return { ok: true, message: 'The ' + spec.id + ' message in ' + tag +
             ' is the built-in wording again.' };
  }

  // -------------------------------------------------------------------------
  // A REFUSAL TO QUEUE, audited with its code (and never with a body).
  // -------------------------------------------------------------------------
  private refuse(req: SendRequest, username: string, code: string,
                 why: string): Json {
    const { log, audit, errorCodes } = this.deps;
    log.debug("Entering Mail.refuse(). " + code);
    // error-code: none — the code is the caller's, passed in as `code`
    audit.audit({ action: 'mail.refused', outcome: 'refused',
      errorCode: code, actor: req.actor || '', target: username,
      protocol: 'Mail', channel: 'internal',
      summary: 'a ' + req.template + ' message for ' + (username || '?') +
               ' was not queued: ' + why,
      detail: { template: req.template, via: String(req.via || '') } });
    log.debug("Leaving Mail.refuse().");
    return errorCodes.mark({ username: username, code: code, why: why },
                           code);
  }

  // How many messages this person has been queued in the window, in all and
  // in one category (header point 7).
  private recentCounts(realmId: string, username: string, category: string):
    Json {
    const { log, now } = this.deps;
    log.debug("Entering Mail.recentCounts().");
    const since = now() - Number(this.setting('mail.rateWindowS')) * 1000;
    const out = { all: 0, category: 0 };
    outbox.realmMap(realmId).forEach(function (row: Json) {
      if (row && row.username === username && Number(row.queuedAt) >= since) {
        out.all++;
        if (row.category === category) {
          out.category++;
        }
      }
    });
    log.debug("Leaving Mail.recentCounts(). " + out.all + "/" +
              out.category);
    return out;
  }

  private duplicateOf(realmId: string, dedup: string): Json {
    const { log, now } = this.deps;
    log.debug("Entering Mail.duplicateOf().");
    const windowMs = Number(this.setting('mail.dedupWindowS')) * 1000;
    if (!dedup || windowMs <= 0) {
      log.debug("Leaving Mail.duplicateOf(). Off.");
      return null;
    }
    const since = now() - windowMs;
    let found: Json = null;
    outbox.realmMap(realmId).forEach(function (row: Json) {
      if (!found && row && row.dedup === dedup &&
          Number(row.queuedAt) >= since) {
        found = row;
      }
    });
    log.debug("Leaving Mail.duplicateOf(). " + (found ? 'found' : 'none'));
    return found;
  }

  // -------------------------------------------------------------------------
  // SEND: queue the message for each recipient and attempt it at once.
  // Answers `{ ok, queued: [view], refused: [{username, code, why}],
  // duplicates: [view] }` — `ok` when at least one was queued or suppressed
  // as a duplicate of one that was. It never throws: a notice is sent from
  // the middle of something else.
  // -------------------------------------------------------------------------
  send(req: SendRequest): Json {
    const { log, realms, errorCodes } = this.deps;
    const deps = this.deps;
    const self = this;
    log.debug("Entering Mail.send(). " + (req && req.template));
    const out: Json = { ok: false, queued: [], refused: [], duplicates: [] };
    try {
      const spec = MailTemplates.builtIn(String((req && req.template) || ''));
      if (!spec) {
        out.refused.push(this.refuse(req || ({} as SendRequest), '',
          'STS-MAIL-0017', 'there is no message "' +
          String((req && req.template) || '') + '"'));
        log.debug("Leaving Mail.send(). Unknown template.");
        return out;
      }
      let names: string[] = [];
      if (req.toAdministrators) {
        names = deps.administrators();
      } else if (req.username) {
        names = [String(req.username)];
      }
      if (!this.available()) {
        names.forEach(function (name) {
          out.refused.push(self.refuse(req, name, 'STS-MAIL-0001',
            'no mail transport is configured in this realm ' +
            '(mail.transport is "' + self.setting('mail.transport') + '")'));
        });
        out.error = 'no mail transport is configured';
        log.debug("Leaving Mail.send(). No transport.");
        return out;
      }
      const base = spec.links.length ? this.linkBase() : '';
      if (spec.links.length && !base) {
        names.forEach(function (name) {
          out.refused.push(self.refuse(req, name, 'STS-MAIL-0015',
            'a link is mailed only on global.publicBaseUrl, which is empty ' +
            'here, and product mode never builds one from a request'));
        });
        out.error = 'global.publicBaseUrl is not set';
        log.debug("Leaving Mail.send(). No link base.");
        return out;
      }
      names.forEach(function (name) {
        const one = self.queueOne(req, spec, name, base);
        if (one.refused) {
          out.refused.push(one.refused);
        } else if (one.duplicate) {
          out.duplicates.push(one.duplicate);
        } else {
          out.queued.push(one.queued);
        }
      });
      out.ok = out.queued.length + out.duplicates.length > 0;
      if (!out.ok && out.refused.length) {
        out.error = out.refused[0].why;
      }
      // THE ATTEMPT, AFTER THE ANSWER: non-enumerable, so it never reaches a
      // JSON reply, and there for a test (or a caller) that must wait on it.
      Object.defineProperty(out, 'delivered',
                            { value: this.dispatch(out.queued),
                              enumerable: false });
    } catch (e) {
      log.debug("Caught in Mail.send(): " + ((e && e.message) || e));
      log.error(errorCodes.tag('STS-MAIL-0031') + 'mail: a ' +
                String((req && req.template) || '?') + ' message could not ' +
                'be queued in the "' + realms.currentId() + '" realm: ' +
                ((e && e.message) || e));
      out.error = String((e && e.message) || e);
    }
    log.debug("Leaving Mail.send(). " + out.queued.length + " queued, " +
              out.refused.length + " refused, " + out.duplicates.length +
              " suppressed.");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE ONE MESSAGE NOT SENT TO THE ADDRESS ON THE ENTRY: `address-changed`,
  // to the address the entry HAD. That address is the directory's own value
  // as it was a moment ago — handed in by `ldap/ldap_server.js`'s account
  // observer, never by a request — and nothing but that template may use it.
  // -------------------------------------------------------------------------
  sendToFormerAddress(req: Json): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Mail.sendToFormerAddress().");
    const out: Json = { ok: false, queued: [], refused: [], duplicates: [] };
    const spec = MailTemplates.builtIn('address-changed');
    if (!req || req.template !== 'address-changed' || !this.available()) {
      log.debug("Leaving Mail.sendToFormerAddress(). Not this template, or " +
                "no transport.");
      return out;
    }
    try {
      const one = this.queueOne(req, spec, String(req.username || ''), '',
                                String(req.formerAddress || ''));
      if (one.refused) {
        out.refused.push(one.refused);
      } else if (one.duplicate) {
        out.duplicates.push(one.duplicate);
      } else {
        out.queued.push(one.queued);
      }
      out.ok = out.queued.length + out.duplicates.length > 0;
      Object.defineProperty(out, 'delivered',
                            { value: this.dispatch(out.queued),
                              enumerable: false });
    } catch (e) {
      log.debug("Caught in Mail.sendToFormerAddress(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-MAIL-0031') + 'mail: an address-changed ' +
               'notice could not be queued: ' + ((e && e.message) || e));
    }
    log.debug("Leaving Mail.sendToFormerAddress().");
    return out;
  }

  // One recipient: every check, then the row. `former` is
  // `sendToFormerAddress()`'s address, and only that.
  private queueOne(req: SendRequest, spec: Json, username: string,
                   base: string, former?: string): Json {
    const { log, realms, audit, now } = this.deps;
    log.debug("Entering Mail.queueOne(). " + username);
    const realmId = realms.currentId();
    const found = this.recipient(username);
    const who = found && former
      ? Object.assign({}, found, { address: former }) : found;
    if (!who) {
      log.debug("Leaving Mail.queueOne(). No entry.");
      return { refused: this.refuse(req, username, 'STS-MAIL-0012',
        'there is no entry for "' + username + '" in this realm') };
    }
    if (!who.address) {
      log.debug("Leaving Mail.queueOne(). No address.");
      return { refused: this.refuse(req, username, 'STS-MAIL-0011',
        username + '\'s entry has no mail attribute') };
    }
    const bad = mailTransports.addressProblem(who.address);
    if (bad) {
      log.debug("Leaving Mail.queueOne(). Bad address.");
      return { refused: this.refuse(req, username, 'STS-MAIL-0023',
        username + '\'s mail attribute ' + bad) };
    }
    const fromBad = mailTransports.addressProblem(this.fromAddress());
    if (fromBad) {
      log.debug("Leaving Mail.queueOne(). Bad From.");
      return { refused: this.refuse(req, username, 'STS-MAIL-0023',
        'the From address (mail.from) ' + fromBad) };
    }
    const cat = MailTemplates.category(spec.category);
    if (cat && cat.optional &&
        this.declined(username).indexOf(cat.id) >= 0) {
      log.debug("Leaving Mail.queueOne(). Declined.");
      return { refused: this.refuse(req, username, 'STS-MAIL-0013',
        username + ' declined ' + cat.label.toLowerCase()) };
    }
    const dedup = req.dedupKey
      ? nodeCrypto.createHash('sha256').update(username + '\n' + spec.id +
          '\n' + String(req.dedupKey)).digest('base64url').slice(0, 22)
      : '';
    const duplicate = this.duplicateOf(realmId, dedup);
    if (duplicate) {
      log.debug("Leaving Mail.queueOne(). A duplicate.");
      return { duplicate: this.view(duplicate) };
    }
    const counts = this.recentCounts(realmId, username, spec.category);
    const perAll = Number(this.setting('mail.ratePerRecipient'));
    const perCat = Number(this.setting('mail.ratePerCategory'));
    if (counts.all >= perAll || counts.category >= perCat) {
      log.debug("Leaving Mail.queueOne(). Over the ceiling.");
      return { refused: this.refuse(req, username, 'STS-MAIL-0010',
        username + ' has been sent ' + (counts.all >= perAll
          ? counts.all + ' message(s)' : counts.category + ' ' +
            spec.category + ' message(s)') + ' in the last ' +
        this.setting('mail.rateWindowS') + ' seconds, the ceiling ' +
        '(mail.ratePerRecipient, mail.ratePerCategory)') };
    }
    const languages = MailTemplates.languageOrder(who.language,
      String(this.setting('mail.defaultLanguage') || 'en'));
    const chosen = this.templateFor(spec.id, languages);
    const values: Json = Object.assign({}, req.values || {});
    values.realm = String((realms.current() && realms.current().name) ||
                          realmId);
    values.service = values.service ||
      String(realms.domainOf(realms.current()) || 'this service');
    const links = req.links || {};
    spec.links.forEach(function (name: string) {
      const path = String(links[name] || '');
      // A PATH, and nothing that could make it another origin.
      values[name] = /^\/(?!\/)/.test(path) && !/[\s\\]/.test(path)
        ? base + path : '';
    });
    const rendered = MailTemplates.render(chosen.parts, values);
    const at = now();
    const id = nodeCrypto.randomBytes(16).toString('base64url');
    const domain = this.fromAddress().split('@').pop();
    const row: Message = {
      id: id, realm: realmId, username: username, to: who.address,
      category: spec.category, template: spec.id, lang: chosen.lang,
      dedup: dedup, subject: rendered.subject, text: rendered.text,
      html: MailTemplates.htmlDocument(rendered.html, chosen.lang),
      from: this.fromAddress(),
      fromName: String(this.setting('mail.fromName') || ''),
      messageId: '<' + id + '@' + domain + '>',
      via: String(req.via || ''), actor: String(req.actor || ''),
      state: 'pending', transport: this.effectiveTransport(),
      generation: 1, attempts: 0, inFlight: 0, fenceAt: 0, holder: '',
      errorCode: '', why: '', providerId: '', queuedAt: at,
      nextAttemptAt: at, lastAttemptAt: 0, finishedAt: 0, updatedAt: at
    };
    this.writeRow(row);
    audit.audit({ action: 'mail.queued', actor: row.actor,
      target: username, protocol: 'Mail', channel: 'internal',
      summary: 'a ' + spec.id + ' message (' + spec.category + ') was ' +
               'queued for ' + username,
      detail: { message: id, template: spec.id, category: spec.category,
                to: who.address, via: row.via, transport: row.transport } });
    log.debug("Leaving Mail.queueOne(). Queued " + id + ".");
    return { queued: this.view(row) };
  }

  // A row as the store holds it now.
  private liveRow(realmId: string, id: string): Message | null {
    const { log } = this.deps;
    log.debug("Entering Mail.liveRow().");
    const held = outbox.realmMap(realmId).get(id);
    log.debug("Leaving Mail.liveRow(). " + (held ? 'held' : 'gone'));
    return held ? Object.assign({}, held) : null;
  }

  // Write a row unless a newer copy stands; answers the copy that stands.
  private writeRow(row: Message): Message {
    const { log, now } = this.deps;
    log.debug("Entering Mail.writeRow(). " + row.id + " " + row.state);
    const store = outbox.realmMap(row.realm);
    const held = store.get(row.id);
    row.updatedAt = Math.max(now(), (held && Number(held.updatedAt) + 1) || 0);
    if (held && compareRows(row, held) < 0) {
      log.debug("Leaving Mail.writeRow(). A newer copy stands.");
      return Object.assign({}, held);
    }
    store.set(row.id, Object.assign({}, row));
    log.debug("Leaving Mail.writeRow().");
    return row;
  }

  private tally(realmId: string, what: string, code?: string): void {
    const { log } = this.deps;
    log.debug("Entering Mail.tally(). " + what);
    let t = tallies.get(realmId);
    if (!t) {
      t = { sent: 0, captured: 0, retried: 0, takenOver: 0, deferred: 0,
            dead: 0, byCode: {} };
      tallies.set(realmId, t);
    }
    t[what] = (t[what] || 0) + 1;
    if (code) {
      t.byCode[code] = (t.byCode[code] || 0) + 1;
    }
    log.debug("Leaving Mail.tally().");
  }

  // -------------------------------------------------------------------------
  // A MESSAGE REACHES ITS FINAL STATE: one audit row, and a SENT message
  // loses its body (header point 8).
  // -------------------------------------------------------------------------
  private finish(row: Message, state: string, code: string,
                 why: string): Message {
    const { log, audit, now } = this.deps;
    log.debug("Entering Mail.finish(). " + row.id + " -> " + state);
    row.state = state;
    row.errorCode = code || '';
    row.why = why || '';
    row.finishedAt = now();
    row.inFlight = 0;
    row.nextAttemptAt = 0;
    if (state === 'sent') {
      row.text = '';
      row.html = '';
    }
    const written = this.writeRow(row);
    if (written.state !== state || written.updatedAt !== row.updatedAt) {
      log.debug("Leaving Mail.finish(). A newer copy stood.");
      return written;
    }
    this.tally(row.realm, state === 'dead' ? 'dead' : state, code);
    audit.audit({
      action: state === 'dead' ? 'mail.dead' : 'mail.sent',
      outcome: state === 'dead' ? 'error' : 'success',
      errorCode: state === 'dead' ? code : '',
      summarised: true,
      actor: row.actor, target: row.username, protocol: 'Mail',
      channel: 'internal',
      summary: state === 'dead'
        ? 'a ' + row.template + ' message for ' + row.username + ' was not ' +
          'delivered and is a dead letter: ' + why
        : 'a ' + row.template + ' message for ' + row.username + ' was ' +
          (state === 'captured' ? 'captured (development: not sent)'
                                : 'accepted by the ' + row.transport +
                                  ' transport'),
      detail: { message: row.id, template: row.template,
                category: row.category, to: row.to,
                transport: row.transport, attempts: String(row.attempts),
                generation: String(row.generation), state: state,
                providerId: row.providerId || '' }
    });
    log.debug("Leaving Mail.finish().");
    return written;
  }

  leaseMs(): number {
    const { log } = this.deps;
    log.debug("Entering Mail.leaseMs().");
    const lease = Math.max(Number(this.setting('mail.leaseMs')),
                           Number(this.setting('mail.timeoutMs')) + 2000);
    log.debug("Leaving Mail.leaseMs(). " + lease);
    return lease;
  }

  // -------------------------------------------------------------------------
  // ONE ATTEMPT of one message, claimed (header point 4). Resolves `sent`,
  // `captured`, `retry`, `dead`, or a reason nothing was done (`not-due`,
  // `claimed-elsewhere`, `deferred`, `gone`). Never rejects.
  // -------------------------------------------------------------------------
  async attempt(realmId: string, id: string): Promise<string> {
    const { log, claims, realms, errorCodes, now } = this.deps;
    const self = this;
    log.debug("Entering Mail.attempt(). " + id);
    const before = this.liveRow(realmId, id);
    if (!before || before.state !== 'pending') {
      log.debug("Leaving Mail.attempt(). Not pending.");
      return 'gone';
    }
    if (Number(before.nextAttemptAt) > now()) {
      log.debug("Leaving Mail.attempt(). Not due.");
      return 'not-due';
    }
    const n = Number(before.inFlight) || (Number(before.attempts) + 1);
    const lease = this.leaseMs();
    const answer: Json = await claims.claim({
      scope: ATTEMPT_SCOPE,
      value: id + ':' + before.generation + ':' + n,
      ttlMs: lease,
      realm: realmId
    });
    if (!answer.ok) {
      if (answer.reason === 'store') {
        this.tally(realmId, 'deferred', 'STS-MAIL-0020');
      }
      log.debug("Leaving Mail.attempt(). Not claimed (" + answer.reason +
                ").");
      return answer.reason === 'store' ? 'deferred' : 'claimed-elsewhere';
    }
    let row = this.liveRow(realmId, id);
    if (!row || row.state !== 'pending' ||
        row.generation !== before.generation) {
      log.debug("Leaving Mail.attempt(). It changed under the claim.");
      return 'gone';
    }
    if (Number(row.inFlight) === n && Number(row.fenceAt) > 0) {
      this.tally(realmId, 'takenOver');
      log.debug("Mail.attempt(): taking over attempt " + n + " of " + id +
                " from " + (row.holder || 'an unnamed holder') + ".");
    }
    const startedAt = now();
    const claimedFence = Number(answer.claimedAt) || startedAt;
    row.inFlight = n;
    row.fenceAt = claimedFence;
    row.holder = HOLDER;
    row.lastAttemptAt = startedAt;
    row.nextAttemptAt = startedAt + lease;
    row = this.writeRow(row);
    if (row.fenceAt !== claimedFence || row.inFlight !== n) {
      log.debug("Leaving Mail.attempt(). Fenced out before sending.");
      return 'claimed-elsewhere';
    }
    const fence = row.fenceAt;
    // THE TRANSPORT IN THE MESSAGE'S OWN REALM, and the send.
    let failure: Json = null;
    let result: Json = null;
    let transportName = row.transport;
    try {
      result = await realms.run(realms.get(realmId) || realms.DEFAULT_REALM,
        async function (): Promise<Json> {
          const transport = await self.transport();
          transportName = transport.name;
          return transport.send({
            from: row.from, fromName: row.fromName, to: row.to,
            subject: row.subject, text: row.text, html: row.html,
            messageId: row.messageId, date: new Date(row.queuedAt),
            lang: row.lang });
        });
    } catch (e) {
      log.debug("Caught in Mail.attempt(): " + ((e && e.message) || e));
      failure = e;
    }
    const current = this.liveRow(realmId, id);
    if (!current || current.fenceAt !== fence ||
        current.generation !== row.generation) {
      log.debug("Leaving Mail.attempt(). Fenced out after sending.");
      return 'claimed-elsewhere';
    }
    current.attempts = n;
    current.inFlight = 0;
    current.transport = transportName;
    if (!failure) {
      current.providerId = String((result && result.providerId) || '');
      const final = transportName === 'capture' ? 'captured' : 'sent';
      this.finish(current, final, '', '');
      log.debug("Leaving Mail.attempt(). " + final);
      return final;
    }
    const code = errorCodes.codeOf(failure) || 'STS-MAIL-0009';
    // A TRANSPORT THAT COULD NOT BE BUILT is worth another attempt: the
    // commonest reason is a setting an operator is correcting.
    const retry = failure.retry !== undefined ? !!failure.retry
      : code === 'STS-MAIL-0004' || code === 'STS-MAIL-0006';
    const worth = retry || code === 'STS-MAIL-0004' ||
                  code === 'STS-MAIL-0006' || code === 'STS-MAIL-0007';
    const attempts = Math.max(1, Number(this.setting('mail.attempts')));
    const why = String((failure && failure.message) || failure);
    if (!worth || n >= attempts) {
      this.finish(current, 'dead', code,
                  why + (n > 1 ? ' (after ' + n + ' attempts)' : ''));
      log.debug("Leaving Mail.attempt(). Dead.");
      return 'dead';
    }
    const backoff = Math.max(1, Number(this.setting('mail.backoffS'))) *
      1000 * Math.pow(2, n - 1);
    current.errorCode = code;
    current.why = why + ' (attempt ' + n + '; trying again)';
    current.nextAttemptAt = now() + backoff;
    this.writeRow(current);
    this.tally(realmId, 'retried', code);
    log.debug("Leaving Mail.attempt(). Retry in " + backoff + "ms.");
    return 'retry';
  }

  // Attempt what was just queued. Returns a promise for a test to wait on;
  // every caller in the service ignores it. Never rejects.
  dispatch(rows: Json[] | null | undefined): Promise<void> {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering Mail.dispatch().");
    const pending = (rows || []).filter(function (row) {
      return row && row.state === 'pending';
    });
    const realmId = realms.currentId();
    log.debug("Leaving Mail.dispatch(). " + pending.length + " to send.");
    return Promise.all(pending.map(function (row) {
      return self.attempt(row.realm || realmId, row.id).catch(function (e) {
        log.debug("Caught in Mail.dispatch(): " + ((e && e.message) || e));
        return 'error';
      });
    })).then(function () {
      return undefined;
    });
  }

  // -------------------------------------------------------------------------
  // AN ADMINISTRATOR'S RETRY OF A DEAD LETTER: a new generation and a fresh
  // attempt budget, the same body and the same Message-ID, to the address the
  // entry holds NOW (the commonest reason to retry is having corrected it).
  // -------------------------------------------------------------------------
  retry(id: string, actor?: string): Json {
    const { log, realms, audit, errorCodes, now } = this.deps;
    log.debug("Entering Mail.retry(). " + id);
    const realmId = realms.currentId();
    const row = this.liveRow(realmId, String(id || ''));
    if (!row) {
      log.debug("Leaving Mail.retry(). Unknown.");
      return errorCodes.mark({ ok: false, errors: ['There is no message "' +
        String(id || '') + '" in this realm\'s outbox; retention may have ' +
        'removed it.'] }, 'STS-MAIL-0018');
    }
    if (row.state !== 'dead') {
      log.debug("Leaving Mail.retry(). Not dead.");
      return errorCodes.mark({ ok: false, errors: ['The message to ' +
        row.username + ' is ' + row.state + ', not a dead letter; only a ' +
        'dead letter is retried by hand.'] }, 'STS-MAIL-0018');
    }
    if (!row.text && !row.html) {
      log.debug("Leaving Mail.retry(). No body.");
      return errorCodes.mark({ ok: false, errors: ['The message to ' +
        row.username + ' kept no body, so it cannot be sent again.'] },
        'STS-MAIL-0018');
    }
    const who = this.recipient(row.username);
    if (!who || !who.address ||
        mailTransports.addressProblem(who.address)) {
      log.debug("Leaving Mail.retry(). No usable address.");
      return errorCodes.mark({ ok: false, errors: [row.username + ' has no ' +
        'usable mail address now, so a retry would fail the same way.'] },
        'STS-MAIL-0018');
    }
    const at = now();
    const fresh: Message = Object.assign(row, {
      to: who.address, state: 'pending', generation: row.generation + 1,
      attempts: 0, inFlight: 0, fenceAt: 0, holder: '', errorCode: '',
      why: 'retried by ' + (actor || 'an administrator'),
      nextAttemptAt: at, finishedAt: 0,
      transport: this.effectiveTransport()
    });
    const written = this.writeRow(fresh);
    audit.audit({ action: 'mail.retry', actor: actor || '',
      target: row.username, protocol: 'Mail', channel: 'http',
      summary: 'a dead ' + row.template + ' message for ' + row.username +
               ' was queued again (generation ' + written.generation + ')',
      detail: { message: row.id, to: who.address } });
    this.dispatch([this.view(written)]);
    log.debug("Leaving Mail.retry().");
    return { ok: true, row: this.view(written),
             message: 'The message to ' + row.username + ' was queued ' +
                      'again; it is sent after this answer, and the outbox ' +
                      'shows where it got to.' };
  }

  // -------------------------------------------------------------------------
  // THE SWEEP (header point 3): every realm, what is due, bounded by
  // `mail.concurrency`; then retention; then the summary line. Resolves
  // `{ attempted, removed, dead }`. Never rejects.
  // -------------------------------------------------------------------------
  sweep(): Promise<Json> {
    const { log, realms, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering Mail.sweep().");
    const total = { attempted: 0, removed: 0, dead: 0 };
    let chain: Promise<unknown> = Promise.resolve();
    realms.list().forEach(function (realm: Json) {
      chain = chain.then(function () {
        return realms.run(realm, function () {
          return self.sweepRealm(realm.id).then(function (one: Json) {
              total.attempted += one.attempted;
              total.removed += one.removed;
              total.dead += one.dead;
            });
        });
      }).catch(function (e) {
        log.debug("Caught in Mail.sweep(): " + ((e && e.message) || e));
        log.error(errorCodes.tag('STS-MAIL-0029') + 'mail: the outbox sweep ' +
                  'failed in the "' + realm.id + '" realm: ' +
                  ((e && e.message) || e));
      });
    });
    log.debug("Leaving Mail.sweep().");
    return chain.then(function () {
      return total;
    });
  }

  private async sweepRealm(realmId: string): Promise<Json> {
    const { log, now } = this.deps;
    const self = this;
    log.debug("Entering Mail.sweepRealm(). " + realmId);
    const at = now();
    const keepMs = Math.max(1, Number(this.setting('mail.retentionS'))) * 1000;
    const cap = Math.max(1, Number(this.setting('mail.maxRows')));
    const store = outbox.realmMap(realmId);
    const due: string[] = [];
    const finished: Json[] = [];
    const stale: Message[] = [];
    store.forEach(function (row: Json, id: string) {
      if (!row) {
        return;
      }
      if (row.state === 'pending') {
        if (at - Number(row.queuedAt) > keepMs) {
          stale.push(Object.assign({}, row));
        } else if (!(Number(row.nextAttemptAt) > at)) {
          due.push(id);
        }
        return;
      }
      finished.push(row);
    });
    let dead = 0;
    stale.forEach(function (row) {
      self.finish(row, 'dead', 'STS-MAIL-0019', 'still unsent ' +
                  Math.round(keepMs / 1000) + ' seconds after it was queued ' +
                  '(mail.retentionS)');
      dead++;
    });
    let removed = 0;
    finished.sort(function (a, b) {
      return Number(a.queuedAt) - Number(b.queuedAt);
    });
    const over = Math.max(0, store.size - cap);
    finished.forEach(function (row, i) {
      if (at - Number(row.queuedAt) > keepMs || i < over) {
        store.delete(row.id);
        removed++;
      }
    });
    const limit = Math.max(1, Number(this.setting('mail.concurrency')));
    let attempted = 0;
    const next = function (): Promise<void> {
      log.debug("Entering next().");
      const id = due.shift();
      if (id === undefined || inFlightHere >= limit) {
        log.debug("Leaving next(). Nothing more this sweep.");
        return Promise.resolve();
      }
      inFlightHere++;
      attempted++;
      log.debug("Leaving next().");
      return self.attempt(realmId, id).catch(function (e) {
        log.debug("Caught in next(): " + ((e && e.message) || e));
        return 'error';
      }).then(function () {
        inFlightHere--;
        return next();
      });
    };
    const lanes = [];
    for (let i = 0; i < limit; i++) {
      lanes.push(next());
    }
    await Promise.all(lanes);
    this.summarise(realmId);
    log.debug("Leaving Mail.sweepRealm(). " + attempted + " attempted, " +
              removed + " removed.");
    return { attempted: attempted, removed: removed, dead: dead };
  }

  // ONE SUMMARY LINE per realm per sweep interval at most, and only when
  // something happened — never a line per message (rcbj's rule for delivery
  // failures).
  summarise(realmId: string, force?: boolean): string {
    const { log, errorCodes, now } = this.deps;
    log.debug("Entering Mail.summarise(). " + realmId);
    const t = tallies.get(realmId);
    const at = now();
    const every = Math.max(60, Number(this.setting('mail.deliverS'))) * 1000;
    if (!t || (!force && at - (lastSummaryAt.get(realmId) || 0) < every)) {
      log.debug("Leaving Mail.summarise(). Not due.");
      return '';
    }
    tallies.delete(realmId);
    lastSummaryAt.set(realmId, at);
    const codes = Object.keys(t.byCode).sort().map(function (code) {
      return code + ' ' + t.byCode[code];
    }).join(', ');
    const line = 'mail in the "' + realmId + '" realm since ' +
      'the last summary: ' + t.sent + ' sent, ' + t.captured + ' captured, ' +
      t.retried + ' retried, ' + t.takenOver + ' taken over from a lapsed ' +
      'lease, ' + t.deferred + ' deferred (claim store unavailable), ' +
      t.dead + ' dead-lettered' + (codes ? ' (' + codes + ')' : '') + '.';
    if (t.dead || t.deferred) {
      log.warn(errorCodes.tag('STS-MAIL-0028') + line + ' Dead letters are ' +
               'listed on /admin/mail/outbox and retried from there.');
    } else {
      log.info(line);
    }
    log.debug("Leaving Mail.summarise().");
    return line;
  }

  // THE SWEEP IS A SCHEDULER JOB (#49): `mail.deliver`, a CLUSTER job — once,
  // on the leader, every `mail.deliverS`. Registered by the wire step.
  scheduleJobs(): void {
    const { log, scheduler } = this.deps;
    const self = this;
    log.debug("Entering Mail.scheduleJobs().");
    const s = scheduler();
    if (!s || typeof s.register !== 'function' || s.job(DELIVER_JOB)) {
      log.debug("Leaving Mail.scheduleJobs(). Registered, or no scheduler.");
      return;
    }
    s.register({
      id: DELIVER_JOB,
      title: 'Mail outbox delivery',
      describe: 'Sends every queued message that is due — a retry whose ' +
                'backoff has passed, a lease that lapsed, a row restored ' +
                'after a restart — dead-letters any still pending past ' +
                'mail.retentionS, and removes finished rows past it.',
      owner: 'common/mail.ts',
      everySetting: 'mail.deliverS', everySettingUnit: 's',
      run: function (): Promise<Json> {
        return self.sweep();
      }
    });
    log.debug("Leaving Mail.scheduleJobs(). On the scheduler.");
  }

  // -------------------------------------------------------------------------
  // PRODUCT REFUSES TO START (header point 2) when a realm's configured
  // transport cannot be built — `capture` included. Resolves '' or the
  // reason, with its code at the front. Development answers '' whatever it
  // finds: a transport it cannot build is a dead letter there, not a boot
  // failure.
  // -------------------------------------------------------------------------
  startupProblem(): Promise<string> {
    const { log, realms, mode, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering Mail.startupProblem().");
    let chain: Promise<string> = Promise.resolve('');
    realms.list().forEach(function (realm: Json) {
      chain = chain.then(function (found: string): Json {
        if (found) {
          return found;
        }
        return realms.run(realm, function (): Json {
          if (!mode.isProduct()) {
            return '';
          }
          const t = self.effectiveTransport();
          if (t === 'off') {
            return '';
          }
          return self.transport().then(function (): string {
            return '';
          }, function (e: Json): string {
            const code = errorCodes.codeOf(e) === 'STS-MAIL-0003'
              ? 'STS-MAIL-0003' : 'STS-MAIL-0002';
            return errorCodes.tag(code) + 'mail: the "' + t + '" transport ' +
              'configured in the "' + realm.id + '" realm cannot be built, ' +
              'and a product service that cannot send the links it offers ' +
              'does not start: ' + String((e && e.message) || e);
          });
        });
      });
    });
    log.debug("Leaving Mail.startupProblem().");
    return chain;
  }

  // -------------------------------------------------------------------------
  // THE VIEWS
  // -------------------------------------------------------------------------
  view(row: Json, withBody?: boolean): Json {
    const { log } = this.deps;
    log.debug("Entering Mail.view().");
    const iso = function (ms: unknown): string {
      log.debug("Entering iso().");
      log.debug("Leaving iso().");
      return Number(ms) ? new Date(Number(ms)).toISOString() : '';
    };
    const out: Json = {
      id: row.id, realm: row.realm, username: row.username, to: row.to,
      category: row.category, template: row.template, lang: row.lang,
      subject: row.subject, from: row.from, messageId: row.messageId,
      via: row.via, actor: row.actor, state: row.state,
      transport: row.transport, generation: row.generation,
      attempts: row.attempts, inFlight: !!row.inFlight,
      holder: row.holder || '', errorCode: row.errorCode, why: row.why,
      providerId: row.providerId || '',
      // WHETHER A BODY IS STILL HELD — a fact, never the body: a dead letter
      // keeps one for its retry, a sent message none (header point 8).
      bodyKept: !!(row.text || row.html),
      queuedAt: iso(row.queuedAt), nextAttemptAt: iso(row.nextAttemptAt),
      lastAttemptAt: iso(row.lastAttemptAt), finishedAt: iso(row.finishedAt)
    };
    // ONLY A CAPTURED MESSAGE'S BODY LEAVES THIS MODULE, and only when asked
    // for (header point 8).
    if (withBody && row.state === 'captured') {
      out.text = row.text;
      out.html = row.html;
    }
    log.debug("Leaving Mail.view().");
    return out;
  }

  // The outbox, newest first; `state` narrows, `q` searches the recipient,
  // the address, the template and the code.
  list(options?: Json): Json[] {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering Mail.list().");
    const o = options || {};
    const q = String(o.q || '').toLowerCase();
    const out: Json[] = [];
    outbox.realmMap(realms.currentId()).forEach(function (row: Json) {
      if (!row || (o.state && row.state !== o.state)) {
        return;
      }
      if (o.username && row.username !== o.username) {
        return;
      }
      if (q && [row.username, row.to, row.template, row.errorCode,
                row.subject].join(' ').toLowerCase().indexOf(q) < 0) {
        return;
      }
      out.push(row);
    });
    out.sort(function (a, b) {
      return (Number(b.queuedAt) - Number(a.queuedAt)) ||
             String(a.id).localeCompare(String(b.id));
    });
    log.debug("Leaving Mail.list(). " + out.length + " row(s).");
    return out.map(function (row) {
      return self.view(row);
    });
  }

  // One message, with its body when it was captured.
  message(id: string): Json {
    const { log, realms } = this.deps;
    log.debug("Entering Mail.message(). " + id);
    const row = outbox.realmMap(realms.currentId()).get(String(id || ''));
    log.debug("Leaving Mail.message().");
    return row ? this.view(row, true) : null;
  }

  counts(): Json {
    const { log, realms } = this.deps;
    log.debug("Entering Mail.counts().");
    const out = { pending: 0, sent: 0, captured: 0, dead: 0 };
    outbox.realmMap(realms.currentId()).forEach(function (row: Json) {
      if (row && out[row.state] !== undefined) {
        out[row.state]++;
      }
    });
    log.debug("Leaving Mail.counts().");
    return out;
  }

  // What the console and the API show about the channel in this realm. It
  // never carries a secret: only where each one is configured to be.
  status(): Json {
    const { log, realms, mode } = this.deps;
    log.debug("Entering Mail.status().");
    const cfg = this.transportConfig();
    const problem = this.buildProblem();
    log.debug("Leaving Mail.status().");
    return {
      realm: realms.currentId(),
      mode: mode.current(),
      setting: cfg.setting,
      transport: cfg.transport,
      available: this.available(),
      from: cfg.from,
      linkBase: this.linkBase(),
      linkBasePinned: !!String(this.setting('global.publicBaseUrl') || ''),
      relay: cfg.transport === 'smtp'
        ? { host: cfg.smtpHost, port: cfg.smtpPort, tls: cfg.smtpTls,
            auth: cfg.smtpAuth, dkim: cfg.dkimDomain
              ? cfg.dkimAlgorithm + ' d=' + cfg.dkimDomain + ' s=' +
                cfg.dkimSelector : 'off' }
        : null,
      buildProblem: problem ? { code: problem.code, why: problem.why,
                                at: new Date(problem.at).toISOString() }
                            : null,
      counts: this.counts(),
      categories: MailTemplates.CATEGORIES,
      selfServiceReset: !!this.setting('mail.selfServiceReset'),
      securityNotices: !!this.setting('mail.securityNotices')
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). The wire step
// registers the delivery job (#49).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<Mail>(
  'common/mail',
  () => new Mail(Mail.defaultDeps()),
  function (instance: Mail): void {
    instance.scheduleJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  Mail: Mail,
  installInstance: (instance: Mail): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  STATES: Mail.STATES,
  TRANSPORTS: Mail.TRANSPORTS,
  ATTEMPT_SCOPE: Mail.ATTEMPT_SCOPE,
  DELIVER_JOB: Mail.DELIVER_JOB,
  CATEGORIES: MailTemplates.CATEGORIES,
  compareRows: compareRows,
  // The directory's slot (rule 3e), filled by `ldap/ldap_server.js`. A
  // plain function, not an instance method: the directory fills it at its
  // own require, which may come before the root installs this module.
  setDirectory: function (d: Directory): void {
    helpers.log.debug("Entering setDirectory().");
    directory = d || null;
    helpers.log.debug("Leaving setDirectory().");
  },
  effectiveTransport: slot.forward('effectiveTransport'),
  available: slot.forward('available'),
  transportConfig: slot.forward('transportConfig'),
  transport: slot.forward('transport'),
  buildProblem: slot.forward('buildProblem'),
  fromAddress: slot.forward('fromAddress'),
  linkBase: slot.forward('linkBase'),
  directory: slot.forward('directory'),
  recipient: slot.forward('recipient'),
  declined: slot.forward('declined'),
  setDeclined: slot.forward('setDeclined'),
  templateFor: slot.forward('templateFor'),
  listTemplates: slot.forward('listTemplates'),
  templateView: slot.forward('templateView'),
  saveTemplate: slot.forward('saveTemplate'),
  resetTemplate: slot.forward('resetTemplate'),
  send: slot.forward('send'),
  sendToFormerAddress: slot.forward('sendToFormerAddress'),
  attempt: slot.forward('attempt'),
  dispatch: slot.forward('dispatch'),
  retry: slot.forward('retry'),
  sweep: slot.forward('sweep'),
  summarise: slot.forward('summarise'),
  startupProblem: slot.forward('startupProblem'),
  view: slot.forward('view'),
  list: slot.forward('list'),
  message: slot.forward('message'),
  counts: slot.forward('counts'),
  status: slot.forward('status'),
  leaseMs: slot.forward('leaseMs')
};
