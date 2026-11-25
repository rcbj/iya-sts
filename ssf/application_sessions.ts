// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssf/application_sessions.ts
//
// ===========================================================================
// AN APPLICATION'S STREAM IS ABOUT THE PEOPLE SIGNED IN TO IT (#2234,
// 2026-11-25).
//
// rcbj's rule: "By default, a subscribing app should only receive CAEP & RISC
// events about users that have active sessions on their app." Until this
// change a stream an APPLICATION owned — created with its client credentials,
// a GNAP key or its certificate — was sent, under `default_subjects: ALL`,
// every person's events in the realm: `gnap-demo-user`'s CAEP events arrived
// on the OIDC demo's stream although that person never signed in to it. SSF
// 1.0 section 7.1 leaves what "appropriate for the stream" means to the
// transmitter; section 9.2 says a transmitter "SHOULD validate that they are
// permitted to share the information contained within an event", and section
// 10.1 that it SHOULD NOT leak information about subjects. This file is that
// definition for an application's stream.
//
// **IT IS A REGISTERED SUBJECT SCOPE, NOT BUILT IN.** `ssf_streams.ts`'s
// person rule (#336) is built in because who OWNS a stream is the store's
// own fact. Whether a person has a session on an application is not: it is
// `authn/`'s session and GNAP's grants, and `setSubjectScope()` is the hook a
// family's narrowing goes through. `ssf.ts` registers `scope()` there when it
// installs its hooks, and asks the same function at Add Subject.
//
// WHAT "AN ACTIVE SESSION ON THIS APPLICATION" IS — THE ONE MODEL OF A LIVE
// SESSION, READ, NEVER A REGISTER OF ITS OWN (`logout/CLAUDE.md`):
//
//   * a live sign-on session (not expired, not an arrival session nobody
//     chose) whose relying-party lists name the application: `oidcClients`
//     (every OpenID Connect / OAuth client an authorization response went to,
//     by client_id), `saml2ServiceProviders` (by entityID),
//     `saml11RelyingParties` (by relying party, and its providerId), and
//     `wsfedRealms` (by wtrealm). The application is named by the identifiers
//     its registry entry answers to (`applications.ssfAllowedEventsFor()`'s
//     cached `names`) and by its registry identifier;
//   * for a GNAP client, a live grant the person approved to it
//     (`gnap_store.ts`'s `grantsApprovedTo()`, an index on the grants).
//
// The sessions are read through `authn.sessionsHeldUnder()`, the two indexed
// columns (#774) — never a walk of the session store while the session window
// is on — and asked ONCE per person per turn of the event loop however many
// streams a candidate filter asks about (`memo`, below). The session rows
// are persisted and replicated, so any node answers the same.
//
// **THE EVENT THAT ENDS A SESSION STILL REACHES THE APPLICATION WHOSE SESSION
// IT ENDED.** A sign-out's `session-revoked` is built after the session is
// gone, and a RISC `account-disabled` or `account-purged` may be sent after
// the sessions it ended. So `noteEnded()` — called from `ssf.ts`'s session
// observer on every `revoked` notice, BEFORE the event is built — keeps the
// parties the session carried, in `ssf_application_sessions.ended`, for
// ENDED_GRACE_MS. An event naming that session (its `session` member) is
// covered for every application on it for as long as the row lives; an event
// about the person is covered for those applications within the grace too,
// which is what makes the RISC event that ended the sessions arrive whichever
// order its door sent the two in. A GNAP `session-revoked` names its grant
// (`gnap-grant:<id>`) or token (`gnap-token:<jti>`), and both outlive their
// end in the GNAP store, so they are read from there.
//
// WHAT IT HAS NO OPINION ON (answers undefined, and `streamCoversSubject()`
// goes on as before):
//
//   * a stream no application owns — a person's (#336), this service's own
//     receivers (`internalSurface`), a Basic name that is nobody, an
//     unauthenticated one;
//   * a GNAP resource server's stream (#432's `rsCovers()` is its rule);
//   * **an event about no PERSON**: SSF's own two (no subject at all), and a
//     subject that names an application, a device, a workload or a stream
//     without a `user` — an application's own credential changes, GNAP's
//     subject for a token nobody approved, #2028's `pep-policies-changed`
//     (the application's complex subject, on its own stream). Only `iss_sub`,
//     `email`, `phone_number`, `account`, `aliases` holding one of those, and
//     a complex subject's `user` member name a person here; a bare `opaque`
//     or `uri` does not;
//   * everything while `ssf.applicationStreamScope` is `all`.
//
// A LIBRARY (rule 3): no route. It requires `config`, the error codes,
// `realms` and `helpers`, none of which requires it, and reaches `authn`, the
// registry, RISC, the directory and GNAP lazily, at call time.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import InstanceSlot = require('../common/instance_slot');

const log = helpers.log;

// HOW LONG THE PARTIES OF AN ENDED SESSION ARE KEPT. Not a tunable: it is
// the time between a session ending and the event that ended it being built,
// which is one request (a sign-out, a disable, a delete) or one sweep, with
// a margin for a RISC event sent on the other side of the same act. Two
// minutes; an event about the person sent later than that to an application
// they have left is the leak this file exists to stop.
const ENDED_GRACE_MS = 120 * 1000;

// The most ended sessions a realm keeps at once. A bound at the insert, not
// a timer (root CLAUDE.md, *Anything periodic*): past it the oldest goes.
const MAX_ENDED = 5000;

// session id -> { username, subjectId, parties, endedAt }, per realm.
// Persisted with the sessions it describes (`persistence/tiers.js`, cell
// local), so a node that did not end the session reads the same row; indexed
// by the person, so an event about them asks two keys rather than walking.
// Expired at the read, and dropped from a restore by `expiresAt` (#333).
const ended = realms.map({
  persist: 'ssf_application_sessions.ended',
  // A hot path (every write): no Entering/Leaving pair.
  expiresAt: function (row: any): number | null {
    const at = row && Number(row.endedAt);
    return at > 0 ? at + ENDED_GRACE_MS : null;
  },
  // A hot path (every write): no Entering/Leaving pair.
  indexBy: function (row: any): string[] {
    return ApplicationSessions.personKeysOf(row);
  }
});

// The parts of a `realms.map()` store this module uses.
interface EndedStore {
  get(key: string): any;
  set(key: string, value: any): unknown;
  delete(key: string): boolean;
  keys(): IterableIterator<string>;
  readonly size: number;
  lookup?(indexKey: string): string[];
}

interface Person {
  username: string;
  subjectId: string;
}

interface AppNames {
  identifier: string;
  names: string[];
  gnapClient: boolean;
  resourceServer: boolean;
}

interface ApplicationSessionsDeps {
  log: typeof helpers.log;
  config: { value(key: string): unknown };
  errorCodes: { tag(code: string): string };
  realms: { currentId(): string };
  ended: EndedStore;
  now(): number;
  nameForSubject(sub: string): string;
  subjectForName(name: string): string;
  // Lazy requires, each a loader called at the moment it is needed.
  loadAuthn(): any;
  loadApplications(): any;
  loadRisc(): any;
  loadDirectory(): any;
  loadGnapStore(): any;
  loadGnapRevocation(): any;
}

// The formats that name a PERSON here (see the header).
const PERSON_FORMATS = ['iss_sub', 'email', 'phone_number', 'account'];

/**
 * The active-session scope of an application's Shared Signals stream
 * (#2234): which people an application's stream may carry events about.
 */
class ApplicationSessions {
  // realm|username|subject -> the parties of that person's live sessions,
  // for the rest of this turn of the event loop (`memoClear` empties it on a
  // microtask — a per-operation cache, not a timer).
  private memo: Map<string, Set<string> | null> = new Map();
  private memoArmed = false;

  /**
   * Builds the scope from the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: ApplicationSessionsDeps) {
    deps.log.debug("Entering ApplicationSessions.constructor().");
    deps.log.debug("Leaving ApplicationSessions.constructor().");
  }

  // The index keys an ended-session row is filed under. A hot path (every
  // write to the store): no Entering/Leaving pair.
  static personKeysOf(row: any): string[] {
    const out: string[] = [];
    if (row && row.username) {
      out.push('u:' + String(row.username).toLowerCase());
    }
    if (row && row.subjectId) {
      out.push('s:' + String(row.subjectId));
    }
    return out;
  }

  /**
   * Says whether the scope is on: `ssf.applicationStreamScope` is
   * `active-sessions`.
   *
   * @returns true when application streams are scoped
   */
  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering ApplicationSessions.enabled().");
    const on = String(config.value('ssf.applicationStreamScope') ||
                      'active-sessions') !== 'all';
    log.debug("Leaving ApplicationSessions.enabled(). " + on);
    return on;
  }

  /**
   * The names every relying-party list of a sign-on session records it
   * signed into: OpenID Connect / OAuth clients, SAML 2.0 service providers,
   * SAML 1.1 relying parties (and their providerId) and WS-Federation realms.
   *
   * @param session - the session row
   * @returns the party names
   */
  partiesOf(session: any): string[] {
    const { log } = this.deps;
    log.debug("Entering ApplicationSessions.partiesOf().");
    const out: string[] = [];
    const add = function (one: unknown): void {
      const name = String(one || '');
      if (name && out.indexOf(name) < 0) {
        out.push(name);
      }
    };
    if (!session || typeof session !== 'object') {
      log.debug("Leaving ApplicationSessions.partiesOf(). No session.");
      return out;
    }
    ['oidcClients', 'saml2ServiceProviders', 'saml11RelyingParties',
     'wsfedRealms'].forEach(function (field) {
      const list = session[field];
      if (list && typeof list === 'object') {
        Object.keys(list).forEach(add);
      }
    });
    const saml11 = session.saml11RelyingParties;
    if (saml11 && typeof saml11 === 'object') {
      Object.keys(saml11).forEach(function (rp) {
        add(saml11[rp] && saml11[rp].providerId);
      });
    }
    log.debug("Leaving ApplicationSessions.partiesOf(). " + out.length);
    return out;
  }

  /**
   * Keeps the parties a session carried as it ends, so the event that ended
   * it still reaches them (see the header). Called from `ssf.ts`'s session
   * observer on a `revoked` notice, before the event is built. A session
   * that signed into nobody writes nothing. Never throws.
   *
   * @param session - the session row as it was
   */
  noteEnded(session: any): void {
    const { log, ended, now, errorCodes } = this.deps;
    log.debug("Entering ApplicationSessions.noteEnded().");
    try {
      const parties = this.partiesOf(session);
      const noted = session && session.id
        ? ended.get(String(session.id)) : null;
      if (!session || !session.id || (!parties.length && !noted)) {
        log.debug("Leaving ApplicationSessions.noteEnded(). Nobody to tell.");
        return;
      }
      const user = session.user || {};
      // A SESSION NOTED TWICE KEEPS EVERY PARTY EITHER NOTE SAW: a global
      // sign-out notes it before its families take the SAML and WS-Federation
      // parties off it (`logout.ts`'s terminate()), and the session observer
      // notes it again, lists emptied, as it ends.
      const before = ended.get(String(session.id));
      (before && Array.isArray(before.parties) ? before.parties : [])
        .forEach(function (one: string) {
          if (parties.indexOf(one) < 0) {
            parties.push(one);
          }
        });
      ended.set(String(session.id), {
        username: String(user.username || ''),
        subjectId: String(session.subjectId || user.sub || ''),
        parties: parties,
        endedAt: now()
      });
      // THE BOUND IS AT THE INSERT: the oldest rows go first (a realm Map
      // keeps insertion order).
      if (ended.size > MAX_ENDED) {
        const extra = ended.size - MAX_ENDED;
        const keys = ended.keys();
        for (let i = 0; i < extra; i++) {
          const next = keys.next();
          if (next.done) {
            break;
          }
          ended.delete(next.value);
        }
      }
      this.memo.clear();
    } catch (e) {
      log.debug("Caught in ApplicationSessions.noteEnded(): " +
                ((e && e.message) || e));
      // Bookkeeping on a sign-out's path; never allowed to fail one. The
      // ending event then reaches only the applications still signed in.
      log.warn(errorCodes.tag('STS-SSF-0165') + 'ssf: the parties of an ' +
               'ending session could not be kept: ' + e.message);
    }
    log.debug("Leaving ApplicationSessions.noteEnded().");
  }

  /**
   * The application that owns a stream, as the registry knows it, or null
   * for a stream no application owns.
   *
   * @param record - the stream
   * @returns its names and kinds, or null
   */
  applicationOf(record: any): AppNames | null {
    const { log, loadApplications } = this.deps;
    log.debug("Entering ApplicationSessions.applicationOf().");
    if (!record || record.internalSurface || record.ownerPerson ||
        !record.createdBy) {
      log.debug("Leaving ApplicationSessions.applicationOf(). Nobody's.");
      return null;
    }
    const by = String(record.createdBy);
    // A pre-#336 person's stream carries no ownerPerson, only their
    // `urn:uuid:` subject as createdBy; it is a person's, not an
    // application's.
    if (/^urn:uuid:/i.test(by)) {
      log.debug("Leaving ApplicationSessions.applicationOf(). A person's.");
      return null;
    }
    let owner = null;
    try {
      owner = loadApplications().ssfAllowedEventsFor(by);
    } catch (e) {
      log.debug("Caught in ApplicationSessions.applicationOf(): " +
                ((e && e.message) || e));
      // No registry: no application owns it.
      owner = null;
    }
    if (!owner) {
      log.debug("Leaving ApplicationSessions.applicationOf(). No " +
                "application.");
      return null;
    }
    const names = [by, String(owner.identifier || '')]
      .concat(Array.isArray(owner.names) ? owner.names.map(String) : [])
      .filter(function (one, i, all) {
        return !!one && all.indexOf(one) === i;
      });
    const kinds = Array.isArray(owner.kinds) ? owner.kinds : [];
    log.debug("Leaving ApplicationSessions.applicationOf(). " +
              owner.identifier);
    return { identifier: String(owner.identifier || by), names: names,
             gnapClient: kinds.indexOf('gnap-client') >= 0,
             resourceServer: kinds.indexOf('gnap-resource-server') >= 0 };
  }

  // The person a subject names, or null for a subject about no person (see
  // the header). A person nobody here can resolve comes back with both
  // members empty — and has, then, no session here either.
  private personOf(subject: any): Person | null {
    const { log, nameForSubject, subjectForName, loadRisc,
            loadDirectory } = this.deps;
    log.debug("Entering ApplicationSessions.personOf().");
    if (!subject || typeof subject !== 'object') {
      log.debug("Leaving ApplicationSessions.personOf(). No subject.");
      return null;
    }
    if (subject.format === 'complex') {
      const user = subject.user;
      log.debug("Leaving ApplicationSessions.personOf(). Complex.");
      return user && typeof user === 'object' ? this.personOf(user) : null;
    }
    if (subject.format === 'aliases') {
      const list = Array.isArray(subject.identifiers)
        ? subject.identifiers : [];
      let first: Person | null = null;
      for (const one of list) {
        const found = this.personOf(one);
        if (found && (found.username || found.subjectId)) {
          log.debug("Leaving ApplicationSessions.personOf(). An alias.");
          return found;
        }
        first = first || found;
      }
      log.debug("Leaving ApplicationSessions.personOf(). Aliases.");
      return first;
    }
    const format = String(subject.format || subject.subject_type || '');
    if (PERSON_FORMATS.indexOf(format) < 0) {
      log.debug("Leaving ApplicationSessions.personOf(). Not a person.");
      return null;
    }
    if (format === 'iss_sub') {
      // The `sub` is the person's subject even when their entry is gone —
      // an account-purged arrives after the delete — so it is kept as it is.
      const sub = String(subject.sub || '');
      const username = sub ? String(nameForSubject(sub) || '') : '';
      log.debug("Leaving ApplicationSessions.personOf(). iss_sub.");
      return { username: username,
               subjectId: /^urn:uuid:/i.test(sub) ? sub
                 : (username ? String(subjectForName(username) || '') : '') };
    }
    let username = '';
    try {
      username = String(loadRisc().accountIdOf(subject) || '');
    } catch (e) {
      log.debug("Caught in ApplicationSessions.personOf(): " +
                ((e && e.message) || e));
      // No RISC register here: the directory is asked below.
      username = '';
    }
    if (!username && format === 'email' && subject.email) {
      try {
        const directory = loadDirectory();
        username = typeof directory.personByMail === 'function'
          ? String(directory.personByMail(String(subject.email)) || '') : '';
      } catch (e) {
        log.debug("Caught in ApplicationSessions.personOf(): " +
                  ((e && e.message) || e));
        // No directory: an address nobody resolves names nobody here.
        username = '';
      }
    }
    log.debug("Leaving ApplicationSessions.personOf(). " +
              (username || '(unresolved)'));
    return { username: username,
             subjectId: username ? String(subjectForName(username) || '')
                                 : '' };
  }

  // The parties of a person's LIVE sign-on sessions, asked once per turn;
  // null when the sessions could not be read.
  private livePartiesOf(person: Person): Set<string> | null {
    const { log, realms, loadAuthn, now } = this.deps;
    log.debug("Entering ApplicationSessions.livePartiesOf().");
    const key = realms.currentId() + '|' + person.username + '|' +
                person.subjectId;
    if (this.memo.has(key)) {
      log.debug("Leaving ApplicationSessions.livePartiesOf(). This turn.");
      return this.memo.get(key);
    }
    let held = null;
    try {
      held = loadAuthn().sessionsHeldUnder(person.username, person.subjectId);
    } catch (e) {
      log.debug("Caught in ApplicationSessions.livePartiesOf(): " +
                ((e && e.message) || e));
      // Unread, as a null answer is.
      held = null;
    }
    let out: Set<string> | null = null;
    if (Array.isArray(held)) {
      out = new Set();
      const at = now();
      held.forEach((session) => {
        if (!session || session.chosen === false ||
            (Number(session.expires) > 0 && Number(session.expires) <= at)) {
          return;
        }
        this.partiesOf(session).forEach(function (one) {
          out.add(one);
        });
      });
    }
    this.remember(key, out);
    log.debug("Leaving ApplicationSessions.livePartiesOf().");
    return out;
  }

  private remember(key: string, value: Set<string> | null): void {
    const { log } = this.deps;
    log.debug("Entering ApplicationSessions.remember().");
    this.memo.set(key, value);
    if (!this.memoArmed) {
      this.memoArmed = true;
      // Emptied once this turn's synchronous work is done: every stream one
      // event is offered to shares the answer, and the next event asks
      // again. A microtask, not a timer.
      Promise.resolve().then(() => {
        this.memo.clear();
        this.memoArmed = false;
      });
    }
    log.debug("Leaving ApplicationSessions.remember().");
  }

  // The live ended-session rows of a person, or of one session id.
  private endedRows(person: Person | null, sessionId: string): any[] {
    const { log, ended, now } = this.deps;
    log.debug("Entering ApplicationSessions.endedRows().");
    const ids: string[] = [];
    if (sessionId) {
      ids.push(sessionId);
    }
    if (person && typeof ended.lookup === 'function') {
      ApplicationSessions.personKeysOf(person).forEach(function (key) {
        ended.lookup(key).forEach(function (id) {
          if (ids.indexOf(id) < 0) {
            ids.push(id);
          }
        });
      });
    }
    const at = now();
    const out = [];
    ids.forEach(function (id) {
      const row = ended.get(id);
      if (!row) {
        return;
      }
      // THE EXPIRY CHECK IS AT THE READ, whenever a restore last ran.
      if (!(Number(row.endedAt) + ENDED_GRACE_MS > at)) {
        ended.delete(id);
        return;
      }
      out.push(Object.assign({ id: id }, row));
    });
    log.debug("Leaving ApplicationSessions.endedRows(). " + out.length);
    return out;
  }

  // Whether a session id an event names is a session of this application:
  // a sign-on session live or just ended, a GNAP grant or token of its.
  private sessionNamesApplication(sessionId: string,
                                  app: AppNames): boolean {
    const { log, loadAuthn, loadGnapStore } = this.deps;
    log.debug("Entering ApplicationSessions.sessionNamesApplication().");
    const has = (list: string[]): boolean => {
      return list.some(function (one) {
        return app.names.indexOf(one) >= 0;
      });
    };
    const gnap = /^gnap-(grant|token):(.+)$/.exec(sessionId);
    if (gnap) {
      try {
        const store = loadGnapStore();
        let grant = null;
        if (gnap[1] === 'grant') {
          grant = store.getGrant(gnap[2]);
        } else {
          const token = store.tokenByJti(gnap[2]);
          grant = token && token.grantId ? store.getGrant(token.grantId)
                                         : null;
        }
        const named = !!(grant && grant.client &&
                         app.names.indexOf(String(grant.client.identifier)) >=
                         0);
        log.debug("Leaving ApplicationSessions.sessionNamesApplication(). " +
                  "GNAP: " + named);
        return named;
      } catch (e) {
        log.debug("Caught in ApplicationSessions.sessionNamesApplication(): " +
                  ((e && e.message) || e));
        // No GNAP store: a GNAP session names no application here.
        log.debug("Leaving ApplicationSessions.sessionNamesApplication(). " +
                  "No GNAP store.");
        return false;
      }
    }
    let live = null;
    try {
      live = loadAuthn().sessionById(sessionId);
    } catch (e) {
      log.debug("Caught in ApplicationSessions.sessionNamesApplication(): " +
                ((e && e.message) || e));
      // Not found is the same answer: the ended rows are asked next.
      live = null;
    }
    // An arrival session nobody chose is nobody's; an EXPIRED one still in
    // the store is the session its expiry's session-revoked names.
    if (live && live.chosen !== false && has(this.partiesOf(live))) {
      log.debug("Leaving ApplicationSessions.sessionNamesApplication(). " +
                "Live.");
      return true;
    }
    const gone = this.endedRows(null, sessionId).some(function (row) {
      return has(Array.isArray(row.parties) ? row.parties : []);
    });
    log.debug("Leaving ApplicationSessions.sessionNamesApplication(). " +
              "Ended: " + gone);
    return gone;
  }

  // Whether the person holds a live GNAP grant they approved to the
  // application.
  private liveGrant(app: AppNames, person: Person): boolean {
    const { log, loadGnapStore, loadGnapRevocation } = this.deps;
    log.debug("Entering ApplicationSessions.liveGrant().");
    if (!app.gnapClient || !person.username) {
      log.debug("Leaving ApplicationSessions.liveGrant(). Not asked.");
      return false;
    }
    const store = loadGnapStore();
    const revocation = loadGnapRevocation();
    const live = store.grantsApprovedTo(app.identifier, person.username)
      .some(function (grant) {
        return revocation.isLive(grant);
      });
    log.debug("Leaving ApplicationSessions.liveGrant(). " + live);
    return live;
  }

  /**
   * The subject scope registered with `ssf_streams.setSubjectScope()`:
   * whether an application's stream may carry an event about a subject.
   *
   * @param record - the stream
   * @param subject - the event's subject
   * @returns true or false for an application's stream and a subject naming
   *   a person; undefined (no opinion) otherwise
   */
  scope(record: any, subject: any): boolean | undefined {
    const { log, errorCodes } = this.deps;
    log.debug("Entering ApplicationSessions.scope().");
    if (!subject || !this.enabled()) {
      log.debug("Leaving ApplicationSessions.scope(). No opinion.");
      return undefined;
    }
    const app = this.applicationOf(record);
    if (!app || app.resourceServer) {
      log.debug("Leaving ApplicationSessions.scope(). Not an application's " +
                "stream this rule is about.");
      return undefined;
    }
    const person = this.personOf(subject);
    if (!person) {
      log.debug("Leaving ApplicationSessions.scope(). About no person.");
      return undefined;
    }
    const sessionId = subject.format === 'complex' && subject.session &&
      subject.session.format === 'opaque' ? String(subject.session.id || '')
                                          : '';
    try {
      // THE SESSION THE EVENT NAMES, live or just ended: how a sign-out's
      // session-revoked reaches the application whose session it was.
      if (sessionId && this.sessionNamesApplication(sessionId, app)) {
        log.debug("Leaving ApplicationSessions.scope(). The session is " +
                  "the application's.");
        return true;
      }
      if (!person.username && !person.subjectId) {
        log.debug("Leaving ApplicationSessions.scope(). Nobody known here.");
        return false;
      }
      const live = this.livePartiesOf(person);
      if (live === null) {
        log.warn(errorCodes.tag('STS-SSF-0165') + 'ssf: whether ' +
                 (person.username || person.subjectId) + ' has a session ' +
                 'on ' + app.identifier + ' could not be read; the event is ' +
                 'withheld from its stream.');
        log.debug("Leaving ApplicationSessions.scope(). Unread.");
        return false;
      }
      if (app.names.some(function (one) { return live.has(one); })) {
        log.debug("Leaving ApplicationSessions.scope(). A live session.");
        return true;
      }
      if (this.liveGrant(app, person)) {
        log.debug("Leaving ApplicationSessions.scope(). A live GNAP grant.");
        return true;
      }
      const justEnded = this.endedRows(person, '').some(function (row) {
        return (Array.isArray(row.parties) ? row.parties : [])
          .some(function (one) { return app.names.indexOf(one) >= 0; });
      });
      log.debug("Leaving ApplicationSessions.scope(). Just ended: " +
                justEnded);
      return justEnded;
    } catch (e) {
      log.debug("Caught in ApplicationSessions.scope(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-SSF-0165') + 'ssf: whether a person has ' +
               'a session on ' + app.identifier + ' could not be decided (' +
               e.message + '); the event is withheld from its stream.');
      log.debug("Leaving ApplicationSessions.scope(). Failed closed.");
      return false;
    }
  }

  /**
   * Returns the real modules this scope depends on, as the composition root
   * passes them.
   *
   * @returns the dependencies
   */
  static defaultDeps(): ApplicationSessionsDeps {
    log.debug("Entering ApplicationSessions.defaultDeps().");
    log.debug("Leaving ApplicationSessions.defaultDeps().");
    return {
      log: log,
      config: config,
      errorCodes: errorCodes,
      realms: realms,
      ended: ended as unknown as EndedStore,
      now: function () {
        return Date.now();
      },
      nameForSubject: function (sub) {
        return helpers.nameForSubject(sub) || '';
      },
      subjectForName: function (name) {
        return helpers.subjectForName(name) || '';
      },
      loadAuthn: function () {
        return require('../authn/authn');
      },
      loadApplications: function () {
        return require('../common/applications');
      },
      loadRisc: function () {
        return require('./risc');
      },
      // JavaScript, and a route module: reached only at call time in a
      // running service, where it is a cache hit, so it moves no route.
      loadDirectory: function () {
        return require('../ldap/ldap_server');
      },
      loadGnapStore: function () {
        return require('../gnap/gnap_store');
      },
      loadGnapRevocation: function () {
        return require('../gnap/gnap_revocation');
      }
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). The exports below
// are FACADES that forward to it; a process that never runs the root gets a
// default instance, built from `defaultDeps()` (`common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<ApplicationSessions>(
  'ssf/application_sessions',
  () => new ApplicationSessions(ApplicationSessions.defaultDeps()),
  null,
  log);

// Standalone, build the default now.
slot.buildNowUnlessDeferred();

/**
 * The active-session scope of an application's Shared Signals stream.
 *
 * Exports the `ApplicationSessions` class and facades that forward to the
 * installed instance.
 *
 * @namespace
 */
export = {
  ApplicationSessions: ApplicationSessions,
  ENDED_GRACE_MS: ENDED_GRACE_MS,
  /**
   * Installs the instance the facades forward to.
   */
  installInstance: (instance: ApplicationSessions): void =>
    slot.install(instance),
  /**
   * Says where the current instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  enabled: slot.forward('enabled'),
  scope: slot.forward('scope'),
  noteEnded: slot.forward('noteEnded'),
  partiesOf: slot.forward('partiesOf'),
  applicationOf: slot.forward('applicationOf')
};
