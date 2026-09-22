'use strict';
//
// File: gnap_signals.ts
//
// ---------------------------------------------------------------------------
// GNAP AND THE SHARED SIGNALS FRAMEWORK: CAEP FOR GRANTS, AND A STREAM THAT
// HEARS ONLY ABOUT ITS OWN USERS.
//
// The user asked (2026-09-12) for three things and explicitly not a fourth:
//
//   1. **GNAP sessions emit CAEP.** A resource owner signs in through the one
//      authentication service, so `session-established` and `session-revoked`
//      already follow; `gnap_interact.ts` makes the `notePresented()` call when
//      an interaction honours an existing session. Nothing in this file.
//   2. **GNAP web applications are receivers whose streams are SCOPED.** A
//      stream owned by a GNAP client application carries events only about
//      people who approved a grant to that application. `ssf/ssf_streams.ts`
//      offers one hook, `setSubjectScope()`, consulted by
//      `streamCoversSubject()` — the single function every CAEP, RISC and
//      by-hand delivery already asks — and this file fills it.
//   3. **Grant and token revocation emit CAEP.** This REVERSES a documented
//      rule — docs/caep-events.md said revoking a token emits nothing — for
//      GNAP only, and the reason it is not a contradiction is the shape of a
//      GNAP grant: it is a DELEGATED SESSION between a client instance and a
//      resource owner (RFC 9767 section 2.1.13 calls it the grant's current
//      state), with a lifetime, a continuation and a revocation of its own. So
//      a grant revoked is a `session-revoked` whose session is the GRANT, a
//      token revoked is a `session-revoked` whose session is that token, and a
//      grant modified onto different rights is a `token-claims-change`
//      carrying the new `access`.
//   4. NOT: signals revoking grants. Nothing here listens to CAEP or RISC.
//
// **THE SUBJECT IS A COMPLEX ONE, `user` + `session`**, with the session id
// prefixed `gnap-grant:` or `gnap-token:` — the same shape `caep.subjectFor()`
// builds for a sign-on session, so a receiver that already matches
// `session-revoked` by user needs nothing new, and the prefix means a GNAP
// grant id can never be mistaken for a sign-on session id of the same bytes.
//
// **SSF IS REQUIRED LAZILY**, inside the functions that deliver. `ssf/ssf.ts`
// registers every `/ssf` route (rule 1), and this file is required by the
// grant engine, which an in-process test loads with no router at all. Here, at
// call time in a running service, the require is a cache hit.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GnapSignals` takes the logger, the two subject readers, the
// error-code table, the settings, the approver store and a LOADER for each
// module it requires lazily (so each require stays lazy) through its
// constructor. The approver store is still declared at module scope, as
// `realms.map()`, because a store becomes per realm at its declaration. The
// module still exports its old names as FACADES forwarding to the instance the
// composition root builds (#50, R2), for the unconverted modules that require
// it. A process that loads this module without the root builds a default
// instance when the module loads.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import config = require('../common/config');

// The parts of a `realms.map()` store this module uses.
interface ApproverStore {
  has(key: string): boolean;
  get(key: string): string[] | undefined;
  set(key: string, list: string[]): unknown;
}

interface GnapSignalsDeps {
  log: {
    debug(message: string): void;
    error(message: string): void;
  };
  userFor(username: string): { sub: string };
  nameForSubject(sub: string): string | null | undefined;
  errorCodes: { tag(code: string): string };
  config: { value(key: string): unknown };
  approvers: ApproverStore;
  // Lazy requires, each a loader called at the moment it is needed.
  loadConsent(): any;
  loadSsfHttp(): any;
  loadSsf(): any;
  loadApplications(): any;
  loadSsfStreams(): any;
}

// WHO APPROVED WHICH APPLICATION, for the scope. The durable record is the
// consent register (gnap_grants.ts's header); this is its index for the one
// case the register cannot answer — `gnap.rememberApprovals` off, where no
// consent is written and a person who approved a grant must still be a person
// the application's stream may hear about. Persisted like every GNAP store.
const approvers = realms.map({ persist: 'gnap.approvers' });

class GnapSignals {
  constructor(private readonly deps: GnapSignalsDeps) {
    deps.log.debug("Entering GnapSignals.constructor().");
    deps.log.debug("Leaving GnapSignals.constructor().");
  }

  noteApprover(identifier: unknown, username: unknown): void {
    const { log, errorCodes, approvers } = this.deps;
    log.debug("Entering GnapSignals.noteApprover().");
    try {
      const key = String(identifier);
      const list = approvers.has(key) ? approvers.get(key).slice() : [];
      const name = String(username || '').toLowerCase();
      if (name && list.indexOf(name) < 0) {
        list.push(name);
        approvers.set(key, list.slice(-5000));
      }
    } catch (e) {
      log.debug("Caught in GnapSignals.noteApprover(): " +
                ((e && e.message) || e));
      // Bookkeeping on the path of an approval; never allowed to fail one.
      log.error(errorCodes.tag('STS-GNAP-0700') + 'gnap: an approver could ' +
                'not be recorded: ' + e.message);
    }
    log.debug("Leaving GnapSignals.noteApprover().");
  }

  approvedBy(identifier: unknown, username: unknown): boolean {
    const { log, approvers, loadConsent } = this.deps;
    log.debug("Entering GnapSignals.approvedBy().");
    const name = String(username || '').toLowerCase();
    if (!name) {
      log.debug("Leaving GnapSignals.approvedBy().");
      return false;
    }
    const list = approvers.get(String(identifier)) || [];
    if (list.indexOf(name) >= 0) {
      log.debug("Leaving GnapSignals.approvedBy().");
      return true;
    }
    try {
      log.debug("Leaving GnapSignals.approvedBy().");
      return loadConsent().consentsOf(name).some(function (row) {
        return row.client === String(identifier) &&
               String(row.scope).indexOf('gnap:') === 0;
      });
    } catch (e) {
      log.debug("Caught in GnapSignals.approvedBy(): " +
                ((e && e.message) || e));
      // No consent register reachable; the index above is the whole answer.
      log.debug("approvedBy(): the consent register could not be read: " +
                e.message);
      log.debug("Leaving GnapSignals.approvedBy().");
      return false;
    }
  }

  private subjectFor(req: unknown, username: string, sessionId: string) {
    const { log, userFor, loadSsfHttp } = this.deps;
    log.debug("Entering GnapSignals.subjectFor().");
    const transport = loadSsfHttp();
    log.debug("Leaving GnapSignals.subjectFor().");
    // SSF 1.0 final's complex subject, `"format": "complex"` included.
    return {
      format: 'complex',
      user: { format: 'iss_sub',
              iss: transport.transmitterIssuer(req),
              sub: userFor(username).sub },
      session: { format: 'opaque', id: sessionId }
    };
  }

  // Deliver one CAEP event to every stream that takes it. Never rejects.
  private emit(req: unknown, type: string, username: string,
               sessionId: string, values: object,
               reason: string): Promise<any> {
    const { log, errorCodes, config, loadSsf } = this.deps;
    log.debug("Entering GnapSignals.emit(). type=" + type);
    if (!username || config.value('gnap.caepEvents') === false) {
      log.debug("Leaving GnapSignals.emit(). No resource owner, or GNAP " +
                "CAEP events are off.");
      return Promise.resolve({ sent: 0 });
    }
    let ssf;
    try {
      ssf = loadSsf();
    } catch (e) {
      log.debug("Caught in GnapSignals.emit(): " + ((e && e.message) || e));
      // No SSF family in this process (an in-process test): nothing to
      // deliver to.
      log.debug("Leaving GnapSignals.emit(). SSF is not loaded: " +
                e.message);
      return Promise.resolve({ sent: 0 });
    }
    if (typeof ssf.emitProtocolEvent !== 'function') {
      log.debug("Leaving GnapSignals.emit(). This SSF build has no protocol " +
                "emission.");
      return Promise.resolve({ sent: 0 });
    }
    log.debug("Leaving GnapSignals.emit(). Delivering.");
    return Promise.resolve(ssf.emitProtocolEvent({
      req: req, protocol: 'GNAP', type: type,
      subject: this.subjectFor(req, username, sessionId),
      values: values || {}, initiatingEntity: 'system',
      reasonAdmin: reason, reasonUser: reason
    })).catch(function (e) {
      log.debug("Caught in GnapSignals.emit(): " + ((e && e.message) || e));
      log.error(errorCodes.tag('STS-GNAP-0701') + 'gnap: a CAEP ' + type +
                ' ' + 'could not be delivered: ' +
                e.message);
      return { sent: 0, why: e.message };
    });
  }

  grantRevoked(req: unknown, grant: any, reason?: string): Promise<any> {
    const { log } = this.deps;
    log.debug("Entering GnapSignals.grantRevoked().");
    log.debug("Leaving GnapSignals.grantRevoked().");
    return this.emit(req, 'session-revoked', grant.ro && grant.ro.username,
                     'gnap-grant:' + grant.id, {},
                     reason || 'A GNAP grant was revoked.');
  }

  tokenRevoked(req: unknown, record: any, grant?: any): Promise<any> {
    const { log } = this.deps;
    log.debug("Entering GnapSignals.tokenRevoked().");
    const username = record.username ||
      (grant && grant.ro && grant.ro.username);
    log.debug("Leaving GnapSignals.tokenRevoked().");
    return this.emit(req, 'session-revoked', username,
                     'gnap-token:' + record.jti, {},
                     'A GNAP access token was revoked by its client ' +
                     'instance.');
  }

  grantModified(req: unknown, grant: any, access: unknown): Promise<any> {
    const { log } = this.deps;
    log.debug("Entering GnapSignals.grantModified().");
    log.debug("Leaving GnapSignals.grantModified().");
    return this.emit(req, 'token-claims-change',
                     grant.ro && grant.ro.username,
                     'gnap-grant:' + grant.id,
                     { claims: { access: access } }, 'A GNAP grant was ' +
                                                     'modified onto ' +
                                                     'different access.');
  }

  // -------------------------------------------------------------------------
  // THE SCOPE. `(record, subject) -> true | false | undefined`: undefined
  // means "not a GNAP-owned stream; this file has no opinion", which is every
  // stream that existed before this feature.
  // -------------------------------------------------------------------------
  usernameOf(subjectValue: any): string | null {
    const { log, nameForSubject } = this.deps;
    log.debug("Entering GnapSignals.usernameOf().");
    if (!subjectValue || typeof subjectValue !== 'object') {
      log.debug("Leaving GnapSignals.usernameOf().");
      return null;
    }
    const one = subjectValue.format === 'complex' ? subjectValue.user
                                                  : subjectValue;
    if (!one) {
      log.debug("Leaving GnapSignals.usernameOf().");
      return null;
    }
    const sub = String(one.sub || one.uri || '');
    // Either subject form this service issued — see
    // `helpers.nameForSubject()`.
    const named = nameForSubject(sub);
    if (named) {
      log.debug("Leaving GnapSignals.usernameOf().");
      return named;
    }
    if (one.email) {
      log.debug("Leaving GnapSignals.usernameOf().");
      return String(one.email).split('@')[0];
    }
    if (one.format === 'account' && one.uri) {
      const match = String(one.uri).match(/^acct:([^@]+)@/);
      log.debug("Leaving GnapSignals.usernameOf().");
      return match ? match[1] : null;
    }
    log.debug("Leaving GnapSignals.usernameOf().");
    return null;
  }

  scope(record: any, subjectValue: any): boolean | undefined {
    const { log, config, loadApplications } = this.deps;
    log.debug("Entering GnapSignals.scope().");
    if (config.value('gnap.scopedSignals') === false || !record ||
        !record.createdBy || !subjectValue) {
      log.debug("Leaving GnapSignals.scope().");
      return undefined;
    }
    let app = null;
    try {
      app = loadApplications().get(String(record.createdBy));
    } catch (e) {
      log.debug("Caught in GnapSignals.scope(): " + ((e && e.message) || e));
      log.debug("Leaving GnapSignals.scope().");
      // No registry: no opinion.
      return undefined;
    }
    if (!app || (app.kinds || []).indexOf('gnap-client') < 0) {
      log.debug("Leaving GnapSignals.scope().");
      return undefined;
    }
    const fields = app.fields || {};
    if (String(fields.gnapScopedSignals || '').toUpperCase() === 'FALSE') {
      log.debug("Leaving GnapSignals.scope().");
      return undefined;
    }
    // A WEB APPLICATION is the population the user named: a client that
    // finishes an interaction in a browser or by push has a finish URI on its
    // entry.
    if (!fields.gnapFinishUri ||
        (Array.isArray(fields.gnapFinishUri) &&
         !fields.gnapFinishUri.length)) {
      log.debug("Leaving GnapSignals.scope().");
      return undefined;
    }
    const username = this.usernameOf(subjectValue);
    log.debug("Leaving GnapSignals.scope().");
    return username ? this.approvedBy(app.identifier, username) : false;
  }

  install(): boolean {
    const { log, loadSsfStreams } = this.deps;
    log.debug("Entering GnapSignals.install().");
    try {
      const streams = loadSsfStreams();
      if (typeof streams.setSubjectScope === 'function') {
        // Bound, because ssf_streams calls the scope as a plain function.
        streams.setSubjectScope('gnap', this.scope.bind(this));
        log.debug("Leaving GnapSignals.install().");
        return true;
      }
    } catch (e) {
      log.debug("Caught in GnapSignals.install(): " +
                ((e && e.message) || e));
      // SSF absent in this process; the scope is simply not installed.
      log.debug("install(): ssf_streams is not loadable: " + e.message);
    }
    log.debug("Leaving GnapSignals.install().");
    return false;
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before. The loaders keep every require
  // as lazy as it was.
  static defaultDeps(): GnapSignalsDeps {
    helpers.log.debug("Entering GnapSignals.defaultDeps().");
    helpers.log.debug("Leaving GnapSignals.defaultDeps().");
    return {
      log: helpers.log,
      userFor: helpers.userFor,
      nameForSubject: helpers.nameForSubject,
      errorCodes: errorCodes,
      config: config,
      approvers: approvers,
      loadConsent: function () {
        return require('../common/consent');
      },
      loadSsfHttp: function () {
        return require('../ssf/ssf_http');
      },
      loadSsf: function () {
        return require('../ssf/ssf');
      },
      loadApplications: function () {
        return require('../common/applications');
      },
      loadSsfStreams: function () {
        return require('../ssf/ssf_streams');
      }
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GnapSignals>(
  'gnap/gnap_signals',
  () => new GnapSignals(GnapSignals.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  GnapSignals: GnapSignals,
  installInstance: (instance: GnapSignals): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  noteApprover: slot.forward('noteApprover'),
  approvedBy: slot.forward('approvedBy'),
  grantRevoked: slot.forward('grantRevoked'),
  tokenRevoked: slot.forward('tokenRevoked'),
  grantModified: slot.forward('grantModified'),
  scope: slot.forward('scope'),
  usernameOf: slot.forward('usernameOf'),
  install: slot.forward('install')
};
