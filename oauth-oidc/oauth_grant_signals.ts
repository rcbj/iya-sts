'use strict';
//
// File: oauth_grant_signals.ts
//
// ---------------------------------------------------------------------------
// AN OAUTH GRANT REVOKED IS CAEP's `session-revoked` ABOUT THE GRANT (#239,
// 2026-09-26).
//
// GNAP has said this since 2026-09-12 (`gnap/gnap_signals.ts`): a grant is a
// DELEGATED SESSION between a client and the person who granted it, with a
// lifetime, a renewal and a revocation of its own, so its revocation is a
// `session-revoked` whose session is the GRANT. An OAuth 2.0 grant is the same
// thing under another protocol's words — RFC 6749 section 1.5's refresh token
// "represents an authorization granted to the client by the resource owner" —
// and until this file an OAuth grant revoked at `/oauth2/revoke`, by Grant
// Management's DELETE, by a refresh-token REPLAY, by a consent withdrawn or on
// `/admin/tokens` sent nothing, while the same act on a GNAP grant did.
//
// **ONE OBSERVER, ON THE ONE REVOCATION SET.** Every one of those doors
// revokes through `common/admin_stats.js`'s `revoke()` / `revokeWhere()`, and
// this file fills that module's `setRevocationObserver()` slot (its header
// argues the slot) — so a door added later cannot forget to report, because
// no door reports: the set does.
//
// **ONE EVENT PER GRANT, NOT PER TOKEN.** A door revokes a grant as a list of
// jtis — the refresh token, its family, the access tokens minted beside them
// — and a receiver is to be told that ONE session ended. So a revocation is
// queued, the queue is flushed once the door's synchronous act has finished
// (a microtask, so nothing waits and nothing repeats), and each grant is
// announced once per process (a bounded register below). What names the
// grant is what the issuer stated when it minted the token
// (`oauth2.ts`'s `issuanceContext()`, recorded as `grantId`): the Grant
// Management `grant_id` a client was handed, else the refresh-token family,
// else the one token response.
//
// **WHICH REVOCATIONS END A GRANT.** A refresh token revoked, or an access
// token revoked whose grant holds no refresh token (`grantRefresh`): either
// way nothing is left that can renew it. An access token revoked beside a
// live refresh token ends that token and not the grant — RFC 7009 section
// 2.1 leaves the refresh token alone — and is NOT reported. A refresh token
// retired by ROTATION, or refused because its Grant Management grant was
// merged or replaced, is `superseded`: its successor carries the grant on.
// An ID Token, a GNAP token (GNAP reports its own) and a token with no person
// behind it (client credentials: CAEP's subject here names a person) are
// not reported either.
//
// **WHO ENDED IT is the door's own statement**, `how.initiatingEntity`, never
// inferred from the words of `via`: `user` at `/oauth2/revoke`, a Grant
// Management DELETE, a consent the person withdrew and their own `/logout`;
// `admin` at `/admin/tokens`, the console's Grant Management and consent
// controls and every console or API logout; `policy` for a replay and a
// refresh refused because its consent is gone. A door that says nothing is
// `system`.
//
// **A REPLAY IS ALSO A RISK SIGNAL.** A refresh token presented after it was
// rotated (RFC 9700 section 2.2.2), or an authorization code redeemed twice
// (section 4.5), means a copy of the grant's credential is in two hands —
// which is the one fact a receiver most needs and a `session-revoked` alone
// does not say. So a replay sends CAEP's `risk-level-change` about the same
// grant FIRST — `principal: SESSION`, `current_level: HIGH`, `risk_reason`
// naming the replay — and then the `session-revoked`, both `policy`. The
// person's own risk standing is the risk engine's and is not written here.
//
// **HELD TO CAEP's OWN SWITCHES**: `session-revoked` only while
// `caep.autoEmitTypes` names it, and the risk signal only while it names
// `risk-level-change` — the settings every automatic CAEP event already
// obeys. Delivery is `ssf.emitProtocolEvent()`, GNAP's, and never rejects.
//
// **SSF IS REQUIRED LAZILY**, at the flush, for `gnap_signals.ts`'s reason:
// `admin_stats.js` is loaded by everything and an in-process test loads this
// file with no router. In a running service the require is a cache hit.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import stats = require('../common/admin_stats');

type Json = any;

// What a door states about its act (`admin_stats.revoke()`'s third
// argument).
interface RevocationHow {
  initiatingEntity?: string;
  superseded?: boolean;
  replay?: string;
}

interface Pending {
  realmId: string;
  grantId: string;
  username: string;
  sub: string;
  clientId: string;
  via: string;
  initiatingEntity: string;
  replay: string;
}

interface OAuthGrantSignalsDeps {
  log: {
    debug(message: string): void;
    info(message: string): void;
    error(message: string): void;
  };
  errorCodes: { tag(code: string): string };
  realms: {
    currentId(): string;
    get(id: string): unknown;
    run(realm: unknown, fn: () => unknown): unknown;
  };
  subjectForName(username: string): string | null | undefined;
  stats: { setRevocationObserver(fn: unknown): void };
  // Lazy requires, each a loader called at the moment it is needed.
  loadSsf(): Json;
  loadSsfHttp(): Json;
  loadCaep(): Json;
}

// The kinds whose revocation can end an OAuth grant.
const GRANT_KINDS = ['access_token', 'refresh_token'];

// CAEP section 2's four values; anything else a door says is `system`.
const ENTITIES = ['admin', 'user', 'policy', 'system'];

// How many grants one process remembers having announced, per realm. A grant
// forgotten to the cap and revoked again is announced again, which a
// receiver is told to be idempotent about (CAEP section 3.1).
const ANNOUNCED_CAP = 5000;

class OAuthGrantSignals {
  private pending: Map<string, Pending> = new Map();
  private flushing: Promise<Json[]> | null = null;
  private announced: Map<string, Map<string, number>> = new Map();

  constructor(private readonly deps: OAuthGrantSignalsDeps) {
    deps.log.debug("Entering OAuthGrantSignals.constructor().");
    deps.log.debug("Leaving OAuthGrantSignals.constructor().");
  }

  // -------------------------------------------------------------------------
  // THE OBSERVER `admin_stats.revoke()` CALLS, once per jti newly revoked.
  // Decides whether the revocation ends a grant and queues it; never throws
  // on its own account and sends nothing itself.
  // -------------------------------------------------------------------------
  observe(record: Json, via: unknown, how?: RevocationHow): boolean {
    const { log, realms } = this.deps;
    log.debug("Entering OAuthGrantSignals.observe().");
    const said = how || {};
    const r = record || {};
    const kind = String(r.kind || '');
    if (said.superseded) {
      log.debug("Leaving OAuthGrantSignals.observe(). Superseded, not " +
                "ended.");
      return false;
    }
    if (GRANT_KINDS.indexOf(kind) < 0) {
      log.debug("Leaving OAuthGrantSignals.observe(). A " +
                (kind || 'token of no known kind') + " ends no OAuth grant.");
      return false;
    }
    if (kind === 'access_token' && r.grantRefresh === true) {
      log.debug("Leaving OAuthGrantSignals.observe(). An access token; its " +
                "grant's refresh token carries the grant on.");
      return false;
    }
    const username = String(r.username || '');
    if (!username) {
      log.debug("Leaving OAuthGrantSignals.observe(). No person behind " +
                "this grant.");
      return false;
    }
    const grantId = String(r.grantId || r.setId || r.jti || '');
    const realmId = String(realms.currentId() || '');
    const key = realmId + '\n' + grantId;
    const entity = ENTITIES.indexOf(String(said.initiatingEntity || '')) >= 0
      ? String(said.initiatingEntity) : 'system';
    const held = this.pending.get(key);
    if (held) {
      // One act revokes a grant as several jtis; the first names the act,
      // and a replay anywhere in it makes it a replay.
      held.replay = held.replay || String(said.replay || '');
      log.debug("Leaving OAuthGrantSignals.observe(). Already queued.");
      return true;
    }
    this.pending.set(key, {
      realmId: realmId, grantId: grantId, username: username,
      sub: String(r.sub || ''), clientId: String(r.client_id || ''),
      via: String(via || 'unstated'), initiatingEntity: entity,
      replay: String(said.replay || '')
    });
    this.scheduleFlush();
    log.debug("Leaving OAuthGrantSignals.observe(). Queued grant " +
              grantId + ".");
    return true;
  }

  // Once the door's own synchronous act has finished. A microtask: nothing
  // waits on it and nothing repeats (`tests/no_periodic_timers.js`).
  private scheduleFlush(): void {
    const { log } = this.deps;
    log.debug("Entering OAuthGrantSignals.scheduleFlush().");
    if (!this.flushing) {
      this.flushing = Promise.resolve().then(() => {
        return this.flush();
      });
    }
    log.debug("Leaving OAuthGrantSignals.scheduleFlush().");
  }

  // What the queue became. For the tests, which await it; the service never
  // does.
  settled(): Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering OAuthGrantSignals.settled().");
    log.debug("Leaving OAuthGrantSignals.settled().");
    return this.flushing || Promise.resolve([]);
  }

  private flush(): Promise<Json[]> {
    const { log, realms } = this.deps;
    log.debug("Entering OAuthGrantSignals.flush().");
    const due = Array.from(this.pending.values());
    this.pending.clear();
    this.flushing = null;
    const sent = due.filter((one) => {
      return this.firstAnnouncement(one);
    }).map((one) => {
      const realm = realms.get(one.realmId);
      return Promise.resolve(realm
        ? realms.run(realm, () => {
          return this.announce(one);
        })
        : this.announce(one));
    });
    log.debug("Leaving OAuthGrantSignals.flush(). " + sent.length +
              " grant(s).");
    return Promise.all(sent);
  }

  private firstAnnouncement(one: Pending): boolean {
    const { log } = this.deps;
    log.debug("Entering OAuthGrantSignals.firstAnnouncement().");
    let seen = this.announced.get(one.realmId);
    if (!seen) {
      seen = new Map();
      this.announced.set(one.realmId, seen);
    }
    if (seen.has(one.grantId)) {
      log.debug("Leaving OAuthGrantSignals.firstAnnouncement(). Already " +
                "announced.");
      return false;
    }
    seen.set(one.grantId, Date.now());
    while (seen.size > ANNOUNCED_CAP) {
      seen.delete(seen.keys().next().value);
    }
    log.debug("Leaving OAuthGrantSignals.firstAnnouncement().");
    return true;
  }

  // SSF 1.0 section 3.3's complex subject, GNAP's shape: the person, and the
  // grant as the session, prefixed so it cannot be read as a sign-on
  // session's id of the same bytes.
  subjectFor(one: Pending): Json {
    const { log, subjectForName, loadSsfHttp } = this.deps;
    log.debug("Entering OAuthGrantSignals.subjectFor().");
    const transport = loadSsfHttp();
    log.debug("Leaving OAuthGrantSignals.subjectFor().");
    return {
      format: 'complex',
      user: { format: 'iss_sub', iss: transport.transmitterIssuer(null),
              sub: subjectForName(one.username) || one.sub || one.username },
      session: { format: 'opaque', id: 'oauth-grant:' + one.grantId }
    };
  }

  private reasonUser(one: Pending): string {
    const { log } = this.deps;
    log.debug("Entering OAuthGrantSignals.reasonUser().");
    const app = one.clientId ? '"' + one.clientId + '"' : 'an application';
    let said = 'The access you gave ' + app + ' was revoked.';
    if (one.replay) {
      said = 'The access you gave ' + app + ' was ended because its ' +
             'credentials were used twice, which means a copy of them may ' +
             'be in somebody else\'s hands.';
    } else if (one.initiatingEntity === 'admin') {
      said = 'An administrator revoked the access you gave ' + app + '.';
    } else if (one.initiatingEntity === 'policy') {
      said = 'The access you gave ' + app + ' was ended by this service\'s ' +
             'policy.';
    }
    log.debug("Leaving OAuthGrantSignals.reasonUser().");
    return said;
  }

  // The events one grant's end sends: the risk signal first where it was a
  // replay, then `session-revoked`. Never rejects.
  announce(one: Pending): Promise<Json> {
    const { log, errorCodes, loadSsf, loadCaep } = this.deps;
    log.debug("Entering OAuthGrantSignals.announce(). grant=" + one.grantId);
    let ssf: Json = null;
    let acts: string[] = [];
    try {
      ssf = loadSsf();
      acts = loadCaep().autoEmitActs();
    } catch (e) {
      log.debug("Caught in OAuthGrantSignals.announce(): " +
                ((e && e.message) || e));
      // No SSF family in this process (an in-process test): nothing to
      // deliver to.
      log.debug("Leaving OAuthGrantSignals.announce(). SSF is not loaded.");
      return Promise.resolve({ sent: 0, why: 'no SSF' });
    }
    if (acts.indexOf('revoked') < 0 ||
        typeof ssf.emitProtocolEvent !== 'function') {
      log.info('caep: OAuth grant ' + one.grantId + ' of "' + one.clientId +
               '" was revoked and NO session-revoked was sent: caep.enabled, ' +
               'caep.autoEmit or caep.autoEmitTypes excludes it.');
      log.debug("Leaving OAuthGrantSignals.announce(). Not an emitted act.");
      return Promise.resolve({ sent: 0, why: 'not emitted' });
    }
    const subject = this.subjectFor(one);
    const reasonAdmin = 'An OAuth 2.0 grant of "' + one.clientId + '" for ' +
                        one.username + ' was revoked: ' + one.via + '.';
    const reasonUser = this.reasonUser(one);
    const risk = one.replay && acts.indexOf('risk') >= 0
      ? Promise.resolve(ssf.emitProtocolEvent({
        req: null, protocol: 'OAuth 2.0', type: 'risk-level-change',
        subject: subject,
        values: { principal: 'SESSION', current_level: 'HIGH',
                  risk_reason: one.replay },
        initiatingEntity: 'policy', reasonAdmin: reasonAdmin,
        reasonUser: reasonUser }))
      : Promise.resolve(null);
    log.debug("Leaving OAuthGrantSignals.announce(). Delivering.");
    return risk.then(function (riskSent: Json) {
      return Promise.resolve(ssf.emitProtocolEvent({
        req: null, protocol: 'OAuth 2.0', type: 'session-revoked',
        subject: subject, values: {},
        initiatingEntity: one.initiatingEntity,
        reasonAdmin: reasonAdmin, reasonUser: reasonUser
      })).then(function (revokedSent: Json) {
        return { grant: one.grantId, risk: riskSent, revoked: revokedSent };
      });
    }).catch(function (e: Json) {
      log.debug("Caught in OAuthGrantSignals.announce(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-OAUTH-0786') + 'oauth2: a CAEP event ' +
                'about the revoked OAuth grant ' + one.grantId + ' could not ' +
                'be delivered: ' + ((e && e.message) || e));
      return { grant: one.grantId, sent: 0, why: String((e && e.message) ||
                                                        e) };
    });
  }

  // The slot this file fills (`admin_stats.setRevocationObserver()`).
  install(): void {
    const { log, stats } = this.deps;
    log.debug("Entering OAuthGrantSignals.install().");
    stats.setRevocationObserver(this.observe.bind(this));
    log.debug("Leaving OAuthGrantSignals.install().");
  }

  // What the composition root passes (#50, R2): the real modules, each lazy
  // one behind a loader.
  static defaultDeps(): OAuthGrantSignalsDeps {
    helpers.log.debug("Entering OAuthGrantSignals.defaultDeps().");
    helpers.log.debug("Leaving OAuthGrantSignals.defaultDeps().");
    return {
      log: helpers.log,
      errorCodes: errorCodes,
      realms: realms,
      subjectForName: helpers.subjectForName,
      stats: stats,
      loadSsf: function () {
        return require('../ssf/ssf');
      },
      loadSsfHttp: function () {
        return require('../ssf/ssf_http');
      },
      loadCaep: function () {
        return require('../ssf/caep');
      }
    };
  }

  // What loading this module does with its instance: fill the slot.
  static wire(instance: OAuthGrantSignals): void {
    helpers.log.debug("Entering OAuthGrantSignals.wire().");
    instance.install();
    helpers.log.debug("Leaving OAuthGrantSignals.wire().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `gnap/gnap_signals.ts`. Standalone, the default is built and wired when the
// module loads, which fills the slot.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<OAuthGrantSignals>(
  'oauth-oidc/oauth_grant_signals',
  () => new OAuthGrantSignals(OAuthGrantSignals.defaultDeps()),
  OAuthGrantSignals.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  OAuthGrantSignals: OAuthGrantSignals,
  installInstance: (instance: OAuthGrantSignals): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  observe: slot.forward('observe'),
  settled: slot.forward('settled'),
  announce: slot.forward('announce')
};
