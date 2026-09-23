'use strict';
//
// File: ciba.ts
//
// ===========================================================================
// OPENID CONNECT CLIENT-INITIATED BACKCHANNEL AUTHENTICATION (CIBA) CORE 1.0
// (#131, 2026-09-23) — THE REQUESTS, THEIR APPROVAL AND THE NOTIFICATIONS.
//
// A client that cannot put a browser in front of the person — a call centre,
// a point of sale — asks this service to authenticate them ELSEWHERE. The
// request names the person by a hint; the person approves it on a device of
// their own; and the client collects tokens by polling, is pinged to collect
// them, or has them pushed. `oauth-oidc/oauth2.ts` owns the two doors — the
// Backchannel Authentication Endpoint (`POST /oauth2/bc-authorize`, section
// 7) and the `urn:openid:params:grant-type:ciba` grant (section 10) — because
// client authentication and token issuance live there; this file owns what
// they share.
//
// rcbj's answers (#131):
//
//   * **THE AUTHENTICATION DEVICE IS THE PORTAL** (section 8): a "Sign-in
//     requests" page (`portal/portal_ciba.ts`) lists the requests waiting
//     for the signed-in person — the client, the scopes, the
//     `binding_message` — with Approve and Deny. Nothing leaves the service
//     to reach the person; a push to a registered device waits for #164.
//   * **ALL THREE DELIVERY MODES** (section 10): poll, ping and push. A ping
//     or a push is a DELIVERY — a persisted row sent once for the cluster
//     under a claimed lease, retried by the `oauth2.ciba-sweep` scheduler job
//     and dead-lettered, back-channel logout's arrangement — through
//     `federation_http.deliverJson()`, so the outbound policy applies to the
//     client's registered notification endpoint as to every address this
//     service sends something to.
//   * **THE APPROVAL IS AS STRONG AS `acr_values` ASKS** (RFC 9470's levels,
//     `step_up.ts`): a live sign-on session is enough unless the request
//     demands more, and then the person signs in again with what it asks
//     before the Approve button takes.
//   * **DEVELOPMENT RELAXES NOTHING**: an unknown hint is `unknown_user_id`
//     and a hint token is verified in both modes. Tests approve through the
//     portal, or through `/admin-api`'s test control, which product closes.
//
// **THE REQUEST IS A ROW** in `oauth2.cibaRequests`, per realm, persisted and
// shared where this service persists what it mints, keyed by its
// `auth_req_id` — 256 random bits, so the id is also the only credential the
// token request needs beside the client's. Its states: `pending` →
// `approved` or `denied` → `redeemed`, and `expired` once `expiresAt` passes.
// Redemption is a cluster claim (`oauth.ciba`), so one approval is one token
// response however many nodes are polled.
//
// **ABUSE** (sections 12 and 14): a person has at most
// `oauth2.cibaMaxPendingPerPerson` requests waiting, the rest refused
// `access_denied`, so a client cannot fill somebody's page; the page shows
// the client and the binding message so the person can tell whose request it
// is; and only the hinted person sees or answers it.
//
// A LIBRARY (rule 3): it registers no route. It reaches `oauth2.ts` LAZILY,
// once, to mint a push's tokens at the moment of approval.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import clusterClaims = require('../cluster/cluster_claims');
import fedHttp = require('../federation/federation_http');
import credentials = require('../common/credentials');
import stsCrypto = require('../common/crypto');

type Json = any;

// The two stores. PER TRUST REALM, persisted where minted rows are.
const requests = realms.map({ persist: 'oauth2.cibaRequests',
                              retain: 'age' });
const deliveries = realms.map({ persist: 'oauth2.cibaDeliveries',
                                retain: 'age' });

const GRANT_TYPE = 'urn:openid:params:grant-type:ciba';
const MODES = Object.freeze(['poll', 'ping', 'push']);
const SWEEP_JOB = 'oauth2.ciba-sweep';
const ATTEMPT_SCOPE = 'oauth.ciba-notify';
const REDEEM_SCOPE = 'oauth.ciba';
const ADDRESS_ATTRIBUTE = 'oauthBackchannelClientNotificationEndpoint';
// How long a finished request or delivery is kept, for the console and for
// a late poll to be told what happened rather than "unknown".
const RETENTION_MS = 60 * 60 * 1000;

interface CibaDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  claims: typeof clusterClaims;
  fedHttp: typeof fedHttp;
  credentials: typeof credentials;
  stsCrypto: typeof stsCrypto;
  now: () => number;
}

class Ciba {
  static readonly GRANT_TYPE = GRANT_TYPE;
  static readonly MODES = MODES;

  constructor(private readonly deps: CibaDeps) {
    deps.log.debug("Entering Ciba.constructor().");
    deps.log.debug("Leaving Ciba.constructor().");
  }

  static defaultDeps(): CibaDeps {
    helpers.log.debug("Entering Ciba.defaultDeps().");
    helpers.log.debug("Leaving Ciba.defaultDeps().");
    return { log: helpers.log, config: config, realms: realms,
             errorCodes: errorCodes, audit: audit, claims: clusterClaims,
             fedHttp: fedHttp, credentials: credentials,
             stsCrypto: stsCrypto, now: Date.now };
  }

  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering Ciba.enabled().");
    log.debug("Leaving Ciba.enabled().");
    return config.value('oauth2.ciba') === true;
  }

  private setting(key: string): number {
    const { log, config } = this.deps;
    log.debug("Entering Ciba.setting(). " + key);
    log.debug("Leaving Ciba.setting().");
    return Number(config.value(key));
  }

  // -------------------------------------------------------------------------
  // THE PERSON'S USER CODE (section 7.1's `user_code`): a secret they set on
  // /portal/ciba, hashed like a password, which a request from a client that
  // registered `backchannel_user_code_parameter` must carry. 4 to 64
  // characters; '' clears it.
  // -------------------------------------------------------------------------
  setUserCode(username: unknown, code: unknown): Json {
    const { log, credentials, stsCrypto } = this.deps;
    log.debug("Entering Ciba.setUserCode().");
    const text = String(code || '');
    if (text && (text.length < 4 || text.length > 64)) {
      log.debug("Leaving Ciba.setUserCode(). Wrong length.");
      return { ok: false, error: 'a user code is 4 to 64 characters.' };
    }
    const written = credentials.writeCibaUserCode(String(username || ''),
      text ? stsCrypto.hashSecret(text) : '');
    log.debug("Leaving Ciba.setUserCode(). " + written);
    return written ? { ok: true, set: !!text } :
      { ok: false, error: 'the directory did not store it.' };
  }

  hasUserCode(username: unknown): boolean {
    const { log, credentials } = this.deps;
    log.debug("Entering Ciba.hasUserCode().");
    log.debug("Leaving Ciba.hasUserCode().");
    return !!credentials.readCibaUserCode(String(username || ''));
  }

  userCodeMatches(username: unknown, code: unknown): boolean {
    const { log, credentials, stsCrypto } = this.deps;
    log.debug("Entering Ciba.userCodeMatches().");
    const stored = credentials.readCibaUserCode(String(username || ''));
    let ok = false;
    try {
      ok = !!stored && !!code && stsCrypto.verifySecret(String(code), stored);
    } catch (e) {
      log.debug("Caught in Ciba.userCodeMatches(): " +
                ((e && e.message) || e));
      ok = false;
    }
    log.debug("Leaving Ciba.userCodeMatches(). " + ok);
    return ok;
  }

  // -------------------------------------------------------------------------
  // THE REQUESTS
  // -------------------------------------------------------------------------

  get(id: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering Ciba.get().");
    const found = requests.get(String(id || '')) || null;
    log.debug("Leaving Ciba.get(). " + !!found);
    return found;
  }

  save(record: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Ciba.save(). " + record.state);
    requests.set(String(record.id), record);
    log.debug("Leaving Ciba.save().");
    return record;
  }

  // Every request in the realm that is still waiting for `username`,
  // oldest first; an expired one is marked so on the way past.
  pendingFor(username: unknown): Json[] {
    const { log, now } = this.deps;
    log.debug("Entering Ciba.pendingFor(). user=" + username);
    const who = String(username || '').toLowerCase();
    const out: Json[] = [];
    const self = this;
    requests.forEach(function (record: Json) {
      if (record.state === 'pending' && record.expiresAt <= now()) {
        self.expire(record);
        return;
      }
      if (record.state === 'pending' &&
          String(record.username || '').toLowerCase() === who) {
        out.push(record);
      }
    });
    out.sort(function (a, b) {
      return a.createdAt - b.createdAt;
    });
    log.debug("Leaving Ciba.pendingFor(). " + out.length + ".");
    return out;
  }

  // THE ACKNOWLEDGEMENT'S ROW (section 7.3). `spec` carries what the
  // endpoint checked; the id, the expiry and the interval are made here.
  // Returns { ok, record } or { ok: false, error, code, description }.
  create(spec: Json): Json {
    const { log, now } = this.deps;
    log.debug("Entering Ciba.create(). client=" + spec.clientId);
    const waiting = this.pendingFor(spec.username).length;
    if (waiting >= this.setting('oauth2.cibaMaxPendingPerPerson')) {
      log.debug("Leaving Ciba.create(). Too many waiting.");
      return { ok: false, error: 'access_denied', code: 'STS-OAUTH-0635',
               description: 'this person already has ' + waiting +
                 ' sign-in requests waiting, the most ' +
                 'oauth2.cibaMaxPendingPerPerson allows; ask again once ' +
                 'they have answered or those have expired.' };
    }
    const maxExpiry = this.setting('oauth2.cibaMaxExpiryS');
    const asked = Number(spec.requestedExpiry);
    const expiresIn = asked > 0 ? Math.min(Math.floor(asked), maxExpiry) :
      Math.min(this.setting('oauth2.cibaDefaultExpiryS'), maxExpiry);
    const record = {
      id: nodeCrypto.randomBytes(32).toString('base64url'),
      state: 'pending',
      clientId: String(spec.clientId),
      clientName: String(spec.clientName || spec.clientId),
      username: String(spec.username),
      scope: String(spec.scope || 'openid'),
      acrValues: (spec.acrValues || []).slice(0),
      bindingMessage: String(spec.bindingMessage || ''),
      mode: String(spec.mode),
      notificationToken: String(spec.notificationToken || ''),
      notificationEndpoint: String(spec.notificationEndpoint || ''),
      base: String(spec.base || ''),
      createdAt: now(),
      expiresAt: now() + expiresIn * 1000,
      interval: this.setting('oauth2.cibaIntervalS'),
      lastPolledAt: 0,
      approval: null
    };
    this.save(record);
    log.info('ciba: "' + record.clientId + '" asked to authenticate ' +
             record.username + ' (' + record.mode + ', expires in ' +
             expiresIn + ' s).');
    log.debug("Leaving Ciba.create().");
    return { ok: true, record: record, expiresIn: expiresIn };
  }

  private expire(record: Json): void {
    const { log } = this.deps;
    log.debug("Entering Ciba.expire().");
    record.state = 'expired';
    record.finishedAt = this.deps.now();
    this.save(record);
    if (record.mode === 'push') {
      this.queue(record, { auth_req_id: record.id, error: 'expired_token',
        error_description: 'The person did not answer in time.' });
    }
    log.debug("Leaving Ciba.expire().");
  }

  // -------------------------------------------------------------------------
  // THE PERSON'S ANSWER (section 8). `facts` is what the approving session
  // proved: { acr, amr, authTime }. Returns { ok, record } or { ok: false,
  // why }. Only the hinted person may answer; only a pending request.
  // -------------------------------------------------------------------------
  answer(id: unknown, username: unknown, approve: boolean,
         facts?: Json): Json {
    const { log, now } = this.deps;
    log.debug("Entering Ciba.answer(). approve=" + approve);
    const record = this.get(id);
    if (!record || String(record.username || '').toLowerCase() !==
        String(username || '').toLowerCase()) {
      log.debug("Leaving Ciba.answer(). Not theirs.");
      return { ok: false, why: 'no such sign-in request is waiting for you.' };
    }
    if (record.state === 'pending' && record.expiresAt <= now()) {
      this.expire(record);
    }
    if (record.state !== 'pending') {
      log.debug("Leaving Ciba.answer(). Not pending.");
      return { ok: false, why: 'this request has already been ' +
               (record.state === 'expired' ? 'left to expire' :
                'answered') + '.' };
    }
    record.state = approve ? 'approved' : 'denied';
    record.finishedAt = now();
    record.approval = approve ? {
      acr: String((facts && facts.acr) || ''),
      amr: (facts && facts.amr) || [],
      authTime: Number(facts && facts.authTime) || Math.floor(now() / 1000)
    } : null;
    this.save(record);
    this.deps.audit.record({
      category: 'authentication', action: approve ? 'ciba.approved' :
                                                    'ciba.denied',
      actor: record.username, target: record.clientId,
      outcome: approve ? 'success' : 'refused',
      summary: record.username + (approve ? ' approved' : ' denied') +
               ' a backchannel sign-in request from "' + record.clientId +
               '"',
      detail: { mode: record.mode, scope: record.scope,
                bindingMessage: record.bindingMessage }
    });
    log.debug("Leaving Ciba.answer(). " + record.state);
    return { ok: true, record: record };
  }

  // THE ANSWER, AND WHAT IT SENDS (sections 10.2 and 10.3): a ping client
  // is told to come for its tokens (or its refusal); a push client is sent
  // its tokens — minted here, at the approval, through `oauth2.ts`, reached
  // lazily because that module requires this one — or the error. A push
  // whose tokens cannot be minted (the issuance policy refused, the person
  // gone) is sent `transaction_failed`. The portal and the management API's
  // test control both answer through this.
  async answerAndNotify(id: unknown, username: unknown, approve: boolean,
                        facts?: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering Ciba.answerAndNotify(). approve=" + approve);
    const answered = this.answer(id, username, approve, facts);
    if (answered.ok) {
      await this.notifyAnswered(answered.record);
    }
    log.debug("Leaving Ciba.answerAndNotify(). " + answered.ok);
    return answered;
  }

  // What an answered request sends, by its mode. Never rejects.
  async notifyAnswered(record: Json): Promise<void> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Ciba.notifyAnswered(). " + record.mode);
    const approve = record.state === 'approved';
    if (record.mode === 'ping') {
      this.queue(record, { auth_req_id: record.id });
    } else if (record.mode === 'push' && !approve) {
      this.queue(record, { auth_req_id: record.id, error: 'access_denied',
        error_description: 'The person denied the request.' });
    } else if (record.mode === 'push') {
      let tokens: Json = null;
      try {
        tokens = await require('./oauth2').cibaPushTokens(record);
      } catch (e) {
        log.warn(errorCodes.tag('STS-OAUTH-0661') + 'ciba: the tokens for ' +
                 'an approved push to "' + record.clientId + '" could not ' +
                 'be minted: ' + ((e && e.message) || e));
        tokens = null;
      }
      record.state = tokens ? 'redeemed' : 'failed';
      record.redeemedAt = this.deps.now();
      this.save(record);
      this.queue(record, tokens
        ? Object.assign({ auth_req_id: record.id }, tokens)
        : { auth_req_id: record.id, error: 'transaction_failed',
            error_description: 'The tokens could not be issued.' });
    }
    log.debug("Leaving Ciba.notifyAnswered(). " + record.state);
  }

  // What a poll finds (section 10.1 / 11): the state, with the interval
  // enforced. Returns { state, record } where state is `pending`,
  // `slow_down`, `approved`, `denied`, `expired`, `redeemed` or `unknown`.
  poll(id: unknown, clientId: unknown): Json {
    const { log, now } = this.deps;
    log.debug("Entering Ciba.poll().");
    const record = this.get(id);
    if (!record || record.clientId !== String(clientId || '')) {
      log.debug("Leaving Ciba.poll(). Unknown.");
      return { state: 'unknown', record: null };
    }
    if (record.state === 'pending' && record.expiresAt <= now()) {
      this.expire(record);
    }
    if (record.state !== 'pending') {
      log.debug("Leaving Ciba.poll(). " + record.state);
      return { state: record.state, record: record };
    }
    const since = now() - Number(record.lastPolledAt || 0);
    const tooSoon = record.lastPolledAt &&
      since < Number(record.interval) * 1000;
    if (tooSoon) {
      // Section 11: slow_down, and the interval grows by five seconds for
      // every request after it (RFC 8628 section 3.5's rule).
      record.interval = Number(record.interval) + 5;
    }
    record.lastPolledAt = now();
    this.save(record);
    log.debug("Leaving Ciba.poll(). " + (tooSoon ? 'slow_down' : 'pending'));
    return { state: tooSoon ? 'slow_down' : 'pending', record: record };
  }

  // One token response per approval, cluster-wide.
  async redeem(record: Json): Promise<boolean> {
    const { log, claims } = this.deps;
    log.debug("Entering Ciba.redeem().");
    const claimed: Json = await claims.claim({
      scope: REDEEM_SCOPE, value: record.id,
      ttlMs: Math.max(0, record.expiresAt - this.deps.now()) + RETENTION_MS });
    if (!claimed.ok) {
      log.debug("Leaving Ciba.redeem(). " + claimed.reason);
      return false;
    }
    record.state = 'redeemed';
    record.redeemedAt = this.deps.now();
    this.save(record);
    log.debug("Leaving Ciba.redeem().");
    return true;
  }

  // -------------------------------------------------------------------------
  // PING AND PUSH (sections 10.2 and 10.3): a delivery per notification,
  // attempted at once and by the sweep until it lands or dies.
  // -------------------------------------------------------------------------
  queue(record: Json, body: Json): Json {
    const { log, now } = this.deps;
    log.debug("Entering Ciba.queue(). " + record.mode);
    const row = {
      id: nodeCrypto.randomBytes(16).toString('base64url'),
      realm: this.deps.realms.currentId(),
      authReqId: record.id, clientId: record.clientId, mode: record.mode,
      uri: record.notificationEndpoint, token: record.notificationToken,
      body: body, state: 'pending', attempts: 0, dueAt: now(),
      createdAt: now(), status: 0, why: ''
    };
    deliveries.set(row.id, row);
    this.attempt(row.id).catch(function (e) {
      log.debug("Caught in Ciba.queue(): " + ((e && e.message) || e));
    });
    log.debug("Leaving Ciba.queue().");
    return row;
  }

  // Retried: a transport failure, a timeout, 5xx, 408 and 429.
  private retryable(result: Json): boolean {
    this.deps.log.debug("Entering Ciba.retryable().");
    const status = Number(result && result.status) || 0;
    this.deps.log.debug("Leaving Ciba.retryable().");
    return status === 0 ? ['url', 'attribute', 'outbound-off', 'internal',
      'redirect', 'ca-file'].indexOf(String(result.kind)) < 0 :
      (status >= 500 || status === 408 || status === 429);
  }

  async attempt(id: string): Promise<string> {
    const { log, claims, fedHttp, now, errorCodes } = this.deps;
    log.debug("Entering Ciba.attempt(). " + id);
    const row = deliveries.get(id);
    if (!row || row.state !== 'pending' || Number(row.dueAt) > now()) {
      log.debug("Leaving Ciba.attempt(). Not due.");
      return 'not-due';
    }
    const n = Number(row.attempts) + 1;
    const lease = this.setting('oauth2.cibaNotifyTimeoutMs') * 2;
    const claimed: Json = await claims.claim({ scope: ATTEMPT_SCOPE,
      value: id + ':' + n, ttlMs: lease });
    if (!claimed.ok) {
      log.debug("Leaving Ciba.attempt(). Claimed elsewhere.");
      return 'claimed-elsewhere';
    }
    row.dueAt = now() + lease;
    deliveries.set(id, row);
    const target: Json = { id: row.clientId };
    target[ADDRESS_ATTRIBUTE] = row.uri;
    let result: Json;
    try {
      result = await fedHttp.deliverJson(target, ADDRESS_ATTRIBUTE, row.body,
        { Authorization: 'Bearer ' + row.token },
        { timeoutMs: this.setting('oauth2.cibaNotifyTimeoutMs') });
    } catch (e) {
      log.debug("Caught in Ciba.attempt(): " + ((e && e.message) || e));
      result = { ok: false, status: 0, kind: 'build',
                 why: String((e && e.message) || e) };
    }
    const current = deliveries.get(id) || row;
    current.attempts = n;
    current.status = Number(result.status) || 0;
    if (result.ok) {
      current.state = 'sent';
      current.finishedAt = now();
      deliveries.set(id, current);
      log.info('ciba: the ' + current.mode + ' for "' + current.clientId +
               '" was delivered.');
      log.debug("Leaving Ciba.attempt(). Sent.");
      return 'sent';
    }
    const attempts = this.setting('oauth2.cibaNotifyAttempts');
    if (!this.retryable(result) || n >= attempts) {
      current.state = 'dead';
      current.finishedAt = now();
      current.why = String(result.why || 'it failed');
      deliveries.set(id, current);
      log.warn(errorCodes.tag('STS-OAUTH-0636') + 'ciba: the ' +
               current.mode + ' for "' + current.clientId + '" to ' +
               current.uri + ' was given up after ' + n + ' attempt(s): ' +
               current.why);
      log.debug("Leaving Ciba.attempt(). Dead.");
      return 'dead';
    }
    current.why = String(result.why || 'it failed');
    current.dueAt = now() + this.setting('oauth2.cibaNotifyBackoffMs') *
      Math.pow(2, n - 1);
    deliveries.set(id, current);
    log.debug("Leaving Ciba.attempt(). Retrying.");
    return 'retry';
  }

  // THE SWEEP (the `oauth2.ciba-sweep` job, #49): every realm's due
  // deliveries attempted, waiting requests past their expiry expired, and
  // what finished longer ago than an hour dropped.
  async sweep(): Promise<Json> {
    const { log, realms, now } = this.deps;
    const self = this;
    log.debug("Entering Ciba.sweep().");
    const counts = { attempted: 0, expired: 0, dropped: 0 };
    // `realms.run()` takes the realm itself, not its id.
    for (const realm of realms.list()) {
      await realms.run(realm, async function () {
        const cut = now() - RETENTION_MS;
        const due: string[] = [];
        const gone: string[] = [];
        deliveries.forEach(function (row: Json, key: string) {
          if (row.state === 'pending' && Number(row.dueAt) <= now()) {
            due.push(key);
          } else if (row.state !== 'pending' &&
                     Number(row.finishedAt) < cut) {
            gone.push(key);
          }
        });
        gone.forEach(function (key) {
          deliveries.delete(key);
          counts.dropped++;
        });
        for (const key of due) {
          await self.attempt(key);
          counts.attempted++;
        }
        const old: string[] = [];
        requests.forEach(function (record: Json, key: string) {
          if (record.state === 'pending' && record.expiresAt <= now()) {
            self.expire(record);
            counts.expired++;
          } else if (record.state !== 'pending' &&
                     Number(record.finishedAt || record.redeemedAt ||
                            record.expiresAt) < cut) {
            old.push(key);
          }
        });
        old.forEach(function (key) {
          requests.delete(key);
          counts.dropped++;
        });
      });
    }
    log.debug("Leaving Ciba.sweep(). " + JSON.stringify(counts));
    return counts;
  }

  scheduleSweep(): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Ciba.scheduleSweep().");
    const scheduler = require('../cluster/scheduler');
    if (scheduler.job(SWEEP_JOB)) {
      log.debug("Leaving Ciba.scheduleSweep(). Registered.");
      return;
    }
    scheduler.register({
      id: SWEEP_JOB,
      title: 'CIBA sweep',
      describe: 'Attempts every CIBA ping and push that is due, expires ' +
                'backchannel authentication requests nobody answered in ' +
                'time, and drops what finished more than an hour ago.',
      owner: 'oauth-oidc/ciba.ts',
      everySetting: 'oauth2.cibaSweepS', everySettingUnit: 's',
      run: function (): Promise<Json> {
        return self.sweep();
      }
    });
    log.debug("Leaving Ciba.scheduleSweep(). On the scheduler.");
  }

  // The deliveries, for the console and the tests: never the token.
  deliveryViews(authReqId?: unknown): Json[] {
    const { log } = this.deps;
    log.debug("Entering Ciba.deliveryViews().");
    const out: Json[] = [];
    deliveries.forEach(function (row: Json) {
      if (authReqId === undefined || row.authReqId === String(authReqId)) {
        out.push({ id: row.id, clientId: row.clientId, mode: row.mode,
                   uri: row.uri, state: row.state, attempts: row.attempts,
                   status: row.status, why: row.why });
      }
    });
    log.debug("Leaving Ciba.deliveryViews(). " + out.length + ".");
    return out;
  }

  // A request as a page or the API shows it: never the notification token.
  static view(record: Json): Json {
    helpers.log.debug("Entering Ciba.view().");
    helpers.log.debug("Leaving Ciba.view().");
    return { id: record.id, state: record.state, clientId: record.clientId,
             clientName: record.clientName, username: record.username,
             scope: record.scope, acrValues: record.acrValues,
             bindingMessage: record.bindingMessage, mode: record.mode,
             createdAt: record.createdAt, expiresAt: record.expiresAt };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). The wire step
// registers the sweep's scheduler job (#49).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<Ciba>(
  'oauth-oidc/ciba',
  () => new Ciba(Ciba.defaultDeps()),
  function (instance: Ciba): void {
    instance.scheduleSweep();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  Ciba: Ciba,
  installInstance: (instance: Ciba): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  GRANT_TYPE: GRANT_TYPE,
  MODES: MODES,
  view: Ciba.view,
  enabled: slot.forward('enabled'),
  setUserCode: slot.forward('setUserCode'),
  hasUserCode: slot.forward('hasUserCode'),
  userCodeMatches: slot.forward('userCodeMatches'),
  get: slot.forward('get'),
  pendingFor: slot.forward('pendingFor'),
  create: slot.forward('create'),
  answer: slot.forward('answer'),
  answerAndNotify: slot.forward('answerAndNotify'),
  notifyAnswered: slot.forward('notifyAnswered'),
  poll: slot.forward('poll'),
  redeem: slot.forward('redeem'),
  queue: slot.forward('queue'),
  attempt: slot.forward('attempt'),
  sweep: slot.forward('sweep'),
  deliveryViews: slot.forward('deliveryViews')
};
