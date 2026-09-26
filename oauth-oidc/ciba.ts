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
import applications = require('../common/applications');
import outbound = require('./outbound_delivery');

type Json = any;

// The two stores. PER TRUST REALM, persisted where minted rows are.
const requests = realms.map({ persist: 'oauth2.cibaRequests',
                              retain: 'age' });
// A notification is a row of `outbound_delivery.ts`'s shared queue (#151):
// tombstoned and merged by rank, as every kind's store is.
const deliveries = realms.map({ persist: 'oauth2.cibaDeliveries',
                                tombstone: true,
                                mergeRow: outbound.mergeRow });

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
  // A timer for the queue's own retries (`outbound_delivery.ts`).
  later?: (fn: () => void, ms: number) => void;
}

class Ciba {
  static readonly GRANT_TYPE = GRANT_TYPE;
  static readonly MODES = MODES;
  // PING AND PUSH ARE A KIND OF THE SHARED OUTBOUND QUEUE (#151): the fence,
  // the merge, retention, the summary line, the audit row and the retry by
  // hand CIBA's own copy of the pattern did not have.
  private readonly outbox: InstanceType<typeof outbound.OutboundDelivery>;

  constructor(private readonly deps: CibaDeps) {
    deps.log.debug("Entering Ciba.constructor().");
    const self = this;
    this.outbox = new outbound.OutboundDelivery({
      label: 'CIBA notification',
      store: deliveries,
      attemptScope: ATTEMPT_SCOPE,
      attribute: ADDRESS_ATTRIBUTE,
      body: 'json',
      settings: {
        attempts: 'oauth2.cibaNotifyAttempts',
        timeoutMs: 'oauth2.cibaNotifyTimeoutMs',
        backoffMs: 'oauth2.cibaNotifyBackoffMs',
        retentionS: 'oauth2.cibaNotifyRetentionS',
        maxRows: 'oauth2.cibaNotifyMaxRows',
        concurrency: 'oauth2.cibaNotifyConcurrency',
        summaryS: 'oauth2.cibaNotifySummaryS'
      },
      codes: {
        outboundOff: 'STS-OAUTH-0708', url: 'STS-OAUTH-0709',
        internal: 'STS-OAUTH-0710', unresolved: 'STS-OAUTH-0711',
        redirect: 'STS-OAUTH-0712', build: 'STS-OAUTH-0713',
        timeout: 'STS-OAUTH-0714', network: 'STS-OAUTH-0715',
        status400: 'STS-OAUTH-0716', status: 'STS-OAUTH-0636',
        deferred: 'STS-OAUTH-0717', stale: 'STS-OAUTH-0718',
        summary: 'STS-OAUTH-0719', sweepFailed: 'STS-OAUTH-0752',
        retry: 'STS-OAUTH-0753'
      },
      deadLetterHint: 'Dead letters are listed on /admin/deliveries and ' +
        'retried from there.',
      prepare: function (row: Json): Promise<Json> {
        return Promise.resolve({ body: row.body,
          headers: { Authorization: 'Bearer ' + row.token } });
      },
      onFinish: function (row: Json, state: string, code: string,
                          why: string): void {
        self.audited(row, state, code, why);
      },
      onRetry: function (row: Json): Json {
        const now = applications.cibaOf(row.clientId);
        if (!now.endpoint) {
          return { problem: row.clientId + ' has no ' +
            'backchannel_client_notification_endpoint now, so a retry ' +
            'would fail the same way.' };
        }
        return { patch: { uri: now.endpoint } };
      },
      viewExtra: function (row: Json): Json {
        return { authReqId: row.authReqId, mode: row.mode,
                 username: row.username || '' };
      },
      searchText: function (row: Json): string {
        return String(row.authReqId || '') + ' ' + String(row.mode || '');
      },
      sweepJob: {
        id: SWEEP_JOB,
        title: 'CIBA sweep',
        describe: 'Attempts every CIBA ping and push that is due, ' +
                  'dead-letters one still pending past ' +
                  'oauth2.cibaNotifyRetentionS, expires backchannel ' +
                  'authentication requests nobody answered in time, and ' +
                  'drops what finished more than an hour ago.',
        owner: 'oauth-oidc/ciba.ts',
        everySetting: 'oauth2.cibaSweepS'
      },
      onSweepRealm: function (): Json {
        return self.sweepRequests();
      }
    }, {
      log: deps.log, config: deps.config, realms: deps.realms,
      errorCodes: deps.errorCodes, fedHttp: deps.fedHttp,
      claims: deps.claims, now: deps.now,
      later: deps.later || outbound.OutboundDelivery.later
    });
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
    const name = String(username || '');
    const had = !!credentials.readCibaUserCode(name);
    const written = credentials.writeCibaUserCode(name,
      text ? stsCrypto.hashSecret(text) : '');
    // CAEP `credential-change` (#237): the user code is a secret the person
    // chose and a client must present — a `pin` in CAEP 1.0 section 3.3.1's
    // words. This is the only writer (an LDAP write of it is refused), so
    // it is sent here: create, update, or delete when cleared. Clearing a
    // code nobody held changes nothing and sends nothing.
    const change = text ? (had ? 'update' : 'create') : (had ? 'delete' : '');
    if (written && change) {
      try {
        require('../ssf/account_signals').credentialChanged({
          username: name, credentialType: 'pin', changeType: change,
          initiatingEntity: 'user', friendlyName: 'CIBA user code',
          via: 'portal',
          reasonAdmin: name + ' ' + (change === 'create' ? 'set'
            : change === 'update' ? 'changed' : 'cleared') + ' their CIBA ' +
            'user code.',
          reasonUser: 'Your CIBA user code was ' + (change === 'create'
            ? 'set.' : change === 'update' ? 'changed.' : 'cleared.') });
      } catch (e) {
        log.debug("Caught in Ciba.setUserCode(): " + ((e && e.message) || e));
        // No Shared Signals facade in this process; the code is written.
      }
    }
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
      // FAPI-CIBA section 5.3 (#142): what the client said about the
      // consumption device, shown to the person beside the binding message.
      requestContext: spec.requestContext && typeof spec.requestContext ===
                      'object' ? spec.requestContext : null,
      // Grant Management (#142): what the grant will be when this request's
      // tokens are claimed — `grant_management.ts`'s plan, or null.
      grantManagement: spec.grantManagement || null,
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
  // PING AND PUSH (sections 10.2 and 10.3): a delivery per notification on
  // the shared queue, attempted at once and by the sweep until it lands or
  // is a dead letter.
  // -------------------------------------------------------------------------
  queue(record: Json, body: Json): Json {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Ciba.queue(). " + record.mode);
    const queued = this.outbox.queue({
      authReqId: record.id, clientId: record.clientId, mode: record.mode,
      uri: record.notificationEndpoint, token: record.notificationToken,
      username: record.username || '', body: body
    });
    this.outbox.dispatch([queued.row]).catch(function (e) {
      log.debug("Caught in Ciba.queue(): " + ((e && e.message) || e));
    });
    log.debug("Leaving Ciba.queue(). " + queued.row.id);
    return self.outbox.view(queued.row);
  }

  // One audit row when a notification finishes, summarised.
  private audited(row: Json, state: string, code: string, why: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering Ciba.audited(). " + state);
    audit.audit({
      action: 'oauth2.ciba.notify',
      outcome: state === 'sent' ? 'success' : 'error',
      errorCode: state === 'sent' ? '' : code,
      summarised: true,
      actor: row.username || '',
      protocol: 'OAuth 2.0 / OIDC',
      channel: 'internal',
      target: row.clientId,
      summary: state === 'sent'
        ? 'the CIBA ' + row.mode + ' for request ' + row.authReqId +
          ' was accepted by ' + row.clientId + ' (HTTP ' + row.status + ')'
        : 'the CIBA ' + row.mode + ' for request ' + row.authReqId +
          ' was not delivered to ' + row.clientId + ' and is a dead ' +
          'letter: ' + why,
      detail: { delivery: row.id, authReqId: row.authReqId, uri: row.uri,
                attempts: String(row.attempts), state: state }
    });
    log.debug("Leaving Ciba.audited().");
  }

  // One attempt of one notification, through the shared queue.
  attempt(id: string): Promise<string> {
    const { log, realms } = this.deps;
    log.debug("Entering Ciba.attempt(). " + id);
    log.debug("Leaving Ciba.attempt().");
    return this.outbox.attempt(realms.currentId(), id);
  }

  // An operator's retry of a dead notification (a new generation).
  retryDelivery(id: string, actor?: string): Json {
    const { log } = this.deps;
    log.debug("Entering Ciba.retryDelivery(). " + id);
    const done = this.outbox.retry(id, actor || '', 'CIBA notification');
    log.debug("Leaving Ciba.retryDelivery(). " + done.ok);
    return done.ok ? { ok: true, row: this.outbox.view(done.row),
                       message: 'The notification to ' + done.row.clientId +
                         ' was queued again; it is sent after this answer.' }
                   : done;
  }

  // THE SWEEP (the `oauth2.ciba-sweep` job, #49): the shared queue's sweep
  // — due notifications attempted, stale ones dead-lettered, finished ones
  // past retention dropped — and, per realm, `sweepRequests()`.
  sweep(): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering Ciba.sweep().");
    log.debug("Leaving Ciba.sweep().");
    return this.outbox.sweep();
  }

  // The requests half of a realm's sweep: waiting requests past their
  // expiry expired, and what finished longer ago than an hour dropped.
  private sweepRequests(): Json {
    const { log, now } = this.deps;
    const self = this;
    log.debug("Entering Ciba.sweepRequests().");
    const counts = { expired: 0, dropped: 0 };
    const cut = now() - RETENTION_MS;
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
    log.debug("Leaving Ciba.sweepRequests(). " + JSON.stringify(counts));
    return counts;
  }

  scheduleSweep(): void {
    const { log } = this.deps;
    log.debug("Entering Ciba.scheduleSweep().");
    this.outbox.scheduleSweep();
    log.debug("Leaving Ciba.scheduleSweep().");
  }

  // The deliveries, for the console and the tests: never the token or the
  // body.
  deliveryViews(authReqId?: unknown): Json[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Ciba.deliveryViews().");
    const rows = this.outbox.rows({
      where: authReqId === undefined ? undefined : function (row: Json) {
        return row.authReqId === String(authReqId);
      }
    }).map(function (row: Json) {
      return self.outbox.view(row);
    });
    log.debug("Leaving Ciba.deliveryViews(). " + rows.length + ".");
    return rows;
  }

  // The shared queue's list and counts, for `/admin/deliveries` (#151).
  deliveryRows(options?: Json): Json[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Ciba.deliveryRows().");
    log.debug("Leaving Ciba.deliveryRows().");
    return this.outbox.rows(options).map(function (row: Json) {
      return self.outbox.view(row);
    });
  }

  deliveryCounts(): Json {
    const { log } = this.deps;
    log.debug("Entering Ciba.deliveryCounts().");
    log.debug("Leaving Ciba.deliveryCounts().");
    return this.outbox.counts();
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
  deliveryViews: slot.forward('deliveryViews'),
  deliveryRows: slot.forward('deliveryRows'),
  deliveryCounts: slot.forward('deliveryCounts'),
  retryDelivery: slot.forward('retryDelivery')
};
