// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssf_transmitters.ts
//
// ===========================================================================
// A FEDERATION PARTNER'S SHARED SIGNALS (#373, #374, 2026-10-01) — Shared
// Signals Framework 1.0 with this realm as the RECEIVER.
//
// #153 built this as a register of its own (`ssf.foreignTransmitters`) that
// had to name a federation relationship to map subjects. rcbj's call on #373:
// a foreign transmitter is a federation partner in spirit — a party that asks
// this service for nothing and makes statements about people who sign in
// through it — so it is CONFIGURED ON THE RELATIONSHIP (`fedSignals*`,
// `federation/federation.js`) and this module keeps only what is MINTED: the
// discovered configuration, the stream at the partner, the push secret's
// digest, verification, the inbox and the account locks. #374 added the
// partner that signs nobody in — an MDM, an EDR, an HR feed — as a sixth
// relationship protocol, `ssf`.
//
// **1. ONLY A RELATIONSHIP AN ADMINISTRATOR CONFIGURED.** The issuer is
// `fedSignalsIssuer`, else `fedPeer`; its `/.well-known/ssf-configuration`
// (SSF 1.0 section 7; the path inserted before the issuer's own, as RFC 8414
// does) must name it, and every address dialled afterwards comes from that
// document, through `federation_http.fetchPublished()` — internal addresses
// refused in product mode, the connection pinned, no redirect, a cap. That
// is the fifteenth row of root CLAUDE.md's "Dial a URL" index. Nothing is
// received unless the relationship is enabled AND its signals are.
//
// **2. A STREAM AT THE PARTNER, AND BOTH DELIVERIES.** This realm creates,
// reads, updates and deletes its stream at the configuration endpoint
// (section 8.1.1), sets its status, adds and removes subjects and asks for
// verification, with an access token from client credentials (falling back to
// the sign-in relationship's own client) or a bearer the administrator
// pasted, both sealed on the entry. POLL (RFC 8936) is the `ssf.foreign-poll`
// cluster job, per realm, acknowledging what it received on the next request;
// PUSH (RFC 8935) is `POST /federation/signals/{id}`, authenticated by the
// authorization header this realm gave the partner when it created the
// stream (kept only as its digest, compared in constant time).
//
// **3. NOTHING ACTS ON A SET UNLESS IT VERIFIED** (#117's rule): the
// signature against the keys at the configuration document's `jwks_uri` (the
// algorithms named, never taken from the token), `typ` secevent+jwt, `iss`
// the partner's SSF issuer, `aud` the stream's, a `jti` never seen before. In
// product an unverified SET is refused (`mode.refusesUnverifiedSignals()`);
// in development it is recorded and acted on in no way. What a verified one
// leads to is the `signal-response` policy's decision, asked with the surface
// `federation:<id>` and the relationship KIND:
//
//   * a SIGN-IN partner (#373): end the sessions IT started for the person
//     (the one a complex subject's session names, else every one), as its
//     own sign-out does (#167); block its sign-ins of the person on
//     account-disabled (`federation/federation_blocks.ts`) and lift that on
//     account-enabled. A local sign-in and other partners are untouched.
//   * a SIGNALS-ONLY partner (#374): recorded, and nothing more, by default;
//     a global sign-out and an account lock exist for a policy to permit.
//   * either: a device's compliance (`device-compliance-change`) is set.
//
// Development only RECORDS what it would do unless
// `ssf.actOnSignalsInDevelopment` is on (`mode.observesSignalsOnly()`) — the
// device's compliance included.
//
// **4. A FOREIGN SUBJECT IS A LOCAL PERSON THROUGH THE RELATIONSHIP.** A
// sign-in partner's `iss_sub` subject (its issuer being fedPeer or the SSF
// issuer) is the ONE person whose `federationLink` holds
// `<id> <fedPeer> <sub>` — the identifier that partner signs them in with,
// which for SAML is the persistent NameID. A signals-only partner's links are
// written by an administrator: `<id> <iss> <sub>` for an iss_sub subject,
// `<id> opaque <id>` for an opaque one. An `email` subject matches only where
// `fedSignalEmailMatch` is on. Anything else — no link, two people — is
// recorded and acts on nobody.
//
// A LIBRARY with one route of its own (the push endpoint); its acts are the
// relationship's (`admin-core/admin_actions.ts`'s federationAction) and its
// report is Monitoring → Shared Signals from partners
// (`ssf_transmitters_admin.ts`).
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import mode = require('../common/mode');
import stsCrypto = require('../common/crypto');
import fedBlocks = require('../federation/federation_blocks');

type Json = any;
type Req = import('express').Request;
type Res = import('express').Response;

/**
 * The scheduler job that polls every relationship with a poll stream,
 * `ssf.foreign-poll`.
 */
const POLL_JOB = 'ssf.foreign-poll';
const PUSH = 'urn:ietf:rfc:8935';
const POLL = 'urn:ietf:rfc:8936';
const SET_TYPES = ['secevent+jwt', 'application/secevent+jwt'];
const CAEP_PREFIX = 'https://schemas.openid.net/secevent/caep/event-type/';
const RISC_PREFIX = 'https://schemas.openid.net/secevent/risc/event-type/';
const SSF_PREFIX = 'https://schemas.openid.net/secevent/ssf/event-type/';
// The push route's prefix: `federation.js`'s PATHS.signals, spelled here so
// this module needs the register only lazily.
const PUSH_PATH = '/federation/signals';

/**
 * The acts on a relationship's signals, as `federationAction()` names them.
 */
const ACTIONS = ['signals-discover', 'signals-create-stream',
  'signals-read-stream', 'signals-update-stream', 'signals-delete-stream',
  'signals-set-status', 'signals-add-subject', 'signals-remove-subject',
  'signals-verify', 'signals-poll-now', 'signals-unblock'];

// Per realm and persisted, keyed by the relationship: the stream's state; what
// arrived (which is also the jti history); and which account lock a
// signals-only partner's event put on whom. The relationship's own
// CONFIGURATION is on its entry, never copied here.
const streams = realms.map({ persist: 'ssf.relationshipStreams' });
const inbox = realms.map({ persist: 'ssf.relationshipInbox' });
const locks = realms.map({ persist: 'ssf.relationshipLocks' });

// Access tokens, per process and short-lived: `<realm>|<id>|<client>` →
// { token, until }. A process that has none asks again; nothing is lost.
const tokens = new Map<string, Json>();

interface TransmittersDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  mode: typeof mode;
  blocks: typeof fedBlocks;
  now: () => number;
  // Lazily, each: the outbound door, the key cache, the federation register,
  // the links, the policy, the sign-out, the sessions, the account lock, the
  // device register, this service's own streams and the applications.
  fedHttp: () => Json;
  jwks: () => Json;
  federation: () => Json;
  links: () => Json;
  signalPep: () => Json;
  logout: () => Json;
  authn: () => Json;
  accountState: () => Json;
  devices: () => Json;
  ownStreams: () => Json;
  applications: () => Json;
}

/**
 * This realm as the receiver of its federation partners' Shared Signals:
 * discovery, the stream at the partner, poll and push delivery,
 * verification, and what a verified SET leads to.
 *
 * Configuration is the relationship's (`fedSignals*`); this keeps what is
 * minted. A SET is acted on only when it verified, and then only as the
 * `signal-response` policy permits.
 */
class SsfTransmitters {
  /**
   * The poll job's id; the module's `POLL_JOB`.
   */
  static readonly POLL_JOB = POLL_JOB;
  /**
   * The acts `act()` takes.
   */
  static readonly ACTIONS = ACTIONS;
  /**
   * Where a partner pushes, the relationship's id after it.
   */
  static readonly PUSH_PATH = PUSH_PATH;

  /**
   * Builds the receiver from its dependencies.
   *
   * @param deps - the modules it reads, from `SsfTransmitters.defaultDeps()`
   * or the composition root
   */
  constructor(private readonly deps: TransmittersDeps) {
    deps.log.debug("Entering SsfTransmitters.constructor().");
    deps.log.debug("Leaving SsfTransmitters.constructor().");
  }

  /**
   * Returns the real modules the receiver depends on, as the composition root
   * passes them.
   *
   * @returns the dependencies
   */
  static defaultDeps(): TransmittersDeps {
    helpers.log.debug("Entering SsfTransmitters.defaultDeps().");
    helpers.log.debug("Leaving SsfTransmitters.defaultDeps().");
    return {
      log: helpers.log, config: config, realms: realms,
      errorCodes: errorCodes, audit: audit, mode: mode, blocks: fedBlocks,
      now: function (): number {
        return Date.now();
      },
      fedHttp: function (): Json {
        return require('../federation/federation_http');
      },
      jwks: function (): Json {
        return require('../oauth-oidc/client_jwks');
      },
      federation: function (): Json {
        return require('../federation/federation');
      },
      links: function (): Json {
        return require('../federation/federation_links');
      },
      signalPep: function (): Json {
        return require('../xacml/xacml_signal_pep');
      },
      logout: function (): Json {
        const found = require.cache[require.resolve('../logout/logout')];
        return found ? found.exports : null;
      },
      authn: function (): Json {
        return require('../authn/authn');
      },
      accountState: function (): Json {
        return require('../common/account_state');
      },
      devices: function (): Json {
        return require('../common/devices');
      },
      ownStreams: function (): Json {
        return require('./ssf_streams');
      },
      applications: function (): Json {
        return require('../common/applications');
      }
    };
  }

  private setting(key: string): number {
    const { log, config } = this.deps;
    log.debug("Entering SsfTransmitters.setting(). " + key);
    log.debug("Leaving SsfTransmitters.setting().");
    return Number(config.value(key));
  }

  /**
   * Returns the SHA-256 digest of a text, base64url, as a push authorization
   * header is kept.
   *
   * @param text - the text
   * @returns the digest
   */
  static digest(text: string): string {
    helpers.log.debug("Entering SsfTransmitters.digest().");
    helpers.log.debug("Leaving SsfTransmitters.digest().");
    return stsCrypto.digest('sha256', String(text), 'base64url');
  }

  // SSF 1.0 section 7: the configuration document's address for an issuer —
  // `/.well-known/ssf-configuration` inserted before the issuer's path.
  /**
   * Returns an issuer's SSF configuration address (SSF 1.0 section 7):
   * `/.well-known/ssf-configuration` inserted before the issuer's path.
   *
   * @param issuer - the issuer
   * @returns the URL
   * @throws when the issuer is not a URL
   */
  static discoveryUrlFor(issuer: string): string {
    helpers.log.debug("Entering SsfTransmitters.discoveryUrlFor().");
    const u = new URL(String(issuer));
    const path = u.pathname.replace(/\/+$/, '');
    helpers.log.debug("Leaving SsfTransmitters.discoveryUrlFor().");
    return u.origin + '/.well-known/ssf-configuration' +
      (path && path !== '/' ? path : '');
  }

  // -------------------------------------------------------------------------
  // THE MINTED STATE, keyed by the relationship.
  // -------------------------------------------------------------------------
  /**
   * Returns a copy of a relationship's stream state in the ambient realm.
   *
   * @param fedId - the relationship
   * @returns the state, or a fresh one when there is none
   */
  stateOf(fedId: string): Json {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.stateOf(). " + fedId);
    const held = streams.get(String(fedId || ''));
    log.debug("Leaving SsfTransmitters.stateOf(). " + !!held);
    return held ? Object.assign({}, held)
      : { fedId: String(fedId), config: null, streamId: '', stream: null,
          streamAud: [], pollEndpoint: '', pushSecretDigest: '',
          delivery: '', verifyState: '', verifiedAt: 0, state: 'new',
          lastPollAt: 0, lastPollResult: '', lastError: '',
          counts: { received: 0, verified: 0, refused: 0, acted: 0 },
          createdAt: this.deps.now() };
  }

  private save(state: Json): void {
    const { log, now } = this.deps;
    log.debug("Entering SsfTransmitters.save(). " + state.fedId);
    state.updatedAt = now();
    streams.set(state.fedId, Object.assign({}, state));
    log.debug("Leaving SsfTransmitters.save().");
  }

  private tokenKey(record: Json): string {
    const { realms } = this.deps;
    this.deps.log.debug("Entering SsfTransmitters.tokenKey().");
    const c = this.deps.federation().signalsCredentialOf(record);
    this.deps.log.debug("Leaving SsfTransmitters.tokenKey().");
    return realms.currentId() + '|' + record.fedId + '|' +
      String(c.tokenEndpoint || '') + '|' + String(c.clientId || '');
  }

  // One outbound request to an endpoint the partner's document named, JSON
  // both ways. `{ ok, status, json, why }`; never rejects.
  private async call(record: Json, method: string, url: string,
                     body?: Json, withToken?: boolean): Promise<Json> {
    const { log, fedHttp } = this.deps;
    log.debug("Entering SsfTransmitters.call(). " + method + " " + url);
    if (!url) {
      log.debug("Leaving SsfTransmitters.call(). No endpoint.");
      return { ok: false, status: 0, json: null,
               why: 'the partner\'s configuration names no such endpoint' };
    }
    const headers: Json = {};
    if (withToken !== false) {
      const token = await this.accessToken(record);
      if (!token.ok) {
        log.debug("Leaving SsfTransmitters.call(). No token.");
        return { ok: false, status: 0, json: null, why: token.why };
      }
      headers.Authorization = 'Bearer ' + token.token;
    }
    const answer: Json = await fedHttp().fetchPublished(url, {
      method: method, headers: headers, accept: 'application/json',
      body: body === undefined ? undefined : JSON.stringify(body),
      contentType: 'application/json',
      timeoutMs: this.setting('ssf.foreignTimeoutMs') });
    let json: Json = null;
    try {
      json = answer.body && answer.body.length
        ? JSON.parse(answer.body.toString('utf8')) : null;
    } catch (e) {
      log.debug("Caught in SsfTransmitters.call(): " +
                ((e && e.message) || e));
      json = null;
    }
    log.debug("Leaving SsfTransmitters.call(). " + answer.status);
    return { ok: !!answer.ok, status: Number(answer.status) || 0, json: json,
             why: answer.ok ? '' : String(answer.why || 'it answered ' +
               answer.status) + (json && (json.description || json.error)
               ? ' (' + String(json.description || json.error_description ||
                               json.error).slice(0, 200) + ')' : '') };
  }

  // The access token this realm presents to the partner: a pasted bearer, or
  // client credentials at the token endpoint the relationship names.
  private async accessToken(record: Json): Promise<Json> {
    const { log, fedHttp, now } = this.deps;
    log.debug("Entering SsfTransmitters.accessToken(). " + record.fedId);
    const credential = this.deps.federation().signalsCredentialOf(record);
    if (credential.method === 'bearer') {
      log.debug("Leaving SsfTransmitters.accessToken(). Pasted.");
      return { ok: true, token: credential.bearer };
    }
    if (!credential.tokenEndpoint || !credential.clientId) {
      log.debug("Leaving SsfTransmitters.accessToken(). Not configured.");
      return { ok: false, why: 'the relationship names no bearer token and ' +
                               'no token endpoint and client for its signals' };
    }
    const key = this.tokenKey(record);
    const held = tokens.get(key);
    if (held && held.until > now()) {
      log.debug("Leaving SsfTransmitters.accessToken(). Cached.");
      return { ok: true, token: held.token };
    }
    const form = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: String(credential.clientId),
      client_secret: String(credential.clientSecret || ''),
      scope: String(credential.scope)
    }).toString();
    const answer: Json = await fedHttp().fetchPublished(
      String(credential.tokenEndpoint), {
        method: 'POST', accept: 'application/json', body: form,
        contentType: 'application/x-www-form-urlencoded',
        timeoutMs: this.setting('ssf.foreignTimeoutMs') });
    let json: Json = null;
    try {
      json = JSON.parse(answer.body.toString('utf8'));
    } catch (e) {
      log.debug("Caught in SsfTransmitters.accessToken(): " +
                ((e && e.message) || e));
      json = null;
    }
    if (!answer.ok || !json || !json.access_token) {
      log.debug("Leaving SsfTransmitters.accessToken(). Refused.");
      return { ok: false, why: 'the token endpoint gave no access token: ' +
        (json && json.error ? json.error : String(answer.why ||
                                                  answer.status)) };
    }
    tokens.set(key, { token: String(json.access_token),
                      until: now() + Math.max(10,
                        Number(json.expires_in) || 60) * 1000 - 5000 });
    log.debug("Leaving SsfTransmitters.accessToken(). Issued.");
    return { ok: true, token: String(json.access_token) };
  }

  private audited(action: string, ctx: Json, record: Json,
                  what: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering SsfTransmitters.audited(). " + action);
    const state = this.stateOf(record.fedId);
    audit.audit({ action: action, actor: (ctx && ctx.actor) || '',
      protocol: 'Shared Signals', channel: (ctx && ctx.via) || 'http',
      target: record.fedId,
      summary: 'the Shared Signals of the federation relationship ' +
               record.fedId + ': ' + what,
      detail: { relationship: record.fedId,
                issuer: this.deps.federation().signalsIssuerOf(record),
                streamId: state.streamId || '' } });
    log.debug("Leaving SsfTransmitters.audited().");
  }

  private refusal(code: string, message: string): Json {
    this.deps.log.debug("Entering SsfTransmitters.refusal(). " + code);
    this.deps.log.debug("Leaving SsfTransmitters.refusal().");
    return this.deps.errorCodes.mark({ ok: false, errors: [message] }, code);
  }

  // -------------------------------------------------------------------------
  // DISCOVERY: the partner's configuration and keys, from its SSF issuer.
  // -------------------------------------------------------------------------
  /**
   * Fetches the partner's SSF configuration (which must name its issuer) and
   * its keys, and keeps them. Audited.
   *
   * @param record - the relationship
   * @param ctx - `via` and `actor`
   * @returns a promise of `{ ok, signals }` or `{ ok: false, errors }`
   */
  async discover(record: Json, ctx: Json): Promise<Json> {
    const { log, fedHttp } = this.deps;
    log.debug("Entering SsfTransmitters.discover(). " + record.fedId);
    const issuer = this.deps.federation().signalsIssuerOf(record);
    let discovery = '';
    try {
      discovery = SsfTransmitters.discoveryUrlFor(issuer);
    } catch (e) {
      log.debug("Caught in SsfTransmitters.discover(): " +
                ((e && e.message) || e));
      log.debug("Leaving SsfTransmitters.discover(). The issuer.");
      return this.refusal('STS-SSF-0114', 'The SSF issuer "' + issuer +
        '" (fedSignalsIssuer, else fedPeer) is not a URL.');
    }
    const fetched: Json = await fedHttp().fetchPublished(discovery, {
      accept: 'application/json',
      timeoutMs: this.setting('ssf.foreignTimeoutMs') });
    let doc: Json = null;
    try {
      doc = fetched.ok ? JSON.parse(fetched.body.toString('utf8')) : null;
    } catch (e) {
      log.debug("Caught in SsfTransmitters.discover(): " +
                ((e && e.message) || e));
      doc = null;
    }
    const state = this.stateOf(record.fedId);
    if (!doc) {
      state.lastError = 'discovery: ' + String(fetched.why || fetched.status);
      this.save(state);
      log.debug("Leaving SsfTransmitters.discover(). Unreadable.");
      return this.refusal('STS-SSF-0114', 'The configuration document at ' +
        discovery + ' could not be read: ' + String(fetched.why ||
                                                    fetched.status) + '.');
    }
    if (doc.issuer !== issuer || !doc.jwks_uri ||
        !doc.configuration_endpoint) {
      state.lastError = 'discovery: not the issuer\'s document';
      this.save(state);
      log.debug("Leaving SsfTransmitters.discover(). Not the issuer's.");
      return this.refusal('STS-SSF-0114', 'The configuration document must ' +
        'name the issuer ' + issuer + ' (it names ' + String(doc.issuer) +
        ') and a jwks_uri and configuration_endpoint (SSF 1.0 section 7.1).');
    }
    const keys: Json = await this.deps.jwks().ensure(String(doc.jwks_uri),
                                                     '');
    if (!keys.ok) {
      state.lastError = 'discovery: the jwks_uri: ' + keys.why;
      this.save(state);
      log.debug("Leaving SsfTransmitters.discover(). Keys.");
      return this.refusal('STS-SSF-0114', 'The partner\'s jwks_uri could ' +
        'not be read: ' + keys.why + '.');
    }
    state.config = {
      issuer: doc.issuer, jwks_uri: doc.jwks_uri,
      configuration_endpoint: doc.configuration_endpoint,
      status_endpoint: doc.status_endpoint || '',
      add_subject_endpoint: doc.add_subject_endpoint || '',
      remove_subject_endpoint: doc.remove_subject_endpoint || '',
      verification_endpoint: doc.verification_endpoint || '',
      delivery_methods_supported: Array.isArray(
        doc.delivery_methods_supported) ? doc.delivery_methods_supported : []
    };
    state.discoveryUrl = discovery;
    state.discoveredAt = this.deps.now();
    if (state.state === 'new') {
      state.state = 'discovered';
    }
    state.lastError = '';
    this.save(state);
    this.audited('ssf.signals.discover', ctx, record, 'discovered from ' +
                 discovery);
    log.debug("Leaving SsfTransmitters.discover().");
    return { ok: true, signals: this.view(record),
             message: 'Discovered ' + record.fedId + '\'s Shared Signals ' +
                      'configuration at ' + discovery + '.' };
  }

  // The configuration, discovered again when the issuer it was discovered
  // for is not the one the relationship names now.
  private async configured(record: Json, ctx: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.configured().");
    const state = this.stateOf(record.fedId);
    const issuer = this.deps.federation().signalsIssuerOf(record);
    if (state.config && state.config.issuer === issuer) {
      log.debug("Leaving SsfTransmitters.configured(). Held.");
      return { ok: true, state: state };
    }
    const found = await this.discover(record, ctx);
    log.debug("Leaving SsfTransmitters.configured(). " + found.ok);
    return found.ok ? { ok: true, state: this.stateOf(record.fedId) }
                    : found;
  }

  // -------------------------------------------------------------------------
  // THE STREAM AT THE PARTNER (section 8.1.1).
  // -------------------------------------------------------------------------
  /**
   * Creates this realm's stream at the partner (SSF 1.0 section 8.1.1): a
   * poll stream, or a push stream to `/federation/signals/{id}` with an
   * authorization header only this realm and the partner know. Audited.
   *
   * @param record - the relationship
   * @param ctx - `via`, `actor` and `base`
   * @returns a promise of the outcome
   */
  async createStream(record: Json, ctx: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.createStream(). " + record.fedId);
    const ready = this.deps.federation().signalsReadinessOf(record);
    if (!ready.ready) {
      log.debug("Leaving SsfTransmitters.createStream(). Not configured.");
      return this.refusal('STS-SSF-0113', 'The relationship ' +
        record.fedId + ' cannot reach the partner\'s stream yet: ' +
        ready.missing.join(', ') + ' still to set.');
    }
    const found = await this.configured(record, ctx);
    if (!found.ok) {
      log.debug("Leaving SsfTransmitters.createStream(). Discovery.");
      return found;
    }
    const state = found.state;
    if (state.streamId) {
      log.debug("Leaving SsfTransmitters.createStream(). Has one.");
      return this.refusal('STS-SSF-0113', 'The relationship ' +
        record.fedId + ' already has stream ' + state.streamId + '.');
    }
    const delivery = String(record.fedSignalsDelivery || 'poll') === 'push'
      ? 'push' : 'poll';
    if ((state.config.delivery_methods_supported || [])
          .indexOf(delivery === 'push' ? PUSH : POLL) < 0) {
      log.debug("Leaving SsfTransmitters.createStream(). Unsupported.");
      return this.refusal('STS-SSF-0113', 'The partner does not offer ' +
        delivery + ' delivery (fedSignalsDelivery).');
    }
    const asked: Json = { delivery: { method: delivery === 'push' ? PUSH
                                                                   : POLL },
                          description: 'iya-sts federation relationship ' +
                                       record.fedId };
    let secret = '';
    if (delivery === 'push') {
      if (!ctx || !ctx.base) {
        log.debug("Leaving SsfTransmitters.createStream(). No base.");
        return this.refusal('STS-SSF-0113', 'A push stream needs this ' +
          'realm\'s address, which comes from the request.');
      }
      secret = stsCrypto.randomBytes(32).toString('base64url');
      asked.delivery.endpoint_url = String(ctx.base) + PUSH_PATH + '/' +
                                    encodeURIComponent(record.fedId);
      asked.delivery.authorization_header = 'Bearer ' + secret;
    }
    const events = [].concat(record.fedSignalsEvents || []).map(String);
    if (events.length) {
      asked.events_requested = events;
    }
    const answer = await this.call(record, 'POST',
                                   state.config.configuration_endpoint,
                                   asked);
    if (!answer.ok || !answer.json || !answer.json.stream_id) {
      state.lastError = 'create stream: ' + answer.why;
      this.save(state);
      log.debug("Leaving SsfTransmitters.createStream(). Refused.");
      return this.refusal('STS-SSF-0115', 'The partner did not create the ' +
        'stream: ' + answer.why + '.');
    }
    state.delivery = delivery;
    this.adoptStream(state, answer.json);
    if (secret) {
      state.pushSecretDigest = SsfTransmitters.digest('Bearer ' + secret);
    }
    state.state = 'streaming';
    state.lastError = '';
    this.save(state);
    this.audited('ssf.signals.stream', ctx, record, 'stream ' +
                 state.streamId + ' created (' + delivery + ')');
    log.debug("Leaving SsfTransmitters.createStream().");
    return { ok: true, signals: this.view(record),
             message: 'Stream ' + state.streamId + ' created at ' +
                      state.config.issuer + '.' };
  }

  private adoptStream(state: Json, stream: Json): void {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.adoptStream().");
    state.streamId = String(stream.stream_id || state.streamId);
    state.stream = { stream_id: stream.stream_id, aud: stream.aud,
      events_supported: stream.events_supported,
      events_requested: stream.events_requested,
      events_delivered: stream.events_delivered,
      delivery: { method: stream.delivery && stream.delivery.method,
                  endpoint_url: stream.delivery &&
                                stream.delivery.endpoint_url } };
    state.streamAud = Array.isArray(stream.aud) ? stream.aud.map(String)
      : (stream.aud ? [String(stream.aud)] : []);
    if (state.delivery === 'poll' && stream.delivery &&
        stream.delivery.endpoint_url) {
      state.pollEndpoint = String(stream.delivery.endpoint_url);
    }
    log.debug("Leaving SsfTransmitters.adoptStream().");
  }

  private streamUrl(state: Json): string {
    this.deps.log.debug("Entering SsfTransmitters.streamUrl().");
    const u = new URL(state.config.configuration_endpoint);
    u.searchParams.set('stream_id', state.streamId);
    this.deps.log.debug("Leaving SsfTransmitters.streamUrl().");
    return u.toString();
  }

  /**
   * Performs an act on the stream at the partner: `read-stream`,
   * `update-stream` (to the relationship's `fedSignalsEvents`),
   * `delete-stream`, `set-status`, `add-subject`, `remove-subject` or
   * `verify`.
   *
   * @param record - the relationship
   * @param action - the act, without its `signals-` prefix
   * @param body - its fields
   * @param ctx - `via` and `actor`
   * @returns a promise of the outcome
   */
  async streamAct(record: Json, action: string, body: Json,
                  ctx: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.streamAct(). " + action);
    const state = this.stateOf(record.fedId);
    if (!state.streamId || !state.config) {
      log.debug("Leaving SsfTransmitters.streamAct(). No stream.");
      return this.refusal('STS-SSF-0113', 'The relationship ' +
        record.fedId + ' has no stream yet.');
    }
    const b = body || {};
    let answer: Json = null;
    let what = '';
    if (action === 'read-stream') {
      answer = await this.call(record, 'GET', this.streamUrl(state));
      if (answer.ok && answer.json) {
        this.adoptStream(state, answer.json);
      }
      what = 'stream read';
    } else if (action === 'update-stream') {
      const events = [].concat(record.fedSignalsEvents || []).map(String);
      answer = await this.call(record, 'PATCH',
        state.config.configuration_endpoint,
        { stream_id: state.streamId, events_requested: events });
      if (answer.ok && answer.json) {
        this.adoptStream(state, answer.json);
      }
      what = 'events_requested set to fedSignalsEvents';
    } else if (action === 'delete-stream') {
      answer = await this.call(record, 'DELETE', this.streamUrl(state));
      if (answer.ok || answer.status === 404) {
        answer.ok = true;
        state.streamId = '';
        state.stream = null;
        state.streamAud = [];
        state.pollEndpoint = '';
        state.pushSecretDigest = '';
        state.delivery = '';
        state.state = 'discovered';
      }
      what = 'stream deleted';
    } else if (action === 'set-status') {
      const status = String(b.status || '');
      if (['enabled', 'paused', 'disabled'].indexOf(status) < 0) {
        log.debug("Leaving SsfTransmitters.streamAct(). Status.");
        return this.refusal('STS-SSF-0113', 'status must be enabled, ' +
                                            'paused or disabled.');
      }
      answer = await this.call(record, 'POST',
        state.config.status_endpoint,
        { stream_id: state.streamId, status: status,
          reason: String(b.reason || 'set by an administrator') });
      what = 'status set to ' + status;
    } else if (action === 'add-subject' || action === 'remove-subject') {
      let subject: Json = b.subject;
      if (typeof subject === 'string') {
        try {
          subject = JSON.parse(subject);
        } catch (e) {
          log.debug("Caught in SsfTransmitters.streamAct(): " +
                    ((e && e.message) || e));
          subject = null;
        }
      }
      if (!subject || typeof subject !== 'object' || !subject.format) {
        log.debug("Leaving SsfTransmitters.streamAct(). Subject.");
        return this.refusal('STS-SSF-0113', 'subject must be an SSF ' +
                                            'subject identifier with a ' +
                                            'format.');
      }
      answer = await this.call(record, 'POST', action === 'add-subject'
        ? state.config.add_subject_endpoint
        : state.config.remove_subject_endpoint,
        Object.assign({ stream_id: state.streamId, subject: subject },
                      action === 'add-subject' ? { verified: true } : {}));
      what = (action === 'add-subject' ? 'subject added'
                                       : 'subject removed');
    } else if (action === 'verify') {
      state.verifyState = stsCrypto.randomBytes(12).toString('base64url');
      answer = await this.call(record, 'POST',
        state.config.verification_endpoint,
        { stream_id: state.streamId, state: state.verifyState });
      what = 'verification asked';
    }
    if (!answer) {
      log.debug("Leaving SsfTransmitters.streamAct(). Unknown.");
      return this.refusal('STS-SSF-0113', 'Unknown stream act.');
    }
    state.lastError = answer.ok ? '' : action + ': ' + answer.why;
    this.save(state);
    if (!answer.ok) {
      log.debug("Leaving SsfTransmitters.streamAct(). Refused.");
      return this.refusal('STS-SSF-0115', 'The partner refused ' + action +
                                          ': ' + answer.why + '.');
    }
    this.audited('ssf.signals.' + action, ctx, record, what);
    log.debug("Leaving SsfTransmitters.streamAct().");
    return { ok: true, signals: this.view(record),
             answer: answer.json || null,
             message: record.fedId + '\'s Shared Signals: ' + what + '.' };
  }

  // -------------------------------------------------------------------------
  // WHETHER A RELATIONSHIP RECEIVES AT ALL: enabled, and its signals on.
  // -------------------------------------------------------------------------
  private receives(record: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.receives().");
    const federation = this.deps.federation();
    log.debug("Leaving SsfTransmitters.receives().");
    return !!record && federation.isEnabled(record) &&
           federation.signalsEnabled(record);
  }

  // -------------------------------------------------------------------------
  // POLL (RFC 8936): ask, act, acknowledge on the next request.
  // -------------------------------------------------------------------------
  /**
   * Polls a partner (RFC 8936) for up to `ssf.foreignPollMaxRounds` rounds,
   * receiving each SET and acknowledging it on the next request.
   *
   * @param record - the relationship
   * @returns a promise of `{ received, acted, refused, rounds, why }`
   */
  async pollOnce(record: Json): Promise<Json> {
    const { log, now } = this.deps;
    log.debug("Entering SsfTransmitters.pollOnce(). " + record.fedId);
    const out = { received: 0, acted: 0, refused: 0, rounds: 0, why: '' };
    const state = this.stateOf(record.fedId);
    if (!state.pollEndpoint || state.delivery !== 'poll') {
      log.debug("Leaving SsfTransmitters.pollOnce(). No poll stream.");
      out.why = 'no poll stream';
      return out;
    }
    if (!this.receives(record)) {
      log.debug("Leaving SsfTransmitters.pollOnce(). Not receiving.");
      out.why = 'the relationship, or its signals, are turned off';
      return out;
    }
    let ack: string[] = [];
    let setErrs: Json = {};
    const rounds = Math.max(1, this.setting('ssf.foreignPollMaxRounds'));
    for (let i = 0; i < rounds + 1; i++) {
      const last = i === rounds;
      // `stream_id` too: RFC 8936 has no such member because a poll URL is
      // per stream, but a transmitter publishing ONE poll URL for every
      // stream (this service's own does) needs it, and one that does not
      // ignores a member it does not know.
      const asked: Json = { returnImmediately: true, stream_id:
        state.streamId,
        maxEvents: last ? 0 : this.setting('ssf.foreignPollMaxEvents') };
      if (ack.length) {
        asked.ack = ack;
      }
      if (Object.keys(setErrs).length) {
        asked.setErrs = setErrs;
      }
      const answer = await this.call(record, 'POST', state.pollEndpoint,
                                     asked);
      out.rounds++;
      if (!answer.ok || !answer.json) {
        out.why = answer.why;
        break;
      }
      ack = [];
      setErrs = {};
      const sets = answer.json.sets || {};
      for (const jti of Object.keys(sets)) {
        const result = await this.receive(record, String(sets[jti]), 'poll');
        out.received++;
        if (result.ok) {
          ack.push(jti);
          out.acted += result.acted || 0;
        } else {
          out.refused++;
          setErrs[jti] = { err: result.err, description: result.description };
        }
      }
      if (!answer.json.moreAvailable && !ack.length &&
          !Object.keys(setErrs).length) {
        break;
      }
      if (last) {
        break;
      }
    }
    const current = this.stateOf(record.fedId);
    current.lastPollAt = now();
    current.lastPollResult = out.why ? 'failed: ' + out.why
      : out.received + ' received, ' + out.refused + ' refused';
    this.save(current);
    log.debug("Leaving SsfTransmitters.pollOnce(). " + out.received);
    return out;
  }

  // The scheduler job: every realm, every receiving relationship streaming
  // by poll.
  /**
   * Polls every receiving relationship with a poll stream in every realm; the
   * scheduler job's body.
   *
   * @returns a promise of the totals
   */
  async pollAll(): Promise<Json> {
    const { log, realms, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering SsfTransmitters.pollAll().");
    const total = { relationships: 0, received: 0, refused: 0 };
    for (const realm of realms.list()) {
      await realms.run(realm, async function () {
        const due: Json[] = [];
        streams.forEach(function (row: Json) {
          if (row && row.delivery === 'poll' && row.state === 'streaming' &&
              row.pollEndpoint) {
            due.push(row);
          }
        });
        for (const row of due) {
          const record = self.deps.federation().get(row.fedId);
          if (!self.receives(record)) {
            continue;
          }
          try {
            const one = await self.pollOnce(record);
            total.relationships++;
            total.received += one.received;
            total.refused += one.refused;
          } catch (e) {
            log.error(errorCodes.tag('STS-SSF-0116') + 'ssf: polling the ' +
                      'partner of the federation relationship ' + row.fedId +
                      ' failed: ' + ((e && e.message) || e));
          }
        }
      });
    }
    log.debug("Leaving SsfTransmitters.pollAll(). " +
              JSON.stringify(total));
    return total;
  }

  /**
   * Registers the `ssf.foreign-poll` scheduler job, once.
   */
  scheduleJobs(): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SsfTransmitters.scheduleJobs().");
    const scheduler = require('../cluster/scheduler');
    if (!scheduler.job(POLL_JOB)) {
      scheduler.register({
        id: POLL_JOB,
        title: 'Federation partners\' Shared Signals poll',
        describe: 'Polls every federation relationship whose partner\'s ' +
                  'Shared Signals stream is a poll stream (RFC 8936): the ' +
                  'Security Event Tokens it holds are verified, acted on ' +
                  'and acknowledged.',
        owner: 'ssf/ssf_transmitters.ts',
        everySetting: 'ssf.foreignPollS', everySettingUnit: 's',
        run: function (): Promise<Json> {
          return self.pollAll();
        }
      });
    }
    log.debug("Leaving SsfTransmitters.scheduleJobs().");
  }

  // -------------------------------------------------------------------------
  // PUSH (RFC 8935): the authorization header this realm gave, then a SET.
  // -------------------------------------------------------------------------
  /**
   * Answers `POST /federation/signals/:id` (RFC 8935): checks the
   * relationship receives, then the authorization header this realm gave the
   * partner, then receives the SET, answering 202 or an RFC 8935 error.
   *
   * @param req - the request
   * @param res - the response
   * @returns a promise of the answer sent
   */
  async pushRoute(req: Req, res: Res): Promise<unknown> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering SsfTransmitters.pushRoute().");
    const id = String((req.params as Json).id || '');
    const record = this.deps.federation().get(id);
    const state = this.stateOf(id);
    const refuse = function (status: number, code: string, err: string,
                             description: string): unknown {
      log.debug("Entering refuse(). " + code);
      errorCodes.mark(res, code);
      log.debug("Leaving refuse().");
      return res.status(status).json({ err: err, description: description });
    };
    if (!record || !this.receives(record) || state.delivery !== 'push' ||
        !state.pushSecretDigest) {
      log.debug("Leaving SsfTransmitters.pushRoute(). Unknown.");
      return refuse(404, 'STS-SSF-0117', 'invalid_request',
                    'No push stream is registered here.');
    }
    const given = SsfTransmitters.digest(String(req.headers.authorization ||
                                                ''));
    // A length difference answers false in constantTimeEquals(), as the
    // check that stood here did.
    if (!stsCrypto.constantTimeEquals(given,
                                      String(state.pushSecretDigest))) {
      log.debug("Leaving SsfTransmitters.pushRoute(). Authorization.");
      return refuse(401, 'STS-SSF-0117', 'authentication_failed',
                    'The Authorization header is not this stream\'s.');
    }
    // The body as `ssf_receivers.ts` reads one: bytes, text, or `{token}`.
    const raw: Json = (req as Json).body;
    const token = (Buffer.isBuffer(raw) ? raw.toString('utf8')
      : (typeof raw === 'string' ? raw
        : String((raw && raw.token) || ''))).trim();
    const result = await this.receive(record, token, 'push');
    if (!result.ok) {
      log.debug("Leaving SsfTransmitters.pushRoute(). " + result.err);
      return refuse(400, result.code || 'STS-SSF-0118', result.err,
                    result.description);
    }
    log.debug("Leaving SsfTransmitters.pushRoute(). 202.");
    res.status(202).end();
    return undefined;
  }

  /**
   * Registers the push endpoint, `POST /federation/signals/:id`.
   *
   * @param app - the express app
   */
  registerRoutes(app: Json): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SsfTransmitters.registerRoutes().");
    app.post(PUSH_PATH + '/:id', function (req: Req, res: Res) {
      return self.pushRoute(req, res).catch(function (e) {
        log.debug("Caught in the push route: " + ((e && e.message) || e));
        self.deps.errorCodes.mark(res, 'STS-SSF-0118');
        return res.status(500).json({ err: 'invalid_request',
                                      description: 'It could not be read.' });
      });
    });
    log.debug("Leaving SsfTransmitters.registerRoutes().");
  }

  // -------------------------------------------------------------------------
  // ONE SET: verified, then acted on, then recorded. `{ ok, acted } |
  // { ok: false, err, description, code }` — RFC 8935 / 8936 error codes.
  // -------------------------------------------------------------------------
  /**
   * Takes one SET from a partner: verifies it (signature, `typ`, `iss`,
   * `aud`, a fresh `jti`), acts on a verified one as policy permits, and
   * records it. Product mode refuses an unverified SET.
   *
   * @param record - the relationship
   * @param token - the SET, as a compact JWS
   * @param via - `poll` or `push`
   * @returns a promise of `{ ok, acted }` or `{ ok: false, err, description,
   * code }`
   */
  async receive(record: Json, token: string, via: string): Promise<Json> {
    const { log, mode, now } = this.deps;
    log.debug("Entering SsfTransmitters.receive(). " + record.fedId + " " +
              via);
    const state = this.stateOf(record.fedId);
    const parts = String(token || '').split('.');
    let header: Json = null;
    let claims: Json = null;
    try {
      header = JSON.parse(Buffer.from(parts[0] || '', 'base64url')
        .toString('utf8'));
      claims = JSON.parse(Buffer.from(parts[1] || '', 'base64url')
        .toString('utf8'));
    } catch (e) {
      log.debug("Caught in SsfTransmitters.receive(): " +
                ((e && e.message) || e));
      header = null;
    }
    if (parts.length !== 3 || !header || !claims) {
      log.debug("Leaving SsfTransmitters.receive(). Malformed.");
      return this.refused(record, null, 'invalid_request',
        'This is not a Security Event Token.', 'STS-SSF-0118', via);
    }
    const key = record.fedId + '|' + String(claims.jti || '');
    if (claims.jti && inbox.get(key)) {
      // A SET seen before: acknowledged, never acted on twice.
      log.debug("Leaving SsfTransmitters.receive(). A duplicate.");
      return { ok: true, acted: 0, duplicate: true };
    }
    const issuer = (state.config && state.config.issuer) || '';
    let problem = '';
    let err = 'invalid_request';
    let code = 'STS-SSF-0118';
    if (SET_TYPES.indexOf(String(header.typ || '').toLowerCase()) < 0) {
      problem = 'typ is not secevent+jwt';
    } else if (!issuer || claims.iss !== issuer) {
      problem = 'iss is ' + String(claims.iss) + ', not the partner\'s SSF ' +
                'issuer ' + (issuer || '(not discovered)');
      err = 'invalid_issuer';
      code = 'STS-SSF-0119';
    } else if (!this.audienceMatches(state, claims.aud)) {
      problem = 'aud does not name this stream\'s audience';
      err = 'invalid_audience';
      code = 'STS-SSF-0120';
    } else if (!claims.jti || !claims.events ||
               typeof claims.events !== 'object') {
      problem = 'a SET needs a jti and events';
    }
    if (problem) {
      log.debug("Leaving SsfTransmitters.receive(). " + problem);
      return this.refused(record, claims, err, problem, code, via);
    }
    const verified = await this.verifies(state, token, header);
    if (!verified.ok && mode.refusesUnverifiedSignals()) {
      log.debug("Leaving SsfTransmitters.receive(). Unverified.");
      return this.refused(record, claims, 'invalid_key', 'The signature ' +
        'does not verify against the partner\'s keys: ' + verified.why,
        'STS-SSF-0121', via);
    }
    const events = Object.keys(claims.events);
    const subject = claims.sub_id || null;
    const mapped = verified.ok ? this.personFor(record, subject)
                               : { username: '', why: 'unverified' };
    const reactions: Json[] = [];
    let acted = 0;
    if (verified.ok) {
      for (const uri of events) {
        const done = await this.actOn(record, uri, claims.events[uri] || {},
                                      mapped, subject, String(claims.jti));
        done.forEach(function (one: Json) {
          reactions.push(one);
          if (one.done) {
            acted++;
          }
        });
      }
    }
    this.record(record, {
      jti: String(claims.jti), via: via, receivedAt: now(),
      verified: !!verified.ok, refusal: '', why: verified.ok ? ''
        : 'unverified: ' + verified.why,
      events: events, subject: subject, person: mapped.username || '',
      mapping: mapped.why || '', reactions: reactions,
      iat: Number(claims.iat) || 0 });
    const current = this.stateOf(record.fedId);
    current.counts = current.counts || {};
    current.counts.received = (current.counts.received || 0) + 1;
    current.counts.verified = (current.counts.verified || 0) +
      (verified.ok ? 1 : 0);
    current.counts.acted = (current.counts.acted || 0) + acted;
    this.save(current);
    log.debug("Leaving SsfTransmitters.receive(). " + acted + " acted.");
    return { ok: true, acted: acted };
  }

  private audienceMatches(state: Json, aud: Json): boolean {
    this.deps.log.debug("Entering SsfTransmitters.audienceMatches().");
    const given = Array.isArray(aud) ? aud.map(String)
                                     : (aud ? [String(aud)] : []);
    const want = state.streamAud || [];
    this.deps.log.debug("Leaving SsfTransmitters.audienceMatches().");
    return want.length > 0 && given.some(function (one: string) {
      return want.indexOf(one) >= 0;
    });
  }

  // The signature, against the partner's keys: the kid named, else each;
  // the algorithms this service verifies, never taken from the token.
  private async verifies(state: Json, token: string,
                         header: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.verifies().");
    if (!state.config || !state.config.jwks_uri) {
      log.debug("Leaving SsfTransmitters.verifies(). No keys known.");
      return { ok: false, why: 'the partner\'s configuration was never ' +
                               'discovered' };
    }
    const got: Json = await this.deps.jwks().ensure(state.config.jwks_uri,
                                                    header.kid || '');
    const keys = got && got.jwks && Array.isArray(got.jwks.keys)
      ? got.jwks.keys : [];
    const candidates = keys.filter(function (k: Json) {
      return !header.kid || k.kid === header.kid;
    });
    let why = candidates.length ? '' : 'no key ' + (header.kid ? 'with kid ' +
      header.kid + ' ' : '') + 'at the partner\'s jwks_uri';
    for (const jwk of candidates) {
      try {
        stsCrypto.verifyCompactJws(token, jwk,
          { algorithms: stsCrypto.JWS_ASYMMETRIC_ALGS });
        log.debug("Leaving SsfTransmitters.verifies(). Verified.");
        return { ok: true, why: '' };
      } catch (e) {
        log.debug("Caught in SsfTransmitters.verifies(): " +
                  ((e && e.message) || e));
        why = String((e && e.message) || e);
      }
    }
    log.debug("Leaving SsfTransmitters.verifies(). Not verified.");
    return { ok: false, why: why };
  }

  private refused(record: Json, claims: Json, err: string,
                  description: string, code: string, via: string): Json {
    const { log, now } = this.deps;
    log.debug("Entering SsfTransmitters.refused(). " + code);
    if (claims && claims.jti) {
      this.record(record, { jti: String(claims.jti), via: via,
        receivedAt: now(), verified: false, refusal: err,
        why: description, events: Object.keys(claims.events || {}),
        subject: claims.sub_id || null, person: '', mapping: '',
        reactions: [], iat: Number(claims.iat) || 0 });
    }
    const current = this.stateOf(record.fedId);
    current.counts = current.counts || {};
    current.counts.refused = (current.counts.refused || 0) + 1;
    this.save(current);
    log.debug("Leaving SsfTransmitters.refused().");
    return { ok: false, err: err, description: description, code: code };
  }

  // What arrived, capped per realm: the oldest goes first.
  private record(record: Json, row: Json): void {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.record().");
    const cap = Math.max(10, this.setting('ssf.foreignInboxMax'));
    if (inbox.size >= cap) {
      const oldest = inbox.keys().next().value;
      if (oldest !== undefined) {
        inbox.delete(oldest);
      }
    }
    inbox.set(record.fedId + '|' + row.jti, Object.assign({
      relationship: record.fedId }, row));
    log.debug("Leaving SsfTransmitters.record().");
  }

  // -------------------------------------------------------------------------
  // THE PERSON A FOREIGN SUBJECT NAMES (header point 4), or why nobody.
  // -------------------------------------------------------------------------
  /**
   * Finds the one local person a partner's subject names through the
   * relationship: an `iss_sub` (or, from a signals-only partner, an `opaque`)
   * subject by its link, an `email` only where the relationship allows it.
   *
   * @param record - the relationship
   * @param subject - the SET's subject
   * @returns `{ username, ... }`, with `why` when it names nobody
   */
  personFor(record: Json, subject: Json): Json {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.personFor().");
    let s = subject;
    if (s && s.format === 'complex') {
      s = s.user || null;
    }
    if (!s || !s.format) {
      log.debug("Leaving SsfTransmitters.personFor(). No subject.");
      return { username: '', why: 'the SET names no user subject' };
    }
    const federation = this.deps.federation();
    const links = this.deps.links();
    const signalsOnly = !federation.signsIn(record);
    let found: Json[] = [];
    if (s.format === 'iss_sub') {
      const iss = String(s.iss || '');
      if (signalsOnly) {
        // A link an administrator wrote names the iss itself (#374).
        found = federation.peopleLinkedBy(links.linkValue(record.fedId, iss,
          String(s.sub || '')));
      } else {
        // A sign-in partner's people are linked under its fedPeer — the
        // identifier it signs them in with — whichever of its two names
        // the subject carries.
        const peer = String(record.fedPeer || '');
        if (iss !== peer && iss !== federation.signalsIssuerOf(record)) {
          log.debug("Leaving SsfTransmitters.personFor(). Another issuer.");
          return { username: '', why: 'the subject\'s iss ' + iss +
                   ' is neither the partner (' + peer + ') nor its SSF ' +
                   'issuer' };
        }
        found = federation.peopleLinkedBy(links.linkValue(record.fedId, peer,
          String(s.sub || '')));
      }
    } else if (s.format === 'opaque' && signalsOnly) {
      found = federation.peopleLinkedBy(links.linkValue(record.fedId,
        links.OPAQUE, String(s.id || '')));
    } else if (s.format === 'email') {
      if (!federation.boolOf(record.fedSignalEmailMatch, false)) {
        log.debug("Leaving SsfTransmitters.personFor(). No email match.");
        return { username: '', why: 'the relationship does not allow a ' +
                                    'match by mail (fedSignalEmailMatch)' };
      }
      found = federation.peopleByMail(String(s.email || ''));
    } else {
      log.debug("Leaving SsfTransmitters.personFor(). Format.");
      return { username: '', why: 'a ' + s.format + ' subject names nobody ' +
                                  'here' };
    }
    if (found.length !== 1) {
      log.debug("Leaving SsfTransmitters.personFor(). " + found.length);
      return { username: '', why: found.length ? 'the subject names ' +
        found.length + ' people, which is none of them' :
        'nobody here is linked to the subject' };
    }
    log.debug("Leaving SsfTransmitters.personFor(). Found.");
    return { username: String(found[0].username), why: '' };
  }

  // A CAEP session-revoked's session, where a complex subject names one: the
  // OpenID Connect `sid` (or SAML session index) the partner gave it.
  private sessionIdOf(subject: Json): string {
    this.deps.log.debug("Entering SsfTransmitters.sessionIdOf().");
    const session = subject && subject.format === 'complex'
      ? subject.session : null;
    this.deps.log.debug("Leaving SsfTransmitters.sessionIdOf().");
    return session ? String(session.id || session.sub || '') : '';
  }

  // -------------------------------------------------------------------------
  // ONE EVENT, ACTED ON AS THE POLICY SAYS (header point 3).
  // -------------------------------------------------------------------------
  private async actOn(record: Json, uri: string, body: Json, mapped: Json,
                      subject: Json, jti: string): Promise<Json[]> {
    const { log, mode } = this.deps;
    log.debug("Entering SsfTransmitters.actOn(). " + uri);
    const family = uri.indexOf(CAEP_PREFIX) === 0 ? 'caep'
      : uri.indexOf(RISC_PREFIX) === 0 ? 'risc'
      : uri.indexOf(SSF_PREFIX) === 0 ? 'ssf' : '';
    const short = uri.replace(/^.*\//, '');
    const out: Json[] = [];
    if (family === 'ssf') {
      const state = this.stateOf(record.fedId);
      if (short === 'verification' && body.state &&
          body.state === state.verifyState) {
        state.verifiedAt = this.deps.now();
        state.verifyState = '';
        this.save(state);
        out.push({ event: short, reaction: 'verified', done: false });
      }
      log.debug("Leaving SsfTransmitters.actOn(). SSF.");
      return out;
    }
    if (!family) {
      log.debug("Leaving SsfTransmitters.actOn(). Not CAEP or RISC.");
      return [{ event: short, reaction: '', done: false,
                why: 'not a CAEP or RISC event' }];
    }
    if (family === 'caep' && short === 'session-revoked' &&
        body.initiating_entity === 'policy') {
      log.debug("Leaving SsfTransmitters.actOn(). An expiry.");
      return [{ event: short, reaction: '', done: false,
                why: 'an expiry at the partner, not a revocation' }];
    }
    const federation = this.deps.federation();
    const pep = this.deps.signalPep();
    const RESPONSE = pep.RESPONSE || {};
    const decided: Json = pep.decide({
      event: short, family: family, surface: 'federation:' + record.fedId,
      level: String(body.current_level || ''),
      kind: federation.signsIn(record) ? 'sign-in' : 'signals-only' });
    const permitted: string[] = decided.reactions || [];
    const observe = mode.observesSignalsOnly();
    // A DEVICE'S COMPLIANCE (#164, #374) names a device, not a person, so it
    // is decided before the person is needed — and through the policy and
    // the observe gate like every other reaction.
    if (family === 'caep' && short === 'device-compliance-change') {
      if (permitted.indexOf(RESPONSE.SET_DEVICE_COMPLIANCE) < 0) {
        log.debug("Leaving SsfTransmitters.actOn(). Device: not permitted.");
        return [{ event: short, reaction: '', done: false,
                  why: 'the signal-response policy permits no reaction' }];
      }
      if (observe) {
        log.debug("Leaving SsfTransmitters.actOn(). Device: observed.");
        return [{ event: short, reaction: RESPONSE.SET_DEVICE_COMPLIANCE,
                  observed: true, done: false }];
      }
      log.debug("Leaving SsfTransmitters.actOn(). A device.");
      return [this.deviceCompliance(record, body, subject)];
    }
    if (!mapped.username) {
      log.debug("Leaving SsfTransmitters.actOn(). Nobody.");
      return [{ event: short, reaction: '', done: false,
                why: mapped.why || 'the subject names nobody here' }];
    }
    const PERSON = [RESPONSE.REVOKE_GRANTS, RESPONSE.END_PARTNER_SESSIONS,
      RESPONSE.BLOCK_RELATIONSHIP, RESPONSE.UNBLOCK_RELATIONSHIP,
      RESPONSE.END_PERSON_SESSIONS, RESPONSE.DISABLE_ACCOUNT,
      RESPONSE.ENABLE_ACCOUNT];
    // THE SESSIONS THIS RELATIONSHIP STARTED THAT A session-revoked NAMES
    // (#432), worked out BEFORE any reaction runs: ending the partner's
    // sessions is another reaction, and what was issued on them is still
    // recorded against their ids after they are gone.
    const partnerSessions = family === 'caep' && short === 'session-revoked'
      ? this.partnerSessionIds(record, mapped.username,
                               this.sessionIdOf(subject)) : null;
    for (const reaction of permitted) {
      if (PERSON.indexOf(reaction) < 0) {
        continue;
      }
      // THE OPERATOR'S SWITCH (#432): `ssf.signalsRevokeGrants` off records
      // the reaction as skipped, whatever the policy permitted — in
      // development too, so a run that would have revoked says it would not.
      if (reaction === RESPONSE.REVOKE_GRANTS &&
          this.deps.config.value('ssf.signalsRevokeGrants') === false) {
        out.push({ event: short, reaction: reaction, done: false,
                   skipped: 'ssf.signalsRevokeGrants is off' });
        continue;
      }
      if (observe) {
        out.push({ event: short, reaction: reaction, observed: true,
                   done: false });
        continue;
      }
      out.push(await this.react(record, reaction, short, mapped.username,
                                RESPONSE, { jti: jti,
                                  sid: this.sessionIdOf(subject),
                                  partnerSessions: partnerSessions }));
    }
    if (!out.length) {
      out.push({ event: short, reaction: '', done: false,
                 why: 'the signal-response policy permits no reaction' });
    }
    log.debug("Leaving SsfTransmitters.actOn(). " + out.length);
    return out;
  }

  // The ids of the sessions this relationship started for the person — the
  // one `sid` names where the event gave one — live or not yet swept (#432).
  private partnerSessionIds(record: Json, username: string,
                            sid: string): string[] {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.partnerSessionIds(). " +
              record.fedId);
    const out: string[] = [];
    if (!username) {
      log.debug("Leaving SsfTransmitters.partnerSessionIds(). Nobody.");
      return out;
    }
    const wanted = String(username).toLowerCase();
    let authn: Json = null;
    try {
      authn = this.deps.authn();
    } catch (e) {
      log.debug("Caught in SsfTransmitters.partnerSessionIds(): " +
                ((e && e.message) || e));
      authn = null;
    }
    if (authn && authn.sessions) {
      authn.sessions.forEach(function (session: Json): void {
        const held = session && session.fedPartnerSession;
        if (!held || held.relationship !== record.fedId) {
          return;
        }
        if (String((session.user && session.user.username) || '')
              .toLowerCase() !== wanted) {
          return;
        }
        if (sid && String(held.sid || held.sessionIndex || '') !== sid) {
          return;
        }
        out.push(String(session.id));
      });
    }
    log.debug("Leaving SsfTransmitters.partnerSessionIds(). " + out.length);
    return out;
  }

  // THE SESSIONS THIS RELATIONSHIP STARTED FOR THE PERSON — the one `sid`
  // names where the event gave one — ended through the one model, as the
  // partner's own sign-out ends them (#167).
  private endPartnerSessions(record: Json, username: string, sid: string,
                             by: string): number {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.endPartnerSessions(). " +
              record.fedId);
    const authn = this.deps.authn();
    const logout = this.deps.logout();
    const wanted = String(username).toLowerCase();
    const matching: Json[] = [];
    authn.sessions.forEach(function (session: Json): void {
      const held = session && session.fedPartnerSession;
      if (!held || held.relationship !== record.fedId) {
        return;
      }
      if (String((session.user && session.user.username) || '')
            .toLowerCase() !== wanted) {
        return;
      }
      if (authn.sessionEnded(session)) {
        return;
      }
      if (sid && String(held.sid || held.sessionIndex || '') !== sid) {
        return;
      }
      matching.push(session);
    });
    let ended = 0;
    matching.forEach(function (session: Json): void {
      if (logout) {
        const result = logout.endPartnerSession(session, {
          by: by, channel: 'internal',
          // The signal-response policy decided it (#242).
          initiatingEntity: 'policy' });
        ended += ((result && result.terminated) || []).length ? 1 : 0;
      }
    });
    log.debug("Leaving SsfTransmitters.endPartnerSessions(). " + ended);
    return ended;
  }

  // ---------------------------------------------------------------------------
  // signal-revoke-grants (#432, rcbj's decision 1): the person's GNAP grants
  // and OAuth grants, tokens and codes, through `logout.revokeGrantsOf()` —
  // a selective sign-out of exactly those families, so it is the same act
  // `/admin/logout` performs with them ticked (its audit row, CAEP, the
  // grant observer #239). A `session-revoked` narrows it to what was issued
  // on the sessions this relationship started (`partnerSessions`), and one
  // that names none of them revokes nothing. Realm-confined: the ambient
  // realm is the relationship's, and every register read is per realm.
  // `policy` is CAEP's initiating entity, as for every reaction here (#242).
  // ---------------------------------------------------------------------------
  private revokeGrants(record: Json, username: string, event: string,
                       by: string, actor: string,
                       partnerSessions: string[] | null): Json {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.revokeGrants(). " + event);
    const logout = this.deps.logout();
    if (!logout || typeof logout.revokeGrantsOf !== 'function') {
      log.debug("Leaving SsfTransmitters.revokeGrants(). No sign-out here.");
      return { event: event, reaction: 'signal-revoke-grants', done: false,
               why: 'no sign-out module is loaded in this process' };
    }
    if (partnerSessions && !partnerSessions.length) {
      log.debug("Leaving SsfTransmitters.revokeGrants(). No session named.");
      return { event: event, reaction: 'signal-revoke-grants', done: false,
               why: 'the event names no session this relationship started' };
    }
    const result: Json = logout.revokeGrantsOf(username, {
      actor: actor, channel: 'internal', by: by, initiatingEntity: 'policy',
      sessionIds: partnerSessions || undefined });
    const ended = ((result && result.terminated) || []);
    const count = function (family: string): number {
      return ended.filter(function (one: Json): boolean {
        return one && one.family === family;
      }).length;
    };
    log.debug("Leaving SsfTransmitters.revokeGrants(). " + ended.length);
    return { event: event, reaction: 'signal-revoke-grants', done: true,
             revoked: ended.length, gnapGrants: count('gnap'),
             oauthGrants: count('oauth-grant'), tokens: count('token'),
             codes: count('code') };
  }

  private async react(record: Json, reaction: string, event: string,
                      username: string, RESPONSE: Json,
                      ctx: Json): Promise<Json> {
    const { log, errorCodes, blocks } = this.deps;
    log.debug("Entering SsfTransmitters.react(). " + reaction);
    const by = 'a ' + event + ' Security Event Token from the partner of ' +
               'the federation relationship ' + record.fedId;
    const actor = 'federation:' + record.fedId;
    try {
      if (reaction === RESPONSE.REVOKE_GRANTS) {
        const done = this.revokeGrants(record, username, event, by, actor,
                                       ctx.partnerSessions);
        log.debug("Leaving SsfTransmitters.react(). Grants.");
        return done;
      }
      if (reaction === RESPONSE.END_PARTNER_SESSIONS) {
        const ended = this.endPartnerSessions(record, username, ctx.sid, by);
        log.debug("Leaving SsfTransmitters.react(). Partner sessions.");
        return { event: event, reaction: reaction, done: true,
                 ended: ended };
      }
      if (reaction === RESPONSE.BLOCK_RELATIONSHIP) {
        const fresh = blocks.block(record.fedId, username,
          { event: event, jti: ctx.jti, by: by });
        // The partner stopped vouching for them, so what it vouched for
        // ends too (#373).
        const ended = this.endPartnerSessions(record, username, '', by);
        this.deps.audit.audit({ action: 'federation.signal-block',
          actor: actor, protocol: 'Shared Signals', channel: 'internal',
          target: username, summary: username + '\'s sign-ins through ' +
            record.fedId + ' are blocked by ' + by + '; ' + ended +
            ' session(s) it started were ended',
          detail: { relationship: record.fedId, username: username,
                    event: event, ended: String(ended) } });
        log.debug("Leaving SsfTransmitters.react(). Blocked.");
        return { event: event, reaction: reaction, done: true,
                 ended: ended, why: fresh ? '' : 'already blocked' };
      }
      if (reaction === RESPONSE.UNBLOCK_RELATIONSHIP) {
        const lifted = blocks.unblock(record.fedId, username);
        if (lifted) {
          this.deps.audit.audit({ action: 'federation.signal-unblock',
            actor: actor, protocol: 'Shared Signals', channel: 'internal',
            target: username, summary: username + '\'s sign-ins through ' +
              record.fedId + ' are no longer blocked (' + by + ')',
            detail: { relationship: record.fedId, username: username,
                      event: event } });
        }
        log.debug("Leaving SsfTransmitters.react(). Unblocked.");
        return { event: event, reaction: reaction, done: lifted,
                 why: lifted ? '' : 'this relationship had not blocked them' };
      }
      if (reaction === RESPONSE.END_PERSON_SESSIONS) {
        const logout = this.deps.logout();
        const ended = logout ? logout.terminate(username, [], {
          actor: actor, channel: 'internal', by: by,
          // The signal-response policy decided it (#242).
          initiatingEntity: 'policy' }) : null;
        log.debug("Leaving SsfTransmitters.react(). Ended.");
        return { event: event, reaction: reaction, done: true,
                 ended: ((ended && ended.terminated) || []).length };
      }
      if (reaction === RESPONSE.DISABLE_ACCOUNT) {
        const state = this.deps.accountState();
        if (state.isDisabled(username)) {
          log.debug("Leaving SsfTransmitters.react(). Already disabled.");
          return { event: event, reaction: reaction, done: false,
                   why: 'already disabled' };
        }
        const act: Json = state.setDisabled(username, true, {
          actor: actor, door: actor, by: by, reason: by });
        if (act && act.ok) {
          locks.set(String(username), { relationship: record.fedId,
                                        at: this.deps.now() });
        }
        log.debug("Leaving SsfTransmitters.react(). Disabled.");
        return { event: event, reaction: reaction, done: !!(act && act.ok),
                 why: act && !act.ok ? String(act.message || '') : '' };
      }
      if (reaction === RESPONSE.ENABLE_ACCOUNT) {
        const lock = locks.get(String(username));
        if (!lock || lock.relationship !== record.fedId) {
          log.debug("Leaving SsfTransmitters.react(). Not its lock.");
          return { event: event, reaction: reaction, done: false,
                   why: 'the account was not disabled by this relationship' };
        }
        const act: Json = this.deps.accountState().setDisabled(username,
          false, { actor: actor, door: actor, by: by, reason: by });
        if (act && act.ok) {
          locks.delete(String(username));
        }
        log.debug("Leaving SsfTransmitters.react(). Enabled.");
        return { event: event, reaction: reaction, done: !!(act && act.ok) };
      }
    } catch (e) {
      log.warn(errorCodes.tag('STS-SSF-0122') + 'ssf: acting on a ' + event +
               ' from the partner of ' + record.fedId + ' failed: ' +
               ((e && e.message) || e));
    }
    log.debug("Leaving SsfTransmitters.react(). Nothing.");
    return { event: event, reaction: reaction, done: false,
             why: 'it could not be done' };
  }

  // CAEP device-compliance-change (#164's register): the device the
  // subject names, by its id or its key thumbprint, marked as the partner
  // says. Only where the register offers `setCompliance()`.
  private deviceCompliance(record: Json, body: Json, subject: Json): Json {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.deviceCompliance().");
    let devices: Json = null;
    try {
      devices = this.deps.devices();
    } catch (e) {
      log.debug("Caught in SsfTransmitters.deviceCompliance(): " +
                ((e && e.message) || e));
      devices = null;
    }
    if (!devices || typeof devices.setCompliance !== 'function') {
      log.debug("Leaving SsfTransmitters.deviceCompliance(). No register.");
      return { event: 'device-compliance-change', reaction: '', done: false,
               why: 'no device compliance register here' };
    }
    const d = subject && subject.format === 'complex' ? subject.device
                                                      : subject;
    const id = d && d.format === 'iss_sub' ? String(d.sub || '') : '';
    let device: Json = id && typeof devices.byId === 'function'
      ? devices.byId(id) : null;
    if (!device && d && d.jkt && typeof devices.byKeyThumbprint ===
                                 'function') {
      device = devices.byKeyThumbprint(String(d.jkt));
    }
    if (!device) {
      log.debug("Leaving SsfTransmitters.deviceCompliance(). No device.");
      return { event: 'device-compliance-change', reaction: '', done: false,
               why: 'no device here is the subject' };
    }
    const status = String(body.current_status || '');
    devices.setCompliance(device.id || id, status, 'caep',
                          'federation:' + record.fedId,
                          String(body.reason_admin || body.reason || ''));
    log.debug("Leaving SsfTransmitters.deviceCompliance(). Set.");
    return { event: 'device-compliance-change',
             reaction: this.deps.signalPep().RESPONSE.SET_DEVICE_COMPLIANCE,
             done: true };
  }

  // -------------------------------------------------------------------------
  // A RELATIONSHIP DELETED: its stream at the partner first, best effort,
  // then everything minted for it here.
  // -------------------------------------------------------------------------
  /**
   * Forgets a relationship's signals: deletes its stream at the partner
   * (best effort), and drops its state, its arrivals, its blocks and its
   * account-lock records. The accounts it disabled stay disabled.
   *
   * @param record - the relationship, while it still exists
   * @param ctx - `via` and `actor`
   * @returns a promise of what was dropped
   */
  async forget(record: Json, ctx: Json): Promise<Json> {
    const { log, blocks } = this.deps;
    log.debug("Entering SsfTransmitters.forget(). " + record.fedId);
    const state = this.stateOf(record.fedId);
    let streamDeleted = false;
    if (state.streamId && state.config) {
      try {
        const done = await this.streamAct(record, 'delete-stream', {}, ctx);
        streamDeleted = !!done.ok;
      } catch (e) {
        log.debug("Caught in SsfTransmitters.forget(): " +
                  ((e && e.message) || e));
        streamDeleted = false;
      }
    }
    streams.delete(record.fedId);
    const arrivals: string[] = [];
    inbox.forEach(function (row: Json, key: string): void {
      if (row && row.relationship === record.fedId) {
        arrivals.push(key);
      }
    });
    arrivals.forEach(function (key: string): void {
      inbox.delete(key);
    });
    const lockKeys: string[] = [];
    locks.forEach(function (row: Json, key: string): void {
      if (row && row.relationship === record.fedId) {
        lockKeys.push(key);
      }
    });
    lockKeys.forEach(function (key: string): void {
      locks.delete(key);
    });
    const lifted = blocks.clearRelationship(record.fedId);
    tokens.delete(this.tokenKey(record));
    log.debug("Leaving SsfTransmitters.forget().");
    return { streamDeleted: streamDeleted, arrivals: arrivals.length,
             blocks: lifted, locks: lockKeys.length };
  }

  // -------------------------------------------------------------------------
  // THE RELATIONSHIP'S ACTS (rule 7): `admin-core/admin_actions.ts`'s
  // federationAction() hands every `signals-*` action here.
  // -------------------------------------------------------------------------
  /**
   * Performs one of a relationship's Shared Signals acts: `signals-discover`,
   * `-create-stream`, `-read-stream`, `-update-stream`, `-delete-stream`,
   * `-set-status`, `-add-subject`, `-remove-subject`, `-verify`, `-poll-now`
   * or `-unblock` (with `user`).
   *
   * @param body - `action`, `id` (the relationship) and the act's fields
   * @param ctx - `via`, `actor` and `base`
   * @returns a promise of the outcome
   */
  async act(body: Json, ctx: Json): Promise<Json> {
    const { log, blocks } = this.deps;
    log.debug("Entering SsfTransmitters.act().");
    const b = body || {};
    const action = String(b.action || '');
    if (ACTIONS.indexOf(action) < 0) {
      log.debug("Leaving SsfTransmitters.act(). Unknown.");
      return this.refusal('STS-SSF-0113', 'Unknown action "' + action +
        '". The ' + ACTIONS.length + ' are: ' + ACTIONS.join(', ') + '.');
    }
    const id = String(b.id || b.relationship || '').trim();
    const federation = this.deps.federation();
    const record = federation.get(id);
    if (!record || record.fedRole !== 'service-provider') {
      log.debug("Leaving SsfTransmitters.act(). No such relationship.");
      return this.refusal('STS-SSF-0113', 'There is no service-provider-' +
        'side federation relationship "' + id + '" in this realm.');
    }
    if (action === 'signals-unblock') {
      const who = String(b.user || b.username || '').trim();
      const lifted = who ? blocks.unblock(record.fedId, who) : false;
      if (!lifted) {
        log.debug("Leaving SsfTransmitters.act(). Nothing to unblock.");
        return this.refusal('STS-SSF-0132', (who ? who : 'Nobody') +
          ' is not blocked through ' + record.fedId + '.');
      }
      this.audited('ssf.signals.unblock', ctx, record, who + '\'s sign-ins ' +
                   'through it unblocked by an administrator');
      log.debug("Leaving SsfTransmitters.act(). Unblocked.");
      return { ok: true, signals: this.view(record),
               message: who + ' may sign in through ' + record.fedId +
                        ' again.' };
    }
    if (!federation.signalsEnabled(record)) {
      log.debug("Leaving SsfTransmitters.act(). Signals off.");
      return this.refusal('STS-SSF-0132', 'The relationship ' + id +
        '\'s Shared Signals are off: turn fedSignalsEnabled on first.');
    }
    let result: Json;
    if (action === 'signals-discover') {
      result = await this.discover(record, ctx);
    } else if (action === 'signals-create-stream') {
      result = await this.createStream(record, ctx);
    } else if (action === 'signals-poll-now') {
      const polled = await this.pollOnce(record);
      result = polled.why && !polled.received
        ? this.refusal('STS-SSF-0116', 'The poll failed: ' + polled.why + '.')
        : { ok: true, polled: polled, signals: this.view(record),
            message: 'Polled ' + record.fedId + ': ' + polled.received +
              ' received, ' + polled.refused + ' refused, ' + polled.acted +
              ' reaction(s).' };
    } else {
      result = await this.streamAct(record,
        action.replace(/^signals-/, ''), b, ctx);
    }
    log.debug("Leaving SsfTransmitters.act(). " + action + " " + result.ok);
    return result;
  }

  // -------------------------------------------------------------------------
  // WHAT A CALLER SEES: never a secret or a token.
  // -------------------------------------------------------------------------
  /**
   * Returns a relationship's Shared Signals as a caller sees them: the
   * configuration it reads, the stream's state, and never a secret.
   *
   * @param record - the relationship
   * @returns the view
   */
  view(record: Json): Json {
    const { log, blocks } = this.deps;
    log.debug("Entering SsfTransmitters.view().");
    const federation = this.deps.federation();
    const state = this.stateOf(record.fedId);
    const iso = function (ms: unknown): string {
      log.debug("Entering iso().");
      log.debug("Leaving iso().");
      return Number(ms) ? new Date(Number(ms)).toISOString() : '';
    };
    const c = federation.signalsCredentialOf(record);
    const readiness = federation.signalsReadinessOf(record);
    log.debug("Leaving SsfTransmitters.view().");
    return {
      relationship: record.fedId, name: record.fedName || record.fedId,
      kind: federation.signsIn(record) ? 'sign-in' : 'signals-only',
      enabled: federation.isEnabled(record),
      signalsEnabled: federation.signalsEnabled(record),
      receiving: this.receives(record),
      issuer: federation.signalsIssuerOf(record),
      delivery: String(record.fedSignalsDelivery || 'poll'),
      eventsRequested: [].concat(record.fedSignalsEvents || []),
      credential: { method: c.method, tokenEndpoint: c.tokenEndpoint || '',
                    clientId: c.clientId || '', scope: c.scope || '',
                    secretHeld: !!(c.clientSecret || c.bearer) },
      ready: readiness.ready, missing: readiness.missing,
      config: state.config, discoveryUrl: state.discoveryUrl || '',
      discoveredAt: iso(state.discoveredAt),
      streamId: state.streamId, stream: state.stream,
      streamDelivery: state.delivery || '',
      streamAud: state.streamAud || [], pollEndpoint: state.pollEndpoint,
      pushEndpoint: PUSH_PATH + '/' + encodeURIComponent(record.fedId),
      pushEndpointSet: !!state.pushSecretDigest, state: state.state,
      verifiedAt: iso(state.verifiedAt), lastPollAt: iso(state.lastPollAt),
      lastPollResult: state.lastPollResult || '',
      lastError: state.lastError || '', counts: state.counts || {},
      blocks: blocks.list(record.fedId)
    };
  }

  /**
   * Returns what arrived from one relationship, or from all, newest first.
   *
   * @param fedId - the relationship, or empty for all
   * @param limit - the most rows (default 200)
   * @returns the rows, `receivedAt` as an ISO time
   */
  arrivals(fedId?: string, limit?: number): Json[] {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.arrivals().");
    const received: Json[] = [];
    inbox.forEach(function (row: Json) {
      if (row && (!fedId || row.relationship === fedId)) {
        received.push(Object.assign({}, row, {
          receivedAt: new Date(Number(row.receivedAt)).toISOString() }));
      }
    });
    received.sort(function (a, b) {
      return String(b.receivedAt).localeCompare(String(a.receivedAt));
    });
    log.debug("Leaving SsfTransmitters.arrivals(). " + received.length);
    return received.slice(0, Number(limit) || 200);
  }

  /**
   * Builds the monitoring report: every relationship whose signals are on (or
   * that holds a stream), what arrived newest first, the blocks and account
   * locks partners put on people here, and whether this realm only observes.
   *
   * @param options - `relationship`, which narrows what arrived, and `limit`
   * (default 200)
   * @returns `{ relationships, received, blocks, locks, observeOnly }`
   */
  report(options?: Json): Json {
    const { log, blocks } = this.deps;
    const self = this;
    log.debug("Entering SsfTransmitters.report().");
    const o = options || {};
    const federation = this.deps.federation();
    const list: Json[] = [];
    (federation.inRole('service-provider') || []).forEach(
      function (record: Json): void {
        if (federation.signalsEnabled(record) || streams.get(record.fedId)) {
          list.push(self.view(record));
        }
      });
    const held: Json[] = [];
    locks.forEach(function (row: Json, username: string) {
      held.push({ username: username, relationship: row.relationship,
                  at: new Date(Number(row.at)).toISOString() });
    });
    log.debug("Leaving SsfTransmitters.report().");
    return { relationships: list,
             received: this.arrivals(o.relationship, o.limit),
             blocks: blocks.list(), locks: held,
             observeOnly: this.deps.mode.observesSignalsOnly() };
  }

  // -------------------------------------------------------------------------
  // THE OTHER DIRECTION (#373): what this service SENDS the partner of an
  // identity-provider-side relationship, read off this service's own
  // transmitter — the streams its application owns. Read-only; the streams
  // stay the application's.
  // -------------------------------------------------------------------------
  /**
   * Returns the streams on this service's own transmitter that an
   * identity-provider-side relationship's application owns, with what each
   * delivered and its dead letters.
   *
   * @param record - the relationship
   * @returns `{ application, streams }`
   */
  outboundFor(record: Json): Json {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.outboundFor().");
    const application = String((record && record.fedApplication) || '')
      .trim();
    if (!application) {
      log.debug("Leaving SsfTransmitters.outboundFor(). No application.");
      return { application: '', streams: [] };
    }
    let own: Json = null;
    let applications: Json = null;
    try {
      own = this.deps.ownStreams();
      applications = this.deps.applications();
    } catch (e) {
      log.debug("Caught in SsfTransmitters.outboundFor(): " +
                ((e && e.message) || e));
      log.debug("Leaving SsfTransmitters.outboundFor(). No transmitter.");
      return { application: application, streams: [] };
    }
    const iso = function (s: unknown): string {
      log.debug("Entering iso().");
      log.debug("Leaving iso().");
      return Number(s) ? new Date(Number(s) * 1000).toISOString() : '';
    };
    const rows = (own.listStreams() || []).filter(function (one: Json) {
      if (own.isInternal(one)) {
        return false;
      }
      const owner = applications.ssfAllowedEventsFor(one.createdBy);
      return !!owner && owner.identifier === application;
    }).map(function (one: Json): Json {
      const letters = own.deadLettersOf(one) || [];
      return { streamId: one.stream_id,
               delivery: own.deliveryName(one.delivery &&
                                          one.delivery.method),
               status: one.status || 'enabled',
               eventsDelivered: one.events_delivered || [],
               createdBy: one.createdBy || '',
               lastActivityAt: iso(one.lastActivityAt),
               dead: !!own.isDead(one),
               deadLetters: letters.length };
    });
    log.debug("Leaving SsfTransmitters.outboundFor(). " + rows.length);
    return { application: application, streams: rows };
  }
}

const slot = new InstanceSlot<SsfTransmitters>(
  'ssf/ssf_transmitters',
  () => new SsfTransmitters(SsfTransmitters.defaultDeps()),
  function (instance: SsfTransmitters): void {
    instance.scheduleJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * This realm as the receiver of its federation partners' Shared Signals.
 *
 * Exports the `SsfTransmitters` class, `POLL_JOB`, `ACTIONS`, and facades
 * that forward to the installed instance.
 *
 * @namespace
 */
export = {
  SsfTransmitters: SsfTransmitters,
  /**
   * Installs the instance the facades forward to.
   */
  installInstance: (instance: SsfTransmitters): void => slot.install(instance),
  /**
   * Says where the current instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  POLL_JOB: POLL_JOB,
  ACTIONS: ACTIONS,
  PUSH_PATH: PUSH_PATH,
  discoveryUrlFor: SsfTransmitters.discoveryUrlFor,
  stateOf: slot.forward('stateOf'),
  discover: slot.forward('discover'),
  createStream: slot.forward('createStream'),
  streamAct: slot.forward('streamAct'),
  pollOnce: slot.forward('pollOnce'),
  pollAll: slot.forward('pollAll'),
  receive: slot.forward('receive'),
  personFor: slot.forward('personFor'),
  forget: slot.forward('forget'),
  act: slot.forward('act'),
  view: slot.forward('view'),
  arrivals: slot.forward('arrivals'),
  report: slot.forward('report'),
  outboundFor: slot.forward('outboundFor'),
  registerRoutes: slot.forward('registerRoutes')
};
