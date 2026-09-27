'use strict';
//
// File: ssf_transmitters.ts
//
// ===========================================================================
// THIS REALM AS THE RECEIVER OF A FOREIGN TRANSMITTER (#153, 2026-09-26) —
// Shared Signals Framework 1.0 with the roles the other way round.
//
// Until #153 the only receivers here were this service's own console and
// portal, fed by its own transmitter (`ssf_receivers.ts`), and the debugger's
// inbox. Another identity service that transmits CAEP and RISC events about
// people who ALSO sign in here — a partner this realm federates with — had
// nowhere to send them. rcbj's answers on #153 were every recommendation:
//
// **1. ONLY A TRANSMITTER AN ADMINISTRATOR REGISTERS.** Per realm, an issuer,
// discovered through its `/.well-known/ssf-configuration` (SSF 1.0 section
// 7; the path inserted before the issuer's own, as RFC 8414 does), whose
// document must name that issuer. Its `jwks_uri` is fetched and cached for
// verification (`oauth-oidc/client_jwks.js`), and every endpoint the
// document names is dialled through `federation_http.fetchPublished()` —
// internal addresses refused in product mode, the connection pinned, no
// redirect, a cap. The administrator supplied the issuer and nothing a
// request carries can name another; that is the argued row in root
// CLAUDE.md's "Dial a URL a CALLER supplied" index.
//
// **2. A STREAM AT THE TRANSMITTER, AND BOTH DELIVERIES.** This realm creates,
// reads, updates and deletes its stream at the transmitter's configuration
// endpoint (section 8.1.1), sets its status, adds and removes subjects and
// asks for verification — with an access token the transmitter's
// authorization server issues this realm by client credentials (or a bearer
// token the administrator pasted). POLL (RFC 8936) is the
// `ssf.foreign-poll` scheduler job — a cluster job, per realm — acknowledging
// what it received on the next request; PUSH (RFC 8935) is
// `POST /ssf/transmitters/{id}/push`, authenticated by the authorization
// header this realm gave the transmitter when it created the stream (kept
// only as its digest, compared in constant time).
//
// **3. NOTHING ACTS ON A SET UNLESS IT VERIFIED** (#117's rule): the
// signature against the transmitter's keys (the algorithms named, never
// taken from the token), `typ` secevent+jwt, `iss` the transmitter's issuer,
// `aud` the stream's, a `jti` never seen before. In product an unverified
// SET is refused (`mode.refusesUnverifiedSignals()`); in development it is
// recorded and acted on in no way. What a verified one leads to is the
// `signal-response` policy's decision, asked with the surface
// `foreign:<id>`: end the person's sessions here (session-revoked,
// credential-change, …), disable their account (account-disabled), enable
// it again (account-enabled — only a lock this transmitter's own event
// put there). Development only RECORDS what it would do unless
// `ssf.actOnSignalsInDevelopment` is on (`mode.observesSignalsOnly()`).
//
// **4. A FOREIGN SUBJECT IS A LOCAL PERSON THROUGH A FEDERATION
// RELATIONSHIP.** The registration names one (`ou=federations`): an
// `iss_sub` subject with that relationship's issuer is the ONE person whose
// `federationLink` holds it; an `email` subject is the one person with that
// address only where the relationship sets `fedSignalEmailMatch`. Anything
// else — no relationship, no link, two people — is recorded and acts on
// nobody.
//
// A LIBRARY with two routes of its own (the push endpoint, and the page's
// JSON is the console's): `common/protocol_stack.ts` builds it after the
// directory and registers its route.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import mode = require('../common/mode');
import stsCrypto = require('../common/crypto');

type Json = any;
type Req = import('express').Request;
type Res = import('express').Response;

const POLL_JOB = 'ssf.foreign-poll';
const PUSH = 'urn:ietf:rfc:8935';
const POLL = 'urn:ietf:rfc:8936';
const SET_TYPES = ['secevent+jwt', 'application/secevent+jwt'];
const CAEP_PREFIX = 'https://schemas.openid.net/secevent/caep/event-type/';
const RISC_PREFIX = 'https://schemas.openid.net/secevent/risc/event-type/';
const SSF_PREFIX = 'https://schemas.openid.net/secevent/ssf/event-type/';

// Per realm and persisted: the registrations; what arrived (which is also
// the jti history); which lock each transmitter put on whom.
const transmitters = realms.map({ persist: 'ssf.foreignTransmitters' });
const inbox = realms.map({ persist: 'ssf.foreignInbox' });
const locks = realms.map({ persist: 'ssf.foreignLocks' });

// Access tokens, per process and short-lived: `<realm>|<id>` → { token,
// until }. A process that has none asks again; nothing is lost.
const tokens = new Map<string, Json>();

interface TransmittersDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  mode: typeof mode;
  now: () => number;
  // Lazily, each: the outbound door, the key cache, the federation register,
  // the policy, the sign-out and the account lock.
  fedHttp: () => Json;
  jwks: () => Json;
  federation: () => Json;
  links: () => Json;
  signalPep: () => Json;
  logout: () => Json;
  accountState: () => Json;
  devices: () => Json;
}

class SsfTransmitters {
  static readonly POLL_JOB = POLL_JOB;

  constructor(private readonly deps: TransmittersDeps) {
    deps.log.debug("Entering SsfTransmitters.constructor().");
    deps.log.debug("Leaving SsfTransmitters.constructor().");
  }

  static defaultDeps(): TransmittersDeps {
    helpers.log.debug("Entering SsfTransmitters.defaultDeps().");
    helpers.log.debug("Leaving SsfTransmitters.defaultDeps().");
    return {
      log: helpers.log, config: config, realms: realms,
      errorCodes: errorCodes, audit: audit, mode: mode,
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
      accountState: function (): Json {
        return require('../common/account_state');
      },
      devices: function (): Json {
        return require('../common/devices');
      }
    };
  }

  private setting(key: string): number {
    const { log, config } = this.deps;
    log.debug("Entering SsfTransmitters.setting(). " + key);
    log.debug("Leaving SsfTransmitters.setting().");
    return Number(config.value(key));
  }

  static digest(text: string): string {
    helpers.log.debug("Entering SsfTransmitters.digest().");
    helpers.log.debug("Leaving SsfTransmitters.digest().");
    return nodeCrypto.createHash('sha256').update(String(text))
      .digest('base64url');
  }

  // SSF 1.0 section 7: the configuration document's address for an issuer —
  // `/.well-known/ssf-configuration` inserted before the issuer's path.
  static discoveryUrlFor(issuer: string): string {
    helpers.log.debug("Entering SsfTransmitters.discoveryUrlFor().");
    const u = new URL(String(issuer));
    const path = u.pathname.replace(/\/+$/, '');
    helpers.log.debug("Leaving SsfTransmitters.discoveryUrlFor().");
    return u.origin + '/.well-known/ssf-configuration' +
      (path && path !== '/' ? path : '');
  }

  get(id: string): Json {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.get(). " + id);
    const held = transmitters.get(String(id || ''));
    log.debug("Leaving SsfTransmitters.get(). " + !!held);
    return held ? Object.assign({}, held) : null;
  }

  private save(record: Json): void {
    const { log, now } = this.deps;
    log.debug("Entering SsfTransmitters.save(). " + record.id);
    record.updatedAt = now();
    transmitters.set(record.id, Object.assign({}, record));
    log.debug("Leaving SsfTransmitters.save().");
  }

  // One outbound request to an endpoint the transmitter's document named,
  // JSON both ways. `{ ok, status, json, why }`; never rejects.
  private async call(record: Json, method: string, url: string,
                     body?: Json, withToken?: boolean): Promise<Json> {
    const { log, fedHttp } = this.deps;
    log.debug("Entering SsfTransmitters.call(). " + method + " " + url);
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

  // The access token this realm presents to the transmitter: a pasted
  // bearer, or client credentials at the administrator's token endpoint.
  private async accessToken(record: Json): Promise<Json> {
    const { log, fedHttp, now, realms } = this.deps;
    log.debug("Entering SsfTransmitters.accessToken(). " + record.id);
    const credential = record.credential || {};
    if (credential.method === 'bearer') {
      log.debug("Leaving SsfTransmitters.accessToken(). Pasted.");
      return credential.bearer ? { ok: true, token: credential.bearer }
        : { ok: false, why: 'no bearer token is configured' };
    }
    const key = realms.currentId() + '|' + record.id;
    const held = tokens.get(key);
    if (held && held.until > now()) {
      log.debug("Leaving SsfTransmitters.accessToken(). Cached.");
      return { ok: true, token: held.token };
    }
    const form = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: String(credential.clientId || ''),
      client_secret: String(credential.clientSecret || ''),
      scope: String(credential.scope || 'ssf:read ssf:write')
    }).toString();
    const answer: Json = await fedHttp().fetchPublished(
      String(credential.tokenEndpoint || ''), {
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

  // -------------------------------------------------------------------------
  // REGISTER: discover the issuer's configuration and keys, and keep them.
  // -------------------------------------------------------------------------
  async add(body: Json, ctx: Json): Promise<Json> {
    const { log, fedHttp, errorCodes, now } = this.deps;
    log.debug("Entering SsfTransmitters.add().");
    const b = body || {};
    const refuse = function (message: string): Json {
      log.debug("Entering refuse().");
      log.debug("Leaving refuse().");
      return errorCodes.mark({ ok: false, errors: [message] },
                             'STS-SSF-0113');
    };
    const id = String(b.id || '').trim();
    if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(id)) {
      log.debug("Leaving SsfTransmitters.add(). The id.");
      return refuse('The id must be lower-case letters, digits and hyphens.');
    }
    if (transmitters.get(id)) {
      log.debug("Leaving SsfTransmitters.add(). Taken.");
      return refuse('A transmitter "' + id + '" is already registered.');
    }
    if (transmitters.size >= this.setting('ssf.foreignMaxTransmitters')) {
      log.debug("Leaving SsfTransmitters.add(). Full.");
      return refuse('This realm already holds ssf.foreignMaxTransmitters ' +
                    'transmitters.');
    }
    const issuer = String(b.issuer || '').trim();
    let discovery = String(b.discoveryUrl || '').trim();
    try {
      discovery = discovery || SsfTransmitters.discoveryUrlFor(issuer);
    } catch (e) {
      log.debug("Caught in SsfTransmitters.add(): " +
                ((e && e.message) || e));
      log.debug("Leaving SsfTransmitters.add(). The issuer.");
      return refuse('The issuer must be a URL.');
    }
    const fed = this.deps.federation().get(String(b.federationId || ''));
    if (!fed) {
      log.debug("Leaving SsfTransmitters.add(). No relationship.");
      return refuse('federationId must name a federation relationship in ' +
        'this realm: it is how a subject the transmitter names becomes a ' +
        'person here.');
    }
    const delivery = String(b.delivery || 'poll');
    if (delivery !== 'poll' && delivery !== 'push') {
      log.debug("Leaving SsfTransmitters.add(). Delivery.");
      return refuse('delivery must be poll or push.');
    }
    const method = b.bearer ? 'bearer' : 'client_credentials';
    if (method === 'client_credentials' &&
        (!b.tokenEndpoint || !b.clientId)) {
      log.debug("Leaving SsfTransmitters.add(). No credential.");
      return refuse('Give tokenEndpoint, clientId and clientSecret (client ' +
        'credentials), or bearer — how this realm authenticates to the ' +
        'transmitter.');
    }
    const fetched: Json = await fedHttp().fetchPublished(discovery, {
      accept: 'application/json',
      timeoutMs: this.setting('ssf.foreignTimeoutMs') });
    let doc: Json = null;
    try {
      doc = fetched.ok ? JSON.parse(fetched.body.toString('utf8')) : null;
    } catch (e) {
      log.debug("Caught in SsfTransmitters.add(): " +
                ((e && e.message) || e));
      doc = null;
    }
    if (!doc) {
      log.debug("Leaving SsfTransmitters.add(). Discovery.");
      return errorCodes.mark({ ok: false, errors: ['The configuration ' +
        'document at ' + discovery + ' could not be read: ' +
        String(fetched.why || fetched.status) + '.'] }, 'STS-SSF-0114');
    }
    if (doc.issuer !== issuer || !doc.jwks_uri ||
        !doc.configuration_endpoint) {
      log.debug("Leaving SsfTransmitters.add(). Not the issuer's.");
      return errorCodes.mark({ ok: false, errors: ['The configuration ' +
        'document must name the issuer ' + issuer + ' (it names ' +
        String(doc.issuer) + ') and a jwks_uri and configuration_endpoint ' +
        '(SSF 1.0 section 7.1).'] }, 'STS-SSF-0114');
    }
    const methods = Array.isArray(doc.delivery_methods_supported)
      ? doc.delivery_methods_supported : [];
    if (methods.indexOf(delivery === 'push' ? PUSH : POLL) < 0) {
      log.debug("Leaving SsfTransmitters.add(). Delivery unsupported.");
      return refuse('The transmitter does not offer ' + delivery +
                    ' delivery.');
    }
    const keys: Json = await this.deps.jwks().ensure(String(doc.jwks_uri),
                                                     '');
    if (!keys.ok) {
      log.debug("Leaving SsfTransmitters.add(). Keys.");
      return errorCodes.mark({ ok: false, errors: ['The transmitter\'s ' +
        'jwks_uri could not be read: ' + keys.why + '.'] }, 'STS-SSF-0114');
    }
    const record = {
      id: id, issuer: issuer, discoveryUrl: discovery,
      config: {
        issuer: doc.issuer, jwks_uri: doc.jwks_uri,
        configuration_endpoint: doc.configuration_endpoint,
        status_endpoint: doc.status_endpoint || '',
        add_subject_endpoint: doc.add_subject_endpoint || '',
        remove_subject_endpoint: doc.remove_subject_endpoint || '',
        verification_endpoint: doc.verification_endpoint || '',
        delivery_methods_supported: methods
      },
      federationId: String(fed.fedId || b.federationId),
      delivery: delivery,
      eventsRequested: Array.isArray(b.eventsRequested)
        ? b.eventsRequested.map(String)
        : String(b.eventsRequested || '').split(/[\s,]+/).filter(Boolean),
      credential: method === 'bearer'
        ? { method: 'bearer', bearer: String(b.bearer) }
        : { method: 'client_credentials',
            tokenEndpoint: String(b.tokenEndpoint),
            clientId: String(b.clientId),
            clientSecret: String(b.clientSecret || ''),
            scope: String(b.scope || 'ssf:read ssf:write') },
      streamId: '', stream: null, streamAud: [], pollEndpoint: '',
      pushSecretDigest: '', verifyState: '', verifiedAt: 0,
      state: 'registered', createdAt: now(), lastPollAt: 0,
      lastPollResult: '', lastError: '',
      counts: { received: 0, verified: 0, refused: 0, acted: 0 }
    };
    this.save(record);
    this.audited('ssf.transmitter.add', ctx, record, 'registered');
    log.debug("Leaving SsfTransmitters.add().");
    return { ok: true, transmitter: this.view(record),
             message: 'Transmitter ' + id + ' registered from ' + discovery +
                      '. Create its stream next.' };
  }

  private audited(action: string, ctx: Json, record: Json,
                  what: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering SsfTransmitters.audited(). " + action);
    audit.audit({ action: action, actor: (ctx && ctx.actor) || '',
      protocol: 'Shared Signals', channel: (ctx && ctx.via) || 'http',
      target: record.issuer,
      summary: 'foreign SSF transmitter ' + record.id + ': ' + what,
      detail: { transmitter: record.id, streamId: record.streamId || '' } });
    log.debug("Leaving SsfTransmitters.audited().");
  }

  // -------------------------------------------------------------------------
  // THE STREAM AT THE TRANSMITTER (section 8.1.1).
  // -------------------------------------------------------------------------
  async createStream(record: Json, ctx: Json): Promise<Json> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering SsfTransmitters.createStream(). " + record.id);
    if (record.streamId) {
      log.debug("Leaving SsfTransmitters.createStream(). Has one.");
      return errorCodes.mark({ ok: false, errors: ['Transmitter ' +
        record.id + ' already has stream ' + record.streamId + '.'] },
        'STS-SSF-0113');
    }
    const delivery: Json = { method: record.delivery === 'push' ? PUSH
                                                                  : POLL };
    let secret = '';
    if (record.delivery === 'push') {
      if (!ctx || !ctx.base) {
        log.debug("Leaving SsfTransmitters.createStream(). No base.");
        return errorCodes.mark({ ok: false, errors: ['A push stream needs ' +
          'this realm\'s address, which comes from the request.'] },
          'STS-SSF-0113');
      }
      secret = nodeCrypto.randomBytes(32).toString('base64url');
      delivery.endpoint_url = String(ctx.base) + '/ssf/transmitters/' +
                              record.id + '/push';
      delivery.authorization_header = 'Bearer ' + secret;
    }
    const asked: Json = { delivery: delivery,
                          description: 'iya-sts realm receiver ' + record.id };
    if (record.eventsRequested.length) {
      asked.events_requested = record.eventsRequested;
    }
    const answer = await this.call(record, 'POST',
                                   record.config.configuration_endpoint,
                                   asked);
    if (!answer.ok || !answer.json || !answer.json.stream_id) {
      record.lastError = 'create stream: ' + answer.why;
      this.save(record);
      log.debug("Leaving SsfTransmitters.createStream(). Refused.");
      return errorCodes.mark({ ok: false, errors: ['The transmitter did ' +
        'not create the stream: ' + answer.why + '.'] }, 'STS-SSF-0115');
    }
    this.adoptStream(record, answer.json);
    if (secret) {
      record.pushSecretDigest = SsfTransmitters.digest('Bearer ' + secret);
    }
    record.state = 'streaming';
    record.lastError = '';
    this.save(record);
    this.audited('ssf.transmitter.stream', ctx, record, 'stream ' +
                 record.streamId + ' created');
    log.debug("Leaving SsfTransmitters.createStream().");
    return { ok: true, transmitter: this.view(record),
             message: 'Stream ' + record.streamId + ' created at ' +
                      record.issuer + '.' };
  }

  private adoptStream(record: Json, stream: Json): void {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.adoptStream().");
    record.streamId = String(stream.stream_id || record.streamId);
    record.stream = { stream_id: stream.stream_id, aud: stream.aud,
      events_supported: stream.events_supported,
      events_requested: stream.events_requested,
      events_delivered: stream.events_delivered,
      delivery: { method: stream.delivery && stream.delivery.method,
                  endpoint_url: stream.delivery &&
                                stream.delivery.endpoint_url } };
    record.streamAud = Array.isArray(stream.aud) ? stream.aud.map(String)
      : (stream.aud ? [String(stream.aud)] : []);
    if (record.delivery === 'poll' && stream.delivery &&
        stream.delivery.endpoint_url) {
      record.pollEndpoint = String(stream.delivery.endpoint_url);
    }
    log.debug("Leaving SsfTransmitters.adoptStream().");
  }

  private streamUrl(record: Json): string {
    this.deps.log.debug("Entering SsfTransmitters.streamUrl().");
    const u = new URL(record.config.configuration_endpoint);
    u.searchParams.set('stream_id', record.streamId);
    this.deps.log.debug("Leaving SsfTransmitters.streamUrl().");
    return u.toString();
  }

  async streamAct(record: Json, action: string, body: Json,
                  ctx: Json): Promise<Json> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering SsfTransmitters.streamAct(). " + action);
    if (!record.streamId) {
      log.debug("Leaving SsfTransmitters.streamAct(). No stream.");
      return errorCodes.mark({ ok: false, errors: ['Transmitter ' +
        record.id + ' has no stream yet.'] }, 'STS-SSF-0113');
    }
    const b = body || {};
    let answer: Json = null;
    let what = '';
    if (action === 'read-stream') {
      answer = await this.call(record, 'GET', this.streamUrl(record));
      if (answer.ok && answer.json) {
        this.adoptStream(record, answer.json);
      }
      what = 'stream read';
    } else if (action === 'update-stream') {
      const events = Array.isArray(b.eventsRequested) ? b.eventsRequested
        : String(b.eventsRequested || '').split(/[\s,]+/).filter(Boolean);
      answer = await this.call(record, 'PATCH',
        record.config.configuration_endpoint,
        { stream_id: record.streamId, events_requested: events });
      if (answer.ok && answer.json) {
        record.eventsRequested = events;
        this.adoptStream(record, answer.json);
      }
      what = 'events_requested updated';
    } else if (action === 'delete-stream') {
      answer = await this.call(record, 'DELETE', this.streamUrl(record));
      if (answer.ok || answer.status === 404) {
        answer.ok = true;
        record.streamId = '';
        record.stream = null;
        record.streamAud = [];
        record.pollEndpoint = '';
        record.pushSecretDigest = '';
        record.state = 'registered';
      }
      what = 'stream deleted';
    } else if (action === 'set-status') {
      const status = String(b.status || '');
      if (['enabled', 'paused', 'disabled'].indexOf(status) < 0) {
        log.debug("Leaving SsfTransmitters.streamAct(). Status.");
        return errorCodes.mark({ ok: false, errors: ['status must be ' +
          'enabled, paused or disabled.'] }, 'STS-SSF-0113');
      }
      answer = await this.call(record, 'POST',
        record.config.status_endpoint,
        { stream_id: record.streamId, status: status,
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
        return errorCodes.mark({ ok: false, errors: ['subject must be an ' +
          'SSF subject identifier with a format.'] }, 'STS-SSF-0113');
      }
      answer = await this.call(record, 'POST', action === 'add-subject'
        ? record.config.add_subject_endpoint
        : record.config.remove_subject_endpoint,
        Object.assign({ stream_id: record.streamId, subject: subject },
                      action === 'add-subject' ? { verified: true } : {}));
      what = (action === 'add-subject' ? 'subject added'
                                       : 'subject removed');
    } else if (action === 'verify') {
      record.verifyState = nodeCrypto.randomBytes(12).toString('base64url');
      answer = await this.call(record, 'POST',
        record.config.verification_endpoint,
        { stream_id: record.streamId, state: record.verifyState });
      what = 'verification asked';
    }
    if (!answer) {
      log.debug("Leaving SsfTransmitters.streamAct(). Unknown.");
      return errorCodes.mark({ ok: false, errors: ['Unknown stream act.'] },
                             'STS-SSF-0113');
    }
    record.lastError = answer.ok ? '' : action + ': ' + answer.why;
    this.save(record);
    if (!answer.ok) {
      log.debug("Leaving SsfTransmitters.streamAct(). Refused.");
      return errorCodes.mark({ ok: false, errors: ['The transmitter ' +
        'refused ' + action + ': ' + answer.why + '.'] }, 'STS-SSF-0115');
    }
    this.audited('ssf.transmitter.' + action, ctx, record, what);
    log.debug("Leaving SsfTransmitters.streamAct().");
    return { ok: true, transmitter: this.view(record),
             answer: answer.json || null,
             message: 'Transmitter ' + record.id + ': ' + what + '.' };
  }

  // -------------------------------------------------------------------------
  // POLL (RFC 8936): ask, act, acknowledge on the next request.
  // -------------------------------------------------------------------------
  async pollOnce(record: Json): Promise<Json> {
    const { log, now } = this.deps;
    log.debug("Entering SsfTransmitters.pollOnce(). " + record.id);
    const out = { received: 0, acted: 0, refused: 0, rounds: 0, why: '' };
    if (!record.pollEndpoint) {
      log.debug("Leaving SsfTransmitters.pollOnce(). No poll stream.");
      out.why = 'no poll stream';
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
        record.streamId,
        maxEvents: last ? 0 : this.setting('ssf.foreignPollMaxEvents') };
      if (ack.length) {
        asked.ack = ack;
      }
      if (Object.keys(setErrs).length) {
        asked.setErrs = setErrs;
      }
      const answer = await this.call(record, 'POST', record.pollEndpoint,
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
    const current = this.get(record.id) || record;
    current.lastPollAt = now();
    current.lastPollResult = out.why ? 'failed: ' + out.why
      : out.received + ' received, ' + out.refused + ' refused';
    this.save(current);
    log.debug("Leaving SsfTransmitters.pollOnce(). " + out.received);
    return out;
  }

  // The scheduler job: every realm, every poll stream that is streaming.
  async pollAll(): Promise<Json> {
    const { log, realms, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering SsfTransmitters.pollAll().");
    const total = { transmitters: 0, received: 0, refused: 0 };
    for (const realm of realms.list()) {
      await realms.run(realm, async function () {
        const due: Json[] = [];
        transmitters.forEach(function (row: Json) {
          if (row && row.delivery === 'poll' && row.state === 'streaming' &&
              row.pollEndpoint) {
            due.push(row);
          }
        });
        for (const row of due) {
          try {
            const one = await self.pollOnce(row);
            total.transmitters++;
            total.received += one.received;
            total.refused += one.refused;
          } catch (e) {
            log.error(errorCodes.tag('STS-SSF-0116') + 'ssf: polling the ' +
                      'foreign transmitter ' + row.id + ' failed: ' +
                      ((e && e.message) || e));
          }
        }
      });
    }
    log.debug("Leaving SsfTransmitters.pollAll(). " +
              JSON.stringify(total));
    return total;
  }

  scheduleJobs(): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SsfTransmitters.scheduleJobs().");
    const scheduler = require('../cluster/scheduler');
    if (!scheduler.job(POLL_JOB)) {
      scheduler.register({
        id: POLL_JOB,
        title: 'Foreign SSF transmitters poll',
        describe: 'Polls every foreign Shared Signals transmitter this ' +
                  'realm registered with a poll stream (RFC 8936): the ' +
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
  async pushRoute(req: Req, res: Res): Promise<unknown> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering SsfTransmitters.pushRoute().");
    const record = this.get(String((req.params as Json).id || ''));
    const refuse = function (status: number, code: string, err: string,
                             description: string): unknown {
      log.debug("Entering refuse(). " + code);
      errorCodes.mark(res, code);
      log.debug("Leaving refuse().");
      return res.status(status).json({ err: err, description: description });
    };
    if (!record || record.delivery !== 'push' || !record.pushSecretDigest) {
      log.debug("Leaving SsfTransmitters.pushRoute(). Unknown.");
      return refuse(404, 'STS-SSF-0117', 'invalid_request',
                    'No push stream is registered here.');
    }
    const given = SsfTransmitters.digest(String(req.headers.authorization ||
                                                ''));
    const a = Buffer.from(given);
    const b = Buffer.from(String(record.pushSecretDigest));
    if (a.length !== b.length || !nodeCrypto.timingSafeEqual(a, b)) {
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

  registerRoutes(app: Json): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SsfTransmitters.registerRoutes().");
    app.post('/ssf/transmitters/:id/push', function (req: Req, res: Res) {
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
  async receive(record: Json, token: string, via: string): Promise<Json> {
    const { log, mode, now } = this.deps;
    log.debug("Entering SsfTransmitters.receive(). " + record.id + " " + via);
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
    const key = record.id + '|' + String(claims.jti || '');
    if (claims.jti && inbox.get(key)) {
      // A SET seen before: acknowledged, never acted on twice.
      log.debug("Leaving SsfTransmitters.receive(). A duplicate.");
      return { ok: true, acted: 0, duplicate: true };
    }
    let problem = '';
    let err = 'invalid_request';
    let code = 'STS-SSF-0118';
    if (SET_TYPES.indexOf(String(header.typ || '').toLowerCase()) < 0) {
      problem = 'typ is not secevent+jwt';
    } else if (claims.iss !== record.config.issuer) {
      problem = 'iss is ' + String(claims.iss) + ', not the transmitter\'s ' +
                record.config.issuer;
      err = 'invalid_issuer';
      code = 'STS-SSF-0119';
    } else if (!this.audienceMatches(record, claims.aud)) {
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
    const verified = await this.verifies(record, token, header);
    if (!verified.ok && mode.refusesUnverifiedSignals()) {
      log.debug("Leaving SsfTransmitters.receive(). Unverified.");
      return this.refused(record, claims, 'invalid_key', 'The signature ' +
        'does not verify against the transmitter\'s keys: ' + verified.why,
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
                                      mapped, subject);
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
    const current = this.get(record.id) || record;
    current.counts = current.counts || {};
    current.counts.received = (current.counts.received || 0) + 1;
    current.counts.verified = (current.counts.verified || 0) +
      (verified.ok ? 1 : 0);
    current.counts.acted = (current.counts.acted || 0) + acted;
    this.save(current);
    log.debug("Leaving SsfTransmitters.receive(). " + acted + " acted.");
    return { ok: true, acted: acted };
  }

  private audienceMatches(record: Json, aud: Json): boolean {
    this.deps.log.debug("Entering SsfTransmitters.audienceMatches().");
    const given = Array.isArray(aud) ? aud.map(String)
                                     : (aud ? [String(aud)] : []);
    const want = record.streamAud || [];
    this.deps.log.debug("Leaving SsfTransmitters.audienceMatches().");
    return want.length > 0 && given.some(function (one: string) {
      return want.indexOf(one) >= 0;
    });
  }

  // The signature, against the transmitter's keys: the kid named, else
  // each; the algorithms this service verifies, never taken from the token.
  private async verifies(record: Json, token: string,
                         header: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.verifies().");
    const got: Json = await this.deps.jwks().ensure(record.config.jwks_uri,
                                                    header.kid || '');
    const keys = got && got.jwks && Array.isArray(got.jwks.keys)
      ? got.jwks.keys : [];
    const candidates = keys.filter(function (k: Json) {
      return !header.kid || k.kid === header.kid;
    });
    let why = candidates.length ? '' : 'no key ' + (header.kid ? 'with kid ' +
      header.kid + ' ' : '') + 'at the transmitter\'s jwks_uri';
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
    const current = this.get(record.id) || record;
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
    inbox.set(record.id + '|' + row.jti, Object.assign({
      transmitter: record.id }, row));
    log.debug("Leaving SsfTransmitters.record().");
  }

  // -------------------------------------------------------------------------
  // THE PERSON A FOREIGN SUBJECT NAMES (header point 4), or why nobody.
  // -------------------------------------------------------------------------
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
    const fed = federation.get(record.federationId);
    if (!fed) {
      log.debug("Leaving SsfTransmitters.personFor(). No relationship.");
      return { username: '', why: 'the relationship ' + record.federationId +
                                  ' is gone' };
    }
    let found: Json[] = [];
    if (s.format === 'iss_sub') {
      if (String(s.iss) !== String(fed.fedPeer || '')) {
        log.debug("Leaving SsfTransmitters.personFor(). Another issuer.");
        return { username: '', why: 'the subject\'s iss is not the ' +
                                    'relationship\'s partner' };
      }
      found = federation.peopleLinkedBy(this.deps.links().linkValue(
        fed.fedId, fed.fedPeer, String(s.sub || '')));
    } else if (s.format === 'email') {
      if (!federation.boolOf(fed.fedSignalEmailMatch, false)) {
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

  // -------------------------------------------------------------------------
  // ONE EVENT, ACTED ON AS THE POLICY SAYS (header point 3).
  // -------------------------------------------------------------------------
  private async actOn(record: Json, uri: string, body: Json, mapped: Json,
                      subject: Json): Promise<Json[]> {
    const { log, mode } = this.deps;
    log.debug("Entering SsfTransmitters.actOn(). " + uri);
    const family = uri.indexOf(CAEP_PREFIX) === 0 ? 'caep'
      : uri.indexOf(RISC_PREFIX) === 0 ? 'risc'
      : uri.indexOf(SSF_PREFIX) === 0 ? 'ssf' : '';
    const short = uri.replace(/^.*\//, '');
    const out: Json[] = [];
    if (family === 'ssf') {
      if (short === 'verification' && body.state &&
          body.state === record.verifyState) {
        const current = this.get(record.id) || record;
        current.verifiedAt = this.deps.now();
        current.verifyState = '';
        this.save(current);
        out.push({ event: short, reaction: 'verified', done: false });
      }
      log.debug("Leaving SsfTransmitters.actOn(). SSF.");
      return out;
    }
    if (family === 'caep' && short === 'device-compliance-change') {
      out.push(this.deviceCompliance(record, body, subject));
      log.debug("Leaving SsfTransmitters.actOn(). A device.");
      return out;
    }
    if (!family || !mapped.username) {
      log.debug("Leaving SsfTransmitters.actOn(). Nobody.");
      return [{ event: short, reaction: '', done: false,
                why: mapped.why || 'not a CAEP or RISC event' }];
    }
    if (family === 'caep' && short === 'session-revoked' &&
        body.initiating_entity === 'policy') {
      log.debug("Leaving SsfTransmitters.actOn(). An expiry.");
      return [{ event: short, reaction: '', done: false,
                why: 'an expiry at the transmitter, not a revocation' }];
    }
    const decided: Json = this.deps.signalPep().decide({
      event: short, family: family, surface: 'foreign:' + record.id,
      level: String(body.current_level || '') });
    const observe = mode.observesSignalsOnly();
    const RESPONSE = this.deps.signalPep().RESPONSE || {};
    for (const reaction of (decided.reactions || [])) {
      if ([RESPONSE.END_PERSON_SESSIONS, RESPONSE.DISABLE_ACCOUNT,
           RESPONSE.ENABLE_ACCOUNT].indexOf(reaction) < 0) {
        continue;
      }
      if (observe) {
        out.push({ event: short, reaction: reaction, observed: true,
                   done: false });
        continue;
      }
      out.push(await this.react(record, reaction, short,
                                mapped.username, RESPONSE));
    }
    if (!out.length) {
      out.push({ event: short, reaction: '', done: false,
                 why: 'the signal-response policy permits no reaction' });
    }
    log.debug("Leaving SsfTransmitters.actOn(). " + out.length);
    return out;
  }

  private async react(record: Json, reaction: string, event: string,
                      username: string, RESPONSE: Json): Promise<Json> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering SsfTransmitters.react(). " + reaction);
    const by = 'a ' + event + ' Security Event Token from the foreign ' +
               'transmitter ' + record.id + ' (' + record.issuer + ')';
    const actor = 'ssf:' + record.id;
    try {
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
          locks.set(String(username), { transmitter: record.id,
                                        at: this.deps.now() });
        }
        log.debug("Leaving SsfTransmitters.react(). Disabled.");
        return { event: event, reaction: reaction, done: !!(act && act.ok),
                 why: act && !act.ok ? String(act.message || '') : '' };
      }
      if (reaction === RESPONSE.ENABLE_ACCOUNT) {
        const lock = locks.get(String(username));
        if (!lock || lock.transmitter !== record.id) {
          log.debug("Leaving SsfTransmitters.react(). Not its lock.");
          return { event: event, reaction: reaction, done: false,
                   why: 'the account was not disabled by this transmitter' };
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
               ' from the foreign transmitter ' + record.id + ' failed: ' +
               ((e && e.message) || e));
    }
    log.debug("Leaving SsfTransmitters.react(). Nothing.");
    return { event: event, reaction: reaction, done: false,
             why: 'it could not be done' };
  }

  // CAEP device-compliance-change (#164's register): the device the
  // subject names, by its id or its key thumbprint, marked as the
  // transmitter says. Only where the register offers `setCompliance()`.
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
                          'ssf:' + record.id, String(body.reason_admin ||
                                                     body.reason || ''));
    log.debug("Leaving SsfTransmitters.deviceCompliance(). Set.");
    return { event: 'device-compliance-change', reaction: 'set-compliance',
             done: true };
  }

  async remove(record: Json, ctx: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.remove(). " + record.id);
    if (record.streamId) {
      await this.streamAct(record, 'delete-stream', {}, ctx);
    }
    transmitters.delete(record.id);
    tokens.delete(this.deps.realms.currentId() + '|' + record.id);
    this.audited('ssf.transmitter.remove', ctx, record, 'removed');
    log.debug("Leaving SsfTransmitters.remove().");
    return { ok: true, message: 'Transmitter ' + record.id + ' removed.' };
  }

  // -------------------------------------------------------------------------
  // THE CONSOLE'S AND THE API'S ACTS (rule 7).
  // -------------------------------------------------------------------------
  async act(body: Json, ctx: Json): Promise<Json> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering SsfTransmitters.act().");
    const b = body || {};
    const action = String(b.action || '');
    const ACTIONS = ['add', 'create-stream', 'read-stream', 'update-stream',
                     'delete-stream', 'set-status', 'add-subject',
                     'remove-subject', 'verify', 'poll-now', 'remove'];
    if (ACTIONS.indexOf(action) < 0) {
      log.debug("Leaving SsfTransmitters.act(). Unknown.");
      return errorCodes.mark({ ok: false, errors: ['Unknown action "' +
        action + '". The ' + ACTIONS.length + ' are: ' +
        ACTIONS.slice(0, -1).join(', ') + ' and ' +
        ACTIONS[ACTIONS.length - 1] + '.'] }, 'STS-SSF-0113');
    }
    if (action === 'add') {
      log.debug("Leaving SsfTransmitters.act(). Add.");
      return this.add(b, ctx);
    }
    const record = this.get(String(b.id || ''));
    if (!record) {
      log.debug("Leaving SsfTransmitters.act(). No such transmitter.");
      return errorCodes.mark({ ok: false, errors: ['There is no ' +
        'transmitter "' + String(b.id || '') + '" in this realm.'] },
        'STS-SSF-0113');
    }
    let result: Json;
    if (action === 'create-stream') {
      result = await this.createStream(record, ctx);
    } else if (action === 'poll-now') {
      const polled = await this.pollOnce(record);
      result = polled.why && !polled.received
        ? errorCodes.mark({ ok: false, errors: ['The poll failed: ' +
            polled.why + '.'] }, 'STS-SSF-0116')
        : { ok: true, polled: polled, message: 'Polled ' + record.id +
            ': ' + polled.received + ' received, ' + polled.refused +
            ' refused, ' + polled.acted + ' reaction(s).' };
    } else if (action === 'remove') {
      result = await this.remove(record, ctx);
    } else {
      result = await this.streamAct(record, action, b, ctx);
    }
    log.debug("Leaving SsfTransmitters.act(). " + action + " " + result.ok);
    return result;
  }

  // A registration as a caller sees it: never a secret or a token.
  view(record: Json): Json {
    const { log } = this.deps;
    log.debug("Entering SsfTransmitters.view().");
    const iso = function (ms: unknown): string {
      log.debug("Entering iso().");
      log.debug("Leaving iso().");
      return Number(ms) ? new Date(Number(ms)).toISOString() : '';
    };
    const c = record.credential || {};
    log.debug("Leaving SsfTransmitters.view().");
    return {
      id: record.id, issuer: record.issuer, discoveryUrl: record.discoveryUrl,
      config: record.config, federationId: record.federationId,
      delivery: record.delivery, eventsRequested: record.eventsRequested,
      credential: { method: c.method, tokenEndpoint: c.tokenEndpoint || '',
                    clientId: c.clientId || '', scope: c.scope || '',
                    secretHeld: !!(c.clientSecret || c.bearer) },
      streamId: record.streamId, stream: record.stream,
      streamAud: record.streamAud, pollEndpoint: record.pollEndpoint,
      pushEndpointSet: !!record.pushSecretDigest, state: record.state,
      verifiedAt: iso(record.verifiedAt), lastPollAt: iso(record.lastPollAt),
      lastPollResult: record.lastPollResult || '',
      lastError: record.lastError || '', counts: record.counts || {},
      createdAt: iso(record.createdAt)
    };
  }

  report(options?: Json): Json {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SsfTransmitters.report().");
    const o = options || {};
    const list: Json[] = [];
    transmitters.forEach(function (row: Json) {
      if (row) {
        list.push(self.view(row));
      }
    });
    const received: Json[] = [];
    inbox.forEach(function (row: Json) {
      if (row && (!o.transmitter || row.transmitter === o.transmitter)) {
        received.push(Object.assign({}, row, {
          receivedAt: new Date(Number(row.receivedAt)).toISOString() }));
      }
    });
    received.sort(function (a, b) {
      return String(b.receivedAt).localeCompare(String(a.receivedAt));
    });
    const held: Json[] = [];
    locks.forEach(function (row: Json, username: string) {
      held.push({ username: username, transmitter: row.transmitter,
                  at: new Date(Number(row.at)).toISOString() });
    });
    log.debug("Leaving SsfTransmitters.report().");
    return { transmitters: list, received: received.slice(0,
             Number(o.limit) || 200), locks: held,
             observeOnly: this.deps.mode.observesSignalsOnly() };
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

export = {
  SsfTransmitters: SsfTransmitters,
  installInstance: (instance: SsfTransmitters): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  POLL_JOB: POLL_JOB,
  discoveryUrlFor: SsfTransmitters.discoveryUrlFor,
  get: slot.forward('get'),
  add: slot.forward('add'),
  createStream: slot.forward('createStream'),
  streamAct: slot.forward('streamAct'),
  pollOnce: slot.forward('pollOnce'),
  pollAll: slot.forward('pollAll'),
  receive: slot.forward('receive'),
  personFor: slot.forward('personFor'),
  act: slot.forward('act'),
  report: slot.forward('report'),
  view: slot.forward('view'),
  registerRoutes: slot.forward('registerRoutes')
};
