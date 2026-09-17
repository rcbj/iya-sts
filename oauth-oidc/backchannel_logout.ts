'use strict';
//
// File: backchannel_logout.ts
//
// ===========================================================================
// OPENID CONNECT BACK-CHANNEL LOGOUT 1.0 — TELLING THE RELYING PARTIES
// WITHOUT THE BROWSER (2026-09-17, #36).
//
// `frontchannel_logout.ts` tells a relying party that a session ended by
// loading its `frontchannel_logout_uri` in an iframe in the browser that is
// signing out — which works only while that browser is on the sign-out page,
// and cannot say whether anything happened. Back-Channel Logout is the other
// half: this service POSTs a signed Logout Token to each relying party's
// registered `backchannel_logout_uri`, server to server, and the relying party
// answers 200 (or 204) when it has ended its own session and 400 when it will
// not. Until this file the discovery document said
// `backchannel_logout_supported: false`, and the root CLAUDE.md listed it among
// the things this service deliberately does not do. rcbj's direction on #36
// was to eliminate that list, and this is the row.
//
// It is a LIBRARY (rule 3): it registers no route. It requires `common/`
// libraries and `federation/federation_http.ts`, none of which requires it
// back, so `authn/authn.ts` (lazily, at the moment a session ends),
// `oauth-oidc/oauth2.ts`, `logout/logout.ts` and the console can all reach it.
//
// ---------------------------------------------------------------------------
// SIX THINGS ARE WORTH KNOWING BEFORE READING FURTHER.
//
// **1. IT IS TRIGGERED WHERE A SESSION ENDS, NOT AT EACH SIGN-OUT DOOR.**
// `authn.dropSession()` is the one function every sign-out reaches —
// `/oauth2/logout`, `wsignout1.0`, SAML Single Logout, `/logout`,
// `/admin/logout`, `/admin/sessions` and `/admin-api` — and it already argues
// at length why the refresh revocation, the `session.end` row and CAEP's
// `session-revoked` live there rather than at five doors. The Logout Token is
// the same kind of consequence and goes in the same place: `plan()` is called
// before the session's end is reported, `dispatch()` inside the report. A
// front-channel notification could not be placed there — it is an iframe, and
// only a door with a page can draw one — which is why the two are triggered
// differently, and why a back-channel RP is told about a WS-Federation or SAML
// sign-out that its front-channel neighbour never hears of. The one other
// trigger is `logout/logout.ts`'s `oidc-rp` row, which forgets a client —
// one, on a session that stays, or every one, ahead of the session, in a
// global logout — and tells it itself.
//
// **2. AN EXPIRED SESSION SENDS NOTHING.** `expireSession()` is a policy
// ending a session nobody signed out of, and the specification's trigger is an
// End-User logging out. A relying party's session commonly outlives the
// provider's idle timeout by design, and a Logout Token for every idle expiry
// would sign people out of applications they are actively using. Stated in the
// setting's description and in `oauth-oidc/CLAUDE.md`, not left to be found.
//
// **3. IT IS ASYNCHRONOUS, WITH BOUNDED RETRY, AND "PENDING" IS THE HONEST
// ANSWER.** The sign-out answers at once; the POSTs go out after it. A
// relying party that is down is tried `oauth2.backchannelLogoutAttempts`
// times, `oauth2.backchannelLogoutBackoffMs` apart and doubling, each bounded
// by `oauth2.backchannelLogoutTimeoutMs`. Only what is worth repeating is
// retried — a timeout, a connection failure, 5xx, 408, 429 (section 2.5: "the
// OP should not retransmit ... unless ... potentially recoverable errors");
// a 400 is section 2.8's refusal and is final, and so is anything the outbound
// policy refuses. So every sign-out result lists each delivery with the state
// it has AT THAT MOMENT — `pending` for nearly all of them — and
// `/admin/logout` (and `GET /admin-api/logout`) lists the recent deliveries
// with the state they reached. ONE audit row per delivery, written when it
// reaches its final state, never one per attempt: the standing rule is to log
// state changes, not every failure.
//
// **4. IT GOES OUT THROUGH THE OUTBOUND POLICY, NOT A SECOND ONE.**
// `federation_http.deliverForm()` — `federation.outbound`, https unless
// `federation.outboundAllowInsecure`, no redirect followed, the body drained
// and discarded, and in product mode no internal address (the name resolved
// once and the connection pinned to the address that was checked). That
// module's header argues why an address a client REGISTERED may be sent to
// when it may not be fetched from.
//
// **5. WHICH PROCESS SENDS, AND WHAT IS NOT COORDINATED.** The process that
// ends the session sends, inside `authn.sessionEndOnce()` — the claim that
// already makes a session's end reported ONCE across processes on a store that
// can claim (postgres). So two nodes, or two request workers
// (`workers.requestCount`), ending the same session do not both send. A
// sign-out request is handled by exactly one process, so a single sign-out
// never sends twice either. What is NOT coordinated, said here where it is
// declared: (a) the retries are in this process's memory — a process that
// dies between attempts loses the delivery, which stays `pending` on no page
// because the register below is process-local; (b) on a store that cannot
// claim (memory, ldif) two processes ending one session at the same moment
// each send, which is CAEP's existing duplicate and costs a relying party an
// idempotent repeat; (c) the delivery register is per process, so
// `/admin/logout` on another node does not show a delivery this node made —
// the audit row, which is shared, is the durable record. A process that loses
// the claim marks its planned rows `elsewhere` rather than leaving them
// `pending`. The `oidc-rp` row's sends (point 1) are made by the one process
// handling that request, outside the claim.
//
// **6. THE TOKEN.** Section 2.4: `iss` (the issuer the client's ID Token was
// issued by — recorded per client on the session by
// `frontchannel_logout.noteClient()`, because this service runs several named
// authorization servers), `aud` (the client), `iat`, `exp` (short:
// `oauth2.backchannelLogoutTokenTtlS`, default the two minutes section 4
// encourages), `jti`, `events` with the one member, `sub` AND `sid` — both,
// always, so `backchannel_logout_session_required` is honoured whatever it
// says — and NO `nonce`, which section 2.4 forbids. The header carries
// `typ: logout+jwt`. It is signed like the client's ID Token: the algorithm
// the client registered as `id_token_signed_response_alg` (RS256 when none),
// with the realm's key — section 2.4's "the same keys ... as are used for ID
// Tokens" — and never `none`. It is signed ONCE and resent unchanged, so the
// relying party can deduplicate on `jti`.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import applications = require('../common/applications');
import validation = require('../common/validation');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import fedHttp = require('../federation/federation_http');

// A session, a registration document.
type Json = any;

// The event member section 2.4 requires.
const EVENT = 'http://schemas.openid.net/event/backchannel-logout';

// The `typ` header value section 2.4 recommends.
const TOKEN_TYPE = 'logout+jwt';

// The attribute the outbound policy reads the address from.
const ADDRESS_ATTRIBUTE = 'oauthBackchannelLogoutUri';

// How many deliveries one realm's register keeps. The register is a VIEW —
// the audit row is the record — so it is bounded, and a finished delivery is
// the first to go.
const REGISTER_CAP = 200;

// The states a delivery passes through. `pending` until it reaches one of the
// other three: `sent` (200 or 204), `failed` (with a code), `elsewhere` (the
// session's end was reported by another process, which sends).
const STATES = ['pending', 'sent', 'failed', 'elsewhere'];

// One delivery. Nothing secret is on it: the token is not kept.
interface Delivery {
  id: string;
  seq: number;
  sessionId: string;
  clientId: string;
  uri: string;
  sessionRequired: boolean;
  iss: string;
  sub: string;
  sid: string;
  username: string;
  via: string;
  state: string;
  attempts: number;
  status: number;
  errorCode: string;
  why: string;
  queuedAt: number;
  finishedAt: number;
}

interface PlanOptions {
  via?: string;
  clients?: string[];
  issuer?: string;
}

interface BackchannelLogoutDeps {
  log: typeof helpers.log;
  xmlEscape: typeof helpers.xmlEscape;
  randomId: typeof helpers.randomId;
  nowSec: typeof helpers.nowSec;
  signJwtAsAsync: typeof helpers.signJwtAsAsync;
  config: typeof config;
  realms: typeof realms;
  applications: typeof applications;
  validation: typeof validation;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  fedHttp: typeof fedHttp;
}

// PER TRUST REALM, at its declaration (root CLAUDE.md, trust realms rule 2).
// NOT persisted: it is this process's view of the deliveries it is making,
// and a delivery another process makes is that process's to show — see
// header point 5.
const deliveries = realms.map();

// The sequence a caller reads before a sign-out and filters by after it.
// Process-wide and only ever compared, so one counter serves every realm.
let sequence = 0;

class BackchannelLogout {
  static readonly EVENT = EVENT;
  static readonly TOKEN_TYPE = TOKEN_TYPE;
  static readonly STATES = STATES;

  constructor(private readonly deps: BackchannelLogoutDeps) {
    deps.log.debug("Entering BackchannelLogout.constructor().");
    deps.log.debug("Leaving BackchannelLogout.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): BackchannelLogoutDeps {
    helpers.log.debug("Entering BackchannelLogout.defaultDeps().");
    helpers.log.debug("Leaving BackchannelLogout.defaultDeps().");
    return {
      log: helpers.log,
      xmlEscape: helpers.xmlEscape,
      randomId: helpers.randomId,
      nowSec: helpers.nowSec,
      signJwtAsAsync: helpers.signJwtAsAsync,
      config: config,
      realms: realms,
      applications: applications,
      validation: validation,
      errorCodes: errorCodes,
      audit: audit,
      fedHttp: fedHttp
    };
  }

  // Is the feature on? Per call, which is what `runtime: true` promises.
  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering BackchannelLogout.enabled().");
    log.debug("Leaving BackchannelLogout.enabled().");
    return !!config.value('oauth2.backchannelLogout');
  }

  // The four tunables, read directly: every one has a `min` on its row.
  private setting(key: string): number {
    const { log, config } = this.deps;
    log.debug("Entering BackchannelLogout.setting(). " + key);
    log.debug("Leaving BackchannelLogout.setting().");
    return Number(config.value(key));
  }

  // The current sequence. A caller reads it before ending something and
  // passes it to `deliveriesFor()` afterwards, so it is shown what THIS act
  // queued and not a previous sign-out of the same session id.
  mark(): number {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.mark().");
    log.debug("Leaving BackchannelLogout.mark(). " + sequence);
    return sequence;
  }

  // -------------------------------------------------------------------------
  // PLAN: one row per relying party on this session that registered a
  // `backchannel_logout_uri`, written to the register as `pending` before
  // anything is sent. A client with no URI is not a row here — the
  // front-channel list already reports "there is nowhere to tell it" for
  // every client on the session, and two lists saying it would be noise.
  //
  // A row that cannot be sent at all — a stored URI that is not http(s), no
  // issuer recorded — is written `failed` straight away, with its code and
  // its audit row, so it is visible in the same place as the rest.
  //
  // It cannot throw: it is called from the middle of ending a session, and a
  // bookkeeping failure must never be the reason a sign-out did not happen.
  // -------------------------------------------------------------------------
  plan(session: Json, options?: PlanOptions): Delivery[] {
    const { log, applications, validation, errorCodes, randomId } = this.deps;
    const self = this;
    log.debug("Entering BackchannelLogout.plan().");
    const opts = options || {};
    const out: Delivery[] = [];
    try {
      if (!session || !this.enabled()) {
        log.debug("Leaving BackchannelLogout.plan(). Off, or no session.");
        return out;
      }
      const held = session.oidcClients || {};
      const wanted = Array.isArray(opts.clients) ? opts.clients.map(String)
                                                 : null;
      Object.keys(held).sort(function (a, b) {
        return ((held[a] && held[a].first) || 0) -
               ((held[b] && held[b].first) || 0);
      }).forEach(function (clientId) {
        if (wanted && wanted.indexOf(clientId) < 0) {
          return;
        }
        const client: Json = applications.clientConfigOf(clientId) || {};
        const uri = String(client.backchannel_logout_uri || '');
        if (!uri) {
          return;
        }
        sequence++;
        const row: Delivery = {
          id: randomId(12),
          seq: sequence,
          sessionId: String(session.id || ''),
          clientId: clientId,
          uri: uri,
          sessionRequired: !!client.backchannel_logout_session_required,
          iss: String((held[clientId] && held[clientId].iss) ||
                      opts.issuer || ''),
          sub: String((session.user && session.user.sub) || ''),
          sid: String(session.id || ''),
          username: String((session.user && session.user.username) || ''),
          via: String(opts.via || 'a sign-out'),
          state: 'pending',
          attempts: 0,
          status: 0,
          errorCode: '',
          why: '',
          queuedAt: Date.now(),
          finishedAt: 0
        };
        self.remember(row);
        // THE SAME RULE REGISTRATION APPLIES, APPLIED AGAIN WHEN IT IS READ,
        // for `frontchannel_logout.ts`'s reason: `ldapmodify` reaches the
        // attribute without passing registration, the console or the API.
        const stored = validation.backchannelUriProblem(uri);
        if (stored) {
          log.warn(errorCodes.tag('STS-OAUTH-0544') + 'back-channel ' +
                   'logout: ' + clientId + '\'s stored ' +
                   'backchannel_logout_uri is not sent a Logout Token, ' +
                   'because it ' + stored + '.');
          self.finish(row, 'failed', 'STS-OAUTH-0544',
                      'the stored backchannel_logout_uri ' + stored +
                      '. Correct oauthBackchannelLogoutUri on its entry.');
        } else if (!row.iss) {
          self.finish(row, 'failed', 'STS-OAUTH-0542',
                      'the session did not record which issuer this ' +
                      'client\'s ID Token came from, so a Logout Token ' +
                      'naming the right iss cannot be built');
        }
        out.push(row);
      });
    } catch (e) {
      log.debug("Caught in BackchannelLogout.plan(): " +
                ((e && e.message) || e));
      log.warn('back-channel logout: the deliveries for a session could not ' +
               'be planned, and none will be sent for it: ' + e.message);
    }
    log.debug("Leaving BackchannelLogout.plan(). " + out.length +
              " delivery(ies).");
    return out;
  }

  // Into the ambient realm's register, trimming the oldest finished rows
  // (then the oldest of any) past the cap.
  private remember(row: Delivery): void {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.remember().");
    deliveries.set(row.id, row);
    if (deliveries.size > REGISTER_CAP) {
      const rows = [];
      deliveries.forEach(function (one) { rows.push(one); });
      rows.sort(function (a, b) {
        const aDone = a.state === 'pending' ? 1 : 0;
        const bDone = b.state === 'pending' ? 1 : 0;
        return (aDone - bDone) || (a.seq - b.seq);
      });
      rows.slice(0, deliveries.size - REGISTER_CAP).forEach(function (one) {
        deliveries.delete(one.id);
      });
    }
    log.debug("Leaving BackchannelLogout.remember().");
  }

  // A delivery reaches its final state: the row changes and ONE audit row is
  // written. Never throws — `audit()` does not.
  private finish(row: Delivery, state: string, code: string,
                 why: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering BackchannelLogout.finish(). " + row.clientId + " -> " +
              state);
    row.state = state;
    row.errorCode = code || '';
    row.why = why || '';
    row.finishedAt = Date.now();
    if (state === 'elsewhere') {
      // Not an outcome of THIS process's: the process that reported the
      // session's end writes the row for the delivery it makes.
      log.debug("Leaving BackchannelLogout.finish(). Handed off.");
      return;
    }
    audit.audit({
      action: 'logout.backchannel',
      outcome: state === 'sent' ? 'success' : 'error',
      errorCode: state === 'sent' ? '' : code,
      actor: row.username,
      protocol: 'OAuth 2.0 / OIDC',
      channel: 'internal',
      target: row.clientId,
      summary: state === 'sent'
        ? 'a back-channel Logout Token for session ' + row.sessionId +
          ' was accepted by ' + row.clientId + ' (HTTP ' + row.status + ')'
        : 'a back-channel Logout Token for session ' + row.sessionId +
          ' was not delivered to ' + row.clientId + ': ' + why,
      detail: {
        sessionId: row.sessionId,
        clientId: row.clientId,
        uri: row.uri,
        attempts: String(row.attempts),
        status: String(row.status || ''),
        state: state,
        via: row.via
      }
    });
    log.debug("Leaving BackchannelLogout.finish().");
  }

  // -------------------------------------------------------------------------
  // THE LOGOUT TOKEN'S CLAIMS — header point 6. Exported for the tests, which
  // hold the shape to section 2.4 without a listener.
  // -------------------------------------------------------------------------
  claimsFor(row: Delivery): Json {
    const { log, nowSec, randomId } = this.deps;
    log.debug("Entering BackchannelLogout.claimsFor().");
    const iat = nowSec();
    const claims: Json = {
      iss: row.iss,
      aud: row.clientId,
      iat: iat,
      exp: iat + this.setting('oauth2.backchannelLogoutTokenTtlS'),
      jti: randomId(16),
      events: {},
      sub: row.sub,
      sid: row.sid
    };
    claims.events[EVENT] = {};
    // `sub` and `sid` are both sent; section 2.4 requires at least one. An
    // empty `sub` — a session with no subject, which the identity model does
    // not produce — is left out rather than sent empty.
    if (!claims.sub) {
      delete claims.sub;
    }
    log.debug("Leaving BackchannelLogout.claimsFor().");
    return claims;
  }

  // The token, signed like the client's ID Token. Resolves with the JWS, or
  // rejects with a sentence.
  logoutToken(row: Delivery): Promise<string> {
    const { log, applications, signJwtAsAsync } = this.deps;
    log.debug("Entering BackchannelLogout.logoutToken(). " + row.clientId);
    let alg = 'RS256';
    let secret = '';
    try {
      const registered = applications.registrationOf(row.clientId) || {};
      alg = String(registered.id_token_signed_response_alg || 'RS256');
      secret = String(registered.client_secret || '');
    } catch (e) {
      log.debug("Caught in BackchannelLogout.logoutToken(): " +
                ((e && e.message) || e));
      alg = 'RS256';
    }
    if (alg === 'none') {
      log.debug("Leaving BackchannelLogout.logoutToken(). alg none.");
      return Promise.reject(new Error('this client registered ' +
        'id_token_signed_response_alg "none", and section 2.4 says a Logout ' +
        'Token MUST be signed'));
    }
    let signing: Promise<string>;
    try {
      signing = Promise.resolve(signJwtAsAsync(this.claimsFor(row), alg,
        secret || undefined,
        { header: { typ: TOKEN_TYPE }, certificateHeader: 'id-token',
          session: row.sub }));
    } catch (e) {
      log.debug("Caught in BackchannelLogout.logoutToken(): " +
                ((e && e.message) || e));
      signing = Promise.reject(e);
    }
    log.debug("Leaving BackchannelLogout.logoutToken(). alg=" + alg);
    return signing;
  }

  // How a failed attempt is coded, and whether it is worth another.
  private classify(result: Json): Json {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.classify(). kind=" + result.kind);
    const status = Number(result.status) || 0;
    const table = {
      'outbound-off': ['STS-OAUTH-0532', false],
      'url': ['STS-OAUTH-0533', false],
      'attribute': ['STS-OAUTH-0533', false],
      'internal': ['STS-OAUTH-0534', false],
      'unresolved': ['STS-OAUTH-0535', false],
      'redirect': ['STS-OAUTH-0540', false],
      'build': ['STS-OAUTH-0543', false],
      'timeout': ['STS-OAUTH-0538', true],
      'network': ['STS-OAUTH-0539', true]
    };
    let answer = null;
    if (result.kind === 'status') {
      answer = status === 400
        ? { code: 'STS-OAUTH-0536', retry: false }
        : { code: 'STS-OAUTH-0537',
            retry: status >= 500 || status === 408 || status === 429 };
    } else {
      const row = table[result.kind] || ['STS-OAUTH-0539', true];
      answer = { code: row[0], retry: row[1] };
    }
    log.debug("Leaving BackchannelLogout.classify(). " + answer.code +
              ", retry=" + answer.retry);
    return answer;
  }

  private pause(ms: number): Promise<void> {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.pause(). " + ms + "ms");
    log.debug("Leaving BackchannelLogout.pause().");
    return new Promise<void>(function (resolve) {
      const timer = setTimeout(resolve, Math.max(0, ms));
      // Never the reason a process that is shutting down stays up.
      if (timer && typeof timer.unref === 'function') {
        timer.unref();
      }
    });
  }

  // One delivery, start to finish. Never rejects.
  private async deliverOne(row: Delivery): Promise<void> {
    const { log, fedHttp } = this.deps;
    const self = this;
    log.debug("Entering BackchannelLogout.deliverOne(). " + row.clientId);
    let token = '';
    try {
      token = await this.logoutToken(row);
    } catch (e) {
      log.debug("Caught in BackchannelLogout.deliverOne(): " +
                ((e && e.message) || e));
      self.finish(row, 'failed', 'STS-OAUTH-0541',
                  'the Logout Token could not be signed: ' +
                  ((e && e.message) || e));
      log.debug("Leaving BackchannelLogout.deliverOne(). Not signed.");
      return;
    }
    const attempts = Math.max(1,
      this.setting('oauth2.backchannelLogoutAttempts'));
    const timeoutMs = this.setting('oauth2.backchannelLogoutTimeoutMs');
    const backoffMs = Math.max(0,
      this.setting('oauth2.backchannelLogoutBackoffMs'));
    const record = { id: row.clientId };
    record[ADDRESS_ATTRIBUTE] = row.uri;
    for (let n = 1; n <= attempts; n++) {
      row.attempts = n;
      const result = await fedHttp.deliverForm(record, ADDRESS_ATTRIBUTE,
        { logout_token: token }, { timeoutMs: timeoutMs });
      row.status = Number(result.status) || 0;
      if (result.ok) {
        self.finish(row, 'sent', '', '');
        log.debug("Leaving BackchannelLogout.deliverOne(). Sent.");
        return;
      }
      const judged = this.classify(result);
      if (!judged.retry || n === attempts) {
        self.finish(row, 'failed', judged.code,
                    String(result.why || 'it failed') +
                    (n > 1 ? ' (after ' + n + ' attempts)' : ''));
        log.debug("Leaving BackchannelLogout.deliverOne(). Failed.");
        return;
      }
      log.debug('back-channel logout: attempt ' + n + ' to ' + row.clientId +
                ' failed (' + result.why + '); trying again.');
      await this.pause(backoffMs * Math.pow(2, n - 1));
    }
    log.debug("Leaving BackchannelLogout.deliverOne().");
  }

  // -------------------------------------------------------------------------
  // DISPATCH: send every row still `pending`. Returns a promise that settles
  // when all of them have reached a final state — for a test to wait on;
  // every caller in the service ignores it, which is the whole point of
  // header point 3. It never rejects.
  // -------------------------------------------------------------------------
  dispatch(rows: Delivery[] | null | undefined): Promise<void> {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering BackchannelLogout.dispatch().");
    const pending = (rows || []).filter(function (row) {
      return row && row.state === 'pending';
    });
    if (!pending.length) {
      log.debug("Leaving BackchannelLogout.dispatch(). Nothing to send.");
      return Promise.resolve();
    }
    log.debug("Leaving BackchannelLogout.dispatch(). " + pending.length +
              " to send.");
    return Promise.all(pending.map(function (row) {
      return self.deliverOne(row).catch(function (e) {
        log.debug("Caught in BackchannelLogout.dispatch(): " +
                  ((e && e.message) || e));
        if (row.state === 'pending') {
          self.finish(row, 'failed', 'STS-OAUTH-0543',
                      'the delivery failed: ' + ((e && e.message) || e));
        }
      });
    })).then(function () {
      return undefined;
    });
  }

  // Another process reported the session's end and sends; these rows are not
  // this process's to send. See header point 5.
  abandon(rows: Delivery[] | null | undefined, why?: string): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering BackchannelLogout.abandon().");
    (rows || []).forEach(function (row) {
      if (row && row.state === 'pending') {
        self.finish(row, 'elsewhere', '', why ||
                    'another process reported this session\'s end first, ' +
                    'and that process sends the Logout Token');
      }
    });
    log.debug("Leaving BackchannelLogout.abandon().");
  }

  // A row as a caller sees it: a COPY, so a page or a JSON answer cannot
  // change the register, and a snapshot of the state it had when asked.
  private view(row: Delivery): Json {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.view().");
    log.debug("Leaving BackchannelLogout.view().");
    return {
      id: row.id, sessionId: row.sessionId, clientId: row.clientId,
      uri: row.uri, sessionRequired: row.sessionRequired, state: row.state,
      attempts: row.attempts, status: row.status, errorCode: row.errorCode,
      why: row.why, via: row.via,
      queuedAt: new Date(row.queuedAt).toISOString(),
      finishedAt: row.finishedAt ? new Date(row.finishedAt).toISOString() : ''
    };
  }

  // The deliveries queued for these sessions since `since` (see `mark()`),
  // oldest first. The sign-out result pages and JSON answers call this.
  deliveriesFor(sessionIds: string[] | null | undefined,
                since?: number): Json[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering BackchannelLogout.deliveriesFor().");
    const ids = (sessionIds || []).map(String);
    const after = Number(since) || 0;
    const out = [];
    deliveries.forEach(function (row) {
      if (row.seq > after && ids.indexOf(row.sessionId) >= 0) {
        out.push(row);
      }
    });
    out.sort(function (a, b) { return a.seq - b.seq; });
    log.debug("Leaving BackchannelLogout.deliveriesFor(). " + out.length +
              " row(s).");
    return out.map(function (row) { return self.view(row); });
  }

  // The most recent deliveries in this realm, newest first — what
  // `/admin/logout` and `GET /admin-api/logout` list, so the state a
  // `pending` row reached can be seen after the sign-out that queued it.
  recent(limit?: number): Json[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering BackchannelLogout.recent().");
    const out = [];
    deliveries.forEach(function (row) { out.push(row); });
    out.sort(function (a, b) { return b.seq - a.seq; });
    const cap = Number(limit) > 0 ? Number(limit) : 25;
    log.debug("Leaving BackchannelLogout.recent(). " +
              Math.min(cap, out.length) + " of " + out.length + ".");
    return out.slice(0, cap).map(function (row) { return self.view(row); });
  }

  // A one-sentence summary of a set of rows, for a result message.
  summarize(rows: Json[] | null | undefined): string {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.summarize().");
    const list = rows || [];
    if (!list.length) {
      log.debug("Leaving BackchannelLogout.summarize(). None.");
      return '';
    }
    const count = {};
    list.forEach(function (row) {
      count[row.state] = (count[row.state] || 0) + 1;
    });
    const parts = STATES.filter(function (state) {
      return !!count[state];
    }).map(function (state) {
      return count[state] + ' ' + state;
    });
    log.debug("Leaving BackchannelLogout.summarize().");
    return list.length + ' back-channel Logout Token' +
           (list.length === 1 ? '' : 's') + ' (' + parts.join(', ') + ')' +
           (count['pending'] ? '; a pending one is sent after this answer, ' +
                               'and /admin/logout shows where it got to' : '') +
           '.';
  }

  // -------------------------------------------------------------------------
  // THE BLOCK OF HTML, for `/logout`, `/oauth2/logout` and `/admin/logout`.
  // A table, because every row has a state and a reason, and the paragraph
  // under it says what `pending` means rather than leaving it to be guessed.
  // -------------------------------------------------------------------------
  render(rows: Json[] | null | undefined, heading?: string): string {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering BackchannelLogout.render().");
    const list = rows || [];
    if (!list.length) {
      log.debug("Leaving BackchannelLogout.render(). Nothing to show.");
      return '';
    }
    const body = list.map(function (row) {
      return '<tr><td><code>' + xmlEscape(row.clientId) + '</code></td>' +
        '<td><code>' + xmlEscape(row.uri) + '</code></td>' +
        '<td>' + xmlEscape(row.state) +
        (row.attempts ? ' <span class="sub">(' + row.attempts + ' attempt' +
                        (row.attempts === 1 ? '' : 's') +
                        (row.status ? ', HTTP ' + row.status : '') +
                        ')</span>' : '') +
        (row.why ? '<br><span class="sub">' + xmlEscape(row.why) +
                   '</span>' : '') +
        '</td></tr>';
    }).join('');
    log.debug("Leaving BackchannelLogout.render(). " + list.length +
              " row(s).");
    return '<h2>' + xmlEscape(heading || 'Back-channel Logout Tokens') +
      '</h2><p class="sub">OpenID Connect Back-Channel Logout 1.0. Each ' +
      'relying party below registered a backchannel_logout_uri and is POSTed ' +
      'a signed Logout Token by this service, not by this browser. They go ' +
      'out AFTER this page was answered, so <code>pending</code> is the ' +
      'honest state here; a relying party that is down is tried again a ' +
      'bounded number of times, and <code>/admin/logout</code> shows where ' +
      'each one got to.</p><table><thead><tr><th>Client</th><th>' +
      'backchannel_logout_uri</th><th>State</th></tr></thead><tbody>' +
      body + '</tbody></table>';
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2), exactly as
// `frontchannel_logout.ts` does it: the root builds and installs one, the
// exports are FACADES, and a process without the root builds a default at
// load.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<BackchannelLogout>(
  'oauth-oidc/backchannel_logout',
  () => new BackchannelLogout(BackchannelLogout.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading a module always did.
slot.buildNowUnlessDeferred();

export = {
  BackchannelLogout: BackchannelLogout,
  installInstance: (instance: BackchannelLogout): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  EVENT: BackchannelLogout.EVENT,
  TOKEN_TYPE: BackchannelLogout.TOKEN_TYPE,
  STATES: BackchannelLogout.STATES,
  enabled: slot.forward('enabled'),
  mark: slot.forward('mark'),
  plan: slot.forward('plan'),
  claimsFor: slot.forward('claimsFor'),
  logoutToken: slot.forward('logoutToken'),
  dispatch: slot.forward('dispatch'),
  abandon: slot.forward('abandon'),
  deliveriesFor: slot.forward('deliveriesFor'),
  recent: slot.forward('recent'),
  summarize: slot.forward('summarize'),
  render: slot.forward('render')
};
