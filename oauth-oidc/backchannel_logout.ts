'use strict';
//
// File: backchannel_logout.ts
//
// ===========================================================================
// OPENID CONNECT BACK-CHANNEL LOGOUT 1.0 — TELLING THE RELYING PARTIES
// WITHOUT THE BROWSER (2026-09-17, #36; DURABLE AND COORDINATED THE SAME DAY).
//
// `frontchannel_logout.ts` tells a relying party that a session ended by
// loading its `frontchannel_logout_uri` in an iframe in the browser that is
// signing out — which works only while that browser is on the sign-out page,
// and cannot say whether anything happened. Back-Channel Logout is the other
// half: this service POSTs a signed Logout Token to each relying party's
// registered `backchannel_logout_uri`, server to server, and the relying party
// answers 200 (or 204) when it has ended its own session and 400 when it will
// not. Until #36 the discovery document said
// `backchannel_logout_supported: false`, and the root CLAUDE.md listed it among
// the things this service deliberately does not do.
//
// It is a LIBRARY (rule 3): it registers no route. It requires `common/`
// libraries, `federation/federation_http.ts`, `cluster/cluster_claims.js` and
// `id_token_encryption.ts`, none of which requires it back, so
// `authn/authn.ts` (lazily, at the moment a session ends), `oauth2.ts`,
// `logout/logout.ts` and the console can all reach it.
//
// ---------------------------------------------------------------------------
// SEVEN THINGS ARE WORTH KNOWING BEFORE READING FURTHER.
//
// **1. IT IS TRIGGERED WHERE A SESSION ENDS, NOT AT EACH SIGN-OUT DOOR.**
// `authn.dropSession()` is the one function every sign-out reaches —
// `/oauth2/logout`, `wsignout1.0`, SAML Single Logout, `/logout`,
// `/admin/logout`, `/admin/sessions` and `/admin-api` — and `expireSession()`
// the one every expiry reaches. `plan()` is called before the session's end
// is reported, `dispatch()` inside the report, which is the
// `authn.session-end` claim — so a session's end sends ONCE for the cluster.
// A global logout (`logout/logout.ts`) leaves the relying parties on the
// session for that path rather than sending for them itself; only a relying
// party FORGOTTEN on a session that stays is sent for by the sign-out
// request, and header point 4 is why that is once as well.
//
// **2. AN EXPIRED SESSION SENDS TOO (SINCE THE FOLLOW-UP), AND IT IS A
// SETTING.** Section 2.1 lets the provider notify whenever the OP session
// ends, and a relying party that never hears of an expiry keeps a session the
// provider no longer vouches for. `oauth2.backchannelLogoutOnExpiry` (on)
// turns it off for a test — or a deployment whose relying parties' sessions
// deliberately outlive the provider's idle timeout. Front-channel logout
// CANNOT follow: it is an iframe, and an expiry has no browser.
//
// **3. DELIVERIES ARE ROWS IN A PERSISTED, REPLICATED STORE, AND THE ROW IS
// THE RETRY.** `oauth2.backchannelDeliveries`, per realm, a row per (session,
// client) — persisted and shared exactly where this service persists what it
// mints (product mode on postgres, `persistence/CLAUDE.md`), and this
// process's own map in development or on memory, where there is one process
// to be in. A stored row is SEALED under the key-encryption key like every
// minted row, which is what lets it carry the signed token. Nothing about a delivery lives only in the memory of the process
// that queued it: its state, its attempt count, when it is next due and the
// signed token are on the row, so a restarted process — or another node —
// picks it up where it was left. A SWEEP — the scheduler job
// `oauth2.backchannel-logout-sweep`, on the leader, every
// `oauth2.backchannelLogoutSweepS` (#49 P5) — attempts the rows that are
// due; the process that planned a row attempts it at once and schedules its
// own retries too, so the sweep is the safety net and not the delay. Retries
// back off (`oauth2.backchannelLogoutBackoffMs`, doubling), only what is worth
// repeating is retried (a timeout, a connection failure, 5xx, 408, 429 —
// section 2.5), and a final failure is a DEAD LETTER: `state: 'dead'`, with
// its code, listed on `/admin/logout` and `GET /admin-api/logout`
// (`deliveryState=dead`), and sent again only when an operator asks
// (`retry-backchannel`). A row still pending after
// `oauth2.backchannelLogoutRetentionS` is dead-lettered too, so nothing is
// pending for ever. Finished rows go after the same retention, the oldest
// first past `oauth2.backchannelLogoutMaxRows`.
//
// **4. EXACTLY ONE PROCESS SENDS EACH ATTEMPT: A CLAIM WITH A LEASE, AND THE
// CLAIM TIME IS THE FENCING TOKEN.** An attempt is claimed through
// `cluster_claims.claim()` on (realm, delivery, generation, attempt number)
// for `oauth2.backchannelLogoutLeaseMs` — one `INSERT … ON CONFLICT` on
// postgres, this process's map elsewhere. The winner writes the row (the
// attempt in flight, and not due again until the lease lapses), sends, and
// writes the outcome. A process that dies mid-attempt leaves the claim to
// lapse; the next sweep anywhere claims the SAME attempt number again — an
// expired claim is re-claimable — and sends it. The claim's database time is
// the row's FENCE, and the store's `mergeRow` keeps the row with the higher
// (generation, attempt, fence): a process that paused past its lease and
// wakes to write its outcome loses to the one that took over. What cannot be
// excluded is that both POSTed — HTTP is at-least-once when the sender can
// die between the request and recording the answer — and the token they sent
// is the SAME token with the same `jti`, which section 2.6 tells the relying
// party to deduplicate on. That is why a lease and not a lock: a lock would
// need the dead process to release it. `cluster.withLease()` was not used
// because it names a NODE-wide role with one row per name; a lease per
// delivery would be a row per delivery in `sts_cluster_leases`, never
// expired-and-reused, where a claim row lapses and is swept.
//
// The row's id is DERIVED — a digest of the session, the client, and when
// the client was first noted on the session — so two processes that plan the
// same delivery (two nodes noticing one expiry, a forget racing a global
// logout) write ONE row, and the attempt claim does the rest. A client that
// signs in on the session again after being forgotten is a new noting and a
// new row.
//
// **5. IT GOES OUT THROUGH THE OUTBOUND POLICY, NOT A SECOND ONE.**
// `federation_http.deliverForm()` — `federation.outbound`, https with the
// certificate verified (#171), no redirect followed, the body drained
// and discarded, and in product mode no internal address (the name resolved
// once and the connection pinned to the address that was checked).
//
// **6. THE TOKEN.** Section 2.4: `iss` (the issuer the client's ID Token was
// issued by — recorded per client on the session by
// `frontchannel_logout.noteClient()`), `aud`, `iat`, `exp`
// (`oauth2.backchannelLogoutTokenTtlS`), `jti`, `events` with the one
// member, `sub` AND `sid`, and NO `nonce`. `typ: logout+jwt`. Signed like the
// client's ID Token — its `id_token_signed_response_alg`, the whole table
// including the post-quantum and composite algorithms, through
// `signJwtAsAsync()` and the worker pool — and never `none`; and ENCRYPTED
// like its ID Token when it registered `id_token_encrypted_response_alg`
// (`id_token_encryption.ts`). Signed once per generation and resent
// unchanged, re-signed with the SAME `jti` only if it expired before a retry;
// an operator's retry is a new generation and a new `jti`.
//
// **7. LOGGING IS A SUMMARY.** One `logout.backchannel` audit row per
// delivery when it reaches `sent` or `dead` — the row carries its code and is
// `summarised`, so it writes no log line of its own — and at most one log
// line per realm per `oauth2.backchannelLogoutSummaryS`, counting what was
// sent, retried, taken over and dead-lettered (by code) since the last
// (`STS-OAUTH-0545`). Never a line per attempt.
//
// **SINCE #151 THE MACHINERY OF POINTS 3, 4, 5 AND 7 IS
// `outbound_delivery.ts`**, shared with CIBA's notifications and OpenID
// Provider Commands: this file supplies the kind — the store, the claim
// scope, the Logout Token, the audit row, the retry's re-validation — and
// keeps its own API.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import applications = require('../common/applications');
import validation = require('../common/validation');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import cacheRegistry = require('../common/cache_registry');
import fedHttp = require('../federation/federation_http');
import clusterClaims = require('../cluster/cluster_claims');
import idTokenEncryption = require('./id_token_encryption');
import outbound = require('./outbound_delivery');
// A leaf: a client's fetched `jwks_uri` key set (#120).
import clientJwks = require('./client_jwks');

// A session, a registration document, a delivery result.
type Json = any;

// The event member section 2.4 requires.
const EVENT = 'http://schemas.openid.net/event/backchannel-logout';

// The `typ` header value section 2.4 recommends.
const TOKEN_TYPE = 'logout+jwt';

// The attribute the outbound policy reads the address from.
const ADDRESS_ATTRIBUTE = 'oauthBackchannelLogoutUri';

// The claim scope an attempt is spent under.
const ATTEMPT_SCOPE = 'oauth2.backchannel-attempt';

// The states a delivery passes through: `pending` until it is `sent` (200 or
// 204) or `dead` (a final failure, with a code, until an operator retries it).
const STATES = outbound.STATES;

// A token this close to its `exp` is signed again before a retry.
const EXPIRY_MARGIN_S = 5;

// One delivery — a row of the store: `outbound_delivery.ts`'s generic fields
// and these. The token IS on it: a Logout Token is not a credential anybody
// can use to act as the person, it is a statement that a session ended, and
// a retry after a restart must resend the same one. The store is sealed at
// rest like every minted row; no page or answer shows it (`view()`).
interface Delivery {
  id: string;
  realm: string;
  sessionId: string;
  clientId: string;
  uri: string;
  sessionRequired: boolean;
  iss: string;
  sub: string;
  sid: string;
  username: string;
  via: string;
  trigger: string;
  state: string;
  generation: number;
  attempts: number;
  inFlight: number;
  fenceAt: number;
  holder: string;
  status: number;
  errorCode: string;
  why: string;
  jti: string;
  token: string;
  tokenExp: number;
  encrypted: string;
  queuedAt: number;
  nextAttemptAt: number;
  lastAttemptAt: number;
  finishedAt: number;
  updatedAt: number;
}

interface PlanOptions {
  via?: string;
  clients?: string[];
  issuer?: string;
  trigger?: string;
}

interface ListOptions {
  state?: string;
  sessionIds?: string[];
  since?: number;
  q?: string;
}

interface BackchannelLogoutDeps {
  log: typeof helpers.log;
  xmlEscape: typeof helpers.xmlEscape;
  nowSec: typeof helpers.nowSec;
  randomId: typeof helpers.randomId;
  signJwtAsAsync: typeof helpers.signJwtAsAsync;
  config: typeof config;
  realms: typeof realms;
  applications: typeof applications;
  validation: typeof validation;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  fedHttp: typeof fedHttp;
  claims: typeof clusterClaims;
  idTokenEncryption: typeof idTokenEncryption;
  now: () => number;
  // A timer for this process's own retries. A dependency so a test can make a
  // process that "dies" before its timer fires.
  later: (fn: () => void, ms: number) => void;
}

// The order of two copies of a row — the library's, exported under the
// name the tests have always used.
const compareRows = outbound.compareRows;

// PER TRUST REALM, at its declaration (root CLAUDE.md, trust realms rule 2),
// PERSISTED (header point 3), TOMBSTONED — a derived id is never
// legitimately written again once retention deleted it, and a node holding
// an old copy must not bring a delivery back — and MERGED by rank (header
// point 4).
const deliveries = realms.map({
  persist: 'oauth2.backchannelDeliveries',
  tombstone: true,
  mergeRow: outbound.mergeRow
});

// Described to `/admin/caches` (#74, rule 3ap) as a REPLAY store, which is
// what its derived key makes it: planning a delivery that is already queued —
// a second process noticing the same end — finds it and queues nothing.
const plannedCount = cacheRegistry.register({
  name: 'oauth2.backchannelDeliveries',
  title: 'Back-channel Logout deliveries',
  description: 'One row per relying party told that a session ended ' +
    '(OpenID Connect Back-Channel Logout 1.0): its state, its attempts, ' +
    'when it is next due and the signed Logout Token. The durable queue ' +
    'every process sweeps; a dead letter stays until retried or retention ' +
    'removes it.',
  owner: 'oauth-oidc/backchannel_logout.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  hitMeaning: 'a delivery already queued for that session and client, so ' +
    'a second process ending the same session queued nothing',
  settings: ['oauth2.backchannelLogoutRetentionS',
             'oauth2.backchannelLogoutMaxRows',
             'oauth2.backchannelLogoutSweepS'],
  maxEntries: function (): number {
    return Number(config.value('oauth2.backchannelLogoutMaxRows'));
  },
  bound: 'Enforced: oauth2.backchannelLogoutMaxRows per realm, the oldest ' +
    'FINISHED delivery dropped first; a pending one is never dropped to ' +
    'make room.',
  lifetime: function (): string {
    return 'Until oauth2.backchannelLogoutRetentionS after it was queued ' +
      '(finished or not), the oldest finished first past ' +
      'oauth2.backchannelLogoutMaxRows per realm.';
  },
  entries: function (): unknown[] {
    const keepS = Number(config.value('oauth2.backchannelLogoutRetentionS'));
    return cacheRegistry.realmMapRows(realms, deliveries,
      function (row: Json, key: unknown): object {
        return { key: String(key) + ' (' + String((row && row.state) || '?') +
                      ')',
                 validUntil: Number(row && row.queuedAt) + keepS * 1000,
                 basis: 'time' };
      });
  }
});

// The sweep's scheduler job (#49 P5).
const SWEEP_JOB = 'oauth2.backchannel-logout-sweep';

class BackchannelLogout {
  static readonly EVENT = EVENT;
  static readonly TOKEN_TYPE = TOKEN_TYPE;
  static readonly STATES = STATES;
  static readonly ATTEMPT_SCOPE = ATTEMPT_SCOPE;
  // The shared queue, with this file as its kind (#151).
  private readonly queue: InstanceType<typeof outbound.OutboundDelivery>;

  constructor(private readonly deps: BackchannelLogoutDeps) {
    deps.log.debug("Entering BackchannelLogout.constructor().");
    const self = this;
    this.queue = new outbound.OutboundDelivery({
      label: 'back-channel logout',
      store: deliveries,
      attemptScope: ATTEMPT_SCOPE,
      attribute: ADDRESS_ATTRIBUTE,
      body: 'form',
      settings: {
        attempts: 'oauth2.backchannelLogoutAttempts',
        timeoutMs: 'oauth2.backchannelLogoutTimeoutMs',
        backoffMs: 'oauth2.backchannelLogoutBackoffMs',
        leaseMs: 'oauth2.backchannelLogoutLeaseMs',
        retentionS: 'oauth2.backchannelLogoutRetentionS',
        maxRows: 'oauth2.backchannelLogoutMaxRows',
        concurrency: 'oauth2.backchannelLogoutConcurrency',
        summaryS: 'oauth2.backchannelLogoutSummaryS'
      },
      codes: {
        outboundOff: 'STS-OAUTH-0532', url: 'STS-OAUTH-0533',
        internal: 'STS-OAUTH-0534', unresolved: 'STS-OAUTH-0535',
        redirect: 'STS-OAUTH-0540', build: 'STS-OAUTH-0543',
        timeout: 'STS-OAUTH-0538', network: 'STS-OAUTH-0539',
        status400: 'STS-OAUTH-0536', status: 'STS-OAUTH-0537',
        deferred: 'STS-OAUTH-0547', stale: 'STS-OAUTH-0548',
        summary: 'STS-OAUTH-0545', sweepFailed: 'STS-OAUTH-0549',
        retry: 'STS-OAUTH-0550'
      },
      deadLetterHint: 'Dead letters are listed on /admin/logout and ' +
        'retried from there.',
      prepare: function (row: Json): Promise<Json> {
        return self.prepare(row);
      },
      onFinish: function (row: Json, state: string, code: string,
                          why: string): void {
        self.audited(row, state, code, why);
      },
      onRetry: function (row: Json): Json {
        return self.refreshForRetry(row);
      },
      viewExtra: function (row: Json): Json {
        return {
          sessionId: row.sessionId,
          // What the token names — none of it secret, all of it already in
          // the ID Token the client holds.
          iss: row.iss, sub: row.sub, sid: row.sid,
          sessionRequired: !!row.sessionRequired,
          via: row.via, trigger: row.trigger || 'sign-out',
          encrypted: row.encrypted || ''
        };
      },
      searchText: function (row: Json): string {
        return String(row.sessionId || '') + ' ' + String(row.username || '');
      },
      sweepJob: {
        id: SWEEP_JOB,
        title: 'Back-channel logout sweep',
        describe: 'Sends every Logout Token delivery that is due — a retry ' +
                  'whose backoff has passed, a lease that lapsed, a row ' +
                  'restored after a restart — and dead-letters any still ' +
                  'pending past oauth2.backchannelLogoutRetentionS.',
        owner: 'oauth-oidc/backchannel_logout.ts',
        everySetting: 'oauth2.backchannelLogoutSweepS'
      }
    }, {
      log: deps.log, config: deps.config, realms: deps.realms,
      errorCodes: deps.errorCodes, fedHttp: deps.fedHttp,
      claims: deps.claims, now: deps.now, later: deps.later
    });
    deps.log.debug("Leaving BackchannelLogout.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): BackchannelLogoutDeps {
    helpers.log.debug("Entering BackchannelLogout.defaultDeps().");
    helpers.log.debug("Leaving BackchannelLogout.defaultDeps().");
    return {
      log: helpers.log,
      xmlEscape: helpers.xmlEscape,
      nowSec: helpers.nowSec,
      randomId: helpers.randomId,
      signJwtAsAsync: helpers.signJwtAsAsync,
      config: config,
      realms: realms,
      applications: applications,
      validation: validation,
      errorCodes: errorCodes,
      audit: audit,
      fedHttp: fedHttp,
      claims: clusterClaims,
      idTokenEncryption: idTokenEncryption,
      now: function (): number {
        return Date.now();
      },
      later: outbound.OutboundDelivery.later
    };
  }

  // Is the feature on? Per call, which is what `runtime: true` promises.
  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering BackchannelLogout.enabled().");
    log.debug("Leaving BackchannelLogout.enabled().");
    return !!config.value('oauth2.backchannelLogout');
  }

  // Whether an EXPIRED session sends too (header point 2).
  onExpiry(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering BackchannelLogout.onExpiry().");
    log.debug("Leaving BackchannelLogout.onExpiry().");
    return this.enabled() &&
           !!config.value('oauth2.backchannelLogoutOnExpiry');
  }

  // How long an attempt's claim lasts.
  leaseMs(): number {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.leaseMs().");
    log.debug("Leaving BackchannelLogout.leaseMs().");
    return this.queue.leaseMs();
  }

  // A caller reads this before ending something and passes it to
  // `deliveriesFor()` afterwards, so it is shown what THIS act queued.
  mark(): number {
    const { log, now } = this.deps;
    log.debug("Entering BackchannelLogout.mark().");
    const at = now();
    log.debug("Leaving BackchannelLogout.mark(). " + at);
    return at;
  }

  // The derived id of header point 4.
  deliveryIdFor(sessionId: string, clientId: string, first: unknown): string {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.deliveryIdFor().");
    const digest = nodeCrypto.createHash('sha256')
      .update(String(sessionId) + '\n' + String(clientId) + '\n' +
              String(first || 0))
      .digest('base64url').slice(0, 22);
    log.debug("Leaving BackchannelLogout.deliveryIdFor().");
    return digest;
  }

  // -------------------------------------------------------------------------
  // PLAN: one row per relying party on this session that registered a
  // `backchannel_logout_uri`, written to the store as `pending` and due NOW.
  // A client with no URI is not a row — the front-channel list already says
  // "there is nowhere to tell it" for every client on the session.
  //
  // A row that cannot be sent at all — a stored URI that is not http(s), no
  // issuer recorded — is dead-lettered straight away, with its code, so an
  // operator who fixes the entry can retry it.
  //
  // A row already in the store is LEFT ALONE and answered as it stands
  // (header point 4). It cannot throw: it is called from the middle of ending
  // a session.
  // -------------------------------------------------------------------------
  plan(session: Json, options?: PlanOptions): Json[] {
    const { log, applications, validation, errorCodes, realms } = this.deps;
    const self = this;
    log.debug("Entering BackchannelLogout.plan().");
    const opts = options || {};
    const out: Json[] = [];
    try {
      if (!session || !this.enabled()) {
        log.debug("Leaving BackchannelLogout.plan(). Off, or no session.");
        return out;
      }
      const realmId = realms.currentId();
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
        const id = self.deliveryIdFor(String(session.id || ''), clientId,
                                      held[clientId] && held[clientId].first);
        const existing = self.queue.liveRow(realmId, id);
        if (existing) {
          plannedCount.hit();
          out.push(self.view(existing));
          return;
        }
        plannedCount.miss();
        const fields = {
          id: id,
          realm: realmId,
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
          trigger: String(opts.trigger || 'sign-out'),
          jti: '',
          token: '',
          tokenExp: 0,
          encrypted: ''
        };
        // THE SAME RULE REGISTRATION APPLIES, APPLIED AGAIN WHEN IT IS READ,
        // for `frontchannel_logout.ts`'s reason: `ldapmodify` reaches the
        // attribute without passing registration, the console or the API.
        const stored = validation.backchannelUriProblem(uri);
        let row: Json = self.queue.queue(fields).row;
        if (stored) {
          log.warn(errorCodes.tag('STS-OAUTH-0544') + 'back-channel ' +
                   'logout: ' + clientId + '\'s stored ' +
                   'backchannel_logout_uri is not sent a Logout Token, ' +
                   'because it ' + stored + '.');
          row = self.queue.finish(row, 'dead', 'STS-OAUTH-0544',
                                  'the stored backchannel_logout_uri ' +
                                  stored + '. Correct ' +
                                  'oauthBackchannelLogoutUri on its entry ' +
                                  'and retry.');
        } else if (!row.iss) {
          row = self.queue.finish(row, 'dead', 'STS-OAUTH-0542',
                                  'the session did not record which ' +
                                  'issuer this client\'s ID Token came ' +
                                  'from, so a Logout Token naming the ' +
                                  'right iss cannot be built');
        }
        out.push(self.view(row));
      });
    } catch (e) {
      log.debug("Caught in BackchannelLogout.plan(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-OAUTH-0543') + 'back-channel logout: ' +
               'the deliveries for a session could not be planned, and ' +
               'none will be sent for it: ' + ((e && e.message) || e));
    }
    log.debug("Leaving BackchannelLogout.plan(). " + out.length +
              " delivery(ies).");
    return out;
  }

  // The ONE audit row a delivery writes when it finishes (header point 7).
  private audited(row: Json, state: string, code: string, why: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering BackchannelLogout.audited(). " + state);
    audit.audit({
      action: 'logout.backchannel',
      outcome: state === 'sent' ? 'success' : 'error',
      errorCode: state === 'sent' ? '' : code,
      summarised: true,
      actor: row.username,
      protocol: 'OAuth 2.0 / OIDC',
      channel: 'internal',
      target: row.clientId,
      summary: state === 'sent'
        ? 'a back-channel Logout Token for session ' + row.sessionId +
          ' was accepted by ' + row.clientId + ' (HTTP ' + row.status + ')'
        : 'a back-channel Logout Token for session ' + row.sessionId +
          ' was not delivered to ' + row.clientId + ' and is a dead ' +
          'letter: ' + why,
      detail: {
        delivery: row.id,
        sessionId: row.sessionId,
        clientId: row.clientId,
        uri: row.uri,
        attempts: String(row.attempts),
        generation: String(row.generation),
        status: String(row.status || ''),
        state: state,
        via: row.via,
        trigger: row.trigger,
        encrypted: row.encrypted || 'no'
      }
    });
    log.debug("Leaving BackchannelLogout.audited().");
  }

  // THE BODY: the Logout Token, signed once per generation and again (same
  // jti) only when it would expire before this attempt reached the relying
  // party. A signing failure rejects with its code, and the library
  // dead-letters the row.
  private async prepare(row: Json): Promise<Json> {
    const { log, now } = this.deps;
    log.debug("Entering BackchannelLogout.prepare(). " + row.clientId);
    if (row.token && Number(row.tokenExp) - EXPIRY_MARGIN_S >
                     Math.floor(now() / 1000)) {
      log.debug("Leaving BackchannelLogout.prepare(). The token stands.");
      return { body: { logout_token: row.token } };
    }
    const made = await this.signedToken(row);
    log.debug("Leaving BackchannelLogout.prepare(). Signed.");
    return { body: { logout_token: made.token },
             patch: { token: made.token, tokenExp: made.exp, jti: made.jti,
                      encrypted: made.encrypted } };
  }

  // -------------------------------------------------------------------------
  // THE LOGOUT TOKEN'S CLAIMS — header point 6. `jti` is the row's, so a
  // token signed again for a retry is the same statement.
  // -------------------------------------------------------------------------
  claimsFor(row: Json): Json {
    const { log, nowSec, randomId, config } = this.deps;
    log.debug("Entering BackchannelLogout.claimsFor().");
    const iat = nowSec();
    const claims: Json = {
      iss: row.iss,
      aud: row.clientId,
      iat: iat,
      exp: iat + Number(config.value('oauth2.backchannelLogoutTokenTtlS')),
      jti: String(row.jti || '') || randomId(16),
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

  // The token, signed like the client's ID Token and encrypted like it.
  // Resolves `{ token, exp, jti, encrypted }`, or rejects with a sentence
  // carrying its code.
  async signedToken(row: Json): Promise<Json> {
    const { log, applications, signJwtAsAsync, errorCodes,
            idTokenEncryption } = this.deps;
    log.debug("Entering BackchannelLogout.signedToken(). " + row.clientId);
    let registered: Json = {};
    try {
      registered = applications.registrationOf(row.clientId) || {};
    } catch (e) {
      log.debug("Caught in BackchannelLogout.signedToken(): " +
                ((e && e.message) || e));
      registered = {};
    }
    const alg = String(registered.id_token_signed_response_alg || 'RS256');
    if (alg === 'none') {
      log.debug("Leaving BackchannelLogout.signedToken(). alg none.");
      throw errorCodes.mark(new Error('this client registered ' +
        'id_token_signed_response_alg "none", and section 2.4 says a Logout ' +
        'Token MUST be signed'), 'STS-OAUTH-0541');
    }
    const claims = this.claimsFor(row);
    let signed = '';
    try {
      signed = await signJwtAsAsync(claims, alg,
        String(registered.client_secret || '') || undefined,
        { header: { typ: TOKEN_TYPE }, certificateHeader: 'id-token',
          session: row.sub });
    } catch (e) {
      log.debug("Caught in BackchannelLogout.signedToken(): " +
                ((e && e.message) || e));
      log.debug("Leaving BackchannelLogout.signedToken(). Not signed.");
      throw errorCodes.mark(new Error('the Logout Token could not be signed ' +
        'with ' + alg + ': ' + ((e && e.message) || e)), 'STS-OAUTH-0541');
    }
    // Encrypted like the client's ID Token (section 2.4), or not at all.
    // `protect()` throws with STS-OAUTH-0546 when the registration can no
    // longer be honoured.
    // A key registered by `jwks_uri` is fetched first (#120), for
    // `recipientKey()`'s synchronous read.
    if (registered.id_token_encrypted_response_alg && !registered.jwks &&
        registered.jwks_uri) {
      await clientJwks.ensure(String(registered.jwks_uri), '');
    }
    const wrapped = idTokenEncryption.protect(signed, registered, TOKEN_TYPE);
    log.debug("Leaving BackchannelLogout.signedToken(). alg=" + alg +
              (wrapped.encrypted ? ', encrypted' : ''));
    return { token: wrapped.token, exp: claims.exp, jti: claims.jti,
             encrypted: wrapped.encrypted
               ? wrapped.alg + ' ' + wrapped.enc : '',
             alg: alg };
  }

  // Kept for the tests and for a caller that wants the wire value only.
  logoutToken(row: Json): Promise<string> {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.logoutToken(). " + row.clientId);
    log.debug("Leaving BackchannelLogout.logoutToken().");
    return this.signedToken(row).then(function (made: Json): string {
      return made.token;
    });
  }

  // ONE ATTEMPT of one delivery, through the shared queue (header point 4).
  attempt(realmId: string, id: string): Promise<string> {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.attempt(). " + id);
    log.debug("Leaving BackchannelLogout.attempt().");
    return this.queue.attempt(realmId, id);
  }

  // Attempt every planned row still pending, now. For a test to wait on;
  // every caller in the service ignores it. It never rejects.
  dispatch(rows: Json[] | null | undefined): Promise<void> {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.dispatch().");
    log.debug("Leaving BackchannelLogout.dispatch().");
    return this.queue.dispatch(rows);
  }

  // Before an operator's retry: the client's CURRENT address, because the
  // commonest reason to retry is having corrected it, and an issuer.
  private refreshForRetry(row: Json): Json {
    const { log, applications, validation } = this.deps;
    log.debug("Entering BackchannelLogout.refreshForRetry(). " + row.clientId);
    const client: Json = applications.clientConfigOf(row.clientId) || {};
    const uri = String(client.backchannel_logout_uri || '');
    if (!uri || validation.backchannelUriProblem(uri)) {
      log.debug("Leaving BackchannelLogout.refreshForRetry(). No address.");
      return { problem: row.clientId + ' has no usable ' +
        'backchannel_logout_uri now (' +
        (uri ? validation.backchannelUriProblem(uri) : 'none is registered') +
        '), so a retry would fail the same way.' };
    }
    if (!row.iss) {
      log.debug("Leaving BackchannelLogout.refreshForRetry(). No issuer.");
      return { problem: 'The session recorded no issuer for ' + row.clientId +
        ', so no Logout Token can name the right iss; retrying cannot ' +
        'change that.' };
    }
    log.debug("Leaving BackchannelLogout.refreshForRetry().");
    return { patch: { uri: uri, sessionRequired:
                        !!client.backchannel_logout_session_required } };
  }

  // -------------------------------------------------------------------------
  // AN OPERATOR'S RETRY OF A DEAD LETTER: a new generation — a new `jti`, a
  // fresh attempt budget, and the client's CURRENT address. `{ ok, message,
  // row }` with a code on a refusal. The attempt itself is made at once, by
  // this process, through the claim like any other.
  // -------------------------------------------------------------------------
  retry(id: string, actor?: string): Json {
    const { log, audit } = this.deps;
    log.debug("Entering BackchannelLogout.retry(). " + id);
    const done = this.queue.retry(id, actor || '', 'back-channel',
      { jti: '', token: '', tokenExp: 0, encrypted: '' });
    if (!done.ok) {
      log.debug("Leaving BackchannelLogout.retry(). Refused.");
      return done;
    }
    const row = done.row;
    audit.audit({
      action: 'logout.backchannel.retry', actor: actor || '',
      protocol: 'OAuth 2.0 / OIDC', channel: 'http', target: row.clientId,
      summary: 'a dead back-channel Logout Token delivery for session ' +
               row.sessionId + ' to ' + row.clientId + ' was retried ' +
               '(generation ' + row.generation + ')',
      detail: { delivery: row.id, sessionId: row.sessionId, uri: row.uri }
    });
    log.debug("Leaving BackchannelLogout.retry(). Generation " +
              row.generation + ".");
    return { ok: true, row: this.view(row),
             message: 'The delivery to ' + row.clientId + ' was queued ' +
                      'again with a new Logout Token; it is sent after this ' +
                      'answer, and the list shows where it got to.' };
  }

  // THE SWEEP (header point 3). Resolves `{ attempted, removed, dead }`.
  sweep(): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.sweep().");
    log.debug("Leaving BackchannelLogout.sweep().");
    return this.queue.sweep();
  }

  // THE SUMMARY LINE (header point 7).
  summarise(realmId: string, force?: boolean): string {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.summarise(). " + realmId);
    log.debug("Leaving BackchannelLogout.summarise().");
    return this.queue.summarise(realmId, force);
  }

  // THE SWEEP IS A SCHEDULER JOB (#49 P5, rcbj's directive of 2026-09-21):
  // `oauth2.backchannel-logout-sweep`, a CLUSTER job — once, on the leader,
  // every `oauth2.backchannelLogoutSweepS`. Registered once per process, by
  // the composition root's wire step.
  scheduleSweep(): void {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.scheduleSweep().");
    this.queue.scheduleSweep();
    log.debug("Leaving BackchannelLogout.scheduleSweep().");
  }

  // A row as a caller sees it: a COPY without the token, so a page or a JSON
  // answer cannot change the store and never carries a Logout Token.
  view(row: Json): Json {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.view().");
    log.debug("Leaving BackchannelLogout.view().");
    return this.queue.view(row);
  }

  // -------------------------------------------------------------------------
  // THE LIST, from the SHARED store — so every node's `/admin/logout` shows
  // every node's deliveries. Newest first. `state` narrows to one state,
  // `sessionIds` and `since` to what one act queued, `q` to a substring of
  // the client, session, address or code.
  // -------------------------------------------------------------------------
  list(options?: ListOptions): Json[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering BackchannelLogout.list().");
    const o = options || {};
    const ids = Array.isArray(o.sessionIds) ? o.sessionIds.map(String) : null;
    const rows = this.queue.rows({
      state: o.state, since: o.since, q: o.q,
      where: ids ? function (row: Json): boolean {
        return ids.indexOf(row.sessionId) >= 0;
      } : undefined
    });
    log.debug("Leaving BackchannelLogout.list(). " + rows.length +
              " row(s).");
    return rows.map(function (row) {
      return self.view(row);
    });
  }

  // The deliveries queued for these sessions since `since` (see `mark()`),
  // oldest first. The sign-out result pages and JSON answers call this.
  deliveriesFor(sessionIds: string[] | null | undefined,
                since?: number): Json[] {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.deliveriesFor().");
    const rows = this.list({ sessionIds: sessionIds || [], since: since })
      .reverse();
    log.debug("Leaving BackchannelLogout.deliveriesFor(). " + rows.length +
              " row(s).");
    return rows;
  }

  // The most recent deliveries in this realm, newest first.
  recent(limit?: number): Json[] {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.recent().");
    const cap = Number(limit) > 0 ? Number(limit) : 25;
    log.debug("Leaving BackchannelLogout.recent().");
    return this.list().slice(0, cap);
  }

  // How many rows are in each state, in this realm.
  counts(): Json {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.counts().");
    log.debug("Leaving BackchannelLogout.counts().");
    return this.queue.counts();
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
  // THE BLOCK OF HTML, for `/logout`, `/oauth2/logout` and `/admin/logout`'s
  // results.
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
      'honest state here; a relying party that is down is tried again with ' +
      'backoff — by any node, across restarts — and one that never accepts ' +
      'becomes a dead letter an administrator can retry from ' +
      '<code>/admin/logout</code>.</p><table><thead><tr><th>Client</th><th>' +
      'backchannel_logout_uri</th><th>State</th></tr></thead><tbody>' +
      body + '</tbody></table>';
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). The wire step
// registers the sweep's scheduler job (#49 P5), which runs on the leader.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<BackchannelLogout>(
  'oauth-oidc/backchannel_logout',
  () => new BackchannelLogout(BackchannelLogout.defaultDeps()),
  function (instance: BackchannelLogout): void {
    instance.scheduleSweep();
  },
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
  ATTEMPT_SCOPE: BackchannelLogout.ATTEMPT_SCOPE,
  compareRows: compareRows,
  enabled: slot.forward('enabled'),
  onExpiry: slot.forward('onExpiry'),
  leaseMs: slot.forward('leaseMs'),
  mark: slot.forward('mark'),
  deliveryIdFor: slot.forward('deliveryIdFor'),
  plan: slot.forward('plan'),
  claimsFor: slot.forward('claimsFor'),
  signedToken: slot.forward('signedToken'),
  logoutToken: slot.forward('logoutToken'),
  attempt: slot.forward('attempt'),
  dispatch: slot.forward('dispatch'),
  retry: slot.forward('retry'),
  sweep: slot.forward('sweep'),
  summarise: slot.forward('summarise'),
  list: slot.forward('list'),
  deliveriesFor: slot.forward('deliveriesFor'),
  recent: slot.forward('recent'),
  counts: slot.forward('counts'),
  summarize: slot.forward('summarize'),
  render: slot.forward('render')
};
