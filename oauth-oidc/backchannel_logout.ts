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
// picks it up where it was left. Every process runs a SWEEP
// (`oauth2.backchannelLogoutSweepS`) that attempts the rows that are due; the
// process that planned a row attempts it at once and schedules its own
// retries too, so the sweep is the safety net and not the delay. Retries back
// off (`oauth2.backchannelLogoutBackoffMs`, doubling), only what is worth
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
// `federation_http.deliverForm()` — `federation.outbound`, https unless
// `federation.outboundAllowInsecure`, no redirect followed, the body drained
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
// ===========================================================================

import nodeCrypto = require('crypto');
import os = require('os');
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
const STATES = ['pending', 'sent', 'dead'];

// A token this close to its `exp` is signed again before a retry.
const EXPIRY_MARGIN_S = 5;

// One delivery — a row of the store. The token IS on it: a Logout Token is
// not a credential anybody can use to act as the person, it is a statement
// that a session ended, and a retry after a restart must resend the same one.
// The store is sealed at rest like every minted row; no page or answer shows
// it (`view()`).
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

// ---------------------------------------------------------------------------
// WHICH OF TWO COPIES OF A ROW IS NEWER — the store's `mergeRow`, and the
// same comparison every write in this file makes before it writes. A total
// order, so the merge is pure and converges: (generation, the attempt number
// the row is at, the fence of that attempt, final over pending, the last
// update). Ties keep the STORED copy.
// ---------------------------------------------------------------------------
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

// PER TRUST REALM, at its declaration (root CLAUDE.md, trust realms rule 2),
// PERSISTED (header point 3), TOMBSTONED — a derived id is never
// legitimately written again once retention deleted it, and a node holding
// an old copy must not bring a delivery back — and MERGED by rank (header
// point 4).
const deliveries = realms.map({
  persist: 'oauth2.backchannelDeliveries',
  tombstone: true,
  mergeRow: function (mine: Json, theirs: Json): Json {
    helpers.log.debug("Entering mergeRow().");
    helpers.log.debug("Leaving mergeRow().");
    return compareRows(mine, theirs) > 0 ? mine : theirs;
  }
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

// This process's name on a row it is sending, for the console.
const HOLDER = os.hostname() + ':' + process.pid;

// Per realm, what this process did since its last summary line.
const tallies = new Map<string, Json>();

// When each realm's last summary line was written.
const lastSummaryAt = new Map<string, number>();

// The sweep's timer: one per process.
let sweepTimer: NodeJS.Timeout | null = null;

// Attempts in flight in this process, and the cap on them.
let inFlightHere = 0;

class BackchannelLogout {
  static readonly EVENT = EVENT;
  static readonly TOKEN_TYPE = TOKEN_TYPE;
  static readonly STATES = STATES;
  static readonly ATTEMPT_SCOPE = ATTEMPT_SCOPE;

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
      later: function (fn: () => void, ms: number): void {
        const timer = setTimeout(fn, Math.max(0, ms));
        // Never the reason a process that is shutting down stays up.
        if (timer && typeof timer.unref === 'function') {
          timer.unref();
        }
      }
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

  // The numeric tunables, read directly: every one has a `min` on its row.
  private setting(key: string): number {
    const { log, config } = this.deps;
    log.debug("Entering BackchannelLogout.setting(). " + key);
    log.debug("Leaving BackchannelLogout.setting().");
    return Number(config.value(key));
  }

  // How long an attempt's claim lasts: the setting, and never less than one
  // request's timeout and a second.
  leaseMs(): number {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.leaseMs().");
    const lease = Math.max(this.setting('oauth2.backchannelLogoutLeaseMs'),
      this.setting('oauth2.backchannelLogoutTimeoutMs') + 1000);
    log.debug("Leaving BackchannelLogout.leaseMs(). " + lease);
    return lease;
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

  // A row as the store holds it NOW, in its own realm.
  private liveRow(realmId: string, id: string): Delivery | null {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.liveRow().");
    const held = deliveries.realmMap(realmId).get(id);
    log.debug("Leaving BackchannelLogout.liveRow(). " + (held ? 'held' :
                                                        'gone'));
    return held ? Object.assign({}, held) : null;
  }

  // WRITE A ROW, unless the store already holds a newer copy — the same
  // comparison `mergeRow` makes at the flush, made here so this process's own
  // copy never goes backwards either. Answers the copy that stands.
  private writeRow(row: Delivery): Delivery {
    const { log, now } = this.deps;
    log.debug("Entering BackchannelLogout.writeRow(). " + row.id + " " +
              row.state);
    const store = deliveries.realmMap(row.realm);
    const held = store.get(row.id);
    row.updatedAt = Math.max(now(), (held && Number(held.updatedAt) + 1) || 0);
    if (held && compareRows(row, held) < 0) {
      log.debug("Leaving BackchannelLogout.writeRow(). A newer copy stands.");
      return Object.assign({}, held);
    }
    store.set(row.id, Object.assign({}, row));
    log.debug("Leaving BackchannelLogout.writeRow().");
    return row;
  }

  // What this process did, for the summary line.
  private tally(realmId: string, what: string, code?: string): void {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.tally(). " + what);
    let t = tallies.get(realmId);
    if (!t) {
      t = { sent: 0, retried: 0, takenOver: 0, deferred: 0, dead: 0,
            byCode: {} };
      tallies.set(realmId, t);
    }
    t[what] = (t[what] || 0) + 1;
    if (code) {
      t.byCode[code] = (t.byCode[code] || 0) + 1;
    }
    log.debug("Leaving BackchannelLogout.tally().");
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
    const { log, applications, validation, errorCodes, realms,
            now } = this.deps;
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
        const existing = self.liveRow(realmId, id);
        if (existing) {
          plannedCount.hit();
          out.push(self.view(existing));
          return;
        }
        plannedCount.miss();
        const at = now();
        let row: Delivery = {
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
          state: 'pending',
          generation: 1,
          attempts: 0,
          inFlight: 0,
          fenceAt: 0,
          holder: '',
          status: 0,
          errorCode: '',
          why: '',
          jti: '',
          token: '',
          tokenExp: 0,
          encrypted: '',
          queuedAt: at,
          nextAttemptAt: at,
          lastAttemptAt: 0,
          finishedAt: 0,
          updatedAt: at
        };
        // THE SAME RULE REGISTRATION APPLIES, APPLIED AGAIN WHEN IT IS READ,
        // for `frontchannel_logout.ts`'s reason: `ldapmodify` reaches the
        // attribute without passing registration, the console or the API.
        const stored = validation.backchannelUriProblem(uri);
        if (stored) {
          log.warn(errorCodes.tag('STS-OAUTH-0544') + 'back-channel ' +
                   'logout: ' + clientId + '\'s stored ' +
                   'backchannel_logout_uri is not sent a Logout Token, ' +
                   'because it ' + stored + '.');
          row = self.finish(row, 'dead', 'STS-OAUTH-0544',
                            'the stored backchannel_logout_uri ' + stored +
                            '. Correct oauthBackchannelLogoutUri on its ' +
                            'entry and retry.');
        } else if (!row.iss) {
          row = self.finish(row, 'dead', 'STS-OAUTH-0542',
                            'the session did not record which issuer this ' +
                            'client\'s ID Token came from, so a Logout ' +
                            'Token naming the right iss cannot be built');
        } else {
          row = self.writeRow(row);
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

  // A delivery reaches its final state: the row changes and ONE audit row is
  // written, `summarised` (header point 7). Answers the row as written.
  private finish(row: Delivery, state: string, code: string,
                 why: string): Delivery {
    const { log, audit, now } = this.deps;
    log.debug("Entering BackchannelLogout.finish(). " + row.clientId + " -> " +
              state);
    row.state = state;
    row.errorCode = code || '';
    row.why = why || '';
    row.finishedAt = now();
    row.inFlight = 0;
    row.nextAttemptAt = 0;
    const written = this.writeRow(row);
    if (written.state !== state || written.updatedAt !== row.updatedAt) {
      log.debug("Leaving BackchannelLogout.finish(). A newer copy stood; " +
                "its writer reports it.");
      return written;
    }
    this.tally(row.realm, state === 'sent' ? 'sent' : 'dead', code);
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
    log.debug("Leaving BackchannelLogout.finish().");
    return written;
  }

  // -------------------------------------------------------------------------
  // THE LOGOUT TOKEN'S CLAIMS — header point 6. `jti` is the row's, so a
  // token signed again for a retry is the same statement.
  // -------------------------------------------------------------------------
  claimsFor(row: Json): Json {
    const { log, nowSec, randomId } = this.deps;
    log.debug("Entering BackchannelLogout.claimsFor().");
    const iat = nowSec();
    const claims: Json = {
      iss: row.iss,
      aud: row.clientId,
      iat: iat,
      exp: iat + this.setting('oauth2.backchannelLogoutTokenTtlS'),
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

  // A retry of this process's own, at the row's due time. The sweep would
  // find it anyway; this is what keeps a short backoff short.
  private scheduleRetry(realmId: string, id: string, atMs: number): void {
    const { log, realms, now, later } = this.deps;
    const self = this;
    log.debug("Entering BackchannelLogout.scheduleRetry(). " + id);
    const realm = realms.get(realmId);
    later(function () {
      realms.run(realm, function () {
        return self.attempt(realmId, id).catch(function (e) {
          log.debug("Caught in BackchannelLogout.scheduleRetry(): " +
                    ((e && e.message) || e));
        });
      });
    }, atMs - now());
    log.debug("Leaving BackchannelLogout.scheduleRetry().");
  }

  // -------------------------------------------------------------------------
  // ONE ATTEMPT of one delivery, claimed (header point 4). Resolves what
  // happened — `sent`, `retry`, `dead`, or a reason nothing was done
  // (`not-due`, `claimed-elsewhere`, `deferred`, `gone`). Never rejects.
  // -------------------------------------------------------------------------
  async attempt(realmId: string, id: string): Promise<string> {
    const { log, claims, fedHttp, now, errorCodes } = this.deps;
    log.debug("Entering BackchannelLogout.attempt(). " + id);
    const before = this.liveRow(realmId, id);
    if (!before || before.state !== 'pending') {
      log.debug("Leaving BackchannelLogout.attempt(). Not pending.");
      return 'gone';
    }
    if (Number(before.nextAttemptAt) > now()) {
      log.debug("Leaving BackchannelLogout.attempt(). Not due.");
      return 'not-due';
    }
    // The attempt a lapsed lease left unfinished is claimed again under its
    // own number; otherwise the next one.
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
        this.tally(realmId, 'deferred', 'STS-OAUTH-0547');
      }
      log.debug("Leaving BackchannelLogout.attempt(). Not claimed (" +
                answer.reason + ").");
      return answer.reason === 'store' ? 'deferred' : 'claimed-elsewhere';
    }
    // RE-READ UNDER THE CLAIM: another process may have finished it, or an
    // operator started a new generation, while the claim was being asked.
    let row = this.liveRow(realmId, id);
    if (!row || row.state !== 'pending' ||
        row.generation !== before.generation) {
      log.debug("Leaving BackchannelLogout.attempt(). It changed under the " +
                "claim.");
      return 'gone';
    }
    if (Number(row.inFlight) === n && Number(row.fenceAt) > 0) {
      // A LAPSED LEASE: this attempt was claimed before — by another process,
      // or this one before a stall — and its outcome never recorded. The claim
      // just won is proof the earlier one expired.
      this.tally(realmId, 'takenOver');
      log.debug("BackchannelLogout.attempt(): taking over attempt " + n +
                " of " + id + " from " + (row.holder || 'an unnamed holder') +
                ".");
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
      log.debug("Leaving BackchannelLogout.attempt(). Fenced out before " +
                "sending.");
      return 'claimed-elsewhere';
    }
    const fence = row.fenceAt;
    // THE TOKEN: signed once per generation, and again (same jti) only when
    // it would expire before this attempt reached the relying party.
    if (!row.token || Number(row.tokenExp) - EXPIRY_MARGIN_S <=
                      Math.floor(now() / 1000)) {
      try {
        const made = await this.signedToken(row);
        row.token = made.token;
        row.tokenExp = made.exp;
        row.jti = made.jti;
        row.encrypted = made.encrypted;
        row = this.writeRow(row);
      } catch (e) {
        log.debug("Caught in BackchannelLogout.attempt(): " +
                  ((e && e.message) || e));
        const current = this.liveRow(realmId, id) || row;
        if (current.fenceAt === fence) {
          current.attempts = n;
          this.finish(current, 'dead',
                      errorCodes.codeOf(e) || 'STS-OAUTH-0541',
                      String((e && e.message) || e));
        }
        log.debug("Leaving BackchannelLogout.attempt(). Not signed.");
        return 'dead';
      }
    }
    const record = { id: row.clientId };
    record[ADDRESS_ATTRIBUTE] = row.uri;
    let result: Json = null;
    try {
      result = await fedHttp.deliverForm(record, ADDRESS_ATTRIBUTE,
        { logout_token: row.token },
        { timeoutMs: this.setting('oauth2.backchannelLogoutTimeoutMs') });
    } catch (e) {
      log.debug("Caught in BackchannelLogout.attempt(): " +
                ((e && e.message) || e));
      result = { ok: false, kind: 'build', status: 0,
                 why: String((e && e.message) || e) };
    }
    // THE OUTCOME, WRITTEN ONLY IF THIS PROCESS STILL HOLDS THE ATTEMPT: a
    // row whose fence moved was taken over while this one was sending.
    const current = this.liveRow(realmId, id);
    if (!current || current.fenceAt !== fence ||
        current.generation !== row.generation) {
      log.debug("Leaving BackchannelLogout.attempt(). Fenced out after " +
                "sending; the process that took over records it.");
      return 'claimed-elsewhere';
    }
    current.attempts = n;
    current.inFlight = 0;
    current.status = Number(result.status) || 0;
    if (result.ok) {
      this.finish(current, 'sent', '', '');
      log.debug("Leaving BackchannelLogout.attempt(). Sent.");
      return 'sent';
    }
    const judged = this.classify(result);
    const attempts = Math.max(1,
      this.setting('oauth2.backchannelLogoutAttempts'));
    if (!judged.retry || n >= attempts) {
      this.finish(current, 'dead', judged.code,
                  String(result.why || 'it failed') +
                  (n > 1 ? ' (after ' + n + ' attempts)' : ''));
      log.debug("Leaving BackchannelLogout.attempt(). Dead.");
      return 'dead';
    }
    const backoff = Math.max(0,
      this.setting('oauth2.backchannelLogoutBackoffMs')) * Math.pow(2, n - 1);
    current.errorCode = judged.code;
    current.why = String(result.why || 'it failed') + ' (attempt ' + n +
                  '; trying again)';
    current.nextAttemptAt = now() + backoff;
    const written = this.writeRow(current);
    this.tally(realmId, 'retried');
    this.scheduleRetry(realmId, id, written.nextAttemptAt);
    log.debug("Leaving BackchannelLogout.attempt(). Retry in " + backoff +
              "ms.");
    return 'retry';
  }

  // -------------------------------------------------------------------------
  // DISPATCH: attempt every planned row that is still pending, now, in the
  // ambient realm. Returns a promise that settles when each has reached a
  // final state or been handed to the sweep — for a test to wait on; every
  // caller in the service ignores it. It never rejects.
  // -------------------------------------------------------------------------
  dispatch(rows: Json[] | null | undefined): Promise<void> {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering BackchannelLogout.dispatch().");
    const pending = (rows || []).filter(function (row) {
      return row && row.state === 'pending';
    });
    if (!pending.length) {
      log.debug("Leaving BackchannelLogout.dispatch(). Nothing to send.");
      return Promise.resolve();
    }
    const realmId = realms.currentId();
    log.debug("Leaving BackchannelLogout.dispatch(). " + pending.length +
              " to send.");
    return Promise.all(pending.map(function (row) {
      return self.attempt(row.realm || realmId, row.id)
        .catch(function (e) {
          log.debug("Caught in BackchannelLogout.dispatch(): " +
                    ((e && e.message) || e));
          return 'error';
        });
    })).then(function () {
      return undefined;
    });
  }

  // -------------------------------------------------------------------------
  // AN OPERATOR'S RETRY OF A DEAD LETTER: a new generation — a new `jti`, a
  // fresh attempt budget, and the client's CURRENT address, because the
  // commonest reason to retry is having corrected it. `{ ok, message, row }`
  // with a code on a refusal. The attempt itself is made at once, by this
  // process, through the claim like any other.
  // -------------------------------------------------------------------------
  retry(id: string, actor?: string): Json {
    const { log, realms, applications, validation, errorCodes, audit,
            now } = this.deps;
    log.debug("Entering BackchannelLogout.retry(). " + id);
    const realmId = realms.currentId();
    const row = this.liveRow(realmId, String(id || ''));
    if (!row) {
      log.debug("Leaving BackchannelLogout.retry(). Unknown.");
      return errorCodes.mark({ ok: false, message: 'There is no back-channel ' +
        'delivery "' + String(id || '') + '" in this realm; it may have ' +
        'been removed by retention.' }, 'STS-OAUTH-0550');
    }
    if (row.state !== 'dead') {
      log.debug("Leaving BackchannelLogout.retry(). Not dead.");
      return errorCodes.mark({ ok: false, message: 'The delivery to ' +
        row.clientId + ' is ' + row.state + ', not a dead letter; only a ' +
        'dead letter is retried by hand.' }, 'STS-OAUTH-0550');
    }
    const client: Json = applications.clientConfigOf(row.clientId) || {};
    const uri = String(client.backchannel_logout_uri || '');
    if (!uri || validation.backchannelUriProblem(uri)) {
      log.debug("Leaving BackchannelLogout.retry(). No usable address.");
      return errorCodes.mark({ ok: false, message: row.clientId + ' has no ' +
        'usable backchannel_logout_uri now (' +
        (uri ? validation.backchannelUriProblem(uri) : 'none is registered') +
        '), so a retry would fail the same way.' }, 'STS-OAUTH-0550');
    }
    if (!row.iss) {
      log.debug("Leaving BackchannelLogout.retry(). No issuer.");
      return errorCodes.mark({ ok: false, message: 'The session recorded no ' +
        'issuer for ' + row.clientId + ', so no Logout Token can name the ' +
        'right iss; retrying cannot change that.' }, 'STS-OAUTH-0550');
    }
    const at = now();
    const fresh: Delivery = Object.assign(row, {
      uri: uri,
      sessionRequired: !!client.backchannel_logout_session_required,
      state: 'pending', generation: row.generation + 1, attempts: 0,
      inFlight: 0, fenceAt: 0, holder: '', status: 0, errorCode: '',
      why: 'retried by ' + (actor || 'an administrator'),
      jti: '', token: '', tokenExp: 0, encrypted: '', nextAttemptAt: at,
      finishedAt: 0, via: row.via
    });
    const written = this.writeRow(fresh);
    audit.audit({
      action: 'logout.backchannel.retry', actor: actor || '',
      protocol: 'OAuth 2.0 / OIDC', channel: 'http', target: row.clientId,
      summary: 'a dead back-channel Logout Token delivery for session ' +
               row.sessionId + ' to ' + row.clientId + ' was retried ' +
               '(generation ' + written.generation + ')',
      detail: { delivery: row.id, sessionId: row.sessionId, uri: uri }
    });
    this.dispatch([this.view(written)]);
    log.debug("Leaving BackchannelLogout.retry(). Generation " +
              written.generation + ".");
    return { ok: true, row: this.view(written),
             message: 'The delivery to ' + row.clientId + ' was queued ' +
                      'again with a new Logout Token; it is sent after this ' +
                      'answer, and the list shows where it got to.' };
  }

  // -------------------------------------------------------------------------
  // THE SWEEP (header point 3): every realm, the rows that are due, bounded by
  // `oauth2.backchannelLogoutConcurrency` in flight in this process; then
  // retention; then the summary line. Resolves `{ attempted, removed }` for a
  // test. Never rejects.
  // -------------------------------------------------------------------------
  sweep(): Promise<Json> {
    const { log, realms, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering BackchannelLogout.sweep().");
    const total = { attempted: 0, removed: 0, dead: 0 };
    let chain: Promise<unknown> = Promise.resolve();
    realms.list().forEach(function (realm) {
      chain = chain.then(function () {
        return realms.run(realm, function () {
          return self.sweepRealm(realm.id).then(function (one: Json) {
            total.attempted += one.attempted;
            total.removed += one.removed;
            total.dead += one.dead;
          });
        });
      }).catch(function (e) {
        log.debug("Caught in BackchannelLogout.sweep(): " +
                  ((e && e.message) || e));
        log.error(errorCodes.tag('STS-OAUTH-0549') + 'back-channel logout: ' +
                  'the delivery sweep failed in the "' + realm.id +
                  '" realm: ' + ((e && e.message) || e));
      });
    });
    log.debug("Leaving BackchannelLogout.sweep().");
    return chain.then(function () {
      return total;
    });
  }

  private async sweepRealm(realmId: string): Promise<Json> {
    const { log, now } = this.deps;
    const self = this;
    log.debug("Entering BackchannelLogout.sweepRealm(). " + realmId);
    const at = now();
    const keepMs = Math.max(1, this.setting(
      'oauth2.backchannelLogoutRetentionS')) * 1000;
    const cap = Math.max(1, this.setting('oauth2.backchannelLogoutMaxRows'));
    const store = deliveries.realmMap(realmId);
    const due: string[] = [];
    const finished: Json[] = [];
    let dead = 0;
    const stale: Delivery[] = [];
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
    // NOTHING IS PENDING FOR EVER: a row the retention window passed while
    // still pending is dead-lettered with the reason.
    stale.forEach(function (row) {
      self.finish(row, 'dead', 'STS-OAUTH-0548',
                  'still unsent ' + Math.round(keepMs / 1000) + ' seconds ' +
                  'after it was queued (oauth2.backchannelLogoutRetentionS)');
      dead++;
    });
    // Retention, then the cap — oldest finished first.
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
    // The attempts, bounded per process.
    const limit = Math.max(1,
      this.setting('oauth2.backchannelLogoutConcurrency'));
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
    log.debug("Leaving BackchannelLogout.sweepRealm(). " + attempted +
              " attempted, " + removed + " removed.");
    return { attempted: attempted, removed: removed, dead: dead };
  }

  // THE SUMMARY LINE (header point 7), at most once per
  // `oauth2.backchannelLogoutSummaryS` per realm, and only when something
  // happened.
  summarise(realmId: string, force?: boolean): string {
    const { log, errorCodes, now } = this.deps;
    log.debug("Entering BackchannelLogout.summarise(). " + realmId);
    const t = tallies.get(realmId);
    const at = now();
    const every = Math.max(1, this.setting(
      'oauth2.backchannelLogoutSummaryS')) * 1000;
    if (!t || (!force && at - (lastSummaryAt.get(realmId) || 0) < every)) {
      log.debug("Leaving BackchannelLogout.summarise(). Not due.");
      return '';
    }
    tallies.delete(realmId);
    lastSummaryAt.set(realmId, at);
    const codes = Object.keys(t.byCode).sort().map(function (code) {
      return code + ' ' + t.byCode[code];
    }).join(', ');
    const line = 'back-channel logout in the "' + realmId + '" realm since ' +
      'the last summary: ' + t.sent + ' sent, ' + t.retried + ' retried, ' +
      t.takenOver + ' taken over from a lapsed lease, ' + t.deferred +
      ' deferred (claim store unavailable), ' + t.dead + ' dead-lettered' +
      (codes ? ' (' + codes + ')' : '') + '.';
    if (t.dead || t.deferred) {
      log.warn(errorCodes.tag('STS-OAUTH-0545') + line + ' Dead letters are ' +
               'listed on /admin/logout and retried from there.');
    } else {
      log.info(line);
    }
    log.debug("Leaving BackchannelLogout.summarise().");
    return line;
  }

  // Armed once per process, by the composition root's wire step. `unref()`
  // so it cannot be the reason a process will not exit.
  scheduleSweep(): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering BackchannelLogout.scheduleSweep().");
    if (sweepTimer) {
      clearTimeout(sweepTimer);
    }
    const seconds = Math.max(1,
      this.setting('oauth2.backchannelLogoutSweepS') || 10);
    sweepTimer = setTimeout(function () {
      self.sweep().then(function () {
        self.scheduleSweep();
      }, function () {
        self.scheduleSweep();
      });
    }, seconds * 1000);
    if (sweepTimer && typeof sweepTimer.unref === 'function') {
      sweepTimer.unref();
    }
    log.debug("Leaving BackchannelLogout.scheduleSweep(). " + seconds + "s.");
  }

  // A row as a caller sees it: a COPY without the token, so a page or a JSON
  // answer cannot change the store and never carries a Logout Token.
  view(row: Json): Json {
    const { log } = this.deps;
    log.debug("Entering BackchannelLogout.view().");
    const iso = function (ms: unknown): string {
      log.debug("Entering iso().");
      log.debug("Leaving iso().");
      return Number(ms) ? new Date(Number(ms)).toISOString() : '';
    };
    log.debug("Leaving BackchannelLogout.view().");
    return {
      id: row.id, realm: row.realm, sessionId: row.sessionId,
      clientId: row.clientId, uri: row.uri,
      // What the token names — none of it secret, all of it already in the
      // ID Token the client holds.
      iss: row.iss, sub: row.sub, sid: row.sid,
      sessionRequired: !!row.sessionRequired, state: row.state,
      generation: row.generation, attempts: row.attempts,
      inFlight: !!row.inFlight, holder: row.holder || '',
      status: row.status, errorCode: row.errorCode, why: row.why,
      via: row.via, trigger: row.trigger || 'sign-out',
      encrypted: row.encrypted || '',
      queuedAt: iso(row.queuedAt), nextAttemptAt: iso(row.nextAttemptAt),
      lastAttemptAt: iso(row.lastAttemptAt), finishedAt: iso(row.finishedAt)
    };
  }

  // -------------------------------------------------------------------------
  // THE LIST, from the SHARED store — so every node's `/admin/logout` shows
  // every node's deliveries. Newest first. `state` narrows to one state,
  // `sessionIds` and `since` to what one act queued, `q` to a substring of
  // the client, session, address or code.
  // -------------------------------------------------------------------------
  list(options?: ListOptions): Json[] {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering BackchannelLogout.list().");
    const o = options || {};
    const ids = Array.isArray(o.sessionIds) ? o.sessionIds.map(String) : null;
    const since = Number(o.since) || 0;
    const q = String(o.q || '').toLowerCase();
    const out: Json[] = [];
    deliveries.realmMap(realms.currentId()).forEach(function (row: Json) {
      if (!row) {
        return;
      }
      if (o.state && row.state !== o.state) {
        return;
      }
      if (ids && ids.indexOf(row.sessionId) < 0) {
        return;
      }
      if (since && Number(row.queuedAt) < since) {
        return;
      }
      if (q && [row.clientId, row.sessionId, row.uri, row.errorCode,
                row.username].join(' ').toLowerCase().indexOf(q) < 0) {
        return;
      }
      out.push(row);
    });
    out.sort(function (a, b) {
      return (Number(b.queuedAt) - Number(a.queuedAt)) ||
             String(a.id).localeCompare(String(b.id));
    });
    log.debug("Leaving BackchannelLogout.list(). " + out.length +
              " row(s).");
    return out.map(function (row) { return self.view(row); });
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
    const { log, realms } = this.deps;
    log.debug("Entering BackchannelLogout.counts().");
    const out = { pending: 0, sent: 0, dead: 0 };
    deliveries.realmMap(realms.currentId()).forEach(function (row: Json) {
      if (row && out[row.state] !== undefined) {
        out[row.state]++;
      }
    });
    log.debug("Leaving BackchannelLogout.counts().");
    return out;
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
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). The wire step arms
// the sweep — every process that loads the family sweeps (header point 3).
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
