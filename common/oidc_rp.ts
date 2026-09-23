'use strict';
//
// File: oidc_rp.ts
//
// ===========================================================================
// THIS SERVICE'S OWN HOSTED SURFACES, AS RELYING PARTIES OF ITS OWN
// AUTHORIZATION SERVER (2026-09-06).
//
// `/admin` and `/portal` used to authenticate by REDIRECTING STRAIGHT TO THE
// SIGN-IN SCREEN: `authn.beginAuthentication()` stashed the interrupted
// request, the screen took a name, and the session it minted was the one those
// surfaces then read. That worked, and what was wrong with it is that **this
// service's own two applications were the only applications in the process that
// did not use the protocol this service exists to demonstrate.** An OpenID
// Connect relying party does not read the provider's session store — it has no
// access to one. It sends the person to the authorization endpoint, gets a code
// back at a registered redirect URI, redeems it with a client credential,
// verifies an ID Token and establishes a session of its OWN.
//
// So they do that now, and this module is the client.
//
//   GET /admin                                     no console session
//     -> 302 /oauth2/authorize?client_id=sts-admin-console
//                             &redirect_uri=<base>/admin/callback
//                             &response_type=code&scope=openid profile email
//                             &state=…&nonce=…&code_challenge=…&method=S256
//        the AS finds no SIGN-ON session and redirects to /authn/login;
//        the person signs in; the AS comes back to its own /oauth2/authorize
//     -> 302 <base>/admin/callback?code=…&state=…
//        POST /oauth2/token   Authorization: Basic <client_id:secret>
//                             grant_type=authorization_code&code_verifier=…
//        verify the ID Token against /oauth2/jwks
//     -> 302 wherever the person was going
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3): IT REGISTERS NOTHING.
//
// The callback routes are registered by the surfaces —
// `/admin/callback` in `admin-ui/admin.ts`, `/portal/callback` in
// `portal/portal.ts`, and (since 2026-09-13) the debugger's `/_sts/callback`
// on its own listener in `debugger/debugger_server.ts` — and that is
// deliberate rather than tidy. A route
// registered HERE would land wherever this file was first required, which is a
// position decided by whoever edits an import list; a route registered there
// lands where that surface's other routes are, which is what
// `/admin/sts-metadata` walks and what the console's gate applies to. It also
// keeps the one exemption that gate needs (its own callback) in the file that
// has the gate in it.
//
// It requires `authn.js`, which is loaded at 8 — long before either surface —
// so requiring it here is a cache hit and cannot move a route.
//
// **AND IT REQUIRES `tls/tls_server.js` LAZILY, INSIDE THE ONE FUNCTION THAT
// NEEDS IT.** That module is at 20 and registers every /tls route; a require
// at the top of this file would drag them ahead of `/admin`'s own, of
// `/admin-api`'s, and of ldap, scim and spiffe (rule 1). The precedent is
// `xacml_admin.js`, which requires `xacml.js` back the same way and for the
// same reason. By the time anybody signs in, every module is loaded and the
// require is a cache hit.
//
// ---------------------------------------------------------------------------
// THE BACK CHANNEL IS A REAL HTTP REQUEST, AND IT WAS THE FOURTH OUTBOUND ONE.
//
// This repository had three when it was written (federation's, SSF's push, and
// XACML's nudge) — more have followed since — and each argues its own case
// rather than citing the others. This one is the narrowest, because of who it
// dials: **itself, at a
// loopback address it computes, on a port it is listening on.** Nothing about
// it is influenced by a caller. `DIALLABLE` in `federation_http.ts` exists to
// stop a URL from a request becoming a URL this service fetches; here there is
// no URL at all — the address is `helpers.loopbackHost()` and `helpers.PORT`,
// and the paths are this service's own, three constants below.
//
// **IT IS AN HTTP REQUEST RATHER THAN A FUNCTION CALL ON PURPOSE.** Redeeming
// the code in process would be a client that skips client authentication, skips
// PKCE verification, writes no audit row at the token endpoint, mints nothing
// on `/admin/tokens` and proves nothing about the flow. The whole value of
// moving these surfaces onto the code flow is that the flow is REALLY RUN, and
// a back channel that was a function call would be the half of it that only
// looked run.
//
// Four things bound it, and each is `federation_http.ts`'s rule made again:
//
//   * **THE HOST HEADER IS THE BROWSER'S, THE ADDRESS IS LOOPBACK.** The
//     connection goes to the loopback address of the interface this service
//     LISTENS on — `helpers.loopbackHost()`, which is 127.0.0.1 for a wildcard
//     bind, ::1 for an IPv6 one, and the address itself where `global.host`
//     names one — because that is reachable from inside this process whatever
//     DNS says outside it. It was the literal `127.0.0.1` until 2026-09-12,
//     which reaches nothing when the listener is bound to one interface
//     address or to IPv6 only. The `Host` header carries the name
//     the BROWSER used, because `issuerOf()` builds the `iss` claim from the
//     request when `oauth2.issuer` is not pinned. Dial loopback and say
//     loopback, and the ID Token comes back issued by `https://127.0.0.1:8081`
//     — which is not the issuer the authorization endpoint advertised to the
//     browser, so the RP would have to accept an issuer it should refuse.
//   * **TLS IS VERIFIED AGAINST THIS SERVICE'S OWN TRUST ANCHOR** — the
//     service Root since 2026-09-11, when the listener certificate became a
//     leaf of it, and the self-signed certificate itself where there is no
//     Root (see `backChannel()`); what is skipped is the HOSTNAME check,
//     because the certificate names the service and the connection names the
//     loopback interface. Skipping the hostname while pinning the anchor is
//     the stronger half of the two — it is the same argument
//     `federation/CLAUDE.md` makes about a pinned partner certificate.
//   * **NO REDIRECT IS FOLLOWED.** A 302 from the token endpoint would hand the
//     Basic credential in the `Authorization` header to whatever `Location`
//     said. This service's token endpoint does not redirect; the rule is here
//     because the day it does is the day nobody remembers this.
//   * **THE BODY IS CAPPED AND THE REQUEST IS TIMED OUT**, because a browser is
//     waiting on the far end of it.
//
// ---------------------------------------------------------------------------
// WHAT IT DELIBERATELY DOES NOT DO.
//
//   * **No discovery document is fetched.** An RP normally learns the endpoints
//     from `/.well-known/openid-configuration`, and this one already knows
//     them: it is inside the service that serves them. Fetching it would mean
//     reading back three paths this file could not be wrong about, and then
//     REBASING every absolute URL in it onto the loopback address — because
//     that document advertises the address a BROWSER uses. That is more moving
//     parts for no check.
//   * **It presents the access token to nobody.** These surfaces read the
//     directory directly; there is no resource server to present one to.
//
// **TWO BULLETS HERE SAID "NO REFRESH TOKEN IS KEPT" AND "THE ACCESS TOKEN IS
// DISCARDED TOO" UNTIL 2026-09-12, AND THE FIRST WAS THE DEFECT.** Its argument
// was that a refresh token would be this service refreshing a session nobody is
// using, kept in a store that is the wrong one. What it cost is the thing a
// relying party exists to avoid: an operator working in the console was sent
// back through the sign-in screen, off the page they were on, the moment the
// hour ran out. Both halves of the argument are answered in section 4 below —
// a renewal happens only on a request somebody made, so nothing is refreshed
// for nobody, and the tokens live on the relying-party session itself, which
// is the store the session already is rather than a second one.
// ===========================================================================

//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `OidcRelyingParty` takes every module it reads — the helpers, the
// settings, the mode, the realms, the registry, the crypto module, the audit
// log, the sign-in service, the two cluster libraries, node's `http` and
// `https`, and the lazy reader of `tls/tls_server.js` — through its
// constructor as `OidcRelyingPartyDeps`. The flow store (`realms.map()`) and
// the in-flight renewal map are still declared at module scope, because a
// store becomes per realm at its declaration. The module still exports every
// name it exported before, for the unconverted surfaces and the tests that
// require it. Since #50's R2 the composition root builds the instance
// (`OidcRelyingParty.defaultDeps()`) and installs it; the module's old export
// names are FACADES that forward to it, for the JavaScript callers, and a
// process without the root builds a default when this module finishes loading.
// `OidcRelyingParty` is exported beside them for that root.
// ---------------------------------------------------------------------------

import https = require('https');
import http = require('http');
import nodeCrypto = require('crypto');

import helpers = require('./helpers');
import config = require('./config');
// Whether a redirect URI a request's address produced may be written onto one
// of these two entries — see `ensureRedirectUri()`. A LEAF (rule 3): it
// requires only `config`.
import mode = require('./mode');
import realms = require('./realms');
import applications = require('./applications');
import stsCrypto = require('./crypto');
import audit = require('./audit');
import authn = require('../authn/authn');
// The error codes (common/error_codes.js). Every refusal below answers
// `{ ok: false, why }` to the console or the portal, which draws the page — so
// the code rides on that answer non-enumerably (`codeOf()` reads it) AND is
// marked on the response where this file holds one, so the call-log row
// carries the specific reason whichever of the two callers forgets.
import errorCodes = require('./error_codes');
// SEVERAL NODES AGAINST ONE STORE (2026-09-14, #46): the atomic "once" a
// renewal is single-flight across nodes through, and the barrier the node that
// lost that race waits on to see the winner's renewed tokens. Libraries that
// register nothing; both require `config`, `error_codes` and the capability
// table and reach `persistence.js` only lazily, so neither closes a cycle.
import clusterClaims = require('../cluster/cluster_claims');
import clusterBarrier = require('../cluster/cluster_barrier');
import InstanceSlot = require('./instance_slot');
// FAPI (#139): whether this realm is in FAPI 1.0 Advanced, which changes how
// a surface signs in. A leaf that requires only `helpers` and `config`.
import fapi = require('../oauth-oidc/fapi');

type SurfaceId = 'admin' | 'portal' | 'debugger';

interface Surface {
  id: SurfaceId;
  clientId: string;
  label: string;
  callbackPath: string;
  cookie: string;
  flowRealm: 'ambient' | 'default';
  sessionRealm: 'ambient' | 'default';
  scopes: string[];
}

// What the back channel is asked to send. See backChannel().
interface BackChannelOptions {
  method: string;
  path: string;
  host: string;
  headers?: Record<string, string>;
  body?: string;
  poolPin?: unknown;
  // The request being served; a surface worker reads its protocol-worker
  // hint off it.
  from?: { stsProtocolWorker?: unknown } | null;
  // A TLS client certificate to present (#139): the surface's own, under
  // FAPI 1.0 Advanced with oauth2.fapiRequireMtls on.
  clientCertificate?: { cert: string; key: string } | null;
}

// A key this relying party proves possession of (#34).
interface DpopKey {
  privateKeyPem: string | Buffer;
  publicJwk: { crv: unknown; kty: unknown; x: unknown; y: unknown };
}

// What `beginSignIn()` and `handleCallback()` may be told by a caller.
interface SignInOptions {
  returnTo?: string;
  fallback?: string;
  prompt?: string;
  callbackBase?: string;
  authorizationBase?: string;
  poolPin?: unknown;
}

// A renewal's answer. See renewIfDue().
interface RenewalAnswer {
  renewed: boolean;
  ended?: boolean;
  elsewhere?: boolean;
  session?: any;
  why?: string;
}

// What a relying party needs from the rest of the service. Named for what is
// asked of each, so a test can supply exactly that and nothing more.
interface OidcRelyingPartyDeps {
  log: typeof helpers.log;
  helpers: typeof helpers;
  // `helpers.PORT` and `helpers.baseUrlOf`, taken at load as they always
  // were.
  PORT: typeof helpers.PORT;
  baseUrlOf: typeof helpers.baseUrlOf;
  config: typeof config;
  mode: typeof mode;
  realms: typeof realms;
  applications: typeof applications;
  stsCrypto: typeof stsCrypto;
  audit: typeof audit;
  authn: typeof authn;
  errorCodes: typeof errorCodes;
  clusterClaims: typeof clusterClaims;
  clusterBarrier: typeof clusterBarrier;
  fapi: typeof fapi;
  http: typeof http;
  https: typeof https;
  // `tls/tls_server.js`, required only when the back channel runs — see the
  // header.
  loadTlsServer(): any;
  // `common/pki.js` and `oauth-oidc/jwt_access_token.ts`, required only when
  // a surface needs its client-assertion key or the issuer that assertion is
  // addressed to (#138) — lazily, for the TLS module's reason: neither may
  // be loaded from here at require time.
  loadPki(): any;
  loadJwtAccessTokens(): any;
  flows: typeof flows;
  renewing: typeof renewing;
}

// ---------------------------------------------------------------------------
// THE SURFACES — the console and the portal, and since 2026-09-13 the embedded
// debugger (see its row).
//
// `clientId` is the identifier of the entry `applications.js` seeds under
// `ou=applications` — this file does not create it and must not: that
// container IS the registry, and a client this module invented would be a
// second answer to what a client is. If the entry is gone, the flow REFUSES
// and says so, which is what makes "an operator who deleted one of these meant
// it" a sentence with an observable consequence.
//
// `cookie` is the surface's own session cookie and is never `authn.js`'s. One
// cookie per surface: signing in to the portal does not sign anybody in to
// the console, which is what makes them separate applications rather than one
// wearing several paths.
//
// **A SURFACE HAS TWO REALMS AND THEY ARE NOT THE SAME QUESTION (2026-09-11).**
// It had one — `realm`, meaning both — and that one answer is what stopped
// these two surfaces from sharing a sign-on session anywhere but the default
// realm.
//
// `flowRealm` is where the AUTHORIZATION CODE FLOW runs: which
// `/oauth2/authorize` the browser is sent to, which `/oauth2/token` the code
// is redeemed at, and therefore **which realm's sign-on session the
// authorization endpoint is able to answer out of**. It is `ambient` for both,
// because that is the whole of single sign-on between them: a person who
// signed in at `/realm/acme/portal` and then opens `/realm/acme/admin` is
// answered out of the session they already have, and the sign-in screen is
// never reached. The console's used to be `default` wherever it was reached,
// which meant the two surfaces authenticated against two different partitions
// of `authn.js`'s session store and neither endpoint could see the other's —
// two sign-ins, in both directions, for one person in one browser.
//
// `sessionRealm` is where the surface's OWN session lives, and the console's
// is still `default` whatever realm it was reached in. That is what `admin.js`
// calls "sign in once, in one realm, read every realm": one console session,
// found by the gate from every realm, with the ROLE checked against the
// default realm's `ou=groups` — so who may administer this service is still
// decided in one place and a realm nobody could create cannot make anybody an
// administrator. Moving it to the ambient realm would have bought
// cross-surface single sign-on by taking the realm switcher away.
//
// The consequence is the one thing worth knowing before reading further: **a
// console session's PARENT lives in a different realm's partition from the
// session itself**, whenever the console is reached in a realm. `authn.js`
// carries `derivedFromRealm` for exactly that, and the cascade that ends a
// derived session with its sign-on session reaches across.
// ---------------------------------------------------------------------------
const SURFACES: Record<SurfaceId, Surface> = {
  admin: {
    id: 'admin',
    clientId: 'sts-admin-console',
    label: 'Admin console',
    callbackPath: '/admin/callback',
    cookie: 'sts_admin',
    flowRealm: 'ambient',
    sessionRealm: 'default',
    scopes: ['openid', 'profile', 'email', 'offline_access']
  },
  portal: {
    id: 'portal',
    clientId: 'sts-user-portal',
    label: 'User portal',
    callbackPath: '/portal/callback',
    cookie: 'sts_portal',
    flowRealm: 'ambient',
    sessionRealm: 'ambient',
    scopes: ['openid', 'profile', 'email', 'offline_access']
  },
  // THE EMBEDDED PROTOCOL DEBUGGER (2026-09-13), and the first surface that
  // is NOT ON THIS SERVICE'S ORIGIN: it is served by
  // `debugger/debugger_server.ts` on a listener of its own. Two things follow
  // and both are options rather than fields, because they are addresses a
  // REQUEST decides:
  //
  //   * the redirect URI is on the debugger's origin and the authorization
  //     endpoint is on the main port's, so `beginSignIn()` and
  //     `handleCallback()` take `callbackBase` and `authorizationBase` where
  //     the other two surfaces use one base for both;
  //   * the back channel's Host header is the AUTHORIZATION base's, because
  //     that is the issuer the browser was sent to.
  //
  // Both realms are the default realm's: the listener has no realm prefix,
  // and the roster that decides who may use the debugger is the default
  // realm's.
  //
  // THE FOURTH SCOPE IS THE DEBUGGER API'S PERMISSION, written out here for
  // the reason `applications.js` writes it out — this library is read by
  // every hosted surface and must not depend on a feature directory — and
  // compared with `debugger/debugger_access.ts` by `tests/debugger_access.js`.
  // The authorization server takes it off the grant for anybody who is not a
  // console administrator, and the debugger's gate reports that.
  debugger: {
    id: 'debugger',
    clientId: 'sts-debugger-ui',
    label: 'Protocol debugger',
    callbackPath: '/_sts/callback',
    cookie: 'sts_debugger',
    flowRealm: 'default',
    sessionRealm: 'default',
    scopes: ['openid', 'profile', 'email', 'offline_access',
             'urn:sts:debugger-api:debugger']
  }
};

// The paths this client knows because it is inside the server that serves
// them. See "no discovery document is fetched" above.
const AUTHORIZE_PATH = '/oauth2/authorize';
const TOKEN_PATH = '/oauth2/token';
const JWKS_PATH = '/oauth2/jwks';

// ---------------------------------------------------------------------------
// HOW A SURFACE AUTHENTICATES AT THE TOKEN ENDPOINT (#138, 2026-09-22).
//
// The seeded entries declare `private_key_jwt` and hold NO client secret.
// They had a secret minted at every start, sent as `client_secret_basic`, and
// FAPI 1.0 Baseline section 5.2.2 item 4 refuses both secret methods — so a
// realm in FAPI mode would have locked its own console out. rcbj's direction
// was the stronger of the two answers FAPI allows, and one rule beside it:
// no client secret or other credential may reach a BROWSER. None does: the
// key is issued, kept and used on this side of the back channel.
//
// * **The key is ISSUED, not generated here** — by this realm's certificate
//   authority, through `pki.issueSigningKeyPair()` exactly as `/admin/pki`
//   issues an application's, and written onto the entry with
//   `applications.storeIssuedJwtKeyPair()`: the certificate and its JWKS for
//   the token endpoint to verify against (3i's second source of key), the
//   private half SEALED under the key-encryption key like every
//   `oauthAssertionPrivateKey`. So it is visible on `/admin/applications`,
//   replaceable on `/admin/pki`, revocable, and in product mode kept across
//   a restart with the entry. P-256 (ES256): FAPI item 6's 160-bit floor
//   for an elliptic curve key, and a signature of microseconds.
// * **Issued on first need and again before it runs out** — within
//   `KEY_RENEW_BEFORE_MS` of `oauthAssertionExpiresAt`, or when the entry has
//   none (a fresh realm, an entry an operator cleared), **or when its
//   certificate no longer chains** (2026-09-23): `/admin/pki`'s build-root
//   replaces the Root and every Intermediate, the token endpoint validates the
//   registered certificate's whole chain at every use
//   (`pki.verifySignerChain()`), and a held key whose chain ran through the
//   old branch was refused there for the rest of the process's life — every
//   console and portal sign-in after one build-root, in product mode, until a
//   restart. The same function is asked here first. Through a CLUSTER
//   CLAIM, because two nodes issuing at once would each write a key and the
//   loser's sign-in would sign with a key the entry no longer holds. The
//   node that loses the claim waits for the winner's key to reach the entry.
// * **The assertion** is RFC 7523 section 3's: `iss` and `sub` the client,
//   `aud` the ISSUER this back-channel request will be answered as — OAuth
//   2.1 mode requires it as the sole value, and every other mode accepts it
//   — a `jti` spent once ever (3ae), and a lifetime of a minute.
//
// A secret method is still honoured for an entry an operator SET to one; the
// surface then sends the entry's secret from this process as it always did.
// ---------------------------------------------------------------------------
const SECRET_METHODS = ['client_secret_basic', 'client_secret_post'];
const ASSERTION_TYPE =
  'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const SURFACE_KEY_ALG = 'ec-p256';
const SURFACE_SIGNING_ALG = 'ES256';
const SURFACE_KEY_DAYS = 365;
const KEY_RENEW_BEFORE_MS = 30 * 24 * 3600 * 1000;
const ASSERTION_LIFETIME_S = 60;
// A signed request object's lifetime under FAPI 1.0 Advanced (#139): well
// inside Part 2's sixty minutes, because it is used within a redirect.
const REQUEST_OBJECT_LIFETIME_S = 300;
const PAR_PATH = '/oauth2/par';

// A flow in progress, per realm, keyed by `state`. `federation_sp.ts`'s
// decision 3 exactly: the partner — here, the browser — carries an opaque
// handle and every fact about the request stays on this side. The `returnTo`
// in particular must never ride in a parameter, because a return address a
// caller can write is an open redirect operated by whoever can forge a state.
const flows = realms.map({ persist: 'oidc_rp.flows', retain: 'age' });
// In flight at once, per realm rather than per process, for the reason
// `federation_sp.ts` gives about a shared cap: one realm's flood would
// otherwise evict another realm's in-flight sign-ins. `oidcRp.maxFlows` since
// 2026-09-12; this is its default.
const MAX_FLOWS = 200;
// How long somebody has to get through the sign-in screen. It is the
// pending-authentication record's own lifetime over in `authn.js`, and the two
// are deliberately the same: a flow that outlived the screen it is waiting on
// would be a state this service accepts and an authorization endpoint that no
// longer has anything to answer with.
//
// **THEY WERE "THE SAME" AS TWO LITERALS UNTIL 2026-09-12**, which is the one
// way that sentence can quietly stop being true. Both read `authn.pendingTtlS`
// now, so they cannot differ.
const FLOW_TTL_MS = 10 * 60 * 1000;
// The back channel's bounds. Both are `federation_http.ts`'s and are set to
// the same values for the same reasons. The timeout is
// `oidcRp.backChannelTimeoutS` since 2026-09-12; the body cap is not a
// deployment decision.
const BACK_CHANNEL_TIMEOUT_MS = 10 * 1000;
const MAX_BODY_BYTES = 256 * 1024;
// How many redirect URIs the two entries may carry before learning stops —
// `oidcRp.maxRedirectUris`. See `ensureRedirectUri()`.
const MAX_REDIRECT_URIS = 20;

// See section 4 below, above `renewing`.
const RENEW_BEFORE_EXPIRY_S = 60;
// Keyed by the realm the session lives in and the session id. Process-wide
// rather than `realms.map()` because it is keyed BY realm already and holds a
// promise for one back-channel round trip: nothing to persist, and nothing
// another process could use — a console or portal request holds affinity to
// one request worker.
const renewing = new Map<string, Promise<RenewalAnswer>>();

const RENEWAL_POLL_MS = 50;

class OidcRelyingParty {
  static readonly SURFACES = SURFACES;
  static readonly AUTHORIZE_PATH = AUTHORIZE_PATH;
  static readonly TOKEN_PATH = TOKEN_PATH;
  static readonly JWKS_PATH = JWKS_PATH;
  static readonly MAX_FLOWS = MAX_FLOWS;
  static readonly FLOW_TTL_MS = FLOW_TTL_MS;
  static readonly BACK_CHANNEL_TIMEOUT_MS = BACK_CHANNEL_TIMEOUT_MS;
  static readonly MAX_BODY_BYTES = MAX_BODY_BYTES;
  static readonly MAX_REDIRECT_URIS = MAX_REDIRECT_URIS;
  static readonly RENEW_BEFORE_EXPIRY_S = RENEW_BEFORE_EXPIRY_S;
  static readonly RENEWAL_POLL_MS = RENEWAL_POLL_MS;

  constructor(private readonly deps: OidcRelyingPartyDeps) {
    deps.log.debug("Entering OidcRelyingParty.constructor().");
    deps.log.debug("Leaving OidcRelyingParty.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  static defaultDeps(): OidcRelyingPartyDeps {
    helpers.log.debug("Entering OidcRelyingParty.defaultDeps().");
    helpers.log.debug("Leaving OidcRelyingParty.defaultDeps().");
    return {
      log: helpers.log,
      helpers: helpers,
      PORT: helpers.PORT,
      baseUrlOf: helpers.baseUrlOf,
      config: config,
      mode: mode,
      realms: realms,
      applications: applications,
      stsCrypto: stsCrypto,
      audit: audit,
      authn: authn,
      errorCodes: errorCodes,
      clusterClaims: clusterClaims,
      clusterBarrier: clusterBarrier,
      http: http,
      https: https,
      loadTlsServer: function () {
        return require('../tls/tls_server');
      },
      fapi: fapi,
      loadPki: function () {
        return require('./pki');
      },
      loadJwtAccessTokens: function () {
        return require('../oauth-oidc/jwt_access_token');
      },
      flows: flows,
      renewing: renewing
    };
  }

  private coded(code: string, answer: any, res?: any): any {
    const { log, errorCodes } = this.deps;
    log.debug("Entering OidcRelyingParty.coded().");
    if (res) {
      errorCodes.mark(res, code);
    }
    log.debug("Leaving OidcRelyingParty.coded().");
    return errorCodes.mark(answer, code);
  }

  // A positive-integer setting, or its default where the store holds none.
  private positiveSetting(key: string, fallback: number): number {
    const { log, config } = this.deps;
    log.debug("Entering OidcRelyingParty.positiveSetting().");
    const n = Number(config.value(key));
    log.debug("Leaving OidcRelyingParty.positiveSetting().");
    return isFinite(n) && n > 0 ? Math.floor(n) : fallback;
  }

  private maxFlows(): number {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.maxFlows().");
    log.debug("Leaving OidcRelyingParty.maxFlows().");
    return this.positiveSetting('oidcRp.maxFlows', MAX_FLOWS);
  }

  flowTtlMs(): number {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.flowTtlMs().");
    log.debug("Leaving OidcRelyingParty.flowTtlMs().");
    return this.positiveSetting('authn.pendingTtlS',
                                FLOW_TTL_MS / 1000) * 1000;
  }

  private backChannelTimeoutMs(): number {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.backChannelTimeoutMs().");
    log.debug("Leaving OidcRelyingParty.backChannelTimeoutMs().");
    return this.positiveSetting('oidcRp.backChannelTimeoutS',
                                BACK_CHANNEL_TIMEOUT_MS / 1000) * 1000;
  }

  private maxRedirectUris(): number {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.maxRedirectUris().");
    log.debug("Leaving OidcRelyingParty.maxRedirectUris().");
    return this.positiveSetting('oidcRp.maxRedirectUris', MAX_REDIRECT_URIS);
  }

  // -------------------------------------------------------------------------
  // The surface, by id. A caller naming one that does not exist is a bug in
  // this repository rather than anything a request can cause, so it throws
  // rather than answering null: a null here would produce a sign-in that
  // redirects to `undefined`.
  // -------------------------------------------------------------------------
  surfaceOf(id: string): Surface {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.surfaceOf().");
    const surface = SURFACES[String(id)];
    if (!surface) {
      log.debug("Leaving OidcRelyingParty.surfaceOf(). No such surface.");
      throw new Error('oidc_rp: there is no surface called "' + id + '". ' +
                      'The surfaces are ' + Object.keys(SURFACES).join(', ') +
                      '.');
    }
    log.debug("Leaving OidcRelyingParty.surfaceOf().");
    return surface;
  }

  // Run `fn` in the realm this surface's CODE FLOW belongs to — the
  // authorization request, the token request, the JWKS fetch and the flow
  // record that joins them. The console and the portal answer `ambient`; the
  // debugger, added later, is the surface that wanted the other answer — its
  // listener has no realm prefix, so its flow runs in the default realm.
  private inFlowRealm<T>(surface: Surface, fn: () => T): T {
    const { log, realms } = this.deps;
    log.debug("Entering OidcRelyingParty.inFlowRealm().");
    if (surface.flowRealm === 'default') {
      log.debug("Leaving OidcRelyingParty.inFlowRealm().");
      return realms.run(realms.DEFAULT_REALM, fn);
    }
    log.debug("Leaving OidcRelyingParty.inFlowRealm().");
    return fn();
  }

  // Run `fn` in the realm this surface's OWN SESSION belongs to. The
  // console's is always the default realm, so that one console session is
  // found by the gate from every realm; the portal's is the realm it was
  // reached in, because a person in `acme` is a different person from the
  // one in the default realm; the debugger's is the default realm's, like its
  // flow.
  private inSessionRealm<T>(surface: Surface, fn: () => T): T {
    const { log, realms } = this.deps;
    log.debug("Entering OidcRelyingParty.inSessionRealm().");
    if (surface.sessionRealm === 'default') {
      log.debug("Leaving OidcRelyingParty.inSessionRealm().");
      return realms.run(realms.DEFAULT_REALM, fn);
    }
    log.debug("Leaving OidcRelyingParty.inSessionRealm().");
    return fn();
  }

  // The id of that realm, for the readers that take one rather than running
  // in it.
  private sessionRealmIdOf(surface: Surface): string {
    const { log, realms } = this.deps;
    log.debug("Entering OidcRelyingParty.sessionRealmIdOf().");
    log.debug("Leaving OidcRelyingParty.sessionRealmIdOf().");
    return surface.sessionRealm === 'default' ? realms.DEFAULT_ID :
           realms.currentId();
  }

  // -------------------------------------------------------------------------
  // THE ADDRESSES.
  //
  // `publicBaseOf()` is what the BROWSER is sent to and what goes in the
  // redirect URI. `loopbackOrigin()` is where this process dials itself. They
  // are different strings on purpose and the difference is the whole of the
  // back channel's design — see the header.
  // -------------------------------------------------------------------------
  private publicBaseOf(req: any): string {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering OidcRelyingParty.publicBaseOf().");
    log.debug("Leaving OidcRelyingParty.publicBaseOf().");
    return baseUrlOf(req);
  }

  loopbackOrigin(): string {
    const { log, config, helpers, PORT } = this.deps;
    log.debug("Entering OidcRelyingParty.loopbackOrigin().");
    const scheme = config.value('global.https') ? 'https' : 'http';
    log.debug("Leaving OidcRelyingParty.loopbackOrigin().");
    // An ADDRESS rather than `localhost`, which resolves to ::1 first on some
    // hosts while this service binds 0.0.0.0 — a connection refused on a name
    // that pings, which is among the least obvious failures available. Which
    // address is `helpers.loopbackHost()`'s answer about the interface this
    // service is bound to; `hostForUrl()` brackets it when it is IPv6.
    return scheme + '://' + helpers.hostForUrl(helpers.loopbackHost()) + ':' +
           PORT;
  }

  // The Host header the loopback request carries: the authority the browser
  // used, so that `issuerOf()` builds the issuer the browser was told about.
  // It is taken from the public base rather than from `req.headers.host`
  // directly because the public base has already been through
  // `forwardedFrom()`, which is where `global.trustProxy` is honoured.
  private hostHeaderFrom(publicBase: string): string {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.hostHeaderFrom().");
    log.debug("Leaving OidcRelyingParty.hostHeaderFrom().");
    return String(publicBase).replace(/^https?:\/\//i, '').split('/')[0];
  }

  // -------------------------------------------------------------------------
  // THE CLIENT'S OWN REGISTRATION, READ FROM THE REGISTRY AT THE MOMENT IT IS
  // USED.
  //
  // Not cached, and that is the same rule `/admin/xacml`'s repository reads
  // and `federation.js`'s register reads: there are four doors onto this
  // entry — the console, the management API, an `ldapmodify` and RFC 7591's
  // `PUT /oauth2/register/{id}` — and a copy held here would be the one that
  // is wrong exactly when somebody has just edited it.
  // -------------------------------------------------------------------------
  // The members are RFC 7591's own spellings — `client_secret`,
  // `redirect_uris`, `token_endpoint_auth_method` — because that is what
  // `clientConfigOf()` answers with: the registry speaks the registration
  // document's vocabulary and this client reads it rather than a camelCase
  // copy of it.
  private clientOf(surface: Surface): any {
    const { log, applications } = this.deps;
    log.debug('Entering OidcRelyingParty.clientOf(). clientId=' +
              surface.clientId);
    const entry = applications.clientConfigOf(surface.clientId);
    if (!entry || !entry.registered) {
      log.debug('Leaving OidcRelyingParty.clientOf(). It is not registered.');
      return this.coded('STS-AUTHN-0112', { ok: false,
               why: 'the application "' + surface.clientId + '" is not in ' +
                    'this realm\'s registry. It is seeded at startup ' +
                    '(applications.seedInternal) and something has deleted ' +
                    'it, or seeding is off. Recreate it on ' +
                    '/admin/applications, or restart this service.' });
    }
    // #138: the seeded entries authenticate by `private_key_jwt` and hold NO
    // secret — a secret is asked for only where an operator set the entry
    // to one of the two secret methods.
    const method = String(entry.token_endpoint_auth_method ||
                          'client_secret_basic');
    if (SECRET_METHODS.indexOf(method) >= 0 && !entry.client_secret) {
      log.debug('Leaving OidcRelyingParty.clientOf(). It has no secret.');
      return this.coded('STS-AUTHN-0113', { ok: false,
               why: 'the application "' + surface.clientId + '" declares ' +
                    method + ' and carries no oauthClientSecret, so this ' +
                    'surface cannot authenticate at the token endpoint. ' +
                    'The seeded entry uses private_key_jwt; set ' +
                    'oauthTokenEndpointAuthMethod back to it, or give the ' +
                    'entry a secret.' });
    }
    log.debug('Leaving OidcRelyingParty.clientOf(). Registered.');
    return { ok: true, client: entry };
  }

  // -------------------------------------------------------------------------
  // THE REDIRECT URI THE ENTRY LEARNS — IN DEVELOPMENT, FROM AN ADDRESS
  // NOBODY PINNED.
  //
  // The seeded entry carries a callback built before any request exists. The
  // BROWSER reaches this service at whatever address it was given — a
  // container name, a proxy's hostname, an IP — and RFC 9700 mode matches
  // `redirect_uri` by exact string, so the address actually in use has to be
  // ON the entry or the first sign-in in that mode is refused by this service
  // against itself.
  //
  // So in DEVELOPMENT the entry LEARNS it: the first flow through a given base
  // adds that base's callback to `oauthRedirectUri`, which is multi-valued
  // precisely so a client can have several. It is added and never replaced —
  // a deployment reached at two names has two, both legitimate — and it is
  // written through `applications.updateApplication()` like every other
  // change to an entry, so it is audited and an operator can take it off
  // again.
  //
  // -------------------------------------------------------------------------
  // **THIS COMMENT SAID LEARNING WAS "NOT A URL FROM A REQUEST BEING
  // TRUSTED", AND IT WAS (corrected 2026-09-12).** It argued that a `Host`
  // header a caller invented reaches `baseUrlOf()` only when
  // `global.trustProxy` is on. That is false: `helpers.forwardedFrom()` reads
  // the forwarded headers only with that setting on and reads the request's
  // own `Host` header ALWAYS — so an anonymous `GET /admin` carrying
  // `Host: evil.example` wrote `https://evil.example/admin/callback`
  // PERMANENTLY onto `sts-admin-console`, with nothing typed and nobody
  // signed in. A registered redirect URI is the thing an authorization server
  // hands a code to; planting one is the first half of stealing the
  // console's.
  //
  // **THREE ANSWERS NOW, AND THE MODE ASKS `acceptsUnregisteredAddresses()`**,
  // which is the question exactly — may a response go to an address the
  // request named and no registration did:
  //
  //   * `global.publicBaseUrl` SET → the base is pinned, whatever Host a
  //     request carried, and NOTHING IS LEARNT. The callback is the pinned
  //     one; an entry that does not carry it is used anyway in development
  //     and refused in product, where the entry is a statement about the
  //     deployment.
  //   * not set, DEVELOPMENT → learnt as before, up to
  //     `oidcRp.maxRedirectUris` values on the entry. The cap is what keeps a
  //     service reached under many names — or asked with many invented Host
  //     headers — from growing an entry without bound; past it the flow still
  //     runs and nothing is written.
  //   * not set, PRODUCT → nothing is written, and a flow at an address the
  //     entry does not carry is REFUSED before a browser is sent anywhere,
  //     with a sentence naming `global.publicBaseUrl` and the entry.
  //
  // It answers `{ ok, why }` and `beginSignIn()` refuses on `ok: false`. A
  // write the registry refuses is still only a warning, as it always was.
  // -------------------------------------------------------------------------
  ensureRedirectUri(surface: Surface, client: any, uri: string): any {
    const { log, helpers, mode, applications, errorCodes } = this.deps;
    log.debug('Entering OidcRelyingParty.ensureRedirectUri(). uri=' + uri);
    const held = [].concat(client.redirect_uris || []);
    if (held.indexOf(uri) >= 0) {
      log.debug('Leaving OidcRelyingParty.ensureRedirectUri(). Already ' +
                'registered.');
      return { ok: true, learnt: false };
    }
    const pinned = !!helpers.pinnedBaseUrl();
    // -----------------------------------------------------------------------
    // AN ADDRESS DEVELOPMENT LEARNT IS NOT A REGISTERED ONE (2026-09-12).
    // `client.redirect_uris` comes from `applications.clientConfigOf()`,
    // which asks `returnAddressesOf()` — so in product a callback this
    // function taught the entry while the realm was in development is not in
    // `held` above, it is in `unconfirmed_redirect_uris`, still marked
    // OBSERVED. It is refused like any unregistered address, with a sentence
    // that says it IS on the entry and how to confirm it rather than one
    // sending the operator to add a value they can already see there.
    // -----------------------------------------------------------------------
    if (!mode.acceptsUnregisteredAddresses() &&
        [].concat(client.unconfirmed_redirect_uris || []).indexOf(uri) >= 0) {
      const why = uri + ' is on the oauthRedirectUri of "' +
                  surface.clientId + '", but this service LEARNT it from a ' +
                  'request while the ' +
                  'realm was in development mode and nobody has confirmed ' +
                  'it, so in product mode it is not a registered redirect ' +
                  'URI. Confirm it on that application\'s page under ' +
                  '/admin/applications, or with POST ' +
                  '/admin-api/applications/confirm-address, if people ' +
                  'really reach this service at that address.';
      log.warn('oidc_rp: the ' + surface.label + ' refused to start a ' +
               'sign-in. ' + why);
      log.debug('Leaving OidcRelyingParty.ensureRedirectUri(). Refused: ' +
                'still marked observed.');
      return this.coded('STS-REG-0049', { ok: false, why: why });
    }
    if (!mode.acceptsUnregisteredAddresses()) {
      const why = 'this service is being reached at an address that is not ' +
                  'a redirect URI of "' + surface.clientId + '" (' + uri +
                  '), and in product mode that entry is not taught new ' +
                  'addresses by the requests that arrive at them — an ' +
                  'invented Host header would otherwise plant a callback ' +
                  'on this service\'s own client. ' +
                  (pinned
                    ? 'global.publicBaseUrl is set, so add ' + uri + ' to ' +
                      'that entry\'s oauthRedirectUri on ' +
                      '/admin/applications or through POST ' +
                      '/admin-api/applications/add.'
                    : 'Set global.publicBaseUrl to the address people reach ' +
                      'this service at, and register ' +
                      'its ' + surface.callbackPath +
                      ' on that entry\'s oauthRedirectUri.');
      log.warn('oidc_rp: the ' + surface.label + ' refused to start a ' +
               'sign-in. ' + why);
      log.debug('Leaving OidcRelyingParty.ensureRedirectUri(). Refused in ' +
                'product mode.');
      return this.coded('STS-AUTHN-0114', { ok: false, why: why });
    }
    if (pinned) {
      log.info('oidc_rp: "' + surface.clientId + '" does not carry the ' +
               'pinned callback ' + uri + '. It is used without being ' +
               'written, because global.publicBaseUrl is set and a pinned ' +
               'address is never learnt; register it on the entry if ' +
               'oauth2.rfc9700 is on, where a redirect URI is matched by ' +
               'exact string.');
      log.debug('Leaving OidcRelyingParty.ensureRedirectUri(). Pinned; not ' +
                'learnt.');
      return { ok: true, learnt: false };
    }
    const cap = this.maxRedirectUris();
    if (held.length >= cap) {
      log.warn('oidc_rp: "' + surface.clientId + '" already carries ' +
               held.length + ' redirect URI(s), the most ' +
               'oidcRp.maxRedirectUris allows ' +
               '(' + cap + '), so ' + uri + ' was NOT added. The ' +
               'sign-in goes ahead; it will be refused only where ' +
               'oauth2.rfc9700 matches redirect URIs by exact string. Set ' +
               'global.publicBaseUrl rather than raising the cap.');
      log.debug('Leaving OidcRelyingParty.ensureRedirectUri(). At the cap.');
      return { ok: true, learnt: false, capped: true };
    }
    // -----------------------------------------------------------------------
    // **THIS CALL NEVER WORKED UNTIL 2026-09-12, AND THE LOG SAID "no reason
    // given".** It passed ONE object — `{ application, action, attribute, … }`
    // — to a function whose signature is `(identifier, change)` with the verb
    // in `change.mode`, so the registry looked up an application called
    // "[object Object]", refused, and this function read `answer.error` where
    // the refusal is `answer.errors`. So the entry had never learnt anything:
    // the documented behaviour above, and the self-refusal in RFC 9700 mode
    // it exists to prevent, were both a comment. Found by the test written for
    // the Host-header finding, which asserted a learnt address and got none.
    // -----------------------------------------------------------------------
    const answer = applications.updateApplication(surface.clientId, {
      attribute: 'oauthRedirectUri',
      mode: 'add',
      value: uri,
      // A SIGHTING WEARING AN UPDATE'S SHAPE (2026-09-12): the address came
      // off a request's Host header, so it is marked OBSERVED on the entry
      // and a realm later switched to product does not believe it until
      // somebody confirms it. Without the flag this call would be an
      // operator's explicit registration, which is exactly what it is not.
      observed: true,
      actor: 'the ' + surface.label
    });
    if (!answer || answer.ok === false) {
      log.warn(errorCodes.tag('STS-AUTHN-0115') +
               'oidc_rp: ' + uri + ' could not be added to "' +
               surface.clientId + '" (' +
               ((answer && (answer.errors || []).join(' ')) ||
                'no reason given') + '). The ' +
               'sign-in will still work unless oauth2.rfc9700 is on, where ' +
               'the redirect URI is matched by exact string.');
      log.debug('Leaving OidcRelyingParty.ensureRedirectUri(). The write ' +
                'was refused.');
      return { ok: true, learnt: false };
    }
    log.info('oidc_rp: "' + surface.clientId + '" learnt the redirect URI ' +
             uri +
             '. This service is being reached at an address the seeded ' +
             'entry did not name, which is the ordinary case behind a proxy ' +
             'or in a container. It is ADDED rather than replacing what was ' +
             'there. Development mode only; set global.publicBaseUrl to ' +
             'stop it.');
    log.debug('Leaving OidcRelyingParty.ensureRedirectUri(). Added.');
    return { ok: true, learnt: true };
  }

  // -------------------------------------------------------------------------
  // PKCE. RFC 7636, S256, always — there is no setting to turn it off, which
  // is `federation_sp.ts`'s position on the same question: the one thing
  // worse than not sending PKCE is a flag that stops.
  // -------------------------------------------------------------------------
  private pkcePair(): { verifier: string; challenge: string } {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.pkcePair().");
    const verifier = nodeCrypto.randomBytes(32).toString('base64url');
    const challenge = nodeCrypto.createHash('sha256')
                                .update(verifier)
                                .digest('base64url');
    log.debug("Leaving OidcRelyingParty.pkcePair().");
    return { verifier: verifier, challenge: challenge };
  }

  // -------------------------------------------------------------------------
  // WHERE THE BROWSER GOES AFTERWARDS, checked the way
  // `beginAuthentication()` checks its own AND stored server-side. Both,
  // because they fail differently: the check catches a caller's bug and the
  // storage catches an attacker.
  // -------------------------------------------------------------------------
  private safeReturnTo(value: unknown, fallback: string): string {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.safeReturnTo().");
    const wanted = String(value || '');
    // A single-slash-rooted path with no whitespace and no scheme. `//host` is
    // refused rather than corrected, because it is the shape an open redirect
    // takes and correcting it would teach a caller that it works.
    if (/^\/(?!\/)[^\s]*$/.test(wanted)) {
      log.debug("Leaving OidcRelyingParty.safeReturnTo().");
      return wanted;
    }
    log.debug("Leaving OidcRelyingParty.safeReturnTo().");
    return fallback;
  }

  // -------------------------------------------------------------------------
  // AND IT COMES BACK INTO THE REALM IT LEFT FROM (2026-09-11).
  //
  // A `Location` header is not markup, so `app.js`'s HTML rewrite — which is
  // what carries the console's several hundred hand-written links into a
  // realm — never sees it. Two callers pass a return address and they were
  // paying that differently by accident: the console passes
  // `req.originalUrl`, which still carries the prefix, and the portal passes
  // the CONSTANT `/portal`. So a person signing in at `/realm/acme/portal`
  // completed the flow in acme, was handed a session in acme, and was then
  // redirected to the DEFAULT realm's portal — which correctly has no session
  // for them, and asks them to sign in again. The symptom is a sign-in that
  // works and then immediately asks again, with nothing in the flow having
  // failed.
  //
  // It is fixed HERE rather than at the `requireSignIn()` call sites, because
  // a prefix somebody has to remember to add is a prefix that will be missing
  // from the next one added. It is IDEMPOTENT for the same reason — the
  // console's address already carries the prefix, and a caller should not
  // have to know which kind it is holding.
  //
  // The default realm's prefix is empty, so this is inert there: the bytes of
  // every redirect in a service with no realms defined are untouched.
  // -------------------------------------------------------------------------
  private inThisRealm(path: string): string {
    const { log, realms } = this.deps;
    log.debug("Entering OidcRelyingParty.inThisRealm().");
    const prefix = realms.currentPrefix();
    if (!prefix) {
      log.debug("Leaving OidcRelyingParty.inThisRealm().");
      return path;
    }
    if (path === prefix || path.indexOf(prefix + '/') === 0) {
      log.debug("Leaving OidcRelyingParty.inThisRealm().");
      return path;
    }
    log.debug("Leaving OidcRelyingParty.inThisRealm().");
    return prefix + path;
  }

  // -------------------------------------------------------------------------
  // THE BACK CHANNEL.
  //
  // One function for both calls it makes, because they differ only in the
  // method and the body. Everything the header promises is here.
  // -------------------------------------------------------------------------
  private backChannel(options: BackChannelOptions): Promise<any> {
    const { log, config, helpers, PORT, http, https } = this.deps;
    const self = this;
    log.debug('Entering OidcRelyingParty.backChannel(). ' + options.method +
              ' ' + options.path);
    log.debug("Leaving OidcRelyingParty.backChannel().");
    return new Promise(function (resolve) {
      const useHttps = config.value('global.https');
      // THE LAZY REQUIRE. See the header: at the top of this file it would
      // move every /tls route; here every module is loaded and it is a cache
      // hit.
      let anchor = null;
      if (useHttps) {
        try {
          // **THE ANCHOR AND NOT THE CERTIFICATE.** Since 2026-09-11 this
          // listener's certificate is a LEAF of this service's own Root, so
          // pinning it puts a certified certificate in a truststore and no
          // path terminates there — `unable to get local issuer
          // certificate`, reported by the console as *Signing in did not
          // complete*, which is this flow correctly describing a token
          // request that never got a connection. `trustAnchorPems()` answers
          // the Root while there is one and the self-signed certificate while
          // there is not, so this call site does not have to know which.
          anchor =
            self.deps.loadTlsServer().serverCertificate().trustAnchorPem;
        } catch (e) {
          log.debug('Leaving OidcRelyingParty.backChannel(). No server ' +
                    'certificate: ' + e.message);
          resolve(self.coded('STS-AUTHN-0116', { ok: false,
                    why: 'this service could not read its own TLS ' +
                         'certificate to verify the loopback connection ' +
                         'against: ' + e.message }));
          return;
        }
      }
      const body = options.body || '';
      const headers: Record<string, string | number> = Object.assign({
        host: options.host,
        accept: 'application/json',
        'content-length': Buffer.byteLength(body)
      }, options.headers || {});

      // ---------------------------------------------------------------------
      // THE BACK CHANNEL HAS TO COME BACK TO THE PROCESS THAT MINTED THE CODE
      // (2026-09-07).
      //
      // This is a SERVER-TO-SERVER request and it carries no cookies, which
      // is correct — it is not the browser and it must not present the
      // browser's credentials. With request dispatching on, that made it the
      // one hop in either hosted surface that could not work: the
      // authorization code was minted in the worker that ran
      // `/oauth2/authorize`, this request goes out to the front process with
      // nothing to route it by, and the front process sends it to whichever
      // worker is least loaded — which does not have the code. The symptom
      // is `/admin/callback` answering 400 on a flow where every earlier hop
      // was correct.
      //
      // So it names the worker it is running in. The value is the pool's
      // routing cookie and NOT a credential — it selects which of N identical
      // processes answers, and nothing is authorized by it; the front process
      // would otherwise have chosen by load. See common/request_pool.js.
      //
      // In the front process, and in any process with no pool, the variable
      // is unset and no header is added — so this is inert everywhere
      // dispatching is not in use.
      // ---------------------------------------------------------------------
      //
      // **AND IN A HOSTED-SURFACE WORKER ITS OWN PID IS THE WRONG ANSWER
      // (2026-09-13).** With `workers.surfaceCount` set, this callback runs
      // in a worker of the SECOND pool and the code is in a worker of the
      // first, so naming itself names no protocol worker at all and the
      // token request is routed by load. The front process knows which
      // protocol worker holds this browser and says so on the request
      // (`request_pool.js`'s PROTOCOL_WORKER_HEADER); `request_worker.ts`
      // puts it on `req`, and the caller passes `req` as `options.from`. No
      // hint — a browser the protocol pool holds nothing for — means no
      // cookie, which is the load-routed request this was before 2026-09-07
      // and is still correct under `workers.readYourWrite`, which a surface
      // pool cannot start without.
      if (process.env.STS_REQUEST_WORKER) {
        const inSurfacePool =
          process.env.STS_REQUEST_WORKER_POOL === 'surfaces';
        const target = inSurfacePool
          ? (Number(options.from && options.from.stsProtocolWorker) || 0)
          : process.pid;
        if (target) {
          const pin = 'sts_pool=' + target;
          headers.cookie = headers.cookie ? (headers.cookie + '; ' + pin) :
            pin;
        }
      } else if (options.poolPin &&
                 /^[0-9]{1,10}$/.test(String(options.poolPin))) {
        // THE SAME PIN FROM THE FRONT PROCESS (2026-09-13), for a surface
        // that is served there rather than by a worker — the embedded
        // debugger. Its browser holds the pool's routing cookie from the
        // authorization endpoint on the main port (a cookie is scoped to a
        // host, not a port), and that names the worker the code was minted
        // in. Digits only: it selects a process and authorizes nothing.
        const pin = 'sts_pool=' + String(options.poolPin);
        headers.cookie = headers.cookie ? (headers.cookie + '; ' + pin) :
          pin;
      }
      if (body) {
        headers['content-type'] = 'application/x-www-form-urlencoded';
      }
      const request = (useHttps ? https : http).request({
        // THE INTERFACE THIS SERVICE LISTENS ON — see the header. Node takes
        // an IPv6 literal here without brackets, which is why this is
        // `loopbackHost()` and not `hostForUrl()`.
        host: helpers.loopbackHost(),
        port: PORT,
        method: options.method,
        path: options.path,
        headers: headers,
        // THE PIN. Our own trust anchor — the service Root, or the
        // self-signed certificate where there is no Root (see the anchor
        // block above) — and the hostname check skipped, because the
        // certificate names this service and the connection names the
        // loopback interface. Pinning the anchor is the stronger half of the
        // two.
        ca: anchor ? [anchor] : undefined,
        // THE SURFACE'S CLIENT CERTIFICATE (#139), where FAPI 1.0 Advanced
        // requires every access token to be bound to one: the certificate
        // this realm's CA issued with the surface's signing key.
        cert: useHttps && options.clientCertificate
          ? options.clientCertificate.cert : undefined,
        key: useHttps && options.clientCertificate
          ? options.clientCertificate.key : undefined,
        checkServerIdentity: useHttps ? function () {
          return undefined;
        } : undefined
      }, function (response) {
        // NO REDIRECT IS FOLLOWED. See the header: a 302 here would hand the
        // Basic credential to whatever Location said.
        if (response.statusCode >= 300 && response.statusCode < 400) {
          response.resume();
          resolve(self.coded('STS-AUTHN-0117', { ok: false,
                    why: 'the token endpoint answered ' +
                         response.statusCode +
                         ' with a redirect, which this client does not ' +
                         'follow — a redirect from a credentialed request ' +
                         'is how the credential ends up somewhere else' }));
          return;
        }
        let text = '';
        let over = false;
        response.setEncoding('utf8');
        response.on('data', function (chunk) {
          if (over) {
            return;
          }
          text += chunk;
          if (text.length > MAX_BODY_BYTES) {
            over = true;
            request.destroy();
          }
        });
        response.on('end', function () {
          if (over) {
            resolve(self.coded('STS-AUTHN-0118', { ok: false,
              why: 'the answer was larger than ' + MAX_BODY_BYTES +
                   ' bytes' }));
            return;
          }
          let json = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            log.debug("Caught in a callback in " +
                      "OidcRelyingParty.backChannel(): " +
                      ((e && e.message) || e));
            // Not JSON; the raw text is what gets reported, because an HTML
            // error page from a door that answers JSON is the interesting
            // case.
            json = null;
          }
          log.debug('Leaving OidcRelyingParty.backChannel(). status=' +
                    response.statusCode);
          // THE RESPONSE HEADERS TRAVEL WITH IT SINCE #34 (2026-09-15), for
          // one reader: `DPoP-Nonce`, which RFC 9449 section 8 says a client
          // takes off the refusal and puts in its next proof. Nothing else
          // here reads them, and no credential is among them — this is a
          // loopback call to this service's own token endpoint.
          resolve({ ok: true, status: response.statusCode, json: json,
                    headers: response.headers || {},
                    text: text.slice(0, 2000) });
        });
      });
      const timeoutMs = self.backChannelTimeoutMs();
      request.setTimeout(timeoutMs, function () {
        request.destroy();
        resolve(self.coded('STS-AUTHN-0119', { ok: false,
                  why: 'this service did not answer its own ' +
                       options.path + ' within ' + (timeoutMs / 1000) +
                       's (oidcRp.backChannelTimeoutS)' }));
      });
      request.on('error', function (e) {
        log.debug('Leaving OidcRelyingParty.backChannel(). error=' +
                  e.message);
        resolve(self.coded('STS-AUTHN-0120', { ok: false,
                  why: 'the loopback request to ' + options.path +
                       ' failed: ' + e.message }));
      });
      if (body) {
        request.write(body);
      }
      request.end();
    });
  }

  // -------------------------------------------------------------------------
  // THE ID TOKEN.
  //
  // Verified against the JWKS this service publishes, fetched over the same
  // loopback channel — NOT against the key material in this process, which
  // would prove nothing about what was actually served. `federation_sp.ts`'s
  // `verifyForeignJwt()` is the model and two of its rules are copied here
  // deliberately rather than referenced: `alg: none` is refused BY NAME,
  // because it is an attack with a name; and the algorithm family comes from
  // the KEY rather than from the token, which is the classic JWT forgery.
  // -------------------------------------------------------------------------
  private jsonFromB64u(part: unknown): any {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.jsonFromB64u().");
    log.debug("Leaving OidcRelyingParty.jsonFromB64u().");
    return JSON.parse(Buffer.from(String(part), 'base64url')
      .toString('utf8'));
  }

  private verifyIdToken(token: string, keys: any[],
                        expected: { issuer: string | undefined;
                                    audience: string;
                                    nonce: string | null }): any {
    const { log, config, stsCrypto } = this.deps;
    log.debug('Entering OidcRelyingParty.verifyIdToken().');
    let header = null;
    try {
      header = this.jsonFromB64u(String(token).split('.')[0]);
    } catch (e) {
      log.debug('Leaving OidcRelyingParty.verifyIdToken(). The header will ' +
                'not decode.');
      return this.coded('STS-AUTHN-0129', { ok: false,
                        why: 'its header is not base64url JSON: ' +
                             e.message });
    }
    if (!header || !header.alg) {
      log.debug("Leaving OidcRelyingParty.verifyIdToken().");
      return this.coded('STS-AUTHN-0130', { ok: false,
                        why: 'it has no alg in its header' });
    }
    if (String(header.alg).toLowerCase() === 'none') {
      log.debug("Leaving OidcRelyingParty.verifyIdToken().");
      return this.coded('STS-AUTHN-0131', { ok: false,
               why: 'its header says alg=none, which is an unsigned token ' +
                    'presented as a signed one' });
    }
    const kid = header.kid || '';
    const candidates = keys.filter(function (key) {
      if (kid && key.kid) {
        return key.kid === kid;
      }
      return true;
    });
    if (!candidates.length) {
      log.debug("Leaving OidcRelyingParty.verifyIdToken().");
      return this.coded('STS-AUTHN-0132', { ok: false,
               why: kid
                 ? 'its header names kid "' + kid + '" and ' + JWKS_PATH +
                   ' publishes no such key'
                 : 'this service publishes no keys at ' + JWKS_PATH });
    }
    let lastWhy = '';
    for (let i = 0; i < candidates.length; i++) {
      let key = null;
      try {
        key = nodeCrypto.createPublicKey({ key: candidates[i],
                                           format: 'jwk' });
      } catch (e) {
        lastWhy = 'a published key could not be read: ' + e.message;
        continue;
      }
      try {
        const payload = stsCrypto.verifyJws(String(token), key, {
          algorithms: candidates[i].kty === 'EC'
            ? ['ES256', 'ES384', 'ES512']
            : ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'],
          clockTolerance: config.value('oauth2.clockSkewS'),
          issuer: expected.issuer,
          audience: expected.audience
        });
        // THE NONCE, which is OpenID Connect Core section 3.1.3.7 step 11 and
        // is the check that makes this an authentication rather than a token
        // handover. `oauth2_bcp.js` records it as unenforceable on the
        // ISSUING side because nothing there can observe a client doing it;
        // here this service IS the client, so it does it.
        //
        // `expected.nonce === null` is a RENEWAL (2026-09-12): OpenID Connect
        // Core section 12.2 says an ID Token from a refresh response SHOULD
        // NOT carry a nonce, because no authorization request sent one — so
        // there is nothing to compare, and what binds that token to this
        // session instead is `checkRenewedClaims()`: the same issuer, the
        // same subject and the same authentication time.
        if (expected.nonce !== null &&
            String(payload.nonce || '') !== String(expected.nonce)) {
          log.debug('Leaving OidcRelyingParty.verifyIdToken(). The nonce ' +
                    'does not match.');
          return this.coded('STS-AUTHN-0134', { ok: false,
                   why: 'its nonce is not the one this sign-in sent, which ' +
                        'is what OpenID Connect Core section 3.1.3.7 step ' +
                        '11 is for: the token is genuine and belongs to a ' +
                        'different request' });
        }
        log.debug('Leaving OidcRelyingParty.verifyIdToken(). Verified.');
        return { ok: true, claims: payload };
      } catch (e) {
        lastWhy = e.message;
      }
    }
    log.debug('Leaving OidcRelyingParty.verifyIdToken(). Nothing verified ' +
              'it: ' + lastWhy);
    return this.coded('STS-AUTHN-0133', { ok: false,
                      why: lastWhy || 'no published key verified it' });
  }

  // -------------------------------------------------------------------------
  // CLIENT AUTHENTICATION AT THE TOKEN ENDPOINT, for both grants this client
  // makes — the code redemption and the renewal. `client_secret_basic` is
  // what the entry's own `token_endpoint_auth_method` says, read off the
  // registration rather than assumed, so an operator who changes it there
  // gets a client that says so rather than one that silently keeps using
  // Basic. Adds the POST members to `form` where the method puts the secret
  // in the body, and answers the headers to send.
  // -------------------------------------------------------------------------
  // -------------------------------------------------------------------------
  // THIS RELYING PARTY PROVES POSSESSION OF A KEY (#34, 2026-09-15).
  //
  // `oauth2.refreshTokenRequireDpop` refuses to issue a refresh token to a
  // request that carries no DPoP proof, and `oauth2.accessTokenRequireDpop`
  // refuses an unbound access token at every resource. The console and the
  // portal are ordinary confidential clients of this authorization server, so
  // with either setting on and nothing done here, turning it on would have
  // meant "nobody can sign in to /admin any more" — which is not what either
  // setting says, and is the kind of exemption that quietly becomes
  // permanent.
  //
  // So they carry a key instead. ONE KEY PER SIGN-IN, generated at the code
  // redemption and kept with that session's tokens: the refresh token minted
  // there is bound to it (`cnf.jkt`), and the renewal months later has to
  // prove the SAME key or the grant is refused. It is an ordinary EC P-256
  // key, generated per sign-in and never written down — it lives exactly as
  // long as the session it belongs to, and a session ending takes it with it.
  //
  // The proof is built here rather than in `dpop.js` because that file is the
  // SERVER side — it verifies proofs and knows nothing about making one — and
  // a verifier that grew a signer would be a module that could be asked to
  // forge what it checks. The two meet at the specification, and at
  // `tests/oidc_rp_dpop.js`, which puts a proof from here through
  // `verifyProof()` there.
  // -------------------------------------------------------------------------
  dpopKey(): DpopKey {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.dpopKey().");
    const pair = nodeCrypto.generateKeyPairSync('ec',
                                                { namedCurve: 'P-256' });
    const jwk = pair.publicKey.export({ format: 'jwk' });
    log.debug("Leaving OidcRelyingParty.dpopKey().");
    return {
      privateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
      // The PUBLIC members only, in the order RFC 7638 thumbprints them. A
      // private member in a proof's `jwk` header is refused by
      // `verifyProof()`, and rightly — it would be this client publishing its
      // own key.
      publicJwk: { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
    };
  }

  // RFC 9449 section 4.2. `nonce` is set only on the retry after the server
  // asked for one; `accessToken` only where a proof accompanies one, which
  // this client never does — it presents its access token to no resource
  // server.
  dpopProof(key: DpopKey, method: string, url: string,
            opts?: { nonce?: string; accessToken?: string }): string {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering OidcRelyingParty.dpopProof(). " + method + " " + url);
    const o = opts || {};
    const payload: Record<string, unknown> = {
      jti: nodeCrypto.randomBytes(16).toString('hex'),
      htm: String(method || 'POST').toUpperCase(),
      // WITHOUT QUERY OR FRAGMENT, which is what section 4.2 asks for and
      // what `dpop.htuOf()` compares against on the other side.
      htu: String(url || '').split('#')[0].split('?')[0],
      iat: Math.floor(Date.now() / 1000)
    };
    if (o.nonce) {
      payload.nonce = String(o.nonce);
    }
    if (o.accessToken) {
      payload.ath = stsCrypto.b64u(nodeCrypto.createHash('sha256')
        .update(String(o.accessToken), 'ascii').digest());
    }
    // A DPoP proof is verified by the `jwk` in its own header (RFC 9449
    // section 4.2) — an x5c or x5t beside it would name a certificate nobody
    // here has and nothing on the other side reads.
    // certificate-header: none — the proof carries its own public key.
    const proof = stsCrypto.signJws(payload, key.privateKeyPem, {
      algorithm: 'ES256',
      header: { typ: 'dpop+jwt', jwk: key.publicJwk }
    });
    log.debug("Leaving OidcRelyingParty.dpopProof().");
    return proof;
  }

  // The URL a proof is made for: the token endpoint this request is about to
  // be sent to, spelled the way the server will read it back off the request.
  private tokenEndpointUrl(host: string, path: string): string {
    const { log, config } = this.deps;
    log.debug("Entering OidcRelyingParty.tokenEndpointUrl().");
    const scheme = config.value('global.https') ? 'https' : 'http';
    log.debug("Leaving OidcRelyingParty.tokenEndpointUrl().");
    return scheme + '://' + String(host || '') + String(path || '');
  }

  // A token request carrying a proof, with RFC 9449 section 8's ONE retry.
  // Nonce mode answers the first request with `use_dpop_nonce` and a
  // `DPoP-Nonce` header, and a client that does not retry is a client that
  // never gets a token while `oauth2.dpopNonceRequired` is on. One retry and
  // no more: a server that asks twice for a nonce it has just supplied is a
  // server this client cannot satisfy by trying again, and a loop here would
  // be a loop inside a sign-in.
  private async tokenRequestWithProof(key: DpopKey,
                                      options: BackChannelOptions):
      Promise<any> {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.tokenRequestWithProof().");
    const self = this;
    const url = this.tokenEndpointUrl(options.host, options.path);
    const send = function (nonce) {
      return self.backChannel(Object.assign({}, options, {
        headers: Object.assign({}, options.headers,
                               { dpop: self.dpopProof(key, 'POST', url,
                                                      { nonce: nonce }) })
      }));
    };
    const first = await send('');
    const needsNonce = first.ok && first.json &&
                       String(first.json.error || '') === 'use_dpop_nonce';
    if (!needsNonce) {
      log.debug("Leaving OidcRelyingParty.tokenRequestWithProof(). One " +
                "request was enough.");
      return first;
    }
    const nonce = String((first.headers || {})['dpop-nonce'] || '');
    if (!nonce) {
      log.debug("Leaving OidcRelyingParty.tokenRequestWithProof(). Asked " +
                "for a nonce and sent none.");
      return first;
    }
    log.debug("Leaving OidcRelyingParty.tokenRequestWithProof(). Retrying " +
              "with the nonce.");
    return send(nonce);
  }

  // The token endpoint's client authentication for one request: headers to
  // send, or a refusal. `form` gains the parameters that go in the body.
  private async clientAuthentication(surface: Surface, client: any,
                                     form: URLSearchParams, host: string):
      Promise<{ ok: boolean; headers?: Record<string, string>;
                why?: string }> {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.clientAuthentication().");
    const method = String(client.token_endpoint_auth_method ||
                          'client_secret_basic');
    const headers: Record<string, string> = {};
    if (method === 'private_key_jwt') {
      const key = await this.surfaceKey(surface);
      if (!key.ok) {
        log.debug("Leaving OidcRelyingParty.clientAuthentication(). No " +
                  "key.");
        return key;
      }
      form.set('client_id', surface.clientId);
      form.set('client_assertion_type', ASSERTION_TYPE);
      form.set('client_assertion',
               this.clientAssertion(surface, key, host));
      log.debug("Leaving OidcRelyingParty.clientAuthentication(). " +
                "method=private_key_jwt");
      return { ok: true, headers: headers };
    }
    if (method === 'client_secret_post') {
      form.set('client_id', surface.clientId);
      form.set('client_secret', client.client_secret);
    } else if (method === 'client_secret_basic') {
      headers.authorization = 'Basic ' + Buffer.from(
        encodeURIComponent(surface.clientId) + ':' +
        encodeURIComponent(client.client_secret)).toString('base64');
    } else {
      log.debug("Leaving OidcRelyingParty.clientAuthentication(). " +
                "Unsupported method " + method + ".");
      return this.coded('STS-AUTHN-0209', { ok: false,
               why: 'the application "' + surface.clientId + '" declares ' +
                    method + ', which this surface does not implement. It ' +
                    'authenticates by private_key_jwt (the seeded value), ' +
                    'or by client_secret_basic or client_secret_post.' });
    }
    log.debug("Leaving OidcRelyingParty.clientAuthentication(). method=" +
              method);
    return { ok: true, headers: headers };
  }

  // RFC 7523 section 3's claims, signed with the surface's issued key.
  private clientAssertion(surface: Surface, key: any, host: string): string {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering OidcRelyingParty.clientAssertion().");
    const now = Math.floor(Date.now() / 1000);
    // certificate-header: none — the token endpoint verifies against the key
    // registered on the surface's own entry, never one the assertion carries.
    const signed = stsCrypto.signJws({
      iss: surface.clientId,
      sub: surface.clientId,
      aud: this.assertionAudience(host),
      jti: nodeCrypto.randomBytes(16).toString('base64url'),
      iat: now,
      exp: now + ASSERTION_LIFETIME_S
    }, key.privateKeyPem, { algorithm: SURFACE_SIGNING_ALG,
                            keyid: key.kid });
    log.debug("Leaving OidcRelyingParty.clientAssertion().");
    return signed;
  }

  // The issuer the token endpoint answers this back-channel request as —
  // what `issuerOf()` there computes from the request, which carries the
  // Host header the browser used and no forwarded headers. Computed through
  // the same two functions rather than fetched from discovery, for the
  // reason "no discovery document is fetched" gives in this file's header.
  private assertionAudience(host: string): string {
    const { log, config, baseUrlOf } = this.deps;
    log.debug("Entering OidcRelyingParty.assertionAudience().");
    const scheme = config.value('global.https') ? 'https' : 'http';
    const view = {
      protocol: scheme,
      headers: { host: host },
      get: function (name: string) {
        return String(name).toLowerCase() === 'host' ? host : undefined;
      }
    };
    const base = baseUrlOf(view as any);
    const issuer = this.deps.loadJwtAccessTokens().issuerFor(base);
    log.debug("Leaving OidcRelyingParty.assertionAudience(). " + issuer);
    return issuer;
  }

  // The key on the entry, if it is one this surface can sign with for a
  // while yet.
  private heldSurfaceKey(surface: Surface): any {
    const { log, applications } = this.deps;
    log.debug("Entering OidcRelyingParty.heldSurfaceKey().");
    const entry = applications.get(surface.clientId);
    const fields = (entry && entry.fields) || {};
    const first = function (value: any): string {
      return String((Array.isArray(value) ? value[0] : value) || '');
    };
    const pem = first(fields.oauthAssertionPrivateKey);
    const kid = first(fields.oauthAssertionKid);
    const expires = first(fields.oauthAssertionExpiresAt);
    const m = expires.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
    const expiresAt = m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5],
                                   +m[6]) : 0;
    if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(pem) || !kid ||
        expiresAt - Date.now() < KEY_RENEW_BEFORE_MS) {
      log.debug("Leaving OidcRelyingParty.heldSurfaceKey(). None usable.");
      return null;
    }
    log.debug("Leaving OidcRelyingParty.heldSurfaceKey(). kid=" + kid);
    return { ok: true, privateKeyPem: pem, kid: kid,
             certificatePem: first(fields.oauthAssertionCertificate),
             chainPem: first(fields.oauthAssertionCertificateChain) };
  }

  // The held key, if the token endpoint would still believe it: its
  // certificate's chain asked of `pki.verifySignerChain()`, the function
  // `client_auth.js` asks at every use. A chain that no longer holds — the
  // Root rebuilt under it — answers null, so the caller issues a new key
  // through the claim. With no Root at all there is nothing to ask and the
  // held key is used, since issuing would fail for the same reason.
  private async usableSurfaceKey(surface: Surface): Promise<any> {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.usableSurfaceKey().");
    const held = this.heldSurfaceKey(surface);
    if (!held) {
      log.debug("Leaving OidcRelyingParty.usableSurfaceKey(). None held.");
      return null;
    }
    const pki = this.deps.loadPki();
    if (!held.certificatePem || (pki.hasRoot && !pki.hasRoot())) {
      log.debug("Leaving OidcRelyingParty.usableSurfaceKey(). Nothing to " +
                "ask.");
      return held;
    }
    let verdict: any = null;
    try {
      verdict = await pki.verifySignerChain(undefined, {
        certificate: held.certificatePem, chain: held.chainPem,
        source: 'the key the ' + surface.label + ' holds'
      });
    } catch (e) {
      log.debug("Caught in OidcRelyingParty.usableSurfaceKey(): " +
                ((e && e.message) || e));
      // Not a verdict: the held key is used, and the token endpoint, which
      // asks the same question, answers for it.
      verdict = { ok: true };
    }
    if (!verdict || !verdict.ok) {
      log.info('oidc_rp: the ' + surface.label + '\'s key (kid ' +
               held.kid + ') no longer chains to this realm\'s certificate ' +
               'authority, so a new one is issued: ' +
               String((verdict && verdict.why) || ''));
      log.debug("Leaving OidcRelyingParty.usableSurfaceKey(). Chain refused.");
      return null;
    }
    log.debug("Leaving OidcRelyingParty.usableSurfaceKey(). Usable.");
    return held;
  }

  // The certificate and key this surface presents at the handshake: under
  // FAPI 1.0 Advanced with oauth2.fapiRequireMtls on, the certificate this
  // realm's CA issued with its signing key (#139); none otherwise.
  surfaceCertificate(surface: Surface): { cert: string; key: string } | null {
    const { log, applications, fapi } = this.deps;
    log.debug("Entering OidcRelyingParty.surfaceCertificate().");
    if (!fapi.requiresMtls()) {
      log.debug("Leaving OidcRelyingParty.surfaceCertificate(). Not asked.");
      return null;
    }
    const entry = applications.get(surface.clientId);
    const fields = (entry && entry.fields) || {};
    const first = function (value: any): string {
      return String((Array.isArray(value) ? value[0] : value) || '');
    };
    const cert = first(fields.oauthAssertionCertificate);
    const key = first(fields.oauthAssertionPrivateKey);
    if (!cert || !key) {
      log.debug("Leaving OidcRelyingParty.surfaceCertificate(). None held.");
      return null;
    }
    log.debug("Leaving OidcRelyingParty.surfaceCertificate(). Held.");
    return { cert: cert + first(fields.oauthAssertionCertificateChain),
             key: key };
  }

  // -------------------------------------------------------------------------
  // THE SIGN-IN UNDER FAPI 1.0 ADVANCED (#139, rcbj's decision: the surfaces
  // CONFORM rather than being exempted). The request the browser would have
  // carried becomes a signed request object (ES256, the surface's issued key;
  // `exp`, `nbf` and `aud` as Part 2 section 5.2.2 items 13, 15 and 17 ask),
  // asks for `response_mode=jwt` — JARM, which is what `response_type=code`
  // needs under the profile — and is PUSHED to /oauth2/par with the surface's
  // `private_key_jwt`, so the browser carries only a request_uri. Where PAR is
  // switched off the object goes by value instead. The callback opens the
  // JARM response before anything else (`openJarmResponse()`).
  // -------------------------------------------------------------------------
  private async advancedRedirect(req: any, res: any, surface: Surface,
                                 client: any, query: URLSearchParams,
                                 authorizationBase: string, state: string,
                                 poolPin: unknown): Promise<any> {
    const { log, config, stsCrypto, realms } = this.deps;
    log.debug("Entering OidcRelyingParty.advancedRedirect().");
    const key = await this.surfaceKey(surface);
    if (!key.ok) {
      log.debug("Leaving OidcRelyingParty.advancedRedirect(). No key.");
      return this.coded(this.deps.errorCodes.codeOf(key) || 'STS-AUTHN-0207',
                        { ok: false, why: key.why, reason: 'no-client' });
    }
    const host = this.hostHeaderFrom(authorizationBase);
    const now = Math.floor(Date.now() / 1000);
    const claims: any = {};
    query.forEach(function (value, name) {
      claims[name] = value;
    });
    if (this.deps.fapi.advanced()) {
      claims.response_mode = 'jwt';
    }
    claims.iss = surface.clientId;
    claims.aud = this.assertionAudience(host);
    claims.iat = now;
    claims.nbf = now;
    claims.exp = now + REQUEST_OBJECT_LIFETIME_S;
    claims.jti = nodeCrypto.randomBytes(16).toString('base64url');
    // certificate-header: none — a request object is verified against the
    // key registered on the surface's own entry.
    const requestObject = stsCrypto.signJws(claims, key.privateKeyPem,
      { algorithm: SURFACE_SIGNING_ALG, keyid: key.kid,
        header: { typ: 'oauth-authz-req+jwt' } });
    const to = new URLSearchParams({ client_id: surface.clientId });
    if (config.value('oauth2.pushedAuthorizationRequests')) {
      const form = new URLSearchParams({ request: requestObject });
      const auth = await this.clientAuthentication(surface, client, form,
                                                   host);
      if (!auth.ok) {
        log.debug("Leaving OidcRelyingParty.advancedRedirect(). No client " +
                  "authentication.");
        return auth;
      }
      const pushed = await this.backChannel({
        method: 'POST', path: realms.currentPrefix() + PAR_PATH, host: host,
        headers: auth.headers || {}, body: form.toString(),
        clientCertificate: this.surfaceCertificate(surface),
        poolPin: poolPin, from: req
      });
      if (!pushed.ok || pushed.status !== 201 || !pushed.json ||
          !pushed.json.request_uri) {
        const why = 'the pushed authorization request was refused: ' +
          (pushed.why || (pushed.status + ' ' +
            ((pushed.json && (pushed.json.error_description ||
                              pushed.json.error)) || pushed.text || '')));
        log.error(this.deps.errorCodes.tag('STS-AUTHN-0211') + 'oidc_rp: ' +
                  'the ' + surface.label + ' could not push its request. ' +
                  why);
        log.debug("Leaving OidcRelyingParty.advancedRedirect(). PAR failed.");
        return this.coded('STS-AUTHN-0211', { ok: false, why: why,
                                               reason: 'no-client' });
      }
      to.set('request_uri', String(pushed.json.request_uri));
    } else {
      to.set('request', requestObject);
    }
    res.status(303).set('Location', authorizationBase + AUTHORIZE_PATH + '?' +
                        to.toString()).end();
    log.debug("Leaving OidcRelyingParty.advancedRedirect(). Redirected.");
    return { ok: true, state: state };
  }

  // -------------------------------------------------------------------------
  // A JARM RESPONSE AT THE CALLBACK (#139): verified against this realm's
  // JWKS — fetched over the back channel, as the ID Token's is — held to
  // JARM section 2.4's checks (issuer, audience, expiry, signature, in that
  // order of meaning), and only then read for `code`, `state` or `error`.
  // -------------------------------------------------------------------------
  private async openJarmResponse(req: any, surface: Surface, opts: any,
                                 jwt: string): Promise<any> {
    const { log, realms, stsCrypto } = this.deps;
    log.debug("Entering OidcRelyingParty.openJarmResponse().");
    const publicBase = opts.authorizationBase || this.publicBaseOf(req);
    const host = this.hostHeaderFrom(publicBase);
    const refuse = function (why: string): any {
      log.debug("Leaving OidcRelyingParty.openJarmResponse(). " + why);
      return { ok: false, why: 'the JWT-secured authorization response ' +
               'did not verify: ' + why };
    };
    let header: any = null;
    let peeked: any = null;
    try {
      const parts = String(jwt).split('.');
      header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      peeked = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch (e) {
      log.debug("Caught in OidcRelyingParty.openJarmResponse(): " +
                ((e && e.message) || e));
      return refuse('it is not a signed JWT');
    }
    const alg = String((header && header.alg) || '');
    const spec = stsCrypto.JWS_ALGS[alg];
    if (!spec || spec.family === 'hmac') {
      return refuse('it is signed "' + alg + '", and a response from this ' +
                    'service is signed with one of its own published keys');
    }
    const jwksAnswer = await this.backChannel({
      method: 'GET', path: realms.currentPrefix() + JWKS_PATH, host: host,
      poolPin: opts.poolPin, from: req
    });
    const keys = (jwksAnswer.ok && jwksAnswer.json &&
                  Array.isArray(jwksAnswer.json.keys)) ? jwksAnswer.json.keys
                                                       : [];
    const jwk = keys.filter(function (one: any) {
      return one && one.kid === header.kid;
    })[0];
    if (!jwk) {
      return refuse('it names key "' + String(header.kid || '') + '", which ' +
                    'this realm\'s JWKS does not hold');
    }
    let verified: any = null;
    try {
      const key = spec.family === 'pq' ? jwk
        : nodeCrypto.createPublicKey({ key: jwk, format: 'jwk' })
          .export({ type: 'spki', format: 'pem' });
      verified = stsCrypto.verifyCompactJws(jwt, key, { algorithms: [alg] });
    } catch (e) {
      log.debug("Caught in OidcRelyingParty.openJarmResponse(): " +
                ((e && e.message) || e));
      return refuse('its signature: ' + ((e && e.message) || e));
    }
    const claims = (verified && verified.claims) || peeked || {};
    const issuer = this.assertionAudience(host);
    if (String(claims.iss || '') !== issuer) {
      return refuse('its iss is "' + String(claims.iss || '') + '", and ' +
                    'this surface expects "' + issuer + '"');
    }
    const audiences = Array.isArray(claims.aud) ? claims.aud.map(String)
                                                : [String(claims.aud || '')];
    if (audiences.indexOf(surface.clientId) < 0) {
      return refuse('its aud does not name ' + surface.clientId);
    }
    if (!(Number(claims.exp) > Math.floor(Date.now() / 1000))) {
      return refuse('it has expired');
    }
    log.debug("Leaving OidcRelyingParty.openJarmResponse(). Verified.");
    return { ok: true, params: claims };
  }

  // The surface's signing key, issued if the entry holds none it can use.
  // See "HOW A SURFACE AUTHENTICATES" above the paths.
  private async surfaceKey(surface: Surface): Promise<any> {
    const { log, realms, clusterClaims, errorCodes } = this.deps;
    log.debug("Entering OidcRelyingParty.surfaceKey(). " + surface.clientId);
    const held = await this.usableSurfaceKey(surface);
    if (held) {
      log.debug("Leaving OidcRelyingParty.surfaceKey(). Held.");
      return held;
    }
    const realmId = realms.currentId();
    const waitMs = this.backChannelTimeoutMs() * 2 + 1000;
    const answer = await clusterClaims.claim({
      scope: 'oidc_rp.surface-key', realm: realmId,
      value: surface.clientId, ttlMs: waitMs
    });
    if (answer.ok) {
      const issued = await this.issueSurfaceKey(surface, realmId);
      log.debug("Leaving OidcRelyingParty.surfaceKey(). Issued here.");
      return issued;
    }
    if (answer.reason === 'used') {
      const until = Date.now() + waitMs;
      while (Date.now() < until) {
        await new Promise(function (resolve) {
          setTimeout(resolve, 200);
        });
        const arrived = await this.usableSurfaceKey(surface);
        if (arrived) {
          log.debug("Leaving OidcRelyingParty.surfaceKey(). Issued by " +
                    "another process.");
          return arrived;
        }
      }
    }
    log.error(errorCodes.tag('STS-AUTHN-0208') + 'oidc_rp: the ' +
              surface.label + '\'s signing key was being issued elsewhere ' +
              'and did not arrive (' + String(answer.reason || 'used') +
              ').');
    log.debug("Leaving OidcRelyingParty.surfaceKey(). Nothing arrived.");
    return this.coded('STS-AUTHN-0208', { ok: false,
             why: 'the key the ' + surface.label + ' signs its client ' +
                  'assertion with is being issued by another process, and ' +
                  'it did not arrive in time. Try again.' });
  }

  private async issueSurfaceKey(surface: Surface, realmId: string):
      Promise<any> {
    const { log, applications, errorCodes, audit } = this.deps;
    log.debug("Entering OidcRelyingParty.issueSurfaceKey(). " +
              surface.clientId);
    const pki = this.deps.loadPki();
    let issued: any = null;
    try {
      if (!pki.hasRoot || pki.hasRoot()) {
        await pki.ensureScope(realmId);
      }
      issued = await pki.issueSigningKeyPair(realmId, {
        identifier: surface.clientId,
        purpose: 'jwt',
        commonName: surface.clientId,
        keyAlg: SURFACE_KEY_ALG,
        days: SURFACE_KEY_DAYS
      });
    } catch (e) {
      log.debug("Caught in OidcRelyingParty.issueSurfaceKey(): " +
                ((e && e.message) || e));
      issued = { ok: false, errors: [String((e && e.message) || e)] };
    }
    const stored = issued && issued.ok
      ? applications.storeIssuedJwtKeyPair(surface.clientId, issued.issued)
      : null;
    if (!stored || !stored.ok) {
      const why = issued && issued.ok
        ? 'the key was issued and ' + stored.failed + ' could not be ' +
          'written onto the entry'
        : ((issued && issued.errors) || []).join(' ');
      log.error(errorCodes.tag('STS-AUTHN-0207') + 'oidc_rp: the ' +
                surface.label + ' has no key to sign its client assertion ' +
                'with: ' + why);
      log.debug("Leaving OidcRelyingParty.issueSurfaceKey(). Failed.");
      return this.coded('STS-AUTHN-0207', { ok: false,
               why: 'the ' + surface.label + ' authenticates at the token ' +
                    'endpoint with a key this realm\'s certificate ' +
                    'authority issues it, and none could be issued: ' + why });
    }
    audit.audit({
      action: 'application.key-issued', actor: '', protocol: 'internal',
      channel: 'internal', target: surface.clientId,
      summary: 'The ' + surface.label + ' was issued the key it signs its ' +
               'private_key_jwt client assertions with (kid ' +
               issued.issued.kid + ')',
      detail: { identifier: surface.clientId, kid: issued.issued.kid,
                purpose: 'jwt', seeded: true }
    });
    log.debug("Leaving OidcRelyingParty.issueSurfaceKey(). kid=" +
              issued.issued.kid);
    return { ok: true, privateKeyPem: issued.issued.privateKeyPem,
             kid: issued.issued.kid };
  }

  // -------------------------------------------------------------------------
  // WHAT THIS RELYING PARTY KEEPS OF A TOKEN RESPONSE (2026-09-12).
  //
  // The three tokens, the instants the access token and the ID Token run
  // out, and — from the ID Token, which is the only one this client can read
  // — the issuer, subject and authentication time a renewed ID Token must
  // repeat. `flowRealm` and `host` are how a renewal reaches the SAME
  // authorization server later: the realm whose token endpoint issued the
  // refresh token (a refresh token is encrypted to that realm's keys and
  // opens nowhere else) and the Host header the issuer was built from, so a
  // renewal made while the browser is reading another realm, or reached this
  // service under another name, still gets an ID Token from the issuer it
  // started with.
  //
  // A token response WITHOUT a refresh token — the entry's grant types no
  // longer include `refresh_token` — keeps the rest, and a session holding no
  // refresh token is not renewed: it ends with its sign-on session, exactly
  // as every console session did before renewal existed.
  // -------------------------------------------------------------------------
  tokensFrom(json: any, claims: any, flowRealmId?: string, host?: string,
             previous?: any): any {
    const { log, realms } = this.deps;
    log.debug("Entering OidcRelyingParty.tokensFrom().");
    const now = Date.now();
    const kept = previous || {};
    const expiresIn = Number(json.expires_in);
    const tokens = {
      accessToken: String(json.access_token || ''),
      tokenType: String(json.token_type || 'Bearer'),
      scope: String(json.scope || kept.scope || ''),
      accessExpiresAt: isFinite(expiresIn) && expiresIn > 0
        ? now + expiresIn * 1000
        : (Number(claims && claims.exp) || 0) * 1000,
      // A renewal that came back with no NEW refresh token keeps using the
      // one it has: RFC 6749 section 6 makes a new one optional, and outside
      // RFC 9700 mode the old one is still good.
      refreshToken: String(json.refresh_token || kept.refreshToken || ''),
      idToken: String(json.id_token || kept.idToken || ''),
      // A renewal answered with NO ID Token (section 12.2 makes it optional)
      // leaves the access token's expiry as the only clock: keeping the old
      // ID Token's would make a renewal due on every request for ever.
      idTokenExpiresAt: claims && claims.exp ? Number(claims.exp) * 1000 : 0,
      issuer: String((claims && claims.iss) || kept.issuer || ''),
      sub: String((claims && claims.sub) || kept.sub || ''),
      authTime: Number(kept.authTime || (claims && claims.auth_time)) || 0,
      flowRealm: String(flowRealmId || kept.flowRealm || realms.DEFAULT_ID),
      host: String(host || kept.host || ''),
      // #34: the DPoP key this session's tokens are bound to. Carried forward
      // on a renewal — `previous` is where it comes from — because the
      // refresh token the renewal presents is bound to THIS key and a new one
      // would be refused. It never leaves this process and dies with the
      // session.
      dpop: (previous && previous.dpop) || null
    };
    log.debug("Leaving OidcRelyingParty.tokensFrom().");
    return tokens;
  }

  // -------------------------------------------------------------------------
  // A RENEWED ID TOKEN MUST DESCRIBE THE SAME SIGN-IN (OpenID Connect Core
  // section 12.2): the same `iss`, the same `sub`, and where both carry one,
  // the same `auth_time`. The signature, the audience and the expiry are
  // `verifyIdToken()`'s; these three are what make it THIS session's token
  // rather than a genuine token about somebody else. Pure, and exported for
  // `tests/oidc_rp_renewal.js`, because the case worth asserting — an
  // authorization server answering a refresh with a different person — is
  // one this service will not produce on demand.
  // -------------------------------------------------------------------------
  checkRenewedClaims(previous: any, claims: any):
      { ok: boolean; why?: string } {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.checkRenewedClaims().");
    const was = previous || {};
    const now = claims || {};
    if (was.issuer && String(now.iss || '') !== was.issuer) {
      log.debug("Leaving OidcRelyingParty.checkRenewedClaims(). The issuer " +
                "moved.");
      return { ok: false, why: 'the renewed ID Token was issued by "' +
               String(now.iss || '') + '", and the sign-in\'s by "' +
               was.issuer + '"' };
    }
    if (was.sub && String(now.sub || '') !== was.sub) {
      log.debug("Leaving OidcRelyingParty.checkRenewedClaims(). The subject " +
                "moved.");
      return { ok: false, why: 'the renewed ID Token names subject "' +
               String(now.sub || '') + '", and the sign-in named "' +
               was.sub + '"' };
    }
    if (was.authTime && now.auth_time !== undefined &&
        Number(now.auth_time) !== Number(was.authTime)) {
      log.debug("Leaving OidcRelyingParty.checkRenewedClaims(). The " +
                "authentication time moved.");
      return { ok: false, why: 'the renewed ID Token says the person ' +
               'authenticated ' +
               'at ' + Number(now.auth_time) + ', and the sign-in said ' +
               Number(was.authTime) + ' — a refresh is not an ' +
               'authentication' };
    }
    log.debug("Leaving OidcRelyingParty.checkRenewedClaims(). The same " +
              "sign-in.");
    return { ok: true };
  }

  // -------------------------------------------------------------------------
  // 1. BEGIN. Where an unauthenticated request to a hosted surface goes.
  //
  // It answers by SENDING a redirect, and returns whether it did — a caller
  // that gets `false` has already had a refusal drawn for it and must not
  // write to the response again.
  // -------------------------------------------------------------------------
  beginSignIn(req: any, res: any, surfaceId: string,
              options?: SignInOptions): any {
    const { log, errorCodes, flows } = this.deps;
    const self = this;
    log.debug('Entering OidcRelyingParty.beginSignIn(). surface=' +
              surfaceId);
    const surface = this.surfaceOf(surfaceId);
    const opts: SignInOptions = options || {};
    log.debug("Leaving OidcRelyingParty.beginSignIn().");
    return this.inFlowRealm(surface, function () {
      const found = self.clientOf(surface);
      if (!found.ok) {
        log.error(errorCodes.tag(errorCodes.codeOf(found) ||
                                 'STS-AUTHN-0112') +
                  'oidc_rp: the ' + surface.label + ' cannot start a ' +
                  'sign-in. ' + found.why);
        log.debug('Leaving OidcRelyingParty.beginSignIn(). There is no ' +
                  'client.');
        return self.coded(errorCodes.codeOf(found) || 'STS-AUTHN-0112',
                          { ok: false, why: found.why, reason: 'no-client' },
                          res);
      }
      const publicBase = opts.callbackBase || self.publicBaseOf(req);
      const redirectUri = publicBase + surface.callbackPath;
      const registered = self.ensureRedirectUri(surface, found.client,
                                                redirectUri);
      if (!registered.ok) {
        log.debug('Leaving OidcRelyingParty.beginSignIn(). The address is ' +
                  'not registered.');
        return self.coded(errorCodes.codeOf(registered) || 'STS-AUTHN-0114',
                          { ok: false, why: registered.why,
                            reason: 'unregistered-address' }, res);
      }

      const store = flows;
      const cap = self.maxFlows();
      if (store.size >= cap) {
        // The oldest goes, exactly as `federation_sp.ts` does it: the cap
        // bounds memory and the eviction has to fall on the flow least likely
        // to still be wanted.
        let oldestKey = null;
        let oldestAt = Infinity;
        store.forEach(function (held, key) {
          if (held.startedAt < oldestAt) {
            oldestAt = held.startedAt;
            oldestKey = key;
          }
        });
        if (oldestKey) {
          log.warn('oidc_rp: ' + cap + ' sign-ins are in flight in this ' +
                   'realm, so the oldest is being dropped. Somebody who was ' +
                   'part way through will be sent round again.');
          store.delete(oldestKey);
        }
      }

      const pkce = self.pkcePair();
      const state = nodeCrypto.randomBytes(24).toString('base64url');
      const nonce = nodeCrypto.randomBytes(24).toString('base64url');
      store.set(state, {
        surface: surface.id,
        nonce: nonce,
        verifier: pkce.verifier,
        redirectUri: redirectUri,
        issuer: null,
        returnTo: self.inThisRealm(self.safeReturnTo(opts.returnTo,
                                                     opts.fallback || '/')),
        startedAt: Date.now()
      });

      const query = new URLSearchParams({
        response_type: 'code',
        client_id: surface.clientId,
        redirect_uri: redirectUri,
        scope: surface.scopes.join(' '),
        state: state,
        nonce: nonce,
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256'
      });
      // `prompt=login` where the caller asked for a fresh authentication.
      // Nothing does today; it is threaded because the alternative is a
      // caller reaching into the URL, and a sign-in that must be re-done is a
      // real thing to want.
      if (opts.prompt) {
        query.set('prompt', String(opts.prompt));
      }
      // FAPI 1.0 ADVANCED (#139): signed, pushed and answered with JARM —
      // `advancedRedirect()`. A promise, which the three callers settle.
      // FAPI 2.0 (#140) takes the same path without JARM: its section
      // 5.3.2.2 requires the push and `code`, and a signed object inside the
      // push is allowed.
      if (self.deps.fapi.advanced() || self.deps.fapi.fapi2()) {
        log.debug('Leaving OidcRelyingParty.beginSignIn(). FAPI Advanced.');
        return self.advancedRedirect(req, res, surface, found.client, query,
                                     opts.authorizationBase || publicBase,
                                     state, opts.poolPin);
      }
      const to = (opts.authorizationBase || publicBase) + AUTHORIZE_PATH +
                 '?' + query.toString();
      log.info('oidc_rp: sending a browser to the authorization endpoint ' +
               'for the ' + surface.label + ' (client_id ' +
               surface.clientId + ', state ' + state + '). It comes back ' +
               'to ' + redirectUri + '.');
      // 303 rather than 302: this is reached from a GET today and from a POST
      // the moment somebody adds a form that needs a session, and a 302
      // leaves the method up to the browser.
      res.status(303).set('Location', to).end();
      log.debug('Leaving OidcRelyingParty.beginSignIn(). Redirected.');
      return { ok: true, state: state };
    });
  }

  // -------------------------------------------------------------------------
  // 2. THE CALLBACK. Where the browser comes back with a code.
  //
  // Every refusal here is REPORTED and never redirected, which is
  // `federation_sp.ts`'s decision 6 and its reason applies unchanged: the
  // person's sign-in has already succeeded at the authorization endpoint, so
  // the only interesting question is what THIS side disliked about the
  // answer — and that is unanswerable from a redirect that has thrown the
  // detail away.
  //
  // It returns `{ ok, session, returnTo, why }`. The caller draws its own
  // refusal, because the console's shell and the portal's are different
  // applications and a page drawn here would belong to neither.
  // -------------------------------------------------------------------------
  async handleCallback(req: any, res: any, surfaceId: string,
                       options?: SignInOptions): Promise<any> {
    const { log, realms, errorCodes, applications, config, audit, authn,
            flows } = this.deps;
    const self = this;
    log.debug('Entering OidcRelyingParty.handleCallback(). surface=' +
              surfaceId);
    const surface = this.surfaceOf(surfaceId);
    const opts: SignInOptions = options || {};
    let query = req.query || {};

    // A JARM RESPONSE (#139) is opened first: what it carries — `code` and
    // `state`, or `error` — is believed only once it verified, and then read
    // exactly as the plain parameters are below.
    if (query.response !== undefined && query.response !== '') {
      const opened = await this.inFlowRealm(surface, function () {
        return self.openJarmResponse(req, surface, opts,
                                     String(query.response));
      });
      if (!opened.ok) {
        log.warn(errorCodes.tag('STS-AUTHN-0210') + 'oidc_rp: the ' +
                 surface.label + ' refused its authorization response. ' +
                 opened.why);
        log.debug('Leaving OidcRelyingParty.handleCallback(). The JARM ' +
                  'response did not verify.');
        return this.coded('STS-AUTHN-0210', { ok: false, why: opened.why },
                          res);
      }
      query = opened.params;
    }

    // THE AUTHORIZATION SERVER'S OWN REFUSAL, first: `error` beats everything
    // below it, and reporting "no such state" for a request that carries a
    // perfectly good `error=access_denied` would send somebody to debug the
    // wrong half.
    if (query.error) {
      const why = 'the authorization endpoint refused the request: ' +
                  String(query.error) +
                  (query.error_description ?
                   ' — ' + String(query.error_description) : '');
      log.info('oidc_rp: the ' + surface.label + ' sign-in was refused. ' +
               why);
      log.debug('Leaving OidcRelyingParty.handleCallback(). The AS ' +
                'refused.');
      return this.coded('STS-AUTHN-0121',
                        { ok: false, why: why, refusedByAs: true }, res);
    }

    const state = String(query.state || '');
    const code = String(query.code || '');
    if (!state || !code) {
      log.debug('Leaving OidcRelyingParty.handleCallback(). No code or no ' +
                'state.');
      return this.coded('STS-AUTHN-0122', { ok: false,
               why: 'the callback carried no ' + (state ? 'code' : 'state') +
                    '. It is reached by the authorization endpoint sending ' +
                    'a browser here and not by being opened directly.' },
                        res);
    }

    log.debug("Leaving OidcRelyingParty.handleCallback().");
    return this.inFlowRealm(surface, async function () {
      const flow = flows.get(state);
      // SPENT ON SIGHT, whatever happens next. A state is single use: the
      // second presentation of one is either a browser reloading a page it
      // should not reload or somebody replaying a code, and both must fail.
      // Deleting before the work rather than after it is what makes that
      // true even where the work throws.
      flows.delete(state);
      if (!flow) {
        log.debug('Leaving OidcRelyingParty.handleCallback(). No such ' +
                  'flow.');
        return self.coded('STS-AUTHN-0123', { ok: false,
                 why: 'this sign-in is not one this service started, or it ' +
                      'has already been completed, or it took longer than ' +
                      Math.round(self.flowTtlMs() / 1000) + ' seconds. ' +
                      'Start again.' },
                          res);
      }
      if (flow.surface !== surface.id) {
        // The state belongs to the OTHER surface. Refused rather than
        // honoured, because a code redeemed at the wrong callback would put
        // a portal session behind the console's cookie or the other way
        // round.
        log.warn('oidc_rp: a ' + flow.surface + ' state was presented at ' +
                 'the ' + surface.id + ' callback. Refused.');
        return self.coded('STS-AUTHN-0124',
                          { ok: false, why: 'this sign-in belongs to a ' +
                                            'different surface' }, res);
      }
      const ttlMs = self.flowTtlMs();
      if (Date.now() - flow.startedAt > ttlMs) {
        log.debug('Leaving OidcRelyingParty.handleCallback(). The flow ' +
                  'expired.');
        return self.coded('STS-AUTHN-0125', { ok: false,
                 why: 'this sign-in took longer than ' +
                      Math.round(ttlMs / 1000) +
                      ' seconds (authn.pendingTtlS) and has expired. ' +
                      'Start again.' }, res);
      }

      const found = self.clientOf(surface);
      if (!found.ok) {
        return self.coded(errorCodes.codeOf(found) || 'STS-AUTHN-0112',
                          { ok: false, why: found.why }, res);
      }
      const client = found.client;
      // The authorization server's base, which is the request's own for the
      // console and the portal and the main port's for the debugger — see
      // the surface table.
      const publicBase = opts.authorizationBase || self.publicBaseOf(req);
      const host = self.hostHeaderFrom(publicBase);

      // ---------------------------------------------------------------------
      // THE TOKEN REQUEST. Client authentication is `client_secret_basic`,
      // which is what the entry's own `token_endpoint_auth_method` says —
      // read off the registration rather than assumed, so an operator who
      // changes it there gets a client that says so rather than one that
      // silently keeps using Basic.
      // ---------------------------------------------------------------------
      const form = new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      });
      const auth = await self.clientAuthentication(surface, client, form,
                                                   host);
      if (!auth.ok) {
        return self.coded(errorCodes.codeOf(auth) || 'STS-AUTHN-0207',
                          { ok: false, why: auth.why }, res);
      }
      const headers = auth.headers || {};
      // #34: the key this sign-in proves possession of, from here to the
      // last renewal of the session it becomes. Made even when no setting
      // requires one — a proof is accepted in every mode, the tokens come
      // back bound, and a relying party that only carried a key when it had
      // to would be one whose behaviour changed under an operator turning a
      // setting on, which is the thing that would break at the worst moment.
      const dpop = self.dpopKey();
      const tokenAnswer = await self.tokenRequestWithProof(dpop, {
        method: 'POST',
        path: realms.currentPrefix() + TOKEN_PATH,
        host: host,
        headers: headers,
        body: form.toString(),
        clientCertificate: self.surfaceCertificate(surface),
        poolPin: opts.poolPin,
        // Which protocol worker redeems it when there are two pools; see
        // backChannel().
        from: req
      });
      if (!tokenAnswer.ok) {
        log.error(errorCodes.tag(errorCodes.codeOf(tokenAnswer) ||
                                 'STS-AUTHN-0120') +
                  'oidc_rp: the ' + surface.label +
                  ' could not redeem its code. ' +
                  tokenAnswer.why);
        return self.coded(errorCodes.codeOf(tokenAnswer) || 'STS-AUTHN-0120',
                          { ok: false, why: tokenAnswer.why }, res);
      }
      if (tokenAnswer.status !== 200 || !tokenAnswer.json) {
        const detail = (tokenAnswer.json && tokenAnswer.json.error)
          ? tokenAnswer.json.error +
            (tokenAnswer.json.error_description
              ? ' — ' + tokenAnswer.json.error_description : '')
          : tokenAnswer.text;
        return self.coded('STS-AUTHN-0126', { ok: false,
                 why: 'the token endpoint answered ' + tokenAnswer.status +
                      ': ' + detail }, res);
      }
      const idToken = String(tokenAnswer.json.id_token || '');
      if (!idToken) {
        // The one refusal here that is about OIDC rather than OAuth: an
        // access token alone says a client was AUTHORIZED and not that
        // anybody signed in, which is the distinction `federation_sp.ts`
        // warns about on every OAuth-shaped federated sign-in. Signing
        // somebody in on it would be signing in as nobody.
        return self.coded('STS-AUTHN-0127', { ok: false,
                 why: 'the token response carried no id_token, so nothing ' +
                      'in it says who signed in. An access token means a ' +
                      'client was authorized, not that a person ' +
                      'authenticated.' }, res);
      }

      // ---------------------------------------------------------------------
      // THE KEYS, FETCHED. See verifyIdToken()'s header for why they are
      // fetched rather than read out of this process.
      // ---------------------------------------------------------------------
      const jwksAnswer = await self.backChannel({
        method: 'GET',
        path: realms.currentPrefix() + JWKS_PATH,
        host: host,
        poolPin: opts.poolPin,
        from: req
      });
      if (!jwksAnswer.ok || jwksAnswer.status !== 200 || !jwksAnswer.json) {
        return self.coded('STS-AUTHN-0128', { ok: false,
                 why: 'this service\'s own JWKS at ' + JWKS_PATH +
                      ' could not be read: ' +
                      (jwksAnswer.why ||
                       ('it answered ' + jwksAnswer.status)) },
                          res);
      }
      const keys = Array.isArray(jwksAnswer.json.keys) ?
        jwksAnswer.json.keys : [];

      const verified = self.verifyIdToken(idToken, keys, {
        // The issuer the AUTHORIZATION endpoint would have advertised, which
        // is why the loopback request carries the browser's Host header —
        // see the header of this file.
        issuer: undefined,
        audience: surface.clientId,
        nonce: flow.nonce
      });
      if (!verified.ok) {
        const idTokenCode = errorCodes.codeOf(verified) || 'STS-AUTHN-0133';
        log.error(errorCodes.tag(idTokenCode) +
                  'oidc_rp: the ' + surface.label + ' refused the ID Token ' +
                  'it was issued. ' + verified.why);
        audit.audit({
          action: 'session.refused',
          errorCode: idTokenCode,
          actor: '',
          protocol: 'OAuth 2.0 / OIDC',
          channel: 'http',
          target: surface.clientId,
          outcome: 'refused',
          summary: 'the ' + surface.label + ' refused an ID Token from ' +
                   'this service: ' + verified.why,
          detail: { surface: surface.id, client_id: surface.clientId,
                    why: verified.why }
        });
        return self.coded(idTokenCode, { ok: false,
                 why: 'the ID Token this service issued did not verify: ' +
                      verified.why }, res);
      }

      const claims = verified.claims || {};
      // THE PERSON THE `sub` NAMES, looked up in the directory (#118). A
      // code-flow ID Token carries no profile claims any more — OIDC Core
      // section 5.4 puts them in UserInfo — so `preferred_username` is no
      // longer there to read, and it was never the right thing to identify a
      // session by anyway: `sub` is what an ID Token vouches for. These
      // surfaces are public clients of this very service, so `sub` is the
      // public `urn:uuid:<entryUUID>` and the directory names its person.
      const username = String(helpers.nameForSubject(claims.sub) ||
                              claims.preferred_username || claims.sub || '');
      if (!username) {
        return self.coded('STS-AUTHN-0135', { ok: false,
                 why: 'the ID Token names nobody: it carries neither ' +
                      'preferred_username nor sub' }, res);
      }

      // ---------------------------------------------------------------------
      // AND THE SESSION, WHICH IS NOT ALWAYS IN THE REALM THE FLOW JUST RAN
      // IN.
      //
      // The flow ran in the AMBIENT realm — that is what made the sign-on
      // session it was answered out of the same one the other surface
      // reached — and the console's own session lives in the DEFAULT realm's
      // partition wherever it was reached, because that is what lets one
      // console session read every realm. So the two are stated separately
      // rather than both being "here": `parentRealm` says where the sign-on
      // session named by `sid` lives, and `inSessionRealm()` says where this
      // session is created.
      //
      // `sid` is what joins them — see startRelyingPartySession(), where the
      // cascade that ends a derived session with its sign-on session is
      // argued and where the parent is now looked up in the realm named here
      // rather than assumed to be in its own.
      // ---------------------------------------------------------------------
      const parentRealm = realms.currentId();
      // THE TOKENS, KEPT (2026-09-12), and the window they may be renewed in:
      // the refresh token's lifetime from now, which is what the
      // authorization server states for THIS client — the service-wide
      // `oauth2.refreshTokenTtlS` or the entry's own `oauthRefreshTokenTtlS`.
      // It is read off this client's own registry entry, the same entry its
      // secret came from two steps up, rather than decoded out of the refresh
      // token, which is encrypted to the authorization server and is nothing
      // this client can or should read. See renewIfDue().
      // `{ dpop: dpop }` as the PREVIOUS record, which is how the key made
      // for this redemption becomes the key the session keeps (#34).
      const tokens = self.tokensFrom(tokenAnswer.json, claims, parentRealm,
                                     host, { dpop: dpop });
      const refreshTtlS = Number(applications.settingFor(
        surface.clientId, 'oauth2.refreshTokenTtlS', config));
      const renewableUntil = tokens.refreshToken && isFinite(refreshTtlS) &&
                             refreshTtlS > 0
        ? Date.now() + refreshTtlS * 1000 : 0;
      const session = self.inSessionRealm(surface, function () {
        return authn.startRelyingPartySession({
          res: res,
          username: username,
          claims: claims,
          // THE VERIFIED ID TOKEN'S `amr` IS RECORDED ON THE SESSION, as
          // `amr`, and beside it the kind of authority that vouched for the
          // sign-on session named by `sid` (`signInAuthority`). The console
          // reads both before the bootstrap administrator has claimed it, in
          // product mode (#103): only a password this service verified may
          // claim it, and `amr` alone cannot say who verified what.
          amr: Array.isArray(claims.amr) ? claims.amr.map(String) : [],
          // THE SURFACE, as the protocol this session came through — which
          // is what `/admin/sessions` draws in its Protocol column and what
          // the old arrangement passed to `beginAuthentication()`. The
          // SIGN-ON session beside it says `OAuth 2.0 / OIDC`, correctly: it
          // was created by an authorization request. Two rows, two true
          // answers.
          via: surface.label,
          parent: String(claims.sid || ''),
          surface: surface.id,
          label: surface.label,
          clientId: surface.clientId,
          cookie: surface.cookie,
          // WHERE THE PARENT LIVES. Absent means "the same realm as this
          // session", which is what every session made before 2026-09-11
          // meant and what the portal still means; the console says `acme`
          // while being created in the default realm's partition.
          parentRealm: parentRealm,
          tokens: tokens,
          renewableUntil: renewableUntil
        });
      });
      log.info('oidc_rp: ' + username + ' completed the authorization code ' +
               'flow for ' +
               'the ' + surface.label + ' and holds session ' + session.id +
               '. The ID Token verified against ' + JWKS_PATH + '.');
      log.debug('Leaving OidcRelyingParty.handleCallback(). Signed in.');
      return { ok: true, session: session, returnTo: flow.returnTo,
               username: username };
    });
  }

  // -------------------------------------------------------------------------
  // 3. THE READER. What a hosted surface asks on every request.
  // -------------------------------------------------------------------------
  sessionFor(req: any, surfaceId: string): any {
    const { log, authn } = this.deps;
    log.debug("Entering OidcRelyingParty.sessionFor().");
    const surface = this.surfaceOf(surfaceId);
    log.debug("Leaving OidcRelyingParty.sessionFor().");
    return authn.relyingPartySessionOf(req, surface.cookie,
                                       this.sessionRealmIdOf(surface));
  }

  // -------------------------------------------------------------------------
  // 4. RENEWAL — THE SAME SESSION, NEW TOKENS (2026-09-12).
  //
  // **WHAT WAS WRONG IS WHAT A PERSON SAW.** A console session expired an
  // hour after the sign-in, together with its ID Token and access token, and
  // the next click sent the operator back through the sign-in screen — off
  // the page they were on, and with any form they had open refused for want
  // of a session. A real relying party does not do that: it holds a refresh
  // token, and when its tokens run out it asks the token endpoint for new
  // ones and carries on. This one was issued a refresh token on every sign-in
  // (the entry's grant types have always included `refresh_token`) and threw
  // it away.
  //
  // So now:
  //
  //   * the tokens are KEPT on the relying-party session (`tokensFrom()`,
  //     `authn.startRelyingPartySession()`);
  //   * every request to the surface passes through `renewal()` BEFORE the
  //     surface's own gate, and `renewIfDue()` asks one question — do this
  //     session's tokens run out within `oidcRp.renewBeforeExpiryS`? — and
  //     where they do, redeems the refresh token over the same loopback back
  //     channel the sign-in used, verifies the new ID Token, and writes the
  //     new tokens onto THE SAME SESSION (`authn.renewRelyingPartySession()`);
  //   * and the request goes on to the page it asked for. Same session id,
  //     same cookie, same CSRF token on every form already open: nothing
  //     about the browser changes, which is what "stay signed in on the page
  //     I was on" means.
  //
  // **IT IS NOT A SIGN-IN AND CREATES NO SESSION.** No authentication is
  // recorded, no `session.start` row is written, no CAEP event is sent, and
  // the sign-on session the relying-party session descends from is not
  // touched: `session.renew` is the one audit row, and it says the session is
  // unchanged.
  //
  // **THE WINDOW IS BOUNDED.** A session may renew until the refresh token it
  // was issued at sign-in would have expired (`renewableUntil`) and never
  // past it — renewing does not extend the window, so a console somebody
  // keeps using still signs them out after `oauth2.refreshTokenTtlS`
  // (twenty-four hours by default, and the client's own
  // `oauthRefreshTokenTtlS` where one is set).
  //
  // **THE SIGN-ON SESSION'S LIFETIME NO LONGER ENDS IT; A SIGN-OUT STILL
  // DOES.** `dropSession()`'s cascade ends every relying-party session
  // derived from a sign-on session that is ended — by any sign-out door, by a
  // Revoke on `/admin/sessions`, by a global logout — exactly as before. What
  // changed is the case where the sign-on session simply RAN OUT: a session
  // that can renew carries on, and `authn.relyingPartySessionOf()` tells the
  // two cases apart by the clock (see there).
  //
  // **A RENEWAL THAT FAILS ENDS THE SESSION**, and the gate then does what it
  // always did for a request with no session: a GET is sent through the
  // authorization code flow and comes back to the page it asked for. A
  // refused refresh token, a renewed ID Token about a different sign-in, a
  // client entry that has gone — each is an audit row coded `session.renew`
  // refused and a `session.end` beside it. What it never does is let a
  // request through on tokens that have run out and could not be renewed.
  //
  // **ONE RENEWAL AT A TIME PER SESSION.** A page's several requests arriving
  // together would otherwise each redeem the refresh token — and in RFC 9700
  // mode a refresh token is rotated on use, so the second redemption is a
  // REPLAY, and a replay revokes the whole family. `renewing` holds the
  // promise for the length of one round trip and every concurrent caller
  // waits on it.
  //
  // **AND ONE ACROSS NODES (2026-09-14, #46).** `renewing` is this process's,
  // so a page's requests spread over two nodes each found no renewal in
  // flight, both redeemed the refresh token, and in RFC 9700 mode the second
  // redemption revoked the family and ended the console session — which is
  // exactly what the paragraph above exists to prevent, one load balancer
  // later. So the renewal is also CLAIMED (`renewOnce()`): scope
  // `oidc_rp.renewal`, keyed by the session and the ACCESS TOKEN being
  // replaced — not the refresh token, which a renewal outside RFC 9700 mode
  // may hand back unchanged, and which would then make the next renewal an
  // hour later look like this one. The node that wins renews; a node that
  // loses does not touch the token endpoint at all, catches up with the
  // change log (`cluster_barrier.syncShared()`) and re-reads the session
  // until the winner's tokens are on it, and the request goes on with them. A
  // winner that takes longer than the wait leaves the request to go on with
  // the tokens it has (`STS-AUTHN-0189`) rather than redeem the refresh token
  // a second time, and a store that cannot be asked does the same
  // (`STS-AUTHN-0190`): in both cases the next request asks again.
  //
  // (`RENEW_BEFORE_EXPIRY_S` and `renewing` are declared at module scope,
  // above the class.)
  // -------------------------------------------------------------------------

  // `oidcRp.renewBeforeExpiryS`, where ZERO is legal and means "only once
  // they have run out" — so not `Number(x || n)`.
  private renewBeforeExpiryMs(): number {
    const { log, config } = this.deps;
    log.debug("Entering OidcRelyingParty.renewBeforeExpiryMs().");
    const n = Number(config.value('oidcRp.renewBeforeExpiryS'));
    log.debug("Leaving OidcRelyingParty.renewBeforeExpiryMs().");
    return (isFinite(n) && n >= 0 ? Math.floor(n) :
            RENEW_BEFORE_EXPIRY_S) * 1000;
  }

  // Ending a session whose tokens could not be renewed: the refused
  // `session.renew` row, the log line, the session ended through
  // `dropSession()` like every other, and the surface's cookie cleared. In
  // the SESSION's realm, so both rows land in the audit log the
  // `session.start` for it is in.
  private renewalFailed(surface: Surface, session: any,
                        sessionRealmId: string, res: any, code: string,
                        why: string): RenewalAnswer {
    const { log, errorCodes, realms, audit, authn } = this.deps;
    log.debug("Entering OidcRelyingParty.renewalFailed(). code=" + code);
    log.warn(errorCodes.tag(code) + 'oidc_rp: the ' + surface.label +
             ' could not renew the tokens of session ' + session.id +
             ' for ' + session.user.username + ', so the session is ended ' +
             'and the next page runs the authorization code flow again. ' +
             why);
    realms.run(realms.get(sessionRealmId), function () {
      // The code is the caller's, one of STS-AUTHN-0136 to STS-AUTHN-0141 or
      // the back channel's own (STS-AUTHN-0112, -0120, -0128, -0133).
      audit.audit({
        action: 'session.renew',
        outcome: 'refused',
        errorCode: code,
        actor: session.user.username,
        protocol: 'OAuth 2.0 / OIDC',
        channel: 'http',
        target: session.id,
        summary: 'the ' + surface.label + ' could not renew the tokens of ' +
                 session.user.username + '\'s session ' + session.id + ': ' +
                 why,
        detail: { sessionId: session.id, surface: surface.id,
                  client_id: surface.clientId, why: why }
      });
      // `via` deliberately names neither "admin" nor "console":
      // dropSession() reads those words as an ADMINISTRATOR ending
      // somebody's session and says so in the CAEP event, and nobody did.
      authn.endSessionById(session.id,
                           'a token renewal that did not complete');
    });
    if (res && !res.headersSent) {
      authn.clearSessionCookie(res, surface.cookie);
    }
    log.debug("Leaving OidcRelyingParty.renewalFailed().");
    return { renewed: false, ended: true, why: why };
  }

  // The round trip. Runs in the realm the sign-in's code flow ran in,
  // because that realm's token endpoint issued the refresh token and its keys
  // are the only ones that open it.
  private async renewNow(req: any, res: any, surface: Surface, session: any,
                         sessionRealmId: string): Promise<RenewalAnswer> {
    const { log, errorCodes, realms, authn } = this.deps;
    log.debug("Entering OidcRelyingParty.renewNow(). session=" + session.id);
    const tokens = session.rpTokens;
    const found = this.clientOf(surface);
    if (!found.ok) {
      log.debug("Leaving OidcRelyingParty.renewNow(). There is no client.");
      return this.renewalFailed(surface, session, sessionRealmId, res,
                                errorCodes.codeOf(found) || 'STS-AUTHN-0112',
                                found.why);
    }
    const host = tokens.host ||
      this.hostHeaderFrom(this.publicBaseOf(req));
    const form = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: tokens.refreshToken
    });
    const auth = await this.clientAuthentication(surface, found.client, form,
                                                 host);
    if (!auth.ok) {
      log.debug("Leaving OidcRelyingParty.renewNow(). No client " +
                "authentication.");
      return this.renewalFailed(surface, session, sessionRealmId, res,
                                errorCodes.codeOf(auth) || 'STS-AUTHN-0207',
                                auth.why || '');
    }
    const headers = auth.headers || {};
    // #34: THE SAME KEY THE SIGN-IN USED, or a new one for a session that
    // predates this code. A session from before carries an UNBOUND refresh
    // token, so any key proves what there is to prove; with
    // `oauth2.refreshTokenRequireDpop` on, that token is refused outright and
    // the person signs in again, which is what the setting says it does to
    // every unbound refresh token.
    const dpop = tokens.dpop || this.dpopKey();
    const tokenAnswer = await this.tokenRequestWithProof(dpop, {
      method: 'POST',
      path: realms.currentPrefix() + TOKEN_PATH,
      host: host,
      headers: headers,
      body: form.toString(),
      clientCertificate: this.surfaceCertificate(surface),
      from: req
    });
    if (!tokenAnswer.ok) {
      log.debug("Leaving OidcRelyingParty.renewNow(). The back channel " +
                "failed.");
      return this.renewalFailed(surface, session, sessionRealmId, res,
                                errorCodes.codeOf(tokenAnswer) ||
                                'STS-AUTHN-0120',
                                tokenAnswer.why);
    }
    if (tokenAnswer.status !== 200 || !tokenAnswer.json ||
        !tokenAnswer.json.access_token) {
      const detail = (tokenAnswer.json && tokenAnswer.json.error)
        ? tokenAnswer.json.error +
          (tokenAnswer.json.error_description
            ? ' — ' + tokenAnswer.json.error_description : '')
        : tokenAnswer.text;
      log.debug("Leaving OidcRelyingParty.renewNow(). The token endpoint " +
                "refused.");
      return this.renewalFailed(surface, session, sessionRealmId, res,
                                'STS-AUTHN-0137',
                                'the token endpoint answered the refresh ' +
                                'token grant ' + tokenAnswer.status + ': ' +
                                detail);
    }
    let claims = null;
    const idToken = String(tokenAnswer.json.id_token || '');
    if (idToken) {
      const jwksAnswer = await this.backChannel({
        method: 'GET',
        path: realms.currentPrefix() + JWKS_PATH,
        host: host,
        from: req
      });
      if (!jwksAnswer.ok || jwksAnswer.status !== 200 || !jwksAnswer.json) {
        log.debug("Leaving OidcRelyingParty.renewNow(). The JWKS could not " +
                  "be read.");
        return this.renewalFailed(surface, session, sessionRealmId, res,
                                  'STS-AUTHN-0128',
                                  'this service\'s own JWKS at ' + JWKS_PATH +
                                  ' could not be read: ' +
                                  (jwksAnswer.why ||
                                   ('it answered ' + jwksAnswer.status)));
      }
      const keys = Array.isArray(jwksAnswer.json.keys) ?
        jwksAnswer.json.keys : [];
      const verified = this.verifyIdToken(idToken, keys, {
        issuer: undefined,
        audience: surface.clientId,
        nonce: null
      });
      if (!verified.ok) {
        log.debug("Leaving OidcRelyingParty.renewNow(). The renewed ID " +
                  "Token did not verify.");
        return this.renewalFailed(surface, session, sessionRealmId, res,
                                  errorCodes.codeOf(verified) ||
                                  'STS-AUTHN-0133',
                                  'the renewed ID Token did not verify: ' +
                                  verified.why);
      }
      const same = this.checkRenewedClaims(tokens, verified.claims);
      if (!same.ok) {
        log.debug("Leaving OidcRelyingParty.renewNow(). The renewed ID " +
                  "Token is about another sign-in.");
        return this.renewalFailed(surface, session, sessionRealmId, res,
                                  'STS-AUTHN-0138',
                                  same.why);
      }
      claims = verified.claims;
    }
    // The key travels with them, and a session that had none keeps the one
    // this renewal just made — so the refresh token that came back bound to
    // it can be proved next time (#34).
    const renewedTokens = this.tokensFrom(tokenAnswer.json, claims,
                                          tokens.flowRealm, tokens.host,
                                          Object.assign({}, tokens,
                                                        { dpop: dpop }));
    const renewed = realms.run(realms.get(sessionRealmId), function () {
      return authn.renewRelyingPartySession({ realmId: sessionRealmId,
                                              id: session.id,
                                              tokens: renewedTokens });
    });
    log.debug("Leaving OidcRelyingParty.renewNow(). " +
              (renewed ? "Renewed." : "The session had gone."));
    return renewed ? { renewed: true, session: renewed }
                   : { renewed: false, why: 'the session ended while it ' +
                                            'was renewed' };
  }

  // How long a node that lost the renewal race waits for the winner's
  // tokens, and how long the claim is held: the winner's two back-channel
  // round trips (the token endpoint and the JWKS), each bounded by the same
  // timeout, and a second's slack for its commit.
  private renewalWaitMs(): number {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.renewalWaitMs().");
    log.debug("Leaving OidcRelyingParty.renewalWaitMs().");
    return this.backChannelTimeoutMs() * 2 + 1000;
  }

  // The single-flight across nodes described above `renewing`. Runs in the
  // flow realm, like `renewNow()`; the claim is in the SESSION's realm, where
  // the session it guards lives.
  private async renewOnce(req: any, res: any, surface: Surface, session: any,
                          sessionRealmId: string): Promise<RenewalAnswer> {
    const { log, errorCodes, authn, clusterClaims,
            clusterBarrier } = this.deps;
    log.debug("Entering OidcRelyingParty.renewOnce(). session=" +
              session.id);
    const replacing = String((session.rpTokens &&
                              session.rpTokens.accessToken) || '');
    const answer = await clusterClaims.claim({
      scope: 'oidc_rp.renewal', realm: sessionRealmId,
      value: session.id + '\n' + replacing,
      ttlMs: this.renewalWaitMs()
    });
    if (answer.ok) {
      log.debug("Leaving OidcRelyingParty.renewOnce(). This node renews.");
      return this.renewNow(req, res, surface, session, sessionRealmId);
    }
    if (answer.reason !== 'used') {
      log.warn(errorCodes.tag('STS-AUTHN-0190') + 'oidc_rp: the ' +
               surface.label + ' did not renew the tokens of session ' +
               session.id + ', because the claim store could not be asked (' +
               (answer.why || 'no reason given') + '). The request goes on ' +
               'with the tokens it has, and the next one asks again.');
      log.debug("Leaving OidcRelyingParty.renewOnce(). The store failed.");
      return { renewed: false, why: 'the renewal could not be claimed' };
    }
    const deadline = Date.now() + this.renewalWaitMs();
    for (;;) {
      // Resolves rather than rejects, and at once where nothing coordinates.
      await clusterBarrier.syncShared();
      const now = authn.relyingPartySessionOf(req, surface.cookie,
                                              sessionRealmId);
      if (!now) {
        log.debug("Leaving OidcRelyingParty.renewOnce(). The session ended " +
                  "while another node renewed it.");
        return { renewed: false,
                 why: 'the session ended while it was renewed' };
      }
      if (now.id === session.id && now.rpTokens &&
          String(now.rpTokens.accessToken || '') !== replacing) {
        log.debug("Leaving OidcRelyingParty.renewOnce(). Another node " +
                  "renewed it.");
        return { renewed: true, session: now, elsewhere: true };
      }
      if (Date.now() >= deadline) {
        break;
      }
      await new Promise(function (resolve) {
        setTimeout(resolve, RENEWAL_POLL_MS);
      });
    }
    log.warn(errorCodes.tag('STS-AUTHN-0189') + 'oidc_rp: the ' +
             surface.label + ' found the renewal of session ' + session.id +
             ' in flight elsewhere, and its renewed tokens had not arrived ' +
             'within ' + this.renewalWaitMs() + 'ms. The request goes on ' +
             'with the tokens it has rather than redeem the refresh token a ' +
             'second time.');
    log.debug("Leaving OidcRelyingParty.renewOnce(). The wait ran out.");
    return { renewed: false, why: 'another node\'s renewal did not arrive ' +
                                  'in time' };
  }

  // Is this session's renewal due, and may it happen? Answers what to do
  // rather than doing it, so the one decision is readable in one place:
  //   `none`   — nothing to do (no tokens, or not due yet)
  //   `renew`  — redeem the refresh token now
  //   `end`    — the tokens have run out and cannot be renewed
  renewalDecision(session: any, nowMs: number, marginMs: number):
      { action: 'none' | 'renew' | 'end'; code?: string; why?: string } {
    const { log, authn } = this.deps;
    log.debug("Entering OidcRelyingParty.renewalDecision().");
    const tokens = session && session.rpTokens;
    const expireAt = authn.tokensExpireAt(tokens);
    if (!expireAt || nowMs < expireAt - marginMs) {
      log.debug("Leaving OidcRelyingParty.renewalDecision(). Not due.");
      return { action: 'none' };
    }
    const windowOpen = tokens.refreshToken &&
      (!session.rpRenewableUntil ||
       nowMs < Number(session.rpRenewableUntil));
    if (windowOpen) {
      log.debug("Leaving OidcRelyingParty.renewalDecision(). Due.");
      return { action: 'renew' };
    }
    if (nowMs < expireAt) {
      // Inside the lead time with nothing to renew with: the tokens are
      // still good, so they are left to run out rather than the session
      // being ended early.
      log.debug("Leaving OidcRelyingParty.renewalDecision(). Due, not " +
                "renewable, not yet run out.");
      return { action: 'none' };
    }
    log.debug("Leaving OidcRelyingParty.renewalDecision(). Run out and not " +
              "renewable.");
    return tokens.refreshToken
      ? { action: 'end', code: 'STS-AUTHN-0141',
          why: 'its tokens have run out and the window it could renew them ' +
               'in (the refresh token\'s lifetime from the sign-in, ' +
               'oauth2.refreshTokenTtlS) has closed' }
      : { action: 'end', code: 'STS-AUTHN-0136',
          why: 'its tokens have run out and the sign-in was issued no ' +
               'refresh token to renew them with — the client entry does ' +
               'not allow the refresh_token grant' };
  }

  async renewIfDue(req: any, res: any, surfaceId: string):
      Promise<RenewalAnswer> {
    const { log, realms, renewing } = this.deps;
    const self = this;
    log.debug('Entering OidcRelyingParty.renewIfDue(). surface=' + surfaceId);
    const surface = this.surfaceOf(surfaceId);
    const session = this.sessionFor(req, surfaceId);
    if (!session || !session.rpTokens) {
      log.debug("Leaving OidcRelyingParty.renewIfDue(). No session holding " +
                "tokens.");
      return { renewed: false };
    }
    const sessionRealmId = this.sessionRealmIdOf(surface);
    const flowRealm = realms.get(session.rpTokens.flowRealm);
    if (!flowRealm) {
      log.debug("Leaving OidcRelyingParty.renewIfDue(). The realm the " +
                "sign-in ran in is gone.");
      return this.renewalFailed(surface, session, sessionRealmId, res,
                                'STS-AUTHN-0139',
                                'the trust realm "' +
                                session.rpTokens.flowRealm + '" ' +
                                'the sign-in ran in no longer exists, so ' +
                                'there is no token endpoint that can open ' +
                                'its refresh token');
    }
    const decision = this.renewalDecision(session, Date.now(),
                                          realms.run(flowRealm, function () {
                                            return self.renewBeforeExpiryMs();
                                          }));
    if (decision.action === 'none') {
      log.debug("Leaving OidcRelyingParty.renewIfDue(). Nothing to do.");
      return { renewed: false };
    }
    if (decision.action === 'end') {
      log.debug("Leaving OidcRelyingParty.renewIfDue(). Ended.");
      return this.renewalFailed(surface, session, sessionRealmId, res,
                                decision.code, decision.why);
    }
    const key = sessionRealmId + ' ' + session.id;
    if (renewing.has(key)) {
      log.debug("Leaving OidcRelyingParty.renewIfDue(). Waiting on the " +
                "renewal already in flight.");
      return renewing.get(key);
    }
    const work = realms.run(flowRealm, function () {
      return self.renewOnce(req, res, surface, session, sessionRealmId);
    });
    renewing.set(key, work);
    try {
      const answer = await work;
      log.debug("Leaving OidcRelyingParty.renewIfDue().");
      return answer;
    } finally {
      renewing.delete(key);
    }
  }

  // The middleware each surface registers ABOVE its own gate and routes
  // (rule 1: middleware applies only to routes added after it). It never
  // answers the request itself — a renewal that ended the session leaves the
  // gate to send the browser through the code flow, which is the one place
  // that decision is made — and a renewal that throws is logged and the
  // request goes on, because the session it was renewing is still what the
  // gate reads.
  renewal(surfaceId: string):
      (req: any, res: any, next: () => void) => void {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OidcRelyingParty.renewal(). surface=" + surfaceId);
    this.surfaceOf(surfaceId);
    log.debug("Leaving OidcRelyingParty.renewal().");
    return function renewTokensIfDue(req, res, next) {
      self.renewIfDue(req, res, surfaceId).then(function () {
        next();
      }, function (e) {
        log.error(errorCodes.tag('STS-AUTHN-0140') + 'oidc_rp: renewing ' +
                  'the ' + surfaceId + ' session\'s tokens threw, and the ' +
                  'request goes on without them: ' + ((e && e.stack) || e));
        next();
      });
    };
  }

  // Ending one. The surface's own cookie is cleared and the session goes
  // through `dropSession()` like every other, so the audit row and the CAEP
  // event are the ones every sign-out writes.
  endSessionFor(req: any, res: any, surfaceId: string, via?: string):
      boolean {
    const { log, authn } = this.deps;
    log.debug('Entering OidcRelyingParty.endSessionFor(). surface=' +
              surfaceId);
    const surface = this.surfaceOf(surfaceId);
    const session = this.sessionFor(req, surfaceId);
    if (session) {
      this.inSessionRealm(surface, function () {
        authn.endSessionById(session.id, via || 'the ' + surface.label);
      });
    }
    authn.clearSessionCookie(res, surface.cookie);
    log.debug('Leaving OidcRelyingParty.endSessionFor(). ' +
              (session ? 'Ended.' : 'Nothing to end.'));
    return !!session;
  }

  // For the two surfaces' own metadata pages and for the tests: which client
  // a surface is, so that nothing has to write the identifier down twice.
  clientIdFor(surfaceId: string): string {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.clientIdFor().");
    log.debug("Leaving OidcRelyingParty.clientIdFor().");
    return this.surfaceOf(surfaceId).clientId;
  }

  cookieFor(surfaceId: string): string {
    const { log } = this.deps;
    log.debug("Entering OidcRelyingParty.cookieFor().");
    log.debug("Leaving OidcRelyingParty.cookieFor().");
    return this.surfaceOf(surfaceId).cookie;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module finishes loading (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<OidcRelyingParty>(
  'common/oidc_rp',
  () => new OidcRelyingParty(OidcRelyingParty.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  OidcRelyingParty: OidcRelyingParty,
  installInstance: (instance: OidcRelyingParty): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  SURFACES: SURFACES,
  surfaceOf: slot.forward('surfaceOf'),
  beginSignIn: slot.forward('beginSignIn'),
  handleCallback: slot.forward('handleCallback'),
  sessionFor: slot.forward('sessionFor'),
  endSessionFor: slot.forward('endSessionFor'),
  // THE RENEWAL (2026-09-12): the middleware both surfaces register above
  // their routes, the function it calls, and — for
  // `tests/oidc_rp_renewal.js` — the two pure decisions no request can be
  // made to exercise on demand.
  renewal: slot.forward('renewal'),
  renewIfDue: slot.forward('renewIfDue'),
  renewalDecision: slot.forward('renewalDecision'),
  checkRenewedClaims: slot.forward('checkRenewedClaims'),
  tokensFrom: slot.forward('tokensFrom'),
  // #34: the key and the proof, exported for `tests/oidc_rp_dpop.js` — which
  // puts a proof made here through `dpop.verifyProof()` there, so the one
  // place in this service that MAKES a DPoP proof is held to the same reading
  // as the one that checks them. Nothing else calls either.
  dpopKey: slot.forward('dpopKey'),
  dpopProof: slot.forward('dpopProof'),
  // For the two surfaces' own metadata pages and for the tests: which client
  // a surface is, so that nothing has to write the identifier down twice.
  clientIdFor: slot.forward('clientIdFor'),
  cookieFor: slot.forward('cookieFor'),
  // For `tests/oidc_rp_addresses.js` (2026-09-12): the address rule and the
  // loopback origin are the two halves of this file no request can see
  // directly — one decides what is written onto an entry, the other where a
  // socket is opened.
  ensureRedirectUri: slot.forward('ensureRedirectUri'),
  loopbackOrigin: slot.forward('loopbackOrigin'),
  flowTtlMs: slot.forward('flowTtlMs')
};
