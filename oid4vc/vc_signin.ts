// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: vc_signin.ts
//
// ---------------------------------------------------------------------------
// OPENID4VP AS A WAY OF SIGNING IN (2026-09-17, #38) — a wallet's
// presentation producing the SESSION every protocol family here reads.
//
// SINCE #574 (2026-10-12) THE PAGES ARE ROUTES OF THE SIGN-IN SURFACE (#571):
//
//   GET  /authn/wallet?authn={id}          the shell; the browser asks the
//        /authn/wallet?mfa={step}          API below to START one, bound to
//        [&siop=1][&enrol=1]               the pending authentication (or to
//                                          a second-factor step)
//   GET  /authn/wallet/wait?authn={id}&state={state}[&response_code={code}]
//                           [&mfa={step}][&enrol=1][&qr=1]
//                                          the shell the browser waits on;
//                                          the runtime draws the Digital
//                                          Credentials API button, the
//                                          same-device link and — with
//                                          `?qr=1` — the QR code, and asks
//                                          the API whether the wallet answered
//
//   GET  /authn-api/wallet?…               what the start page needs: the
//                                          door's kind, and the CSRF token
//   POST /authn-api/wallet                 START: the transaction, the
//                                          binding cookie, and the wait page
//   GET  /authn-api/wallet/{state}         the wait page's view
//   POST /authn-api/wallet/{state}/status  the poll, which FINISHES the
//                                          sign-in once the wallet answered
//   POST /authn-api/wallet/{state}/dc-api  the Digital Credentials API's
//                                          answer, finished in that request
//
// `authn/authn_api.ts` is the door — the operation table, JSON, the Origin
// and the X-CSRF-Token bound to the `sts_session` cookie — and hands each
// operation here. Everything these answers say is JSON; refusals are
// English and carry no error code (codes are recorded, never sent). The
// pages that were drawn here (the wait page, the QR page, every refusal)
// are drawn in the browser by `oid4vc/web_vc_signin.ts`, and the script that
// was served at `/authn/wallet.js` is part of the sign-in surface's bundle.
//
// THE PENDING ID, THE STEP ID AND THE STATE ARE BEARER CAPABILITIES (#574):
// none of them is written to a log line here, and `common/audit.js` redacts
// them from the paths and queries a row or the call log records.
//
// The Verifier (then the bar door at `/oid4vp/verifier`, a demonstration that
// left on #594) checked presentations properly and then said yes on a web
// page and stopped; that was a row of the root `CLAUDE.md`'s
// *Things this service deliberately does not do* until this module existed.
// It is `kerberos/spnego_authn.ts`'s shape, followed on purpose: a door in
// `/authn/*` that `authn.ts` links to and does not require, reached with an
// `?authn=` naming the pending record the sign-in screen was drawn from, and
// leaving through `authn.startSession()` and `authn.completeAuthentication()`
// so the flow that was interrupted — an authorization request, a
// `wsignin1.0`, a SAML `AuthnRequest`, the console — carries on.
//
// ---------------------------------------------------------------------------
// WHO MAY BE SIGNED IN is `vc_verifier.ts`'s `signInOutcome()`, and the
// register behind it is `vc_issued.ts`: a holder-bound credential this realm
// issued, on an access token this realm verified and nobody has disowned,
// for a directory entry that still exists — signed in as that entry.
// Everything else still VERIFIES and is recorded exactly as before, and this
// page says why it signed nobody in.
//
// **EVERY FORMAT THIS ISSUER MINTS SIGNS IN (#38's follow-ups)**, with the same
// guarantee each time — a fresh proof, by the key the credential is bound to,
// for this request's nonce and this Verifier's audience (the Client
// Identifier, or `origin:<origin>` over the Digital Credentials API):
//
//   dc+sd-jwt    a Key Binding JWT (`iat` within `oid4vp.kbMaxAgeS`, over
//                exactly the bytes presented)
//   jwt_vc_json  a VP JWT signed by the credential's `cnf` key, with `nonce`,
//                `aud` and an `iat` held to the same bound
//   ldp_vc       a W3C VerifiablePresentation whose Data Integrity proof —
//                `challenge` and `domain` — is made by the did:jwk the
//                credential names as its subject (`vc_data_integrity.ts`)
//
// The request asks for all of them at once (`oid4vp.signInFormats`), one
// credential query each and a credential set saying any one will do.
//
// ---------------------------------------------------------------------------
// THE BROWSER THAT STARTED IT IS THE ONLY ONE IT CAN FINISH IN.
//
// Three things decide it, and none of them is anything the wallet chooses:
//
//   * **A BINDING COOKIE.** `/authn/wallet` sets `sts_wallet_binding`, a
//     random value HttpOnly and SameSite=Lax, and the transaction keeps its
//     SHA-256. The wait page and the Digital Credentials API answer are
//     accepted only from a request carrying the value whose hash is on the
//     transaction. That is the session-fixation half of OpenID4VP section 13.
//   * **THE PENDING RECORD** (or the second-factor step) the transaction was
//     started for, and no other.
//   * **A `response_code` ON THE SAME-DEVICE PATH** (OpenID4VP section 8.2).
//
// ---------------------------------------------------------------------------
// THE RELAY, AND THE DIGITAL CREDENTIALS API (#38's follow-ups, rcbj's
// decision).
//
// A plain cross-device QR code is relayable: somebody starts a sign-in in
// their own browser and shows the code to a victim, whose wallet presents to
// this service, and the attacker's browser — the one holding the cookie — is
// signed in as the victim. Nothing in `direct_post` can see where the wallet
// is. The W3C Digital Credentials API can: the browser that asked is the one
// the answer comes back to, a wallet on another device is reached over CTAP
// hybrid, which proves Bluetooth PROXIMITY to that browser, and the signed
// request names the one origin it may be used from (`expected_origins`), so
// a relayed request fails at the victim's phone. So the page offers:
//
//   1. **"Use a wallet"** — `navigator.credentials.get()` with the signed
//      request (`openid4vp-v1-signed`, response mode `dc_api.jwt`), for a
//      wallet on this device or a nearby one. The answer is posted here by
//      the page and checked against this service's origin.
//   2. **"Open your wallet on this device"** — the same-device link,
//      `direct_post`, which a relay cannot use either (the wallet is on the
//      device showing the page).
//   3. **The plain QR code, only where `oid4vp.signInCrossDevice` is ON** —
//      OFF by default in every mode. It is the one path the relay still
//      works on, and where it is on the page says so.
//
// ---------------------------------------------------------------------------
// THE PAGE NEEDS A SCRIPT, AND SINCE #574 IT IS THE SIGN-IN SURFACE'S.
//
// The Digital Credentials API is a BROWSER API CALL —
// `navigator.credentials.get()` — and no markup, form or link makes a
// browser ask a wallet over CTAP hybrid; the answer arrives in the page and
// in nowhere else. That was the argument for `/authn/wallet.js`, the one
// script the server-drawn wait page carried. The wait page is a route of the
// static sign-in surface now (#569: script is required), so the call is the
// surface's runtime's, and the `<meta>` refresh the QR page polled with is
// the runtime's poll of `POST …/status`.
//
// ---------------------------------------------------------------------------
// A WALLET AND ANOTHER FACTOR (#38's follow-ups). A presentation is one
// factor. A request that demands two is answered by the presentation and then
// a second factor (`authn.beginSecondFactorAfterWallet()`); a password
// sign-in's second-factor step may be answered by a wallet (`?mfa=`,
// `authn.finishWithWallet()`), for the same person only.
//
// TRUST REALMS: `/realm/acme/authn/wallet` signs somebody in to `acme`, with
// `acme`'s Verifier, against `acme`'s register. An address an answer names
// goes through `authn.locationOf()`, which a redirect would have used.
//
// A ROUTE MODULE ON THE COMPOSITION ROOT'S PATTERN (#50): it registers nothing
// when required; `common/protocol_stack.ts` builds it and calls
// `registerRoutes(app)` after `vc_verifier` and after `authn`.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
import validation = require('../common/validation');
// THE SESSION, and the reason this file is below #8 in the require order.
import authn = require('../authn/authn');
// THE VERIFIER, whose transactions a sign-in is. Required, never required
// back.
import verifier = require('./vc_verifier');
// The realm's own DID, which an ldp_vc may name as its issuer.
import vcDid = require('./vc_did');
// THE ATOMIC "ONCE" (#46), for finishing a sign-in on exactly one node.
import clusterClaims = require('../cluster/cluster_claims');
import identityAssurance = require('../common/identity_assurance');
// SIOPv2 (#129): an enrolment, when the browser collects one.
import siop = require('./siop');

const { log } = helpers;

type Json = any;

// What the console and the audit log call a sign-in that came through here.
const VIA = 'OpenID4VP (a wallet)';

// The cookie that ties a sign-in to the browser that started it.
const BINDING_COOKIE = 'sts_wallet_binding';

// A claim outlives the transaction by the clock disagreement the other
// single-use values allow, for `vc_offers.ts`'s reason.
const CLAIM_SKEW_MS = 60 * 1000;

// Where an enrolment is started from and returns to (#129).
const ENROL_HOME = '/portal/self-issued';

// The query parameters the two shells and the start view take, and
// `wallet`, which the start passes to the Verifier's own rule
// (`vpWalletFor()`).
const QUERY = validation.z.looseObject({
  authn: validation.types.opt(validation.types.opaque),
  mfa: validation.types.opt(validation.types.opaque),
  state: validation.types.opt(validation.types.opaque),
  response_code: validation.types.opt(validation.types.opaque),
  wallet: validation.types.opt(validation.types.uri),
  qr: validation.types.opt(validation.types.oneOf(['1'])),
  // SIOPv2 (#129): a self-issued ID Token instead of a presentation, and —
  // from a session somebody already holds — to enrol its key rather than to
  // sign in with it.
  siop: validation.types.opt(validation.types.oneOf(['1'])),
  enrol: validation.types.opt(validation.types.oneOf(['1']))
});

type RouteApp = typeof app;

interface VcSigninDeps {
  log: typeof log;
  randomId: typeof helpers.randomId;
  baseUrlOf: typeof helpers.baseUrlOf;
  config: typeof config;
  realms: typeof realms;
  stsCrypto: typeof stsCrypto;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  authn: typeof authn;
  verifier: typeof verifier;
  stsDid: (req: any) => string;
  clusterClaims: typeof clusterClaims;
  identityAssurance: typeof identityAssurance;
  siop: typeof siop;
}

/**
 * What `/authn-api`'s door hands an operation: the transaction's `state` (a
 * path parameter), the act's checked `body`, the request's `query`, and the
 * `csrf` token a view answers.
 */
interface WalletArgs {
  state?: string;
  body?: Json;
  query?: Json;
  csrf?: string;
}

/**
 * OpenID4VP as a way of signing in (#38): `/authn/wallet`, where a wallet's
 * presentation — through the Digital Credentials API, the same-device link or,
 * when offered, a QR code — produces the session every protocol family reads.
 * Its pages are routes of the sign-in surface since #574, and its acts are
 * `/authn-api/wallet` operations.
 */
class VcSignin {
  /**
   * What the console and the audit log call a sign-in that came through here.
   */
  static readonly VIA = VIA;
  /**
   * The cookie that ties a sign-in to the browser that started it.
   */
  static readonly BINDING_COOKIE = BINDING_COOKIE;

  /**
   * Builds the wallet sign-in from the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: VcSigninDeps) {
    deps.log.debug("Entering VcSignin.constructor().");
    deps.log.debug("Leaving VcSignin.constructor().");
  }

  // What the composition root passes, from the real modules.
  /**
   * Returns the dependencies built from the real modules.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): VcSigninDeps {
    helpers.log.debug("Entering VcSignin.defaultDeps().");
    helpers.log.debug("Leaving VcSignin.defaultDeps().");
    return {
      log: log,
      randomId: helpers.randomId,
      baseUrlOf: helpers.baseUrlOf,
      config: config,
      realms: realms,
      stsCrypto: stsCrypto,
      errorCodes: errorCodes,
      validation: validation,
      authn: authn,
      verifier: verifier,
      stsDid: vcDid.stsDid,
      clusterClaims: clusterClaims,
      identityAssurance: identityAssurance,
      siop: siop
    };
  }

  // Is this door open? A function, because the setting is live.
  /**
   * Says whether the wallet sign-in is open (`oid4vp.signIn`).
   *
   * @returns true when it is
   */
  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering VcSignin.enabled().");
    log.debug("Leaving VcSignin.enabled().");
    return !!config.value('oid4vp.signIn');
  }

  // SIOPv2 (#129): is a self-issued ID Token a way in here? It is its own
  // switch, OFF by default — a way in is something a realm turns on.
  /**
   * Says whether a self-issued ID Token (SIOPv2) is a way in here, off by
   * default.
   *
   * @returns true when it is
   */
  selfIssuedEnabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering VcSignin.selfIssuedEnabled().");
    log.debug("Leaving VcSignin.selfIssuedEnabled().");
    return !!config.value('oid4vp.signInSelfIssued');
  }

  // Who holds the sign-on session this browser carries, or '' — for an
  // enrolment, which is only ever for the person already signed in.
  /**
   * Returns who holds the sign-on session this browser carries, for an
   * enrolment.
   *
   * @param req - the request
   * @returns the username, or ''
   */
  personOf(req: any): string {
    const { log, authn } = this.deps;
    log.debug("Entering VcSignin.personOf().");
    const session = authn.sessionOf(req);
    const name = session && session.user && session.authenticated !== false
      ? String(session.user.username || '') : '';
    log.debug("Leaving VcSignin.personOf(). " + (name ? 'Signed in.' :
                                                        'Nobody.'));
    return name;
  }

  // IS THE PLAIN QR CODE OFFERED? `oid4vp.signInCrossDevice`, OFF by default
  // in every mode (#38's follow-ups): it is the relayable path, and the
  // Digital Credentials API reaches a wallet on another device without it.
  /**
   * Says whether the plain QR code is offered (`oid4vp.signInCrossDevice`, off
   * by default in every mode).
   *
   * @returns true when it is
   */
  qrOffered(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering VcSignin.qrOffered().");
    log.debug("Leaving VcSignin.qrOffered().");
    return !!config.value('oid4vp.signInCrossDevice');
  }

  private ttlMs(): number {
    const { log, config } = this.deps;
    log.debug("Entering VcSignin.ttlMs().");
    const seconds = Number(config.value('oid4vp.signInTtlS'));
    log.debug("Leaving VcSignin.ttlMs().");
    return (isFinite(seconds) && seconds > 0 ? Math.floor(seconds) : 300) *
      1000;
  }

  private pollSeconds(): number {
    const { log, config } = this.deps;
    log.debug("Entering VcSignin.pollSeconds().");
    const seconds = Number(config.value('oid4vp.signInPollS'));
    log.debug("Leaving VcSignin.pollSeconds().");
    return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) : 3;
  }

  /**
   * Returns the SHA-256 of a value, base64url-encoded.
   *
   * @param value - the value
   * @returns the hash
   */
  hashOf(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering VcSignin.hashOf().");
    log.debug("Leaving VcSignin.hashOf().");
    return stsCrypto.digest('sha256', String(value || ''), 'base64url');
  }

  // A TRANSACTION AS A LOG LINE NAMES IT (#574): the first characters of its
  // state's hash, enough to follow one sign-in through the log and nothing
  // a reader could act with — the state itself is a bearer capability.
  private tagOf(state: unknown): string {
    const { log } = this.deps;
    log.debug("Entering VcSignin.tagOf().");
    log.debug("Leaving VcSignin.tagOf().");
    return '#' + this.hashOf(state).slice(0, 10);
  }

  // This service's origin — what `expected_origins` names and what the
  // answer's audience must carry. The realm prefix is a path, and an origin
  // has none.
  /**
   * Returns this service's origin, which `expected_origins` names and the
   * answer's audience must carry; the realm prefix is not part of it.
   *
   * @param req - the request
   * @returns the origin
   */
  originOf(req: any): string {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering VcSignin.originOf().");
    log.debug("Leaving VcSignin.originOf().");
    return new URL(baseUrlOf(req)).origin;
  }

  // The binding value this browser already holds, or ''.
  private bindingOf(req: any): string {
    const { log, authn } = this.deps;
    log.debug("Entering VcSignin.bindingOf().");
    const value = String(authn.cookiesOf(req)[BINDING_COOKIE] || '');
    log.debug("Leaving VcSignin.bindingOf(). " +
              (value ? "Present." : "Absent."));
    return /^[A-Za-z0-9_-]{32,64}$/.test(value) ? value : '';
  }

  // The cookie line. Appended rather than set, so nothing else this response
  // carries is replaced. Path=/ because a realm's pages live under a prefix
  // and the cookie is one per browser, not one per realm: the transaction
  // keeps the hash, and a realm's transaction is in that realm's store.
  // SameSite=Lax as before: the API's acts are same-origin fetches, which
  // send it.
  private bindingCookie(res: any, value: string): void {
    const { log, config } = this.deps;
    log.debug("Entering VcSignin.bindingCookie().");
    res.append('Set-Cookie', BINDING_COOKIE + '=' + value +
      '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' +
      Math.ceil(this.ttlMs() / 1000) +
      (config.value('global.https') ? '; Secure' : ''));
    log.debug("Leaving VcSignin.bindingCookie().");
  }

  // ---------------------------------------------------------------------------
  // THE ANSWERS. Every one is JSON (`authn.answerJson()`), as every
  // `/authn-api` answer is. A REFUSAL is `{ ok: false, next: 'refused',
  // errors: [why] }` with the English sentence the page used to draw, and —
  // where the page drew more than a sentence — a `view` of kind `refused` the
  // surface draws under it: the heading, the presentation's checks, and the
  // ways on (`retry`, `back`). The code is marked on the response by the
  // caller and is never in the body.
  // ---------------------------------------------------------------------------
  // error-code: none — the definition of this helper; every call site marks its own code first
  private refuse(res: any, status: number, why: string, view?: Json): void {
    const { log, authn } = this.deps;
    log.debug("Entering VcSignin.refuse(). " + status);
    const body: Json = { ok: false, next: 'refused', errors: [String(why)] };
    if (view) {
      body.view = Object.assign({ wallet: 'refused' }, view);
    }
    authn.answerJson(res, status, body);
    log.debug("Leaving VcSignin.refuse().");
  }

  // The way back to the screen the person came from, for a refusal's view:
  // the sign-in screen of the pending record, the portal for an enrolment,
  // or nothing where nothing is waiting.
  private backOf(ctx: any): Json {
    const { log, authn } = this.deps;
    log.debug("Entering VcSignin.backOf().");
    if (ctx && ctx.enrol) {
      log.debug("Leaving VcSignin.backOf(). The portal.");
      return { back: ENROL_HOME, backKind: 'portal' };
    }
    const record = ctx && ctx.record;
    if (!record || !record.id) {
      log.debug("Leaving VcSignin.backOf(). Nothing to go back to.");
      return { back: '', backKind: 'none' };
    }
    log.debug("Leaving VcSignin.backOf().");
    return { back: authn.LOGIN_PATH + '?authn=' +
                   encodeURIComponent(record.id),
             backKind: 'screen' };
  }

  // A refusal's view: its heading (English, as every refusal), the way back,
  // and anything more the caller adds.
  private refusedView(heading: string, ctx: any, more?: Json): Json {
    const { log } = this.deps;
    log.debug("Entering VcSignin.refusedView().");
    log.debug("Leaving VcSignin.refusedView().");
    return Object.assign({ heading: heading, retry: '', checks: [],
                           verdict: '' }, this.backOf(ctx), more || {});
  }

  // A sign-in whose request cannot be signed or built (2026-10-12): the
  // Verifier's certificate for an x509 Client Identifier, or a configured
  // Verifier Attestation, is unusable. Logged where it was found, with its
  // code; marked here and refused as a 500, because nothing the person can
  // do fixes it.
  private unbuildable(res: any, ctx: any, e: any): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering VcSignin.unbuildable().");
    errorCodes.mark(res, String((e && e.code) || 'STS-VC-0112'));
    // error-code: none — marked on the line above with the builder's code.
    this.refuse(res, 500, 'This service cannot sign a wallet request at the ' +
      'moment (' + String((e && e.message) || e) + '). Sign in another way.',
      this.refusedView('A wallet request could not be made', ctx));
    log.debug("Leaving VcSignin.unbuildable().");
  }

  private closed(res: any, ctx: any): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering VcSignin.closed().");
    log.info('oid4vp-signin: refused because oid4vp.signIn is off.');
    errorCodes.mark(res, 'STS-VC-0052');
    this.refuse(res, 403, 'This service can sign people in with a ' +
      'verifiable presentation, and oid4vp.signIn is set to false. Turn it ' +
      'on at /admin/oid4vp, or with POST /admin-api/config/set. The ' +
      'Verifier still checks the presentations a verification asks for ' +
      '(POST /admin-api/verifications/start); it signs nobody in.',
      this.refusedView('Signing in with a wallet is off', ctx));
    log.debug("Leaving VcSignin.closed().");
  }

  // A query or a body this door does not take.
  private parsed(res: any, value: Json, where: string, schema: any): Json {
    const { log, validation, errorCodes } = this.deps;
    log.debug("Entering VcSignin.parsed(). " + where);
    const checked = validation.checkParsed(value || {}, where, schema);
    if (!checked.ok) {
      errorCodes.mark(res, 'STS-VC-0069');
      this.refuse(res, 400, 'Not a sign-in request: ' +
                  String(checked.detail || ''));
      log.debug("Leaving VcSignin.parsed(). Refused.");
      return null;
    }
    log.debug("Leaving VcSignin.parsed().");
    return checked.value;
  }

  // ---------------------------------------------------------------------------
  // WHAT A REQUEST NAMES: the pending record, and — for a wallet as a second
  // factor — the step and the record it carries. `{ record, step, mfaId }`,
  // any of them null.
  // ---------------------------------------------------------------------------
  private contextOf(query: any): any {
    const { log, authn } = this.deps;
    log.debug("Entering VcSignin.contextOf().");
    const mfaId = String(query.mfa || '');
    // AN ENROLMENT (#129) waits on no pending record: its "record" is the
    // enrolment's own id, carried as `authn`, and nothing else reads it.
    if (query.enrol === '1') {
      log.debug("Leaving VcSignin.contextOf(). An enrolment.");
      return { record: query.authn ? { id: String(query.authn),
                                       protocol: 'self-issued enrolment' }
                                   : null,
               step: null, mfaId: '', enrol: true };
    }
    if (mfaId) {
      const step = authn.mfaStepFor(mfaId);
      log.debug("Leaving VcSignin.contextOf(). A second-factor step.");
      return { record: step ? step.authn : null, step: step, mfaId: mfaId };
    }
    log.debug("Leaving VcSignin.contextOf(). A pending record.");
    return { record: authn.pendingFor(query.authn), step: null, mfaId: '' };
  }

  // The wait page's own address, for this transaction: a path of the
  // sign-in surface, without the realm's prefix.
  private waitPathFor(ctx: any, state: string): string {
    const { log, authn } = this.deps;
    log.debug("Entering VcSignin.waitPathFor().");
    log.debug("Leaving VcSignin.waitPathFor().");
    return authn.WALLET_WAIT_PATH + '?authn=' +
      encodeURIComponent(ctx.record.id) + '&state=' +
      encodeURIComponent(state) +
      (ctx.mfaId ? '&mfa=' + encodeURIComponent(ctx.mfaId) : '') +
      (ctx.enrol ? '&enrol=1' : '');
  }

  // The kind of sign-in a page is drawn for: an enrolment, a self-issued ID
  // Token, or a presentation.
  private kindOf(ctx: any, selfIssued: boolean): string {
    const { log } = this.deps;
    log.debug("Entering VcSignin.kindOf().");
    log.debug("Leaving VcSignin.kindOf().");
    return ctx.enrol ? 'enrol' : (selfIssued ? 'selfIssued' : 'wallet');
  }

  // What a view answers beside itself for the browser's language (#539):
  // the pending record's `ui_locales`, as the sign-in screen it came from was
  // drawn in, and — for an enrolment — the person enrolling's own language.
  private languageOf(ctx: any, username: string): Json {
    const { log, authn } = this.deps;
    log.debug("Entering VcSignin.languageOf().");
    const record = (ctx && ctx.record) || {};
    const own = username ? authn.preferredLanguageOf(username) : null;
    log.debug("Leaving VcSignin.languageOf().");
    return Object.assign({ uiLocales: String(record.uiLocales || '') },
                         own ? { preferredLanguage: own } : {});
  }

  // ---------------------------------------------------------------------------
  // WHAT A START IS REFUSED FOR, asked by the start view and by the start
  // itself, in this order: an enrolment with nobody signed in; the door
  // closed; a self-issued ID as a second factor; nothing pending. Answers
  // `{ ctx, selfIssued, enrolFor }`, or null once it has sent a refusal.
  // ---------------------------------------------------------------------------
  private startable(req: any, res: any, query: Json): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering VcSignin.startable().");
    const selfIssued = query.siop === '1';
    // AN ENROLMENT STARTS HERE WITH NO RECORD: it is given one at the start,
    // and it is for the person this browser is signed in as, or for nobody.
    let enrolFor = '';
    if (query.enrol === '1') {
      enrolFor = this.personOf(req);
      if (!selfIssued || !enrolFor || query.mfa) {
        errorCodes.mark(res, 'STS-VC-0093');
        this.refuse(res, 403, 'A self-issued key is enrolled for the person ' +
          'who is signed in, from their own portal, and this browser holds ' +
          'no sign-on session.',
          this.refusedView('Sign in before enrolling a wallet',
                           { enrol: true }));
        log.debug("Leaving VcSignin.startable(). No session to enrol for.");
        return null;
      }
    }
    const ctx = enrolFor ? { record: null, step: null, mfaId: '',
                             enrol: true }
                         : this.contextOf(query);
    if (!this.enabled() || (selfIssued && !this.selfIssuedEnabled())) {
      this.closed(res, ctx);
      log.debug("Leaving VcSignin.startable(). The door is closed.");
      return null;
    }
    if (selfIssued && ctx.mfaId) {
      errorCodes.mark(res, 'STS-VC-0093');
      this.refuse(res, 400, 'A self-issued ID is not offered as a second ' +
        'factor.', this.refusedView('Not a second factor', ctx));
      log.debug("Leaving VcSignin.startable(). SIOPv2 as a second factor.");
      return null;
    }
    if (!enrolFor && !ctx.record) {
      errorCodes.mark(res, 'STS-VC-0053');
      this.refuse(res, 400, 'A wallet sign-in continues a request that is ' +
        'waiting at the sign-in screen, and this link names none — it was ' +
        'never started, it has expired, or it has been used.',
        this.refusedView('Nothing is waiting for this sign-in', null));
      log.debug("Leaving VcSignin.startable(). No pending record.");
      return null;
    }
    log.debug("Leaving VcSignin.startable().");
    return { ctx: ctx, selfIssued: selfIssued, enrolFor: enrolFor };
  }

  // ---------------------------------------------------------------------------
  // GET /authn-api/wallet — what the start page needs: what it is starting,
  // and the CSRF token the start carries. It creates NOTHING: a GET is
  // followed by link checkers and prefetchers, and the transaction and the
  // binding cookie are made by the POST.
  // ---------------------------------------------------------------------------
  /**
   * `GET /authn-api/wallet`: the start page's view, after the refusals a
   * start would meet.
   *
   * @param req - the request
   * @param res - the response
   * @param args - `query`, `csrf`
   * @returns nothing
   */
  startView(req: any, res: any, args: WalletArgs): void {
    const { log } = this.deps;
    log.debug("Entering VcSignin.startView().");
    const query = this.parsed(res, args.query, 'query', QUERY);
    if (!query) {
      log.debug("Leaving VcSignin.startView(). Malformed.");
      return;
    }
    const can = this.startable(req, res, query);
    if (!can) {
      log.debug("Leaving VcSignin.startView(). Refused.");
      return;
    }
    this.deps.authn.answerJson(res, 200, Object.assign({ ok: true,
      view: { wallet: 'start', kind: this.kindOf(can.ctx, can.selfIssued),
              secondFactor: !!can.ctx.mfaId },
      csrf: String(args.csrf || '') },
      this.languageOf(can.ctx, can.enrolFor)));
    log.debug("Leaving VcSignin.startView().");
  }

  // ---------------------------------------------------------------------------
  // POST /authn-api/wallet — start a sign-in: the transaction, bound to the
  // pending record (or step, or enrolment) and to this browser by the
  // binding cookie this answer sets; the answer names the wait page.
  // ---------------------------------------------------------------------------
  /**
   * `POST /authn-api/wallet`: starts a sign-in bound to the pending
   * authentication or second-factor step, and names the wait page.
   *
   * @param req - the request
   * @param res - the response
   * @param args - `body`: `authn`, `mfa`, `siop`, `enrol`, `wallet`
   * @returns a promise settled when the answer is sent
   */
  async start(req: any, res: any, args: WalletArgs): Promise<void> {
    const { log, authn, verifier, errorCodes, randomId, stsDid } = this.deps;
    log.debug("Entering VcSignin.start().");
    const query = Object.assign({}, args.body || {});
    const can = this.startable(req, res, query);
    if (!can) {
      log.debug("Leaving VcSignin.start(). Refused.");
      return;
    }
    const { selfIssued, enrolFor } = can;
    let ctx = can.ctx;
    if (enrolFor) {
      ctx = this.contextOf({ enrol: '1', authn: 'enrol-' + randomId(18) });
    }
    const record = ctx.record;
    const wallet = verifier.vpWalletFor(req, String(query.wallet || ''));
    if (wallet.error) {
      errorCodes.mark(res, 'STS-VC-0033');
      this.refuse(res, 400, String(wallet.error),
        this.refusedView('That wallet address is not registered', ctx));
      log.debug("Leaving VcSignin.start(). The wallet was refused.");
      return;
    }
    // An x509 Client Identifier (#230) signs under the Verifier's
    // certificate, which is issued here, before the synchronous build
    // below reads it; nothing for any other prefix. A sign-in's prefix is
    // `oid4vp.signInClientIdPrefix` (x509_hash by default since
    // 2026-10-12), and a certificate that cannot be issued — or a
    // request that cannot be built under it — is a refusal naming the
    // builder's code (STS-VC-0110 to STS-VC-0113, STS-VC-0092), rather than
    // an unanswered promise.
    try {
      await verifier.prepareSignedClientId(req,
                                           verifier.signInClientIdPrefix());
    } catch (e) {
      log.debug("Caught in VcSignin.start(): " + ((e && e.message) || e));
      this.unbuildable(res, ctx, e);
      log.debug("Leaving VcSignin.start(). The request cannot be signed.");
      return;
    }
    const binding = this.bindingOf(req) || randomId(32);
    let did = '';
    try {
      did = stsDid(req);
    } catch (e) {
      log.debug("Caught in VcSignin.start(): " + ((e && e.message) || e));
      did = '';
    }
    // WHERE THE WALLET SENDS THE PERSON BACK (`afterResponseUri()` adds the
    // record, the state and the response_code): the wait page — with the
    // step a second factor waits on, which it must name to be admitted.
    const completeQuery = enrolFor ? '?enrol=1'
      : (ctx.mfaId ? '?mfa=' + encodeURIComponent(ctx.mfaId) : '');
    let tx: any = null;
    try {
      tx = verifier.buildVpRequest(req, {
        responseType: selfIssued ? 'id_token' : 'vp_token',
        signIn: {
          authnId: record.id,
          bindingHash: this.hashOf(binding),
          completePath: authn.WALLET_WAIT_PATH + completeQuery,
          ttlMs: this.ttlMs(),
          crossDevice: this.qrOffered(),
          issuerDids: did ? [did] : [],
          dcApiOrigin: this.originOf(req)
        }
      });
    } catch (e) {
      log.debug("Caught in VcSignin.start(): " + ((e && e.message) || e));
      this.unbuildable(res, ctx, e);
      log.debug("Leaving VcSignin.start(). The request was not built.");
      return;
    }
    // A WEB WALLET's address, where one is configured or was named, or ''
    // (2026-10-12): the link a wallet APP opens is the scheme's, drawn by
    // the wait view whatever this holds.
    tx.signIn.walletUrl = wallet.url;
    tx.signIn.walletNamed = !!(wallet as any).named;
    tx.signIn.mfaId = ctx.mfaId;
    if (enrolFor) {
      tx.signIn.enrol = { username: enrolFor };
    }
    verifier.saveTransaction(tx);
    this.bindingCookie(res, binding);
    log.info('oid4vp-signin: a wallet sign-in was started for a pending ' +
             (enrolFor ? 'enrolment' : 'authentication (' +
                         (record.protocol || '') + ')') +
             (ctx.mfaId ? ', as a second factor' : '') + ', transaction ' +
             this.tagOf(tx.state) + '.');
    authn.answerJson(res, 200, { ok: true, next: 'wait', state: tx.state,
                                 go: this.waitPathFor(ctx, tx.state) });
    log.debug("Leaving VcSignin.start(). The wait page.");
  }

  // ---------------------------------------------------------------------------
  // THE CHECKS EVERY ANSWER TO A WAITING BROWSER MAKES FIRST, in order, for
  // the wait view, the poll and the Digital Credentials API answer alike:
  // the door is open; the transaction exists and was started for this
  // record; this is the browser that started it; it is not already
  // finished; the record is still pending. Answers `{ ctx, tx }`, or null
  // once it has sent a refusal.
  // ---------------------------------------------------------------------------
  private admitted(req: any, res: any, query: any): any {
    const { log, authn, verifier, errorCodes, stsCrypto } = this.deps;
    log.debug("Entering VcSignin.admitted().");
    const ctx = this.contextOf(query);
    const record = ctx.record;
    if (!this.enabled()) {
      this.closed(res, ctx);
      log.debug("Leaving VcSignin.admitted(). The door is closed.");
      return null;
    }
    const tx = verifier.transactionFor(query.state);
    if (!tx || !tx.signIn || !query.authn ||
        tx.signIn.authnId !== String(query.authn) ||
        String(tx.signIn.mfaId || '') !== ctx.mfaId ||
        !!tx.signIn.enrol !== !!ctx.enrol) {
      errorCodes.mark(res, 'STS-VC-0056');
      this.refuse(res, 400, 'This sign-in was never started here, or it ' +
        'has expired. Each lives oid4vp.signInTtlS seconds.',
        this.refusedView('No such wallet sign-in', ctx,
          { retry: record && !ctx.enrol && !ctx.mfaId
            ? authn.WALLET_PATH + '?authn=' + encodeURIComponent(record.id)
            : '' }));
      log.debug("Leaving VcSignin.admitted(). Unknown or expired.");
      return null;
    }
    const binding = this.bindingOf(req);
    if (!binding || !stsCrypto.constantTimeEquals(this.hashOf(binding),
                                                  tx.signIn.bindingHash)) {
      log.warn(errorCodes.tag('STS-VC-0055') + 'oid4vp-signin: transaction ' +
               this.tagOf(tx.state) + ' was asked about by a browser that ' +
               'did not start it. Refused.');
      errorCodes.mark(res, 'STS-VC-0055');
      this.refuse(res, 403, 'A wallet sign-in finishes only in the browser ' +
        'that started it. If that was you, go back to that browser; ' +
        'otherwise somebody sent you a link to their own sign-in.',
        this.refusedView('This sign-in was started in another browser',
                         null));
      log.debug("Leaving VcSignin.admitted(). Wrong browser.");
      return null;
    }
    // Asked BEFORE the pending record, whose absence is the ordinary state
    // of a finished sign-in: `completeAuthentication()` spent it.
    if (tx.signIn.completed) {
      errorCodes.mark(res, 'STS-VC-0062');
      this.refuse(res, 400, 'This sign-in has already been used.',
        this.refusedView('This sign-in has already been used', ctx));
      log.debug("Leaving VcSignin.admitted(). Already completed.");
      return null;
    }
    // AN ENROLMENT'S PERSON must still be the one signed in here: a sign-out,
    // or another person signing in on this browser, ends it.
    if (ctx.enrol) {
      if (this.personOf(req).toLowerCase() !==
          String(tx.signIn.enrol.username).toLowerCase()) {
        errorCodes.mark(res, 'STS-VC-0093');
        this.refuse(res, 403, 'You are no longer signed in as the person ' +
          'this enrolment was for.',
          this.refusedView('Signed out', ctx, { retry: ENROL_HOME }));
        log.debug("Leaving VcSignin.admitted(). The enrolment's person " +
                  "left.");
        return null;
      }
      log.debug("Leaving VcSignin.admitted(). An enrolment.");
      return { ctx: ctx, tx: tx };
    }
    if (!record || (!ctx.mfaId && !authn.pendingFor(record.id))) {
      errorCodes.mark(res, 'STS-VC-0053');
      this.refuse(res, 400, 'The request you were signing in for has ' +
        'expired. Start again from the application.',
        this.refusedView('Nothing to sign in to', null));
      log.debug("Leaving VcSignin.admitted(). The pending record is gone.");
      return null;
    }
    log.debug("Leaving VcSignin.admitted().");
    return { ctx: ctx, tx: tx };
  }

  // A state in a path, checked for shape: what the door hands in, which an
  // empty or overlong segment never names.
  private stateOf(res: any, args: WalletArgs): string | null {
    const { log } = this.deps;
    log.debug("Entering VcSignin.stateOf().");
    const asked = this.parsed(res, { state: args.state }, 'params',
      validation.z.object({ state: validation.types.opaque }));
    log.debug("Leaving VcSignin.stateOf().");
    return asked ? String(asked.state) : null;
  }

  // ---------------------------------------------------------------------------
  // GET /authn-api/wallet/{state} — the wait page's view. The record, the
  // step and the enrolment are the TRANSACTION's (the binding cookie says
  // this is the browser that started it), so the view's address carries
  // nothing but the state. It finishes nothing: the poll does.
  // ---------------------------------------------------------------------------
  /**
   * `GET /authn-api/wallet/{state}`: what the wait page draws.
   *
   * @param req - the request
   * @param res - the response
   * @param args - `state`, `csrf`
   * @returns nothing
   */
  waitView(req: any, res: any, args: WalletArgs): void {
    const { log, verifier, authn } = this.deps;
    log.debug("Entering VcSignin.waitView().");
    const state = this.stateOf(res, args);
    if (state === null) {
      log.debug("Leaving VcSignin.waitView(). Malformed.");
      return;
    }
    const known = verifier.transactionFor(state);
    const signIn = (known && known.signIn) || {};
    const admitted = this.admitted(req, res, {
      state: state, authn: String(signIn.authnId || ''),
      mfa: String(signIn.mfaId || ''), enrol: signIn.enrol ? '1' : '' });
    if (!admitted) {
      log.debug("Leaving VcSignin.waitView(). Not admitted.");
      return;
    }
    const { ctx, tx } = admitted;
    const selfIssued = tx.responseType === 'id_token';
    const query = verifier.vpRequestQuery(req, tx);
    const scheme = verifier.walletScheme(tx);
    const dcRequest = verifier.dcApiRequestFor(tx);
    const record = ctx.record;
    authn.answerJson(res, 200, Object.assign({ ok: true,
      view: {
        wallet: 'wait',
        state: tx.state,
        kind: this.kindOf(ctx, selfIssued),
        secondFactor: !!ctx.mfaId,
        authn: String(record.id),
        mfa: ctx.mfaId,
        enrol: !!ctx.enrol,
        // The Digital Credentials API's request (openid4vp-v1-signed), or
        // null where the transaction offers none.
        dcRequest: dcRequest || null,
        // THE SAME-DEVICE LINK (2026-10-12): the request by reference
        // under the scheme a wallet APP registers for
        // (`oid4vp.walletInvocation`, `siopv2://` for an ID Token alone),
        // or the web wallet the start NAMED.
        sameDevice: (tx.signIn.walletNamed && tx.signIn.walletUrl
          ? String(tx.signIn.walletUrl) : scheme) + '?' + query,
        // A configured WEB wallet's link beside it, or '' — none is
        // offered where none is configured.
        webWallet: !tx.signIn.walletNamed && tx.signIn.walletUrl
          ? String(tx.signIn.walletUrl) + '?' + query : '',
        // The plain QR code's text, only where it is offered: the same
        // scheme, for a wallet app on another device.
        qr: tx.signIn.crossDevice ? scheme + '?' + query : '',
        expiresIn: Math.max(0, Math.round((tx.expires - Date.now()) / 1000)),
        pollSeconds: this.pollSeconds(),
        protocol: String(record.protocol || ''),
        verifier: String(tx.clientId || ''),
        back: this.backOf(ctx).back,
        backKind: this.backOf(ctx).backKind
      },
      csrf: String(args.csrf || '') },
      this.languageOf(ctx, ctx.enrol ? String(tx.signIn.enrol.username) : '')));
    log.debug("Leaving VcSignin.waitView().");
  }

  // ---------------------------------------------------------------------------
  // POST /authn-api/wallet/{state}/status — the poll, and the collection: an
  // answer the wallet has not given yet is `{ next: 'wait' }`; one it has is
  // finished here, as the wait page's GET finished it until #574. A
  // `response_code` the wallet sent the person back with must be the one it
  // was given (OpenID4VP section 8.2).
  // ---------------------------------------------------------------------------
  /**
   * `POST /authn-api/wallet/{state}/status`: whether the wallet has
   * answered, and the sign-in finished once it has.
   *
   * @param req - the request
   * @param res - the response
   * @param args - `state`, `body`: `authn`, `mfa`, `enrol`, `response_code`
   * @returns a promise settled when the answer is sent
   */
  async status(req: any, res: any, args: WalletArgs): Promise<void> {
    const { log, errorCodes, stsCrypto, authn } = this.deps;
    log.debug("Entering VcSignin.status().");
    const state = this.stateOf(res, args);
    if (state === null) {
      log.debug("Leaving VcSignin.status(). Malformed.");
      return;
    }
    const body = Object.assign({}, args.body || {}, { state: state });
    const admitted = this.admitted(req, res, body);
    if (!admitted) {
      log.debug("Leaving VcSignin.status(). Not admitted.");
      return;
    }
    const { ctx, tx } = admitted;
    if (body.response_code !== undefined &&
        !(tx.signIn.responseCodeHash &&
          stsCrypto.constantTimeEquals(this.hashOf(body.response_code),
                                       tx.signIn.responseCodeHash))) {
      errorCodes.mark(res, 'STS-VC-0065');
      this.refuse(res, 403, 'The link your wallet sent you back with does ' +
        'not carry the code this service gave it.',
        this.refusedView('That response code is not this sign-in\'s', ctx));
      log.debug("Leaving VcSignin.status(). response_code mismatch.");
      return;
    }
    if (!tx.verdict || !tx.signIn.outcome) {
      authn.answerJson(res, 200, { ok: true, next: 'wait',
        expiresIn: Math.max(0, Math.round((tx.expires - Date.now()) /
                                          1000)) });
      log.debug("Leaving VcSignin.status(). Still waiting.");
      return;
    }
    await this.finish(req, res, ctx, tx);
    log.debug("Leaving VcSignin.status().");
  }

  // ---------------------------------------------------------------------------
  // POST /authn-api/wallet/{state}/dc-api — the Digital Credentials API's
  // answer, sent by the wait page's runtime.
  //
  // Admitted exactly as the poll is — the binding cookie, the transaction,
  // the record — after the door's own binding (JSON, an Origin of this
  // service, the CSRF token), and then:
  //
  //   * **THE PAGE'S ORIGIN** (`Origin`) must be this service's own — the
  //     origin the request named in `expected_origins` and the audience the
  //     answer is verified against — not merely one of the origins the door
  //     accepts (`STS-VC-0074`).
  //   * **AN EMPTY ANSWER** is refused: nothing came back from the browser's
  //     API (`STS-VC-0081`).
  //   * otherwise `vc_verifier.ts`'s `answerDcApi()` decrypts, checks the
  //     protocol, verifies with `origin:<origin>` as the audience, and writes
  //     the verdict once; and the sign-in is finished HERE, in this request
  //     — it is the browser's own.
  // ---------------------------------------------------------------------------
  /**
   * `POST /authn-api/wallet/{state}/dc-api`: the Digital Credentials API's
   * answer, verified with `origin:<origin>` as the audience, and the sign-in
   * finished in this request.
   *
   * @param req - the request
   * @param res - the response
   * @param args - `state`, `body`: `authn`, `mfa`, `enrol`, `response`
   * @returns a promise settled when the answer is sent
   */
  async dcApi(req: any, res: any, args: WalletArgs): Promise<void> {
    const { log, errorCodes, verifier } = this.deps;
    log.debug("Entering VcSignin.dcApi().");
    const state = this.stateOf(res, args);
    if (state === null) {
      log.debug("Leaving VcSignin.dcApi(). Malformed.");
      return;
    }
    const body = Object.assign({}, args.body || {}, { state: state });
    const admitted = this.admitted(req, res, body);
    if (!admitted) {
      log.debug("Leaving VcSignin.dcApi(). Not admitted.");
      return;
    }
    const { ctx, tx } = admitted;
    const origin = this.originOf(req);
    const posted = String(req.headers.origin || '');
    if (posted !== origin) {
      log.warn(errorCodes.tag('STS-VC-0074') + 'oid4vp-signin: a Digital ' +
               'Credentials API answer for ' + this.tagOf(tx.state) +
               ' was posted from origin "' + posted + '", not "' + origin +
               '". Refused.');
      errorCodes.mark(res, 'STS-VC-0074');
      this.refuse(res, 403, 'A wallet\'s answer is accepted only from the ' +
        'page on ' + origin + ' that asked for it.',
        this.refusedView('That answer did not come from this page', ctx));
      log.debug("Leaving VcSignin.dcApi(). Wrong origin.");
      return;
    }
    const response = body.response;
    if (!response || (typeof response === 'string' && !response.trim())) {
      errorCodes.mark(res, 'STS-VC-0081');
      this.refuse(res, 400, 'Nothing came back from the browser\'s Digital ' +
        'Credentials API. Use the same-device link instead.');
      log.debug("Leaving VcSignin.dcApi(). Nothing was posted.");
      return;
    }
    const answered = await verifier.answerDcApi(tx,
      typeof response === 'string' ? response : JSON.stringify(response),
      origin);
    if (!answered.ok) {
      errorCodes.mark(res, answered.errorCode);
      // error-code: none — marked on the line above with the Verifier's code
      this.refuse(res, answered.status, String(answered.why),
        this.refusedView('Nobody was signed in', ctx));
      log.debug("Leaving VcSignin.dcApi(). " + answered.errorCode);
      return;
    }
    const fresh = verifier.transactionFor(tx.state);
    await this.finish(req, res, ctx, fresh || tx);
    log.debug("Leaving VcSignin.dcApi().");
  }

  // The checks a presentation went through, for a refusal that has to say
  // why nobody was signed in.
  private checksOf(tx: any): Json[] {
    const { log } = this.deps;
    log.debug("Entering VcSignin.checksOf().");
    const checks = (tx.verdict && tx.verdict.checks) || [];
    log.debug("Leaving VcSignin.checksOf(). " + checks.length);
    return checks.map(function (c: any) {
      return { ok: !!c.ok, name: String(c.name || ''),
               detail: String(c.detail || '') };
    });
  }

  // ---------------------------------------------------------------------------
  // A DECIDED TRANSACTION, FINISHED: the refusal, or the session — after a
  // second factor where one is needed, or as the second factor itself. The
  // answers are the sign-in screen's (`authn.ts`, *What the sign-in screen's
  // acts answer*): `redirect` back to what was interrupted, the session
  // cookie set on that answer and no other; `mfa`, a second factor's page.
  // ---------------------------------------------------------------------------
  private async finish(req: any, res: any, ctx: any, tx: any): Promise<void> {
    const { log, authn, verifier, errorCodes, clusterClaims, siop } =
      this.deps;
    log.debug("Entering VcSignin.finish().");
    const record = ctx.record;
    const outcome = tx.signIn.outcome;
    const selfIssued = tx.responseType === 'id_token';
    const retry = ctx.enrol ? ENROL_HOME
      : ctx.mfaId
        ? authn.WALLET_PATH + '?mfa=' + encodeURIComponent(ctx.mfaId)
        : authn.WALLET_PATH + '?authn=' + encodeURIComponent(record.id) +
          (selfIssued ? '&siop=1' : '');
    if (!outcome.ok) {
      errorCodes.mark(res, outcome.errorCode || 'STS-VC-0061');
      this.refuse(res, 403, String(outcome.reason || 'Nobody was signed in.'),
        this.refusedView('Nobody was signed in', ctx, {
          retry: retry,
          verdict: (selfIssued ? 'selfIssued' : 'presentation') +
                   (tx.verdict.ok ? '.verified' : '.notVerified'),
          checks: this.checksOf(tx) }));
      log.debug("Leaving VcSignin.finish(). " + outcome.errorCode + ".");
      return;
    }

    // ---------------------------------------------------------------------
    // SIGNED IN. Spent first — here and then on every node — so a second
    // poll racing this one finds it gone rather than minting a second
    // session; then the session; then back to what was interrupted.
    // ---------------------------------------------------------------------
    const claimed = await clusterClaims.claim({
      scope: 'oid4vp.sign-in', value: tx.state,
      ttlMs: Math.max(0, tx.expires - Date.now()) + CLAIM_SKEW_MS });
    if (!claimed.ok) {
      const store = claimed.reason !== 'used';
      if (store) {
        log.error(errorCodes.tag('STS-VC-0063') + 'oid4vp-signin: the claim ' +
                  'store could not be asked about transaction ' +
                  this.tagOf(tx.state) + ' (' +
                  (claimed.why || 'no reason given') + '); refused rather ' +
                  'than finished unproven.');
      }
      errorCodes.mark(res, store ? 'STS-VC-0063' : 'STS-VC-0062');
      this.refuse(res, store ? 503 : 400, store
        ? 'This sign-in could not be finished just now; try again shortly.'
        : 'This sign-in has already been used.',
        this.refusedView(store ? 'Try again shortly'
                               : 'This sign-in has already been used', ctx));
      log.debug("Leaving VcSignin.finish(). The claim was refused.");
      return;
    }
    tx.signIn.completed = true;
    verifier.saveTransaction(tx);
    const username = outcome.username;

    // AN ENROLMENT (#129): the proved key, for the person signed in here —
    // `siop.enrol()` refuses one enrolled for somebody else. No session is
    // started: this browser already holds one.
    if (ctx.enrol) {
      const enrolled = siop.enrol(username, outcome.subject,
                                  'enrolled with a wallet', 'self (SIOPv2)');
      if (!enrolled.ok) {
        errorCodes.mark(res, 'STS-VC-0094');
        this.refuse(res, 400, String(enrolled.error),
          this.refusedView('That key was not enrolled', ctx));
        log.debug("Leaving VcSignin.finish(). Enrolment refused.");
        return;
      }
      log.info('oid4vp-signin: ' + username + ' enrolled the self-issued ' +
               'subject ' + outcome.subject + ' (transaction ' +
               this.tagOf(tx.state) + ').');
      authn.answerJson(res, 200, { ok: true, next: 'redirect',
        location: authn.locationOf(res, ENROL_HOME + '?enrolled=1') });
      log.debug("Leaving VcSignin.finish(). Enrolled.");
      return;
    }

    // THE WALLET AS THE SECOND FACTOR: `finishWithWallet()` answers the
    // redirect (or the set-up step) itself.
    if (ctx.mfaId) {
      const finished = authn.finishWithWallet(req, res, ctx.mfaId, outcome);
      if (finished && finished.refused) {
        errorCodes.mark(res, finished.refused === 'policy' ? 'STS-VC-0064' :
                             'STS-VC-0084');
        this.refuse(res, 403, String(finished.why),
          this.refusedView('Nobody was signed in', ctx));
        log.debug("Leaving VcSignin.finish(). Second factor refused.");
        return;
      }
      log.info('oid4vp-signin: ' + username + ' completed a second factor ' +
               'with a wallet (transaction ' + this.tagOf(tx.state) + ').');
      log.debug("Leaving VcSignin.finish(). Signed in, two factors.");
      return;
    }

    // THE RISK OF THIS SIGN-IN (#62 P3), assessed before any session and
    // handed on: the issuance policy decides on it with the roles, and a
    // step-up it names is asked for after the wallet, as a demanded second
    // factor is.
    const assessed = await authn.assessSignIn(req, username, VIA,
      { application: record.application || '',
        credential: { kind: 'wallet' },
        // A key may answer as the second factor (#259).
        deviceAwaited: true });

    // A SECOND FACTOR AFTER THE WALLET, where one is needed: the answer
    // names its page (`next: 'mfa'`).
    const second = authn.beginSecondFactorAfterWallet(req, res, record,
                                                      username, outcome,
                                                      assessed);
    if (second.refused && second.onRisk) {
      errorCodes.mark(res, second.errorCode || 'STS-RISK-0016');
      this.refuse(res, 403, 'Authentication failed.',
        this.refusedView('Nobody was signed in', ctx));
      log.debug("Leaving VcSignin.finish(). Refused on risk.");
      return;
    }
    if (second.refused) {
      errorCodes.mark(res, 'STS-VC-0064');
      this.refuse(res, 403, String(second.refused),
        this.refusedView('The issuance policy refused this sign-in', null));
      log.debug("Leaving VcSignin.finish(). Refused by policy.");
      return;
    }
    if (second.handled) {
      log.info('oid4vp-signin: ' + username + ' presented a wallet ' +
               'credential and is asked for a second factor (transaction ' +
               this.tagOf(tx.state) + ').');
      log.debug("Leaving VcSignin.finish(). Second factor asked.");
      return;
    }

    const session = authn.startSession(res, username, outcome.amr || ['pop'],
      outcome.acr || '1', VIA, {
        request: req,
        // Which credential answered (#62 P0): a wallet presentation.
        credential: { kind: 'wallet' },
        // The sign-in's assessment (#62 P3).
        risk: assessed || undefined,
        application: record.application || '',
        protocol: selfIssued ? 'SIOPv2' : 'OpenID4VP',
        method: selfIssued
          ? 'a self-issued ID Token (SIOPv2) signed by the enrolled key ' +
            outcome.subject
          : 'a wallet: a ' + (outcome.format || 'dc+sd-jwt') +
            ' credential this realm issued, with a fresh holder proof (' +
            (outcome.holderKey || 'holder key') + ')' +
            (outcome.keyStorage ? ', key storage attested ' +
                                  outcome.keyStorage : ''),
        note: (selfIssued
          ? 'A self-issued ID Token signed by ' + outcome.subject + ', a ' +
            'key enrolled for this person, verified'
          : 'A verifiable presentation of a credential this realm issued ' +
            'to ' + outcome.subject + ' verified, including proof of ' +
            'possession of the key it is bound to') +
              ', and a session was ' +
              'started in the browser that asked for it' +
              (tx.signIn.via === 'dc_api' ? ', through the Digital ' +
                                            'Credentials API' : '') +
              '. The request it completes is a ' +
              (record.protocol || 'unnamed') + ' one' +
              (record.application ? ' for "' + record.application + '"' :
                                    '') + '.',
        summary: username + ' was signed in with a wallet'
      });
    if (!session) {
      log.info('oid4vp-signin: the issuance policy refused a session for ' +
               username + ' after a verified presentation.');
      errorCodes.mark(res, 'STS-VC-0064');
      this.refuse(res, 403, 'Your presentation verified. This service will ' +
        'not start a session for this identity. That is a policy decision ' +
        'rather than anything wrong with the credential.',
        this.refusedView('The issuance policy refused this sign-in', null));
      log.debug("Leaving VcSignin.finish(). Refused by policy.");
      return;
    }
    log.info('oid4vp-signin: ' + username + ' signed in with a wallet ' +
             '(transaction ' + this.tagOf(tx.state) + ').');
    // AN IDENTITY VERIFICATION (#127): the disclosed claims the entry agrees
    // with, checked cryptographically, as an electronic_record. Never throws;
    // `oauth2.idaAutomaticVerifications` switches it.
    // A self-issued ID Token (#129) verified a key, not a claim, so it
    // records nothing.
    if (!selfIssued) {
      this.deps.identityAssurance.recordAutomatic(username, 'wallet',
        { claims: outcome.disclosed || {}, format: outcome.format });
    }
    // The session cookie is on this answer, which names where to go.
    authn.completeAuthentication(res, record);
    log.debug("Leaving VcSignin.finish(). Signed in.");
  }

  // Every operation writes an answer; one that threw would leave a browser
  // waiting on a request nothing answers. `/authn-api`'s door hands a throw
  // here so that a refusal carrying its own code keeps it.
  /**
   * Answers an operation that threw: a refusal that carries its own code
   * (the Verifier's, #230: an x509 Client Identifier with no certificate or
   * name) keeps it; anything else is the unhandled failure.
   *
   * @param res - the response
   * @param e - what was thrown
   * @returns nothing
   */
  failed(res: any, e: any): void {
    const { log, errorCodes, authn } = this.deps;
    log.debug("Entering VcSignin.failed().");
    const code = e && typeof e.code === 'string' &&
                 /^STS-[A-Z]+-\d{4}$/.test(e.code) ? e.code : 'STS-VC-0067';
    log.error(errorCodes.tag(code) + 'oid4vp-signin: ' +
              (code === 'STS-VC-0067' ? 'unhandled failure: ' : '') +
              ((e && (e.stack || e.message)) || e));
    if (!res.headersSent) {
      errorCodes.mark(res, code);
      authn.answerJson(res, 500, { ok: false, next: 'refused',
        errors: [String((e && e.message) || e)] });
    }
    log.debug("Leaving VcSignin.failed().");
  }

  // ---------------------------------------------------------------------------
  // THE TWO SHELLS (#574): `/authn/wallet` and `/authn/wallet/wait` answer the
  // sign-in surface's document, drawn for the application the pending
  // sign-in is for (its locale policy's default), and the browser draws the
  // page from `/authn-api/wallet`. Nothing is checked here that the API does
  // not check: a shell for an id that names nothing draws the API's refusal.
  // ---------------------------------------------------------------------------
  private shell(req: any, res: any): void {
    const { log, authn, validation } = this.deps;
    log.debug("Entering VcSignin.shell().");
    const asked = validation.check(req, 'query', QUERY);
    let application = '';
    if (asked.ok) {
      const ctx = this.contextOf(asked.value);
      application = String((ctx.record && ctx.record.application) || '');
    }
    authn.signInShell(req, res, application);
    log.debug("Leaving VcSignin.shell().");
  }

  // THE ROUTES, registered by the composition root after `vc_verifier`: the
  // two shells. The API's operations are `/authn-api`'s
  // (`authn/authn_api.ts`), which hands each one here.
  /**
   * Registers the wallet sign-in's two shells, after `vc_verifier`'s routes.
   *
   * Called by `common/protocol_stack.ts`.
   *
   * @param app - the shared express application
   */
  registerRoutes(app: RouteApp): void {
    const { log, authn } = this.deps;
    const self = this;
    log.debug("Entering VcSignin.registerRoutes().");
    [authn.WALLET_PATH, authn.WALLET_WAIT_PATH].forEach(function (path) {
      app.get(path, function (req, res) {
        log.debug('Entering GET ' + path + '.');
        self.shell(req, res);
        log.debug('Leaving GET ' + path + '.');
      });
    });
    log.debug("Leaving VcSignin.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2), as every route module
// on the pattern is.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<VcSignin>(
  'oid4vc/vc_signin',
  () => new VcSignin(VcSignin.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading any module on the pattern does.
slot.buildNowUnlessDeferred();

/**
 * OpenID4VP as a way of signing in: `/authn/wallet` and its pages.
 *
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  VcSignin: VcSignin,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: VcSignin): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  VIA: VcSignin.VIA,
  BINDING_COOKIE: VcSignin.BINDING_COOKIE,
  enabled: slot.forward('enabled'),
  // The `/authn-api/wallet` operations (#574), which `authn/authn_api.ts`
  // hands here.
  startView: slot.forward('startView'),
  start: slot.forward('start'),
  waitView: slot.forward('waitView'),
  status: slot.forward('status'),
  dcApi: slot.forward('dcApi'),
  failed: slot.forward('failed'),
  qrOffered: slot.forward('qrOffered'),
  hashOf: slot.forward('hashOf'),
  originOf: slot.forward('originOf')
};
