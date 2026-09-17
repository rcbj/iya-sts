'use strict';
//
// File: vc_signin.ts
//
// ---------------------------------------------------------------------------
// OPENID4VP AS A WAY OF SIGNING IN (2026-09-17, #38) — a wallet's
// presentation producing the SESSION every protocol family here reads.
//
//   GET  /authn/wallet?authn={id}          starts one: an OpenID4VP request
//        /authn/wallet?mfa={step}          bound to the pending authentication
//                                          (or to a second-factor step), and a
//                                          303 to the page below
//   GET  /authn/wallet/wait?authn={id}&state={state}[&response_code={code}]
//                           [&mfa={step}][&qr=1]
//                                          the page the browser waits on: the
//                                          Digital Credentials API button, the
//                                          same-device link, and — once the
//                                          wallet has answered — the sign-in
//   POST /authn/wallet/dc-api              what that button's script posts:
//                                          the wallet's answer through the
//                                          Digital Credentials API
//   GET  /authn/wallet.js                  that script
//
// The Verifier at `/oid4vp/verifier` checked presentations properly and then
// said yes on a web page and stopped; that was a row of the root `CLAUDE.md`'s
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
// THE PAGE HAS A SCRIPT NOW, AND IT IS THE ROOT CLAUDE.md's EXCEPTION, ARGUED
// AGAIN.
//
// The wait page had none, and argued that it needed none: a `<meta>` refresh
// was the poll and the answer a page this server drew. The Digital
// Credentials API is a BROWSER API CALL — `navigator.credentials.get()` —
// and there is no markup, no form and no link that makes a browser ask a
// wallet over CTAP hybrid; the answer arrives in the page and in nowhere
// else. So the page CANNOT offer the one path that resists the relay without
// a script, which is the test the root CLAUDE.md sets. The exception is the
// same shape as every other: `script-src 'self'`, one static resource
// (`/authn/wallet.js`), never `'unsafe-inline'`, set through
// `app.contentSecurityPolicy()` so `frame-ancestors` cannot be lost — and a
// REAL SUBMIT BUTTON, whose form posts to the answer endpoint. With the
// script blocked the button still submits, the endpoint answers with a page
// saying the Digital Credentials API did not run, and the same-device link —
// a plain link, on this page and that one — is the way on.
//
// **THE `<meta>` REFRESH MOVED TO THE QR PAGE.** A reload while the browser's
// credential dialog is open throws the dialog away, so the scripted page does
// not refresh itself; it has a *Check now* link for a same-device wallet that
// does not come back. The QR page — `?qr=1`, drawn only where the QR code is
// on — has no script and polls exactly as the wait page used to.
//
// ---------------------------------------------------------------------------
// A WALLET AND ANOTHER FACTOR (#38's follow-ups). A presentation is one
// factor. A request that demands two is answered by the presentation and then
// a second factor (`authn.beginSecondFactorAfterWallet()`); a password
// sign-in's second-factor step may be answered by a wallet (`?mfa=`,
// `authn.finishWithWallet()`), for the same person only.
//
// TRUST REALMS: `/realm/acme/authn/wallet` signs somebody in to `acme`, with
// `acme`'s Verifier, against `acme`'s register. The one URL this file builds
// that `app.js` does not rewrite — the `meta refresh` target — goes through
// `realms.href()` itself.
//
// A ROUTE MODULE ON THE COMPOSITION ROOT'S PATTERN (#50): it registers nothing
// when required; `common/protocol_stack.ts` builds it and calls
// `registerRoutes(app)` after `vc_verifier` and after `authn`.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
import qrcode = require('qrcode');
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

const { log, xmlEscape } = helpers;

// What the console and the audit log call a sign-in that came through here.
const VIA = 'OpenID4VP (a wallet)';

// The cookie that ties a sign-in to the browser that started it.
const BINDING_COOKIE = 'sts_wallet_binding';

// A claim outlives the transaction by the clock disagreement the other
// single-use values allow, for `vc_offers.ts`'s reason.
const CLAIM_SKEW_MS = 60 * 1000;

// The query parameters these pages take, and `wallet`, which the start page
// passes to the Verifier's own rule (`vpWalletFor()`).
const QUERY = validation.z.looseObject({
  authn: validation.types.opt(validation.types.opaque),
  mfa: validation.types.opt(validation.types.opaque),
  state: validation.types.opt(validation.types.opaque),
  response_code: validation.types.opt(validation.types.opaque),
  wallet: validation.types.opt(validation.types.uri),
  qr: validation.types.opt(validation.types.oneOf(['1']))
});

const DC_API_FORM = validation.z.looseObject({
  authn: validation.types.opt(validation.types.opaque),
  mfa: validation.types.opt(validation.types.opaque),
  state: validation.types.opt(validation.types.opaque),
  response: validation.types.opt(validation.z.string().max(1024 * 1024))
});

// ---------------------------------------------------------------------------
// THE SCRIPT (`/authn/wallet.js`). Static: everything it needs is on the page
// as data attributes, so the resource never changes and names nothing about a
// transaction. It finds the form, hides the button where the browser has no
// Digital Credentials API (and says so), and otherwise turns the submit into
// `navigator.credentials.get()`, puts the DigitalCredential it gets back into
// the form's hidden field, and submits the form for real. A refusal from the
// browser is shown and the button comes back.
// ---------------------------------------------------------------------------
const WALLET_SCRIPT = [
  '(function () {',
  '  var form = document.getElementById("wallet-dcapi-form");',
  '  if (!form) { return; }',
  '  var button = document.getElementById("wallet-dcapi");',
  '  var field = document.getElementById("wallet-dcapi-response");',
  '  var missing = document.getElementById("wallet-dcapi-missing");',
  '  var problem = document.getElementById("wallet-dcapi-error");',
  '  var supported = typeof window.DigitalCredential !== "undefined" &&',
  '    !!navigator.credentials &&',
  '    typeof navigator.credentials.get === "function";',
  '  if (!supported) {',
  '    missing.hidden = false;',
  '    button.disabled = true;',
  '    return;',
  '  }',
  '  form.addEventListener("submit", function (event) {',
  '    event.preventDefault();',
  '    var request = JSON.parse(form.getAttribute("data-request"));',
  '    button.disabled = true;',
  '    problem.hidden = true;',
  '    navigator.credentials.get({ mediation: "required",',
  '      digital: { requests: [request] } })',
  '      .then(function (credential) {',
  '        field.value = JSON.stringify({ protocol: credential.protocol,',
  '          data: credential.data });',
  '        form.submit();',
  '      }, function (error) {',
  '        button.disabled = false;',
  '        problem.textContent = "The wallet did not answer: " +',
  '          ((error && (error.name + " " + error.message)) || error);',
  '        problem.hidden = false;',
  '      });',
  '  });',
  '})();',
  ''
].join('\n');

type RouteApp = typeof app;

interface VcSigninDeps {
  log: typeof log;
  xmlEscape: typeof xmlEscape;
  randomId: typeof helpers.randomId;
  baseUrlOf: typeof helpers.baseUrlOf;
  parseBody: typeof helpers.parseBody;
  config: typeof config;
  realms: typeof realms;
  stsCrypto: typeof stsCrypto;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  authn: typeof authn;
  verifier: typeof verifier;
  stsDid: (req: any) => string;
  clusterClaims: typeof clusterClaims;
  contentSecurityPolicy: (overrides: any) => string;
  qrSvg: (text: string) => Promise<string>;
}

class VcSignin {
  static readonly VIA = VIA;
  static readonly BINDING_COOKIE = BINDING_COOKIE;
  static readonly WALLET_SCRIPT = WALLET_SCRIPT;

  constructor(private readonly deps: VcSigninDeps) {
    deps.log.debug("Entering VcSignin.constructor().");
    deps.log.debug("Leaving VcSignin.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): VcSigninDeps {
    helpers.log.debug("Entering VcSignin.defaultDeps().");
    helpers.log.debug("Leaving VcSignin.defaultDeps().");
    return {
      log: log,
      xmlEscape: xmlEscape,
      randomId: helpers.randomId,
      baseUrlOf: helpers.baseUrlOf,
      parseBody: helpers.parseBody,
      config: config,
      realms: realms,
      stsCrypto: stsCrypto,
      errorCodes: errorCodes,
      validation: validation,
      authn: authn,
      verifier: verifier,
      stsDid: vcDid.stsDid,
      clusterClaims: clusterClaims,
      contentSecurityPolicy: app.contentSecurityPolicy,
      // The QR code as SVG, as `common/totp.ts` draws its own — see there for
      // why SVG and why server-side.
      qrSvg: function qrSvg(text: string): Promise<string> {
        helpers.log.debug("Entering qrSvg().");
        helpers.log.debug("Leaving qrSvg().");
        return qrcode.toString(text, { type: 'svg',
          errorCorrectionLevel: 'M', margin: 2, width: 240 });
      }
    };
  }

  // Is this door open? A function, because the setting is live.
  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering VcSignin.enabled().");
    log.debug("Leaving VcSignin.enabled().");
    return !!config.value('oid4vp.signIn');
  }

  // IS THE PLAIN QR CODE OFFERED? `oid4vp.signInCrossDevice`, OFF by default
  // in every mode (#38's follow-ups): it is the relayable path, and the
  // Digital Credentials API reaches a wallet on another device without it.
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

  hashOf(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering VcSignin.hashOf().");
    log.debug("Leaving VcSignin.hashOf().");
    return crypto.createHash('sha256').update(String(value || ''), 'utf8')
      .digest('base64url');
  }

  // This service's origin — what `expected_origins` names and what the
  // answer's audience must carry. The realm prefix is a path, and an origin
  // has none.
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
  private bindingCookie(res: any, value: string): void {
    const { log, config } = this.deps;
    log.debug("Entering VcSignin.bindingCookie().");
    res.append('Set-Cookie', BINDING_COOKIE + '=' + value +
      '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' +
      Math.ceil(this.ttlMs() / 1000) +
      (config.value('global.https') ? '; Secure' : ''));
    log.debug("Leaving VcSignin.bindingCookie().");
  }

  // Every page this door draws, in the sign-in screen's own look. `opts`
  // carries the refresh target (the QR page) or `scripted` (the wait page,
  // the one this door relaxes the policy for).
  private page(res: any, status: number, title: string, body: string,
               opts?: { refreshUrl?: string; scripted?: boolean }): void {
    const { log, xmlEscape, authn, contentSecurityPolicy } = this.deps;
    const o = opts || {};
    log.debug("Entering VcSignin.page(). status=" + status);
    const html = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
      'charset="utf-8">' +
      (o.refreshUrl
        ? '<meta http-equiv="refresh" content="' + this.pollSeconds() +
          ';url=' + xmlEscape(o.refreshUrl) + '">'
        : '') +
      '<title>' + xmlEscape(title) + '</title><style>' + authn.CARD_CSS +
      '.qr{display:block;margin:12px auto;border:1px solid #eee;' +
      'border-radius:8px}.checks{font-size:.8em;margin:8px 0;' +
      'padding-left:18px}.checks .bad{color:#b00020}' +
      'form.dcapi button{width:100%}' +
      '</style></head><body><div class="card">' + body +
      '</div>' +
      (o.scripted ? '<script src="' + authn.WALLET_SCRIPT_PATH +
                    '"></script>' : '') +
      '</body></html>\n';
    if (o.scripted) {
      // THE ONE RELAXATION, through the builder — see the header.
      res.set('Content-Security-Policy',
              contentSecurityPolicy({ 'script-src': "'self'" }));
    }
    res.status(status).type('text/html').set('Cache-Control', 'no-store')
      .send(html);
    log.debug("Leaving VcSignin.page().");
  }

  // The way back to the screen the person came from, when there is one.
  private fallbackHtml(record: any): string {
    const { log, authn } = this.deps;
    log.debug("Entering VcSignin.fallbackHtml().");
    if (!record) {
      log.debug("Leaving VcSignin.fallbackHtml(). Nothing to go back to.");
      return '<p class="sub">Nothing is waiting for this sign-in, so there ' +
        'is nothing to go back to. Start from the application you were ' +
        'signing in to.</p>';
    }
    log.debug("Leaving VcSignin.fallbackHtml().");
    return '<p><a id="wallet-fallback" href="' + authn.LOGIN_PATH +
      '?authn=' + encodeURIComponent(record.id) + '">Sign in another way' +
      '</a> &mdash; the request that sent you here is still waiting.</p>';
  }

  private asked(req: any, res: any, where: string, schema: any): any {
    const { log, validation, errorCodes } = this.deps;
    log.debug("Entering VcSignin.asked().");
    const checked = where === 'body'
      ? validation.checkParsed(this.deps.parseBody(req), 'body', schema)
      : validation.check(req, 'query', schema);
    if (!checked.ok) {
      errorCodes.mark(res, 'STS-VC-0069');
      this.page(res, 400, 'Not a sign-in request',
        '<h1>400 &mdash; not a sign-in request</h1><div class="err">' +
        this.deps.xmlEscape(checked.detail) + '</div>');
      log.debug("Leaving VcSignin.asked(). Refused.");
      return null;
    }
    log.debug("Leaving VcSignin.asked().");
    return checked.value;
  }

  private closedPage(res: any, record: any): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering VcSignin.closedPage().");
    log.info('oid4vp-signin: refused because oid4vp.signIn is off.');
    errorCodes.mark(res, 'STS-VC-0052');
    this.page(res, 403, 'Wallet sign-in is off',
      '<h1>403 &mdash; signing in with a wallet is off</h1><div ' +
      'class="err">This service can sign people in with a verifiable ' +
      'presentation, and <code>oid4vp.signIn</code> is set to false.</div>' +
      '<p>Turn it on at <a href="/admin/oid4vp">/admin/oid4vp</a>, or with ' +
      '<code>POST /admin-api/config/set</code>. The Verifier at <a ' +
      'href="/oid4vp/verifier">/oid4vp/verifier</a> still checks ' +
      'presentations; it signs nobody in.</p>' + this.fallbackHtml(record));
    log.debug("Leaving VcSignin.closedPage().");
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
    if (mfaId) {
      const step = authn.mfaStepFor(mfaId);
      log.debug("Leaving VcSignin.contextOf(). A second-factor step.");
      return { record: step ? step.authn : null, step: step, mfaId: mfaId };
    }
    log.debug("Leaving VcSignin.contextOf(). A pending record.");
    return { record: authn.pendingFor(query.authn), step: null, mfaId: '' };
  }

  // The wait page's own address, for this transaction.
  private waitPathFor(ctx: any, state: string): string {
    const { log, authn } = this.deps;
    log.debug("Entering VcSignin.waitPathFor().");
    log.debug("Leaving VcSignin.waitPathFor().");
    return authn.WALLET_WAIT_PATH + '?authn=' +
      encodeURIComponent(ctx.record.id) + '&state=' +
      encodeURIComponent(state) +
      (ctx.mfaId ? '&mfa=' + encodeURIComponent(ctx.mfaId) : '');
  }

  // ---------------------------------------------------------------------------
  // GET /authn/wallet — start a sign-in.
  // ---------------------------------------------------------------------------
  handleStart(req: any, res: any): void {
    const { log, authn, verifier, errorCodes, xmlEscape, randomId,
            stsDid } = this.deps;
    log.debug("Entering VcSignin.handleStart().");
    const query = this.asked(req, res, 'query', QUERY);
    if (!query) {
      log.debug("Leaving VcSignin.handleStart(). Malformed.");
      return;
    }
    const ctx = this.contextOf(query);
    const record = ctx.record;
    if (!this.enabled()) {
      this.closedPage(res, record);
      log.debug("Leaving VcSignin.handleStart(). The door is closed.");
      return;
    }
    if (!record) {
      errorCodes.mark(res, 'STS-VC-0053');
      this.page(res, 400, 'Nothing to sign in to',
        '<h1>400 &mdash; nothing is waiting for this sign-in</h1><div ' +
        'class="err">A wallet sign-in continues a request that is waiting ' +
        'at the sign-in screen, and this link names none — it was never ' +
        'started, it has expired, or it has been used.</div>' +
        this.fallbackHtml(null));
      log.debug("Leaving VcSignin.handleStart(). No pending record.");
      return;
    }
    const wallet = verifier.vpWalletFor(req);
    if (wallet.error) {
      errorCodes.mark(res, 'STS-VC-0033');
      this.page(res, 400, 'Wallet address refused',
        '<h1>400 &mdash; that wallet address is not registered</h1>' +
        '<div class="err">' + xmlEscape(wallet.error) + '</div>' +
        this.fallbackHtml(record));
      log.debug("Leaving VcSignin.handleStart(). The wallet was refused.");
      return;
    }
    const binding = this.bindingOf(req) || randomId(32);
    let did = '';
    try {
      did = stsDid(req);
    } catch (e) {
      log.debug("Caught in VcSignin.handleStart(): " + ((e && e.message) ||
                                                        e));
      did = '';
    }
    const tx = verifier.buildVpRequest(req, {
      signIn: {
        authnId: record.id,
        bindingHash: this.hashOf(binding),
        completePath: authn.WALLET_WAIT_PATH,
        ttlMs: this.ttlMs(),
        crossDevice: this.qrOffered(),
        issuerDids: did ? [did] : [],
        dcApiOrigin: this.originOf(req)
      }
    });
    tx.signIn.walletUrl = wallet.url;
    tx.signIn.mfaId = ctx.mfaId;
    verifier.saveTransaction(tx);
    this.bindingCookie(res, binding);
    log.info('oid4vp-signin: a wallet sign-in was started for the pending ' +
             'authentication ' + record.id + ' (' + (record.protocol || '') +
             (ctx.mfaId ? ', as a second factor' : '') + '), transaction ' +
             tx.state + '.');
    res.redirect(303, this.waitPathFor(ctx, tx.state));
    log.debug("Leaving VcSignin.handleStart(). Sent to the wait page.");
  }

  // The checks a presentation went through, for a page that has to say why
  // nobody was signed in.
  private checksHtml(tx: any): string {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering VcSignin.checksHtml().");
    const checks = (tx.verdict && tx.verdict.checks) || [];
    if (!checks.length) {
      log.debug("Leaving VcSignin.checksHtml(). None.");
      return '';
    }
    log.debug("Leaving VcSignin.checksHtml().");
    return '<ul class="checks" id="wallet-checks">' +
      checks.map(function (c: any) {
        return '<li class="' + (c.ok ? 'ok' : 'bad') + '">' +
          (c.ok ? '&#10003; ' : '&#10007; ') + xmlEscape(c.name) + ' &mdash; ' +
          xmlEscape(c.detail) + '</li>';
      }).join('') + '</ul>';
  }

  // The same-device link, on the wait page and on the no-script answer.
  private sameDeviceHtml(req: any, tx: any): string {
    const { log, xmlEscape, verifier } = this.deps;
    log.debug("Entering VcSignin.sameDeviceHtml().");
    const query = verifier.vpRequestQuery(req, tx);
    const sameDevice = String(tx.signIn.walletUrl || '') + '?' + query;
    log.debug("Leaving VcSignin.sameDeviceHtml().");
    return '<p><a class="fedbtn" id="wallet-open" href="' +
      xmlEscape(sameDevice) + '">Open your wallet on this device<span>a ' +
      'link, no script needed</span></a></p>';
  }

  // The page while nothing has arrived: the Digital Credentials API button
  // (scripted), the same-device link, and — where it is on — a link to the
  // QR page.
  private waitingPage(req: any, res: any, ctx: any, tx: any): void {
    const { log, xmlEscape, verifier } = this.deps;
    log.debug("Entering VcSignin.waitingPage().");
    const self = this.waitPathFor(ctx, tx.state);
    const seconds = Math.max(0, Math.round((tx.expires - Date.now()) / 1000));
    const dcRequest = verifier.dcApiRequestFor(tx);
    const dcHtml = dcRequest
      ? '<form method="post" class="dcapi" id="wallet-dcapi-form" action="' +
        this.deps.authn.WALLET_DCAPI_PATH + '" data-request="' +
        xmlEscape(JSON.stringify(dcRequest)) + '">' +
        '<input type="hidden" name="authn" value="' +
        xmlEscape(ctx.record.id) + '">' +
        '<input type="hidden" name="state" value="' + xmlEscape(tx.state) +
        '">' +
        (ctx.mfaId ? '<input type="hidden" name="mfa" value="' +
                     xmlEscape(ctx.mfaId) + '">' : '') +
        '<input type="hidden" name="response" id="wallet-dcapi-response" ' +
        'value="">' +
        '<button type="submit" class="fedbtn" id="wallet-dcapi">Use a ' +
        'wallet on this or a nearby device<span>Digital Credentials API' +
        '</span></button></form>' +
        '<p class="sub" id="wallet-dcapi-missing" hidden>This browser has ' +
        'no Digital Credentials API, so it cannot ask a wallet directly. ' +
        'Use the link below' + (this.qrOffered() ? ', or the QR code' : '') +
        '.</p>' +
        '<p class="err" id="wallet-dcapi-error" hidden></p>' +
        '<noscript><p class="sub" id="wallet-noscript">Scripts are off, so ' +
        'the button above cannot reach a wallet; the link below needs ' +
        'none.</p></noscript>'
      : '';
    const qrLink = tx.signIn.crossDevice
      ? '<p class="sub"><a id="wallet-qr-link" href="' + xmlEscape(self) +
        '&amp;qr=1">Show a QR code instead</a> &mdash; for a wallet that ' +
        'cannot be reached through this browser. Only use it for your own ' +
        'phone: a QR code can be passed to somebody else, and whoever ' +
        'scans it signs THIS browser in.</p>'
      : '';
    this.page(res, 200, 'Sign in with a wallet',
      '<h1>Sign in with a wallet</h1>' +
      '<p class="sub">Your wallet will be asked for a credential this ' +
      'service issued to you, and shown exactly what is asked for before ' +
      'anything is sent.' + (ctx.mfaId ? ' It is your second factor: the ' +
      'credential must be yours.' : '') + '</p>' +
      dcHtml + this.sameDeviceHtml(req, tx) + qrLink +
      '<p id="wallet-waiting">The request expires in ' + seconds +
      ' seconds. If your wallet on this device does not bring you back, <a ' +
      'id="wallet-check" href="' + xmlEscape(self) + '">check now</a>.</p>' +
      this.fallbackHtml(ctx.record) +
      '<div class="meta"><div>Signing in for: <code>' +
      xmlEscape(ctx.record.protocol || '') + '</code></div><div>Verifier: ' +
      '<code>' + xmlEscape(tx.clientId) + '</code></div></div>',
      { scripted: !!dcRequest });
    log.debug("Leaving VcSignin.waitingPage().");
  }

  // The QR page: no script, a server-drawn code, and a `<meta>` refresh as
  // the poll.
  private async qrPage(req: any, res: any, ctx: any, tx: any): Promise<void> {
    const { log, xmlEscape, verifier, realms, qrSvg } = this.deps;
    log.debug("Entering VcSignin.qrPage().");
    const query = verifier.vpRequestQuery(req, tx);
    const svg = await qrSvg('openid4vp://?' + query);
    const self = this.waitPathFor(ctx, tx.state) + '&qr=1';
    const seconds = Math.max(0, Math.round((tx.expires - Date.now()) / 1000));
    this.page(res, 200, 'Sign in with a wallet',
      '<h1>Scan with your wallet</h1>' +
      '<img class="qr" id="wallet-qr" alt="OpenID4VP request QR code" ' +
      'src="data:image/svg+xml;base64,' +
      Buffer.from(svg, 'utf8').toString('base64') + '">' +
      '<p class="err" id="wallet-qr-warning">Only scan this with your own ' +
      'phone. Whoever scans it signs THIS browser in, so a code somebody ' +
      'else showed you is a way for them to sign in as you.</p>' +
      '<p id="wallet-waiting">Waiting for your wallet &mdash; this page ' +
      'checks again every ' + this.pollSeconds() + ' seconds, and the ' +
      'request expires in ' + seconds + ' seconds. <a href="' +
      xmlEscape(self) + '">Check now</a>.</p>' +
      this.fallbackHtml(ctx.record),
      { refreshUrl: realms.href(self) });
    log.debug("Leaving VcSignin.qrPage().");
  }

  // ---------------------------------------------------------------------------
  // THE CHECKS EVERY ANSWER TO A WAITING BROWSER MAKES FIRST, in order, for
  // the wait page and the Digital Credentials API answer alike: the door is
  // open; the transaction exists and was started for this record; this is
  // the browser that started it; it is not already finished; the record is
  // still pending. Answers `{ ctx, tx }`, or null once it has drawn a
  // refusal.
  // ---------------------------------------------------------------------------
  private admitted(req: any, res: any, query: any): any {
    const { log, authn, verifier, errorCodes, stsCrypto } = this.deps;
    log.debug("Entering VcSignin.admitted().");
    const ctx = this.contextOf(query);
    const record = ctx.record;
    if (!this.enabled()) {
      this.closedPage(res, record);
      log.debug("Leaving VcSignin.admitted(). The door is closed.");
      return null;
    }
    const tx = verifier.transactionFor(query.state);
    if (!tx || !tx.signIn || !query.authn ||
        tx.signIn.authnId !== String(query.authn) ||
        String(tx.signIn.mfaId || '') !== ctx.mfaId) {
      errorCodes.mark(res, 'STS-VC-0056');
      this.page(res, 400, 'No such sign-in',
        '<h1>400 &mdash; no such wallet sign-in</h1><div class="err">This ' +
        'sign-in was never started here, or it has expired. Each lives ' +
        '<code>oid4vp.signInTtlS</code> seconds.</div>' +
        '<p><a href="' + (record ? authn.WALLET_PATH + '?authn=' +
          encodeURIComponent(record.id) : '/') + '">Start again</a></p>' +
        this.fallbackHtml(record));
      log.debug("Leaving VcSignin.admitted(). Unknown or expired.");
      return null;
    }
    const binding = this.bindingOf(req);
    if (!binding || !stsCrypto.constantTimeEquals(this.hashOf(binding),
                                                  tx.signIn.bindingHash)) {
      log.warn(errorCodes.tag('STS-VC-0055') + 'oid4vp-signin: transaction ' +
               tx.state + ' was asked about by a browser that did not start ' +
               'it. Refused.');
      errorCodes.mark(res, 'STS-VC-0055');
      this.page(res, 403, 'Not this browser',
        '<h1>403 &mdash; this sign-in was started in another browser' +
        '</h1><div class="err">A wallet sign-in finishes only in the ' +
        'browser that started it. If that was you, go back to that ' +
        'browser; otherwise somebody sent you a link to their own ' +
        'sign-in.</div>');
      log.debug("Leaving VcSignin.admitted(). Wrong browser.");
      return null;
    }
    // Asked BEFORE the pending record, whose absence is the ordinary state
    // of a finished sign-in: `completeAuthentication()` spent it.
    if (tx.signIn.completed) {
      errorCodes.mark(res, 'STS-VC-0062');
      this.page(res, 400, 'Already used',
        '<h1>400 &mdash; this sign-in has already been used</h1>' +
        this.fallbackHtml(record));
      log.debug("Leaving VcSignin.admitted(). Already completed.");
      return null;
    }
    if (!record || (!ctx.mfaId && !authn.pendingFor(record.id))) {
      errorCodes.mark(res, 'STS-VC-0053');
      this.page(res, 400, 'Nothing to sign in to',
        '<h1>400 &mdash; the request you were signing in for has ' +
        'expired</h1><div class="err">Start again from the application.' +
        '</div>');
      log.debug("Leaving VcSignin.admitted(). The pending record is gone.");
      return null;
    }
    log.debug("Leaving VcSignin.admitted().");
    return { ctx: ctx, tx: tx };
  }

  // ---------------------------------------------------------------------------
  // GET /authn/wallet/wait — wait, and finish.
  // ---------------------------------------------------------------------------
  async handleWait(req: any, res: any): Promise<void> {
    const { log, errorCodes, stsCrypto } = this.deps;
    log.debug("Entering VcSignin.handleWait().");
    const query = this.asked(req, res, 'query', QUERY);
    if (!query) {
      log.debug("Leaving VcSignin.handleWait(). Malformed.");
      return;
    }
    const admitted = this.admitted(req, res, query);
    if (!admitted) {
      log.debug("Leaving VcSignin.handleWait(). Not admitted.");
      return;
    }
    const { ctx, tx } = admitted;
    if (query.response_code !== undefined &&
        !(tx.signIn.responseCodeHash &&
          stsCrypto.constantTimeEquals(this.hashOf(query.response_code),
                                       tx.signIn.responseCodeHash))) {
      errorCodes.mark(res, 'STS-VC-0065');
      this.page(res, 403, 'Wrong response code',
        '<h1>403 &mdash; that response code is not this sign-in\'s</h1>' +
        '<div class="err">The link your wallet sent you back with does not ' +
        'carry the code this service gave it.</div>' +
        this.fallbackHtml(ctx.record));
      log.debug("Leaving VcSignin.handleWait(). response_code mismatch.");
      return;
    }
    const outcome = tx.signIn.outcome;
    if (!tx.verdict || !outcome) {
      if (query.qr === '1' && tx.signIn.crossDevice) {
        await this.qrPage(req, res, ctx, tx);
      } else {
        this.waitingPage(req, res, ctx, tx);
      }
      log.debug("Leaving VcSignin.handleWait(). Still waiting.");
      return;
    }
    await this.finish(req, res, ctx, tx);
    log.debug("Leaving VcSignin.handleWait().");
  }

  // ---------------------------------------------------------------------------
  // POST /authn/wallet/dc-api — the Digital Credentials API's answer, posted
  // by the wait page's script (or, with no script, an empty form).
  //
  // Admitted exactly as the wait page is — the binding cookie, the
  // transaction, the record — and then:
  //
  //   * **THE PAGE'S ORIGIN** (`Origin`) must be this service's, which is also
  //     the origin the request named in `expected_origins`: a form another
  //     site made could only post here without the cookie (SameSite=Lax), and
  //     this says so even where the cookie arrives.
  //   * **AN EMPTY ANSWER IS THE NO-SCRIPT PATH** and is answered with a page
  //     saying the Digital Credentials API did not run, and the same-device
  //     link.
  //   * otherwise `vc_verifier.ts`'s `answerDcApi()` decrypts, verifies with
  //     `origin:<origin>` as the audience, and writes the verdict; and the
  //     sign-in is finished HERE, in this request — it is the browser's own.
  // ---------------------------------------------------------------------------
  async handleDcApi(req: any, res: any): Promise<void> {
    const { log, errorCodes, xmlEscape, verifier } = this.deps;
    log.debug("Entering VcSignin.handleDcApi().");
    const body = this.asked(req, res, 'body', DC_API_FORM);
    if (!body) {
      log.debug("Leaving VcSignin.handleDcApi(). Malformed.");
      return;
    }
    const admitted = this.admitted(req, res, body);
    if (!admitted) {
      log.debug("Leaving VcSignin.handleDcApi(). Not admitted.");
      return;
    }
    const { ctx, tx } = admitted;
    const origin = this.originOf(req);
    const posted = String(req.headers.origin || '');
    if (posted !== origin) {
      log.warn(errorCodes.tag('STS-VC-0074') + 'oid4vp-signin: a Digital ' +
               'Credentials API answer for ' + tx.state + ' was posted from ' +
               'origin "' + posted + '", not "' + origin + '". Refused.');
      errorCodes.mark(res, 'STS-VC-0074');
      this.page(res, 403, 'Not this origin',
        '<h1>403 &mdash; that answer did not come from this page</h1>' +
        '<div class="err">A wallet\'s answer is accepted only from the page ' +
        'on ' + xmlEscape(origin) + ' that asked for it.</div>' +
        this.fallbackHtml(ctx.record));
      log.debug("Leaving VcSignin.handleDcApi(). Wrong origin.");
      return;
    }
    if (!body.response) {
      errorCodes.mark(res, 'STS-VC-0081');
      this.page(res, 400, 'Your browser did not ask a wallet',
        '<h1>Your browser did not ask a wallet</h1><div class="err" ' +
        'id="wallet-dcapi-noscript">The button uses the browser\'s Digital ' +
        'Credentials API, which needs scripts, and nothing came back from ' +
        'it. Use the link below instead.</div>' +
        this.sameDeviceHtml(req, tx) +
        '<p><a href="' + xmlEscape(this.waitPathFor(ctx, tx.state)) +
        '">Back</a></p>' + this.fallbackHtml(ctx.record));
      log.debug("Leaving VcSignin.handleDcApi(). Nothing was posted.");
      return;
    }
    const answered = await verifier.answerDcApi(tx, body.response, origin);
    if (!answered.ok) {
      errorCodes.mark(res, answered.errorCode);
      this.page(res, answered.status, 'Not signed in',
        '<h1>Nobody was signed in</h1><div class="err" ' +
        'id="wallet-reason">' + xmlEscape(answered.why) + '</div>' +
        this.fallbackHtml(ctx.record));
      log.debug("Leaving VcSignin.handleDcApi(). " + answered.errorCode);
      return;
    }
    const fresh = verifier.transactionFor(tx.state);
    await this.finish(req, res, ctx, fresh || tx);
    log.debug("Leaving VcSignin.handleDcApi().");
  }

  // ---------------------------------------------------------------------------
  // A DECIDED TRANSACTION, FINISHED: the refusal page, or the session — after
  // a second factor where one is needed, or as the second factor itself.
  // ---------------------------------------------------------------------------
  private async finish(req: any, res: any, ctx: any, tx: any): Promise<void> {
    const { log, authn, verifier, errorCodes, xmlEscape,
            clusterClaims } = this.deps;
    log.debug("Entering VcSignin.finish().");
    const record = ctx.record;
    const outcome = tx.signIn.outcome;
    const retry = ctx.mfaId
      ? authn.WALLET_PATH + '?mfa=' + encodeURIComponent(ctx.mfaId)
      : authn.WALLET_PATH + '?authn=' + encodeURIComponent(record.id);
    if (!outcome.ok) {
      errorCodes.mark(res, outcome.errorCode || 'STS-VC-0061');
      this.page(res, 403, 'Not signed in',
        '<h1>Nobody was signed in</h1>' +
        '<p id="wallet-verdict">The presentation ' +
        (tx.verdict.ok ? '<strong>verified</strong>' :
                         '<strong>did not verify</strong>') + '.</p>' +
        '<div class="err" id="wallet-reason">' + xmlEscape(outcome.reason) +
        '</div>' + this.checksHtml(tx) +
        '<p><a href="' + retry + '">Try another credential</a></p>' +
        this.fallbackHtml(record));
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
                  'store could not be asked about transaction ' + tx.state +
                  ' (' + (claimed.why || 'no reason given') + '); refused ' +
                  'rather than finished unproven.');
      }
      errorCodes.mark(res, store ? 'STS-VC-0063' : 'STS-VC-0062');
      this.page(res, store ? 503 : 400, 'Not signed in',
        '<h1>' + (store ? '503 &mdash; try again shortly' :
                          '400 &mdash; this sign-in has already been used') +
        '</h1>' + this.fallbackHtml(record));
      log.debug("Leaving VcSignin.finish(). The claim was refused.");
      return;
    }
    tx.signIn.completed = true;
    verifier.saveTransaction(tx);
    const username = outcome.username;

    // THE WALLET AS THE SECOND FACTOR.
    if (ctx.mfaId) {
      const finished = authn.finishWithWallet(req, res, ctx.mfaId, outcome);
      if (finished && finished.refused) {
        errorCodes.mark(res, finished.refused === 'policy' ? 'STS-VC-0064' :
                             'STS-VC-0084');
        this.page(res, 403, 'Not signed in',
          '<h1>Nobody was signed in</h1><div class="err" ' +
          'id="wallet-reason">' + xmlEscape(finished.why) + '</div>' +
          this.fallbackHtml(record));
        log.debug("Leaving VcSignin.finish(). Second factor refused.");
        return;
      }
      log.info('oid4vp-signin: ' + username + ' completed a second factor ' +
               'with a wallet (transaction ' + tx.state + ').');
      log.debug("Leaving VcSignin.finish(). Signed in, two factors.");
      return;
    }

    // A SECOND FACTOR AFTER THE WALLET, where one is needed.
    const second = authn.beginSecondFactorAfterWallet(req, res, record,
                                                      username, outcome);
    if (second.refused) {
      errorCodes.mark(res, 'STS-VC-0064');
      this.page(res, 403, 'Not permitted',
        '<h1>403 &mdash; the issuance policy refused this sign-in</h1>' +
        '<div class="err">' + xmlEscape(second.refused) + '</div>');
      log.debug("Leaving VcSignin.finish(). Refused by policy.");
      return;
    }
    if (second.handled) {
      log.info('oid4vp-signin: ' + username + ' presented a wallet ' +
               'credential and is asked for a second factor (transaction ' +
               tx.state + ').');
      log.debug("Leaving VcSignin.finish(). Second factor asked.");
      return;
    }

    const session = authn.startSession(res, username, outcome.amr || ['pop'],
      outcome.acr || '1', VIA, {
        request: req,
        application: record.application || '',
        protocol: 'OpenID4VP',
        method: 'a wallet: a ' + (outcome.format || 'dc+sd-jwt') +
                ' credential this realm issued, with a fresh holder proof (' +
                (outcome.holderKey || 'holder key') + ')' +
                (outcome.keyStorage ? ', key storage attested ' +
                                      outcome.keyStorage : ''),
        note: 'A verifiable presentation of a credential this realm issued ' +
              'to ' + outcome.subject + ' verified, including proof of ' +
              'possession of the key it is bound to, and a session was ' +
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
      this.page(res, 403, 'Not permitted',
        '<h1>403 &mdash; the issuance policy refused this sign-in</h1>' +
        '<div class="err">Your presentation verified. This service will not ' +
        'start a session for this identity.</div><p>That is a policy ' +
        'decision rather than anything wrong with the credential.</p>');
      log.debug("Leaving VcSignin.finish(). Refused by policy.");
      return;
    }
    log.info('oid4vp-signin: ' + username + ' signed in with a wallet ' +
             '(transaction ' + tx.state + ', session ' + session.id + ').');
    authn.completeAuthentication(res, record);
    log.debug("Leaving VcSignin.finish(). Signed in.");
  }

  // Every path writes a response; one that threw would leave a browser
  // waiting on a request nothing answers.
  private failed(res: any, e: any): void {
    const { log, errorCodes, xmlEscape } = this.deps;
    log.debug("Entering VcSignin.failed().");
    log.error(errorCodes.tag('STS-VC-0067') + 'oid4vp-signin: unhandled ' +
              'failure: ' + ((e && (e.stack || e.message)) || e));
    if (!res.headersSent) {
      errorCodes.mark(res, 'STS-VC-0067');
      this.page(res, 500, 'Failed', '<h1>500</h1><div class="err">' +
                xmlEscape((e && e.message) || String(e)) + '</div>');
    }
    log.debug("Leaving VcSignin.failed().");
  }

  // THE ROUTES, registered by the composition root after `vc_verifier`.
  registerRoutes(app: RouteApp): void {
    const { log, authn, contentSecurityPolicy } = this.deps;
    const self = this;
    log.debug("Entering VcSignin.registerRoutes().");
    app.get(authn.WALLET_PATH, function (req, res) {
      log.debug('Entering GET ' + authn.WALLET_PATH + '.');
      try {
        self.handleStart(req, res);
      } catch (e) {
        log.debug("Caught in VcSignin.registerRoutes(): " +
                  ((e && e.message) || e));
        self.failed(res, e);
      }
      log.debug('Leaving GET ' + authn.WALLET_PATH + '.');
    });
    app.get(authn.WALLET_WAIT_PATH, function (req, res) {
      log.debug('Entering GET ' + authn.WALLET_WAIT_PATH + '.');
      self.handleWait(req, res).catch(function (e) {
        log.debug("Caught in VcSignin.registerRoutes(): " +
                  ((e && e.message) || e));
        self.failed(res, e);
      });
      log.debug('Leaving GET ' + authn.WALLET_WAIT_PATH + '.');
    });
    app.post(authn.WALLET_DCAPI_PATH, function (req, res) {
      log.debug('Entering POST ' + authn.WALLET_DCAPI_PATH + '.');
      self.handleDcApi(req, res).catch(function (e) {
        log.debug("Caught in VcSignin.registerRoutes(): " +
                  ((e && e.message) || e));
        self.failed(res, e);
      });
      log.debug('Leaving POST ' + authn.WALLET_DCAPI_PATH + '.');
    });
    app.get(authn.WALLET_SCRIPT_PATH, function (req, res) {
      log.debug('Entering GET ' + authn.WALLET_SCRIPT_PATH + '.');
      // Through the builder, as the WebAuthn script is: "a script resource
      // does not need it" is the reasoning that ends with a page that does
      // not have it.
      res.set('Content-Security-Policy',
              contentSecurityPolicy({ 'style-src': null, 'img-src': null }));
      res.type('application/javascript').set('Cache-Control', 'no-store')
        .send(WALLET_SCRIPT);
      log.debug('Leaving GET ' + authn.WALLET_SCRIPT_PATH + '.');
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

export = {
  registerRoutes: slot.forward('registerRoutes'),
  VcSignin: VcSignin,
  installInstance: (instance: VcSignin): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  VIA: VcSignin.VIA,
  BINDING_COOKIE: VcSignin.BINDING_COOKIE,
  WALLET_SCRIPT: VcSignin.WALLET_SCRIPT,
  enabled: slot.forward('enabled'),
  qrOffered: slot.forward('qrOffered'),
  hashOf: slot.forward('hashOf'),
  originOf: slot.forward('originOf')
};
