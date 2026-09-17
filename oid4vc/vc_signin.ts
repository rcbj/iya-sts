'use strict';
//
// File: vc_signin.ts
//
// ---------------------------------------------------------------------------
// OPENID4VP AS A WAY OF SIGNING IN (2026-09-17, #38) — a wallet's
// presentation producing the SESSION every protocol family here reads.
//
//   GET /authn/wallet?authn={id}         starts one: an OpenID4VP request
//                                        bound to the pending authentication,
//                                        and a 303 to the page below
//   GET /authn/wallet/wait?authn={id}&state={state}[&response_code={code}]
//                                        the page the browser waits on: the
//                                        same-device link, the cross-device
//                                        QR code, and — once the wallet has
//                                        answered — the sign-in itself
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
// register behind it is `vc_issued.ts`: a holder-bound SD-JWT VC this realm
// issued, on an access token this realm verified, for a directory entry that
// still exists — signed in as that entry. Everything else still VERIFIES and
// is recorded exactly as before, and this page says why it signed nobody in.
//
// **ONLY `dc+sd-jwt` IS ASKED FOR.** A `jwt_vc_json` presentation is bound by a
// VP JWT whose `iat` nobody checks for freshness and which cannot withhold a
// single claim, so a sign-in would hand over the whole credential to prove a
// name; an `ldp_vc` presentation is a bbs-2023 derived proof with no holder
// key at all. The SD-JWT's Key Binding JWT is the one of the three that
// proves possession of the credential's `cnf` key, for this nonce and this
// audience, within `oid4vp.kbMaxAgeS`, over exactly the bytes presented.
//
// ---------------------------------------------------------------------------
// THE BROWSER THAT STARTED IT IS THE ONLY ONE IT CAN FINISH IN.
//
// The wallet answers this service directly (`response_mode=direct_post`), so
// the request that verifies the presentation is the WALLET'S, and a cookie set
// on it would land in the wallet. The session has to be minted on a request
// from the browser — and the question is which browser. Three things decide
// it, and none of them is anything the wallet chooses:
//
//   * **A BINDING COOKIE.** `/authn/wallet` sets `sts_wallet_binding`, a
//     random value HttpOnly and SameSite=Lax, and the transaction keeps its
//     SHA-256. `/authn/wallet/wait` finishes a sign-in only for a request
//     carrying the value whose hash is on the transaction. Knowing the
//     `authn` id and the `state` — both of which are in URLs — is not enough:
//     a page shown in another browser, or a link somebody was sent, cannot
//     finish it. That is the session-fixation half of OpenID4VP section 13.
//   * **THE PENDING RECORD.** The transaction names the pending
//     authentication it was started for, and the wait page must be asked
//     about that same one; the session is started for the flow that record
//     holds and no other.
//   * **A `response_code` ON THE SAME-DEVICE PATH** (OpenID4VP section 8.2):
//     a successful `direct_post` is answered with a `redirect_uri` carrying a
//     one-time code only the wallet saw, and a wait request that carries one
//     must carry the right one. It adds nothing the cookie does not already
//     give against a stranger, and it is what the specification asks a
//     Verifier to do, so a wallet author exercising that path finds it.
//
// **WHAT NONE OF THIS PREVENTS** is the cross-device relay every QR-code
// sign-in has: somebody starts a sign-in in their own browser and shows the
// code to a victim, whose wallet presents to this service, and the attacker's
// browser — the one holding the cookie — is signed in as the victim. The
// wallet is shown this service's client identifier and a SIGNED request (a
// sign-in is always by reference) so it can say where the presentation is
// going; the transaction lives `oid4vp.signInTtlS` (five minutes by default);
// and `oid4vp.signInCrossDevice` turns the QR code off for a deployment that
// would rather not offer it at all.
//
// **ONCE.** A transaction is answered once (`vc_verifier.ts` refuses a second
// `direct_post` for a sign-in) and finished once: the wait page claims the
// state through `cluster/cluster_claims.js` before it starts a session, so two
// polls on two nodes cannot both sign somebody in.
//
// ---------------------------------------------------------------------------
// THE WAIT PAGE HAS NO SCRIPT, AND IT DID NOT NEED ONE.
//
// Waiting for something to happen elsewhere looks like the case for a script
// that polls. It is not: `<meta http-equiv="refresh">` reloads the page every
// `oid4vp.signInPollS` seconds, the reload IS the poll, and the answer is a
// page this server draws — the QR code again while nothing has arrived, the
// sign-in once something has. The QR code is an SVG rendered here, as
// `/authn/totp`'s is, under the `img-src 'self' data:` the base policy already
// has. So `script-src` stays `'none'` and the root `CLAUDE.md`'s inventory of
// scripted pages does not grow: the page works with every script blocked
// because it never had one. What it costs is a full page per poll, a few
// kilobytes every few seconds for at most `oid4vp.signInTtlS`.
//
// ---------------------------------------------------------------------------
// TRUST REALMS: `/realm/acme/authn/wallet` signs somebody in to `acme`, with
// `acme`'s Verifier, against `acme`'s register, exactly as the other doors do:
// every store here is the ambient realm's. The one URL this file builds that
// `app.js` does not rewrite — the `meta refresh` target, which is not an
// `href` — goes through `realms.href()` itself.
//
// A ROUTE MODULE ON THE COMPOSITION ROOT'S PATTERN (#50): it registers nothing
// when required; `common/protocol_stack.ts` builds it and calls
// `registerRoutes(app)` after `vc_verifier`, whose transactions it reads, and
// after `authn`, whose session it starts. Neither of those requires this file.
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
// back: `vc_verifier.ts` learns the path it sends a wallet to from the
// transaction this module writes.
import verifier = require('./vc_verifier');
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

// The three query parameters these pages take, and `wallet`, which the start
// page passes to the Verifier's own rule (`vpWalletFor()`).
const QUERY = validation.z.looseObject({
  authn: validation.types.opt(validation.types.opaque),
  state: validation.types.opt(validation.types.opaque),
  response_code: validation.types.opt(validation.types.opaque),
  wallet: validation.types.opt(validation.types.uri)
});

type RouteApp = typeof app;

interface VcSigninDeps {
  log: typeof log;
  xmlEscape: typeof xmlEscape;
  randomId: typeof helpers.randomId;
  config: typeof config;
  realms: typeof realms;
  stsCrypto: typeof stsCrypto;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  authn: typeof authn;
  verifier: typeof verifier;
  clusterClaims: typeof clusterClaims;
  qrSvg: (text: string) => Promise<string>;
}

class VcSignin {
  static readonly VIA = VIA;
  static readonly BINDING_COOKIE = BINDING_COOKIE;

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
      config: config,
      realms: realms,
      stsCrypto: stsCrypto,
      errorCodes: errorCodes,
      validation: validation,
      authn: authn,
      verifier: verifier,
      clusterClaims: clusterClaims,
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

  // Every page this door draws, in the sign-in screen's own look.
  private page(res: any, status: number, title: string, body: string,
               refreshUrl?: string): void {
    const { log, xmlEscape, authn } = this.deps;
    log.debug("Entering VcSignin.page(). status=" + status);
    const html = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
      'charset="utf-8">' +
      (refreshUrl
        ? '<meta http-equiv="refresh" content="' + this.pollSeconds() +
          ';url=' + xmlEscape(refreshUrl) + '">'
        : '') +
      '<title>' + xmlEscape(title) + '</title><style>' + authn.CARD_CSS +
      '.qr{display:block;margin:12px auto;border:1px solid #eee;' +
      'border-radius:8px}.checks{font-size:.8em;margin:8px 0;' +
      'padding-left:18px}.checks .bad{color:#b00020}' +
      '</style></head><body><div class="card">' + body +
      '</div></body></html>\n';
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

  private asked(req: any, res: any): any {
    const { log, validation, errorCodes } = this.deps;
    log.debug("Entering VcSignin.asked().");
    const checked = validation.check(req, 'query', QUERY);
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
  // GET /authn/wallet — start a sign-in.
  // ---------------------------------------------------------------------------
  handleStart(req: any, res: any): void {
    const { log, authn, verifier, errorCodes, xmlEscape, randomId,
            config } = this.deps;
    log.debug("Entering VcSignin.handleStart().");
    const query = this.asked(req, res);
    if (!query) {
      log.debug("Leaving VcSignin.handleStart(). Malformed.");
      return;
    }
    const record = authn.pendingFor(query.authn);
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
    if (record.forceMfa) {
      errorCodes.mark(res, 'STS-VC-0054');
      this.page(res, 403, 'Two factors are required',
        '<h1>403 &mdash; this request demands two factors</h1><div ' +
        'class="err">A wallet presentation proves possession of one key, ' +
        'and the request you are signing in for asked for two.</div>' +
        this.fallbackHtml(record));
      log.debug("Leaving VcSignin.handleStart(). forceMfa.");
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
    const tx = verifier.buildVpRequest(req, {
      signIn: {
        authnId: record.id,
        bindingHash: this.hashOf(binding),
        completePath: authn.WALLET_WAIT_PATH,
        ttlMs: this.ttlMs(),
        crossDevice: !!config.value('oid4vp.signInCrossDevice')
      }
    });
    tx.signIn.walletUrl = wallet.url;
    verifier.saveTransaction(tx);
    this.bindingCookie(res, binding);
    log.info('oid4vp-signin: a wallet sign-in was started for the pending ' +
             'authentication ' + record.id + ' (' + (record.protocol || '') +
             '), transaction ' + tx.state + '.');
    res.redirect(303, authn.WALLET_WAIT_PATH + '?authn=' +
                 encodeURIComponent(record.id) + '&state=' +
                 encodeURIComponent(tx.state));
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

  // The page while nothing has arrived.
  private async waitingPage(req: any, res: any, record: any,
                            tx: any): Promise<void> {
    const { log, xmlEscape, verifier, realms, authn, qrSvg } = this.deps;
    log.debug("Entering VcSignin.waitingPage().");
    const query = verifier.vpRequestQuery(req, tx);
    const sameDevice = String(tx.signIn.walletUrl || '') + '?' + query;
    let qr = '';
    if (tx.signIn.crossDevice) {
      const svg = await qrSvg('openid4vp://?' + query);
      qr = '<img class="qr" id="wallet-qr" alt="OpenID4VP request QR code" ' +
        'src="data:image/svg+xml;base64,' +
        Buffer.from(svg, 'utf8').toString('base64') + '">' +
        '<p class="sub">On another device? Scan this with your wallet. ' +
        'Only this browser can be signed in by what it presents.</p>';
    }
    const self = authn.WALLET_WAIT_PATH + '?authn=' +
      encodeURIComponent(record.id) + '&state=' + encodeURIComponent(tx.state);
    const seconds = Math.max(0, Math.round((tx.expires - Date.now()) / 1000));
    this.page(res, 200, 'Sign in with a wallet',
      '<h1>Sign in with a wallet</h1>' +
      '<p class="sub">Your wallet will be asked for a credential this ' +
      'service issued to you, and shown exactly what is asked for before ' +
      'anything is sent.</p>' +
      '<p><a class="fedbtn" id="wallet-open" href="' +
      xmlEscape(sameDevice) + '">Open your wallet<span>this device' +
      '</span></a></p>' + qr +
      '<p id="wallet-waiting">Waiting for your wallet &mdash; this page ' +
      'checks again every ' + this.pollSeconds() + ' seconds, and the ' +
      'request expires in ' + seconds + ' seconds. <a href="' +
      xmlEscape(self) + '">Check now</a>.</p>' +
      this.fallbackHtml(record) +
      '<div class="meta"><div>Signing in for: <code>' +
      xmlEscape(record.protocol || '') + '</code></div><div>Verifier: ' +
      '<code>' + xmlEscape(tx.clientId) + '</code></div></div>',
      realms.href(self));
    log.debug("Leaving VcSignin.waitingPage().");
  }

  // ---------------------------------------------------------------------------
  // GET /authn/wallet/wait — wait, and finish.
  // ---------------------------------------------------------------------------
  async handleWait(req: any, res: any): Promise<void> {
    const { log, authn, verifier, errorCodes, xmlEscape, stsCrypto,
            clusterClaims } = this.deps;
    log.debug("Entering VcSignin.handleWait().");
    const query = this.asked(req, res);
    if (!query) {
      log.debug("Leaving VcSignin.handleWait(). Malformed.");
      return;
    }
    const record = authn.pendingFor(query.authn);
    if (!this.enabled()) {
      this.closedPage(res, record);
      log.debug("Leaving VcSignin.handleWait(). The door is closed.");
      return;
    }
    const tx = verifier.transactionFor(query.state);
    if (!tx || !tx.signIn || !query.authn ||
        tx.signIn.authnId !== String(query.authn)) {
      errorCodes.mark(res, 'STS-VC-0056');
      this.page(res, 400, 'No such sign-in',
        '<h1>400 &mdash; no such wallet sign-in</h1><div class="err">This ' +
        'sign-in was never started here, or it has expired. Each lives ' +
        '<code>oid4vp.signInTtlS</code> seconds.</div>' +
        '<p><a href="' + (record ? authn.WALLET_PATH + '?authn=' +
          encodeURIComponent(record.id) : '/') + '">Start again</a></p>' +
        this.fallbackHtml(record));
      log.debug("Leaving VcSignin.handleWait(). Unknown or expired.");
      return;
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
      log.debug("Leaving VcSignin.handleWait(). Wrong browser.");
      return;
    }
    // Asked BEFORE the pending record, whose absence is the ordinary state
    // of a finished sign-in: `completeAuthentication()` spent it.
    if (tx.signIn.completed) {
      errorCodes.mark(res, 'STS-VC-0062');
      this.page(res, 400, 'Already used',
        '<h1>400 &mdash; this sign-in has already been used</h1>' +
        this.fallbackHtml(record));
      log.debug("Leaving VcSignin.handleWait(). Already completed.");
      return;
    }
    if (!record) {
      errorCodes.mark(res, 'STS-VC-0053');
      this.page(res, 400, 'Nothing to sign in to',
        '<h1>400 &mdash; the request you were signing in for has ' +
        'expired</h1><div class="err">Start again from the application.' +
        '</div>');
      log.debug("Leaving VcSignin.handleWait(). The pending record is gone.");
      return;
    }
    if (query.response_code !== undefined &&
        !(tx.signIn.responseCodeHash &&
          stsCrypto.constantTimeEquals(this.hashOf(query.response_code),
                                       tx.signIn.responseCodeHash))) {
      errorCodes.mark(res, 'STS-VC-0065');
      this.page(res, 403, 'Wrong response code',
        '<h1>403 &mdash; that response code is not this sign-in\'s</h1>' +
        '<div class="err">The link your wallet sent you back with does not ' +
        'carry the code this service gave it.</div>' +
        this.fallbackHtml(record));
      log.debug("Leaving VcSignin.handleWait(). response_code mismatch.");
      return;
    }
    const outcome = tx.signIn.outcome;
    if (!tx.verdict || !outcome) {
      await this.waitingPage(req, res, record, tx);
      log.debug("Leaving VcSignin.handleWait(). Still waiting.");
      return;
    }
    if (!outcome.ok) {
      errorCodes.mark(res, outcome.errorCode || 'STS-VC-0061');
      this.page(res, 403, 'Not signed in',
        '<h1>Nobody was signed in</h1>' +
        '<p id="wallet-verdict">The presentation ' +
        (tx.verdict.ok ? '<strong>verified</strong>' :
                         '<strong>did not verify</strong>') + '.</p>' +
        '<div class="err" id="wallet-reason">' + xmlEscape(outcome.reason) +
        '</div>' + this.checksHtml(tx) +
        '<p><a href="' + authn.WALLET_PATH + '?authn=' +
        encodeURIComponent(record.id) + '">Try another credential</a></p>' +
        this.fallbackHtml(record));
      log.debug("Leaving VcSignin.handleWait(). " + outcome.errorCode + ".");
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
      log.debug("Leaving VcSignin.handleWait(). The claim was refused.");
      return;
    }
    tx.signIn.completed = true;
    verifier.saveTransaction(tx);
    const username = outcome.username;
    const session = authn.startSession(res, username, outcome.amr || ['pop'],
      outcome.acr || '1', VIA, {
        request: req,
        application: record.application || '',
        protocol: 'OpenID4VP',
        method: 'a wallet: an SD-JWT VC this realm issued, presented with a ' +
                'Key Binding JWT (' + (outcome.holderKey || 'holder key') +
                ')',
        note: 'A verifiable presentation of a credential this realm issued ' +
              'to ' + outcome.subject + ' verified, including proof of ' +
              'possession of the key it is bound to, and a session was ' +
              'started in the browser that asked for it. The request it ' +
              'completes is a ' + (record.protocol || 'unnamed') + ' one' +
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
      log.debug("Leaving VcSignin.handleWait(). Refused by policy.");
      return;
    }
    log.info('oid4vp-signin: ' + username + ' signed in with a wallet ' +
             '(transaction ' + tx.state + ', session ' + session.id + ').');
    authn.completeAuthentication(res, record);
    log.debug("Leaving VcSignin.handleWait(). Signed in.");
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
    const { log, authn } = this.deps;
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
  enabled: slot.forward('enabled'),
  hashOf: slot.forward('hashOf')
};
