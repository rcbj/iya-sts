// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_vc_signin.ts
//
// ---------------------------------------------------------------------------
// THE WALLET SIGN-IN, DRAWN IN THE BROWSER (#574, 2026-10-12).
//
// `/authn/wallet` and `/authn/wallet/wait` were pages `oid4vc/vc_signin.ts`
// drew until #574 — the wait page with its one script (`/authn/wallet.js`),
// the QR page with a `<meta>` refresh as its poll, and a page per refusal.
// They are routes of the sign-in surface now (`authn/web_authn_pages.ts`),
// drawn here from `/authn-api/wallet`'s views, and what the script did is
// `WalletFlow`'s, below:
//
//   * THE START PAGE (`/authn/wallet`) says what is being started and, once
//     drawn, STARTS it (`POST /authn-api/wallet`): the transaction and the
//     binding cookie are made by that act, never by a GET, and the answer
//     names the wait page, which REPLACES the start in the history so Back
//     does not start a second.
//   * THE WAIT PAGE (`/authn/wallet/wait`): the Digital Credentials API
//     button, the same-device link, and — where the realm offers it — a link
//     to the QR code (`?qr=1`), drawn here from the request's text by
//     `common/web_qr.ts` (the portal's encoder, moved to `common/` by #572).
//   * THE POLL: `POST …/status` every `pollSeconds` on the QR page, as its
//     `<meta>` refresh did; once at once where the wallet sent the person
//     back with a `response_code`; and on *Check now*. The plain wait page
//     does not poll by itself, as it never did: a same-device wallet that
//     comes back opens the wait page with its `response_code`, and that page
//     collects the sign-in — a poll in the tab left behind would collect it
//     first and leave the returning tab to say it was already used.
//   * THE DIGITAL CREDENTIALS API: `navigator.credentials.get()` with the
//     signed request, its answer sent to `POST …/dc-api`, the poll paused
//     while the browser's dialog is open so the two never race to finish
//     one sign-in.
//   * A REFUSAL answers a view of kind `refused`, drawn under its sentence
//     (English, as every refusal): the heading, the presentation's checks,
//     and the ways on.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing;
// the browser arrives through the surface's `env`.
// ---------------------------------------------------------------------------

import WebQr = require('../common/web_qr');

type Json = any;

/**
 * Escapes text for HTML, as `Html.esc()` does.
 *
 * @param value - anything
 * @returns the escaped text
 */
function esc(value: unknown): string {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * The wallet sign-in's renderers. A static utility class.
 */
class WebVcSignin {
  /**
   * The wait page's own address for a view, without the realm's prefix.
   *
   * @param v - the wait view
   * @returns the path and query
   */
  static waitPath(v: Json): string {
    return '/authn/wallet/wait?authn=' + encodeURIComponent(String(v.authn)) +
      '&state=' + encodeURIComponent(String(v.state)) +
      (v.mfa ? '&mfa=' + encodeURIComponent(String(v.mfa)) : '') +
      (v.enrol ? '&enrol=1' : '');
  }

  /**
   * The page's heading, as text.
   *
   * @param v - the view
   * @param t - the translator
   * @returns the heading
   */
  static heading(v: Json, t: Json): string {
    if (v.wallet === 'refused') {
      return String(v.heading || 'Nobody was signed in');
    }
    if (v.kind === 'enrol') {
      return t.text('wallet.heading.enrol');
    }
    return v.kind === 'selfIssued' ? t.text('wallet.heading.selfIssued')
                                   : t.text('wallet.heading.wallet');
  }

  /**
   * The way back to where the person came from, in the page's language.
   *
   * @param v - the view, with `back` and `backKind`
   * @param t - the translator
   * @returns the markup
   */
  static back(v: Json, t: Json): string {
    if (v.backKind === 'portal') {
      return '<p><a id="wallet-fallback" href="' + esc(v.back) +
        '">Your self-issued IDs</a></p>';
    }
    if (!v.back) {
      return '<p class="sub">' + t.html('wallet.fallback.nothing') + '</p>';
    }
    return '<p><a id="wallet-fallback" href="' + esc(v.back) + '">' +
      t.html('wallet.fallback.another') + '</a> &mdash; ' +
      t.html('wallet.fallback.stillWaiting') + '</p>';
  }

  /**
   * The start page: what is being started, while the runtime starts it.
   *
   * @param v - the start view
   * @param t - the translator
   * @returns the body
   */
  static start(v: Json, t: Json): string {
    const sub = v.kind === 'enrol' ? 'wallet.sub.enrol'
      : (v.kind === 'selfIssued' ? 'wallet.sub.selfIssued'
        : (v.secondFactor ? 'wallet.sub.walletSecondFactor'
                          : 'wallet.sub.wallet'));
    return '<h1>' + esc(WebVcSignin.heading(v, t)) + '</h1>' +
      '<p class="sub">' + t.html(sub) + '</p>' +
      '<p id="wallet-starting">' + t.html('wallet.start.starting') + '</p>';
  }

  /**
   * The wait page, or — with `?qr=1` where the realm offers it — the QR
   * code.
   *
   * @param v - the wait view
   * @param ctx - the context: `t`, `query`
   * @returns the body
   */
  static wait(v: Json, ctx: Json): string {
    const t = ctx.t;
    const self = WebVcSignin.waitPath(v);
    const query = ctx.query || {};
    const seconds = Number(v.expiresIn) || 0;
    if (query.qr === '1' && v.qr) {
      // A warning the person must read before scanning, not a refusal: it
      // is drawn in their language.
      return '<h1>' + t.html('wallet.qr.heading') + '</h1>' +
        '<div class="qr">' + WebQr.svg(String(v.qr),
          { id: 'wallet-qr', label: t.text('wallet.qr.alt') }) + '</div>' +
        '<p class="err" id="wallet-qr-warning">' +
        t.html('wallet.qr.warning') + '</p>' +
        '<p id="wallet-waiting">' +
        t.html('wallet.qr.waiting', { poll: Number(v.pollSeconds) || 3,
                                      seconds: seconds }) +
        ' <a id="wallet-check" href="' + esc(self + '&qr=1') + '">' +
        t.html('wallet.qr.checkNow') + '</a>' + t.html('wallet.end') +
        '</p>' + WebVcSignin.back(v, t);
    }
    const sub = v.kind === 'enrol' ? 'wallet.sub.enrol'
      : (v.kind === 'selfIssued' ? 'wallet.sub.selfIssued'
        : (v.secondFactor ? 'wallet.sub.walletSecondFactor'
                          : 'wallet.sub.wallet'));
    const dc = v.dcRequest
      ? '<button type="button" class="fedbtn" id="wallet-dcapi">' +
        t.html('wallet.wait.dcButton') +
        // The API's name is a product name, and stays as it is.
        '<span>Digital Credentials API</span></button>' +
        '<p class="sub" id="wallet-dcapi-missing" hidden>' +
        (v.qr ? t.html('wallet.wait.dcMissingQr')
              : t.html('wallet.wait.dcMissing')) + '</p>' +
        '<p class="err" id="wallet-dcapi-error" hidden></p>'
      : '';
    const qrLink = v.qr
      ? '<p class="sub"><a id="wallet-qr-link" href="' +
        esc(self + '&qr=1') + '">' + t.html('wallet.wait.qrLink') +
        '</a> &mdash; ' + t.html('wallet.wait.qrLinkNote') + '</p>'
      : '';
    return '<h1>' + esc(WebVcSignin.heading(v, t)) + '</h1>' +
      '<p class="sub">' + t.html(sub) + '</p>' + dc +
      '<p><a class="fedbtn" id="wallet-open" href="' + esc(v.sameDevice) +
      '">' + t.html('wallet.sameDevice.open') + '<span>' +
      t.html('wallet.sameDevice.note') + '</span></a></p>' + qrLink +
      '<p id="wallet-waiting">' +
      t.html('wallet.wait.expires', { seconds: seconds }) + ' ' +
      t.html('wallet.wait.notBack') + ' <a id="wallet-check" href="' +
      esc(self) + '">' + t.html('wallet.wait.checkNow') + '</a>' +
      t.html('wallet.end') + '</p>' + WebVcSignin.back(v, t) +
      '<div class="meta"><div>' +
      t.html('wallet.wait.signingInFor', { protocol: String(v.protocol) }) +
      '</div><div>' +
      t.html('wallet.wait.verifier', { verifier: String(v.verifier) }) +
      '</div></div>';
  }

  /**
   * A refusal's page under its sentence: the heading, what the presentation
   * was found to be and the checks it went through, and the ways on. English,
   * as every refusal is — but for the way back to the sign-in screen, which
   * the wait page draws too.
   *
   * @param v - the refused view
   * @param t - the translator
   * @returns the body
   */
  static refused(v: Json, t: Json): string {
    const verdicts: Json = {
      'presentation.verified': 'The presentation <strong>verified</strong>.',
      'presentation.notVerified': 'The presentation <strong>did not ' +
        'verify</strong>.',
      'selfIssued.verified': 'The self-issued ID Token ' +
        '<strong>verified</strong>.',
      'selfIssued.notVerified': 'The self-issued ID Token <strong>did not ' +
        'verify</strong>.'
    };
    const checks = Array.isArray(v.checks) ? v.checks : [];
    return '<h1>' + esc(WebVcSignin.heading(v, t)) + '</h1>' +
      (verdicts[String(v.verdict)]
        ? '<p id="wallet-verdict">' + verdicts[String(v.verdict)] + '</p>'
        : '') +
      (checks.length
        ? '<ul class="checks" id="wallet-checks">' +
          checks.map(function (c: Json) {
            return '<li class="' + (c.ok ? 'ok' : 'bad') + '">' +
              (c.ok ? '&#10003; ' : '&#10007; ') + esc(c.name) +
              ' &mdash; ' + esc(c.detail) + '</li>';
          }).join('') + '</ul>'
        : '') +
      (v.retry
        ? '<p><a id="wallet-retry" href="' + esc(v.retry) + '">' +
          (v.verdict ? 'Try another credential' : 'Start again') + '</a></p>'
        : '') +
      WebVcSignin.back(v, t);
  }

  /**
   * Draws a wallet page from its view.
   *
   * @param view - the view: `wallet` is `start`, `wait` or `refused`
   * @param ctx - the surface's context
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const v = view || {};
    if (v.wallet === 'start') {
      return WebVcSignin.start(v, ctx.t);
    }
    if (v.wallet === 'wait') {
      return WebVcSignin.wait(v, ctx);
    }
    return WebVcSignin.refused(v, ctx.t);
  }

  /**
   * The document's title.
   *
   * @param view - the view
   * @param ctx - the context
   * @returns the title, as text
   */
  static title(view: Json, ctx: Json): string {
    return WebVcSignin.heading(view || {}, ctx.t);
  }
}

/**
 * What the wallet's pages RUN, for the sign-in surface's runtime: the start,
 * the poll, the Digital Credentials API call. It holds the surface it runs
 * in, whose `env` is the browser.
 */
class WalletFlow {
  // PROTECTED, NOT PRIVATE (#582): the OpenID4VC demonstration's runtime
  // (`web_vc_demo.ts`) runs this flow's poll over its own QR page — one
  // timer at a time, re-armed by the answer — by overriding what a page
  // starts (`onPut()`) and what the poll asks (`check()`).
  protected surface: Json;
  // The poll's pending timer, and the page it was armed for.
  protected timer: Json;
  protected armedFor: string;
  // An act in flight: the poll does not race the API's answer.
  protected busy: boolean;

  /**
   * Makes the flow for a surface.
   *
   * @param surface - the sign-in surface's runtime
   */
  constructor(surface: Json) {
    this.surface = surface;
    this.timer = null;
    this.armedFor = '';
    this.busy = false;
  }

  /**
   * The browser's objects.
   *
   * @returns the surface's `env`
   */
  env(): Json {
    return this.surface.env;
  }

  /**
   * Stops a poll the last page armed.
   *
   * @returns nothing
   */
  stop(): void {
    if (this.timer && this.env().window && this.env().window.clearTimeout) {
      this.env().window.clearTimeout(this.timer);
    }
    this.timer = null;
    this.armedFor = '';
  }

  /**
   * Called once a page of the surface is in the document: starts what a
   * wallet page runs.
   *
   * @param view - the page's view
   * @param ctx - its context
   * @returns nothing
   */
  onPut(view: Json, ctx: Json): void {
    this.stop();
    if (!view || !view.wallet) {
      return;
    }
    if (view.wallet === 'start') {
      this.start(ctx.query || {});
      return;
    }
    if (view.wallet === 'wait') {
      this.arm(view, ctx.query || {});
    }
  }

  /**
   * An operation of the API's index, by its id — a control no operation is
   * the door of is refused, the surface's rule.
   *
   * @param id - the operationId
   * @returns the operation, or null with the refusal drawn
   */
  async operation(id: string): Promise<Json> {
    if (!await this.surface.ensureIndex()) {
      this.surface.refused('The service\'s API could not be reached.');
      return null;
    }
    const rows = (this.surface.indexRows || []).filter(function (op: Json) {
      return op.operationId === id;
    });
    if (!rows.length) {
      this.surface.refused('This page has no API operation (' + id +
                           '), so it refuses rather than guess.');
      return null;
    }
    return rows[0];
  }

  /**
   * The ids an act names beside the transaction, from a view or a query.
   *
   * @param from - `{ authn, mfa, enrol }`
   * @returns the body's members, empty ones left out
   */
  static ids(from: Json): Json {
    const out: Json = {};
    if (from.authn) {
      out.authn = String(from.authn);
    }
    if (from.mfa) {
      out.mfa = String(from.mfa);
    }
    if (from.enrol === true || from.enrol === '1') {
      out.enrol = '1';
    }
    return out;
  }

  /**
   * Starts the sign-in the start page names, and goes to its wait page,
   * which replaces the start in the history.
   *
   * @param query - the start page's query
   * @returns nothing
   */
  async start(query: Json): Promise<void> {
    const op = await this.operation('startWalletSignIn');
    if (!op) {
      return;
    }
    const body = WalletFlow.ids(query);
    if (query.siop === '1') {
      body.siop = '1';
    }
    if (query.wallet) {
      body.wallet = String(query.wallet);
    }
    const answer = await this.surface.send(String(op.path), body);
    const json = answer.json;
    if (json && json.ok && json.go) {
      this.env().history.replaceState(null, '', this.surface.prefix +
                                                String(json.go));
      await this.surface.route();
      return;
    }
    this.follow(answer);
  }

  /**
   * Wires the wait page: the Digital Credentials API button, *Check now*,
   * the collection a returning same-device wallet asks for, and the QR
   * page's poll.
   *
   * @param view - the wait view
   * @param query - the page's query
   * @returns nothing
   */
  arm(view: Json, query: Json): void {
    const self = this;
    const env = this.env();
    const doc = env.document;
    const button = doc.getElementById && doc.getElementById('wallet-dcapi');
    if (button) {
      const nav = env.navigator;
      const supported = !!env.window &&
        typeof env.window.DigitalCredential !== 'undefined' && !!nav &&
        !!nav.credentials && typeof nav.credentials.get === 'function';
      if (!supported) {
        const missing = doc.getElementById('wallet-dcapi-missing');
        if (missing) {
          missing.hidden = false;
        }
        button.disabled = true;
      } else {
        button.addEventListener('click', function () {
          self.dcApi(view, query, button);
        });
      }
    }
    const check = doc.getElementById && doc.getElementById('wallet-check');
    if (check) {
      check.addEventListener('click', function (event: Json) {
        // Not a navigation: the surface would draw the same page again.
        event.preventDefault();
        self.check(view, query, true);
      });
    }
    this.armedFor = String(view.state);
    if (query.response_code) {
      this.check(view, query, false);
    } else if (query.qr === '1' && view.qr) {
      this.schedule(view, query);
    }
  }

  /**
   * Arms the QR page's next poll.
   *
   * @param view - the wait view
   * @param query - the page's query
   * @returns nothing
   */
  schedule(view: Json, query: Json): void {
    const self = this;
    const state = String(view.state);
    const win = this.env().window;
    if (!win || !win.setTimeout) {
      return;
    }
    // ONE TIMER AT A TIME, re-armed by the answer, in the browser: this is
    // the QR page's `<meta>` refresh, not work this service repeats.
    this.timer = win.setTimeout(function () {
      self.timer = null;
      if (self.armedFor !== state) {
        return;
      }
      self.check(view, query, false).then(function (waiting: boolean) {
        if (waiting && self.armedFor === state) {
          self.schedule(view, query);
        }
      });
    }, (Number(view.pollSeconds) || 3) * 1000);
  }

  /**
   * Asks whether the wallet has answered; the sign-in is finished by the
   * answer when it has.
   *
   * @param view - the wait view
   * @param query - the page's query
   * @param manual - *Check now*: a page still waiting is drawn again, with
   *   the time left
   * @returns whether the sign-in is still waiting
   */
  async check(view: Json, query: Json, manual: boolean): Promise<boolean> {
    if (this.busy) {
      return true;
    }
    const op = await this.operation('walletStatus');
    if (!op) {
      return false;
    }
    const body = WalletFlow.ids(view);
    if (query.response_code) {
      body.response_code = String(query.response_code);
    }
    this.busy = true;
    const answer = await this.surface.send(String(op.path)
      .replace('{state}', encodeURIComponent(String(view.state))), body);
    this.busy = false;
    const json = answer.json;
    if (json && json.ok && json.next === 'wait') {
      if (manual) {
        await this.surface.route();
      }
      return true;
    }
    this.stop();
    this.follow(answer);
    return false;
  }

  /**
   * Asks a wallet through the browser's Digital Credentials API, and sends
   * its answer to be verified and the sign-in finished.
   *
   * @param view - the wait view
   * @param query - the page's query
   * @param button - the button pressed
   * @returns nothing
   */
  async dcApi(view: Json, query: Json, button: Json): Promise<void> {
    const env = this.env();
    const problem = env.document.getElementById('wallet-dcapi-error');
    const op = await this.operation('answerWalletDcApi');
    if (!op) {
      return;
    }
    // THE POLL IS PAUSED while the browser's dialog is open, so it cannot
    // collect the answer this request is about to send.
    this.stop();
    this.busy = true;
    button.disabled = true;
    if (problem) {
      problem.hidden = true;
    }
    let credential: Json = null;
    try {
      credential = await env.navigator.credentials.get({
        mediation: 'required',
        digital: { requests: [view.dcRequest] } });
    } catch (e) {
      this.busy = false;
      button.disabled = false;
      if (problem) {
        // A refusal, and refusals stay English (#539).
        problem.textContent = 'The wallet did not answer: ' +
          ((e && ((e as Json).name + ' ' + (e as Json).message)) || e);
        problem.hidden = false;
      }
      this.armedFor = String(view.state);
      if (query.qr === '1' && view.qr) {
        this.schedule(view, query);
      }
      return;
    }
    const body = WalletFlow.ids(view);
    body.response = JSON.stringify({ protocol: credential && credential.protocol,
                                     data: credential && credential.data });
    const answer = await this.surface.send(String(op.path)
      .replace('{state}', encodeURIComponent(String(view.state))), body);
    this.busy = false;
    this.follow(answer);
  }

  /**
   * Follows an act's answer: an address to go to, or the refusal drawn with
   * its view.
   *
   * @param answer - `{ status, json }`
   * @returns nothing
   */
  follow(answer: Json): void {
    const json = answer.json;
    if (json && json.ok && json.location) {
      this.env().location.assign(String(json.location));
      return;
    }
    const why = (json && ((json.errors || []).join(' ') ||
                          json.error_description)) ||
      'The service answered ' + answer.status + '.';
    this.surface.showView(json && json.view ? json.view : null, why);
  }
}

/**
 * The wallet sign-in's renderers, and the flow its pages run.
 */
class WebVcSigninModule {
  /**
   * The renderers.
   */
  static readonly Pages = WebVcSignin;
  /**
   * The runtime's half.
   */
  static readonly Flow = WalletFlow;
}

export = WebVcSigninModule;
