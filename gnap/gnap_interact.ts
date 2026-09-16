'use strict';
//
// File: gnap_interact.ts
//
// ---------------------------------------------------------------------------
// THE PAGES A RESOURCE OWNER SEES: WHERE A GNAP INTERACTION STARTS, WHERE THEY
// SIGN IN, WHERE THEY DECIDE, AND HOW THE CLIENT IS TOLD.
//
// RFC 9635 section 4 leaves consent "deliberately flexible", and this service
// runs the shape nearly every AS runs:
//
//   GET  /gnap/interact/:id   the `redirect` start mode (section 4.1.1)
//   GET  /gnap/app/:id        the `app` start mode (section 4.1.4) — an https
//                             URI a native app can hand to the system browser
//   GET  /gnap/code           the static user code page (section 4.1.2), and
//   POST /gnap/code           the short dynamic `user_code_uri` (section
//                             4.1.3)
//   GET  /gnap/approve/:id    sign-in, then the approval page
//   POST /gnap/approve/:id    the resource owner's answer, then the finish
//                             method
//
// Every start mode spends itself and leads to ONE approval page per grant, so
// the rule of section 4.1 — once a start mode has completed, every other must
// be refused — is a property of the grant rather than of four handlers.
//
// ---------------------------------------------------------------------------
// SIGN-IN IS THE ONE AUTHENTICATION SERVICE (the user's requirement).
//
// `authn.beginAuthentication()` with `protocol: 'GNAP'` and the client's
// application identifier, exactly as `/oauth2/authorize` and `/saml2/sso` call
// it — so the sign-in screen's mechanism choice, second factors, federation and
// SPNEGO all apply, the session it mints is the one every other protocol reads
// (single sign-on in both directions), CAEP's `session-established` fires, and
// `startSession()` records the authentication, which is what puts the person's
// entry in the embedded directory (ldap_server.js's observer). A GNAP-specific
// sign-in would have been a second answer to every one of those.
//
// **`notePresented(session, 'GNAP', req)` is called where an EXISTING session
// is honoured**, below every refusal, as the four browser SSO profiles do —
// that is CAEP's `session-presented` (tests/caep_presented_every_protocol.js
// reads the literal call).
//
// ---------------------------------------------------------------------------
// THE APPROVAL PAGE IS GNAP'S OWN, AND THE CONSENT REGISTER IS NOT.
//
// `/oauth2/consent` draws scope strings and writes `oauthConsent` values keyed
// by scope. A GNAP right is an OBJECT (section 8) as often as a string, and the
// resource owner may untick individual rights (section 4: "allow the RO to
// modify the client instance's requested access, including limiting ... that
// access"), which that page cannot express. So the page is drawn here, with the
// sign-in screen's own stylesheet, and the ANSWER goes into the same consent
// register as digest tokens (gnap_grants.ts's header).
//
// **UNLIKE `/oauth2/consent`, THE ANSWER IS CSRF-CHECKED.** The approval page
// is reached from a URI a client chose to send a browser to, which is exactly
// the setup a cross-site form post exploits: a page elsewhere that auto-submits
// "approve" for a signed-in person. The token is `websecurity.field()`'s, bound
// to the session.
//
// **NO PAGE HERE HAS A SCRIPT** (root CLAUDE.md, *Seven pages here have a
// script*): every control is a form, and a client logo is drawn only when it is
// a `data:` image, which `img-src 'self' data:` allows — an external logo URI
// is shown as a link, because fetching it would be the "client-hosted logo"
// section 11.16 warns about, and CSP would refuse it anyway.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, for a module that registers routes (rule 1): `GnapInteract` takes
// the sign-in service, the stores and the rest through its constructor, and
// its `registerRoutes(app)` holds the six routes in their old order. The
// TRANSITIONAL instance below is built from the real modules and registers
// them at load, where the file registered them before.
//
// **THE APPROVAL ROUTES ARE WRITTEN LAST, AND THEIR HANDLERS INLINE**, because
// `tests/cluster_followups.js` reads this file from the approval route to its
// end and counts the calls that record a decision there.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import config = require('../common/config');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import validation = require('../common/validation');
import websecurity = require('../common/websecurity');
import authn = require('../authn/authn');
import store = require('./gnap_store');
import grants = require('./gnap_grants');
import monitor = require('./gnap_monitor');

type Req = import('express').Request;
type Res = import('express').Response;
type Next = import('express').NextFunction;
type Handler = (req: Req, res: Res, next?: Next) => unknown;

interface GnapInteractDeps {
  config: typeof config;
  log: typeof helpers.log;
  xmlEscape: typeof helpers.xmlEscape;
  parseBody: typeof helpers.parseBody;
  bodyValues: typeof helpers.bodyValues;
  nowSec: typeof helpers.nowSec;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  websecurity: typeof websecurity;
  authn: typeof authn;
  store: typeof store;
  grants: typeof grants;
  monitor: typeof monitor;
}

// The routes' own table of what an express app offers.
interface RouteTable {
  get(path: string, ...handlers: Handler[]): unknown;
  post(path: string, ...handlers: Handler[]): unknown;
}

const vz = validation.z;
const vt = validation.types;

const ID_PARAMS = vz.object({ id: vt.base64url });
const APPROVE_QUERY = vz.object({
  authn_error: vt.opt(vt.token),
  authn_error_description: vt.opt(vt.text)
});
const APPROVE_FORM = vz.object({
  action: vt.opt(vt.oneOf(['allow', 'deny'])),
  subject: vt.opt(vt.oneOf(['yes'])),
  right: vt.repeatable(vt.token).optional(),
  csrf_token: vt.opt(vt.token)
});
const CODE_FORM = vz.object({
  code: vt.opt(vt.text),
  csrf_token: vt.opt(vt.token)
});

const PAGE_CSS =
  '.card{width:520px}p.app{font-size:.9em;margin:0 0 ' +
  '14px}ul.rights{list-style:none;padding:0;margin:0 0 8px}ul.rights ' +
  'li{padding:8px 10px;margin:6px 0;border:1px solid ' +
  '#e3e3ea;border-radius:6px;background:#fafafd;font-size:.85em}ul.rights li ' +
  'label{display:flex;gap:8px;align-items:flex-start}ul.rights li ' +
  'span{display:block;color:#666;font-size:.9em;margin-top:3px}' +
  'img.logo{max-width:48px;max-height:48px;float:right;margin:0 0 6px 8px}' +
  'input.code{font-size:1.4em;letter-spacing:.2em;text-transform:uppercase;' +
  'width:100%}';

class GnapInteract {
  constructor(private readonly deps: GnapInteractDeps) {
    deps.log.debug("Entering GnapInteract.constructor().");
    deps.log.debug("Leaving GnapInteract.constructor().");
  }

  private sendPage(res: Res, status: number, title: string,
                   inner: string): void {
    const { log, xmlEscape, authn } = this.deps;
    log.debug("Entering GnapInteract.sendPage().");
    const html = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
                 'charset="utf-8"><title>' +
      xmlEscape(title) + ' — GNAP authorization server</title><style>' +
                 authn.CARD_CSS + PAGE_CSS +
      '</style></head><body><div class="card">' + inner +
                 '</div></body></html>\n';
    res.status(status)
       .type('text/html')
       .set('Cache-Control', 'no-store')
       .send(html);
    log.debug("Leaving GnapInteract.sendPage().");
  }

  // Section 4.1.1/4.1.2: a URI or code that names no active request gets an
  // error SHOWN, and the browser is NEVER sent back to any client.
  // error-code: none — the helper's definition, not a call to it.
  private interactionError(res: Res, code: string, heading: string,
                           detail: string): void {
    const { log, errorCodes, xmlEscape } = this.deps;
    log.debug("Entering GnapInteract.interactionError().");
    errorCodes.mark(res, code);
    // error-code: none — the helper's own send; every caller passes its STS-GNAP code, marked on the line above.
    this.sendPage(res, 400, heading, '<h1>' + xmlEscape(heading) + '</h1><p ' +
        'class="err">' +
             xmlEscape(detail) + '</p><div class="meta"><div>Nothing was ' +
             'approved and nothing was sent to any application. Start again ' +
             'from the application that sent you here.</div></div>');
    log.debug("Leaving GnapInteract.interactionError().");
  }

  private activeForInteraction(grant: any): boolean {
    const { log, store, nowSec } = this.deps;
    log.debug("Entering GnapInteract.activeForInteraction().");
    log.debug("Leaving GnapInteract.activeForInteraction().");
    return grant && grant.state === store.STATE.PENDING &&
      grant.interaction && !grant.interaction.decided &&
      grant.interaction.expiresAt >= nowSec();
  }

  // -------------------------------------------------------------------------
  // START MODES. Each spends itself and forwards to the one approval page.
  // -------------------------------------------------------------------------
  // ASYNCHRONOUS SINCE 2026-09-14 (#46): a start link is spent through
  // `store.spend()` before it is honoured, so two nodes cannot both follow
  // one. The handler is wrapped in `settled()` so a defect is a coded 500
  // rather than an unhandled rejection, which is what `gnap.ts`'s `guarded()`
  // does for the JSON endpoints.
  private startMode(mode: string): Handler {
    const self = this;
    const { log, validation, store, nowSec } = this.deps;
    log.debug("Entering GnapInteract.startMode().");
    log.debug("Leaving GnapInteract.startMode().");
    return this.settled('the GNAP ' + mode + ' start',
                        async function (req, res) {
      log.debug("Entering the GNAP " + mode + " start.");
      const params = validation.checkParsed({ id: req.params.id }, 'params',
                                            ID_PARAMS);
      const grant: any = params.ok ?
        store.grantByInteraction(mode + ':' + params.value.id) : null;
      if (!self.activeForInteraction(grant)) {
        log.debug("Leaving the GNAP " + mode + " start. No active request.");
        return self.interactionError(res, 'STS-GNAP-0400',
          'This link is not active',
          'The link does not belong to a request that is still waiting for ' +
          'approval — it may have expired, been used already, or been ' +
          'answered.');
      }
      const one = grant.interaction.modes[mode];
      if (!one || one.used || one.id !== params.value.id) {
        log.debug("Leaving the GNAP " + mode + " start. Already used.");
        return self.interactionError(res, 'STS-GNAP-0401', 'This link has ' +
                                     'already been used',
          'Each interaction link works once (RFC 9635 section 4).');
      }
      // ONCE ACROSS THE CLUSTER (#46): `one.used` is a field on a replicated
      // grant, so another node still reading the grant before this start
      // would follow the same link. Claimed for the interaction's own
      // lifetime.
      const spent: any = await store.spend('interaction', mode + ':' +
                                           params.value.id,
                                           grant.interaction.expiresAt -
                                             nowSec(),
                                           'STS-GNAP-0712');
      if (!spent.ok) {
        log.debug("Leaving the GNAP " + mode + " start. Spent elsewhere.");
        return self.interactionError(res, spent.reason === 'used' ?
                                     'STS-GNAP-0712' : 'STS-GNAP-0716',
                                     'This link has already been used',
          'Each interaction link works once (RFC 9635 section 4).');
      }
      one.used = true;
      grant.interaction.started = grant.interaction.started || mode;
      store.dropInteraction(mode + ':' + params.value.id);
      store.saveGrant(grant, 'interaction started by ' + mode);
      log.debug("Leaving the GNAP " + mode + " start. To the approval page.");
      return res.set('Cache-Control', 'no-store')
                .redirect(303, '/gnap/approve/' +
                               grant.interaction.approvalId);
    });
  }

  // An asynchronous page handler, with its failure caught and coded.
  private settled(name: string, handler: Handler): Handler {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapInteract.settled().");
    log.debug("Leaving GnapInteract.settled().");
    return function (req, res, next) {
      Promise.resolve().then(function () {
        return handler(req, res, next);
      }).catch(function (e) {
        log.debug("Caught in GnapInteract.settled(): " +
                  ((e && e.message) || e));
        log.error(errorCodes.tag('STS-GNAP-0160') + 'gnap: ' + name +
                  ' failed: ' + ((e && e.stack) || e));
        if (!res.headersSent) {
          self.interactionError(res, 'STS-GNAP-0160', 'Something went wrong',
                                'The request could not be completed.');
        }
      });
    };
  }

  // -------------------------------------------------------------------------
  // USER CODES (sections 4.1.2 and 4.1.3).
  // -------------------------------------------------------------------------
  private codePage(req: Req, res: Res, status: number,
                   problem: string): void {
    const { log, authn, xmlEscape, websecurity } = this.deps;
    log.debug("Entering GnapInteract.codePage().");
    const session = authn.sessionOf(req);
    this.sendPage(res, status, 'Enter your code',
      '<h1>Enter the code</h1><p class="sub">The code your device or ' +
      'application is showing ' +
      'you.</p>' +
      (problem ? '<p class="err">' + xmlEscape(problem) + '</p>' : '') +
      '<form method="post" action="/gnap/code">' +
      websecurity.field(session ? session.id : '') +
      '<input class="code" name="code" autocomplete="one-time-code" ' +
      'autofocus ' +
      'required><div class="row"><button ' +
      'type="submit">Continue</button></div></form><div ' +
      'class="meta"><div>Spaces and dashes are ignored, and letters may be ' +
      'typed in either case (RFC 9635 section 4.1.2).</div></div>');
    log.debug("Leaving GnapInteract.codePage().");
  }

  // -------------------------------------------------------------------------
  // THE APPROVAL PAGE.
  // -------------------------------------------------------------------------
  private describeRight(right: any): string {
    const { log, store, xmlEscape } = this.deps;
    log.debug("Entering GnapInteract.describeRight().");
    if (typeof right === 'string') {
      const registered: any = store.resourceByReference(right);
      log.debug("Leaving GnapInteract.describeRight().");
      return '<code>' + xmlEscape(right) + '</code><span>' + (registered
        ? 'a resource set registered by <code>' +
          xmlEscape(registered.rsIdentifier) + '</code>: ' +
          xmlEscape(registered.access.map(function (one) {
            return typeof one === 'string' ? one : one.type;
          }).join(', '))
        : 'an access reference this authorization server attaches no ' +
          'further meaning to') +
        '</span>';
    }
    const parts = [];
    ['actions', 'datatypes', 'locations', 'privileges'].forEach(
        function (dimension) {
      if (right[dimension] && right[dimension].length) {
        parts.push(dimension + ': ' + right[dimension].join(', '));
      }
    });
    if (right.identifier) {
      parts.push('identifier: ' + right.identifier);
    }
    log.debug("Leaving GnapInteract.describeRight().");
    return '<code>' + xmlEscape(right.type) + '</code><span>' +
      xmlEscape(parts.join('; ') || 'every action this API defines') +
      '</span>';
  }

  private approvalPage(req: Req, res: Res, grant: any, session: any): void {
    const self = this;
    const { log, xmlEscape, websecurity } = this.deps;
    log.debug("Entering GnapInteract.approvalPage().");
    const display = grant.client.display || {};
    const logo = display.logoUri && /^data:image\//i.test(display.logoUri)
      ? '<img class="logo" alt="" src="' + xmlEscape(display.logoUri) + '">'
      : '';
    let rows = '';
    grant.request.tokens.forEach(function (token, t) {
      rows += (grant.request.tokens.length > 1 || token.label
        ? '<li><strong>Token ' + xmlEscape(token.label || String(t + 1)) +
          '</strong>' +
          (token.bearer ? ' — a bearer token, usable by whoever holds it' :
           '') + '</li>' : '');
      token.access.forEach(function (right, r) {
        rows += '<li><label><input type="checkbox" name="right" value="t' +
          t + 'r' + r +
          '" checked><span>' + self.describeRight(right) +
          '</span></label></li>';
      });
    });
    const subjectAsked = grant.request.subject &&
      (grant.request.subject.subIdFormats.length ||
       grant.request.subject.assertionFormats.length);
    if (subjectAsked) {
      rows += '<li><label><input type="checkbox" name="subject" value="yes" ' +
        'checked><span><strong>Who you are</strong><span>identifiers (' +
        xmlEscape(grant.request.subject.subIdFormats.join(', ') || 'none') +
        ') ' +
            'and assertions (' +
        xmlEscape(grant.request.subject.assertionFormats.join(', ') ||
                  'none') +
        ')</span></span></label></li>';
    }
    const finish = grant.interaction.finish;
    const inner = logo + '<h1>Allow access?</h1>' +
      '<p class="sub">Signed in as <code>' +
      xmlEscape(session.user.username) +
      '</code></p><p ' +
      'class="app"><strong>' +
      xmlEscape(display.name || grant.client.identifier) +
      '</strong> is asking for access on your behalf.' +
      (display.uri ? '<br><a href="' + xmlEscape(display.uri) + '" ' +
          'rel="noreferrer">' +
        xmlEscape(display.uri) + '</a>' : '') + '</p>' +
      '<form method="post" action="/gnap/approve/' +
      xmlEscape(grant.interaction.approvalId) + '">' +
      websecurity.field(session.id) +
      '<ul class="rights">' + (rows || '<li>Nothing specific — this ' +
        'request ' +
        'asks only to be continued.</li>') + '</ul><div class="row"><button ' +
      'type="submit" id="gnap-allow" name="action" ' +
      'value="allow">Allow</button><button type="submit" id="gnap-deny" ' +
      'name="action" value="deny" ' +
      'class="secondary">Deny</button></div></form><div ' +
      'class="meta"><div>Untick anything you do not want to allow; the ' +
      'application receives only what stays ticked (RFC 9635 section ' +
      '4).</div>' +
      (finish ? '<div>Afterwards ' + (finish.method === 'redirect'
        ? 'you are sent back to <code>' + xmlEscape(finish.uri) + '</code>.'
        : 'the application is notified directly at <code>' +
          xmlEscape(finish.uri) + '</code>.') + '</div>'
        : '<div>Afterwards you can close this page and return to the ' +
          'application.</div>') +
      '<div>Client instance: <code>' + xmlEscape(grant.client.identifier) +
      '</code> ' +
          '· proof: <code>' +
      xmlEscape(grant.client.proof) + '</code>' +
      (grant.client.classId ? ' · ' +
          'class: <code>' +
      xmlEscape(grant.client.classId) + '</code>' : '') + '</div>' +
      '<div>Authorization server: <code>' + xmlEscape(grant.grantEndpoint) +
      '</code></div></div>';
    this.sendPage(res, 200, 'Allow access?', inner);
    log.debug("Leaving GnapInteract.approvalPage().");
  }

  // What the browser sees once the decision is made and the finish followed.
  private afterDecision(res: Res, grant: any, finished: any): unknown {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering GnapInteract.afterDecision().");
    if (finished.redirect) {
      log.debug("Leaving GnapInteract.afterDecision().");
      // Section 11.19: 303, so a POST carrying the form is not replayed at the
      // client's callback.
      return res.set('Cache-Control', 'no-store')
                .redirect(303, finished.redirect);
    }
    const approved = grant.decision && grant.decision.approved;
    const name = (grant.client.display &&
                  grant.client.display.name) || grant.client.identifier;
    log.debug("Leaving GnapInteract.afterDecision().");
    return this.sendPage(res, 200, approved ? 'Approved' : 'Not approved',
      '<h1>' + (approved ? 'You approved the request' : 'The request was ' +
                                                        'not ' +
                                                        'approved') +
      '</h1><p ' +
      'class="sub">' + (finished.pushed === true
        ? xmlEscape(name) + ' has been told.'
        : (finished.pushed === false
          ? xmlEscape(name) + ' could not be told directly; it will find ' +
                              'out when it next checks.'
          : 'Return to ' + xmlEscape(name) + '; it will pick up the ' +
            'answer.')) +
      '</p>');
  }

  // -------------------------------------------------------------------------
  // ONE DECISION PER INTERACTION ACROSS THE CLUSTER (2026-09-14, #46
  // follow-up).
  //
  // `activeForInteraction()` refuses a grant whose `interaction.decided` is
  // set, and that field is on a REPLICATED grant: two answers to one approval
  // page — a double submit, or the same form posted to two nodes — each found
  // the grant undecided, each recorded a decision, each enacted the finish
  // method, and the grant kept whichever write landed last, possibly a denial
  // after the client had been told of an approval. So a decision is claimed
  // through `store.spend()` for the interaction's own lifetime before it is
  // recorded; the second is refused (`STS-GNAP-0717`, or `STS-GNAP-0716` when
  // the store cannot be asked), and a decision that then fails to complete
  // gives its claim back. Resolves to the claim, or null once the refusal has
  // been answered.
  // -------------------------------------------------------------------------
  private async claimDecision(res: Res, grant: any): Promise<any> {
    const { log, store, nowSec } = this.deps;
    log.debug("Entering GnapInteract.claimDecision().");
    const spent: any = await store.spend('decision', grant.id + ':' +
                                         grant.interaction.approvalId,
                                         grant.interaction.expiresAt -
                                           nowSec(),
                                         'STS-GNAP-0717');
    if (!spent.ok) {
      this.interactionError(res, spent.reason === 'used' ? 'STS-GNAP-0717' :
                            'STS-GNAP-0716',
                            'This request has already been answered',
        'An answer to this request has already been recorded — on this page ' +
        'in another tab, or by a second submission of it. It is answered ' +
        'once.');
      log.debug("Leaving GnapInteract.claimDecision(). Refused.");
      return null;
    }
    log.debug("Leaving GnapInteract.claimDecision(). Claimed.");
    return spent;
  }

  private approvalGrant(req: Req, res: Res): any {
    const { log, validation, store } = this.deps;
    log.debug("Entering GnapInteract.approvalGrant().");
    const params = validation.checkParsed({ id: req.params.id }, 'params',
                                          ID_PARAMS);
    const grant: any = params.ok ?
      store.grantByInteraction('approve:' + params.value.id) : null;
    if (!this.activeForInteraction(grant) || !grant.interaction.started) {
      this.interactionError(res, 'STS-GNAP-0406',
        'This request is not waiting for you',
        'There is no request waiting for approval at this address, or it ' +
        'was already answered or has expired.');
      log.debug("Leaving GnapInteract.approvalGrant().");
      return null;
    }
    log.debug("Leaving GnapInteract.approvalGrant().");
    return grant;
  }

  // The six routes, in the order this file has always registered them.
  registerRoutes(app: RouteTable): void {
    const self = this;
    const { log, config, validation, parseBody, bodyValues, errorCodes,
            websecurity, grants, store, monitor, authn, nowSec } = this.deps;
    const { notePresented } = authn;
    log.debug("Entering GnapInteract.registerRoutes().");

    app.get('/gnap/interact/:id', self.startMode('redirect'));
    app.get('/gnap/app/:id', self.startMode('app'));

    app.get('/gnap/code', function (req, res) {
      log.debug("Entering GET /gnap/code.");
      if (config.value('gnap.enabled') === false) {
        log.debug("Leaving GET /gnap/code. Off.");
        return self.interactionError(res, 'STS-GNAP-0402',
                                     'GNAP is turned off',
                                     'This trust realm does not run GNAP ' +
                                     '(gnap.enabled).');
      }
      self.codePage(req, res, 200, '');
      log.debug("Leaving GET /gnap/code.");
      return undefined;
    });

    app.post('/gnap/code', self.settled('POST /gnap/code',
                                        async function (req, res) {
      log.debug("Entering POST /gnap/code.");
      const posted = validation.checkParsed(parseBody(req), 'body',
                                            CODE_FORM);
      if (!posted.ok) {
        log.debug("Leaving POST /gnap/code. Malformed.");
        errorCodes.mark(res, 'STS-GNAP-0403');
        return self.codePage(req, res, 400, posted.detail);
      }
      // Section 4.1.2: "If the AS detects too many unrecognized code enter
      // attempts, the interaction component SHOULD display an error". Counted
      // per address, because the code is what is being guessed and has no
      // owner yet. COUNTED AGAINST ONE BUDGET FOR THE CLUSTER (#46):
      // `attemptShared()`.
      const allowed: any = await websecurity.attemptShared('gnap-user-code',
                                                           req, '');
      if (!allowed.ok) {
        log.debug("Leaving POST /gnap/code. Rate limited.");
        errorCodes.mark(res, errorCodes.codeOf(allowed) || 'STS-GNAP-0404');
        return self.codePage(req, res, 429,
                             'Too many codes have been tried from here. ' +
                             allowed.detail);
      }
      const code = grants.normaliseUserCode(posted.value.code);
      const grant: any = code ? store.grantByUserCode(code) : null;
      const mode = grant && grant.interaction && grant.interaction.modes
        ? (grant.interaction.modes.user_code &&
           grant.interaction.modes.user_code.code === code ? 'user_code'
          : (grant.interaction.modes.user_code_uri &&
             grant.interaction.modes.user_code_uri.code === code
            ? 'user_code_uri' : null)) : null;
      if (!self.activeForInteraction(grant) || !mode) {
        log.debug("Leaving POST /gnap/code. Unknown code.");
        errorCodes.mark(res, 'STS-GNAP-0405');
        return self.codePage(req, res, 400, 'That code is not recognised, ' +
                             'or it has expired.');
      }
      // ONCE ACROSS THE CLUSTER (#46). Both user-code modes of a grant are
      // spent together below, so what is claimed is "a user code of this
      // grant was entered" — one claim however the End-User reached it.
      const codeSpent: any = await store.spend('user-code', grant.id,
                                               grant.interaction.expiresAt -
                                                 nowSec(),
                                               'STS-GNAP-0713');
      if (!codeSpent.ok) {
        log.debug("Leaving POST /gnap/code. Spent elsewhere.");
        errorCodes.mark(res, codeSpent.reason === 'used' ? 'STS-GNAP-0713' :
                        'STS-GNAP-0716');
        return self.codePage(req, res, 400, 'That code is not recognised, ' +
                             'or it has expired.');
      }
      await websecurity.succeededShared('gnap-user-code', req, '',
                                        { keepAddress: true });
      ['user_code', 'user_code_uri'].forEach(function (one) {
        if (grant.interaction.modes[one]) {
          grant.interaction.modes[one].used = true;
        }
      });
      grant.interaction.started = grant.interaction.started || mode;
      store.dropUserCode(code);
      store.saveGrant(grant, 'interaction started by ' + mode);
      log.debug("Leaving POST /gnap/code. To the approval page.");
      return res.set('Cache-Control', 'no-store')
                .redirect(303, '/gnap/approve/' +
                               grant.interaction.approvalId);
    }));

    app.get('/gnap/approve/:id', function (req, res) {
      log.debug("Entering GET /gnap/approve.");
      const grant = self.approvalGrant(req, res);
      if (!grant) {
        log.debug("Leaving GET /gnap/approve. No grant.");
        return undefined;
      }
      const query = validation.check(req, 'query', APPROVE_QUERY);
      if (query.ok && query.value.authn_error) {
        // The person cancelled the sign-in screen. Section 4.2: the finish
        // method is still enacted, with the grant recording the denial.
        log.debug("Leaving GET /gnap/approve. Sign-in cancelled.");
        return self.claimDecision(res, grant).then(function (claimed) {
          if (!claimed) {
            return undefined;
          }
          grant.interaction.decided = true;
          grant.decision = { approved: false, error: 'user_denied' };
          monitor.record(grant.client.identifier, 'grant.denied',
                         { gnapError: 'user_denied' });
          return grants.finishInteraction(req, grant)
            .then(function (finished) {
              store.saveGrant(grant, 'sign-in cancelled');
              return self.afterDecision(res, grant, finished);
            });
        });
      }
      const session = authn.sessionOf(req);
      if (!session) {
        log.debug("Leaving GET /gnap/approve. To the sign-in screen.");
        return res.set('Cache-Control', 'no-store')
                  .redirect(303, authn.beginAuthentication({
          returnTo: '/gnap/approve/' + grant.interaction.approvalId,
          protocol: 'GNAP',
          application: grant.client.identifier,
          hint: grant.userHint || '',
          details: [
            { label: 'Application',
              value: (grant.client.display && grant.client.display.name) ||
              grant.client.identifier },
            { label: 'Protocol', value: 'GNAP (RFC 9635)' }
          ]
        }));
      }
      // An EXISTING session is being honoured: CAEP session-presented.
      notePresented(session, 'GNAP', req);
      if (grants.rememberedFor(grant, session.user.username)) {
        log.debug("Leaving GET /gnap/approve. Already approved before.");
        return self.claimDecision(res, grant).then(function (claimed) {
          if (!claimed) {
            return undefined;
          }
          return grants.decide(req, grant, session,
                               { approve: true, tokens: grant.request.tokens,
                                 subject: false })
            .then(function (finished) {
              return self.afterDecision(res, grant, finished);
            }, function (e) {
              log.debug("Caught in GET /gnap/approve: " +
                        ((e && e.message) || e));
              store.unspend(claimed.handle);
              throw e;
            });
        });
      }
      self.approvalPage(req, res, grant, session);
      log.debug("Leaving GET /gnap/approve. Page drawn.");
      return undefined;
    });

    app.post('/gnap/approve/:id', function (req, res) {
      log.debug("Entering POST /gnap/approve.");
      const grant = self.approvalGrant(req, res);
      if (!grant) {
        log.debug("Leaving POST /gnap/approve. No grant.");
        return undefined;
      }
      const session = authn.sessionOf(req);
      if (!session) {
        log.debug("Leaving POST /gnap/approve. No session; back to the " +
                  "page.");
        return res.redirect(303, '/gnap/approve/' +
                                 grant.interaction.approvalId);
      }
      const body = parseBody(req);
      const csrf: any = websecurity.checkCsrf(session.id, body);
      if (!csrf.ok) {
        log.debug("Leaving POST /gnap/approve. CSRF.");
        errorCodes.mark(res, errorCodes.codeOf(csrf) || 'STS-GNAP-0407');
        return self.interactionError(res, 'STS-GNAP-0407', 'This answer ' +
                                     'could not be accepted',
          'The form did not come from this page (its anti-forgery token is ' +
          'missing or wrong).');
      }
      // `right` is a CHECKBOX COLUMN, one per access right, so it arrives
      // once per ticked box — and `parseBody()` keeps only the last. The
      // repeated values are read off the raw body and handed to the schema as
      // the array they are.
      const ticked = bodyValues(req, body, 'right');
      const posted = validation.checkParsed(Object.assign({}, body,
                                                          { right: ticked }),
                                            'body',
                                            APPROVE_FORM);
      if (!posted.ok) {
        log.debug("Leaving POST /gnap/approve. Malformed: " + posted.detail);
        return self.interactionError(res, 'STS-GNAP-0408', 'This answer ' +
                                     'could not be read', posted.detail);
      }
      const approve = posted.value.action === 'allow';
      const tokens = grant.request.tokens.map(function (token, t) {
        return { label: token.label, bearer: token.bearer,
                 access: token.access.filter(function (right, r) {
          return ticked.indexOf('t' + t + 'r' + r) >= 0;
        }) };
      });
      const anything = tokens.some(function (token) {
        return token.access.length;
      }) || posted.value.subject === 'yes';
      let claimedDecision = null;
      return self.claimDecision(res, grant).then(function (claimed) {
        if (!claimed) {
          log.debug("Leaving POST /gnap/approve. Already answered.");
          return undefined;
        }
        claimedDecision = claimed;
        return grants.decide(req, grant, session, {
          approve: approve && anything,
          tokens: tokens,
          subject: posted.value.subject === 'yes'
        }).then(function (finished) {
          log.debug("Leaving POST /gnap/approve. Decided.");
          return self.afterDecision(res, grant, finished);
        });
      }).catch(function (e) {
        log.debug("Caught in GnapInteract.registerRoutes(): " +
                  ((e && e.message) || e));
        if (claimedDecision) {
          store.unspend(claimedDecision.handle);
        }
        log.error(errorCodes.tag('STS-GNAP-0409') + 'gnap: the approval ' +
                  'could not be completed: ' +
                  (e && e.stack || e));
        return self.interactionError(res, 'STS-GNAP-0409',
                                     'Something went wrong',
                                     'The answer could not be completed.');
      });
    });

    log.debug("Leaving GnapInteract.registerRoutes().");
  }
}

// THE TRANSITIONAL INSTANCE — see the header above. Built from the real
// modules, and its routes registered at load, where they always were.
const interaction = new GnapInteract({
  config: config,
  log: helpers.log,
  xmlEscape: helpers.xmlEscape,
  parseBody: helpers.parseBody,
  bodyValues: helpers.bodyValues,
  nowSec: helpers.nowSec,
  errorCodes: errorCodes,
  validation: validation,
  websecurity: websecurity,
  authn: authn,
  store: store,
  grants: grants,
  monitor: monitor
});
interaction.registerRoutes(app);

export = {
  GnapInteract: GnapInteract
};
