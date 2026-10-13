// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: consent_screen.ts
//
// ---------------------------------------------------------------------------
// THE SCREEN A PERSON SEES BEFORE ANYTHING IS ISSUED FOR A SCOPE THEY HAVE NOT
// AGREED TO.
//
// `common/consent.ts` is the REGISTER — what has been agreed, what is
// configured, and which of a request's scopes are outstanding. This file is the
// SCREEN: it holds the pending records, draws the page, and spends a record on
// Allow or Deny. The split is exactly `common/app_permissions.ts` /
// `admin-ui/admin.ts`'s and `common/delegation.js` / `delegation_map.js`'s —
// what something MEANS in one file, what it LOOKS like in another.
//
// ---------------------------------------------------------------------------
// IT IS `authn.js`'s SHAPE, DELIBERATELY, AND THAT IS THE WHOLE DESIGN.
//
// `beginConsent()` takes a `returnTo` on this service, mints a pending record,
// and answers with a path. The browser goes there, presses a button, and is
// sent BACK to `returnTo` — which is the authorization request, whole, exactly
// as it was. So the authorization endpoint keeps no state across the hop, for
// the reason it keeps none across the sign-in hop: the second pass is the same
// request over again, and everything it reads (PKCE, nonce, `claims`,
// `authorization_details`) is read from the query string both times.
//
// **THE RECORD IS SERVER-SIDE AND `returnTo` IS NEVER IN THE URL.** Same rule
// `federation_sp.ts`'s decision 3 states: a page carrying a return address
// anybody could rewrite is an open redirect with a heading on it. The only
// thing on the query string is an unguessable id.
//
// **`returnTo` IS CHECKED TO BE A PATH ON THIS SERVICE**, in `beginConsent()`,
// with the same two-character test `beginAuthentication()` uses — a leading `/`
// that is not `//`. A caller that gets it wrong is a bug in this service rather
// than a hostile request, so it throws rather than quietly sending somebody
// somewhere else.
//
// ---------------------------------------------------------------------------
// THREE THINGS ARE CHECKED WHEN THE SCREEN IS DRAWN, AND ONLY ONE OF THEM IS
// OBVIOUS.
//
//   * THE RECORD EXISTS AND HAS NOT EXPIRED. Ten minutes, the same window
//     `authn.js` gives a pending sign-in, because they are two halves of one
//     flow and a person who is slow at one is slow at the other.
//   * THE PERSON LOOKING AT IT IS THE PERSON IT WAS MINTED FOR. The record
//     names a username; the request carries a session cookie. If the session
//     ended, or somebody else's browser opened the link, the answer would be
//     recorded against the wrong entry — which is the one failure here that
//     writes a lie into the directory rather than merely refusing something.
//   * THE ANSWER IS POSTED, NEVER GOT. A GET that recorded consent would be a
//     consent anything that prefetches a link could give — a browser, a chat
//     client unfurling a URL, a security scanner. The screen is a GET and the
//     decision is a POST: since #576, `POST /authn-api/consent/{id}`.
//
// ---------------------------------------------------------------------------
// A PAGE OF THE SIGN-IN SURFACE SINCE #576 (#569's umbrella).
//
// Until #576 this module drew the page (two buttons in a form, no script)
// and took the form's POST. It is a static surface's page now, on #571's
// pattern (`authn/CLAUDE.md`): `GET /oauth2/consent` answers the SHELL after
// the three checks — refusing as it always did — and the sign-in surface's
// bundle, served here as `/oauth2/consent.js`, draws the page from
// `GET /authn-api/consent/{id}` (`consentView()`) and sends Allow or Deny to
// `POST /authn-api/consent/{id}` (`consentAct()`), bound by
// `authn/authn_api.ts` as every act there is: JSON, an Origin of this
// service, and the CSRF token of the browser's `sts_session` cookie.
// SCRIPT IS REQUIRED (rcbj on #569): the shell's `<noscript>` says so.
//
// NOTHING THE SCREEN DECIDES MOVED. The record, its three checks, the
// limits a person may lower, the record spent either way, the audit rows,
// the consent written and `consent_error` handed back are what the form's
// POST did; the answer that was a 303 now NAMES the address
// (`next: redirect`) and the page goes there with a GET. The authorization
// endpoint, its redirects and its response modes are untouched.
//
// The stylesheet is the card every page of the sign-in surface is drawn
// with (`/web/card.css`, `common/web_card_css.ts`), whose `.card.consent`
// rules are the ones this module appended to it while it drew the page. A
// person meets the sign-in screen and this screen in one flow, seconds
// apart, and two stylesheets would drift into looking like two services.
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, for a module that registers routes (rule 1): `ConsentScreen` takes
// the session owner, the consent register, the audit log and the rest through
// its constructor, and its `registerRoutes(app)` holds the GET (the shell
// since #576) and the page's script. The pending store stays module-level, declared at load as
// before. The module logs the line it always logged at load, and registers
// NOTHING (#50, R1): it exports `registerRoutes(app)`, which
// `common/protocol_stack.ts` calls at the point in the route order where
// requiring this module used to register the routes. Since R2 that root also
// builds the instance and installs it, and `registerRoutes`, `beginConsent`
// and `pendingFor` are FACADES that forward to it; a process that loads this
// module without the root builds a default instance at load. The module
// still exports `CONSENT_PATH`.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import app = require('../common/app');
// The pending-record clock, shared with the sign-in screen. See consentTtlMs().
import config = require('../common/config');
import realms = require('../common/realms');
import consent = require('../common/consent');
import applications = require('../common/applications');
import audit = require('../common/audit');
// The registry of error codes, a leaf. A refusal is MARKED on the response
// and never written into it.
import errorCodes = require('../common/error_codes');

// The input validator. A LEAF (rule 3): registers no route, closes no cycle.
import validation = require('../common/validation');
// The session, the answers and the sign-in surface's bundle. This module
// is required AFTER authn.js in `common/protocol_stack.ts`, so this is a cache
// hit — and since #50's R1 requiring a converted module registers nothing, so
// it could move no route from anywhere; and that module does not require this
// one, so there is no cycle.
import authn = require('../authn/authn');
// #432 phase 5: a detail's limits as controls the person can lower — the
// same ones GNAP's approval page draws. A static utility class, a leaf.
import LimitsForm = require('../common/limits_form');
// RFC 9396: what an authorization_details row says, and the one-time Allow.
// A library that registers nothing, so requiring it here moves no route.
import authorizationDetails = require('./authorization_details');
// The page's language (#539): the authorization request's `ui_locales`, the
// person, the client's locale policy. A library that registers nothing.
import PageLocale = require('../common/page_locale');

// The static surfaces' one shell writer (#570, #576).
import ShellDocument = require('../common/shell_document');
// Which listener this request arrived on, and whether it answers `/authn`
// (#472), for the language chooser's address. A LEAF.
import listenerMap = require('../common/listener_map');
// What a detail's limits say, row by row, for the view (#576).
import AccessLimits = require('../common/access_limits');

// A loose JSON-shaped object: a pending record, a row, an answer.
type Json = any;

// The express request and response, as far as this file reads them.
type Req = any;
type Res = any;

interface ConsentScreenDeps {
  log: typeof helpers.log;
  xmlEscape: typeof helpers.xmlEscape;
  parseBody: typeof helpers.parseBody;
  randomId: typeof helpers.randomId;
  oauthError: typeof helpers.oauthError;
  baseUrlOf: typeof helpers.baseUrlOf;
  config: typeof config;
  consent: typeof consent;
  // Not read here: required for the order it was always required in.
  applications: typeof applications;
  audit: typeof audit;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  authn: typeof authn;
  authorizationDetails: typeof authorizationDetails;
}

const vt = validation.types;
const vz = validation.z;

const CONSENT_PATH = '/oauth2/consent';

// THE PAGE'S SCRIPT (#576): the sign-in surface's bundle, at this page's
// own address.
const CONSENT_SCRIPT_PATH = '/oauth2/consent.js';

// Ten minutes, `authn.js`'s AUTHN_TTL_MS by intention rather than by accident:
// the two records are two halves of one interrupted request, and a consent that
// expired while the sign-in beside it had not would strand somebody halfway
// with no way to tell which half had gone.
//
// **SO IT READS THE SAME SETTING, SINCE 2026-09-12** — `authn.pendingTtlS`,
// which is that module's clock made configurable — rather than a second copy
// of the number. A consent row of its own was drafted and withdrawn the same
// day for exactly the sentence above: two settings that must agree are a
// setting and a comment claiming a match. The constant is the fallback for a
// process whose table predates the row.
const CONSENT_TTL_MS = 10 * 60 * 1000;

// ---------------------------------------------------------------------------
// PER REALM, BECAUSE EVERYTHING THIS RECORD POINTS AT IS.
//
// `returnTo` is a path inside one realm, the username is a person in that
// realm's directory, and the client_id names an entry in that realm's
// ou=applications. A process-wide Map would let a record minted in `acme` be
// spent in the default realm and write somebody's consent into the wrong
// directory — which is the exact failure `common/CLAUDE.md` describes for the
// stores that were left shared, and the reason `realms.map()` exists.
// ---------------------------------------------------------------------------
const pending = realms.map({ persist: 'consent_screen.pending',
                             retain: 'age',
                             // #333: the screen's `expires`, ms.
                             expiresAt: realms.expiryField('expires', 1) });

// ---------------------------------------------------------------------------
// WHAT THE CONSENT SCREEN TAKES: a pending id, and an answer.
//
// The id is `randomId()`'s base64url, and typing it is what stops
// `pendingFor(['a','b'])` reporting "this consent has expired" about a request
// that was malformed rather than stale — the same confusion the sign-in screen
// had, one door along.
//
// **THE ANSWER IS A CLOSED SET**, because it decides whether a credential is
// issued. Anything that is not `allow` or `deny` is not a third option this
// screen is willing to interpret.
// ---------------------------------------------------------------------------
const CONSENT_QUERY = vz.object({
  consent: vt.opt(vt.base64url)
});

// THE ANSWER'S BODY (#576) is `POST /authn-api/consent/{id}`'s, checked by
// `authn/authn_api.ts`: `action`, and the limit controls by their names.

/**
 * The OAuth consent screen at `/oauth2/consent`: the pending records, the page,
 * and Allow or Deny. What has been agreed is `common/consent.ts`'s.
 */
class ConsentScreen {
  /**
   * The consent screen's path.
   */
  static readonly CONSENT_PATH = CONSENT_PATH;

  /**
   * Builds the screen from its dependencies.
   *
   * @param deps - the helpers, consent register, audit log and other modules
   *   this class reads
   */
  constructor(private readonly deps: ConsentScreenDeps) {
    deps.log.debug("Entering ConsentScreen.constructor().");
    deps.log.debug("Leaving ConsentScreen.constructor().");
  }

  // What the composition root passes: the deps the module built its
  // own instance from before R2, from the same imports.
  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): ConsentScreenDeps {
    helpers.log.debug("Entering ConsentScreen.defaultDeps().");
    helpers.log.debug("Leaving ConsentScreen.defaultDeps().");
    return {
      log: helpers.log,
      xmlEscape: helpers.xmlEscape,
      parseBody: helpers.parseBody,
      randomId: helpers.randomId,
      oauthError: helpers.oauthError,
      baseUrlOf: helpers.baseUrlOf,
      config: config,
      consent: consent,
      applications: applications,
      audit: audit,
      errorCodes: errorCodes,
      validation: validation,
      authn: authn,
      authorizationDetails: authorizationDetails
    };
  }

  private consentTtlMs(): number {
    const { log, config } = this.deps;
    log.debug('Entering ConsentScreen.consentTtlMs().');
    let seconds = NaN;
    try {
      seconds = Number(config.value('authn.pendingTtlS'));
    } catch (e) {
      log.debug("Caught in ConsentScreen.consentTtlMs(): " +
                ((e && e.message) || e));
      // A table without the row — an older `config.js` beside this file. The
      // fallback is the number both clocks had before either was a setting,
      // so the two halves of an interrupted request still expire together.
      log.debug('consentTtlMs(): authn.pendingTtlS is not in this table (' +
                e.message + '); using the ten-minute default.');
    }
    log.debug('Leaving ConsentScreen.consentTtlMs().');
    return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) * 1000 :
           CONSENT_TTL_MS;
  }

  // -------------------------------------------------------------------------
  // BEGIN. Called by the authorization endpoint and by nothing else.
  //
  // It returns a PATH rather than performing the redirect, exactly as
  // `beginAuthentication()` does, so that the caller decides what its protocol
  // does with it — and so that this module never has to know that a
  // `form_post` response is not a redirect.
  // -------------------------------------------------------------------------
  /**
   * Mints a pending consent record for an authorization request and returns the
   * path the browser is sent to. Called by the authorization endpoint only.
   *
   * The browser is sent back to `returnTo`, the authorization request whole,
   * once the person answers; `returnTo` is kept server-side and never in the
   * URL.
   *
   * @param opts - `returnTo` (a path on this service), `username`, `clientId`,
   *   `clientName`, `scopes` (the outstanding rows), `already`, `details` and
   *   the other facts the screen shows
   * @returns the consent screen's path for the new record
   * @throws an Error when `returnTo` is not a path on this service
   */
  beginConsent(opts: Json): string {
    const { log, randomId } = this.deps;
    log.debug("Entering ConsentScreen.beginConsent().");
    const info = opts || {};
    const returnTo = String(info.returnTo || '');
    if (returnTo.charAt(0) !== '/' || returnTo.charAt(1) === '/') {
      log.debug("Leaving ConsentScreen.beginConsent(). Not a path here.");
      throw new Error('beginConsent() needs a path on this service to ' +
                      'return to, not "' +
                      returnTo + '".');
    }
    const record = {
      id: randomId(18),
      returnTo: returnTo,
      // WHO IS ANSWERING. Checked again when the screen is drawn and again
      // when the button is pressed — see the header. It is the normalised
      // local name, because that is what `consent.record()` will file the
      // answer under and a record naming one spelling while the write used
      // another would be a consent nobody could revoke.
      username: String(info.username || ''),
      clientId: String(info.clientId || ''),
      clientName: String(info.clientName || info.clientId || ''),
      // The rows `consent.outstanding()` produced: the scope, whether it
      // resolves to a defined delegated permission, and what somebody typed as
      // that permission's description. Carried whole rather than re-derived at
      // render time, so that what the person is shown is what was decided —
      // the same rule `authn.js`'s record follows for `forcePasswordless`.
      scopes: Array.isArray(info.scopes) ? info.scopes : [],
      // What the whole request asked for, including the scopes already
      // agreed. Shown under a fold, because "you already agreed to these
      // three" is the answer to the question somebody asks when a screen they
      // have seen before comes back with one line on it.
      already: Array.isArray(info.already) ? info.already : [],
      details: Array.isArray(info.details) ? info.details : [],
      // RFC 9396's rows, as `authorization_details.describe()` drew them, and
      // the digest Allow is recorded against. Asked EVERY time and never
      // remembered — see that module's header.
      authorizationDetails: Array.isArray(info.authorizationDetails)
        ? info.authorizationDetails : [],
      detailsDigest: String(info.detailsDigest || ''),
      // The details THEMSELVES (#432 phase 5), so a detail's limits can be
      // drawn as controls and read back lowered; `authorizationDetails`
      // above is how each is described.
      rawAuthorizationDetails: Array.isArray(info.rawAuthorizationDetails)
        ? info.rawAuthorizationDetails : [],
      protocol: String(info.protocol || 'OAuth 2.0 / OIDC'),
      // OpenID Connect Core 1.0 section 3.1.2.1 (#539): the languages the
      // relying party asked the consent screen to be drawn in. The caller
      // passes them; where it did not, the request the person resumes has
      // them on its query — `returnTo` is that request whole, unless it is a
      // request object, whose `ui_locales` is inside the JWT and is only
      // known to a caller that resolved it.
      uiLocales: String(info.uiLocales ||
                        ConsentScreen.uiLocalesOf(returnTo)),
      expires: Date.now() + this.consentTtlMs()
    };
    pending.set(record.id, record);
    pending.forEach(function (v, k) {
      if (v.expires < Date.now()) {
        pending.delete(k);
      }
    });
    log.info('consent: "' + record.username + '" is being asked whether "' +
             record.clientId + '" may have ' +
             record.scopes.map(function (one) {
               return one.scope;
             }).concat(record.authorizationDetails.map(function (one) {
               return 'authorization_details of type ' + one.type;
             })).join(', ') +
             ' on their behalf. Nothing is issued until they answer; ' +
             returnTo +
             ' is where they come back to.');
    log.debug("Leaving ConsentScreen.beginConsent(). " + record.id +
              " will return to " + returnTo + ".");
    return CONSENT_PATH + '?consent=' + encodeURIComponent(record.id);
  }

  // The `ui_locales` on a return path's query, or ''.
  private static uiLocalesOf(returnTo: string): string {
    helpers.log.debug("Entering ConsentScreen.uiLocalesOf().");
    const at = returnTo.indexOf('?');
    const out = at < 0 ? ''
      : String(new URLSearchParams(returnTo.slice(at + 1))
        .get('ui_locales') || '');
    helpers.log.debug("Leaving ConsentScreen.uiLocalesOf().");
    return out;
  }

  // The record a request names, or null. Expired ones are dropped on the way
  // past, which is the only cleanup this store needs beyond the sweep above —
  // `authn.js`'s `pendingFor()` exactly.
  /**
   * Returns the pending record a request names, dropping expired ones on the
   * way past.
   *
   * @param id - the record's id
   * @returns the record, or null
   */
  pendingFor(id: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering ConsentScreen.pendingFor(). id=" + (id || '(none)'));
    const record = pending.get(String(id || ''));
    if (!record) {
      log.debug("Leaving ConsentScreen.pendingFor(). No such consent is " +
                "pending.");
      return null;
    }
    if (record.expires < Date.now()) {
      pending.delete(record.id);
      log.debug("Leaving ConsentScreen.pendingFor(). It had expired.");
      return null;
    }
    log.debug("Leaving ConsentScreen.pendingFor(). Found it.");
    return record;
  }

  // -------------------------------------------------------------------------
  // WHO IS ACTUALLY HERE, AND IS IT THE PERSON THIS RECORD IS ABOUT?
  //
  // The session is read through `authn.js` rather than from a cookie here,
  // because that module owns what a session is. The comparison is on the
  // NORMALISED name, which is what `beginConsent()` was given and what
  // `consent.record()` files under — comparing the raw values would make
  // `alice` and `alice@EXAMPLE.COM` two people at this one door and one person
  // everywhere else.
  // -------------------------------------------------------------------------
  private answeredBy(req: Req, record: Json): Json {
    const { log, authn } = this.deps;
    log.debug("Entering ConsentScreen.answeredBy().");
    const session = authn.sessionOf(req);
    if (!session) {
      log.debug("Leaving ConsentScreen.answeredBy(). Nobody is signed in.");
      return { ok: false, why: 'nosession' };
    }
    // `session.user` is the CLAIMS OBJECT `helpers.userFor()` built, not a
    // string — this read was `session.user` for one afternoon and put
    // `[object Object]` on the screen where a name belongs. The typed name is
    // `username` on it, and it is normalised below exactly as the record's
    // was.
    const here = this.consentIdentity((session.user || {}).username);
    if (here !== this.consentIdentity(record.username)) {
      log.debug("Leaving ConsentScreen.answeredBy(). The session is " +
                "somebody else's.");
      return { ok: false, why: 'mismatch', who: here };
    }
    log.debug("Leaving ConsentScreen.answeredBy(). It is them.");
    return { ok: true, session: session, who: here };
  }

  // One normalisation, through the register, so that this file has no opinion
  // of its own about who somebody is.
  private consentIdentity(value: unknown): string {
    const { log, consent } = this.deps;
    log.debug("Entering ConsentScreen.consentIdentity().");
    log.debug("Leaving ConsentScreen.consentIdentity().");
    return consent.identityOf(value);
  }

  // -------------------------------------------------------------------------
  // THE PAGE IS DRAWN IN THE BROWSER SINCE #576.
  //
  // `/oauth2/consent` answers the sign-in surface's SHELL (`shell()`,
  // below), and `/authn/signin.js` — served here as `/oauth2/consent.js`
  // too — draws the page from `GET /authn-api/consent/{id}`, whose view is
  // `consentView()`: what `consentPage()` drew, as facts and no words.
  // What it shows, and why each part is on it, did not change:
  //
  //   * WHICH APPLICATION, by the name on its entry with the raw client_id
  //     under it. Both, because the name is what somebody recognises and the
  //     client_id is what the request actually carried — and a mock exists to
  //     show the difference between what a screen says and what a protocol
  //     sent.
  //   * ONE ROW PER SCOPE, with the permission's description where the scope
  //     resolves to one somebody defined. A screen that lists five opaque
  //     words is a screen that teaches a person to press Allow.
  //   * RFC 9396 section 11.2's SHOULD: every detail is shown, member by
  //     member, because the person is agreeing to THIS payment or THIS
  //     account access and a type name alone says nothing about the amount.
  //   * WHAT WAS ALREADY AGREED, under a `<details>`, so that a second visit
  //     explains itself.
  //   * A DETAIL'S LIMITS (#432 phase 5), which the person may lower: the
  //     limits themselves and `AccessLimits.rows()` of them, which the
  //     browser draws as the controls GNAP's approval page draws
  //     (`common/web_limits_form.ts`).
  //   * THE REQUEST'S OWN PARAMETERS at the foot, because this is a
  //     debugging tool and the redirect_uri is the thing somebody is usually
  //     here to check.
  //
  // IN THE PERSON'S LANGUAGE (#539), chosen in the browser from the
  // authorization request's `ui_locales` (`uiLocales` beside the view), the
  // person's own (`preferredLanguage`), the chooser, the browser's and the
  // client's locale policy (the shell's `data-sts-locale-default`). What the
  // request carried is data and is drawn as it is.
  // -------------------------------------------------------------------------
  /**
   * The consent screen's view: every fact the page is drawn from, and no
   * words.
   *
   * @param req - the request
   * @param record - the pending consent
   * @returns the view
   */
  consentView(req: Req, record: Json): Json {
    const { log, baseUrlOf, consent } = this.deps;
    log.debug("Entering ConsentScreen.consentView(). " +
              record.scopes.length + " scope(s).");
    const raw = Array.isArray(record.rawAuthorizationDetails)
      ? record.rawAuthorizationDetails : [];
    const view = {
      // The frame's marker: the card is drawn wider for the scope rows.
      consent: true,
      username: String(record.username || ''),
      base: baseUrlOf(req),
      client: { id: String(record.clientId || ''),
                name: String(record.clientName || '') },
      scopes: record.scopes.map(function (one: Json): Json {
        const p = one.permission;
        return { scope: String(one.scope),
                 permission: p ? { description: p.description || '',
                                   name: p.name || '',
                                   identifier: p.identifier || '',
                                   baseUri: p.baseUri || '' } : null };
      }),
      authorizationDetails: record.authorizationDetails.map(
        function (one: Json): Json {
          return { type: String(one.type || ''),
                   description: one.description || '',
                   resource: one.resourceName || one.resource || '',
                   audience: one.audience || '',
                   members: (one.members || []).map(function (m: Json) {
                     return { name: String(m.name), value: m.value == null
                       ? '' : String(m.value) };
                   }) };
        }),
      already: record.already.map(function (one: Json): Json {
        return { scope: String(one.scope), global: !!one.global,
                 at: one.at ? String(one.at) : '' };
      }),
      // Each detail that carries limits, by its index in the request — the
      // index the controls' names carry and `loweredDetails()` reads back.
      limits: raw.map(function (detail: Json, r: number): Json {
        return detail && typeof detail === 'object' && detail.limits &&
          typeof detail.limits === 'object'
          ? { r: r, type: String(detail.type || ''), limits: detail.limits,
              rows: AccessLimits.rows(detail.limits) }
          : null;
      }).filter(Boolean),
      attribute: consent.USER_ATTRIBUTE,
      protocol: String(record.protocol || ''),
      details: record.details.map(function (d: Json): Json {
        return { label: String(d.label), value: d.value == null ? ''
                   : String(d.value), note: d.note ? String(d.note) : '' };
      })
    };
    log.debug("Leaving ConsentScreen.consentView().");
    return view;
  }

  // -------------------------------------------------------------------------
  // THE THREE CHECKS, ASKED BY THE SHELL, THE VIEW AND THE ACT ALIKE: the
  // record exists and has not expired, and the session in this browser is
  // the person the question was asked of. Each refusal leaves the record
  // ALONE — a screen that spent itself on a refusal would turn each of them
  // into a denial of service against the person it was asked of — and
  // names its code (marked by the caller) and its sentence (English).
  // `answering` words the sentence for an answer rather than the page.
  // -------------------------------------------------------------------------
  /**
   * The pending consent a request may see or answer, or why not.
   *
   * @param req - the request
   * @param id - the consent's id
   * @param answering - the request is an answer, not the page
   * @returns `{ ok: true, record, who }`, or `{ ok: false, code, why }`
   */
  askedOf(req: Req, id: unknown, answering: boolean): Json {
    const { log } = this.deps;
    log.debug("Entering ConsentScreen.askedOf().");
    const record = this.pendingFor(id);
    if (!record) {
      log.debug("Leaving ConsentScreen.askedOf(). Nothing pending.");
      return { ok: false, code: 'STS-OAUTH-0149', why: answering
        ? 'This consent form has expired, or it has already been answered. ' +
          'Start the request again from the application that sent you here.'
        : 'There is no consent waiting under that id, or it has expired. ' +
          'Start the request again from the application that sent you ' +
          'here — nothing was issued and nothing was recorded.' };
    }
    const who = this.answeredBy(req, record);
    if (!who.ok) {
      log.debug("Leaving ConsentScreen.askedOf(). " + who.why + ".");
      return { ok: false,
        code: who.why === 'nosession' ? 'STS-OAUTH-0150' : 'STS-OAUTH-0151',
        why: who.why === 'nosession'
          ? (answering
            ? 'Nobody is signed in here any more, so this answer belongs to ' +
              'nobody. Nothing was recorded.'
            : 'Nobody is signed in here any more, so there is nobody to ' +
              'record an answer for. Start the request again from the ' +
              'application that sent you here.')
          : (answering
            ? 'This consent was asked of "' + record.username + '" and ' +
              'this browser is signed in as "' + who.who + '". Nothing was ' +
              'recorded.'
            : 'This consent was asked of "' + record.username + '" and the ' +
              'session in this browser belongs to "' + who.who + '". It is ' +
              'refused rather than recorded against whoever happens to be ' +
              'signed in, which is the one failure at this door that would ' +
              'write something untrue into the directory.') };
    }
    log.debug("Leaving ConsentScreen.askedOf(). It is them.");
    return { ok: true, record: record, who: who };
  }

  // -------------------------------------------------------------------------
  // #432 PHASE 5: A DETAIL'S LIMITS, WHICH THE PERSON MAY LOWER. RFC 9396
  // lets a detail carry `limits` (an amount, a count, an interval …), and
  // the person agreeing to it may agree to LESS — as on GNAP's approval page,
  // with the same controls (`common/limits_form.ts`): each detail carrying
  // limits gets them inside the form, `allow` reads them back, and only a
  // lower value is accepted. The details as lowered are recorded with the
  // Allow and are what the authorization endpoint's next pass issues.
  // Since #576 the controls' values arrive as members of the act's JSON
  // body, under the names the controls carry.
  // -------------------------------------------------------------------------
  // The details as the person lowered their limits: `{ ok, lowered }`
  // (lowered null when nothing changed), or `{ ok: false, code, why }`.
  private loweredDetails(req: Req, body: Json, record: Json): Json {
    const { log, authorizationDetails } = this.deps;
    log.debug("Entering ConsentScreen.loweredDetails().");
    const raw = Array.isArray(record.rawAuthorizationDetails)
      ? record.rawAuthorizationDetails : [];
    if (!raw.length) {
      log.debug("Leaving ConsentScreen.loweredDetails(). No details.");
      return { ok: true, lowered: null };
    }
    const read = LimitsForm.lowered([{ access: raw }], [{ access: raw }], {
      value: function (name: string): string | undefined {
        return typeof body[name] === 'string' ? body[name] : undefined;
      },
      values: function (name: string): string[] {
        return helpers.bodyValues(req, body, name);
      }
    }, function (tokens: Json[]): Json {
      // The catalogue's own reading (RFC 9396 and GNAP alike).
      const detail = tokens[0].access[0];
      const entry = authorizationDetails.typeOf(detail.type);
      const found = entry ? authorizationDetails.conformance(detail, entry,
        'the lowered authorization detail') : { kind: '' };
      return found.kind ? { why: found.problem } : null;
    });
    if (!read.ok) {
      log.debug("Leaving ConsentScreen.loweredDetails(). " + read.code);
      return { ok: false, code: read.code === 'STS-GNAP-0867'
                 ? 'STS-OAUTH-0919' : 'STS-OAUTH-0918', why: read.why };
    }
    const lowered = read.tokens[0].access;
    const changed = JSON.stringify(lowered) !== JSON.stringify(raw);
    log.debug("Leaving ConsentScreen.loweredDetails(). changed=" + changed);
    return { ok: true, lowered: changed ? lowered : null };
  }

  // -------------------------------------------------------------------------
  // BACK TO THE AUTHORIZATION REQUEST.
  //
  // The form's answer was a 303 — `returnToCaller()`'s reason in `authn.js`,
  // the redirect that follows a POST — and since #576 the act's answer NAMES
  // that address (`next: redirect`), which the page goes to with a GET:
  // what a 303 did. The address is the one `res.location()` would have
  // sent (`authn.locationOf()`: the realm's prefix, the listener that
  // answers it), so the two cannot differ.
  //
  // A REFUSAL RIDES BACK ON `consent_error`, which the authorization endpoint
  // reads exactly as it reads `authn_error`: this module names the outcome and
  // THAT module decides what OAuth does about it, because `redirectBack()`
  // knows about `response_mode` and in `form_post` the answer is not a
  // redirect at all. Putting the error in the client's redirect_uri from here
  // would be this file making a protocol decision it has no way to make
  // correctly.
  // -------------------------------------------------------------------------
  private backToCaller(res: Res, record: Json, error: string | null,
                       description: string | null): void {
    const { log, authn } = this.deps;
    log.debug("Entering ConsentScreen.backToCaller(). error=" +
              (error || '(none)'));
    let target = record.returnTo;
    if (error) {
      target += (target.indexOf('?') === -1 ? '?' : '&') +
        'consent_error=' + encodeURIComponent(error) +
        '&consent_error_description=' + encodeURIComponent(description || '');
    }
    authn.answerJson(res, 200, { ok: true, next: 'redirect',
                                 location: authn.locationOf(res, target) });
    log.debug("Leaving ConsentScreen.backToCaller(). Named " + target + ".");
  }

  // A refusal of an answer, in the vocabulary every refusal at this door
  // used (`oauthError()`'s members), with `ok: false` and `errors` beside
  // them, as `/authn-api`'s refusals are. The code was marked by the caller;
  // it is never in the body.
  // error-code: none — the definition of this helper; every call site marks its own code first
  private refused(res: Res, status: number, why: string): void {
    const { log, authn } = this.deps;
    log.debug("Entering ConsentScreen.refused(). " + status);
    authn.answerJson(res, status, { ok: false, next: 'refused',
                                    errors: [why], error: 'invalid_request',
                                    error_description: why });
    log.debug("Leaving ConsentScreen.refused().");
  }

  // -------------------------------------------------------------------------
  // THE ANSWER: `POST /authn-api/consent/{id}` (#576), bound by
  // `authn/authn_api.ts` (JSON, an Origin of this service, the CSRF token of
  // the browser's session) and its body checked there; what it decides is
  // what the form's POST decided, moved whole.
  //
  // THE RECORD IS SPENT EITHER WAY, before anything is written or anybody
  // is sent anywhere. A consent id that survived being answered would be one
  // a back button could answer a second time, and on Allow that is a second
  // write of something already agreed; on Deny it is an `access_denied`
  // delivered twice to a client that has already given up.
  // -------------------------------------------------------------------------
  /**
   * Answers a pending consent: Allow (with the limits a person lowered) or
   * Deny. The answer names the authorization request to go back to.
   *
   * @param req - the request
   * @param res - the response
   * @param id - the consent's id
   * @param body - the act's JSON: `action` and the limit controls
   * @returns nothing
   */
  consentAct(req: Req, res: Res, id: string, body: Json): void {
    const { log, consent, audit, errorCodes, authorizationDetails } =
      this.deps;
    log.debug("Entering ConsentScreen.consentAct().");
    const asked = this.askedOf(req, id, true);
    if (!asked.ok) {
      errorCodes.mark(res, asked.code);
      this.refused(res, 400, asked.why);
      log.debug("Leaving ConsentScreen.consentAct(). " + asked.code);
      return;
    }
    const record = asked.record;
    // THE LIMITS, before the record is spent: a value raised or no longer
    // meeting its type is refused, and the page can be answered again.
    let lowered: Json = null;
    if (String(body.action || '') === 'allow') {
      const read = this.loweredDetails(req, body, record);
      if (!read.ok) {
        errorCodes.mark(res, read.code === 'STS-OAUTH-0919'
          ? 'STS-OAUTH-0919' : 'STS-OAUTH-0918');
        // error-code: none — marked on the line above
        this.refused(res, 400, read.why);
        log.debug("Leaving ConsentScreen.consentAct(). The limits.");
        return;
      }
      lowered = read.lowered;
    }
    pending.delete(record.id);

    const names = record.scopes.map(function (one) {
      return one.scope;
    }).concat(record.authorizationDetails.map(function (one) {
      return 'authorization_details:' + one.type;
    }));
    if (String(body.action || '') !== 'allow') {
      audit.record({
        action: 'consent.deny', actor: record.username,
        target: record.clientId,
        protocol: 'OAuth 2.0 / OIDC', channel: 'http', outcome: 'refused',
        errorCode: 'STS-OAUTH-0152',
        detail: 'refused ' + names.join(', ')
      });
      log.info('consent: "' + record.username + '" refused "' +
               record.clientId + '" the scope(s) ' + names.join(', ') +
               '. Nothing was recorded and nothing was issued; the ' +
               'client is told access_denied.');
      errorCodes.mark(res, 'STS-OAUTH-0152');
      this.backToCaller(res, record, 'access_denied',
        'The user did not consent to ' + names.join(' ') + '.');
      log.debug("Leaving ConsentScreen.consentAct(). Denied.");
      return;
    }

    // RFC 9396: Allow on details is ONE answer for ONE request, recorded
    // here and spent by the authorization endpoint's second pass. The
    // scopes are written down as they always were; the details never are.
    if (record.detailsDigest) {
      authorizationDetails.noteConsented(record.username, record.clientId,
                                         record.detailsDigest, lowered);
    }
    const written = consent.record(record.username, record.clientId,
      record.scopes.map(function (one) {
        return one.scope;
      }));
    audit.record({
      action: 'consent.grant', actor: record.username,
      target: record.clientId,
      protocol: 'OAuth 2.0 / OIDC', channel: 'http',
      outcome: written.stored ? 'success' : 'warning',
      detail: 'consented ' + names.join(', ') +
              (written.stored ? '' :
               ' (not written down: ' + (written.reason || 'no entry') +
               ', so they will be asked again)')
    });
    this.backToCaller(res, record, null, null);
    log.debug("Leaving ConsentScreen.consentAct(). Allowed.");
  }

  // -------------------------------------------------------------------------
  // THE SHELL (#576): what `/oauth2/consent` answers once the three checks
  // pass, through `common/shell_document.ts` (3cl's recipe), loading the
  // sign-in surface's bundle from `/oauth2/consent.js` — this page's own
  // listener's address for it, so the page's script is served wherever
  // the OAuth 2.0 / OpenID Connect application is mapped (#472), and
  // `/authn-api/consent` is that application's too
  // (`common/hosted_applications.js`).
  //
  // SCRIPT IS REQUIRED (rcbj on #569): no form is drawn here for a browser
  // without it — the `<noscript>` says so — and no submit button stands in
  // for the script. The policy is the shell's: `script-src 'self'`,
  // `connect-src 'self'` (and the sign-in service's origin where it is on
  // another listener, for the language chooser), `style-src 'self'`,
  // `frame-ancestors` re-added by `app.contentSecurityPolicy()` whatever is
  // asked.
  // -------------------------------------------------------------------------
  /**
   * Sends the consent screen's shell document.
   *
   * @param req - the request
   * @param res - the response
   * @param record - the pending consent
   * @returns nothing
   */
  private shell(req: Req, res: Res, record: Json): void {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering ConsentScreen.shell().");
    const authnAt = listenerMap.isTrivial() ||
      listenerMap.admits(listenerMap.listenerOf(req), 'authn')
      ? '' : baseUrlOf(req, 'authn');
    const html = ShellDocument.document({
      title: 'Allow access? — IYA STS',
      attributes: ([['data-sts-prefix', realms.currentPrefix()],
                    ['data-sts-authn', authnAt]] as Array<[string, string]>)
        .concat(PageLocale.shellAttributes(req,
                                           String(record.clientId || ''))),
      stylesheets: ['/web/card.css'],
      script: CONSENT_SCRIPT_PATH,
      open: '<div class="card consent">',
      close: '</div>',
      noscript: '<h1>Allow access?</h1><div class="err">This consent page ' +
        'is a script that runs in your browser, and with scripts blocked ' +
        'there is nothing it can show. Allow scripts for this page to ' +
        'answer it.</div>',
      loading: '<p class="sub">Loading&hellip;</p>'
    });
    ShellDocument.serve(app, req, res, html, {
      connect: ShellDocument.originsOf([authnAt]),
      csp: { 'style-src': "'self'" } });
    log.debug("Leaving ConsentScreen.shell().");
  }

  /**
   * Registers `GET /oauth2/consent` — the shell — and `GET
   * /oauth2/consent.js`, the sign-in surface's bundle at this page's own
   * address. The answer is `/authn-api/consent`'s (#576); `POST
   * /oauth2/consent` is gone.
   *
   * @param app - the express app
   */
  registerRoutes(app: Json): void {
    const { log, oauthError, errorCodes, validation, authn } = this.deps;
    const self = this;
    log.debug("Entering ConsentScreen.registerRoutes().");

    // -----------------------------------------------------------------------
    // GET — the shell, after the three checks, which refuse as they always
    // did (400, `invalid_request`) so that a stale or borrowed link says why
    // without a script.
    // -----------------------------------------------------------------------
    app.get(CONSENT_PATH, function (req, res) {
      log.debug("Entering the consent screen.");
      const asked = validation.check(req, 'query', CONSENT_QUERY);
      if (!asked.ok) {
        log.debug("Leaving the consent screen. The request is malformed.");
        errorCodes.mark(res, 'STS-OAUTH-0148');
        return oauthError(res, 400, 'invalid_request', asked.detail);
      }
      const found = self.askedOf(req, asked.value.consent, false);
      if (!found.ok) {
        log.debug("Leaving the consent screen. " + found.code + ".");
        errorCodes.mark(res, found.code);
        // error-code: none — marked on the line above, askedOf()'s code
        return oauthError(res, 400, 'invalid_request', found.why);
      }
      self.shell(req, res, found.record);
      log.debug("Leaving the consent screen. The shell, for " +
                found.record.scopes.length + " scope(s).");
    });

    // THE PAGE'S SCRIPT: the sign-in surface's bundle, brotli, gzip or
    // neither by the request's Accept-Encoding, read once by `authn.ts`.
    app.get(CONSENT_SCRIPT_PATH, function (req, res) {
      log.debug("Entering the consent screen's script.");
      ShellDocument.sendFile(req, res, authn.signInBundle(),
                             'application/javascript');
      log.debug("Leaving the consent screen's script.");
    });

    log.debug("Leaving ConsentScreen.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<ConsentScreen>(
  'oauth-oidc/consent_screen',
  () => new ConsentScreen(ConsentScreen.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

helpers.log.info('The consent screen is registered at ' + CONSENT_PATH +
                 '. The authorization endpoint sends a person here before ' +
                 'it issues anything for a scope they have not agreed to ' +
                 'for that application, and they come back to the request ' +
                 'they interrupted.');

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The OAuth consent screen, a sign-in-like hop the authorization endpoint sends
 * a person through before issuing for an outstanding scope.
 *
 * The composition root builds the instance and calls `registerRoutes()`.
 *
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  ConsentScreen: ConsentScreen,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   * Refused once an instance is installed or a default built.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: ConsentScreen): void => slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  CONSENT_PATH: ConsentScreen.CONSENT_PATH,
  beginConsent: slot.forward('beginConsent'),
  pendingFor: slot.forward('pendingFor'),
  // `/authn-api/consent/{id}`'s view and act (#576), for `authn_api.ts`.
  askedOf: slot.forward('askedOf'),
  consentView: slot.forward('consentView'),
  consentAct: slot.forward('consentAct'),
  CONSENT_SCRIPT_PATH: CONSENT_SCRIPT_PATH
};
