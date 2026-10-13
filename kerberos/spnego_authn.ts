// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: spnego_authn.ts
//
// ---------------------------------------------------------------------------
// SPNEGO AS A WAY OF SIGNING IN — Kerberos, over HTTP, producing the SESSION
// that every protocol family in this service reads.
//
// `/spnego/protected` next door has authenticated people since the day it was
// written, and then thrown the identity away: it prints a table saying who the
// ticket named and stops. This module is the same handshake with the last step
// added. Past it, a person who holds a Kerberos ticket has a browser session
// here, and `/oauth2/authorize`, `/wsfed`, `/saml2/sso`, `/saml11/sso`,
// `/federation` and `/admin` all see it — because they all read the one session
// `authn.js` owns and none of them is told how it was established.
//
// **IT IS AVAILABLE TO EVERY APPLICATION AND NOTHING HAS TO BE CONFIGURED FOR
// IT.** There are three ways in and they are three different amounts of
// configuration, which is the same ladder federation already has:
//
//   1. A BUTTON ON THE SIGN-IN SCREEN, offered to every application that ever
//      reaches it (`krb5.spnegoLoginButton`). Nothing is registered, nothing
//      is named: whatever flow is in progress carries on afterwards, because
//      the button hands this door the pending record the screen was drawn
//      from.
//   2. `appAuthnMechanism: spnego` ON THE APPLICATION ENTRY, which is home
//      realm discovery by configuration — that application's people never see
//      the screen at all.
//   3. `fedAuthnMechanism: spnego` ON AN IDENTITY-PROVIDER-SIDE FEDERATION
//      RELATIONSHIP, which answers a different question: when THAT partner
//      asks this service to authenticate somebody, integrated Kerberos is
//      what happens. A SAML 2.0 partner satisfied by a Kerberos ticket, with
//      the partner never learning it.
//
// All three land here, and all three arrive the same way: with an `?authn=`
// naming a pending record `authn.js` minted. See the endpoint below.
//
// ---------------------------------------------------------------------------
// WHY THIS IS A DOOR OF ITS OWN AND NOT A BRANCH INSIDE `authn.js`.
//
// Because of the require order, and it is a dependency rather than a
// preference. `authn.js` is #8 — before `oauth2.js`, which reads the session it
// owns — and every Kerberos module is at #15 and below, because the KDC's
// listeners and the acceptor's socket must not be dragged to the front of the
// router by something the authorization endpoint depends on. A require from
// `authn.js` to this file would do exactly that, and would close a cycle
// besides, since this file requires `authn.js` for `startSession()`. #50's R1
// did not change that: this file registers nothing when required any more,
// but it requires `./spnego.js`, a JavaScript file (this repository's own,
// copied by the parent's tests image) that still registers its routes when
// it is required.
//
// **AND IT NEEDED NO INVERTED HOOK EITHER**, which is worth saying because rule
// 3e's inventory already holds many slots and one more is the obvious move. It
// is not needed here: the only two things `authn.js` has to know are the PATH
// and whether the door is open. The path is `/authn/spnego` — a path in the
// space that module already owns, so it declares the constant and this file
// imports it — and whether the door is open is `krb5.spnegoAuthentication`, a
// setting both files read from `config.js`. A slot costs a reader an
// indirection every time, and rule 3e's own test is whether a require would
// close a cycle or move a route. Here nothing has to point anywhere: two files
// read one constant and one setting.
//
// ---------------------------------------------------------------------------
// WHAT IS CHECKED, AND WHY THAT IS NOT THE INTERESTING SENTENCE.
//
// Everything `krb5_service.js` checks, which is nine things and includes the
// replay cache — so a captured AP-REQ cannot be replayed into a second session.
// Not one line of that is here, and not one line of RFC 4178 is here either:
// `spnego_exchange.js` performs the negotiation and this module renders and
// signs in. That split exists precisely so that the sign-in and the page
// documenting it cannot come to disagree about what was checked.
//
// **THE INTERESTING SENTENCE IS THE OTHER ONE.** In development mode this
// service checks no password anywhere — the username typed at `/authn/login`
// IS the identity — and Kerberos is the one family where that is impossible,
// because the password there IS the key. So in development a session minted
// here is the ONLY kind in this service that rests on a credential the service
// genuinely verified. (Product mode verifies passwords too; see the root
// CLAUDE.md's *Things this service deliberately does not do*.)
// `krb5_principals.js` makes the KDC as permissive as the protocol allows (one
// password shared by every user account, an account created for any name on
// first sight), which keeps the mock a mock — but the verification is real, and
// the difference between "any name is accepted" and "any name is accepted once
// it has been to the KDC" is the whole of what this door adds.
//
// ---------------------------------------------------------------------------
// TRUST REALMS: THIS DOOR IS PER REALM, AND SINCE 2026-09-15 SO IS THE KDC.
//
// `/realm/acme/authn/spnego` mints a session in `acme` — the ambient-realm
// middleware strips the prefix before the router sees the URL, and
// `startSession()` writes into whichever realm's partition is ambient, so this
// module needed no realm code at all and has none. A session minted in `acme`
// does not satisfy the default realm's `/oauth2/authorize`, exactly as every
// other sign-in here behaves.
//
// **AND SINCE 2026-09-15 THE KDC BEHIND IT IS PER REALM TOO.** This paragraph
// read *what is NOT per realm is the KDC … so every realm here trusts the SAME
// principal database and the same long-term keys, and a ticket good for one
// realm's door is good for all of them*. It is not: each trust realm whose
// Kerberos is on has a Kerberos realm name of its own, and the acceptor behind
// this door refuses a ticket from a realm the door's trust realm does not
// serve (STS-KRB-0126). So a ticket good for `acme`'s door is good for `acme`,
// and the session this module mints in `acme` was authenticated by `acme`'s
// KDC. A realm with Kerberos OFF has no acceptor to reach: every ticket is
// refused there, whoever issued it.
//
// ---------------------------------------------------------------------------
// THE FALLBACK IS PART OF THE DESIGN AND NOT AN AFTERTHOUGHT.
//
// A 401 carrying `WWW-Authenticate: Negotiate` and nothing else is a dead end
// for most browsers: Chrome and Firefox use Negotiate only for hosts on an
// explicit allow-list, and the machine needs a credential cache in the realm
// besides. A person who meets that on the way into an application is stuck with
// no way back. So every refusal here draws a PAGE with a link to
// `/authn/login?authn=<the same record>` on it — the sign-in they were already
// having, resumed — which is what real intranet sites do and is the reason
// `?authn=` is carried through rather than being spent on arrival.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `SpnegoAuthn` takes the modules it uses through its constructor
// (`SpnegoAuthnDeps`). Since #50's R2 the composition root builds the
// instance; the module's old names are FACADES forwarding to it, for the
// callers that are not converted, and a process without the root builds a
// default at load.
// `SpnegoAuthn` is exported beside them for that root.
//
// **THE ROUTES ARE REGISTERED BY `registerRoutes()`**, and not at load
// (#50, R1): the module exports it, and `common/protocol_stack.ts` calls it at
// the point in the route order where requiring this module used to register
// the first route, so rule 1's order is unchanged.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
const { log, xmlEscape } = helpers;
import config = require('../common/config');
// THE SESSION. This is the dependency that decides where this file sits in the
// require order — see the header. `authn.js` requires nothing in this directory
// and must not, so the arrow points one way only.
import authn = require('../authn/authn');
import principals = require('./krb5_principals.js');
import spnego = require('./krb5_spnego.js');
import exchange = require('./spnego_exchange.js');
// The shell and the check table. See that module's export list for why the
// sign-in door wears the debugger page's look rather than the sign-in screen's.
import spnegoPage = require('./spnego.js');
// ERROR CODES, a leaf. A negotiation's refusal is marked by
// exchange.applyVerdict(); the three marked here are this door's own.
import errorCodes = require('../common/error_codes');
// THE LANGUAGE OF THE PAGE (#539). Libraries: the catalogs, the request's
// language and the chooser, and the realm prefix the chooser posts under.
import i18n = require('../common/i18n');
import PageLocale = require('../common/page_locale');
import realms = require('../common/realms');
// THE SIGN-IN SURFACE'S SHELL (#575): the document three of this door's
// bodies are now, with the state its page is drawn from. A library.
import ShellDocument = require('../common/shell_document');

type Translator = InstanceType<typeof i18n.Translator>;

const page = spnegoPage.page;
const checksTable = spnegoPage.checksTable;

// The path, from the module that owns `/authn/*`. Imported rather than spelled
// again here: `authn.js` builds a redirect to it and draws a button pointing at
// it, and a string spelled in two files is a string that drifts.
/**
 * The path of the SPNEGO sign-in, `authn`'s `SPNEGO_PATH`.
 */
const SPNEGO_PATH = authn.SPNEGO_PATH;

// What the console and the audit log call a sign-in that came through here. It
// names the PROTOCOL rather than the flow that was interrupted, exactly as
// federation's `via` does: what a reader of /admin/users wants to know is how
// this person proved who they are, and the flow they were signing in TO is on
// the record's own `protocol`, which the note below carries.
const VIA = 'Kerberos v5 (SPNEGO)';

// What `SpnegoAuthn` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface SpnegoAuthnDeps {
  log: typeof log;
  xmlEscape: typeof xmlEscape;
  config: typeof config;
  authn: typeof authn;
  principals: typeof principals;
  spnego: typeof spnego;
  exchange: typeof exchange;
  errorCodes: typeof errorCodes;
  page: typeof page;
  checksTable: typeof checksTable;
  SPNEGO_PATH: typeof SPNEGO_PATH;
}

type RouteApp = typeof app;

/**
 * SPNEGO as a way of signing in: the Negotiate handshake at `/authn/spnego`,
 * ending in the session every protocol family reads.
 */
class SpnegoAuthn {
  /**
   * Builds the sign-in over the given dependencies.
   *
   * @param deps - the modules it uses
   */
  constructor(private readonly deps: SpnegoAuthnDeps) {
    deps.log.debug("Entering SpnegoAuthn.constructor().");
    deps.log.debug("Leaving SpnegoAuthn.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  /**
   * Returns the dependencies the composition root passes, from the real
   * modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): SpnegoAuthnDeps {
    helpers.log.debug("Entering SpnegoAuthn.defaultDeps().");
    helpers.log.debug("Leaving SpnegoAuthn.defaultDeps().");
    return {
      log: log,
      xmlEscape: xmlEscape,
      config: config,
      authn: authn,
      principals: principals,
      spnego: spnego,
      exchange: exchange,
      errorCodes: errorCodes,
      page: page,
      checksTable: checksTable,
      SPNEGO_PATH: SPNEGO_PATH
    };
  }

  // ---------------------------------------------------------------------------
  // THE NAME THE SESSION IS FOR, out of the principal the ticket named.
  //
  // `krb5_service.js` hands back `alice@EXAMPLE.COM` — the client name joined
  // with '/' and the ticket's realm after an '@' — and what goes in the session
  // is `alice`, when and only when that realm is THIS KDC's own.
  //
  // **THE STRIPPING IS THE POINT AND IT IS NOT COSMETIC.** The session's
  // username names the entry whose `urn:uuid:<entryUUID>` is the `sub` of every
  // token, assertion and credential that follows. Leaving the realm on would
  // mean that somebody who types `alice` at the sign-in screen and the same
  // person arriving with a ticket are TWO SUBJECTS as far as every relying
  // party is concerned — which is the exact failure this service's
  // one-entry-per-person rule exists to prevent,
  // and the exact shape of the defect the first federated sign-in shipped with
  // (a foreign subject reaching `startSession()` unnormalised).
  //
  // **A FOREIGN REALM KEEPS ITS REALM**, and that asymmetry is deliberate.
  // `bob@PARTNER.COM` arriving over a cross-realm ticket is not this
  // service's `bob`, and issuing a token that says he is would be an assertion
  // nothing here has any basis for. What happens instead is worth knowing
  // rather than discovering: `admin_stats.js`'s `identityOf()` splits at the
  // last '@' for filing purposes, so the DIRECTORY still folds the two onto one
  // entry and the Realms column says which realms were folded. The directory
  // answers "which human is this" and the token answers "who am I asserting" —
  // they are allowed to differ, and this is one of the few places where they
  // do.
  //
  // A multi-component name (`a/b@REALM`) is kept whole before the '@', because
  // a service principal signing in is unusual but not wrong and the components
  // ARE the name.
  // ---------------------------------------------------------------------------
  /**
   * Returns the username a session is for, from the principal a ticket named:
   * the realm is stripped only when it is this KDC's own, case-sensitively.
   *
   * @param clientPrincipal - the client principal, `name@REALM`
   * @returns the username
   */
  usernameFor(clientPrincipal) {
    const { log, principals } = this.deps;
    log.debug('Entering SpnegoAuthn.usernameFor(). principal=' +
              clientPrincipal);
    const text = String(clientPrincipal || '');
    const at = text.lastIndexOf('@');
    if (at <= 0) {
      log.debug('Leaving SpnegoAuthn.usernameFor(). No realm on it.');
      return text;
    }
    const realm = text.slice(at + 1);
    // Case-sensitively. Kerberos realms are case-sensitive by specification and
    // `EXAMPLE.COM` and `example.com` are two realms — folding them here would
    // be this module deciding a question the KDC did not.
    if (realm !== principals.REALM) {
      log.debug('Leaving SpnegoAuthn.usernameFor(). A foreign realm, kept ' +
                'whole.');
      return text;
    }
    log.debug('Leaving SpnegoAuthn.usernameFor(). ' + text.slice(0, at));
    return text.slice(0, at);
  }

  // ---------------------------------------------------------------------------
  // WHAT THE SESSION CLAIMS, READ OFF THE TICKET'S OWN FLAGS.
  //
  // This is the one place in this service where `amr` and `acr` are DERIVED
  // from something a credential actually says, rather than from what somebody
  // ticked on a screen — so it is worth being exact about what the two flags
  // mean, since both are easy to over-read.
  //
  //   pre-authent   RFC 4120 section 2.1: the KDC verified pre-authentication
  //                 before issuing the initial ticket. On this KDC that is
  //                 PA-ENC-TIMESTAMP, a timestamp encrypted under the client's
  //                 long-term key — which is derived from a password. So `pwd`,
  //                 RFC 8176's "password-based authentication", is the honest
  //                 value: a password WAS proven, to the KDC, at some point in
  //                 this credential's lineage.
  //   hw-authent    section 2.1 again: "the protocol employed for initial
  //                 authentication required the use of hardware expected to be
  //                 possessed solely by the named client". That is `hwk` —
  //                 proof-of-possession of a hardware key — and nothing else in
  //                 RFC 8176 fits it.
  //
  // NEITHER FLAG IS NOT A FAILURE. A ticket carrying neither is one this KDC
  // issued without pre-authentication, which is a configuration a real KDC can
  // have and which this one can be made to produce; the honest answer is then
  // an EMPTY `amr` and an `acr` of "0", which is RFC 6711's way of saying no
  // level of assurance is being claimed. Filling in `pwd` there would be this
  // service telling a relying party that a password was checked when nothing
  // anywhere knows whether one was.
  //
  // **THE FLAGS ARE ON THE TICKET AND THE TICKET MAY BE SECOND-HAND.** A
  // service ticket obtained from a TGT inherits `pre-authent` from the AS
  // exchange that produced the TGT, which may have been hours ago — that is
  // Kerberos's model and not a weakness here, and it is exactly what `authTime`
  // on the session then means. What a ticket does NOT carry is the `initial`
  // flag once it has been through the TGS, so `initial` is reported on the page
  // and used for nothing: it says the credential was minted at the AS exchange,
  // which is interesting to a person and is not an authentication method.
  //
  // **AND THE AUTHENTICATION INDICATORS (RFC 8129, #173, 2026-09-22).** A
  // ticket whose TGT came from FAST with OTP pre-authentication carries the
  // indicator `otp` — the KDC checked the password AND an authenticator app's
  // code in one AS exchange (kerberos/krb5_fast.ts) — and the acceptor reads
  // it only from an AD-CAMMAC whose verifier checks under its own key. That is
  // `otp` in `amr`, beside `pwd`, and `acr "mfa"`: the same two claims the
  // sign-in screen makes after `/authn/totp`, from the same verifier. RFC 8129
  // section 5 says an indicator must be read with the realm that wrote it, so
  // `ownRealm` is false for a ticket from a foreign realm and its indicators
  // count for nothing.
  //
  // **AND PKINIT (#179, 2026-10-05).** A ticket whose TGT came from a
  // certificate carries `pkinit`, and `pre-authent` — but NO password was
  // proven, so `pre-authent` is not `pwd` on it. The certificate is `swk`, as
  // `/tls/sign-in` says of one, unless the KDC also wrote `pkinit-hardware`:
  // a smart-card logon certificate over a key this service did not generate
  // (krb5_pkinit.ts's header), with hw-authent set, which is `hwk`. One
  // factor either way, so `acr "1"` — rcbj's answer on #179.
  // ---------------------------------------------------------------------------
  /**
   * Derives the session's `amr` and `acr` from a ticket's own flags and
   * authentication indicators: `pwd` for pre-authent, `hwk` for hw-authent,
   * `otp` for the RFC 8129 indicator from this realm, `swk` for a PKINIT
   * certificate not marked hardware-bound (and never `pwd` for one); `mfa`
   * only for two.
   *
   * @param ticketFlags - the ticket's flag names
   * @param indicators - the ticket's authentication indicators
   * @param ownRealm - false for a ticket from a foreign realm, whose indicators
   *   count for nothing
   * @returns `{ amr, acr, method, password, hardware, otp, pkinit }`
   */
  factorsFor(ticketFlags, indicators?, ownRealm?) {
    const { log } = this.deps;
    log.debug('Entering SpnegoAuthn.factorsFor(). flags=' +
              (ticketFlags || []).join(',') + ' indicators=' +
              (indicators || []).join(','));
    const flags = ticketFlags || [];
    const own = ownRealm !== false ? (indicators || []) : [];
    const pkinit = own.indexOf('pkinit') !== -1;
    const password = flags.indexOf('pre-authent') !== -1 && !pkinit;
    const hardware = flags.indexOf('hw-authent') !== -1;
    const otp = own.indexOf('otp') !== -1;
    const amr = [];
    if (password) {
      amr.push('pwd');
    }
    if (hardware) {
      amr.push('hwk');
    } else if (pkinit) {
      amr.push('swk');
    }
    if (otp) {
      amr.push('otp');
    }
    // "mfa" only where TWO are claimed, and for the reason authn.js gives
    // about the passwordless WebAuthn path: one factor does not become two by
    // being phishing-resistant, and a relying party that asked for two must not
    // be told it got them.
    const acr = (password && (hardware || otp)) ? 'mfa'
      : (amr.length ? '1' : '0');
    const method = 'Kerberos ticket over SPNEGO' +
      (pkinit
         ? ' (the KDC checked a certificate with PKINIT' +
           (hardware ? ', a smart-card logon certificate whose key this ' +
                       'service never held' : '') + ')'
         : password && otp
         ? ' (the KDC checked the password and an authenticator app code, ' +
           'with FAST and OTP pre-authentication)'
         : password && hardware
         ? ' (the KDC required pre-authentication AND hardware)'
         : password
           ? ' (the KDC required pre-authentication, so a long-term key ' +
             'derived from a password was proven to it)'
           : hardware
             ? ' (the KDC required hardware for the initial authentication)'
             : ' (the ticket claims no pre-authentication at all, so nothing ' +
               'here knows what the KDC checked)');
    log.debug('Leaving SpnegoAuthn.factorsFor(). amr=' + amr.join(',') +
              ', acr=' + acr);
    return { amr: amr, acr: acr, method: method, password: password,
             hardware: hardware, otp: otp, pkinit: pkinit };
  }

  // Is this door open at all? A function rather than a constant, because the
  // setting is settable at runtime and a value read at require time would be
  // the one the process started with.
  /**
   * Says whether the SPNEGO sign-in is on (`krb5.spnegoAuthentication`).
   *
   * @returns whether it is
   */
  enabled() {
    const { log, config } = this.deps;
    log.debug("Entering SpnegoAuthn.enabled().");
    log.debug("Leaving SpnegoAuthn.enabled().");
    return !!config.value('krb5.spnegoAuthentication');
  }

  // The link back to the password screen, which every page here carries. It is
  // the whole of the fallback story — see the header — and it is empty when
  // there is no pending record, because there is then nothing to fall back
  // INTO: a person who came to this URL directly was not in the middle of
  // anything.
  /**
   * Returns the link back to the password screen for a pending sign-in.
   *
   * @param record - the pending sign-in record, or null
   * @returns the HTML
   */
  fallbackHtml(record, translator?: Translator) {
    const { log, xmlEscape, authn } = this.deps;
    log.debug('Entering SpnegoAuthn.fallbackHtml().');
    // A REFUSAL PAGE draws it in English (#539: refusals are not translated),
    // from the English catalog, so its words are written once.
    const t = translator || this.english();
    if (!record) {
      log.debug('Leaving SpnegoAuthn.fallbackHtml(). Nothing was interrupted.');
      return '<p class="sub">' + t.html('spnego.fallback.none') + '</p>';
    }
    const html = '<p><a href="' + xmlEscape(authn.LOGIN_PATH) + '?authn=' +
      encodeURIComponent(record.id) + '">' +
      t.html('spnego.fallback.instead') + '</a> ' +
      t.html('spnego.fallback.stillWaiting') + '</p>' +
      '<p class="sub">' + t.html('spnego.fallback.signingInFor',
                                 { protocol: record.protocol || '' }) +
      (record.application
         ? ' &middot; <code>' + xmlEscape(record.application) + '</code>'
         : '') + '</p>';
    log.debug('Leaving SpnegoAuthn.fallbackHtml(). Offered the screen.');
    return html;
  }

  // THE TWO TRANSLATORS (#539). English, from the English catalog, for a
  // refusal page and a caller that names none; and the request's, with the
  // `framing` `spnego.js`'s page() draws it in — `lang` and `dir`, the
  // language chooser returning to this same GET, and the chooser's CSS.
  /**
   * Returns a translator that always answers in English.
   *
   * @returns the translator
   */
  private english(): Translator {
    const { log } = this.deps;
    log.debug('Entering SpnegoAuthn.english().');
    log.debug('Leaving SpnegoAuthn.english().');
    return i18n.translator([i18n.SOURCE]);
  }

  /**
   * Returns the request's translator, and the framing `page()` draws a
   * translated page with.
   *
   * @param record - the interrupted sign-in, or null
   * @param username - the person signed in, where one is
   * @returns `{ t, framing }`
   */
  private framed(record, username?: string): { t: Translator;
                                                framing: any } {
    const { log } = this.deps;
    log.debug('Entering SpnegoAuthn.framed().');
    const t = PageLocale.forPage({
      application: record ? String(record.application || '') : '',
      uiLocales: record ? String(record.uiLocales || '') : '',
      username: username || ''
    });
    const prefix = realms.currentPrefix();
    const framing = {
      htmlAttributes: PageLocale.htmlAttributes(t),
      top: PageLocale.chooser(t, prefix, PageLocale.herePath(prefix +
        SPNEGO_PATH + (record ? '?authn=' + encodeURIComponent(record.id)
                              : ''))),
      style: CHOOSER_CSS
    };
    log.debug('Leaving SpnegoAuthn.framed(). ' + t.locale);
    return { t: t, framing: framing };
  }

  // ---------------------------------------------------------------------------
  // THE SIGN-IN SURFACE'S SHELL, FOR THREE OF THIS DOOR'S BODIES (#575).
  //
  // The RFC 4559 exchange is not converted (#569's rule): the first 401 and
  // its `WWW-Authenticate: Negotiate`, the `Authorization` round trips, the
  // final mutual-authentication token, the 403 when the door is off and the
  // 303 to `returnTo` keep their statuses, their headers and the top-level
  // navigation that carries them — the browser's Negotiate, never a
  // `fetch()`. Only what a PERSON reads on three of those responses changes:
  // the first 401's body, the 403's, and the signed-in 200's when nothing was
  // interrupted. Each is the sign-in surface's shell (`authn.signInShell()`'s
  // document and policy), and the page's state rides on it in
  // `data-sts-state` — there is nothing to fetch it from, since the verdict
  // and the session it drew exist only on this one response.
  // `kerberos/web_authn_spnego.ts` draws it, in the browser's language
  // (#539's order; the pending sign-in's `ui_locales`, a signed-in person's
  // own language), and SCRIPT IS REQUIRED (rcbj on #569).
  //
  // THE CALLER HAS SET THE STATUS AND THE HEADERS (`applyVerdict()`, or the
  // refusal's own). This sets the shell's Content-Security-Policy — the one
  // header that has to change for a page that runs a script, through
  // `app.contentSecurityPolicy()` so `frame-ancestors` cannot be dropped — and
  // the body. Not `ShellDocument.serve()`, which answers 200.
  // ---------------------------------------------------------------------------
  /**
   * Returns what a page needs of the pending sign-in: its id, protocol and
   * application, or null where nothing was interrupted.
   *
   * @param record - the pending sign-in record, or null
   * @returns `{ id, protocol, application }`, or null
   */
  pendingView(record) {
    const { log } = this.deps;
    log.debug('Entering SpnegoAuthn.pendingView().');
    if (!record) {
      log.debug('Leaving SpnegoAuthn.pendingView(). Nothing was interrupted.');
      return null;
    }
    log.debug('Leaving SpnegoAuthn.pendingView().');
    return { id: String(record.id), protocol: String(record.protocol || ''),
             application: String(record.application || '') };
  }

  /**
   * Sends the sign-in surface's shell carrying a page's state, keeping the
   * status and headers the caller set.
   *
   * @param req - the request
   * @param res - the response, its status and headers set
   * @param record - the pending sign-in, or null
   * @param view - the page's view
   * @param own - a signed-in person's own language, or null
   */
  sendShell(req, res, record, view, own?) {
    const { log, authn } = this.deps;
    log.debug('Entering SpnegoAuthn.sendShell(). ' + view.kind);
    const state = Object.assign({ view: view },
      record && record.uiLocales ? { uiLocales: String(record.uiLocales) }
                                 : {},
      own ? { preferredLanguage: own } : {});
    const html = ShellDocument.document({
      title: 'Sign in with Kerberos — IYA STS',
      attributes: ([['data-sts-prefix', realms.currentPrefix()],
                    ['data-sts-state', JSON.stringify(state)]] as
                   Array<[string, string]>)
        .concat(PageLocale.shellAttributes(req, record
          ? String(record.application || '') : '')),
      stylesheets: ['/web/card.css'],
      script: authn.SIGNIN_SCRIPT_PATH,
      open: '<div class="card wide">',
      close: '</div>',
      noscript: '<h1>Sign in with Kerberos</h1><div class="err">This page ' +
        'is a script that runs in your browser, and with scripts blocked ' +
        'there is nothing it can show. Allow scripts for this page.</div>',
      loading: '<p class="sub">Loading&hellip;</p>'
    });
    res.set('Content-Security-Policy',
            ShellDocument.policy(app, { csp: { 'style-src': "'self'" } }));
    res.type('html').send(html);
    log.debug('Leaving SpnegoAuthn.sendShell().');
  }

  // ---------------------------------------------------------------------------
  // The endpoint.
  //
  // A GET, because that is what a redirect from a protocol endpoint produces
  // and what a browser repeats when it answers a 401 — the whole exchange is
  // one URL fetched twice, which is what makes `?authn=` the right place to
  // carry the interrupted request. It is never in the URL as a return ADDRESS:
  // the record is server-side and holds `returnTo`, so there is no
  // open-redirect surface here at all. (`/federation/login/{id}` does take a
  // `returnTo`, and has to — the browser leaves this origin there and comes
  // back to a different endpoint. This one never leaves.)
  // ---------------------------------------------------------------------------
  /**
   * Handles `GET /authn/spnego`: the Negotiate handshake, and on an accepted
   * ticket a session and the return to the interrupted flow.
   *
   * Answers 403 when the sign-in is off.
   *
   * @param req - the request
   * @param res - the response
   * @returns a promise that settles once the response is written
   */
  async handleSignIn(req, res) {
    const { log, authn, errorCodes, page, exchange, SPNEGO_PATH, xmlEscape,
            checksTable, principals, spnego } = this.deps;
    log.debug('Entering SpnegoAuthn.handleSignIn().');
    const record = authn.pendingFor((req.query || {}).authn);

    if (!this.enabled()) {
      // A REFUSAL WITH A REASON, not a 404. The route exists — it is in the
      // router, it is on /admin/sts-metadata — and answering "no such page"
      // would send somebody to look for a deployment problem when what they
      // have is a setting. Every other switchable refusal in this service says
      // which setting it was, for the same reason.
      log.info('krb5-spnego-authn: refused a sign-in because ' +
        'krb5.spnegoAuthentication is off.');
      errorCodes.mark(res, 'STS-KRB-0097');
      // THE STATUS AND THE HEADERS ARE THE REFUSAL'S, AS THEY WERE (#575):
      // 403 and `no-store`. The body is the sign-in surface's shell, whose
      // page names the setting — and so does the state it carries.
      res.status(403).set('Cache-Control', 'no-store');
      this.sendShell(req, res, record, {
        door: 'spnego', kind: 'off',
        setting: 'krb5.spnegoAuthentication',
        // The demonstration page only where this realm is served it (#585).
        demoPath: app.demoPathHidden('/spnego/protected') ? ''
                                                        : '/spnego/protected',
        pending: this.pendingView(record)
      });
      log.debug('Leaving SpnegoAuthn.handleSignIn(). The door is closed.');
      return;
    }

    const verdict = await exchange.negotiate(req, {
      door: SPNEGO_PATH,
      // WHAT krb5_service.js CALLS THIS on /admin/users, and it is deliberately
      // not the protected page's phrasing: "SPNEGO over HTTP" is a transport,
      // and this is a sign-on.
      via: 'SPNEGO sign-in over HTTP (RFC 4559)',
      // AND IT MUST NOT RECORD IT ITSELF. See krb5_service.js, where this
      // parameter is argued: the act here is a ticket accepted AND a session
      // minted, `startSession()` is the funnel that records exactly that with
      // the session id on it, and two records would make /admin/users count one
      // sign-in twice — which is the defect federation shipped with and fixed
      // the same way.
      record: false
    });

    exchange.applyVerdict(res, verdict);

    if (!verdict.ok && verdict.code === 'no-authorization') {
      // THE FIRST 401 (#575): `applyVerdict()` has set its status, its
      // `WWW-Authenticate: Negotiate` and `no-store`, exactly as before; the
      // body a person reads when their browser does not answer the challenge
      // is the sign-in surface's shell, drawn from the state it carries —
      // the link back to the password screen, and the service principal a
      // program asks a ticket for.
      this.sendShell(req, res, record, {
        door: 'spnego', kind: 'challenge',
        pending: this.pendingView(record),
        spn: exchange.SPN, realm: principals.REALM,
        // Empty in product mode: the KDC knows only `spn` (2026-10-12).
        hosts: principals.ADVERTISED_SERVICE_HOSTS,
        checks: verdict.checks || null
      });
      log.debug('Leaving SpnegoAuthn.handleSignIn(). The challenge.');
      return;
    }

    if (!verdict.ok) {
      // A CONTINUATION AND A TERMINAL REFUSAL are the negotiation's own
      // diagnostics, and stay drawn here: #575 converts the first 401's body
      // only, the one a person whose browser does not negotiate reads.
      //
      // A CONTINUATION IS NOT A FAILURE, and saying so is the one thing this
      // page has to get right that the protected page does not: three of the
      // fifteen outcomes are the acceptor asking for another round trip, and a
      // person told "you could not be signed in" over one of them would go and
      // fix something that is working.
      const waiting = !exchange.OUTCOMES[verdict.code] ||
                      !exchange.OUTCOMES[verdict.code].terminal;
      // A CONTINUATION IS TRANSLATED (#539); a terminal refusal is not —
      // rcbj's decision on #539 — so it is drawn in English, as it was, with
      // no chooser. The acceptor's own reason and the checks table are the
      // negotiation's diagnostics, and stay as they are.
      const framed = waiting ? this.framed(record)
        : { t: this.english(), framing: undefined };
      const t = framed.t;
      res.type('html').send(page(
        waiting ? t.text('spnego.waiting.title') : 'Kerberos sign-in refused',
        '<h1>' + (waiting
          ? t.html('spnego.waiting.heading')
          : '401 &mdash; that ticket did not sign you in') + '</h1>' +
        '<div class="' + (waiting ? 'ok' : 'err') + '">' +
          xmlEscape(verdict.reason) + '</div>' +
        (waiting ? '<p>' + t.html('spnego.waiting.note') + '</p>' : '') +
        (verdict.checks ? '<h2>' + t.html('spnego.checked') + '</h2>' +
          checksTable(verdict.checks) : '') +
        this.fallbackHtml(record, t),
        framed.framing));
      log.debug('Leaving SpnegoAuthn.handleSignIn(). ' + verdict.code + '.');
      return;
    }

    // ---------------------------------------------------------------------
    // ACCEPTED. Everything below this line is the sign-in, and the order is the
    // one federation_sp.js uses for the same reason: the thing with an effect
    // outside this process goes LAST, and everything above it is a record of
    // why.
    // ---------------------------------------------------------------------
    const username = this.usernameFor(verdict.client);
    // The indicators count only from a ticket this realm's KDC wrote.
    const clientRealm = String(verdict.client || '').split('@').pop();
    const factors = this.factorsFor(verdict.ticketFlags,
                                    verdict.authIndicators || [],
                                    clientRealm === principals.REALM);
    const detail = {
      // The PRINCIPAL as presented, not the username the session carries. They
      // differ by the realm and `admin_stats.js`'s identityOf() folds them onto
      // one person anyway — so recording the stripped form here would lose the
      // only place the full principal is ever written down.
      presented: verdict.client,
      protocol: 'Kerberos v5',
      method: factors.method,
      note: 'A Kerberos service ticket for ' + exchange.SPN + '@' +
            principals.REALM + ' was accepted over SPNEGO and a browser ' +
            'session was started for the principal inside it. This is the ' +
            'one sign-in in this service that rests on a credential it ' +
            'genuinely verified — every other one takes the name it is ' +
            'given. Ticket flags: ' +
            ((verdict.ticketFlags || []).join(', ') || 'none') + '.' +
            (record ? ' The request it completes is a ' +
                      (record.protocol || 'unnamed') + ' one' +
                      (record.application ? ' for "' + record.application + '"'
                                          : '') + '.'
                    : ' Nothing was interrupted; this door was used directly.'),
      summary: username + ' was signed in with a Kerberos ticket over SPNEGO'
    };
    // THE RISK OF THIS SIGN-IN (#62 P3), assessed before the session and
    // decided in the same question as the roles. This door cannot ask for a
    // second factor, so a step-up the policy names refuses here like HIGH;
    // a ticket whose flags already claim two factors (acr `mfa`) meets a
    // second-factor step-up as it stands.
    const application = record ? (record.application || '') : '';
    const assessed = await authn.assessSignIn(req, username, VIA,
      { application: application, credential: { kind: 'kerberos' } });
    const session = authn.startSession(res, username, factors.amr, factors.acr,
                                       VIA,
                                       Object.assign({
                                         request: req,
                                         // Which credential answered (#62).
                                         credential: { kind: 'kerberos' },
                                         application: application,
                                         risk: assessed || undefined
                                       }, detail));
    // THE ISSUANCE POLICY CAN REFUSE THE SESSION (2026-09-06). A null is how
    // `startSession()` says so; it never throws, because two of its callers
    // wrap it in a `try` that treats a failure as bookkeeping.
    //
    // **THE TICKET WAS REAL AND THE REFUSAL IS NOT ABOUT IT**, which is the one
    // thing this page has to get across: `/authn/spnego` is the surface where
    // this service verifies a credential properly, so "your ticket did not
    // verify" and "you may not have a session" must not read alike. The
    // Kerberos half succeeded; the policy declined.
    if (!session) {
      log.info('krb5-spnego-authn: the issuance policy refused a session for ' +
               username + ' after a valid ticket from ' + verdict.client + '.');
      errorCodes.mark(res, 'STS-KRB-0098');
      res.status(403).type('html').set('Cache-Control', 'no-store').send(
        page('Not permitted',
          '<h1>403 &mdash; the issuance policy refused this sign-in</h1><div ' +
          'class="err">Your Kerberos ticket verified. This service will not ' +
          'start a session for this identity.</div><p>That is a POLICY ' +
          'decision rather than anything wrong with the ticket, the KDC or ' +
          'the service principal &mdash; presenting it again will not change ' +
          'it. The role an application requires is on ' +
          '<code>/admin/roles</code> and the document that decides is on ' +
          '<code>/admin/xacml</code>.</p>'));
      log.debug("Leaving SpnegoAuthn.handleSignIn().");
      return undefined;
    }
    log.info('krb5-spnego-authn: ' + username + ' signed in as ' +
      verdict.client +
      ' over ' + spnego.mechName(verdict.selected) +
      (verdict.micVerified ? ', mechListMIC verified' : '') +
      (verdict.rawKerberos ? ' (a bare Kerberos token, no negotiation)' : '') +
      '. amr [' + factors.amr.join(',') + '], acr "' + factors.acr +
      '". Session ' + session.id + '.');

    if (record) {
      // Back to whatever was interrupted, which now runs a second time, sees
      // the session cookie and completes. `completeAuthentication()` is
      // authn.js's, and going through it rather than redirecting from here is
      // what keeps the pending record from being spendable twice and the 303 in
      // one place — RFC 9700 section 4.12, argued at length over there.
      authn.completeAuthentication(res, record);
      log.debug('Leaving SpnegoAuthn.handleSignIn(). Signed in and returned ' +
                'to ' +
        record.returnTo + '.');
      return;
    }

    // Nothing was interrupted, so this is the whole of it: a page saying who
    // you now are. The same shape federation's own entry point draws when it is
    // reached without a `returnTo`. THE STATUS AND THE HEADERS ARE
    // `applyVerdict()`'s and the session's (#575): 200, the final
    // `WWW-Authenticate` token that is the mutual half of the exchange,
    // `no-store` and the session cookie; the body is the sign-in surface's
    // shell, drawn in the signed-in person's language (#539) from the state
    // it carries.
    this.sendShell(req, res, null, {
      door: 'spnego', kind: 'signed-in',
      username: username, principal: verdict.client,
      session: session.id, subject: session.user.sub,
      flags: (verdict.ticketFlags || []).slice(),
      indicators: (verdict.authIndicators || []).slice(),
      amr: factors.amr.slice(), acr: factors.acr,
      mechanism: spnego.mechName(verdict.selected),
      bare: !!verdict.rawKerberos, mic: !!verdict.micVerified,
      checks: verdict.checks || null
    }, authn.preferredLanguageOf(username));
    log.debug('Leaving SpnegoAuthn.handleSignIn(). Signed in with nothing to ' +
              'return to.');
  }

  // THE ROUTES, registered where they always were: the composition
  // root (`common/protocol_stack.ts`) calls this, through the module's
  // `registerRoutes(app)`, at the point the first of them used to be
  // registered, so the route order is unchanged (rule 1).
  /**
   * Registers `GET /authn/spnego`.
   *
   * @param app - the express app
   */
  registerRoutes(app: RouteApp): void {
    const { log, SPNEGO_PATH, errorCodes, page, xmlEscape } = this.deps;
    const self = this;
    log.debug("Entering SpnegoAuthn.registerRoutes().");
    app.get(SPNEGO_PATH, function (req, res) {
      log.debug('Entering GET ' + SPNEGO_PATH + '.');
      self.handleSignIn(req, res).catch(function (e) {
        // Every path in that function writes a response; an exception that
        // escaped would leave the browser holding an open request in the middle
        // of a sign-in, which reads as an unreachable service rather than as a
        // fault here.
        log.error('krb5-spnego-authn: unhandled failure: ' +
                  (e.stack || e.message));
        if (!res.headersSent) {
          errorCodes.mark(res, 'STS-KRB-0099');
          res.status(500).type('html').send(page('Failed',
            '<h1>500</h1><div class="err">' + xmlEscape(e.message) + '</div>'));
        }
      });
      log.debug('Leaving GET ' + SPNEGO_PATH + '.');
    });
    log.debug("Leaving SpnegoAuthn.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<SpnegoAuthn>(
  'kerberos/spnego_authn',
  () => new SpnegoAuthn(SpnegoAuthn.defaultDeps()),
  null,
  helpers.log);

// What a browser that cannot do Negotiate is looking at, said once. It is on
// the first challenge only: the later pages are refusals of a token that WAS
// sent, so the client evidently can.
// "If nothing happened", which was a constant here, is three messages of the
// `spnego` catalog since #539 (`spnego.ifNothing.*`).

// The language chooser's look on this page (#539): the shell's own CSS knows
// nothing of it, and its `button` and `select` would otherwise be unstyled.
const CHOOSER_CSS = 'form.language-chooser{float:right;font-size:.8em;' +
  'margin:0 0 6px 8px}form.language-chooser select,form.language-chooser ' +
  'button{font-size:1em;padding:2px 6px}form.language-chooser label{margin:' +
  '0 4px 0 0}';

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * SPNEGO as a way of signing in: a Kerberos ticket over HTTP, turned into the
 * session every protocol family in this service reads.
 *
 * @namespace
 */
export = {
  /**
   * Forwards to `SpnegoAuthn.registerRoutes()` on the installed instance.
   */
  registerRoutes: slot.forward('registerRoutes'),
  SpnegoAuthn: SpnegoAuthn,
  /**
   * Installs the instance the composition root built, which the facades below
   * forward to.
   *
   * @param instance - the instance to install
   */
  installInstance: (instance: SpnegoAuthn): void => slot.install(instance),
  /**
   * Says whether the installed instance came from the root or the default.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  SPNEGO_PATH: SPNEGO_PATH,
  /**
   * Forwards to `SpnegoAuthn.enabled()` on the installed instance.
   */
  enabled: slot.forward('enabled'),
  /**
   * Forwards to `SpnegoAuthn.usernameFor()` on the installed instance.
   */
  usernameFor: slot.forward('usernameFor'),
  /**
   * Forwards to `SpnegoAuthn.factorsFor()` on the installed instance.
   */
  factorsFor: slot.forward('factorsFor')
};
