// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: certificate_handoff.ts
//
// ===========================================================================
// A CERTIFICATE SIGN-IN ON A LISTENER OF ITS OWN, BOUND TO THE SIGN-IN THAT
// SENT THE PERSON THERE (#2012, rcbj 2026-11-23: an option, OFF BY DEFAULT).
//
// **WHY.** The sign-in screen offers the certificate ON ITS OWN CONNECTION
// (#1051), so the listener the screen is on has to ask every connection for
// one — and a browser with a smart card in the reader then prompts for it,
// and for its PIN, whoever came to type a password. FIPS 201-3's PKI-AUTH is
// client-authenticated TLS (RFC 8446 sections 4.3.2 and 4.4.3); it only needs
// the TLS ask on the ONE request that carries the certificate. So, with
// `certSignIn.handoff` on:
//
//   1. the screen's view carries `certificate.handoff`, a link to
//      `/authn/certificate/continue?h=<id>` — on the listener the
//      `certificate-sign-in` hosted application is mapped to
//      (`listeners.applications`), a custom listener whose `clientAuth` asks
//      for a certificate. The id names a HANDOFF in this file's store: the
//      pending sign-in it is for and the browser's sign-on session
//      (`sts_session`), live for `HANDOFF_S`;
//   2. on that listener the browser and the operating system's smart-card
//      stack choose the certificate and ask for the PIN, and the card signs
//      the handshake. `continue()` holds the certificate to exactly what the
//      screen's own door holds it to (`tls_server.screenCertificateHolder()`:
//      revocation, the identity gate, every certificate sign-in profile, the
//      card-authentication refusal) in the pending sign-in's realm, writes the
//      answer on the handoff, and sends the browser back to the screen;
//   3. the screen's view offers "Continue as <name> with your certificate"
//      from that answer, and the act (`authn.ts`'s `certificateSignIn()`)
//      completes the pending sign-in as it would have for the certificate on
//      its connection — the policy, the risk, a second factor.
//
// **THE BINDING, BOTH LEGS.** The certificate is bound to the transaction
// that started the handoff, not merely to the link: `continue()` refuses a
// request whose `sts_session` is not the browser's that the view was drawn
// for (STS-TLS-0075), so a link sent to somebody else cannot attach THEIR
// certificate to the sender's sign-in, and the act takes the answer only
// from a handoff bound to the acting browser's session and its own pending
// sign-in, once. The cookie must therefore reach the certificate listener:
// mapped with `session: true` (`common/hosted_applications.js`), the
// application falls under `listener_map.js`'s cookie rule (D3) — one host
// name, or every host under `authn.cookieDomain` — and a mapping that breaks
// it is refused when written.
//
// **WHAT IT IS NOT.** It is not a second door: the certificate's questions are
// the screen's, asked by the same function, and the sign-in is the screen's
// act. Off, the link is not drawn and `continue()` answers 400
// (STS-TLS-0074) for every id.
//
// A ROUTE MODULE (#50's R1): requiring it registers nothing; the composition
// root calls `registerRoutes()`. `authn/authn.ts` and `tls/tls_server.js` are
// reached at the request.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import stsCrypto = require('../common/crypto');

type Json = any;

/** Where the certificate listener answers. */
const CONTINUE_PATH = '/authn/certificate/continue';

/** The screen it goes back to. */
const LOGIN_PATH = '/authn/login';

/** How long a handoff is live, seconds: a PIN prompt and a card. */
const HANDOFF_S = 300;

const HANDOFF_ID = /^[A-Za-z0-9_-]{43}$/;

// THE HANDOFFS. Per realm at the declaration (`tests/realm_isolation.js`),
// kept in the store as a pending sign-in is, so the listener and the screen
// may be answered by different processes or nodes; each row expires with
// its handoff. id -> { pendingId, sid, expires, state, result }.
const handoffs = realms.map({ persist: 'tls.certificateHandoffs',
                              retain: 'age',
                              expiresAt: realms.expiryField('expires', 1) });

interface CertificateHandoffDeps {
  log: typeof helpers.log;
  helpers: typeof helpers;
  config: typeof config;
  realms: typeof realms;
  errorCodes: typeof errorCodes;
  stsCrypto: typeof stsCrypto;
  store: Json;
  now: () => number;
  // Reached at the request (header).
  loadAuthn: () => Json;
  loadTlsServer: () => Json;
  loadIdentityAssurance: () => Json;
}

/**
 * The certificate sign-in handoff to a listener that asks for a certificate
 * (#2012).
 */
class CertificateHandoff {
  static readonly CONTINUE_PATH = CONTINUE_PATH;

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: CertificateHandoffDeps) {
    deps.log.debug("Entering CertificateHandoff.constructor().");
    deps.log.debug("Leaving CertificateHandoff.constructor().");
  }

  /**
   * The dependencies the service uses.
   *
   * @returns the dependencies
   */
  static defaultDeps(): CertificateHandoffDeps {
    helpers.log.debug("Entering CertificateHandoff.defaultDeps().");
    helpers.log.debug("Leaving CertificateHandoff.defaultDeps().");
    return {
      log: helpers.log, helpers: helpers, config: config, realms: realms,
      errorCodes: errorCodes, stsCrypto: stsCrypto, store: handoffs,
      now: Date.now,
      loadAuthn: function (): Json {
        return require('../authn/authn');
      },
      loadTlsServer: function (): Json {
        return require('./tls_server');
      },
      loadIdentityAssurance: function (): Json {
        return require('../common/identity_assurance');
      }
    };
  }

  /**
   * Whether the handoff is offered in the ambient realm.
   *
   * @returns true where `certSignIn.handoff` is on
   */
  enabled(): boolean {
    const { log, config: settings } = this.deps;
    log.debug("Entering CertificateHandoff.enabled().");
    let on = false;
    try {
      on = settings.value('certSignIn.handoff') === true;
    } catch (e) {
      log.debug("Caught in CertificateHandoff.enabled(): " +
                ((e && e.message) || e));
      on = false;
    }
    log.debug("Leaving CertificateHandoff.enabled(). " + on);
    return on;
  }

  /**
   * The sign-on session id behind a request's cookie, or ''.
   *
   * @param req - the request
   * @returns the id
   */
  private sessionIdOf(req: Json): string {
    const { log } = this.deps;
    log.debug("Entering CertificateHandoff.sessionIdOf().");
    let sid = '';
    try {
      const authn = this.deps.loadAuthn();
      const found = authn.cookieSession(req, authn.SESSION_COOKIE);
      sid = String((found && found.id) || '');
    } catch (e) {
      log.debug("Caught in CertificateHandoff.sessionIdOf(): " +
                ((e && e.message) || e));
      sid = '';
    }
    log.debug("Leaving CertificateHandoff.sessionIdOf(). " +
              (sid ? 'A session.' : 'None.'));
    return sid;
  }

  /**
   * A handoff that is still live, or null.
   *
   * @param id - the handoff's id
   * @returns the row, or null
   */
  private live(id: string): Json {
    const { log, store } = this.deps;
    log.debug("Entering CertificateHandoff.live().");
    const row = HANDOFF_ID.test(String(id || '')) ? store.get(String(id))
                                                    : null;
    const ok = !!row && Number(row.expires) > this.deps.now();
    log.debug("Leaving CertificateHandoff.live(). " + ok);
    return ok ? row : null;
  }

  /**
   * The link the screen draws for a pending sign-in, reusing the handoff the
   * record already names while it is live and bound to this browser; null
   * where the handoff is off or the browser holds no session to bind to.
   *
   * @param req - the view's request
   * @param pendingId - the pending sign-in's id
   * @param already - the handoff id the record names, if any
   * @returns `{ id, href }`, or null
   */
  offer(req: Json, pendingId: string, already: string): Json {
    const { log, helpers: h, store, stsCrypto: c } = this.deps;
    log.debug("Entering CertificateHandoff.offer().");
    if (!this.enabled()) {
      log.debug("Leaving CertificateHandoff.offer(). Off.");
      return null;
    }
    const sid = this.sessionIdOf(req);
    if (!sid) {
      log.debug("Leaving CertificateHandoff.offer(). No session.");
      return null;
    }
    let id = String(already || '');
    const held = this.live(id);
    if (!held || held.sid !== sid || held.pendingId !== String(pendingId) ||
        held.state !== 'issued') {
      id = c.randomToken(256);
      store.set(id, { pendingId: String(pendingId), sid: sid,
                      expires: this.deps.now() + HANDOFF_S * 1000,
                      state: 'issued', result: null });
    }
    const href = h.urlOf(req, CONTINUE_PATH) + '?h=' +
      encodeURIComponent(id);
    log.debug("Leaving CertificateHandoff.offer().");
    return { id: id, href: href };
  }

  /**
   * What the certificate listener found, for the pending sign-in and the
   * browser asking: the holder in `screenCertificateHolder()`'s shape, its
   * `recordVerification()` rebuilt, or the refusal; null where the handoff
   * named is not this browser's, not this sign-in's, or not yet presented.
   * `consume` marks it used, so an answer completes one sign-in.
   *
   * @param req - the screen's request
   * @param pendingId - the pending sign-in's id
   * @param id - the handoff id the record names
   * @param consume - true at the act
   * @returns the holder or the refusal, or null
   */
  resultFor(req: Json, pendingId: string, id: string, consume: boolean): Json {
    const { log, store } = this.deps;
    log.debug("Entering CertificateHandoff.resultFor().");
    const row = this.live(id);
    if (!row || row.state !== 'presented' || !row.result ||
        row.pendingId !== String(pendingId) ||
        row.sid !== this.sessionIdOf(req)) {
      log.debug("Leaving CertificateHandoff.resultFor(). None here.");
      return null;
    }
    if (consume) {
      store.set(String(id), Object.assign({}, row, { state: 'used' }));
    }
    const kept = row.result;
    if (!kept.ok) {
      log.debug("Leaving CertificateHandoff.resultFor(). A refusal.");
      return { ok: false, code: String(kept.code || 'STS-AUTHN-0463'),
               why: String(kept.why || '') };
    }
    const self = this;
    log.debug("Leaving CertificateHandoff.resultFor(). " + kept.username);
    return {
      ok: true, handedOff: true,
      username: String(kept.username), credentialId: String(kept.credentialId),
      serial: String(kept.serial || ''),
      amr: Array.isArray(kept.amr) ? kept.amr.map(String) : ['swk'],
      revocationSaid: String(kept.revocationSaid || ''),
      recordVerification: function recordVerification(): void {
        self.deps.log.debug('Entering recordVerification(). (handoff)');
        self.deps.loadIdentityAssurance().recordAutomatic(
          String(kept.username), 'certificate', kept.facts || {});
        self.deps.log.info('tls: ' + String(kept.username) + ' continued ' +
          'at the sign-in screen with a client certificate presented on ' +
          'the certificate sign-in listener. The chain verified and ' +
          String(kept.revocationSaid || ''));
        self.deps.log.debug('Leaving recordVerification(). (handoff)');
      }
    };
  }

  /**
   * Sends a refusal of the listener's own: English, plain text, never
   * cached, with no referrer — the handoff id is in the address.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param why - the sentence
   */
  // error-code: none — the helper's definition; each caller marks its code
  private refuse(res: Json, status: number, why: string): void {
    const { log } = this.deps;
    log.debug("Entering CertificateHandoff.refuse(). " + status);
    res.status(status).type('text/plain').set({
      'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer'
    }).send(why + '\n');
    log.debug("Leaving CertificateHandoff.refuse().");
  }

  /**
   * `GET /authn/certificate/continue?h=<id>` (header, step 2).
   *
   * @param req - the request
   * @param res - the response
   * @returns a promise that settles once answered
   */
  async continueHandoff(req: Json, res: Json): Promise<void> {
    const { log, errorCodes: codes, store, helpers: h } = this.deps;
    log.debug("Entering CertificateHandoff.continueHandoff().");
    const id = String((req.query && req.query.h) || '');
    const row = this.enabled() ? this.live(id) : null;
    if (!row || row.state !== 'issued') {
      log.info(codes.tag('STS-TLS-0074') + 'certificate_handoff: no live ' +
               'certificate sign-in handoff was named' +
               (this.enabled() ? '' : ' (certSignIn.handoff is off)') + '.');
      codes.mark(res, 'STS-TLS-0074');
      this.refuse(res, 400, 'This certificate sign-in link has expired or ' +
        'was already used. Go back to the sign-in screen and choose the ' +
        'certificate again.');
      log.debug("Leaving CertificateHandoff.continueHandoff(). No handoff.");
      return;
    }
    if (row.sid !== this.sessionIdOf(req)) {
      log.info(codes.tag('STS-TLS-0075') + 'certificate_handoff: a handoff ' +
               'arrived without the sign-on session of the browser that ' +
               'started it.');
      codes.mark(res, 'STS-TLS-0075');
      this.refuse(res, 403, 'This certificate sign-in was started in ' +
        'another browser, or this browser\'s sign-in cookie does not reach ' +
        'this address. Start again from the sign-in screen in this browser.');
      log.debug("Leaving CertificateHandoff.continueHandoff(). Another " +
                "browser.");
      return;
    }
    let holder: Json = null;
    try {
      holder = await this.deps.loadTlsServer().screenCertificateHolder(req);
    } catch (e) {
      log.debug("Caught in CertificateHandoff.continueHandoff(): " +
                ((e && e.message) || e));
      holder = null;
    }
    const result = holder && holder.ok
      ? { ok: true, username: String(holder.username),
          credentialId: String(holder.credentialId || ''),
          serial: String(holder.serial || ''),
          amr: Array.isArray(holder.amr) ? holder.amr.map(String) : ['swk'],
          revocationSaid: String(holder.revocationSaid || ''),
          facts: holder.verificationFacts || {} }
      : { ok: false,
          code: String((holder && holder.code) || 'STS-AUTHN-0463'),
          why: String((holder && holder.why) ||
                      'No verified client certificate arrived.') };
    store.set(id, Object.assign({}, row, { state: 'presented',
                                           result: result }));
    const back = h.urlOf(req, LOGIN_PATH) + '?authn=' +
      encodeURIComponent(String(row.pendingId));
    res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
    log.debug("Leaving CertificateHandoff.continueHandoff(). " +
              (result.ok ? 'Presented.' : 'Refused.'));
    res.redirect(303, back);
  }

  /**
   * Registers `GET /authn/certificate/continue`. Called by
   * `common/protocol_stack.ts`; requiring this module registers nothing.
   *
   * @param app - the shared express application
   */
  registerRoutes(app: Json): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CertificateHandoff.registerRoutes().");
    app.get(CONTINUE_PATH, function (req: Json, res: Json) {
      return self.continueHandoff(req, res).catch(function (e: Json) {
        log.debug("Caught in GET " + CONTINUE_PATH + ": " +
                  ((e && e.message) || e));
        errorCodes.mark(res, 'STS-TLS-0074');
        if (!res.headersSent) {
          self.refuse(res, 400, 'This certificate sign-in could not be ' +
                                'completed. Go back to the sign-in screen.');
        }
      });
    });
    log.debug("Leaving CertificateHandoff.registerRoutes().");
  }
}

const slot = new InstanceSlot<CertificateHandoff>(
  'tls/certificate_handoff',
  () => new CertificateHandoff(CertificateHandoff.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The certificate sign-in handoff (#2012).
 * @namespace
 */
export = {
  CertificateHandoff: CertificateHandoff,
  CONTINUE_PATH: CONTINUE_PATH,
  installInstance: (instance: CertificateHandoff): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  registerRoutes: slot.forward('registerRoutes'),
  enabled: slot.forward('enabled'),
  offer: slot.forward('offer'),
  resultFor: slot.forward('resultFor')
};
