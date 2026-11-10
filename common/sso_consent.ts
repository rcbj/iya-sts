// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: common/sso_consent.ts
//
// ---------------------------------------------------------------------------
// ASKING A PERSON BEFORE SINGLE SIGN-ON SIGNS THEM IN (ASVS 5.0.0 7.6.2).
//
// SAML 2.0, SAML 1.1 and WS-Federation answer a request from a session the
// person already has without asking anything: that is what single sign-on
// is. It also means any page that can send the request can start a session
// at an application without the person doing anything. OpenID Connect asks
// for consent; these three now ask too, ONCE PER APPLICATION, through the
// same register (`common/consent.ts`) and the same screen
// (`oauth-oidc/consent_screen.ts`) the authorization endpoint uses, under the
// one scope `consent.SSO_SIGN_IN_SCOPE`.
//
// * **Per protocol, per application.** `saml2.ssoConsent`,
//   `saml11.ssoConsent` and `wsfed.ssoConsent` turn it on (product) or off
//   (development); `saml2SsoConsent`, `saml11SsoConsent` and
//   `wsfedSsoConsent` on an application's entry override the setting for
//   that application (`applications.settingFor()`).
// * **Remembered.** The person's Allow is filed on their entry and answers
//   every later sign-in to the same application; a global consent on the
//   application answers for everybody, which is what an operator sets for an
//   application the whole realm uses.
// * **A passive request is not shown the screen.** SAML 2.0's IsPassive says
//   the identity provider MUST NOT take control of the user interface
//   (saml-core-2.0-os section 3.4.1), so it is answered NoPassive, as a
//   missing session is.
//
// A library: it holds no state and registers no route. Every module it uses
// is required lazily, so a protocol module may require it at load.
// ---------------------------------------------------------------------------
import bunyan = require('bunyan');
import config = require('./config');

type Json = any;

const log = bunyan.createLogger({
  name: 'sso_consent',
  level: config.value('global.logLevel') || 'info'
});

/**
 * Whether single sign-on to one application must ask the person first, and
 * the hand-off to the consent screen when it must.
 */
class SsoConsent {
  /**
   * What single sign-on to one application owes before it answers.
   *
   * @param opts - `setting` (`saml2.ssoConsent` and the like), `application`
   *   (its identifier in the register), `username`, `passive` (the request
   *   may not interact) and `denied` (the person answered Deny)
   * @returns `{ action: 'proceed' }`, `{ action: 'ask', decision }` or
   *   `{ action: 'refuse', passive, why }`
   */
  static check(opts: Json): Json {
    log.debug("Entering SsoConsent.check(). " + String(opts && opts.setting));
    const asked = opts || {};
    const applications = require('./applications');
    const consent = require('./consent');
    const application = String(asked.application || '');
    const username = String(asked.username || '');
    if (!application || !username ||
        applications.settingFor(application, String(asked.setting),
                                config) !== true) {
      log.debug("Leaving SsoConsent.check(). Not asked here.");
      return { action: 'proceed' };
    }
    if (asked.denied) {
      log.debug("Leaving SsoConsent.check(). The person said no.");
      return { action: 'refuse', passive: false,
               why: 'The person declined to sign in to this application.' };
    }
    const decision = consent.outstanding({
      username: username, clientId: application,
      scope: consent.SSO_SIGN_IN_SCOPE, required: true });
    if (!decision || !decision.outstanding || !decision.outstanding.length) {
      log.debug("Leaving SsoConsent.check(). Already agreed.");
      return { action: 'proceed' };
    }
    if (asked.passive) {
      log.debug("Leaving SsoConsent.check(). Passive, and not yet agreed.");
      return { action: 'refuse', passive: true,
               why: 'The person has not yet agreed to sign in to this ' +
                    'application, and a passive request cannot ask them.' };
    }
    log.debug("Leaving SsoConsent.check(). Ask.");
    return { action: 'ask', decision: decision };
  }

  /**
   * Hands the browser to the consent screen for a sign-in that must ask.
   *
   * @param opts - `returnTo` (a path on this service that resumes the
   *   request), `username`, `application`, `decision` (from `check()`),
   *   `protocol` and `details` (rows the screen shows under a fold)
   * @returns the address to redirect to
   */
  static begin(opts: Json): string {
    log.debug("Entering SsoConsent.begin().");
    const asked = opts || {};
    const applications = require('./applications');
    const consentScreen = require('../oauth-oidc/consent_screen');
    const application = String(asked.application || '');
    const entry = applications.get(application);
    const where = consentScreen.beginConsent({
      returnTo: String(asked.returnTo || ''),
      username: String(asked.username || ''),
      clientId: application,
      clientName: (entry && entry.name) || application,
      scopes: (asked.decision && asked.decision.outstanding) || [],
      already: [],
      protocol: String(asked.protocol || ''),
      details: Array.isArray(asked.details) ? asked.details : []
    });
    log.debug("Leaving SsoConsent.begin().");
    return where;
  }
}

export = SsoConsent;
