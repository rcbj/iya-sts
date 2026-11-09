// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// File: common/step_address.ts
// ---------------------------------------------------------------------------
// A SIGN-IN STEP'S ID STAYS OUT OF WHAT A SERVER IS SENT (#1454, ASVS 5.0.0
// 14.2.1), IN PRODUCT.
//
// These ids are this service's own, not any specification's, and the sign-in
// pages are scripts: so where a redirect names `?authn=`, `?mfa=`, `?change=` or
// `?consent=`, it moves into the fragment, which a browser does not send. The
// application's id goes in the query instead: the shell needs it for the
// client's logo and language, and it is not a secret.
//
// `/authn/spnego` cannot use a fragment: RFC 4559's exchange is plain HTTP with
// no script, so the server has to read the id. In product it travels in a
// short-lived HttpOnly cookie instead (#1487). Nothing here touches a protocol
// endpoint's own parameters.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import mode = require('./mode');
import config = require('./config');

const log = helpers.log;

const STEP = new RegExp('^((?:https?://[^/]+)?(?:/realm/[^/]+)?' +
  '(?:/authn/(?!spnego)[a-z0-9/-]+|/oauth2/consent))' +
  '\\?((authn|mfa|change|consent)=([^&#]+)(?:&[^#]*)?)$');

const SPNEGO = new RegExp('^((?:https?://[^/]+)?(?:/realm/[^/]+)?' +
  '/authn/spnego)\\?authn=([^&#]+)$');
const SPNEGO_COOKIE = 'sts_spnego_step';
// Longer than a Negotiate exchange and no longer than a pending sign-in.
const SPNEGO_COOKIE_S = 600;

class StepAddress {
  /**
   * Splits a redirect to the SPNEGO door into its address and its step.
   *
   * @param location - the address
   * @returns `{ location, id }`, or null where it is not one, or not hidden
   */
  static spnegoStep(location: string): { location: string; id: string } | null {
    log.debug("Entering StepAddress.spnegoStep().");
    const found = SPNEGO.exec(String(location));
    log.debug("Leaving StepAddress.spnegoStep().");
    return found && mode.hidesStepIds()
      ? { location: found[1], id: found[2] } : null;
  }

  /**
   * The Set-Cookie line that carries a step to the SPNEGO door.
   *
   * @param id - the step's id, as it stands in an address
   * @returns the header value
   */
  static spnegoCookie(id: string): string {
    log.debug("Entering StepAddress.spnegoCookie().");
    log.debug("Leaving StepAddress.spnegoCookie().");
    return SPNEGO_COOKIE + '=' + encodeURIComponent(decodeURIComponent(id)) +
      '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + SPNEGO_COOKIE_S +
      (config.value('global.https') ? '; Secure' : '');
  }

  /**
   * The step a request to the SPNEGO door carries in its cookie.
   *
   * @param req - the request
   * @returns the step's id, or ''
   */
  static spnegoStepOf(req: any): string {
    log.debug("Entering StepAddress.spnegoStepOf().");
    const header = String((req && req.headers && req.headers.cookie) || '');
    const pair = header.split(';').map(function (one: string) {
      return one.trim();
    }).filter(function (one: string) {
      return one.indexOf(SPNEGO_COOKIE + '=') === 0;
    })[0] || '';
    log.debug("Leaving StepAddress.spnegoStepOf().");
    return pair && mode.hidesStepIds()
      ? decodeURIComponent(pair.slice(SPNEGO_COOKIE.length + 1)) : '';
  }

  /**
   * Moves a sign-in step's id from an address's query to its fragment.
   *
   * @param location - the address
   * @param applicationOf - finds the application a step belongs to
   * @returns the address to send
   */
  static hide(location: string,
              applicationOf?: (name: string, id: string) => string): string {
    log.debug("Entering StepAddress.hide().");
    const found = STEP.exec(String(location));
    if (!found || !mode.hidesStepIds()) {
      log.debug("Leaving StepAddress.hide(). Unchanged.");
      return location;
    }
    const application = applicationOf
      ? applicationOf(found[3], decodeURIComponent(found[4])) : '';
    log.debug("Leaving StepAddress.hide(). Moved.");
    return found[1] +
      (application ? '?app=' + encodeURIComponent(application) : '') +
      '#' + found[2];
  }
}

export = StepAddress;
