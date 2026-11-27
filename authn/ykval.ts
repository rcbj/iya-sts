// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ykval.ts
//
// YK-VAL 2.0's verify endpoint (#1955 P5, decision D4). GET and POST
// /wsapi/2.0/verify. Off by default (`yubiotp.ykval`): the route stays
// registered and answers OPERATION_NOT_ALLOWED. On, the client id and the
// HMAC-SHA1 are checked in every mode, including development. No request
// is sent to YubiCloud.
//
// The signature is computed in common/yubiotp.ts. This file decides the
// status and writes text/plain. A code is marked on the response and is
// never written into the body.
//
// **EVERY VERIFY IS AUDITED** (`ykval.verify`, the #1955 review): the
// client, the OTP's public identity (never the OTP), the person it named
// and the status, with the code of a refusal. **A DISABLED ACCOUNT'S OTP IS
// BAD_OTP** (rule 3at, STS-YUBIOTP-0032): a PAM or RADIUS caller must not
// let in a person this service would refuse at its own sign-in, and the
// status says nothing more than a wrong OTP would. **THE NONCE IS SPENT BY
// A CLUSTER CLAIM** (`yubiotp_store.rememberNonceAsync()`), so a request
// replayed to another node is REPLAYED_REQUEST there too.

import querystring = require('querystring');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');

type Json = { [key: string]: any };

const log = helpers.log;

/**
 * YK-VAL 2.0 verify (#1955 P5).
 */
class Ykval {
  /**
   * Registers GET and POST /wsapi/2.0/verify.
   *
   * @param app - the express application
   */
  static registerRoutes(app: any): void {
    log.debug("Entering Ykval.registerRoutes().");
    app.get('/wsapi/2.0/verify', function (req, res) {
      log.debug("Entering GET /wsapi/2.0/verify.");
      Ykval.handle(req, res);
      log.debug("Leaving GET /wsapi/2.0/verify.");
    });
    app.post('/wsapi/2.0/verify', function (req, res) {
      log.debug("Entering POST /wsapi/2.0/verify.");
      Ykval.handle(req, res);
      log.debug("Leaving POST /wsapi/2.0/verify.");
    });
    log.debug("Leaving Ykval.registerRoutes().");
  }

  /**
   * Reads id, otp, nonce and h from the query or a form body.
   *
   * @param req - the request
   * @returns the parameters
   */
  static paramsOf(req: any): Json {
    log.debug("Entering Ykval.paramsOf().");
    const out: Json = {};
    const query = (req && req.query) || {};
    Object.keys(query).forEach(function (key) {
      const value = query[key];
      out[key] = Array.isArray(value) ? String(value[0] || '')
                                       : String(value == null ? '' : value);
    });
    if (req && typeof req.body === 'string' && req.body) {
      const parsed = querystring.parse(req.body);
      Object.keys(parsed).forEach(function (key) {
        const value = parsed[key];
        out[key] = Array.isArray(value) ? String(value[0] || '')
                                         : String(value == null ? '' : value);
      });
    }
    log.debug("Leaving Ykval.paramsOf().");
    return out;
  }

  /**
   * Answers one verify request.
   *
   * @param req - the request
   * @param res - the response
   */
  static handle(req: any, res: any): void {
    log.debug("Entering Ykval.handle().");
    Ykval.verify(Ykval.paramsOf(req)).then(function (answer) {
      Ykval.send(res, answer);
      log.debug("Leaving Ykval.handle().");
    }, function (e) {
      log.error(errorCodes.tag('STS-YUBIOTP-0027') +
                'ykval: verify threw: ' + ((e && e.message) || e));
      errorCodes.mark(res, 'STS-YUBIOTP-0027');
      Ykval.send(res, { status: 'BACKEND_ERROR',
                        fields: { status: 'BACKEND_ERROR' }, key: '' });
      log.debug("Leaving Ykval.handle(). It threw.");
    });
  }

  /**
   * Decides the YK-VAL status. Exported for the tests.
   *
   * @param params - id, otp, nonce, h and anything else the client sent
   * @returns a promise of `{ status, fields, key, code }`
   */
  static verify(params: Json): Promise<Json> {
    log.debug("Entering Ykval.verify().");
    const fields = params || {};
    return Ykval.decide(fields).then(function (answer: Json): Json {
      Ykval.recordAudit(fields, answer);
      log.debug("Leaving Ykval.verify(). " + String(answer.status));
      return answer;
    });
  }

  // One audit row per verify (header). Never throws: the answer stands.
  private static recordAudit(params: Json, answer: Json): void {
    log.debug("Entering Ykval.recordAudit().");
    try {
      const otp = String((params && params.otp) || '');
      const parsed = otp ? require('../common/yubiotp').parse(otp) : null;
      const code = String((answer && answer.code) || '');
      require('../common/audit').audit(Object.assign({
        category: 'authentication', action: 'ykval.verify',
        protocol: 'YK-VAL 2.0', channel: 'http',
        actor: 'ykval:' + String((params && params.id) || '').slice(0, 64),
        target: String((answer && answer.username) || ''),
        outcome: answer && answer.status === 'OK' ? 'success' : 'refused',
        summary: 'YK-VAL verify for client ' +
                 String((params && params.id) || '?').slice(0, 64) +
                 ': ' + String((answer && answer.status) || '?'),
        detail: { status: String((answer && answer.status) || ''),
                  publicId: parsed && parsed.publicId
                    ? String(parsed.publicId) : '' }
      }, code ? { errorCode: code } : {}));
    } catch (e) {
      log.debug("Caught in Ykval.recordAudit(): " + ((e && e.message) || e));
      // The verdict is the caller's either way; a lost row is logged here.
    }
    log.debug("Leaving Ykval.recordAudit().");
  }

  // The decision itself (verify()'s, before the audit row).
  private static decide(params: Json): Promise<Json> {
    log.debug("Entering Ykval.decide().");
    const yubi = require('../common/yubiotp');
    const store = require('../common/yubiotp_store');
    const fields = params || {};
    if (!yubi.ykvalEnabled()) {
      log.debug("Leaving Ykval.decide(). Off.");
      return Promise.resolve({
        status: 'OPERATION_NOT_ALLOWED', code: 'STS-YUBIOTP-0012', key: '',
        fields: { status: 'OPERATION_NOT_ALLOWED' } });
    }
    const id = String(fields.id || '');
    const otp = String(fields.otp || '');
    const nonce = String(fields.nonce || '');
    const h = String(fields.h || '');
    // THE ORDER OF THE CHECKS IS THE REFERENCE SERVER'S (#2094). The
    // Validation Protocol V2.0 lists the statuses and which parameters are
    // required (id, otp, nonce), and names no order between them. The one
    // order there is is Yubico's own yubikey-val (ykval-verify.php),
    // published with that specification, and the clients that read the
    // status (pam_yubico, ykclient) were written against it:
    //   1. no nonce                          MISSING_PARAMETER
    //   2. the otp not in an OTP's format    BAD_OTP ("invalid format")
    //   3. no client id                      MISSING_PARAMETER
    //   4. a nonce not 16-40 characters      MISSING_PARAMETER
    //   5. a client nobody created           NO_SUCH_CLIENT
    //   6. a signature that does not match   BAD_SIGNATURE
    // So an unknown client with a malformed OTP is BAD_OTP: the format is
    // judged before any client is looked up. This file answered
    // MISSING_PARAMETER to `?id=1&otp=x&nonce=...` because it asked for
    // `h` first. **ONE DEPARTURE, AND IT IS THIS SERVICE'S POLICY**: the
    // specification makes `h` optional, and here it is required (the
    // header: the HMAC is checked in every mode), so an unsigned request
    // from a KNOWN client is MISSING_PARAMETER at step 6, after the lookup.
    // An unknown client is NO_SUCH_CLIENT whether it signed or not. A
    // malformed nonce was REPLAYED_REQUEST, after the signature; it is the
    // reference's MISSING_PARAMETER at step 4 now. A refusal before the
    // lookup is signed when the id names a client, as a missing parameter
    // always was, and unsigned otherwise.
    const key = id ? store.clientKey(id) : '';
    if (!nonce) {
      log.debug("Leaving Ykval.decide(). No nonce.");
      return Promise.resolve(Ykval.signed({
        status: 'MISSING_PARAMETER', code: 'STS-YUBIOTP-0013', key: key,
        otp: otp, nonce: nonce }));
    }
    if (!yubi.parse(otp)) {
      log.debug("Leaving Ykval.decide(). Not an OTP's format.");
      return Promise.resolve(Ykval.signed({
        status: 'BAD_OTP', code: 'STS-YUBIOTP-0033', key: key,
        otp: otp, nonce: nonce }));
    }
    if (!id) {
      log.debug("Leaving Ykval.decide(). No client id.");
      return Promise.resolve(Ykval.signed({
        status: 'MISSING_PARAMETER', code: 'STS-YUBIOTP-0013', key: '',
        otp: otp, nonce: nonce }));
    }
    const YubiOtp = yubi.YubiOtp;
    if (!YubiOtp.NONCE_RE.test(nonce)) {
      log.debug("Leaving Ykval.decide(). Nonce.");
      return Promise.resolve(Ykval.signed({
        status: 'MISSING_PARAMETER', code: 'STS-YUBIOTP-0034', key: key,
        otp: otp, nonce: nonce }));
    }
    if (!key) {
      log.debug("Leaving Ykval.decide(). No client.");
      return Promise.resolve({
        status: 'NO_SUCH_CLIENT', code: 'STS-YUBIOTP-0015', key: '',
        fields: { status: 'NO_SUCH_CLIENT' } });
    }
    if (!h) {
      log.debug("Leaving Ykval.decide(). Unsigned.");
      return Promise.resolve(Ykval.signed({
        status: 'MISSING_PARAMETER', code: 'STS-YUBIOTP-0013', key: key,
        otp: otp, nonce: nonce }));
    }
    if (!yubi.signatureOk(key, fields)) {
      log.debug("Leaving Ykval.decide(). Bad signature.");
      return Promise.resolve({
        status: 'BAD_SIGNATURE', code: 'STS-YUBIOTP-0014', key: '',
        fields: { status: 'BAD_SIGNATURE' } });
    }
    log.debug("Leaving Ykval.decide(). The nonce is spent next.");
    return store.rememberNonceAsync(id, nonce).then(function (spent: Json) {
      if (!spent || !spent.ok) {
        const backend = !!spent && spent.reason === 'store';
        return Ykval.signed({
          status: backend ? 'BACKEND_ERROR' : 'REPLAYED_REQUEST',
          code: backend ? 'STS-YUBIOTP-0031' : 'STS-YUBIOTP-0016',
          key: key, otp: otp, nonce: nonce });
      }
      return Ykval.checkOtp(store, otp, nonce, key);
    });
  }

  // The OTP, after the client and the nonce have been accepted.
  private static checkOtp(store: any, otp: string, nonce: string,
                          key: string): Promise<Json> {
    log.debug("Entering Ykval.checkOtp().");
    const parsed = require('../common/yubiotp').parse(otp);
    const row = parsed && parsed.publicId
      ? store.lookupPublicId(parsed.publicId) : null;
    if (!row || !row.username) {
      log.debug("Leaving Ykval.checkOtp(). No public id.");
      return Promise.resolve(Ykval.signed({
        status: 'BAD_OTP', code: 'STS-YUBIOTP-0017', key: key,
        otp: otp, nonce: nonce }));
    }
    // A DISABLED ACCOUNT (rule 3at, header): BAD_OTP, and the counter is not
    // spent, since no OTP of theirs is accepted.
    let disabled = false;
    try {
      disabled = require('../common/account_state')
        .isDisabled(String(row.username));
    } catch (e) {
      log.debug("Caught in Ykval.checkOtp(): " + ((e && e.message) || e));
      // A state that cannot be read is not a lock this door may invent; the
      // sign-in screen reads it the same way.
      disabled = false;
    }
    if (disabled) {
      log.debug("Leaving Ykval.checkOtp(). A disabled account.");
      return Promise.resolve(Object.assign(Ykval.signed({
        status: 'BAD_OTP', code: 'STS-YUBIOTP-0032', key: key,
        otp: otp, nonce: nonce }), { username: String(row.username) }));
    }
    return require('../common/credentials')
      .verifyYubiOtpAsync(row.username, otp)
      .then(function (verdict) {
        if (verdict && verdict.ok) {
          log.debug("Leaving Ykval.checkOtp(). OK.");
          return Object.assign(Ykval.signed({
            status: 'OK', code: '', key: key, otp: otp, nonce: nonce,
            extra: { sl: '100' } }), { username: String(row.username) });
        }
        const replay = verdict && verdict.reason === 'replay';
        const backend = verdict && (verdict.reason === 'store' ||
                                    verdict.reason === 'unusable');
        const status = replay ? 'REPLAYED_OTP'
          : (backend ? 'BACKEND_ERROR' : 'BAD_OTP');
        const code = replay ? 'STS-YUBIOTP-0018'
          : (backend ? 'STS-YUBIOTP-0027' : 'STS-YUBIOTP-0017');
        log.debug("Leaving Ykval.checkOtp(). " + status + ".");
        return Object.assign(Ykval.signed({ status: status, code: code,
          key: key, otp: otp, nonce: nonce }),
          { username: String(row.username) });
      }, function (e) {
        log.error(errorCodes.tag('STS-YUBIOTP-0027') +
                  'ykval: the OTP check threw: ' + ((e && e.message) || e));
        log.debug("Leaving Ykval.checkOtp(). It threw.");
        return Ykval.signed({
          status: 'BACKEND_ERROR', code: 'STS-YUBIOTP-0027', key: key,
          otp: otp, nonce: nonce });
      });
  }

  /**
   * A signed status when a client key is known, and an unsigned one when
   * it is not (a missing parameter for an unknown id).
   *
   * @param spec - status, code, key, otp, nonce, extra
   * @returns the answer
   */
  static signed(spec: Json): Json {
    log.debug("Entering Ykval.signed().");
    const fields: Json = {
      t: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      otp: spec.otp || '', nonce: spec.nonce || '', status: spec.status
    };
    const extra = spec.extra || {};
    Object.keys(extra).forEach(function (name) {
      fields[name] = extra[name];
    });
    log.debug("Leaving Ykval.signed().");
    return { status: spec.status, code: spec.code || '',
             key: spec.key || '', fields: fields };
  }

  /**
   * Writes the text/plain body. The HMAC is added here, never earlier.
   *
   * @param res - the response
   * @param answer - what verify() resolved
   */
  static send(res: any, answer: Json): void {
    log.debug("Entering Ykval.send().");
    const fields = Object.assign({}, (answer && answer.fields) || {});
    if (answer && answer.key) {
      const yubi = require('../common/yubiotp');
      fields.h = yubi.sign(answer.key, fields);
    }
    if (answer && answer.code) {
      errorCodes.mark(res, answer.code);
    }
    const lines = Object.keys(fields).sort().map(function (name) {
      return name + '=' + String(fields[name]);
    });
    res.set('Cache-Control', 'no-store');
    res.type('text/plain');
    res.send(lines.join('\r\n') + '\r\n');
    log.debug("Leaving Ykval.send().");
  }
}

export = {
  Ykval: Ykval,
  registerRoutes: (app: any): void => Ykval.registerRoutes(app),
  verify: (params: Json): Promise<Json> => Ykval.verify(params)
};
