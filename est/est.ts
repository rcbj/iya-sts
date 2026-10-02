// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: est.ts
//
// ---------------------------------------------------------------------------
// ENROLLMENT OVER SECURE TRANSPORT (RFC 7030, with RFC 8951's clarifications),
// 2026-09-13.
//
// Six operations under `/.well-known/est/`, and the same six under
// `/.well-known/est/<label>/`, where a LABEL is one of the nine certificate
// profiles `common/cert_enrollment.ts` issues (RFC 7030 section 3.2.2 lets a
// server give its CAs labels; here a label names what kind of certificate is
// being asked for, and the CA is always this realm's EST Issuing CA). The
// unlabelled path issues `est.defaultProfile`.
//
// **A REALM CAN BE NAMED IN THE LABEL POSITION TOO** (#251):
// `/.well-known/est/<realm>/…` is entered as that realm and rewritten to
// `/.well-known/est/…` by `common/realms.js`'s `matchPath()` before the router,
// so nothing here knows it happened — except that a label which names a realm
// reaching THIS file means the realm was already named, and is refused
// (STS-EST-0022).
//
//   GET  cacerts          the CA certificates, certs-only (section 4.1)
//   POST simpleenroll     a PKCS#10 in, a certificate out (4.2.1)
//   POST simplereenroll   the same, renewing a certificate (4.2.2)
//   POST serverkeygen     a key pair this service generates (4.4)
//   GET  csrattrs         what a request should carry (4.5)
//   POST fullcmc          501: Full CMC (4.3) is not implemented
//
// **EVERYTHING THAT IS NOT A WIRE FORMAT IS THE CORE'S.** Who may be issued a
// certificate for whom, which names it may carry, whether a request proves
// possession, what the certificate contains and where it is kept are decided in
// `common/cert_enrollment.ts` and nowhere here. This file authenticates in
// EST's own way, reads the body, calls the core, and writes the answer — which
// is what keeps "a person may only obtain a certificate for themselves" one
// rule in three protocols rather than three rules that agree today.
//
// **AUTHENTICATION, AND THE ORDER A BASIC USERNAME IS READ IN.** RFC 7030
// section 3.2.3 allows HTTP Basic and section 3.3.2 a TLS client certificate.
// A Basic username is looked up as a PERSON first, then as an APPLICATION's
// client_id, and — when it is neither — handed to the person path anyway,
// because an administrator of the SERVICE may have no entry in this realm and
// `authenticatePerson()` is where that case is decided. So a person and an
// application sharing a name authenticate as the person, and an application
// that wants to enroll under a name somebody also signs in with has to be given
// a client_id that is not a username. A request with no Authorization header is
// authenticated by its TLS client certificate when there is one; with neither,
// it is refused 401 with `WWW-Authenticate: Basic realm="EST"`.
//
// **THE ORDER OF THE CHECKS IS A DECISION.** Enabled, then transport, then the
// label, then the method-specific settings, then the rate limit, then the media
// type and the size — all of which are decided without reading a credential or
// a body — and only then authentication, and only after THAT the body. An
// unauthenticated client is never the reason this service decodes and verifies
// a CSR.
//
// **WHAT IS NOT DONE, AND WHY** — the documented exceptions, argued at length
// in `est/CLAUDE.md`:
//   * Full CMC (section 4.3) answers 501.
//   * RFC 7030 section 3.5's tls-unique channel binding is not implemented:
//     TLS 1.3 has no tls-unique (RFC 8446 section C.5 and RFC 9266), and this
//     service prefers TLS 1.3. A CSR's challengePassword is therefore not read
//     as a binding and is ignored by EST.
//   * A 202 with Retry-After (section 4.2.3) is never sent: every request is
//     decided at once, issued or refused.
//   * /serverkeygen does not encrypt the private key (section 4.4.1.2). A
//     template asking for that is refused 501, as the RFC requires, rather than
//     answered with a key in the clear it did not ask for.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `Est` takes the modules it uses through its constructor
// (`EstDeps`). Since #50's R2 the composition root builds the instance
// (`Est.defaultDeps()`) and installs it; the module's old export names are
// FACADES that forward to it, for the JavaScript callers, and a process without
// the root builds a default when the module finishes loading. `Est` is exported
// beside them for the composition root.
//
// **THE ROUTES ARE REGISTERED BY `registerRoutes()`**, which the module
// exports and `common/protocol_stack.ts` calls (#50, R1) at the point in the
// route order where requiring this module used to register them, so rule 1's
// order is unchanged. Requiring the module registers nothing.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import validation = require('../common/validation');
import applications = require('../common/applications');
import core = require('../common/cert_enrollment');
import monitor = require('../common/enrollment_monitor');
import keyMaterial = require('../common/vendored/key_material');
import x509 = require('../common/vendored/x509');
import mtls = require('../oauth-oidc/mtls');
import codec = require('./est_codec');
import InstanceSlot = require('../common/instance_slot');
// WHICH CELL ANSWERS (#98 D10): the cell map, the placement helpers and the
// routing index. Libraries; each is a no-op in a single-cell service.
import cells = require('../common/cells');
import cellPlacement = require('../common/cell_placement');
import cellRouting = require('../common/cell_routing');

/**
 * The enrollment family's name in the core and the monitor, `est`.
 */
const FAMILY = 'est';

/**
 * The base path of every EST operation, `/.well-known/est`.
 */
const BASE = '/.well-known/est';

// The six operations, and the one method each answers. HEAD is answered for a
// GET by Express itself.
/**
 * The six operations of RFC 7030 and the one method each answers.
 */
const OPERATIONS = [
  { name: 'cacerts', method: 'GET' },
  { name: 'simpleenroll', method: 'POST' },
  { name: 'simplereenroll', method: 'POST' },
  { name: 'serverkeygen', method: 'POST' },
  { name: 'csrattrs', method: 'GET' },
  { name: 'fullcmc', method: 'POST' }
];

// Every path this module registers, for `sts_metadata.js` and the endpoints
// table to be checked against.
/**
 * Every path this module registers: each operation under the base and under
 * `/:label`.
 */
const PATHS = [];
OPERATIONS.forEach(function (op) {
  PATHS.push(BASE + '/' + op.name);
});
OPERATIONS.forEach(function (op) {
  PATHS.push(BASE + '/:label/' + op.name);
});

/**
 * The media types EST reads and writes: PKCS#10, certs-only CMS, CSR attributes
 * and PKCS#8.
 */
const MEDIA = {
  pkcs10: 'application/pkcs10',
  certsOnly: 'application/pkcs7-mime; smime-type=certs-only',
  csrattrs: 'application/csrattrs',
  pkcs8: 'application/pkcs8'
};

// No EST operation takes a query string.
const NO_QUERY = validation.z.strictObject({});

// A label is a profile id's shape before it is a profile id; anything longer or
// stranger is not looked up at all.
const LABEL_SHAPE = /^[a-z][a-z-]{0,39}$/;

// The largest Authorization header read. A Basic credential for a 256-character
// name and a long password is well inside it.
const MAX_AUTHORIZATION = 4096;

// The statuses a refusal is COUNTED at against the caller's rate limit: the
// ones a guessing client produces. A 404 label, a 405, a 501 and a 503 are the
// server's own shape and are not.
const COUNTED_STATUSES = [400, 401, 403, 409, 413, 415];

// What `Est` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface EstDeps {
  log: typeof log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  applications: typeof applications;
  core: typeof core;
  monitor: typeof monitor;
  keyMaterial: typeof keyMaterial;
  x509: typeof x509;
  mtls: typeof mtls;
  codec: typeof codec;
  cells: typeof cells;
  cellPlacement: typeof cellPlacement;
  cellRouting: typeof cellRouting;
  // Required when first called, as the JavaScript did, for the reason
  // given where each is called.
  loadPkijs(): typeof import('pkijs');
  loadAsn1js(): typeof import('asn1js');
}

type RouteApp = typeof app;

/**
 * Enrollment over Secure Transport (RFC 7030, with RFC 8951): the six
 * operations under `/.well-known/est/` and `/.well-known/est/<label>/`, where a
 * label names a certificate profile.
 *
 * It authenticates in EST's own way (HTTP Basic, or a TLS client certificate),
 * reads the body, and leaves every decision about what may be issued to
 * `common/cert_enrollment.ts`. Nothing about a credential or a body is read
 * before the checks that need neither.
 */
class Est {
  /**
   * Builds the server from its dependencies.
   *
   * @param deps - the modules it reads, from `Est.defaultDeps()` or the
   * composition root
   */
  constructor(private readonly deps: EstDeps) {
    deps.log.debug("Entering Est.constructor().");
    deps.log.debug("Leaving Est.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  /**
   * Returns the real modules the server depends on, as the composition root
   * passes them.
   *
   * @returns the dependencies
   */
  static defaultDeps(): EstDeps {
    log.debug("Entering Est.defaultDeps().");
    log.debug("Leaving Est.defaultDeps().");
    return {
      log: log,
      config: config,
      errorCodes: errorCodes,
      validation: validation,
      applications: applications,
      core: core,
      monitor: monitor,
      keyMaterial: keyMaterial,
      x509: x509,
      mtls: mtls,
      codec: codec,
      cells: cells,
      cellPlacement: cellPlacement,
      cellRouting: cellRouting,
      loadPkijs: function () {
        return require('pkijs');
      },
      loadAsn1js: function () {
        return require('asn1js');
      }
    };
  }

  // ---------------------------------------------------------------------------
  // ANSWERS.
  // ---------------------------------------------------------------------------

  // Record one request in the family monitor. Never throws.
  /**
   * Records one request in the enrollment monitor. Never throws.
   *
   * @param ctx - the request's context: operation, profile, identity and target
   * @param detail - the outcome, status and anything else to record
   */
  counted(ctx, detail) {
    const { log, monitor } = this.deps;
    log.debug("Entering Est.counted().");
    monitor.record(FAMILY, Object.assign({
      operation: ctx.op,
      profile: ctx.profile || null,
      principal: ctx.identity || null,
      target: ctx.targetUri || null
    }, detail || {}));
    log.debug("Leaving Est.counted().");
  }

  /**
   * Answers an EST refusal with a one-sentence text body, recording it in the
   * monitor and, for a status a guessing client produces, against the caller's
   * rate limit. The caller has marked the error code on `res`.
   *
   * @param req - the request
   * @param res - the response
   * @param ctx - the request's context
   * @param status - the HTTP status
   * @param sentence - what is wrong
   * @param headers - extra response headers
   */
  // THE ONE REFUSAL WRITER. The caller has marked the code on `res` on the line
  // before, so the code travels to the audit row and the monitor and never into
  // the body. The body is one sentence of text, which is all RFC 7030 section
  // 4.2.3 asks of an error ("a human-readable error message").
  // error-code: none — the definition of this helper, not a call to it
  estError(req, res, ctx, status, sentence, headers?) {
    const { log, errorCodes, core } = this.deps;
    const self = this;
    log.debug("Entering Est.estError(). status=" + status);
    const code = errorCodes.codeOf(res) || '';
    // error-code: none — the monitor row carries the code the caller marked.
    this.counted(ctx, { outcome: 'refused', status: status, errorCode: code });
    if (COUNTED_STATUSES.indexOf(status) >= 0 && core.sharesThrottle() &&
        status !== 429) {
      // WHERE THE THROTTLE IS SHARED THE COUNT DECIDES THE ANSWER (2026-09-14):
      // a refusal whose count took the caller past the limit is answered with
      // the throttle's 429, so a burst of wrong credentials across nodes gets
      // at most `limit` answers about the credential.
      // `core.countFailureShared()`.
      core.countFailureShared(FAMILY, req, ctx.identity || '')
        .then(function (overLimit) {
          if (!overLimit) {
            self.sendEstError(res, status, sentence, headers);
            return;
          }
          errorCodes.mark(res, 'STS-ENROLL-0061');
          self.sendEstError(res, 429, overLimit.why, {
            'Retry-After': String(core.retryAfterOf(overLimit))
          });
        });
      log.info('est: ' + ctx.op + ' refused ' + status + ' ' + code + ' for ' +
               (ctx.identity || 'an unauthenticated client') +
               ' (counted against the shared throttle first)');
      log.debug("Leaving Est.estError(). Counting first.");
      return undefined;
    }
    if (COUNTED_STATUSES.indexOf(status) >= 0) {
      core.countFailure(FAMILY, req, ctx.identity || '');
    }
    this.sendEstError(res, status, sentence, headers);
    log.info('est: ' + ctx.op + ' refused ' + status + ' ' + code + ' for ' +
             (ctx.identity || 'an unauthenticated client'));
    log.debug("Leaving Est.estError().");
    return undefined;
  }

  // The bytes of an EST refusal.
  /**
   * Writes the bytes of an EST refusal, unless the headers are already sent.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param sentence - the text body
   * @param headers - extra response headers
   */
  sendEstError(res, status, sentence, headers) {
    const { log } = this.deps;
    log.debug("Entering Est.sendEstError(). status=" + status);
    if (!res.headersSent) {
      Object.keys(headers || {}).forEach(function (name) {
        res.set(name, headers[name]);
      });
      res.status(status)
         .set('Cache-Control', 'no-store')
         .type('text/plain')
         .send(String(sentence || 'The request was refused.') + '\n');
    }
    log.debug("Leaving Est.sendEstError().");
  }

  // A refusal the core returned, answered with its own status and sentence. A
  // 401 carries the Basic challenge where Basic is accepted; a 429 carries
  // Retry-After.
  /**
   * Answers a refusal the core returned with its own status and sentence: a 401
   * carries the Basic challenge where Basic is accepted, and a 429 carries
   * `Retry-After`.
   *
   * @param req - the request
   * @param res - the response
   * @param ctx - the request's context
   * @param refusal - the core's refusal
   * @param fallbackCode - the error code to mark when the refusal carries none
   */
  refuseWith(req, res, ctx, refusal, fallbackCode?) {
    const { log, config, core, errorCodes } = this.deps;
    log.debug("Entering Est.refuseWith().");
    const status = Number(refusal && refusal.status) || 400;
    const headers = {};
    if (status === 401 && config.value('est.basicAuthentication') !== false) {
      headers['WWW-Authenticate'] = 'Basic realm="EST"';
    }
    if (status === 429) {
      headers['Retry-After'] = String(core.retryAfterOf(refusal));
    }
    const sentence = ((refusal && refusal.errors) || [])[0] ||
                     (refusal && refusal.why) || 'The request was refused.';
    log.debug("Leaving Est.refuseWith().");
    errorCodes.mark(res, errorCodes.codeOf(refusal) || fallbackCode ||
                         'STS-EST-0020');
    return this.estError(req, res, ctx, status, sentence, headers);
  }

  // A body answered base64, as RFC 8951 section 3 requires of every EST
  // response that carries DER.
  /**
   * Answers 200 with a DER body in base64, as RFC 8951 section 3 requires.
   *
   * @param res - the response
   * @param contentType - the media type
   * @param der - the bytes
   */
  sendBase64(res, contentType, der) {
    const { log, codec } = this.deps;
    log.debug("Entering Est.sendBase64().");
    res.status(200)
       .set('Content-Type', contentType)
       .set('Content-Transfer-Encoding', 'base64')
       .set('Cache-Control', 'no-store')
       .send(Buffer.from(codec.base64Lines(der), 'latin1'));
    log.debug("Leaving Est.sendBase64().");
  }

  // ---------------------------------------------------------------------------
  // THE CHECKS EVERY OPERATION MAKES BEFORE READING A CREDENTIAL.
  // Returns true when the request has been answered.
  // ---------------------------------------------------------------------------
  /**
   * Makes the checks every operation makes before reading a credential: no
   * query string, EST enabled, the transport, and the label.
   *
   * @param req - the request
   * @param res - the response
   * @param ctx - the request's context, given the profile
   * @returns true when the request has been answered
   */
  refusedBeforeAuthentication(req, res, ctx) {
    const { log, validation, errorCodes, config, core } = this.deps;
    log.debug("Entering Est.refusedBeforeAuthentication(). op=" + ctx.op);
    const query = validation.check(req, 'query', NO_QUERY);
    if (!query.ok) {
      errorCodes.mark(res, 'STS-EST-0019');
      this.estError(req, res, ctx, 400,
                    'No EST operation takes a query string: ' +
                    query.detail);
      log.debug("Leaving Est.refusedBeforeAuthentication(). A query.");
      return true;
    }
    if (config.value('est.enabled') === false) {
      errorCodes.mark(res, 'STS-EST-0001');
      this.estError(req, res, ctx, 503, 'EST is turned off in this realm ' +
                    '(est.enabled).');
      log.debug("Leaving Est.refusedBeforeAuthentication(). Disabled.");
      return true;
    }
    const transport = core.transportRefusal(req, FAMILY);
    if (transport) {
      this.refuseWith(req, res, ctx, transport);
      log.debug("Leaving Est.refusedBeforeAuthentication(). Transport.");
      return true;
    }
    const label = req.params ? req.params.label : undefined;
    if (label !== undefined) {
      const known = LABEL_SHAPE.test(String(label)) &&
        (core.PROFILE_IDS.indexOf(String(label)) >= 0 ||
         String(label) === core.DEVICE_PROFILE ||
         core.REFUSED_PROFILES.some(function (one) {
           return one.id === String(label);
         }));
      // A LABEL THAT NAMES A TRUST REALM, reached here only when the realm
      // was already named — by the `/realm/<id>` prefix or by a label segment
      // before this one — because `realms.matchPath()` enters a realm named
      // in the first label position and strips it (#251). A request names
      // its realm once, so this is refused rather than read as a second
      // realm or as a profile.
      if (!known && realms.get(String(label)) &&
          String(label) !== realms.DEFAULT_ID) {
        errorCodes.mark(res, 'STS-EST-0022');
        this.estError(req, res, ctx, 404, 'The EST label "' +
                      String(label).slice(0, 40) + '" names a trust realm, ' +
                      'and this request already named one. Name the realm ' +
                      'once: /.well-known/est/<realm>/[<profile>/]' +
                      '<operation> or /realm/<realm>/.well-known/est/' +
                      '[<profile>/]<operation>.');
        log.debug("Leaving Est.refusedBeforeAuthentication(). A realm, " +
                  "named twice.");
        return true;
      }
      if (!known) {
        errorCodes.mark(res, 'STS-EST-0002');
        this.estError(req, res, ctx, 404, 'There is no EST label "' +
                      String(label).slice(0, 40) + '" here. A label is a ' +
                      'certificate profile, one of: ' +
                      core.PROFILE_IDS.concat([core.DEVICE_PROFILE])
                        .join(', ') +
                      '.');
        log.debug("Leaving Est.refusedBeforeAuthentication(). Unknown label.");
        return true;
      }
      ctx.labelled = true;
      ctx.profile = String(label);
    } else {
      ctx.labelled = false;
      ctx.profile = core.defaultProfile(FAMILY);
    }
    // A label always has to be a profile this realm issues; the unlabelled path
    // is refused for its default profile only where it would issue with it — a
    // client asking an unlabelled /cacerts is asking for the CA, not a profile.
    const enrolling = ['simpleenroll', 'simplereenroll', 'serverkeygen']
      .indexOf(ctx.op) >= 0;
    // STRUCTURAL ONLY before the credential (rcbj, 2026-10-01): whether the
    // label is a profile at all. Whether it is ALLOWED depends on whose
    // request it is — an application's own list overrides the realm's — so
    // `core.issue()` asks that once it knows the entry.
    if (ctx.labelled || (enrolling && ctx.op !== 'simplereenroll')) {
      const profile = core.checkProfile(FAMILY, ctx.profile, null,
                                        { structural: true });
      if (!profile.ok) {
        this.refuseWith(req, res, ctx, profile);
        log.debug("Leaving Est.refusedBeforeAuthentication(). Profile.");
        return true;
      }
    }
    log.debug("Leaving Est.refusedBeforeAuthentication(). Passed.");
    return false;
  }

  // The checks an enrollment makes of the REQUEST before its credential: the
  // rate limit, the media type, the size.
  // ASYNCHRONOUS SINCE 2026-09-14 (#46): the throttle is the cluster's one
  // budget (`throttledShared()`), which is a round trip.
  /**
   * Makes an enrollment's checks of the request before its credential: the
   * cluster's shared rate limit, the media type and the size.
   *
   * @param req - the request
   * @param res - the response
   * @param ctx - the request's context
   * @returns a promise of true when the request has been answered
   */
  async refusedBeforeBody(req, res, ctx) {
    const { log, core, errorCodes, config } = this.deps;
    log.debug("Entering Est.refusedBeforeBody().");
    const throttled = await core.throttledShared(FAMILY, req,
                                                 ctx.identity || '');
    if (throttled) {
      this.refuseWith(req, res, ctx, throttled);
      log.debug("Leaving Est.refusedBeforeBody(). Throttled.");
      return true;
    }
    const type = String(req.headers['content-type'] || '').split(';')[0]
      .trim().toLowerCase();
    if (type !== MEDIA.pkcs10) {
      errorCodes.mark(res, 'STS-EST-0006');
      this.estError(req, res, ctx, 415,
                    'An EST enrollment body is ' + MEDIA.pkcs10 +
                    ' (RFC 7030 section 4.2.1), and this one was "' +
                    type.slice(0, 80) + '".');
      log.debug("Leaving Est.refusedBeforeBody(). Media type.");
      return true;
    }
    const max = Number(config.value('est.maxRequestBytes'));
    const declared = Number(req.headers['content-length']);
    const bytes = Buffer.isBuffer(req.body) ? req.body.length : 0;
    if ((Number.isFinite(declared) && declared > max) || bytes > max) {
      errorCodes.mark(res, 'STS-EST-0007');
      this.estError(req, res, ctx, 413,
                    'The request body is larger than the ' + max +
                    ' bytes est.maxRequestBytes allows.');
      log.debug("Leaving Est.refusedBeforeBody(). Too large.");
      return true;
    }
    log.debug("Leaving Est.refusedBeforeBody(). Passed.");
    return false;
  }

  // ---------------------------------------------------------------------------
  // AUTHENTICATION.
  // ---------------------------------------------------------------------------

  // The Authorization header, READ but not believed: which scheme, and for
  // Basic the name and password. A malformed Basic credential is reported as
  // such rather than as a wrong password.
  /**
   * Reads the Authorization header without believing it: which scheme, and for
   * Basic the name and password.
   *
   * @param req - the request
   * @returns `{ present, basic, username, password }`, or `malformed` for a
   * Basic credential that does not decode
   */
  basicCredentialOf(req) {
    const { log, core } = this.deps;
    log.debug("Entering Est.basicCredentialOf().");
    const header = String(req.headers.authorization || '');
    if (!header) {
      log.debug("Leaving Est.basicCredentialOf(). None.");
      return { present: false };
    }
    if (!/^basic(\s|$)/i.test(header)) {
      log.debug("Leaving Est.basicCredentialOf(). Another scheme.");
      return { present: true, basic: false };
    }
    const match = /^basic\s+([A-Za-z0-9+/]+={0,2})\s*$/i.exec(header);
    if (!match || header.length > MAX_AUTHORIZATION ||
        match[1].length % 4 !== 0) {
      log.debug("Leaving Est.basicCredentialOf(). Malformed.");
      return { present: true, basic: true, malformed: true };
    }
    const decoded = Buffer.from(match[1], 'base64');
    if (decoded.toString('base64') !== match[1]) {
      log.debug("Leaving Est.basicCredentialOf(). Not canonical.");
      return { present: true, basic: true, malformed: true };
    }
    const text = decoded.toString('utf8');
    const colon = text.indexOf(':');
    const username = colon > 0 ? text.slice(0, colon) : '';
    if (colon < 1 || !core.wellFormedId(username)) {
      log.debug("Leaving Est.basicCredentialOf(). No usable name.");
      return { present: true, basic: true, malformed: true };
    }
    log.debug("Leaving Est.basicCredentialOf().");
    return { present: true, basic: true, username: username,
             password: text.slice(colon + 1) };
  }

  /**
   * Says whether a name is an application's client_id or identifier in the
   * realm.
   *
   * @param clientId - the name
   * @returns true when an application answers to it
   */
  applicationNamed(clientId) {
    const { log, applications } = this.deps;
    log.debug("Entering Est.applicationNamed().");
    let view = null;
    try {
      view = applications.forClientId(clientId) || applications.get(clientId);
    } catch (e) {
      log.debug("Caught in Est.applicationNamed(): " + ((e && e.message) || e));
      view = null;
    }
    log.debug("Leaving Est.applicationNamed().");
    return !!(view && view.identifier);
  }

  // Is certificate authentication on for the certificate presented? The
  // realm's switch, unless the certificate NAMES an application (read, not
  // believed: it is verified next either way) whose own
  // estCertificateAuthentication says otherwise (rcbj, 2026-10-01).
  /**
   * Answers whether EST accepts the presented client certificate's method:
   * the named application's own switch where it set one, the realm's
   * otherwise.
   *
   * @param req - the request
   * @returns true when certificate authentication is on for it
   */
  certificateAuthenticationOn(req) {
    const { log, core, mtls } = this.deps;
    log.debug("Entering Est.certificateAuthenticationOn().");
    const presented = mtls.peerCertificate(req);
    let named = null;
    try {
      named = presented && presented.raw
        ? core.entryNamedByCertificate(Buffer.from(presented.raw)) : null;
    } catch (e) {
      log.debug("Caught in Est.certificateAuthenticationOn(): " +
                ((e && e.message) || e));
      named = null;
    }
    const entry = named && named.kind === 'application' ? named : null;
    log.debug("Leaving Est.certificateAuthenticationOn().");
    return core.estSwitch('certificateAuthentication', entry);
  }

  // { ok, principal } or a marked refusal the caller answers with.
  /**
   * Authenticates an enrollment: HTTP Basic, as a person first and then as an
   * application, or, with no Authorization header, the TLS client certificate.
   *
   * @param req - the request
   * @param ctx - the request's context, carrying the parsed `basic` credential
   * @returns a promise of `{ ok, principal }`, or a marked refusal
   */
  async authenticate(req, ctx) {
    const { log, core, config, mtls } = this.deps;
    log.debug("Entering Est.authenticate().");
    const basic = ctx.basic;
    if (basic.present) {
      if (!basic.basic) {
        log.debug("Leaving Est.authenticate(). Not Basic.");
        return core.refuse('STS-EST-0013', 401, 'EST accepts HTTP Basic ' +
                           '(RFC 7030 section 3.2.3) and no other ' +
                           'Authorization scheme.');
      }
      // Off for the realm, unless the name is an application whose own
      // estBasicAuthentication turns it on (rcbj, 2026-10-01: the
      // application's setting overrides the realm's). Its secret is still
      // checked below; the name only chooses which switch is asked.
      const basicOn = config.value('est.basicAuthentication') !== false ||
        (!core.resolveEntry('person', basic.username).ok &&
         this.applicationNamed(basic.username) &&
         core.estSwitch('basicAuthentication',
                        { kind: 'application', id: basic.username }));
      if (!basicOn) {
        log.debug("Leaving Est.authenticate(). Basic is off.");
        return core.refuse('STS-EST-0010', 401, 'HTTP Basic is turned off ' +
                           'for EST in this realm (est.basicAuthentication).');
      }
      if (basic.malformed) {
        log.debug("Leaving Est.authenticate(). Malformed Basic.");
        return core.refuse('STS-EST-0011', 401,
                           'The HTTP Basic credential is ' +
                           'malformed: it must be base64 of a name, a colon ' +
                           'and a password (RFC 7617).');
      }
      // A person first; an application's client_id second; and a name that is
      // neither is still the person path, where an administrator of the service
      // with no entry in this realm is recognised (see the header).
      if (core.resolveEntry('person', basic.username).ok ||
          !this.applicationNamed(basic.username)) {
        const person = await core.authenticatePerson(basic.username,
                                                     basic.password,
                                                     'est-basic');
        log.debug("Leaving Est.authenticate(). Person path ok=" + !!person.ok);
        return person;
      }
      const application = await core.authenticateApplication(basic.username,
                                                             basic.password,
                                                             'est-basic');
      log.debug("Leaving Est.authenticate(). Application path ok=" +
                !!application.ok);
      return application;
    }
    if (mtls.peerCertificate(req)) {
      if (!this.certificateAuthenticationOn(req)) {
        log.debug("Leaving Est.authenticate(). Certificates are off.");
        return core.refuse('STS-EST-0012', 401, 'TLS client certificate ' +
                           'authentication is turned off for EST in this ' +
                           'realm (est.certificateAuthentication).');
      }
      const byCertificate =
        await core.authenticateCertificate(req, 'est-certificate');
      log.debug("Leaving Est.authenticate(). Certificate ok=" +
                !!byCertificate.ok);
      return byCertificate;
    }
    log.debug("Leaving Est.authenticate(). No credential.");
    return core.refuse('STS-EST-0009', 401, 'This EST operation is ' +
                       'authenticated: send HTTP Basic, or present a TLS ' +
                       'client certificate this realm issued.');
  }

  // The label a request is counted and rate-limited under before it has been
  // authenticated: the Basic name, or the presented certificate's serial.
  /**
   * Returns the label a request is counted and rate-limited under before it is
   * authenticated: the Basic name, or the presented certificate's serial.
   *
   * @param req - the request
   * @param basic - what `basicCredentialOf()` read
   * @returns the label; empty when there is none
   */
  identityHintOf(req, basic) {
    const { log, mtls, core } = this.deps;
    log.debug("Entering Est.identityHintOf().");
    if (basic.present && basic.username) {
      log.debug("Leaving Est.identityHintOf(). Basic.");
      return basic.username;
    }
    const presented = basic.present ? null : mtls.peerCertificate(req);
    log.debug("Leaving Est.identityHintOf().");
    return presented && presented.serialNumber
      ? 'certificate:' + core.normalSerial(presented.serialNumber) : '';
  }

  /**
   * Returns a principal as `kind:id`.
   *
   * @param principal - the principal
   * @returns the label; empty for none
   */
  principalLabel(principal) {
    const { log } = this.deps;
    log.debug("Entering Est.principalLabel().");
    log.debug("Leaving Est.principalLabel().");
    return principal ? principal.kind + ':' + principal.id : '';
  }

  // ---------------------------------------------------------------------------
  // WHICH CELL ANSWERS AN ENROLLMENT (#98 D10), decided before the throttle,
  // the credential and the body: the entry the request authenticates as is
  // held — its password, its enrolled certificates, the certificates about
  // to be written onto it — only by the cell it is homed in, so the request
  // is relayed there WHOLE, its client certificate with it (the channel
  // forwards it as the front process hands one to a request worker). What
  // names the entry is READ, NOT BELIEVED, and chooses only where it is
  // checked:
  //
  //   * **an HTTP Basic username** — a person's login name goes to their
  //     home cell. An application's client_id is not a person the routing
  //     index knows, so it is served here: an application's entry is the
  //     global tier's and every cell holds it.
  //   * **a TLS client certificate**, when there is no Authorization header
  //     (the order `authenticate()` reads them in) — the person its
  //     `urn:sts:person:` subjectAltName names goes home the same way.
  //
  // A name nobody knows, or a certificate naming no person, is served here
  // and refused here for its own reasons. A single-cell service places
  // nothing.
  // ---------------------------------------------------------------------------
  /**
   * Relays an enrollment to the home cell of the person its credential
   * names, when that is another cell.
   *
   * @param req - the request
   * @param res - the response
   * @param basic - what `basicCredentialOf()` read
   * @returns a promise of true when the request was relayed
   */
  async placeRequest(req, res, basic): Promise<boolean> {
    const { log, mtls, core, cells, cellPlacement } = this.deps;
    log.debug("Entering Est.placeRequest().");
    if (!cells.isMulti() || req.stsCellRelay) {
      log.debug("Leaving Est.placeRequest(). Here.");
      return false;
    }
    const realmId = realms.currentId();
    if (basic.present) {
      const named = basic.basic && !basic.malformed && basic.username
        ? String(basic.username) : '';
      log.debug("Leaving Est.placeRequest(). By the Basic name.");
      return named
        ? cellPlacement.relayToHome(req, res, realmId, 'name', named,
                                    'est:basic')
        : false;
    }
    const presented = mtls.peerCertificate(req);
    const entry = presented && presented.raw
      ? core.entryNamedByCertificate(Buffer.from(presented.raw)) : null;
    log.debug("Leaving Est.placeRequest(). By the client certificate.");
    return entry && entry.kind === 'person'
      ? cellPlacement.relayToHome(req, res, realmId, 'name', entry.id,
                                  'est:certificate')
      : false;
  }

  // A TARGET HOMED IN ANOTHER CELL (#98). The request was placed by its
  // CREDENTIAL, which is right for everything but one case: an administrator
  // enrolling on somebody else's behalf, whose own home and the target's can
  // differ. The certificate is written onto the target's entry, which only
  // its home cell holds, and the administrator's password is checked only
  // at theirs — one relay cannot reach both. So it is refused with a
  // sentence that says why, rather than as "there is no such person"
  // (STS-ENROLL-0012), which would be false. `est/CLAUDE.md` records it.
  /**
   * Refuses an enrollment whose target person is homed in another cell.
   *
   * @param req - the request
   * @param res - the response
   * @param ctx - the request's context
   * @param target - the entry the certificate is for
   * @returns a promise of true when the request was refused
   */
  async refusedAsElsewhere(req, res, ctx, target): Promise<boolean> {
    const { log, core, cells, cellRouting } = this.deps;
    log.debug("Entering Est.refusedAsElsewhere().");
    if (!cells.isMulti() || !target || target.kind !== 'person' ||
        core.resolveEntry('person', target.id).ok) {
      log.debug("Leaving Est.refusedAsElsewhere(). Here.");
      return false;
    }
    const home = await cellRouting.homeOf(realms.currentId(), 'name',
                                          target.id);
    if (!home || home === cells.id()) {
      log.debug("Leaving Est.refusedAsElsewhere(). Not homed elsewhere.");
      return false;
    }
    this.refuseWith(req, res, ctx, core.refuse('STS-CELL-0101', 403,
      'The person "' + target.id + '" is homed in another region of this ' +
      'service, and a certificate is written onto their entry only there. ' +
      'Enroll as that person, or ask an administrator homed in their ' +
      'region.'));
    log.debug("Leaving Est.refusedAsElsewhere(). Refused.");
    return true;
  }

  // The common start of the three enrollments: the pre-body checks, the
  // credential, and the body decoded and parsed. Answers `null` when it has
  // already answered.
  /**
   * Runs the common start of the three enrollments: the pre-body checks, the
   * credential, and the body decoded and parsed as a PKCS#10 request.
   *
   * @param req - the request
   * @param res - the response
   * @param ctx - the request's context
   * @param parseOptions - passed to the core's CSR parser
   * @returns a promise of the parsed request, or null when the request has been
   * answered
   */
  async enrollmentRequest(req, res, ctx, parseOptions?) {
    const { log, codec, errorCodes, core } = this.deps;
    log.debug("Entering Est.enrollmentRequest().");
    ctx.basic = this.basicCredentialOf(req);
    ctx.identity = this.identityHintOf(req, ctx.basic);
    // FIRST, before the throttle reads its window (#98 D10): see
    // `placeRequest()`.
    if (await this.placeRequest(req, res, ctx.basic)) {
      log.debug("Leaving Est.enrollmentRequest(). Relayed to another cell.");
      return null;
    }
    if (await this.refusedBeforeBody(req, res, ctx)) {
      log.debug("Leaving Est.enrollmentRequest(). Refused before the body.");
      return null;
    }
    const authenticated = await this.authenticate(req, ctx);
    if (!authenticated.ok) {
      this.refuseWith(req, res, ctx, authenticated);
      log.debug("Leaving Est.enrollmentRequest(). Not authenticated.");
      return null;
    }
    ctx.principal = authenticated.principal;
    ctx.identity = this.principalLabel(ctx.principal);
    const decoded = codec.decodeBody(req.body);
    if (!decoded.ok) {
      errorCodes.mark(res, 'STS-EST-0008');
      this.estError(req, res, ctx, 400, decoded.why);
      log.debug("Leaving Est.enrollmentRequest(). Not base64.");
      return null;
    }
    const csr = await core.parseCsr(decoded.der, parseOptions || {});
    if (!csr.ok) {
      this.refuseWith(req, res, ctx, csr);
      log.debug("Leaving Est.enrollmentRequest(). The CSR was refused.");
      return null;
    }
    log.debug("Leaving Est.enrollmentRequest(). key=" + csr.keyAlg);
    return csr;
  }

  // The certificate the core issued, as RFC 7030 section 4.2.3 returns it.
  /**
   * Answers an issued certificate as RFC 7030 section 4.2.3 returns it: a
   * certs-only message in base64.
   *
   * @param res - the response
   * @param ctx - the request's context
   * @param issued - what the core issued
   */
  answerIssued(res, ctx, issued) {
    const { log, core, codec } = this.deps;
    log.debug("Entering Est.answerIssued().");
    ctx.targetUri = core.entryUri(issued.target);
    this.counted(ctx, { outcome: 'issued', status: 200,
                        serialHex: issued.record.serialHex });
    this.sendBase64(res, MEDIA.certsOnly,
                    codec.certsOnly([issued.record.certificatePem]));
    log.info('est: ' + ctx.op + ' issued ' + issued.record.profile +
             ' serial ' +
             issued.record.serialHex + ' for ' + ctx.targetUri + ' to ' +
             ctx.identity);
    log.debug("Leaving Est.answerIssued().");
  }

  // ---------------------------------------------------------------------------
  // THE OPERATIONS.
  // ---------------------------------------------------------------------------

  // 4.1 — the CA certificates: the EST Issuing CA, this realm's Intermediate
  // and the service Root. Unauthenticated, as section 4.1.1 says it MUST be: a
  // client needs the anchor before it can check anything else.
  /**
   * Answers `cacerts` (section 4.1): the EST Issuing CA, the realm's
   * Intermediate and the service Root. Unauthenticated.
   *
   * @param req - the request
   * @param res - the response
   * @param ctx - the request's context
   * @returns a promise that settles when it has answered
   */
  async cacerts(req, res, ctx) {
    const { log, core, errorCodes, codec } = this.deps;
    log.debug("Entering Est.cacerts().");
    const chain = await core.ensureAuthority(FAMILY);
    if (!chain.ok) {
      errorCodes.mark(res, 'STS-EST-0014');
      this.estError(req, res, ctx, 503,
                    'This realm has no certificate hierarchy ' +
                    'yet, so there is no EST CA certificate to return. Build ' +
                    'one on /admin/pki.');
      log.debug("Leaving Est.cacerts(). No hierarchy.");
      return;
    }
    this.counted(ctx, { outcome: 'answered', status: 200 });
    this.sendBase64(res, MEDIA.certsOnly, codec.certsOnly(chain.chainPem));
    log.debug("Leaving Est.cacerts().");
  }

  // 4.2.1 — a certificate for a key the client holds.
  /**
   * Answers `simpleenroll` (section 4.2.1): a certificate for a key the client
   * holds.
   *
   * @param req - the request
   * @param res - the response
   * @param ctx - the request's context
   * @returns a promise that settles when it has answered
   */
  async simpleenroll(req, res, ctx) {
    const { log, core } = this.deps;
    log.debug("Entering Est.simpleenroll().");
    const csr = await this.enrollmentRequest(req, res, ctx);
    if (!csr) {
      log.debug("Leaving Est.simpleenroll(). Answered.");
      return;
    }
    const target = core.targetFromRequest(csr.requested, csr.commonName,
                                          ctx.principal);
    if (!target.ok) {
      this.refuseWith(req, res, ctx, target);
      log.debug("Leaving Est.simpleenroll(). No target.");
      return;
    }
    if (await this.refusedAsElsewhere(req, res, ctx, target.target)) {
      log.debug("Leaving Est.simpleenroll(). Homed in another cell.");
      return;
    }
    ctx.targetUri = core.entryUri(target.target);
    const issued = await core.issue({
      family: FAMILY, profile: ctx.profile, principal: ctx.principal,
      target: target.target, publicKeyPem: csr.publicKeyPem,
      requested: csr.requested, keySource: 'client', keyAlg: csr.keyAlg,
      // The request's key attestation, read only by the device profile
      // (#164 phase 2, `core.issueForDevice()`).
      attestations: csr.attestations,
      // The unlabelled path's profile is the realm default, which an
      // application's own default replaces (2026-10-01).
      profileDefaulted: !ctx.labelled,
      via: 'est:simpleenroll'
    });
    if (!issued.ok) {
      this.refuseWith(req, res, ctx, issued);
      log.debug("Leaving Est.simpleenroll(). Refused by the core.");
      return;
    }
    this.answerIssued(res, ctx, issued);
    log.debug("Leaving Est.simpleenroll().");
  }

  // The subject of a certificate in `parseCsr()`'s spelling — `type=value` by
  // OID, in encoded order — so a request and a certificate compare as equal
  // only when they carry the same attributes in the same order.
  /**
   * Returns a certificate's subject in the CSR parser's spelling, so a request
   * and a certificate compare equal only with the same attributes in the same
   * order.
   *
   * @param pem - the certificate
   * @returns the subject, or null when it cannot be read
   */
  subjectOfCertificate(pem) {
    const { log, loadPkijs, loadAsn1js, codec } = this.deps;
    log.debug("Entering Est.subjectOfCertificate().");
    const pkijs = loadPkijs();
    const asn1js = loadAsn1js();
    let subject = null;
    try {
      const der = codec.pemToDer(pem);
      const parsed = asn1js.fromBER(der.buffer.slice(der.byteOffset,
                                                     der.byteOffset +
                                                     der.byteLength));
      const cert = new pkijs.Certificate({ schema: parsed.result });
      subject = cert.subject.typesAndValues.map(function (tv) {
        const block = tv.value && tv.value.valueBlock;
        return tv.type + '=' + String(block && block.value !== undefined
          ? block.value : '');
      }).join(',');
    } catch (e) {
      log.debug("Caught in Est.subjectOfCertificate(): " +
                ((e && e.message) || e));
      subject = null;
    }
    log.debug("Leaving Est.subjectOfCertificate().");
    return subject;
  }

  // The names a request asks for, in the spelling an enrolled record keeps them
  // (`kind:value`), lower-cased where the name is case-insensitive.
  /**
   * Returns the names a request asks for as an enrolled record keeps them
   * (`kind:value`), lower-cased where a name is case-insensitive.
   *
   * @param requested - the request's names
   * @returns the sorted names
   */
  requestedNameSet(requested) {
    const { log, core } = this.deps;
    log.debug("Entering Est.requestedNameSet().");
    const want = requested || {};
    const out = [];
    (want.uris || []).forEach(function (one) {
      out.push('uri:' + one);
    });
    (want.dns || []).forEach(function (one) {
      out.push('dns:' + core.normalHostName(one));
    });
    (want.ips || []).forEach(function (one) {
      out.push('ip:' + core.normalHostName(one));
    });
    (want.emails || []).forEach(function (one) {
      out.push('email:' + String(one).toLowerCase());
    });
    (want.upns || []).forEach(function (one) {
      out.push('upn:' + String(one).toLowerCase());
    });
    log.debug("Leaving Est.requestedNameSet().");
    return out.filter(function (one, i) {
      return out.indexOf(one) === i;
    }).sort();
  }

  /**
   * Returns an enrolled certificate's names in the same spelling as
   * `requestedNameSet()`.
   *
   * @param record - the enrolled certificate's record
   * @returns the sorted names
   */
  recordNameSet(record) {
    const { log } = this.deps;
    log.debug("Entering Est.recordNameSet().");
    const out = (record.names || []).map(function (one) {
      const text = String(one);
      const colon = text.indexOf(':');
      const kind = text.slice(0, colon);
      const value = text.slice(colon + 1);
      return kind === 'uri' ? text : kind + ':' + value.toLowerCase();
    });
    log.debug("Leaving Est.recordNameSet().");
    return out.filter(function (one, i) {
      return out.indexOf(one) === i;
    }).sort();
  }

  // Does this request repeat the renewed certificate's subject and names
  // exactly (RFC 7030 section 4.2.2)?
  /**
   * Says whether a request repeats a certificate's subject and names exactly
   * (RFC 7030 section 4.2.2).
   *
   * @param csr - the parsed request
   * @param record - the certificate being renewed
   * @returns true when it does
   */
  repeats(csr, record) {
    const { log } = this.deps;
    log.debug("Entering Est.repeats().");
    const subject = this.subjectOfCertificate(record.certificatePem);
    const same = subject !== null && subject === csr.subject &&
      JSON.stringify(this.requestedNameSet(csr.requested)) ===
      JSON.stringify(this.recordNameSet(record));
    log.debug("Leaving Est.repeats(). " + same);
    return same;
  }

  // 4.2.2 — renew or rekey a certificate. The certificate being renewed is the
  // TLS client certificate when one is presented; with Basic alone it is found
  // among the target entry's valid EST certificates by the subject and names
  // the request repeats. Either way it is superseded on the EST CRL once the
  // new one is issued.
  /**
   * Answers `simplereenroll` (section 4.2.2): renews the TLS client certificate
   * presented or, with Basic alone, the target's EST certificate whose subject
   * and names the request repeats; the old one is superseded on the EST CRL.
   *
   * @param req - the request
   * @param res - the response
   * @param ctx - the request's context
   * @returns a promise that settles when it has answered
   */
  async simplereenroll(req, res, ctx) {
    const { log, mtls, config, core, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering Est.simplereenroll().");
    const csr = await this.enrollmentRequest(req, res, ctx);
    if (!csr) {
      log.debug("Leaving Est.simplereenroll(). Answered.");
      return;
    }
    let target = null;
    let renewed = null;
    const byCertificate = ctx.principal.certificateSerial
      ? { ok: true, principal: ctx.principal }
      : (mtls.peerCertificate(req) &&
         this.certificateAuthenticationOn(req)
          ? await core.authenticateCertificate(req, 'est-certificate')
          : null);
    if (byCertificate) {
      if (!byCertificate.ok) {
        this.refuseWith(req, res, ctx, byCertificate);
        log.debug("Leaving Est.simplereenroll(). The presented certificate.");
        return;
      }
      target = { kind: byCertificate.principal.kind,
                 id: byCertificate.principal.id };
      const allowed = core.authorizeTarget(ctx.principal, target);
      if (!allowed.ok) {
        this.refuseWith(req, res, ctx, allowed);
        log.debug("Leaving Est.simplereenroll(). Not authorized.");
        return;
      }
      renewed = core.enrolledOf(target).filter(function (one) {
        return core.normalSerial(one.serialHex) ===
               byCertificate.principal.certificateSerial;
      })[0] || null;
      ctx.targetUri = core.entryUri(target);
      if (!renewed || !this.repeats(csr, renewed)) {
        errorCodes.mark(res, 'STS-EST-0016');
        this.estError(req, res, ctx, 400,
                      'A re-enrollment request must repeat the ' +
                      'subject and subjectAltName of the certificate being ' +
                      'renewed (RFC 7030 section 4.2.2), and this one ' +
                      'differs from the TLS client certificate presented.');
        log.debug("Leaving Est.simplereenroll(). Differs from the " +
                  "certificate.");
        return;
      }
    } else {
      const named = core.targetFromRequest(csr.requested, csr.commonName,
                                           ctx.principal);
      if (!named.ok) {
        this.refuseWith(req, res, ctx, named);
        log.debug("Leaving Est.simplereenroll(). No target.");
        return;
      }
      if (await this.refusedAsElsewhere(req, res, ctx, named.target)) {
        log.debug("Leaving Est.simplereenroll(). Homed in another cell.");
        return;
      }
      target = named.target;
      ctx.targetUri = core.entryUri(target);
      // Authorized BEFORE the entry's certificates are searched, so a refusal
      // for somebody else's entry says nothing about what that entry holds.
      const allowed = core.authorizeTarget(ctx.principal, target);
      if (!allowed.ok) {
        this.refuseWith(req, res, ctx, allowed);
        log.debug("Leaving Est.simplereenroll(). Not authorized.");
        return;
      }
      const held = core.enrolledOf(target).filter(function (one) {
        return one.family === FAMILY && self.repeats(csr, one);
      });
      renewed = held.filter(function (one) {
        return one.status === 'valid';
      })[0] || null;
      if (!renewed) {
        errorCodes.mark(res, held.length ? 'STS-EST-0021' : 'STS-EST-0015');
        this.estError(req, res, ctx, 400, held.length
          ? 'The certificate this request renews has expired or been ' +
            'revoked; ask /simpleenroll for a new one.'
          : 'No EST certificate held by the ' + core.entryLabel(target) +
            ' has the subject and subjectAltName this request repeats, so ' +
            'there is nothing to renew (RFC 7030 section 4.2.2).');
        log.debug("Leaving Est.simplereenroll(). Nothing to renew.");
        return;
      }
    }
    if (renewed.status !== 'valid') {
      errorCodes.mark(res, 'STS-EST-0021');
      this.estError(req, res, ctx, 400,
                    'The certificate this request renews has expired or been ' +
                    'revoked; ask /simpleenroll for a new one.');
      log.debug("Leaving Est.simplereenroll(). Not valid.");
      return;
    }
    // An unlabelled re-enrollment renews the certificate as the profile it was
    // issued for; a labelled one asks for the label's.
    if (!ctx.labelled) {
      ctx.profile = renewed.profile;
    }
    const issued = await core.issue({
      family: FAMILY, profile: ctx.profile, principal: ctx.principal,
      target: target, publicKeyPem: csr.publicKeyPem, requested: csr.requested,
      keySource: 'client', keyAlg: csr.keyAlg, via: 'est:simplereenroll',
      replaces: renewed.serialHex
    });
    if (!issued.ok) {
      this.refuseWith(req, res, ctx, issued);
      log.debug("Leaving Est.simplereenroll(). Refused by the core.");
      return;
    }
    this.answerIssued(res, ctx, issued);
    log.debug("Leaving Est.simplereenroll().");
  }

  // The key algorithm a /serverkeygen template asks for: the template key's own
  // when this service generates that algorithm, and otherwise the profile's
  // sensible default — RSA for key encipherment, P-256 for everything else.
  /**
   * Returns the key algorithm a `serverkeygen` template asks for: the template
   * key's own when this service generates it, else RSA for key encipherment and
   * P-256 for everything else.
   *
   * @param csr - the parsed template request
   * @param profile - the profile
   * @returns the key algorithm's id
   */
  serverKeyAlgorithm(csr, profile) {
    const { log, keyMaterial } = this.deps;
    log.debug("Entering Est.serverKeyAlgorithm().");
    const ids = keyMaterial.keyAlgIds();
    const alg = ids.indexOf(String(csr.keyAlg)) >= 0
      ? String(csr.keyAlg)
      : (profile === 'key-encipherment' ? 'rsa-2048' : 'ec-p256');
    log.debug("Leaving Est.serverKeyAlgorithm(). " + alg);
    return alg;
  }

  // 4.4 — a key pair generated here and certified in the same act. The private
  // key is sent ONCE, PKCS#8, and kept sealed on the entry by the core.
  /**
   * Answers `serverkeygen` (section 4.4): a key pair generated here and
   * certified in the same act, the private key sent once as PKCS#8 in a
   * `multipart/mixed` response and kept sealed on the entry.
   *
   * @param req - the request
   * @param res - the response
   * @param ctx - the request's context
   * @returns a promise that settles when it has answered
   */
  async serverkeygen(req, res, ctx) {
    const { log, config, errorCodes, codec, keyMaterial, core } = this.deps;
    log.debug("Entering Est.serverkeygen().");
    // Off for the realm refuses here, before the template is read — unless
    // the caller is an application whose own estServerKeyGeneration turns
    // it on, or an administrator, who may be asking for such an
    // application; `core.issue()` then asks the switch of the TARGET
    // (rcbj, 2026-10-01: the application's setting overrides the realm's).
    const asker = ctx.principal || {};
    const mayStillBeOn = asker.kind === 'person' && asker.admin === true ||
      (asker.kind === 'application' &&
       core.estSwitch('serverKeyGeneration', asker));
    if (config.value('est.serverKeyGeneration') === false && !mayStillBeOn) {
      errorCodes.mark(res, 'STS-EST-0005');
      this.estError(req, res, ctx, 501,
                    'Server-side key generation is turned off ' +
                    'for EST in this realm (est.serverKeyGeneration).');
      log.debug("Leaving Est.serverkeygen(). Off.");
      return;
    }
    const csr = await this.enrollmentRequest(req, res, ctx, { template: true });
    if (!csr) {
      log.debug("Leaving Est.serverkeygen(). Answered.");
      return;
    }
    const encrypted = (csr.attributeTypes || []).filter(function (type) {
      return type === codec.OIDS.decryptKeyIdentifier ||
             type === codec.OIDS.asymmetricDecryptKeyIdentifier;
    });
    if (encrypted.length) {
      errorCodes.mark(res, 'STS-EST-0018');
      this.estError(req, res, ctx, 501,
                    'The request asks for the private key to be encrypted ' +
                    '(RFC 7030 section 4.4.1.2), which this server does not ' +
                    'do; it refuses rather than return the key unencrypted.');
      log.debug("Leaving Est.serverkeygen(). Encryption asked for.");
      return;
    }
    const keyAlg = this.serverKeyAlgorithm(csr, ctx.profile);
    const described = keyMaterial.keyAlg(keyAlg) || {};
    if (described.kind === 'pqc' && described.use === 'kem' &&
        ctx.profile !== 'key-encipherment') {
      errorCodes.mark(res, 'STS-EST-0017');
      this.estError(req, res, ctx, 400, 'A ' + keyAlg + ' key is a ' +
                    'key-encapsulation key and can be certified only for ' +
                    'key-encipherment; this request is for ' + ctx.profile +
                    '.');
      log.debug("Leaving Est.serverkeygen(). A KEM key for a signing profile.");
      return;
    }
    const target = core.targetFromRequest(csr.requested, csr.commonName,
                                          ctx.principal);
    if (!target.ok) {
      this.refuseWith(req, res, ctx, target);
      log.debug("Leaving Est.serverkeygen(). No target.");
      return;
    }
    if (await this.refusedAsElsewhere(req, res, ctx, target.target)) {
      log.debug("Leaving Est.serverkeygen(). Homed in another cell.");
      return;
    }
    ctx.targetUri = core.entryUri(target.target);
    const issued = await core.issueWithServerKey({
      family: FAMILY, profile: ctx.profile, principal: ctx.principal,
      target: target.target, keyAlg: keyAlg, requested: csr.requested,
      profileDefaulted: !ctx.labelled,
      via: 'est:serverkeygen'
    });
    if (!issued.ok) {
      this.refuseWith(req, res, ctx, issued);
      log.debug("Leaving Est.serverkeygen(). Refused by the core.");
      return;
    }
    const parts = codec.multipartMixed([
      { contentType: MEDIA.pkcs8, der: codec.pemToDer(issued.privateKeyPem) },
      { contentType: MEDIA.certsOnly,
        der: codec.certsOnly([issued.record.certificatePem]) }
    ]);
    this.counted(ctx, { outcome: 'issued', status: 200,
                        serialHex: issued.record.serialHex });
    res.status(200)
       .set('Content-Type', 'multipart/mixed; boundary=' + parts.boundary)
       .set('Cache-Control', 'no-store')
       .send(parts.body);
    log.info('est: serverkeygen issued ' + issued.record.profile + ' (' +
             keyAlg + ') serial ' + issued.record.serialHex + ' for ' +
             ctx.targetUri + ' to ' + ctx.identity);
    log.debug("Leaving Est.serverkeygen().");
  }

  // What csrattrs says about one profile.
  /**
   * Returns what the CSR attributes response says for a profile: the signature
   * algorithms, the extension request, and the profile's extended key usages.
   *
   * @param profileId - the profile
   * @returns the items, as `est_codec.ts`'s `csrAttrs()` takes them
   */
  csrAttributesFor(profileId) {
    const { log, codec, x509 } = this.deps;
    log.debug("Entering Est.csrAttributesFor(). profile=" + profileId);
    const items: any[] = codec.SIGNATURE_ALGORITHMS.map(function (one) {
      return { oid: one.oid };
    });
    items.push({ oid: codec.OIDS.extensionRequest });
    const profile = x509.profile(profileId) || {};
    const ekus = (profile.extKeyUsage || []).map(function (name) {
      return x509.EKU_OIDS[name];
    }).filter(function (one) {
      return !!one;
    });
    if (ekus.length) {
      items.push({ type: codec.OIDS.extKeyUsage, values: ekus.map(function (o) {
        return { oid: o };
      }) });
    }
    const names = {
      'tls-server': ['dNSName', 'iPAddress'],
      'tls-server-client': ['dNSName', 'iPAddress'],
      'email': ['rfc822Name'],
      'smartcard-logon': ['otherName:1.3.6.1.4.1.311.20.2.3']
    }[profileId];
    if (names) {
      items.push({ type: codec.OIDS.subjectAltName, values: names.map(
        function (name) { return { utf8: name }; }) });
    }
    log.debug("Leaving Est.csrAttributesFor(). " + items.length + " item(s).");
    return items;
  }

  // 4.5 — what a request for this label should carry. Unauthenticated: section
  // 4.5.1 lets a server require authentication and this one does not, because
  // nothing in the answer is about anybody and a client asks it before it has a
  // certificate to authenticate with.
  /**
   * Answers `csrattrs` (section 4.5) for the request's profile.
   * Unauthenticated.
   *
   * @param req - the request
   * @param res - the response
   * @param ctx - the request's context
   * @returns a promise that settles when it has answered
   */
  async csrattrs(req, res, ctx) {
    const { log, codec } = this.deps;
    log.debug("Entering Est.csrattrs().");
    this.counted(ctx, { outcome: 'answered', status: 200 });
    this.sendBase64(res, MEDIA.csrattrs,
                    codec.csrAttrs(this.csrAttributesFor(ctx.profile)));
    log.debug("Leaving Est.csrattrs().");
  }

  // 4.3 — Full CMC is optional and not implemented.
  /**
   * Answers `fullcmc` (section 4.3) with 501: Full CMC is not implemented.
   *
   * @param req - the request
   * @param res - the response
   * @param ctx - the request's context
   * @returns a promise that settles when it has answered
   */
  async fullcmc(req, res, ctx) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Est.fullcmc().");
    errorCodes.mark(res, 'STS-EST-0004');
    this.estError(req, res, ctx, 501,
                  'Full CMC (RFC 7030 section 4.3) is not ' +
                  'implemented here; use /simpleenroll, /simplereenroll or ' +
                  '/serverkeygen.');
    log.debug("Leaving Est.fullcmc().");
  }

  // One operation, with the checks every operation makes and a catch that turns
  // anything unexpected into a 500 with no detail in it.
  /**
   * Returns the route handler for one operation: the checks every operation
   * makes, the operation, and a catch that answers anything unexpected with a
   * 500 carrying no detail.
   *
   * @param op - the `OPERATIONS` row
   * @returns the handler
   */
  operation(op) {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering Est.operation(). op=" + op.name);
    log.debug("Leaving Est.operation().");
    return function (req, res) {
      log.debug("Entering the EST " + op.name + " endpoint.");
      const ctx = { op: op.name };
      let started = null;
      try {
        if (self.refusedBeforeAuthentication(req, res, ctx)) {
          log.debug("Leaving the EST " + op.name + " endpoint. Refused.");
          return Promise.resolve();
        }
        started = HANDLERS[op.name](req, res, ctx);
      } catch (e) {
        started = Promise.reject(e);
      }
      return Promise.resolve(started).catch(function (e) {
        log.error(errorCodes.tag('STS-EST-0020') + 'est: ' + op.name +
                  ' failed: ' + ((e && e.stack) || e));
        errorCodes.mark(res, 'STS-EST-0020');
        self.estError(req, res, ctx, 500,
                      'The EST server could not answer this request.');
      }).then(function () {
        log.debug("Leaving the EST " + op.name + " endpoint.");
      });
    };
  }

  // The wrong method on a known path.
  /**
   * Returns the handler that answers the wrong method on an operation's path
   * with 405 and `Allow`.
   *
   * @param op - the `OPERATIONS` row
   * @returns the handler
   */
  wrongMethod(op) {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering Est.wrongMethod(). op=" + op.name);
    log.debug("Leaving Est.wrongMethod().");
    return function (req, res) {
      log.debug("Entering the EST wrong-method answer.");
      errorCodes.mark(res, 'STS-EST-0003');
      self.estError(req, res, { op: op.name }, 405,
                    'EST ' + op.name + ' answers ' +
                    op.method + ' only.', { Allow: op.method === 'GET'
                                                     ? 'GET, HEAD' :
                                                       op.method });
      log.debug("Leaving the EST wrong-method answer.");
    };
  }

  // THE ROUTES, registered where they always were: the module exports
  // this, and `common/protocol_stack.ts` calls it (#50, R1) at the point
  // where requiring the module used to register them, so the route order
  // is unchanged (rule 1). Nothing calls it at load.
  /**
   * Registers every EST operation under the base and under `/:label`, and the
   * wrong-method answer. Called by `common/protocol_stack.ts`.
   *
   * @param app - the express app
   */
  registerRoutes(app: RouteApp): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Est.registerRoutes().");
    [BASE, BASE + '/:label'].forEach(function (base) {
      OPERATIONS.forEach(function (op) {
        const path = base + '/' + op.name;
        if (op.method === 'GET') {
          app.get(path, self.operation(op));
        } else {
          app.post(path, self.operation(op));
        }
      });
    });

    app.use(function (req, res, next) {
      log.debug("Entering the EST method check.");
      const match = EST_PATH.exec(String(req.path || ''));
      if (!match) {
        log.debug("Leaving the EST method check. Not an EST path.");
        return next();
      }
      const op = OPERATIONS.filter(function (one) {
        return one.name === match[1];
      })[0];
      log.debug("Leaving the EST method check. Wrong method.");
      return self.wrongMethod(op)(req, res);
    });
    log.debug("Leaving Est.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module finishes loading (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<Est>(
  'est/est',
  () => new Est(Est.defaultDeps()),
  null,
  log);

// FACADES since #50's R2: each resolves the installed instance when called.
const HANDLERS = {
  cacerts: slot.forward('cacerts'),
  simpleenroll: slot.forward('simpleenroll'),
  simplereenroll: slot.forward('simplereenroll'),
  serverkeygen: slot.forward('serverkeygen'),
  csrattrs: slot.forward('csrattrs'),
  fullcmc: slot.forward('fullcmc')
};

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// THE WRONG METHOD, as middleware rather than an `app.all()` per path. Express
// 4 records `all` as every method it knows on the ROUTE, so `sts_metadata.js`'s
// reading of the router would list thirty-four methods for each EST path — a
// page describing an endpoint as answering PROPFIND. A request only reaches
// this when no route above took it, which for one of these paths means the
// method.
const EST_PATH = new RegExp('^' + BASE.replace(/\./g, '\\.') +
                            '/(?:[^/]+/)?(' + OPERATIONS.map(function (op) {
                              return op.name;
                            }).join('|') + ')$');

// The two console pages, required HERE so that the family is one require in
// `common/protocol_stack.ts`. Requiring them registers nothing: their routes
// are registered there by `est_admin`'s own `registerRoutes(app)`, right
// after this module's (#50, R1).
require('./est_admin');

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * Enrollment over Secure Transport (RFC 7030).
 *
 * Exports `registerRoutes`, the `Est` class, its tables, the route handlers for
 * tests, and facades that forward to the installed instance.
 *
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  Est: Est,
  /**
   * Installs the instance the facades forward to.
   */
  installInstance: (instance: Est): void => slot.install(instance),
  /**
   * Says where the current instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  FAMILY: FAMILY,
  BASE: BASE,
  PATHS: PATHS,
  OPERATIONS: OPERATIONS,
  MEDIA: MEDIA,
  handlers: {
    // The route functions, for `tests/est_handlers.js` to drive with a fake
    // request — exactly what Express calls.
    operation: slot.forward('operation'),
    wrongMethod: slot.forward('wrongMethod')
  },
  basicCredentialOf: slot.forward('basicCredentialOf'),
  csrAttributesFor: slot.forward('csrAttributesFor'),
  serverKeyAlgorithm: slot.forward('serverKeyAlgorithm'),
  requestedNameSet: slot.forward('requestedNameSet'),
  recordNameSet: slot.forward('recordNameSet')
};
