// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: common/surface_refusals.ts
//
// ---------------------------------------------------------------------------
// A REQUEST REFUSED BEFORE ANY ROUTE, ANSWERED IN THE ERROR SHAPE OF THE API
// IT WAS SENT TO (2026-11-16, rcbj: "fix any issues you find").
//
// Three middlewares in `common/app.js`'s chain refuse a request before the
// router has chosen an endpoint: the body parsers (a body over 5 MB, in a
// charset or content encoding they do not read, or cut off before its
// Content-Length), the validation guard (`common/validation.js`: a parameter
// named `__proto__`, `constructor` or `prototype`, or a control character in
// a query value) and the request ceiling (`common/request_budget.ts`). Until
// this module each answered ONE way whatever the path: Express's own HTML
// error page for a body, `text/plain` for the guard and the ceiling. On a
// JSON API that is an answer no client of it can read and no model of it
// declares; the fuzzing of the remote PEP's control plane (PR #1858) found
// both on every pull and every JSON POST.
//
// **THE ROUTER HAS NOT CHOSEN AN ENDPOINT, BUT THE PATH HAS ALREADY CHOSEN AN
// API.** That is the whole argument: `validation.js` used to say no dialect
// could be spoken here because no specification had been picked, which is
// true of an endpoint and not of a prefix. Every API below documents ONE error
// shape for every operation it has, so the shape is known from the path alone.
// Each is that API's own, never a generic one:
//
//   | Path                       | Shape                                   |
//   |----------------------------|-----------------------------------------|
//   | `/admin-api`               | `{ ok: false, errors }` (RefusalFailure) |
//   | `/account-api`             | `{ ok: false, errors }`                  |
//   | `/authn-api`               | `refuse()`'s: `ok`, `errors`, `error`, `error_description` |
//   | `/report-api`              | `{ error, error_description }`           |
//   | `/xacml/pep/*`             | the control plane's `Error` (and `TooManyRequests`) |
//   | `POST /xacml/pip`          | a `PIPError` in XML, as every PIP refusal |
//   | `/access/v1/*`             | AuthZEN's `{ error: { status, message } }` |
//   | `/scim/v2/*`               | RFC 7644 section 3.12's Error, `application/scim+json` |
//   | OAuth's JSON endpoints     | RFC 6749 section 5.2's `{ error, error_description }` |
//   | GNAP's JSON endpoints      | RFC 9635 section 3.6's `{ error: { code, description } }` |
//
// **WHAT IS LEFT ALONE, AND WHY.** Every other path answers as before. The
// console's and the static surfaces' pages are documents for a browser; SAML,
// WS-Trust, WS-Federation and Kerberos are formats their specifications fix;
// `/oauth2/authorize` is a person's browser, whose errors RFC 6749 section
// 4.1.2.1 sends to the client or shows the person, never as JSON. ACME is not
// here because its problem documents carry a fresh `Replay-Nonce` (RFC 8555
// section 6.5), which only `acme.ts` can mint. **AN UNROUTED PATH IS NOT A
// REFUSAL HERE AT ALL**: Express's `Cannot GET /path` is untouched, because
// `tests/protocol/sts_metadata.js` tells an unrouted path by it.
//
// **NO CODE IS EVER IN A BODY.** The caller has already marked the response
// and written the audit row; this module writes the sentence, the status and
// the shape, and nothing else (root `CLAUDE.md`, *Every failure has an error
// code, and no client ever sees one*).
//
// A LEAF (rule 3): it requires nothing of this service, because
// `common/validation.js` may never require `helpers.js` and calls it. Each
// caller hands it its own logger.
// ---------------------------------------------------------------------------

type Json = any;

interface Deps {
  log: Json;
}

// What a refusal is about, beyond its status: the part of the request that
// was refused (SCIM's `scimType` differs between a body and a query value),
// and a 429's wait.
interface Refused {
  part?: 'body' | 'query' | 'request';
  retryAfterS?: number;
}

// The PIP's namespace, as `xacml/xacml.ts` writes every PIPError.
const PIP_NS = 'urn:sts:xacml:pip:1.0';

const SCIM_ERROR = 'urn:ietf:params:scim:api:messages:2.0:Error';

// RFC 6749's and OpenID4VCI's JSON endpoints. Not `/oauth2/authorize` (a
// browser's, see the header), nor the static pages and scripts under the
// prefix (`/oauth2/consent`, `/oauth2/check_session`, `autopost.js`).
const OAUTH = /^\/(?:oauth2\/(?:token|introspect|revoke|par|challenge|userinfo|device_authorization|bc-authorize|register|grants)|oid4vci\/(?:credential|deferred_credential|nonce|notification))(?:\/|$)/;

// GNAP's grant request, continuation, token management and resource server
// endpoints: not its interaction pages, which are a person's.
const GNAP = /^\/gnap(?:\/(?:continue|token|introspect|resource)(?:\/.*)?)?$/;

// The surfaces, in the order they are asked: the first that matches answers.
const SURFACES: { name: string; pattern: RegExp }[] = [
  { name: 'management', pattern: /^\/admin-api(?:\/|$)/ },
  { name: 'account', pattern: /^\/account-api(?:\/|$)/ },
  { name: 'authn', pattern: /^\/authn-api(?:\/|$)/ },
  { name: 'report', pattern: /^\/report-api(?:\/|$)/ },
  { name: 'pip', pattern: /^\/xacml\/pip\/?$/ },
  { name: 'pep', pattern: /^\/xacml\/pep\// },
  { name: 'authzen', pattern: /^\/access\/v1(?:\/|$)/ },
  { name: 'scim', pattern: /^\/scim\/v2(?:\/|$)/ },
  { name: 'oauth', pattern: OAUTH },
  { name: 'gnap', pattern: GNAP }
];

class SurfaceRefusals {
  private readonly deps: Deps;

  constructor(deps: Deps) {
    this.deps = deps;
  }

  /**
   * Names the API a path belongs to, where that API answers a refusal in a
   * shape of its own.
   *
   * @param path - the request's path, after the realm's prefix came off
   * @returns the surface's name, or '' for a path that answers as before
   */
  surfaceOf(path: string): string {
    const { log } = this.deps;
    log.debug("Entering SurfaceRefusals.surfaceOf().");
    const p = String(path || '');
    const found = SURFACES.filter(function (one) {
      return one.pattern.test(p);
    })[0];
    log.debug("Leaving SurfaceRefusals.surfaceOf(). " +
              (found ? found.name : 'None.'));
    return found ? found.name : '';
  }

  /**
   * The body and media type a surface answers one refusal with. Separate
   * from `answer()` so a test can hold each shape with no response.
   *
   * @param surface - a name `surfaceOf()` gives
   * @param status - the HTTP status
   * @param sentence - what the caller is told, in English, with no code
   * @param refused - the part refused, and a 429's wait
   * @returns `{ type, body }`, the body already a string
   */
  shape(surface: string, status: number, sentence: string,
        refused?: Refused): { type: string; body: string } {
    const { log } = this.deps;
    log.debug("Entering SurfaceRefusals.shape(). " + surface + " " + status);
    const s = String(sentence);
    const tooMany = status === 429;
    const oauthError = tooMany ? 'too_many_requests' : 'invalid_request';
    let type = 'application/json';
    let body = '';
    if (surface === 'management' || surface === 'account') {
      body = JSON.stringify({ ok: false, errors: [s] });
    } else if (surface === 'authn') {
      body = JSON.stringify({ ok: false, errors: [s], error: oauthError,
                              error_description: s });
    } else if (surface === 'report') {
      body = JSON.stringify({ error: oauthError, error_description: s });
    } else if (surface === 'pep') {
      const pep: Json = { error: oauthError, error_description: s };
      if (tooMany) {
        // The control plane's `TooManyRequests`: the wait in the body as
        // well as in `Retry-After`, as every validation door answers it.
        pep.retryAfterS = Math.max(1,
          Number(refused && refused.retryAfterS) || 1);
      }
      body = JSON.stringify(pep, null, 2);
    } else if (surface === 'pip') {
      type = 'application/xml';
      body = '<?xml version="1.0" encoding="UTF-8"?>\n' +
             '<PIPError xmlns="' + PIP_NS + '" error="' + oauthError +
             '">\n  <Description>' + this.xmlText(s) +
             '</Description>\n</PIPError>\n';
    } else if (surface === 'authzen') {
      body = JSON.stringify({ error: { status: status, message: s } },
                            null, 2);
    } else if (surface === 'scim') {
      // RFC 7644 section 3.12: `status` is the HTTP status AS A STRING, and
      // `scimType` only where the section defines one for it — a body that
      // is not what was sent is `invalidSyntax`, a query value this service
      // will not read is `invalidValue`, and 413, 415 and 429 have none.
      type = 'application/scim+json';
      const scim: Json = { schemas: [SCIM_ERROR], status: String(status) };
      if (status === 400) {
        scim.scimType = refused && refused.part === 'query' ?
          'invalidValue' : 'invalidSyntax';
      }
      scim.detail = s;
      body = JSON.stringify(scim, null, 2);
    } else if (surface === 'oauth') {
      // RFC 6749 section 5.2 has no code for a rate limit or an oversized
      // body; `invalid_request` is the one that fits every refusal here.
      body = JSON.stringify({ error: 'invalid_request',
                              error_description: s });
    } else if (surface === 'gnap') {
      body = JSON.stringify({ error: { code: 'invalid_request',
                                       description: s } });
    } else {
      type = 'text/plain';
      body = s + '\n';
    }
    log.debug("Leaving SurfaceRefusals.shape().");
    return { type: type, body: body };
  }

  // An XML text node's escapes, for the PIP's Description. Inline rather than
  // `helpers.xmlEscape()`, which this leaf may not require.
  private xmlText(s: string): string {
    const { log } = this.deps;
    log.debug("Entering SurfaceRefusals.xmlText().");
    log.debug("Leaving SurfaceRefusals.xmlText().");
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  /**
   * Answers a refusal made before any route in the shape of the API the path
   * belongs to. The caller has marked the response with its code already.
   *
   * @param req - the request
   * @param res - the response
   * @param status - the HTTP status
   * @param sentence - what the caller is told, with no code in it
   * @param refused - the part refused, and a 429's wait
   * @returns true where it answered; false for a path that answers as before,
   *   which the caller then answers as it always did
   */
  answer(req: Json, res: Json, status: number, sentence: string,
         refused?: Refused): boolean {
    const { log } = this.deps;
    log.debug("Entering SurfaceRefusals.answer(). " + status);
    const surface = this.surfaceOf(String((req && req.path) || ''));
    if (!surface || !res || res.headersSent) {
      log.debug("Leaving SurfaceRefusals.answer(). Not an API's refusal.");
      return false;
    }
    const shaped = this.shape(surface, status, sentence, refused);
    // error-code: none — every caller marks its own code before it asks.
    res.status(status).type(shaped.type).set('Cache-Control', 'no-store');
    res.send(shaped.body);
    log.debug("Leaving SurfaceRefusals.answer(). " + surface + ".");
    return true;
  }
}

export = SurfaceRefusals;
