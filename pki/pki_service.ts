'use strict';
//
// File: pki_service.ts
//
// ===========================================================================
// THE REVOCATION ENDPOINTS: A CRL AND AN OCSP RESPONDER PER CA (2026-09-11).
//
// **THIS IS A PROTOCOL SURFACE AND NOT A CONSOLE ONE**, which is why it is a
// directory of its own rather than more routes in `admin-ui/pki_admin.ts`.
// Nothing here is behind the console's gate and nothing here takes a
// credential: a CRL and an OCSP answer are PUBLIC documents by construction —
// a relying party fetches them before it has decided to trust anything, often
// before it has authenticated to anybody, and a revocation list nobody can
// read is a revocation nobody acts on.
//
// Six routes, and the shape of the first four is the same:
//
//   GET  /pki/crl/{scope}/{ca}.crl    the signed CRL, DER
//   GET  /pki/ca/{scope}/{ca}.cer     the authority's own certificate, DER
//   GET  /pki/ocsp/{scope}/{ca}/{b64} RFC 6960 section A.1.1, base64 appended
//   POST /pki/ocsp/{scope}/{ca}       RFC 6960 section A.1.1, DER in a body
//   GET  /pki/ocsp/{scope}/{ca}       the address as written, asking nothing
//   GET  /pki/revocation              what this service publishes, as JSON
//
// and a seventh since 2026-09-13, which is not about revocation but exists so
// that a relying party can REACH it:
//
//   GET  /pki/chain/{scope}/{sha256}.pem  the chain an `x5u` header names
//
// **AND ON TWO LISTENERS** since 2026-09-13: the main port, and the plain-HTTP
// revocation listener at the foot of this file, which serves `/pki/` and
// nothing else and is the address every certificate names.
//
// **`{scope}` IS IN THE PATH AND NOT TAKEN FROM THE REALM PREFIX**, which is
// the one routing decision here. Every other endpoint in this service reads
// the ambient realm, and these could have: `/realm/acme/pki/crl/jose.crl`
// would work. It is not done that way because these addresses go INSIDE
// certificates and are fetched by clients that know nothing about this
// service's realm convention — and because the process branch and the service
// Root belong to no realm at all, so two of the scopes could not be spelled.
// One address shape for all of them is what a certificate can carry.
//
// ---------------------------------------------------------------------------
// WHY THE BYTES ARE WHAT A CLIENT GETS, AND NOTHING ELSE.
//
// A CRL is `application/pkix-crl` and an OCSP response is
// `application/ocsp-response`, both DER. Every one of these handlers therefore
// sends a Buffer and sets the media type by hand rather than going through
// this service's JSON conventions — a revocation client is not a browser and
// will not parse an error page.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `PkiService` takes the modules it uses through its constructor
// (`PkiServiceDeps`), and the module still exports its old names from a
// TRANSITIONAL instance built from the real modules, for the callers that
// are not converted. `PkiService` is exported beside them for the
// composition root.
//
// **THE ROUTES ARE REGISTERED BY `registerRoutes()`**, which the
// transitional code calls at load where the first route used to be
// registered, so rule 1's order is unchanged.
// ---------------------------------------------------------------------------

import http = require('http');
import nodeCrypto = require('crypto');
import app = require('../common/app');
import helpers = require('../common/helpers');
const { log, parseBody } = helpers;
import config = require('../common/config');
import pki = require('../common/pki');
import revocation = require('../common/pki_revocation');
// Which JOSE certificate an `x5u` names, and its chain. A library.
import certificateHeader = require('../common/jose_certificate_header');
// The error-code registry (a leaf). Every refusal below is `mark()`ed on the
// response before it is sent and never written into it: a revocation client
// is shown exactly the text and the OCSP status it was always shown.
import errorCodes = require('../common/error_codes');
// The PROXY protocol v2 reader (2026-09-14, #46), a LIBRARY, installed in
// listen() like every TCP listener's.
import proxyProtocol = require('../common/proxy_protocol');

// What `PkiService` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface PkiServiceDeps {
  http: typeof http;
  nodeCrypto: typeof nodeCrypto;
  app: typeof app;
  log: typeof log;
  config: typeof config;
  pki: typeof pki;
  revocation: typeof revocation;
  certificateHeader: typeof certificateHeader;
  errorCodes: typeof errorCodes;
  proxyProtocol: typeof proxyProtocol;
}

type RouteApp = typeof app;

class PkiService {
  constructor(private readonly deps: PkiServiceDeps) {
    deps.log.debug("Entering PkiService.constructor().");
    deps.log.debug("Leaving PkiService.constructor().");
  }

  // ---------------------------------------------------------------------------
  // CACHING. A CRL says how long it is fresh for and a client is entitled to
  // cache it for exactly that long — so the header says the same thing the
  // document does, computed from the same setting, rather than `no-store`.
  //
  // **THIS IS THE ONE FAMILY OF DOCUMENTS IN THIS SERVICE THAT IS DELIBERATELY
  // CACHEABLE.** Everything else that publishes key material is `no-store`,
  // because a key regenerated at every start must not be cached. A CRL is the
  // opposite case: it carries its own validity window, and a client that
  // refetches it on every check is a client hammering this service for a
  // document that has not changed.
  // ---------------------------------------------------------------------------
  // The floor is the setting row's own `min: 1`; see `crlLifetimeMs()` in
  // common/pki_revocation.js for why a second floor of 60 here was a bug.
  cacheSeconds() {
    const { log, config } = this.deps;
    log.debug("Entering PkiService.cacheSeconds().");
    const minutes = Number(config.value('pki.crlLifetimeMinutes'));
    log.debug("Leaving PkiService.cacheSeconds().");
    return Math.max(1, Number.isFinite(minutes) ? minutes : 60) * 60;
  }

  sendDer(res, mediaType, der, cacheable) {
    const { log } = this.deps;
    log.debug("Entering PkiService.sendDer().");
    res.status(200)
       .set('Content-Type', mediaType)
       .set('Content-Length', String(der.length))
       .set('Cache-Control', cacheable
         ? 'public, max-age=' + this.cacheSeconds()
         : 'no-store')
       .send(der);
    log.debug("Leaving PkiService.sendDer().");
  }

  // A refusal a revocation client can read. **NOT JSON and not a page**: it is
  // text, because there is no error format either protocol defines for the
  // transport layer and a client that meets one is being debugged by a person.
  // error-code: none — the definition of this helper, not a call to it
  refuse(res, status, sentence) {
    const { log } = this.deps;
    log.debug("Entering PkiService.refuse().");
    res.status(status).type('text/plain').set('Cache-Control', 'no-store')
       .send(sentence + '\n');
    log.debug("Leaving PkiService.refuse().");
  }

  crlFor(req, res, scopeSegment, caId) {
    const { log, revocation, errorCodes } = this.deps;
    const self = this;
    log.debug('Entering PkiService.crlFor(). scope=' + scopeSegment + ' ca=' +
              caId);
    const scope = revocation.scopeFromSegment(scopeSegment);
    const authority = revocation.authorityFor(scope, caId);
    if (!authority) {
      errorCodes.mark(res, 'STS-PKI-0068');
      this.refuse(res, 404,
                  'There is no "' + caId + '" certificate authority in the "' +
                  scopeSegment + '" scope of this service, so there is no ' +
                  'revocation list for it. GET /pki/revocation lists every ' +
                  'CRL this service publishes.');
      log.debug('Leaving PkiService.crlFor(). No such authority.');
      return;
    }
    revocation.buildCrl(scope, caId).then(function (made) {
      if (!made.ok) {
        errorCodes.mark(res, errorCodes.codeOf(made) || 'STS-PKI-0069');
        self.refuse(res, 500, made.errors.join(' '));
        log.debug('Leaving PkiService.crlFor(). It could not be built.');
        return;
      }
      self.sendDer(res, 'application/pkix-crl', made.der, true);
      log.debug('Leaving PkiService.crlFor(). ' + made.count + ' entry(ies).');
    }).catch(function (e) {
      log.error(errorCodes.tag('STS-PKI-0069') + 'pki: the "' + caId +
                '" CRL ' +
          'could not be built: ' +
                (e && e.stack ? e.stack : e));
      errorCodes.mark(res, 'STS-PKI-0069');
      self.refuse(res, 500, 'That CRL could not be built: ' +
                            (e && e.message ? e.message : e));
    });
    log.debug("Leaving PkiService.crlFor().");
  }

  caCertificateFor(req, res, scopeSegment, caId) {
    const { log, revocation, errorCodes, nodeCrypto } = this.deps;
    log.debug("Entering PkiService.caCertificateFor().");
    const scope = revocation.scopeFromSegment(scopeSegment);
    const authority = revocation.authorityFor(scope, caId);
    if (!authority) {
      errorCodes.mark(res, 'STS-PKI-0070');
      this.refuse(res, 404,
                  'There is no "' + caId + '" certificate authority in the "' +
                  scopeSegment + '" scope of this service.');
      log.debug("Leaving PkiService.caCertificateFor().");
      return;
    }
    const der = Buffer.from(
      String(authority.tier.certificatePem).replace(/-----[^-]+-----/g, '')
        .replace(/\s+/g, ''), 'base64');
    // **REVALIDATED RATHER THAN CACHED FOR AN HOUR (2026-09-13).** This said a
    // CA certificate is durable by construction — *an authority that changed
    // would be a different authority with a different name* — and sent
    // `max-age` for the CRL lifetime. It is not true here: a rebuilt branch and
    // a replaced Root keep their subjects and their caIssuers URL, so a client
    // holding the old certificate for an hour built chains to a key that no
    // longer signs anything. `no-cache` with a strong ETag lets a client keep
    // the bytes and costs it one conditional request to learn they are still
    // right.
    res.status(200)
       .set('Content-Type', 'application/pkix-cert')
       .set('Content-Length', String(der.length))
       .set('Cache-Control', 'no-cache')
       .set('ETag', '"' + nodeCrypto.createHash('sha1').update(der)
         .digest('hex') + '"')
       .send(der);
    log.debug("Leaving PkiService.caCertificateFor().");
  }

  // ---------------------------------------------------------------------------
  // THE CACHE HEADERS AN AUTHORITATIVE OCSP ANSWER CARRIES (RFC 5019 section
  // 6.2).
  //
  // It was sent `Cache-Control: no-store`, on the argument that the interesting
  // thing a person does here is revoke something and ask again. RFC 5019
  // section 6.2 says the opposite in capitals: *OCSP responders MUST NOT
  // include a "Pragma: no-cache", "Cache-Control: no-cache", or "Cache-Control:
  // no-store" header in authoritative OCSP responses*, and asks for `max-age`
  // no later than
  // `nextUpdate`, `Last-Modified` at `thisUpdate`, `Expires` at `nextUpdate`
  // and an `ETag` of the response. What a person revoking something needs is
  // served anyway: a client asking with a nonce gets an answer no cache may
  // hand to anybody else, and `nextUpdate` is `pki.crlLifetimeMinutes` away.
  //
  // **A RESPONSE CARRYING A NONCE IS `private, max-age=0`**, because that
  // answer belongs to one request and a shared cache handing it to the next
  // asker would be the replay a nonce exists to detect. **A REFUSAL
  // (`malformedRequest`,
  // `unauthorized`, `internalError`) is not authoritative**, carries no
  // `nextUpdate` and stays `no-store`.
  // ---------------------------------------------------------------------------
  sendOcsp(res, made) {
    const { log, nodeCrypto } = this.deps;
    log.debug("Entering PkiService.sendOcsp().");
    if (made.status !== 'successful' || !made.nextUpdate) {
      this.sendDer(res, 'application/ocsp-response', made.der, false);
      log.debug("Leaving PkiService.sendOcsp(). Not an authoritative answer.");
      return;
    }
    const nextMs = new Date(made.nextUpdate).getTime();
    const maxAge = Math.max(0, Math.floor((nextMs - Date.now()) / 1000));
    res.status(200)
       .set('Content-Type', 'application/ocsp-response')
       .set('Content-Length', String(made.der.length))
       .set('Cache-Control', made.nonce
         ? 'private, max-age=0, no-transform'
         : 'max-age=' + maxAge + ', public, no-transform, must-revalidate')
       .set('Last-Modified', new Date(made.thisUpdate).toUTCString())
       .set('Expires', new Date(nextMs).toUTCString())
       .set('ETag', '"' + nodeCrypto.createHash('sha1').update(made.der)
         .digest('hex') + '"')
       .send(made.der);
    log.debug("Leaving PkiService.sendOcsp(). Authoritative.");
  }

  answer(req, res, scopeSegment, caId, der) {
    const { log, revocation, errorCodes } = this.deps;
    const self = this;
    log.debug('Entering PkiService.answer(). scope=' + scopeSegment + ' ca=' +
              caId);
    const scope = revocation.scopeFromSegment(scopeSegment);
    revocation.answerOcsp(scope, caId, der || Buffer.alloc(0))
      .then(function (made) {
      // **EVEN A REFUSAL IS AN OCSP RESPONSE.** `malformedRequest` and
      // `unauthorized` are statuses inside the protocol, not HTTP errors, so a
      // client that meets one can report what happened rather than guessing
      // from a status code. The HTTP status stays 200 for all of them, which is
      // what RFC 6960 section A.2 asks for.
      //
      // An OCSP REFUSAL (`unauthorized`, `malformedRequest`, `internalError`)
      // carries its code on the answer; `good`, `revoked` and `unknown` are
      // answers rather than failures and carry none.
      if (errorCodes.codeOf(made)) {
        errorCodes.mark(res, errorCodes.codeOf(made));
      }
      self.sendOcsp(res, made);
      log.debug('Leaving PkiService.answer(). ' + made.status + '.');
    }).catch(function (e) {
      log.error(errorCodes.tag('STS-PKI-0074') +
                'pki: an OCSP request to the "' +
          caId + '" ' +
          'responder threw: ' +
                (e && e.stack ? e.stack : e));
      errorCodes.mark(res, 'STS-PKI-0074');
      self.refuse(res, 500, 'That OCSP request could not be answered.');
    });
    log.debug("Leaving PkiService.answer().");
  }

  revocationOnly(req, res) {
    const { log, app, errorCodes } = this.deps;
    log.debug("Entering PkiService.revocationOnly().");
    const path = String(req.url || '').split('?')[0];
    if (/^\/pki\//.test(path) && path.indexOf('..') < 0) {
      log.debug("Leaving PkiService.revocationOnly(). Handed to the app.");
      app(req, res);
      return;
    }
    errorCodes.mark(res, 'STS-PKI-0134');
    res.statusCode = 404;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end('This plain-HTTP listener serves the revocation endpoints under ' +
            '/pki/ and nothing else. Everything else this service answers is ' +
            'on its main port.\n');
    log.debug("Leaving PkiService.revocationOnly(). Not a revocation path.");
  }

  listen() {
    const { log, config, http, proxyProtocol } = this.deps;
    log.debug("Entering PkiService.listen().");
    const port = Number(config.value('pki.httpPort'));
    if (!(port > 0)) {
      httpListenError = 'pki.httpPort is 0, so no plain-HTTP revocation ' +
                        'listener was bound';
      log.debug("Leaving PkiService.listen(). Switched off.");
      return { whenReady: Promise.resolve({ port: null,
                                            why: httpListenError }) };
    }
    const server = http.createServer(this.revocationOnly.bind(this));
    proxyProtocol.install(server, {
      label: 'the plain-HTTP revocation listener (' + port + ')',
      channel: 'http' });
    const whenReady = new Promise(function (resolve, reject) {
      server.once('error', function (err) {
        httpListenError = err.message;
        reject(err);
      });
      server.listen(port, config.value('global.host'), function () {
        httpListening = true;
        httpBoundPort = (server.address() as { port: number }).port;
        resolve({ port: httpBoundPort });
      });
    });
    log.debug("Leaving PkiService.listen().");
    return { whenReady: whenReady, server: server };
  }

  status() {
    const { log } = this.deps;
    log.debug("Entering PkiService.status().");
    log.debug("Leaving PkiService.status().");
    return { listening: httpListening, port: httpBoundPort || null,
             listenError: httpListenError || null };
  }

  // THE ROUTES, registered where they always were: the transitional
  // code below calls this at load, at the point the first of them
  // used to be registered, so the route order is unchanged (rule 1).
  registerRoutes(app: RouteApp): void {
    const { log, certificateHeader, revocation, errorCodes, pki,
            config } = this.deps;
    const self = this;
    log.debug("Entering PkiService.registerRoutes().");
    // -------------------------------------------------------------------------
    // GET /pki/crl/{scope}/{ca}.crl
    // -------------------------------------------------------------------------
    // **ONE ROUTE, AND THE `.crl` SUFFIX IS STRIPPED IN THE HANDLER RATHER THAN
    // BEING PART OF THE PATH.** `/pki/crl/:scope/:ca.crl` is a legal express
    // pattern on some versions of path-to-regexp and throws at registration on
    // others, and a client following a URL out of a certificate must never meet
    // a 404 over a routing detail — so the suffix, which is there for the
    // benefit of whatever saves the file, is taken off here. Both spellings
    // answer.
    app.get('/pki/crl/:scope/:ca', function (req, res) {
      log.debug('Entering the CRL endpoint.');
      self.crlFor(req, res, String(req.params.scope),
                  String(req.params.ca).replace(/\.crl$/, ''));
    });

    // -------------------------------------------------------------------------
    // GET /pki/ca/{scope}/{ca}.cer — the authority's own certificate.
    //
    // This is the `caIssuers` address in every certificate that authority
    // signed, and it is what lets a client sent an incomplete chain finish
    // building one.
    // -------------------------------------------------------------------------
    app.get('/pki/ca/:scope/:ca', function (req, res) {
      log.debug('Entering the CA certificate endpoint.');
      self.caCertificateFor(req, res, String(req.params.scope),
                            String(req.params.ca).replace(/\.cer$/, ''));
    });

    // -------------------------------------------------------------------------
    // GET /pki/chain/{scope}/{sha256}.pem — THE CHAIN AN `x5u` HEADER NAMES
    // (2026-09-13).
    //
    // A JWS this service signs with a certified key may carry `x5u` (RFC 7515
    // section 4.1.5) pointing HERE, per `common/jose_certificate_header.js`, so
    // a relying party holding only the token can fetch the certificate chain
    // and with it every CRL distribution point, OCSP responder and caIssuers
    // address the chain names. Leaf first, the service Root last, in PEM, as
    // `application/pem-certificate-chain` (RFC 8555 section 7.4.2 registered
    // it, and RFC 7515 asks for exactly this layout).
    //
    // **NAMED BY THE LEAF'S SHA-256, NOT BY A `kid` OR A SLOT.** The address is
    // written into a token that outlives the key that signed it, so it must
    // name one certificate for ever: a key rotated since is a 404, never a
    // chain over a different key. The value is matched against the register,
    // not parsed.
    //
    // **`no-store`**, for the rule every document that publishes this service's
    // key material follows: in development mode the keys behind these
    // certificates die with the process, and a cached chain would outlive them.
    // Ungated, like every endpoint in this file — what it returns is already
    // inside every token whose header names it.
    // -------------------------------------------------------------------------
    app.get('/pki/chain/:scope/:certificate', function (req, res) {
      log.debug('Entering the certificate chain endpoint.');
      const scopeSegment = String(req.params.scope);
      const thumbprint = String(req.params.certificate).replace(/\.pem$/, '');
      const pem = certificateHeader.chainPemFor(
        revocation.scopeFromSegment(scopeSegment), thumbprint);
      if (!pem) {
        errorCodes.mark(res, 'STS-PKI-0162');
        self.refuse(res, 404,
                    'There is no JOSE signing certificate with that SHA-256 ' +
                    'in the "' +
                    scopeSegment +
                    '" scope of this service. A certificate replaced ' +
                    'since a token named it is no longer published here.');
        log.debug("Leaving the certificate chain endpoint. Not found.");
        return;
      }
      res.status(200)
         .set('Content-Type', 'application/pem-certificate-chain')
         .set('Cache-Control', 'no-store')
         .send(pem);
      log.debug("Leaving the certificate chain endpoint.");
    });

    // -------------------------------------------------------------------------
    // OCSP, both transports RFC 6960 appendix A.1 defines.
    //
    // **THE GET FORM IS BASE64 IN A PATH SEGMENT AND IT NEEDS DECODING TWICE.**
    // Section A.1.1 says the base64 of the DER request, URL-encoded — and
    // base64 contains `+`, `/` and `=`, all of which a client must
    // percent-encode and some do not. Express has already decoded the parameter
    // once; a `+` that arrived raw is a space by then, which is why it is put
    // back. Getting this wrong produces `malformedRequest` for a request that
    // was perfectly well formed, and the client has no way to tell the two
    // apart.
    //
    // **AND A `/` THE CLIENT DID NOT ENCODE IS STILL PART OF THE REQUEST
    // (2026-09-13).** The route was `/:request`, one path segment, so a base64
    // request containing a raw `/` — RFC 5019 section 5 says a client MUST
    // encode it, and some do not — split into two segments and answered
    // Express's HTML 404, which reads as a responder that is not there. `/*`
    // takes the rest of the path whole.
    //
    // **A REQUEST THAT IS NOT ONE IS ANSWERED `malformedRequest`, NOT A 400.**
    // RFC 6960 section 2.3: *malformedRequest — the request received does not
    // conform to the OCSP syntax.* A path segment that is not base64, or
    // decodes to nothing, is exactly that, and an OCSP client dispatches on the
    // response status rather than on a text body it will not parse.
    // -------------------------------------------------------------------------
    app.get('/pki/ocsp/:scope/:ca/*', function (req, res) {
      log.debug('Entering the OCSP endpoint (GET).');
      let der = Buffer.alloc(0);
      try {
        const text = String(req.params[0] || '').replace(/ /g, '+');
        der = /^[A-Za-z0-9+/=_-]+$/.test(text)
          ? Buffer.from(text, 'base64') : Buffer.alloc(0);
      } catch (e) {
        log.debug("Caught in a callback in module scope: " +
                  ((e && e.message) || e));
        der = Buffer.alloc(0);
      }
      self.answer(req, res, String(req.params.scope), String(req.params.ca),
                  der);
    });

    // -------------------------------------------------------------------------
    // GET /pki/ocsp/{scope}/{ca} — THE ADDRESS AS IT IS WRITTEN IN A
    // CERTIFICATE.
    //
    // **THIS WAS EXPRESS'S 404 UNTIL 2026-09-13, AND IT IS THE FIRST URL
    // ANYBODY TRIES.** The `id-ad-ocsp` access location in every certificate
    // this service issues is this path with nothing after it, because RFC 6960
    // appendix A.1.1 makes it the BASE of both transports: a POST to it, or a
    // GET to it with the base64 of a request appended. Only the POST and the
    // suffixed GET had routes, so the one fetch a person makes first — the URL
    // copied out of `openssl x509 -text` — answered `Cannot GET`, which reads
    // exactly like a responder that is not there, and cannot be told apart from
    // an authority this service does not have.
    //
    // RFC 6960 defines no answer to a GET that carries no request, so this one
    // is the nearest thing to useful the specification allows: a 400 naming
    // both transports for an authority that exists, and the CRL endpoint's own
    // 404 for one that does not — so "this responder exists and you asked it
    // nothing" and "there is no such responder" are two different answers. Text
    // and not an OCSPResponse, because no OCSP client makes this request and a
    // person does.
    // -------------------------------------------------------------------------
    app.get('/pki/ocsp/:scope/:ca', function (req, res) {
      log.debug('Entering the OCSP endpoint (GET with no request).');
      const scopeSegment = String(req.params.scope);
      const caId = String(req.params.ca);
      const scope = revocation.scopeFromSegment(scopeSegment);
      if (!revocation.authorityFor(scope, caId)) {
        errorCodes.mark(res, 'STS-PKI-0131');
        self.refuse(res, 404,
                    'There is no "' + caId +
                    '" certificate authority in the "' +
                    scopeSegment +
                    '" scope of this service, so there is no OCSP ' +
                    'responder for it. GET /pki/revocation lists every ' +
                    'responder this service answers.');
        log.debug('Leaving the OCSP endpoint. No such authority.');
        return;
      }
      errorCodes.mark(res, 'STS-PKI-0130');
      self.refuse(res, 400,
                  'This is the OCSP responder of the "' + caId +
                  '" certificate authority in the "' + scopeSegment +
                  '" scope, and this request asked it nothing. RFC 6960 ' +
                  'appendix A.1.1 defines two transports on this address: ' +
                  'POST the DER OCSPRequest here as ' +
                  'application/ocsp-request, or GET this address with "/" ' +
                  'and the URL-encoded base64 of the DER request appended. ' +
                  'For example: openssl ocsp -issuer issuer.pem -cert ' +
                  'cert.pem -url <this URL> -CAfile root.pem');
      log.debug('Leaving the OCSP endpoint. No request.');
    });

    app.post('/pki/ocsp/:scope/:ca', function (req, res) {
      log.debug('Entering the OCSP endpoint (POST).');
      // ---------------------------------------------------------------------
      // **THE BODY IS `req.body` AND IT IS A BUFFER, BECAUSE `common/app.js`'S
      // RAW PARSER TAKES `application/ocsp-request`.** The first version of
      // this handler read the stream itself — `req.on('data')`, `req.on('end')`
      // — and every POST to this endpoint HUNG, with no error anywhere: `curl`
      // reported `000`, nothing was logged, and the service answered everything
      // else in milliseconds.
      //
      // The cause is one line further down that file: `bodyParser.text({ type:
      // () => true })` takes EVERY content type, so by the time this handler
      // ran the body had already been read and `end` was never going to fire
      // again. And had it fired, the bytes would have been decoded as UTF-8 —
      // which is the corruption the Kerberos MS-KKDCP row in that parser exists
      // to prevent, met a second time by a second binary endpoint.
      //
      // **THE LESSON IS THE GENERAL ONE**: in this service a handler never
      // reads the request stream, because something above it already has. A new
      // binary endpoint costs a content type in that parser's list and nothing
      // else.
      // ---------------------------------------------------------------------
      const body = req.body;
      // ANYTHING ELSE IS NO BYTES AT ALL, not `null`: a JSON content type
      // reaches here as a parsed object, and until 2026-09-16 `der.length`
      // below threw on it and the responder answered 500.
      const der = Buffer.isBuffer(body) ? body
        : (typeof body === 'string' ? Buffer.from(body, 'binary')
                                    : Buffer.alloc(0));
      // NO BODY IS A REQUEST THAT DOES NOT CONFORM TO THE OCSP SYNTAX, and it
      // is answered `malformedRequest` inside the protocol rather than a 400 —
      // see the GET route above. `answer()` hands it to the responder like any
      // other bytes, which is what keeps the two transports answering alike.
      // A CAP, because this is an unauthenticated endpoint that reads a body.
      // An OCSP request for one certificate is about eighty bytes and for a
      // hundred is still under ten kilobytes; a megabyte is a client doing
      // something else. It is checked HERE as well as by the parser's own 5mb
      // limit, because that limit is shared with SOAP and Kerberos and is far
      // too generous for this.
      if (der.length > 65536) {
        errorCodes.mark(res, 'STS-PKI-0073');
        self.refuse(res, 413,
                    'That OCSP request is larger than ' +
                    'this responder accepts (64KB). ' +
                    'A request for one certificate is about eighty bytes.');
        log.debug('Leaving the OCSP endpoint. Too large.');
        return;
      }
      self.answer(req, res, String(req.params.scope), String(req.params.ca),
                  der);
    });

    // -------------------------------------------------------------------------
    // GET /pki/revocation — WHAT THIS SERVICE PUBLISHES, as JSON.
    //
    // Not part of either protocol and deliberately here anyway: a person
    // pointing a client at these endpoints needs to know what the addresses
    // ARE, and reading them out of a certificate with `openssl x509 -text` is a
    // poor first step. It is the same shape of courtesy `/tls` and `/realms`
    // already are — ungated, because everything in it is already inside every
    // certificate this service hands out.
    //
    // **NO SERIAL NUMBERS ARE IN IT.** The list of what is revoked is the CRL,
    // and a JSON copy beside it would be a second answer to the same question —
    // the one that goes stale, and the one nobody signed.
    // -------------------------------------------------------------------------
    app.get('/pki/revocation', function (req, res) {
      log.debug('Entering the revocation index.');
      const all = revocation.authorities(pki.knownScopes());
      const out = {
        what: 'Every certificate revocation list and OCSP responder this ' +
              'service publishes. There is one of each PER CERTIFICATE ' +
              'AUTHORITY, because a CRL is signed by an issuer and lists ' +
              'serials that issuer minted — a list per realm would be a ' +
              'document with no valid issuer.',
        revocationIsPublishedNotEnforced:
          'This service publishes revocation and cannot make anybody consult ' +
          'it. A certificate revoked here goes on the list and its OCSP ' +
          'responder answers `revoked`; whether that stops anything depends ' +
          'entirely on the relying party, which is ' +
          'true of every certificate authority and ' +
          'is the reason a client author would point their stack here.',
        crlLifetimeMinutes: Number(config.value('pki.crlLifetimeMinutes')),
        publishedToDirectory: !!config.value('pki.publishCrlToDirectory'),
        authorities: all.map(function (one) {
          const points = revocation.distributionPoints(one.scope, one.ca);
          return {
            scope: revocation.scopeSegment(one.scope),
            ca: one.ca,
            label: one.label,
            subject: one.tier.subject,
            revokedCount: revocation.listFor(one.scope, one.ca).length,
            crl: { http: points.http, ldap: points.ldap },
            ocsp: points.ocsp,
            caIssuers: points.caIssuers,
            directoryDn: points.dn
          };
        })
      };
      res.status(200).type('application/json').set('Cache-Control', 'no-store')
         .send(JSON.stringify(out, null, 2));
      log.debug('Leaving the revocation index. ' + out.authorities.length +
                ' authority(ies).');
    });
    log.debug("Leaving PkiService.registerRoutes().");
  }
}

// THE TRANSITIONAL INSTANCE (#50): built from the real modules, as the
// composition root will build one, and the source of every name this
// module exports. It goes when that root exists.
const pkiService = new PkiService({
  http: http,
  nodeCrypto: nodeCrypto,
  app: app,
  log: log,
  config: config,
  pki: pki,
  revocation: revocation,
  certificateHeader: certificateHeader,
  errorCodes: errorCodes,
  proxyProtocol: proxyProtocol
});

pkiService.registerRoutes(app);

log.info('The PKI revocation endpoints are registered: a CRL at ' +
         'GET /pki/crl/{scope}/{ca}.crl, an OCSP responder at ' +
         'GET|POST /pki/ocsp/{scope}/{ca}, the issuing certificate at ' +
         'GET /pki/ca/{scope}/{ca}.cer, an index of all of them at ' +
         'GET /pki/revocation, and the chain a signed token\'s x5u names at ' +
         'GET /pki/chain/{scope}/{sha256}.pem. Every certificate this ' +
         'service issues names ' +
         'its CRL over http and ldap, its OCSP responder and its issuer\'s ' +
         'certificate over http.');

// ===========================================================================
// THE PLAIN-HTTP LISTENER, AND WHY THIS SERVICE HAS ONE AT ALL (2026-09-13).
//
// **EVERY CERTIFICATE NAMED `https://` FOR ITS REVOCATION ADDRESSES**, on the
// main port, and two specifications say not to:
//
//   * **RFC 5280 section 8**: *CAs SHOULD NOT include URIs that specify https,
//     ldaps, or similar schemes in extensions*, and one that does MUST make
//     sure the server's certificate can be validated without the information
//     at that URI. Here it could not: the main port's own TLS certificate
//     names its OCSP responder and its issuer's certificate ON THAT LISTENER,
//     so a client that checks revocation before it trusts a connection needs
//     the answer to open the connection that carries the answer.
//   * **RFC 5019 section 5**: *the OCSP responder MUST support requests and
//     responses over HTTP.*
//
// The main port is TLS or it is not, for every path at once, and turning it
// into plain HTTP to satisfy this would undo the RFC 9700 argument that made it
// TLS. So there is a SECOND listener, plain HTTP, which answers `/pki/` and
// nothing else, and the certificates name it.
//
// **IT CARRIES NOTHING SECRET AND NOTHING THAT NEEDS INTEGRITY FROM THE
// TRANSPORT.** A CRL and an OCSP response are signed by the authority they are
// about, and a relying party verifies them against a key it already trusts; a
// CA certificate fetched from a caIssuers address is only ever used if it
// chains to an anchor the relying party holds. That is the whole reason the
// specifications ask for plain HTTP here and nowhere else.
//
// **EVERYTHING ELSE IS REFUSED ON THIS SOCKET, BEFORE THE APP SEES IT.** The
// app behind it is the whole service — the console, the token endpoint,
// `/admin-api` — and a plain-HTTP door onto any of those would be a door no
// setting in this service opens on purpose. The check is on the PATH before
// express is reached, so no middleware ordering can widen it.
//
// `pki.httpPort` 0 binds nothing, and the certificates then name the main
// port's own scheme and port instead — see `httpBase()` in
// `common/pki_revocation.js`.
// ===========================================================================
let httpListening = false;
let httpListenError = '';
let httpBoundPort = 0;

export = {
  PkiService: PkiService,
  // `listen()` is what `server.js` calls. The other three are exported so a
  // caller can read the listener's state, the CRL cache policy and the path
  // filter without binding a socket; the URL shapes themselves are
  // `common/pki_revocation.js`'s `distributionPoints()`.
  cacheSeconds: pkiService.cacheSeconds.bind(pkiService) as
    PkiService['cacheSeconds'],
  listen: pkiService.listen.bind(pkiService) as PkiService['listen'],
  status: pkiService.status.bind(pkiService) as PkiService['status'],
  revocationOnly: pkiService.revocationOnly.bind(pkiService) as
    PkiService['revocationOnly']
};
