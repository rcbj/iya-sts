'use strict';
//
// File: pki_service.js
//
// ===========================================================================
// THE REVOCATION ENDPOINTS: A CRL AND AN OCSP RESPONDER PER CA (2026-09-11).
//
// **THIS IS A PROTOCOL SURFACE AND NOT A CONSOLE ONE**, which is why it is a
// directory of its own rather than more routes in `admin-ui/pki_admin.js`.
// Nothing here is behind the console's gate and nothing here takes a
// credential: a CRL and an OCSP answer are PUBLIC documents by construction —
// a relying party fetches them before it has decided to trust anything, often
// before it has authenticated to anybody, and a revocation list nobody can
// read is a revocation nobody acts on.
//
// Four routes, and the shape of the first three is the same:
//
//   GET  /pki/crl/{scope}/{ca}.crl    the signed CRL, DER
//   GET  /pki/ca/{scope}/{ca}.cer     the authority's own certificate, DER
//   GET  /pki/ocsp/{scope}/{ca}/{b64} RFC 6960 section A.1.1, base64 in a path
//   POST /pki/ocsp/{scope}/{ca}       RFC 6960 section A.1.1, DER in a body
//   GET  /pki/revocation              what this service publishes, as JSON
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

const app = require('../common/app');
const { log, parseBody } = require('../common/helpers');
const config = require('../common/config');
const pki = require('../common/pki');
const revocation = require('../common/pki_revocation');
// The error-code registry (a leaf). Every refusal below is `mark()`ed on the
// response before it is sent and never written into it: a revocation client
// is shown exactly the text and the OCSP status it was always shown.
const errorCodes = require('../common/error_codes');

// ---------------------------------------------------------------------------
// CACHING. A CRL says how long it is fresh for and a client is entitled to
// cache it for exactly that long — so the header says the same thing the
// document does, computed from the same setting, rather than `no-store`.
//
// **THIS IS THE ONE FAMILY OF DOCUMENTS IN THIS SERVICE THAT IS DELIBERATELY
// CACHEABLE.** Everything else that publishes key material is `no-store`,
// because a key regenerated at every start must not be cached. A CRL is the
// opposite case: it carries its own validity window, and a client that
// refetches it on every check is a client hammering this service for a document
// that has not changed.
// ---------------------------------------------------------------------------
// The floor is the setting row's own `min: 1`; see `crlLifetimeMs()` in
// common/pki_revocation.js for why a second floor of 60 here was a bug.
function cacheSeconds() {
  log.debug("Entering cacheSeconds().");
  const minutes = Number(config.value('pki.crlLifetimeMinutes'));
  log.debug("Leaving cacheSeconds().");
  return Math.max(1, Number.isFinite(minutes) ? minutes : 60) * 60;
}

function sendDer(res, mediaType, der, cacheable) {
  log.debug("Entering sendDer().");
  res.status(200)
     .set('Content-Type', mediaType)
     .set('Content-Length', String(der.length))
     .set('Cache-Control', cacheable
       ? 'public, max-age=' + cacheSeconds()
       : 'no-store')
     .send(der);
  log.debug("Leaving sendDer().");
}

// A refusal a revocation client can read. **NOT JSON and not a page**: it is
// text, because there is no error format either protocol defines for the
// transport layer and a client that meets one is being debugged by a person.
function refuse(res, status, sentence) {
  log.debug("Entering refuse().");
  res.status(status).type('text/plain').set('Cache-Control', 'no-store')
     .send(sentence + '\n');
  log.debug("Leaving refuse().");
}

// ---------------------------------------------------------------------------
// GET /pki/crl/{scope}/{ca}.crl
// ---------------------------------------------------------------------------
// **ONE ROUTE, AND THE `.crl` SUFFIX IS STRIPPED IN THE HANDLER RATHER THAN
// BEING PART OF THE PATH.** `/pki/crl/:scope/:ca.crl` is a legal express
// pattern on some versions of path-to-regexp and throws at registration on
// others, and a client following a URL out of a certificate must never meet a
// 404 over a routing detail — so the suffix, which is there for the benefit of
// whatever saves the file, is taken off here. Both spellings answer.
app.get('/pki/crl/:scope/:ca', function (req, res) {
  log.debug('Entering the CRL endpoint.');
  crlFor(req, res, String(req.params.scope),
         String(req.params.ca).replace(/\.crl$/, ''));
});

function crlFor(req, res, scopeSegment, caId) {
  log.debug('Entering crlFor(). scope=' + scopeSegment + ' ca=' + caId);
  const scope = revocation.scopeFromSegment(scopeSegment);
  const authority = revocation.authorityFor(scope, caId);
  if (!authority) {
    errorCodes.mark(res, 'STS-PKI-0068');
    refuse(res, 404,
           'There is no "' + caId + '" certificate authority in the "' +
           scopeSegment + '" scope of this service, so there is no ' +
           'revocation list for it. GET /pki/revocation lists every CRL this ' +
           'service publishes.');
    log.debug('Leaving crlFor(). No such authority.');
    return;
  }
  revocation.buildCrl(scope, caId).then(function (made) {
    if (!made.ok) {
      errorCodes.mark(res, errorCodes.codeOf(made) || 'STS-PKI-0069');
      refuse(res, 500, made.errors.join(' '));
      log.debug('Leaving crlFor(). It could not be built.');
      return;
    }
    sendDer(res, 'application/pkix-crl', made.der, true);
    log.debug('Leaving crlFor(). ' + made.count + ' entry(ies).');
  }).catch(function (e) {
    log.error(errorCodes.tag('STS-PKI-0069') + 'pki: the "' + caId + '" CRL ' +
        'could not be built: ' +
              (e && e.stack ? e.stack : e));
    errorCodes.mark(res, 'STS-PKI-0069');
    refuse(res, 500, 'That CRL could not be built: ' +
                     (e && e.message ? e.message : e));
  });
  log.debug("Leaving crlFor().");
}

// ---------------------------------------------------------------------------
// GET /pki/ca/{scope}/{ca}.cer — the authority's own certificate.
//
// This is the `caIssuers` address in every certificate that authority signed,
// and it is what lets a client sent an incomplete chain finish building one.
// ---------------------------------------------------------------------------
app.get('/pki/ca/:scope/:ca', function (req, res) {
  log.debug('Entering the CA certificate endpoint.');
  caCertificateFor(req, res, String(req.params.scope),
                   String(req.params.ca).replace(/\.cer$/, ''));
});

function caCertificateFor(req, res, scopeSegment, caId) {
  log.debug("Entering caCertificateFor().");
  const scope = revocation.scopeFromSegment(scopeSegment);
  const authority = revocation.authorityFor(scope, caId);
  if (!authority) {
    errorCodes.mark(res, 'STS-PKI-0070');
    refuse(res, 404,
           'There is no "' + caId + '" certificate authority in the "' +
           scopeSegment + '" scope of this service.');
    log.debug("Leaving caCertificateFor().");
    return;
  }
  const der = Buffer.from(
    String(authority.tier.certificatePem).replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, ''), 'base64');
  // **CACHEABLE, unlike every other place this service publishes a
  // certificate.** A CA certificate is a durable document by construction —
  // an authority that changed would be a different authority with a different
  // name — so a client is entitled to keep it, and the `caIssuers` fetch is
  // meant to happen once.
  sendDer(res, 'application/pkix-cert', der, true);
  log.debug("Leaving caCertificateFor().");
}

// ---------------------------------------------------------------------------
// OCSP, both transports RFC 6960 appendix A.1 defines.
//
// **THE GET FORM IS BASE64 IN A PATH SEGMENT AND IT NEEDS DECODING TWICE.**
// Section A.1.1 says the base64 of the DER request, URL-encoded — and base64
// contains `+`, `/` and `=`, all of which a client must percent-encode and
// some do not. Express has already decoded the parameter once; a `+` that
// arrived raw is a space by then, which is why it is put back. Getting this
// wrong produces `malformedRequest` for a request that was perfectly well
// formed, and the client has no way to tell the two apart.
// ---------------------------------------------------------------------------
app.get('/pki/ocsp/:scope/:ca/:request', function (req, res) {
  log.debug('Entering the OCSP endpoint (GET).');
  let der = null;
  try {
    const text = String(req.params.request).replace(/ /g, '+');
    der = Buffer.from(text, 'base64');
  } catch (e) {
    log.debug("Caught in a callback in module scope: " +
              ((e && e.message) || e));
    der = null;
  }
  if (!der || !der.length) {
    errorCodes.mark(res, 'STS-PKI-0071');
    refuse(res, 400,
           'That is not a base64 OCSP request. RFC 6960 appendix A.1.1: the ' +
           'GET form is the base64 of the DER request, URL-encoded, as the ' +
           'last path segment.');
    log.debug('Leaving the OCSP endpoint. Not base64.');
    return;
  }
  answer(req, res, String(req.params.scope), String(req.params.ca), der);
});

app.post('/pki/ocsp/:scope/:ca', function (req, res) {
  log.debug('Entering the OCSP endpoint (POST).');
  // ---------------------------------------------------------------------
  // **THE BODY IS `req.body` AND IT IS A BUFFER, BECAUSE `common/app.js`'S
  // RAW PARSER TAKES `application/ocsp-request`.** The first version of this
  // handler read the stream itself — `req.on('data')`, `req.on('end')` — and
  // every POST to this endpoint HUNG, with no error anywhere: `curl`
  // reported `000`, nothing was logged, and the service answered everything
  // else in milliseconds.
  //
  // The cause is one line further down that file: `bodyParser.text({ type:
  // () => true })` takes EVERY content type, so by the time this handler ran
  // the body had already been read and `end` was never going to fire again.
  // And had it fired, the bytes would have been decoded as UTF-8 — which is
  // the corruption the Kerberos MS-KKDCP row in that parser exists to
  // prevent, met a second time by a second binary endpoint.
  //
  // **THE LESSON IS THE GENERAL ONE**: in this service a handler never reads
  // the request stream, because something above it already has. A new binary
  // endpoint costs a content type in that parser's list and nothing else.
  // ---------------------------------------------------------------------
  const body = req.body;
  const der = Buffer.isBuffer(body) ? body
    : (typeof body === 'string' ? Buffer.from(body, 'binary') : null);
  if (!der || !der.length) {
    errorCodes.mark(res, 'STS-PKI-0072');
    refuse(res, 400,
           'An OCSP request has a body, and it must be sent as ' +
           'application/ocsp-request so that the bytes arrive intact. This ' +
           'one had none.');
    log.debug('Leaving the OCSP endpoint. No body.');
    return;
  }
  // A CAP, because this is an unauthenticated endpoint that reads a body. An
  // OCSP request for one certificate is about eighty bytes and for a hundred
  // is still under ten kilobytes; a megabyte is a client doing something
  // else. It is checked HERE as well as by the parser's own 5mb limit,
  // because that limit is shared with SOAP and Kerberos and is far too
  // generous for this.
  if (der.length > 65536) {
    errorCodes.mark(res, 'STS-PKI-0073');
    refuse(res, 413,
           'That OCSP request is larger than this responder accepts (64KB). ' +
           'A request for one certificate is about eighty bytes.');
    log.debug('Leaving the OCSP endpoint. Too large.');
    return;
  }
  answer(req, res, String(req.params.scope), String(req.params.ca), der);
});

function answer(req, res, scopeSegment, caId, der) {
  log.debug('Entering answer(). scope=' + scopeSegment + ' ca=' + caId);
  if (!der || !der.length) {
    errorCodes.mark(res, 'STS-PKI-0072');
    refuse(res, 400, 'An OCSP request has a body. This one had none.');
    log.debug('Leaving answer(). Empty request.');
    return;
  }
  const scope = revocation.scopeFromSegment(scopeSegment);
  revocation.answerOcsp(scope, caId, der).then(function (made) {
    // **EVEN A REFUSAL IS AN OCSP RESPONSE.** `malformedRequest` and
    // `unauthorized` are statuses inside the protocol, not HTTP errors, so a
    // client that meets one can report what happened rather than guessing from
    // a status code. The HTTP status stays 200 for all of them, which is what
    // RFC 6960 section A.2 asks for.
    //
    // An OCSP answer is NOT cacheable here: it carries `nextUpdate`, and the
    // interesting thing a person does with this responder is revoke something
    // and ask again.
    // An OCSP REFUSAL (`unauthorized`, `malformedRequest`, `internalError`)
    // carries its code on the answer; `good`, `revoked` and `unknown` are
    // answers rather than failures and carry none.
    if (errorCodes.codeOf(made)) {
      errorCodes.mark(res, errorCodes.codeOf(made));
    }
    sendDer(res, 'application/ocsp-response', made.der, false);
    log.debug('Leaving answer(). ' + made.status + '.');
  }).catch(function (e) {
    log.error(errorCodes.tag('STS-PKI-0074') + 'pki: an OCSP request to the "' +
        caId + '" ' +
        'responder threw: ' +
              (e && e.stack ? e.stack : e));
    errorCodes.mark(res, 'STS-PKI-0074');
    refuse(res, 500, 'That OCSP request could not be answered.');
  });
  log.debug("Leaving answer().");
}

// ---------------------------------------------------------------------------
// GET /pki/revocation — WHAT THIS SERVICE PUBLISHES, as JSON.
//
// Not part of either protocol and deliberately here anyway: a person pointing
// a client at these endpoints needs to know what the addresses ARE, and
// reading them out of a certificate with `openssl x509 -text` is a poor first
// step. It is the same shape of courtesy `/tls` and `/realms` already are —
// ungated, because everything in it is already inside every certificate this
// service hands out.
//
// **NO SERIAL NUMBERS ARE IN IT.** The list of what is revoked is the CRL, and
// a JSON copy beside it would be a second answer to the same question — the
// one that goes stale, and the one nobody signed.
// ---------------------------------------------------------------------------
app.get('/pki/revocation', function (req, res) {
  log.debug('Entering the revocation index.');
  const all = revocation.authorities(pki.knownScopes());
  const out = {
    what: 'Every certificate revocation list and OCSP responder this service ' +
          'publishes. There is one of each PER CERTIFICATE AUTHORITY, ' +
          'because a CRL is signed by an issuer and lists serials that ' +
          'issuer minted — a list per realm would be a document with no ' +
          'valid issuer.',
    revocationIsPublishedNotEnforced:
      'This service publishes revocation and cannot make anybody consult it. ' +
      'A certificate revoked here goes on the list and its OCSP responder ' +
      'answers `revoked`; whether that stops anything depends entirely on ' +
      'the relying party, which is true of every certificate authority and ' +
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
        crl: { http: points.http, ldap: points.ldap, ldaps: points.ldaps },
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

log.info('The PKI revocation endpoints are registered: a CRL at ' +
         'GET /pki/crl/{scope}/{ca}.crl, an OCSP responder at ' +
         'GET|POST /pki/ocsp/{scope}/{ca}, the issuing certificate at ' +
         'GET /pki/ca/{scope}/{ca}.cer, and an index of all of them at ' +
         'GET /pki/revocation. Every certificate this service issues names ' +
         'its own in three schemes — http, ldap and ldaps.');

module.exports = {
  // For `sts_metadata.js` and the tests: the shapes, so nothing has to
  // hand-build one of these URLs.
  cacheSeconds: cacheSeconds
};
