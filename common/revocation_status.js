'use strict';
//
// File: revocation_status.js
//
// ===========================================================================
// REVOCATION, CONSULTED (2026-09-12): THE OTHER HALF OF `pki_revocation.js`.
//
// `common/pki_revocation.js` PUBLISHES — every certificate authority this
// service holds signs an RFC 5280 CRL and answers RFC 6960 OCSP. Until this file
// existed nothing here CONSULTED anything: a client certificate presented on
// 8443, 9443 or the main port, an X509-SVID at the SPIRE Server API and a chain
// in an assertion's `x5c` were all checked against their anchors and never
// against a list, so **a certificate revoked on this service's own /admin/pki
// still authenticated to this service.** `common/mode.js` carried that as its
// `certificate-revocation` NOT_YET row, and this file is what narrowed it.
//
// ---------------------------------------------------------------------------
// ONE FUNCTION ANSWERS, AND EVERY DOOR ASKS IT.
//
// `verdictFor()` takes a presented chain — the leaf, whatever came with it, and
// whether it VERIFIED — and answers `good`, `revoked` (with the reason and the
// moment) or `unknown` (with why). `decide()` applies `pki.revocationCheck` to
// that answer. The doors that accept a certificate call one or the other and
// nothing else, so there is ONE reading of "is this certificate revoked" in the
// service rather than five that agree today.
//
// ---------------------------------------------------------------------------
// TWO SOURCES, AND WHICH ONE ANSWERS IS DECIDED BY WHO SIGNED THE CERTIFICATE.
//
//   * **A CERTIFICATE ONE OF THIS SERVICE'S OWN AUTHORITIES SIGNED is answered
//     from the REGISTER** — `pki_revocation.isRevoked()` — with no fetch. The
//     issuer is found by NAME AND SIGNATURE among the Root, every Intermediate
//     and every Issuing CA this process holds, which is the only comparison that
//     tells two same-named authorities apart (`pki.js` says why at length). It
//     is synchronous, so it has no failure mode: the answer is `good` or
//     `revoked` and never `unknown`. **The walk goes UP through the tiers this
//     service holds whether or not the client sent them**, because a revoked
//     Intermediate revokes everything under it and a client that sends only its
//     leaf must not be how that is got around.
//   * **A CERTIFICATE FROM ANYBODY ELSE'S AUTHORITY is answered by the OCSP
//     responder its Authority Information Access names and by the CRL its
//     `cRLDistributionPoints` names** — in the order `pki.revocationOcsp`
//     chooses, `first` by default, with the other as the fallback — each
//     fetched over http or https only, with a timeout, a size cap and a cache
//     that honours the document's own validity, and each verified against a
//     key the certificate's ISSUER vouched for: its own, a delegated OCSP
//     responder it certified, or the CRL issuer it named. A CRL and an OCSP
//     response are signed documents, so where one came from decides nothing;
//     whose key signed it decides everything. Delta CRLs are merged onto their
//     base and indirect CRLs are read entry by entry, both below.
//
// ---------------------------------------------------------------------------
// THE OUTBOUND REQUEST, AND WHY IT IS ALLOWED. This is the FIFTH outbound
// request in this repository, and it is argued from scratch rather than cited,
// because `federation/federation_http.js` is explicit that "this feature needs
// it" is the argument every SSRF ever shipped was made with.
//
//   **THE URL IS WRITTEN BY AN AUTHORITY THE OPERATOR CHOSE TO TRUST, AND ONLY
//   THEN.** A distribution point is dialled ONLY for a chain that VERIFIED
//   against an anchor in this service's truststore (`tls.trustAnchorsFile`, or
//   the gated `/admin/tls/trust` door) — so the certificate carrying the URL was
//   signed by a CA an administrator installed, which is federation's
//   *administrator-supplied* argument reached through a signature rather than
//   through a form. An UNVERIFIED certificate is answered from the register and
//   nothing it names is dialled: anybody can mint a certificate naming any URL,
//   and following one would be exactly the request-forwarder that file refuses
//   to be.
//
// **AN OCSP RESPONDER IS THE SAME CASE.** Its URL is in the same certificate,
// written by the same issuer, and dialled under the same condition; the request
// is a POST of a DER document naming one certificate, and nothing from the
// presented chain but that certificate's CertID and a random nonce is sent.
//
// Six more things are enforced, for both, and each is a different failure:
//
//   1. **`http:`, `https:` AND — FOR A CRL OR A CA CERTIFICATE — `ldaps:`.**
//      Never `file:`, never anything else; plain `ldap:` only where
//      `pki.revocationLdap` says so, and an OCSP responder is http(s) only
//      because RFC 6960 appendix A defines no other transport. A distribution
//      point in another scheme is REPORTED as not fetchable, which is a fact
//      about the issuer and not a failure to check. LDAP is argued at
//      `fetchLdap()` as the second protocol this file speaks outbound.
//   2. **NO REDIRECT IS FOLLOWED.** RFC 5280 section 4.2.1.13 names the URL;
//      a 302 is a different URL nobody signed, and following one is the SSRF
//      arriving through the front door.
//   3. **A TIMEOUT AND A SIZE CAP**, `pki.revocationFetchTimeoutMs` and
//      `pki.revocationMaxCrlBytes`. A CRL server that answers slowly is a
//      request to this service hanging; one that answers forever is this
//      process's memory.
//   4. **https IS NOT CERTIFICATE-CHECKED, AND THAT IS ARGUED RATHER THAN
//      FORGOTTEN.** A CRL is authenticated by its own signature against the
//      issuer, which this file verifies; the transport adds a second, UNRELATED
//      trust decision — the Web PKI — and a CRL server's certificate commonly
//      chains to the very CA being checked, which is the circularity RFC 5280
//      warns about when it recommends http for distribution points. A forged or
//      replayed list fails the signature or the `nextUpdate` check whatever the
//      transport said.
//   5. **A FAILURE IS CACHED TOO**, for `pki.revocationFailureRetryS`, so an
//      unreachable server costs one timeout per window rather than one per
//      request.
//   6. **ONE FETCH PER URL AT A TIME.** Concurrent requests presenting the same
//      chain wait on the same promise rather than each dialling.
//
// `User-Agent` is `common/version.js`'s product token, `(crl-fetch)`, for the
// reason every other outbound requester here gives: somebody else's access
// log is where an integration with a service they did not install is
// diagnosed.
//
// ---------------------------------------------------------------------------
// THE POLICY: `off`, `soft-fail`, `hard-fail`, AND `auto` CHOOSING BY MODE.
//
//   off        consult nothing. What this service did for its whole life.
//   soft-fail  refuse a certificate that is KNOWN to be revoked; accept one
//              whose status could not be established, and report it.
//   hard-fail  refuse revoked, AND refuse a status that could not be
//              established because a CRL could not be fetched, did not verify,
//              was stale or named another issuer.
//
// `auto` — the default — is `mode.refusesUnknownRevocationStatus()`: hard-fail
// in product, soft-fail in development. **SOFT-FAIL IS THE CLASSIC WEAKNESS
// AND THAT IS WHY PRODUCT DOES NOT USE IT**: an attacker holding a revoked
// certificate who can block the CRL fetch turns "revoked" into "unknown", and
// soft-fail waves "unknown" through. Hard-fail closes that.
//
// **DEVELOPMENT CHECKS TOO**, and that is safe for a reason worth stating:
// checking this service's OWN register cannot make a good certificate fail —
// the register is what this service itself says, synchronously, with no
// network in it — and soft-fail lets an unreachable foreign CRL through. So
// what development refuses is exactly what somebody revoked, which is the
// behaviour a client author points a stack here to watch.
//
// **A CERTIFICATE NAMING NO FETCHABLE DISTRIBUTION POINT IS NOT REFUSED BY
// HARD-FAIL** unless `pki.revocationRequireDistributionPoint` says so. That is
// not a softening of hard-fail: hard-fail exists because an attacker can block
// a fetch, and a certificate whose issuer publishes no list gives an attacker
// nothing to block. Refusing it would make every private CA that publishes no
// CRL — the remote PEP credential the launchers mint is one — unusable in
// product mode, for no attack it prevents.
//
// ---------------------------------------------------------------------------
// OCSP (RFC 6960), ADDED THE SAME DAY: what is sent, and what is believed.
//
//   * **A NONCE IS ALWAYS SENT**, 32 random octets (RFC 8954's ceiling). A
//     response that echoes a DIFFERENT one is refused — it answers somebody
//     else's request, which is a replay. A response that echoes NONE is
//     believed by default, because the pre-produced responses of RFC 5019 —
//     what large and CDN-fronted responders serve — cannot carry one, and
//     refusing them would make OCSP useless against most real issuers; the
//     replay window is then the response's own freshness, which is checked.
//     `pki.revocationOcspRequireNonce` refuses those too, for a responder known
//     to sign per request.
//   * **THE SIGNER MUST BE THE ISSUER OR A RESPONDER THE ISSUER DELEGATED TO**:
//     a certificate in the response, issued by that same issuer, carrying
//     id-kp-OCSPSigning and inside its validity period (section 4.2.2.2), whose
//     key the responderID names and whose key verifies. A response signed by
//     any other CA — even one this service trusts — is not an answer about this
//     issuer's certificates.
//   * **THE DELEGATED RESPONDER'S OWN REVOCATION IS CHECKED** (RFC 6960 section
//     4.2.2.2.1), and never through OCSP: asking the responder about itself is
//     a recursion whose answer comes from the certificate in question. A
//     responder certificate carrying id-pkix-ocsp-nocheck is not checked, and
//     the verdict says so; any other is looked up on the CRL its own
//     distribution points name. REVOKED makes its answers unusable under every
//     policy. UNKNOWN is decided by the policy at the moment of use —
//     `responderStatusOf()` argues it.
//   * **A SIGNED `unknown` IS AN ANSWER**: the issuer's responder saying it does
//     not know this certificate. It is kept as unknown under the policy — so
//     hard-fail refuses it — and a CRL that does not list the certificate does
//     not upgrade it, while one that lists it still wins.
//
// ---------------------------------------------------------------------------
// DELTA AND INDIRECT CRLs (RFC 5280 sections 5.2.4, 5.2.5 and 5.3.3), ALSO THE
// SAME DAY, and the issuing distribution point that scopes them both.
//
//   * **A DELTA** is fetched from the freshestCRL the certificate or its base
//     CRL names, verified like any list, and merged only when it is a delta,
//     from the same issuer and signer, of the same scope, built on a base no
//     newer than the one held (BaseCRLNumber <= cRLNumber) and newer than it.
//     `removeFromCRL` takes an entry off. A delta that cannot be applied leaves
//     a base's permanent revocation standing and makes everything else unknown,
//     because blocking a delta must not hide the newest revocations.
//   * **AN INDIRECT CRL** is one the certificate's cRLDistributionPoints says is
//     issued by a named cRLIssuer. The list must declare indirectCRL, carry that
//     name, and be signed by a certificate for it that may sign CRLs and chains
//     to an authority the presented path passes through — found in the chain,
//     among this service's authorities, in `pki.revocationCrlIssuersFile`, or
//     at the caIssuers address the CRL's own Authority Information Access
//     names (`crlSignerFromCaIssuers()`).
//     Entries are attributed to the certificateIssuer before them, so a serial
//     is only ever matched under the right issuer.
//   * **THE ISSUING DISTRIBUTION POINT IS HONOURED**: its name must match the
//     point the certificate named; onlyContainsUserCerts, onlyContainsCACerts
//     and onlyContainsAttributeCerts decide whether it is about this
//     certificate at all; onlySomeReasons narrows the reasons it covers, and a
//     certificate is only GOOD once the lists it names cover every reason
//     between them.
//
// ---------------------------------------------------------------------------
// WHAT IS NOT DONE, SAID HERE SO THAT EVERY SURFACE REPEATS IT:
//
//   * **A BARE KEY IS NOT CHECKED, BECAUSE THERE IS NOTHING TO CHECK.** A JWK
//     with no x5c — in `oauthJwks`, `fedJwks`, a SPIFFE JWT bundle — names no
//     issuer and no serial. Every verdict about one says `bare` rather than
//     `good`; taking it off the entry is the only way to stop it verifying.
//   * **A NAME RELATIVE TO ITS CRL ISSUER IS RESOLVED ONLY WHERE IT IS
//     UNAMBIGUOUS**: every RDN single-valued, and a directory named by
//     `pki.revocationLdapDirectory`. A multi-valued RDN has no single string
//     form a directory is guaranteed to index it under, and the directory is not
//     in the certificate at all, so either absence is REFUSED by name rather
//     than guessed (`wholeNameOf()`, `relativeAddressOf()`).
//   * **A PRESENTED CERTIFICATE WHOSE ISSUER WAS NOT PRESENTED IS NOT
//     PATH-BUILT** from its caIssuers address. A verified chain already carries
//     its issuer — the TLS handshake would not have verified otherwise — so the
//     case does not arise at a door that verified; a REGISTERED certificate,
//     which nothing presents, is the one whose issuers are fetched.
//   * **LDAPS 636 ASKS FOR NO CLIENT CERTIFICATE**, so there is nothing there to
//     consult (`ldap/ldap_server.js` says so at the listener).
//   * **A SPIFFE FEDERATED BUNDLE IS A SET OF TRUST ANCHORS**, and an anchor is
//     trusted by being installed; no list can revoke one, which is what the walk
//     answers for a self-signed link anywhere.
//   * **RFC 8705 TOKEN BINDING IS NOT A REFUSAL POINT.** A `cnf` thumbprint binds
//     a token to whichever key completed the handshake, and section 3 explicitly
//     permits a certificate nobody vouched for; binding authenticates nobody.
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3): it registers no route. It requires `config`, `mode`,
// `error_codes`, `keystore`, `pki`, `pki_revocation` and `version` — none of
// which requires it back at load time; `pki.js` requires it LAZILY inside
// `verifyLeaf()`, for the same cycle `pki_revocation.js` is required lazily
// from there for.
// ===========================================================================

const bunyan = require('bunyan');
const fs = require('fs');
const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const nodeCrypto = require('crypto');
const { URL } = require('url');
const asn1js = require('asn1js');
const pkijs = require('pkijs');
const config = require('./config');

const log = bunyan.createLogger({
  name: 'revocation_status',
  level: config.value('global.logLevel')
});

const mode = require('./mode');
// The registry of failures (a leaf). A verdict this module RETURNS carries its
// code non-enumerably through `mark()`, because verdicts are copied whole onto
// `/tls/whoami` and `/admin-api` replies and a code must never reach a client.
const errorCodes = require('./error_codes');
const keystore = require('./keystore');
const pki = require('./pki');
// Required for `isRevoked()` and the reason table, AND for its side effect:
// it installs the Web Crypto engine pkijs verifies a CRL signature with.
const pkiRevocation = require('./pki_revocation');
const USER_AGENT = require('./version').userAgent('crl-fetch');

const POLICIES = ['auto', 'off', 'soft-fail', 'hard-fail'];

// The two REFUSAL codes, named once, because `decide()` marks a verdict with one
// and three doors elsewhere compare against them. The two FAILURE codes —
// STS-PKI-0120 (a CRL could not be fetched) and STS-PKI-0121 (it could not be
// used) — are written as literals at each log line, where `tests/error_codes.js`
// looks for a code beside a failure.
const CODE_REVOKED = 'STS-PKI-0118';
const CODE_UNKNOWN = 'STS-PKI-0119';

// The deepest chain walked. It is a bound on somebody else's bytes rather than
// a tunable: a real path is three or four certificates deep, and a loop in a
// presented chain must end.
const MAX_DEPTH = 8;

// ---------------------------------------------------------------------------
// THE POLICY IN FORCE, read per call and never cached — it is runtime and per
// realm, exactly like every other setting here.
// ---------------------------------------------------------------------------
function policy() {
  log.debug('Entering policy().');
  const configured = String(config.value('pki.revocationCheck') || 'auto');
  let effective = configured;
  if (configured === 'auto' || POLICIES.indexOf(configured) < 0) {
    effective = mode.refusesUnknownRevocationStatus() ? 'hard-fail'
                                                      : 'soft-fail';
  }
  log.debug('Leaving policy(). ' + effective);
  return {
    configured: configured,
    effective: effective,
    requireDistributionPoint:
      config.value('pki.revocationRequireDistributionPoint') === true,
    decidedBy: configured === 'auto'
      ? 'pki.revocationCheck is auto, so the mode decides: ' +
        (mode.isProduct() ? 'product mode hard-fails' : 'development mode soft-fails')
      : 'pki.revocationCheck is set to ' + configured
  };
}

// ---------------------------------------------------------------------------
// SMALL READERS.
// ---------------------------------------------------------------------------

// A serial as the register compares them. One spelling, `pki_revocation.js`'s,
// because two spellings of one serial is a certificate that is revoked and
// reports as good.
function normalSerial(text) {
  return pkiRevocation.normalSerial(text);
}

// An ArrayBuffer holding EXACTLY these bytes, for pkijs. `buf.buffer` is node's
// shared pool, and handing that to `fromBER()` parses whatever was allocated
// before this certificate — `pki_revocation.js`'s `derFromPem()` records the
// afternoon that cost.
function arrayBufferOf(buf) {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

function derOfPem(pem) {
  return Buffer.from(String(pem || '').replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, ''), 'base64');
}

// A parsed certificate, or null. Accepts PEM, DER or an X509Certificate.
function x509Of(value) {
  if (!value) {
    return null;
  }
  if (value instanceof nodeCrypto.X509Certificate) {
    return value;
  }
  try {
    if (Buffer.isBuffer(value)) {
      return new nodeCrypto.X509Certificate(value);
    }
    return new nodeCrypto.X509Certificate(String(value));
  } catch (e) {
    // Not a certificate this OpenSSL can read — a composite post-quantum one,
    // or bytes that are not a certificate at all. Answered as absent: the
    // caller reports a link it could not read rather than a verdict about it.
    log.debug('x509Of(): unreadable: ' + e.message);
    return null;
  }
}

// Did `issuer` sign `cert`? Name AND signature, because two authorities this
// service built carry the same subject and only the key tells them apart.
function signedBy(cert, issuer) {
  if (!cert || !issuer || cert.issuer !== issuer.subject) {
    return false;
  }
  try {
    return cert.checkIssued(issuer) && cert.verify(issuer.publicKey);
  } catch (e) {
    // `verify()` throws for a key of the wrong type rather than answering
    // false. That is an ordinary "not this issuer", not an error.
    return false;
  }
}

function selfSigned(cert) {
  return !!cert && cert.subject === cert.issuer && signedBy(cert, cert);
}

// ---------------------------------------------------------------------------
// EVERY AUTHORITY THIS PROCESS HOLDS.
//
// **READ OFF THE KEYSTORE AND NOT THROUGH `pki.rawRowFor()`**, because that
// accessor reads an empty scope id as "the ambient realm" — so asked for the
// DEFAULT realm's row from inside `acme` it answers acme's. A walk over every
// held row has no ambient realm to be confused by.
//
// The parsed certificates are memoised by PEM. It is a parse cache and nothing
// else: a tier that is replaced has a different PEM and a fresh entry, and the
// bound only decides how often a parse is repeated.
// ---------------------------------------------------------------------------
const parsed = new Map();
const PARSE_MEMO_ENTRIES = 256;

function parsedTier(pem) {
  const key = String(pem || '');
  if (!key) {
    return null;
  }
  if (parsed.has(key)) {
    return parsed.get(key);
  }
  const cert = x509Of(key);
  if (parsed.size >= PARSE_MEMO_ENTRIES) {
    parsed.clear();
  }
  parsed.set(key, cert);
  return cert;
}

function heldAuthorities() {
  log.debug('Entering heldAuthorities().');
  const out = [];
  const rows = typeof keystore.pkiAll === 'function' ? keystore.pkiAll() : [];
  (rows || []).forEach(function (one) {
    const scope = String(one && one.realm !== undefined ? one.realm : '');
    const row = (one && one.chain) || {};
    if (scope === pki.SERVICE_SCOPE) {
      if (row.root) {
        out.push({ scope: scope, ca: 'root', tier: row.root });
      }
      return;
    }
    if (row.intermediate) {
      out.push({ scope: scope, ca: 'intermediate', tier: row.intermediate });
    }
    Object.keys(row.issuing || {}).forEach(function (useCaseId) {
      out.push({ scope: scope, ca: useCaseId, tier: row.issuing[useCaseId] });
    });
  });
  log.debug('Leaving heldAuthorities(). ' + out.length + ' held.');
  return out;
}

// The authority this service holds that signed `cert`, or null.
function localIssuerOf(cert) {
  const held = heldAuthorities();
  for (let i = 0; i < held.length; i++) {
    const tierCert = parsedTier(held[i].tier && held[i].tier.certificatePem);
    if (tierCert && signedBy(cert, tierCert)) {
      return { scope: held[i].scope, ca: held[i].ca, tier: held[i].tier,
               cert: tierCert };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// THE IDENTIFIERS THIS FILE READS, AND THE BIT POSITIONS INSIDE TWO OF THEM.
//
// A reason MASK is RFC 5280's ReasonFlags read as an integer with bit N set for
// reason N — keyCompromise is 1, aACompromise is 8, bit 0 (`unused`) is never
// set — so "every reason" is 0x1FE and section 6.3.3's reasons_mask, which
// accumulates what several lists cover between them, is an OR.
// ---------------------------------------------------------------------------
const OID = {
  CRL_DISTRIBUTION_POINTS: '2.5.29.31',
  FRESHEST_CRL: '2.5.29.46',
  AUTHORITY_INFO_ACCESS: '1.3.6.1.5.5.7.1.1',
  AD_OCSP: '1.3.6.1.5.5.7.48.1',
  CRL_NUMBER: '2.5.29.20',
  DELTA_CRL_INDICATOR: '2.5.29.27',
  ISSUING_DISTRIBUTION_POINT: '2.5.29.28',
  CERTIFICATE_ISSUER: '2.5.29.29',
  KEY_USAGE: '2.5.29.15',
  EXT_KEY_USAGE: '2.5.29.37',
  BASIC_CONSTRAINTS: '2.5.29.19',
  KP_OCSP_SIGNING: '1.3.6.1.5.5.7.3.9',
  OCSP_BASIC: '1.3.6.1.5.5.7.48.1.1',
  OCSP_NONCE: '1.3.6.1.5.5.7.48.1.2',
  OCSP_NOCHECK: '1.3.6.1.5.5.7.48.1.5',
  AD_CA_ISSUERS: '1.3.6.1.5.5.7.48.2',
  SHA1: '1.3.14.3.2.26'
};
const ALL_REASONS = 0x1FE;
const REASON_CERTIFICATE_HOLD = 6;
const REASON_REMOVE_FROM_CRL = 8;
const KEY_USAGE_CRL_SIGN = 6;
// The CertID digests a response may be keyed by. This file ASKS with SHA-1 and
// matches an answer keyed by any of these, because a responder may re-key.
const CERT_ID_HASHES = {
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512'
};
const OCSP_RESPONSE_STATUS = { 1: 'malformedRequest', 2: 'internalError',
                               3: 'tryLater', 5: 'sigRequired', 6: 'unauthorized' };
const SHORT_NAMES = { '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU',
                      '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
                      '0.9.2342.19200300.100.1.25': 'DC',
                      '0.9.2342.19200300.100.1.1': 'UID' };

// `pki.revocationClockSkewS`, read directly: zero is legal and means the clocks
// agree exactly, which `Number(x || n)` would have made unreachable.
function skewMs() {
  const seconds = Number(config.value('pki.revocationClockSkewS'));
  return seconds > 0 ? seconds * 1000 : 0;
}

function ocspMaxAgeMs() {
  return Math.max(1, Number(config.value('pki.revocationOcspMaxAgeS'))) * 1000;
}

function ocspOrder() {
  const order = String(config.value('pki.revocationOcsp') || 'first');
  return ['first', 'after-crl', 'off'].indexOf(order) >= 0 ? order : 'first';
}

// ---------------------------------------------------------------------------
// DER AND NAME READERS.
//
// **THREE EXTENSIONS ARE READ OUT OF THEIR RAW DER RATHER THAN THROUGH pkijs**,
// and it is not a preference: pkijs parses an IssuingDistributionPoint's
// `onlySomeReasons` into a NUMBER that is not the bit string (a list covering
// keyCompromise and superseded came back as 3), and hands a distribution
// point's `reasons` over with the unused-bits octet still in front. A reason
// mask read wrongly is a list believed to cover reasons it does not, which is
// a certificate reported good by a list that was never about it.
//
// **A NAME IS COMPARED AS ITS ATTRIBUTES, NOT AS ITS BYTES.** The same issuer is
// written as a PrintableString by one encoder and a UTF8String by another, and
// the CRL, the certificateIssuer entry and the cRLIssuer each come from a
// different one. Order is kept — a DN is an ordered sequence.
// ---------------------------------------------------------------------------
function derParse(bytes) {
  const parsed = asn1js.fromBER(arrayBufferOf(Buffer.from(bytes)));
  if (parsed.offset === -1) {
    throw new Error('not DER: ' + parsed.result.error);
  }
  return parsed.result;
}

function contextTagOf(element) {
  return element && element.idBlock && element.idBlock.tagClass === 3
    ? element.idBlock.tagNumber : -1;
}

function childrenOf(element) {
  return element && element.valueBlock && Array.isArray(element.valueBlock.value)
    ? element.valueBlock.value : [];
}

function booleanOf(element) {
  const view = element && element.valueBlock && element.valueBlock.valueHexView;
  return !!(view && view.length && view[0] !== 0);
}

function generalNamesOf(element) {
  return childrenOf(element).map(function (one) {
    return new pkijs.GeneralName({ schema: one });
  });
}

// A reason mask from the CONTENT octets of an implicitly tagged BIT STRING —
// the unused-bits count first, then the bits, MSB first.
function reasonMaskOf(content) {
  const bits = Buffer.from(content).slice(1);
  let mask = 0;
  for (let reason = 1; reason <= 8; reason++) {
    if (((bits[reason >> 3] || 0) >> (7 - (reason & 7))) & 1) {
      mask |= (1 << reason);
    }
  }
  return mask;
}

function nameKey(rdn) {
  if (!rdn || !Array.isArray(rdn.typesAndValues)) {
    return '';
  }
  return rdn.typesAndValues.map(function (one) {
    const value = one.value && one.value.valueBlock ? one.value.valueBlock.value : '';
    return one.type + '=' + String(value === undefined ? '' : value).trim()
      .replace(/\s+/g, ' ').toLowerCase();
  }).join(',');
}

function describeName(rdn) {
  if (!rdn || !Array.isArray(rdn.typesAndValues)) {
    return '(an unreadable name)';
  }
  return rdn.typesAndValues.map(function (one) {
    const value = one.value && one.value.valueBlock ? one.value.valueBlock.value : '';
    return (SHORT_NAMES[one.type] || one.type) + '=' + String(value);
  }).join(', ');
}

// The DER of a Name exactly as it was received, which is what a CertID hashes.
function nameDerOf(rdn) {
  if (rdn.valueBeforeDecode && rdn.valueBeforeDecode.byteLength) {
    return Buffer.from(rdn.valueBeforeDecode);
  }
  return Buffer.from(rdn.toSchema().toBER(false));
}

function generalNameKey(name) {
  if (name.type === 6) {
    return 'uri:' + String(name.value || '');
  }
  if (name.type === 4) {
    return 'dn:' + nameKey(name.value);
  }
  return 'type' + name.type;
}

function pkijsOf(cert) {
  if (!cert || !cert.raw) {
    return null;
  }
  try {
    return pkijs.Certificate.fromBER(arrayBufferOf(cert.raw));
  } catch (e) {
    // A certificate OpenSSL read and pkijs could not. Answered as absent, and
    // every caller reports what it therefore could not look at.
    log.debug('pkijsOf(): pkijs could not parse it: ' + e.message);
    return null;
  }
}

function extensionOf(parsedCert, oid) {
  return ((parsedCert && parsedCert.extensions) || []).filter(function (ext) {
    return ext.extnID === oid;
  })[0] || null;
}

function isCaCertificate(parsedCert) {
  const ext = extensionOf(parsedCert, OID.BASIC_CONSTRAINTS);
  return !!(ext && ext.parsedValue && ext.parsedValue.cA);
}

// RFC 5280 section 4.2.1.3: a certificate with no keyUsage is unrestricted.
function keyUsageAllows(parsedCert, bit) {
  const ext = extensionOf(parsedCert, OID.KEY_USAGE);
  if (!ext || !ext.parsedValue || !ext.parsedValue.valueBlock) {
    return true;
  }
  const bytes = Buffer.from(ext.parsedValue.valueBlock.valueHexView);
  return !!(((bytes[bit >> 3] || 0) >> (7 - (bit & 7))) & 1);
}

function hasExtendedKeyUsage(parsedCert, oid) {
  const ext = extensionOf(parsedCert, OID.EXT_KEY_USAGE);
  return !!(ext && ext.parsedValue && Array.isArray(ext.parsedValue.keyPurposes) &&
            ext.parsedValue.keyPurposes.indexOf(oid) >= 0);
}

function validAt(cert, now) {
  const skew = skewMs();
  return !(Date.parse(cert.validFrom) - skew > now) &&
         !(Date.parse(cert.validTo) + skew < now);
}

function integerExtensionOf(ext) {
  if (!ext) {
    return null;
  }
  const integer = derParse(ext.extnValue.valueBlock.valueHexView);
  const hex = Buffer.from(integer.valueBlock.valueHexView).toString('hex');
  return BigInt('0x' + (hex || '0'));
}

// ---------------------------------------------------------------------------
// THE DISTRIBUTION POINTS A CERTIFICATE NAMES — or a CRL names, in freshestCRL.
//
// One entry per DistributionPoint, because RFC 5280 section 6.3.3 is a loop
// over POINTS and not over URLs: each point carries the reasons it covers and,
// where the list is indirect, the name of whoever issues it. `fetchable` is
// every http and https URI across them; `other` is every other URI, kept so a
// verdict can say what was there and why it was not dialled.
// ---------------------------------------------------------------------------
function pointNameOf(wrapper) {
  const inner = childrenOf(wrapper)[0];
  if (contextTagOf(inner) === 0) {
    return { names: generalNamesOf(inner), relative: false, rdn: null };
  }
  return { names: [], relative: contextTagOf(inner) === 1,
           rdn: contextTagOf(inner) === 1 ? inner : null };
}

// ---------------------------------------------------------------------------
// A NAME RELATIVE TO ITS CRL ISSUER, made whole (RFC 5280 section 4.2.1.13):
// the issuer's DN with the relative RDN appended as its most specific part.
//
// **IT IS REFUSED WHEREVER THE RESULT COULD BE READ TWO WAYS.** pkijs flattens a
// Name into one list of attribute values and forgets which of them shared an
// RDN, so a multi-valued RDN — in the issuer's name or in the relative part —
// cannot be written back as the one DN it was; and a value that is not a string
// cannot be written in RFC 4514 at all. Anything else is one DN, and the
// comparison key is the same one every other name here is compared by.
// ---------------------------------------------------------------------------
function escapeDnValue(value) {
  let out = String(value).replace(/[\\,+"<>;=]/g, function (c) { return '\\' + c; })
    .replace(/\u0000/g, '\\00');
  if (/^[ #]/.test(out)) {
    out = '\\' + out;
  }
  if (/ $/.test(out)) {
    out = out.slice(0, -1) + '\\ ';
  }
  return out;
}

function wholeNameOf(issuerName, rdnElement) {
  log.debug('Entering wholeNameOf().');
  let issuerSets;
  let atvs;
  try {
    issuerSets = childrenOf(derParse(nameDerOf(issuerName)));
    atvs = childrenOf(rdnElement).map(function (one) {
      return new pkijs.AttributeTypeAndValue({ schema: one });
    });
  } catch (e) {
    log.debug('Leaving wholeNameOf(). Unreadable: ' + e.message);
    return { ok: false, why: 'its relative name could not be read: ' + e.message };
  }
  if (atvs.length !== 1 || issuerSets.some(function (set) {
    return childrenOf(set).length !== 1;
  })) {
    log.debug('Leaving wholeNameOf(). Multi-valued.');
    return { ok: false,
             why: 'its name relative to the CRL issuer involves a multi-valued RDN, ' +
                  'which cannot be written back as one unambiguous DN' };
  }
  const all = issuerName.typesAndValues.concat(atvs);
  const plain = all.every(function (one) {
    return one.value && one.value.valueBlock && typeof one.value.valueBlock.value === 'string';
  });
  if (!plain) {
    log.debug('Leaving wholeNameOf(). A value that is not a string.');
    return { ok: false, why: 'its name relative to the CRL issuer carries a value that ' +
                             'is not a string, which has no RFC 4514 spelling' };
  }
  const whole = new pkijs.RelativeDistinguishedNames({ typesAndValues: all });
  const dn = all.slice().reverse().map(function (one) {
    return (SHORT_NAMES[one.type] || one.type) + '=' + escapeDnValue(one.value.valueBlock.value);
  }).join(',');
  log.debug('Leaving wholeNameOf(). ' + dn);
  return { ok: true, name: whole, key: 'dn:' + nameKey(whole), dn: dn };
}

// ---------------------------------------------------------------------------
// WHICH ADDRESSES ARE DIALLED. http and https always; ldaps unless
// `pki.revocationLdap` is `off`; plain ldap only when it says `ldaps-and-ldap`;
// nothing else, ever. An address not dialled is REPORTED with the reason, which
// is a fact about the issuer's choice and this service's policy rather than a
// failure to check.
// ---------------------------------------------------------------------------
function ldapPolicy() {
  const value = String(config.value('pki.revocationLdap') || 'ldaps');
  return ['ldaps', 'ldaps-and-ldap', 'off'].indexOf(value) >= 0 ? value : 'ldaps';
}

function dialability(uri) {
  const text = String(uri || '');
  if (/^https?:\/\//i.test(text)) {
    return { dial: true };
  }
  if (!/^ldaps?:\/\//i.test(text)) {
    return { dial: false, why: 'only http, https and ldap addresses are dialled' };
  }
  const parsed = parseLdapUrl(text);
  if (!parsed.ok) {
    return { dial: false, why: parsed.why };
  }
  const allowed = ldapPolicy();
  if (allowed === 'off') {
    return { dial: false, why: 'pki.revocationLdap is off' };
  }
  if (parsed.scheme === 'ldap' && allowed !== 'ldaps-and-ldap') {
    return { dial: false, why: 'plain ldap is not dialled unless pki.revocationLdap is ' +
                               'ldaps-and-ldap' };
  }
  return { dial: true };
}

function readPoint(pointElement) {
  log.debug('Entering readPoint().');
  const point = { urls: [], other: [], keys: [], reasons: ALL_REASONS,
                  relative: false, relativeRdn: null, crlIssuer: null,
                  crlIssuerNamed: false };
  childrenOf(pointElement).forEach(function (field) {
    const tag = contextTagOf(field);
    try {
      if (tag === 0) {
        const name = pointNameOf(field);
        point.relative = name.relative;
        point.relativeRdn = name.rdn;
        name.names.forEach(function (one) {
          point.keys.push(generalNameKey(one));
          const uri = one.type === 6 ? String(one.value || '') : '';
          const verdict = uri ? dialability(uri) : null;
          if (verdict && verdict.dial) {
            point.urls.push(uri);
          } else if (uri) {
            point.other.push(uri + ' (' + verdict.why + ')');
          }
        });
      } else if (tag === 1) {
        point.reasons = reasonMaskOf(field.valueBlock.valueHexView);
      } else if (tag === 2) {
        point.crlIssuerNamed = true;
        const dn = generalNamesOf(field).filter(function (one) {
          return one.type === 4;
        })[0];
        point.crlIssuer = dn ? dn.value : null;
      }
    } catch (e) {
      // A field this file could not read. The point keeps what WAS read, and a
      // point naming a CRL issuer nobody could read is refused where it is
      // resolved, rather than guessed at here.
      log.debug('readPoint(): field [' + tag + '] unreadable: ' + e.message);
    }
  });
  log.debug('Leaving readPoint(). ' + point.urls.length + ' fetchable.');
  return point;
}

function pointsOfExtension(ext) {
  log.debug('Entering pointsOfExtension().');
  const out = { points: [], fetchable: [], other: [], indirect: 0 };
  if (!ext) {
    log.debug('Leaving pointsOfExtension(). None.');
    return out;
  }
  let sequence;
  try {
    sequence = derParse(ext.extnValue.valueBlock.valueHexView);
  } catch (e) {
    // An extension that is not DER names no point this file can see, which
    // the caller reports as "names none".
    log.debug('Leaving pointsOfExtension(). Unreadable: ' + e.message);
    return out;
  }
  childrenOf(sequence).forEach(function (pointElement) {
    const point = readPoint(pointElement);
    if (point.crlIssuerNamed) {
      out.indirect += 1;
    }
    out.fetchable = out.fetchable.concat(point.urls);
    out.other = out.other.concat(point.other);
    out.points.push(point);
  });
  log.debug('Leaving pointsOfExtension(). ' + out.points.length + ' point(s).');
  return out;
}

function distributionPointsOf(cert, extensionOid) {
  return pointsOfExtension(extensionOf(pkijsOf(cert),
                                       extensionOid || OID.CRL_DISTRIBUTION_POINTS));
}

function ocspRespondersOf(cert) {
  const out = { fetchable: [], other: [] };
  const ext = extensionOf(pkijsOf(cert), OID.AUTHORITY_INFO_ACCESS);
  ((ext && ext.parsedValue && ext.parsedValue.accessDescriptions) || [])
    .forEach(function (one) {
      if (one.accessMethod !== OID.AD_OCSP || !one.accessLocation ||
          one.accessLocation.type !== 6) {
        return;
      }
      const uri = String(one.accessLocation.value || '');
      if (/^https?:\/\//i.test(uri)) {
        out.fetchable.push(uri);
      } else if (uri) {
        out.other.push(uri);
      }
    });
  return out;
}

// ---------------------------------------------------------------------------
// CERTIFICATES THAT MAY SIGN AN INDIRECT CRL, from `pki.revocationCrlIssuersFile`.
//
// Read again when the file's mtime moves. It is the operator's half of the
// answer; the list's own caIssuers address is the issuer's, and both are held
// to the same authorisation before either is believed.
// ---------------------------------------------------------------------------
function configuredCrlIssuers() {
  return pemFileOf('pki.revocationCrlIssuersFile').certs;
}

// ---------------------------------------------------------------------------
// THE CACHES.
//
// A parsed list is cached under the URL AND the fingerprints of the signers it
// was verified against, because a second issuer naming the same URL must verify
// it again. It expires at the earlier of its own `nextUpdate` and
// `pki.revocationCrlMaxAgeS` after it was fetched. An OCSP answer is cached
// under the URL, the issuer and the SERIAL — it is an answer about one
// certificate — until the earlier of its nextUpdate and
// `pki.revocationOcspMaxAgeS`. Insertion order is the eviction order, and the
// failure memory and the in-flight dedupe serve both.
// ---------------------------------------------------------------------------
const crlCache = new Map();
const ocspCache = new Map();
const failures = new Map();
const inFlight = new Map();

function cacheLimit() {
  return Math.max(1, Number(config.value('pki.revocationCrlCacheEntries')));
}

function remember(cache, key, entry) {
  cache.delete(key);
  cache.set(key, entry);
  while (cache.size > cacheLimit()) {
    cache.delete(cache.keys().next().value);
  }
}

function cached(cache, key) {
  const entry = cache.get(key);
  if (!entry) {
    return null;
  }
  if (entry.expiresAt <= Date.now()) {
    cache.delete(key);
    return null;
  }
  return entry;
}

function failedRecently(url) {
  const failed = failures.get(url);
  if (!failed) {
    return null;
  }
  if (failed.until <= Date.now()) {
    failures.delete(url);
    return null;
  }
  return failed;
}

function rememberFailure(url, why, kind) {
  log.debug('Entering rememberFailure().');
  // `pki.revocationFailureRetryS` read directly: zero is legal and means "try
  // again on the next request", which `Number(x || n)` would have made
  // unreachable.
  const seconds = Number(config.value('pki.revocationFailureRetryS'));
  if (!(seconds > 0)) {
    log.debug('Leaving rememberFailure(). Not remembered (retry window is zero).');
    return;
  }
  failures.set(url, { until: Date.now() + seconds * 1000, why: why, kind: kind });
  while (failures.size > cacheLimit()) {
    failures.delete(failures.keys().next().value);
  }
  log.debug('Leaving rememberFailure(). Remembered for ' + seconds + 's.');
}

// One piece of work per key at a time: a concurrent caller waits on the same
// promise rather than dialling again.
async function once(key, work) {
  if (inFlight.has(key)) {
    return inFlight.get(key);
  }
  const running = work();
  inFlight.set(key, running);
  try {
    return await running;
  } finally {
    inFlight.delete(key);
  }
}

// ---------------------------------------------------------------------------
// THE FETCH. Resolves { ok, der, why } and NEVER rejects — a rejected promise
// here would have to be caught at every door, and the next door would not. A
// CRL is a GET; an OCSP request is a POST of the DER request (RFC 6960 appendix
// A.1), which needs no URL encoding and has no length limit a GET would.
// ---------------------------------------------------------------------------
function fetchBytes(url, options) {
  log.debug('Entering fetchBytes(). url=' + url);
  const opts = options || {};
  let target;
  try {
    target = new URL(url);
  } catch (e) {
    log.debug('Leaving fetchBytes(). Not a URL.');
    return Promise.resolve({ ok: false, why: '"' + url + '" is not a URL' });
  }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    log.debug('Leaving fetchBytes(). Wrong scheme.');
    return Promise.resolve({ ok: false,
                             why: 'only http and https addresses are dialled, ' +
                                  'and this is ' + target.protocol });
  }
  const secure = target.protocol === 'https:';
  const cap = Math.max(1, Number(config.value('pki.revocationMaxCrlBytes')));
  const timeout = Math.max(1, Number(config.value('pki.revocationFetchTimeoutMs')));
  const headers = { 'Accept': opts.accept || 'application/pkix-crl, application/octet-stream, */*',
                    'User-Agent': opts.userAgent || USER_AGENT };
  if (opts.body) {
    headers['Content-Type'] = opts.contentType;
    headers['Content-Length'] = String(opts.body.length);
  }
  log.debug('Leaving fetchBytes(). Dialling.');
  return new Promise(function (resolve) {
    let settled = false;
    const done = function (result) {
      if (settled) {
        return;
      }
      settled = true;
      resolve(result);
    };
    let request;
    try {
      request = (secure ? https : http).request({
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (secure ? 443 : 80),
        path: target.pathname + target.search,
        method: opts.body ? 'POST' : 'GET',
        headers: headers,
        // See the header, point 4: the document's own signature is the check.
        rejectUnauthorized: false,
        agent: false
      }, function (response) {
        const status = response.statusCode || 0;
        if (status >= 300 && status < 400) {
          response.destroy();
          return done({ ok: false,
                        why: 'it answered ' + status + ' redirecting to "' +
                             String(response.headers.location || '') +
                             '", and a redirect is not followed — the address ' +
                             'a certificate names is the only one its issuer ' +
                             'signed' });
        }
        if (status < 200 || status >= 300) {
          response.destroy();
          return done({ ok: false, why: 'it answered HTTP ' + status });
        }
        const chunks = [];
        let bytes = 0;
        response.on('data', function (chunk) {
          bytes += chunk.length;
          if (bytes > cap) {
            response.destroy();
            done({ ok: false,
                   why: 'it answered with more than ' + cap + ' bytes ' +
                        '(pki.revocationMaxCrlBytes)' });
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', function () {
          done({ ok: true, der: Buffer.concat(chunks) });
        });
        response.on('error', function (e) {
          done({ ok: false, why: 'the response failed: ' + e.message });
        });
      });
    } catch (e) {
      return done({ ok: false, why: 'the request could not be built: ' + e.message });
    }
    request.setTimeout(timeout, function () {
      request.destroy();
      done({ ok: false,
             why: 'it did not answer within ' + timeout + 'ms ' +
                  '(pki.revocationFetchTimeoutMs)' });
    });
    request.on('error', function (e) {
      done({ ok: false, why: 'the request failed: ' +
                             (e.code ? e.code + ' — ' : '') + e.message });
    });
    request.end(opts.body || undefined);
  });
}

// ---------------------------------------------------------------------------
// LDAP: THE SECOND OUTBOUND PROTOCOL, ARGUED ON ITS OWN RATHER THAN AS "ANOTHER
// FETCH" (see the module header). What is written here:
//
//   * **AN RFC 4516 URL, READ STRICTLY.** A host is required (`ldap:///…` means
//     "the directory this client already uses", and this service has none it
//     could mean); the scope must be `base`, so exactly one entry is named; a
//     CRITICAL extension (`!name`) is refused as RFC 4516 section 2.1 requires,
//     which also refuses `!bindname` — this service binds as nobody.
//   * **ONLY THE ATTRIBUTES A LIST OR A CERTIFICATE IS KEPT IN.** A URL naming
//     some other attribute is refused rather than read; one naming none gets the
//     standard ones — `certificateRevocationList;binary` (and
//     `authorityRevocationList;binary` for a CA certificate), and
//     `cACertificate;binary` for a caIssuers address.
//   * **THE SAME LIMITS AS THE HTTP FETCH**: one deadline for the whole
//     exchange, `pki.revocationFetchTimeoutMs`; the connection's bytes counted
//     against `pki.revocationMaxCrlBytes` as they arrive, and the socket
//     destroyed at the cap; one entry; no referral or search reference followed;
//     an anonymous search and nothing else; a fresh client per fetch, destroyed
//     afterwards, never reconnecting.
//   * **ldaps VERIFIES THE DIRECTORY, AND THAT IS WHY IT IS THE DEFAULT.** An
//     http fetch hands this service a byte stream it parses itself under a cap,
//     and the list's signature is the whole of the trust. An LDAP session is a
//     protocol a library speaks on its behalf — results, referrals, search
//     references, extended responses — so whoever answers on that port reaches
//     far more code than a DER parser. TLS against node's CA store and
//     `pki.revocationLdapCaFile` bounds WHO may speak it. Plain ldap removes that
//     bound, and `pki.revocationLdap=ldaps-and-ldap` is an operator saying their
//     directory's network is theirs.
// ---------------------------------------------------------------------------
const LDAP_CRL_ATTRIBUTES = ['certificaterevocationlist', 'authorityrevocationlist',
                             'deltarevocationlist'];
const LDAP_CERTIFICATE_ATTRIBUTES = ['cacertificate'];

function parseLdapUrl(text) {
  log.debug('Entering parseLdapUrl().');
  const match = /^(ldaps?):\/\/([^/?]*)(?:\/([^?]*)(?:\?([^?]*)(?:\?([^?]*)(?:\?([^?]*)(?:\?(.*))?)?)?)?)?$/i
    .exec(String(text || ''));
  if (!match) {
    log.debug('Leaving parseLdapUrl(). Not an LDAP URL.');
    return { ok: false, why: 'it is not an RFC 4516 LDAP URL' };
  }
  const scheme = match[1].toLowerCase();
  if (!match[2]) {
    log.debug('Leaving parseLdapUrl(). No host.');
    return { ok: false, why: 'it names no host — an ldap:/// address means "the directory ' +
                             'this client already uses", and this service has none it could mean' };
  }
  const hostPort = /^(?:\[([^\]]+)\]|([^:]+))(?::(\d+))?$/.exec(match[2]);
  if (!hostPort) {
    log.debug('Leaving parseLdapUrl(). Bad host.');
    return { ok: false, why: 'its host "' + match[2] + '" cannot be read' };
  }
  let dn;
  let attributes;
  let scope;
  let filter;
  let extensions;
  try {
    dn = decodeURIComponent(match[3] || '');
    attributes = (match[4] || '').split(',').map(function (one) {
      return decodeURIComponent(one).trim();
    }).filter(function (one) { return !!one; });
    scope = decodeURIComponent(match[5] || '').toLowerCase();
    filter = decodeURIComponent(match[6] || '');
    extensions = (match[7] || '').split(',').map(function (one) {
      return decodeURIComponent(one).trim();
    }).filter(function (one) { return !!one; });
  } catch (e) {
    log.debug('Leaving parseLdapUrl(). Bad percent-encoding.');
    return { ok: false, why: 'it is not percent-encoded correctly: ' + e.message };
  }
  if (scope && scope !== 'base') {
    log.debug('Leaving parseLdapUrl(). Scope ' + scope + '.');
    return { ok: false, why: 'its scope is "' + scope + '", and only a base-object search ' +
                             'names exactly one entry' };
  }
  const critical = extensions.filter(function (one) { return one.charAt(0) === '!'; })[0];
  if (critical) {
    log.debug('Leaving parseLdapUrl(). A critical extension.');
    return { ok: false, why: 'it carries a critical extension (' + critical + ') this ' +
                             'service does not implement (RFC 4516 section 2.1)' };
  }
  log.debug('Leaving parseLdapUrl(). ' + scheme + '://' + match[2]);
  return { ok: true, scheme: scheme, host: hostPort[1] || hostPort[2],
           port: Number(hostPort[3] || (scheme === 'ldaps' ? 636 : 389)), dn: dn,
           attributes: attributes, filter: filter || '(objectClass=*)' };
}

// PEM certificates in a file named by a setting, memoised on the path and mtime.
const pemFiles = new Map();

function pemFileOf(settingKey) {
  log.debug('Entering pemFileOf(). ' + settingKey);
  const file = String(config.value(settingKey) || '');
  if (!file) {
    log.debug('Leaving pemFileOf(). None configured.');
    return { pems: [], certs: [] };
  }
  let stat;
  let text;
  try {
    stat = fs.statSync(file);
    const held = pemFiles.get(settingKey);
    if (held && held.file === file && held.mtimeMs === stat.mtimeMs) {
      log.debug('Leaving pemFileOf(). Unchanged.');
      return held;
    }
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    if (settingKey === 'pki.revocationLdapCaFile') {
      log.warn(errorCodes.tag('STS-PKI-0128') + 'revocation: ' + settingKey + ' "' + file +
               '" could not be read: ' + e.message + '. Nothing is taken from it.');
    } else {
      log.warn(errorCodes.tag('STS-PKI-0125') + 'revocation: ' + settingKey + ' "' + file +
               '" could not be read: ' + e.message + '. Nothing is taken from it.');
    }
    log.debug('Leaving pemFileOf(). Unreadable.');
    return { pems: [], certs: [] };
  }
  const pems = text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  const entry = { file: file, mtimeMs: stat.mtimeMs, pems: pems,
                  certs: pems.map(x509Of).filter(function (one) { return !!one; }) };
  pemFiles.set(settingKey, entry);
  log.debug('Leaving pemFileOf(). ' + entry.certs.length + ' certificate(s).');
  return entry;
}

function attributeBaseOf(name) {
  return String(name || '').split(';')[0].trim().toLowerCase();
}

// Resolves { ok, values: [Buffer], why } and never rejects.
function fetchLdap(url, want) {
  log.debug('Entering fetchLdap(). url=' + url);
  const parsed = parseLdapUrl(url);
  const dial = dialability(url);
  if (!parsed.ok || !dial.dial) {
    log.warn(errorCodes.tag('STS-PKI-0128') + 'revocation: ' + url + ' is not dialled: ' +
             (parsed.why || dial.why) + '.');
    log.debug('Leaving fetchLdap(). Not dialled.');
    return Promise.resolve({ ok: false, why: parsed.why || dial.why });
  }
  const requested = parsed.attributes.length ? parsed.attributes : want.defaults;
  const stray = requested.filter(function (one) {
    return want.allowed.indexOf(attributeBaseOf(one)) < 0;
  })[0];
  if (stray) {
    log.warn(errorCodes.tag('STS-PKI-0128') + 'revocation: ' + url + ' asks for "' + stray +
             '", which is not where ' + want.what + ' is kept.');
    log.debug('Leaving fetchLdap(). A stray attribute.');
    return Promise.resolve({ ok: false, why: 'it asks for "' + stray + '", which is not an ' +
                                             'attribute ' + want.what + ' is kept in' });
  }
  const cap = Math.max(1, Number(config.value('pki.revocationMaxCrlBytes')));
  const timeout = Math.max(1, Number(config.value('pki.revocationFetchTimeoutMs')));
  log.debug('Leaving fetchLdap(). Dialling.');
  return new Promise(function (resolve) {
    let settled = false;
    let client = null;
    const done = function (result) {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(deadline);
      if (client) {
        try {
          client.destroy();
        } catch (e) {
          // A client already torn down by the failure being reported. There is
          // nothing left to close, and the result is what matters.
          log.debug('fetchLdap(): destroy threw: ' + e.message);
        }
      }
      if (!result.ok && result.protocol) {
        log.warn(errorCodes.tag('STS-PKI-0128') + 'revocation: the directory at ' + url +
                 ' did not answer usably: ' + result.why + '.');
      }
      resolve(result);
    };
    const deadline = setTimeout(function () {
      done({ ok: false, why: 'it did not answer within ' + timeout + 'ms ' +
                             '(pki.revocationFetchTimeoutMs)' });
    }, timeout);
    const tlsOptions = { rejectUnauthorized: true,
                         ca: tls.rootCertificates.concat(pemFileOf('pki.revocationLdapCaFile').pems) };
    if (!net.isIP(parsed.host)) {
      tlsOptions.servername = parsed.host;
    }
    try {
      const ldap = require('ldapjs');
      client = ldap.createClient({
        url: parsed.scheme + '://' + (net.isIPv6(parsed.host) ? '[' + parsed.host + ']' : parsed.host) +
             ':' + parsed.port,
        timeout: timeout, connectTimeout: timeout, reconnect: false,
        tlsOptions: parsed.scheme === 'ldaps' ? tlsOptions : undefined
      });
    } catch (e) {
      return done({ ok: false, why: 'the client could not be built: ' + e.message });
    }
    client.on('error', function (e) {
      done({ ok: false, why: 'the connection failed: ' + (e.code ? e.code + ' — ' : '') + e.message });
    });
    client.on('connectError', function (e) {
      done({ ok: false, why: 'the connection failed: ' + (e.code ? e.code + ' — ' : '') + e.message });
    });
    client.on('connect', function (socket) {
      let bytes = 0;
      socket.on('data', function (chunk) {
        bytes += chunk.length;
        if (bytes > cap) {
          socket.destroy();
          done({ ok: false, why: 'it answered with more than ' + cap + ' bytes ' +
                                 '(pki.revocationMaxCrlBytes)' });
        }
      });
    });
    client.search(parsed.dn, { scope: 'base', filter: parsed.filter, attributes: requested,
                               sizeLimit: 1, timeLimit: Math.max(1, Math.ceil(timeout / 1000)) },
      function (err, res) {
        if (err) {
          return done({ ok: false, why: 'the search could not be sent: ' + err.message });
        }
        const entries = [];
        res.on('searchEntry', function (entry) {
          entries.push(entry);
        });
        res.on('searchReference', function (reference) {
          done({ ok: false, protocol: true,
                 why: 'it answered with a referral to ' + ((reference && reference.uris) || []).join(', ') +
                      ', and a referral is not followed — the address the issuer signed is ' +
                      'the only one' });
        });
        res.on('error', function (e) {
          done({ ok: false, protocol: true, why: 'the search failed: ' + e.message });
        });
        res.on('end', function (result) {
          const status = result && typeof result.status === 'number' ? result.status : -1;
          if (status !== 0) {
            return done({ ok: false, protocol: true,
                          why: 'the directory answered result code ' + status +
                               (status === 10 ? ' (a referral, which is not followed)' : '') });
          }
          if (entries.length !== 1) {
            return done({ ok: false, protocol: true,
                          why: entries.length
                            ? 'it answered with ' + entries.length + ' entries where one was named'
                            : 'there is no entry at "' + parsed.dn + '"' });
          }
          const attributes = entries[0].attributes || [];
          for (let i = 0; i < requested.length; i++) {
            const found = attributes.filter(function (one) {
              return attributeBaseOf(one.type) === attributeBaseOf(requested[i]);
            })[0];
            if (found && (found.buffers || []).length) {
              return done({ ok: true, values: found.buffers.map(function (b) { return Buffer.from(b); }) });
            }
          }
          done({ ok: false, protocol: true,
                 why: 'the entry at "' + parsed.dn + '" carries none of ' + requested.join(', ') });
        });
      });
  });
}

// A list, from whichever kind of address names it. { ok, der, why }.
async function fetchCrlDocument(url, context) {
  if (!/^ldaps?:\/\//i.test(url)) {
    return fetchBytes(url);
  }
  const isCa = !!(context && context.target && context.target.isCa);
  const defaults = context && context.purpose === 'delta'
    ? ['deltaRevocationList;binary', 'certificateRevocationList;binary']
    : (isCa ? ['authorityRevocationList;binary', 'certificateRevocationList;binary']
            : ['certificateRevocationList;binary']);
  const got = await fetchLdap(url, { allowed: LDAP_CRL_ATTRIBUTES, defaults: defaults,
                                     what: 'a revocation list' });
  return got.ok ? { ok: true, der: got.values[0] } : got;
}

// ---------------------------------------------------------------------------
// CERTIFICATES PUBLISHED AT A caIssuers ADDRESS — a DER certificate, PEM, or a
// PKCS#7 certs-only bundle over http (RFC 5280 section 4.2.2.1), or
// `cACertificate;binary` values over LDAP. Cached per URL for
// `pki.revocationCrlMaxAgeS`, with the failure memory and the in-flight dedupe
// every other fetch here has. WHAT IS FETCHED IS NEVER TRUSTED FOR BEING
// FETCHED: every caller decides whether a certificate it got here may do what
// it is being asked to do, by signature and by chain.
// ---------------------------------------------------------------------------
const certCache = new Map();

function certificatesOfDocument(buffers) {
  log.debug('Entering certificatesOfDocument().');
  const out = [];
  buffers.forEach(function (buffer) {
    const text = buffer.slice(0, 64).toString('latin1');
    if (/-----BEGIN/.test(text)) {
      (buffer.toString('latin1').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [])
        .forEach(function (pem) { out.push(x509Of(pem)); });
      return;
    }
    const single = x509Of(buffer);
    if (single) {
      out.push(single);
      return;
    }
    try {
      const info = pkijs.ContentInfo.fromBER(arrayBufferOf(buffer));
      const signed = new pkijs.SignedData({ schema: info.content });
      (signed.certificates || []).forEach(function (one) {
        if (one instanceof pkijs.Certificate) {
          out.push(x509Of(Buffer.from(one.toSchema().toBER(false))));
        }
      });
    } catch (e) {
      // Neither a certificate nor a certs-only bundle. Nothing is taken from it,
      // and the caller reports an address that held no certificate.
      log.debug('certificatesOfDocument(): not PKCS#7 either: ' + e.message);
    }
  });
  const certs = out.filter(function (one) { return !!one; });
  log.debug('Leaving certificatesOfDocument(). ' + certs.length + ' certificate(s).');
  return certs;
}

async function certificatesFrom(url) {
  log.debug('Entering certificatesFrom(). url=' + url);
  const key = 'certificates|' + url;
  const hit = cached(certCache, key);
  if (hit) {
    log.debug('Leaving certificatesFrom(). Cached.');
    return { ok: true, certs: hit.certs };
  }
  const failed = failedRecently(key);
  if (failed) {
    log.debug('Leaving certificatesFrom(). Failed recently.');
    return { ok: false, why: failed.why + ' (remembered for pki.revocationFailureRetryS)' };
  }
  log.debug('Leaving certificatesFrom(). Fetching, or joining a fetch in flight.');
  return once(key, async function () {
    const fetched = /^ldaps?:\/\//i.test(url)
      ? await fetchLdap(url, { allowed: LDAP_CERTIFICATE_ATTRIBUTES,
                               defaults: ['cACertificate;binary'], what: 'a CA certificate' })
      : await fetchBytes(url, { accept: 'application/pkix-cert, application/pkcs7-mime, */*' });
    const certs = fetched.ok ? certificatesOfDocument(fetched.values || [fetched.der]) : [];
    if (!certs.length) {
      const why = fetched.ok ? 'what it answered holds no certificate' : fetched.why;
      log.warn(errorCodes.tag('STS-PKI-0126') + 'revocation: no certificate could be taken ' +
               'from the caIssuers address ' + url + ': ' + why + '.');
      rememberFailure(key, why, 'unreachable');
      return { ok: false, why: why };
    }
    const maxAge = Math.max(1, Number(config.value('pki.revocationCrlMaxAgeS')));
    remember(certCache, key, { url: url, certs: certs, expiresAt: Date.now() + maxAge * 1000 });
    return { ok: true, certs: certs };
  });
}

function caIssuersOf(extensions) {
  const ext = (extensions || []).filter(function (one) {
    return one.extnID === OID.AUTHORITY_INFO_ACCESS;
  })[0];
  return ((ext && ext.parsedValue && ext.parsedValue.accessDescriptions) || [])
    .filter(function (one) {
      return one.accessMethod === OID.AD_CA_ISSUERS && one.accessLocation &&
             one.accessLocation.type === 6 && dialability(one.accessLocation.value).dial;
    }).map(function (one) { return String(one.accessLocation.value); });
}

// ---------------------------------------------------------------------------
// A LIST'S SIGNER, FETCHED FROM THE LIST'S OWN caIssuers ADDRESS (RFC 5280
// section 5.2.7).
//
// **THE URL IS WRITTEN INSIDE THE DOCUMENT WHOSE SIGNER IS IN QUESTION, AND THAT
// IS WHY FETCHING IT IS SAFE RATHER THAN WHY IT IS NOT.** Whatever is fetched is
// believed only if it carries the name the list must be issued by, may sign
// CRLs, is valid now, CHAINS — through CA certificates in the presented chain,
// this service's authorities, the issuers file or the same address — to a
// certificate the target's own verified path passes through, and its key
// verifies the list. A list pointing at an impostor's certificate gets nothing
// the impostor could not already have had from anywhere else: an unrelated key
// that chains nowhere. It serves both the indirect case, where the certificate
// NAMED a separate CRL issuer, and the direct one, where the issuer signed its
// list with a different key than the one that signed the certificate — which
// RFC 5280 permits and which the presented chain cannot contain.
// ---------------------------------------------------------------------------
async function crlSignerFromCaIssuers(crl, context) {
  log.debug('Entering crlSignerFromCaIssuers().');
  const urls = caIssuersOf((crl.crlExtensions && crl.crlExtensions.extensions) || []);
  if (!urls.length) {
    log.debug('Leaving crlSignerFromCaIssuers(). No address.');
    return { why: 'the list names no caIssuers address to fetch its signer\'s certificate from' };
  }
  const wanted = nameKey(context.expectName);
  const problems = [];
  for (let i = 0; i < urls.length; i++) {
    const got = await certificatesFrom(urls[i]);
    if (!got.ok) {
      problems.push(urls[i] + ': ' + got.why);
      continue;
    }
    const seen = new Set();
    const pool = context.target.offered.concat(heldCertificates(), configuredCrlIssuers(), got.certs)
      .filter(function (one) {
        if (seen.has(one.fingerprint256)) {
          return false;
        }
        seen.add(one.fingerprint256);
        return true;
      });
    const named = got.certs.filter(function (one) {
      const parsed = pkijsOf(one);
      return !!parsed && nameKey(parsed.subject) === wanted;
    });
    const authorised = named.filter(function (one) {
      return crlSignerAuthorised(one, context.target, pool);
    });
    if (!authorised.length) {
      problems.push(urls[i] + ': ' + (named.length
        ? 'the certificate there for "' + describeName(context.expectName) + '" may not sign ' +
          'CRLs, is not valid now or does not chain to an authority the presented path passes ' +
          'through'
        : 'none of the ' + got.certs.length + ' certificate(s) there is for "' +
          describeName(context.expectName) + '"'));
      continue;
    }
    const signer = await crlSignerOf(crl, authorised);
    if (signer) {
      log.debug('Leaving crlSignerFromCaIssuers(). Signed by a certificate from ' + urls[i]);
      return { signer: signer, url: urls[i] };
    }
    problems.push(urls[i] + ': the certificate there does not verify the list\'s signature');
  }
  log.debug('Leaving crlSignerFromCaIssuers(). Nothing usable.');
  return { why: 'no certificate fetched from its caIssuers address could sign it — ' +
                problems.join('; ') };
}

// ---------------------------------------------------------------------------
// A NAME RELATIVE TO ITS CRL ISSUER, turned into an address. The DN is
// unambiguous (see `wholeNameOf()`); the directory is not in the certificate at
// all, so it is `pki.revocationLdapDirectory` or it is refused by name.
// ---------------------------------------------------------------------------
function relativeAddressOf(point, target) {
  log.debug('Entering relativeAddressOf().');
  const whole = wholeNameOf(point.crlIssuer || target.parsed.issuer, point.relativeRdn);
  if (!whole.ok) {
    log.debug('Leaving relativeAddressOf(). Not resolvable.');
    return { why: whole.why };
  }
  const directory = String(config.value('pki.revocationLdapDirectory') || '').replace(/\/+$/, '');
  if (!directory) {
    log.debug('Leaving relativeAddressOf(). No directory.');
    return { key: whole.key,
             why: 'it names its list relative to its CRL issuer, as "' + whole.dn + '", and ' +
                  'says nothing about which directory holds it — pki.revocationLdapDirectory ' +
                  'names none' };
  }
  if (!/^ldaps?:\/\/[^/?]+$/i.test(directory)) {
    log.debug('Leaving relativeAddressOf(). A malformed directory setting.');
    return { key: whole.key,
             why: 'pki.revocationLdapDirectory is not an ldap:// or ldaps:// address with a host ' +
                  'and nothing after it' };
  }
  const url = directory + '/' + encodeURIComponent(whole.dn);
  const dial = dialability(url);
  log.debug('Leaving relativeAddressOf(). ' + (dial.dial ? url : dial.why));
  return dial.dial ? { key: whole.key, url: url } : { key: whole.key, why: dial.why };
}

// ---------------------------------------------------------------------------
// A FETCHED LIST, READ AND VERIFIED, or a sentence saying why it cannot be used.
//
// The checks are RFC 5280 section 6.3.3's, in the order that makes a refusal
// most useful: it parses; it names the issuer it has to (the certificate's
// issuer, or the cRLIssuer the certificate names); one of the signers it may
// have been signed by did sign it, and that signer may sign CRLs; it carries no
// critical extension this file does not implement; it is not past its
// nextUpdate. What is true of the LIST — its number, whether it is a delta, its
// issuing distribution point, the freshestCRL it names — is read here once; what
// is true of a list FOR ONE CERTIFICATE (its scope) is decided per certificate,
// because a cached list serves many.
//
// **ENTRIES ARE KEYED BY ISSUER AND SERIAL**, and the issuer is RFC 5280 section
// 5.3.3's: the CRL issuer, until an entry carries a certificateIssuer, which
// then applies to it and to every entry after it until the next one. A serial is
// only unique per issuer, and an indirect list holds several.
// ---------------------------------------------------------------------------
const UNDERSTOOD_CRL_EXTENSIONS = ['2.5.29.20', '2.5.29.35', '2.5.29.18', '2.5.29.27',
                                   '2.5.29.28', '2.5.29.46', '1.3.6.1.5.5.7.1.1'];
const UNDERSTOOD_ENTRY_EXTENSIONS = ['2.5.29.21', '2.5.29.24', '2.5.29.29'];

function reasonNameOf(code) {
  const known = pkiRevocation.REASONS.filter(function (one) {
    return one.code === code;
  })[0];
  return known ? known.id : 'code ' + code;
}

function reasonOfEntry(entry) {
  log.debug('Entering reasonOfEntry().');
  const extensions = (entry.crlEntryExtensions &&
                      entry.crlEntryExtensions.extensions) || [];
  const found = extensions.filter(function (ext) {
    return ext.extnID === '2.5.29.21';
  })[0];
  if (!found) {
    log.debug('Leaving reasonOfEntry(). No reason code.');
    return { code: 0, id: 'unspecified' };
  }
  try {
    const decoded = asn1js.fromBER(found.extnValue.valueBlock.valueHexView);
    const code = decoded.result.valueBlock.valueDec;
    log.debug('Leaving reasonOfEntry(). code=' + code);
    return { code: code, id: reasonNameOf(code) };
  } catch (e) {
    // A reason this file cannot decode. The entry is still a revocation —
    // the reason is a detail and the serial is the fact.
    log.debug('Leaving reasonOfEntry(). Undecodable: ' + e.message);
    return { code: -1, id: 'undecodable' };
  }
}

function readIssuingDistributionPoint(ext) {
  log.debug('Entering readIssuingDistributionPoint().');
  const out = { present: false, keys: [], relative: false, onlyUser: false,
                onlyCa: false, onlyAttribute: false, reasons: ALL_REASONS,
                indirect: false, derHex: '' };
  if (!ext) {
    log.debug('Leaving readIssuingDistributionPoint(). Absent.');
    return out;
  }
  out.present = true;
  out.derHex = Buffer.from(ext.extnValue.valueBlock.valueHexView).toString('hex');
  childrenOf(derParse(ext.extnValue.valueBlock.valueHexView)).forEach(function (field) {
    const tag = contextTagOf(field);
    if (tag === 0) {
      const name = pointNameOf(field);
      out.relative = name.relative;
      out.relativeRdn = name.rdn;
      out.keys = name.names.map(generalNameKey);
    } else if (tag === 1) {
      out.onlyUser = booleanOf(field);
    } else if (tag === 2) {
      out.onlyCa = booleanOf(field);
    } else if (tag === 3) {
      out.reasons = reasonMaskOf(field.valueBlock.valueHexView);
    } else if (tag === 4) {
      out.indirect = booleanOf(field);
    } else if (tag === 5) {
      out.onlyAttribute = booleanOf(field);
    }
  });
  log.debug('Leaving readIssuingDistributionPoint(). indirect=' + out.indirect);
  return out;
}

// Which of `signers` signed it. Null when none did.
//
// **THE SIGNATURE IS CHECKED WITH THE ENGINE AND NOT WITH `crl.verify()`**,
// because that method answers FALSE for a list carrying a critical extension it
// does not know and for an issuer name whose BYTES differ from the signer's
// subject — so a list this file would refuse for its extension was reported as
// forged, and one whose issuer an encoder spelled differently could never verify.
// Both of those are decided above and below this call, in their own words.
async function crlSignerOf(crl, signers) {
  log.debug('Entering crlSignerOf(). ' + signers.length + ' candidate(s).');
  for (let i = 0; i < signers.length; i++) {
    const candidate = pkijsOf(signers[i]);
    if (!candidate) {
      continue;
    }
    let verified = false;
    try {
      verified = await pkijs.getCrypto(true).verifyWithPublicKey(
        crl.tbsView, crl.signatureValue, candidate.subjectPublicKeyInfo,
        crl.signatureAlgorithm);
    } catch (e) {
      // `verify()` throws for a key of a type the engine cannot use with this
      // algorithm rather than answering false. That is "not this signer".
      log.debug('crlSignerOf(): verify threw: ' + e.message);
      verified = false;
    }
    if (verified) {
      log.debug('Leaving crlSignerOf(). Verified.');
      return { x509: signers[i], parsed: candidate };
    }
  }
  log.debug('Leaving crlSignerOf(). None verified.');
  return null;
}

function entriesOf(crl, crlIssuerKey, indirect) {
  log.debug('Entering entriesOf().');
  const entries = new Map();
  let problem = '';
  let attributed = crlIssuerKey;
  (crl.revokedCertificates || []).forEach(function (entry) {
    if (problem) {
      return;
    }
    const extensions = (entry.crlEntryExtensions && entry.crlEntryExtensions.extensions) || [];
    const unknownCritical = extensions.filter(function (ext) {
      return ext.critical && UNDERSTOOD_ENTRY_EXTENSIONS.indexOf(ext.extnID) < 0;
    });
    if (unknownCritical.length) {
      problem = 'an entry carries a critical extension this service does not ' +
                'implement (' + unknownCritical[0].extnID + '), which makes the ' +
                'list unusable';
      return;
    }
    const named = extensions.filter(function (ext) {
      return ext.extnID === OID.CERTIFICATE_ISSUER;
    })[0];
    if (named) {
      if (!indirect) {
        problem = 'an entry names a certificate issuer, but the list does not ' +
                  'declare itself indirect in its issuing distribution point (RFC ' +
                  '5280 section 5.3.3)';
        return;
      }
      let dn = null;
      try {
        dn = generalNamesOf(derParse(named.extnValue.valueBlock.valueHexView))
          .filter(function (one) { return one.type === 4; })[0] || null;
      } catch (e) {
        // Unreadable, which is reported below exactly as a name in a form this
        // file cannot compare is: the entry's issuer is unknown, so the list is.
        log.debug('entriesOf(): certificateIssuer unreadable: ' + e.message);
        dn = null;
      }
      if (!dn) {
        problem = 'an entry names its certificate issuer in a form this service ' +
                  'cannot compare — only a directory name is';
        return;
      }
      attributed = nameKey(dn.value);
    }
    const serial = normalSerial(Buffer.from(entry.userCertificate.valueBlock
      .valueHexView).toString('hex'));
    const reason = reasonOfEntry(entry);
    entries.set(attributed + '|' + serial, {
      revokedAt: entry.revocationDate && entry.revocationDate.value
        ? entry.revocationDate.value.toISOString() : '',
      reason: reason.id, reasonCode: reason.code
    });
  });
  log.debug('Leaving entriesOf(). ' + entries.size + ' entry(ies)' +
            (problem ? ', unusable' : '') + '.');
  return { entries: entries, problem: problem };
}

async function readCrl(der, context) {
  log.debug('Entering readCrl(). ' + der.length + ' bytes.');
  let bytes = der;
  // SOME SERVERS PUBLISH PEM. RFC 5280 says DER; accepting both costs one test.
  if (/^-----BEGIN/.test(der.slice(0, 32).toString('latin1'))) {
    bytes = derOfPem(der.toString('latin1'));
  }
  let crl;
  try {
    crl = pkijs.CertificateRevocationList.fromBER(arrayBufferOf(bytes));
  } catch (e) {
    log.debug('Leaving readCrl(). It did not parse.');
    return { ok: false, why: 'what it answered is not a CRL: ' + e.message };
  }
  const issuerKey = nameKey(crl.issuer);
  if (issuerKey !== nameKey(context.expectName)) {
    log.debug('Leaving readCrl(). Another issuer.');
    return { ok: false, signerProblem: true,
             why: context.indirect
               ? 'the list is issued by "' + describeName(crl.issuer) + '", not by ' +
                 'the CRL issuer the certificate names'
               : 'the list is issued by "' + describeName(crl.issuer) + '", ' +
                 'somebody other than the certificate\'s issuer — and the ' +
                 'certificate names no separate CRL issuer who could have signed it' };
  }
  let signer = await crlSignerOf(crl, context.signers || []);
  let signerFetchedFrom = '';
  let caIssuersWhy = '';
  if (!signer && context.target) {
    const fetched = await crlSignerFromCaIssuers(crl, context);
    signer = fetched.signer || null;
    signerFetchedFrom = fetched.url || '';
    caIssuersWhy = fetched.why || '';
  }
  if (!signer) {
    log.debug('Leaving readCrl(). No signer.');
    const first = context.localWhy
      ? context.localWhy
      : 'its signature does not verify against the ' +
        (context.indirect ? 'certificate of the CRL issuer the certificate names'
                          : 'issuer\'s certificate') +
        ', so it says nothing about what that issuer revoked';
    return { ok: false, signerProblem: true,
             caIssuersProblem: !!caIssuersWhy && caIssuersWhy.indexOf('names no caIssuers') < 0,
             why: first + (caIssuersWhy ? '; and ' + caIssuersWhy : '') };
  }
  if (!keyUsageAllows(signer.parsed, KEY_USAGE_CRL_SIGN)) {
    log.debug('Leaving readCrl(). Signer may not sign CRLs.');
    return { ok: false, signerProblem: true,
             why: 'it was signed by a certificate whose keyUsage does not include ' +
                  'cRLSign (RFC 5280 section 4.2.1.3)' };
  }
  const extensions = (crl.crlExtensions && crl.crlExtensions.extensions) || [];
  const critical = extensions.filter(function (ext) {
    return ext.critical && UNDERSTOOD_CRL_EXTENSIONS.indexOf(ext.extnID) < 0;
  });
  if (critical.length) {
    log.debug('Leaving readCrl(). An unsupported critical extension.');
    return { ok: false,
             why: 'it carries a critical extension this service does not ' +
                  'implement (' + critical.map(function (ext) {
                    return ext.extnID;
                  }).join(', ') + '), which RFC 5280 section 6.3.3 says ' +
                  'makes the list unusable' };
  }
  const find = function (oid) {
    return extensions.filter(function (ext) { return ext.extnID === oid; })[0] || null;
  };
  let facts;
  try {
    facts = {
      crlNumber: integerExtensionOf(find(OID.CRL_NUMBER)),
      baseCrlNumber: integerExtensionOf(find(OID.DELTA_CRL_INDICATOR)),
      idp: readIssuingDistributionPoint(find(OID.ISSUING_DISTRIBUTION_POINT)),
      freshest: pointsOfExtension(find(OID.FRESHEST_CRL)).fetchable
    };
  } catch (e) {
    log.debug('Leaving readCrl(). An extension could not be read.');
    return { ok: false, why: 'an extension it carries could not be read: ' + e.message };
  }
  if (facts.idp.relative) {
    // A name relative to the CRL issuer is made whole against THIS list's issuer
    // and compared like any other directory name; one that cannot be made whole
    // unambiguously leaves the list unusable rather than matched by a guess.
    const whole = wholeNameOf(crl.issuer, facts.idp.relativeRdn);
    if (!whole.ok) {
      log.debug('Leaving readCrl(). An unresolvable relative distribution point name.');
      return { ok: false, why: 'its issuing distribution point ' + whole.why.replace(/^its /, 'has a ') };
    }
    facts.idp.keys = [whole.key];
  }
  const now = Date.now();
  const nextUpdate = crl.nextUpdate && crl.nextUpdate.value
    ? crl.nextUpdate.value.getTime() : 0;
  if (nextUpdate && nextUpdate + skewMs() < now) {
    log.debug('Leaving readCrl(). Stale.');
    return { ok: false,
             why: 'it is STALE — its nextUpdate was ' +
                  new Date(nextUpdate).toISOString() + ', so the issuer has ' +
                  'stopped vouching for it' };
  }
  const read = entriesOf(crl, issuerKey, facts.idp.indirect);
  if (read.problem) {
    log.debug('Leaving readCrl(). An entry is unusable.');
    return { ok: false, why: read.problem };
  }
  log.debug('Leaving readCrl(). ' + read.entries.size + ' entry(ies).');
  return Object.assign(facts, {
    ok: true, entries: read.entries, issuerKey: issuerKey,
    signerFingerprint: signer.x509.fingerprint256,
    signerFetchedFrom: signerFetchedFrom,
    isDelta: facts.baseCrlNumber !== null,
    thisUpdate: crl.thisUpdate && crl.thisUpdate.value
      ? crl.thisUpdate.value.toISOString() : '',
    nextUpdate: nextUpdate ? new Date(nextUpdate).toISOString() : '',
    nextUpdateMs: nextUpdate
  });
}

// One list, answered from the cache or fetched. Resolves
// { ok, list, why, kind, fromCache } and never rejects. `context.purpose` is
// `base` or `delta` and decides only which code a failure is logged under.
async function listFrom(url, context) {
  log.debug('Entering listFrom(). url=' + url);
  // The path is part of the key once a signer may be FETCHED: which fetched
  // certificate is authorised depends on the path it has to chain to.
  const key = url + '|' + (context.signers || []).map(function (one) {
    return one.fingerprint256;
  }).join(',') + (context.target ? '|' + Array.from(context.target.above).sort().join(',') : '');
  const hit = cached(crlCache, key);
  if (hit) {
    log.debug('Leaving listFrom(). Cached.');
    return { ok: true, list: hit, fromCache: true };
  }
  const failed = failedRecently(key);
  if (failed) {
    log.debug('Leaving listFrom(). Failed recently.');
    return { ok: false, why: failed.why + ' (remembered for ' +
                             'pki.revocationFailureRetryS)', kind: failed.kind };
  }
  log.debug('Leaving listFrom(). Fetching, or joining a fetch in flight.');
  return once(key, async function () {
    const fetched = await fetchCrlDocument(url, context);
    if (!fetched.ok) {
      log.warn(errorCodes.tag('STS-PKI-0120') + 'revocation: the CRL at ' + url +
               ' could not be fetched: ' + fetched.why + '.');
      rememberFailure(key, fetched.why, 'unreachable');
      return { ok: false, why: fetched.why, kind: 'unreachable' };
    }
    const read = await readCrl(fetched.der, context);
    if (!read.ok) {
      if (context.purpose === 'delta') {
        log.warn(errorCodes.tag('STS-PKI-0124') + 'revocation: the delta CRL at ' +
                 url + ' cannot be used: ' + read.why + '.');
      } else if (read.caIssuersProblem) {
        log.warn(errorCodes.tag('STS-PKI-0126') + 'revocation: no certificate fetched ' +
                 'from the caIssuers address of the CRL at ' + url + ' could sign it: ' +
                 read.why + '.');
      } else if (context.indirect && read.signerProblem) {
        log.warn(errorCodes.tag('STS-PKI-0125') + 'revocation: the indirect CRL ' +
                 'at ' + url + ' cannot be trusted: ' + read.why + '.');
      } else {
        log.warn(errorCodes.tag('STS-PKI-0121') + 'revocation: the CRL at ' + url +
                 ' cannot be used: ' + read.why + '.');
      }
      rememberFailure(key, read.why, 'unusable');
      return { ok: false, why: read.why, kind: 'unusable' };
    }
    const maxAge = Math.max(1, Number(config.value('pki.revocationCrlMaxAgeS')));
    const ceiling = Date.now() + maxAge * 1000;
    const entry = Object.assign({}, read, {
      url: url, fetchedAt: new Date().toISOString(),
      expiresAt: read.nextUpdateMs ? Math.min(read.nextUpdateMs, ceiling) : ceiling
    });
    remember(crlCache, key, entry);
    log.info('revocation: fetched and verified the ' +
             (entry.isDelta ? 'delta ' : '') + 'CRL at ' + url + ' (' +
             entry.entries.size + ' entry(ies), nextUpdate ' +
             (entry.nextUpdate || 'absent') + ').');
    return { ok: true, list: entry, fromCache: false };
  });
}

// ---------------------------------------------------------------------------
// OCSP (RFC 6960): THE REQUEST, AND THE RESPONSE READ AND VERIFIED.
//
// The request carries ONE CertID and a nonce. The CertID is SHA-1 over the
// issuer's name and key, which is what the RFC 5019 lightweight profile every
// high-volume responder implements requires — and it is an IDENTIFIER, not a
// signature: nothing here relies on SHA-1's collision resistance, because the
// answer is believed only once its own signature verifies and its CertID
// matches the certificate this file computed it from.
//
// A response is believed when all of these hold:
//   * responseStatus is `successful` and the type is the basic response;
//   * a SingleResponse's CertID matches this certificate — issuer name hash,
//     issuer key hash and serial — under whichever digest it is keyed by;
//   * it is signed by the ISSUER, or by a DELEGATED RESPONDER whose certificate
//     is in the response, was issued by that same issuer, carries
//     id-kp-OCSPSigning and is inside its validity period (section 4.2.2.2) —
//     and the responderID names the key that actually verifies;
//   * the nonce it echoes, if it echoes one, is the one sent;
//   * thisUpdate is not in the future and nextUpdate is not past (with
//     `pki.revocationClockSkewS`), or, with no nextUpdate, thisUpdate is within
//     `pki.revocationOcspMaxAgeS`.
// ---------------------------------------------------------------------------
function digestOf(algorithm, bytes) {
  return nodeCrypto.createHash(algorithm).update(Buffer.from(bytes)).digest();
}

function keyBitsOf(parsedCert) {
  return Buffer.from(parsedCert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
}

function buildOcspRequest(target) {
  log.debug('Entering buildOcspRequest().');
  const nonce = nodeCrypto.randomBytes(32);
  const nonceValue = Buffer.from(new asn1js.OctetString({
    valueHex: arrayBufferOf(nonce) }).toBER(false));
  const certId = new pkijs.CertID({
    hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: OID.SHA1,
                                                   algorithmParams: new asn1js.Null() }),
    issuerNameHash: new asn1js.OctetString({
      valueHex: arrayBufferOf(digestOf('sha1', nameDerOf(target.parsed.issuer))) }),
    issuerKeyHash: new asn1js.OctetString({
      valueHex: arrayBufferOf(digestOf('sha1', keyBitsOf(target.issuerParsed))) }),
    serialNumber: target.parsed.serialNumber
  });
  const request = new pkijs.OCSPRequest({
    tbsRequest: new pkijs.TBSRequest({
      requestList: [new pkijs.Request({ reqCert: certId })],
      requestExtensions: [new pkijs.Extension({ extnID: OID.OCSP_NONCE,
                                                extnValue: arrayBufferOf(nonceValue) })]
    })
  });
  log.debug('Leaving buildOcspRequest().');
  return { der: Buffer.from(request.toSchema(true).toBER(false)), nonceValue: nonceValue };
}

function certIdMatches(certId, target) {
  const algorithm = CERT_ID_HASHES[certId.hashAlgorithm.algorithmId];
  if (!algorithm) {
    return false;
  }
  const serial = normalSerial(Buffer.from(certId.serialNumber.valueBlock.valueHexView)
    .toString('hex'));
  return serial === target.serial &&
    Buffer.from(certId.issuerNameHash.valueBlock.valueHexView)
      .equals(digestOf(algorithm, nameDerOf(target.parsed.issuer))) &&
    Buffer.from(certId.issuerKeyHash.valueBlock.valueHexView)
      .equals(digestOf(algorithm, keyBitsOf(target.issuerParsed)));
}

async function ocspSignatureVerifies(basic, parsedCert) {
  try {
    return await pkijs.getCrypto(true).verifyWithPublicKey(
      basic.tbsResponseData.tbsView, basic.signature,
      parsedCert.subjectPublicKeyInfo, basic.signatureAlgorithm);
  } catch (e) {
    // A key of a type the engine cannot use for this algorithm answers by
    // throwing. That is "this key did not sign it", which is what false says.
    log.debug('ocspSignatureVerifies(): threw: ' + e.message);
    return false;
  }
}

// ---------------------------------------------------------------------------
// A DELEGATED RESPONDER'S OWN STATUS (RFC 6960 section 4.2.2.2.1).
//
// **id-pkix-ocsp-nocheck MEANS DO NOT CHECK IT**, and it is honoured: the issuer
// that put it there has said the responder's certificate is short-lived enough
// that its revocation is not a question, and the answer says so rather than
// reporting a status nobody established.
//
// **OTHERWISE ITS STATUS COMES FROM ITS CRL AND NEVER FROM OCSP.** The one
// responder this file could ask is the one whose certificate is in question, and
// asking it whether it is revoked is a question whose answer it signs; any other
// responder the certificate names would be asked with this same machinery, a
// loop in the general case. The CRL route is the same one a leaf goes through —
// deltas, indirect lists, caIssuers and all — with the responder's issuer (the
// certificate's issuer, by the rule above) as the issuer.
//
// **REVOKED MAKES EVERY ANSWER IT SIGNED UNUSABLE**, in both policies — a signed
// fact wins everywhere else here, and does here. **UNKNOWN IS THE POLICY'S** and
// is decided where the answer is USED (`ocspRoute()`), because the answer is
// cached and the policy is read per call: hard-fail does not believe a responder
// whose status could not be established, soft-fail does and says so. A responder
// certificate naming no list at all is refused by hard-fail only under
// `pki.revocationRequireDistributionPoint`, which is the rule a leaf gets.
// ---------------------------------------------------------------------------
async function responderStatusOf(parsedCert, x509, target) {
  log.debug('Entering responderStatusOf().');
  if (extensionOf(parsedCert, OID.OCSP_NOCHECK)) {
    log.debug('Leaving responderStatusOf(). nocheck.');
    return { status: 'not-checked', nocheck: true, refusable: false,
             why: 'its certificate carries id-pkix-ocsp-nocheck, so its own status is not ' +
                  'checked (RFC 6960 section 4.2.2.2.1)' };
  }
  const responderTarget = targetOf({ cert: x509, issuerCert: target.issuerCert,
                                     offered: target.offered, serialHex: x509.serialNumber,
                                     subject: x509.subject, depth: target.link.depth });
  if (!responderTarget) {
    log.debug('Leaving responderStatusOf(). Unreadable.');
    return { status: 'unknown', refusable: true,
             why: 'its certificate could not be read closely enough to look it up' };
  }
  const result = await crlRoute(responderTarget);
  log.debug('Leaving responderStatusOf(). ' + result.status);
  return { status: result.status, kind: result.kind || '',
           refusable: result.status === 'unknown'
             ? (result.none ? policy().requireDistributionPoint : !!result.refusable) : false,
           why: 'from its CRL: ' + result.why };
}

// Who signed it, and whether they were entitled to. RFC 6960 section 4.2.2.2.
async function ocspSignerOf(basic, target) {
  log.debug('Entering ocspSignerOf().');
  const responderId = basic.tbsResponseData.responderID;
  const named = function (parsedCert) {
    if (responderId instanceof pkijs.RelativeDistinguishedNames) {
      return nameKey(responderId) === nameKey(parsedCert.subject);
    }
    const byKey = responderId && responderId.valueBlock
      ? Buffer.from(responderId.valueBlock.valueHexView) : null;
    return !!byKey && byKey.equals(digestOf('sha1', keyBitsOf(parsedCert)));
  };
  const tried = [];
  if (named(target.issuerParsed)) {
    if (await ocspSignatureVerifies(basic, target.issuerParsed)) {
      log.debug('Leaving ocspSignerOf(). The issuer.');
      return { ok: true, kind: 'issuer' };
    }
    tried.push('it names the issuer as its responder, and the issuer\'s key does ' +
               'not verify its signature');
  }
  const now = Date.now();
  const certs = basic.certs || [];
  for (let i = 0; i < certs.length; i++) {
    if (!named(certs[i])) {
      continue;
    }
    const label = 'the responder certificate "' + describeName(certs[i].subject) + '"';
    const x509 = x509Of(Buffer.from(certs[i].toSchema().toBER(false)));
    if (!x509 || !signedBy(x509, target.issuerCert)) {
      tried.push(label + ' was not issued by the certificate\'s issuer, so the ' +
                 'issuer never delegated anything to it');
      continue;
    }
    if (!hasExtendedKeyUsage(certs[i], OID.KP_OCSP_SIGNING)) {
      tried.push(label + ' carries no id-kp-OCSPSigning in its extendedKeyUsage, ' +
                 'so its issuer did not make it a responder (RFC 6960 section 4.2.2.2)');
      continue;
    }
    if (!validAt(x509, now)) {
      tried.push(label + ' is outside its validity period');
      continue;
    }
    if (await ocspSignatureVerifies(basic, certs[i])) {
      const responderStatus = await responderStatusOf(certs[i], x509, target);
      if (responderStatus.status === 'revoked') {
        log.warn(errorCodes.tag('STS-PKI-0127') + 'revocation: the delegated OCSP ' +
                 'responder "' + describeName(certs[i].subject) + '" is itself revoked: ' +
                 responderStatus.why + '.');
        tried.push(label + ' is itself REVOKED — ' + responderStatus.why + ' — so ' +
                   'nothing it signs is an answer (RFC 6960 section 4.2.2.2.1)');
        continue;
      }
      log.debug('Leaving ocspSignerOf(). A delegated responder.');
      return { ok: true, kind: 'delegated', responder: describeName(certs[i].subject),
               responderStatus: responderStatus };
    }
    tried.push(label + '\'s key does not verify its signature');
  }
  log.debug('Leaving ocspSignerOf(). Nobody authorised.');
  return { ok: false,
           why: tried.length
             ? 'it was not signed by anybody the issuer authorised — ' + tried.join('; ')
             : 'its responderID names neither the certificate\'s issuer nor a ' +
               'responder certificate the response carries, so nothing the issuer ' +
               'vouched for signed it' };
}

function ocspNonceOf(data, sent) {
  const echoed = (data.responseExtensions || []).filter(function (ext) {
    return ext.extnID === OID.OCSP_NONCE;
  })[0];
  if (!echoed) {
    if (config.value('pki.revocationOcspRequireNonce') === true) {
      return { ok: false, why: 'it echoes no nonce, and ' +
                               'pki.revocationOcspRequireNonce requires one' };
    }
    return { ok: true, state: 'absent' };
  }
  if (!Buffer.from(echoed.extnValue.valueBlock.valueHexView).equals(sent)) {
    return { ok: false, why: 'it echoes a nonce that is not the one this request ' +
                             'sent, so it answers somebody else\'s question — a replay' };
  }
  return { ok: true, state: 'matched' };
}

function ocspFreshness(single) {
  log.debug('Entering ocspFreshness().');
  const now = Date.now();
  const skew = skewMs();
  const thisUpdate = single.thisUpdate instanceof Date ? single.thisUpdate.getTime() : 0;
  const nextUpdate = single.nextUpdate instanceof Date ? single.nextUpdate.getTime() : 0;
  let why = '';
  if (!thisUpdate) {
    why = 'it carries no thisUpdate';
  } else if (thisUpdate - skew > now) {
    why = 'its thisUpdate is ' + new Date(thisUpdate).toISOString() + ', in the ' +
          'future by more than pki.revocationClockSkewS';
  } else if (nextUpdate && nextUpdate + skew < now) {
    why = 'it is STALE — its nextUpdate was ' + new Date(nextUpdate).toISOString();
  } else if (!nextUpdate && thisUpdate + ocspMaxAgeMs() + skew < now) {
    why = 'it is STALE — it carries no nextUpdate, and its thisUpdate, ' +
          new Date(thisUpdate).toISOString() + ', is older than ' +
          'pki.revocationOcspMaxAgeS';
  }
  log.debug('Leaving ocspFreshness(). ' + (why ? 'Not fresh.' : 'Fresh.'));
  return { ok: !why, why: why, thisUpdate: thisUpdate, nextUpdate: nextUpdate };
}

function ocspStatusOf(single) {
  const status = single.certStatus;
  const tag = status && status.idBlock ? status.idBlock.tagNumber : -1;
  if (tag === 0) {
    return { status: 'good' };
  }
  if (tag !== 1) {
    return { status: 'unknown' };
  }
  const parts = childrenOf(status);
  const at = parts[0] && typeof parts[0].toDate === 'function' ? parts[0].toDate() : null;
  const holder = parts.filter(function (one) { return contextTagOf(one) === 0; })[0];
  const enumerated = childrenOf(holder)[0];
  const code = enumerated && enumerated.valueBlock &&
               typeof enumerated.valueBlock.valueDec === 'number'
    ? enumerated.valueBlock.valueDec : 0;
  return { status: 'revoked', revokedAt: at ? at.toISOString() : '',
           reasonCode: code, reason: holder ? reasonNameOf(code) : 'unspecified' };
}

async function readOcsp(der, target, nonceValue) {
  log.debug('Entering readOcsp(). ' + der.length + ' bytes.');
  let response;
  let basic;
  try {
    response = pkijs.OCSPResponse.fromBER(arrayBufferOf(der));
  } catch (e) {
    log.debug('Leaving readOcsp(). Not a response.');
    return { ok: false, why: 'what it answered is not an OCSP response: ' + e.message };
  }
  const statusCode = response.responseStatus.valueBlock.valueDec;
  if (statusCode !== 0) {
    log.debug('Leaving readOcsp(). responseStatus ' + statusCode + '.');
    return { ok: false, transport: true,
             why: 'the responder answered ' + (OCSP_RESPONSE_STATUS[statusCode] ||
                                               'status ' + statusCode) +
                  ' rather than a response' };
  }
  if (!response.responseBytes || response.responseBytes.responseType !== OID.OCSP_BASIC) {
    log.debug('Leaving readOcsp(). Not a basic response.');
    return { ok: false, why: 'it is not a basic OCSP response, the one type RFC 6960 ' +
                             'section 4.2.1 requires a responder to support' };
  }
  try {
    basic = pkijs.BasicOCSPResponse.fromBER(arrayBufferOf(
      Buffer.from(response.responseBytes.response.valueBlock.valueHexView)));
  } catch (e) {
    log.debug('Leaving readOcsp(). The basic response did not parse.');
    return { ok: false, why: 'its basic response did not parse: ' + e.message };
  }
  const single = (basic.tbsResponseData.responses || []).filter(function (one) {
    return certIdMatches(one.certID, target);
  })[0];
  if (!single) {
    log.debug('Leaving readOcsp(). No answer about this certificate.');
    return { ok: false, why: 'it carries no answer about this certificate — no single ' +
                             'response names its issuer and serial' };
  }
  const signer = await ocspSignerOf(basic, target);
  if (!signer.ok) {
    log.debug('Leaving readOcsp(). Unauthorised signer.');
    return { ok: false, why: signer.why };
  }
  const nonce = ocspNonceOf(basic.tbsResponseData, nonceValue);
  if (!nonce.ok) {
    log.debug('Leaving readOcsp(). Nonce.');
    return { ok: false, why: nonce.why };
  }
  const fresh = ocspFreshness(single);
  if (!fresh.ok) {
    log.debug('Leaving readOcsp(). Not fresh.');
    return { ok: false, why: fresh.why };
  }
  log.debug('Leaving readOcsp(). Usable.');
  return Object.assign({ ok: true, responder: signer.kind,
                         responderName: signer.responder || '', nonce: nonce.state,
                         responderStatus: signer.responderStatus || null,
                         thisUpdateMs: fresh.thisUpdate, nextUpdateMs: fresh.nextUpdate,
                         nextUpdate: fresh.nextUpdate
                           ? new Date(fresh.nextUpdate).toISOString() : '' },
                       ocspStatusOf(single));
}

// One responder, answered from the cache or asked. Never rejects.
async function ocspFrom(url, target) {
  log.debug('Entering ocspFrom(). url=' + url);
  const key = url + '|' + target.issuerCert.fingerprint256 + '|' + target.serial;
  const hit = cached(ocspCache, key);
  if (hit) {
    log.debug('Leaving ocspFrom(). Cached.');
    return { ok: true, answer: hit, fromCache: true };
  }
  const failed = failedRecently(key);
  if (failed) {
    log.debug('Leaving ocspFrom(). Failed recently.');
    return { ok: false, why: failed.why + ' (remembered for ' +
                             'pki.revocationFailureRetryS)' };
  }
  log.debug('Leaving ocspFrom(). Asking, or joining a request in flight.');
  return once(key, async function () {
    let built;
    try {
      built = buildOcspRequest(target);
    } catch (e) {
      log.warn(errorCodes.tag('STS-PKI-0122') + 'revocation: an OCSP request for ' +
               url + ' could not be built: ' + e.message + '.');
      return { ok: false, why: 'the request could not be built: ' + e.message };
    }
    const fetched = await fetchBytes(url, { body: built.der,
                                            contentType: 'application/ocsp-request',
                                            accept: 'application/ocsp-response' });
    const read = fetched.ok ? await readOcsp(fetched.der, target, built.nonceValue)
                            : { ok: false, transport: true, why: fetched.why };
    if (!read.ok) {
      if (read.transport) {
        log.warn(errorCodes.tag('STS-PKI-0122') + 'revocation: the OCSP responder ' +
                 'at ' + url + ' could not be asked: ' + read.why + '.');
      } else {
        log.warn(errorCodes.tag('STS-PKI-0123') + 'revocation: the OCSP response ' +
                 'from ' + url + ' cannot be used: ' + read.why + '.');
      }
      rememberFailure(key, read.why, read.transport ? 'unreachable' : 'unusable');
      return { ok: false, why: read.why };
    }
    const now = Date.now();
    const expiresAt = Math.min(read.nextUpdateMs || read.thisUpdateMs + ocspMaxAgeMs(),
                               now + ocspMaxAgeMs());
    const entry = Object.assign({}, read, { url: url, fetchedAt: new Date(now).toISOString(),
                                            expiresAt: expiresAt });
    remember(ocspCache, key, entry);
    log.info('revocation: the OCSP responder at ' + url + ' answered ' + read.status +
             ' (signed by ' + read.responder + ', nonce ' + read.nonce + ').');
    return { ok: true, answer: entry, fromCache: false };
  });
}

// ---------------------------------------------------------------------------
// THE INPUT, FROM WHEREVER A CERTIFICATE ARRIVED.
//
//   { leaf: PEM | DER | X509Certificate,
//     chain: [ PEM | DER | X509Certificate ],   what came with it, any order
//     verified: boolean }                        did the chain build to an anchor
//
// `fromSocket()` builds it off a TLS socket: node's own `issuerCertificate`
// links where the socket is real, and the `issuerChain` a request worker is
// handed where it is the worker's shim (`common/request_pool.js`'s `peerOf()`),
// because that shim carries the leaf and, without this, nothing above it.
// ---------------------------------------------------------------------------
function fromSocket(socket) {
  log.debug('Entering fromSocket().');
  if (!socket || typeof socket.getPeerCertificate !== 'function') {
    log.debug('Leaving fromSocket(). Not TLS.');
    return null;
  }
  let peer;
  try {
    peer = socket.getPeerCertificate(true);
  } catch (e) {
    // A socket that went away between the handshake and this line. There is
    // nothing presented to answer about.
    log.debug('Leaving fromSocket(). Unreadable: ' + e.message);
    return null;
  }
  if (!peer || !peer.raw || !peer.raw.length) {
    log.debug('Leaving fromSocket(). Nothing presented.');
    return null;
  }
  const chain = [];
  if (peer.issuerCertificate) {
    let at = peer.issuerCertificate;
    let hop = 0;
    while (at && at.raw && hop < MAX_DEPTH) {
      if (at.raw.equals(peer.raw) && hop > 0) {
        break;
      }
      if (!chain.some(function (one) { return one.equals(at.raw); }) &&
          !at.raw.equals(peer.raw)) {
        chain.push(at.raw);
      }
      if (!at.issuerCertificate || at.issuerCertificate === at) {
        break;
      }
      at = at.issuerCertificate;
      hop += 1;
    }
  } else if (Array.isArray(peer.issuerChain)) {
    peer.issuerChain.slice(0, MAX_DEPTH).forEach(function (b64) {
      chain.push(Buffer.from(String(b64), 'base64'));
    });
  }
  log.debug('Leaving fromSocket(). ' + chain.length + ' above the leaf.');
  return { leaf: peer.raw, chain: chain, verified: socket.authorized === true };
}

// ---------------------------------------------------------------------------
// THE WALK: one link per certificate from the leaf up, each answered by the
// register where this service signed it and marked for a CRL where it did not.
//
// `external`: 'fetch' — resolve foreign links from their CRLs when the chain
// verified; 'not-consulted' — never fetch, which is what the synchronous doors
// ask for (`verifyLeaf()` walks a path that is ours by construction, and the
// SPIRE Server API has no revocation mechanism for a federated SVID).
// ---------------------------------------------------------------------------
function walk(input) {
  log.debug('Entering walk().');
  const leaf = x509Of(input && input.leaf);
  const links = [];
  if (!leaf) {
    log.debug('Leaving walk(). The leaf is unreadable.');
    return { links: links, readable: false };
  }
  const offered = ((input && input.chain) || []).map(x509Of)
    .filter(function (one) { return !!one; });
  let current = leaf;
  for (let depth = 0; depth < MAX_DEPTH && current; depth++) {
    if (selfSigned(current)) {
      // AN ANCHOR. A self-signed certificate has nobody who could revoke it,
      // and an anchor is trusted by being installed rather than by a list.
      links.push({ depth: depth, subject: current.subject,
                   serialHex: normalSerial(current.serialNumber),
                   status: 'good', source: 'anchor',
                   why: depth === 0
                     ? 'self-signed: there is no issuer to revoke it'
                     : 'a trust anchor, which no list can revoke' });
      break;
    }
    const local = localIssuerOf(current);
    if (local) {
      const entry = pkiRevocation.isRevoked(local.scope, local.ca,
                                            current.serialNumber);
      links.push({
        depth: depth, subject: current.subject,
        serialHex: normalSerial(current.serialNumber),
        issuer: local.cert.subject,
        authority: { scope: local.scope, ca: local.ca,
                     label: (local.scope === pki.SERVICE_SCOPE ? 'service'
                             : (local.scope === pki.PROCESS_SCOPE ? 'process'
                                : (local.scope || 'default'))) + '/' + local.ca },
        source: 'register',
        status: entry ? 'revoked' : 'good',
        reason: entry ? entry.reason : '',
        reasonCode: entry ? entry.reasonCode : undefined,
        revokedAt: entry ? entry.revokedAt : '',
        why: entry
          ? 'on the ' + local.ca + ' authority\'s own revocation list since ' +
            entry.revokedAt + ' (' + entry.reason + ')'
          : 'signed by this service\'s ' + local.ca + ' authority, whose list ' +
            'does not name it'
      });
      current = local.cert;
      continue;
    }
    const presentedIssuer = offered.filter(function (one) {
      return signedBy(current, one);
    })[0] || null;
    links.push({
      depth: depth, subject: current.subject,
      serialHex: normalSerial(current.serialNumber),
      issuer: current.issuer, source: 'crl', status: 'unknown',
      cert: current, issuerCert: presentedIssuer, offered: offered,
      why: presentedIssuer ? 'signed by an authority this service does not hold'
                           : 'its issuer is neither held here nor in the chain ' +
                             'that was presented, so nothing can verify a list ' +
                             'about it'
    });
    current = presentedIssuer;
  }
  log.debug('Leaving walk(). ' + links.length + ' link(s).');
  return { links: links, readable: true };
}

// ---------------------------------------------------------------------------
// THE FOREIGN LINK, READ ONCE: the certificate and its issuer as pkijs sees
// them, the issuer's name as a comparable key, whether it is a CA, and the
// fingerprints of the certificates ABOVE it in the path that verified — which
// is what an indirect CRL's signer has to chain to.
// ---------------------------------------------------------------------------
function targetOf(link) {
  log.debug('Entering targetOf().');
  const parsed = pkijsOf(link.cert);
  const issuerParsed = pkijsOf(link.issuerCert);
  if (!parsed || !issuerParsed) {
    log.debug('Leaving targetOf(). Unreadable.');
    return null;
  }
  const offered = link.offered || [];
  const above = new Set();
  let current = link.issuerCert;
  for (let depth = 0; depth < MAX_DEPTH && current; depth++) {
    if (above.has(current.fingerprint256)) {
      break;
    }
    above.add(current.fingerprint256);
    if (selfSigned(current)) {
      break;
    }
    const at = current;
    current = offered.filter(function (one) { return signedBy(at, one); })[0] || null;
  }
  log.debug('Leaving targetOf(). ' + above.size + ' above it.');
  return { link: link, cert: link.cert, parsed: parsed, issuerCert: link.issuerCert,
           issuerParsed: issuerParsed, issuerKey: nameKey(parsed.issuer),
           serial: normalSerial(link.serialHex), isCa: isCaCertificate(parsed),
           offered: offered, above: above };
}

// ---------------------------------------------------------------------------
// WHO MAY HAVE SIGNED THE LIST AT ONE DISTRIBUTION POINT.
//
// **A point with no cRLIssuer is DIRECT**: the list must be issued by the
// certificate's own issuer and signed by the issuer certificate out of the
// presented chain — which is where every list was trusted from before this.
//
// **A point naming a cRLIssuer is INDIRECT**, and the certificate's own
// signature is what authorises that name: its issuer wrote "this list is
// issued by X" into the certificate. What remains is finding X's certificate
// and making sure it is REALLY X's. It is looked for in the presented chain,
// among this service's own authorities and in `pki.revocationCrlIssuersFile`,
// and one is authorised only if it may sign CRLs, is inside its validity period,
// and chains — through CA certificates from the same three places — to a
// certificate the target's own verified path passes through. A certificate that
// merely carries the right name and chains somewhere else is an impostor, which
// is the case `signedBy()` exists for one level up.
// ---------------------------------------------------------------------------
function heldCertificates() {
  return heldAuthorities().map(function (one) {
    return parsedTier(one.tier && one.tier.certificatePem);
  }).filter(function (one) { return !!one; });
}

function crlSignerAuthorised(candidate, target, pool) {
  log.debug('Entering crlSignerAuthorised().');
  const parsed = pkijsOf(candidate);
  const now = Date.now();
  if (!parsed || !keyUsageAllows(parsed, KEY_USAGE_CRL_SIGN) || !validAt(candidate, now)) {
    log.debug('Leaving crlSignerAuthorised(). May not sign CRLs now.');
    return false;
  }
  let current = candidate;
  for (let depth = 0; depth < MAX_DEPTH && current; depth++) {
    if (target.above.has(current.fingerprint256)) {
      log.debug('Leaving crlSignerAuthorised(). Chains to the path.');
      return true;
    }
    if (selfSigned(current)) {
      break;
    }
    const at = current;
    current = pool.filter(function (one) {
      return one.ca && validAt(one, now) && signedBy(at, one);
    })[0] || null;
  }
  log.debug('Leaving crlSignerAuthorised(). Chains elsewhere.');
  return false;
}

function crlContextFor(target, point) {
  log.debug('Entering crlContextFor().');
  if (!point.crlIssuerNamed) {
    log.debug('Leaving crlContextFor(). Direct.');
    return { ok: true, indirect: false, signers: [target.issuerCert],
             expectName: target.parsed.issuer, target: target };
  }
  if (!point.crlIssuer) {
    log.warn(errorCodes.tag('STS-PKI-0125') + 'revocation: "' + target.link.subject +
             '" names a CRL issuer that is not a directory name.');
    log.debug('Leaving crlContextFor(). Unreadable cRLIssuer.');
    return { ok: false, why: 'it names a CRL issuer that is not a directory name, ' +
                             'which this service has no way to look for' };
  }
  const wanted = nameKey(point.crlIssuer);
  const seen = new Set();
  const pool = target.offered.concat(heldCertificates(), configuredCrlIssuers())
    .filter(function (one) {
      if (seen.has(one.fingerprint256)) {
        return false;
      }
      seen.add(one.fingerprint256);
      return true;
    });
  const named = pool.filter(function (one) {
    const parsed = pkijsOf(one);
    return !!parsed && nameKey(parsed.subject) === wanted;
  });
  const authorised = named.filter(function (one) {
    return crlSignerAuthorised(one, target, pool);
  });
  if (!authorised.length) {
    // NOTHING HELD HERE MAY SIGN IT — which is not yet a refusal: the list
    // itself may name, in its Authority Information Access, where its signer's
    // certificate is published (RFC 5280 section 5.2.7). The list is fetched and
    // that address is tried; the sentence below is what the refusal says if it
    // names none or what is there is not authorised either.
    const why = named.length
      ? 'the CRL issuer it names, "' + describeName(point.crlIssuer) + '", has a ' +
        'certificate here only in forms that may not sign CRLs, are not valid now or ' +
        'do not chain to an authority its own path passes through'
      : 'it names "' + describeName(point.crlIssuer) + '" as its CRL issuer, and no ' +
        'certificate for that name is in the presented chain, among this service\'s ' +
        'authorities or in pki.revocationCrlIssuersFile';
    log.debug('Leaving crlContextFor(). No authorised signer held; caIssuers next.');
    return { ok: true, indirect: true, signers: [], expectName: point.crlIssuer,
             target: target, localWhy: why };
  }
  log.debug('Leaving crlContextFor(). Indirect, ' + authorised.length + ' signer(s).');
  return { ok: true, indirect: true, signers: authorised, expectName: point.crlIssuer,
           target: target };
}

// ---------------------------------------------------------------------------
// WHETHER A VERIFIED LIST IS ABOUT THIS CERTIFICATE AT ALL (RFC 5280 section
// 6.3.3 (b)): an empty string when it is, a sentence when it is not.
// ---------------------------------------------------------------------------
function scopeProblem(list, target, point) {
  const idp = list.idp;
  if (list.isDelta) {
    return 'it is a DELTA CRL — it carries a deltaCRLIndicator — at a distribution ' +
           'point, which names a complete list';
  }
  if (point.crlIssuerNamed && !idp.indirect) {
    return 'the certificate names a separate CRL issuer, and this list does not ' +
           'declare itself indirect';
  }
  if (idp.keys.length && !idp.keys.some(function (key) {
    return point.keys.indexOf(key) >= 0;
  })) {
    return 'its issuing distribution point names a different list from the one the ' +
           'certificate points at';
  }
  if (idp.onlyUser && target.isCa) {
    return 'it covers only end-entity certificates, and this is a CA certificate';
  }
  if (idp.onlyCa && !target.isCa) {
    return 'it covers only CA certificates, and this is an end-entity certificate';
  }
  if (idp.onlyAttribute) {
    return 'it covers only attribute certificates';
  }
  return '';
}

// ---------------------------------------------------------------------------
// A DELTA CRL (RFC 5280 section 5.2.4), and whether it may be merged.
//
// It must BE a delta; be issued and signed by the base's issuer; describe the
// same scope (the same issuing distribution point, byte for byte); be built on
// a base no newer than the one here (BaseCRLNumber <= the base's cRLNumber); and
// be newer than it (its own cRLNumber > the base's). Merged, an entry replaces
// the base's for that certificate and a `removeFromCRL` entry takes the base's
// away — which is how a certificateHold is released between two complete lists.
// ---------------------------------------------------------------------------
function deltaProblem(base, delta) {
  if (!delta.isDelta) {
    return 'it carries no deltaCRLIndicator, so it is not a delta CRL';
  }
  if (delta.issuerKey !== base.issuerKey || delta.signerFingerprint !== base.signerFingerprint) {
    return 'it was issued or signed by somebody other than the base CRL\'s issuer';
  }
  if (delta.idp.derHex !== base.idp.derHex) {
    return 'its issuing distribution point differs from the base CRL\'s, so it ' +
           'describes a different scope';
  }
  if (base.crlNumber === null) {
    return 'the base CRL carries no cRLNumber to check its BaseCRLNumber against';
  }
  if (delta.baseCrlNumber > base.crlNumber) {
    return 'its BaseCRLNumber is ' + delta.baseCrlNumber + ', newer than the base ' +
           'CRL\'s cRLNumber ' + base.crlNumber + ', so it was built on a list this ' +
           'service does not have';
  }
  if (delta.crlNumber === null || delta.crlNumber <= base.crlNumber) {
    return 'its cRLNumber is not greater than the base CRL\'s, so it is not newer ' +
           'than the list it would update';
  }
  return '';
}

function mergedEntries(baseEntries, deltaEntries) {
  const out = new Map(baseEntries);
  deltaEntries.forEach(function (entry, key) {
    if (entry.reasonCode === REASON_REMOVE_FROM_CRL) {
      out.delete(key);
    } else {
      out.set(key, entry);
    }
  });
  return out;
}

async function deltaFor(context, base, urls) {
  log.debug('Entering deltaFor(). ' + urls.length + ' url(s).');
  const problems = [];
  for (let i = 0; i < urls.length; i++) {
    const got = await listFrom(urls[i], Object.assign({}, context, { purpose: 'delta' }));
    if (!got.ok) {
      problems.push(urls[i] + ': ' + got.why);
      continue;
    }
    const why = deltaProblem(base, got.list);
    if (why) {
      log.warn(errorCodes.tag('STS-PKI-0124') + 'revocation: the delta CRL at ' +
               urls[i] + ' cannot be applied to the CRL at ' + base.url + ': ' + why + '.');
      problems.push(urls[i] + ': ' + why);
      continue;
    }
    log.debug('Leaving deltaFor(). Merged.');
    return { ok: true, url: urls[i],
             entries: mergedEntries(base.entries, got.list.entries) };
  }
  log.debug('Leaving deltaFor(). No usable delta.');
  return { ok: false, why: 'the delta CRL it names could not be applied — ' +
                           problems.join('; ') };
}

// ---------------------------------------------------------------------------
// THE CRL ROUTE: every distribution point, in order, until the reasons the
// usable lists cover between them are all of them.
//
// A certificate is REVOKED by the first usable list (merged with its delta)
// that lists it under its issuer with any reason but removeFromCRL. It is GOOD
// once the lists that do not list it cover every reason. Anything else is
// UNKNOWN — and when some list DID answer but covered only some reasons, the
// kind says so, because "the issuer publishes part of the answer" and "the
// answer could not be fetched" are different findings.
//
// **A DELTA THAT CANNOT BE APPLIED LEAVES THE BASE'S PERMANENT REVOCATION
// STANDING AND NOTHING ELSE.** A base listing a certificate as keyCompromise is
// revoked whatever a newer list says, because no delta can un-revoke it — but
// a base that does not list it, or lists it on hold, is exactly what a delta
// exists to update, and believing it would let whoever blocks the delta hide
// the newest revocations. So that is unknown, and hard-fail refuses it.
// ---------------------------------------------------------------------------
function crlRevokedResult(target, got, context, delta, entry) {
  return {
    status: 'revoked', answeredBy: 'crl', crlUrl: got.url,
    crlNextUpdate: got.list.nextUpdate, crlFromCache: !!got.fromCache,
    deltaUrl: delta && delta.ok ? delta.url : '', indirect: context.indirect,
    reason: entry.reason, reasonCode: entry.reasonCode, revokedAt: entry.revokedAt,
    why: 'the CRL at ' + got.url + (delta && delta.ok ? ' with its delta at ' + delta.url : '') +
         ', signed by ' + (context.indirect ? 'the CRL issuer the certificate names'
                                            : 'its issuer') +
         ', lists it as revoked since ' + entry.revokedAt + ' (' + entry.reason + ')'
  };
}

function crlNoPointResult(points) {
  let why = 'its issuer publishes no CRL for it — it names no distribution point';
  if (points.other.length) {
    why = 'it names only distribution points this service does not dial (' +
          points.other.join(', ') + ')';
  } else if (points.indirect) {
    why = 'it names only a CRL issuer, with no address to fetch that issuer\'s list from';
  }
  return { status: 'unknown', none: true, kind: 'no-distribution-point', why: why };
}

async function crlRoute(target) {
  log.debug('Entering crlRoute().');
  const points = distributionPointsOf(target.cert);
  points.points.forEach(function (point) {
    if (!point.relative) {
      return;
    }
    const address = relativeAddressOf(point, target);
    if (address.key) {
      point.keys.push(address.key);
    }
    if (address.url) {
      point.urls.push(address.url);
    } else {
      log.warn(errorCodes.tag('STS-PKI-0128') + 'revocation: a distribution point of "' +
               target.link.subject + '" is not dialled: ' + address.why + '.');
      point.other.push('a name relative to its CRL issuer (' + address.why + ')');
      points.other.push('a name relative to its CRL issuer (' + address.why + ')');
    }
  });
  const usable = points.points.filter(function (one) { return one.urls.length > 0; });
  if (!usable.length) {
    log.debug('Leaving crlRoute(). Nothing fetchable.');
    return crlNoPointResult(points);
  }
  const certificateDeltas = distributionPointsOf(target.cert, OID.FRESHEST_CRL).fetchable;
  const key = target.issuerKey + '|' + target.serial;
  const problems = [];
  let covered = 0;
  let answered = null;
  for (let i = 0; i < usable.length; i++) {
    const point = usable[i];
    const context = crlContextFor(target, point);
    if (!context.ok) {
      problems.push(context.why);
      continue;
    }
    let got = null;
    for (let u = 0; u < point.urls.length && !got; u++) {
      const one = await listFrom(point.urls[u], Object.assign({ purpose: 'base' }, context));
      if (one.ok) {
        got = Object.assign({ url: point.urls[u] }, one);
      } else {
        problems.push(point.urls[u] + ': ' + one.why);
      }
    }
    if (!got) {
      continue;
    }
    const outOfScope = scopeProblem(got.list, target, point);
    if (outOfScope) {
      log.warn(errorCodes.tag('STS-PKI-0121') + 'revocation: the CRL at ' + got.url +
               ' does not cover "' + target.link.subject + '": ' + outOfScope + '.');
      problems.push(got.url + ': ' + outOfScope);
      continue;
    }
    const baseEntry = got.list.entries.get(key) || null;
    const deltaUrls = certificateDeltas.concat(got.list.freshest).filter(function (url, at, all) {
      return all.indexOf(url) === at;
    });
    let entry = baseEntry;
    let delta = null;
    if (deltaUrls.length) {
      delta = await deltaFor(context, Object.assign({ url: got.url }, got.list), deltaUrls);
      if (delta.ok) {
        entry = delta.entries.get(key) || null;
      } else if (!baseEntry || baseEntry.reasonCode === REASON_CERTIFICATE_HOLD ||
                 baseEntry.reasonCode === REASON_REMOVE_FROM_CRL) {
        problems.push(got.url + ': ' + delta.why);
        continue;
      }
    }
    if (entry && entry.reasonCode !== REASON_REMOVE_FROM_CRL) {
      log.debug('Leaving crlRoute(). Revoked.');
      return crlRevokedResult(target, got, context, delta, entry);
    }
    covered |= (point.reasons & got.list.idp.reasons);
    answered = { got: got, delta: delta, context: context };
    if ((covered & ALL_REASONS) === ALL_REASONS) {
      log.debug('Leaving crlRoute(). Good.');
      return {
        status: 'good', answeredBy: 'crl', crlUrl: got.url,
        crlNextUpdate: got.list.nextUpdate, crlFromCache: !!got.fromCache,
        deltaUrl: delta && delta.ok ? delta.url : '', indirect: context.indirect,
        why: 'the CRL at ' + got.url + (delta && delta.ok ? ' with its delta at ' + delta.url : '') +
             ', signed by ' + (context.indirect ? 'the CRL issuer the certificate names'
                                                : 'its issuer') +
             ' and fresh until ' + (got.list.nextUpdate || 'an unstated time') +
             ', does not list it'
      };
    }
  }
  if (answered && !problems.length) {
    log.debug('Leaving crlRoute(). Only some reasons covered.');
    return { status: 'unknown', kind: 'incomplete-reasons', refusable: true,
             crlUrl: answered.got.url,
             why: 'the lists it names cover only some revocation reasons between them ' +
                  '(RFC 5280 section 6.3.3), and the CRL at ' + answered.got.url +
                  ' does not list it for those' };
  }
  log.debug('Leaving crlRoute(). Unknown.');
  return { status: 'unknown', kind: 'unreachable', refusable: true,
           why: 'no distribution point it names produced a usable list — ' +
                problems.join('; ') };
}

// ---------------------------------------------------------------------------
// THE OCSP ROUTE: each responder the certificate names, until one answers in a
// response this file believes.
// ---------------------------------------------------------------------------
async function ocspRoute(target) {
  log.debug('Entering ocspRoute().');
  const responders = ocspRespondersOf(target.cert);
  if (!responders.fetchable.length) {
    log.debug('Leaving ocspRoute(). No responder.');
    return { status: 'unknown', none: true, kind: 'no-responder',
             why: responders.other.length
               ? 'it names only OCSP responders this service does not dial (' +
                 responders.other.join(', ') + ')'
               : 'it names no OCSP responder' };
  }
  const problems = [];
  for (let i = 0; i < responders.fetchable.length; i++) {
    const url = responders.fetchable[i];
    const got = await ocspFrom(url, target);
    if (!got.ok) {
      problems.push(url + ': ' + got.why);
      continue;
    }
    const answer = got.answer;
    const responderStatus = answer.responderStatus;
    // A DELEGATED RESPONDER WHOSE OWN STATUS COULD NOT BE ESTABLISHED is the
    // policy's question, decided per call rather than when the answer was cached:
    // hard-fail does not believe it, because blocking the responder's CRL is
    // exactly how a compromised responder's "good" would otherwise get in; and
    // soft-fail believes it and says so, because accepting what could not be
    // established is what soft-fail is.
    if (responderStatus && responderStatus.status === 'unknown' && responderStatus.refusable &&
        policy().effective === 'hard-fail') {
      log.warn(errorCodes.tag('STS-PKI-0127') + 'revocation: the answer from ' + url +
               ' is not used under hard-fail — its delegated responder\'s own status could ' +
               'not be established: ' + responderStatus.why + '.');
      problems.push(url + ': it was signed by a delegated responder whose own status could ' +
                    'not be established — ' + responderStatus.why);
      continue;
    }
    const facts = { answeredBy: 'ocsp', ocspUrl: url, ocspFromCache: !!got.fromCache,
                    ocspResponder: answer.responder, ocspNonce: answer.nonce,
                    ocspNextUpdate: answer.nextUpdate,
                    ocspResponderStatus: responderStatus ? responderStatus.status : '' };
    const by = answer.responder === 'delegated'
      ? 'a responder its issuer delegated ("' + answer.responderName + '", whose own status ' +
        'is ' + (responderStatus ? responderStatus.status + ': ' + responderStatus.why : 'unrecorded') +
        ')'
      : 'its issuer';
    log.debug('Leaving ocspRoute(). ' + answer.status);
    if (answer.status === 'revoked') {
      return Object.assign(facts, {
        status: 'revoked', reason: answer.reason, reasonCode: answer.reasonCode,
        revokedAt: answer.revokedAt,
        why: 'the OCSP responder at ' + url + ', in a response signed by ' + by +
             ', answers that it was revoked at ' + (answer.revokedAt || 'an unstated time') +
             ' (' + answer.reason + ')' });
    }
    if (answer.status === 'good') {
      return Object.assign(facts, {
        status: 'good',
        why: 'the OCSP responder at ' + url + ', in a response signed by ' + by +
             ' and fresh until ' + (answer.nextUpdate || 'pki.revocationOcspMaxAgeS runs out') +
             ', answers good' });
    }
    return Object.assign(facts, {
      status: 'unknown', kind: 'responder-unknown', refusable: true,
      why: 'the OCSP responder at ' + url + ', in a response signed by ' + by +
           ', answers UNKNOWN — it does not know this certificate' });
  }
  log.debug('Leaving ocspRoute(). Unknown.');
  return { status: 'unknown', kind: 'unreachable', refusable: true,
           why: 'no OCSP responder it names gave a usable answer — ' + problems.join('; ') };
}

// ---------------------------------------------------------------------------
// RESOLVE ONE FOREIGN LINK. Mutates the link.
//
// **THE ORDER IS `pki.revocationOcsp`, AND `first` IS THE DEFAULT FOR THREE
// REASONS.** An OCSP answer is about ONE certificate, so it is a few hundred
// bytes where a list is every revocation the issuer ever made; a responder is
// typically updated more often than a list is reissued, so it is the FRESHER
// answer; and a certificate that names a responder is one whose issuer chose to
// answer that way. The CRL is the fallback, and the fallback is what keeps a
// responder that is down from being the thing that turns revoked into unknown.
//
// Three rules decide between the two routes' answers:
//   * REVOKED from either route wins — a revocation is a signed fact, and no
//     second source can make it untrue;
//   * a signed `unknown` from a responder is NOT UPGRADED to good by a CRL. The
//     issuer's own responder saying it does not know this certificate is the
//     issuer disowning it, and a list that happens not to name it does not
//     answer that;
//   * a route that could not answer (unreachable, unusable) is replaced by the
//     other route's answer, and both reasons are kept on the link.
// A certificate is only a `no-distribution-point` unknown — the one hard-fail
// accepts by default — when NEITHER route had anything to dial.
// ---------------------------------------------------------------------------
function applyRouteResult(link, result, results) {
  log.debug('Entering applyRouteResult(). ' + result.status);
  ['answeredBy', 'crlUrl', 'crlNextUpdate', 'crlFromCache', 'deltaUrl', 'indirect',
   'ocspUrl', 'ocspFromCache', 'ocspResponder', 'ocspNonce', 'ocspNextUpdate',
   'ocspResponderStatus',
   'reason', 'reasonCode', 'revokedAt'].forEach(function (field) {
    if (result[field] !== undefined && result[field] !== '') {
      link[field] = result[field];
    }
  });
  link.status = result.status;
  const others = results.filter(function (one) {
    return one !== result && !one.none;
  }).map(function (one) { return one.why; });
  link.why = result.why + (others.length ? ' (and ' + others.join('; ') + ')' : '');
  if (result.status === 'unknown') {
    link.unknownKind = result.kind;
    link.refusable = !!result.refusable;
  }
  log.debug('Leaving applyRouteResult().');
}

function combinedUnknown(results) {
  const failed = results.filter(function (one) { return !one.none; });
  if (!failed.length) {
    return { status: 'unknown', kind: 'no-distribution-point',
             refusable: policy().requireDistributionPoint,
             why: results.map(function (one) { return one.why; }).join(', and ') };
  }
  return { status: 'unknown', kind: failed[0].kind, refusable: true,
           why: failed.concat(results.filter(function (one) { return one.none; }))
             .map(function (one) { return one.why; }).join('; and ') };
}

async function resolveForeign(link, verified, opts) {
  log.debug('Entering resolveForeign(). depth=' + link.depth);
  if (!link.issuerCert) {
    link.unknownKind = 'issuer-not-presented';
    link.refusable = true;
    const missing = opts && opts.issuerMissing && opts.issuerMissing(link);
    if (missing) {
      // A REGISTERED certificate's issuer is not presented by anybody: it is
      // looked for at the certificate's own caIssuers address, and the caller
      // says what its absence means. See `registeredVerdictFor()`.
      link.unknownKind = missing.kind;
      link.refusable = missing.refusable;
      link.why = missing.why;
    }
    log.debug('Leaving resolveForeign(). No issuer.');
    return;
  }
  if (!verified) {
    // See the header: an unverified chain names URLs anybody could have
    // written, so nothing is dialled for it.
    link.unknownKind = 'unverified-chain';
    link.refusable = false;
    link.why = 'signed by an authority this service does not hold, in a chain ' +
               'that did not verify — so no URL it names was dialled';
    log.debug('Leaving resolveForeign(). Not verified.');
    return;
  }
  const target = targetOf(link);
  if (!target) {
    link.unknownKind = 'unreadable';
    link.refusable = true;
    link.why = 'the certificate or its issuer could not be read closely enough to ' +
               'build an OCSP request or decide a CRL\'s scope';
    log.debug('Leaving resolveForeign(). Unreadable.');
    return;
  }
  const points = distributionPointsOf(link.cert);
  link.distributionPoints = points.fetchable.concat(points.other);
  const order = ocspOrder();
  link.ocspOrder = order;
  const routes = order === 'first' ? [ocspRoute, crlRoute]
    : (order === 'after-crl' ? [crlRoute, ocspRoute] : [crlRoute]);
  const results = [];
  for (let i = 0; i < routes.length; i++) {
    const result = await routes[i](target);
    results.push(result);
    if (result.status === 'revoked' ||
        (result.status === 'good' && !results.some(function (one) {
          return one.kind === 'responder-unknown';
        }))) {
      applyRouteResult(link, result, results);
      log.debug('Leaving resolveForeign(). ' + result.status);
      return;
    }
  }
  const signedUnknown = results.filter(function (one) {
    return one.kind === 'responder-unknown';
  })[0];
  if (signedUnknown) {
    applyRouteResult(link, signedUnknown, results);
  } else {
    // The combined sentence already carries every route's reason.
    applyRouteResult(link, combinedUnknown(results), []);
  }
  log.debug('Leaving resolveForeign(). Unknown.');
}

// Fold the links into one answer. Revoked anywhere is revoked; otherwise an
// unknown link makes the whole chain unknown; otherwise good.
function summarise(links, checked) {
  log.debug('Entering summarise(). ' + links.length + ' link(s).');
  const revoked = links.filter(function (one) { return one.status === 'revoked'; })[0];
  const unknown = links.filter(function (one) { return one.status === 'unknown'; });
  const status = revoked ? 'revoked' : (unknown.length ? 'unknown' : 'good');
  log.debug('Leaving summarise(). ' + status);
  return {
    status: status,
    checked: checked,
    revoked: revoked ? { depth: revoked.depth, subject: revoked.subject,
                         serialHex: revoked.serialHex, reason: revoked.reason,
                         reasonCode: revoked.reasonCode,
                         revokedAt: revoked.revokedAt, source: revoked.source,
                         answeredBy: revoked.answeredBy || '' }
                     : null,
    unknown: unknown.map(function (one) {
      return { depth: one.depth, subject: one.subject, kind: one.unknownKind || '',
               refusable: !!one.refusable, why: one.why };
    }),
    links: links.map(function (one) {
      const out = Object.assign({}, one);
      delete out.cert;
      delete out.issuerCert;
      delete out.offered;
      return out;
    })
  };
}

// ---------------------------------------------------------------------------
// THE ONE FUNCTION. Asynchronous because a foreign list may have to be
// fetched; never rejects.
// ---------------------------------------------------------------------------
async function verdictFor(input, options) {
  log.debug('Entering verdictFor().');
  const opts = options || {};
  const pol = policy();
  if (pol.effective === 'off') {
    log.debug('Leaving verdictFor(). Off.');
    return decide({ status: 'unchecked', checked: false, revoked: null,
                    unknown: [], links: [] }, pol);
  }
  let walked;
  try {
    walked = walk(input);
  } catch (e) {
    // A defect in this file must not become a refusal nobody can explain, nor
    // an acceptance nobody chose. It is an unknown, and the policy decides.
    log.error(errorCodes.tag('STS-PKI-0121') + 'revocation: walking a presented ' +
              'chain threw: ' + e.message);
    walked = { links: [{ depth: 0, status: 'unknown', source: 'error',
                         unknownKind: 'error', refusable: true,
                         why: 'the chain could not be walked: ' + e.message }],
               readable: true };
  }
  if (!walked.readable) {
    log.debug('Leaving verdictFor(). Unreadable.');
    return decide({ status: 'unknown', checked: true, revoked: null,
                    unknown: [{ depth: 0, kind: 'unreadable', refusable: false,
                                why: 'the certificate could not be read, so ' +
                                     'there is nothing to look up' }],
                    links: [] }, pol);
  }
  const locallyRevoked = walked.links.some(function (one) {
    return one.status === 'revoked';
  });
  const foreign = walked.links.filter(function (one) {
    return one.source === 'crl';
  });
  for (let i = 0; i < foreign.length; i++) {
    if (locallyRevoked || opts.external === 'not-consulted') {
      // ALREADY REVOKED BY THE REGISTER, or a door that never fetches. Nothing
      // is dialled: the answer cannot get better than revoked, and a
      // synchronous door has no way to wait.
      foreign[i].unknownKind = locallyRevoked ? 'not-needed' : 'not-consulted';
      foreign[i].refusable = false;
      continue;
    }
    await resolveForeign(foreign[i], !!(input && input.verified), opts);
  }
  log.debug('Leaving verdictFor().');
  return decide(summarise(walked.links, true), pol);
}

// The SYNCHRONOUS door: the register only, never a fetch. For a path this
// service built (`verifyLeaf()`) and for a surface with no revocation mechanism
// of its own for a foreign certificate (the SPIRE Server API).
function localVerdictFor(input) {
  log.debug('Entering localVerdictFor().');
  const pol = policy();
  if (pol.effective === 'off') {
    log.debug('Leaving localVerdictFor(). Off.');
    return decide({ status: 'unchecked', checked: false, revoked: null,
                    unknown: [], links: [] }, pol);
  }
  let walked;
  try {
    walked = walk(input);
  } catch (e) {
    log.error(errorCodes.tag('STS-PKI-0121') + 'revocation: walking a presented ' +
              'chain threw: ' + e.message);
    log.debug('Leaving localVerdictFor(). Threw.');
    return decide({ status: 'unknown', checked: true, revoked: null,
                    unknown: [{ depth: 0, kind: 'error', refusable: true,
                                why: 'the chain could not be walked: ' + e.message }],
                    links: [] }, pol);
  }
  walked.links.forEach(function (one) {
    if (one.source === 'crl') {
      one.unknownKind = 'not-consulted';
      one.refusable = false;
      one.why = 'signed by an authority this service does not hold; this door ' +
                'consults the register only';
    }
  });
  log.debug('Leaving localVerdictFor().');
  return decide(summarise(walked.links, true), pol);
}

// ---------------------------------------------------------------------------
// A REGISTERED CERTIFICATE, USED (2026-09-12).
//
// Everything above answers about a certificate somebody PRESENTED. This
// answers about one an operator WROTE DOWN — `oauthSamlAssertionCertificate`,
// the x5c of a key in `oauthAssertionJwks` or `oauthJwks`, a federation
// relationship's `fedSigningCertificate` — at the moment it is USED to verify
// something. The header said these were out of scope because *Take the key
// pair off* is the act that stops this service accepting them; that is still
// the act for a key an operator no longer wants, and it is not an answer for a
// key its ISSUER withdrew, which nobody here may have heard about.
//
// **SAME ANSWER, SAME POLICY, SAME TWO SOURCES.** A certificate one of this
// service's authorities signed is answered from the register; anybody else's
// from its OCSP responder and CRL, and `pki.revocationCheck` decides what an
// unknown means. Only the refusal code differs (STS-PKI-0129), because "a
// client presented a revoked certificate" and "a key an operator registered
// has been revoked since" send an operator to two different places.
//
// **WHY DIALLING ITS ADDRESSES IS ALLOWED.** The presented case dials only for a
// chain that verified against an installed anchor. A registered certificate has
// no anchor and needs none: the operator installed THE CERTIFICATE ITSELF, which
// is a stronger statement than installing a CA that signed it. So the URLs it
// carries were written by an authority the operator chose — the same argument
// reached one step shorter.
//
// **ITS ISSUER IS FETCHED, BECAUSE NOTHING PRESENTS IT.** A registered leaf
// usually arrives alone. The issuer is looked for in whatever chain was
// registered with it, among this service's authorities, and then at the
// certificate's OWN caIssuers address (RFC 5280 section 4.2.2.1), hop by hop,
// each fetched certificate believed only because its key verifies the one below
// it. A certificate that names no caIssuers address and whose issuer is nowhere
// here gives an attacker nothing to block, so it is refused only under
// `pki.revocationRequireDistributionPoint` — the no-distribution-point argument
// made again. One that names an address that could not be fetched IS
// refusable under hard-fail: that fetch is exactly what an attacker blocks.
//
// **A BARE KEY IS REPORTED, NOT PRETENDED ABOUT.** A JWK with no x5c has no
// issuer, no serial and no list; there is nothing to look up, and the verdict
// says so (`status: 'unchecked'`, `bare: true`) rather than answering `good`.
//
// **ONE DOOR, ASYNCHRONOUS.** There is no register-only twin of this, as there
// is of `verdictFor()`: every place that uses a registered certificate — the
// RFC 7523 and RFC 7522 grants and client authentication, the federation
// consumer in all five protocols, the OID4VP response endpoint — was made to
// wait for it, because a registered certificate is usually somebody else's and
// the register alone would answer nothing about it.
// ---------------------------------------------------------------------------
const CODE_REGISTERED = 'STS-PKI-0129';

// One certificate out of whatever spelling it was registered in: PEM, base64
// DER (what `fedSigningCertificate` and an x5c member hold), DER bytes or a
// parsed certificate.
function registeredCertificateOf(value) {
  if (!value) {
    return null;
  }
  if (Buffer.isBuffer(value) || value instanceof nodeCrypto.X509Certificate) {
    return x509Of(value);
  }
  const text = String(value).trim();
  if (!text) {
    return null;
  }
  if (/-----BEGIN/.test(text)) {
    return x509Of(text);
  }
  return x509Of(Buffer.from(text.replace(/\s+/g, ''), 'base64'));
}

function registeredChainOf(value) {
  log.debug('Entering registeredChainOf().');
  const out = [];
  (Array.isArray(value) ? value : [value]).forEach(function (one) {
    if (!one) {
      return;
    }
    const pems = typeof one === 'string' ? one.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) : null;
    (pems || [one]).forEach(function (each) {
      const cert = registeredCertificateOf(each);
      if (cert) {
        out.push(cert);
      }
    });
  });
  log.debug('Leaving registeredChainOf(). ' + out.length + ' certificate(s).');
  return out;
}

// The material a registered JWK carries: its x5c, or nothing, which is a bare key.
function registeredKeyMaterial(jwk, source) {
  const x5c = jwk && Array.isArray(jwk.x5c) ? jwk.x5c : [];
  return { certificate: x5c[0] || '', chain: x5c.slice(1), source: source || 'a registered key',
           kid: (jwk && jwk.kid) || '' };
}

// The issuers above `leaf` that nothing presented, fetched from each hop's own
// caIssuers address. Stops at a self-signed certificate, at one this service
// signed (the register answers from there), or where an issuer is already in
// the registered chain.
async function issuersFetchedFor(leaf, offered) {
  log.debug('Entering issuersFetchedFor().');
  const fetched = [];
  const problems = [];
  let named = false;
  let current = leaf;
  for (let depth = 0; depth < MAX_DEPTH && current; depth++) {
    if (selfSigned(current) || localIssuerOf(current)) {
      break;
    }
    const at = current;
    const inHand = offered.concat(fetched).filter(function (one) { return signedBy(at, one); })[0];
    if (inHand) {
      current = inHand;
      continue;
    }
    const parsedCert = pkijsOf(current);
    const urls = parsedCert ? caIssuersOf(parsedCert.extensions || []) : [];
    if (!urls.length) {
      break;
    }
    named = named || depth === 0;
    let found = null;
    for (let i = 0; i < urls.length && !found; i++) {
      const got = await certificatesFrom(urls[i]);
      if (!got.ok) {
        problems.push(urls[i] + ': ' + got.why);
        continue;
      }
      found = got.certs.filter(function (one) { return signedBy(at, one); })[0] || null;
      if (!found) {
        problems.push(urls[i] + ': none of the ' + got.certs.length + ' certificate(s) there ' +
                      'signed "' + at.subject.replace(/\n/g, ', ') + '"');
      }
    }
    if (!found) {
      break;
    }
    fetched.push(found);
    current = found;
  }
  log.debug('Leaving issuersFetchedFor(). ' + fetched.length + ' fetched.');
  return { certs: fetched, problems: problems, named: named };
}

function bareRegisteredVerdict(source) {
  return decide({ status: 'unchecked', checked: false, revoked: null, unknown: [], links: [],
                  registered: true, bare: true, source: source }, policy());
}

// Stamp a verdict as being about registered material, and move its refusal code
// to the registered one.
function asRegistered(verdict, material, extra) {
  verdict.registered = true;
  verdict.bare = false;
  verdict.source = material.source || 'a registered certificate';
  Object.keys(extra || {}).forEach(function (key) { verdict[key] = extra[key]; });
  if (verdict.refused) {
    verdict.why = 'The certificate ' + verdict.source + ' names: ' + verdict.why;
    return errorCodes.mark(verdict, CODE_REGISTERED);
  }
  return verdict;
}

async function registeredVerdictFor(material) {
  log.debug('Entering registeredVerdictFor().');
  const m = material || {};
  const source = m.source || 'a registered certificate';
  const leaf = registeredCertificateOf(m.certificate);
  if (!leaf) {
    const bare = bareRegisteredVerdict(source);
    bare.why = 'Nothing to check: ' + source + ' is a bare key with no certificate, so it has ' +
               'no issuer, no serial and no list that could revoke it. Taking it off the ' +
               'entry is the only way to stop it verifying.';
    log.debug('Leaving registeredVerdictFor(). Bare key.');
    return bare;
  }
  const pol = policy();
  if (pol.effective === 'off') {
    log.debug('Leaving registeredVerdictFor(). Off.');
    return asRegistered(decide({ status: 'unchecked', checked: false, revoked: null,
                                 unknown: [], links: [] }, pol), m);
  }
  const offered = registeredChainOf(m.chain);
  const found = await issuersFetchedFor(leaf, offered);
  const verdict = await verdictFor({ leaf: leaf, chain: offered.concat(found.certs), verified: true }, {
    issuerMissing: function (link) {
      if (found.problems.length) {
        return { kind: 'issuer-not-fetched', refusable: true,
                 why: '"' + String(link.subject || '').replace(/\n/g, ', ') + '" names a ' +
                      'caIssuers address and its issuer could not be taken from it — ' +
                      found.problems.join('; ') };
      }
      return { kind: 'no-distribution-point', refusable: pol.requireDistributionPoint,
               why: '"' + String(link.subject || '').replace(/\n/g, ', ') + '" was issued by ' +
                    'an authority that is neither held here nor registered with it, and it ' +
                    'names no caIssuers address to fetch it from, so nothing can verify a ' +
                    'list about it' };
    }
  });
  log.debug('Leaving registeredVerdictFor(). ' + verdict.status);
  return asRegistered(verdict, m, { issuersFetched: found.certs.map(function (one) {
    return one.subject.replace(/\n/g, ', ');
  }) });
}

// A registered JWK: its x5c answered as above, or reported bare.
function registeredKeyVerdictFor(jwk, source) {
  return registeredVerdictFor(registeredKeyMaterial(jwk, source));
}

// A short sentence for a door's audit row and log line.
function registeredSummary(verdict) {
  if (!verdict) {
    return '';
  }
  if (verdict.bare) {
    return 'revocation: not checked (a bare key has no certificate)';
  }
  return 'revocation: ' + verdict.status + (verdict.refused ? ' (refused)' : '') +
         ' under ' + verdict.policy;
}

// ---------------------------------------------------------------------------
// THE POLICY APPLIED. Sets `refused`, `policy` and a sentence, and marks the
// verdict with its refusal code non-enumerably.
// ---------------------------------------------------------------------------
function decide(verdict, pol) {
  log.debug('Entering decide(). status=' + verdict.status);
  const p = pol || policy();
  verdict.policy = p.effective;
  verdict.policyConfigured = p.configured;
  if (verdict.status === 'unchecked') {
    verdict.refused = false;
    verdict.why = 'Revocation is not consulted (pki.revocationCheck is off).';
    log.debug('Leaving decide(). Not consulted.');
    return verdict;
  }
  if (verdict.status === 'revoked') {
    verdict.refused = true;
    verdict.why = 'REVOKED: "' + verdict.revoked.subject + '" (serial ' +
                  verdict.revoked.serialHex + ') was revoked at ' +
                  (verdict.revoked.revokedAt || 'an unstated time') + ' for "' +
                  (verdict.revoked.reason || 'unspecified') + '", according to ' +
                  (verdict.revoked.source === 'register'
                    ? 'this service\'s own register'
                    : (verdict.revoked.answeredBy === 'ocsp'
                        ? 'its issuer\'s OCSP responder' : 'its issuer\'s CRL')) + '.';
    log.debug('Leaving decide(). Refused: revoked.');
    return errorCodes.mark(verdict, CODE_REVOKED);
  }
  if (verdict.status === 'unknown') {
    const refusable = verdict.unknown.filter(function (one) { return one.refusable; });
    verdict.refused = p.effective === 'hard-fail' && refusable.length > 0;
    verdict.why = (verdict.refused
      ? 'REFUSED UNDER HARD-FAIL: the revocation status could not be established — '
      : 'Status unknown and accepted (' + p.effective + '): ') +
      verdict.unknown.map(function (one) { return one.why; }).join('; ') + '.';
    log.debug('Leaving decide(). Unknown, refused=' + verdict.refused);
    return verdict.refused ? errorCodes.mark(verdict, CODE_UNKNOWN) : verdict;
  }
  verdict.refused = false;
  verdict.why = 'Not revoked: every certificate in the chain was looked up ' +
                'and none is on a list.';
  log.debug('Leaving decide(). Good.');
  return verdict;
}

// ---------------------------------------------------------------------------
// THE MAIN PORT'S ANNOTATION, and the reason it is a middleware.
//
// The doors on the main port that accept a certificate — `mtls.peerVerified()`
// (the XACML PEP and XACML user chains), SCIM's client-certificate scheme and
// RFC 8705 client authentication — are SYNCHRONOUS, and a foreign list may need
// a fetch. So `common/app.js` computes the verdict once, before any route, onto
// `req.certificateRevocation`, and those doors READ it. That is still refusing
// at the point the certificate is USED: the annotation refuses nothing, and a
// request that never reaches a door that reads it is unaffected.
//
// It runs in whichever process answers the request — in a request worker for a
// dispatched one — which is where the certificate is evaluated, and where the
// register is visible because it is a `pki:` row every process holds.
// ---------------------------------------------------------------------------
async function annotateRequest(req) {
  log.debug('Entering annotateRequest().');
  try {
    const input = fromSocket(req && req.socket);
    if (!input) {
      log.debug('Leaving annotateRequest(). No certificate.');
      return null;
    }
    req.certificateRevocation = await verdictFor(input);
    log.debug('Leaving annotateRequest(). ' + req.certificateRevocation.status);
    return req.certificateRevocation;
  } catch (e) {
    // A request must not hang or fail because the annotation did. Nothing is
    // set, and every door reads an absent verdict as "not consulted".
    log.error(errorCodes.tag('STS-PKI-0121') + 'revocation: annotating a request ' +
              'failed and was skipped: ' + e.message);
    log.debug('Leaving annotateRequest(). Threw.');
    return null;
  }
}

// What a door reads. Null when nothing was annotated.
function requestVerdict(req) {
  return (req && req.certificateRevocation) || null;
}

// The refusal code a refused verdict carries, for a door that marks a response.
function codeOf(verdict) {
  return errorCodes.codeOf(verdict) ||
         (verdict && verdict.status === 'revoked' ? CODE_REVOKED : CODE_UNKNOWN);
}

// ---------------------------------------------------------------------------
// WHAT EVERY SURFACE SAYS. One sentence, so /tls, /admin/pki, the crypto report
// and the mode page cannot describe the policy four ways.
// ---------------------------------------------------------------------------
function describePolicy() {
  log.debug('Entering describePolicy().');
  const p = policy();
  const out = {
    configured: p.configured,
    effective: p.effective,
    decidedBy: p.decidedBy,
    requireDistributionPoint: p.requireDistributionPoint,
    consultedAt: ['the 8443 and 9443 listeners (a session and the recorded ' +
                  'authentication)', 'the main port (the remote XACML PEP and ' +
                  'XACML user chains, SCIM\'s client-certificate scheme, RFC 8705 ' +
                  'client authentication)', 'the SPIRE Server API (the register ' +
                  'only)', 'an RFC 7523 assertion\'s x5c chain (the register only)'],
    ocsp: ocspOrder(),
    ocspRequiresNonce: config.value('pki.revocationOcspRequireNonce') === true,
    clockSkewS: skewMs() / 1000,
    crlIssuersFile: String(config.value('pki.revocationCrlIssuersFile') || ''),
    notConsultedAt: ['LDAPS 636, which asks for no client certificate',
                     'a key or certificate REGISTERED on an application entry',
                     'RFC 8705 token binding, which authenticates nobody',
                     'a delegated OCSP responder\'s own revocation status',
                     'a CRL or responder at an ldap: or other non-http address, ' +
                     'and a CRL issuer\'s certificate that would have to be ' +
                     'fetched'],
    sentence: p.effective === 'off'
      ? 'CONSULTED NOWHERE: pki.revocationCheck is off, so a presented ' +
        'certificate is checked against its anchors and against no list.'
      : 'CONSULTED, ' + p.effective.toUpperCase() + ' (' + p.decidedBy + '). A ' +
        'presented certificate this service issued is looked up in its own ' +
        'register — the whole chain, including the tiers it did not send — and ' +
        'one from another authority, for a chain that verified, ' +
        (ocspOrder() === 'first'
          ? 'by the OCSP responder it names, falling back to the CRL it names'
          : (ocspOrder() === 'after-crl'
              ? 'by the CRL it names, falling back to the OCSP responder it names'
              : 'by the CRL it names (OCSP is off)')) +
        ', over http or https, with delta CRLs merged and indirect CRLs read ' +
        'per issuer. A revoked certificate is refused; ' +
        (p.effective === 'hard-fail'
          ? 'so is one whose status could not be fetched, verified or trusted as ' +
            'fresh, or that the responder does not know' + (p.requireDistributionPoint
              ? ', and one whose issuer names no list and no responder at all.'
              : ' (one whose issuer names no list and no responder at all is ' +
                'accepted, because there is nothing an attacker could block).')
          : 'one whose status could not be established is accepted and reported.') +
        ' LDAPS 636 requests no client certificate.'
  };
  log.debug('Leaving describePolicy().');
  return out;
}

function cacheReport() {
  const out = [];
  crlCache.forEach(function (entry, key) {
    out.push({ url: entry.url, signerFingerprints: key.split('|')[1] || '',
               delta: !!entry.isDelta, indirect: !!entry.idp.indirect,
               entries: entry.entries.size, fetchedAt: entry.fetchedAt,
               nextUpdate: entry.nextUpdate,
               expiresAt: new Date(entry.expiresAt).toISOString() });
  });
  const responses = [];
  ocspCache.forEach(function (entry) {
    responses.push({ url: entry.url, status: entry.status, responder: entry.responder,
                     nonce: entry.nonce, fetchedAt: entry.fetchedAt,
                     nextUpdate: entry.nextUpdate,
                     expiresAt: new Date(entry.expiresAt).toISOString() });
  });
  return { lists: out, ocspResponses: responses, failures: failures.size };
}

// For a test: forget every cached list and failure.
function resetCache() {
  crlCache.clear();
  ocspCache.clear();
  failures.clear();
  inFlight.clear();
  parsed.clear();
  certCache.clear();
  pemFiles.clear();
}

module.exports = {
  POLICIES: POLICIES,
  CODE_REVOKED: CODE_REVOKED,
  CODE_UNKNOWN: CODE_UNKNOWN,
  policy: policy,
  verdictFor: verdictFor,
  localVerdictFor: localVerdictFor,
  registeredVerdictFor: registeredVerdictFor,
  registeredKeyVerdictFor: registeredKeyVerdictFor,
  registeredKeyMaterial: registeredKeyMaterial,
  registeredSummary: registeredSummary,
  parseLdapUrl: parseLdapUrl,
  CODE_REGISTERED: CODE_REGISTERED,
  decide: decide,
  fromSocket: fromSocket,
  annotateRequest: annotateRequest,
  requestVerdict: requestVerdict,
  codeOf: codeOf,
  distributionPointsOf: distributionPointsOf,
  ocspRespondersOf: ocspRespondersOf,
  describePolicy: describePolicy,
  cacheReport: cacheReport,
  resetCache: resetCache
};
