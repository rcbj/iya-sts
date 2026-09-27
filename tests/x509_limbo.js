'use strict';
//
// File: x509_limbo.js
//
// ===========================================================================
// C2SP x509-LIMBO AGAINST EVERY CERTIFICATE PATH VALIDATOR IN THIS SERVICE
// (#201, 2026-09-24).
//
// x509-limbo (github.com/C2SP/x509-limbo, Apache-2.0) is about ten thousand
// X.509 path-validation testcases — name constraints, key usage and EKU,
// basic constraints and path length, validity, signature algorithms, CRLs,
// pathological path building and the Web PKI's rules — each a set of trusted
// certificates, untrusted intermediates, a leaf, a validation time and the
// answer a conforming validator gives. This file feeds every one of them to
// every validator here that can be handed a case, and compares.
//
// THE CORPUS IS NOT IN THIS REPOSITORY. About two hundred of its cases carry
// the leaf's private key, and nothing here commits key material; the tests
// image fetches `limbo.json` at a pinned commit and refuses it unless its
// SHA-256 is the recorded one (`tools/fetch-x509-limbo.sh`,
// `STS_X509_LIMBO_DIR`). Run anywhere else, this file FAILS naming that
// variable: a conformance run that quietly ran nothing is the failure this
// directory exists to prevent. NIST PKITS is NOT in the corpus — the ticket
// supposed it might be, and at the pinned commit no testcase names it.
//
// ---------------------------------------------------------------------------
// THE VALIDATORS, AND WHICH DRIVER REACHES EACH.
//
// Every certificate path this service checks is checked by one of four pieces
// of code, and #201 made the first three one set of rules
// (`pki.pathRuleProblem()`):
//
//   anchors   `pki.verifyPathToAnchors()` — a path to anchors a caller names:
//             WebAuthn attestation (and the FIDO MDS BLOB), SPIFFE's x509pop,
//             tpm_devid and azure_imds attestors, sigstore. Every case.
//   signer    `pki.verifySignerChain()` — the certificate behind a key that
//             verified an assertion: RFC 7523 and 7522 grants and client
//             authentication, JAR, software statements, the hosted surfaces'
//             ID Tokens. Its registered-root branch is driven, the case's
//             certificates registered as the chain; its realm branch is
//             `verifyLeaf()`, whose anchor is this service's own Root and
//             which asks the same `authorityProblem()`. Every case.
//   direct    `pki.verifyIssuedDirectly()` — the synchronous one-hop door:
//             the SPIRE Server and Broker API's caller check
//             (`spiffe_auth.ts`) and an OpenID4VCI key attestation's x5c
//             (`vc_issuer.ts`). Every case.
//   crl       `revocation_status.crlInHandVerdict()` — the CRL reader every
//             foreign revocation answer comes from, on the path `anchors`
//             built. The seventeen `crl::` cases.
//   inbound   OpenSSL, as node's TLS runs it on the main port: `requestCert`,
//             `rejectUnauthorized: false`, the truststore as `ca`, and
//             `socket.authorized` — what certificate sign-in, RFC 8705, the
//             XACML gate and the portal read. The CLIENT cases that carry
//             the leaf's key (a handshake needs it).
//   outbound  OpenSSL, as `common/outbound_tls.ts` configures an outbound
//             request (#171): the CA file beside node's store, verification
//             on, the host name checked. The SERVER cases that carry a key.
//
// A validator DISAGREEING with limbo is one of two things, and the file says
// which for every disagreement: a documented EXCEPTION — a rule this service
// deliberately does not apply, or a case the driver cannot put to that
// validator faithfully, each with its reason in `EXCEPTIONS` below — or a
// FAILURE, which fails this file. An exception that no longer matches
// anything also fails it, so the list cannot outlive what it excuses.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const tls = require('tls');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'x509_limbo',
  level: process.env.LOG_LEVEL || 'info' });

// The pin `tools/fetch-x509-limbo.sh` fetches, and the count at that pin. A
// corpus that is not this one is refused before anything runs.
const LIMBO_COMMIT = '554528a9b0c0d95e071f55de018326f0b65a8364';
const LIMBO_CASES = 9802;

// ---------------------------------------------------------------------------
// THE CLOCK. A case names its validation time; the validators read the clock
// (the vendored engine's `new Date()`, `Date.now()` in the CRL reader), so a
// case is run with `Date` replaced by one whose "now" is the case's. Restored
// in a `finally`, and never across an `await` that is not the case's own.
// ---------------------------------------------------------------------------
const RealDate = Date;

async function atTime(ms, work) {
  log.debug("Entering atTime().");
  if (ms === null) {
    log.debug("Leaving atTime(). Real time.");
    return work();
  }
  class CaseDate extends RealDate {
    constructor(...args) {
      if (args.length === 0) {
        super(ms);
      } else {
        // @ts-ignore — a spread into Date's overloads.
        super(...args);
      }
    }

    static now() {
      return ms;
    }
  }
  global.Date = /** @type {any} */ (CaseDate);
  try {
    const out = await work();
    log.debug("Leaving atTime().");
    return out;
  } finally {
    global.Date = RealDate;
  }
}

function derOf(pem) {
  log.debug("Entering derOf().");
  log.debug("Leaving derOf().");
  return Buffer.from(String(pem).replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, ''), 'base64');
}

// ---------------------------------------------------------------------------
// FACTS THE EXCEPTIONS ARE DECIDED ON. None of them is the validator under
// test deciding its own case: host-name matching is RFC 9525 over the
// subjectAltName only, written here; purposes are read off the certificates.
// ---------------------------------------------------------------------------
function x509Of(pem) {
  log.debug("Entering x509Of().");
  try {
    const one = new nodeCrypto.X509Certificate(pem);
    log.debug("Leaving x509Of().");
    return one;
  } catch (e) {
    log.debug("Caught in x509Of(): " + ((e && e.message) || e));
    log.debug("Leaving x509Of(). Unreadable.");
    return null;
  }
}

// Does the leaf's subjectAltName name the case's expected peer (RFC 9525:
// DNS-ID and IP-ID only, a wildcard only as the whole left-most label, no
// common-name fallback)? true when the case names no peer.
function peerNameMatches(t) {
  log.debug("Entering peerNameMatches().");
  const want = t.expected_peer_name;
  if (!want) {
    log.debug("Leaving peerNameMatches(). No peer named.");
    return true;
  }
  const leaf = x509Of(t.peer_certificate);
  const san = leaf ? String(leaf.subjectAltName || '') : '';
  const entries = san ? san.split(/,\s*/) : [];
  let matched = false;
  entries.forEach(function (entry) {
    const at = entry.indexOf(':');
    const kind = entry.slice(0, at);
    const value = entry.slice(at + 1);
    if (want.kind === 'DNS' && kind === 'DNS') {
      const host = String(want.value).toLowerCase();
      const name = value.toLowerCase();
      if (name === host) {
        matched = true;
      } else if (/^\*\.[^*]+$/.test(name)) {
        const rest = name.slice(1);
        const dot = host.indexOf('.');
        if (dot > 0 && host.slice(dot) === rest) {
          matched = true;
        }
      }
    } else if (want.kind === 'IP' && kind === 'IP Address') {
      matched = matched || value.toLowerCase() === String(want.value)
        .toLowerCase();
    }
  });
  log.debug("Leaving peerNameMatches(). " + matched);
  return matched;
}

// The extKeyUsage purposes a certificate states, or null when it states none.
function ekusOf(pem) {
  log.debug("Entering ekusOf().");
  const one = x509Of(pem);
  const ekus = one && one.keyUsage ? one.keyUsage.slice(0) : null;
  log.debug("Leaving ekusOf().");
  return ekus;
}

// Does any certificate the case supplies restrict a purpose the case's kind
// needs — the leaf's EKU without serverAuth (clientAuth for a CLIENT case),
// or an intermediate's, which the Web PKI and OpenSSL read as nesting?
const SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
const CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';
const ANY_EKU = '2.5.29.37.0';

function purposeRestricted(t) {
  log.debug("Entering purposeRestricted().");
  const want = t.validation_kind === 'CLIENT' ? CLIENT_AUTH : SERVER_AUTH;
  const restricts = [t.peer_certificate].concat(t.untrusted_intermediates)
    .concat(t.trusted_certs).some(function (pem) {
      const ekus = ekusOf(pem);
      return !!ekus && ekus.indexOf(want) < 0;
    });
  log.debug("Leaving purposeRestricted(). " + restricts);
  return restricts;
}

// Is some certificate the case supplies valid at one of the two times and not
// the other? A TLS handshake runs at the real time, never the case's.
function clockSensitive(t) {
  log.debug("Entering clockSensitive().");
  if (!t.validation_time) {
    log.debug("Leaving clockSensitive(). No time named.");
    return false;
  }
  // At the granularity a certificate's times are written in, as the
  // validators compare (`pki.pathValidityProblem()`).
  const then = Math.floor(RealDate.parse(t.validation_time) / 1000) * 1000;
  const now = RealDate.now();
  const sensitive = [t.peer_certificate].concat(t.untrusted_intermediates)
    .concat(t.trusted_certs).some(function (pem) {
      const one = x509Of(pem);
      if (!one) {
        return false;
      }
      const from = RealDate.parse(one.validFrom);
      const to = RealDate.parse(one.validTo);
      return (from <= then && then <= to) !== (from <= now && now <= to);
    });
  log.debug("Leaving clockSensitive(). " + sensitive);
  return sensitive;
}

// Is some trusted certificate not self-signed, or some untrusted one
// self-signed? The signer driver registers the case's certificates as a
// chain, and a registration makes EVERY self-signed certificate in it an
// anchor and none of the others.
function registrationDiffers(t) {
  log.debug("Entering registrationDiffers().");
  const selfSigned = function (pem) {
    log.debug("Entering selfSigned().");
    const one = x509Of(pem);
    let yes = false;
    try {
      yes = !!one && one.subject === one.issuer && one.verify(one.publicKey);
    } catch (e) {
      log.debug("Caught in selfSigned(): " + ((e && e.message) || e));
      yes = !!one && one.subject === one.issuer;
    }
    log.debug("Leaving selfSigned().");
    return yes;
  };
  const differs = t.trusted_certs.some(function (pem) {
    return !selfSigned(pem);
  }) || t.untrusted_intermediates.some(selfSigned);
  log.debug("Leaving registrationDiffers(). " + differs);
  return differs;
}

function leafIsCa(t) {
  log.debug("Entering leafIsCa().");
  const one = x509Of(t.peer_certificate);
  log.debug("Leaving leafIsCa().");
  return !!one && !!one.ca;
}

function hasPrefix(t, prefixes) {
  log.debug("Entering hasPrefix().");
  log.debug("Leaving hasPrefix().");
  return prefixes.some(function (p) { return t.id.indexOf(p) === 0; });
}

// ---------------------------------------------------------------------------
// THE EXCEPTIONS. Each is one rule this service deliberately does not apply,
// or one thing a driver cannot put to its validator, with the reason — the
// record #201 asks for. `drivers` says where it applies; `applies(t, v)`
// decides it from the case and the verdict (`v.ok` the validator's answer).
// An exception excuses only a DISAGREEMENT: a case the validator answers as
// limbo does is never counted against one.
// ---------------------------------------------------------------------------
const PATH_DRIVERS = ['anchors', 'signer', 'direct'];
const RULE_DRIVERS = PATH_DRIVERS.concat(['outbound']);

const EXCEPTIONS = [
  { id: 'revocation-is-its-own-door',
    drivers: RULE_DRIVERS,
    reason: 'The case is about a CRL (limbo `crl::`). A path validator ' +
      'here builds and checks the path; revocation is ' +
      '`revocation_status.js`\'s, asked afterwards through the door each ' +
      'surface uses, and its CRL reader is driven by the `crl` driver on ' +
      'exactly these cases. OpenSSL is given no CRL at the handshake.',
    applies: function (t) { return hasPrefix(t, ['crl::']); } },
  { id: 'host-name-is-not-this-validators',
    drivers: PATH_DRIVERS,
    reason: 'limbo expects the path refused because the leaf does not name ' +
      'the peer (RFC 9525) — or names it only in a form the Web PKI refuses ' +
      '(the webpki `san::` and `cn::` cases). These validators are asked ' +
      'who SIGNED a certificate, never which host it is for: an ' +
      'attestation, an assertion signer and an SVID are not host names. ' +
      'The host check is the `outbound` driver\'s, where one is made.',
    applies: function (t, v) {
      return v.ok && t.expected_result === 'FAILURE' &&
             (!peerNameMatches(t) ||
              hasPrefix(t, ['webpki::san::', 'webpki::cn::']));
    } },
  { id: 'purpose-is-the-callers',
    drivers: PATH_DRIVERS,
    reason: 'limbo expects the path refused for its extKeyUsage — the leaf ' +
      'lacks serverAuth, or an intermediate\'s EKU does not nest it (the ' +
      'Web PKI\'s and OpenSSL\'s reading; RFC 5280 does not chain EKU). ' +
      'The purpose is each CALLER\'s question, as Go\'s ExtKeyUsageAny ' +
      'leaves it: an EK certificate carries no EKU, an SVID names ' +
      'clientAuth and serverAuth, a JWS signing key none of the TLS ones.',
    applies: function (t, v) {
      return v.ok && t.expected_result === 'FAILURE' &&
             (purposeRestricted(t) || hasPrefix(t, ['webpki::eku::',
                                                    'rfc5280::eku::']));
    } },
  { id: 'issuer-profile-rules',
    drivers: RULE_DRIVERS,
    reason: 'RFC 5280 section 4 rules on what a conforming CA ISSUES that ' +
      'section 6 does not ask a relying party to check: an ' +
      'authorityKeyIdentifier on every non-root and non-critical, a ' +
      'subjectKeyIdentifier on every CA and non-critical, a serial of at ' +
      'most 20 octets and not zero (4.1.2.2 asks relying parties to handle ' +
      'a non-conforming one gracefully), basicConstraints, ' +
      'policyConstraints and nameConstraints marked critical — every one ' +
      'of those constraints is still ENFORCED as written. Refusing them ' +
      'would refuse Android Keystore and TPM EK attestation chains, which ' +
      'omit identifiers, and protect nothing the path check does not.',
    applies: function (t, v) {
      return v.ok && t.expected_result === 'FAILURE' &&
             hasPrefix(t, ['rfc5280::aki::', 'rfc5280::ski::',
                           'rfc5280::serial::',
                           'rfc5280::root-non-critical-basic-constraints',
                           'rfc5280::pc::ica-noncritical-pc',
                           'rfc5280::nc::permitted-dns-match-noncritical',
                           'webpki::aki::']);
    } },
  { id: 'dnsname-spelling-unconstrained',
    drivers: RULE_DRIVERS,
    reason: 'A dNSName that is not in preferred name syntax (an underscore, ' +
      'an IP address written as a DNS name) where NO name constraint ' +
      'reaches it. Where one does, the spelling is checked and the path ' +
      'refused (`nc-permits-invalid-dns-san`). A name no constraint limits ' +
      'decides nothing the path validators are asked; an outbound request ' +
      'dials a host an operator or a registration named, and the ' +
      'certificate names exactly that host (an IP address written as a ' +
      'DNS name never matches an IP host: RFC 9525 compares IP-IDs only).',
    applies: function (t, v) {
      return v.ok && t.expected_result === 'FAILURE' &&
             hasPrefix(t, ['rfc5280::san::underscore-dns',
                           'rfc5280::san::ip-in-dns']);
    } },
  { id: 'web-pki-only',
    drivers: RULE_DRIVERS,
    reason: 'A CA/Browser Forum Baseline Requirements rule, not RFC 5280: ' +
      'key sizes and algorithms (RSA under 2048 bits or not a multiple of ' +
      '8, DSA, P-192), X.509 v1 leaves, a CA certificate or cA=TRUE as a ' +
      'leaf, a malformed non-critical Authority Information Access nothing ' +
      'here reads, a critical subjectAltName beside a non-empty subject. ' +
      'This service is not a Web PKI client; the certificates it validates ' +
      'are attestations, assertion signers and SVIDs, whose profiles are ' +
      'their own specifications\'.',
    applies: function (t, v) {
      return v.ok && t.expected_result === 'FAILURE' &&
             hasPrefix(t, ['webpki::forbidden-', 'webpki::v1-cert',
                           'webpki::ee-basicconstraints-ca',
                           'webpki::ca-as-leaf', 'webpki::malformed-aia',
                           'webpki::san::san-critical-with-nonempty-subject',
                           'rfc5280::ca-as-leaf-wrong-san']);
    } },
  { id: 'web-pki-host-rules',
    drivers: ['outbound'],
    reason: 'Three more CA/Browser Forum rules, on the one validator that ' +
      'makes a host check. That a subject common name repeat a ' +
      'subjectAltName entry character for character (BR 7.1.4.3) — the ' +
      'host check here never reads the common name at all (RFC 9525 ' +
      'section 6.3), so what it says decides nothing. That a server leaf ' +
      'carry serverAuth and nothing else ' +
      '(OpenSSL\'s TLS-server purpose, as RFC 5280 section 4.2.1.12 reads ' +
      'it, accepts a leaf with no extKeyUsage — every purpose — and one ' +
      'naming anyExtendedKeyUsage, and does not read EKU on a root), and ' +
      'that a wildcard not cover a whole public suffix (the Public Suffix ' +
      'List is the Web PKI\'s data; a private CA here may name what it ' +
      'likes under its own namespace).',
    applies: function (t, v) {
      return v.ok && t.expected_result === 'FAILURE' &&
             hasPrefix(t, ['webpki::eku::', 'webpki::cn::',
                           'webpki::san::public-suffix-']);
    } },
  { id: 'no-caller-sets-a-depth',
    drivers: RULE_DRIVERS,
    reason: 'The case sets `max_chain_depth`, a parameter of the validator. ' +
      'No caller here sets one: the builder\'s own bound is ' +
      'pki.js\'s PATH_MAX_LENGTH (12 certificates) and ' +
      'PATH_MAX_SIGNATURES, which the pathological cases are held to.',
    applies: function (t) {
      return (t.features || []).indexOf('max-chain-depth') >= 0;
    } },
  { id: 'signer-registration',
    drivers: ['signer'],
    reason: 'The signer driver registers the case\'s certificates as the ' +
      'chain behind a key, as an operator does — and a registration is ' +
      'the trust decision: every self-signed certificate registered is an ' +
      'anchor, and a chain must END at one (STS-PKI-0156). A case whose ' +
      'trusted certificate is not self-signed (a cross-signed anchor, a ' +
      'bridge) or whose untrusted set holds a self-signed one cannot be ' +
      'expressed as a registration.',
    applies: function (t) { return registrationDiffers(t); } },
  { id: 'signer-is-not-a-ca',
    drivers: ['signer'],
    reason: 'A key that verifies an assertion must be a LEAF\'s: a CA as ' +
      'the signer is refused (STS-PKI-0159). RFC 5280 lets a CA be a ' +
      'path\'s end entity; an assertion signer may not be one.',
    applies: function (t, v) {
      return !v.ok && t.expected_result === 'SUCCESS' && leafIsCa(t);
    } },
  { id: 'direct-is-one-hop',
    drivers: ['direct'],
    reason: 'The synchronous door walks no chain by design: the SPIRE ' +
      'Server API\'s SVIDs are signed directly by this realm\'s Issuing CA ' +
      'and a key attestation\'s x5c leaf directly by a trusted attester, so ' +
      'a case whose path needs an intermediate — or whose anchor is not the ' +
      'leaf\'s direct issuer — is refused there as unsigned.',
    applies: function (t, v) {
      return !v.ok && t.expected_result === 'SUCCESS' &&
             (t.untrusted_intermediates.length > 0 ||
              v.check === 'no-path');
    } },
  { id: 'handshake-at-real-time',
    drivers: ['outbound'],
    reason: 'A TLS handshake validates at the real time and node offers no ' +
      'way to set another (OpenSSL\'s X509_VERIFY_PARAM_set_time is not ' +
      'exposed). A case where some certificate is valid at its validation ' +
      'time and not now, or the reverse, is not the same case over TLS.',
    applies: function (t) { return clockSensitive(t); } },
  { id: 'openssl-path-building',
    drivers: ['outbound'],
    reason: 'OpenSSL refused a path the shared builder finds and holds ' +
      'valid. ' +
      'OpenSSL builds one path and does not try the next when that one ' +
      'breaks an excluded subtree or runs into a cycle of cross-' +
      'certificates, and it anchors only at a SELF-SIGNED certificate ' +
      'unless X509_V_FLAG_PARTIAL_CHAIN is set, which node does not ' +
      'expose — so a trusted intermediate is not an anchor to it; and its ' +
      'TLS-server purpose refuses a CA certificate as the server\'s leaf, ' +
      'which RFC 5280 allows. Each refusal is of a valid path: it fails ' +
      'closed, and an operator names the self-signed root in the family\'s ' +
      'CA file.',
    applies: function (t, v) {
      return !v.ok && t.expected_result === 'SUCCESS' && !!v.sharedOk;
    } },
  { id: 'not-presentable-over-tls',
    drivers: ['outbound'],
    skips: true,
    reason: 'Node will not load the case\'s certificate and key to present ' +
      'them in a handshake (a key OpenSSL cannot decode), so there is no ' +
      'handshake for OpenSSL to judge. The same case is judged by the path ' +
      'validators, which read it.',
    applies: function (t, v) {
      return !!v.skip && /would not load/.test(v.skip);
    } }
];

// ---------------------------------------------------------------------------
// THE CORPUS.
// ---------------------------------------------------------------------------
function loadCorpus() {
  log.debug("Entering loadCorpus().");
  const dir = process.env.STS_X509_LIMBO_DIR || '';
  if (!dir) {
    log.debug("Leaving loadCorpus(). No directory.");
    return { error: 'STS_X509_LIMBO_DIR is not set. The corpus is fetched ' +
                    'into the tests image when it is built ' +
                    '(tests/tools/fetch-x509-limbo.sh); run this file there, ' +
                    'with ./docker-npm-test.sh.' };
  }
  let commit = '';
  let corpus = null;
  try {
    commit = fs.readFileSync(path.join(dir, 'COMMIT'), 'utf8').trim();
    corpus = JSON.parse(fs.readFileSync(path.join(dir, 'limbo.json'),
                                        'utf8'));
  } catch (e) {
    log.debug("Caught in loadCorpus(): " + ((e && e.message) || e));
    log.debug("Leaving loadCorpus(). Unreadable.");
    return { error: 'the corpus in ' + dir + ' could not be read: ' +
                    ((e && e.message) || e) };
  }
  log.debug("Leaving loadCorpus().");
  return { commit: commit, cases: (corpus && corpus.testcases) || [] };
}

// ---------------------------------------------------------------------------
// THE DRIVERS. Each resolves `{ ok, check, why }` for one case, or
// `{ skip: why }` where the case cannot be put to that validator at all
// (counted and reported, never a pass).
// ---------------------------------------------------------------------------
function anchorsOf(t) {
  log.debug("Entering anchorsOf().");
  const pki = require('../common/pki');
  log.debug("Leaving anchorsOf().");
  return t.trusted_certs.map(function (pem) {
    return pki.certificateFromDer(derOf(pem));
  }).filter(Boolean);
}

function timeOf(t) {
  log.debug("Entering timeOf().");
  log.debug("Leaving timeOf().");
  return t.validation_time ? RealDate.parse(t.validation_time) : null;
}

async function driveAnchors(t) {
  log.debug("Entering driveAnchors().");
  const pki = require('../common/pki');
  const at = timeOf(t);
  const v = await pki.verifyPathToAnchors(derOf(t.peer_certificate),
    t.untrusted_intermediates.map(derOf), anchorsOf(t),
    { now: at === null ? RealDate.now() : at });
  log.debug("Leaving driveAnchors().");
  return { ok: v.ok, check: v.check || '', why: v.reason || '',
           chain: v.chain || null };
}

async function driveSigner(t) {
  log.debug("Entering driveSigner().");
  const pki = require('../common/pki');
  const v = await atTime(timeOf(t), function () {
    return pki.verifySignerChain(undefined, {
      certificate: t.peer_certificate,
      chain: t.untrusted_intermediates.concat(t.trusted_certs),
      source: 'the x509-limbo case'
    });
  });
  const errorCodes = require('../common/error_codes');
  log.debug("Leaving driveSigner().");
  return { ok: !!v.ok, check: errorCodes.codeOf(v) || '',
           why: v.why || '' };
}

async function driveDirect(t) {
  log.debug("Entering driveDirect().");
  const pki = require('../common/pki');
  const at = timeOf(t);
  const v = pki.verifyIssuedDirectly(derOf(t.peer_certificate),
    t.trusted_certs.map(derOf),
    { now: at === null ? RealDate.now() : at });
  log.debug("Leaving driveDirect().");
  return { ok: v.ok, check: v.check || '', why: v.reason || '' };
}

async function driveCrl(t) {
  log.debug("Entering driveCrl().");
  const revocation = require('../common/revocation_status');
  const path1 = await driveAnchors(t);
  if (!path1.ok) {
    log.debug("Leaving driveCrl(). No path.");
    return { ok: false, check: 'path', why: path1.why };
  }
  const v = await atTime(timeOf(t), function () {
    return revocation.crlInHandVerdict({
      certificate: path1.chain[0].pem,
      issuer: path1.chain[1] ? path1.chain[1].pem : path1.chain[0].pem,
      crls: (t.crls || []).map(function (crl) { return Buffer.from(crl); })
    });
  });
  log.debug("Leaving driveCrl(). " + v.status);
  // `unknown` is what `pki.revocationCheck=hard-fail` refuses: the list could
  // not be used. Under soft-fail the door accepts it, which is that policy's
  // documented trade-off and not the reader's answer.
  return { ok: v.status === 'good', check: v.status, why: v.why };
}

// One TLS handshake on loopback. `server` and `client` are node's options;
// resolves what the side named by `judge` concluded. `onServerSocket` runs on
// the server's socket before its verdict is read, as the main port's own
// `secureConnection` handler does.
function handshake(serverOptions, clientOptions, judge, onServerSocket) {
  log.debug("Entering handshake(). judge=" + judge);
  return new Promise(function (resolve) {
    let server;
    let settled = false;
    let timer = null;
    const settle = function (verdict) {
      log.debug("Entering settle().");
      if (!settled) {
        settled = true;
        if (timer) {
          clearTimeout(timer);
        }
        try {
          server.close();
        } catch (e) {
          log.debug("Caught in settle(): " + ((e && e.message) || e));
        }
        resolve(verdict);
      }
      log.debug("Leaving settle().");
    };
    try {
      server = tls.createServer(serverOptions);
    } catch (e) {
      log.debug("Caught in handshake(): " + ((e && e.message) || e));
      log.debug("Leaving handshake(). The server would not load it.");
      resolve({ skip: 'node would not load the certificate to present it: ' +
                      ((e && e.message) || e) });
      return;
    }
    server.on('secureConnection', function (socket) {
      if (onServerSocket) {
        onServerSocket(socket);
      }
      if (judge === 'server') {
        settle({ ok: socket.authorized === true,
                 check: String(socket.authorizationError || ''),
                 why: String(socket.authorizationError || '') });
      }
      socket.end();
    });
    server.on('tlsClientError', function (e) {
      if (judge === 'server') {
        settle({ ok: false, check: String((e && e.code) || ''),
                 why: 'the handshake failed: ' + ((e && e.message) || e) });
      }
    });
    server.listen(0, '127.0.0.1', function () {
      const port = server.address().port;
      let socket;
      try {
        socket = tls.connect(Object.assign({ host: '127.0.0.1', port: port },
                                           clientOptions), function () {
          if (judge === 'client') {
            settle({ ok: true, check: '', why: '' });
          }
          socket.end();
        });
      } catch (e) {
        log.debug("Caught in handshake(): " + ((e && e.message) || e));
        settle({ skip: 'node would not load the client\'s certificate: ' +
                       ((e && e.message) || e) });
        return;
      }
      socket.on('error', function (e) {
        if (judge === 'client') {
          settle({ ok: false, check: String((e && e.code) || ''),
                   why: String((e && e.message) || e) });
        }
      });
    });
    timer = setTimeout(function () {
      settle({ skip: 'the handshake did not finish in ten seconds' });
    }, 10000);
  });
}

// A server identity for the inbound driver, made at run time.
let inboundIdentity = null;

function inboundServerIdentity() {
  log.debug("Entering inboundServerIdentity().");
  if (!inboundIdentity) {
    const stsCrypto = require('../common/crypto');
    const made = stsCrypto.selfSignedRsaCertificate({
      commonName: 'x509-limbo inbound listener' });
    inboundIdentity = { key: made.privateKeyPem, cert: made.certPem };
  }
  log.debug("Leaving inboundServerIdentity().");
  return inboundIdentity;
}

async function driveInbound(t) {
  log.debug("Entering driveInbound().");
  if (t.validation_kind !== 'CLIENT' || !t.peer_certificate_key) {
    log.debug("Leaving driveInbound(). Not a client case with a key.");
    return { skip: 'not a CLIENT case carrying the leaf\'s key' };
  }
  const tlsServer = require('../tls/tls_server');
  const identity = inboundServerIdentity();
  // The main port's own posture (`server.js`): asked for, never required,
  // the truststore as the only anchors, and `socket.authorized` read after.
  const v = await handshake(Object.assign({
    key: identity.key, cert: identity.cert,
    ca: t.trusted_certs, requestCert: true, rejectUnauthorized: false
  }, tlsServer.protocolOptions()), {
    key: t.peer_certificate_key,
    cert: [t.peer_certificate].concat(t.untrusted_intermediates).join('\n'),
    rejectUnauthorized: false
  }, 'server', function (socket) {
    // What `observeConnectionsOn()` does on the main port before any request
    // is read: the chain OpenSSL verified, held to the path rules (#201).
    tlsServer.holdToPathRules(socket, 'the x509-limbo inbound driver');
  });
  log.debug("Leaving driveInbound().");
  return v;
}

// The CA file the outbound driver names: the case's anchors, written where
// `ssf.pushCaFile` points while the case runs.
const CA_FILE = path.join(os.tmpdir(), 'x509-limbo-anchors-' + process.pid +
                                       '.pem');

async function driveOutbound(t) {
  log.debug("Entering driveOutbound().");
  if (t.validation_kind !== 'SERVER' || !t.peer_certificate_key) {
    log.debug("Leaving driveOutbound(). Not a server case with a key.");
    return { skip: 'not a SERVER case carrying the leaf\'s key' };
  }
  const OutboundTls = require('../common/outbound_tls');
  fs.writeFileSync(CA_FILE, t.trusted_certs.join('\n'));
  const verdict = OutboundTls.tlsVerdict({
    what: 'the x509-limbo outbound driver', allowHttpKey: 'ssf.pushAllowHttp',
    skipTlsKey: 'ssf.pushSkipTlsVerification', caFileKey: 'ssf.pushCaFile',
    loopbackHttpInProduct: false, httpRefusedCode: '', skipIgnoredCode: ''
  }, 'https://limbo.invalid');
  if (!verdict.ok) {
    log.debug("Leaving driveOutbound(). The policy refused.");
    return { ok: false, check: verdict.errorCode, why: verdict.why };
  }
  const want = t.expected_peer_name;
  const v = await handshake({
    key: t.peer_certificate_key,
    cert: [t.peer_certificate].concat(t.untrusted_intermediates).join('\n')
  }, {
    ca: verdict.ca, rejectUnauthorized: verdict.rejectUnauthorized,
    servername: want && want.kind === 'DNS' ? want.value : undefined,
    // The policy's own host check (`OutboundTls.checkServerIdentity()`:
    // node's, then the verified chain held to the path rules) against the
    // name the case expects — which is what a request to that host runs. The
    // loopback address is only where the listener happens to be.
    checkServerIdentity: function (host, cert) {
      if (want) {
        return verdict.checkServerIdentity(want.value, cert);
      }
      // A case that names no peer asks about the path alone: the chain
      // rules the host check carries, and no name.
      const pki = require('../common/pki');
      const problem = pki.peerChainProblem(cert);
      return problem ? new Error(problem.why) : undefined;
    }
  }, 'client');
  // Whether the shared builder finds a path, for the exception that records
  // where OpenSSL's builder does not.
  if (!v.skip && !v.ok) {
    v.sharedOk = (await driveAnchors(t)).ok;
  }
  log.debug("Leaving driveOutbound().");
  return v;
}

const DRIVERS = {
  anchors: driveAnchors, signer: driveSigner, direct: driveDirect,
  crl: driveCrl, inbound: driveInbound, outbound: driveOutbound
};

// Which cases each driver is handed at all.
function handedTo(driver, t) {
  log.debug("Entering handedTo().");
  let yes = true;
  if (driver === 'crl') {
    yes = !!(t.crls && t.crls.length);
  }
  log.debug("Leaving handedTo().");
  return yes;
}

// ---------------------------------------------------------------------------
// RUN.
// ---------------------------------------------------------------------------
async function run(t) {
  log.debug("Entering run().");
  delete process.env.CONFIG_FILE;
  const loaded = loadCorpus();
  if (loaded.error) {
    t.bad('the x509-limbo corpus is present', loaded.error);
    log.debug("Leaving run(). No corpus.");
    return;
  }
  t.equal(loaded.commit, LIMBO_COMMIT, 'the corpus is x509-limbo at the ' +
          'pinned commit');
  t.equal(loaded.cases.length, LIMBO_CASES, 'the corpus holds every ' +
          'testcase at that commit');
  const config = require('../common/config');
  config.setOverride('ssf.pushCaFile', CA_FILE);
  const used = {};
  const summary = {};
  try {
    const names = Object.keys(DRIVERS);
    for (let d = 0; d < names.length; d++) {
      const driver = names[d];
      const counts = { cases: 0, agree: 0, excepted: 0, failed: 0,
                       skipped: 0, byException: {} };
      const failures = [];
      for (let c = 0; c < loaded.cases.length; c++) {
        const testcase = loaded.cases[c];
        if (!handedTo(driver, testcase)) {
          continue;
        }
        let v;
        try {
          v = await DRIVERS[driver](testcase);
        } catch (e) {
          log.debug("Caught in run(): " + ((e && e.message) || e));
          v = { ok: false, check: 'threw',
                why: 'the driver threw: ' + ((e && e.stack) || e) };
        }
        if (v.skip) {
          if (driver === 'inbound' || driver === 'outbound') {
            // A handshake driver is handed only its own cases; the others are
            // not counted at all.
            if (/^not a (CLIENT|SERVER) case/.test(v.skip)) {
              continue;
            }
          }
          counts.cases++;
          const skipExcuse = EXCEPTIONS.filter(function (one) {
            return one.drivers.indexOf(driver) >= 0 && one.skips &&
                   one.applies(testcase, v);
          })[0];
          if (skipExcuse) {
            counts.skipped++;
            counts.byException[skipExcuse.id] =
              (counts.byException[skipExcuse.id] || 0) + 1;
            used[driver + ':' + skipExcuse.id] = true;
            continue;
          }
          counts.failed++;
          failures.push(testcase.id + ' could not be run: ' + v.skip);
          continue;
        }
        counts.cases++;
        const got = v.ok ? 'SUCCESS' : 'FAILURE';
        if (got === testcase.expected_result) {
          counts.agree++;
          continue;
        }
        const excuse = EXCEPTIONS.filter(function (one) {
          return one.drivers.indexOf(driver) >= 0 && !one.skips &&
                 one.applies(testcase, v);
        })[0];
        if (excuse) {
          counts.excepted++;
          counts.byException[excuse.id] =
            (counts.byException[excuse.id] || 0) + 1;
          used[driver + ':' + excuse.id] = true;
          continue;
        }
        counts.failed++;
        failures.push(testcase.id + ': limbo expects ' +
                      testcase.expected_result + ', the validator answered ' +
                      got + (v.why ? ' (' + String(v.why).slice(0, 300) +
                                     ')' : ''));
      }
      summary[driver] = counts;
      t.log.info('x509-limbo, ' + driver + ': ' + counts.cases +
                 ' case(s), ' + counts.agree + ' agree, ' + counts.excepted +
                 ' documented exception(s) ' +
                 JSON.stringify(counts.byException) + ', ' + counts.failed +
                 ' failure(s), ' + counts.skipped + ' not runnable.');
      t.check(counts.cases > 0, driver + ': the driver was handed cases',
              counts.cases + ' case(s)');
      t.check(failures.length === 0, driver + ': every disagreement with ' +
              'x509-limbo is a documented exception',
              failures.length + ' not: ' + failures.slice(0, 40).join(' | '));
    }
  } finally {
    config.setOverride('ssf.pushCaFile', '');
    try {
      fs.unlinkSync(CA_FILE);
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  }
  // EVERY EXCEPTION STILL EXCUSES SOMETHING, on every driver it names — so
  // the list cannot outlive the gap it records.
  EXCEPTIONS.forEach(function (one) {
    one.drivers.forEach(function (driver) {
      t.check(!!used[driver + ':' + one.id], 'the exception "' + one.id +
              '" still excuses a disagreement on the ' + driver + ' driver',
              'it matched nothing — the gap it records is closed, so it is ' +
              'removed or narrowed');
    });
  });
  log.info('x509-limbo summary: ' + JSON.stringify(summary));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'x509_limbo',
  describe: '#201: C2SP x509-limbo against every certificate path validator ' +
            '— pki.verifyPathToAnchors, verifySignerChain, ' +
            'verifyIssuedDirectly, the CRL reader, and OpenSSL as the main ' +
            'port and outbound requests configure it',
  run: run,
  EXCEPTIONS: EXCEPTIONS
};
