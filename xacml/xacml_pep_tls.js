'use strict';
//
// File: xacml_pep_tls.js
//
// ===========================================================================
// THE HTTPS LISTENER CERTIFICATE OF A REMOTE XACML PEP (2026-09-13).
//
// A remote Policy Enforcement Point answers its CLIENTS — the callers of
// `/protected` — and until this date it answered them in plain http, because a
// certificate for it had to come from somewhere and nothing here could provide
// one. This service already runs a certificate authority with an Issuing CA per
// use case per realm (`common/pki.js`), so the answer is one more use case,
// `pep-tls`, and this file is the XACML half of issuing from it.
//
// ---------------------------------------------------------------------------
// ISSUED TO A REGISTERED PEP, AND THE REGISTRATION IS WHAT DECIDES THE REALM.
//
// The certificate comes from the Issuing CA of **the realm the PEP registered
// to** — which is the realm this request is in, because `ou=peps` is per realm
// and the row is looked up in it. A PEP that registered against
// `/realm/acme/xacml/pep/register` is certified by acme's Intermediate, so a
// client that installed the service Root verifies it and the chain still says
// which realm vouched for that front door.
//
// **REQUIRING A ROW IS NOT A PERMISSION CHECK ON THE PEP**, and the registry's
// own header is careful about that word: registering is still not what lets a
// PEP pull or enforce. It is the only record this service has that a PEP of
// that name EXISTS in this realm, and it carries the one address the PEP
// itself published — its notify URL — which is where the certificate's default
// DNS name comes from. Issuing to a name nothing in the realm has heard of
// would be minting a front-door certificate for a component this console
// cannot show.
//
// ---------------------------------------------------------------------------
// WHAT THE CERTIFICATE NAMES.
//
// The PEP's registered NAME and the HOST of its notify URL, unless the caller
// names others — and names the caller adds are ADDED rather than replacing,
// because the notify host is where this service itself would dial the PEP and a
// certificate that did not name it is one the nudge could never verify. The PEP
// name is only used where it is a DNS name (a certificate subject folded into
// an entry name may not be), and an IP host becomes an IP subjectAltName rather
// than a DNS one, which is the difference `checkServerIdentity()` reads.
//
// ---------------------------------------------------------------------------
// THE PRIVATE KEY IS HANDED OVER ONCE.
//
// `pki.issueTlsServerKeyPair()` generates it, certifies the public half and
// forgets the private half, and this function returns it to the caller — the
// console draws it once on the response page, `/admin-api` answers it once in
// the JSON. **Nothing writes it onto the PEP's entry**, which is where this
// differs from an application's RFC 7523 key pair: that key signs assertions
// this service verifies against the entry, and this key signs TLS handshakes
// between the PEP and ITS clients, which this service is never party to. A
// copy here would be a server key held by something that has no use for it.
//
// How the pair reaches the container is the operator's — or the launcher's —
// to decide: `xacml-pep/pep.js` reads it from two files and picks up a pair
// written after it started, so writing the two members of this reply to a
// mounted directory is the whole of the deployment step.
//
// A LIBRARY: it registers no route. Required by `xacml_admin.js`, which draws
// the control and answers the action for the console and `/admin-api`.
// ===========================================================================

const nodeCrypto = require('crypto');
const net = require('net');
const { URL } = require('url');
const { log } = require('../common/helpers');
const audit = require('../common/audit');
// The error-code registry (a leaf). A refusal carries its code as the
// non-enumerable mark `xacml_admin.js` reads back onto its response.
const errorCodes = require('../common/error_codes');
// A LIBRARY (rule 3) that registers no route, so requiring it here moves
// nothing and closes no cycle.
const pki = require('../common/pki');
const peps = require('./xacml_pep_registry');

const USE_CASE = 'pep-tls';

// A list from either spelling a caller may send it in: a JSON array from
// `/admin-api`, or one textarea from the console with one item per line (commas
// accepted too, because an address list is the kind of thing people type on
// one line).
function listFrom(value) {
  log.debug("Entering listFrom().");
  const raw = Array.isArray(value) ? value
                                   : String(value || '').split(/[\s,]+/);
  log.debug("Leaving listFrom().");
  return raw.map(function (one) {
    return String(one || '').trim();
  }).filter(Boolean);
}

// Whether a string can be a DNS subjectAltName. The same labels
// `pki.issueTlsServerKeyPair()` enforces, asked here only for the names this
// file DERIVES — a derived name that cannot be carried is left out quietly,
// where one a caller typed is refused by name over there.
function isDnsName(text) {
  log.debug("Entering isDnsName().");
  log.debug("Leaving isDnsName().");
  return String(text || '').length <= 253 &&
    String(text || '').split('.').every(function (label) {
      return /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label);
    });
}

// The names a certificate for this row carries by default — see the header.
function derivedNames(row) {
  log.debug("Entering derivedNames().");
  const dnsNames = [];
  const ipAddresses = [];
  if (row && isDnsName(row.name)) {
    dnsNames.push(row.name);
  }
  if (row && row.notifyUrl) {
    try {
      // `URL` keeps the brackets on an IPv6 host, and `net.isIP()` wants them
      // off — so a notify URL of http://[::1]:9090 is an IP name, not a DNS
      // name nothing would match.
      const host = new URL(row.notifyUrl).hostname.replace(/^\[|\]$/g, '');
      if (net.isIP(host)) {
        ipAddresses.push(host);
      } else if (isDnsName(host)) {
        dnsNames.push(host);
      }
    } catch (e) {
      // A notify URL that will not parse names no host. The row already says
      // so on the console (`pepHttp.urlProblem()`), and the caller can still
      // name one — so this is a name left out, not a refusal.
      log.debug("Caught in derivedNames(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving derivedNames().");
  return { dnsNames: dnsNames, ipAddresses: ipAddresses };
}

// The subjectAltName of a PEM, split into its two kinds, read back with node's
// own parser — so what the console says a certificate names is what a client
// will match against, and not what this service meant to write.
function namesIn(pem) {
  log.debug("Entering namesIn().");
  const out = { dnsNames: [], ipAddresses: [] };
  try {
    const san = new nodeCrypto.X509Certificate(pem).subjectAltName || '';
    san.split(/,\s*/).forEach(function (one) {
      if (one.indexOf('DNS:') === 0) {
        out.dnsNames.push(one.slice(4));
      } else if (one.indexOf('IP Address:') === 0) {
        out.ipAddresses.push(one.slice(11));
      }
    });
  } catch (e) {
    // A stored certificate node will not parse is reported with no names
    // rather than failing the page that lists every PEP in the realm.
    log.debug("Caught in namesIn(): " + ((e && e.message) || e));
  }
  log.debug("Leaving namesIn().");
  return out;
}

// The listener certificate this realm has issued to a PEP, as the console and
// `GET /admin-api/xacml/peps` draw it — PUBLIC, and never a key: the register
// keeps none. Null when none has been issued.
function certificateOf(name) {
  log.debug("Entering certificateOf().");
  let held = null;
  try {
    held = pki.certificateFor('', USE_CASE, String(name || ''));
  } catch (e) {
    // No certificate authority in this process (a PKI switched off, a store
    // with no hierarchy yet) is "none issued", which is the truthful reading
    // for a page that only wants to know whether there is one.
    log.debug("Caught in certificateOf(): " + ((e && e.message) || e));
    held = null;
  }
  if (!held) {
    log.debug("Leaving certificateOf(). None.");
    return null;
  }
  const view = pki.describeCertificate(held);
  const names = namesIn(held.certificatePem);
  log.debug("Leaving certificateOf().");
  return {
    subject: view.subject,
    serialHex: view.serialHex,
    notBefore: view.notBefore,
    notAfter: view.notAfter,
    expired: view.expired,
    thumbprint: view.thumbprint,
    keyAlg: view.keyAlg,
    signatureAlg: view.signatureAlg,
    dnsNames: names.dnsNames,
    ipAddresses: names.ipAddresses,
    issuedAt: view.createdAt ? new Date(view.createdAt).toISOString() : '',
    certificatePem: view.certificatePem,
    chainPem: view.chainPem
  };
}

// ---------------------------------------------------------------------------
// ISSUE. `body` is the action's: `name` (required — a registered PEP in this
// realm), and optionally `dnsNames`, `ipAddresses`, `keyAlg` and `days`.
// Answers a PROMISE, because generating a key pair and signing a certificate
// are both asynchronous; `xacml_admin.js`'s `pepAction()` returns it as it is.
// ---------------------------------------------------------------------------
async function issue(body) {
  log.debug('Entering issue(). name=' + (body || {}).name);
  const b = body || {};
  const name = String(b.name || '').trim();
  if (!name) {
    log.debug('Leaving issue(). No name.');
    return errorCodes.mark({ ok: false,
                             why: 'Which registered PEP? Send `name`.' },
                           'STS-XACML-0038');
  }
  const row = peps.read(name);
  if (!row) {
    log.debug('Leaving issue(). Not registered.');
    return errorCodes.mark({ ok: false,
             why: 'No Policy Enforcement Point is registered as "' + name +
                  '" in this realm, so there is no realm to issue its ' +
                  'listener certificate from. A certificate comes from the ' +
                  'Issuing CA of the realm a PEP REGISTERED to: register it ' +
                  'first (it does so on its own once it can reach ' +
                  '/xacml/pep/register), then issue here.' },
                           'STS-XACML-0071');
  }
  const derived = derivedNames(row);
  const dnsNames = derived.dnsNames.concat(listFrom(b.dnsNames));
  const ipAddresses = derived.ipAddresses.concat(listFrom(b.ipAddresses));
  const result = await pki.issueTlsServerKeyPair('', USE_CASE, {
    slot: name,
    label: 'remote PEP ' + name,
    commonName: name,
    dnsNames: dnsNames,
    ipAddresses: ipAddresses,
    keyAlg: b.keyAlg ? String(b.keyAlg) : undefined,
    days: b.days
  });
  if (!result.ok) {
    log.debug('Leaving issue(). The certificate authority refused.');
    return errorCodes.mark({ ok: false,
                             why: (result.errors || []).join(' ') ||
                                  'The certificate could not be issued.' },
                           errorCodes.codeOf(result) || 'STS-XACML-0072');
  }
  const issued = result.issued;
  audit.audit({ action: 'xacml.pep.certificate', actor: '',
                protocol: 'XACML',
                detail: 'Issued an HTTPS listener certificate to remote PEP "' +
                        name + '" (serial ' + issued.serialHex + ', names ' +
                        issued.dnsNames.concat(issued.ipAddresses).join(', ') +
                        ', expires ' + issued.notAfter + ')' +
                        (issued.replacedSerialHex
                          ? '; the certificate it replaces (serial ' +
                            issued.replacedSerialHex + ') is superseded'
                          : '') + '.' });
  // WHAT node's `cert` option wants: the leaf FOLLOWED BY the chain, so the
  // PEP sends its Issuing CA and the realm Intermediate and a client holding
  // only the service Root can build the path. The Root is left out, for
  // `certify()`'s reason — it is the anchor, and relying on it having been
  // sent is the mistake.
  const fullChainPem = [issued.certificatePem].concat(issued.chainPem || [])
    .map(function (one) {
      return String(one).replace(/\s*$/, '\n');
    }).join('');
  log.debug('Leaving issue(). serial=' + issued.serialHex);
  return {
    ok: true,
    what: 'Issued an HTTPS listener certificate to "' + name + '" from the ' +
          'Remote PEP listeners Issuing CA of the realm it registered to, ' +
          'naming ' + issued.dnsNames.concat(issued.ipAddresses).join(', ') +
          '. THE PRIVATE KEY IS IN THIS REPLY AND NOWHERE ELSE: this ' +
          'service keeps the certificate and not the key, so the pair must ' +
          'be saved now. Write `fullChainPem` and `privateKeyPem` to the two ' +
          'files the container reads (PEP_HTTPS_CERT and PEP_HTTPS_KEY); it ' +
          'picks up a pair written after it started.' +
          (issued.replacedSerialHex
            ? ' The certificate this replaces (serial ' +
              issued.replacedSerialHex + ') is on its issuer\'s revocation ' +
              'list as superseded.'
            : ''),
    pep: name,
    realm: issued.scope,
    serialHex: issued.serialHex,
    subject: issued.subject,
    notBefore: issued.notBefore,
    notAfter: issued.notAfter,
    thumbprint: issued.thumbprint,
    dnsNames: issued.dnsNames,
    ipAddresses: issued.ipAddresses,
    replacedSerialHex: issued.replacedSerialHex,
    certificatePem: issued.certificatePem,
    chainPem: issued.chainPem,
    fullChainPem: fullChainPem,
    anchorPem: issued.anchorPem,
    privateKeyPem: issued.privateKeyPem
  };
}

module.exports = {
  USE_CASE: USE_CASE,
  issue: issue,
  certificateOf: certificateOf,
  derivedNames: derivedNames,
  listFrom: listFrom
};
