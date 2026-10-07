// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: common/crypto.js
//
// ---------------------------------------------------------------------------
// THE ONE PLACE THIS SERVICE SIGNS, VERIFIES, ENCRYPTS AND DECRYPTS.
//
// Before 2026-08-27 it did all four in about twenty places. There were SIX
// independent XML signers and FOUR independent XML signature verifiers, each
// with the same four algorithm URIs typed out again; ten `jwt.verify()` calls
// against this service's own certificate, four of which had quietly stopped
// applying the configured clock skew; two RFC 7638 JWK thumbprints; two forge
// self-signed certificate builders; and two `timingSafeEqual` wrappers. None of
// that was carelessness — each one was written where it was needed, and the
// copies agreed on the day they were made.
//
// **THE COST WAS NOT ABSTRACT AND IT IS WORTH NAMING, BECAUSE IT IS THE WHOLE
// ARGUMENT FOR THIS FILE.** `saml/CLAUDE.md` records the `Id="_0"` defect:
// every SAML 1.1 assertion this service ever issued carried an attribute the
// schema does not have, because xml-crypto invents one when it cannot find an
// id it recognises. It verified anyway, so it survived for months, and the fix
// had to be applied to EACH SIGNER SEPARATELY. A single signer would have been
// one edit and one place to be wrong. The four verifiers had drifted the same
// way: three of them took the FIRST <ds:Signature> in the document, which on a
// SAML 1.1 Response carrying a signed assertion is the ASSERTION'S — so a
// caller asking "is this Response signed by us" was answered about a different
// element and told yes.
//
// ---------------------------------------------------------------------------
// WHERE THE XML CODE CAME FROM, AND WHY IT IS NOT WRITTEN HERE.
//
// `common/vendored/xmldsig.js` is the parent project's own XML security module,
// copied here byte-identical under the rule that directory already has. It is
// not a library somebody found: it is the OTHER END of most of these exchanges.
// The debugger signs, verifies, encrypts and decrypts with it on its WS-Trust,
// SAML and Digital Signature pages, and `tests/xmlsec_interop.js` over there
// already drives it against xml-crypto AND xml-encryption — two independent
// implementations — across all three SAML versions and their three different
// signature placements.
//
// So using it here buys three things a local implementation could not. Both
// ends of an exchange now canonicalize with the same code, which matters
// because a disagreement about c14n is invisible until it is a signature that
// verifies on one side and not the other. It resolves `AssertionID`,
// `ResponseID` and `RequestID` natively, so the `Id="_0"` class of bug cannot
// recur — there is no attribute to invent. And its algorithm coverage is wider
// than what replaced it: RSA, RSASSA-PSS, ECDSA and HMAC, every c14n mode,
// InclusiveNamespaces, the XPath transforms.
//
// **THIS FILE IS THE POLICY AND THAT FILE IS THE MECHANISM**, and the split is
// deliberate rather than tidy. What is here is what is true of THIS service:
// which placements its six documents use, that a verifier must be told WHICH
// element's signature to check, that a decryption ANSWERS rather than throws,
// that a token verified against our own certificate gets the configured clock
// skew. None of that belongs in a file that has to stay byte-identical to
// somebody else's copy.
//
// ---------------------------------------------------------------------------
// THIS MODULE IS A LEAF AND MUST STAY ONE.
//
// It requires npm packages, `./vendored/xmldsig.js`, and `./config` — and
// `config.js` requires nothing in this repository, so there is no cycle to
// close and no route order to disturb. It registers no endpoint, exactly like
// `oauth-oidc/dpop.ts` (rule 3), and it is BELOW `helpers.js` rather than
// beside it: helpers requires this file for its key generation and its token
// minting, so this file may never require helpers back. Concretely, that means
// **nothing here reads `STS`, the ambient realm, or a session** — every
// function takes the key it is to use as a parameter. Realm-awareness is
// helpers.js's job and stays there.
//
// It also means `logArtifact()` is not reachable from here. That is on purpose:
// the callers keep their own `logArtifact('SAML assertion', 'before signing',
// …)` lines exactly where they were, so the debug log of a mock — which is the
// point of a mock — is unchanged by this refactor. A hook back into helpers
// would have been a sixth inverted slot, and the root CLAUDE.md's rule 3e is
// explicit that a slot is for a require that would close a cycle or move a
// route, not for convenience.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const zlib = require('zlib');
const forge = require('node-forge');
// FORGE'S GENERATOR IS NODE'S (#65, section 13). forge keeps a Fortuna DRBG
// of its own and draws from it INSIDE the library — the blinding of every
// RSA private-key operation (every XML signature `vendored/xmldsig.js` makes
// with forge's `pk.sign()`, every certificate forge signs), OAEP seeds,
// PKCS#1 v1.5 padding, PKCS#7 content keys. Calling node here instead of
// `forge.random` at our own call sites stopped none of that. forge is one
// module instance, so pointing its default generator at node's once, on
// load, covers every caller — the vendored ones included, which may not be
// edited here. `createInstance()` answers the same, so no forge generator of
// forge's own exists in this process; `tests/random_values.js` holds it.
installForgeRandom(forge);
// The DER writer for the post-quantum certificate below. node-forge cannot
// represent an ML-DSA key at all, so that one certificate is built by hand.
const asn1js = require('asn1js');
const jwt = require('jsonwebtoken');
const bunyan = require('bunyan');
const config = require('./config');
const pqJose = require('./pq_jose');

const xmldom = require('@xmldom/xmldom');
// THE FAILURE CODES. A LEAF with no requires, so this file stays one (rule 3r).
// A verdict that refuses carries its code NON-ENUMERABLY — `errorCodes.mark()`
// puts it under a Symbol — so no member a caller compares or serialises moves;
// a caller that wants the condition's name reads it with `codeOf()`.
const errorCodes = require('./error_codes');
// THE MODE, for the two broken algorithms this file can be asked to accept
// (#181): SHA-1 in a verified signature and an rsa-1_5 key transport on an
// unwrap. A LEAF too — it requires `config` and `error_codes` and nothing
// else — so this file stays one.
const mode = require('./mode');

const log = bunyan.createLogger({
  name: 'crypto',
  level: config.value('global.logLevel')
});

// ---------------------------------------------------------------------------
// THE TWO DOM CONSTRUCTORS, INSTALLED AS GLOBALS BEFORE xmldsig.js IS REQUIRED.
//
// The vendored module is the parent project's BROWSER code, where `DOMParser`
// and `XMLSerializer` are ambient. Node has neither. `@xmldom/xmldom` supplies
// both and is already a dependency of this service, and this is exactly what
// the parent's own `api/server.js` does at its line 987 for the same file — so
// this is the established way to run it server-side rather than something
// invented here.
//
// THE ORDER OF THE NEXT FIVE LINES IS LOAD-BEARING. `xmldsig.js` captures
// nothing at require time, but every function in it reaches for the bare
// globals, so a `require` that happened before this ran would load fine and
// then fail on the first signature with "DOMParser is not defined" — a message
// that names neither this file nor the real problem.
//
// They are set only when absent. Something else in the process may have
// installed a real DOM (a test harness, a future jsdom), and quietly replacing
// it would be the kind of action at a distance that is impossible to find.
// ---------------------------------------------------------------------------
// The casts are for the type checker (#50): xmldom's classes are the DOM's
// in behaviour and not, to the letter, in their declared types.
if (!global.DOMParser) {
  global.DOMParser = /** @type {any} */ (xmldom.DOMParser);
}
if (!global.XMLSerializer) {
  global.XMLSerializer = /** @type {any} */ (xmldom.XMLSerializer);
}
/** The vendored XML Signature engine. */
const xmldsig = require('./vendored/xmldsig.js');

// The namespace URIs this file names. They are also exported by xmldsig.js and
// are repeated here ONLY as local constants for readability — a caller that
// needs one should take it from the re-export at the bottom, so that there
// stays exactly one spelling of each in the process.
const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';
const XENC_NS = 'http://www.w3.org/2001/04/xmlenc#';
const XENC11_NS = 'http://www.w3.org/2009/xmlenc11#';
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';

// ===========================================================================
// SECTION 1 — XML DIGITAL SIGNATURE
// ===========================================================================

// ---------------------------------------------------------------------------
// WHERE THE <ds:Signature> GOES, and all three are schema-mandated rather than
// a matter of taste. Getting one wrong produces a document that VERIFIES and
// that a strict parser rejects, which is the worst of both worlds and is why
// they are named here rather than passed as raw strings from six call sites.
//
//   AFTER_ISSUER  a SAML 2.0 protocol message or assertion, and a signed
//                 AuthnRequest. The schema puts ds:Signature immediately after
//                 <Issuer>; xml-crypto with no location appended it to the
//                 document element instead, which several identity providers
//                 refuse without saying why.
//   FIRST         a metadata <EntityDescriptor>, and a SAML 1.1 Response whose
//                 signature precedes the assertion.
//   LAST          a SAML 1.1 assertion, which has no <Issuer> ELEMENT at all —
//                 in 1.1 the issuer is an ATTRIBUTE, so "after the issuer" is
//                 not a position that exists.
// ---------------------------------------------------------------------------
/**
 * Where an enveloped `<ds:Signature>` goes: after the issuer, first, or
 * last, as each document's schema requires.
 */
const PLACEMENT = {
  AFTER_ISSUER: 'after-issuer',
  FIRST: 'first',
  LAST: 'last'
};

// The id attributes an XML signature reference may name, in the order the
// vendored findById() searches. SAML 1.1 gives every message type its own
// spelling instead of one shared attribute, which is the whole reason the old
// xml-crypto call sites had to be told the name and this one does not.
const ID_ATTRIBUTES = ['ID', 'AssertionID', 'ResponseID', 'RequestID', 'Id',
                       'id'];

// The id an element carries, whatever it is called. Returns '' when there is
// none, which is a legal signature reference (URI="" means the whole document)
// rather than an error.
/**
 * Returns the id an element carries, whatever its attribute is called.
 *
 * @param element - the DOM element
 * @returns the id, or empty when there is none
 */
function idOf(element) {
  log.debug("Entering idOf().");
  for (let i = 0; i < ID_ATTRIBUTES.length; i++) {
    const value = element.getAttribute(ID_ATTRIBUTES[i]);
    if (value) {
      log.debug("Leaving idOf().");
      return value;
    }
  }
  log.debug("Leaving idOf().");
  return '';
}

// A direct child by local name, namespace-insensitively. `getElementsByTagName`
// would reach into descendants, and on a Response carrying a signed assertion
// that is the difference between this element's signature and somebody else's.
function directChildByLocal(parent, localName, namespaceUri) {
  log.debug("Entering directChildByLocal().");
  for (let child = parent.firstChild; child; child = child.nextSibling) {
    if (child.nodeType !== 1 || child.localName !== localName) {
      continue;
    }
    if (namespaceUri && child.namespaceURI !== namespaceUri) {
      continue;
    }
    log.debug("Leaving directChildByLocal().");
    return child;
  }
  log.debug("Leaving directChildByLocal().");
  return null;
}

// ---------------------------------------------------------------------------
// SIGN ONE DOCUMENT, ENVELOPED.
//
// This replaces six near-identical functions. `opts`:
//
//   privateKeyPem  required. The PEM, not a KeyObject — forge parses PEM, and
//                  this is why helpers.js still keeps `STS.privateKeyPem`
//                  alongside the pre-parsed `STS.privateKey` that jsonwebtoken
//                  wants.
//   certPem        embedded as <ds:KeyInfo><ds:X509Data>. Omit to sign with no
//                  KeyInfo, which nothing here does but the profile allows.
//   placement      one of PLACEMENT above. Defaults to AFTER_ISSUER because
//                  five of the six callers want it.
//   refUri         normally omitted: the vendored signer reads the root
//                  element's own id, trying ID, AssertionID and Id in turn, and
//                  references THAT. Pass it only to reference something the
//                  root does not carry.
//   what           a label for the debug line. Not part of the signature.
//
// **THE ARGUMENT THAT USED TO LIVE AT EVERY CALL SITE — that exclusive
// canonicalization is load-bearing — is now made once, here.** A SAML assertion
// is signed as a standalone document and then embedded inside an RSTR, a
// Response or a wresult that declares prefixes of its own (wst, wsp, wsa,
// samlp). INCLUSIVE c14n would pull those ancestor declarations into the digest
// at verification time, so the signature would fail for every relying party
// while verifying perfectly here — the worst shape of bug to chase. Exclusive
// renders only visibly-utilized prefixes and is therefore stable under
// embedding. It is the default below and no caller overrides it.
// ---------------------------------------------------------------------------
/**
 * Signs one XML document with an enveloped signature, exclusive c14n.
 *
 * @param xml - the document
 * @param opts - `privateKeyPem` or `privateKey`, `certPem`, `refUri`,
 *   `placement`, `sigAlg`, `includeKeyInfo` and `what`
 * @returns the signed document
 */
function signXml(xml, opts) {
  log.debug("Entering signXml().");
  const options = opts || {};
  const what = options.what || 'XML document';
  log.debug('Entering signXml(). what=' + what + ', placement=' +
            (options.placement || PLACEMENT.AFTER_ISSUER));
  // A post-quantum signer-group key (#68 phase 4b) is raw bytes and has no
  // PEM, so `privateKey` stands in for it; every other caller passes a PEM.
  if (!options.privateKeyPem && !options.privateKey) {
    log.debug('Leaving signXml(). No private key.');
    throw new Error('signXml: privateKeyPem is required to sign ' + what + '.');
  }
  // ---------------------------------------------------------------------
  // THE REFERENCE IS RESOLVED HERE RATHER THAN LEFT TO THE SIGNER, AND A TEST
  // IS WHY. The vendored signer works the id out from the root element when it
  // is given none — but it looks for `ID`, `AssertionID` and `Id` only. SAML
  // 1.1 spells a RESPONSE'S id `ResponseID`, which is on neither that list nor
  // xml-crypto's, so a SAML 1.1 Response signed without an explicit reference
  // came out with `URI=""`.
  //
  // That is not a broken signature — an empty URI means the whole document and
  // it verifies — but it is not the document a SAML 1.1 relying party is
  // looking at, and it is the SAME SHAPE OF DEFECT as the `Id="_0"` bug this
  // module exists to have made impossible: a signature that verifies
  // everywhere and references the wrong thing, which is exactly what survives
  // for months. `saml11_sso.js` passes its id explicitly and was never
  // affected; this is about what happens when the next caller does not.
  //
  // `idOf()` knows all six spellings, so the safe behaviour is now the default
  // one and a caller has to work to get anything else. An explicit `refUri` is
  // still honoured — including a deliberate empty string.
  // ---------------------------------------------------------------------
  let refUri = options.refUri;
  if (refUri === undefined || refUri === null) {
    const root = new xmldom.DOMParser()
      .parseFromString(String(xml), 'text/xml').documentElement;
    const id = root ? idOf(root) : '';
    refUri = id ? ('#' + id) : '';
  }
  // -------------------------------------------------------------------
  // THE SIGNER GROUPS' XML ALGORITHMS (2026-09-26, #68 phase 4b).
  //
  // RSA — every signature this service made before #68 — goes through
  // `signEnveloped()` exactly as it did, byte for byte. The two new families
  // are ADDITIVE and each takes the vendored path that can carry it:
  //
  //   * POST-QUANTUM (ML-DSA, SLH-DSA; the W3C xmldsig-more draft's
  //     identifiers): `signEnveloped()` itself, which takes an injected
  //     `signer` for exactly these and holds the identifiers but not the
  //     lattice — `pq_jose.js` signs, as it does every post-quantum JWS.
  //   * ECDSA: the vendored GENERAL engine (`xmldsig.signXml()`), because
  //     `signEnveloped()`'s classical branch is RSA through forge and the
  //     vendored file is not edited here (rcbj's D8). The signature is the
  //     raw r||s XML Signature 1.1 section 6.4.3 specifies, which node's
  //     `ieee-p1363` encoding produces.
  // -------------------------------------------------------------------
  const method = XML_SIGNATURE_METHODS[options.sigAlg] || null;
  const pqMethod = xmldsig.SIG_METHODS[options.sigAlg] &&
    xmldsig.SIG_METHODS[options.sigAlg].postQuantum
    ? xmldsig.SIG_METHODS[options.sigAlg] : null;
  if (pqMethod) {
    const pqAlg = String(pqMethod.alg);
    const pqKey = options.privateKey;
    const pqSigned = xmldsig.signEnveloped(xml, {
      certPem: options.certPem,
      placement: options.placement || PLACEMENT.AFTER_ISSUER,
      refUri: refUri,
      sigAlg: options.sigAlg,
      c14nAlg: options.c14nAlg,
      includeKeyInfo: options.includeKeyInfo,
      signer: function (octets) {
        return Buffer.from(pqJose.sign(pqAlg, pqKey,
                                       Buffer.from(octets, 'binary')));
      }
    });
    log.debug('Leaving signXml(). ' + pqAlg + ', ' + pqSigned.length +
              ' characters.');
    return pqSigned;
  }
  if (method && method.family === 'ecdsa') {
    const ecKey = options.privateKey ||
                  nodeCrypto.createPrivateKey(options.privateKeyPem);
    const ecHash = String(method.hash);
    const ecSigned = xmldsig.signXml(xml, {
      mode: 'enveloped',
      sigAlg: options.sigAlg,
      c14nAlg: options.c14nAlg || xmldsig.C14N_EXCLUSIVE,
      keyInfo: options.includeKeyInfo === false ? 'none' : 'x509',
      certPem: options.certPem,
      refUri: refUri,
      placement: options.placement || PLACEMENT.AFTER_ISSUER,
      signer: function (octets) {
        return nodeCrypto.sign(ecHash, Buffer.from(octets, 'binary'),
                               { key: ecKey, dsaEncoding: 'ieee-p1363' });
      }
    });
    const ecXml = typeof ecSigned === 'string' ? ecSigned : ecSigned.xml;
    log.debug('Leaving signXml(). ECDSA, ' + ecXml.length + ' characters.');
    return ecXml;
  }
  const signed = xmldsig.signEnveloped(xml, {
    privateKeyPem: options.privateKeyPem,
    certPem: options.certPem,
    placement: options.placement || PLACEMENT.AFTER_ISSUER,
    refUri: refUri,
    sigAlg: options.sigAlg,
    c14nAlg: options.c14nAlg,
    includeKeyInfo: options.includeKeyInfo
  });
  log.debug('Leaving signXml(). ' + signed.length + ' characters.');
  return signed;
}

// ===========================================================================
// SECTION 1a — WHICH XML SIGNATURE ALGORITHMS ARE VERIFIED, AND WITH WHAT
// (2026-09-17, #37 follow-up).
//
// **UNTIL THIS SECTION EVERY XML SIGNATURE THIS SERVICE CHECKED HAD TO BE
// RSA.** The vendored engine implements RSA itself and takes everything else
// through an injected `verifier` (its own header says why: the curves belong
// in the browser page that has them loaded, not in the SAML bundle). Nothing
// here ever injected one, so an ECDSA, EdDSA or post-quantum signature from a
// service provider, a federation partner or a WS-Trust client was refused as
// "cannot be checked", and an EC certificate could not even be registered.
//
// **THE VERIFIER IS NOW ALWAYS INJECTED, AND IT IS NODE'S OWN OPENSSL.** One
// table below names every SignatureMethod this process verifies and how; the
// vendored engine still does everything else — the canonicalization, the
// transform chain, the reference resolution and the digests — so both ends
// of an exchange with the debugger still canonicalize with the same code,
// which was the whole argument for using it.
//
// **THE TABLE IS ALSO REGISTERED INTO THE VENDORED MODULE'S OWN TABLES**, and
// that is the one thing here that reaches into another file's state. It is
// ADDITIVE ONLY — a URI the vendored table already names is never touched —
// and it is required because the engine refuses a SignatureMethod or a
// DigestMethod it has no row for before it ever calls a verifier. The
// alternative was a second canonicalizing verifier in this file, which is
// exactly the drift section 1's header exists to prevent; editing the
// vendored file is forbidden (`common/vendored/CLAUDE.md`). A registered
// digest row's `md` is a node hash dressed as forge's, because that is the
// shape the engine calls.
//
// WHAT IS VERIFIED (XMLDSig core names RSA-SHA1 and DSA-SHA1, XMLDSig 1.1
// DSA-SHA256, the post-quantum draft its own rows, RFC 9231 the rest):
//
//   RSA PKCS#1 v1.5    SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, RIPEMD-160
//   RSASSA-PSS         SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
//                      SHA3-224..512, RIPEMD-160 with MGF1 (section 2.3.10),
//                      and `rsa-pss` WITH RSAPSSParams (section 2.3.9)
//   ECDSA              SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
//                      SHA3-224..512, RIPEMD-160; any curve node accepts —
//                      P-256, P-384, P-521 in practice. The value is r||s
//                      (XMLDSig 1.1 section 4.4.2.2), with a DER value
//                      accepted too, because the encoding is not what makes a
//                      signature genuine
//   EdDSA              Ed25519 and Ed448 (section 2.3.12, pure)
//   DSA                SHA-1 (XMLDSig core) and SHA-256 (XMLDSig 1.1)
//   ML-DSA, SLH-DSA    every parameter set in the vendored registry's
//                      post-quantum rows (draft-eastlake-rfc9231bis-xmlsec-
//                      uris — an individual DRAFT, no W3C or IETF standard
//                      names an XML identifier for either yet), pure, empty
//                      context, with the key from an X.509 certificate
//                      (RFC 9881 for ML-DSA; the LAMPS profile for SLH-DSA)
//
// WHAT IS NOT, BY NAME, and each refusal says which of these it is:
//
//   MD5 and MD2, in any family   broken; RFC 9231 says MUST NOT
//   HMAC, Poly1305, SipHash      a MAC needs a secret shared with the signer,
//                                and a SAML party registers a certificate
//   Whirlpool, RIPEMD-128        not in node's OpenSSL default provider
//   ESIGN                        no implementation in OpenSSL
//   Ed25519ph, Ed25519ctx,       node exposes pure EdDSA only
//   Ed448ph
//   HSS/LMS, XMSS, XMSS^MT       stateful hash-based schemes: OpenSSL 3.5
//                                (node 24) verifies none of them
//
// SHA-1 IS A POLICY, NOT A GAP: `saml.allowSha1Signatures`, off by default,
// decides whether a signature whose SignatureMethod or any DigestMethod is
// SHA-1 is accepted at all — on EVERY path through this file, because every
// XML signature this service checks comes through it. With it on, SHA-1 is
// accepted and the verdict still says `weak` (as it does for RIPEMD-160,
// whose 160-bit output is SHA-1's, and which no setting refuses).
// ===========================================================================
const XMLDSIG_MORE = 'http://www.w3.org/2001/04/xmldsig-more#';
const XMLDSIG_MORE_2007 = 'http://www.w3.org/2007/05/xmldsig-more#';
const XMLDSIG_MORE_2021 = 'http://www.w3.org/2021/04/xmldsig-more#';
const XMLDSIG11 = 'http://www.w3.org/2009/xmldsig11#';
const PSS_PARAMS_NS = XMLDSIG_MORE_2007;

// uri -> { family, hash, keyTypes, label, weak, sha1 }
const XML_SIGNATURE_METHODS = {};
// uri -> why it is not verified
const XML_SIGNATURE_REFUSED = {};
// uri -> { hash, label, weak, sha1 }
const XML_DIGEST_METHODS = {};
const XML_DIGEST_REFUSED = {};

// The node digest names, and the ones that are weak. SHA-1 is the one a
// setting governs; RIPEMD-160 is recorded as weak and accepted.
const WEAK_HASHES = ['sha1', 'ripemd160'];

// `sha3-256` -> `SHA3-256`, the spelling the method names use; a digest's
// own label (`digest` true) spells SHA-1 and SHA-256 with the hyphen.
function hashLabel(hash, digest) {
  log.debug("Entering hashLabel().");
  const upper = String(hash).toUpperCase();
  log.debug("Leaving hashLabel().");
  return digest ? upper.replace(/^SHA(\d+)$/, 'SHA-$1')
    .replace('RIPEMD160', 'RIPEMD-160') : upper;
}

function addSignatureMethod(uri, family, hash, keyTypes, label) {
  log.debug("Entering addSignatureMethod().");
  XML_SIGNATURE_METHODS[uri] = {
    family: family, hash: hash, keyTypes: keyTypes, label: label,
    weak: WEAK_HASHES.indexOf(String(hash)) >= 0,
    sha1: hash === 'sha1'
  };
  log.debug("Leaving addSignatureMethod().");
}

[['sha1', DS_NS + 'rsa-sha1'],
 ['sha224', XMLDSIG_MORE + 'rsa-sha224'],
 // RFC 6931's spelling, which Apache Santuario still uses; the same method.
 ['sha224', XMLDSIG_MORE_2007 + 'rsa-sha224'],
 ['sha256', XMLDSIG_MORE + 'rsa-sha256'],
 ['sha384', XMLDSIG_MORE + 'rsa-sha384'],
 ['sha512', XMLDSIG_MORE + 'rsa-sha512'],
 ['ripemd160', XMLDSIG_MORE + 'rsa-ripemd160']].forEach(function (row) {
  addSignatureMethod(row[1], 'rsa', row[0], ['rsa'],
                     'RSA-' + hashLabel(row[0]));
});
['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3-224', 'sha3-256',
 'sha3-384', 'sha3-512', 'ripemd160'].forEach(function (hash) {
  addSignatureMethod(XMLDSIG_MORE_2007 + hash + '-rsa-MGF1', 'rsa-pss', hash,
                     ['rsa', 'rsa-pss'],
                     'RSASSA-PSS ' + hashLabel(hash) + ' with MGF1');
});
addSignatureMethod(XMLDSIG_MORE_2007 + 'rsa-pss', 'rsa-pss', 'sha256',
                   ['rsa', 'rsa-pss'],
                   'RSASSA-PSS with parameters (RFC 9231 section 2.3.9)');
[['sha1', XMLDSIG_MORE + 'ecdsa-sha1'],
 ['sha224', XMLDSIG_MORE + 'ecdsa-sha224'],
 ['sha256', XMLDSIG_MORE + 'ecdsa-sha256'],
 ['sha384', XMLDSIG_MORE + 'ecdsa-sha384'],
 ['sha512', XMLDSIG_MORE + 'ecdsa-sha512'],
 ['sha3-224', XMLDSIG_MORE_2021 + 'ecdsa-sha3-224'],
 ['sha3-256', XMLDSIG_MORE_2021 + 'ecdsa-sha3-256'],
 ['sha3-384', XMLDSIG_MORE_2021 + 'ecdsa-sha3-384'],
 ['sha3-512', XMLDSIG_MORE_2021 + 'ecdsa-sha3-512'],
 ['ripemd160', XMLDSIG_MORE_2007 + 'ecdsa-ripemd160']].forEach(function (row) {
  addSignatureMethod(row[1], 'ecdsa', row[0], ['ec'],
                     'ECDSA-' + hashLabel(row[0]));
});
addSignatureMethod(XMLDSIG_MORE_2021 + 'eddsa-ed25519', 'eddsa', null,
                   ['ed25519'], 'EdDSA Ed25519 (RFC 9231)');
addSignatureMethod(XMLDSIG_MORE_2021 + 'eddsa-ed448', 'eddsa', null,
                   ['ed448'], 'EdDSA Ed448 (RFC 9231)');
addSignatureMethod(DS_NS + 'dsa-sha1', 'dsa', 'sha1', ['dsa'], 'DSA-SHA1');
addSignatureMethod(XMLDSIG11 + 'dsa-sha256', 'dsa', 'sha256', ['dsa'],
                   'DSA-SHA256 (XMLDSig 1.1)');
// The post-quantum rows come from the vendored registry, so the two cannot
// disagree about an identifier. Only the stateless families: HSS/LMS has a
// row there and no verifier in node.
Object.keys(xmldsig.SIG_METHODS).forEach(function (uri) {
  const spec = xmldsig.SIG_METHODS[uri];
  if (spec.postQuantum && (spec.family === 'mldsa' ||
                           spec.family === 'slhdsa')) {
    addSignatureMethod(uri, 'pq', null, [String(spec.alg).toLowerCase()],
                       spec.label);
  }
});

['rsa-md5', 'hmac-md5'].forEach(function (name) {
  XML_SIGNATURE_REFUSED[XMLDSIG_MORE + name] = 'MD5 is broken and RFC 9231 ' +
    'says it MUST NOT be used';
});
['md2-rsa-MGF1', 'md5-rsa-MGF1'].forEach(function (name) {
  XML_SIGNATURE_REFUSED[XMLDSIG_MORE_2007 + name] = 'MD2 and MD5 are broken';
});
['rsa-whirlpool', 'ecdsa-whirlpool', 'whirlpool-rsa-MGF1',
 'ripemd128-rsa-MGF1'].forEach(function (name) {
  XML_SIGNATURE_REFUSED[XMLDSIG_MORE_2007 + name] = 'Whirlpool and ' +
    'RIPEMD-128 are not in node\'s OpenSSL default provider';
});
['sha1', 'sha224', 'sha256', 'sha384', 'sha512'].forEach(function (hash) {
  XML_SIGNATURE_REFUSED[XMLDSIG_MORE + 'esign-' + hash] = 'ESIGN has no ' +
    'implementation in OpenSSL';
});
['eddsa-ed25519ph', 'eddsa-ed25519ctx', 'eddsa-ed448ph'].forEach(
  function (name) {
    XML_SIGNATURE_REFUSED[XMLDSIG_MORE_2021 + name] = 'node verifies pure ' +
      'EdDSA only, not the pre-hashed or context variants';
  });
XML_SIGNATURE_REFUSED[xmldsig.HSS_LMS_URI] = 'HSS/LMS is a stateful ' +
  'hash-based scheme and OpenSSL 3.5 (node 24) has no verifier for it';

[['sha1', DS_NS + 'sha1'],
 ['sha224', XMLDSIG_MORE + 'sha224'],
 ['sha256', XENC_NS + 'sha256'],
 ['sha384', XMLDSIG_MORE + 'sha384'],
 ['sha512', XENC_NS + 'sha512'],
 ['sha3-224', XMLDSIG_MORE_2007 + 'sha3-224'],
 ['sha3-256', XMLDSIG_MORE_2007 + 'sha3-256'],
 ['sha3-384', XMLDSIG_MORE_2007 + 'sha3-384'],
 ['sha3-512', XMLDSIG_MORE_2007 + 'sha3-512'],
 ['ripemd160', XENC_NS + 'ripemd160']].forEach(function (row) {
  XML_DIGEST_METHODS[row[1]] = {
    hash: row[0], label: hashLabel(row[0], true),
    weak: WEAK_HASHES.indexOf(row[0]) >= 0, sha1: row[0] === 'sha1'
  };
});
XML_DIGEST_REFUSED[XMLDSIG_MORE + 'md5'] = 'MD5 is broken';
XML_DIGEST_REFUSED[XMLDSIG_MORE_2007 + 'whirlpool'] = 'Whirlpool is not in ' +
  'node\'s OpenSSL default provider';

// A node hash with the three members of a forge message digest the vendored
// engine calls: `create()`, `update(binaryString)`, `digest().getBytes()`.
// The three inner methods are a HOT PATH — called for every block of every
// reference digest — so they carry no Entering/Leaving pair, which would
// drown the log; the factory that builds them does.
function forgeShapedDigest(hash) {
  log.debug("Entering forgeShapedDigest(). " + hash);
  log.debug("Leaving forgeShapedDigest().");
  return {
    create: function () {
      const h = nodeCrypto.createHash(hash);
      const md = {
        update: function (bytes) {
          h.update(Buffer.from(String(bytes), 'binary'));
          return md;
        },
        digest: function () {
          const out = h.digest('binary');
          return {
            getBytes: function () {
              return out;
            }
          };
        }
      };
      return md;
    }
  };
}

// THE REGISTRATION — additive, see the section header.
Object.keys(XML_SIGNATURE_METHODS).forEach(function (uri) {
  if (xmldsig.SIG_METHODS[uri]) {
    return;
  }
  const row = XML_SIGNATURE_METHODS[uri];
  xmldsig.SIG_METHODS[uri] = {
    family: row.family, hash: row.hash, keyKind: row.keyTypes[0],
    digestUri: XENC_NS + 'sha256', label: row.label,
    registeredBy: 'common/crypto.js'
  };
});
Object.keys(XML_DIGEST_METHODS).forEach(function (uri) {
  if (xmldsig.DIGEST_METHODS[uri]) {
    return;
  }
  const row = XML_DIGEST_METHODS[uri];
  xmldsig.DIGEST_METHODS[uri] = {
    md: forgeShapedDigest(row.hash),
    label: row.label + (row.weak ? ' (weak)' : ''),
    registeredBy: 'common/crypto.js'
  };
});

// Whether SHA-1 signatures are accepted. Read on every call: runtime. As IN
// FORCE since #181: `saml.allowSha1Signatures` on is development's, so a
// product realm refuses SHA-1 whatever is stored and says so once
// (`mode.valueInForce()`, STS-CORE-0106).
/**
 * Says whether SHA-1 XML signatures are accepted, as in force now; a
 * product realm refuses them whatever is stored.
 *
 * @returns true when accepted
 */
function sha1Allowed() {
  log.debug("Entering sha1Allowed().");
  const on = mode.valueInForce('saml.allowSha1Signatures') === true;
  log.debug("Leaving sha1Allowed(). " + on);
  return on;
}

// What a SignatureMethod and a set of DigestMethods amount to, before any
// cryptography: `{ problem, code, weak, sha1 }`. `problem` is '' when the
// algorithms are ones this file verifies and policy allows.
/**
 * Says what a SignatureMethod and DigestMethods amount to, before any
 * cryptography.
 *
 * @param signatureMethod - the SignatureMethod URI
 * @param digestMethods - the DigestMethod URIs
 * @returns `{ problem, code, weak, sha1 }`, `problem` empty when they are
 *   verified here and policy allows them
 */
function xmlAlgorithmVerdict(signatureMethod, digestMethods) {
  log.debug("Entering xmlAlgorithmVerdict(). " + signatureMethod);
  const sig = XML_SIGNATURE_METHODS[String(signatureMethod || '')];
  const out = { problem: '', code: '', weak: false, sha1: false,
                label: sig ? sig.label : String(signatureMethod || '') };
  if (!sig) {
    const why = XML_SIGNATURE_REFUSED[String(signatureMethod || '')];
    out.problem = 'the SignatureMethod ' +
      (signatureMethod ? '"' + signatureMethod + '"' : '(none)') +
      ' is not one this service verifies' + (why ? ': ' + why : '');
    out.code = 'STS-KEYS-0061';
    log.debug("Leaving xmlAlgorithmVerdict(). Unknown SignatureMethod.");
    return out;
  }
  out.weak = sig.weak;
  out.sha1 = sig.sha1;
  const digests = digestMethods || [];
  for (let i = 0; i < digests.length; i++) {
    const uri = String(digests[i] || '');
    const dig = XML_DIGEST_METHODS[uri];
    if (!dig) {
      out.problem = 'the DigestMethod "' + uri + '" is not one this ' +
        'service computes' + (XML_DIGEST_REFUSED[uri]
          ? ': ' + XML_DIGEST_REFUSED[uri] : '');
      out.code = 'STS-KEYS-0061';
      log.debug("Leaving xmlAlgorithmVerdict(). Unknown DigestMethod.");
      return out;
    }
    out.weak = out.weak || dig.weak;
    out.sha1 = out.sha1 || dig.sha1;
  }
  if (out.sha1 && !sha1Allowed()) {
    out.problem = 'the signature uses SHA-1 (' + out.label +
      (digests.some(function (d) {
        return (XML_DIGEST_METHODS[String(d)] || {}).sha1;
      }) ? ', or a SHA-1 DigestMethod' : '') + '), which is weak and ' +
      'refused while saml.allowSha1Signatures is off — and always in ' +
      'product mode';
    out.code = 'STS-KEYS-0062';
    log.debug("Leaving xmlAlgorithmVerdict(). SHA-1 refused.");
    return out;
  }
  log.debug("Leaving xmlAlgorithmVerdict(). Usable, weak=" + out.weak);
  return out;
}

// A public key to verify with, from a certificate (PEM or base64 DER) or a
// public key PEM. `{ key, subject }` or `{ problem }`; never throws.
function verificationKeyFrom(certPem, publicKeyPem) {
  log.debug("Entering verificationKeyFrom().");
  try {
    if (certPem) {
      const text = String(certPem).trim();
      const cert = text.indexOf('-----BEGIN') === 0
        ? new nodeCrypto.X509Certificate(text)
        : new nodeCrypto.X509Certificate(
          Buffer.from(text.replace(/\s+/g, ''), 'base64'));
      const cn = /(?:^|\n)CN=([^\n]*)/.exec(cert.subject || '');
      log.debug("Leaving verificationKeyFrom(). A certificate.");
      return { key: cert.publicKey, subject: cn ? cn[1] : '',
               certificate: cert };
    }
    if (publicKeyPem) {
      log.debug("Leaving verificationKeyFrom(). A public key.");
      return { key: nodeCrypto.createPublicKey(String(publicKeyPem)),
               subject: '' };
    }
  } catch (e) {
    log.debug("Caught in verificationKeyFrom(): " + ((e && e.message) || e));
    log.debug("Leaving verificationKeyFrom(). Unreadable.");
    return { problem: 'the ' + (certPem ? 'certificate' : 'public key') +
             ' could not be read: ' + ((e && e.message) || e) };
  }
  log.debug("Leaving verificationKeyFrom(). Nothing given.");
  return { problem: 'no certificate or public key was given' };
}

// Whether a key TYPE (node's `asymmetricKeyType`) makes an XML signature
// this file verifies.
/**
 * Says whether a key type makes an XML signature this file verifies.
 *
 * @param type - node's `asymmetricKeyType`
 * @returns true when it does
 */
function xmlSignatureKeyTypeUsable(type) {
  log.debug("Entering xmlSignatureKeyTypeUsable(). " + type);
  const usable = Object.keys(XML_SIGNATURE_METHODS).some(function (uri) {
    return XML_SIGNATURE_METHODS[uri].keyTypes.indexOf(String(type)) >= 0;
  });
  log.debug("Leaving xmlSignatureKeyTypeUsable(). " + usable);
  return usable;
}

// Whether a certificate's key can make an XML signature this file verifies —
// the question a registration asks before trusting one. '' when it can.
/**
 * Says whether a certificate's key can make an XML signature this file
 * verifies.
 *
 * @param certificate - the certificate
 * @returns the problem, or empty when it can
 */
function xmlSignatureKeyProblem(certificate) {
  log.debug("Entering xmlSignatureKeyProblem().");
  const found = verificationKeyFrom(certificate, null);
  if (found.problem) {
    log.debug("Leaving xmlSignatureKeyProblem(). Unreadable.");
    return found.problem;
  }
  const type = String(found.key.asymmetricKeyType || '');
  const weakCurve = type === 'ec' ? xmlEcdsaCurveProblem(found.key) : '';
  if (weakCurve) {
    log.debug("Leaving xmlSignatureKeyProblem(). " + weakCurve);
    return 'its public key is ' + weakCurve;
  }
  const usable = xmlSignatureKeyTypeUsable(type);
  log.debug("Leaving xmlSignatureKeyProblem(). " + type + " usable=" + usable);
  return usable ? '' : 'its public key is ' + (type || 'of an unknown type') +
    ', which makes no XML signature this service verifies';
}

// The RSAPSSParams of a `rsa-pss` SignatureMethod element, with RFC 9231
// section 2.3.9's defaults. `{ hash, saltLength }` or `{ problem }`.
function pssParameters(methodElement) {
  log.debug("Entering pssParameters().");
  const out = { hash: 'sha256', saltLength: -1, problem: '' };
  const params = methodElement
    ? methodElement.getElementsByTagNameNS(PSS_PARAMS_NS, 'RSAPSSParams')[0]
    : null;
  if (params) {
    const digest = params.getElementsByTagNameNS(DS_NS, 'DigestMethod')[0];
    if (digest) {
      const row = XML_DIGEST_METHODS[digest.getAttribute('Algorithm') || ''];
      if (!row) {
        out.problem = 'its RSAPSSParams names a DigestMethod this service ' +
          'does not compute';
        log.debug("Leaving pssParameters(). Unknown digest.");
        return out;
      }
      out.hash = row.hash;
    }
    const mgf = params.getElementsByTagNameNS(PSS_PARAMS_NS,
                                              'MaskGenerationFunction')[0];
    if (mgf) {
      const mgfDigest = mgf.getElementsByTagNameNS(DS_NS, 'DigestMethod')[0];
      const mgfRow = mgfDigest
        ? XML_DIGEST_METHODS[mgfDigest.getAttribute('Algorithm') || '']
        : XML_DIGEST_METHODS[XENC_NS + 'sha256'];
      if (String(mgf.getAttribute('Algorithm') || '') !==
            XMLDSIG_MORE_2007 + 'MGF1' ||
          !mgfRow || mgfRow.hash !== out.hash) {
        // Node's PSS verifier hashes MGF1 with the message digest; a
        // different MGF digest is a parameter set it cannot express.
        out.problem = 'its RSAPSSParams asks for a mask generation function ' +
          'other than MGF1 with the message digest, which node cannot verify';
        log.debug("Leaving pssParameters(). MGF mismatch.");
        return out;
      }
    }
    const salt = params.getElementsByTagNameNS(PSS_PARAMS_NS, 'SaltLength')[0];
    if (salt) {
      out.saltLength = parseInt(String(salt.textContent || '').trim(), 10);
      if (!(out.saltLength >= 0)) {
        out.problem = 'its RSAPSSParams SaltLength is not a number';
        log.debug("Leaving pssParameters(). Bad salt.");
        return out;
      }
    }
    const trailer = params.getElementsByTagNameNS(PSS_PARAMS_NS,
                                                  'TrailerField')[0];
    if (trailer && String(trailer.textContent || '').trim() !== '1') {
      out.problem = 'its RSAPSSParams TrailerField is not 1';
      log.debug("Leaving pssParameters(). Bad trailer.");
      return out;
    }
  }
  if (out.saltLength < 0) {
    out.saltLength = nodeCrypto.createHash(out.hash).digest().length;
  }
  log.debug("Leaving pssParameters(). " + out.hash + "/" + out.saltLength);
  return out;
}

// ---------------------------------------------------------------------------
// AN XML ECDSA KEY ON A CURVE WEAKER THAN P-256 (#202, 2026-09-24).
// Wycheproof's secp160/secp192/secp224 vectors verified through
// verifyXmlSignatureValue() because nothing asked which curve a
// certificate's key was on — XMLDSig names no curve, so any curve node's
// OpenSSL loads was accepted. Under 128 bits of security is refused in
// PRODUCT (NIST SP 800-57 part 1, table 2; `mode.usesBrokenAlgorithms()`,
// REQUIREMENTS `xml-ecdsa-curves`) by an ALLOW-list of the curves of at
// least 256 bits, so a curve nobody listed is refused rather than guessed
// at. Development keeps every curve, so a partner on one can be exercised.
// ---------------------------------------------------------------------------
const XML_ECDSA_CURVES = ['prime256v1', 'secp384r1', 'secp521r1',
                          'secp256k1', 'brainpoolP256r1', 'brainpoolP320r1',
                          'brainpoolP384r1', 'brainpoolP512r1'];

function xmlEcdsaCurveProblem(key) {
  log.debug("Entering xmlEcdsaCurveProblem().");
  const curve = String(((key && key.asymmetricKeyDetails) || {})
    .namedCurve || '');
  if (XML_ECDSA_CURVES.indexOf(curve) >= 0 || mode.usesBrokenAlgorithms()) {
    log.debug("Leaving xmlEcdsaCurveProblem(). " + curve + " allowed.");
    return '';
  }
  log.debug("Leaving xmlEcdsaCurveProblem(). " + curve + " refused.");
  return 'an ECDSA key on ' + (curve || 'an unnamed curve') + ', weaker ' +
    'than P-256, which verifies no XML signature in product mode';
}

// THE ONE PRIMITIVE: does `signature` verify over `octets` under
// `signatureMethod` with `key`? A key of the wrong type for the method is
// `false` — another registered certificate may be the right one — and never a
// throw. `pss` is pssParameters()'s answer for `rsa-pss`.
/**
 * Says whether a signature verifies over octets under a SignatureMethod
 * with a key; a key of the wrong type is false, never a throw.
 *
 * @param signatureMethod - the SignatureMethod URI
 * @param key - the public key
 * @param octets - the canonical SignedInfo
 * @param signature - the signature value
 * @param pss - the PSS parameters for `rsa-pss`
 * @returns true when it verifies
 */
function verifyXmlSignatureValue(signatureMethod, key, octets, signature, pss) {
  log.debug("Entering verifyXmlSignatureValue(). " + signatureMethod);
  const row = XML_SIGNATURE_METHODS[String(signatureMethod || '')];
  if (!row) {
    log.debug("Leaving verifyXmlSignatureValue(). Unknown method.");
    throw new Error('no verifier for ' + signatureMethod);
  }
  const type = String((key && key.asymmetricKeyType) || '');
  if (row.keyTypes.indexOf(type) < 0) {
    log.debug("Leaving verifyXmlSignatureValue(). A " + type + " key.");
    return false;
  }
  if ((row.family === 'rsa' || row.family === 'rsa-pss') &&
      rsaKeyProblem(key, 0)) {
    // An exponent or a modulus that makes a forgery (#202, rsaKeyProblem());
    // no size floor, XMLDSig has none and SAML partners still sign with
    // 1024-bit keys.
    log.debug("Leaving verifyXmlSignatureValue(). A forgeable RSA key.");
    return false;
  }
  if (row.family === 'ecdsa' && xmlEcdsaCurveProblem(key)) {
    log.info(errorCodes.tag('STS-KEYS-0077') + 'an XML signature was ' +
             'refused: ' + xmlEcdsaCurveProblem(key));
    log.debug("Leaving verifyXmlSignatureValue(). A weak curve.");
    return false;
  }
  let ok = false;
  try {
    if (row.family === 'rsa') {
      ok = nodeCrypto.verify(row.hash, octets, {
        key: key, padding: nodeCrypto.constants.RSA_PKCS1_PADDING }, signature);
    } else if (row.family === 'rsa-pss') {
      const params = pss || { hash: row.hash,
        saltLength: nodeCrypto.createHash(row.hash).digest().length };
      ok = nodeCrypto.verify(params.hash, octets, {
        key: key, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: params.saltLength }, signature);
    } else if (row.family === 'ecdsa' || row.family === 'dsa') {
      ok = nodeCrypto.verify(row.hash, octets,
        { key: key, dsaEncoding: 'ieee-p1363' }, signature);
      if (!ok && signature.length && signature[0] === 0x30) {
        // A DER Ecdsa-Sig-Value where XMLDSig 1.1 asks for r||s.
        ok = nodeCrypto.verify(row.hash, octets,
          { key: key, dsaEncoding: 'der' }, signature);
      }
    } else {
      // EdDSA and the post-quantum schemes hash internally.
      ok = nodeCrypto.verify(null, octets, key, signature);
    }
  } catch (e) {
    // A malformed value (wrong length, not DER) is a signature that does not
    // verify, which is what the caller reports.
    log.debug("Caught in verifyXmlSignatureValue(): " +
              ((e && e.message) || e));
    ok = false;
  }
  log.debug("Leaving verifyXmlSignatureValue(). " + ok);
  return !!ok;
}

// A description of every method, for the crypto metadata page and the tests.
/**
 * Describes every XML signature method, for the crypto metadata page and
 * the tests.
 *
 * @returns the descriptions
 */
function xmlSignatureAlgorithms() {
  log.debug("Entering xmlSignatureAlgorithms().");
  log.debug("Leaving xmlSignatureAlgorithms().");
  return {
    verified: Object.keys(XML_SIGNATURE_METHODS).map(function (uri) {
      const row = XML_SIGNATURE_METHODS[uri];
      return { uri: uri, label: row.label, family: row.family,
               hash: row.hash || '', keyTypes: row.keyTypes.slice(0),
               weak: row.weak, sha1: row.sha1 };
    }),
    refused: Object.keys(XML_SIGNATURE_REFUSED).map(function (uri) {
      return { uri: uri, why: XML_SIGNATURE_REFUSED[uri] };
    }),
    digests: Object.keys(XML_DIGEST_METHODS).map(function (uri) {
      const row = XML_DIGEST_METHODS[uri];
      return { uri: uri, label: row.label, weak: row.weak, sha1: row.sha1 };
    }),
    refusedDigests: Object.keys(XML_DIGEST_REFUSED).map(function (uri) {
      return { uri: uri, why: XML_DIGEST_REFUSED[uri] };
    }),
    sha1Allowed: sha1Allowed()
  };
}

// Every X509Certificate element's text emptied, in a serialized signature —
// what the vendored engine is handed when the key comes from here, so that it
// never tries to read (with forge, RSA only) a certificate this file already
// decided about. Only the text: the element and KeyInfo stay where they are.
function withoutCertificateText(signatureXml) {
  log.debug("Entering withoutCertificateText().");
  log.debug("Leaving withoutCertificateText().");
  return String(signatureXml).replace(
    /(<(?:[A-Za-z_][\w.-]*:)?X509Certificate\b[^>]*>)[^<]*(<\/)/g, '$1$2');
}

// ---------------------------------------------------------------------------
// VERIFY THE SIGNATURE ON ONE NAMED ELEMENT, AND ON NO OTHER.
//
// **`element` IS THE WHOLE REASON THIS FUNCTION IS NOT ONE LINE OVER THE
// VENDORED verifyXml(), AND THE BUG IT PREVENTS IS A REAL ONE THAT WAS
// MEASURED.** A SAML Response carrying a signed assertion has TWO signatures.
// Every general-purpose verifier — the vendored one, and three of the four
// implementations this replaced — takes the FIRST <ds:Signature> in document
// order. On a SAML 1.1 Browser/POST response, where this service signs the
// Response LAST, the first one is the ASSERTION'S. So a caller asking "is this
// Response signed by us" was handed a confident `true` about a different
// element. That is one small step from accepting a Response whose assertion was
// swapped for another validly-signed one, which is the signature-wrapping
// attack the guards in every XML library exist to stop.
//
// So the target is chosen HERE, by policy: the first element with the wanted
// local name that carries a ds:Signature as a DIRECT CHILD. The vendored engine
// is then handed exactly two things — that one signature, serialized on its
// own, and the target element with that signature removed as `referencedXml`.
// It has no opportunity to choose differently, and it still brings its full
// algorithm coverage: RSA, PSS, ECDSA, HMAC, every canonicalization, the
// transforms.
//
// Removing the signature before handing over is not a trick; it is what the
// enveloped-signature transform is DEFINED to do (XMLDSIG section 6.6.4 — the
// signature element is omitted from the digest). The transform then finds
// nothing left to remove and is a no-op, which is the correct outcome and not a
// skipped check.
//
// It ANSWERS RATHER THAN THROWS, and `present` is separate from `ok` because
// "there is no signature here" and "the signature is wrong" are different facts
// that every caller reports differently.
//
// ONE LIMIT, STATED RATHER THAN DISCOVERED: a NESTED element is verified from
// its serialized subtree, so namespace prefixes declared by an ANCESTOR and
// merely inherited are not in those octets. Under exclusive c14n — which is
// what this service signs with, what SAML mandates, and what every partner seen
// here uses — that is exactly right, because exclusive c14n renders only
// visibly-utilized prefixes and deliberately ignores inherited ones. Under
// INCLUSIVE c14n it would not be, so that case is detected and reported below
// rather than being quietly wrong. **A ROOT element under inclusive c14n IS
// verified since 2026-09-17** — see the SignedInfo note further down, where
// the in-scope namespace declarations are put back before the engine reads it.
// ---------------------------------------------------------------------------
/**
 * Verifies the signature on one named element and on no other, against the
 * certificates the caller trusts. It answers rather than throws.
 *
 * @param xml - the document
 * @param opts - `element` (which one), and `certPem` or `publicKeyPem`
 * @returns the verdict `{ ok, present, why, signatureValid,
 *   referencesValid, signatureMethod, … }`, a refusal carrying its code
 */
function verifyXmlSignature(xml, opts) {
  log.debug("Entering verifyXmlSignature().");
  const options = opts || {};
  const wanted = options.element;
  log.debug('Entering verifyXmlSignature(). element=' + wanted);
  if (!wanted) {
    log.debug('Leaving verifyXmlSignature(). No element named.');
    throw new Error('verifyXmlSignature: `element` is required — a verifier ' +
                    'that guesses which signature it is checking is the bug ' +
                    'this function exists to prevent.');
  }

  let doc;
  try {
    doc = new xmldom.DOMParser().parseFromString(String(xml), 'text/xml');
  } catch (e) {
    // Not XML at all. The parser's own message is more use than one of ours,
    // and this is somebody else's document being wrong rather than a fault
    // here.
    log.debug('Leaving verifyXmlSignature(). It did not parse: ' + e.message);
    return errorCodes.mark({ ok: false, present: false,
             why: 'the document is not well-formed XML: ' + e.message },
                           'STS-KEYS-0007');
  }

  // The target: the first element of that name carrying its OWN signature.
  let target = null;
  let sigEl = null;
  const candidates = doc.getElementsByTagName('*');
  for (let i = 0; i < candidates.length && !target; i++) {
    if (candidates[i].localName !== wanted) {
      continue;
    }
    const own = directChildByLocal(candidates[i], 'Signature', DS_NS);
    if (own) {
      target = candidates[i];
      sigEl = own;
    }
  }

  if (!target) {
    // Two different facts, and telling them apart is most of the diagnosis: a
    // document with no such element is a routing or profile mistake, and one
    // whose element is simply unsigned is a configuration mistake at the far
    // end. Reporting "no signature" for both sends people to the wrong place.
    let exists = false;
    for (let i = 0; i < candidates.length && !exists; i++) {
      exists = candidates[i].localName === wanted;
    }
    log.debug('Leaving verifyXmlSignature(). No signed <' + wanted + '>.');
    return errorCodes.mark({ ok: false, present: false,
             why: exists
               ? 'the <' + wanted + '> carries no ds:Signature of its own'
               : 'the document contains no <' + wanted + '> at all' },
                           'STS-KEYS-0008');
  }

  // The reference must name THIS element. A signature whose reference points
  // somewhere else may verify perfectly and say nothing whatever about the
  // element the caller asked about — which is signature wrapping, exactly.
  const signedInfo = directChildByLocal(sigEl, 'SignedInfo', DS_NS);
  const reference = signedInfo
    ? signedInfo.getElementsByTagNameNS('*', 'Reference')[0] : null;
  const referenceUri = reference ? (reference.getAttribute('URI') || '') : '';
  const targetId = idOf(target);
  if (referenceUri !== '' && referenceUri.replace(/^#/, '') !== targetId) {
    log.debug('Leaving verifyXmlSignature(). The reference names something ' +
              'else.');
    return errorCodes.mark({ ok: false, present: true,
             why: 'the signature on this <' + wanted + '> references "' +
                  referenceUri +
                  '" rather than the element it is attached to (' +
                  (targetId ? '#' + targetId : 'which carries no id') +
                  '), so it says nothing about this element' },
                           'STS-KEYS-0009');
  }

  // Inclusive canonicalization on a NESTED element: see the note above. Said
  // out loud rather than attempted, because a wrong answer here reads as a
  // broken signature and would send somebody looking at the signer.
  const c14nEl = signedInfo
    ? signedInfo.getElementsByTagNameNS('*', 'CanonicalizationMethod')[0] :
                 null;
  const c14nAlg = c14nEl ? (c14nEl.getAttribute('Algorithm') || '') : '';
  const isNested = target !== doc.documentElement;
  if (isNested && c14nAlg && c14nAlg.indexOf('xml-exc-c14n') === -1) {
    log.debug('Leaving verifyXmlSignature(). Inclusive c14n on a nested ' +
              'element.');
    return errorCodes.mark({ ok: false, present: true,
             why: 'this nested <' + wanted + '> is signed with ' + c14nAlg +
                  ', an INCLUSIVE canonicalization whose digest depends on ' +
                  'namespace declarations inherited from its ancestors. This ' +
                  'service verifies a nested element from its own subtree ' +
                  'and cannot reproduce those octets, so it refuses rather ' +
                  'than reporting a failure it did not really test' },
                           'STS-KEYS-0010');
  }

  // THE ALGORITHMS, BEFORE ANY CRYPTOGRAPHY (section 1a): one this file
  // does not verify, or SHA-1 while `saml.allowSha1Signatures` is off, is
  // refused here with its own code — a signature that cannot be checked is
  // not reported as one that was checked and found wrong.
  const methodEl = signedInfo
    ? signedInfo.getElementsByTagNameNS('*', 'SignatureMethod')[0] : null;
  const signatureMethod = methodEl
    ? String(methodEl.getAttribute('Algorithm') || '') : '';
  const digestMethods = [];
  const referenceEls = signedInfo
    ? signedInfo.getElementsByTagNameNS('*', 'Reference') : [];
  for (let i = 0; i < referenceEls.length; i++) {
    const digestEl = referenceEls[i]
      .getElementsByTagNameNS('*', 'DigestMethod')[0];
    digestMethods.push(digestEl
      ? String(digestEl.getAttribute('Algorithm') || '') : '');
  }
  const algorithms = xmlAlgorithmVerdict(signatureMethod, digestMethods);
  const pss = !algorithms.problem &&
    (XML_SIGNATURE_METHODS[signatureMethod] || {}).family === 'rsa-pss' &&
    signatureMethod === XMLDSIG_MORE_2007 + 'rsa-pss'
    ? pssParameters(methodEl) : null;
  if (algorithms.problem || (pss && pss.problem)) {
    log.debug('Leaving verifyXmlSignature(). Algorithm refused: ' +
              (algorithms.problem || pss.problem));
    return errorCodes.mark({ ok: false, present: true,
             why: algorithms.problem ||
                  'the RSASSA-PSS signature cannot be checked: ' + pss.problem,
             signatureMethod: signatureMethod, digestMethods: digestMethods,
             weak: algorithms.weak, sha1: algorithms.sha1 },
                           algorithms.code || 'STS-KEYS-0061');
  }

  // THE KEY, IN THE ORDER A CALLER MEANT: the certificate it named, else the
  // public key it named, else — only when it named neither — the document's
  // own certificate. (The vendored engine preferred the document's
  // certificate to a named public key; nothing here relies on that.) Read by
  // node, so an EC, EdDSA or post-quantum certificate is a key like any other.
  const certEl = sigEl.getElementsByTagNameNS('*', 'X509Certificate')[0];
  const keyInfoCert = certEl
    ? String(certEl.textContent || '').replace(/\s+/g, '') : '';
  const named = options.certPem || options.publicKeyPem;
  const found = named || keyInfoCert
    ? verificationKeyFrom(options.certPem ||
                          (options.publicKeyPem ? '' : keyInfoCert),
                          options.publicKeyPem)
    : null;
  if (found && found.problem) {
    log.debug('Leaving verifyXmlSignature(). No usable key: ' +
              found.problem);
    return errorCodes.mark({ ok: false, present: true,
             why: 'the signature cannot be checked: ' + found.problem,
             signatureMethod: signatureMethod, digestMethods: digestMethods,
             weak: algorithms.weak, sha1: algorithms.sha1,
             signerCertB64: keyInfoCert }, 'STS-KEYS-0014');
  }

  // INCLUSIVE CANONICALIZATION OF THE SIGNEDINFO (#37 follow-up). The
  // SignedInfo is always nested — inside the Signature, inside the signed
  // element — and inclusive c14n renders every namespace declaration IN
  // SCOPE there, including the ancestors'. The engine canonicalizes it from
  // the Signature serialized on its own, which drops those, so an inclusive
  // signature on even a ROOT element never verified. The in-scope
  // declarations are therefore copied onto the Signature before it is
  // serialized: inclusive c14n puts all of them on the SignedInfo either way,
  // so the octets are the signer's. (Exclusive c14n ignores them, and is left
  // alone.)
  if (c14nAlg && c14nAlg.indexOf('xml-exc-c14n') === -1) {
    const declared = {};
    for (let node = sigEl.parentNode; node && node.nodeType === 1;
         node = node.parentNode) {
      for (let i = 0; i < node.attributes.length; i++) {
        const attr = node.attributes[i];
        const name = String(attr.name || '');
        if ((name === 'xmlns' || name.indexOf('xmlns:') === 0) &&
            !Object.prototype.hasOwnProperty.call(declared, name)) {
          declared[name] = attr.value;
        }
      }
    }
    Object.keys(declared).forEach(function (name) {
      if (!sigEl.hasAttribute(name)) {
        sigEl.setAttribute(name, declared[name]);
      }
    });
  }

  const serializer = new xmldom.XMLSerializer();
  // With a key from here, the engine is not shown the certificate text: it
  // would try to read it with forge, which reads RSA only.
  const signatureXml = found
    ? withoutCertificateText(serializer.serializeToString(sigEl))
    : serializer.serializeToString(sigEl);
  sigEl.parentNode.removeChild(sigEl);
  const referencedXml = serializer.serializeToString(target);

  let result;
  try {
    result = xmldsig.verifyXml(signatureXml, found ? {
      referencedXml: referencedXml,
      verifier: function (octets, signatureBytes) {
        return verifyXmlSignatureValue(signatureMethod, found.key,
          Buffer.from(String(octets), 'binary'),
          Buffer.from(String(signatureBytes), 'binary'), pss);
      }
    } : {
      // NO KEY ANYWHERE BUT, PERHAPS, AN RSAKeyValue — the engine's own RSA
      // path, which is what it always was.
      referencedXml: referencedXml
    });
    if (found) {
      result.signerSubject = found.subject;
      result.signerCertB64 = keyInfoCert;
    }
  } catch (e) {
    // The engine throws rather than answering for a malformed signature
    // element or an algorithm it cannot name, and the message says WHICH — an
    // unresolvable reference reads quite differently from a digest mismatch,
    // and that distinction is the whole diagnosis. This comment used to exist,
    // word for word, in four separate files.
    log.debug('Leaving verifyXmlSignature(). It threw: ' + e.message);
    return errorCodes.mark({ ok: false, present: true, why: e.message },
                           'STS-KEYS-0011');
  }

  const firstRef = (result.references || [])[0] || {};
  let why = '';
  let whyCode = '';
  if (!result.valid) {
    if (result.signatureValid === false) {
      whyCode = 'STS-KEYS-0012';
      why = 'the signature value does not verify against the expected ' +
            'certificate' +
            (result.signatureError ? ': ' + result.signatureError : '');
    } else if (firstRef.ok === false) {
      whyCode = 'STS-KEYS-0013';
      why = 'the signature value is genuine but the digest does not match, ' +
            'so the <' + wanted + '> was altered after it was signed' +
            (firstRef.reason ? ' (' + firstRef.reason + ')' : '');
    } else {
      whyCode = 'STS-KEYS-0014';
      why = result.error || 'the signature did not verify';
    }
  }
  log.debug('Leaving verifyXmlSignature(). ok=' + result.valid);
  const verdict = {
    ok: !!result.valid,
    present: true,
    why: why,
    // Passed through for the pages that show a check-by-check verdict — the
    // WS-Federation mock relying party, the SAML mock service provider and the
    // OID4VP verifier all draw one, and one boolean would tell a person nothing
    // they could act on.
    signatureValid: !!result.signatureValid,
    referencesValid: !!result.referencesValid,
    signatureMethod: result.signatureMethod || '',
    canonicalization: result.canonicalization || '',
    signerSubject: result.signerSubject || '',
    signerCertB64: result.signerCertB64 || '',
    referenceUri: firstRef.uri === undefined ? referenceUri : firstRef.uri,
    // WHAT THE SIGNATURE WAS MADE WITH (section 1a): every DigestMethod, and
    // whether any of it is weak or SHA-1 — accepted SHA-1 is still `weak`.
    digestMethods: digestMethods,
    weak: algorithms.weak,
    sha1: algorithms.sha1
  };
  if (whyCode) {
    errorCodes.mark(verdict, whyCode);
  }
  log.debug("Leaving verifyXmlSignature().");
  return verdict;
}

// ---------------------------------------------------------------------------
// THE SAML HTTP REDIRECT BINDING'S DETACHED SIGNATURE (saml-bindings-2.0-os
// section 3.4.4.1). It is a signature over the QUERY STRING and not over any
// document, so it shares nothing with signXml() above except the key.
//
// The ORDER of the parameters in the signed octet string is part of the
// specification — SAMLRequest or SAMLResponse, then RelayState if there is one,
// then SigAlg — and building that string is the CALLER'S job, because only the
// caller knows which of the two message parameters it has. A verifier rebuilds
// it from the parameters as they arrived, so a signer that used a different
// order produces a signature that verifies nowhere and whose only symptom at
// the far end is "invalid signature".
// ---------------------------------------------------------------------------
// `privateKey` (#68 phase 4b) is a signer-group key for an ECDSA or
// post-quantum `sigAlg` — a KeyObject, or the raw bytes `pq_jose.js` signs
// with — for which the vendored signer, RSA through forge, has no path. The
// ECDSA signature is the raw r||s XML Signature 1.1 specifies, which is what
// the binding's SigAlg names; RSA takes the vendored path as it always has.
/**
 * Signs a query string for the SAML HTTP Redirect binding's detached
 * signature.
 *
 * @param queryString - the query string to sign
 * @param privateKeyPem - the RSA private key
 * @param sigAlg - the signature algorithm URI
 * @param privateKey - for an ECDSA or post-quantum `sigAlg`, the signer
 *   group's key
 * @returns the base64 signature
 */
function signQueryString(queryString, privateKeyPem, sigAlg, privateKey) {
  log.debug('Entering signQueryString().');
  const pqMethod = xmldsig.SIG_METHODS[sigAlg] &&
    xmldsig.SIG_METHODS[sigAlg].postQuantum
    ? xmldsig.SIG_METHODS[sigAlg] : null;
  const method = XML_SIGNATURE_METHODS[sigAlg] || null;
  if (pqMethod && privateKey) {
    const pqSignature = Buffer.from(pqJose.sign(String(pqMethod.alg),
      privateKey, Buffer.from(String(queryString), 'utf8')))
      .toString('base64');
    log.debug('Leaving signQueryString(). ' + pqMethod.alg + '.');
    return pqSignature;
  }
  if (method && method.family === 'ecdsa' && (privateKey || privateKeyPem)) {
    const ecSignature = nodeCrypto.sign(String(method.hash),
      Buffer.from(String(queryString), 'utf8'),
      { key: privateKey || nodeCrypto.createPrivateKey(privateKeyPem),
        dsaEncoding: 'ieee-p1363' }).toString('base64');
    log.debug('Leaving signQueryString(). ECDSA.');
    return ecSignature;
  }
  if (!privateKeyPem) {
    log.debug('Leaving signQueryString(). No private key.');
    throw new Error('signQueryString: privateKeyPem is required.');
  }
  const signature = xmldsig.signQueryString(queryString, {
    privateKeyPem: privateKeyPem,
    sigAlg: sigAlg
  });
  log.debug('Leaving signQueryString(). ' + signature.length + ' characters.');
  return signature;
}

// ---------------------------------------------------------------------------
// AND ITS VERIFIER (2026-09-17, #37), for a service provider's request on the
// HTTP Redirect binding.
//
// **THE CALLER BUILDS THE OCTETS, from the parameters AS THEY ARRIVED** —
// still URL-encoded, in the specification's order — for the reason the signer
// above gives: only the caller has the raw query string, and a verifier that
// re-encoded decoded values would fail every signature made by a service
// provider whose percent-encoding differs from node's (lower-case hex is the
// usual one).
//
// **THE CERTIFICATE IS REQUIRED.** A detached signature carries no KeyInfo, so
// there is nothing to fall back to, and the vendored verifier says so — but
// this wrapper refuses before asking it, because a verifier that could be
// called with no key is one somebody will call with no key. The key is any
// section 1a verifies — RSA, ECDSA (r||s), EdDSA, DSA, ML-DSA, SLH-DSA — and
// a `SigAlg` it does not verify, or SHA-1 while that is off, is refused by
// name rather than reported as a signature that failed.
//
// It ANSWERS RATHER THAN THROWS, like `verifyXmlSignature()`, and `ok` is
// separate from `usable`: "this signature is wrong" and "this could not be
// checked at all" are refused under different codes.
// ---------------------------------------------------------------------------
/**
 * Verifies a service provider's HTTP Redirect binding signature. It answers
 * rather than throws.
 *
 * @param queryString - the query string as received
 * @param opts - `signature`, `sigAlg` and `certPem` (the registered
 *   certificates)
 * @returns `{ ok, usable, … }`: `ok` separate from `usable`, whether it
 *   could be checked at all
 */
function verifyQueryString(queryString, opts) {
  log.debug('Entering verifyQueryString().');
  const options = opts || {};
  const sigAlg = String(options.sigAlg || '');
  if (!options.certPem) {
    log.debug('Leaving verifyQueryString(). No certificate.');
    return errorCodes.mark({ ok: false, usable: false,
                             signatureMethod: sigAlg,
                             why: 'no certificate was given to verify the ' +
                                  'detached signature against' },
                           'STS-KEYS-0060');
  }
  if (!options.signature) {
    log.debug('Leaving verifyQueryString(). No signature.');
    return errorCodes.mark({ ok: false, usable: false,
                             signatureMethod: sigAlg,
                             why: 'there is no Signature parameter' },
                           'STS-KEYS-0060');
  }
  // The algorithm and the policy first (section 1a). A binding signature
  // has no DigestMethod: the SigAlg is the whole of it.
  const algorithms = xmlAlgorithmVerdict(sigAlg, []);
  if (algorithms.problem) {
    log.debug('Leaving verifyQueryString(). ' + algorithms.problem);
    return errorCodes.mark({ ok: false, usable: false,
                             signatureMethod: sigAlg, weak: algorithms.weak,
                             sha1: algorithms.sha1,
                             why: algorithms.problem }, algorithms.code);
  }
  const found = verificationKeyFrom(options.certPem, null);
  if (found.problem) {
    log.debug('Leaving verifyQueryString(). ' + found.problem);
    return errorCodes.mark({ ok: false, usable: false,
                             signatureMethod: sigAlg,
                             why: found.problem }, 'STS-KEYS-0060');
  }
  const signature = String(options.signature).replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(signature)) {
    log.debug('Leaving verifyQueryString(). Not base64.');
    return errorCodes.mark({ ok: false, usable: false,
                             signatureMethod: sigAlg,
                             why: 'the Signature parameter is not base64' },
                           'STS-KEYS-0060');
  }
  // THE VENDORED ENGINE STILL DISPATCHES — it decodes the value and hands the
  // octets to the verifier, which is node (section 1a). No certificate is
  // passed to it: it would read one with forge, which reads RSA only.
  let result;
  try {
    result = xmldsig.verifyQueryString(String(queryString), {
      signature: signature,
      sigAlg: sigAlg,
      verifier: function (octets, signatureBytes) {
        return verifyXmlSignatureValue(sigAlg, found.key,
          Buffer.from(String(octets), 'binary'),
          Buffer.from(String(signatureBytes), 'binary'), null);
      }
    });
  } catch (e) {
    // The vendored verifier answers rather than throws for everything it
    // anticipates; this is the case it did not, and it is a signature that
    // could not be checked rather than one that was wrong.
    log.debug('Caught in verifyQueryString(): ' + ((e && e.message) || e));
    log.debug('Leaving verifyQueryString(). It threw.');
    return errorCodes.mark({ ok: false, usable: false,
                             signatureMethod: sigAlg,
                             why: (e && e.message) || String(e) },
                           'STS-KEYS-0060');
  }
  if (result.valid) {
    log.debug('Leaving verifyQueryString(). Verified.');
    return { ok: true, usable: true, signatureMethod: sigAlg,
             signerSubject: found.subject || '', why: '',
             weak: algorithms.weak, sha1: algorithms.sha1 };
  }
  if (result.error) {
    log.debug('Leaving verifyQueryString(). Not checkable: ' + result.error);
    return errorCodes.mark({ ok: false, usable: false,
                             signatureMethod: sigAlg,
                             why: result.error }, 'STS-KEYS-0060');
  }
  // A key of another type than the SigAlg names is reported here too, as a
  // signature that does not verify against THIS certificate: another
  // registered certificate may be the one that made it.
  log.debug('Leaving verifyQueryString(). It did not verify.');
  return errorCodes.mark({ ok: false, usable: true,
                           signatureMethod: sigAlg,
                           weak: algorithms.weak, sha1: algorithms.sha1,
                           why: 'the Signature parameter does not verify ' +
                                'against the certificate over the ' +
                                'parameters as they arrived' },
                         'STS-KEYS-0059');
}

// ===========================================================================
// SECTION 2 — XML ENCRYPTION
// ===========================================================================
//
// ---------------------------------------------------------------------------
// THIS SECTION IS MOVED FROM `saml/saml2.ts` RATHER THAN REPLACED BY THE
// VENDORED encryptXml()/decryptXml(), AND THAT IS A DELIBERATE EXCEPTION TO
// EVERYTHING SAID AT THE TOP OF THIS FILE. It is worth the paragraph, because
// the obvious reading of this refactor is that the vendored module always wins.
//
// It does not win here, for two reasons and neither is inertia. The OUTPUT of
// the two is already byte-compatible — same EncryptedData shape, same
// EncryptedKey nesting, same echoed recipient certificate, verified element by
// element — so there was no interop gap to close, which was the whole argument
// for the signature half. And what this implementation has that the vendored
// one does not is the DIAGNOSIS: it answers rather than throwing, it names an
// unknown cipher and an unknown key transport separately, it checks the
// unwrapped key's LENGTH (because RSA-1_5 unwraps a wrong key to plausible
// garbage instead of failing), it parses the plaintext before calling CBC a
// success, and it tells a NamespaceError in a perfectly good NameID apart from
// a wrong certificate. Every one of those messages exists because somebody once
// chased the wrong thing, and a mock whose whole value is explaining what went
// wrong does not trade them for a shared line count.
//
// So this is centralization by MOVE. It was already one implementation with two
// callers; it is now one implementation in the module where the other three
// crypto families live, and `saml/saml2.ts` re-exports it so WS-Trust's
// `?encrypt=1` path is untouched.
// ---------------------------------------------------------------------------

// Every block cipher this service will encrypt with or decrypt, by its
// algorithm URI. `keyBytes` is the AES key length; `mode` is what forge calls
// it; `ivBytes` and `tagBytes` are the layout above. A URI that is not here is
// refused BY NAME on the way in and cannot be chosen on the way out, because
// the setting is an enum over exactly these keys.
/** Every XML Encryption block cipher this service speaks, by name. */
const BLOCK_CIPHERS = {
  'aes256-gcm': { uri: XENC11_NS + 'aes256-gcm', keyBytes: 32, mode: 'AES-GCM',
                  ivBytes: 12, tagBytes: 16 },
  'aes128-gcm': { uri: XENC11_NS + 'aes128-gcm', keyBytes: 16, mode: 'AES-GCM',
                  ivBytes: 12, tagBytes: 16 },
  'aes256-cbc': { uri: XENC_NS + 'aes256-cbc', keyBytes: 32, mode: 'AES-CBC',
                  ivBytes: 16, tagBytes: 0 },
  'aes128-cbc': { uri: XENC_NS + 'aes128-cbc', keyBytes: 16, mode: 'AES-CBC',
                  ivBytes: 16, tagBytes: 0 },
  // AES-192 IN BOTH MODES JOINED ON 2026-09-24 (#193). XML Encryption 1.1
  // section 5.2 lists both as OPTIONAL, and this service unwrapped a 192-bit
  // key (kw-aes192) and then refused the content it protected: the W3C
  // interop set's P-384 and RSA-3072 cases are exactly that pair. It is a
  // cipher this service READS; nothing encrypts with it unless a caller
  // asks by name — `saml2.encryptionAlgorithm`'s enum does not offer it.
  'aes192-gcm': { uri: XENC11_NS + 'aes192-gcm', keyBytes: 24, mode: 'AES-GCM',
                  ivBytes: 12, tagBytes: 16 },
  'aes192-cbc': { uri: XENC_NS + 'aes192-cbc', keyBytes: 24, mode: 'AES-CBC',
                  ivBytes: 16, tagBytes: 0 }
};

// The three key transports. `rsa-1_5` is RSAES-PKCS1-v1_5 and is offered
// because old service providers require it, not because it is safe.
//
// **`rsa-oaep` JOINED ON 2026-09-23 (#168)**: XML Encryption 1.1 section
// 5.5.2's RSAES-OAEP with the digest and the mask generation function NAMED —
// `<ds:DigestMethod>` and `<xenc11:MGF>` children of the EncryptionMethod —
// written here as SHA-256 and MGF1-SHA-256. It is what a federation
// relationship's service-provider key is published with, so this service's
// own identity provider has to be able to encrypt to it. Node performs it
// (`oaepHash` names the digest of the OAEP padding AND of MGF1), forge does
// not, which is why its two directions below go through node's OpenSSL.
/** The three XML Encryption key transports, by name. */
const KEY_TRANSPORTS = {
  'rsa-oaep': { uri: XENC11_NS + 'rsa-oaep', scheme: 'RSA-OAEP',
                hash: 'sha256', node: true },
  'rsa-oaep-mgf1p': { uri: XENC_NS + 'rsa-oaep-mgf1p', scheme: 'RSA-OAEP' },
  'rsa-1_5': { uri: XENC_NS + 'rsa-1_5', scheme: 'RSAES-PKCS1-V1_5' }
};

// THE DIGESTS AN rsa-oaep EncryptionMethod MAY NAME, by the URI XML Encryption
// 1.1 section 5.2 gives each, and the MGF1 URIs of section 5.5.2. Absent, both
// are SHA-1 (section 5.5.2: "SHA-1 is used as the default"). Node derives the
// MGF1 digest from the OAEP digest, so a document naming two DIFFERENT ones
// is refused by name rather than read under the wrong one — which would fail
// exactly as a wrong key fails, and send somebody to the wrong place.
/** The digests an `rsa-oaep` EncryptionMethod may name, by URI. */
const OAEP_DIGESTS = {
  sha1: DS_NS + 'sha1',
  sha256: XENC_NS + 'sha256',
  sha384: 'http://www.w3.org/2001/04/xmldsig-more#sha384',
  sha512: XENC_NS + 'sha512'
};
/** The MGF1 URIs of XML Encryption 1.1 section 5.5.2. */
const MGF1_URIS = {
  sha1: XENC11_NS + 'mgf1sha1',
  sha256: XENC11_NS + 'mgf1sha256',
  sha384: XENC11_NS + 'mgf1sha384',
  sha512: XENC11_NS + 'mgf1sha512'
};

// ---------------------------------------------------------------------------
// KEY AGREEMENT: XML Encryption 1.1 section 5.6.4's ECDH-ES, and the AES key
// wraps (section 5.7.2) the agreed key encrypts the content key with (#168).
//
// A recipient whose key is EC has no RSA key to transport to, so the sender
// generates an EPHEMERAL key pair on the same curve, agrees a secret with the
// recipient's public key, derives a key-encryption key from it with section
// 5.4.1's ConcatKDF, and wraps the content key under that. The ephemeral
// public key travels in `<xenc:OriginatorKeyInfo>` as a `<dsig11:ECKeyValue>`
// — the curve by OID and the point uncompressed — because without it there is
// no agreement at the far end.
//
// **THE KDF's OtherInfo IS THREE ATTRIBUTES, EACH A BIT STRING WITH A LEADING
// PAD-COUNT OCTET** (section 5.4.1): the octet that says how many padding bits
// the last octet carries is part of the hexBinary and NOT part of the bits.
// Reading it as data would agree with a matching bug and nothing else. This
// service writes AlgorithmID as the key-wrap URI and the two party infos
// empty, and reads whatever a sender wrote.
//
// **NO POST-QUANTUM KEY ENCAPSULATION.** Neither W3C nor OASIS has defined an
// ML-KEM method for XML Encryption, so confidentiality here stays classical
// against a harvest-now-decrypt-later adversary; see federation/CLAUDE.md.
// ---------------------------------------------------------------------------
/** XML Encryption 1.1's ECDH-ES key agreement. */
const KEY_AGREEMENTS = {
  'ecdh-es': { uri: XENC11_NS + 'ECDH-ES' }
};
const CONCAT_KDF_URI = XENC11_NS + 'ConcatKDF';
/** The AES key wraps an agreed key encrypts the content key with. */
const KEY_WRAPS = {
  'kw-aes128': { uri: XENC_NS + 'kw-aes128', bytes: 16 },
  'kw-aes192': { uri: XENC_NS + 'kw-aes192', bytes: 24 },
  'kw-aes256': { uri: XENC_NS + 'kw-aes256', bytes: 32 }
};
const DSIG11_NS = 'http://www.w3.org/2009/xmldsig11#';
// The named curves an ECKeyValue may name, by OID, and each coordinate's
// length in octets.
const XML_EC_CURVES = {
  'urn:oid:1.2.840.10045.3.1.7': { crv: 'P-256', bytes: 32 },
  'urn:oid:1.3.132.0.34': { crv: 'P-384', bytes: 48 },
  'urn:oid:1.3.132.0.35': { crv: 'P-521', bytes: 66 }
};
const XML_EC_OIDS = { 'P-256': 'urn:oid:1.2.840.10045.3.1.7',
                      'P-384': 'urn:oid:1.3.132.0.34',
                      'P-521': 'urn:oid:1.3.132.0.35' };

function keyWrapByUri(uri) {
  log.debug("Entering keyWrapByUri().");
  const name = Object.keys(KEY_WRAPS).filter(function (key) {
    return KEY_WRAPS[key].uri === uri;
  })[0];
  log.debug("Leaving keyWrapByUri().");
  return name ? Object.assign({ name: name }, KEY_WRAPS[name]) : null;
}

function nameOfUri(table, uri) {
  log.debug("Entering nameOfUri().");
  const name = Object.keys(table).filter(function (key) {
    return table[key] === uri;
  })[0];
  log.debug("Leaving nameOfUri().");
  return name || '';
}

// A ConcatKDFParams attribute's bits, as octets: the hexBinary less its
// leading pad-count octet. Bits are only ever whole octets here, so a
// non-zero pad count is refused rather than truncated.
function concatKdfBits(hex, what) {
  log.debug("Entering concatKdfBits(). " + what);
  const text = String(hex || '');
  if (!text) {
    log.debug("Leaving concatKdfBits(). Absent.");
    return Buffer.alloc(0);
  }
  if (!/^([0-9A-Fa-f]{2})+$/.test(text)) {
    log.debug("Leaving concatKdfBits(). Not hexBinary.");
    throw new Error('the ConcatKDFParams ' + what + ' is not hexBinary');
  }
  const bytes = Buffer.from(text, 'hex');
  if (bytes[0] !== 0) {
    log.debug("Leaving concatKdfBits(). A partial octet.");
    throw new Error('the ConcatKDFParams ' + what + ' declares ' + bytes[0] +
                    ' padding bits, and this service reads whole octets');
  }
  log.debug("Leaving concatKdfBits().");
  return bytes.subarray(1);
}

// Section 5.4.1's KDF over Z. `otherInfo` is AlgorithmID || PartyUInfo ||
// PartyVInfo [|| SuppPubInfo [|| SuppPrivInfo]], the counter a 32-bit
// big-endian integer from 1, one digest per round.
function xmlConcatKdf(z, keyBytes, hash, otherInfo) {
  log.debug("Entering xmlConcatKdf(). " + hash + ", " + keyBytes + " bytes.");
  const size = nodeCrypto.createHash(hash).digest().length;
  const rounds = Math.ceil(keyBytes / size);
  const blocks = [];
  for (let i = 1; i <= rounds; i++) {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(i);
    blocks.push(nodeCrypto.createHash(hash)
      .update(Buffer.concat([counter, z, otherInfo])).digest());
  }
  log.debug("Leaving xmlConcatKdf().");
  return Buffer.concat(blocks).subarray(0, keyBytes);
}

function hexBits(bytes) {
  log.debug("Entering hexBits().");
  log.debug("Leaving hexBits().");
  return '00' + Buffer.from(bytes).toString('hex').toUpperCase();
}

/**
 * Returns the block cipher an algorithm URI names.
 *
 * @param uri - the EncryptionMethod URI
 * @returns the cipher with its `name`, or null
 */
function cipherByUri(uri) {
  log.debug("Entering cipherByUri().");
  const name = Object.keys(BLOCK_CIPHERS).filter(function (key) {
    return BLOCK_CIPHERS[key].uri === uri;
  })[0];
  log.debug("Leaving cipherByUri().");
  return name ? Object.assign({ name: name }, BLOCK_CIPHERS[name]) : null;
}

/**
 * Returns the key transport an algorithm URI names.
 *
 * @param uri - the EncryptionMethod URI
 * @returns the transport with its `name`, or null
 */
function transportByUri(uri) {
  log.debug("Entering transportByUri().");
  const name = Object.keys(KEY_TRANSPORTS).filter(function (key) {
    return KEY_TRANSPORTS[key].uri === uri;
  })[0];
  log.debug("Leaving transportByUri().");
  return name ? Object.assign({ name: name }, KEY_TRANSPORTS[name]) : null;
}

// ---------------------------------------------------------------------------
// ENCRYPT ONE ELEMENT, wrapped in whatever the caller says.
//
// `wrapper` is the SAML element that holds the result — `EncryptedAssertion`
// for a Response, `EncryptedID` for a NameID in a LogoutRequest — and it is a
// parameter because those two are the same document with a different name
// around it. A third caller passes a third name and needs no new function.
//
// The RECIPIENT'S CERTIFICATE is echoed into ds:KeyInfo. That is not required
// and it is deliberate: a service provider with more than one key has to be
// told which one this was encrypted to, and the alternative — a KeyName, or
// nothing — leaves it guessing. It is the recipient's OWN public certificate,
// so publishing it back to them discloses nothing.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE ARTIFACT LOG, PASSED IN RATHER THAN REACHED FOR.
//
// `helpers.logArtifact()` writes the before-and-after of everything this
// service mints, and at the default `debug` level that IS the product: a mock
// exists so somebody can see what a protocol looks like. This file cannot
// require helpers.js — helpers requires THIS file, and a cycle in node hands
// back a half-initialised module whose exports are `undefined`, with the
// failure arriving later as something that is not a function.
//
// So it is an ordinary optional parameter. Not a sixth inverted slot (root
// CLAUDE.md rule 3e): a slot costs every reader an indirection and is for a
// require that would close a cycle or move a route, and a caller that already
// has the function can simply hand it over. `saml/saml2.ts` and
// `ws-trust/wstrust.ts` pass `helpers.logArtifact` and their log output is
// byte-for-byte what it was before this move.
// ---------------------------------------------------------------------------
function artifact(opts, what, stage, value) {
  log.debug("Entering artifact().");
  const sink = opts && opts.logArtifact;
  if (typeof sink !== 'function') {
    log.debug("Leaving artifact().");
    return;
  }
  try {
    sink(what, stage, value);
  } catch (e) {
    // A logger that throws must not fail the encryption it was describing —
    // the tail wagging the dog, which is the rule signJwt()'s recorder follows.
    log.error(errorCodes.tag('STS-KEYS-0001') +
              'the artifact logger threw and was ignored: ' + e.message);
  }
  log.debug("Leaving artifact().");
}

/**
 * Encrypts one XML element to a recipient's certificate, wrapped in the
 * element the caller names.
 *
 * @param xml - the element to encrypt
 * @param certPem - the recipient's certificate
 * @param opts - `wrapper` (`saml:EncryptedAssertion` by default),
 *   `algorithm`, `keyTransport`, `keyWrap` and `logArtifact`
 * @returns the wrapper element's XML
 */
function encryptElement(xml, certPem, opts) {
  log.debug("Entering encryptElement().");
  opts = opts || {};
  const wrapper = opts.wrapper || 'saml:EncryptedAssertion';
  const cipher = BLOCK_CIPHERS[opts.algorithm] || BLOCK_CIPHERS['aes256-gcm'];
  const transportName = KEY_TRANSPORTS[opts.keyTransport]
    ? opts.keyTransport : 'rsa-oaep-mgf1p';
  const transport = KEY_TRANSPORTS[transportName];
  const wrapName = KEY_WRAPS[opts.keyWrap] ? opts.keyWrap : 'kw-aes256';
  artifact(opts, 'SAML 2.0 ' + wrapper, 'before encryption', xml);

  // WHICH KIND OF KEY THE RECIPIENT HOLDS decides between transport and
  // agreement (#168): an EC certificate has no RSA key to wrap to, and
  // until this date it made this function throw — which the identity
  // provider turned into an assertion sent IN CLEAR (STS-SAML-0012).
  const recipient = new nodeCrypto.X509Certificate(certPem).publicKey;
  const ec = recipient.asymmetricKeyType === 'ec';
  // Node's generator in forge's binary-string shape: forge.random was a
  // second DRBG, and fifty times slower (#65, section 13).
  const key = randomBytes(cipher.keyBytes).toString('binary');
  const iv = randomBytes(cipher.ivBytes).toString('binary');
  const c = forge.cipher.createCipher(cipher.mode, key);
  // The tag length matters only to GCM; forge ignores it for CBC, and passing
  // it unconditionally keeps this one call rather than two.
  c.start({ iv: iv, tagLength: cipher.tagBytes * 8 });
  c.update(forge.util.createBuffer(forge.util.encodeUtf8(xml)));
  if (!c.finish()) {
    log.debug("Leaving encryptElement(). The cipher refused.");
    throw new Error('SAML encryption failed in ' + cipher.mode);
  }
  const body = cipher.tagBytes
    ? iv + c.output.getBytes() + c.mode.tag.getBytes()
    : iv + c.output.getBytes();
  const certB64 = certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const contentKey = Buffer.from(key, 'binary');
  const recipientInfo = '<ds:X509Data><ds:X509Certificate>' + certB64 +
    '</ds:X509Certificate></ds:X509Data>';

  let encryptedKey = '';
  let how = '';
  if (ec) {
    // ECDH-ES: an ephemeral pair on the recipient's curve, ConcatKDF to a
    // key-encryption key, and the content key wrapped under it.
    const wrap = KEY_WRAPS[wrapName];
    const crv = recipient.export({ format: 'jwk' }).crv;
    const oid = XML_EC_OIDS[crv];
    if (!oid) {
      log.debug("Leaving encryptElement(). Unknown curve.");
      throw new Error('the recipient\'s EC key is on curve ' + crv + ', and ' +
                      'this service agrees over ' +
                      Object.keys(XML_EC_OIDS).join(', '));
    }
    const ephemeral = nodeCrypto.generateKeyPairSync('ec',
      { namedCurve: EC_CURVES[crv] });
    const z = nodeCrypto.diffieHellman({ privateKey: ephemeral.privateKey,
                                         publicKey: recipient });
    const algorithmId = Buffer.from(wrap.uri, 'utf8');
    const kek = xmlConcatKdf(z, wrap.bytes, 'sha256', algorithmId);
    const wrapped = aesKeyWrap(kek, contentKey);
    const point = ephemeral.publicKey.export({ format: 'jwk' });
    const pub = Buffer.concat([Buffer.from([4]),
                               Buffer.from(String(point.x), 'base64url'),
                               Buffer.from(String(point.y), 'base64url')]);
    encryptedKey =
      '<xenc:EncryptedKey>' +
        '<xenc:EncryptionMethod Algorithm="' + wrap.uri + '"/>' +
        '<ds:KeyInfo><xenc:AgreementMethod Algorithm="' +
          KEY_AGREEMENTS['ecdh-es'].uri + '">' +
          '<xenc11:KeyDerivationMethod xmlns:xenc11="' + XENC11_NS + '" ' +
            'Algorithm="' + CONCAT_KDF_URI + '">' +
            '<xenc11:ConcatKDFParams AlgorithmID="' + hexBits(algorithmId) +
              '" PartyUInfo="00" PartyVInfo="00">' +
              '<ds:DigestMethod Algorithm="' + OAEP_DIGESTS.sha256 + '"/>' +
            '</xenc11:ConcatKDFParams></xenc11:KeyDerivationMethod>' +
          '<xenc:OriginatorKeyInfo><ds:KeyValue>' +
            '<dsig11:ECKeyValue xmlns:dsig11="' + DSIG11_NS + '">' +
            '<dsig11:NamedCurve URI="' + oid + '"/>' +
            '<dsig11:PublicKey>' + pub.toString('base64') +
            '</dsig11:PublicKey></dsig11:ECKeyValue>' +
          '</ds:KeyValue></xenc:OriginatorKeyInfo>' +
          '<xenc:RecipientKeyInfo>' + recipientInfo +
          '</xenc:RecipientKeyInfo>' +
        '</xenc:AgreementMethod></ds:KeyInfo>' +
        '<xenc:CipherData><xenc:CipherValue>' + wrapped.toString('base64') +
        '</xenc:CipherValue></xenc:CipherData>' +
      '</xenc:EncryptedKey>';
    how = 'key agreed with ecdh-es, wrapped with ' + wrapName;
  } else {
    let wrappedKey;
    if (transport.node) {
      // rsa-oaep with a named digest: node's OpenSSL, the one MGF1 digest
      // `oaepHash` also sets.
      wrappedKey = nodeCrypto.publicEncrypt({
        key: recipient,
        padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: transport.hash
      }, contentKey).toString('base64');
    } else {
      // rsa-oaep-mgf1p (SHA-1, MGF1-SHA1 — what the URI MEANS) and rsa-1_5,
      // through node's OpenSSL as well since #65: forge drew the OAEP seed
      // and the PKCS#1 v1.5 padding from a generator of its own, in
      // JavaScript. The bytes on the wire are the same scheme either way.
      wrappedKey = nodeCrypto.publicEncrypt({
        key: recipient,
        padding: transport.scheme === 'RSA-OAEP'
          ? nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING
          : nodeCrypto.constants.RSA_PKCS1_PADDING,
        oaepHash: transport.scheme === 'RSA-OAEP' ? 'sha1' : undefined
      }, contentKey).toString('base64');
    }
    encryptedKey =
      '<xenc:EncryptedKey>' +
        '<xenc:EncryptionMethod Algorithm="' + transport.uri + '">' +
          // The digest child belongs to OAEP and is meaningless under
          // RSA-1_5, so it is emitted only where it means something. A
          // service provider parsing strictly refuses the stray element.
          (transport.scheme === 'RSA-OAEP'
            ? '<ds:DigestMethod xmlns:ds="' + DS_NS + '" Algorithm="' +
              OAEP_DIGESTS[transport.hash || 'sha1'] + '"/>'
            : '') +
          (transport.node
            ? '<xenc11:MGF xmlns:xenc11="' + XENC11_NS + '" Algorithm="' +
              MGF1_URIS[transport.hash] + '"/>'
            : '') +
        '</xenc:EncryptionMethod>' +
        '<ds:KeyInfo>' + recipientInfo + '</ds:KeyInfo>' +
        '<xenc:CipherData><xenc:CipherValue>' + wrappedKey +
        '</xenc:CipherValue></xenc:CipherData>' +
      '</xenc:EncryptedKey>';
    how = 'key wrapped with ' + transportName;
  }

  const encrypted =
    '<' + wrapper + ' xmlns:saml="' + NS_SAML + '">' +
    '<xenc:EncryptedData xmlns:xenc="' + XENC_NS + '" Type="' + XENC_NS +
    'Element"><xenc:EncryptionMethod ' +
      'Algorithm="' + cipher.uri + '"/>' +
      '<ds:KeyInfo xmlns:ds="' + DS_NS + '">' + encryptedKey +
      '</ds:KeyInfo>' +
      '<xenc:CipherData><xenc:CipherValue>' + forge.util.encode64(body) +
      '</xenc:CipherValue></xenc:CipherData>' +
    '</xenc:EncryptedData></' + wrapper + '>';

  artifact(opts, 'SAML 2.0 ' + wrapper,
           'after encryption (' + cipher.name + ', ' +
           how + ')',
           encrypted);
  log.debug("Leaving encryptElement(). " + cipher.name + " / " +
            (ec ? 'ecdh-es' : transportName) + ".");
  return encrypted;
}

// The original name, kept because WS-Trust calls it and its signature is part
// of that module's contract. It is now one line over encryptElement().
/**
 * Encrypts an assertion as `encryptElement()` does; the name WS-Trust
 * calls.
 *
 * @param assertionXml - the assertion
 * @param certPem - the recipient's certificate
 * @param opts - as for `encryptElement()`
 * @returns the encrypted element's XML
 */
function encryptAssertion(assertionXml, certPem, opts) {
  log.debug("Entering encryptAssertion().");
  log.debug("Leaving encryptAssertion().");
  return encryptElement(assertionXml, certPem,
    Object.assign({}, opts, { wrapper: 'saml:EncryptedAssertion' }));
}

// ---------------------------------------------------------------------------
// DECRYPT, and it ANSWERS RATHER THAN THROWS.
//
// `{ ok, xml, why, algorithm, keyTransport }`. Every failure here is somebody
// else's document being wrong — encrypted to a key this service does not hold,
// in an algorithm it does not have, or simply corrupt — and a mock that threw
// would turn a bad LogoutRequest into a stack trace instead of into a refusal
// with a sentence. The caller decides what a failure means, which differs: a
// LogoutRequest with an undecryptable EncryptedID is refused, and a future
// caller might carry on without the value.
//
// IT TAKES THE ELEMENT'S XML, NOT A PARSED NODE, so a caller can hand it a
// serialised subtree and this function owns the parsing. That also keeps the
// namespace handling in one place: `getElementsByTagNameNS('*', ...)` matches
// on LOCAL NAME so a document using `xe:` or no prefix at all is read the same,
// which is the same rule helpers.firstByLocal() follows and for the same
// reason.
// ---------------------------------------------------------------------------
// DOES THIS PLAINTEXT PARSE, allowing for a fragment that relies on its parent
// for a namespace prefix?
//
// This is the second bug this check found and it was in the check itself. A
// decrypted <saml:EncryptedID> often contains `<saml:NameID Format="...">` with
// NO xmlns:saml on it, because in the document it came from the prefix was
// declared on the LogoutRequest three levels up. Parsed on its own that is a
// NamespaceError, and the first version of this function reported a perfectly
// good NameID as corrupt.
//
// So it is tried twice: as it stands, and then inside a container that declares
// the prefixes a SAML fragment can legitimately expect to inherit. Only if BOTH
// fail is it rubbish. What this service ITSELF emits is self-contained — see
// subjectFor() in saml2_sso.js — but somebody else's document is not this
// service's to dictate.
function parsesAsFragment(xml) {
  log.debug("Entering parsesAsFragment().");
  const ok = function (doc) {
    log.debug("Entering ok().");
    log.debug("Leaving ok().");
    return !!(doc && doc.documentElement &&
              !doc.getElementsByTagName('parsererror').length);
  };
  try {
    if (ok(new DOMParser().parseFromString(xml, 'text/xml'))) {
      log.debug("Leaving parsesAsFragment().");
      return true;
    }
  } catch (e) {
    // Not a failure yet: the wrapped attempt below is the one that matters for
    // a fragment, and a genuine syntax error fails that too.
    log.debug("Caught in parsesAsFragment(): " + ((e && e.message) || e));
  }
  const wrapped = '<x xmlns:saml="' + NS_SAML +
    '" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
    ' xmlns:ds="' + DS_NS + '" xmlns:xenc="' + XENC_NS + '">' + xml + '</x>';
  try {
    log.debug("Leaving parsesAsFragment().");
    return ok(new DOMParser().parseFromString(wrapped, 'text/xml'));
  } catch (e) {
    log.debug("Caught in parsesAsFragment(): " + ((e && e.message) || e));
    log.debug("Leaving parsesAsFragment().");
    return false;
  }
}

// ---------------------------------------------------------------------------
// THE CALLER'S ALLOW-LIST (#168). `opts.allowedCiphers` names the block
// ciphers, `opts.allowedKeyManagement` the key transports and agreements
// (`rsa-oaep`, `rsa-oaep-mgf1p`, `rsa-1_5`, `ecdh-es`) and
// `opts.allowedOaepDigests` the digests an `rsa-oaep` may name — a federation
// relationship accepts exactly what it published. Each is asked BEFORE any key
// operation, so a refusal says nothing about the ciphertext; the answer
// carries `refused: true` so a caller can tell "an algorithm this door does
// not take" from "a document that did not decrypt", which are two different
// codes there and must not be one.
// ---------------------------------------------------------------------------
function refusedAlgorithm(opts, list, name, what) {
  log.debug("Entering refusedAlgorithm(). " + what + "=" + name);
  const allowed = opts && opts[list];
  if (!Array.isArray(allowed) || allowed.indexOf(name) >= 0) {
    log.debug("Leaving refusedAlgorithm(). Allowed.");
    return null;
  }
  log.debug("Leaving refusedAlgorithm(). Refused.");
  return errorCodes.mark({ ok: false, refused: true, algorithm: name,
                           why: 'the ' + what + ' is ' + name + ', and this ' +
                                'recipient accepts only ' +
                                (allowed.join(', ') || 'nothing') },
                         'STS-KEYS-0071');
}

// The private key, as node's KeyObject, from a PEM or a KeyObject.
function privateKeyObject(key) {
  log.debug("Entering privateKeyObject().");
  if (key && typeof key === 'object' && key.type === 'private') {
    log.debug("Leaving privateKeyObject(). A KeyObject.");
    return key;
  }
  log.debug("Leaving privateKeyObject(). A PEM.");
  return nodeCrypto.createPrivateKey(String(key || ''));
}

function childByLocal(parent, localName) {
  log.debug("Entering childByLocal(). " + localName);
  const kids = parent ? parent.childNodes : null;
  for (let i = 0; kids && i < kids.length; i++) {
    if (kids[i].nodeType === 1 && kids[i].localName === localName) {
      log.debug("Leaving childByLocal(). Found.");
      return kids[i];
    }
  }
  log.debug("Leaving childByLocal(). None.");
  return null;
}

// ---------------------------------------------------------------------------
// ECDH-ES, READ BACKWARDS: the agreed secret from our private key and the
// originator's ephemeral public key, and section 5.4.1's KDF over it.
// `keyBytes` is how much key the caller needs — the key wrap's size, or the
// content key's for an agreement straight under EncryptedData. Throws a
// sentence; the caller codes it.
// ---------------------------------------------------------------------------
function agreedKey(agreement, privateKey, keyBytes) {
  log.debug("Entering agreedKey(). " + keyBytes + " bytes.");
  const kdf = agreement.getElementsByTagNameNS('*', 'KeyDerivationMethod')[0];
  if (!kdf || kdf.getAttribute('Algorithm') !== CONCAT_KDF_URI) {
    log.debug("Leaving agreedKey(). Not ConcatKDF.");
    throw new Error('the ECDH-ES agreement derives its key with ' +
      ((kdf && kdf.getAttribute('Algorithm')) || 'no KeyDerivationMethod') +
      ', and this service derives with ConcatKDF only');
  }
  const params = kdf.getElementsByTagNameNS('*', 'ConcatKDFParams')[0];
  const digestEl = params ? params.getElementsByTagNameNS('*',
    'DigestMethod')[0] : null;
  const hash = nameOfUri(OAEP_DIGESTS,
                         digestEl ? digestEl.getAttribute('Algorithm') : '');
  if (!params || !hash || hash === 'sha1') {
    log.debug("Leaving agreedKey(). An unusable KDF digest.");
    throw new Error('the ConcatKDF names no digest this service derives ' +
                    'with (SHA-256, SHA-384 or SHA-512)');
  }
  const otherInfo = Buffer.concat(['AlgorithmID', 'PartyUInfo', 'PartyVInfo',
                                   'SuppPubInfo', 'SuppPrivInfo']
    .map(function (name) {
      return concatKdfBits(params.getAttribute(name), name);
    }));
  const originator = agreement.getElementsByTagNameNS('*',
    'OriginatorKeyInfo')[0];
  const ecValue = originator ? originator.getElementsByTagNameNS('*',
    'ECKeyValue')[0] : null;
  const curveEl = ecValue ? ecValue.getElementsByTagNameNS('*',
    'NamedCurve')[0] : null;
  const pointEl = ecValue ? ecValue.getElementsByTagNameNS('*',
    'PublicKey')[0] : null;
  const curve = curveEl ? XML_EC_CURVES[curveEl.getAttribute('URI')] : null;
  if (!curve || !pointEl) {
    log.debug("Leaving agreedKey(). No usable originator key.");
    throw new Error('the agreement carries no originator ECKeyValue on a ' +
                    'curve this service agrees over (' +
                    Object.keys(XML_EC_OIDS).join(', ') + ')');
  }
  const point = Buffer.from(String(pointEl.textContent || '').trim(),
                            'base64');
  if (point.length !== 1 + 2 * curve.bytes || point[0] !== 4) {
    log.debug("Leaving agreedKey(). Not an uncompressed point.");
    throw new Error('the originator\'s public key is not an uncompressed ' +
                    'point on ' + curve.crv);
  }
  const originatorKey = nodeCrypto.createPublicKey({ format: 'jwk', key: {
    kty: 'EC', crv: curve.crv,
    x: point.subarray(1, 1 + curve.bytes).toString('base64url'),
    y: point.subarray(1 + curve.bytes).toString('base64url') } });
  const z = nodeCrypto.diffieHellman({ privateKey: privateKey,
                                       publicKey: originatorKey });
  log.debug("Leaving agreedKey().");
  return xmlConcatKdf(z, keyBytes, hash, otherInfo);
}

// ---------------------------------------------------------------------------
// WHAT AN ECDH-ES AGREEMENT ASKS FOR, BEFORE ANY KEY OPERATION (#193). A key
// derivation this service does not perform (PBKDF2, a SHA-1 ConcatKDF, none)
// or an originator key on a curve it does not agree over is a property of
// the DOCUMENT, and until 2026-09-24 it surfaced from inside agreedKey()'s
// throw — reported, under STS-KEYS-0024, as a key encrypted to a different
// certificate. The W3C interop set's AGRMNT.9 (ECDH-ES with PBKDF2) is the
// case that showed it. '' when the agreement is one agreedKey() performs.
// ---------------------------------------------------------------------------
function agreementRefusal(agreement) {
  log.debug("Entering agreementRefusal().");
  const kdf = agreement.getElementsByTagNameNS('*', 'KeyDerivationMethod')[0];
  const kdfUri = kdf ? String(kdf.getAttribute('Algorithm') || '') : '';
  if (kdfUri !== CONCAT_KDF_URI) {
    log.debug("Leaving agreementRefusal(). Not ConcatKDF.");
    return 'the ECDH-ES agreement derives its key with ' +
      (kdfUri || 'no KeyDerivationMethod') + ', and this service derives ' +
      'with ConcatKDF only (XML Encryption 1.1 section 5.4.1)';
  }
  const params = kdf.getElementsByTagNameNS('*', 'ConcatKDFParams')[0];
  const digestEl = params ? params.getElementsByTagNameNS('*',
    'DigestMethod')[0] : null;
  const hash = nameOfUri(OAEP_DIGESTS,
                         digestEl ? digestEl.getAttribute('Algorithm') : '');
  if (!params || !hash || hash === 'sha1') {
    log.debug("Leaving agreementRefusal(). An unusable KDF digest.");
    return 'the ConcatKDF names ' + (digestEl
      ? digestEl.getAttribute('Algorithm') : 'no digest') + ', and this ' +
      'service derives with SHA-256, SHA-384 or SHA-512 only';
  }
  const originator = agreement.getElementsByTagNameNS('*',
    'OriginatorKeyInfo')[0];
  const curveEl = originator ? originator.getElementsByTagNameNS('*',
    'NamedCurve')[0] : null;
  if (!curveEl || !XML_EC_CURVES[curveEl.getAttribute('URI')]) {
    log.debug("Leaving agreementRefusal(). No usable originator curve.");
    return 'the agreement carries no originator ECKeyValue on a curve this ' +
      'service agrees over (' + Object.keys(XML_EC_OIDS).join(', ') + ')';
  }
  log.debug("Leaving agreementRefusal(). Usable.");
  return '';
}

// ---------------------------------------------------------------------------
// THE AES-CBC PADDING ORACLE, CLOSED (#202, 2026-09-24).
//
// Jager and Somorovsky, "How To Break XML Encryption" (CCS 2011), and XML
// Encryption 1.1 section 6.1.3: an UNAUTHENTICATED CBC decryption that
// answers "bad padding" differently from "decrypted, but not XML" lets an
// attacker who can submit ciphertexts recover the plaintext a byte at a time
// — no key needed, just the difference between two answers. This function
// answered with three: STS-KEYS-0022 (padding), STS-KEYS-0025 (not UTF-8,
// from the catch) and STS-KEYS-0023 (not XML), each with its own sentence,
// and returned early on the padding, so even the TIME differed.
//
// Now every CBC failure after the key is unwrapped is ONE refusal —
// STS-KEYS-0078, one sentence (CBC_REFUSAL) — and the three checks all RUN
// whatever the padding said: a bad count strips nothing and is carried as a
// flag, the result is decoded and parsed anyway, and the flags are combined
// only at the end. What still varies with the plaintext is the XML parser's
// own time, which no refusal can hide; the branch that could be avoided is
// gone. The real answer is AES-GCM, which this service writes by default
// and product can be held to per relationship (`allowedCiphers`); CBC stays
// because service providers that require it exist.
//
// A GCM failure keeps its own code and sentence: it is authenticated, and a
// tag that does not verify reveals nothing about the plaintext.
// ---------------------------------------------------------------------------
const CBC_REFUSAL = 'the AES-CBC ciphertext did not decrypt to a ' +
  'well-formed XML element — the key, the ciphertext or its padding is ' +
  'wrong, and which of those it was is deliberately not said (XML ' +
  'Encryption 1.1 section 6.1.3). AES-CBC is unauthenticated; AES-GCM ' +
  'would have detected an altered ciphertext';

function cbcPlaintextUsable(opened) {
  log.debug("Entering cbcPlaintextUsable().");
  const padOk = !!(opened && opened.padOk);
  const bytes = opened ? opened.plain : Buffer.alloc(0);
  let text = '';
  let utf8Ok = true;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (e) {
    log.debug("Caught in cbcPlaintextUsable(): " + ((e && e.message) || e));
    utf8Ok = false;
    text = bytes.toString('utf8');
  }
  // Parsed whether or not the two checks above held, so the three failures
  // cost the same work up to the parser's own.
  const xmlOk = parsesAsFragment(text);
  const ok = padOk && utf8Ok && xmlOk && !!opened;
  log.debug("Leaving cbcPlaintextUsable(). " + ok);
  return { ok: ok, text: text };
}

// ---------------------------------------------------------------------------
// THE CONTENT OF AN EncryptedData, OPENED ON NODE'S OpenSSL (#202,
// 2026-09-24). `raw` is the CipherValue: IV || ciphertext [|| tag]. Returns
// `{ plain, padOk }`, or null when the cipher refuses it outright (a GCM
// tag, a CBC length that is not whole blocks).
//
// **IT WAS forge UNTIL WYCHEPROOF'S AES-CBC VECTORS**, and forge's unpadding
// checks only that the LAST octet is at most a block: a final octet of ZERO
// (zero padding, "no padding") and an EMPTY ciphertext both "finished", and
// the rubbish that came out reached the XML parser (STS-KEYS-0023) instead of
// being refused as padding. XML Encryption 1.1 section 5.2's padding is
// NOT PKCS#7 — the last octet counts the padding, 1 to the block size, and
// the others are arbitrary (Apache Santuario writes ISO 10126 random bytes) —
// so this checks exactly that and no more: a whole number of blocks, at
// least one, and a final octet between 1 and 16. Node with automatic padding
// would refuse every random-padded document real service providers send.
// GCM's IV and tag are the fixed 12 and 16 octets the layout defines, and
// node refuses a tag that does not verify.
// ---------------------------------------------------------------------------
/**
 * Opens the content of an XML EncryptedData on node's OpenSSL.
 *
 * @param cipher - the block cipher's row
 * @param key - the content key
 * @param raw - the CipherValue: IV, ciphertext and, for GCM, the tag
 * @returns `{ plain, padOk }`, or null when it cannot be opened
 */
function openXmlContent(cipher, key, raw) {
  log.debug("Entering openXmlContent(). " + cipher.name);
  const bits = key.length * 8;
  try {
    if (raw.length < cipher.ivBytes + cipher.tagBytes) {
      log.debug("Leaving openXmlContent(). Too short.");
      return null;
    }
    const iv = raw.subarray(0, cipher.ivBytes);
    if (cipher.tagBytes) {
      const tag = raw.subarray(raw.length - cipher.tagBytes);
      const gcm = /** @type {import('crypto').DecipherGCM} */ (
        nodeCrypto.createDecipheriv(
          /** @type {import('crypto').CipherGCMTypes} */
          ('aes-' + bits + '-gcm'), key, iv,
          { authTagLength: cipher.tagBytes }));
      gcm.setAuthTag(tag);
      const out = Buffer.concat([gcm.update(raw.subarray(cipher.ivBytes,
        raw.length - cipher.tagBytes)), gcm.final()]);
      log.debug("Leaving openXmlContent(). GCM.");
      return { plain: out, padOk: true };
    }
    const body = raw.subarray(cipher.ivBytes);
    if (!body.length || body.length % 16) {
      // The LENGTH is public — it is on the wire — so refusing it early
      // tells an attacker nothing the ciphertext did not.
      log.debug("Leaving openXmlContent(). Not whole blocks.");
      return null;
    }
    const cbc = nodeCrypto.createDecipheriv('aes-' + bits + '-cbc', key, iv);
    cbc.setAutoPadding(false);
    const padded = Buffer.concat([cbc.update(body), cbc.final()]);
    // NO EARLY RETURN ON THE PADDING — see cbcPlaintextUsable(). A bad count
    // strips nothing and is carried as a flag; the caller decodes and parses
    // the result either way and refuses all three failures as ONE.
    const count = padded[padded.length - 1];
    const padOk = count >= 1 && count <= 16;
    const plain = padded.subarray(0, padded.length - (padOk ? count : 0));
    log.debug("Leaving openXmlContent(). CBC.");
    return { plain: plain, padOk: padOk };
  } catch (e) {
    log.debug("Caught in openXmlContent(): " + ((e && e.message) || e));
    log.debug("Leaving openXmlContent(). Refused.");
    return null;
  }
}

/**
 * Decrypts one encrypted XML element. It answers rather than throws.
 *
 * @param xml - the encrypted element's XML
 * @param privateKeyPem - the private key it was encrypted to
 * @param opts - `allowedCiphers`, `allowedKeyManagement`,
 *   `allowedOaepDigests` and `logArtifact`
 * @returns `{ ok, xml, why, algorithm, keyTransport }`
 */
function decryptElement(xml, privateKeyPem, opts) {
  log.debug("Entering decryptElement().");
  const options = opts || {};
  let doc;
  try {
    doc = new DOMParser().parseFromString(String(xml), 'text/xml');
  } catch (e) {
    // Not XML at all. The message is the parser's and is more use than ours.
    log.debug("Leaving decryptElement(). It did not parse.");
    return errorCodes.mark({ ok: false, why: 'the encrypted element is not ' +
                                             'well-formed XML: ' +
                             e.message }, 'STS-KEYS-0015');
  }
  const data = doc.getElementsByTagNameNS('*', 'EncryptedData')[0];
  if (!data) {
    log.debug("Leaving decryptElement(). No EncryptedData.");
    return errorCodes.mark({ ok: false, why: 'there is no ' +
                                             '<xenc:EncryptedData> inside it' },
                           'STS-KEYS-0016');
  }
  const dataMethod = childByLocal(data, 'EncryptionMethod');
  const dataUri = dataMethod ? dataMethod.getAttribute('Algorithm') : '';
  const cipher = cipherByUri(dataUri);
  if (!cipher) {
    log.debug("Leaving decryptElement(). Unknown block cipher.");
    return errorCodes.mark({ ok: false, why: 'the data is encrypted with ' +
             (dataUri || '(no algorithm stated)') +
             ', and this service reads only ' +
             Object.keys(BLOCK_CIPHERS).join(', ') },
                           'STS-KEYS-0017');
  }
  const cipherRefused = refusedAlgorithm(options, 'allowedCiphers',
                                         cipher.name, 'block cipher');
  if (cipherRefused) {
    log.debug("Leaving decryptElement(). The caller does not take " +
              cipher.name + ".");
    return cipherRefused;
  }
  // WHERE THE CONTENT KEY IS. Inside the EncryptedData's KeyInfo (what this
  // service writes), or — SAML 2.0 core section 2.3.4 allows it — an
  // EncryptedKey BESIDE the EncryptedData inside the same wrapper, or an
  // AgreementMethod straight under the KeyInfo, whose agreed key IS the
  // content key (XML Encryption 1.1 section 5.6).
  const dataKeyInfo = childByLocal(data, 'KeyInfo');
  const keyEl = (dataKeyInfo && childByLocal(dataKeyInfo, 'EncryptedKey')) ||
                doc.getElementsByTagNameNS('*', 'EncryptedKey')[0] || null;
  const directAgreement = !keyEl && dataKeyInfo
    ? childByLocal(dataKeyInfo, 'AgreementMethod') : null;
  if (!keyEl && !directAgreement) {
    // A <RetrievalMethod> pointing at an EncryptedKey elsewhere is legal and
    // is not implemented: nothing this service issues produces one, and saying
    // so is more useful than a null dereference three lines down.
    log.debug("Leaving decryptElement(). No EncryptedKey.");
    return errorCodes.mark({ ok: false, why: 'there is no ' +
             '<xenc:EncryptedKey> inside the KeyInfo or beside the ' +
             'EncryptedData, and no key agreement. A key pointed at with ' +
             '<ds:RetrievalMethod> is legal and is not implemented here' },
                           'STS-KEYS-0018');
  }
  const keyMethod = keyEl ? childByLocal(keyEl, 'EncryptionMethod') : null;
  const keyUri = keyMethod ? keyMethod.getAttribute('Algorithm') : '';
  const transport = keyEl ? transportByUri(keyUri) : null;
  const wrap = keyEl && !transport ? keyWrapByUri(keyUri) : null;
  const keyInfoOfKey = keyEl ? childByLocal(keyEl, 'KeyInfo') : null;
  const agreement = directAgreement ||
    (wrap && keyInfoOfKey ? childByLocal(keyInfoOfKey, 'AgreementMethod') :
     null);
  if (keyEl && !transport && !(wrap && agreement)) {
    log.debug("Leaving decryptElement(). Unknown key transport.");
    return errorCodes.mark({ ok: false, why: 'the key is wrapped with ' +
             (keyUri || '(no algorithm stated)') +
             ', and this service unwraps only ' +
             Object.keys(KEY_TRANSPORTS).join(', ') + ', or ' +
             Object.keys(KEY_WRAPS).join(', ') + ' under an ECDH-ES ' +
             'agreement' },
                           'STS-KEYS-0019');
  }
  if (agreement &&
      agreement.getAttribute('Algorithm') !== KEY_AGREEMENTS['ecdh-es'].uri) {
    log.debug("Leaving decryptElement(). Unknown key agreement.");
    return errorCodes.mark({ ok: false, refused: true,
             algorithm: agreement.getAttribute('Algorithm') || '',
             why: 'the key is agreed with ' +
                  (agreement.getAttribute('Algorithm') || '(no algorithm)') +
                  ', and this service agrees only with ECDH-ES' },
                           'STS-KEYS-0073');
  }
  const agreementWhy = agreement ? agreementRefusal(agreement) : '';
  if (agreementWhy) {
    log.debug("Leaving decryptElement(). " + agreementWhy);
    return errorCodes.mark({ ok: false, refused: true, algorithm: 'ecdh-es',
                             why: agreementWhy }, 'STS-KEYS-0090');
  }
  const managementName = transport ? transport.name : 'ecdh-es';
  const managementRefused = refusedAlgorithm(options, 'allowedKeyManagement',
                                             managementName,
                                             'key management');
  if (managementRefused) {
    log.debug("Leaving decryptElement(). The caller does not take " +
              managementName + ".");
    return managementRefused;
  }
  // AN rsa-1_5 UNWRAP IS THE DECRYPTION ORACLE, and product never performs
  // one (#181, `mode.usesBrokenAlgorithms()`). XML Encryption 1.1 section
  // 6.1.2 is Bleichenbacher's attack on exactly this, and section 6.1.3 adds
  // the worse half for this service: a server that decrypts PKCS#1 v1.5 under
  // a key it also SIGNS with can be made to forge signatures, and this
  // realm's XML key does both. So the refusal comes before any RSA operation
  // and says nothing about the ciphertext. Development unwraps it, because a
  // service provider that only speaks rsa-1_5 is what it is for.
  if (transport && transport.name === 'rsa-1_5' &&
      !mode.usesBrokenAlgorithms()) {
    log.debug("Leaving decryptElement(). rsa-1_5, in product.");
    return errorCodes.mark({ ok: false, refused: true, algorithm: 'rsa-1_5',
             why: 'the key is wrapped with ' +
             'rsa-1_5 (RSAES-PKCS1-v1_5), which this realm does not unwrap ' +
             'in product mode — XML Encryption 1.1 section 6.1.2. Encrypt ' +
             'to it with rsa-oaep' }, 'STS-KEYS-0070');
  }
  // rsa-oaep's digest and MGF, each SHA-1 where absent (section 5.5.2).
  //
  // **rsa-oaep-mgf1p NAMES A DIGEST TOO (#193)**, and until 2026-09-24 this
  // read it as SHA-1 whatever the EncryptedKey said: section 5.5.1 lets its
  // DigestMethod be any digest while its mask generation function is FIXED
  // at MGF1 with SHA-1. A SHA-256 one (the W3C interop set's WRAP.2) was
  // unwrapped under the wrong digest and reported as a key encrypted to a
  // different certificate. Node derives MGF1 from the OAEP digest, so that
  // pair is refused BY NAME here, exactly as rsa-oaep's differing pair is.
  // (The PSource label, `<xenc:OAEPparams>`, is read once, below — #202's,
  // which #193 had found the same day.)
  let oaepHash = '';
  if (transport && (transport.name === 'rsa-oaep' ||
                    transport.name === 'rsa-oaep-mgf1p')) {
    const mgf1p = transport.name === 'rsa-oaep-mgf1p';
    const digestEl = childByLocal(keyMethod, 'DigestMethod');
    const mgfEl = mgf1p ? null : childByLocal(keyMethod, 'MGF');
    const digest = digestEl ? nameOfUri(OAEP_DIGESTS,
                                        digestEl.getAttribute('Algorithm'))
                            : 'sha1';
    const mgf = mgfEl ? nameOfUri(MGF1_URIS, mgfEl.getAttribute('Algorithm'))
                      : 'sha1';
    if (!digest || !mgf || digest !== mgf) {
      log.debug("Leaving decryptElement(). An unusable OAEP digest.");
      return errorCodes.mark({ ok: false, refused: true,
               algorithm: transport.name,
               why: 'the ' + transport.name + ' key transport names ' +
                    (digestEl ? digestEl.getAttribute('Algorithm') : 'SHA-1') +
                    ' as its digest and ' +
                    (mgfEl ? mgfEl.getAttribute('Algorithm') : 'MGF1-SHA-1') +
                    ' as its mask generation function' +
                    (mgf1p ? ' (rsa-oaep-mgf1p fixes MGF1 at SHA-1)' : '') +
                    '; this service unwraps only a matching pair of ' +
                    'SHA-1, SHA-256, SHA-384 or SHA-512' }, 'STS-KEYS-0072');
    }
    if (!mgf1p) {
      const digestRefused = refusedAlgorithm(options, 'allowedOaepDigests',
                                             digest, 'OAEP digest');
      if (digestRefused) {
        log.debug("Leaving decryptElement(). The caller does not take the " +
                  "OAEP digest " + digest + ".");
        return digestRefused;
      }
    }
    oaepHash = digest;
  }
  // The data's CipherValue: the EncryptedData's own CipherData, never one
  // inside a key.
  const dataCipherData = childByLocal(data, 'CipherData');
  const dataCipher = dataCipherData ? childByLocal(dataCipherData,
                                                   'CipherValue') : null;
  const keyCipherData = keyEl ? childByLocal(keyEl, 'CipherData') : null;
  const keyCipher = keyCipherData ? childByLocal(keyCipherData,
                                                 'CipherValue') : null;
  if ((keyEl && !keyCipher) || !dataCipher) {
    log.debug("Leaving decryptElement(). A CipherValue is missing.");
    return errorCodes.mark({ ok: false, why: 'the element is missing one of ' +
             'its two <xenc:CipherValue>s — the wrapped key, or the ' +
             'data' }, 'STS-KEYS-0020');
  }

  // THE OAEP LABEL (#202, 2026-09-24). XML Encryption 1.1 section 5.5.2:
  // `<xenc:OAEPparams>`, when present, is the base64 of the label P, for
  // rsa-oaep-mgf1p and rsa-oaep alike. It was ignored until Wycheproof's
  // EncryptionWithLabel vectors: a key a sender wrapped under a label then
  // failed to unwrap and was reported as a key for another certificate.
  const paramsEl = keyMethod ? childByLocal(keyMethod, 'OAEPparams') : null;
  const oaepLabel = paramsEl
    ? Buffer.from(String(paramsEl.textContent || '').trim(), 'base64')
    : undefined;
  try {
    let key;
    const wrappedBytes = keyCipher
      ? Buffer.from(String(keyCipher.textContent || '').trim(), 'base64')
      : Buffer.alloc(0);
    if (agreement) {
      const privateKey = privateKeyObject(privateKeyPem);
      if (privateKey.asymmetricKeyType !== 'ec') {
        log.debug("Leaving decryptElement(). An agreement to a non-EC key.");
        return errorCodes.mark({ ok: false, why: 'the element is encrypted ' +
                 'by ECDH-ES key agreement and this recipient\'s key is not ' +
                 'an EC key' }, 'STS-KEYS-0074');
      }
      const agreed = agreedKey(agreement, privateKey,
                               wrap ? wrap.bytes : cipher.keyBytes);
      key = wrap ? aesKeyUnwrap(agreed, wrappedBytes).toString('binary')
                 : agreed.toString('binary');
    } else if (transport.node) {
      key = nodeCrypto.privateDecrypt({
        key: privateKeyObject(privateKeyPem),
        padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: oaepHash,
        oaepLabel: oaepLabel
      }, wrappedBytes).toString('binary');
    } else {
      // rsa-oaep-mgf1p and rsa-1_5 through node's OpenSSL since #65, where
      // forge's JavaScript RSA drew its blinding from a generator of its own
      // and was not constant-time. RSA-1_5 is OpenSSL's IMPLICIT REJECTION
      // (node refuses PKCS#1 v1.5 decryption without it): a padding that
      // does not check unwraps to a deterministic random value instead of
      // throwing, so the length check below is still what names a wrong
      // key, and the timing no longer tells a caller which it was.
      key = nodeCrypto.privateDecrypt({
        key: privateKeyObject(privateKeyPem),
        padding: transport.scheme === 'RSA-OAEP'
          ? nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING
          : nodeCrypto.constants.RSA_PKCS1_PADDING,
        oaepHash: transport.scheme === 'RSA-OAEP' ? 'sha1' : undefined,
        oaepLabel: transport.scheme === 'RSA-OAEP' ? oaepLabel : undefined
      }, wrappedBytes).toString('binary');
    }
    if (!key || key.length !== cipher.keyBytes) {
      // A WRONG KEY IS THE ORDINARY FAILURE and it is worth naming: this
      // service regenerates its key on every start in development mode (the
      // default; product mode keeps it), so a service provider that
      // cached the certificate from a previous run encrypts to a key that no
      // longer exists. Under RSA-1_5 that unwraps to plausible-looking garbage
      // of the wrong length rather than failing, which is the whole reason the
      // length is checked here.
      log.debug("Leaving decryptElement(). The unwrapped key is the wrong " +
                "size.");
      return errorCodes.mark({ ok: false, why: 'the wrapped key did not ' +
                                               'unwrap to ' +
                                               'a ' + cipher.keyBytes +
               '-byte key, so it was encrypted to a different certificate. ' +
               'This service regenerates its key on every start, so a stale ' +
               'copy of its metadata is the usual cause — fetch ' +
               '/saml2/metadata again' }, 'STS-KEYS-0021');
    }
    const opened = openXmlContent(cipher, Buffer.from(key, 'binary'),
      Buffer.from(String(dataCipher.textContent || '').trim(), 'base64'));
    if (!cipher.tagBytes) {
      // AES-CBC: ONE REFUSAL FOR THE PADDING, THE ENCODING AND THE PARSE.
      // See cbcPlaintextUsable() for why.
      const usable = cbcPlaintextUsable(opened);
      if (!usable.ok) {
        log.debug("Leaving decryptElement(). CBC did not yield a document.");
        return errorCodes.mark({ ok: false, why: CBC_REFUSAL },
                               'STS-KEYS-0078');
      }
      opened.plain = Buffer.from(usable.text, 'utf8');
    } else if (!opened) {
      // AES-GCM's tag: the ciphertext was altered. Authenticated, so saying
      // so is no oracle — nothing about the plaintext is learned from it.
      log.debug("Leaving decryptElement(). The GCM tag did not verify.");
      return errorCodes.mark({ ok: false, why: 'the AES-GCM authentication ' +
        'tag did not verify, so the ciphertext was altered after it was ' +
        'encrypted' }, 'STS-KEYS-0022');
    }
    // The plaintext as UTF-8, STRICTLY. For CBC it was decoded and checked
    // inside cbcPlaintextUsable() above, and any failure there is the ONE
    // refusal (STS-KEYS-0078, #202) — so what can fail here is GCM, which is
    // authenticated: binary plaintext is a document that is not XML and is
    // refused as one (STS-KEYS-0023, #193 — the W3C interop set's binary
    // ECDH-ES cases showed it; it was "could not be read", STS-KEYS-0025).
    let plain;
    try {
      plain = new TextDecoder('utf-8', { fatal: true }).decode(opened.plain);
    } catch (e) {
      log.debug("Caught in decryptElement(): " + ((e && e.message) || e));
      log.debug("Leaving decryptElement(). The plaintext is not UTF-8.");
      return errorCodes.mark({ ok: false, why: 'the decryption produced ' +
               'octets that are not UTF-8 text, so not an XML element — ' +
               'binary data, which this service does not decrypt' },
                             'STS-KEYS-0023');
    }
    // ---------------------------------------------------------------------
    // DOES IT PARSE? A cipher that finished is not a document that survived.
    // For GCM (authenticated) a plaintext that is not XML is the sender's
    // bug and is named as such. For CBC the same question is asked inside
    // cbcPlaintextUsable(), above, and answered as one refusal.
    if (!parsesAsFragment(plain)) {
      log.debug("Leaving decryptElement(). The plaintext is not XML.");
      return errorCodes.mark({ ok: false, why: 'the decryption produced ' +
               'something that is not well-formed XML' }, 'STS-KEYS-0023');
    }
    artifact(options, 'SAML 2.0 encrypted element',
             'after decryption (' + cipher.name + ', key ' +
             (agreement ? 'agreed with ecdh-es' : 'unwrapped with ' +
              transport.name) + ')', plain);
    log.debug("Leaving decryptElement(). " + plain.length + " characters.");
    return { ok: true, xml: plain, algorithm: cipher.name,
             keyTransport: managementName, keyWrap: wrap ? wrap.name : '',
             oaepDigest: oaepHash };
  } catch (e) {
    // forge and node throw on a key that will not unwrap at all, which is
    // the RSA-OAEP equivalent of the length check above. Swallowed into an
    // answer for the reason this whole function answers rather than throws.
    //
    // THE MESSAGE IS NOT ASSUMED TO BE ABOUT THE KEY, and that is a correction
    // rather than caution: this catch covers the decryption AND the parse, and
    // while it said "the wrapped key could not be unwrapped" unconditionally, a
    // NamespaceError from a perfectly good NameID was reported as a wrong
    // certificate — which sends somebody to re-fetch metadata over a bug in the
    // parser three lines away.
    const aboutTheKey = /oaep|padding|rsa|decrypt|key|wrap|agree|ecdh|kdf/i
      .test(e.message || '');
    log.debug("Leaving decryptElement(). " + e.message);
    return errorCodes.mark({ ok: false, why: aboutTheKey
      ? 'the wrapped key could not be unwrapped with this service\'s private ' +
        'key (' +
        e.message + '). It was encrypted to a different certificate — and ' +
        'this service regenerates its key on every start, so a stale copy of ' +
        'its metadata is the usual cause'
      : 'the encrypted element could not be read: ' + e.message },
                           aboutTheKey ? 'STS-KEYS-0024' : 'STS-KEYS-0025');
  }
}

// ===========================================================================
// SECTION 3 — JWS / JWT
// ===========================================================================

// ---------------------------------------------------------------------------
// SIGN A JWS. Every RS256 signature this service puts on a JWT goes through
// here — but NOT every token is COUNTED here, and the difference matters.
//
// `helpers.signJwt()` sits directly on top of this and is the funnel that
// records a token in the admin console's register. It stays where it is because
// it needs two things this file must never reach: the ambient realm's key, and
// the recorder that `admin_stats.js` fills. What moved down here is the
// signature itself, so that the eight call sites that sign OUTSIDE that funnel
// — WS-Trust's SAML-shaped JWT, the three OID4VCI credential formats, the
// SD-JWT holder key, the RFC 8414 signed metadata, SPIFFE's JWT-SVID — are
// making the same call with the same defaults rather than each reaching for
// jsonwebtoken on its own.
//
// Those eight are still not counted, which is a documented property rather
// than an oversight (see `oid4vc/vc_issuer.ts` and `ws-trust/wstrust.ts`),
// and centralizing the signature does not change it.
// ---------------------------------------------------------------------------
// The `jsonwebtoken` sign options this service uses, passed through by name.
// A WHITELIST rather than a spread, and that is the point: a caller that hands
// over an object of its own cannot accidentally set `algorithm: 'none'` or
// swap the key, and a reader can see from here exactly what a signature in this
// service is allowed to vary by.
const SIGN_OPTIONS = ['keyid', 'header', 'expiresIn', 'notBefore',
                      'noTimestamp',
                      'issuer', 'audience', 'subject', 'jwtid'];

// ---------------------------------------------------------------------------
// THE ONE JWS ALGORITHM TABLE FOR THIS SERVICE.
//
// Every algorithm this service signs with or verifies is a row here, and every
// module that touches a JWS reads this rather than keeping a table of its own.
// `oauth-oidc/dpop.ts` had the second one — nine rows, node-crypto parameters,
// its own verifier — which is how DPoP came to accept a different set of
// algorithms from everything else in the service for no reason anybody chose.
//
// TWO ROWS EXIST BECAUSE A LIBRARY CANNOT DO THEM. `jsonwebtoken`'s `algorithm`
// is a string enum with no EdDSA and no ES256K, so those two are signed and
// verified directly on node's OpenSSL below. That is a limit of the library and
// never of this service: a client may legitimately register either.
//
// THE ECDSA SIGNATURE FORMAT IS NODE'S JOB AND NOT OURS. RFC 7518 section 3.4
// wants the R||S concatenation, while a general-purpose API returns the DER
// SEQUENCE of two INTEGERs — and `dsaEncoding: 'ieee-p1363'` is node asking
// OpenSSL for the former. This file briefly carried a hand-written DER
// converter for ES256K; it worked, and it was a second implementation of
// something the runtime already does, so it is gone. Anything that needs the
// raw form passes that option.
// ---------------------------------------------------------------------------
/**
 * The one JWS algorithm table: every algorithm this service signs or
 * verifies, with its family, hash and key type.
 */
const JWS_ALGS = {
  HS256: { family: 'hmac', hash: 'sha256' },
  HS384: { family: 'hmac', hash: 'sha384' },
  HS512: { family: 'hmac', hash: 'sha512' },
  RS256: { family: 'rsa', hash: 'sha256', kty: 'RSA' },
  RS384: { family: 'rsa', hash: 'sha384', kty: 'RSA' },
  RS512: { family: 'rsa', hash: 'sha512', kty: 'RSA' },
  PS256: { family: 'rsa', hash: 'sha256', kty: 'RSA',
           padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
           saltLength: 32 },
  PS384: { family: 'rsa', hash: 'sha384', kty: 'RSA',
           padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
           saltLength: 48 },
  PS512: { family: 'rsa', hash: 'sha512', kty: 'RSA',
           padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
           saltLength: 64 },
  ES256: { family: 'ec', hash: 'sha256', kty: 'EC', crv: 'P-256',
           namedCurve: 'prime256v1', sigBytes: 64 },
  ES384: { family: 'ec', hash: 'sha384', kty: 'EC', crv: 'P-384',
           namedCurve: 'secp384r1', sigBytes: 96 },
  ES512: { family: 'ec', hash: 'sha512', kty: 'EC', crv: 'P-521',
           namedCurve: 'secp521r1', sigBytes: 132 },
  // RFC 8812. `jsonwebtoken` has no ES256K, so this one is signed here.
  ES256K: { family: 'ec', hash: 'sha256', kty: 'EC', crv: 'secp256k1',
            namedCurve: 'secp256k1', sigBytes: 64, ownSigner: true },
  // RFC 8037. `jsonwebtoken` has no EdDSA either. Ed25519 hashes internally,
  // so there is no digest to name — which is what `crypto.sign(null, ...)`
  // means.
  EdDSA: { family: 'okp', hash: null, kty: 'OKP', crv: 'Ed25519',
           sigBytes: 64, ownSigner: true }
};

// The post-quantum and composite algorithms join the same table rather than
// living in one of their own — `common/pq_jose.js` performs them, and this is
// what makes them ordinary here: `signJws()` routes to it, `verifyCompactJws()`
// routes to it, and every metadata list that reads JWS_SIGNING_ALGS gained
// eleven entries without being touched.
//
// `kty: 'AKP'` is RFC 9964's key type for all of them, which is also why they
// are absent from DPoP: RFC 7638 defines a JWK Thumbprint for RSA, EC, OKP and
// oct and not for AKP, so a DPoP proof signed with one could not be bound to
// anything. See oauth-oidc/dpop.ts. (RFC 9964 has since defined the
// AKP members and `THUMBPRINT_MEMBERS` carries them, 2026-09-13; since #150
// DPoP takes the three JOSE-registered ML-DSA algorithms and refuses the
// rest by name.)
pqJose.PQ_ALGS.forEach(function (alg) {
  JWS_ALGS[alg] = { family: 'pq', hash: null, kty: 'AKP', alg: alg,
                    ownSigner: true };
});

// Every signing algorithm, and the asymmetric ones — the split matters because
// several specifications say "an asymmetric algorithm, never a MAC and never
// none": DPoP proofs (RFC 9449 section 4.2), OID4VCI proofs of possession, and
// request objects are all in that class.
/** Every JWS signing algorithm this service speaks. */
const JWS_SIGNING_ALGS = Object.keys(JWS_ALGS);
/** The asymmetric JWS algorithms: never a MAC, never `none`. */
const JWS_ASYMMETRIC_ALGS = JWS_SIGNING_ALGS.filter(function (alg) {
  return JWS_ALGS[alg].family !== 'hmac';
});

// ---------------------------------------------------------------------------
// THE HASH AN OPENID CONNECT ID TOKEN'S at_hash, c_hash AND s_hash USE
// (2026-09-22, #118).
//
// OIDC Core sections 3.1.3.6 and 3.3.2.11: the left-most half of "the hash
// algorithm used in the alg Header Parameter of the ID Token's JOSE Header" —
// RS256 is SHA-256, RS384 SHA-384 and so on. Until this date it was SHA-256
// whatever the alg, so a client that registered RS384, ES512, PS512 or EdDSA
// was handed hashes it could not validate.
//
// **WHERE THE ALGORITHM NAMES NO HASH, THIS IS THIS SERVICE'S CHOICE**, and it
// is the one decided on #118: the hash of the same security level.
//
//   EdDSA (Ed25519)          SHA-512 — the hash Ed25519 is built on, and what
//                            deployed providers use.
//   ML-DSA-44 / 65 / 87      SHA-256 / SHA-384 / SHA-512 — NIST security
//                            categories 2, 3 and 5.
//   SLH-DSA-*-128s           SHA-256 — its n is 128 bits (192 would be SHA-384
//                            and 256 SHA-512; neither is offered).
//   a composite              its TRADITIONAL component's hash: ES256 SHA-256,
//                            ES384 SHA-384, Ed25519 SHA-512, Ed448 SHAKE256
//                            with a 114-byte output (Ed448's own construction).
//
// Returns `{ name, outputLength }`: `outputLength` is set only for SHAKE256.
// An unknown algorithm is SHA-256, the value every client has always been
// able to check, and the caller refuses an unknown algorithm before signing
// anyway.
// ---------------------------------------------------------------------------
const PQ_ID_TOKEN_HASH = {
  'ML-DSA-44': 'sha256', 'ML-DSA-65': 'sha384', 'ML-DSA-87': 'sha512',
  'SLH-DSA-SHA2-128s': 'sha256', 'SLH-DSA-SHAKE-128s': 'sha256',
  'ML-DSA-44-ES256': 'sha256', 'ML-DSA-65-ES256': 'sha256',
  'ML-DSA-87-ES384': 'sha384', 'ML-DSA-44-Ed25519': 'sha512',
  'ML-DSA-65-Ed25519': 'sha512', 'ML-DSA-87-Ed448': 'shake256-114'
};

/**
 * Returns the hash an ID Token's `at_hash`, `c_hash` and `s_hash` use for
 * a signing algorithm.
 *
 * @param alg - the JWS algorithm
 * @returns `{ name }`, with `outputLength` for SHAKE256
 */
function idTokenHashFor(alg) {
  log.debug('Entering idTokenHashFor(). alg=' + alg);
  const name = String(alg || '');
  const spec = JWS_ALGS[name];
  let chosen = spec && spec.hash ? spec.hash
    : (name === 'EdDSA' ? 'sha512' : (PQ_ID_TOKEN_HASH[name] || 'sha256'));
  if (chosen === 'shake256-114') {
    log.debug('Leaving idTokenHashFor(). SHAKE256/114.');
    return { name: 'shake256', outputLength: 114 };
  }
  log.debug('Leaving idTokenHashFor(). ' + chosen);
  return { name: chosen };
}

// The base64url of the left-most half of that hash of the ASCII octets of
// `value` — at_hash, c_hash and s_hash alike.
/**
 * Returns the base64url of the left-most half of the algorithm's hash of
 * `value`: `at_hash`, `c_hash` and `s_hash` alike.
 *
 * @param value - the token or code, as ASCII
 * @param alg - the ID Token's JWS algorithm
 * @returns the half hash
 */
function idTokenHalfHash(value, alg) {
  log.debug('Entering idTokenHalfHash(). alg=' + alg);
  const hash = idTokenHashFor(alg);
  const digest = (hash.outputLength
    ? nodeCrypto.createHash(hash.name, { outputLength: hash.outputLength })
    : nodeCrypto.createHash(hash.name))
    .update(String(value), 'ascii').digest();
  log.debug('Leaving idTokenHalfHash().');
  return digest.subarray(0, digest.length / 2).toString('base64url');
}

/**
 * Returns the table row for a JWS algorithm.
 *
 * @param alg - the algorithm
 * @returns the row
 * @throws Error for an algorithm this service does not speak
 */
function jwsSpec(alg) {
  log.debug('Entering jwsSpec(). alg=' + alg);
  const spec = JWS_ALGS[alg];
  if (!spec) {
    log.debug('Leaving jwsSpec(). Unknown.');
    throw new Error('unsupported JWS algorithm "' + alg + '"; this service ' +
      'implements ' + JWS_SIGNING_ALGS.join(', ') + '.');
  }
  log.debug('Leaving jwsSpec().');
  return spec;
}

// The node parameters for one verification or signature. One place, so the PSS
// salt length and the ECDSA encoding cannot disagree between two call sites.
function nodeParamsFor(spec, key) {
  log.debug('Entering nodeParamsFor().');
  const params = { key: key };
  if (spec.padding !== undefined) {
    params.padding = spec.padding;
    params.saltLength = spec.saltLength;
  }
  if (spec.family === 'ec') {
    // RFC 7518 section 3.4 wants R||S; this is node asking OpenSSL for it
    // rather than for the DER SEQUENCE it returns by default.
    params.dsaEncoding = 'ieee-p1363';
  }
  log.debug('Leaving nodeParamsFor().');
  return params;
}

// ---------------------------------------------------------------------------
// THE PROTECTED HEADER THE TWO HAND-ROLLED SIGNERS BUILD.
//
// `jsonwebtoken` merges `options.header` into the header it makes, so the
// library path has always honoured a caller's `typ`. THE OTHER TWO DID NOT:
// the `ownSigner` branch (EdDSA and ES256K, the two the library refuses) and
// the post-quantum branch each hard-coded `typ: 'JWT'` and ignored
// `options.header` entirely — so the SAME call produced a different header
// depending on which algorithm was chosen, and no caller could have seen that
// coming.
//
// **IT COST A REAL DEFECT AND THAT IS WHY THIS FUNCTION EXISTS.** A Security
// Event Token (RFC 8417 section 2.2) carries `typ: "secevent+jwt"`, and a
// receiver that dispatches on the media type — and several do — drops one
// without it with no error anybody sees. `ssf/ssf_events.js` asks for that
// header; on RS256 it got it and on EdDSA, ES256K and every post-quantum
// algorithm it silently did not, which is precisely the shape of failure this
// module was consolidated to end.
//
// `alg` and `kid` are this function's to set and a caller may not override
// them: the algorithm is what was actually used, and the kid names the key
// that was actually used. Everything else in `options.header` is merged.
// ---------------------------------------------------------------------------
/**
 * Builds the protected header the hand-rolled signers use: `alg` and `kid`
 * set here, everything else in `options.header` merged.
 *
 * @param algorithm - the algorithm actually used
 * @param options - `header` and `keyid`
 * @returns the header
 */
function protectedHeaderFor(algorithm, options) {
  log.debug('Entering protectedHeaderFor(). alg=' + algorithm);
  const asked = (options && options.header && typeof options.header ===
    'object') ? options.header : {};
  const header = Object.assign({ typ: 'JWT' }, asked,
      { alg: algorithm });
  if (options && options.keyid) {
    header.kid = options.keyid;
  }
  log.debug('Leaving protectedHeaderFor(). typ=' + header.typ);
  return header;
}

// ---------------------------------------------------------------------------
// The JWS framing a post-quantum signature goes over: header, payload,
// base64url. The same shape as the `ownSigner` branch of signJws() below —
// written out here rather than shared with the debugger's copy ON PURPOSE, see
// the header of common/pq_jose.js — and factored out of it because the
// SYNCHRONOUS and the ASYNCHRONOUS signer must produce the same bytes, and two
// copies of a framing is one copy that will drift.
// ---------------------------------------------------------------------------
function pqSigningInput(payload, algorithm, options) {
  log.debug('Entering pqSigningInput(). alg=' + algorithm);
  const header = protectedHeaderFor(algorithm, options);
  const body = Object.assign({}, payload);
  if (body.iat === undefined) {
    body.iat = Math.floor(Date.now() / 1000);
  }
  const input = b64u(Buffer.from(JSON.stringify(header), 'utf8')) + '.' +
                b64u(Buffer.from(JSON.stringify(body), 'utf8'));
  log.debug('Leaving pqSigningInput(). ' + input.length + ' characters.');
  return input;
}

/**
 * Signs a JWT payload as a compact JWS: the one place this service signs a
 * JWT.
 *
 * @param payload - the claims
 * @param key - the signing key
 * @param opts - `algorithm` (RS256 by default), `header`, `keyid` and the
 *   claim conveniences `jsonwebtoken` takes
 * @returns the compact JWS
 * @throws Error when no key is given or the algorithm is not supported
 */
function signJws(payload, key, opts) {
  log.debug("Entering signJws().");
  const options = opts || {};
  log.debug('Entering signJws(). alg=' + (options.algorithm || 'RS256') +
            ', typ=' + (payload && payload.typ ? payload.typ : '(none)'));
  // b64u() is defined further down this file with the JWE helpers; it is used
  // here too rather than written twice.
  if (!key) {
    log.debug('Leaving signJws(). No key.');
    throw new Error('signJws: a signing key is required.');
  }
  const algorithm = options.algorithm || 'RS256';
  const spec = jwsSpec(algorithm);
  if (spec.family === 'pq') {
    const pqInput = pqSigningInput(payload, algorithm, options);
    const pqSig = jwsSignatureOver(algorithm, key,
                                   Buffer.from(pqInput, 'ascii'));
    const pqOut = pqInput + '.' + b64u(pqSig);
    log.debug('Leaving signJws(). ' + algorithm + ', ' + pqOut.length +
              ' characters.');
    return pqOut;
  }
  if (spec.ownSigner) {
    // EdDSA and ES256K — the two `jsonwebtoken` refuses. Assembled here, on
    // node's OpenSSL, with the same claim conveniences the library gives the
    // others so that a token does not gain or lose `iat` depending on which
    // algorithm signed it.
    const header = protectedHeaderFor(algorithm, options);
    const body = Object.assign({}, payload);
    if (body.iat === undefined) {
      body.iat = Math.floor(Date.now() / 1000);
    }
    const input = b64u(Buffer.from(JSON.stringify(header), 'utf8')) + '.' +
                  b64u(Buffer.from(JSON.stringify(body), 'utf8'));
    const signature = jwsSignatureOver(algorithm, key,
                                       Buffer.from(input, 'ascii'));
    const out = input + '.' + b64u(signature);
    log.debug('Leaving signJws(). ' + algorithm + ', ' + out.length +
              ' characters.');
    return out;
  }
  const signOptions = { algorithm: algorithm };
  for (let i = 0; i < SIGN_OPTIONS.length; i++) {
    const name = SIGN_OPTIONS[i];
    if (options[name] !== undefined) {
      signOptions[name] = options[name];
    }
  }
  const signed = jwt.sign(payload, key, signOptions);
  log.debug('Leaving signJws(). ' + signed.length + ' characters.');
  return signed;
}

// ---------------------------------------------------------------------------
// THE SAME SIGNATURE, WITHOUT HOLDING THE EVENT LOOP.
//
// Post-quantum signing is the one thing this service does that takes long
// enough to matter — SLH-DSA-SHAKE-128s costs about 640 ms even natively
// (#363's measurement; 14.6 s on the JavaScript implementation this replaced)
// — and node runs every listener on one thread, so for that time a
// synchronous signature answers nobody: not another HTTP caller, not the KDC
// on port 88.
//
// So the four call paths that can reach a post-quantum `alg` — the ID Token,
// the signed UserInfo response, a client assertion and an OID4VCI proof —
// call this instead, and `pq_jose.signAsync()` computes on libuv's thread
// pool (#363; a pool of forked processes until then). **EVERY OTHER
// ALGORITHM IS UNCHANGED AND IS NOT DEFERRED**: an RS256 signature is
// microseconds. Those resolve with the value signJws() computed, which is
// what lets a caller be written one way and not two.
// ---------------------------------------------------------------------------
/**
 * Signs as `signJws()` does, with a post-quantum signature computed on
 * libuv's thread pool; every other algorithm is signed in place.
 *
 * @param payload - the claims
 * @param key - the signing key
 * @param opts - as for `signJws()`
 * @returns a promise of the compact JWS
 */
function signJwsAsync(payload, key, opts) {
  log.debug("Entering signJwsAsync().");
  const options = opts || {};
  const algorithm = options.algorithm || 'RS256';
  log.debug('Entering signJwsAsync(). alg=' + algorithm);
  let spec;
  try {
    if (!key) {
      throw new Error('signJwsAsync: a signing key is required.');
    }
    spec = jwsSpec(algorithm);
  } catch (e) {
    log.debug('Leaving signJwsAsync(). Refused.');
    return Promise.reject(e);
  }
  if (spec.family !== 'pq') {
    // Not deferred, and the throw is turned into a rejection so that a caller
    // never has to know which algorithms are computed off the thread.
    try {
      const signed = signJws(payload, key, opts);
      log.debug('Leaving signJwsAsync(). ' + algorithm + ', in process.');
      return Promise.resolve(signed);
    } catch (e) {
      log.debug('Leaving signJwsAsync(). It threw.');
      return Promise.reject(e);
    }
  }
  const input = pqSigningInput(payload, algorithm, options);
  log.debug('Leaving signJwsAsync(). ' + algorithm + ', on libuv.');
  return pqJose.signAsync(algorithm, key, Buffer.from(input, 'ascii'))
    .then(function (signature) {
      return input + '.' + b64u(signature);
    });
}

// ---------------------------------------------------------------------------
// THE CLOCK ALLOWANCE THIS SERVICE APPLIES WHEN IT READS BACK A TOKEN IT
// SIGNED, AND THE DRIFT THAT MADE IT WORTH A FUNCTION.
//
// `oauth2.js` has said for a long time, in capitals, that EVERY `jwt.verify()`
// of one of our own tokens takes it — and then scoped the promise to "IN THIS
// FILE", which is the only part of it that was true. Outside that file four
// verifications of this service's own tokens omitted it entirely:
// `vc_issuer.js` twice and `vc_verifier.js` twice. Each was a second, stricter
// opinion about what "expired" means, reachable only through whichever endpoint
// had forgotten — and the symptom is a token that introspects active and is
// refused at a credential endpoint thirty seconds before it should be, which
// reads as a client bug from every side.
//
// It is read per call rather than captured, because it is runtime-settable from
// the console and a constant taken at require time would be the one value
// nothing could change.
// ---------------------------------------------------------------------------
/**
 * Returns the clock allowance applied when reading back a token this
 * service signed, read per call.
 *
 * @returns the allowance in seconds
 */
function tokenClockSkew() {
  log.debug("Entering tokenClockSkew().");
  log.debug("Leaving tokenClockSkew().");
  return config.value('oauth2.clockSkewS');
}

// ---------------------------------------------------------------------------
// VERIFY A JWS. `key` is whatever jsonwebtoken will verify with: this service's
// own certificate PEM, a client's registered public key, a shared secret.
//
// **THE CLOCK TOLERANCE IS APPLIED UNLESS A CALLER DELIBERATELY OPTS OUT**, and
// that default is the entire point of the function. A caller that wants the
// strict reading passes `clockTolerance: 0` and has said so out loud; a caller
// that says nothing gets the service's configured answer instead of an
// accidental second policy.
//
// It THROWS, exactly as `jwt.verify()` does, because every one of the twelve
// call sites already catches — several of them distinguishing
// `TokenExpiredError` from `JsonWebTokenError`, which is a distinction an
// answer-shaped return would have flattened.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// VERIFY A COMPACT JWS SOMEBODY ELSE SIGNED — the one implementation.
//
// This is for a JWS this service did NOT produce: a DPoP proof, an OID4VCI
// proof of possession, a Key Binding JWT, a client assertion, a request object.
// Its counterpart `verifyJws()` below is for the service's OWN tokens and does
// the claim checking (`exp`, `nbf`, `aud`, clock skew) that `jsonwebtoken`
// gives; this one checks a SIGNATURE and leaves the claims to the caller,
// because each of those five profiles checks different claims for different
// reasons and a shared "verify everything" would be right for none of them.
//
// THE CALLER NAMES THE ACCEPTABLE ALGORITHMS AND THE TOKEN DOES NOT — RFC 8725
// section 3.1. Reading `alg` out of the header and doing as it says is the
// algorithm-confusion defect, and it is the reason `algorithms` has no default
// here: a verifier that let the token choose would accept `none`, or an HS256
// signature made with the RSA public key everybody has.
//
// `key` may be a node KeyObject, a JWK, or a PEM. All three occur — a JWK from
// a proof's own header, a PEM from a registration, a KeyObject already parsed.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// SPLIT IN THREE, AND THE SPLIT IS WHAT LETS THE POST-QUANTUM BRANCH GO TO A
// CHILD PROCESS.
//
// Reading the token, choosing the algorithm and refusing an unacceptable one
// are the same in both directions; only the one line that actually checks the
// bytes differs, and for a composite ML-DSA verification that line took 17.8
// and 23.3 seconds on 2026-08-29 (see common/pq_native.js). So:
//
//   prepareVerification()  everything up to the check — and every refusal that
//                          is about the TOKEN rather than about the signature
//   verifyBytes()          the check itself, for everything but post-quantum
//   finishVerification()   the refusal for a signature that did not hold up,
//                          and the payload
//
// `verifyCompactJws()` below runs the three in a row exactly as it always did.
// `verifyCompactJwsAsync()` runs the same three with the post-quantum check
// on libuv's thread pool. THE ORDER OF THE REFUSALS IS PART OF THE CONTRACT: a
// token whose `alg` is not in the caller's list is refused for that and never
// for its signature, whichever entry point was used.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// STRICT BASE64URL (#202, 2026-09-24). RFC 7515 section 2 and RFC 7516
// section 2: every segment of a compact serialization is base64url with no
// padding and nothing else. Node's decoder SKIPS characters it does not know
// and ignores the unused low bits of the last character, so until
// Wycheproof's `base64` vectors a JWS whose MAC had a space, a `?` or a `#`
// inserted — or whose payload's last character had its unused bits set —
// verified: the signed text and the decoded bytes were two different things,
// and one token had many spellings. A segment is now the ONE canonical
// encoding of its bytes, or it is refused.
// ---------------------------------------------------------------------------
// strictBase64url() is a hot path: every segment of every compact JWS and JWE;
// no Entering/Leaving pair, which would drown the log.
function strictBase64url(segment, what) {
  const text = String(segment);
  const bytes = Buffer.from(text, 'base64url');
  if (!/^[A-Za-z0-9_-]*$/.test(text) || bytes.toString('base64url') !== text) {
    throw new Error('the ' + what + ' is not canonical base64url (RFC 7515 ' +
      'section 2): it carries a character outside the alphabet, padding, or ' +
      'unused bits that are not zero.');
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// A KEY A JWS MAY NOT BE VERIFIED WITH (#202, 2026-09-24). Wycheproof's
// json_web_key vectors found that any key node would load was used:
//
//   * an RSA public exponent below 3, or even — RFC 8017 section 3.1 requires
//     3 <= e, odd. With e = 1 a "signature" is the padded digest itself and
//     anybody can make one. Refused in EVERY mode: it is not a weak key but a
//     forgery.
//   * an RSA modulus with the ROCA fingerprint (CVE-2017-15361, Infineon's
//     RSALib): such a key is factorable. Refused in every mode, by the
//     published test — the modulus's residue modulo each of 38 small primes
//     lies in the subgroup 65537 generates, which a random modulus does with
//     negligible probability.
//   * an RSA modulus under 2048 bits — RFC 7518 section 3.3 (and RFC 8230
//     section 5 for COSE) says a key of 2048 bits or larger MUST be used.
//   * an HMAC key shorter than the hash output — RFC 7518 section 3.2 says a
//     key of the same size as the hash output or larger MUST be used. An
//     EMPTY key is refused in every mode.
//
// The two size floors are refused in PRODUCT (`mode.usesBrokenAlgorithms()`):
// development keeps accepting them so that a client whose key or
// client_secret is too short can be exercised, which is the same bargain
// that predicate makes for SHA-1 and rsa-1_5. Answers '' or the sentence.
// ---------------------------------------------------------------------------
const ROCA_PRIMES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
                     59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109,
                     113, 127, 131, 137, 139, 149, 151, 157, 163, 167];
const ROCA_SUBGROUPS = ROCA_PRIMES.map(function (p) {
  const members = {};
  const g = 65537 % p;
  let x = 1;
  do {
    members[x] = true;
    x = (x * g) % p;
  } while (x !== 1);
  return { p: BigInt(p), members: members };
});

// rsaKeyProblem() is a hot path: every RSA verification; no Entering/Leaving
// pair.
function rsaKeyProblem(publicKey, minimumBits) {
  if (!publicKey || (publicKey.asymmetricKeyType !== 'rsa' &&
                     publicKey.asymmetricKeyType !== 'rsa-pss')) {
    return '';
  }
  const details = publicKey.asymmetricKeyDetails || {};
  const e = BigInt(details.publicExponent || 0);
  if (e < 3n || e % 2n === 0n) {
    return 'an RSA public exponent of ' + e + ' (RFC 8017 section 3.1 ' +
      'requires an odd e of at least 3)';
  }
  const n = rsaModulus(publicKey);
  const roca = ROCA_SUBGROUPS.every(function (row) {
    return row.members[Number(n % row.p)] === true;
  });
  if (roca) {
    return 'an RSA modulus with the ROCA fingerprint (CVE-2017-15361), ' +
      'which is factorable';
  }
  const bits = Number(details.modulusLength || 0);
  if (minimumBits && bits < minimumBits && !mode.usesBrokenAlgorithms()) {
    return 'a ' + bits + '-bit RSA key, where ' + minimumBits + ' bits or ' +
      'more MUST be used (RFC 7518 section 3.3, RFC 8230 section 5)';
  }
  return '';
}

// The modulus of an RSA public key as a BigInt. Node exports an `rsa` key
// as a JWK but not an `rsa-pss` one, so the SubjectPublicKeyInfo's
// RSAPublicKey is read for that.
// rsaModulus() is a hot path: every RSA verification.
function rsaModulus(publicKey) {
  if (publicKey.asymmetricKeyType === 'rsa') {
    const jwk = publicKey.export({ format: 'jwk' });
    return BigInt('0x' + Buffer.from(String(jwk.n), 'base64url')
      .toString('hex'));
  }
  const der = publicKey.export({ type: 'spki', format: 'der' });
  const spki = asn1js.fromBER(new Uint8Array(der).buffer);
  const bits = /** @type {any} */ (spki.result).valueBlock.value[1];
  const inner = asn1js.fromBER(bits.valueBlock.valueHexView.slice().buffer);
  const n = /** @type {any} */ (inner.result).valueBlock.value[0];
  return BigInt('0x' + Buffer.from(n.valueBlock.valueHexView).toString('hex'));
}

// A JWK that says it is not for verifying signatures (RFC 7517 sections
// 4.2 and 4.3): `use` other than `sig`, or `key_ops` without `verify`.
// jwkUseProblem() is a hot path: every verification with a JWK.
function jwkUseProblem(key) {
  if (!key || typeof key !== 'object' || !key.kty) {
    return '';
  }
  if (key.use !== undefined && key.use !== 'sig') {
    return 'a JWK whose "use" is "' + key.use + '" (RFC 7517 section 4.2)';
  }
  if (Array.isArray(key.key_ops) && key.key_ops.indexOf('verify') < 0) {
    return 'a JWK whose "key_ops" do not include "verify" (RFC 7517 ' +
      'section 4.3)';
  }
  return '';
}

// hmacKeyProblem() is a hot path: every HMAC verification; no Entering/Leaving
// pair.
function hmacKeyProblem(spec, key) {
  const bytes = Buffer.isBuffer(key) ? key.length
    : (key && typeof key === 'object' && key.type === 'secret')
      ? Number(key.symmetricKeySize || 0)
      : Buffer.byteLength(String(key == null ? '' : key), 'utf8');
  if (!bytes) {
    return 'an empty HMAC key';
  }
  // RFC 7518 section 3.2: "A key of the same size as the hash output ...
  // or larger MUST be used". Refused in PRODUCT (#202); development accepts
  // a shorter one so a client holding one can be exercised
  // (`mode.usesBrokenAlgorithms()`, REQUIREMENTS `jose-key-sizes`). The key
  // is what `client_secret_jwt` signs with — the UTF-8 octets of the
  // client_secret — which is why `oauth2.registeredSecretBytes` mints one
  // long enough for HS512 by default.
  const need = nodeCrypto.createHash(spec.hash).digest().length;
  if (bytes < need && !mode.usesBrokenAlgorithms()) {
    return 'a ' + (bytes * 8) + '-bit HMAC key for ' + spec.hash + ', where ' +
      'a key of the hash output\'s size (' + (need * 8) + ' bits) or larger ' +
      'MUST be used (RFC 7518 section 3.2)';
  }
  return '';
}

function prepareVerification(token, key, options) {
  log.debug('Entering prepareVerification().');
  const parts = String(token || '').split('.');
  if (parts.length !== 3) {
    log.debug('Leaving prepareVerification(). Not three parts.');
    throw new Error('a compact JWS has three dot-separated parts; this has ' +
      parts.length + '.');
  }
  let header;
  let signatureBytes;
  try {
    strictBase64url(parts[1], 'JWS payload');
    signatureBytes = strictBase64url(parts[2], 'JWS signature');
    header = JSON.parse(strictBase64url(parts[0], 'JWS protected header')
      .toString('utf8'));
  } catch (e) {
    log.debug('Leaving prepareVerification(). The header is not JSON.');
    throw new Error('the JWS protected header is not readable base64url ' +
      'JSON: ' + e.message);
  }
  const allowed = options.algorithms;
  if (!Array.isArray(allowed) || !allowed.length) {
    log.debug('Leaving prepareVerification(). No algorithm list.');
    throw new Error('verifyCompactJws: the caller must name the acceptable ' +
      'algorithms. A verifier that takes them from the token is the ' +
      'algorithm-confusion defect (RFC 8725 section 3.1).');
  }
  if (allowed.indexOf(header.alg) === -1) {
    log.debug('Leaving prepareVerification(). Algorithm not accepted.');
    throw new Error('this JWS is signed with "' + header.alg + '" and only ' +
      allowed.join(', ') + ' ' + (allowed.length === 1 ? 'is' : 'are') +
      ' accepted here.');
  }
  const spec = jwsSpec(header.alg);
  const prepared = {
    header: header,
    spec: spec,
    payload: parts[1],
    signingInput: Buffer.from(parts[0] + '.' + parts[1], 'ascii'),
    signature: signatureBytes,
    // AN EMPTY PAYLOAD IS A MESSAGE, FOR ONE CALLER (2026-09-13). RFC 8555
    // section 6.3's POST-as-GET is a JWS whose payload is the empty string,
    // and it is signed exactly like any other. Only a caller that says so gets
    // `claims: null` for it; every other caller still has an empty payload
    // refused as unreadable, which is what it was before this existed.
    emptyPayload: options.emptyPayload === true && parts[1] === ''
  };
  if (spec.family === 'pq') {
    // `key` is the AKP `pub` value — bytes, or the base64url of them off a
    // JWK, which is what a verifier is handed in practice. Read HERE rather
    // than at the check, so that a key that cannot be read is refused in the
    // same place whichever entry point was used.
    prepared.pub = pqPublicBytes(key);
  }
  log.debug('Leaving prepareVerification(). alg=' + header.alg);
  return prepared;
}

// An AKP public key as bytes: a JWK's `pub`, its base64url text, or bytes.
function pqPublicBytes(key) {
  log.debug('Entering pqPublicBytes().');
  log.debug('Leaving pqPublicBytes().');
  return (key && key.pub) ? Buffer.from(key.pub, 'base64url')
    : (typeof key === 'string' ? Buffer.from(key, 'base64url')
                               : Buffer.from(key));
}

// ---------------------------------------------------------------------------
// THE SIGNATURE CHECK OF A JWS, OVER OCTETS A CALLER NAMES (#202, 2026-09-24).
//
// `verifyCompactJws()` is this and nothing more once it has read the token
// and refused an algorithm the caller did not name: the same `verifyBytes()`
// for every classical algorithm and the same `pqJose.verify()` for the
// post-quantum ones. It is a function of its own so that an EXTERNAL answer
// can be held to exactly the check a JWS gets — C2SP Wycheproof's vectors
// (`tests/wycheproof.js`) and NIST's ACVP ones (`tests/acvp_pqc.js`) are
// signatures over arbitrary octets, which no compact serialization can carry,
// since what a JWS signs is always `BASE64URL(header) '.' BASE64URL(payload)`.
// Refactored rather than copied, so a vector that passes here passes for the
// same reason a token does. Returns true or false, and THROWS where the token
// path throws (an ECDSA signature of the wrong length, a key that will not
// load, an algorithm this service does not implement).
// ---------------------------------------------------------------------------
function checkPreparedSignature(prepared, key) {
  log.debug('Entering checkPreparedSignature(). alg=' + prepared.header.alg);
  const ok = prepared.spec.family === 'pq'
    ? pqJose.verify(prepared.header.alg, prepared.pub, prepared.signingInput,
                    prepared.signature)
    : verifyBytes(prepared, key);
  log.debug('Leaving checkPreparedSignature(). ' + !!ok);
  return !!ok;
}

/**
 * Says whether a JWS signature verifies over a signing input, for external
 * test vectors.
 *
 * @param alg - the algorithm
 * @param key - the verification key
 * @param signingInput - the octets signed
 * @param signature - the signature
 * @returns true when it verifies
 */
function jwsSignatureValid(alg, key, signingInput, signature) {
  log.debug('Entering jwsSignatureValid(). alg=' + alg);
  const spec = jwsSpec(alg);
  const prepared = {
    header: { alg: alg },
    spec: spec,
    signingInput: Buffer.from(signingInput),
    signature: Buffer.from(signature)
  };
  if (spec.family === 'pq') {
    prepared.pub = pqPublicBytes(key);
  }
  const ok = checkPreparedSignature(prepared, key);
  log.debug('Leaving jwsSignatureValid(). ' + ok);
  return ok;
}

// ---------------------------------------------------------------------------
// THE SIGNATURE A JWS CARRIES, OVER OCTETS A CALLER NAMES — for the
// algorithms this file signs ITSELF: EdDSA and ES256K (the `ownSigner` rows)
// and every post-quantum one. `signJws()` signs through this. The rows
// `jsonwebtoken` signs are refused by name: this function would otherwise
// be a second signer for them that nothing in the service uses.
// ---------------------------------------------------------------------------
/**
 * Signs octets as a JWS signature, for the algorithms this file signs
 * itself: EdDSA, ES256K and the post-quantum ones.
 *
 * @param alg - the algorithm
 * @param key - the signing key
 * @param signingInput - the octets to sign
 * @returns the signature
 */
function jwsSignatureOver(alg, key, signingInput) {
  log.debug('Entering jwsSignatureOver(). alg=' + alg);
  const spec = jwsSpec(alg);
  const input = Buffer.from(signingInput);
  if (spec.family === 'pq') {
    const pqSig = Buffer.from(pqJose.sign(alg, key, input));
    log.debug('Leaving jwsSignatureOver(). Post-quantum.');
    return pqSig;
  }
  if (!spec.ownSigner) {
    log.debug('Leaving jwsSignatureOver(). jsonwebtoken signs this one.');
    throw new Error('jwsSignatureOver: ' + alg + ' is signed by ' +
      'jsonwebtoken inside signJws(), not by this file.');
  }
  const signature = nodeCrypto.sign(spec.hash, input,
                                    nodeParamsFor(spec, key));
  log.debug('Leaving jwsSignatureOver(). ' + alg + '.');
  return signature;
}

// Everything but post-quantum, which is every algorithm whose check is
// microseconds and belongs in the process that is holding the request open.
function verifyBytes(prepared, key) {
  log.debug('Entering verifyBytes(). alg=' + prepared.header.alg);
  const spec = prepared.spec;
  const signingInput = prepared.signingInput;
  const signature = prepared.signature;
  const misuse = jwkUseProblem(key);
  if (misuse) {
    log.debug('Leaving verifyBytes(). ' + misuse);
    throw new Error('this JWS cannot be verified with ' + misuse + '.');
  }
  if (spec.family === 'hmac') {
    const weak = hmacKeyProblem(spec, key);
    if (weak) {
      log.debug('Leaving verifyBytes(). ' + weak);
      throw new Error('this JWS cannot be verified with ' + weak + '.');
    }
    const expected = nodeCrypto.createHmac(spec.hash, key)
      .update(signingInput).digest();
    log.debug('Leaving verifyBytes(). HMAC.');
    return expected.length === signature.length &&
           nodeCrypto.timingSafeEqual(expected, signature);
  }
  // A raw ECDSA signature is a fixed length; a wrong one reaches OpenSSL as
  // a buffer it will refuse in a way that names nothing, so it is checked
  // here where the reason can be given.
  if (spec.sigBytes && spec.family === 'ec' &&
      signature.length !== spec.sigBytes) {
    log.debug('Leaving verifyBytes(). Wrong signature length.');
    throw new Error('an ' + prepared.header.alg + ' signature is ' +
      spec.sigBytes + ' bytes — the R||S concatenation of RFC 7518 section ' +
      '3.4 — and this one is ' + signature.length + '. A ~70-byte one is the ' +
      'DER SEQUENCE a general-purpose crypto API returns, sent without ' +
      'converting it.');
  }
  let publicKey;
  try {
    publicKey = (key && key.type === 'public') ? key
      : nodeCrypto.createPublicKey(
          (key && key.kty) ? { key: key, format: 'jwk' } : key);
  } catch (e) {
    log.debug('Leaving verifyBytes(). The key would not load.');
    throw new Error('the verification key could not be read: ' + e.message);
  }
  const weakRsa = spec.family === 'rsa' ? rsaKeyProblem(publicKey, 2048)
                                        : '';
  if (weakRsa) {
    log.debug('Leaving verifyBytes(). ' + weakRsa);
    throw new Error('this JWS cannot be verified with ' + weakRsa + '.');
  }
  log.debug('Leaving verifyBytes(). ' + spec.family + '.');
  return nodeCrypto.verify(spec.hash, signingInput,
      nodeParamsFor(spec, publicKey), signature);
}

function finishVerification(prepared, ok) {
  log.debug('Entering finishVerification(). ok=' + ok);
  if (!ok) {
    log.debug('Leaving finishVerification(). It does not verify.');
    throw new Error('the ' + prepared.header.alg +
      ' signature does not verify.');
  }
  if (prepared.emptyPayload) {
    log.debug('Leaving finishVerification(). An empty payload, as asked.');
    return { header: prepared.header, claims: null };
  }
  let claims;
  try {
    claims = JSON.parse(Buffer.from(prepared.payload, 'base64url')
      .toString('utf8'));
  } catch (e) {
    log.debug('Leaving finishVerification(). The payload is not JSON.');
    throw new Error('the JWS payload is not readable base64url JSON: ' +
      e.message);
  }
  log.debug('Leaving finishVerification(). ' + prepared.header.alg +
            ' verified.');
  return { header: prepared.header, claims: claims };
}

/**
 * Verifies a compact JWS's signature, without the claim checks.
 *
 * @param token - the compact JWS
 * @param key - the verification key
 * @param opts - `algorithms`, and `emptyPayload` for a detached payload
 * @returns `{ header, claims }`
 * @throws Error when it does not verify or the payload is not JSON
 */
function verifyCompactJws(token, key, opts) {
  log.debug("Entering verifyCompactJws().");
  const options = opts || {};
  log.debug('Entering verifyCompactJws().');
  const prepared = prepareVerification(token, key, options);
  const ok = checkPreparedSignature(prepared, key);
  const out = finishVerification(prepared, ok);
  log.debug('Leaving verifyCompactJws(). ' + prepared.header.alg +
            ' verified.');
  return out;
}

// The same verification with the post-quantum check on libuv's thread pool.
// Every other algorithm resolves with what verifyCompactJws() computed, for
// the reason signJwsAsync() gives: an RS256 check is microseconds.
/**
 * Verifies as `verifyCompactJws()` does, with a post-quantum signature
 * checked on libuv's thread pool.
 *
 * @param token - the compact JWS
 * @param key - the verification key
 * @param opts - as for `verifyCompactJws()`
 * @returns a promise of `{ header, claims }`
 */
function verifyCompactJwsAsync(token, key, opts) {
  log.debug("Entering verifyCompactJwsAsync().");
  const options = opts || {};
  log.debug('Entering verifyCompactJwsAsync().');
  let prepared;
  try {
    prepared = prepareVerification(token, key, options);
  } catch (e) {
    log.debug('Leaving verifyCompactJwsAsync(). Refused.');
    return Promise.reject(e);
  }
  if (prepared.spec.family !== 'pq') {
    try {
      const out = finishVerification(prepared, verifyBytes(prepared, key));
      log.debug('Leaving verifyCompactJwsAsync(). In process.');
      return Promise.resolve(out);
    } catch (e) {
      log.debug('Leaving verifyCompactJwsAsync(). It did not verify.');
      return Promise.reject(e);
    }
  }
  log.debug('Leaving verifyCompactJwsAsync(). On libuv.');
  return pqJose.verifyAsync(prepared.header.alg, prepared.pub,
                            prepared.signingInput, prepared.signature)
    .then(function (ok) {
      return finishVerification(prepared, ok);
    });
}

// The claim checks `jsonwebtoken` performs, for the two algorithms it cannot
// verify. Written once, here, so that an EdDSA or ES256K token is held to
// exactly the same rules as an RS256 one — a token that skipped `exp` because
// of the curve it was signed on would be the worst kind of inconsistency.
/**
 * Checks a JWT's claims as `jsonwebtoken` does: expiry, not-before, issuer
 * and audience, with the clock allowance.
 *
 * @param claims - the claims
 * @param options - `issuer`, `audience` and the clock options
 * @returns the claims
 * @throws Error naming the check that failed
 */
function checkJwtClaims(claims, options) {
  log.debug('Entering checkJwtClaims().');
  const now = Math.floor(Date.now() / 1000);
  const skew = options.clockTolerance === undefined ? tokenClockSkew()
                                                    : options.clockTolerance;
  if (claims.exp !== undefined && now > Number(claims.exp) + skew) {
    // `any` because `expiredAt` is jsonwebtoken's member, not Error's.
    const e = /** @type {any} */ (new Error('jwt expired'));
    e.name = 'TokenExpiredError';
    e.expiredAt = new Date(Number(claims.exp) * 1000);
    log.debug('Leaving checkJwtClaims(). Expired.');
    throw e;
  }
  if (claims.nbf !== undefined && now + skew < Number(claims.nbf)) {
    const e = new Error('jwt not active');
    e.name = 'NotBeforeError';
    log.debug('Leaving checkJwtClaims(). Not yet valid.');
    throw e;
  }
  if (options.issuer !== undefined && claims.iss !== options.issuer) {
    log.debug('Leaving checkJwtClaims(). Wrong issuer.');
    throw new Error('jwt issuer invalid. expected: ' + options.issuer);
  }
  if (options.audience !== undefined) {
    // `aud` may be a string or an array, and the expectation may be either
    // too; a match on ANY member is a match, which is the rule RFC 7519
    // section 4.1.3 states and the one jsonwebtoken applies.
    const wanted = Array.isArray(options.audience) ? options.audience
                                                   : [options.audience];
    const held = Array.isArray(claims.aud) ? claims.aud
                                           : [claims.aud];
    const hit = wanted.some(function (one) {
      return held.indexOf(one) !== -1;
    });
    if (wanted.length && !hit) {
      log.debug('Leaving checkJwtClaims(). Wrong audience.');
      throw new Error('jwt audience invalid. expected: ' + wanted.join(' or '));
    }
  }
  log.debug('Leaving checkJwtClaims().');
  return claims;
}

/**
 * Verifies a compact JWS and checks its claims: the one entry point for
 * "verify a JWT", for every algorithm this service speaks.
 *
 * @param token - the compact JWS
 * @param key - the verification key
 * @param opts - `algorithms` (the token's own when omitted), and
 *   `issuer`, `audience` and the clock checks
 * @returns the claims
 * @throws Error when the signature or a claim check fails
 */
function verifyJws(token, key, opts) {
  log.debug("Entering verifyJws().");
  const options = opts || {};
  log.debug('Entering verifyJws().');
  // THE TWO ALGORITHMS `jsonwebtoken` CANNOT VERIFY GO THE OTHER WAY, and they
  // are held to the same claim rules — see checkJwtClaims(). This keeps ONE
  // entry point for "verify a JWS and check its claims": every caller in this
  // service gained EdDSA and ES256K the day this branch was added, without
  // any of them changing, which is the whole point of there being one.
  let peeked = null;
  try {
    peeked = JSON.parse(Buffer.from(String(token || '').split('.')[0],
      'base64url').toString('utf8'));
  } catch (e) {
    log.debug("Caught in verifyJws(): " + ((e && e.message) || e));
    peeked = null;
  }
  if (peeked && JWS_ALGS[peeked.alg] && JWS_ALGS[peeked.alg].ownSigner) {
    const allowed = options.algorithms || [peeked.alg];
    const verified = verifyCompactJws(token, key, { algorithms: allowed });
    log.debug('Leaving verifyJws(). ' + peeked.alg + ' via the shared ' +
              'verifier.');
    return checkJwtClaims(verified.claims, options);
  }
  // The library path is held to the same two rules as the shared verifier
  // (#202): one canonical spelling of each segment, and — for an HMAC — a
  // key RFC 7518 section 3.2 allows. jsonwebtoken already refuses an RSA
  // key under 2048 bits by default (its allowInsecureKeySizes).
  const segments = String(token || '').split('.');
  if (segments.length === 3) {
    strictBase64url(segments[0], 'JWS protected header');
    strictBase64url(segments[1], 'JWS payload');
    strictBase64url(segments[2], 'JWS signature');
  }
  if (peeked && JWS_ALGS[peeked.alg] &&
      JWS_ALGS[peeked.alg].family === 'hmac') {
    const weak = hmacKeyProblem(JWS_ALGS[peeked.alg], key);
    if (weak) {
      log.debug('Leaving verifyJws(). ' + weak);
      throw new Error('this JWS cannot be verified with ' + weak + '.');
    }
  }
  const verifyOptions = Object.assign({}, options);
  if (verifyOptions.algorithms === undefined) {
    // Naming the algorithms is not decoration: jsonwebtoken will otherwise
    // accept whatever the token's own header asks for, which is how `alg: none`
    // and an HS256 token verified against an RSA PUBLIC key — a value the
    // attacker also has — became the two best-known JWT vulnerabilities.
    verifyOptions.algorithms = ['RS256'];
  }
  if (verifyOptions.clockTolerance === undefined) {
    verifyOptions.clockTolerance = tokenClockSkew();
  }
  const claims = jwt.verify(token, key, verifyOptions);
  log.debug('Leaving verifyJws(). sub=' + (claims.sub || '(none)'));
  return claims;
}

// ---------------------------------------------------------------------------
// The same entry point, with a post-quantum signature checked in a child
// process. It is a SEPARATE FUNCTION rather than verifyJws() made async,
// because every one of that function's callers is synchronous and turning the
// return value of all of them into a promise would be a change to code that
// verifies RS256 in microseconds and has nothing to gain from it.
//
// The two share `checkJwtClaims()` and the peek that chooses between the
// library and the shared verifier, so an AKP assertion is held to exactly the
// same `exp`, `nbf`, `aud` and clock-skew rules as an RS256 one. A token that
// skipped a claim check because of the algorithm it was signed with would be
// the worst kind of inconsistency, and it is the reason this is a wrapper of
// the same three steps rather than a second reading of them.
// ---------------------------------------------------------------------------
/**
 * Verifies as `verifyJws()` does, with a post-quantum signature checked on
 * libuv's thread pool, and the same claim checks.
 *
 * @param token - the compact JWS
 * @param key - the verification key
 * @param opts - as for `verifyJws()`
 * @returns a promise of the claims
 */
function verifyJwsAsync(token, key, opts) {
  log.debug("Entering verifyJwsAsync().");
  const options = opts || {};
  log.debug('Entering verifyJwsAsync().');
  let peeked = null;
  try {
    peeked = JSON.parse(Buffer.from(String(token || '').split('.')[0],
      'base64url').toString('utf8'));
  } catch (e) {
    log.debug("Caught in verifyJwsAsync(): " + ((e && e.message) || e));
    peeked = null;
  }
  if (peeked && JWS_ALGS[peeked.alg] && JWS_ALGS[peeked.alg].family === 'pq') {
    const allowed = options.algorithms || [peeked.alg];
    log.debug('Leaving verifyJwsAsync(). On libuv.');
    return verifyCompactJwsAsync(token, key, { algorithms: allowed })
      .then(function (verified) {
        return checkJwtClaims(verified.claims, options);
      });
  }
  // Everything else — including EdDSA and ES256K, which go through the shared
  // verifier but are microseconds — is what verifyJws() already does.
  try {
    const claims = verifyJws(token, key, opts);
    log.debug('Leaving verifyJwsAsync(). In process.');
    return Promise.resolve(claims);
  } catch (e) {
    log.debug('Leaving verifyJwsAsync(). It did not verify.');
    return Promise.reject(e);
  }
}

// ===========================================================================
// SECTION 4a — POST-QUANTUM AND HPKE KEY ESTABLISHMENT FOR JWE (#82,
// 2026-09-27)
// ===========================================================================
//
// It sits BEFORE section 4 rather than after it because section 4's alg
// lists (`JWE_ASYMMETRIC_ALGS` and the rest) are built from this section's
// table when the module loads, and a `const` read before its line throws.
//
// ---------------------------------------------------------------------------
// WHY THIS SECTION EXISTS. Section 4's key management was RSA and ECDH only.
// A signature is checked when it is presented, so a signature algorithm that
// falls in 2035 is a problem in 2035. A CIPHERTEXT captured today can be kept
// and opened then, so every encrypted ID Token, Logout Token, UserInfo
// response and OID4VP response this service sent was only as safe as a
// classical key agreement. This section adds two families, and a JWE reaches
// both through `encryptJweCompact()` and `decryptJweCompact()` above, the
// same two functions every other `alg` goes through (rule 3r):
//
//   ML-KEM-512 / -768 / -1024            draft-ietf-jose-pqc-kem-05, JOSE
//   ML-KEM-512+A128KW / -768+A192KW /    sections 5.1, 6 and 8: the KEM
//     -1024+A256KW                       shared secret through KMAC256, used
//                                        as the CEK (direct) or as an AES Key
//                                        Wrap key; the KEM ciphertext in `ek`
//   HPKE-0 .. HPKE-7 (and -KE forms)     draft-ietf-jose-hpke-encrypt-22:
//                                        HPKE over the classical DHKEMs,
//                                        Integrated or Key Encryption
//   HPKE-8 .. HPKE-16 (and -KE forms)    draft-reddy-cose-jose-pqc-hybrid-
//                                        hpke-11: HPKE over ML-KEM and the
//                                        PQ/T hybrids of draft-ietf-hpke-pq-05
//                                        (X-Wing is HPKE-10 and HPKE-11)
//
// **EVERY ONE OF THESE IS A DRAFT, AND WHICH TEXT WAS READ IS THE RECORD.**
//
//   * pqc-kem: revision -06 (6 July 2026) REMOVED every JOSE section; it is a
//     COSE document now. -05 (9 December 2025) is the last text that defines
//     the JWE algorithms, and it is what is implemented, with one deliberate
//     departure: -05 says an AKP `priv` is "the 32-byte seed", and an ML-KEM
//     key pair cannot be made from 32 bytes (FIPS 203 KeyGen_internal takes
//     d AND z). -06 corrected it to the 64-octet d || z, and that is what is
//     used here. No revision has test vectors.
//   * The hybrid names are from an INDIVIDUAL draft, -11, which expired on
//     2026-08-20. It is the only document that names a hybrid JWE `alg` at
//     all, so it is what is implemented, and the console says so.
//   * jose-hpke-encrypt-22 removed HPKE-4-KE and HPKE-6-KE (their vectors
//     are still in the working group's repository; `tests/jwe_pq_kem.js`
//     classifies them as not applicable for that reason).
//   * The HPKE core is draft-ietf-hpke-hpke (RFC 9180's successor, which adds
//     the one-stage KDFs the SHAKE suites need); the KEMs are
//     draft-ietf-hpke-pq-05, over draft-irtf-cfrg-concrete-hybrid-kems and
//     draft-irtf-cfrg-hybrid-kems-12. hpke-pq-05's and the concrete draft's
//     published vectors are what `tests/jwe_pq_kem.js` holds this to.
//
// **WHAT RUNS WHERE.** ML-KEM is node's OpenSSL through
// `common/pq_native.js` (#363; @noble/post-quantum until then), which takes
// the 64-octet seed the key format is defined in. FIPS 203 section 7.2's
// modulus check on an encapsulation key, which HPKE-PQ section 3 requires,
// is made by `mlkemCheckEncapsulationKey()` below whatever the primitive
// does, so the requirement is visible here rather than assumed of a
// library. The
// traditional half of every hybrid, every DHKEM, AES-GCM, ChaCha20-Poly1305,
// HKDF, SHA3-256 and SHAKE are node's OpenSSL; KMAC256 and TurboSHAKE, which
// node does not offer, are `@noble/hashes`.
//
// **SYNCHRONOUS, AND THAT WAS MEASURED** (#82's note). A whole JWE —
// encrypt and decrypt, key expansion from the seed included — cost
// milliseconds on the JavaScript ML-KEM this used until #363 (RSA-OAEP-256
// 0.5 ms, ML-KEM-768 1.3 ms, X-Wing 3.4 ms, ML-KEM-1024 + P-384 7.4 ms), and
// ML-KEM on node's OpenSSL (`common/pq_native.js`, #363) is a fraction of
// that. `tests/jwe_pq_kem.js` prints the figures on every run.
//
// **THE PUBLISHED VECTORS ARE CHECKED FROM THE RECEIVING SIDE** since #363.
// FIPS 203's Encaps_internal takes the encapsulation randomness m as an
// input, and the vectors are made with it; node's OpenSSL does not take it,
// so `mlkemEncaps()` refuses a given `randomness` rather than ignoring it,
// and the vector tests decapsulate the vector's ciphertext instead.
// ---------------------------------------------------------------------------

const nobleMlKem = require('./pq_native');
const nobleSha3Addons = require('@noble/hashes/sha3-addons');

// ---------------------------------------------------------------------------
// BYTE HELPERS. `I2OSP(n, w)` is RFC 8017's, big-endian; `lengthPrefixed()`
// is draft-ietf-hpke-hpke section 3's two-byte length and the bytes.
// ---------------------------------------------------------------------------
function i2osp(n, width) {
  log.debug('Entering i2osp().');
  const out = Buffer.alloc(width);
  let v = BigInt(n);
  for (let i = width - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) {
    log.debug('Leaving i2osp(). Too wide.');
    throw new Error('i2osp: ' + n + ' does not fit in ' + width + ' octets');
  }
  log.debug('Leaving i2osp().');
  return out;
}

function lengthPrefixed(bytes) {
  log.debug('Entering lengthPrefixed().');
  const b = Buffer.from(bytes);
  if (b.length > 65535) {
    log.debug('Leaving lengthPrefixed(). Too long.');
    throw new Error('lengthPrefixed: ' + b.length + ' octets is more than ' +
                    'two octets can count');
  }
  log.debug('Leaving lengthPrefixed().');
  return Buffer.concat([i2osp(b.length, 2), b]);
}

function shake(bits, input, length) {
  log.debug('Entering shake(). SHAKE' + bits + ', ' + length + ' octets.');
  const out = nodeCrypto.createHash('shake' + bits, { outputLength: length })
    .update(Buffer.from(input)).digest();
  log.debug('Leaving shake().');
  return out;
}

function sha3_256(input) {
  log.debug('Entering sha3_256().');
  const out = nodeCrypto.createHash('sha3-256').update(Buffer.from(input))
    .digest();
  log.debug('Leaving sha3_256().');
  return out;
}

// ---------------------------------------------------------------------------
// ML-KEM, AS THE THREE PARAMETER SETS FIPS 203 DEFINES. `Npk` and `Nct` are
// the encapsulation key and ciphertext sizes; `k` is the module rank, which
// the encapsulation key check needs.
// ---------------------------------------------------------------------------
const MLKEM_SETS = {
  'ML-KEM-512': { impl: nobleMlKem.ml_kem512, k: 2, Npk: 800, Nct: 768 },
  'ML-KEM-768': { impl: nobleMlKem.ml_kem768, k: 3, Npk: 1184, Nct: 1088 },
  'ML-KEM-1024': { impl: nobleMlKem.ml_kem1024, k: 4, Npk: 1568, Nct: 1568 }
};

// FIPS 203 section 7.2, "input checking": the encapsulation key is 384k + 32
// octets, and every one of its 256k twelve-bit coefficients is below q =
// 3329 (ByteEncode12(ByteDecode12(ek)) == ek). An unreduced key is refused,
// never encapsulated to: HPKE-PQ section 3 makes it an EncapError, and a
// sender that encrypts to a malformed key has no idea what it produced.
/**
 * FIPS 203 section 7.2's encapsulation key check.
 *
 * @param set - ML-KEM-512, -768 or -1024
 * @param ek - the encapsulation key
 * @throws Error for a wrong size or an unreduced coefficient
 */
function mlkemCheckEncapsulationKey(set, ek) {
  log.debug('Entering mlkemCheckEncapsulationKey().');
  const spec = MLKEM_SETS[set];
  const bytes = Buffer.from(ek);
  if (!spec || bytes.length !== spec.Npk) {
    log.debug('Leaving mlkemCheckEncapsulationKey(). Wrong size.');
    throw new Error('an ' + set + ' encapsulation key is ' +
                    (spec ? spec.Npk : '?') + ' octets; this one is ' +
                    bytes.length);
  }
  const polyBytes = 384 * spec.k;
  for (let i = 0; i < polyBytes; i += 3) {
    const a = bytes[i] | ((bytes[i + 1] & 0x0f) << 8);
    const b = (bytes[i + 1] >> 4) | (bytes[i + 2] << 4);
    if (a >= 3329 || b >= 3329) {
      log.debug('Leaving mlkemCheckEncapsulationKey(). Unreduced.');
      throw new Error('the ' + set + ' encapsulation key fails FIPS 203 ' +
                      'section 7.2\'s modulus check: a coefficient is not ' +
                      'below q = 3329');
    }
  }
  log.debug('Leaving mlkemCheckEncapsulationKey().');
}

// The key pair from the 64-octet seed d || z (FIPS 203 KeyGen_internal).
// `dk` is the EXPANDED decapsulation key, which never leaves this section:
// the seed is the key's only stored form (pqc-kem-06 section 8, HPKE-PQ
// section 3).
function mlkemFromSeed(set, seed) {
  log.debug('Entering mlkemFromSeed(). ' + set);
  const spec = MLKEM_SETS[set];
  const bytes = Buffer.from(seed);
  if (bytes.length !== 64) {
    log.debug('Leaving mlkemFromSeed(). Wrong seed size.');
    throw new Error('an ML-KEM private key is the 64-octet seed d || z ' +
                    '(FIPS 203 KeyGen_internal); this one is ' +
                    bytes.length + ' octets');
  }
  const pair = spec.impl.keygen(new Uint8Array(bytes));
  log.debug('Leaving mlkemFromSeed().');
  return { ek: Buffer.from(pair.publicKey), dk: pair.secretKey };
}

// `randomness`, when given, is FIPS 203's 32-octet m (Encaps_internal) —
// the deterministic form the published vectors are made with. A caller
// outside a test never passes it.
function mlkemEncaps(set, ek, randomness) {
  log.debug('Entering mlkemEncaps(). ' + set);
  mlkemCheckEncapsulationKey(set, ek);
  const spec = MLKEM_SETS[set];
  const out = randomness
    ? spec.impl.encapsulate(new Uint8Array(ek), new Uint8Array(randomness))
    : spec.impl.encapsulate(new Uint8Array(ek));
  log.debug('Leaving mlkemEncaps().');
  return { ss: Buffer.from(out.sharedSecret), ct: Buffer.from(out.cipherText) };
}

function mlkemDecaps(set, seed, ct) {
  log.debug('Entering mlkemDecaps(). ' + set);
  const spec = MLKEM_SETS[set];
  const bytes = Buffer.from(ct);
  if (bytes.length !== spec.Nct) {
    log.debug('Leaving mlkemDecaps(). Wrong ciphertext size.');
    throw new Error('an ' + set + ' ciphertext is ' + spec.Nct +
                    ' octets; this one is ' + bytes.length);
  }
  const keys = mlkemFromSeed(set, seed);
  const ss = Buffer.from(spec.impl.decapsulate(new Uint8Array(bytes),
                                               keys.dk));
  log.debug('Leaving mlkemDecaps().');
  return ss;
}

// ---------------------------------------------------------------------------
// THE ELLIPTIC-CURVE GROUPS, ON NODE'S OPENSSL. The NIST curves as raw
// big-endian scalars and UNCOMPRESSED points (SEC1), which is how both HPKE
// and the hybrid KEMs serialise them; X25519 and X448 as RFC 7748's raw
// octet strings, carried into node as PKCS#8 / SPKI around the raw bytes.
// ---------------------------------------------------------------------------
const EC_GROUPS = {
  'P-256': { node: 'prime256v1', Nsk: 32, Npk: 65, Ndh: 32,
             order: BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e' +
                           '84f3b9cac2fc632551') },
  'P-384': { node: 'secp384r1', Nsk: 48, Npk: 97, Ndh: 48,
             order: BigInt('0xffffffffffffffffffffffffffffffffffffffffffffff' +
                           'ffc7634d81f4372ddf581a0db248b0a77aecec196accc529' +
                           '73') },
  'P-521': { node: 'secp521r1', Nsk: 66, Npk: 133, Ndh: 66,
             order: BigInt('0x01ffffffffffffffffffffffffffffffffffffffffffff' +
                           'fffffffffffffffffffffa51868783bf2f966b7fcc0148f7' +
                           '09a5d03bb5c9b8899c47aebb6fb71e91386409') }
};
const MONTGOMERY = {
  X25519: { Nsk: 32, Npk: 32,
            pkcs8: Buffer.from('302e020100300506032b656e04220420', 'hex'),
            spki: Buffer.from('302a300506032b656e032100', 'hex') },
  X448: { Nsk: 56, Npk: 56,
          pkcs8: Buffer.from('3046020100300506032b656f043a0438', 'hex'),
          spki: Buffer.from('3042300506032b656f033900', 'hex') }
};

function os2ip(bytes) {
  log.debug('Entering os2ip().');
  const hex = Buffer.from(bytes).toString('hex');
  log.debug('Leaving os2ip().');
  return hex ? BigInt('0x' + hex) : 0n;
}

// The public point of a scalar, uncompressed. createECDH is used rather than
// a KeyObject because it takes a bare scalar, which is the only form HPKE's
// DeriveKeyPair and the hybrid KEMs' RandomScalar produce.
function nistPublic(curve, scalar) {
  log.debug('Entering nistPublic(). ' + curve);
  const ecdh = nodeCrypto.createECDH(EC_GROUPS[curve].node);
  ecdh.setPrivateKey(Buffer.from(scalar));
  log.debug('Leaving nistPublic().');
  return ecdh.getPublicKey(null, 'uncompressed');
}

// The x-coordinate of scalar * point. `computeSecret()` refuses a point that
// is not on the curve (draft-ietf-hpke-hpke section 7.1.4's partial public
// key validation) by throwing, and the caller's message says which input.
function nistDh(curve, scalar, point) {
  log.debug('Entering nistDh(). ' + curve);
  const ecdh = nodeCrypto.createECDH(EC_GROUPS[curve].node);
  ecdh.setPrivateKey(Buffer.from(scalar));
  const bytes = Buffer.from(point);
  if (bytes.length !== EC_GROUPS[curve].Npk || bytes[0] !== 0x04) {
    log.debug('Leaving nistDh(). Not an uncompressed point.');
    throw new Error('a ' + curve + ' public key here is an uncompressed ' +
                    'point of ' + EC_GROUPS[curve].Npk + ' octets');
  }
  const out = ecdh.computeSecret(bytes);
  log.debug('Leaving nistDh().');
  return out;
}

function montgomeryPrivate(group, sk) {
  log.debug('Entering montgomeryPrivate(). ' + group);
  const spec = MONTGOMERY[group];
  const out = nodeCrypto.createPrivateKey({
    key: Buffer.concat([spec.pkcs8, Buffer.from(sk)]),
    format: 'der', type: 'pkcs8' });
  log.debug('Leaving montgomeryPrivate().');
  return out;
}

function montgomeryPublic(group, sk) {
  log.debug('Entering montgomeryPublic(). ' + group);
  const der = nodeCrypto.createPublicKey(montgomeryPrivate(group, sk))
    .export({ type: 'spki', format: 'der' });
  log.debug('Leaving montgomeryPublic().');
  return Buffer.from(der).subarray(der.length - MONTGOMERY[group].Npk);
}

// RFC 7748 section 6: a recipient MUST refuse the all-zero output, which is
// what a small-order public key produces.
/**
 * X25519 or X448, refusing the all-zero output (RFC 7748 section 6).
 *
 * @param group - X25519 or X448
 * @param sk - the raw private key
 * @param pk - the raw public key
 * @returns the shared secret
 * @throws Error for a wrong size or an all-zero output
 */
function montgomeryDh(group, sk, pk) {
  log.debug('Entering montgomeryDh(). ' + group);
  const spec = MONTGOMERY[group];
  const bytes = Buffer.from(pk);
  if (bytes.length !== spec.Npk) {
    log.debug('Leaving montgomeryDh(). Wrong size.');
    throw new Error('an ' + group + ' public key is ' + spec.Npk +
                    ' octets; this one is ' + bytes.length);
  }
  const publicKey = nodeCrypto.createPublicKey({
    key: Buffer.concat([spec.spki, bytes]), format: 'der', type: 'spki' });
  const out = nodeCrypto.diffieHellman({
    privateKey: montgomeryPrivate(group, sk), publicKey: publicKey });
  if (out.every(function (b) {
    return b === 0;
  })) {
    log.debug('Leaving montgomeryDh(). All-zero output.');
    throw new Error('the ' + group + ' exchange produced the all-zero ' +
                    'value, which RFC 7748 section 6 requires refusing ' +
                    '(a small-order public key)');
  }
  log.debug('Leaving montgomeryDh().');
  return out;
}

// ---------------------------------------------------------------------------
// HPKE'S KDFs (draft-ietf-hpke-hpke section 7.2, draft-ietf-hpke-pq section
// 5). The HKDFs are TWO-STAGE (Extract, Expand); the SHAKE and TurboSHAKE
// XOFs are ONE-STAGE (Derive). Every labelled function below takes the
// suite_id explicitly — inside a KEM it names the KEM, in the key schedule
// the whole suite, and a function that picked it up from ambient state would
// be the place the two got mixed.
// ---------------------------------------------------------------------------
const HPKE_KDFS = {
  0x0001: { name: 'HKDF-SHA256', twoStage: true, hash: 'sha256', Nh: 32 },
  0x0002: { name: 'HKDF-SHA384', twoStage: true, hash: 'sha384', Nh: 48 },
  0x0003: { name: 'HKDF-SHA512', twoStage: true, hash: 'sha512', Nh: 64 },
  0x0010: { name: 'SHAKE128', twoStage: false, xof: 'shake128', Nh: 32 },
  0x0011: { name: 'SHAKE256', twoStage: false, xof: 'shake256', Nh: 64 },
  0x0012: { name: 'TurboSHAKE128', twoStage: false, xof: 'turboshake128',
            Nh: 32 },
  0x0013: { name: 'TurboSHAKE256', twoStage: false, xof: 'turboshake256',
            Nh: 64 }
};

const HPKE_V1 = Buffer.from('HPKE-v1', 'ascii');

function hkdfExtract(kdf, salt, ikm) {
  log.debug('Entering hkdfExtract(). ' + kdf.name);
  // RFC 5869: an absent salt is Nh zero octets.
  const key = salt && salt.length ? Buffer.from(salt) : Buffer.alloc(kdf.Nh);
  const out = nodeCrypto.createHmac(kdf.hash, key).update(Buffer.from(ikm))
    .digest();
  log.debug('Leaving hkdfExtract().');
  return out;
}

function hkdfExpand(kdf, prk, info, length) {
  log.debug('Entering hkdfExpand(). ' + kdf.name + ', ' + length);
  if (length > 255 * kdf.Nh) {
    log.debug('Leaving hkdfExpand(). Too long.');
    throw new Error('HKDF-Expand cannot produce ' + length + ' octets');
  }
  const blocks = [];
  let previous = Buffer.alloc(0);
  for (let i = 1; Buffer.concat(blocks).length < length; i++) {
    previous = nodeCrypto.createHmac(kdf.hash, Buffer.from(prk))
      .update(Buffer.concat([previous, Buffer.from(info), Buffer.from([i])]))
      .digest();
    blocks.push(previous);
  }
  log.debug('Leaving hkdfExpand().');
  return Buffer.concat(blocks).subarray(0, length);
}

function xofDerive(kdf, ikm, length) {
  log.debug('Entering xofDerive(). ' + kdf.name + ', ' + length);
  let out;
  if (kdf.xof === 'shake128' || kdf.xof === 'shake256') {
    out = shake(kdf.xof === 'shake128' ? 128 : 256, ikm, length);
  } else {
    // RFC 9861 TurboSHAKE with the domain separation byte HPKE-PQ section 5
    // fixes (D = 0x1f).
    out = Buffer.from(nobleSha3Addons[kdf.xof](new Uint8Array(ikm),
                                               { D: 0x1f, dkLen: length }));
  }
  log.debug('Leaving xofDerive().');
  return out;
}

function labeledExtract(kdf, suiteId, salt, label, ikm) {
  log.debug('Entering labeledExtract(). ' + label);
  const out = hkdfExtract(kdf, salt, Buffer.concat([
    HPKE_V1, suiteId, Buffer.from(label, 'ascii'), Buffer.from(ikm)]));
  log.debug('Leaving labeledExtract().');
  return out;
}

function labeledExpand(kdf, suiteId, prk, label, info, length) {
  log.debug('Entering labeledExpand(). ' + label);
  const out = hkdfExpand(kdf, prk, Buffer.concat([
    i2osp(length, 2), HPKE_V1, suiteId, Buffer.from(label, 'ascii'),
    Buffer.from(info)]), length);
  log.debug('Leaving labeledExpand().');
  return out;
}

function labeledDerive(kdf, suiteId, ikm, label, context, length) {
  log.debug('Entering labeledDerive(). ' + label);
  const out = xofDerive(kdf, Buffer.concat([
    Buffer.from(ikm), HPKE_V1, suiteId,
    lengthPrefixed(Buffer.from(label, 'ascii')), i2osp(length, 2),
    Buffer.from(context)]), length);
  log.debug('Leaving labeledDerive().');
  return out;
}

// ---------------------------------------------------------------------------
// THE HYBRID KEMs (draft-irtf-cfrg-hybrid-kems-12's CG framework, as the
// concrete draft instantiates it): ML-KEM plus a nominal group, SHAKE256 as
// the PRG that splits one 32-octet seed into both components' seeds, and
// SHA3-256 over ss_PQ || ss_T || ct_T || ek_T || Label as the C2PRI
// combiner. MLKEM768-X25519 is X-Wing.
// ---------------------------------------------------------------------------
const HYBRID_KEMS = {
  'MLKEM768-P256': { pq: 'ML-KEM-768', group: 'P-256', Nseed: 128,
                     Nscalar: 32, Nelem: 65,
                     label: Buffer.from('MLKEM768-P256', 'ascii') },
  'MLKEM768-X25519': { pq: 'ML-KEM-768', group: 'X25519', Nseed: 32,
                       Nscalar: 32, Nelem: 32,
                       label: Buffer.from('5c2e2f2f5e5c', 'hex') },
  'MLKEM1024-P384': { pq: 'ML-KEM-1024', group: 'P-384', Nseed: 48,
                      Nscalar: 48, Nelem: 97,
                      label: Buffer.from('MLKEM1024-P384', 'ascii') }
};

// RandomScalar: rejection sampling over Nscalar-octet windows for the NIST
// curves (concrete-hybrid-kems section 3.1.1), the identity for Curve25519.
function hybridRandomScalar(h, seed) {
  log.debug('Entering hybridRandomScalar(). ' + h.group);
  const bytes = Buffer.from(seed);
  if (h.group === 'X25519') {
    log.debug('Leaving hybridRandomScalar(). Identity.');
    return bytes;
  }
  const order = EC_GROUPS[h.group].order;
  for (let start = 0; start + h.Nscalar <= bytes.length;
       start += h.Nscalar) {
    const window = bytes.subarray(start, start + h.Nscalar);
    const sk = os2ip(window);
    if (sk !== 0n && sk < order) {
      log.debug('Leaving hybridRandomScalar().');
      return Buffer.from(window);
    }
  }
  log.debug('Leaving hybridRandomScalar(). Rejection sampling failed.');
  throw new Error('RandomScalar: rejection sampling failed for ' + h.group);
}

function hybridGroupPublic(h, scalar) {
  log.debug('Entering hybridGroupPublic().');
  const out = h.group === 'X25519' ? montgomeryPublic('X25519', scalar)
    : nistPublic(h.group, scalar);
  log.debug('Leaving hybridGroupPublic().');
  return out;
}

function hybridGroupDh(h, scalar, element) {
  log.debug('Entering hybridGroupDh().');
  const out = h.group === 'X25519' ? montgomeryDh('X25519', scalar, element)
    : nistDh(h.group, scalar, element);
  log.debug('Leaving hybridGroupDh().');
  return out;
}

/**
 * Expands a hybrid KEM's 32-octet seed into both components' keys.
 *
 * @param name - MLKEM768-P256, MLKEM768-X25519 or MLKEM1024-P384
 * @param seed - the 32-octet private key
 * @returns the component keys and the encapsulation key `ek`
 */
function hybridExpand(name, seed) {
  log.debug('Entering hybridExpand(). ' + name);
  const h = HYBRID_KEMS[name];
  const bytes = Buffer.from(seed);
  if (bytes.length !== 32) {
    log.debug('Leaving hybridExpand(). Wrong seed size.');
    throw new Error('a ' + name + ' private key is a 32-octet seed; this ' +
                    'one is ' + bytes.length + ' octets');
  }
  const full = shake(256, bytes, 64 + h.Nseed);
  const pq = mlkemFromSeed(h.pq, full.subarray(0, 64));
  const dkT = hybridRandomScalar(h, full.subarray(64));
  const ekT = hybridGroupPublic(h, dkT);
  log.debug('Leaving hybridExpand().');
  return { h: h, seedPq: full.subarray(0, 64), ekPq: pq.ek, dkT: dkT,
           ekT: ekT, ek: Buffer.concat([pq.ek, ekT]) };
}

function hybridCombine(h, ssPq, ssT, ctT, ekT) {
  log.debug('Entering hybridCombine().');
  const out = sha3_256(Buffer.concat([ssPq, ssT, ctT, ekT, h.label]));
  log.debug('Leaving hybridCombine().');
  return out;
}

// `randomness`, for the vectors only: the PQ constituent's 32 octets first,
// then the group's Nseed (hybrid-kems-12 appendix A).
/**
 * A hybrid KEM's Encaps, deterministic where `randomness` is given.
 *
 * @param name - the hybrid KEM
 * @param ek - the encapsulation key
 * @param randomness - the vector's randomness
 * @returns `{ ss, ct }`
 */
function hybridEncaps(name, ek, randomness) {
  log.debug('Entering hybridEncaps(). ' + name);
  const h = HYBRID_KEMS[name];
  const pqSpec = MLKEM_SETS[h.pq];
  const bytes = Buffer.from(ek);
  if (bytes.length !== pqSpec.Npk + h.Nelem) {
    log.debug('Leaving hybridEncaps(). Wrong size.');
    throw new Error('a ' + name + ' encapsulation key is ' +
                    (pqSpec.Npk + h.Nelem) + ' octets; this one is ' +
                    bytes.length);
  }
  const ekPq = bytes.subarray(0, pqSpec.Npk);
  const ekT = bytes.subarray(pqSpec.Npk);
  const rand = randomness ? Buffer.from(randomness) : null;
  const pq = mlkemEncaps(h.pq, ekPq, rand ? rand.subarray(0, 32) : null);
  const skE = hybridRandomScalar(h, rand ? rand.subarray(32)
    : nodeCrypto.randomBytes(h.Nseed));
  const ctT = hybridGroupPublic(h, skE);
  const ssT = hybridGroupDh(h, skE, ekT);
  log.debug('Leaving hybridEncaps().');
  return { ss: hybridCombine(h, pq.ss, ssT, ctT, ekT),
           ct: Buffer.concat([pq.ct, ctT]) };
}

/**
 * A hybrid KEM's Decaps.
 *
 * @param name - the hybrid KEM
 * @param seed - the 32-octet private key
 * @param ct - the ciphertext
 * @returns the shared secret
 */
function hybridDecaps(name, seed, ct) {
  log.debug('Entering hybridDecaps(). ' + name);
  const keys = hybridExpand(name, seed);
  const h = keys.h;
  const pqSpec = MLKEM_SETS[h.pq];
  const bytes = Buffer.from(ct);
  if (bytes.length !== pqSpec.Nct + h.Nelem) {
    log.debug('Leaving hybridDecaps(). Wrong size.');
    throw new Error('a ' + name + ' ciphertext is ' +
                    (pqSpec.Nct + h.Nelem) + ' octets; this one is ' +
                    bytes.length);
  }
  const ctT = bytes.subarray(pqSpec.Nct);
  const ssPq = mlkemDecaps(h.pq, keys.seedPq, bytes.subarray(0, pqSpec.Nct));
  const ssT = hybridGroupDh(h, keys.dkT, ctT);
  log.debug('Leaving hybridDecaps().');
  return hybridCombine(h, ssPq, ssT, ctT, keys.ekT);
}

// ---------------------------------------------------------------------------
// HPKE's KEMs (draft-ietf-hpke-hpke section 7.1, draft-ietf-hpke-pq section
// 8). Each has DeriveKeyPair(ikm) -> { sk, pk } in its SERIALISED forms,
// Encap(pk, ikmE?) -> { ss, enc } and Decap(enc, sk) -> ss. `ikmE` is the
// deterministic encapsulation input the vectors carry.
// ---------------------------------------------------------------------------
const HPKE_KEMS = {
  0x0010: { name: 'DHKEM(P-256, HKDF-SHA256)', kind: 'nist', group: 'P-256',
            kdf: 0x0001, Nsecret: 32, Nenc: 65, Npk: 65, Nsk: 32 },
  0x0011: { name: 'DHKEM(P-384, HKDF-SHA384)', kind: 'nist', group: 'P-384',
            kdf: 0x0002, Nsecret: 48, Nenc: 97, Npk: 97, Nsk: 48 },
  0x0012: { name: 'DHKEM(P-521, HKDF-SHA512)', kind: 'nist', group: 'P-521',
            kdf: 0x0003, Nsecret: 64, Nenc: 133, Npk: 133, Nsk: 66 },
  0x0020: { name: 'DHKEM(X25519, HKDF-SHA256)', kind: 'montgomery',
            group: 'X25519', kdf: 0x0001, Nsecret: 32, Nenc: 32, Npk: 32,
            Nsk: 32 },
  0x0021: { name: 'DHKEM(X448, HKDF-SHA512)', kind: 'montgomery',
            group: 'X448', kdf: 0x0003, Nsecret: 64, Nenc: 56, Npk: 56,
            Nsk: 56 },
  0x0040: { name: 'ML-KEM-512', kind: 'mlkem', set: 'ML-KEM-512',
            Nsecret: 32, Nenc: 768, Npk: 800, Nsk: 64 },
  0x0041: { name: 'ML-KEM-768', kind: 'mlkem', set: 'ML-KEM-768',
            Nsecret: 32, Nenc: 1088, Npk: 1184, Nsk: 64 },
  0x0042: { name: 'ML-KEM-1024', kind: 'mlkem', set: 'ML-KEM-1024',
            Nsecret: 32, Nenc: 1568, Npk: 1568, Nsk: 64 },
  0x0050: { name: 'MLKEM768-P256', kind: 'hybrid', hybrid: 'MLKEM768-P256',
            Nsecret: 32, Nenc: 1153, Npk: 1249, Nsk: 32 },
  0x0051: { name: 'MLKEM1024-P384', kind: 'hybrid',
            hybrid: 'MLKEM1024-P384', Nsecret: 32, Nenc: 1665, Npk: 1665,
            Nsk: 32 },
  0x647a: { name: 'MLKEM768-X25519', kind: 'hybrid',
            hybrid: 'MLKEM768-X25519', Nsecret: 32, Nenc: 1120, Npk: 1216,
            Nsk: 32 }
};

function kemSuiteId(kemId) {
  log.debug('Entering kemSuiteId().');
  log.debug('Leaving kemSuiteId().');
  return Buffer.concat([Buffer.from('KEM', 'ascii'), i2osp(kemId, 2)]);
}

function hpkeKem(kemId) {
  log.debug('Entering hpkeKem(). ' + kemId);
  const kem = HPKE_KEMS[kemId];
  if (!kem) {
    log.debug('Leaving hpkeKem(). Unknown.');
    throw new Error('no HPKE KEM 0x' + Number(kemId).toString(16));
  }
  log.debug('Leaving hpkeKem().');
  return kem;
}

// DeriveKeyPair (hpke-hpke section 7.1.3; hpke-pq sections 3 and 4). The
// ML-KEM and hybrid KEMs derive through SHAKE256 whatever the suite's KDF;
// a DHKEM through its own HKDF.
/**
 * HPKE DeriveKeyPair for a KEM.
 *
 * @param kemId - an HPKE KEM id
 * @param ikm - the input keying material
 * @returns `{ sk, pk }`, serialised
 */
function hpkeDeriveKeyPair(kemId, ikm) {
  log.debug('Entering hpkeDeriveKeyPair(). ' + kemId);
  const kem = hpkeKem(kemId);
  const suiteId = kemSuiteId(kemId);
  if (kem.kind === 'mlkem' || kem.kind === 'hybrid') {
    const shake256 = HPKE_KDFS[0x0011];
    const sk = labeledDerive(shake256, suiteId, ikm, 'DeriveKeyPair', '',
                             kem.Nsk);
    const pk = kem.kind === 'mlkem' ? mlkemFromSeed(kem.set, sk).ek
      : hybridExpand(kem.hybrid, sk).ek;
    log.debug('Leaving hpkeDeriveKeyPair(). ' + kem.kind);
    return { sk: sk, pk: pk };
  }
  const kdf = HPKE_KDFS[kem.kdf];
  const prk = labeledExtract(kdf, suiteId, '', 'dkp_prk', ikm);
  if (kem.kind === 'montgomery') {
    const sk = labeledExpand(kdf, suiteId, prk, 'sk', '', kem.Nsk);
    log.debug('Leaving hpkeDeriveKeyPair(). Montgomery.');
    return { sk: sk, pk: montgomeryPublic(kem.group, sk) };
  }
  const group = EC_GROUPS[kem.group];
  for (let counter = 0; counter < 256; counter++) {
    const bytes = labeledExpand(kdf, suiteId, prk, 'candidate',
                                i2osp(counter, 1), kem.Nsk);
    // The bitmask of section 7.1.3: 0xff for P-256 and P-384, 0x01 for
    // P-521, whose order is a 521-bit number in 66 octets.
    bytes[0] = bytes[0] & (kem.group === 'P-521' ? 0x01 : 0xff);
    const sk = os2ip(bytes);
    if (sk !== 0n && sk < group.order) {
      log.debug('Leaving hpkeDeriveKeyPair(). NIST curve.');
      return { sk: bytes, pk: nistPublic(kem.group, bytes) };
    }
  }
  log.debug('Leaving hpkeDeriveKeyPair(). DeriveKeyPairError.');
  throw new Error('DeriveKeyPairError: no scalar in 256 candidates');
}

/**
 * HPKE GenerateKeyPair for a KEM.
 *
 * @param kemId - an HPKE KEM id
 * @returns `{ sk, pk }`, serialised
 */
function hpkeGenerateKeyPair(kemId) {
  log.debug('Entering hpkeGenerateKeyPair(). ' + kemId);
  const kem = hpkeKem(kemId);
  let out;
  if (kem.kind === 'mlkem' || kem.kind === 'hybrid') {
    // GenerateKeyPair is KeyGen on a random seed (hpke-pq sections 3, 4;
    // hybrid-kems-12 section 5.2): the seed IS the private key.
    const sk = nodeCrypto.randomBytes(kem.Nsk);
    out = { sk: sk, pk: kem.kind === 'mlkem' ? mlkemFromSeed(kem.set, sk).ek
      : hybridExpand(kem.hybrid, sk).ek };
  } else {
    out = hpkeDeriveKeyPair(kemId, nodeCrypto.randomBytes(kem.Nsk));
  }
  log.debug('Leaving hpkeGenerateKeyPair().');
  return out;
}

function dhkemExtractAndExpand(kem, suiteId, dh, kemContext) {
  log.debug('Entering dhkemExtractAndExpand().');
  const kdf = HPKE_KDFS[kem.kdf];
  const prk = labeledExtract(kdf, suiteId, '', 'eae_prk', dh);
  const out = labeledExpand(kdf, suiteId, prk, 'shared_secret', kemContext,
                            kem.Nsecret);
  log.debug('Leaving dhkemExtractAndExpand().');
  return out;
}

/**
 * HPKE Encap, deterministic where `ikmE` is given (the vectors).
 *
 * @param kemId - an HPKE KEM id
 * @param pkR - the recipient's serialised public key
 * @param ikmE - the encapsulation randomness, for a vector
 * @returns `{ ss, enc }`
 */
function hpkeEncap(kemId, pkR, ikmE) {
  log.debug('Entering hpkeEncap(). ' + kemId);
  const kem = hpkeKem(kemId);
  const pk = Buffer.from(pkR);
  if (pk.length !== kem.Npk) {
    log.debug('Leaving hpkeEncap(). Wrong key size.');
    throw new Error('a ' + kem.name + ' public key is ' + kem.Npk +
                    ' octets; this one is ' + pk.length);
  }
  if (kem.kind === 'mlkem') {
    const out = mlkemEncaps(kem.set, pk, ikmE || null);
    log.debug('Leaving hpkeEncap(). ML-KEM.');
    return { ss: out.ss, enc: out.ct };
  }
  if (kem.kind === 'hybrid') {
    const out = hybridEncaps(kem.hybrid, pk, ikmE || null);
    log.debug('Leaving hpkeEncap(). Hybrid.');
    return { ss: out.ss, enc: out.ct };
  }
  const ephemeral = ikmE ? hpkeDeriveKeyPair(kemId, ikmE)
    : hpkeGenerateKeyPair(kemId);
  const dh = kem.kind === 'montgomery'
    ? montgomeryDh(kem.group, ephemeral.sk, pk)
    : nistDh(kem.group, ephemeral.sk, pk);
  const enc = ephemeral.pk;
  const ss = dhkemExtractAndExpand(kem, kemSuiteId(kemId), dh,
                                   Buffer.concat([enc, pk]));
  log.debug('Leaving hpkeEncap(). DHKEM.');
  return { ss: ss, enc: enc };
}

/**
 * HPKE Decap.
 *
 * @param kemId - an HPKE KEM id
 * @param enc - the encapsulated secret
 * @param skR - the recipient's serialised private key
 * @returns the shared secret
 */
function hpkeDecap(kemId, enc, skR) {
  log.debug('Entering hpkeDecap(). ' + kemId);
  const kem = hpkeKem(kemId);
  const e = Buffer.from(enc);
  if (e.length !== kem.Nenc) {
    log.debug('Leaving hpkeDecap(). Wrong enc size.');
    throw new Error('a ' + kem.name + ' encapsulated secret is ' + kem.Nenc +
                    ' octets; this one is ' + e.length);
  }
  if (kem.kind === 'mlkem') {
    const out = mlkemDecaps(kem.set, skR, e);
    log.debug('Leaving hpkeDecap(). ML-KEM.');
    return out;
  }
  if (kem.kind === 'hybrid') {
    const out = hybridDecaps(kem.hybrid, skR, e);
    log.debug('Leaving hpkeDecap(). Hybrid.');
    return out;
  }
  const sk = Buffer.from(skR);
  const dh = kem.kind === 'montgomery' ? montgomeryDh(kem.group, sk, e)
    : nistDh(kem.group, sk, e);
  const pkRm = kem.kind === 'montgomery' ? montgomeryPublic(kem.group, sk)
    : nistPublic(kem.group, sk);
  const out = dhkemExtractAndExpand(kem, kemSuiteId(kemId), dh,
                                    Buffer.concat([e, pkRm]));
  log.debug('Leaving hpkeDecap(). DHKEM.');
  return out;
}

// ---------------------------------------------------------------------------
// HPKE'S AEADs (section 7.3). `ct` is the ciphertext with the 16-octet tag
// appended, which is HPKE's shape and not JWE's.
// ---------------------------------------------------------------------------
const HPKE_AEADS = {
  0x0001: { name: 'AES-128-GCM', cipher: 'aes-128-gcm', Nk: 16, Nn: 12,
            Nt: 16 },
  0x0002: { name: 'AES-256-GCM', cipher: 'aes-256-gcm', Nk: 32, Nn: 12,
            Nt: 16 },
  0x0003: { name: 'ChaCha20Poly1305', cipher: 'chacha20-poly1305', Nk: 32,
            Nn: 12, Nt: 16 },
  0xffff: { name: 'Export-only', cipher: '', Nk: 0, Nn: 0, Nt: 0 }
};

// The key and nonce sizes are the suite's (Nk, Nn — 96 bits for all three),
// checked here rather than left to OpenSSL, whose GCM takes any nonce size.
function hpkeAeadSizes(aead, key, nonce) {
  log.debug('Entering hpkeAeadSizes(). ' + aead.name);
  if (Buffer.from(key).length !== aead.Nk ||
      Buffer.from(nonce).length !== aead.Nn) {
    log.debug('Leaving hpkeAeadSizes(). Wrong size.');
    throw new Error(aead.name + ' takes a ' + (aead.Nk * 8) + '-bit key ' +
                    'and a ' + (aead.Nn * 8) + '-bit nonce in HPKE');
  }
  log.debug('Leaving hpkeAeadSizes().');
}

function hpkeAeadSeal(aead, key, nonce, aad, pt) {
  log.debug('Entering hpkeAeadSeal(). ' + aead.name);
  hpkeAeadSizes(aead, key, nonce);
  const cipher = /** @type {import('crypto').CipherGCM} */ (
    nodeCrypto.createCipheriv(aead.cipher, key, nonce,
                              /** @type {any} */ ({ authTagLength: 16 })));
  cipher.setAAD(Buffer.from(aad), /** @type {any} */ (
    { plaintextLength: Buffer.from(pt).length }));
  const ct = Buffer.concat([cipher.update(Buffer.from(pt)), cipher.final(),
                            cipher.getAuthTag()]);
  log.debug('Leaving hpkeAeadSeal().');
  return ct;
}

function hpkeAeadOpen(aead, key, nonce, aad, ct) {
  log.debug('Entering hpkeAeadOpen(). ' + aead.name);
  hpkeAeadSizes(aead, key, nonce);
  const bytes = Buffer.from(ct);
  if (bytes.length < aead.Nt) {
    log.debug('Leaving hpkeAeadOpen(). Shorter than a tag.');
    throw new Error('an HPKE ciphertext carries a ' + (aead.Nt * 8) +
                    '-bit tag and this one is ' + bytes.length + ' octets');
  }
  const decipher = /** @type {import('crypto').DecipherGCM} */ (
    nodeCrypto.createDecipheriv(aead.cipher, key, nonce,
                                /** @type {any} */ ({ authTagLength: 16 })));
  const body = bytes.subarray(0, bytes.length - aead.Nt);
  decipher.setAAD(Buffer.from(aad), /** @type {any} */ (
    { plaintextLength: body.length }));
  decipher.setAuthTag(bytes.subarray(bytes.length - aead.Nt));
  const out = Buffer.concat([decipher.update(body), decipher.final()]);
  log.debug('Leaving hpkeAeadOpen().');
  return out;
}

// ---------------------------------------------------------------------------
// THE KEY SCHEDULE AND THE CONTEXT (hpke-hpke sections 5.1 and 5.2), for
// mode_base and mode_psk — the two modes the successor to RFC 9180 keeps,
// and the two jose-hpke-encrypt-22 section 4 allows (psk_id present means
// mode_psk). The context is a small object whose sequence number moves on
// each seal or open; a JWE uses it once.
// ---------------------------------------------------------------------------
const HPKE_MODE_BASE = 0x00;
const HPKE_MODE_PSK = 0x01;

function hpkeSuiteId(kemId, kdfId, aeadId) {
  log.debug('Entering hpkeSuiteId().');
  log.debug('Leaving hpkeSuiteId().');
  return Buffer.concat([Buffer.from('HPKE', 'ascii'), i2osp(kemId, 2),
                        i2osp(kdfId, 2), i2osp(aeadId, 2)]);
}

function hpkeKeySchedule(suite, mode, sharedSecret, info, psk, pskId) {
  log.debug('Entering hpkeKeySchedule(). mode=' + mode);
  const kdf = HPKE_KDFS[suite.kdf];
  const aead = HPKE_AEADS[suite.aead];
  if (!kdf || !aead) {
    log.debug('Leaving hpkeKeySchedule(). Unknown suite.');
    throw new Error('no HPKE KDF 0x' + Number(suite.kdf).toString(16) +
                    ' or AEAD 0x' + Number(suite.aead).toString(16));
  }
  const suiteId = hpkeSuiteId(suite.kem, suite.kdf, suite.aead);
  const pskBytes = Buffer.from(psk || '');
  const pskIdBytes = Buffer.from(pskId || '');
  // VerifyPSKInputs.
  if ((pskBytes.length > 0) !== (pskIdBytes.length > 0)) {
    log.debug('Leaving hpkeKeySchedule(). Inconsistent PSK inputs.');
    throw new Error('HPKE: a PSK and its psk_id go together or not at all');
  }
  if (pskBytes.length > 0 && mode === HPKE_MODE_BASE) {
    throw new Error('HPKE: a PSK was given for mode_base');
  }
  if (pskBytes.length === 0 && mode === HPKE_MODE_PSK) {
    throw new Error('HPKE: mode_psk needs a PSK and a psk_id');
  }
  if (mode === HPKE_MODE_PSK && pskBytes.length < 32) {
    // Section 5.1.2: "The PSK MUST have at least 32 bytes of entropy".
    throw new Error('HPKE: a PSK is at least 32 octets');
  }
  let key;
  let baseNonce;
  let exporterSecret;
  if (kdf.twoStage) {
    const pskIdHash = labeledExtract(kdf, suiteId, '', 'psk_id_hash',
                                     pskIdBytes);
    const infoHash = labeledExtract(kdf, suiteId, '', 'info_hash',
                                    Buffer.from(info || ''));
    const context = Buffer.concat([Buffer.from([mode]), pskIdHash,
                                   infoHash]);
    const secret = labeledExtract(kdf, suiteId, sharedSecret, 'secret',
                                  pskBytes);
    key = labeledExpand(kdf, suiteId, secret, 'key', context, aead.Nk);
    baseNonce = labeledExpand(kdf, suiteId, secret, 'base_nonce', context,
                              aead.Nn);
    exporterSecret = labeledExpand(kdf, suiteId, secret, 'exp', context,
                                   kdf.Nh);
  } else {
    const secrets = Buffer.concat([lengthPrefixed(pskBytes),
                                   lengthPrefixed(sharedSecret)]);
    const context = Buffer.concat([Buffer.from([mode]),
                                   lengthPrefixed(pskIdBytes),
                                   lengthPrefixed(Buffer.from(info || ''))]);
    const secret = labeledDerive(kdf, suiteId, secrets, 'secret', context,
                                 aead.Nk + aead.Nn + kdf.Nh);
    key = secret.subarray(0, aead.Nk);
    baseNonce = secret.subarray(aead.Nk, aead.Nk + aead.Nn);
    exporterSecret = secret.subarray(aead.Nk + aead.Nn);
  }
  const context = {
    key: key, baseNonce: baseNonce, exporterSecret: exporterSecret, seq: 0,
    nonce: function () {
      log.debug('Entering hpkeContext.nonce().');
      const seqBytes = i2osp(this.seq, aead.Nn);
      const out = Buffer.alloc(aead.Nn);
      for (let i = 0; i < aead.Nn; i++) {
        out[i] = baseNonce[i] ^ seqBytes[i];
      }
      log.debug('Leaving hpkeContext.nonce().');
      return out;
    },
    seal: function (aad, pt) {
      log.debug('Entering hpkeContext.seal().');
      if (aead.Nk === 0) {
        throw new Error('HPKE: an export-only suite cannot encrypt');
      }
      const ct = hpkeAeadSeal(aead, key, this.nonce(), aad, pt);
      this.seq += 1;
      log.debug('Leaving hpkeContext.seal().');
      return ct;
    },
    open: function (aad, ct) {
      log.debug('Entering hpkeContext.open().');
      if (aead.Nk === 0) {
        throw new Error('HPKE: an export-only suite cannot decrypt');
      }
      const pt = hpkeAeadOpen(aead, key, this.nonce(), aad, ct);
      this.seq += 1;
      log.debug('Leaving hpkeContext.open().');
      return pt;
    },
    exportSecret: function (exporterContext, length) {
      log.debug('Entering hpkeContext.exportSecret().');
      const out = kdf.twoStage
        ? labeledExpand(kdf, suiteId, exporterSecret, 'sec',
                        exporterContext, length)
        : labeledDerive(kdf, suiteId, exporterSecret, 'sec',
                        exporterContext, length);
      log.debug('Leaving hpkeContext.exportSecret().');
      return out;
    }
  };
  log.debug('Leaving hpkeKeySchedule().');
  return context;
}

// SetupS / SetupR for both modes. `opts`: `info`, `psk`, `pskId`, and — for
// the vectors only — `ikmE`.
/**
 * HPKE SetupBaseS / SetupPSKS.
 *
 * @param suite - `{ kem, kdf, aead }`
 * @param pkR - the recipient's serialised public key
 * @param opts - `info`, `psk`, `pskId`, and `ikmE` for a vector
 * @returns `{ enc, sharedSecret, context }`
 */
function hpkeSetupSender(suite, pkR, opts) {
  log.debug('Entering hpkeSetupSender().');
  const o = opts || {};
  const encap = hpkeEncap(suite.kem, pkR, o.ikmE || null);
  const mode = o.psk ? HPKE_MODE_PSK : HPKE_MODE_BASE;
  const context = hpkeKeySchedule(suite, mode, encap.ss, o.info, o.psk,
                                  o.pskId);
  log.debug('Leaving hpkeSetupSender().');
  return { enc: encap.enc, sharedSecret: encap.ss, context: context };
}

/**
 * HPKE SetupBaseR / SetupPSKR.
 *
 * @param suite - `{ kem, kdf, aead }`
 * @param enc - the encapsulated secret
 * @param skR - the recipient's serialised private key
 * @param opts - `info`, `psk`, `pskId`
 * @returns `{ sharedSecret, context }`
 */
function hpkeSetupReceiver(suite, enc, skR, opts) {
  log.debug('Entering hpkeSetupReceiver().');
  const o = opts || {};
  const ss = hpkeDecap(suite.kem, enc, skR);
  const mode = o.psk ? HPKE_MODE_PSK : HPKE_MODE_BASE;
  const context = hpkeKeySchedule(suite, mode, ss, o.info, o.psk, o.pskId);
  log.debug('Leaving hpkeSetupReceiver().');
  return { sharedSecret: ss, context: context };
}

// ---------------------------------------------------------------------------
// THE JWE ALGORITHMS. One table, each row saying what it is built from, so
// that the key checks, the wrap and the unwrap all read the same row.
//
//   family 'mlkem'  pqc-kem-05: `set`, and `kwBytes` for the +AxxxKW forms
//   family 'hpke'   `kem`, `kdf`, `aead`, and `integrated` (no CEK, no
//                   `enc`) or not (Key Encryption: the CEK is the HPKE
//                   plaintext)
//
// `keyType` is what a recipient's JWK must be: 'AKP' (with `alg` equal to the
// JWE alg — draft-ietf-cose-dilithium's rule that an AKP key names exactly
// one algorithm, which pqc-kem-05 section 10 and the hybrid draft section 6
// both apply to KEM keys), or EC / OKP with the curve jose-hpke-encrypt-22's
// Table 3 names.
// ---------------------------------------------------------------------------
const JWE_PQ_KEM_TABLE = {};
['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'].forEach(function (set) {
  JWE_PQ_KEM_TABLE[set] = { family: 'mlkem', set: set, kwBytes: 0,
                            keyType: 'AKP', postQuantum: true,
                            hybrid: false,
                            spec: 'draft-ietf-jose-pqc-kem-05' };
});
[['ML-KEM-512+A128KW', 'ML-KEM-512', 16],
 ['ML-KEM-768+A192KW', 'ML-KEM-768', 24],
 ['ML-KEM-1024+A256KW', 'ML-KEM-1024', 32]].forEach(function (row) {
  JWE_PQ_KEM_TABLE[row[0]] = { family: 'mlkem', set: row[1], kwBytes: row[2],
                               keyType: 'AKP', postQuantum: true,
                               hybrid: false,
                               spec: 'draft-ietf-jose-pqc-kem-05' };
});
// jose-hpke-encrypt-22 Tables 1 and 2 (the classical suites), and the hybrid
// draft's section 9.1 (8 to 16). `crv` is the JWK curve for the classical
// ones; the post-quantum ones are AKP.
[[0, 0x0010, 0x0001, 0x0001, 'EC', 'P-256', true],
 [1, 0x0011, 0x0002, 0x0002, 'EC', 'P-384', true],
 [2, 0x0012, 0x0003, 0x0002, 'EC', 'P-521', true],
 [3, 0x0020, 0x0001, 0x0001, 'OKP', 'X25519', true],
 [4, 0x0020, 0x0001, 0x0003, 'OKP', 'X25519', false],
 [5, 0x0021, 0x0003, 0x0002, 'OKP', 'X448', true],
 [6, 0x0021, 0x0003, 0x0003, 'OKP', 'X448', false],
 [7, 0x0010, 0x0001, 0x0002, 'EC', 'P-256', true],
 [8, 0x0050, 0x0011, 0x0002, 'AKP', '', true],
 [9, 0x0050, 0x0011, 0x0003, 'AKP', '', true],
 [10, 0x647a, 0x0011, 0x0002, 'AKP', '', true],
 [11, 0x647a, 0x0011, 0x0003, 'AKP', '', true],
 [12, 0x0051, 0x0011, 0x0002, 'AKP', '', true],
 [13, 0x0051, 0x0011, 0x0003, 'AKP', '', true],
 [14, 0x0040, 0x0011, 0x0001, 'AKP', '', true],
 [15, 0x0041, 0x0011, 0x0002, 'AKP', '', true],
 [16, 0x0042, 0x0011, 0x0002, 'AKP', '', true]].forEach(function (row) {
  const n = Number(row[0]);
  const kem = HPKE_KEMS[Number(row[1])];
  const pq = kem.kind === 'mlkem' || kem.kind === 'hybrid';
  const base = { family: 'hpke', kem: row[1], kdf: row[2], aead: row[3],
                 keyType: row[4], crv: row[5], postQuantum: pq,
                 hybrid: kem.kind === 'hybrid',
                 spec: n <= 7 ? 'draft-ietf-jose-hpke-encrypt-22'
                   : 'draft-reddy-cose-jose-pqc-hybrid-hpke-11' };
  JWE_PQ_KEM_TABLE['HPKE-' + n] = Object.assign({ integrated: true }, base);
  // HPKE-4-KE and HPKE-6-KE were removed by jose-hpke-encrypt-22 (its
  // change log: at the request of the responsible AD); column 7 says so.
  if (row[6]) {
    JWE_PQ_KEM_TABLE['HPKE-' + n + '-KE'] =
      Object.assign({ integrated: false }, base);
  }
});

/**
 * The ML-KEM JWE algorithms (draft-ietf-jose-pqc-kem-05), #82.
 */
const JWE_MLKEM_ALGS = Object.keys(JWE_PQ_KEM_TABLE).filter(function (a) {
  return JWE_PQ_KEM_TABLE[a].family === 'mlkem';
});
/**
 * The HPKE JWE algorithms, Integrated and Key Encryption, HPKE-0 to 16.
 */
const JWE_HPKE_ALGS = Object.keys(JWE_PQ_KEM_TABLE).filter(function (a) {
  return JWE_PQ_KEM_TABLE[a].family === 'hpke';
});
/**
 * The HPKE algorithms that use Integrated Encryption (no `enc`).
 */
const JWE_HPKE_INTEGRATED_ALGS = JWE_HPKE_ALGS.filter(function (a) {
  return JWE_PQ_KEM_TABLE[a].integrated;
});
// The post-quantum ones: every ML-KEM alg and HPKE-8 to HPKE-16. What the
// console counts as "post-quantum key establishment" and the PQC badge marks.
/**
 * The post-quantum JWE algorithms: every ML-KEM one and HPKE-8 to 16.
 */
const JWE_POST_QUANTUM_ALGS = Object.keys(JWE_PQ_KEM_TABLE).filter(
  function (a) {
    return JWE_PQ_KEM_TABLE[a].postQuantum;
  });
/**
 * The PQ/T hybrid JWE algorithms (HPKE-8 to 13; X-Wing is HPKE-10/11).
 */
const JWE_HYBRID_ALGS = Object.keys(JWE_PQ_KEM_TABLE).filter(function (a) {
  return JWE_PQ_KEM_TABLE[a].hybrid;
});

/**
 * Tells whether an alg is HPKE Integrated Encryption, which carries no
 * `enc`.
 *
 * @param alg - a JWE `alg`
 * @returns true for `HPKE-n` (not `-KE`)
 */
function isIntegratedJweAlg(alg) {
  log.debug('Entering isIntegratedJweAlg().');
  const row = JWE_PQ_KEM_TABLE[String(alg)];
  log.debug('Leaving isIntegratedJweAlg().');
  return !!(row && row.family === 'hpke' && row.integrated);
}

// ---------------------------------------------------------------------------
// A RECIPIENT'S KEY, CHECKED AGAINST THE ALG — the refusal #82's tests ask
// for ("a key that does not match the alg"). Returns the raw public key
// octets in the form the KEM takes. An EC or OKP key that carries an `alg`
// must name this one too (RFC 7517 section 4.4).
// ---------------------------------------------------------------------------
function kemPublicKeyFor(alg, jwk) {
  log.debug('Entering kemPublicKeyFor(). ' + alg);
  const row = JWE_PQ_KEM_TABLE[alg];
  const key = jwk && typeof jwk === 'object' ? jwk : {};
  if (key.kty !== row.keyType) {
    log.debug('Leaving kemPublicKeyFor(). Wrong kty.');
    throw new Error('alg "' + alg + '" encrypts to a key of type "' +
                    row.keyType + '"' + (row.crv ? ' (' + row.crv + ')' : '') +
                    ' and this key is "' + (key.kty || '(none)') + '"');
  }
  if (row.keyType === 'AKP') {
    if (key.alg !== alg) {
      log.debug('Leaving kemPublicKeyFor(). AKP names another alg.');
      throw new Error('an AKP key names exactly one algorithm, and this one ' +
                      'is for "' + (key.alg || '(none)') + '", not "' + alg +
                      '"');
    }
    const pub = Buffer.from(String(key.pub || ''), 'base64url');
    const want = row.family === 'mlkem' ? MLKEM_SETS[row.set].Npk
      : HPKE_KEMS[row.kem].Npk;
    if (pub.length !== want) {
      log.debug('Leaving kemPublicKeyFor(). Wrong size.');
      throw new Error('the AKP key\'s `pub` is ' + pub.length + ' octets ' +
                      'and "' + alg + '" takes ' + want);
    }
    log.debug('Leaving kemPublicKeyFor(). AKP.');
    return pub;
  }
  if (key.alg && key.alg !== alg) {
    log.debug('Leaving kemPublicKeyFor(). The JWK names another alg.');
    throw new Error('this key names alg "' + key.alg + '", not "' + alg +
                    '"');
  }
  if (key.crv !== row.crv) {
    log.debug('Leaving kemPublicKeyFor(). Wrong curve.');
    throw new Error('alg "' + alg + '" encrypts to a ' + row.crv + ' key ' +
                    'and this one is "' + (key.crv || '(none)') + '"');
  }
  if (row.keyType === 'OKP') {
    log.debug('Leaving kemPublicKeyFor(). OKP.');
    return Buffer.from(String(key.x || ''), 'base64url');
  }
  const size = EC_GROUPS[row.crv].Nsk;
  const x = Buffer.from(String(key.x || ''), 'base64url');
  const y = Buffer.from(String(key.y || ''), 'base64url');
  if (x.length !== size || y.length !== size) {
    log.debug('Leaving kemPublicKeyFor(). Bad coordinates.');
    throw new Error('a ' + row.crv + ' key has ' + size + '-octet x and y');
  }
  log.debug('Leaving kemPublicKeyFor(). EC.');
  return Buffer.concat([Buffer.from([0x04]), x, y]);
}

// ---------------------------------------------------------------------------
// WHICH OF A RECIPIENT'S PUBLISHED KEYS AN `alg` CAN ENCRYPT TO, for every
// asymmetric JWE alg — the question `recipientKey()` asks of a client's
// jwks. Section 4's families by `kty`; section 4a's by the whole check above
// (an AKP key names its alg, an EC or OKP key its curve). `need` is the
// phrase a refusal uses for what was missing.
// ---------------------------------------------------------------------------
/**
 * Tells whether a recipient's published JWK can be encrypted to with an
 * alg.
 *
 * @param alg - an asymmetric JWE `alg`
 * @param jwk - the recipient's public JWK
 * @returns true when the key's type, curve or AKP `alg` fits
 */
function jweRecipientKeyFits(alg, jwk) {
  log.debug('Entering jweRecipientKeyFits(). ' + alg);
  if (!jwk || typeof jwk !== 'object') {
    log.debug('Leaving jweRecipientKeyFits(). No key.');
    return false;
  }
  if (JWE_PQ_KEM_TABLE[alg]) {
    try {
      kemPublicKeyFor(alg, jwk);
    } catch (e) {
      log.debug('Caught in jweRecipientKeyFits(): ' +
                ((e && e.message) || e));
      log.debug('Leaving jweRecipientKeyFits(). Does not fit.');
      return false;
    }
    log.debug('Leaving jweRecipientKeyFits(). Fits.');
    return true;
  }
  log.debug('Leaving jweRecipientKeyFits().');
  return JWE_ECDH_ALGS.indexOf(alg) >= 0 ? jwk.kty === 'EC'
    : jwk.kty === 'RSA';
}

/**
 * Names the kind of key an alg encrypts to, for a refusal's sentence.
 *
 * @param alg - an asymmetric JWE `alg`
 * @returns a phrase such as "an AKP key whose alg is …"
 */
function jweRecipientKeyNeed(alg) {
  log.debug('Entering jweRecipientKeyNeed(). ' + alg);
  const row = JWE_PQ_KEM_TABLE[alg];
  log.debug('Leaving jweRecipientKeyNeed().');
  if (!row) {
    return JWE_ECDH_ALGS.indexOf(alg) >= 0 ? 'an EC key' : 'an RSA key';
  }
  return row.keyType === 'AKP' ? 'an AKP key whose alg is "' + alg + '"'
    : 'an ' + row.keyType + ' ' + row.crv + ' key';
}

// The PRIVATE half, from what a caller holds: an AKP JWK with `priv` (the
// seed), an EC or OKP JWK with `d`, or a node KeyObject of an EC or
// Montgomery key. Returns the serialised private key the KEM takes.
function kemPrivateKeyFor(alg, key) {
  log.debug('Entering kemPrivateKeyFor(). ' + alg);
  const row = JWE_PQ_KEM_TABLE[alg];
  let jwk = key;
  if (key && typeof key === 'object' && typeof key.export === 'function' &&
      key.type === 'private') {
    jwk = key.export({ format: 'jwk' });
  }
  if (!jwk || typeof jwk !== 'object') {
    log.debug('Leaving kemPrivateKeyFor(). None.');
    throw new Error('alg "' + alg + '" is encrypted to a private key and ' +
                    'this caller was given none');
  }
  if (row.keyType === 'AKP') {
    if (jwk.kty !== 'AKP' || jwk.alg !== alg || !jwk.priv) {
      log.debug('Leaving kemPrivateKeyFor(). Not this alg\'s AKP key.');
      throw new Error('alg "' + alg + '" is decrypted with an AKP key for ' +
                      'that algorithm, and the key held is ' +
                      (jwk.kty === 'AKP' ? 'for "' + (jwk.alg || '') + '"'
                        : 'of type "' + (jwk.kty || '(none)') + '"'));
    }
    log.debug('Leaving kemPrivateKeyFor(). AKP.');
    return Buffer.from(String(jwk.priv), 'base64url');
  }
  if (jwk.kty !== row.keyType || jwk.crv !== row.crv || !jwk.d) {
    log.debug('Leaving kemPrivateKeyFor(). Wrong key.');
    throw new Error('alg "' + alg + '" is decrypted with a ' + row.crv +
                    ' private key, and the key held is ' +
                    (jwk.crv || jwk.kty || '(none)'));
  }
  const d = Buffer.from(String(jwk.d), 'base64url');
  if (row.keyType === 'EC') {
    // A JWK's d is exactly the curve's size, but a KeyObject's export can
    // lose a leading zero on the coordinate; pad rather than refuse.
    const size = EC_GROUPS[row.crv].Nsk;
    log.debug('Leaving kemPrivateKeyFor(). EC.');
    return d.length >= size ? d
      : Buffer.concat([Buffer.alloc(size - d.length), d]);
  }
  log.debug('Leaving kemPrivateKeyFor(). OKP.');
  return d;
}

// ---------------------------------------------------------------------------
// pqc-kem-05 SECTION 5.1's KDF: KMAC256(K = SS', X, L, S = "") where X is
// AlgorithmID || SuppPubInfo from RFC 7518 section 4.6.2 — the same fields
// section 4's Concat KDF uses, with PartyUInfo and PartyVInfo left out on
// purpose (the draft: a KEM has no sender authentication, and the
// recipient is bound by its key). AlgorithmID is the length-prefixed `enc`
// for direct agreement and the length-prefixed `alg` for key wrapping,
// exactly as in RFC 7518; SuppPubInfo is the key length in bits.
// ---------------------------------------------------------------------------
/**
 * draft-ietf-jose-pqc-kem-05's KMAC256 derivation.
 *
 * @param sharedSecret - the KEM shared secret
 * @param algorithmId - `enc` (direct) or `alg` (key wrapping)
 * @param keyBytes - the key length in octets
 * @returns the derived key
 */
function mlkemJoseKdf(sharedSecret, algorithmId, keyBytes) {
  log.debug('Entering mlkemJoseKdf(). ' + algorithmId);
  const id = Buffer.from(String(algorithmId), 'utf8');
  const x = Buffer.concat([i2osp(id.length, 4), id, i2osp(keyBytes * 8, 4)]);
  const out = Buffer.from(nobleSha3Addons.kmac256(
    new Uint8Array(sharedSecret), new Uint8Array(x),
    { dkLen: keyBytes, personalization: new Uint8Array(0) }));
  log.debug('Leaving mlkemJoseKdf().');
  return out;
}

// The JOSE-HPKE Recipient_structure (jose-hpke-encrypt-22 section 6.1), the
// HPKE info for Key Encryption: "JOSE-HPKE rcpt" 0xFF enc 0xFF extra.
/**
 * jose-hpke-encrypt-22's Recipient_structure, the HPKE info for Key
 * Encryption.
 *
 * @param enc - the JWE `enc`
 * @param extra - recipient_extra_info, empty by default
 * @returns the octets
 */
function joseHpkeRecipientStructure(enc, extra) {
  log.debug('Entering joseHpkeRecipientStructure().');
  log.debug('Leaving joseHpkeRecipientStructure().');
  return Buffer.concat([Buffer.from('JOSE-HPKE rcpt', 'ascii'),
                        Buffer.from([0xff]), Buffer.from(String(enc), 'ascii'),
                        Buffer.from([0xff]), Buffer.from(extra || '')]);
}

// The HPKE PSK inputs a caller named (`psk`, `pskId`), for both directions:
// a psk_id in the header is base64url (jose-hpke-encrypt-22 section 11.2.2).
function joseHpkePsk(options, header, forEncrypt) {
  log.debug('Entering joseHpkePsk().');
  if (forEncrypt) {
    if (!options.psk) {
      log.debug('Leaving joseHpkePsk(). Base mode.');
      return {};
    }
    header.psk_id = b64u(Buffer.from(options.pskId || ''));
    log.debug('Leaving joseHpkePsk(). PSK mode.');
    return { psk: Buffer.from(options.psk),
             pskId: Buffer.from(options.pskId || '') };
  }
  if (header.psk_id === undefined) {
    log.debug('Leaving joseHpkePsk(). Base mode.');
    return {};
  }
  const pskId = Buffer.from(String(header.psk_id), 'base64url');
  const psk = typeof options.psk === 'function' ? options.psk(pskId)
    : options.psk;
  if (!psk) {
    log.debug('Leaving joseHpkePsk(). No PSK for that id.');
    throw new Error('this JWE names an HPKE pre-shared key (psk_id) and ' +
                    'this caller holds none for it');
  }
  log.debug('Leaving joseHpkePsk(). PSK mode.');
  return { psk: Buffer.from(psk), pskId: pskId };
}

// ---------------------------------------------------------------------------
// THE KEY MANAGEMENT HALF FOR THESE FAMILIES, as `wrapCek()` is for section
// 4's. Returns { cek, encryptedKey } and writes `ek` (and `psk_id`) into the
// header. Integrated HPKE is NOT here: it has no CEK, so
// `encryptJweCompact()` calls `hpkeIntegratedSeal()` instead.
// ---------------------------------------------------------------------------
function wrapCekPq(alg, recipientJwk, cek, header, options) {
  log.debug('Entering wrapCekPq(). ' + alg);
  const row = JWE_PQ_KEM_TABLE[alg];
  const pub = kemPublicKeyFor(alg, recipientJwk);
  if (row.family === 'mlkem') {
    const out = mlkemEncaps(row.set, pub, null);
    header.ek = b64u(out.ct);
    if (!row.kwBytes) {
      // Direct Key Agreement (pqc-kem-05 section 6.1): the KDF output IS the
      // CEK, its length the `enc`'s, and the JWE Encrypted Key is empty.
      log.debug('Leaving wrapCekPq(). ML-KEM direct.');
      return { cek: mlkemJoseKdf(out.ss, header.enc, cek.length),
               encryptedKey: Buffer.alloc(0) };
    }
    const kek = mlkemJoseKdf(out.ss, alg, row.kwBytes);
    log.debug('Leaving wrapCekPq(). ML-KEM with key wrapping.');
    return { cek: cek, encryptedKey: aesKeyWrap(kek, cek) };
  }
  const suite = { kem: row.kem, kdf: row.kdf, aead: row.aead };
  const psk = joseHpkePsk(options || {}, header, true);
  const sender = hpkeSetupSender(suite, pub, {
    info: joseHpkeRecipientStructure(header.enc,
                                     (options && options.recipientExtraInfo) ||
                                     ''),
    psk: psk.psk, pskId: psk.pskId });
  header.ek = b64u(sender.enc);
  // Section 6: the HPKE aad is empty and the plaintext is the CEK.
  const wrapped = sender.context.seal(Buffer.alloc(0), cek);
  log.debug('Leaving wrapCekPq(). HPKE Key Encryption.');
  return { cek: cek, encryptedKey: wrapped };
}

function unwrapCekPq(alg, header, encryptedKey, options, spec) {
  log.debug('Entering unwrapCekPq(). ' + alg);
  const row = JWE_PQ_KEM_TABLE[alg];
  if (typeof header.ek !== 'string' || !header.ek) {
    log.debug('Leaving unwrapCekPq(). No ek.');
    throw new Error('an "' + alg + '" JWE carries the KEM ciphertext in the ' +
                    'header as `ek` (' + row.spec + ') and this one has none');
  }
  const ek = strictBase64url(header.ek, 'JWE ek');
  const priv = kemPrivateKeyFor(alg, options.privateKey || options.privateJwk);
  if (row.family === 'mlkem') {
    const ss = mlkemDecaps(row.set, priv, ek);
    if (!row.kwBytes) {
      if (encryptedKey.length) {
        log.debug('Leaving unwrapCekPq(). Direct with an encrypted key.');
        throw new Error('direct key agreement leaves the JWE Encrypted Key ' +
                        'empty (pqc-kem-05 section 6.1), and this one is not');
      }
      if (!spec) {
        throw new Error('alg "' + alg + '" derives the content key at the ' +
                        'length `enc` names, and "' + header.enc + '" is ' +
                        'not one this service knows');
      }
      log.debug('Leaving unwrapCekPq(). ML-KEM direct.');
      return mlkemJoseKdf(ss, header.enc, spec.cekBytes);
    }
    const out = aesKeyUnwrap(mlkemJoseKdf(ss, alg, row.kwBytes), encryptedKey);
    log.debug('Leaving unwrapCekPq(). ML-KEM with key wrapping.');
    return out;
  }
  const psk = joseHpkePsk(options, header, false);
  const receiver = hpkeSetupReceiver(
    { kem: row.kem, kdf: row.kdf, aead: row.aead }, ek, priv, {
      info: joseHpkeRecipientStructure(header.enc,
                                       options.recipientExtraInfo || ''),
      psk: psk.psk, pskId: psk.pskId });
  const out = receiver.context.open(Buffer.alloc(0), encryptedKey);
  log.debug('Leaving unwrapCekPq(). HPKE Key Encryption.');
  return out;
}

// INTEGRATED ENCRYPTION (jose-hpke-encrypt-22 section 5): the plaintext is
// the HPKE plaintext, the HPKE aad is ASCII(Encoded Protected Header), the
// JWE Encrypted Key is the encapsulated secret, and the IV and tag are
// empty. The header is final before this is called — it is the aad.
function hpkeIntegratedSeal(alg, recipientJwk, headerB64, body, options,
                            psk) {
  log.debug('Entering hpkeIntegratedSeal(). ' + alg);
  const row = JWE_PQ_KEM_TABLE[alg];
  const pub = kemPublicKeyFor(alg, recipientJwk);
  const sender = hpkeSetupSender({ kem: row.kem, kdf: row.kdf,
                                   aead: row.aead }, pub, {
    info: (options && options.hpkeInfo) || '',
    psk: psk.psk, pskId: psk.pskId });
  const ct = sender.context.seal(Buffer.from(headerB64, 'ascii'), body);
  log.debug('Leaving hpkeIntegratedSeal().');
  return { encryptedKey: sender.enc, ciphertext: ct };
}

function hpkeIntegratedOpen(alg, header, headerB64, parts, options) {
  log.debug('Entering hpkeIntegratedOpen(). ' + alg);
  const row = JWE_PQ_KEM_TABLE[alg];
  if (header.enc !== undefined) {
    log.debug('Leaving hpkeIntegratedOpen(). enc present.');
    throw new Error('alg "' + alg + '" is HPKE Integrated Encryption, whose ' +
                    'header MUST NOT carry `enc` (jose-hpke-encrypt-22 ' +
                    'section 5)');
  }
  if (header.ek !== undefined) {
    log.debug('Leaving hpkeIntegratedOpen(). ek present.');
    throw new Error('alg "' + alg + '" carries the encapsulated secret as ' +
                    'the JWE Encrypted Key, and its header MUST NOT carry ' +
                    '`ek` (jose-hpke-encrypt-22 section 5)');
  }
  if (parts[2] !== '' || parts[4] !== '') {
    log.debug('Leaving hpkeIntegratedOpen(). IV or tag present.');
    throw new Error('HPKE Integrated Encryption leaves the JWE IV and ' +
                    'Authentication Tag empty (jose-hpke-encrypt-22 section ' +
                    '5), and this JWE carries ' +
                    (parts[2] !== '' ? 'an IV' : 'a tag'));
  }
  const priv = kemPrivateKeyFor(alg, options.privateKey || options.privateJwk);
  const psk = joseHpkePsk(options, header, false);
  const receiver = hpkeSetupReceiver(
    { kem: row.kem, kdf: row.kdf, aead: row.aead },
    Buffer.from(parts[1], 'base64url'), priv, {
      info: options.hpkeInfo || '', psk: psk.psk, pskId: psk.pskId });
  const out = receiver.context.open(Buffer.from(headerB64, 'ascii'),
                                    Buffer.from(parts[3], 'base64url'));
  log.debug('Leaving hpkeIntegratedOpen().');
  return out;
}

// ---------------------------------------------------------------------------
// A KEY PAIR FOR ONE OF THESE ALGS, as JWKs: AKP { alg, pub } and
// { alg, pub, priv } for the post-quantum rows (priv the seed — 64 octets
// for ML-KEM, 32 for a hybrid); EC or OKP for the classical HPKE rows. What
// a realm's opt-in decryption keys and OID4VP's ephemeral keys are made
// with, so there is one generator (the crypto-pki-in-shared-modules rule).
// ---------------------------------------------------------------------------
/**
 * Generates a key pair for an ML-KEM or HPKE JWE alg.
 *
 * @param alg - an ML-KEM or HPKE `alg`
 * @param kid - the kid both JWKs carry, when given
 * @returns `{ publicJwk, privateJwk }` — AKP, EC or OKP
 * @throws Error for an alg that is neither
 */
function generateJweKemKeyPair(alg, kid) {
  log.debug('Entering generateJweKemKeyPair(). ' + alg);
  const row = JWE_PQ_KEM_TABLE[String(alg)];
  if (!row) {
    log.debug('Leaving generateJweKemKeyPair(). Not one of these algs.');
    throw new Error('generateJweKemKeyPair: "' + alg + '" is not an ML-KEM ' +
                    'or HPKE JWE algorithm');
  }
  const extra = { use: 'enc', alg: alg };
  if (kid) {
    extra.kid = kid;
  }
  if (row.keyType === 'AKP') {
    const sk = nodeCrypto.randomBytes(row.family === 'mlkem' ? 64
      : HPKE_KEMS[row.kem].Nsk);
    const pk = row.family === 'mlkem' ? mlkemFromSeed(row.set, sk).ek
      : (HPKE_KEMS[row.kem].kind === 'mlkem'
        ? mlkemFromSeed(HPKE_KEMS[row.kem].set, sk).ek
        : hybridExpand(HPKE_KEMS[row.kem].hybrid, sk).ek);
    const publicJwk = Object.assign({ kty: 'AKP', pub: b64u(pk) }, extra);
    log.debug('Leaving generateJweKemKeyPair(). AKP.');
    return { publicJwk: publicJwk,
             privateJwk: Object.assign({ priv: b64u(sk) }, publicJwk) };
  }
  const pair = row.keyType === 'EC'
    ? nodeCrypto.generateKeyPairSync('ec',
                                     { namedCurve: EC_GROUPS[row.crv].node })
    : nodeCrypto.generateKeyPairSync(
      /** @type {any} */ (row.crv.toLowerCase()));
  const priv = pair.privateKey.export({ format: 'jwk' });
  const pub = pair.publicKey.export({ format: 'jwk' });
  log.debug('Leaving generateJweKemKeyPair(). ' + row.keyType + '.');
  return { publicJwk: Object.assign(pub, extra),
           privateJwk: Object.assign(priv, extra) };
}

// ---------------------------------------------------------------------------
// THE SAME KEY PAIR, DERIVED rather than drawn: from input keying material
// through the KEM's own DeriveKeyPair (draft-ietf-hpke-hpke section 7.1.3,
// draft-ietf-hpke-pq sections 3 and 4) — for an ML-KEM alg, the HPKE ML-KEM
// KEM of the same parameter set, whose DeriveKeyPair yields the 64-octet
// seed. A published KDF, so the derivation is one somebody else can check.
// For a key a realm only ever encrypts to ITSELF (a refresh token), made
// from a secret it already holds, sealed, shares and rotates.
// ---------------------------------------------------------------------------
const MLKEM_HPKE_KEM = { 'ML-KEM-512': 0x0040, 'ML-KEM-768': 0x0041,
                         'ML-KEM-1024': 0x0042 };

/**
 * Derives a key pair for an ML-KEM or HPKE JWE alg through the KEM's own
 * DeriveKeyPair.
 *
 * @param alg - an ML-KEM or HPKE `alg`
 * @param ikm - the input keying material
 * @param kid - the kid both JWKs carry, when given
 * @returns `{ publicJwk, privateJwk }`, the same for the same input
 */
function deriveJweKemKeyPair(alg, ikm, kid) {
  log.debug('Entering deriveJweKemKeyPair(). ' + alg);
  const row = JWE_PQ_KEM_TABLE[String(alg)];
  if (!row) {
    log.debug('Leaving deriveJweKemKeyPair(). Not one of these algs.');
    throw new Error('deriveJweKemKeyPair: "' + alg + '" is not an ML-KEM ' +
                    'or HPKE JWE algorithm');
  }
  const kemId = row.family === 'mlkem' ? MLKEM_HPKE_KEM[row.set] : row.kem;
  const pair = hpkeDeriveKeyPair(kemId, ikm);
  const extra = { use: 'enc', alg: alg };
  if (kid) {
    extra.kid = kid;
  }
  let publicJwk;
  let privateMembers;
  if (row.keyType === 'AKP') {
    publicJwk = Object.assign({ kty: 'AKP', pub: b64u(pair.pk) }, extra);
    privateMembers = { priv: b64u(pair.sk) };
  } else if (row.keyType === 'EC') {
    const size = EC_GROUPS[row.crv].Nsk;
    publicJwk = Object.assign({
      kty: 'EC', crv: row.crv, x: b64u(pair.pk.subarray(1, 1 + size)),
      y: b64u(pair.pk.subarray(1 + size)) }, extra);
    privateMembers = { d: b64u(pair.sk) };
  } else {
    publicJwk = Object.assign({ kty: 'OKP', crv: row.crv,
                                x: b64u(pair.pk) }, extra);
    privateMembers = { d: b64u(pair.sk) };
  }
  log.debug('Leaving deriveJweKemKeyPair().');
  return { publicJwk: publicJwk,
           privateJwk: Object.assign({}, publicJwk, privateMembers) };
}

// The public JWK of a private one, for a realm key read back from the store.
/**
 * Returns the public half of a KEM private JWK.
 *
 * @param privateJwk - an AKP, EC or OKP private JWK
 * @returns a copy without `priv` or `d`
 */
function publicJweKemJwk(privateJwk) {
  log.debug('Entering publicJweKemJwk().');
  const out = Object.assign({}, privateJwk || {});
  delete out.priv;
  delete out.d;
  log.debug('Leaving publicJweKemJwk().');
  return out;
}

// What the console and the crypto-metadata document say about each alg: the
// family, the KEM, the KDF, the AEAD and the draft it comes from.
/**
 * Describes an ML-KEM or HPKE alg for the console and the metadata.
 *
 * @param alg - a JWE `alg`
 * @returns its family, KEM, KDF, AEAD, mode and draft, or null
 */
function describeJweKemAlg(alg) {
  log.debug('Entering describeJweKemAlg(). ' + alg);
  const row = JWE_PQ_KEM_TABLE[String(alg)];
  if (!row) {
    log.debug('Leaving describeJweKemAlg(). Not one of these.');
    return null;
  }
  if (row.family === 'mlkem') {
    log.debug('Leaving describeJweKemAlg(). ML-KEM.');
    return { alg: alg, family: 'ML-KEM', kem: row.set, kdf: 'KMAC256',
             keyWrap: row.kwBytes ? 'A' + (row.kwBytes * 8) + 'KW' : '',
             mode: row.kwBytes ? 'Key Agreement with Key Wrapping'
               : 'Direct Key Agreement',
             keyType: 'AKP', postQuantum: true, hybrid: false,
             spec: row.spec };
  }
  log.debug('Leaving describeJweKemAlg(). HPKE.');
  return { alg: alg, family: 'HPKE', kem: HPKE_KEMS[row.kem].name,
           kdf: HPKE_KDFS[row.kdf].name, aead: HPKE_AEADS[row.aead].name,
           mode: row.integrated ? 'Integrated Encryption' : 'Key Encryption',
           keyType: row.keyType + (row.crv ? ' ' + row.crv : ''),
           postQuantum: row.postQuantum, hybrid: row.hybrid,
           spec: row.spec };
}

// ===========================================================================
// SECTION 4 — JWE (RFC 7516 compact serialization)
// ===========================================================================
//
// ---------------------------------------------------------------------------
// WRITTEN OUT BY HAND, AND THAT IS KEPT ON PURPOSE. `oid4vc/vc_issuer.ts` made
// the argument where this code used to live and it still holds: OID4VCI
// section 10 is a Credential Issuer and a Wallet encrypting to each other, and
// having the steps visible — the content key, the wrap, the AAD, the tag — is
// what a mock is FOR. A call into a JOSE library would show a reader nothing.
//
// What was wrong was not the hand-rolling, it was that the encrypt half and the
// decrypt half sat two hundred lines apart in a protocol module with no shared
// notion of what an `enc` value means. They are together here, over one table,
// so a third algorithm is one row rather than two edits that have to agree.
//
// `common/vendored/jose_jwe.js` is the obvious alternative and is not used
// here. This paragraph used to justify that by saying this service used
// neither ECDH-ES nor the Concat KDF, only RSA-OAEP-256 with AES-GCM — which
// stopped being true when the table below grew to RFC 7518 section 4 entire
// (2026-09-10): ECDH-ES and its KDF are implemented in this file
// (`concatKdf()`), so the two-implementations risk that module's header warns
// about is real and is answered by the interop tests rather than avoided.
// That file stays vendored for `key_material.js` and `x509.js`, which require
// it and which SPIFFE and `pki.js` reach through.
// ---------------------------------------------------------------------------

// The content encryption algorithms this service speaks, in both families RFC
// 7518 section 5 defines. `bits` is the AES key size; `cekBytes` is the size of
// the CONTENT ENCRYPTION KEY, which for the CBC-HMAC family is twice the AES
// key because the CEK carries a MAC key in front of it.
//
// The CBC-HMAC three are here because A128CBC-HS256 is what an OpenID Connect
// client gets by DEFAULT: register `userinfo_encrypted_response_alg` and say
// nothing about `enc` and section 2 of the registration spec has chosen
// A128CBC-HS256 for you. A service that spoke only AES-GCM would refuse the
// commonest encrypted response there is, and would look to the client like it
// had refused the request.
/** The JWE content encryption algorithms, AES-GCM and AES-CBC-HMAC. */
const JWE_ENCS = {
  A128GCM: { bits: 128, cipher: 'aes-128-gcm', cekBytes: 16, mode: 'gcm' },
  A192GCM: { bits: 192, cipher: 'aes-192-gcm', cekBytes: 24, mode: 'gcm' },
  A256GCM: { bits: 256, cipher: 'aes-256-gcm', cekBytes: 32, mode: 'gcm' },
  'A128CBC-HS256': { bits: 128, cipher: 'aes-128-cbc', cekBytes: 32,
                     mode: 'cbc-hmac', hash: 'sha256', halfBytes: 16 },
  'A192CBC-HS384': { bits: 192, cipher: 'aes-192-cbc', cekBytes: 48,
                     mode: 'cbc-hmac', hash: 'sha384', halfBytes: 24 },
  'A256CBC-HS512': { bits: 256, cipher: 'aes-256-cbc', cekBytes: 64,
                     mode: 'cbc-hmac', hash: 'sha512', halfBytes: 32 }
};

// The key management algorithms this service can ENCRYPT with. RSA-OAEP-256 is
// RSA-OAEP with SHA-256, which is what node calls RSA_PKCS1_OAEP_PADDING plus
// an explicit oaepHash — the default is SHA-1 and would interoperate with
// nothing that reads the `alg` header.
//
// RSA-OAEP (SHA-1) is offered beside it because it is what a recipient whose
// stack predates the -256 variant registers, and this is a service for testing
// other people's clients. ECDH-ES and its three key-wrapping variants are here
// because a recipient with an EC key has no RSA one to offer.
/** The default JWE key management algorithm: RSA-OAEP-256. */
const JWE_ALG = 'RSA-OAEP-256';
// ---------------------------------------------------------------------------
// **THE SYMMETRIC FAMILIES JOINED THIS LIST ON 2026-09-10 AND THE DECRYPT LIST
// STOPPED BEING SHORTER THAN IT.** Both changes are for RFC 7521 / RFC 7523:
// an assertion may arrive ENCRYPTED, and the two families it can plausibly be
// encrypted to are the ones this service holds a key for — its own RSA and EC
// keys, and a CLIENT SECRET, which is a shared symmetric key and is the only
// key material a `client_secret_jwt` client has.
//
// So the table is now RFC 7518 section 4 entire, with one deliberate absence
// argued at the foot of it:
//
//   RSA-OAEP-256 / RSA-OAEP        to this service's RSA key
//   ECDH-ES and its three KW forms to an EC key
//   A128KW / A192KW / A256KW       AES Key Wrap under a shared secret
//   A128GCMKW / A192GCMKW / A256GCMKW  the same, AES-GCM, with `iv` and `tag`
//                                  in the header (section 4.7.1)
//   dir                            the shared secret IS the content key
//   PBES2-HS256+A128KW and friends the shared secret is a PASSWORD, stretched
//                                  by PBKDF2 with `p2s` and `p2c` (section 4.8)
//
// **RSA1_5 IS NOT HERE AND IS NOT AN OVERSIGHT.** RFC 8017 deprecated PKCS#1
// v1.5 encryption and every JOSE implementation that still offers it has a
// Bleichenbacher oracle behind it in principle — the failure of an unwrap has
// to be indistinguishable from the failure of everything after it, which is a
// property of a whole code path rather than of one function. This service is a
// mock and it will not carry that path. A caller that sends one is told the
// name and the reason, which is more useful than a list it has to diff.
// ---------------------------------------------------------------------------
/** The RSA-OAEP key management algorithms. */
const JWE_RSA_ALGS = ['RSA-OAEP-256', 'RSA-OAEP'];
/** The ECDH-ES key management algorithms. */
const JWE_ECDH_ALGS = ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW',
                       'ECDH-ES+A256KW'];
const JWE_AESKW_ALGS = ['A128KW', 'A192KW', 'A256KW'];
const JWE_AESGCMKW_ALGS = ['A128GCMKW', 'A192GCMKW', 'A256GCMKW'];
const JWE_PBES2_ALGS = ['PBES2-HS256+A128KW', 'PBES2-HS384+A192KW',
                        'PBES2-HS512+A256KW'];
/** The symmetric JWE key management algorithms, `dir` among them. */
const JWE_SYMMETRIC_ALGS = JWE_AESKW_ALGS.concat(JWE_AESGCMKW_ALGS,
                                                 JWE_PBES2_ALGS, ['dir']);
// The families that encrypt to a RECIPIENT'S PUBLIC KEY. Kept as a name of
// its own because it is what the three surfaces that encrypt OUTWARD may offer
// — a signed UserInfo response, an OID4VCI Credential Response, an encrypted
// assertion this service mints — and every one of them holds the recipient's
// JWKS and no shared secret. Advertising the symmetric families there would be
// a metadata member a client could register and this service would then try to
// satisfy by deriving a key from the JSON of a public key.
//
// **THE POST-QUANTUM AND HPKE FAMILIES JOINED IT ON 2026-09-27 (#82)** —
// section 4a's table, all of it: the six ML-KEM algorithms and HPKE-0 to
// HPKE-16 with their Key Encryption forms. Every one encrypts to a
// recipient's PUBLIC key, which is this list's whole definition, and a
// client registers one the way it registers RSA-OAEP-256. What this service
// can DECRYPT with them is a different question — it needs a key of its own
// for the alg, and those are an administrator's opt-in per realm (rcbj's
// decision on #82), so the discovery lists that describe decryption are
// narrowed to the keys held rather than read from here.
/** The key management algorithms that encrypt to a recipient's public key. */
const JWE_ASYMMETRIC_ALGS = JWE_RSA_ALGS.concat(JWE_ECDH_ALGS, JWE_MLKEM_ALGS,
                                                JWE_HPKE_ALGS);
/** Every JWE key management algorithm this service speaks. */
const JWE_ALGS = JWE_ASYMMETRIC_ALGS.concat(JWE_SYMMETRIC_ALGS);
// **THE SAME LIST, AND THAT IS THE CHANGE.** It was `['RSA-OAEP-256']` on the
// argument that what arrives here is encrypted to the RSA key this service
// publishes — true of the one caller that existed then (OID4VCI's encrypted
// Credential Request) and false the moment a client could encrypt an assertion
// to a key of its own choosing. A caller now picks by what it HOLDS rather
// than by what this table permits, and `decryptJweCompact()` refuses by name
// when it was handed no key of the right kind.
/** The JWE key management algorithms this service decrypts: all of them. */
const JWE_DECRYPT_ALGS = JWE_ALGS.slice();
const ECDH_KW_BYTES = { 'ECDH-ES+A128KW': 16, 'ECDH-ES+A192KW': 24,
                        'ECDH-ES+A256KW': 32 };
// The AES key size each symmetric family wraps with. `dir` has none — the
// secret IS the content encryption key, so its length is decided by `enc`.
const AESKW_BYTES = { A128KW: 16, A192KW: 24, A256KW: 32,
                      A128GCMKW: 16, A192GCMKW: 24, A256GCMKW: 32,
                      'PBES2-HS256+A128KW': 16, 'PBES2-HS384+A192KW': 24,
                      'PBES2-HS512+A256KW': 32 };
const PBES2_HASH = { 'PBES2-HS256+A128KW': 'sha256',
                     'PBES2-HS384+A192KW': 'sha384',
                     'PBES2-HS512+A256KW': 'sha512' };
// RFC 7518 section 4.8.1.2 gives no ceiling and says a recipient SHOULD pick
// one. A `p2c` a caller chose is a caller choosing how long this process
// blocks: PBKDF2 is synchronous here, and 2^31 iterations on the token
// endpoint is a denial of service with a specification citation attached.
const PBES2_MAX_ITERATIONS = 1000000;
const PBES2_DEFAULT_ITERATIONS = 8192;
// JWK curve name -> the name node's OpenSSL knows it by.
const EC_CURVES = { 'P-256': 'prime256v1', 'P-384': 'secp384r1',
                    'P-521': 'secp521r1' };

/**
 * Encodes bytes as base64url.
 *
 * @param buf - the bytes
 * @returns the base64url text
 */
function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString('base64url');
}

// ---------------------------------------------------------------------------
// ENCRYPT TO A COMPACT JWE. `opts`:
//
//   jwk    the recipient's public key as a JWK, straight out of their metadata.
//   enc    one of JWE_ENCS. Required — there is no sensible default when the
//          recipient has told you what they can read.
//   typ    the protected header's `typ`, if the profile wants one.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE CONTENT ENCRYPTION HALF, FOR BOTH FAMILIES.
//
// AES-GCM is one primitive and node does the whole of it. AES-CBC-HMAC is the
// composite of RFC 7518 section 5.2 and has to be assembled: the CEK splits
// MAC-KEY FIRST then ENC-KEY, the MAC covers AAD || IV || CIPHERTEXT || AL
// where AL is the AAD length IN BITS as a 64-bit big-endian integer, and the
// tag is the FIRST HALF of the HMAC output. Each of those four is a place a
// wrong reading round-trips against itself perfectly and interoperates with
// nothing.
// ---------------------------------------------------------------------------
function cbcHmacKeys(spec, cek) {
  log.debug("Entering cbcHmacKeys().");
  log.debug("Leaving cbcHmacKeys().");
  return { macKey: cek.subarray(0, spec.halfBytes),
           encKey: cek.subarray(spec.halfBytes) };
}

function cbcHmacTag(spec, cek, iv, aad, ciphertext) {
  log.debug("Entering cbcHmacTag().");
  const keys = cbcHmacKeys(spec, cek);
  const al = Buffer.alloc(8);
  al.writeBigUInt64BE(BigInt(aad.length * 8));
  log.debug("Leaving cbcHmacTag().");
  return nodeCrypto.createHmac(spec.hash, keys.macKey)
    .update(Buffer.concat([aad, iv, ciphertext, al]))
    .digest().subarray(0, spec.halfBytes);
}

function sealContent(spec, cek, iv, aad, plaintext) {
  log.debug('Entering sealContent(). mode=' + spec.mode);
  if (spec.mode === 'cbc-hmac') {
    const keys = cbcHmacKeys(spec, cek);
    const cipher = nodeCrypto.createCipheriv(spec.cipher, keys.encKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext),
                                      cipher.final()]);
    log.debug('Leaving sealContent(). CBC-HMAC.');
    return { ciphertext: ciphertext,
             tag: cbcHmacTag(spec, cek, iv, aad, ciphertext) };
  }
  const cipher = nodeCrypto.createCipheriv(spec.cipher, cek, iv);
  // The protected header is the additional authenticated data, per RFC 7516
  // section 5.1 step 14 — as its ASCII base64url text, not as the JSON. Getting
  // that wrong produces a tag the far end cannot verify and no other symptom.
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  log.debug('Leaving sealContent(). GCM.');
  return { ciphertext: ciphertext, tag: cipher.getAuthTag() };
}

function openContent(spec, cek, iv, aad, ciphertext, tag) {
  log.debug('Entering openContent(). mode=' + spec.mode);
  if (spec.mode === 'cbc-hmac') {
    const expected = cbcHmacTag(spec, cek, iv, aad, ciphertext);
    // timingSafeEqual throws on a length mismatch, so the length is checked
    // first — and a wrong length is a wrong tag either way.
    if (expected.length !== tag.length ||
        !nodeCrypto.timingSafeEqual(expected, tag)) {
      log.debug('Leaving openContent(). The tag did not verify.');
      throw new Error('the authentication tag does not verify');
    }
    const keys = cbcHmacKeys(spec, cek);
    const decipher = nodeCrypto.createDecipheriv(spec.cipher, keys.encKey, iv);
    const out = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    log.debug('Leaving openContent(). CBC-HMAC.');
    return out;
  }
  // THE IV IS 96 BITS AND THE TAG 128, AND NOTHING ELSE IS OPENED (#202,
  // 2026-09-24). RFC 7518 section 5.3 fixes both. Node's GCM takes any IV
  // length and — without `authTagLength` — any tag from 4 octets up, so
  // until Wycheproof's truncated-tag vectors a JWE whose tag had been cut to
  // four octets was OPENED: an attacker forging content needed to guess 32
  // bits of tag, not 128. Both are checked here, before the cipher, and the
  // tag length is also pinned in the decipher itself.
  if (iv.length !== 12 || tag.length !== 16) {
    log.debug('Leaving openContent(). A ' + iv.length + '-octet IV or a ' +
              tag.length + '-octet tag.');
    throw new Error('an AES-GCM JWE carries a 96-bit IV and a 128-bit ' +
      'authentication tag (RFC 7518 section 5.3); this one has ' +
      (iv.length * 8) + ' and ' + (tag.length * 8) + ' bits');
  }
  const decipher = /** @type {import('crypto').DecipherGCM} */ (
    nodeCrypto.createDecipheriv(spec.cipher, cek, iv,
                                { authTagLength: 16 }));
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const out = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  log.debug('Leaving openContent(). GCM.');
  return out;
}

// ---------------------------------------------------------------------------
// THE CONTENT HALF OF A JWE, BY `enc` NAME (#202, 2026-09-24). What
// `encryptJweCompact()` and `decryptJweCompact()` call, exported so that an
// external answer — Wycheproof's AES-GCM and A*CBC-HS* vectors — reaches the
// same two functions rather than node's cipher directly. A compact JWE
// cannot carry those vectors itself: its AAD is always the protected header.
// ---------------------------------------------------------------------------
function jweContentSpec(enc) {
  log.debug('Entering jweContentSpec(). enc=' + enc);
  const spec = JWE_ENCS[String(enc)];
  if (!spec) {
    log.debug('Leaving jweContentSpec(). Unknown.');
    throw new Error('no JWE content encryption "' + enc + '"; this service ' +
      'speaks ' + Object.keys(JWE_ENCS).join(', ') + '.');
  }
  log.debug('Leaving jweContentSpec().');
  return spec;
}

/**
 * Encrypts JWE content under a named `enc`.
 *
 * @param enc - the content encryption algorithm
 * @param cek - the content encryption key
 * @param iv - the initialization vector
 * @param aad - the additional authenticated data
 * @param plaintext - the plaintext
 * @returns `{ ciphertext, tag }`
 */
function sealJweContent(enc, cek, iv, aad, plaintext) {
  log.debug('Entering sealJweContent(). enc=' + enc);
  const out = sealContent(jweContentSpec(enc), Buffer.from(cek),
                          Buffer.from(iv), Buffer.from(aad),
                          Buffer.from(plaintext));
  log.debug('Leaving sealJweContent().');
  return out;
}

/**
 * Decrypts JWE content under a named `enc`.
 *
 * @param enc - the content encryption algorithm
 * @param cek - the content encryption key
 * @param iv - the initialization vector
 * @param aad - the additional authenticated data
 * @param ciphertext - the ciphertext
 * @param tag - the authentication tag
 * @returns the plaintext
 */
function openJweContent(enc, cek, iv, aad, ciphertext, tag) {
  log.debug('Entering openJweContent(). enc=' + enc);
  const out = openContent(jweContentSpec(enc), Buffer.from(cek),
                          Buffer.from(iv), Buffer.from(aad),
                          Buffer.from(ciphertext), Buffer.from(tag));
  log.debug('Leaving openJweContent().');
  return out;
}

// ---------------------------------------------------------------------------
// THE KEY MANAGEMENT HALF. Returns the encrypted_key segment's bytes and, for
// the ECDH-ES variants, writes the ephemeral public key into the header — the
// recipient cannot agree the secret without it.
//
// The Concat KDF here REPEATS: NIST SP 800-56A produces 32 bytes per SHA-256
// round, and A192CBC-HS384 and A256CBC-HS512 need 48 and 64. A single round
// truncated to length would agree with a matching bug at the far end and with
// nothing else.
// ---------------------------------------------------------------------------
// PartyUInfo and PartyVInfo (RFC 7518 section 4.6.2) are the header's
// `apu` and `apv`, base64url-DECODED, each with its length — and empty only
// when the header has none. They were always written as empty, so a JWE from
// a sender that sets them (an OpenID4VP wallet puts the nonce in `apv`)
// derived a different key here and failed its tag: the OpenID conformance
// suite's direct_post.jwt modules found it (#187).
function partyInfo(header, name) {
  log.debug('Entering partyInfo(). ' + name);
  const value = header && header[name];
  log.debug('Leaving partyInfo().');
  return typeof value === 'string' && value
    ? Buffer.from(value, 'base64url') : Buffer.alloc(0);
}

function concatKdf(z, keyBytes, algId, header) {
  log.debug('Entering concatKdf(). algId=' + algId);
  const u32 = function (n) {
    log.debug("Entering u32().");
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n >>> 0);
    log.debug("Leaving u32().");
    return b;
  };
  const alg = Buffer.from(algId, 'utf8');
  const apu = partyInfo(header, 'apu');
  const apv = partyInfo(header, 'apv');
  const otherInfo = Buffer.concat([u32(alg.length), alg, u32(apu.length), apu,
                                   u32(apv.length), apv,
                                   u32(keyBytes * 8)]);
  const rounds = Math.ceil(keyBytes / 32);
  const blocks = [];
  for (let i = 1; i <= rounds; i++) {
    blocks.push(nodeCrypto.createHash('sha256')
      .update(Buffer.concat([u32(i), z, otherInfo])).digest());
  }
  log.debug('Leaving concatKdf(). ' + rounds + ' round(s).');
  return Buffer.concat(blocks).subarray(0, keyBytes);
}

const AES_KW_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

// RFC 3394 section 2.2: the key data is n >= 2 64-bit semiblocks, so the
// wrapped value is (n + 1) of them — at least 24 octets. Node's
// `id-aes*-wrap` unwrapped an EMPTY value to an empty key until Wycheproof's
// InvalidWrappingSize vectors (#202, 2026-09-24); both directions refuse a
// size the RFC does not define before the cipher is asked.
/**
 * Wraps a key with AES Key Wrap (RFC 3394).
 *
 * @param kek - the key-encryption key
 * @param plaintextKey - the key to wrap, at least two 64-bit semiblocks
 * @returns the wrapped key
 */
function aesKeyWrap(kek, plaintextKey) {
  log.debug('Entering aesKeyWrap().');
  if (plaintextKey.length < 16 || plaintextKey.length % 8) {
    log.debug('Leaving aesKeyWrap(). ' + plaintextKey.length + ' octets.');
    throw new Error('AES Key Wrap wraps a whole number of 64-bit ' +
      'semiblocks, at least two (RFC 3394 section 2.2); this key is ' +
      plaintextKey.length + ' octets.');
  }
  const cipher = nodeCrypto.createCipheriv('id-aes' + (kek.length * 8) +
      '-wrap', kek, AES_KW_IV);
  const out = Buffer.concat([cipher.update(plaintextKey), cipher.final()]);
  log.debug('Leaving aesKeyWrap().');
  return out;
}

/**
 * Unwraps a key wrapped with AES Key Wrap (RFC 3394).
 *
 * @param kek - the key-encryption key
 * @param wrapped - the wrapped key, at least 24 octets
 * @returns the key
 */
function aesKeyUnwrap(kek, wrapped) {
  log.debug('Entering aesKeyUnwrap().');
  if (wrapped.length < 24 || wrapped.length % 8) {
    log.debug('Leaving aesKeyUnwrap(). ' + wrapped.length + ' octets.');
    throw new Error('an AES-wrapped key is a whole number of 64-bit ' +
      'semiblocks, at least three (RFC 3394 section 2.2); this one is ' +
      wrapped.length + ' octets.');
  }
  const decipher = nodeCrypto.createDecipheriv('id-aes' + (kek.length * 8) +
      '-wrap', kek, AES_KW_IV);
  const out = Buffer.concat([decipher.update(wrapped), decipher.final()]);
  log.debug('Leaving aesKeyUnwrap().');
  return out;
}

// ---------------------------------------------------------------------------
// THE SHARED SECRET, AS BYTES. A caller hands one of three things and they are
// three different things on purpose:
//
//   a Buffer      raw key bytes, used as they are
//   an oct JWK    RFC 7517's symmetric key — base64url, decoded
//   a string      **the UTF-8 bytes of it**, which is what a client_secret is
//
// That last row is the one worth stating. RFC 7518 section 4.8 is explicit
// that a PBES2 password is the UTF-8 octets, and OpenID Connect Core section
// 16.19 says the same about deriving a symmetric key from `client_secret` —
// so a secret is never base64-decoded on the way in, however much it looks
// like base64. Guessing there produces a key that is wrong and plausible, and
// the failure is an authentication tag that does not verify.
// ---------------------------------------------------------------------------
function secretBytes(secret) {
  log.debug("Entering secretBytes().");
  if (Buffer.isBuffer(secret)) {
    log.debug("Leaving secretBytes().");
    return secret;
  }
  if (secret && typeof secret === 'object' && secret.kty === 'oct') {
    log.debug("Leaving secretBytes().");
    return Buffer.from(String(secret.k || ''), 'base64url');
  }
  log.debug("Leaving secretBytes().");
  return Buffer.from(String(secret == null ? '' : secret), 'utf8');
}

// RFC 7518 section 4.8.1.1: the salt input is `alg || 0x00 || p2s`, and
// leaving the algorithm name out of it is the classic mistake — it makes one
// password produce the same key for three different key sizes.
/**
 * Derives a PBES2 key (RFC 7518 section 4.8.1.1), the algorithm name in the
 * salt input.
 *
 * @param alg - the PBES2 algorithm
 * @param password - the password
 * @param saltInput - the `p2s` salt input
 * @param iterations - the `p2c` count
 * @returns the key
 */
function pbes2Key(alg, password, saltInput, iterations) {
  log.debug('Entering pbes2Key(). alg=' + alg);
  const salt = Buffer.concat([Buffer.from(alg, 'utf8'), Buffer.alloc(1),
                              saltInput]);
  const out = nodeCrypto.pbkdf2Sync(secretBytes(password), salt, iterations,
                                    AESKW_BYTES[alg], PBES2_HASH[alg]);
  log.debug('Leaving pbes2Key(). ' + iterations + ' iteration(s).');
  return out;
}

// The symmetric half of both directions, so that the key a wrap derives and
// the key an unwrap derives are derived by ONE function. Two copies of the
// PBES2 salt construction is one copy that will eventually leave out the alg.
function symmetricKek(alg, secret, header, forEncrypt) {
  log.debug('Entering symmetricKek(). alg=' + alg);
  if (JWE_PBES2_ALGS.indexOf(alg) >= 0) {
    let salt;
    let iterations;
    if (forEncrypt) {
      salt = nodeCrypto.randomBytes(16);
      iterations = PBES2_DEFAULT_ITERATIONS;
      header.p2s = b64u(salt);
      header.p2c = iterations;
    } else {
      if (!header.p2s) {
        throw new Error('a ' + alg + ' JWE carries its PBKDF2 salt in the ' +
          'header as `p2s` (RFC 7518 section 4.8.1.1) and this one has none.');
      }
      salt = Buffer.from(String(header.p2s), 'base64url');
      iterations = Math.floor(Number(header.p2c));
      if (!isFinite(iterations) || iterations < 1) {
        throw new Error('a ' + alg + ' JWE carries its PBKDF2 iteration ' +
          'count in the header as `p2c` and this one says ' +
          '"' + header.p2c + '".');
      }
      if (iterations > PBES2_MAX_ITERATIONS) {
        // Refused rather than performed: see PBES2_MAX_ITERATIONS.
        throw new Error('this JWE asks for ' + iterations + ' PBKDF2 ' +
          'iterations and this service performs at most ' +
          PBES2_MAX_ITERATIONS + '. RFC 7518 section 4.8.1.2 leaves the ' +
          'ceiling to the recipient, and a caller choosing this number is a ' +
          'caller choosing how long this process blocks.');
      }
    }
    const key = pbes2Key(alg, secret, salt, iterations);
    log.debug('Leaving symmetricKek(). PBES2.');
    return key;
  }
  const bytes = secretBytes(secret);
  if (alg === 'dir') {
    log.debug('Leaving symmetricKek(). Direct.');
    return bytes;
  }
  const need = AESKW_BYTES[alg];
  if (bytes.length !== need) {
    throw new Error(alg + ' wraps with a ' + (need * 8) + '-bit key and the ' +
      'key given is ' + (bytes.length * 8) + ' bits. RFC 7518 section 4.4 ' +
      'has no key derivation in it — the key must be exactly that size, or ' +
      'use a PBES2 algorithm, which stretches a password on purpose.');
  }
  log.debug('Leaving symmetricKek(). AES.');
  return bytes;
}

function wrapCek(alg, recipientJwk, cek, header, options) {
  log.debug('Entering wrapCek(). alg=' + alg);
  if (JWE_ALGS.indexOf(alg) === -1) {
    log.debug('Leaving wrapCek(). Unknown alg.');
    throw new Error('encryptJweCompact: unsupported alg "' + alg +
      '"; this service encrypts with ' + JWE_ALGS.join(', ') + '.');
  }
  // ML-KEM and HPKE Key Encryption (section 4a). Before the symmetric
  // families and before `createPublicKey()`, which cannot read an AKP key.
  if (JWE_PQ_KEM_TABLE[alg]) {
    const out = wrapCekPq(alg, recipientJwk, cek, header, options);
    log.debug('Leaving wrapCek(). ' + alg + '.');
    return out;
  }

  // ---------------------------------------------------------------------
  // THE SYMMETRIC FAMILIES FIRST, because they take a SECRET rather than a
  // recipient's public key and `createPublicKey()` below would throw on one
  // with a message about key data.
  // ---------------------------------------------------------------------
  if (JWE_SYMMETRIC_ALGS.indexOf(alg) >= 0) {
    const kek = symmetricKek(alg, recipientJwk, header, true);
    if (alg === 'dir') {
      // RFC 7518 section 4.5: the shared key IS the content encryption key and
      // encrypted_key is empty. The LENGTH is therefore decided by `enc`, and
      // a mismatch is refused here rather than by the cipher, which reports it
      // as a buffer size.
      const spec = JWE_ENCS[header.enc];
      if (spec && kek.length !== spec.cekBytes) {
        throw new Error('encryptJweCompact: alg "dir" uses the shared key AS ' +
          'the content encryption key, so it must be exactly ' +
          spec.cekBytes + ' bytes for ' + header.enc + '; this one is ' +
          kek.length + '.');
      }
      log.debug('Leaving wrapCek(). Direct.');
      return { cek: kek, encryptedKey: Buffer.alloc(0) };
    }
    if (JWE_AESGCMKW_ALGS.indexOf(alg) >= 0) {
      // Section 4.7: AES-GCM over the CEK, with the IV and the tag carried in
      // the header rather than in the encrypted_key segment.
      const iv = nodeCrypto.randomBytes(12);
      // A GCM cipher; the name is built, so the checker cannot see the mode.
      const cipher = /** @type {import('crypto').CipherGCM} */ (
        nodeCrypto.createCipheriv('aes-' + (kek.length * 8) + '-gcm', kek,
                                  iv));
      const wrapped = Buffer.concat([cipher.update(cek), cipher.final()]);
      header.iv = b64u(iv);
      header.tag = b64u(cipher.getAuthTag());
      log.debug('Leaving wrapCek(). AES-GCM key wrap.');
      return { cek: cek, encryptedKey: wrapped };
    }
    log.debug('Leaving wrapCek(). AES key wrap.');
    return { cek: cek, encryptedKey: aesKeyWrap(kek, cek) };
  }

  const publicKey = nodeCrypto.createPublicKey({ key: recipientJwk,
                                                 format: 'jwk' });

  if (alg === 'RSA-OAEP' || alg === 'RSA-OAEP-256') {
    const wrapped = nodeCrypto.publicEncrypt({
      key: publicKey,
      padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: alg === 'RSA-OAEP' ? 'sha1' : 'sha256'
    }, cek);
    log.debug('Leaving wrapCek(). RSA.');
    return { cek: cek, encryptedKey: wrapped };
  }

  // ECDH-ES, direct or with AES key wrapping.
  const curve = EC_CURVES[recipientJwk.crv];
  if (!curve) {
    log.debug('Leaving wrapCek(). Unknown curve.');
    throw new Error('encryptJweCompact: the recipient key names curve "' +
      recipientJwk.crv + '", and this service agrees over ' +
      Object.keys(EC_CURVES).join(', ') + '.');
  }
  const ephemeral = nodeCrypto.generateKeyPairSync('ec', { namedCurve: curve });
  const z = nodeCrypto.diffieHellman({ privateKey: ephemeral.privateKey,
                                       publicKey: publicKey });
  const epk = ephemeral.publicKey.export({ format: 'jwk' });
  header.epk = { kty: epk.kty, crv: epk.crv, x: epk.x, y: epk.y };
  if (alg === 'ECDH-ES') {
    // Direct agreement: the derived key IS the CEK and encrypted_key is empty.
    // The AlgorithmID is the content encryption `enc`, and the key data length
    // is the WHOLE CEK — both halves, for a CBC-HMAC enc.
    log.debug('Leaving wrapCek(). ECDH-ES direct.');
    return { cek: concatKdf(z, cek.length, header.enc, header),
             encryptedKey: Buffer.alloc(0) };
  }
  const kek = concatKdf(z, ECDH_KW_BYTES[alg], alg, header);
  log.debug('Leaving wrapCek(). ' + alg + '.');
  return { cek: cek, encryptedKey: aesKeyWrap(kek, cek) };
}

/**
 * Encrypts a plaintext as a compact JWE.
 *
 * @param plaintext - the plaintext
 * @param opts - `alg` (`JWE_ALG` by default; ML-KEM and HPKE since #82),
 *   `enc` (left out for HPKE Integrated Encryption), `jwk` (the recipient's
 *   key) or `secret`, `typ`, `cty`, `zip`, and `psk` / `pskId` for HPKE
 * @returns the compact JWE
 * @throws Error for an unsupported `alg`, `enc` or key
 */
function encryptJweCompact(plaintext, opts) {
  log.debug("Entering encryptJweCompact().");
  const options = opts || {};
  log.debug('Entering encryptJweCompact(). alg=' + (options.alg || JWE_ALG) +
            ', enc=' + options.enc);
  // HPKE INTEGRATED ENCRYPTION HAS NO `enc` (jose-hpke-encrypt-22 section
  // 5), so it is answered before the `enc` check below — a caller that
  // passes the `enc` a client registered beside an Integrated alg (OpenID
  // Connect Registration defaults one) gets it left out, not refused.
  if (isIntegratedJweAlg(options.alg)) {
    const out = encryptJweIntegrated(plaintext, options);
    log.debug('Leaving encryptJweCompact(). HPKE Integrated Encryption.');
    return out;
  }
  const spec = JWE_ENCS[options.enc];
  if (!spec) {
    log.debug('Leaving encryptJweCompact(). Unknown enc.');
    throw new Error('encryptJweCompact: unsupported enc "' + options.enc +
                    '"; this service encrypts with ' +
                    Object.keys(JWE_ENCS).join(', ') + '.');
  }
  const alg = options.alg || JWE_ALG;
  const random = nodeCrypto.randomBytes(spec.cekBytes);
  // Sixteen octets — one AES block — for CBC, twelve for GCM. A CBC-HMAC JWE
  // carrying a 12-byte IV is refused by every other implementation.
  const iv = nodeCrypto.randomBytes(spec.mode === 'cbc-hmac' ? 16 : 12);
  const header = { alg: alg, enc: options.enc, typ: options.typ || 'JWT' };
  if (options.cty) {
    header.cty = options.cty;
  }
  // RFC 7516 section 4.1.3's `zip`, DEF alone (RFC 7518 section 7.3: raw
  // DEFLATE, RFC 1951), applied to the plaintext BEFORE it is sealed (#187:
  // OpenID4VCI section 8.2's Credential Response compression, which a wallet
  // asks for from `zip_values_supported`). Anything else is refused by name.
  let body = Buffer.from(plaintext, 'utf8');
  if (options.zip !== undefined && options.zip !== null &&
      options.zip !== '') {
    if (options.zip !== 'DEF') {
      log.debug('Leaving encryptJweCompact(). Unsupported zip.');
      throw new Error('encryptJweCompact: unsupported zip "' + options.zip +
                      '"; this service compresses with DEF only.');
    }
    header.zip = 'DEF';
    body = zlib.deflateRawSync(body);
  }
  if (options.jwk && options.jwk.kid) {
    header.kid = options.jwk.kid;
  }
  // A SECRET is the other way of naming the key, and it is the only way for
  // the symmetric families: `jwk` means "the recipient's public key" and a
  // shared secret is neither public nor the recipient's alone. One member per
  // kind rather than one member holding either, so a caller cannot pass a
  // public JWK to `dir` and get a key derived from its JSON.
  const keyMaterial = JWE_SYMMETRIC_ALGS.indexOf(alg) >= 0
    ? options.secret
    : options.jwk;
  // wrapCek() may WRITE to the header (the ECDH-ES variants add `epk`), so the
  // header is serialised after it and not before — the AAD has to be the bytes
  // that actually go out, and an epk added after the AAD was taken would make
  // every tag fail at the far end.
  const wrapped = wrapCek(alg, keyMaterial, random, header, options);
  const headerB64 = b64u(Buffer.from(JSON.stringify(header), 'utf8'));

  const sealed = sealContent(spec, wrapped.cek, iv,
      Buffer.from(headerB64, 'ascii'), body);

  const compact = [headerB64, b64u(wrapped.encryptedKey), b64u(iv),
                   b64u(sealed.ciphertext), b64u(sealed.tag)].join('.');
  log.debug('Leaving encryptJweCompact(). ' + compact.length + ' characters.');
  return compact;
}

// ---------------------------------------------------------------------------
// HPKE INTEGRATED ENCRYPTION, AS A COMPACT JWE (#82): the header has `alg`
// and no `enc`; the second segment is the encapsulated secret; the IV and
// tag segments are EMPTY; the ciphertext is HPKE's (with its tag inside).
// `zip` works as it does for any other alg — the plaintext is compressed
// before it is sealed (jose-hpke-encrypt-22 section 7.1, step 12).
// ---------------------------------------------------------------------------
function encryptJweIntegrated(plaintext, options) {
  log.debug('Entering encryptJweIntegrated(). alg=' + options.alg);
  const header = { alg: options.alg, typ: options.typ || 'JWT' };
  if (options.cty) {
    header.cty = options.cty;
  }
  let body = Buffer.from(plaintext, 'utf8');
  if (options.zip !== undefined && options.zip !== null &&
      options.zip !== '') {
    if (options.zip !== 'DEF') {
      log.debug('Leaving encryptJweIntegrated(). Unsupported zip.');
      throw new Error('encryptJweCompact: unsupported zip "' + options.zip +
                      '"; this service compresses with DEF only.');
    }
    header.zip = 'DEF';
    body = zlib.deflateRawSync(body);
  }
  if (options.jwk && options.jwk.kid) {
    header.kid = options.jwk.kid;
  }
  const psk = joseHpkePsk(options, header, true);
  const headerB64 = b64u(Buffer.from(JSON.stringify(header), 'utf8'));
  const sealed = hpkeIntegratedSeal(options.alg, options.jwk, headerB64, body,
                                    options, psk);
  const compact = [headerB64, b64u(sealed.encryptedKey), '',
                   b64u(sealed.ciphertext), ''].join('.');
  log.debug('Leaving encryptJweIntegrated(). ' + compact.length +
            ' characters.');
  return compact;
}

// ---------------------------------------------------------------------------
// THE KEY MANAGEMENT HALF OF A DECRYPT — `wrapCek()` read backwards.
//
// It is a function of its own rather than a branch inside `decryptJweCompact()`
// for the reason `wrapCek()` is: the two halves of one algorithm have to be
// able to be read against each other, and an ECDH-ES agreement that derived a
// key one way at one end and another way at the other is the failure that is
// hardest to see — everything parses, and the authentication tag does not
// verify.
//
// It THROWS a sentence rather than a code. Every caller wraps it and says what
// could not be unwrapped.
// ---------------------------------------------------------------------------
function unwrapCek(header, encryptedKey, options, spec) {
  log.debug('Entering unwrapCek(). alg=' + header.alg);
  const alg = String(header.alg);

  if (JWE_SYMMETRIC_ALGS.indexOf(alg) >= 0) {
    if (options.secret === undefined || options.secret === null ||
        options.secret === '') {
      throw new Error('alg "' + alg + '" is encrypted to a SHARED SECRET and ' +
        'this caller holds none for the sender. A client that encrypts to ' +
        'this service should use RSA-OAEP-256 against the key in its JWKS, ' +
        'or one of the symmetric algorithms with the client_secret as the ' +
        'key.');
    }
    const kek = symmetricKek(alg, options.secret, header, false);
    if (alg === 'dir') {
      log.debug('Leaving unwrapCek(). Direct.');
      return kek;
    }
    if (JWE_AESGCMKW_ALGS.indexOf(alg) >= 0) {
      if (!header.iv || !header.tag) {
        throw new Error('a ' + alg + ' JWE carries the key wrapping\'s IV ' +
          'and authentication tag in the header as `iv` and `tag` (RFC 7518 ' +
          'section 4.7.1); this one has ' +
          (header.iv ? 'no tag' : (header.tag ? 'no iv' : 'neither')) + '.');
      }
      // RFC 7518 section 4.7.1: a 96-bit `iv` and a 128-bit `tag`, and a
      // shorter tag is refused rather than checked — see openContent().
      const wrapIv = Buffer.from(String(header.iv), 'base64url');
      const wrapTag = Buffer.from(String(header.tag), 'base64url');
      if (wrapIv.length !== 12 || wrapTag.length !== 16) {
        throw new Error('a ' + alg + ' JWE carries a 96-bit `iv` and a ' +
          '128-bit `tag` (RFC 7518 section 4.7.1); this one has ' +
          (wrapIv.length * 8) + ' and ' + (wrapTag.length * 8) + ' bits.');
      }
      // A GCM decipher; the name is built, so the checker cannot see the mode.
      const decipher = /** @type {import('crypto').DecipherGCM} */ (
        nodeCrypto.createDecipheriv(
          /** @type {import('crypto').CipherGCMTypes} */
          ('aes-' + (kek.length * 8) + '-gcm'), kek, wrapIv,
          { authTagLength: 16 }));
      decipher.setAuthTag(wrapTag);
      const out = Buffer.concat([decipher.update(encryptedKey),
                                 decipher.final()]);
      log.debug('Leaving unwrapCek(). AES-GCM key wrap.');
      return out;
    }
    const out = aesKeyUnwrap(kek, encryptedKey);
    log.debug('Leaving unwrapCek(). AES key wrap.');
    return out;
  }

  // ML-KEM and HPKE Key Encryption (section 4a): the private key is an AKP
  // JWK (`privateJwk`) or, for the classical HPKE suites, an EC or OKP key.
  if (JWE_PQ_KEM_TABLE[alg]) {
    const out = unwrapCekPq(alg, header, encryptedKey, options, spec);
    log.debug('Leaving unwrapCek(). ' + alg + '.');
    return out;
  }

  if (!options.privateKey) {
    throw new Error('alg "' + alg + '" is encrypted to a PRIVATE KEY and ' +
      'this caller was given none.');
  }

  if (JWE_RSA_ALGS.indexOf(alg) >= 0) {
    // The OAEP digest is what the `alg` says and NOT node's default, which is
    // SHA-1 — an unwrap under the wrong digest fails, and it fails in the way
    // an unwrap under the wrong KEY fails, so the two are indistinguishable
    // from the message. See wrapCek().
    const out = nodeCrypto.privateDecrypt({
      key: options.privateKey,
      padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: alg === 'RSA-OAEP' ? 'sha1' : 'sha256'
    }, encryptedKey);
    log.debug('Leaving unwrapCek(). RSA.');
    return out;
  }

  // ECDH-ES, direct or with AES key wrapping. The sender's EPHEMERAL public
  // key is in the header and there is no agreement without it.
  if (!header.epk || !header.epk.crv) {
    throw new Error('an ECDH-ES JWE carries the sender\'s ephemeral public ' +
      'key in the header as `epk` (RFC 7518 section 4.6.1.1) and this one ' +
      'has none.');
  }
  if (!EC_CURVES[header.epk.crv]) {
    throw new Error('the ephemeral key names curve "' + header.epk.crv +
      '", and this service agrees over ' + Object.keys(EC_CURVES).join(', ') +
      '.');
  }
  const senderKey = nodeCrypto.createPublicKey({ key: header.epk,
                                                 format: 'jwk' });
  const z = nodeCrypto.diffieHellman({ privateKey: options.privateKey,
                                       publicKey: senderKey });
  if (alg === 'ECDH-ES') {
    // The AlgorithmID is the content encryption `enc` and the length is the
    // WHOLE CEK — both halves for a CBC-HMAC enc, which is why this needs the
    // spec and the RSA branch does not.
    if (!spec) {
      throw new Error('alg "ECDH-ES" derives the content encryption key at ' +
        'the length `enc` names, and ' +
        '"' + header.enc + '" is not one this ' +
        'service knows.');
    }
    const out = concatKdf(z, spec.cekBytes, header.enc, header);
    log.debug('Leaving unwrapCek(). ECDH-ES direct.');
    return out;
  }
  const kek = concatKdf(z, ECDH_KW_BYTES[alg], alg, header);
  const out = aesKeyUnwrap(kek, encryptedKey);
  log.debug('Leaving unwrapCek(). ' + alg + '.');
  return out;
}

// ---------------------------------------------------------------------------
// DECRYPT A COMPACT JWE. `opts`:
//
//   privateKey    a node KeyObject — RSA for the two RSA-OAEP algorithms, EC
//                 for the four ECDH-ES ones, EC or X25519/X448 for the
//                 classical HPKE suites.
//   privateJwk    a private JWK, for section 4a's algorithms (#82): the AKP
//                 key (`priv` the seed) an ML-KEM or post-quantum HPKE alg
//                 is decrypted with, or an EC / OKP JWK for classical HPKE.
//   psk           HPKE mode_psk only: the pre-shared key, or a function of
//                 the header's decoded `psk_id` returning it.
//   secret        the shared key for the symmetric families: a Buffer, an oct
//                 JWK, or a string whose UTF-8 bytes are the key (which is
//                 what a `client_secret` is). See secretBytes().
//   allowedAlg    the `alg` values this caller accepts. OPTIONAL, and narrower
//                 than the table: a caller that holds only one kind of key
//                 should say so, because "this service can do PBES2" and "this
//                 endpoint will accept a PBES2 assertion" are different claims.
//   allowedEnc    the `enc` values this endpoint accepts. Required.
//   expectedKid   when set, the header's kid must equal it. Checking it is
//                 what makes key rotation DETECTABLE: this service regenerates
//                 its keys on every start in development mode (and on a
//                 rotation in product mode), so a wallet holding a stale one is
//                 told exactly that instead of getting an opaque decryption
//                 failure it will blame on its own code.
//
// It THROWS with a sentence a caller can hand to a client, because every
// failure here is the far end's document being wrong and the OID4VCI error
// responses quote the message directly.
// ---------------------------------------------------------------------------
/**
 * Decrypts a compact JWE.
 *
 * @param compact - the compact JWE
 * @param opts - `privateKey` (a KeyObject), `privateJwk` (an ML-KEM or HPKE
 *   key, #82) or `secret`; `allowedAlg`, `allowedEnc`, `expectedKid`, and
 *   `psk` for HPKE mode_psk. An HPKE Integrated JWE carries no `enc`.
 * @returns `{ header, plaintext }`
 * @throws Error with a sentence a caller can hand to a client
 */
function decryptJweCompact(compact, opts) {
  log.debug("Entering decryptJweCompact().");
  const options = opts || {};
  log.debug('Entering decryptJweCompact().');
  const parts = String(compact || '').trim().split('.');
  if (parts.length !== 5) {
    log.debug('Leaving decryptJweCompact(). Not five parts.');
    throw new Error('an encrypted request must be a JWE in compact ' +
      'serialization (five dot-separated parts); this ' +
      'has ' + parts.length + '.');
  }
  let header;
  try {
    header = JSON.parse(strictBase64url(parts[0], 'JWE protected header')
      .toString('utf8'));
  } catch (e) {
    log.debug('Leaving decryptJweCompact(). The header is not JSON.');
    throw new Error('the JWE protected header is not valid base64url JSON: ' +
                    e.message);
  }
  if (String(header.alg) === 'RSA1_5') {
    // Named rather than left to fall off the end of the list, because a caller
    // that sent one has an implementation that offers it and needs to know
    // this is a refusal rather than an omission. See the table above.
    log.debug('Leaving decryptJweCompact(). RSA1_5.');
    throw new Error('this service does not decrypt RSA1_5, deliberately: ' +
      'RFC 8017 deprecated PKCS#1 v1.5 encryption, and implementing it ' +
      'safely means making an unwrap failure indistinguishable from every ' +
      'later failure, which is a property of a whole code path rather than ' +
      'of one function. Use RSA-OAEP-256.');
  }
  if (JWE_DECRYPT_ALGS.indexOf(header.alg) === -1) {
    log.debug('Leaving decryptJweCompact(). Wrong alg.');
    throw new Error('this service decrypts with alg ' +
      JWE_DECRYPT_ALGS.join(', ') +
      '; the request used "' + header.alg + '".');
  }
  // The CALLER's own narrowing, checked after the table's. Two messages
  // because they are two different refusals: one says this service cannot,
  // the other says this endpoint will not.
  if (options.allowedAlg && options.allowedAlg.indexOf(header.alg) === -1) {
    log.debug('Leaving decryptJweCompact(). The caller does not accept that ' +
              'alg.');
    throw new Error('this endpoint accepts alg ' +
      options.allowedAlg.join(', ') +
      '; the request used "' + header.alg + '".');
  }
  // HPKE INTEGRATED ENCRYPTION (#82) has no `enc` and no CEK: after the
  // alg refusals above and the kid check, it is opened whole by section 4a.
  // A caller's `allowedEnc` does not apply to it — there is nothing for it
  // to narrow — and its `allowedAlg` already has.
  if (isIntegratedJweAlg(header.alg)) {
    const integrated = decryptJweIntegrated(parts, header, options);
    log.debug('Leaving decryptJweCompact(). HPKE Integrated Encryption.');
    return integrated;
  }
  const allowed = options.allowedEnc || Object.keys(JWE_ENCS);
  if (allowed.indexOf(header.enc) === -1) {
    log.debug('Leaving decryptJweCompact(). Unsupported enc.');
    throw new Error('this service supports enc ' + allowed.join(' or ') +
      '; the request used "' + header.enc + '".');
  }
  if (header.zip) {
    // Refused rather than ignored: a compressed payload that is silently read
    // as though it were not compressed is a parse error three frames away.
    log.debug('Leaving decryptJweCompact(). Compressed.');
    throw new Error('this service advertises no zip_values_supported, so a ' +
      'compressed request cannot be read.');
  }
  if (options.expectedKid && header.kid !== options.expectedKid) {
    log.debug('Leaving decryptJweCompact(). Wrong kid.');
    throw new Error('the JWE kid "' + (header.kid || '(absent)') + '" is not ' +
      'this service\'s current encryption key ' +
      '"' + options.expectedKid + '". Re-read the ' +
      'metadata — from the same trust realm, since each realm has a key of ' +
      'its own: this key is regenerated when the service restarts in ' +
      'development mode and when it is rotated.');
  }

  // Every other segment strictly (see strictBase64url()), once the header
  // has been read and its refusals by NAME given — a JWE whose tag or IV has
  // a stray character must not open as though it had none.
  for (let i = 1; i < 5; i++) {
    try {
      strictBase64url(parts[i], ['', 'JWE encrypted key', 'JWE IV',
                                 'JWE ciphertext', 'JWE tag'][i]);
    } catch (e) {
      log.debug('Leaving decryptJweCompact(). A segment is not base64url.');
      throw e;
    }
  }
  const spec = JWE_ENCS[header.enc];
  let cek;
  try {
    cek = unwrapCek(header, Buffer.from(parts[1], 'base64url'), options, spec);
  } catch (e) {
    log.debug('Leaving decryptJweCompact(). The key would not unwrap.');
    throw new Error('the content encryption key could not be unwrapped: ' +
      e.message);
  }
  if (cek.length !== spec.cekBytes) {
    // The wrong-key case, and it is checked rather than left to the cipher for
    // the reason the XML decryption above checks the same thing: an unwrap that
    // succeeds with the wrong length is a wrong key, and saying so beats a
    // cipher error about a buffer size. Note a CBC-HMAC CEK is TWICE the AES
    // key size, which is why this reads cekBytes and not bits/8.
    log.debug('Leaving decryptJweCompact(). The key is the wrong size.');
    throw new Error('the unwrapped content encryption key is ' + cek.length +
        ' ' +
        'bytes; ' +
      header.enc + ' needs ' + spec.cekBytes + '.');
  }

  let plaintext;
  try {
    plaintext = openContent(spec, cek, Buffer.from(parts[2], 'base64url'),
      Buffer.from(parts[0], 'ascii'), Buffer.from(parts[3], 'base64url'),
      Buffer.from(parts[4], 'base64url')).toString('utf8');
  } catch (e) {
    // An authentication tag failure lands here, and it is the interesting case:
    // the ciphertext or the header was altered in flight.
    log.debug('Leaving decryptJweCompact(). The tag did not verify.');
    throw new Error('the ciphertext did not decrypt or its authentication ' +
      'tag did not verify: ' + e.message);
  }
  log.debug('Leaving decryptJweCompact(). ' + plaintext.length +
            ' characters.');
  return { header: header, plaintext: plaintext };
}

// The Integrated half of `decryptJweCompact()`: the same refusals in the
// same order as the rest of it (zip, kid, strict segments), then HPKE.
function decryptJweIntegrated(parts, header, options) {
  log.debug('Entering decryptJweIntegrated(). alg=' + header.alg);
  if (header.zip) {
    log.debug('Leaving decryptJweIntegrated(). Compressed.');
    throw new Error('this service advertises no zip_values_supported, so a ' +
      'compressed request cannot be read.');
  }
  if (options.expectedKid && header.kid !== options.expectedKid) {
    log.debug('Leaving decryptJweIntegrated(). Wrong kid.');
    throw new Error('the JWE kid "' + (header.kid || '(absent)') + '" is not ' +
      'this service\'s current encryption key "' + options.expectedKid +
      '". Re-read the metadata.');
  }
  for (let i = 1; i < 5; i++) {
    strictBase64url(parts[i], ['', 'JWE encrypted key', 'JWE IV',
                               'JWE ciphertext', 'JWE tag'][i]);
  }
  let plaintext;
  try {
    plaintext = hpkeIntegratedOpen(String(header.alg), header, parts[0],
                                   parts, options).toString('utf8');
  } catch (e) {
    log.debug('Leaving decryptJweIntegrated(). Did not open: ' + e.message);
    throw new Error('the HPKE Integrated Encryption JWE did not decrypt: ' +
                    e.message);
  }
  log.debug('Leaving decryptJweIntegrated(). ' + plaintext.length +
            ' characters.');
  return { header: header, plaintext: plaintext };
}

// ===========================================================================
// SECTION 5 — KEYS, CERTIFICATES, THUMBPRINTS
// ===========================================================================

// ---------------------------------------------------------------------------
// A USER AGENT'S FINGERPRINT, for CAEP's `fp_ua` (#145, 2026-09-22): "a
// fingerprint of the user agent computed by the Transmitter". The
// base64url SHA-256 of the `User-Agent` header as it arrived — stable for one
// browser, so a receiver can see that a session was presented from a
// different agent than it was established from, and not the header itself,
// which would hand every receiver a string nobody asked it to hold. '' for no
// header, which leaves the member out.
// ---------------------------------------------------------------------------
/**
 * Returns a User-Agent's fingerprint for CAEP's `fp_ua`: the base64url
 * SHA-256 of the header as it arrived.
 *
 * @param userAgent - the header's value
 * @returns the fingerprint, or empty for no header
 */
function userAgentFingerprint(userAgent) {
  log.debug('Entering userAgentFingerprint().');
  const text = String(userAgent || '');
  if (!text) {
    log.debug('Leaving userAgentFingerprint(). No user agent.');
    return '';
  }
  log.debug('Leaving userAgentFingerprint().');
  return nodeCrypto.createHash('sha256').update(text, 'utf8')
    .digest('base64url');
}

// ---------------------------------------------------------------------------
// A CREDENTIAL'S FINGERPRINT, for the authentication event (#62 P0,
// 2026-09-22): the base64url SHA-256 of a credential identifier as the caller
// holds it — a WebAuthn credential id (itself base64url), a certificate's
// SHA-256 thumbprint. `userAgentFingerprint()`'s reason, one field over: the
// event has to say WHICH key answered, so that a later sign-in can be told to
// be the same one, and it has no business holding the identifier itself —
// a session row is copied into logs, pages and the change log. '' for none.
// ---------------------------------------------------------------------------
/**
 * Returns a credential's fingerprint for the authentication event: the
 * base64url SHA-256 of its identifier.
 *
 * @param identifier - a WebAuthn credential id or certificate thumbprint
 * @returns the fingerprint, or empty for none
 */
function credentialFingerprint(identifier) {
  log.debug('Entering credentialFingerprint().');
  const text = String(identifier || '');
  if (!text) {
    log.debug('Leaving credentialFingerprint(). No identifier.');
    return '';
  }
  log.debug('Leaving credentialFingerprint().');
  return nodeCrypto.createHash('sha256').update(text, 'utf8')
    .digest('base64url');
}

// ---------------------------------------------------------------------------
// THE FIRST `chars` HEX CHARACTERS OF A SHA-256, for JA4 (#62 P0,
// 2026-09-22), whose second and third parts are "a 12 character truncated
// sha256 hash" of a comma-joined list (FoxIO's JA4 specification). A
// truncation of a digest this file computes, rather than a digest computed
// by the caller: the rule is that this service hashes here.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// A PASSWORD AS THE PWNED PASSWORDS RANGE API KEYS IT (#62 P6): SHA-1, upper-
// case hex. **NOT A SECURITY USE OF SHA-1** — nothing is signed, stored or
// compared with it; it is the key the Have I Been Pwned corpus is indexed
// by, and only its first five characters leave this process
// (`common/breached_passwords.ts`, k-anonymity). Here because every digest of
// a secret this service computes is computed in this file.
// ---------------------------------------------------------------------------
/**
 * Returns the SHA-1 digest of a password the Have I Been Pwned corpus is
 * indexed by; only its first five characters ever leave this process.
 *
 * @param password - the password
 * @returns the upper-case hex digest
 */
function pwnedPasswordDigest(password) {
  log.debug('Entering pwnedPasswordDigest().');
  log.debug('Leaving pwnedPasswordDigest().');
  return nodeCrypto.createHash('sha1').update(String(password || ''), 'utf8')
    .digest('hex').toUpperCase();
}

/**
 * Returns the first `chars` hex characters of a SHA-256, as JA4 uses.
 *
 * @param text - the text hashed, as UTF-8
 * @param chars - how many characters, at most 64
 * @returns the truncated digest
 */
function truncatedSha256Hex(text, chars) {
  log.debug('Entering truncatedSha256Hex().');
  const hex = nodeCrypto.createHash('sha256')
    .update(String(text || ''), 'utf8').digest('hex');
  log.debug('Leaving truncatedSha256Hex().');
  return hex.slice(0, Math.max(0, Math.min(64, Number(chars) || 0)));
}

// ---------------------------------------------------------------------------
// WHICH CERTIFICATE THIS IS, IN THE TWO STRINGS A RECEIVER MATCHES ON (#145,
// 2026-09-22): the issuer's distinguished name and the serial number, the
// pair RFC 5280 section 4.1.2.2 makes unique — a serial alone is unique only
// per issuer. CAEP's credential-change carries them as `x509_issuer` and
// `x509_serial` for any change to an X.509 credential.
//
// The issuer is an RFC 4514 string (most specific RDN first); node's
// `X509Certificate#issuer` lists the RDNs, already escaped, one per line in
// the order the certificate encodes them, which is the reverse. The
// serial is lower-case hex with no separators, the form `common/pki.js`
// records as `serialHex`, so an event and the register name one certificate
// the same way. Answers empty strings for anything that is not
// a certificate; it never throws, because every caller is reporting a change
// that has already happened.
// ---------------------------------------------------------------------------
/**
 * Returns the issuer, serial and subject a receiver matches a certificate
 * on. Never throws.
 *
 * @param pem - the certificate
 * @returns `{ issuer, serial, subject }`, empty strings for anything that is
 *   not a certificate
 */
function certificateIdentifiers(pem) {
  log.debug('Entering certificateIdentifiers().');
  let cert = null;
  try {
    cert = new nodeCrypto.X509Certificate(String(pem || ''));
  } catch (e) {
    log.debug('Caught in certificateIdentifiers(): ' +
              ((e && e.message) || e));
    // Not a certificate: nothing to identify, and the event goes without.
    log.debug('Leaving certificateIdentifiers(). Not a certificate.');
    return { issuer: '', serial: '', subject: '' };
  }
  // Node writes each RDN already escaped (OpenSSL's RFC 2253 flags), so only
  // the ORDER is changed here — escaping again would double every backslash.
  const rfc4514 = function (text) {
    return String(text || '').split('\n')
      .filter(function (one) { return one !== ''; })
      .reverse().join(',');
  };
  const issuer = rfc4514(cert.issuer);
  const serial = String(cert.serialNumber || '').toLowerCase()
    .replace(/^(00)+(?=[0-9a-f])/, '');
  log.debug('Leaving certificateIdentifiers().');
  // The SUBJECT too, the same way: for a CA's own certificate it is the
  // issuer of everything that CA signs, which is what a caller holding only
  // a leaf's serial needs.
  return { issuer: issuer, serial: serial, subject: rfc4514(cert.subject) };
}

// ---------------------------------------------------------------------------
// A CERTIFICATE SERIAL NUMBER, AND WHY IT CANNOT BE THE CONSTANT IT WAS.
//
// Every certificate this service minted was — until every key pair became a
// leaf of `common/pki.js` on 2026-09-11 — self-signed, regenerated on every
// start, and carried a subject that never varied: `CN=localhost, O=sts` for
// the listeners' one. The serial was a CONSTANT beside all that: '02' for the
// signing key, '03' for the TLS server certificate, '04' for the ML-DSA one.
// So two starts of this service produced two DIFFERENT KEYS under one
// (issuer, serial) pair, and that pair is the primary key NSS files a
// certificate under.
//
// Firefox therefore refuses the second one outright, before any trust decision
// is offered and with no way past it:
//
//     SEC_ERROR_REUSED_ISSUER_AND_SERIAL
//
// — which is not a trust warning a person can accept, it is a database
// conflict, and it says nothing about this service. Chrome and curl do not
// keep that index and never showed it, which is why this survived: the failure
// appears only in the browser, only after a restart, and only once somebody
// has trusted an earlier copy. Two of these processes running at once (a mock
// beside a test stack) collide the same way with no restart at all.
//
// So the serial is random — 128 bits, the CA/Browser Forum's number, which is
// also what `common/vendored/x509.js` already mints for every SPIFFE SVID.
//
// WHAT THE CONSTANT WAS FOR IS KEPT, because it was a real thing rather than
// laziness: a person looking at a packet capture, or at two PEM files, could
// tell this service's certificates apart by their serial alone. The caller's
// byte is now the leading byte of a random serial rather than the whole of it,
// so `02…`, `03…` and `04…` still say which certificate this is and the
// remaining fifteen bytes make it unique. The top bit of that byte is clear
// for all three, which keeps the DER INTEGER positive without the leading zero
// byte some parsers then report as a seventeen-byte serial.
// ---------------------------------------------------------------------------
/**
 * Returns a random certificate serial number, its first byte the caller's
 * prefix, kept positive.
 *
 * @param prefixHex - the leading byte(s), as hex; none when omitted
 * @returns the serial, as hex
 */
function certificateSerial(prefixHex) {
  log.debug('Entering certificateSerial(). prefix=' + (prefixHex || '(none)'));
  let prefix = String(prefixHex === undefined || prefixHex === null
    ? '' : prefixHex).replace(/[^0-9a-fA-F]/g, '');
  if (prefix.length % 2) {
    prefix = '0' + prefix;
  }
  // A prefix of 0x80 or more would make the INTEGER negative. Rather than
  // silently rewriting the caller's byte — which would break the one property
  // the prefix exists for — the top bit is cleared, which is what
  // x509.js's randomSerialHex() does to its own first byte.
  let head = prefix
    ? Buffer.from(prefix, 'hex')
    : Buffer.from([nodeCrypto.randomBytes(1)[0] || 1]);
  head[0] = head[0] & 0x7f;
  if (head[0] === 0) {
    head[0] = 1;
  }
  const tail = nodeCrypto.randomBytes(Math.max(1, 16 - head.length));
  const serial = Buffer.concat([head, tail]).toString('hex');
  log.debug('Leaving certificateSerial(). serial=' + serial);
  return serial;
}

// ---------------------------------------------------------------------------
// AN RSA KEY AND A SELF-SIGNED CERTIFICATE OVER IT.
//
// Two copies of this existed — `helpers.makeStsKeys()` for the signing key and
// `tls/tls_server.js`'s `makeServerCertificate()` for the listeners' — and they
// were not gratuitous copies: one is a signing certificate with no extensions
// at all and the other is a TLS server certificate that lives or dies by its
// subjectAltName. What they shared was the whole RSA keygen-and-self-sign
// skeleton, which is the part worth having once.
//
// So the differences are PARAMETERS and the skeleton is here. `extensions` is
// passed through to forge untouched rather than being modelled, because the
// two callers want disjoint sets and a third will want a third — modelling it
// would be inventing a certificate profile language for two users.
//
// A THIRD generator is deliberately NOT folded in: `spiffe/spiffe_ca.ts` issues
// through `common/vendored/x509.js` because **node-forge cannot sign with an EC
// key at all** and SPIFFE issues P-256. That is a capability gap, not a
// duplication, and `common/vendored/CLAUDE.md` records it.
// ---------------------------------------------------------------------------
// A forge key pair over an RSA private key given as PEM (PKCS#1 or PKCS#8 —
// node reads either and forge is handed PKCS#1, which is what it writes).
function rsaPairFromPem(pem) {
  log.debug("Entering rsaPairFromPem().");
  const pkcs1 = nodeCrypto.createPrivateKey(pem)
                          .export({ type: 'pkcs1', format: 'pem' });
  const privateKey = forge.pki.privateKeyFromPem(pkcs1);
  log.debug("Leaving rsaPairFromPem().");
  return { privateKey: privateKey,
           publicKey: forge.pki.setRsaPublicKey(privateKey.n, privateKey.e) };
}

/**
 * Makes a self-signed RSA certificate, and its key pair.
 *
 * @param opts - `commonName`, `organizationName`, `bits`, `years`,
 *   `extensions`, `serialNumber` or `serialPrefix`, and `rsaPrivateKeyPem`
 *   to certify an existing key
 * @returns `{ privateKeyPem, publicKeyPem, certPem, certB64, notBefore,
 *   notAfter }`
 */
function selfSignedRsaCertificate(opts) {
  log.debug("Entering selfSignedRsaCertificate().");
  const options = opts || {};
  log.debug('Entering selfSignedRsaCertificate(). cn=' +
            (options.commonName || '(none)'));
  // `rsaPrivateKeyPem` (2026-09-14) is a key a caller generated ASYNCHRONOUSLY
  // — `helpers.js`'s `prepareKeySet()`, in node's thread pool — so that a
  // burst of realms does not stop this process for a tenth of a second each.
  // forge's generation is node's synchronous one underneath; the certificate
  // built over a given key is the same certificate in every other respect.
  const pair = options.rsaPrivateKeyPem
    ? rsaPairFromPem(options.rsaPrivateKeyPem)
    : forge.pki.rsa.generateKeyPair({ bits: options.bits || 2048,
                                      e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = pair.publicKey;
  // `serialPrefix` is the caller's LEADING BYTE because it is how a person
  // tells two of this service's certificates apart in a packet capture, and
  // they are otherwise identical self-signed RSA certificates minted seconds
  // apart. The rest is random — see certificateSerial() for the browser
  // failure that a constant serial produced. `serialNumber` is still honoured
  // verbatim for a caller that means one exact value.
  cert.serialNumber = options.serialNumber ||
      certificateSerial(options.serialPrefix || '01');
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(
    cert.validity.notBefore.getFullYear() + (options.years || 5));
  const attrs = [{ name: 'commonName', value: options.commonName || 'sts' }];
  if (options.organizationName) {
    attrs.push({ name: 'organizationName', value: options.organizationName });
  }
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  if (options.extensions && options.extensions.length) {
    cert.setExtensions(options.extensions);
  }
  cert.sign(pair.privateKey, forge.md.sha256.create());
  const certPem = forge.pki.certificateToPem(cert);
  log.debug('Leaving selfSignedRsaCertificate().');
  return {
    privateKeyPem: forge.pki.privateKeyToPem(pair.privateKey),
    publicKeyPem: forge.pki.publicKeyToPem(pair.publicKey),
    certPem: certPem,
    certB64: stripPem(certPem),
    // The validity window, because a caller that PUBLISHES a certificate has to
    // be able to say when it stops working — `GET /tls` prints `notAfter` so
    // somebody who put this in a truststore knows how long it is good for.
    // Returned rather than re-parsed out of the PEM by the caller, which would
    // be a second reading of a value this function just decided.
    notBefore: cert.validity.notBefore,
    notAfter: cert.validity.notAfter
  };
}

// ---------------------------------------------------------------------------
// AN ML-DSA KEY AND A SELF-SIGNED CERTIFICATE OVER IT (FIPS 204, RFC 9881).
//
// WHY THIS IS WRITTEN OUT HERE AND NOT VENDORED FROM THE DEBUGGER, which is
// the same argument pq_jose.js makes at length and which applies with more
// force to a certificate: this service exists to be the FAR END of the
// debugger's own PKI code. The debugger builds a post-quantum certificate with
// pkijs and signs it with @noble/post-quantum; if this service did the same,
// the two would share one reading of RFC 9881 — of where the OID goes, of
// whether the AlgorithmIdentifier carries a NULL, of what the BIT STRING holds
// — agree with each other perfectly, and interoperate with nothing.
//
// So the two halves here are deliberately the ones the debugger does NOT use:
//
//   * the KEY and the SIGNATURE come from node's OpenSSL 3.5, which has
//     ML-DSA natively. `crypto.generateKeyPairSync('ml-dsa-65')` and
//     `crypto.sign(null, tbs, key)` are C code from a different project.
//   * the ENCODING is written below against RFC 9881 section 3 and RFC 5280
//     section 4.1, with asn1js as the DER writer.
//
// The result is that a debugger which verifies this certificate has verified
// something OpenSSL produced, and a debugger whose certificate this service
// accepts has been read by OpenSSL. That is the only kind of check that means
// anything here.
//
// NODE-FORGE CANNOT DO ANY OF THIS. It has no ML-DSA, cannot parse a
// certificate whose signature algorithm it does not know, and cannot sign with
// a key it cannot represent — which is the same capability gap
// `spiffe/spiffe_ca.ts` records for EC keys, one algorithm generation later.
// ---------------------------------------------------------------------------
/** The ML-DSA parameter sets' object identifiers. */
const ML_DSA_OIDS = {
  'ml-dsa-44': '2.16.840.1.101.3.4.3.17',
  'ml-dsa-65': '2.16.840.1.101.3.4.3.18',
  'ml-dsa-87': '2.16.840.1.101.3.4.3.19'
};

// ---------------------------------------------------------------------------
// WHETHER THIS RUNTIME CAN DO ANY OF IT, WHICH IS A QUESTION ABOUT THE
// INTERPRETER AND NOT ABOUT THIS SERVICE.
//
// ML-DSA reaches node with OpenSSL 3.5, which is node 24 — the version this
// repository's Dockerfile pins (24.16.0). On anything older
// `generateKeyPairSync('ml-dsa-65')` throws `ERR_INVALID_ARG_VALUE: The
// argument 'type' must be a supported key type`, a sentence that names neither
// this service, nor the algorithm's real requirement, nor the way out — and it
// throws from wherever it was called, which for `tls_server.js` is a MODULE
// TOP LEVEL. A require that throws takes the whole process down where a route
// could not, which is the rule the root CLAUDE.md states about listeners and
// is exactly what a developer on node 22 met: a mock that would not start
// because of a certificate algorithm nobody was going to connect with.
//
// So the capability is a question anybody can ask BEFORE calling, and it is
// asked by DOING IT rather than by comparing `process.versions` — the version
// is a proxy for what the linked OpenSSL has, and a node built against a
// different one would make the proxy lie. ML-DSA-44 is the cheapest of the
// three parameter sets and a keygen is well under a millisecond; the answer is
// cached because the interpreter does not acquire the algorithm later.
// ---------------------------------------------------------------------------
let mlDsaProbe = null;

/**
 * Says whether this runtime can generate ML-DSA keys; the reason it cannot
 * is logged once.
 *
 * @returns true when it can
 */
function mlDsaAvailable() {
  log.debug('Entering mlDsaAvailable().');
  if (mlDsaProbe === null) {
    try {
      nodeCrypto.generateKeyPairSync('ml-dsa-44');
      mlDsaProbe = true;
    } catch (e) {
      // EXPECTED on any runtime older than node 24, and it is the whole
      // purpose of this function to turn that throw into an answer. The reason
      // is logged once rather than swallowed, because a service that silently
      // stopped offering a configured algorithm would be the worse failure.
      mlDsaProbe = false;
      log.warn(errorCodes.tag('STS-KEYS-0003') +
               'crypto: this runtime cannot generate ML-DSA keys (' +
               e.message + '). Node ' + process.versions.node +
               ' is linked against OpenSSL ' + process.versions.openssl +
               '; ML-DSA needs OpenSSL 3.5, which is node 24 — this ' +
               'repository pins 24.16.0 in its Dockerfile. Every ' +
               'post-quantum algorithm here needs it since #363, the JOSE ' +
               'ones included (common/pq_native.js).');
    }
  }
  log.debug('Leaving mlDsaAvailable(). ' + mlDsaProbe);
  return mlDsaProbe;
}

function mlDsaOid(algorithm) {
  log.debug('Entering mlDsaOid(). algorithm=' + algorithm);
  const oid = ML_DSA_OIDS[String(algorithm || '').toLowerCase()];
  if (!oid) {
    log.debug('Leaving mlDsaOid(). Unknown.');
    throw new Error('Not an ML-DSA parameter set this service knows: ' +
                    algorithm + '. RFC 9881 defines ML-DSA-44, -65 and -87.');
  }
  log.debug('Leaving mlDsaOid().');
  return oid;
}

// The three DN attribute OIDs this builder writes, and the string type each
// one takes. `C` MUST be a PrintableString and everything else here is a
// UTF8String: a country encoded as UTF8String parses perfectly and is refused
// by several validators, which reads as a signature problem.
const DN_TYPES = {
  commonName: { oid: '2.5.4.3', printable: false },
  organizationName: { oid: '2.5.4.10', printable: false },
  countryName: { oid: '2.5.4.6', printable: true }
};

/**
 * Makes an ML-DSA key pair and a self-signed certificate over it (FIPS 204,
 * RFC 9881). Needs a runtime that can generate ML-DSA keys.
 *
 * @param opts - `algorithm`, `commonName`, `organizationName`, `dnsNames`,
 *   `ipAddresses`, `years`, and `serialNumber` or `serialPrefix`
 * @returns `{ algorithm, privateKeyPem, publicKeyPem, certPem, certB64,
 *   notBefore, notAfter }`
 */
function selfSignedMlDsaCertificate(opts) {
  log.debug("Entering selfSignedMlDsaCertificate().");
  const options = opts || {};
  const algorithm = String(options.algorithm || 'ml-dsa-65').toLowerCase();
  log.debug('Entering selfSignedMlDsaCertificate(). algorithm=' + algorithm +
            ' cn=' + (options.commonName || '(none)'));
  const oid = mlDsaOid(algorithm);
  // CHECKED HERE AS WELL AS BY THE CALLER, because this is the door: a caller
  // that forgot to ask should still meet a sentence naming the algorithm, the
  // runtime and the requirement rather than node's `ERR_INVALID_ARG_VALUE`,
  // which names an argument called `type`.
  if (!mlDsaAvailable()) {
    log.debug('Leaving selfSignedMlDsaCertificate(). Unsupported runtime.');
    throw new Error('This runtime cannot generate an ' + algorithm +
                    ' key, so no ML-DSA certificate can be built here. Node ' +
                    process.versions.node + ' is linked against OpenSSL ' +
                    process.versions.openssl + '; ML-DSA needs OpenSSL 3.5, ' +
                    'which is node 24 — this repository pins 24.16.0, and ' +
                    'every post-quantum algorithm here needs it (#363).');
  }
  // `any`: the algorithm is a variable, and the overloads want literals.
  const pair = /** @type {any} */ (nodeCrypto.generateKeyPairSync)(algorithm);
  const spkiDer = pair.publicKey.export({ type: 'spki', format: 'der' });

  function bufferOf(bytes) {
    log.debug("Entering bufferOf().");
    const view = Uint8Array.from(bytes);
    log.debug("Leaving bufferOf().");
    return view.buffer.slice(view.byteOffset, view.byteOffset +
        view.byteLength);
  }

  function algorithmIdentifier() {
    log.debug("Entering algorithmIdentifier().");
    log.debug("Leaving algorithmIdentifier().");
    // PARAMETERS ABSENT — RFC 9881 section 3 says MUST, and an explicit NULL
    // here (which is what an RSA identifier carries, so it is what a copied
    // line produces) makes a certificate OpenSSL refuses to load at all.
    return new asn1js.Sequence({
      value: [new asn1js.ObjectIdentifier({ value: oid })]
    });
  }

  function name(attributes) {
    log.debug("Entering name().");
    log.debug("Leaving name().");
    // An RDNSequence — a SEQUENCE OF one-element SETs — and not one SET
    // holding every attribute. The second is a multi-valued RDN, which is a
    // DIFFERENT NAME: it parses, it prints with + between the attributes, and
    // nothing chains to it.
    return new asn1js.Sequence({
      value: attributes.map(function (attribute) {
        const type = DN_TYPES[attribute.name];
        const value = type.printable
          ? new asn1js.PrintableString({ value: attribute.value })
          : new asn1js.Utf8String({ value: attribute.value });
        return new asn1js.Set({
          value: [new asn1js.Sequence({
            value: [new asn1js.ObjectIdentifier({ value: type.oid }), value]
          })]
        });
      })
    });
  }

  function utcTime(date) {
    log.debug("Entering utcTime().");
    log.debug("Leaving utcTime().");
    return new asn1js.UTCTime({ valueDate: date });
  }

  function extension(extnOid, critical, valueAsn1) {
    log.debug("Entering extension().");
    const der = new Uint8Array(valueAsn1.toBER(false));
    /** @type {any[]} */
    const value = [new asn1js.ObjectIdentifier({ value: extnOid })];
    if (critical) value.push(new asn1js.Boolean({ value: true }));
    value.push(new asn1js.OctetString({ valueHex: bufferOf(der) }));
    log.debug("Leaving extension().");
    return new asn1js.Sequence({ value: value });
  }

  const attributes = [
    { name: 'commonName', value: options.commonName || 'sts' }
  ];
  if (options.organizationName) {
    attributes.push({ name: 'organizationName',
                     value: options.organizationName });
  }
  const subject = name(attributes);
  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime());
  notAfter.setFullYear(notBefore.getFullYear() + (options.years || 2));

  // subjectAltName: dNSName is [2] and iPAddress is [7], both IMPLICIT and
  // both primitive. The CN is ignored by every current client, so these are
  // not decoration — they are the only place the names are.
  const generalNames = [];
  (options.dnsNames || []).forEach(function (dns) {
    generalNames.push(new asn1js.Primitive({
      idBlock: { tagClass: 3, tagNumber: 2 },
      valueHex: bufferOf(Buffer.from(String(dns), 'utf8'))
    }));
  });
  (options.ipAddresses || []).forEach(function (address) {
    const octets = String(address).split('.').map(function (part) {
      return parseInt(part, 10) & 0xff;
    });
    if (octets.length !== 4) return;
    generalNames.push(new asn1js.Primitive({
      idBlock: { tagClass: 3, tagNumber: 7 },
      valueHex: bufferOf(octets)
    }));
  });

  const extensions = [
    extension('2.5.29.19', true, new asn1js.Sequence({ value: [] })),
    // digitalSignature only: an ML-DSA key cannot encipher anything, so
    // keyEncipherment — which the RSA certificate beside this one sets — would
    // be a lie about the algorithm. RFC 9881 section 4 says the same.
    extension('2.5.29.15', true, new asn1js.BitString({
      valueHex: bufferOf([0x80]), unusedBits: 7 })),
    extension('2.5.29.37', false, new asn1js.Sequence({
      value: [new asn1js.ObjectIdentifier({ value: '1.3.6.1.5.5.7.3.1' })] }))
  ];
  if (generalNames.length) {
    extensions.push(extension('2.5.29.17', false,
        new asn1js.Sequence({ value: generalNames })));
  }

  // Random with the caller's leading byte, for certificateSerial()'s reason:
  // a constant here made two starts of this service two different keys under
  // one (issuer, serial) pair, which Firefox refuses outright.
  const serialHex = String(options.serialNumber ||
      certificateSerial(options.serialPrefix || '04'));
  const serialBytes = Buffer.from(serialHex.length % 2
    ? '0' + serialHex : serialHex, 'hex');

  const tbs = new asn1js.Sequence({
    value: [
      // [0] EXPLICIT version, v3 (2). A v1 certificate cannot carry
      // extensions at all, and a subjectAltName in one is ignored in silence.
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [new asn1js.Integer({ value: 2 })]
      }),
      new asn1js.Integer({ valueHex: bufferOf(serialBytes) }),
      algorithmIdentifier(),
      subject,
      new asn1js.Sequence({ value: [utcTime(notBefore), utcTime(notAfter)] }),
      subject,
      // The SubjectPublicKeyInfo is OpenSSL's own export, parsed in as the DER
      // it already is rather than rebuilt — the one field where a second
      // encoding of the same key would be a second chance to be wrong.
      asn1js.fromBER(bufferOf(spkiDer)).result,
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 3 },
        value: [new asn1js.Sequence({ value: extensions })]
      })
    ]
  });

  const tbsDer = Buffer.from(tbs.toBER(false));
  // `null` as the algorithm is how node asks for the key's own built-in
  // hashing, which is what ML-DSA does: FIPS 204 takes the message, not a
  // digest of it.
  const signature = nodeCrypto.sign(null, tbsDer, pair.privateKey);

  const certificate = new asn1js.Sequence({
    value: [
      tbs,
      algorithmIdentifier(),
      new asn1js.BitString({ valueHex: bufferOf(signature) })
    ]
  });
  const certDer = Buffer.from(certificate.toBER(false));
  const certPem = '-----BEGIN CERTIFICATE-----\n' +
      (certDer.toString('base64').match(/.{1,64}/g) || []).join('\n') +
      '\n-----END CERTIFICATE-----\n';
  // Read back through OpenSSL before it leaves this function. A certificate
  // this service cannot itself load is one the listener would fail to start
  // with, at a point where the error names the socket rather than the encoder.
  new nodeCrypto.X509Certificate(certDer);
  log.debug('Leaving selfSignedMlDsaCertificate(). ' + certDer.length +
            ' bytes.');
  return {
    algorithm: algorithm,
    privateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }),
    certPem: certPem,
    certB64: stripPem(certPem),
    notBefore: notBefore,
    notAfter: notAfter
  };
}

// PEM armour off, whitespace out. What goes inside a <ds:X509Certificate>, and
// what a DER digest is taken over.
/**
 * Takes the PEM armour and whitespace off: what goes inside a
 * `<ds:X509Certificate>`.
 *
 * @param pem - the PEM
 * @returns the base64 body
 */
function stripPem(pem) {
  log.debug("Entering stripPem().");
  log.debug("Leaving stripPem().");
  return String(pem || '').replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

// ---------------------------------------------------------------------------
// RFC 7638 JWK THUMBPRINT.
//
// THERE WERE THREE OF THESE, which is one more than the audit that started this
// work had found: `oauth-oidc/dpop.ts` (hand-built canonical JSON, full member
// table), `spiffe/spiffe_ca.ts` (JSON.stringify over an object literal whose
// keys happen to be in lexicographic order) and `oid4vc/vc_issuer.ts` (the same
// trick, RSA only, inline in a key-generation IIFE).
//
// All three were correct. That is precisely the problem: RFC 7638 is a
// specification whose whole purpose is that two implementations agree, and the
// two that relied on JSON.stringify agreed only because somebody typed the
// members in the right order — a member added out of order later would produce
// a different thumbprint for the same key, and nothing would fail until a
// client's DPoP-bound token stopped matching its own proof.
//
// **ONLY THE LISTED MEMBERS ARE HASHED**, which is the part people get wrong: a
// key carrying `kid`, `alg`, `use` or Web Crypto's `key_ops`/`ext` must hash to
// the same value as the same key without them, because the wallet sends its key
// in every proof header and a stray member would silently break the binding.
//
// **`AKP` JOINED ON 2026-09-13**, for the RFC 9278 `kid` (see
// `common/jose_kid.js`): RFC 9964 names `alg`, `kty` and `pub` as the
// required members of an ML-DSA key's thumbprint, which is what the
// eleven post-quantum and composite keys here are. `alg` is a member for AKP
// where it is not for the other four, because the key bytes alone do not say
// which algorithm they are for. Adding the row changes nothing for DPoP or
// ACME: both refuse a post-quantum algorithm by NAME before a thumbprint is
// asked for, though their comments still give the missing row as the reason.
// ---------------------------------------------------------------------------
const THUMBPRINT_MEMBERS = {
  AKP: ['alg', 'kty', 'pub'],
  EC: ['crv', 'kty', 'x', 'y'],
  RSA: ['e', 'kty', 'n'],
  OKP: ['crv', 'kty', 'x'],
  oct: ['k', 'kty']
};

// The canonical JSON RFC 7638 hashes: the required members, lexicographically
// ordered, no whitespace. Built by hand rather than with JSON.stringify over an
// object, so the order is a property of this list and not of how somebody
// happened to type an object literal.
/**
 * Returns the canonical JSON RFC 7638 hashes: the required members, in
 * order, no whitespace.
 *
 * @param jwk - the key
 * @returns the canonical JSON
 */
function canonicalJwk(jwk) {
  log.debug('Entering canonicalJwk().');
  if (!jwk || !jwk.kty) {
    throw new Error('a JWK Thumbprint needs a key with a kty.');
  }
  const members = THUMBPRINT_MEMBERS[jwk.kty];
  if (!members) {
    throw new Error('no RFC 7638 member list for kty ' + jwk.kty + '.');
  }
  const missing = members.filter(function (m) {
    return jwk[m] === undefined || jwk[m] === null || jwk[m] === '';
  });
  if (missing.length) {
    throw new Error('this ' + jwk.kty + ' key is missing ' +
                    missing.join(', ') + '.');
  }
  log.debug('Leaving canonicalJwk().');
  return '{' + members.map(function (m) {
    return JSON.stringify(m) + ':' + JSON.stringify(jwk[m]);
  }).join(',') + '}';
}

// The thumbprint itself. `opts.truncate` shortens it for the two callers that
// use one as a `kid` rather than as a binding — a kid only has to be unique
// within a JWKS, and a shorter one is readable in a log. DPoP's `jkt` must
// never be truncated: it is compared byte for byte against a value the client
// computed, so it takes the default.
/**
 * Returns a JWK's RFC 7638 thumbprint, SHA-256, base64url.
 *
 * @param jwk - the key
 * @param opts - `truncate`, for a `kid`; never for DPoP's `jkt`
 * @returns the thumbprint
 */
function jwkThumbprint(jwk, opts) {
  log.debug("Entering jwkThumbprint().");
  const options = opts || {};
  const digest = nodeCrypto.createHash('sha256')
    .update(canonicalJwk(jwk), 'utf8').digest('base64url');
  log.debug("Leaving jwkThumbprint().");
  return options.truncate ? digest.slice(0, options.truncate) : digest;
}

// RFC 9278 section 3: the JWK Thumbprint URI. Always SHA-256 and never
// truncated — the URI is compared as a whole string, and a shortened digest
// under a `sha-256` label would name a hash nobody can reproduce.
/** The RFC 9278 JWK Thumbprint URI prefix, SHA-256. */
const JWK_THUMBPRINT_URI_PREFIX =
  'urn:ietf:params:oauth:jwk-thumbprint:sha-256:';

/**
 * Returns a JWK's RFC 9278 thumbprint URI, never truncated.
 *
 * @param jwk - the key
 * @returns the URI
 */
function jwkThumbprintUri(jwk) {
  log.debug("Entering jwkThumbprintUri().");
  const uri = JWK_THUMBPRINT_URI_PREFIX + jwkThumbprint(jwk);
  log.debug("Leaving jwkThumbprintUri().");
  return uri;
}

// ---------------------------------------------------------------------------
// A SIGNING KEY PAIR AS JWKs (2026-10-01), for an application's DID document:
// the public half goes into the document and the private half is handed to
// the caller once. Three algorithms, the ones a DID document's JsonWebKey2020
// method is conventionally read with: ES256 (P-256, the default), ES384
// (P-384) and EdDSA (Ed25519). The `kid` is the RFC 7638 thumbprint, which is
// what names the method in the document.
// ---------------------------------------------------------------------------
/** The algorithms `generateSigningJwkPair()` takes. */
const SIGNING_JWK_PAIR_ALGS = ['ES256', 'ES384', 'EdDSA'];

/**
 * Generates a signing key pair and returns both halves as JWKs, with the
 * private half also as PKCS#8 PEM.
 *
 * @param alg - ES256, ES384 or EdDSA
 * @returns `{ alg, kid, publicJwk, privateJwk, privateKeyPem }`
 */
function generateSigningJwkPair(alg) {
  log.debug("Entering generateSigningJwkPair(). alg=" + alg);
  const which = String(alg || 'ES256');
  if (SIGNING_JWK_PAIR_ALGS.indexOf(which) < 0) {
    log.debug("Leaving generateSigningJwkPair(). Unknown algorithm.");
    throw new Error('the algorithm must be one of ' +
                    SIGNING_JWK_PAIR_ALGS.join(', ') + ', not ' + which + '.');
  }
  const pair = which === 'EdDSA'
    ? nodeCrypto.generateKeyPairSync('ed25519')
    : nodeCrypto.generateKeyPairSync('ec', {
      namedCurve: which === 'ES384' ? 'P-384' : 'P-256' });
  const publicJwk = pair.publicKey.export({ format: 'jwk' });
  const kid = jwkThumbprint(publicJwk);
  const publicOut = Object.assign({ kid: kid, alg: which, use: 'sig' },
                                  publicJwk);
  const privateOut = Object.assign({ kid: kid, alg: which, use: 'sig' },
                                   pair.privateKey.export({ format: 'jwk' }));
  log.debug("Leaving generateSigningJwkPair(). kid=" + kid);
  return { alg: which, kid: kid, publicJwk: publicOut,
           privateJwk: privateOut,
           privateKeyPem: String(pair.privateKey.export({ type: 'pkcs8',
                                                          format: 'pem' })) };
}

// ---------------------------------------------------------------------------
// A CERTIFICATE'S SHA-256 THUMBPRINT, over the DER, in whichever spelling the
// specification that asked for it uses.
//
// There were three of these too, and unlike the JWK thumbprints they are NOT
// interchangeable — which is why this takes a format rather than picking one:
//
//   base64url   RFC 8705 `x5t#S256`, the mTLS certificate binding. Compared
//               byte for byte against a client's confirmation claim.
//   hex         SPIRE's `local authority id`, truncated to 16.
//   colon-hex   what `openssl x509 -fingerprint -sha256` prints, which is what
//               a person is holding when they compare one by eye.
//
// Three formats of one digest was never the duplication. Three functions each
// computing that digest was.
//
// A PEM STRING MAY BE A CHAIN, and taking the first certificate out of it is
// the one thing this function must not skip. `tls.certificateFile` has been
// allowed to be a bundle since it started being supplied from outside, and the
// stack that supplies it hands over a leaf, its issuing CA and the root, in
// that order. stripPem() removes every `-----…-----` line, so a bundle came out
// as three DERs joined end to end and the digest was over the join: a value
// that is not the thumbprint of any certificate, that no tool will ever print —
// not `openssl x509 -fingerprint -sha256`, not node's `fingerprint256`, not
// `x5t#S256` at the far end — and that is nonetheless perfectly stable, so it
// agrees with itself everywhere this service reports it and disagrees only with
// the handshake. It was published on GET /admin/ldap/service and in /tls's
// views as the certificate 636 and the main port present.
//
// The first certificate is the leaf, which is what those sockets present and
// what every consumer of a chain reads; the rest are the path to it.
// ---------------------------------------------------------------------------
/**
 * Returns a certificate's SHA-256 thumbprint over its DER, in the spelling
 * the specification asking for it uses.
 *
 * @param certificate - the certificate, or a chain whose first is the leaf
 * @param opts - `format` and `truncate`
 * @returns the thumbprint
 */
function certificateThumbprint(certificate, opts) {
  log.debug("Entering certificateThumbprint().");
  const options = opts || {};
  let der;
  if (Buffer.isBuffer(certificate)) {
    der = certificate;
  } else if (certificate && certificate.raw) {
    // A node `X509Certificate`, which is what a TLS socket hands over.
    der = certificate.raw;
  } else {
    const first = String(certificate == null ? '' : certificate).match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
    // No BEGIN line at all is a bare base64 DER, which several callers pass
    // (an `x5c` member, most of all), so stripPem() is still the fallback.
    der = Buffer.from(stripPem(first ? first[0] : certificate), 'base64');
  }
  const format = options.format || 'base64url';
  let out;
  if (format === 'hex') {
    out = nodeCrypto.createHash('sha256').update(der).digest('hex');
  } else if (format === 'colon-hex') {
    const hex = nodeCrypto.createHash('sha256')
                          .update(der)
                          .digest('hex')
                          .toUpperCase();
    out = (hex.match(/.{2}/g) || []).join(':');
  } else {
    out = nodeCrypto.createHash('sha256').update(der).digest('base64url');
  }
  log.debug("Leaving certificateThumbprint().");
  return options.truncate ? out.slice(0, options.truncate) : out;
}

// ---------------------------------------------------------------------------
// A CERTIFICATE'S KEY, NOT THE CERTIFICATE: SHA-256 over the DER of its
// SubjectPublicKeyInfo, base64url (#164, 2026-09-26).
//
// `certificateThumbprint()` above hashes the WHOLE certificate, which is what
// RFC 8705's `x5t#S256` binds to — and it changes every time the same key is
// re-certified. A device holds a KEY across renewals (EST's /simplereenroll
// keeps it), and the device register recognises the device by the key, so its
// thumbprint must survive a new certificate over the same key. This is the
// digest RFC 7469 pins and SPIFFE bundles call a key's identity.
//
// READ WITH asn1js RATHER THAN node's `X509Certificate#publicKey`, because
// node cannot load an ML-DSA or SLH-DSA key out of a certificate today, and a
// device certificate this service's own post-quantum Issuing CA signed would
// then have no thumbprint at all. The SPKI is the seventh field of the
// TBSCertificate (the sixth when the optional `[0] version` is absent, a v1
// certificate), and its bytes are taken as they were decoded rather than
// re-encoded, so the digest is over what the issuer signed.
//
// Throws for anything that is not a certificate; the one caller refuses the
// key with its own code and sentence.
// ---------------------------------------------------------------------------
/**
 * Returns the SHA-256 of a certificate's SubjectPublicKeyInfo DER,
 * base64url: its key, not the certificate.
 *
 * @param certificate - the certificate
 * @returns the thumbprint
 * @throws Error for anything that is not a certificate
 */
function certificateSpkiThumbprint(certificate) {
  log.debug("Entering certificateSpkiThumbprint().");
  const text = String(certificate == null ? '' : certificate);
  const first = text.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
  const der = new Uint8Array(Buffer.from(stripPem(first ? first[0] : text),
                                         'base64'));
  const parsed = asn1js.fromBER(der.buffer);
  const top = /** @type {any} */ (parsed.result);
  const outer = parsed.offset === -1 || !top || !top.valueBlock
    ? [] : (top.valueBlock.value || []);
  const tbs = outer.length === 3 ? outer[0] : null;
  const fields = tbs && tbs.valueBlock ? (tbs.valueBlock.value || []) : [];
  const versioned = fields.length > 0 && fields[0].idBlock.tagClass === 3 &&
                    fields[0].idBlock.tagNumber === 0;
  const spki = fields[versioned ? 6 : 5];
  if (!spki || !spki.idBlock || spki.idBlock.tagNumber !== 16 ||
      !spki.valueBlock || (spki.valueBlock.value || []).length !== 2) {
    log.debug("Leaving certificateSpkiThumbprint(). Not a certificate.");
    throw new Error('this is not a DER X.509 certificate with a ' +
                    'SubjectPublicKeyInfo where RFC 5280 puts it.');
  }
  const view = spki.valueBeforeDecodeView;
  const spkiDer = view && view.byteLength
    ? Buffer.from(view.buffer, view.byteOffset, view.byteLength)
    : Buffer.from(spki.toBER(false));
  log.debug("Leaving certificateSpkiThumbprint().");
  return nodeCrypto.createHash('sha256').update(spkiDer).digest('base64url');
}

// ---------------------------------------------------------------------------
// THE SAME DIGEST FROM A KEY RATHER THAN A CERTIFICATE (#432, 2026-10-03):
// SHA-256 over the key's SubjectPublicKeyInfo DER, base64url — so a GNAP
// client key presented as a JWK or inside a certificate can be matched to a
// device's x509 key, whose thumbprint `certificateSpkiThumbprint()` gave it.
// node's own SPKI export, because the key is already a KeyObject here; a key
// node cannot export throws, and the caller matches by what it has left.
// ---------------------------------------------------------------------------
/**
 * Returns the SHA-256 of a public key's SubjectPublicKeyInfo DER, base64url —
 * the digest `certificateSpkiThumbprint()` gives the key in a certificate.
 *
 * @param publicKey - a node KeyObject (public, or private to take its public
 *   half)
 * @returns the thumbprint
 * @throws Error for a key node cannot export as SPKI
 */
function publicKeySpkiThumbprint(publicKey) {
  log.debug("Entering publicKeySpkiThumbprint().");
  const key = publicKey && publicKey.type === 'private'
    ? nodeCrypto.createPublicKey(publicKey) : publicKey;
  const der = key.export({ type: 'spki', format: 'der' });
  log.debug("Leaving publicKeySpkiThumbprint().");
  return nodeCrypto.createHash('sha256').update(der).digest('base64url');
}

// ---------------------------------------------------------------------------
// COMPARE TWO SECRETS WITHOUT LEAKING THEIR LENGTH OR THEIR PREFIX.
//
// `crypto.timingSafeEqual()` THROWS when the two buffers differ in length,
// which is the trap both previous copies had to work around and one of them
// worked around by testing the length first — so the length is compared in
// variable time before the contents are compared in constant time. That is the
// correct shape and it is worth saying why it is not a hole: the length of a
// client secret is not the secret, and there is no constant-time comparison of
// two strings of different lengths to be had.
// ---------------------------------------------------------------------------
/**
 * Compares two secrets in constant time; only a length difference is
 * found in variable time.
 *
 * @param a - one value
 * @param b - the other
 * @returns true when they are equal
 */
function constantTimeEquals(a, b) {
  log.debug("Entering constantTimeEquals().");
  const left = Buffer.from(String(a == null ? '' : a), 'utf8');
  const right = Buffer.from(String(b == null ? '' : b), 'utf8');
  if (left.length !== right.length) {
    log.debug("Leaving constantTimeEquals().");
    return false;
  }
  log.debug("Leaving constantTimeEquals().");
  return nodeCrypto.timingSafeEqual(left, right);
}

// ---------------------------------------------------------------------------
// THE ONE-TIME PASSWORD PRIMITIVE: RFC 4226 SECTION 5.3 (2026-09-10).
//
// **IT IS HERE FOR THE REASON EVERYTHING ELSE IN THIS FILE IS HERE.** An HOTP
// value is an HMAC truncated to N digits, and an HMAC is a keyed signature —
// so this is the fourth thing this service signs with, and the rule this
// module was written to enforce is that there is one place it happens. A
// `createHmac` in `common/totp.ts` would be the fifth call site of a
// cryptographic primitive outside the one module that is supposed to hold
// them all, and the argument against that is the same argument the six XML
// signers lost in 2026-08-27.
//
// **WHAT IS NOT HERE IS THE POLICY**, and the split is exactly the one every
// other pair in this file makes: this function is handed a key, a counter and
// a shape, and it answers with digits. It does not know what a time step is,
// how wide a skew window an operator allows, whether a code has been spent
// before, or what base32 is. `common/totp.ts` owns all four, because all four
// are decisions about a deployment rather than about an algorithm — which is
// why that module can be read for the mechanism's behaviour and this one for
// its arithmetic.
//
// THE TRUNCATION IS RFC 4226's AND IT IS FIDDLY ENOUGH TO BE WORTH NAMING.
// The low four bits of the LAST byte of the digest are an offset; four bytes
// are read from there; the top bit of the first of them is masked off, because
// the RFC's reference implementation is Java and Java has no unsigned int; and
// the result is taken modulo 10^digits. Every one of those four steps has been
// got wrong by somebody, which is why the RFC publishes test vectors and why
// `tests/totp.js` asserts this function against them rather than against
// itself.
//
// **THE COUNTER IS EIGHT BYTES, BIG-ENDIAN, AND IT IS WRITTEN AS A BigInt.**
// A TOTP counter is the Unix time divided by the step, which fits in 53 bits
// for the next several million years — so `Number` would do — but the RFC
// says the HMAC input is a 64-bit counter and a 64-bit counter is what this
// writes. `writeBigUInt64BE` is the only way to say that without arithmetic
// that would be wrong at the boundary nobody will ever reach.
// ---------------------------------------------------------------------------

// The digest algorithms an authenticator app may be asked for. SHA-1 is FIRST
// and is the default, which is the one place in this service where the oldest
// algorithm is the recommended one — and it is not a lapse. RFC 6238 section
// 1.2 names HMAC-SHA-1 as the default, the `otpauth://` URI convention that
// every authenticator app reads treats it as the default, and **Google
// Authenticator, the app most people will point at the QR code this service
// draws, ignores the `algorithm` parameter entirely and always computes
// SHA-1**. A deployment that chose SHA-256 here would produce a QR code that
// scans perfectly and then generates codes this service rejects, with nothing
// anywhere saying why.
//
// The other two are offered because the specification defines them and a
// client author may be testing exactly that, and `/admin/totp` says the above
// beside the setting rather than leaving somebody to discover it.
/** The digests an authenticator app may be asked for; SHA-1 is the default. */
const HOTP_ALGS = {
  SHA1: { hash: 'sha1', bytes: 20,
          note: 'RFC 6238 section 1.2\'s default, and what every ' +
                'authenticator app assumes. HMAC-SHA-1 here is a 30-second ' +
                'keyed MAC over a counter and not a collision-resistant ' +
                'digest, which is why SHA-1\'s weaknesses do not reach it.' },
  SHA256: { hash: 'sha256', bytes: 32,
            note: 'RFC 6238 section 1.2. Interoperable with authenticators ' +
                  'that read the otpauth `algorithm` parameter and broken ' +
                  'with the several that ignore it.' },
  SHA512: { hash: 'sha512', bytes: 64,
            note: 'RFC 6238 section 1.2, same caveat as SHA-256.' }
};

/**
 * Returns the HOTP digest an algorithm name names.
 *
 * @param algorithm - `SHA1` (the default), `SHA256` or `SHA512`
 * @returns `{ name, hash }`
 * @throws Error for any other name
 */
function hotpSpec(algorithm) {
  log.debug("Entering hotpSpec().");
  const name = String(algorithm || 'SHA1').toUpperCase();
  const spec = HOTP_ALGS[name];
  if (!spec) {
    throw new Error('hotp: "' + algorithm + '" is not one of ' +
                    Object.keys(HOTP_ALGS).join(', ') + '.');
  }
  log.debug("Leaving hotpSpec().");
  return { name: name, hash: spec.hash };
}

// RFC 4226 section 5.3. `key` is the shared secret as BYTES — the base32 an
// authenticator app is given is an encoding of it and is `totp.js`'s business,
// not this function's.
/**
 * Computes an HOTP code (RFC 4226 section 5.3).
 *
 * @param key - the shared secret, as bytes
 * @param counter - the counter
 * @param opts - `digits` and `algorithm`
 * @returns the code
 */
function hotpCode(key, counter, opts) {
  log.debug('Entering hotpCode(). counter=' + String(counter));
  const options = opts || {};
  const spec = hotpSpec(options.algorithm);
  const digits = Math.max(6, Math.min(10, Number(options.digits || 6)));
  const material = Buffer.isBuffer(key) ? key :
                   Buffer.from(String(key), 'utf8');
  if (!material.length) {
    throw new Error('hotp: the shared secret is empty, so no code can be ' +
                    'derived from it.');
  }
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = nodeCrypto.createHmac(spec.hash, material)
                           .update(message)
                           .digest();
  // The dynamic truncation, step by step and named, because a one-liner here
  // is the version nobody can check against the RFC.
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) |
                 ((digest[offset + 1] & 0xff) << 16) |
                 ((digest[offset + 2] & 0xff) << 8) |
                 (digest[offset + 3] & 0xff);
  const code = String(binary % Math.pow(10, digits)).padStart(digits, '0');
  log.debug('Leaving hotpCode(). ' + digits + ' digits, ' + spec.name + '.');
  return code;
}

// ---------------------------------------------------------------------------
// PASSWORD AND CLIENT-SECRET HASHING (2026-09-06).
//
// **THIS SERVICE STORED NO SECRET IT COULD VERIFY UNTIL PRODUCT MODE ARRIVED,
// AND ONE IT COULD NOT HIDE.** `userPassword` was a name in the directory's
// attribute list that nothing ever wrote; `oauthClientSecret` was a real value
// held IN THE CLEAR, which is why the pages that dump every attribute had to be
// moved behind the console's gate on 2026-09-01. Both are hashed now, and they
// go through the same pair for the reason everything cryptographic in this
// service goes through this file: one place that decides the algorithm, the
// parameters and the comparison.
//
// **SCRYPT, NOT A DIGEST.** A password is low-entropy and a fast hash over one
// is a wordlist away from being the password. Node has scrypt built in, it is
// memory-hard, and RFC 7914 is the specification — so there is no dependency to
// add and nothing to get wrong beyond the parameters, which are named below
// rather than left at defaults so that a reader can see what they are.
//
// **THE STORED FORM CARRIES ITS OWN PARAMETERS.** `$scrypt$N$r$p$salt$hash`,
// modelled on the Modular Crypt Format every Unix password file uses, so that
// raising the cost later does not invalidate what is already stored: an old
// value verifies against the parameters IT names, and is rewritten at the next
// successful sign-in if a caller asks for that. A bare hash with the parameters
// in a constant somewhere is the version of this that cannot be changed.
//
// **THE COMPARISON IS CONSTANT-TIME** — `constantTimeEquals()` above, the same
// one every other secret comparison here uses. A byte-by-byte early return on a
// password check is a timing oracle, and it is the kind that gets written by
// accident because `===` is right for everything else.
//
// WHAT CANNOT BE HASHED, and the distinction is the one thing to get right
// before reaching for these functions: **a secret this service VERIFIES is
// hashed, and a secret it must PRESENT cannot be.** An application's client
// secret is verified here, so it is hashed and is shown to an operator exactly
// once, at the moment it is created — which is what every real identity
// provider does and is now forced rather than chosen. A FEDERATION
// relationship's `fedClientSecret` is the opposite case: this service sends it
// to somebody else's token endpoint, so it has to be recoverable and hashing it
// would simply break the relationship. `federation/CLAUDE.md` carries that.
// ---------------------------------------------------------------------------

// RFC 7914's parameters. N is the cost, r the block size, p the parallelism.
// 2^15 keeps a single verification around 100ms on the machines this runs on,
// which is the usual trade: slow enough to be expensive in bulk, fast enough
// that a sign-in does not feel broken.
const SCRYPT_N = 32768;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 32;
const SCRYPT_SALT_BYTES = 16;
// scrypt needs memory proportional to 128 * N * r, and node's default limit is
// below what N=2^15 wants — so `maxmem` is raised explicitly rather than left
// to fail at the first hash with an error about memory that says nothing about
// passwords. It is computed from the parameters in `scryptParameters()` below
// since those became settings; it was the constant `128 * N * r * 2`.

// ---------------------------------------------------------------------------
// THE COST OF A NEW HASH IS A SETTING SINCE 2026-09-12, AND THE CONSTANTS ABOVE
// ARE ITS DEFAULTS AND ITS FLOOR.
//
// `security.passwordHashLogN`, `security.passwordHashR` and
// `security.passwordHashP` decide what the NEXT hash is written under. What is
// already stored is untouched by construction — `$scrypt$N$r$p$salt$hash`
// names its own parameters, so `verifySecret()` recomputes against those and
// never reads these — which is the whole reason the stored form was made
// self-describing in the first place.
//
// **THE FLOOR IS ENFORCED HERE AS WELL AS IN THE TABLE.** `config.js` refuses a
// logN under 14 from every door it guards, and this still clamps, because the
// one thing this module must never do is WRITE a hash cheaper than it
// promises: a value that reached `config.value()` some way the table did not
// check would otherwise be a credential store quietly getting weaker. N is set
// as a power of two because scrypt refuses anything else, and a setting that
// could hold 30000 would be one that fails at the first sign-in.
//
// **A LEAF STILL.** `config` is the one module here this file already reads and
// it requires nothing back, so reading three more rows moves no require.
// ---------------------------------------------------------------------------
const SCRYPT_MIN_LOG_N = 14;
const SCRYPT_MAX_LOG_N = 20;

function clampInt(value, low, high, fallback) {
  log.debug("Entering clampInt().");
  const n = Number(value);
  if (value === '' || value === null || value === undefined || !isFinite(n)) {
    log.debug("Leaving clampInt().");
    return fallback;
  }
  log.debug("Leaving clampInt().");
  return Math.max(low, Math.min(high, Math.floor(n)));
}

/**
 * Returns the scrypt cost the settings name now, clamped.
 *
 * @returns `{ N, r, p, keylen, maxmem }`
 */
function scryptParameters() {
  log.debug("Entering scryptParameters().");
  const logN = clampInt(config.value('security.passwordHashLogN'),
                        SCRYPT_MIN_LOG_N, SCRYPT_MAX_LOG_N,
                        Math.log2(SCRYPT_N));
  const r = clampInt(config.value('security.passwordHashR'), 8, 16, SCRYPT_R);
  const p = clampInt(config.value('security.passwordHashP'), 1, 8, SCRYPT_P);
  const n = Math.pow(2, logN);
  log.debug("Leaving scryptParameters().");
  return { N: n, r: r, p: p, keylen: SCRYPT_KEYLEN,
           // RFC 7914's memory is 128 * N * r (plus 128 * r * p for the
           // parallel blocks); doubled for headroom exactly as the retired
           // constant was, so node never refuses a cost this file chose.
           maxmem: 2 * 128 * r * (n + p) };
}

// ---------------------------------------------------------------------------
// ENCRYPTING KEY MATERIAL AT REST (2026-09-06). AES-256-GCM under a
// key-encryption key this service never generates and never stores.
//
// **THIS IS THE OTHER HALF OF PRODUCT MODE'S KEY STORY.** Development mode
// generates a signing key on every start and keeps it in memory, which is what
// makes a mock disposable; product mode generates it ONCE, writes it to the
// persistence store, and reads it back on the next start — so a token issued
// yesterday still verifies today. What is written down is a PRIVATE KEY, and a
// private key in a database in the clear is the whole system's security in
// whatever protects that database.
//
// **AES-256-GCM AND NOT AES-256-CBC**, and the difference is the one that
// matters here: GCM is authenticated, so a ciphertext somebody altered fails to
// decrypt instead of yielding a subtly different key. A signing key that
// decrypts to the wrong bytes would produce signatures nothing can verify, and
// the failure would surface at a relying party as "the signature is invalid" —
// as far from the cause as it is possible to get.
//
// **THE KEK IS NEVER GENERATED HERE AND NEVER WRITTEN ANYWHERE.** It comes from
// `common/secrets.js` — a file mounted into the container, AWS Secrets Manager,
// GCP Secret Manager, Azure Key Vault or HashiCorp Vault — and this file only
// ever receives it as an argument. That is the same rule every other function
// in this module follows (see the header: every function takes the key it is to
// use as a parameter) and it is what keeps the question "where does the master
// key live" answerable in one place rather than in this one too.
//
// **DATA KEYS, WRAPPED UNDER THE KEK (#391, 2026-10-01): ENVELOPE ENCRYPTION.**
// The KEK never encrypts a value. Each value is encrypted under a DATA
// ENCRYPTION KEY (DEK) — 32 random bytes, one per realm per data class — and
// the DEK is stored WRAPPED under the KEK (`wrapDek()`). A process unwraps the
// DEKs it needs once and holds them; a value names the DEK that sealed it, so
// opening it is a lookup and one AES-256-GCM decryption. Rotating the KEK is
// re-wrapping a handful of DEKs, not re-encrypting the store, and a KEK held
// in a key management service is asked once per DEK, never once per value.
// Until #391 each value was encrypted under HKDF-SHA256(KEK, a random salt):
// no DEK, every value tied directly to the KEK, and that format (version 1)
// is gone — a store written before #391 is recreated, not migrated.
//
// **THE STORED FORM IS SELF-DESCRIBING**, modelled on `hashSecret()` above and
// for the same reason: `$aesgcm$2$<dek id>$<iv>$<tag>$<ciphertext>`, the last
// three base64. The DEK id is base64url and so never holds a `$`. The version
// and the DEK id are the additional authenticated data, so a value moved
// under another DEK's name, or rewritten as another version, does not open.
// The LABEL a caller passes is accounting and is deliberately NOT in the AAD:
// a row is opened under a different label than it was sealed under in places
// (a re-homed entry), and the DEK already binds the realm and the class.
//
// **A WRAPPED DEK IS `$dekwrap$1$<iv>$<tag>$<ciphertext>`**: AES-256-GCM under
// a wrapping key derived ONCE from the KEK (HKDF-SHA256, no salt, info
// `sts dek wrapping v1`), with the DEK's id, scope, realm and class as the
// AAD — so a wrapped DEK copied onto another realm's row does not unwrap. The
// wrapping key is derived rather than the KEK used directly so that a KEK
// longer than 32 bytes is all used, and so that nothing else derived from the
// KEK (`keystore.keyedDigest()`) can ever equal it.
// ---------------------------------------------------------------------------

const DEK_ENVELOPE_VERSION = '2';
const DEK_WRAP_INFO = 'sts dek wrapping v1';
const DEK_DERIVE_INFO = 'sts derived dek v1|';
const DEK_ID_INFO = 'sts derived dek id v1';
const KEK_IV_BYTES = 12;      // NIST SP 800-38D's recommended GCM nonce length.
const KEK_KEY_BYTES = 32;     // AES-256.
const DEK_ID_PATTERN = /^[A-Za-z0-9_.-]{8,200}$/;

// The KEK as bytes, however it arrived. A provider may hand back raw bytes, hex
// or base64 — a human pasting a secret into a vault writes text — so the shape
// is decided here, once, rather than by each of the five adapters.
//
// **A KEK SHORTER THAN 32 BYTES IS REFUSED RATHER THAN PADDED OR STRETCHED.**
// Stretching a short secret would let a four-character password protect every
// signing key this service holds while the log said AES-256, which is exactly
// the kind of comfortable lie this repository refuses everywhere else.
/**
 * Returns the key-encryption key as bytes, from raw bytes, hex or base64.
 *
 * @param value - the key as a provider handed it back
 * @returns the bytes
 * @throws Error for a key shorter than 32 bytes
 */
function kekBytes(value) {
  log.debug('Entering kekBytes().');
  if (Buffer.isBuffer(value)) {
    if (value.length < KEK_KEY_BYTES) {
      throw new Error(errorCodes.tag('STS-KEYS-0002') +
                      'the key-encryption key is ' + value.length + ' bytes ' +
                      'and at least ' + KEK_KEY_BYTES + ' are required');
    }
    log.debug('Leaving kekBytes(). Raw bytes.');
    return value;
  }
  const text = String(value == null ? '' : value).trim();
  if (!text) {
    throw new Error(errorCodes.tag('STS-KEYS-0002') +
                    'the key-encryption key is empty');
  }
  // Hex and base64 are TRIED IN THAT ORDER and only when the whole string is
  // one of them: a 64-character hex string is also valid base64, and reading it
  // as base64 would produce 48 different bytes. Hex first means the
  // unambiguous reading wins.
  if (/^[0-9a-fA-F]+$/.test(text) && text.length >= KEK_KEY_BYTES * 2) {
    log.debug('Leaving kekBytes(). Hex.');
    return Buffer.from(text, 'hex');
  }
  if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(text)) {
    const decoded = Buffer.from(text, 'base64');
    if (decoded.length >= KEK_KEY_BYTES) {
      log.debug('Leaving kekBytes(). Base64.');
      return decoded;
    }
  }
  const raw = Buffer.from(text, 'utf8');
  if (raw.length < KEK_KEY_BYTES) {
    throw new Error(errorCodes.tag('STS-KEYS-0002') +
                    'the key-encryption key decodes to ' + raw.length +
                    ' bytes and at least ' + KEK_KEY_BYTES + ' are required. ' +
                    'Generate one with `openssl rand -base64 32`.');
  }
  log.debug('Leaving kekBytes(). Raw text.');
  return raw;
}

// ---------------------------------------------------------------------------
// THE ACCOUNTING (2026-09-11), AND WHY IT IS IN THIS FILE AND NOT IN
// `admin_stats.js` WHERE EVERY OTHER COUNTER IN THIS SERVICE LIVES.
//
// `/admin/encryption` answers *how much has this service encrypted and
// decrypted*, and the only honest place to count that is the funnel the
// operation actually goes through. **This module may not require
// `admin_stats.js`** — rule 3r: `crypto.js` is a LEAF, it sits UNDER
// `helpers.js`, and `admin_stats.js` requires `helpers.js`, so a require in
// that direction closes a cycle and the symptom arrives somewhere else
// entirely as `recordJwt is not a function`. `setJwtRecorder()` is the shape
// that exists for exactly this problem and it was deliberately NOT used here:
// a slot is what you pay for a require that would close a cycle (rule 3e), and
// the thing being carried is four integers rather than a behaviour, so a
// PLAIN TALLY with a reader is strictly less machinery than an inverted hook.
//
// **THE LABEL IS OPTIONAL AND A CALLER THAT OMITS IT IS COUNTED ANYWAY**, in
// `(unlabelled)`. That is the whole reason the count is taken here rather than
// at the eight call sites: a total assembled from call sites is a total that
// is wrong the first time somebody adds a ninth, and it is wrong SILENTLY —
// the page goes on looking complete. So the funnel owns the total and the
// label owns the breakdown, and a missing label costs a row rather than a
// number.
//
// **IT IS PROCESS-WIDE AND NOT PER REALM**, which the page says in as many
// words. A key-encryption key belongs to the PROCESS — `secrets.js` reads one,
// not one per realm — so a realm-partitioned tally would be counting the
// realm a request happened to be in rather than anything about the key. It is
// also why this survives no restart: these are in-memory integers like every
// other counter here, and `audit.js`'s argument about restarting to clear
// applies unchanged.
// ---------------------------------------------------------------------------
const UNLABELLED = '(unlabelled)';

const kekTally = {
  encryptions: 0,
  decryptions: 0,
  // A decrypt that THREW. Almost always the wrong key-encryption key — a
  // rotated secret, a store carried between deployments — which is why it is
  // its own figure rather than being folded into `decryptions`: a page
  // reporting nine hundred decryptions is reporting something different from
  // one reporting nine hundred decryptions and four hundred failures.
  failures: 0,
  plaintextBytes: 0,
  ciphertextBytes: 0,
  startedAt: Date.now(),
  firstAt: 0,
  lastAt: 0,
  byLabel: Object.create(null)
};

function kekRow(label) {
  log.debug("Entering kekRow().");
  const id = String(label || UNLABELLED);
  if (!kekTally.byLabel[id]) {
    kekTally.byLabel[id] = { label: id, encryptions: 0, decryptions: 0,
                             failures: 0, plaintextBytes: 0,
                             ciphertextBytes: 0, firstAt: 0, lastAt: 0 };
  }
  log.debug("Leaving kekRow().");
  return kekTally.byLabel[id];
}

function countKek(label, what, plainBytes, cipherBytes) {
  log.debug("Entering countKek().");
  const now = Date.now();
  const row = kekRow(label);
  kekTally[what] += 1;
  row[what] += 1;
  kekTally.plaintextBytes += plainBytes || 0;
  kekTally.ciphertextBytes += cipherBytes || 0;
  row.plaintextBytes += plainBytes || 0;
  row.ciphertextBytes += cipherBytes || 0;
  if (!kekTally.firstAt) {
    kekTally.firstAt = now;
  }
  if (!row.firstAt) {
    row.firstAt = now;
  }
  kekTally.lastAt = now;
  row.lastAt = now;
  log.debug("Leaving countKek().");
}

// What has been encrypted and decrypted under the key-encryption key, and how
// much of it. A DEEP COPY, because a caller that could mutate the tally could
// make this service under-report its own cryptography — and the one caller is
// a console page, which has no business holding a reference to a counter.
/**
 * Returns what has been encrypted and decrypted under the key-encryption
 * key, and how much: a deep copy.
 *
 * @returns the tally by label
 */
function kekAccounting() {
  log.debug("Entering kekAccounting().");
  const labels = Object.keys(kekTally.byLabel).map(function (id) {
    const row = kekTally.byLabel[id];
    return { label: row.label, encryptions: row.encryptions,
             decryptions: row.decryptions, failures: row.failures,
             plaintextBytes: row.plaintextBytes,
             ciphertextBytes: row.ciphertextBytes,
             firstAt: row.firstAt, lastAt: row.lastAt };
  }).sort(function (a, b) {
    return (b.encryptions + b.decryptions) - (a.encryptions + a.decryptions) ||
           a.label.localeCompare(b.label);
  });
  log.debug("Leaving kekAccounting().");
  return {
    encryptions: kekTally.encryptions,
    decryptions: kekTally.decryptions,
    failures: kekTally.failures,
    operations: kekTally.encryptions + kekTally.decryptions,
    plaintextBytes: kekTally.plaintextBytes,
    ciphertextBytes: kekTally.ciphertextBytes,
    startedAt: kekTally.startedAt,
    firstAt: kekTally.firstAt,
    lastAt: kekTally.lastAt,
    labels: labels
  };
}

// The parameters themselves, READ OUT OF THIS MODULE rather than written down
// on the page. `/admin/crypto-metadata`'s rule one layer along: an algorithm
// this service performs must be in a table here, so that a page describing it
// cannot go on looking complete while being wrong.
/** The parameters of the envelope encryption at rest, for the pages. */
const KEK_PARAMETERS = {
  envelope: '$aesgcm$2$<dek id>$<iv>$<tag>$<ciphertext>, the last three ' +
            'base64',
  version: DEK_ENVELOPE_VERSION,
  cipher: 'aes-256-gcm',
  keyBits: KEK_KEY_BYTES * 8,
  ivBits: KEK_IV_BYTES * 8,
  tagBits: 128,
  dataKeys: 'one data encryption key per realm per data class, random, ' +
            'stored wrapped: 256-bit for AES-256-GCM, 512-bit for ' +
            'AES-256-SIV (keys.directoryCipher, directory data only)',
  dataCiphers: ['aes-256-gcm', 'aes-256-siv'],
  dekWrap: '$dekwrap$1$<iv>$<tag>$<ciphertext>: AES-256-GCM under ' +
           'HKDF-SHA256(KEK, info "' + DEK_WRAP_INFO + '"), the DEK\'s id, ' +
           'scope, realm and class as additional authenticated data',
  aad: 'the version and the DEK id',
  perRecordSubkey: false
};

/**
 * Says whether a stored value is a sealed value this service wrote (the
 * `$aesgcm$` envelope).
 *
 * @param stored - the value
 * @returns true when it is
 */
function isEncryptedWithKek(stored) {
  log.debug("Entering isEncryptedWithKek().");
  log.debug("Leaving isEncryptedWithKek().");
  return /^\$aes(gcm|siv)\$/.test(String(stored || ''));
}

/**
 * Returns the data encryption key a sealed value names, or null for anything
 * that is not a version-2 envelope.
 *
 * @param stored - the sealed value
 * @returns the DEK id, or null
 */
function dekIdOf(stored) {
  log.debug("Entering dekIdOf().");
  const parts = String(stored || '').split('$');
  if (parts.length !== 7 || (parts[1] !== 'aesgcm' && parts[1] !== 'aessiv') ||
      parts[2] !== DEK_ENVELOPE_VERSION || !DEK_ID_PATTERN.test(parts[3])) {
    log.debug("Leaving dekIdOf(). Not a version-2 envelope.");
    return null;
  }
  log.debug("Leaving dekIdOf().");
  return parts[3];
}

// A DEK as bytes: exactly 32 (AES-256-GCM) or 64 (AES-256-SIV, two AES-256
// keys), or refused, because a short key here would be a value sealed under
// less than the AES-256 every page says it is.
function dekBytes(key) {
  log.debug("Entering dekBytes().");
  if (!Buffer.isBuffer(key) ||
      (key.length !== KEK_KEY_BYTES && key.length !== SIV_KEY_BYTES)) {
    throw new Error('a data encryption key must be ' + KEK_KEY_BYTES +
                    ' or ' + SIV_KEY_BYTES + ' bytes');
  }
  log.debug("Leaving dekBytes().");
  return key;
}

// ---------------------------------------------------------------------------
// AES-SIV (RFC 5297) WITH A 512-BIT KEY — `aes-256-siv`, the cipher
// `keys.directoryCipher` may choose for the data keys of directory data
// (#391). Node exposes no SIV cipher, so it is built here on node's AES: S2V
// is AES-256-CMAC (RFC 4493) under the key's LEFT half, and the encryption is
// AES-256-CTR under its RIGHT half, from the synthetic IV with the two bits
// RFC 5297 section 2.6 clears. Held to Wycheproof's `aes_siv_cmac` vectors by
// `tests/wycheproof.js`.
//
// SIV is DETERMINISTIC: one key, one plaintext and one associated data give
// one ciphertext. So a sealed value carries a random 128-bit NONCE as an
// associated-data component (section 3), and two equal values are two
// different ciphertexts, as under GCM. What SIV adds is MISUSE RESISTANCE: a
// repeated nonce leaks only that two values are equal, where a repeated GCM
// nonce leaks their XOR and the authentication key.
// ---------------------------------------------------------------------------
const SIV_KEY_BYTES = 64;
const SIV_NONCE_BYTES = 16;
const BLOCK = 16;

// AES-256 on one block (the CMAC subkeys).
function aesBlock(key, block) {
  log.debug("Entering aesBlock().");
  const c = nodeCrypto.createCipheriv('aes-256-ecb', key, null);
  c.setAutoPadding(false);
  log.debug("Leaving aesBlock().");
  return Buffer.concat([c.update(block), c.final()]);
}

// Doubling in GF(2^128) (RFC 5297 section 2.3; RFC 4493's subkey step).
function sivDbl(block) {
  log.debug("Entering sivDbl().");
  const out = Buffer.alloc(BLOCK);
  let carry = 0;
  for (let i = BLOCK - 1; i >= 0; i--) {
    out[i] = ((block[i] << 1) | carry) & 0xff;
    carry = block[i] >> 7;
  }
  if (block[0] & 0x80) {
    out[BLOCK - 1] ^= 0x87;
  }
  log.debug("Leaving sivDbl().");
  return out;
}

function xorBlocks(a, b) {
  log.debug("Entering xorBlocks().");
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i];
  }
  log.debug("Leaving xorBlocks().");
  return out;
}

// The 10* padding to a whole block.
function sivPad(bytes) {
  log.debug("Entering sivPad().");
  const out = Buffer.alloc(BLOCK);
  bytes.copy(out);
  out[bytes.length] = 0x80;
  log.debug("Leaving sivPad().");
  return out;
}

// AES-256-CMAC (RFC 4493): the CBC-MAC of the message with its last block
// masked by K1 when whole and padded and masked by K2 when not.
function aesCmac(key, message) {
  log.debug("Entering aesCmac().");
  const k1 = sivDbl(aesBlock(key, Buffer.alloc(BLOCK)));
  const k2 = sivDbl(k1);
  const n = Math.max(1, Math.ceil(message.length / BLOCK));
  const whole = message.length > 0 && message.length % BLOCK === 0;
  const lastStart = (n - 1) * BLOCK;
  const last = whole
    ? xorBlocks(message.subarray(lastStart, lastStart + BLOCK), k1)
    : xorBlocks(sivPad(message.subarray(lastStart)), k2);
  const c = nodeCrypto.createCipheriv('aes-256-cbc', key, Buffer.alloc(BLOCK));
  c.setAutoPadding(false);
  const all = Buffer.concat([c.update(Buffer.concat(
    [message.subarray(0, lastStart), last])), c.final()]);
  log.debug("Leaving aesCmac().");
  return all.subarray(all.length - BLOCK);
}

// S2V (RFC 5297 section 2.4): the associated data components, then the
// plaintext, folded into one 128-bit synthetic IV.
function sivS2v(key, components, plaintext) {
  log.debug("Entering sivS2v().");
  let d = aesCmac(key, Buffer.alloc(BLOCK));
  components.forEach(function (one) {
    d = xorBlocks(sivDbl(d), aesCmac(key, one));
  });
  let t;
  if (plaintext.length >= BLOCK) {
    t = Buffer.from(plaintext);
    const at = t.length - BLOCK;
    xorBlocks(t.subarray(at), d).copy(t, at);
  } else {
    t = xorBlocks(sivDbl(d), sivPad(plaintext));
  }
  log.debug("Leaving sivS2v().");
  return aesCmac(key, t);
}

// CTR from the synthetic IV, its bits 63 and 31 cleared (section 2.6).
function sivCtr(key, siv, bytes) {
  log.debug("Entering sivCtr().");
  const q = Buffer.from(siv);
  q[8] &= 0x7f;
  q[12] &= 0x7f;
  const c = nodeCrypto.createCipheriv('aes-256-ctr', key, q);
  log.debug("Leaving sivCtr().");
  return Buffer.concat([c.update(bytes), c.final()]);
}

/**
 * AES-SIV encryption (RFC 5297) under a 512-bit key.
 *
 * @param key - 64 bytes: the S2V key, then the CTR key
 * @param plaintext - the bytes to encrypt
 * @param components - the associated data components, in order
 * @returns the 16-byte synthetic IV followed by the ciphertext
 */
function aesSivEncrypt(key, plaintext, components) {
  log.debug("Entering aesSivEncrypt().");
  if (!Buffer.isBuffer(key) || key.length !== SIV_KEY_BYTES) {
    throw new Error('an AES-256-SIV key is ' + SIV_KEY_BYTES + ' bytes');
  }
  const p = Buffer.from(plaintext);
  const siv = sivS2v(key.subarray(0, 32), components || [], p);
  const out = Buffer.concat([siv, sivCtr(key.subarray(32), siv, p)]);
  log.debug("Leaving aesSivEncrypt().");
  return out;
}

/**
 * AES-SIV decryption (RFC 5297) under a 512-bit key.
 *
 * @param key - 64 bytes
 * @param sealed - the synthetic IV followed by the ciphertext
 * @param components - the associated data components it was sealed with
 * @returns the plaintext
 * @throws Error when the synthetic IV does not verify
 */
function aesSivDecrypt(key, sealed, components) {
  log.debug("Entering aesSivDecrypt().");
  if (!Buffer.isBuffer(key) || key.length !== SIV_KEY_BYTES) {
    throw new Error('an AES-256-SIV key is ' + SIV_KEY_BYTES + ' bytes');
  }
  const all = Buffer.from(sealed);
  if (all.length < BLOCK) {
    throw new Error('an AES-SIV ciphertext is at least 16 bytes');
  }
  const siv = all.subarray(0, BLOCK);
  const plain = sivCtr(key.subarray(32), siv, all.subarray(BLOCK));
  const check = sivS2v(key.subarray(0, 32), components || [], plain);
  if (!nodeCrypto.timingSafeEqual(check, siv)) {
    log.debug("Leaving aesSivDecrypt(). It does not verify.");
    throw new Error('the AES-SIV synthetic IV does not verify');
  }
  log.debug("Leaving aesSivDecrypt().");
  return plain;
}

function envelopeAad(dekId) {
  log.debug("Entering envelopeAad().");
  log.debug("Leaving envelopeAad().");
  return Buffer.from('sts envelope v' + DEK_ENVELOPE_VERSION + '|' + dekId,
                     'utf8');
}

/**
 * Encrypts a value under a data encryption key: AES-256-GCM, as
 * `$aesgcm$2$<dek id>$<iv>$<tag>$<ciphertext>`, and counted.
 *
 * @param dekId - the DEK's id, which the envelope names
 * @param key - the DEK, 32 bytes
 * @param plaintext - the value
 * @param label - what it is, for the accounting
 * @returns the stored form
 */
function encryptWithDek(dekId, key, plaintext, label) {
  log.debug('Entering encryptWithDek().');
  if (!DEK_ID_PATTERN.test(String(dekId || ''))) {
    throw new Error('a data encryption key id must be base64url');
  }
  // A 64-BYTE DEK IS AN AES-256-SIV KEY (#391): the envelope is
  // `$aessiv$2$<dek id>$<nonce>$<siv>$<ciphertext>`, the envelope AAD and the
  // nonce its two associated data components.
  if (dekBytes(key).length === SIV_KEY_BYTES) {
    const nonce = nodeCrypto.randomBytes(SIV_NONCE_BYTES);
    const plain = Buffer.from(String(plaintext), 'utf8');
    const sealedBytes = aesSivEncrypt(key, plain,
                                      [envelopeAad(dekId), nonce]);
    countKek(label, 'encryptions', plain.length, sealedBytes.length);
    log.debug('Leaving encryptWithDek(). AES-256-SIV.');
    return '$aessiv$' + DEK_ENVELOPE_VERSION + '$' + dekId + '$' +
           nonce.toString('base64') + '$' +
           sealedBytes.subarray(0, BLOCK).toString('base64') + '$' +
           sealedBytes.subarray(BLOCK).toString('base64');
  }
  const iv = nodeCrypto.randomBytes(KEK_IV_BYTES);
  const cipher = nodeCrypto.createCipheriv('aes-256-gcm', dekBytes(key), iv);
  cipher.setAAD(envelopeAad(dekId));
  const body = Buffer.concat([cipher.update(Buffer.from(String(plaintext),
                                                        'utf8')),
                              cipher.final()]);
  const tag = cipher.getAuthTag();
  const out = '$aesgcm$' + DEK_ENVELOPE_VERSION + '$' + dekId + '$' +
              iv.toString('base64') + '$' + tag.toString('base64') + '$' +
              body.toString('base64');
  countKek(label, 'encryptions', Buffer.byteLength(String(plaintext), 'utf8'),
           body.length);
  log.debug('Leaving encryptWithDek(). ' + body.length + ' byte(s) of ' +
      'ciphertext.');
  return out;
}

/**
 * Decrypts a value `encryptWithDek()` wrote, and counts it.
 *
 * @param key - the DEK the value names (the caller looked it up by
 * `dekIdOf()`)
 * @param stored - the stored form
 * @param label - what it is, for the accounting
 * @returns the plaintext
 * @throws Error for a value this service did not write, an unknown version,
 *   or the wrong key
 */
function decryptWithDek(key, stored, label) {
  log.debug('Entering decryptWithDek().');
  const parts = String(stored || '').split('$');
  // `$aesgcm$2$id$iv$tag$body` splits to ['', 'aesgcm', '2', d, i, t, b].
  //
  // **EVERY REFUSAL COUNTS AS A FAILURE**, a deliberate flattening: what a
  // reader of that number wants to know is *how often did this service fail
  // to read something it had written*.
  if (parts.length !== 7 || (parts[1] !== 'aesgcm' &&
                              parts[1] !== 'aessiv')) {
    countKek(label, 'failures', 0, 0);
    throw new Error('this is not a record encrypted by this service');
  }
  if (parts[2] !== DEK_ENVELOPE_VERSION) {
    countKek(label, 'failures', 0, 0);
    throw new Error('the record names encryption version "' + parts[2] +
                    '", which this build does not read (version 1 records ' +
                    'were written before data encryption keys, #391)');
  }
  if (parts[1] === 'aessiv') {
    let plain = null;
    try {
      if (dekBytes(key).length !== SIV_KEY_BYTES) {
        throw new Error('an AES-256-SIV value needs a 64-byte key');
      }
      plain = aesSivDecrypt(key, Buffer.concat([
        Buffer.from(parts[5], 'base64'), Buffer.from(parts[6], 'base64')]),
        [envelopeAad(parts[3]), Buffer.from(parts[4], 'base64')]);
    } catch (e) {
      countKek(label, 'failures', 0, 0);
      log.debug('Leaving decryptWithDek(). It would not open.');
      throw e;
    }
    countKek(label, 'decryptions', plain.length, plain.length + BLOCK);
    log.debug('Leaving decryptWithDek(). AES-256-SIV.');
    return plain.toString('utf8');
  }
  const iv = Buffer.from(parts[4], 'base64');
  const tag = Buffer.from(parts[5], 'base64');
  const body = Buffer.from(parts[6], 'base64');
  if (key.length !== KEK_KEY_BYTES) {
    countKek(label, 'failures', 0, 0);
    throw new Error('an AES-256-GCM value needs a 32-byte key');
  }
  let out = null;
  try {
    const decipher = nodeCrypto.createDecipheriv('aes-256-gcm',
                                                 dekBytes(key), iv);
    decipher.setAAD(envelopeAad(parts[3]));
    decipher.setAuthTag(tag);
    // THROWS ON A BAD TAG, and that is the whole point of GCM here: the
    // caller gets an error rather than the wrong bytes. Counted, and still
    // thrown — `keystore.js` turns it into a fatal at startup.
    out = Buffer.concat([decipher.update(body), decipher.final()]);
  } catch (e) {
    countKek(label, 'failures', 0, 0);
    log.debug('Leaving decryptWithDek(). It would not open.');
    throw e;
  }
  countKek(label, 'decryptions', out.length, body.length);
  log.debug('Leaving decryptWithDek(). ' + out.length + ' byte(s).');
  return out.toString('utf8');
}

// The key a DEK is wrapped under: derived once from the KEK, so the whole KEK
// is used whatever its length and nothing else derived from it can equal it.
function dekWrappingKey(kek) {
  log.debug("Entering dekWrappingKey().");
  log.debug("Leaving dekWrappingKey().");
  return Buffer.from(nodeCrypto.hkdfSync('sha256', kekBytes(kek),
                                         Buffer.alloc(0),
                                         Buffer.from(DEK_WRAP_INFO, 'utf8'),
                                         KEK_KEY_BYTES));
}

/**
 * Generates a data encryption key: 32 random bytes for AES-256-GCM, or 64 for
 * AES-256-SIV.
 *
 * @param alg - `aes-256-gcm` (the default) or `aes-256-siv`
 * @returns the key
 */
function generateDek(alg) {
  log.debug("Entering generateDek().");
  log.debug("Leaving generateDek().");
  return nodeCrypto.randomBytes(alg === 'aes-256-siv' ? SIV_KEY_BYTES
                                                      : KEK_KEY_BYTES);
}

/**
 * The cipher a data encryption key is for, from its length.
 *
 * @param key - the DEK
 * @returns `aes-256-siv` for 64 bytes, else `aes-256-gcm`
 */
function dekAlgOf(key) {
  log.debug("Entering dekAlgOf().");
  log.debug("Leaving dekAlgOf().");
  return Buffer.isBuffer(key) && key.length === SIV_KEY_BYTES
    ? 'aes-256-siv' : 'aes-256-gcm';
}

/**
 * Generates a data encryption key's id: 16 random bytes, base64url.
 *
 * @returns the id
 */
function generateDekId() {
  log.debug("Entering generateDekId().");
  log.debug("Leaving generateDekId().");
  return nodeCrypto.randomBytes(16).toString('base64url');
}

/**
 * Wraps a data encryption key under the key-encryption key, as
 * `$dekwrap$1$<iv>$<tag>$<ciphertext>`, binding the AAD given.
 *
 * @param kek - the key-encryption key
 * @param key - the DEK, 32 bytes
 * @param aad - what the wrap is bound to: the DEK's id, scope, realm, class
 * @returns the wrapped form
 */
function wrapDek(kek, key, aad) {
  log.debug("Entering wrapDek().");
  const iv = nodeCrypto.randomBytes(KEK_IV_BYTES);
  const cipher = nodeCrypto.createCipheriv('aes-256-gcm',
                                           dekWrappingKey(kek), iv);
  cipher.setAAD(Buffer.from(String(aad), 'utf8'));
  const body = Buffer.concat([cipher.update(dekBytes(key)), cipher.final()]);
  const tag = cipher.getAuthTag();
  countKek('data-keys', 'encryptions', key.length, body.length);
  log.debug("Leaving wrapDek().");
  return '$dekwrap$1$' + iv.toString('base64') + '$' +
         tag.toString('base64') + '$' + body.toString('base64');
}

/**
 * Unwraps a data encryption key `wrapDek()` wrote.
 *
 * @param kek - the key-encryption key
 * @param wrapped - the wrapped form
 * @param aad - what the wrap was bound to
 * @returns the DEK, 32 bytes
 * @throws Error for a value that is not a wrapped DEK, the wrong key, or AAD
 *   that is not the one it was wrapped with
 */
function unwrapDek(kek, wrapped, aad) {
  log.debug("Entering unwrapDek().");
  const parts = String(wrapped || '').split('$');
  if (parts.length !== 6 || parts[1] !== 'dekwrap' || parts[2] !== '1') {
    countKek('data-keys', 'failures', 0, 0);
    throw new Error('this is not a data encryption key wrapped by this ' +
                    'service');
  }
  let out = null;
  try {
    const decipher = nodeCrypto.createDecipheriv(
      'aes-256-gcm', dekWrappingKey(kek), Buffer.from(parts[3], 'base64'));
    decipher.setAAD(Buffer.from(String(aad), 'utf8'));
    decipher.setAuthTag(Buffer.from(parts[4], 'base64'));
    out = Buffer.concat([decipher.update(Buffer.from(parts[5], 'base64')),
                         decipher.final()]);
  } catch (e) {
    countKek('data-keys', 'failures', 0, 0);
    log.debug("Leaving unwrapDek(). It would not unwrap.");
    throw e;
  }
  countKek('data-keys', 'decryptions', out.length, out.length);
  log.debug("Leaving unwrapDek().");
  return dekBytes(out);
}

// ---------------------------------------------------------------------------
// A DEK DERIVED RATHER THAN STORED — ONLY WHERE NOTHING IS STORED. A process
// that persists no key material (development, where every process of the
// request pool shares one ephemeral KEK) has nowhere to keep a wrapped DEK
// that its sibling threads could read, so the DEK for a (scope, realm, class)
// is derived from the KEK, and so is its id: every process holding that KEK
// arrives at the same key under the same name, and nothing has to be shared.
// It is never used where keys persist — there every DEK is random and wrapped.
// ---------------------------------------------------------------------------
/**
 * Derives a data encryption key and its id from the key-encryption key, for a
 * process that stores none.
 *
 * @param kek - the key-encryption key
 * @param context - what the DEK is for: scope, realm and class
 * @returns `{ id, key }`
 */
function deriveDek(kek, context) {
  log.debug("Entering deriveDek().");
  const info = DEK_DERIVE_INFO + String(context);
  const key = Buffer.from(nodeCrypto.hkdfSync('sha256', kekBytes(kek),
                                              Buffer.alloc(0),
                                              Buffer.from(info, 'utf8'),
                                              KEK_KEY_BYTES));
  const idKey = Buffer.from(nodeCrypto.hkdfSync('sha256', kekBytes(kek),
                                                Buffer.alloc(0),
                                                Buffer.from(DEK_ID_INFO,
                                                            'utf8'),
                                                KEK_KEY_BYTES));
  const id = 'x' + nodeCrypto.createHmac('sha256', idKey).update(info, 'utf8')
    .digest('base64url').slice(0, 22);
  log.debug("Leaving deriveDek().");
  return { id: id, key: key };
}

// ---------------------------------------------------------------------------
// THE FOUR FUNCTIONS BELOW ARE ONE IMPLEMENTATION WITH TWO DOORS, and the
// split is the same one `signJws()` and `signJwsAsync()` above make: the
// POLICY — the cost parameters, the stored form, how it is parsed, how the
// comparison is made — is here and is written once, and the only thing that
// differs between the sync and async door is WHICH PROCESS runs the one
// expensive line.
//
// **WHY THERE IS AN ASYNC DOOR AT ALL.** N is 2^15 on purpose, so one hash or
// one verification measured 68ms on this machine — and node runs this
// service's six listener families on ONE THREAD, so for those 68ms it answers
// nobody: not the next HTTP caller, not the KDC on port 88, not the LDAP
// socket. That is not the 14.6 seconds an SLH-DSA signature costs, but it is
// paid on EVERY authentication — the sign-in screen, an LDAP bind, SCIM
// Basic, WS-Trust, the portal's password form — rather than on the few a
// client points at a post-quantum algorithm. See common/pq_native.js.
//
// The sync door is kept and is not deprecated: the parent project loads this
// tree in process, and a caller that cannot be made asynchronous is better off
// blocking than wrong. Both doors produce the same stored form, because there
// is one definition of it.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// A CREDENTIAL SEVERAL PROCESSES OF THIS SERVICE HAVE TO ARRIVE AT
// INDEPENDENTLY (2026-09-11).
//
// HMAC-SHA256 over a label and the parts that name the thing, under a secret
// the processes share. It is here rather than beside its one caller because
// this file is the one place this service does cryptography, and because the
// property being bought is a cryptographic one: a caller that holds one derived
// credential must not be able to work out another.
//
// **IT IS A DERIVATION AND NOT A SECRET OF ITS OWN**, which is the whole point.
// `ssf_receivers.js` mints a bearer token for each of this service's own two
// SSF receivers, per realm, at startup — and in a dispatched service startup
// happens in the front process and in every request worker, so a random token
// gave four processes four different answers for one stream. The transmitter
// ran in one of them and the receive endpoint in another, and EVERY push this
// service made to itself was refused: 132,546 of them in half an hour on
// 2026-09-11, each one retried, while nothing anywhere was broken enough to
// fail. Derived from a secret that travels in the fork's environment, every
// process computes the same token and none of them has to be told it.
//
// The label is not decoration: it is what keeps a credential derived for one
// purpose from being the credential for another if a second caller ever
// appears.
// ---------------------------------------------------------------------------
// `...parts` rather than `arguments` (#50): the same inputs, in the same
// order, and a signature the type checker can read.
/**
 * Derives a credential several processes of this service must arrive at
 * independently: an HMAC-SHA-256 of the label and parts under a shared
 * secret.
 *
 * @param secret - the shared secret
 * @param label - what the credential is for, so one purpose's credential is
 *   never another's
 * @param parts - further inputs, each separated by a NUL
 * @returns the credential, base64url
 */
function deriveSharedCredential(secret, label, ...parts) {
  log.debug('Entering deriveSharedCredential(). label=' + label);
  const mac = nodeCrypto.createHmac('sha256', Buffer.from(String(secret || ''),
                                                          'utf8'));
  mac.update(String(label || ''), 'utf8');
  for (let i = 0; i < parts.length; i++) {
    // A SEPARATOR THAT CANNOT APPEAR IN A PART. Without one, ('ab', 'c') and
    // ('a', 'bc') derive the same credential, which is the ordinary way a
    // concatenated MAC input goes wrong.
    mac.update('\u0000', 'utf8');
    mac.update(String(parts[i] == null ? '' : parts[i]), 'utf8');
  }
  log.debug('Leaving deriveSharedCredential().');
  return b64u(mac.digest());
}

// The stored form. `$scrypt$N$r$p$salt$hash`, self-describing so that raising
// the cost later does not invalidate what is already stored — see the block
// above the parameters.
function encodeStoredSecret(n, r, p, salt, derived) {
  log.debug("Entering encodeStoredSecret().");
  log.debug("Leaving encodeStoredSecret().");
  return '$scrypt$' + n + '$' + r + '$' + p + '$' +
         salt.toString('base64') + '$' + derived.toString('base64');
}

// The same string read back, or null for anything this file did not write.
// NULL RATHER THAN A THROW, and both verification doors depend on it: this
// runs on a sign-in, and one malformed value on one entry must not be able to
// take the door down for everybody.
function decodeStoredSecret(stored) {
  log.debug('Entering decodeStoredSecret().');
  const text = String(stored || '');
  if (!text) {
    log.debug('Leaving decodeStoredSecret(). Nothing is stored.');
    return null;
  }
  const parts = text.split('$');
  // `$scrypt$N$r$p$salt$hash` splits to ['', 'scrypt', N, r, p, salt, hash].
  if (parts.length !== 7 || parts[1] !== 'scrypt') {
    log.debug('Leaving decodeStoredSecret(). Not a form this file writes.');
    return null;
  }
  const n = parseInt(parts[2], 10);
  const r = parseInt(parts[3], 10);
  const p = parseInt(parts[4], 10);
  let salt;
  let expected;
  try {
    salt = Buffer.from(parts[5], 'base64');
    expected = Buffer.from(parts[6], 'base64');
  } catch (e) {
    // A stored value that is not base64 where it must be.
    log.warn(errorCodes.tag('STS-KEYS-0004') +
             'crypto: a stored secret is not decodable and is being treated ' +
             'as no match: ' + e.message);
    log.debug('Leaving decodeStoredSecret(). Undecodable.');
    return null;
  }
  if (!isFinite(n) || !isFinite(r) || !isFinite(p) || !expected.length) {
    log.debug('Leaving decodeStoredSecret(). The parameters do not parse.');
    return null;
  }
  log.debug('Leaving decodeStoredSecret(). N=' + n + '.');
  return { N: n, r: r, p: p, salt: salt, expected: expected,
           keylen: expected.length, maxmem: 128 * n * r * 2 };
}

/**
 * Hashes a password or client secret with scrypt, in the self-describing
 * `$scrypt$N$r$p$salt$hash` form, at the cost the settings name now.
 *
 * @param plaintext - the secret
 * @returns the stored form
 */
function hashSecret(plaintext) {
  log.debug('Entering hashSecret().');
  const salt = nodeCrypto.randomBytes(SCRYPT_SALT_BYTES);
  // THE COST IS READ PER HASH — see `scryptParameters()`. The stored form
  // names what was used, so a change here reaches the next hash and nothing
  // already written.
  const cost = scryptParameters();
  const derived = nodeCrypto.scryptSync(String(plaintext == null ? '' :
                                               plaintext),
                                    salt, cost.keylen,
                                    { N: cost.N, r: cost.r, p: cost.p,
                                      maxmem: cost.maxmem });
  const out = encodeStoredSecret(cost.N, cost.r, cost.p, salt, derived);
  log.debug('Leaving hashSecret().');
  return out;
}

// The one line that runs off this thread, and the only place either async
// door differs from its sync twin: node's asynchronous scrypt, on libuv's
// thread pool (#363; `common/worker_pool.js`'s `scrypt.derive` job until
// then, a forked process for 68 ms of native work).
function deriveAsync(plaintext, spec) {
  log.debug('Entering deriveAsync(). N=' + spec.N);
  log.debug('Leaving deriveAsync(). On libuv.');
  return new Promise(function (resolve, reject) {
    nodeCrypto.scrypt(String(plaintext == null ? '' : plaintext),
      Buffer.from(spec.salt), spec.keylen,
      { N: spec.N, r: spec.r, p: spec.p, maxmem: spec.maxmem },
      function (err, derived) {
        if (err) {
          reject(err);
          return;
        }
        resolve(derived);
      });
  });
}

/**
 * Hashes a secret as `hashSecret()` does, on libuv's thread pool.
 *
 * @param plaintext - the secret
 * @returns a promise of the stored form
 */
function hashSecretAsync(plaintext) {
  log.debug('Entering hashSecretAsync().');
  const salt = nodeCrypto.randomBytes(SCRYPT_SALT_BYTES);
  // Read ONCE, here: reading the setting again when the answer comes back
  // could encode different parameters from the ones the derivation used.
  const cost = scryptParameters();
  const spec = { N: cost.N, r: cost.r, p: cost.p, salt: salt,
                 keylen: cost.keylen, maxmem: cost.maxmem };
  log.debug('Leaving hashSecretAsync(). On libuv.');
  return deriveAsync(plaintext, spec).then(function (derived) {
    return encodeStoredSecret(spec.N, spec.r, spec.p, salt, derived);
  });
}

// Whether a stored value is one of ours. A directory this service did not seed
// may hold a `userPassword` in any of the forms RFC 4519 permits — including
// plaintext — and a verification that treated one of those as a scrypt string
// would refuse a correct password rather than saying it cannot read the value.
/**
 * Says whether a stored value is one of this service's scrypt forms.
 *
 * @param stored - the value
 * @returns true when it is
 */
function isHashedSecret(stored) {
  log.debug("Entering isHashedSecret().");
  log.debug("Leaving isHashedSecret().");
  return /^\$scrypt\$/.test(String(stored || ''));
}

/**
 * Verifies a secret against a stored scrypt form, in constant time.
 *
 * @param plaintext - the presented secret
 * @param stored - the stored form
 * @returns true when it matches; false for no match or a value it cannot
 *   read
 */
function verifySecret(plaintext, stored) {
  log.debug('Entering verifySecret().');
  const spec = decodeStoredSecret(stored);
  if (!spec) {
    log.debug('Leaving verifySecret(). Nothing readable is stored.');
    return false;
  }
  let derived;
  try {
    derived = nodeCrypto.scryptSync(String(plaintext == null ? '' : plaintext),
                                spec.salt, spec.keylen,
                                { N: spec.N, r: spec.r, p: spec.p,
                                  maxmem: spec.maxmem });
  } catch (e) {
    // Parameters this node cannot satisfy — a value stored by a build with a
    // higher cost, say. Reported rather than thrown, for decodeStoredSecret()'s
    // reason.
    log.warn(errorCodes.tag('STS-KEYS-0005') +
             'crypto: a stored secret names scrypt parameters this process ' +
             'cannot compute and is being treated as no match: ' + e.message);
    log.debug('Leaving verifySecret(). Uncomputable.');
    return false;
  }
  const same = constantTimeEquals(derived, spec.expected);
  log.debug('Leaving verifySecret(). ' +
            (same ? 'It matches.' : 'It does not.'));
  return same;
}

// The same verification off this process's thread. It RESOLVES false for a
// value that does not match and for one it cannot read, and rejects for
// nothing — the sync twin returns false in both cases, and a door that threw
// where the other returned would be two answers to one question.
/**
 * Verifies as `verifySecret()` does, on libuv's thread pool. Never rejects.
 *
 * @param plaintext - the presented secret
 * @param stored - the stored form
 * @returns a promise of true or false
 */
function verifySecretAsync(plaintext, stored) {
  log.debug('Entering verifySecretAsync().');
  const spec = decodeStoredSecret(stored);
  if (!spec) {
    log.debug('Leaving verifySecretAsync(). Nothing readable is stored.');
    return Promise.resolve(false);
  }
  log.debug('Leaving verifySecretAsync(). On libuv.');
  return deriveAsync(plaintext, spec).then(function (derived) {
    return constantTimeEquals(derived, spec.expected);
  }, function (e) {
    // Parameters this node cannot satisfy — verifySecret()'s case, answered
    // as it answers it.
    log.warn(errorCodes.tag('STS-KEYS-0005') +
             'crypto: a stored secret names scrypt parameters this process ' +
             'cannot compute and is being treated as no match: ' +
             ((e && e.message) || e));
    return false;
  });
}

// ===========================================================================
// SECTION 8 — SIGNATURES OVER RAW BYTES, AND THE TPM 2.0 KEY DERIVATION
// (#40, 2026-09-21).
//
// SPIFFE's node attestors prove possession of a key by signing a challenge,
// in four formats none of which is a JWS or an XML signature: SPIRE's x509pop
// (RSA-PSS over a digest, ECDSA as big-endian r and s), OpenSSH signatures
// (sshpop), a TPM's TPMT_SIGNATURE and a DevID's plain X.509 signature
// (tpm_devid). They were written beside their attestors on the first day and
// moved here the same day, at rcbj's direction, for this file's reason:
// every signature this service checks is checked in ONE place.
//
// **ONE PRIMITIVE, `verifyRawSignature()`, AND THE CALLER NAMES THE SCHEME.**
// A signature is `{ family, hash, encoding, saltLength }` — what the
// protocol says was done — and the key is whatever the caller holds. A key of
// the wrong kind for the family is `false`, never a throw, as in section 1a.
// The post-quantum family (ML-DSA, SLH-DSA, composite ML-DSA) goes through
// the vendored `pqc_x509.js` rather than node, because node reads those keys
// only from version 24 and composite never: the same engine that checks a
// post-quantum certificate chain checks a post-quantum proof of possession.
//
// **TPM 2.0 KDFa AND MakeCredential ARE HERE TOO**, because they are a key
// derivation, an OAEP encryption, a CFB encryption and an HMAC — four of this
// file's kinds of thing — and the TPM structures they are fed are a codec
// that stays in `spiffe/spiffe_tpm.ts`.
//
// It stays a LEAF: `./vendored/pqc_x509` requires only noble, asn1js and
// other vendored files.
// ===========================================================================
const pqcX509 = require('./vendored/pqc_x509');

// The families `verifyRawSignature()` understands.
/** The families `verifyRawSignature()` understands. */
const RAW_SIGNATURE_FAMILIES = ['rsa-pkcs1', 'rsa-pss', 'ecdsa', 'eddsa',
                                'pq'];

// The curve sizes an ECDSA r||s signature is padded to.
const ECDSA_BYTES = { 'prime256v1': 32, 'secp384r1': 48, 'secp521r1': 66 };

// What a SubjectPublicKeyInfo holds, as a caller choosing a scheme needs to
// know it: `kind` is 'rsa', 'ec', 'ed25519', 'ed448' or 'pq', `key` the node
// KeyObject where node can read one, `curve` for EC, and `pqAlgorithm` (the
// vendored engine's name, 'ML-DSA-65') for a post-quantum key. `kind` is ''
// for anything else. Never throws.
/**
 * Reads a SubjectPublicKeyInfo as a caller choosing a scheme needs it.
 * Never throws.
 *
 * @param spkiDer - the DER
 * @returns `{ kind, key, curve, pqAlgorithm }`, `kind` empty for anything
 *   unknown
 */
function publicKeyFromSpki(spkiDer) {
  log.debug("Entering publicKeyFromSpki().");
  const der = Buffer.from(spkiDer || []);
  const pq = (function () {
    try {
      return pqcX509.decodeSpki(new Uint8Array(der));
    } catch (e) {
      log.debug("Caught in publicKeyFromSpki(): " + ((e && e.message) || e));
      return null;
    }
  })();
  if (pq && pq.alg) {
    log.debug("Leaving publicKeyFromSpki(). Post-quantum.");
    return { kind: 'pq', key: null, curve: '', pqAlgorithm: String(pq.alg),
             spki: der };
  }
  try {
    const key = nodeCrypto.createPublicKey({ key: der, format: 'der',
                                             type: 'spki' });
    const type = String(key.asymmetricKeyType || '');
    const kind = type === 'rsa-pss' ? 'rsa' : type;
    log.debug("Leaving publicKeyFromSpki(). " + kind);
    return { kind: ['rsa', 'ec', 'ed25519', 'ed448'].indexOf(kind) >= 0
               ? kind : '',
             key: key,
             curve: String((key.asymmetricKeyDetails || {}).namedCurve || ''),
             pqAlgorithm: '', spki: der };
  } catch (e) {
    log.debug("Caught in publicKeyFromSpki(): " + ((e && e.message) || e));
    log.debug("Leaving publicKeyFromSpki(). Unreadable.");
    return { kind: '', key: null, curve: '', pqAlgorithm: '', spki: der };
  }
}

// THE ONE PRIMITIVE FOR A SIGNATURE OVER RAW BYTES. `scheme`:
//   family      one of RAW_SIGNATURE_FAMILIES
//   hash        'sha1' | 'sha256' | 'sha384' | 'sha512' — the digest the
//               signature was made over `data` with (omitted for eddsa, pq)
//   encoding    ecdsa only: 'der' or 'p1363' (r||s, each padded to the curve)
//   saltLength  rsa-pss only: a number, or 'auto' to accept any
// `key` is a node KeyObject, anything `createPublicKey()` takes, or — for the
// pq family, and for any family — a `publicKeyFromSpki()` answer. Resolves
// true or false; a malformed signature or a key of the wrong kind is false.
/**
 * Verifies a signature over raw bytes: the one primitive for it.
 *
 * @param scheme - `family`, `hash`, `encoding` (ECDSA) and `saltLength`
 *   (RSA-PSS)
 * @param key - a KeyObject, anything `createPublicKey()` takes, or a
 *   `publicKeyFromSpki()` answer
 * @param data - the bytes signed
 * @param signature - the signature
 * @returns a promise of true or false
 */
async function verifyRawSignature(scheme, key, data, signature) {
  const s = scheme || {};
  log.debug("Entering verifyRawSignature(). " + s.family + "/" +
            (s.hash || ''));
  const message = Buffer.from(data || []);
  const sig = Buffer.from(signature || []);
  if (RAW_SIGNATURE_FAMILIES.indexOf(s.family) < 0) {
    log.debug("Leaving verifyRawSignature(). Unknown family.");
    return false;
  }
  try {
    if (s.family === 'pq') {
      const described = key && key.spki ? key : publicKeyFromSpki(key);
      if (described.kind !== 'pq') {
        log.debug("Leaving verifyRawSignature(). Not a post-quantum key.");
        return false;
      }
      const read = pqcX509.decodeSpki(new Uint8Array(described.spki));
      const ok = await pqcX509.verify(read.alg, new Uint8Array(sig),
                                      new Uint8Array(message), read.pub);
      log.debug("Leaving verifyRawSignature(). " + read.alg + " " + ok);
      return !!ok;
    }
    const publicKey = key && key.spki !== undefined ? key.key
      : (key && key.type === 'public') ? key : nodeCrypto.createPublicKey(key);
    if (!publicKey) {
      log.debug("Leaving verifyRawSignature(). No key.");
      return false;
    }
    const type = String(publicKey.asymmetricKeyType || '');
    // An exponent or a modulus that makes a forgery (#202,
    // rsaKeyProblem()); no size floor here — a TPM or an attestor's key is
    // what its protocol made it.
    if (rsaKeyProblem(publicKey, 0)) {
      log.debug("Leaving verifyRawSignature(). A forgeable RSA key.");
      return false;
    }
    let ok = false;
    if (s.family === 'rsa-pkcs1' && (type === 'rsa' || type === 'rsa-pss')) {
      ok = nodeCrypto.verify(s.hash, message, { key: publicKey,
        padding: nodeCrypto.constants.RSA_PKCS1_PADDING }, sig);
    } else if (s.family === 'rsa-pss' &&
               (type === 'rsa' || type === 'rsa-pss')) {
      ok = nodeCrypto.verify(s.hash, message, { key: publicKey,
        padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: s.saltLength === 'auto' || s.saltLength === undefined
          ? nodeCrypto.constants.RSA_PSS_SALTLEN_AUTO : s.saltLength }, sig);
    } else if (s.family === 'ecdsa' && type === 'ec') {
      ok = nodeCrypto.verify(s.hash, message, { key: publicKey,
        dsaEncoding: s.encoding === 'p1363' ? 'ieee-p1363' : 'der' }, sig);
    } else if (s.family === 'eddsa' &&
               (type === 'ed25519' || type === 'ed448')) {
      ok = nodeCrypto.verify(null, message, publicKey, sig);
    }
    log.debug("Leaving verifyRawSignature(). " + ok);
    return !!ok;
  } catch (e) {
    log.debug("Caught in verifyRawSignature(): " + ((e && e.message) || e));
    log.debug("Leaving verifyRawSignature(). Threw, so false.");
    return false;
  }
}

// THE SIGNING HALF OF THE PRIMITIVE ABOVE (#194-#196, 2026-09-26), for the
// Data Integrity cryptosuites that sign bytes rather than a JWS: the RDFC
// suites, and ecdsa-sd-2023's base and per-statement signatures. Same
// `scheme` (families 'ecdsa' and 'eddsa' only — nothing here signs raw bytes
// with RSA, and a post-quantum signature goes through `pq_jose`);
// `privateKey` is a node KeyObject or a private JWK. Throws for a key of the
// wrong kind, because a signer handed the wrong key is a bug, not an input.
/**
 * Signs raw bytes with ECDSA or EdDSA, for the Data Integrity
 * cryptosuites.
 *
 * @param scheme - as for `verifyRawSignature()`
 * @param privateKey - a KeyObject or a private JWK
 * @param data - the bytes to sign
 * @returns the signature
 * @throws Error for a key of the wrong kind
 */
function signRawSignature(scheme, privateKey, data) {
  const s = scheme || {};
  log.debug("Entering signRawSignature(). " + s.family + "/" +
            (s.hash || ''));
  const key = privateKey && privateKey.type === 'private' ? privateKey
    : nodeCrypto.createPrivateKey(privateKey && privateKey.kty
        ? { key: privateKey, format: 'jwk' } : privateKey);
  const type = String(key.asymmetricKeyType || '');
  const message = Buffer.from(data || []);
  if (s.family === 'ecdsa' && type === 'ec') {
    const out = nodeCrypto.sign(s.hash, message, { key: key,
      dsaEncoding: s.encoding === 'der' ? 'der' : 'ieee-p1363' });
    log.debug("Leaving signRawSignature(). ECDSA.");
    return out;
  }
  if (s.family === 'eddsa' && (type === 'ed25519' || type === 'ed448')) {
    const out = nodeCrypto.sign(null, message, key);
    log.debug("Leaving signRawSignature(). EdDSA.");
    return out;
  }
  log.debug("Leaving signRawSignature(). Refused.");
  throw new Error('signRawSignature: a ' + (type || 'unknown') + ' key ' +
                  'does not sign ' + String(s.family || 'nothing') + '.');
}

// HMAC-SHA-256 of `data` under `key` — ecdsa-sd-2023's blank node labels
// (vc-di-ecdsa section 3.4.4, createHmacIdLabelMapFunction).
/**
 * Returns HMAC-SHA-256 of data under a key.
 *
 * @param key - the key
 * @param data - the data
 * @returns the MAC
 */
function hmacSha256(key, data) {
  log.debug("Entering hmacSha256().");
  const out = nodeCrypto.createHmac('sha256', Buffer.from(key || []))
    .update(Buffer.from(data || [])).digest();
  log.debug("Leaving hmacSha256().");
  return out;
}

// A fresh key pair of a kind `generateKeyPairSync()` names ('ec' with a
// namedCurve, 'ed25519') — ecdsa-sd-2023's proof-scoped key, made and thrown
// away inside one signature.
/**
 * Makes a fresh key pair of a kind `generateKeyPairSync()` names.
 *
 * @param kind - `ec` or `ed25519`
 * @param curve - the named curve, for `ec`
 * @returns the key pair
 */
function ephemeralKeyPair(kind, curve) {
  log.debug("Entering ephemeralKeyPair(). " + kind + " " + (curve || ''));
  const pair = nodeCrypto.generateKeyPairSync(kind,
    curve ? { namedCurve: curve } : undefined);
  log.debug("Leaving ephemeralKeyPair().");
  return pair;
}

// An ECDSA signature held as its two integers, big-endian and unpadded (Go's
// big.Int.Bytes(), an SSH mpint), as the r||s the primitive above takes.
// `curve` is node's name ('prime256v1'). null when either integer is longer
// than the curve allows.
/**
 * Turns an ECDSA signature held as its two integers into r||s.
 *
 * @param curve - node's curve name
 * @param r - r, big-endian and unpadded
 * @param s - s, big-endian and unpadded
 * @returns the r||s bytes, or null when either is too long for the curve
 */
function ecdsaIntegersToP1363(curve, r, s) {
  log.debug("Entering ecdsaIntegersToP1363(). curve=" + curve);
  const size = ECDSA_BYTES[String(curve || '')];
  let rr = Buffer.from(r || []);
  let ss = Buffer.from(s || []);
  while (rr.length > 1 && rr[0] === 0) rr = rr.subarray(1);
  while (ss.length > 1 && ss[0] === 0) ss = ss.subarray(1);
  if (!size || rr.length > size || ss.length > size) {
    log.debug("Leaving ecdsaIntegersToP1363(). Out of range.");
    return null;
  }
  log.debug("Leaving ecdsaIntegersToP1363().");
  return Buffer.concat([Buffer.alloc(size - rr.length), rr,
                        Buffer.alloc(size - ss.length), ss]);
}

// TPM 2.0 KDFa (Library Part 1, section 11.4.10.2), as go-tpm computes it:
// counter-mode HMAC over label ‖ 0x00 ‖ contextU ‖ contextV ‖ bits.
/**
 * Computes TPM 2.0 KDFa: counter-mode HMAC over label, contexts and bits.
 *
 * @param hash - the hash
 * @param key - the key
 * @param label - the label
 * @param contextU - the first context
 * @param contextV - the second context
 * @param bits - the output size in bits
 * @returns the derived bytes
 */
function tpmKdfa(hash, key, label, contextU, contextV, bits) {
  log.debug("Entering tpmKdfa(). label=" + label);
  const bytes = Math.ceil(bits / 8);
  const parts = [];
  let length = 0;
  const bitsField = Buffer.alloc(4);
  bitsField.writeUInt32BE(bits, 0);
  for (let counter = 1; length < bytes; counter++) {
    const counterField = Buffer.alloc(4);
    counterField.writeUInt32BE(counter, 0);
    const block = nodeCrypto.createHmac(hash, key).update(counterField)
      .update(Buffer.from(label, 'utf8')).update(Buffer.from([0]))
      .update(contextU || Buffer.alloc(0))
      .update(contextV || Buffer.alloc(0)).update(bitsField).digest();
    parts.push(block);
    length += block.length;
  }
  const out = Buffer.from(Buffer.concat(parts).subarray(0, bytes));
  if (bits % 8) out[0] &= (1 << (bits % 8)) - 1;
  log.debug("Leaving tpmKdfa().");
  return out;
}

// TPM2_MakeCredential in software (Library Part 1, section 24), as go-tpm's
// `credactivation.Generate()` computes it for an RSA endorsement key:
//   akName       the AK's Name — nameAlg ‖ digest — whose nameAlg is the hash
//   ekPublicKey  the EK, a node RSA public KeyObject
//   seedBytes    the EK's symmetric key size in bytes (16 for AES-128)
//   secret       what the TPM must give back
// Returns the contents of TPM2B_ID_OBJECT (`credential`) and
// TPM2B_ENCRYPTED_SECRET (`secret`). Only a TPM holding the EK's private key,
// activating FOR that AK, recovers `secret`.
/**
 * Performs TPM2_MakeCredential in software, for an RSA endorsement key.
 *
 * @param akName - the attestation key's Name
 * @param ekPublicKey - the endorsement key
 * @param seedBytes - the endorsement key's symmetric key size in bytes
 * @param secret - what the TPM must give back
 * @param hash - the Name's hash
 * @returns `{ credential, secret }`, the TPM2B_ID_OBJECT and
 *   TPM2B_ENCRYPTED_SECRET contents
 */
function tpmMakeCredential(akName, ekPublicKey, seedBytes, secret, hash) {
  log.debug("Entering tpmMakeCredential().");
  const seed = nodeCrypto.randomBytes(seedBytes);
  const encryptedSeed = nodeCrypto.publicEncrypt({
    key: ekPublicKey, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: hash, oaepLabel: Buffer.from('IDENTITY\0', 'latin1')
  }, seed);
  const storageKey = tpmKdfa(hash, seed, 'STORAGE', akName, null,
                             seed.length * 8);
  const sized = Buffer.alloc(2);
  sized.writeUInt16BE(secret.length, 0);
  const cipher = nodeCrypto.createCipheriv('aes-' + (seed.length * 8) +
                                           '-cfb', storageKey,
                                           Buffer.alloc(16));
  const encIdentity = Buffer.concat([cipher.update(
    Buffer.concat([sized, secret])), cipher.final()]);
  const macKey = tpmKdfa(hash, seed, 'INTEGRITY', null, null,
                         nodeCrypto.createHash(hash).digest().length * 8);
  const integrity = nodeCrypto.createHmac(hash, macKey).update(encIdentity)
    .update(akName).digest();
  const integritySize = Buffer.alloc(2);
  integritySize.writeUInt16BE(integrity.length, 0);
  log.debug("Leaving tpmMakeCredential().");
  return { credential: Buffer.concat([integritySize, integrity, encIdentity]),
           secret: encryptedSeed };
}

// A PKCS#7 / CMS SignedData with its content attached, VERIFIED: the one
// SignerInfo's signature (over its signed attributes, whose messageDigest
// must be the content's) under the signer's certificate. AWS signs an
// instance identity document this way (its RSA-2048 signature) and Azure an
// attested document.
//   der           the SignedData, DER (a ContentInfo)
//   options.certificates  certificate DERs to find the signer among BESIDE
//                 the ones the SignedData carries — AWS's carries none and the
//                 signer is the region's published certificate
// Resolves `{ ok, content, signerDer, embeddedDers, why }`. Never rejects.
// It checks the signature and nothing about the certificate: whether the
// signer is one to believe is the caller's question (`pki.js`).
/**
 * Verifies a PKCS#7 / CMS SignedData with its content attached: the one
 * SignerInfo's signature under the signer's certificate. Never rejects.
 *
 * @param der - the SignedData
 * @param options - `certificates`, the signer's certificates (DER), where
 *   the SignedData carries none
 * @returns a promise of `{ ok, content, signerDer, embeddedDers, why }`
 */
async function verifyPkcs7SignedData(der, options) {
  log.debug("Entering verifyPkcs7SignedData().");
  const opts = options || {};
  const pkijs = require('pkijs');
  const refuse = function (why) {
    log.debug("Entering refuse().");
    log.debug("Leaving refuse().");
    return { ok: false, content: null, signerDer: null, embeddedDers: [],
             why: why };
  };
  let signed = null;
  try {
    const parsed = asn1js.fromBER(new Uint8Array(Buffer.from(der || [])));
    if (parsed.offset === -1) {
      log.debug("Leaving verifyPkcs7SignedData(). Not BER.");
      return refuse('the signature is not DER');
    }
    const info = new pkijs.ContentInfo({ schema: parsed.result });
    signed = new pkijs.SignedData({ schema: info.content });
  } catch (e) {
    log.debug("Caught in verifyPkcs7SignedData(): " + ((e && e.message) || e));
    log.debug("Leaving verifyPkcs7SignedData(). Not a SignedData.");
    return refuse('the signature is not a PKCS#7 SignedData: ' + e.message);
  }
  if (!signed.signerInfos || signed.signerInfos.length !== 1) {
    log.debug("Leaving verifyPkcs7SignedData(). Not one signer.");
    return refuse('expected exactly one signer, found ' +
                  ((signed.signerInfos || []).length));
  }
  const econtent = signed.encapContentInfo &&
    signed.encapContentInfo.eContent;
  if (!econtent) {
    log.debug("Leaving verifyPkcs7SignedData(). Detached.");
    return refuse('the SignedData carries no content');
  }
  const content = Buffer.from(econtent.getValue
    ? econtent.getValue() : econtent.valueBlock.valueHexView);
  const embedded = (signed.certificates || []).filter(function (one) {
    return one instanceof pkijs.Certificate;
  });
  const extra = (opts.certificates || []).map(function (one) {
    return pkijs.Certificate.fromBER(new Uint8Array(Buffer.from(one)));
  });
  signed.certificates = embedded.concat(extra);
  let verdict = null;
  try {
    verdict = await signed.verify({ signer: 0, checkChain: false,
                                    extendedMode: true });
  } catch (e) {
    log.debug("Caught in verifyPkcs7SignedData(): " +
              ((e && (e.message || e.code)) || e));
    const reason = (e && (e.message || (e.signatureVerified === false
      ? 'the signature does not verify' : ''))) || String(e);
    log.debug("Leaving verifyPkcs7SignedData(). Refused.");
    return refuse('the signature does not verify: ' + reason);
  }
  if (!verdict || !verdict.signatureVerified || !verdict.signerCertificate) {
    log.debug("Leaving verifyPkcs7SignedData(). Did not verify.");
    return refuse('the signature does not verify under the signer\'s ' +
                  'certificate');
  }
  log.debug("Leaving verifyPkcs7SignedData(). Verified.");
  return {
    ok: true, content: content, why: '',
    signerDer: Buffer.from(verdict.signerCertificate.toSchema().toBER(false)),
    embeddedDers: embedded.map(function (one) {
      return Buffer.from(one.toSchema().toBER(false));
    })
  };
}

// A SHA-256 FED AS BYTES ARRIVE (#215): `update(chunk)` for each chunk, then
// `hex()` once, lowercase. A dataset upload (`risk/risk_upload.ts`) is hashed
// on its way to disk rather than read a second time afterwards — a file of
// several hundred megabytes read twice is the cost this saves. `update()` is
// a hot path (one call per chunk of the upload), so it logs nothing.
/**
 * Returns a SHA-256 fed as bytes arrive.
 *
 * @returns `{ update(chunk), hex() }`
 */
function sha256Digester() {
  log.debug("Entering sha256Digester().");
  const hash = nodeCrypto.createHash('sha256');
  let digest = '';
  log.debug("Leaving sha256Digester().");
  return {
    update: function (chunk) {
      hash.update(chunk);
    },
    hex: function () {
      log.debug("Entering sha256Digester().hex().");
      if (!digest) {
        digest = hash.digest('hex');
      }
      log.debug("Leaving sha256Digester().hex().");
      return digest;
    }
  };
}

// The SHA-256 of a file, streamed, lowercase hex — refusing one larger than
// `limit` bytes when `limit` is above 0 (SPIRE's `util.GetSHA256Digest()`,
// which the unix workload attestor hashes an executable with, #40). Rejects
// with a sentence.
/**
 * Returns the SHA-256 of a file, streamed, lower-case hex.
 *
 * @param file - the file's path
 * @param limit - the largest size accepted, when above 0
 * @returns a promise of the digest; rejects with a sentence
 */
async function sha256OfFile(file, limit) {
  log.debug("Entering sha256OfFile().");
  const fs = require('fs');
  const size = fs.statSync(file).size;
  if (limit > 0 && size > limit) {
    log.debug("Leaving sha256OfFile(). Too large.");
    // error-code: none — reported by the caller under its own code
    throw new Error('workload ' + file + ' exceeds size limit (' + size +
                    ' > ' + limit + ')');
  }
  const hash = nodeCrypto.createHash('sha256');
  await new Promise(function (resolve, reject) {
    fs.createReadStream(file).on('data', function (chunk) {
      hash.update(chunk);
    }).on('end', function () {
      resolve(undefined);
    }).on('error', reject);
  });
  log.debug("Leaving sha256OfFile().");
  return hash.digest('hex');
}

// ===========================================================================
// SECTION 9 — THE KERBEROS PSEUDO-RANDOM FUNCTION AND KRB-FX-CF2 (#173,
// 2026-09-22).
//
// RFC 6113 FAST combines keys: the ARMOR key is KRB-FX-CF2 of an AP-REQ's
// subkey and its ticket's session key, the encrypted challenge's two keys are
// KRB-FX-CF2 of the armor key and the long-term key, and a reply key is
// STRENGTHENED by KRB-FX-CF2 of a random key and itself. KRB-FX-CF2 (section
// 5.1) is built on RFC 3961's `pseudo-random()`, which each enctype defines
// for itself — and the vendored codec (`kerberos/krb5_crypto.js`) has
// string-to-key, encryption and checksums but no PRF, and may not be edited
// here. So the PRF is written HERE, for this file's reason (every primitive in
// one place), and synchronously on node's own crypto, which is all three
// definitions need:
//
//   * aes128/256-cts-hmac-sha1-96 (RFC 3962 section 4): the SHA-1 of the
//     input, truncated to one AES block, encrypted under DK(key, "prf") —
//     RFC 3961's derived key over the n-folded constant "prf";
//   * aes128-cts-hmac-sha256-128 and aes256-cts-hmac-sha384-192 (RFC 8009
//     section 5): KDF-HMAC-SHA2(key, "prf", input, 256 or 384);
//   * arcfour-hmac-md5 (RFC 4757 section 3): HMAC-SHA1(key, input).
//
// **CHECKED AGAINST EXTERNAL ANSWERS, NOT AGAINST ITSELF**: RFC 3961's n-fold
// vectors, MIT's `t_prf.c` PRF vectors for the four AES types and MIT's
// `t_cf2.expected` for KRB-FX-CF2 over all five (`tests/kerberos_fast_otp.js`)
// — a round trip through FAST with this file on both ends would agree with any
// mistake made the same way twice.
//
// It stays a LEAF: node's `crypto` and nothing else.
// ===========================================================================

// The enctypes the PRF is defined for here, with their key size and PRF output
// size in bytes. Anything else is refused by name.
/** The Kerberos enctypes the PRF is defined for, with their sizes. */
const KRB5_PRF_ETYPES = {
  17: { keyBytes: 16, prfBytes: 16, family: 'aes-sha1', aes: 'aes-128-cbc' },
  18: { keyBytes: 32, prfBytes: 16, family: 'aes-sha1', aes: 'aes-256-cbc' },
  19: { keyBytes: 16, prfBytes: 32, family: 'aes-sha2', hash: 'sha256' },
  20: { keyBytes: 32, prfBytes: 48, family: 'aes-sha2', hash: 'sha384' },
  23: { keyBytes: 16, prfBytes: 20, family: 'rc4' }
};

function krb5PrfProfile(etype) {
  log.debug("Entering krb5PrfProfile(). etype=" + etype);
  const profile = KRB5_PRF_ETYPES[Number(etype)];
  if (!profile) {
    log.debug("Leaving krb5PrfProfile(). Unknown.");
    // error-code: none — a programming error; every caller passes an enctype the KDC negotiated
    throw new Error('crypto: no Kerberos pseudo-random function is defined ' +
                    'here for enctype ' + etype);
  }
  log.debug("Leaving krb5PrfProfile().");
  return profile;
}

// RFC 3961 section 5.1's n-fold, in bytes: MIT's krb5int_nfold(), which
// rotates the input 13 bits per copy and adds the copies with end-around
// carry. The RFC's own section A.1 vectors hold it.
/**
 * Computes RFC 3961 section 5.1's n-fold, in bytes.
 *
 * @param input - the input
 * @param outBytes - the output size
 * @returns the folded bytes
 */
function krb5Nfold(input, outBytes) {
  log.debug("Entering krb5Nfold(). in=" + input.length + " out=" + outBytes);
  const inBytes = Buffer.from(input);
  const inLen = inBytes.length;
  let a = inLen;
  let b = outBytes;
  while (b !== 0) {
    const t = b;
    b = a % b;
    a = t;
  }
  const lcm = (inLen * outBytes) / a;
  const out = Buffer.alloc(outBytes);
  let byte = 0;
  for (let i = lcm - 1; i >= 0; i--) {
    const msbit = (((inLen << 3) - 1) +
                   (((inLen << 3) + 13) * Math.floor(i / inLen)) +
                   ((inLen - (i % inLen)) << 3)) % (inLen << 3);
    byte += (((inBytes[((inLen - 1) - (msbit >>> 3)) % inLen] << 8) |
              inBytes[(inLen - (msbit >>> 3)) % inLen]) >>>
             ((msbit & 7) + 1)) & 0xff;
    byte += out[i % outBytes];
    out[i % outBytes] = byte & 0xff;
    byte >>>= 8;
  }
  if (byte) {
    for (let i = outBytes - 1; i >= 0; i--) {
      byte += out[i];
      out[i] = byte & 0xff;
      byte >>>= 8;
    }
  }
  log.debug("Leaving krb5Nfold().");
  return out;
}

// One AES block under a key, CBC with a zero IV and no padding — which for a
// single block is the block cipher itself, and is what RFC 3961's DR and RFC
// 3962's PRF both call E.
function aesBlocks(cipherName, key, data) {
  log.debug("Entering aesBlocks().");
  const c = nodeCrypto.createCipheriv(cipherName, Buffer.from(key),
                                      Buffer.alloc(16));
  c.setAutoPadding(false);
  const out = Buffer.concat([c.update(Buffer.from(data)), c.final()]);
  log.debug("Leaving aesBlocks().");
  return out;
}

// RFC 3961 section 5.1's DK for the AES-SHA1 profiles: DR — the n-folded
// constant encrypted, fed back, until there are enough bytes — then
// random-to-key, which is the identity for AES.
function aesSha1DerivedKey(profile, key, constant) {
  log.debug("Entering aesSha1DerivedKey().");
  let block = krb5Nfold(Buffer.from(constant), 16);
  const parts = [];
  let have = 0;
  while (have < profile.keyBytes) {
    block = aesBlocks(profile.aes, key, block);
    parts.push(block);
    have += block.length;
  }
  log.debug("Leaving aesSha1DerivedKey().");
  return Buffer.concat(parts).subarray(0, profile.keyBytes);
}

// RFC 3961 pseudo-random(key, octets) for `etype`. Answers a Buffer of that
// enctype's PRF length.
/**
 * Computes RFC 3961's pseudo-random function for an enctype.
 *
 * @param etype - the enctype
 * @param key - the key
 * @param octets - the input
 * @returns the enctype's PRF output
 */
function krb5Prf(etype, key, octets) {
  log.debug("Entering krb5Prf(). etype=" + etype);
  const profile = krb5PrfProfile(etype);
  const input = Buffer.from(octets);
  if (Buffer.from(key).length !== profile.keyBytes) {
    log.debug("Leaving krb5Prf(). Wrong key size.");
    // error-code: none — a programming error; the key comes from the codec that negotiated its enctype
    throw new Error('crypto: a key for enctype ' + etype + ' is ' +
                    profile.keyBytes + ' bytes, not ' +
                    Buffer.from(key).length);
  }
  let out;
  if (profile.family === 'aes-sha1') {
    const tmp = nodeCrypto.createHash('sha1').update(input).digest()
      .subarray(0, 16);
    out = aesBlocks(profile.aes,
                    aesSha1DerivedKey(profile, key, Buffer.from('prf')), tmp);
  } else if (profile.family === 'aes-sha2') {
    const bits = profile.prfBytes * 8;
    const k = Buffer.alloc(4);
    k.writeUInt32BE(bits, 0);
    out = nodeCrypto.createHmac(profile.hash, Buffer.from(key))
      .update(Buffer.concat([Buffer.from([0, 0, 0, 1]), Buffer.from('prf'),
                             Buffer.from([0]), input, k]))
      .digest().subarray(0, profile.prfBytes);
  } else {
    out = nodeCrypto.createHmac('sha1', Buffer.from(key)).update(input)
      .digest();
  }
  log.debug("Leaving krb5Prf().");
  return out;
}

// RFC 6113 section 5.1's PRF+: pseudo-random(key, 1 || info) ||
// pseudo-random(key, 2 || info) || ..., the counter one octet, truncated.
/**
 * Computes RFC 6113 section 5.1's PRF+.
 *
 * @param etype - the enctype
 * @param key - the key
 * @param info - the input
 * @param outBytes - the output size
 * @returns the bytes
 */
function krb5PrfPlus(etype, key, info, outBytes) {
  log.debug("Entering krb5PrfPlus().");
  const parts = [];
  let have = 0;
  for (let counter = 1; have < outBytes; counter++) {
    if (counter > 255) {
      log.debug("Leaving krb5PrfPlus(). Too long.");
      // error-code: none — a programming error; no Kerberos key is 255 PRF blocks long
      throw new Error('crypto: PRF+ ran out of one-octet counters');
    }
    const block = krb5Prf(etype, key,
                          Buffer.concat([Buffer.from([counter]),
                                         Buffer.from(info)]));
    parts.push(block);
    have += block.length;
  }
  log.debug("Leaving krb5PrfPlus().");
  return Buffer.concat(parts).subarray(0, outBytes);
}

// RFC 6113 section 5.1: KRB-FX-CF2(K1, K2, pepper1, pepper2) =
// random-to-key(PRF+(K1, pepper1) XOR PRF+(K2, pepper2)), with K1's enctype
// and key size. The keys are `{ etype, key }`, the peppers strings or bytes;
// the answer is `{ etype, key }` (random-to-key is the identity for every
// enctype above).
/**
 * Computes RFC 6113 section 5.1's KRB-FX-CF2.
 *
 * @param key1 - `{ etype, key }`
 * @param key2 - `{ etype, key }`
 * @param pepper1 - the first pepper
 * @param pepper2 - the second pepper
 * @returns `{ etype, key }`
 */
function krbFxCf2(key1, key2, pepper1, pepper2) {
  log.debug("Entering krbFxCf2(). etypes " + key1.etype + "/" + key2.etype);
  const size = krb5PrfProfile(key1.etype).keyBytes;
  krb5PrfProfile(key2.etype);
  const a = krb5PrfPlus(key1.etype, key1.key, Buffer.from(pepper1), size);
  const b = krb5PrfPlus(key2.etype, key2.key, Buffer.from(pepper2), size);
  const out = Buffer.alloc(size);
  for (let i = 0; i < size; i++) {
    out[i] = a[i] ^ b[i];
  }
  log.debug("Leaving krbFxCf2().");
  return { etype: Number(key1.etype), key: new Uint8Array(out) };
}

// ---------------------------------------------------------------------------
// OPENID CONNECT SESSION MANAGEMENT 1.0 SECTION 3's `session_state` (#121):
// SHA-256 over `client_id + " " + origin + " " + browser_state + " " + salt`,
// base64url, then "." and the salt. The OP iframe's script repeats this
// computation in the browser with the Web Crypto API, so the two must agree
// on every octet: UTF-8, single spaces, no padding. A fresh salt when none is
// given, which is every authorization response.
// ---------------------------------------------------------------------------
/**
 * Computes OpenID Connect Session Management's `session_state`: SHA-256 over
 * `client_id origin browser_state salt`, base64url, then "." and the salt.
 *
 * @param clientId - the client
 * @param origin - the relying party's origin
 * @param browserState - the OP browser state
 * @param salt - the salt; a fresh one when omitted
 * @returns the `session_state` value
 */
function sessionStateHash(clientId, origin, browserState, salt) {
  log.debug('Entering sessionStateHash().');
  const chosen = salt || nodeCrypto.randomBytes(16).toString('base64url');
  const digest = nodeCrypto.createHash('sha256')
    .update(String(clientId) + ' ' + String(origin) + ' ' +
            String(browserState || '') + ' ' + chosen, 'utf8')
    .digest('base64url');
  log.debug('Leaving sessionStateHash().');
  return digest + '.' + chosen;
}

// ===========================================================================
// SECTION 10 — WEBAUTHN: COSE SIGNATURES AND THE ATTESTATION STRUCTURES
// (#105, 2026-09-23).
//
// `authn/webauthn_attestation.ts` verifies the eight attestation statement
// formats of WebAuthn Level 3 section 8, and four of them carry structures
// that are nobody's JWS and nobody's X.509: a TPM's TPMT_PUBLIC, TPMS_ATTEST
// and TPMT_SIGNATURE (section 8.3, TPM 2.0 Library Part 2), Android's
// KeyDescription (section 8.4, the extension 1.3.6.1.4.1.11129.2.1.17),
// Apple's nonce extension (section 8.8) and FIDO's AAGUID extension (section
// 8.2.1). They are HERE and not beside the verifier for rcbj's rule of
// 2026-09-21: every signature, and every codec a signature is checked over,
// is in this file or in `pki.js` — the certificate half (which extension a
// certificate carries, and its subject) is `pki.js`'s.
//
// **`spiffe/spiffe_tpm.ts` HAS A TPM CODEC OF ITS OWN AND IT IS NOT THIS
// ONE.** That one reads the two structures SPIRE's tpm_devid sends (a
// TPMT_PUBLIC and TPM2_Certify's name) and refuses everything else; a
// WebAuthn TPM statement needs the whole TPMS_ATTEST (magic, type,
// extraData) and ECDAA's extra scheme field. Merging them is a refactor of
// an attestor that has its own tests, and is left for when one of them
// changes.
//
// **ONE COSE TABLE FOR THE SIGNATURES.** `verifyCoseSignature()` checks a
// signature made with a COSE algorithm (RFC 9053, RFC 8230, RFC 8812 and RFC
// 9964) — what an attestation statement's `alg` and a credential's key both
// name. ECDSA arrives as DER, which is what WebAuthn section 6.5.5 says an
// authenticator produces; RSASSA-PSS uses a salt as long as the hash (RFC
// 8230 section 2); ML-DSA is RFC 9964's (published May 2026 from
// draft-ietf-cose-dilithium-11): kty AKP (7), `pub` at -1, and the three
// algorithm identifiers -48, -49 and -50, verified by `pq_jose.js`, which
// holds the one ML-DSA implementation this process uses for JOSE as well.
// SHA-1 (RS1, -65535) is in the table MARKED `insecure` (2026-10-01, rcbj:
// "a use insecure passkey algorithms flag that is disabled by default"):
// `verifyCoseSignature()` refuses it unless its caller passes
// `{ allowInsecure: true }`, which only `webauthn.insecureAlgorithms` — a
// development-only setting, off by default — ever makes true. Product never
// uses a broken algorithm (`mode.usesBrokenAlgorithms()`). This module stays
// a leaf and reads no setting; the caller decides.
//
// **EVERY OTHER SIGNATURE ALGORITHM AN AUTHENTICATOR CAN USE (2026-10-01,
// rcbj: "support and request every possible algorithm").** RFC 9864's FULLY
// SPECIFIED ones — ESP256 (-9), ESP384 (-51), ESP512 (-52), Ed25519 (-19) and
// Ed448 (-53) — and RFC 8812's ES256K (-47, secp256k1). A fully specified
// algorithm names its curve, so `curve` (ECDSA, node's name) or `okp`
// (EdDSA, node's key type) is CHECKED against the key: an ESP256 signature
// under a P-384 key is a signature that does not verify, where ES256 and
// EdDSA keep their RFC 9053 meaning of any curve the key carries. Not here,
// besides RS1: HSS-LMS (-46), a stateful hash-based scheme no authenticator
// implements, and the provisional brainpool and SLH-DSA registrations.
//
// It stays a LEAF: node's crypto, asn1js and `pq_jose.js`, all required
// above.
// ===========================================================================

/** The COSE signature algorithms WebAuthn verifies, by identifier. */
const COSE_SIGNATURE_ALGS = {
  '-7': { name: 'ES256', family: 'ecdsa', hash: 'sha256', kty: 'EC' },
  '-35': { name: 'ES384', family: 'ecdsa', hash: 'sha384', kty: 'EC' },
  '-36': { name: 'ES512', family: 'ecdsa', hash: 'sha512', kty: 'EC' },
  '-8': { name: 'EdDSA', family: 'eddsa', hash: null, kty: 'OKP' },
  '-257': { name: 'RS256', family: 'rsa-pkcs1', hash: 'sha256', kty: 'RSA' },
  '-258': { name: 'RS384', family: 'rsa-pkcs1', hash: 'sha384', kty: 'RSA' },
  '-259': { name: 'RS512', family: 'rsa-pkcs1', hash: 'sha512', kty: 'RSA' },
  '-37': { name: 'PS256', family: 'rsa-pss', hash: 'sha256', kty: 'RSA',
           saltLength: 32 },
  '-38': { name: 'PS384', family: 'rsa-pss', hash: 'sha384', kty: 'RSA',
           saltLength: 48 },
  '-39': { name: 'PS512', family: 'rsa-pss', hash: 'sha512', kty: 'RSA',
           saltLength: 64 },
  '-48': { name: 'ML-DSA-44', family: 'pq', hash: null, kty: 'AKP' },
  '-49': { name: 'ML-DSA-65', family: 'pq', hash: null, kty: 'AKP' },
  '-50': { name: 'ML-DSA-87', family: 'pq', hash: null, kty: 'AKP' },
  '-9': { name: 'ESP256', family: 'ecdsa', hash: 'sha256', kty: 'EC',
          curve: 'prime256v1' },
  '-51': { name: 'ESP384', family: 'ecdsa', hash: 'sha384', kty: 'EC',
           curve: 'secp384r1' },
  '-52': { name: 'ESP512', family: 'ecdsa', hash: 'sha512', kty: 'EC',
           curve: 'secp521r1' },
  '-47': { name: 'ES256K', family: 'ecdsa', hash: 'sha256', kty: 'EC',
           curve: 'secp256k1' },
  '-19': { name: 'Ed25519', family: 'eddsa', hash: null, kty: 'OKP',
           okp: 'ed25519' },
  '-53': { name: 'Ed448', family: 'eddsa', hash: null, kty: 'OKP',
           okp: 'ed448' },
  '-65535': { name: 'RS1', family: 'rsa-pkcs1', hash: 'sha1', kty: 'RSA',
              insecure: true }
};

// The COSE entry for an identifier, or null.
/**
 * Returns the COSE entry for an algorithm identifier.
 *
 * @param coseAlg - the identifier
 * @returns the entry, or null
 */
function coseSignatureAlg(coseAlg) {
  log.debug("Entering coseSignatureAlg(). alg=" + coseAlg);
  log.debug("Leaving coseSignatureAlg().");
  return COSE_SIGNATURE_ALGS[String(coseAlg)] || null;
}

// A public key as node holds one, from a KeyObject, a JWK, a PEM or a DER
// SubjectPublicKeyInfo; null when it is none of them.
function nodePublicKeyOf(key) {
  log.debug("Entering nodePublicKeyOf().");
  try {
    if (key && key.type === 'public' && key.asymmetricKeyType) {
      log.debug("Leaving nodePublicKeyOf(). A KeyObject.");
      return key;
    }
    if (key && key.kty) {
      const jwk = Object.assign({}, key);
      // node refuses a JWK carrying an `alg` it does not use for import, on
      // some versions; the algorithm is decided by the caller, not the key.
      delete jwk.alg;
      log.debug("Leaving nodePublicKeyOf(). A JWK.");
      return nodeCrypto.createPublicKey({ key: jwk, format: 'jwk' });
    }
    if (Buffer.isBuffer(key)) {
      log.debug("Leaving nodePublicKeyOf(). DER.");
      return nodeCrypto.createPublicKey({ key: key, format: 'der',
                                          type: 'spki' });
    }
    log.debug("Leaving nodePublicKeyOf(). PEM.");
    return nodeCrypto.createPublicKey(key);
  } catch (e) {
    log.debug("Caught in nodePublicKeyOf(): " + ((e && e.message) || e));
    log.debug("Leaving nodePublicKeyOf(). Unreadable.");
    return null;
  }
}

// Does `signature` verify over `data` under `key` with COSE algorithm
// `coseAlg`? SYNCHRONOUS — the WebAuthn assertion is checked inside a
// synchronous block of `authn.ts`, and every algorithm here is microseconds
// except ML-DSA, whose verification is a few hundred. `key` is anything
// `nodePublicKeyOf()` reads, or for ML-DSA an AKP JWK (`{ kty: 'AKP', pub }`)
// or the raw public key bytes. A key of the wrong kind for the algorithm is
// false, never a throw: an RSA key under ES256 is a signature that does not
// verify, and the caller says so.
/**
 * Says whether a signature verifies under a COSE algorithm, synchronously;
 * a key of the wrong kind is false, never a throw.
 *
 * @param coseAlg - the COSE algorithm identifier
 * @param key - the public key, or for ML-DSA an AKP JWK or the raw bytes
 * @param data - the bytes signed
 * @param signature - the signature
 * @param opts - `allowInsecure`: accept an algorithm marked insecure (RS1);
 *   refused otherwise
 * @returns true when it verifies
 */
function verifyCoseSignature(coseAlg, key, data, signature, opts) {
  log.debug("Entering verifyCoseSignature(). alg=" + coseAlg);
  const spec = coseSignatureAlg(coseAlg);
  if (!spec) {
    log.debug("Leaving verifyCoseSignature(). Unknown algorithm.");
    return false;
  }
  if (spec.insecure && !(opts && opts.allowInsecure)) {
    log.debug("Leaving verifyCoseSignature(). " + spec.name + " is insecure " +
              "and its caller did not allow it.");
    return false;
  }
  const message = Buffer.from(data || []);
  const sig = Buffer.from(signature || []);
  try {
    // A `publicKeyFromSpki()` answer — what a certificate's key is read as,
    // and the one form that carries an ML-DSA key out of a certificate node
    // may not be able to read.
    if (key && key.spki !== undefined && key.kind !== undefined) {
      if (spec.family === 'pq') {
        const read = key.kind === 'pq'
          ? pqcX509.decodeSpki(new Uint8Array(key.spki)) : null;
        const ok = !!read && String(read.alg) === spec.name &&
          !!pqJose.verify(spec.name, Buffer.from(read.pub), message, sig);
        log.debug("Leaving verifyCoseSignature(). " + spec.name +
                  " from a certificate " + ok);
        return ok;
      }
      key = key.key;
    }
    if (spec.family === 'pq') {
      const pub = key && key.pub !== undefined
        ? Buffer.from(key.pub, typeof key.pub === 'string' ? 'base64url'
                                                           : undefined)
        : Buffer.from(key || []);
      const ok = !!pqJose.verify(spec.name, pub, message, sig);
      log.debug("Leaving verifyCoseSignature(). " + spec.name + " " + ok);
      return ok;
    }
    const publicKey = nodePublicKeyOf(key);
    if (!publicKey) {
      log.debug("Leaving verifyCoseSignature(). No key.");
      return false;
    }
    const type = String(publicKey.asymmetricKeyType || '');
    // RFC 8230 section 5: 2048 bits or more, and never an exponent or a
    // modulus that makes a forgery (#202, see rsaKeyProblem()).
    const weak = rsaKeyProblem(publicKey, 2048);
    if (weak) {
      log.debug("Leaving verifyCoseSignature(). " + weak);
      return false;
    }
    // A FULLY SPECIFIED algorithm's curve (RFC 9864), checked against the
    // key rather than trusted from it.
    const curve = String((/** @type {any} */ (
      publicKey.asymmetricKeyDetails || {})).namedCurve || '');
    if ((spec.curve && curve !== spec.curve) ||
        (spec.okp && type !== spec.okp)) {
      log.debug("Leaving verifyCoseSignature(). " + spec.name + " under a " +
                (curve || type) + " key.");
      return false;
    }
    let ok = false;
    if (spec.family === 'ecdsa' && type === 'ec') {
      ok = nodeCrypto.verify(spec.hash, message,
                             { key: publicKey, dsaEncoding: 'der' }, sig);
    } else if (spec.family === 'eddsa' &&
               (type === 'ed25519' || type === 'ed448')) {
      ok = nodeCrypto.verify(null, message, publicKey, sig);
    } else if (spec.family === 'rsa-pkcs1' && type === 'rsa') {
      ok = nodeCrypto.verify(spec.hash, message, { key: publicKey,
        padding: nodeCrypto.constants.RSA_PKCS1_PADDING }, sig);
    } else if (spec.family === 'rsa-pss' &&
               (type === 'rsa' || type === 'rsa-pss')) {
      ok = nodeCrypto.verify(spec.hash, message, { key: publicKey,
        padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: spec.saltLength }, sig);
    }
    log.debug("Leaving verifyCoseSignature(). " + spec.name + " " + ok);
    return !!ok;
  } catch (e) {
    log.debug("Caught in verifyCoseSignature(): " + ((e && e.message) || e));
    log.debug("Leaving verifyCoseSignature(). Threw, so false.");
    return false;
  }
}

// ----- TPM 2.0 (Library Part 2) --------------------------------------------

// TPM_ALG_ID (Part 2, table 9) — the values the structures below name.
/** TPM_ALG_ID values the TPM structures name. */
const TPM_ALG = {
  RSA: 0x0001, SHA1: 0x0004, HMAC: 0x0005, AES: 0x0006, KEYEDHASH: 0x0008,
  SHA256: 0x000b, SHA384: 0x000c, SHA512: 0x000d, NULL: 0x0010,
  RSASSA: 0x0014, RSAES: 0x0015, RSAPSS: 0x0016, OAEP: 0x0017,
  ECDSA: 0x0018, ECDH: 0x0019, ECDAA: 0x001a, SM2: 0x001b,
  ECSCHNORR: 0x001c, ECC: 0x0023, SYMCIPHER: 0x0025
};
const TPM_HASHES = { 0x0004: 'sha1', 0x000b: 'sha256', 0x000c: 'sha384',
                     0x000d: 'sha512' };
// TPM_ECC_CURVE (Part 2, table 10), as a JWK curve and its coordinate size.
const TPM_CURVES = { 0x0003: { crv: 'P-256', bytes: 32 },
                     0x0004: { crv: 'P-384', bytes: 48 },
                     0x0005: { crv: 'P-521', bytes: 66 } };
// TPM_GENERATED_VALUE and TPM_ST_ATTEST_CERTIFY (Part 2, tables 7 and 19).
/** TPM_GENERATED_VALUE, the magic of a TPMS_ATTEST. */
const TPM_GENERATED_VALUE = 0xff544347;
/** TPM_ST_ATTEST_CERTIFY, the type of a certify attestation. */
const TPM_ST_ATTEST_CERTIFY = 0x8017;

// A reader over a TPM structure. Every read throws on a short buffer, and the
// parser's caller turns that into its refusal.
function tpmReader(bytes) {
  log.debug("Entering tpmReader().");
  const buf = Buffer.from(bytes || []);
  let at = 0;
  // A HOT PATH: the reader's methods carry no Entering/Leaving pair, for
  // `pki.js`'s sshReader()'s reason — once per field of every structure.
  const reader = {
    take: function (n) {
      if (n < 0 || at + n > buf.length) {
        // error-code: none — a parse failure, refused by the caller under
        // its own code
        throw new Error('the TPM structure is truncated');
      }
      const out = buf.subarray(at, at + n);
      at += n;
      return out;
    },
    u8: function () {
      return reader.take(1)[0];
    },
    u16: function () {
      return reader.take(2).readUInt16BE(0);
    },
    u32: function () {
      return reader.take(4).readUInt32BE(0);
    },
    u64: function () {
      return reader.take(8).readBigUInt64BE(0);
    },
    sized: function () {
      return Buffer.from(reader.take(reader.u16()));
    },
    left: function () {
      return buf.length - at;
    }
  };
  log.debug("Leaving tpmReader().");
  return reader;
}

// The node digest name of a TPM hash algorithm; throws for one not here.
/**
 * Returns node's digest name for a TPM hash algorithm.
 *
 * @param algId - the TPM_ALG_ID
 * @returns the digest name
 * @throws Error for one not known here
 */
function tpmHashName(algId) {
  log.debug("Entering tpmHashName(). alg=" + algId);
  const name = TPM_HASHES[Number(algId)];
  if (!name) {
    log.debug("Leaving tpmHashName(). Unknown.");
    // error-code: none — a parse failure, refused by the caller
    throw new Error('the TPM hash algorithm 0x' + Number(algId).toString(16) +
                    ' is not supported');
  }
  log.debug("Leaving tpmHashName().");
  return name;
}

// TPMT_PUBLIC (Part 2, section 12.2.4), for an RSA or ECC object — what a
// WebAuthn TPM statement's `pubArea` is. Answers `{ type, nameAlg,
// attributes, authPolicy, symmetric, scheme, keyBits, exponent, curveId,
// kdf, modulus, x, y, raw, jwk }`, `raw` being the bytes a Name hashes and
// `jwk` the public key. A TPM2B_PUBLIC's size prefix is NOT accepted:
// section 8.3 says the two bytes must be removed. Throws a sentence.
/**
 * Parses a TPMT_PUBLIC for an RSA or ECC object.
 *
 * @param bytes - the structure, without a TPM2B size prefix
 * @returns its fields, `raw` (the bytes a Name hashes) and `jwk`
 * @throws Error with a sentence
 */
function tpmParsePublic(bytes) {
  log.debug("Entering tpmParsePublic().");
  const raw = Buffer.from(bytes || []);
  const r = tpmReader(raw);
  const out = { type: r.u16(), nameAlg: r.u16(), attributes: r.u32(),
                authPolicy: r.sized(), symmetric: 0, scheme: 0,
                schemeHash: 0, keyBits: 0, exponent: 0, curveId: 0, kdf: 0,
                modulus: null, x: null, y: null, raw: raw, jwk: null };
  const symmetric = function () {
    log.debug("Entering symmetric().");
    const alg = r.u16();
    if (alg !== TPM_ALG.NULL) {
      r.u16();
      r.u16();
    }
    log.debug("Leaving symmetric().");
    return alg;
  };
  if (out.type === TPM_ALG.RSA) {
    out.symmetric = symmetric();
    out.scheme = r.u16();
    if (out.scheme !== TPM_ALG.NULL) {
      out.schemeHash = r.u16();
    }
    out.keyBits = r.u16();
    out.exponent = r.u32();
    out.modulus = r.sized();
    // An exponent of 0 is the TPM's way of saying the default, 2^16 + 1.
    const exponent = Buffer.alloc(4);
    exponent.writeUInt32BE(out.exponent || 65537, 0);
    let start = 0;
    while (start < 3 && exponent[start] === 0) {
      start++;
    }
    out.jwk = { kty: 'RSA', n: out.modulus.toString('base64url'),
                e: exponent.subarray(start).toString('base64url') };
  } else if (out.type === TPM_ALG.ECC) {
    out.symmetric = symmetric();
    out.scheme = r.u16();
    if (out.scheme !== TPM_ALG.NULL) {
      out.schemeHash = r.u16();
      if (out.scheme === TPM_ALG.ECDAA) {
        // TPMS_SCHEME_ECDAA carries a count beside the hash.
        r.u16();
      }
    }
    out.curveId = r.u16();
    out.kdf = r.u16();
    if (out.kdf !== TPM_ALG.NULL) {
      r.u16();
    }
    out.x = r.sized();
    out.y = r.sized();
    const curve = TPM_CURVES[out.curveId];
    if (!curve) {
      log.debug("Leaving tpmParsePublic(). Unsupported curve.");
      // error-code: none — a parse failure, refused by the caller
      throw new Error('the TPM curve 0x' + out.curveId.toString(16) +
                      ' is not supported');
    }
    const pad = Buffer.alloc(curve.bytes);
    out.jwk = { kty: 'EC', crv: curve.crv,
                x: Buffer.concat([pad, out.x]).subarray(-curve.bytes)
                  .toString('base64url'),
                y: Buffer.concat([pad, out.y]).subarray(-curve.bytes)
                  .toString('base64url') };
  } else {
    log.debug("Leaving tpmParsePublic(). Unsupported type.");
    // error-code: none — a parse failure, refused by the caller
    throw new Error('the TPM object type 0x' + out.type.toString(16) +
                    ' is not an RSA or ECC key');
  }
  if (r.left()) {
    log.debug("Leaving tpmParsePublic(). Trailing bytes.");
    // error-code: none — a parse failure, refused by the caller
    throw new Error(r.left() + ' byte(s) follow the TPMT_PUBLIC');
  }
  log.debug("Leaving tpmParsePublic().");
  return out;
}

// TPMS_ATTEST (Part 2, section 10.12.8), of which WebAuthn reads the
// certify form. Answers `{ magic, type, qualifiedSigner, extraData, clock,
// resetCount, restartCount, safe, firmwareVersion, name, qualifiedName }`;
// `name` and `qualifiedName` only for TPM_ST_ATTEST_CERTIFY. Throws a
// sentence; the caller checks the values.
/**
 * Parses a TPMS_ATTEST.
 *
 * @param bytes - the structure
 * @returns its fields, with `name` and `qualifiedName` for a certify
 * @throws Error with a sentence
 */
function tpmParseAttest(bytes) {
  log.debug("Entering tpmParseAttest().");
  const r = tpmReader(bytes);
  const out = {
    magic: r.u32(), type: r.u16(), qualifiedSigner: r.sized(),
    extraData: r.sized(), clock: r.u64(), resetCount: r.u32(),
    restartCount: r.u32(), safe: r.u8(), firmwareVersion: r.u64(),
    name: null, qualifiedName: null
  };
  if (out.type === TPM_ST_ATTEST_CERTIFY) {
    out.name = r.sized();
    out.qualifiedName = r.sized();
    if (r.left()) {
      log.debug("Leaving tpmParseAttest(). Trailing bytes.");
      // error-code: none — a parse failure, refused by the caller
      throw new Error(r.left() + ' byte(s) follow the TPMS_CERTIFY_INFO');
    }
  }
  log.debug("Leaving tpmParseAttest().");
  return out;
}

// TPMT_SIGNATURE (Part 2, section 11.3.4): `{ sigAlg, hash, signature }`,
// the signature as a verifier takes it — RSA's bytes, or an ECDSA
// signature as DER. null when `bytes` is not exactly one such structure,
// which is how the verifier tells it from a bare signature (see
// `webauthn_attestation.ts`).
/**
 * Parses a TPMT_SIGNATURE.
 *
 * @param bytes - the structure
 * @returns `{ sigAlg, hash, signature }`, or null when it is not exactly
 *   one such structure
 */
function tpmParseSignature(bytes) {
  log.debug("Entering tpmParseSignature().");
  try {
    const r = tpmReader(bytes);
    const sigAlg = r.u16();
    let out = null;
    if (sigAlg === TPM_ALG.RSASSA || sigAlg === TPM_ALG.RSAPSS) {
      out = { sigAlg: sigAlg, hash: r.u16(), signature: r.sized() };
    } else if (sigAlg === TPM_ALG.ECDSA) {
      const hash = r.u16();
      const rr = r.sized();
      const ss = r.sized();
      const integer = function (b) {
        log.debug("Entering integer().");
        log.debug("Leaving integer().");
        return new asn1js.Integer({ valueHex: new Uint8Array(
          Buffer.concat([Buffer.from([0]), b])) });
      };
      const der = new asn1js.Sequence({ value: [integer(rr), integer(ss)] })
        .toBER(false);
      out = { sigAlg: sigAlg, hash: hash, signature: Buffer.from(der) };
    }
    if (!out || r.left()) {
      log.debug("Leaving tpmParseSignature(). Not one TPMT_SIGNATURE.");
      return null;
    }
    log.debug("Leaving tpmParseSignature().");
    return out;
  } catch (e) {
    log.debug("Caught in tpmParseSignature(): " + ((e && e.message) || e));
    log.debug("Leaving tpmParseSignature(). Unreadable.");
    return null;
  }
}

// TPM2B_NAME's contents for an object (Part 1, section 16): nameAlg ‖
// H_nameAlg(TPMT_PUBLIC).
/**
 * Returns an object's TPM2B_NAME contents: nameAlg and the hash of its
 * TPMT_PUBLIC.
 *
 * @param parsedPublic - `tpmParsePublic()`'s answer
 * @returns the Name
 */
function tpmName(parsedPublic) {
  log.debug("Entering tpmName().");
  const alg = Buffer.alloc(2);
  alg.writeUInt16BE(parsedPublic.nameAlg, 0);
  log.debug("Leaving tpmName().");
  return Buffer.concat([alg, nodeCrypto.createHash(
    tpmHashName(parsedPublic.nameAlg)).update(parsedPublic.raw).digest()]);
}

// ----- the certificate extensions WebAuthn defines --------------------------

// The ASN.1 of an extension's value, or null. Typed loosely: its callers
// walk constructed values asn1js's union of value blocks does not narrow.
/** @returns {any} */
function berOf(bytes) {
  log.debug("Entering berOf().");
  const parsed = asn1js.fromBER(new Uint8Array(Buffer.from(bytes || [])));
  log.debug("Leaving berOf().");
  return parsed.offset === -1 ? null : parsed.result;
}

// id-fido-gen-ce-aaguid (1.3.6.1.4.1.45724.1.1.4, section 8.2.1): the
// extension's value is an OCTET STRING of the 16-byte AAGUID. Answers the
// AAGUID or null.
/**
 * Reads the id-fido-gen-ce-aaguid extension's AAGUID.
 *
 * @param extnValue - the extension's value
 * @returns the AAGUID, or null
 */
function fidoAaguidExtension(extnValue) {
  log.debug("Entering fidoAaguidExtension().");
  const read = berOf(extnValue);
  if (!read || !(read instanceof asn1js.OctetString)) {
    log.debug("Leaving fidoAaguidExtension(). Not an OCTET STRING.");
    return null;
  }
  const value = Buffer.from(read.valueBlock.valueHexView);
  log.debug("Leaving fidoAaguidExtension(). " + value.length + " bytes.");
  return value.length === 16 ? value : null;
}

// Apple's anonymous attestation nonce (1.2.840.113635.100.8.2, section
// 8.8): SEQUENCE { [1] EXPLICIT OCTET STRING }. Answers the nonce or null.
/**
 * Reads Apple's anonymous attestation nonce extension.
 *
 * @param extnValue - the extension's value
 * @returns the nonce, or null
 */
function appleAttestationNonce(extnValue) {
  log.debug("Entering appleAttestationNonce().");
  const read = berOf(extnValue);
  const tagged = read && read.valueBlock && Array.isArray(read.valueBlock.value)
    ? read.valueBlock.value.filter(function (one) {
      return one.idBlock.tagClass === 3 && one.idBlock.tagNumber === 1;
    })[0] : null;
  const inner = tagged && tagged.valueBlock &&
    Array.isArray(tagged.valueBlock.value) ? tagged.valueBlock.value[0] : null;
  if (!inner || !(inner instanceof asn1js.OctetString)) {
    log.debug("Leaving appleAttestationNonce(). Not the structure.");
    return null;
  }
  log.debug("Leaving appleAttestationNonce().");
  return Buffer.from(inner.valueBlock.valueHexView);
}

// Android's KeyDescription (1.3.6.1.4.1.11129.2.1.17, section 8.4.1, the
// schema in Android's key attestation documentation):
//
//   KeyDescription ::= SEQUENCE {
//     attestationVersion INTEGER, attestationSecurityLevel ENUMERATED,
//     keyMintVersion INTEGER, keyMintSecurityLevel ENUMERATED,
//     attestationChallenge OCTET STRING, uniqueId OCTET STRING,
//     softwareEnforced AuthorizationList,
//     hardwareEnforced AuthorizationList }   -- "teeEnforced" before v100
//
// Of an AuthorizationList, the three fields section 8.4 reads: `purpose`
// ([1] EXPLICIT SET OF INTEGER), `allApplications` ([600] EXPLICIT NULL)
// and `origin` ([702] EXPLICIT INTEGER). Answers `{ attestationVersion,
// attestationSecurityLevel, attestationChallenge, softwareEnforced,
// teeEnforced }` with each list as `{ purpose: [], allApplications,
// origin }`, or throws a sentence.
/**
 * Reads Android's KeyDescription extension.
 *
 * @param extnValue - the extension's value
 * @returns `{ attestationVersion, attestationSecurityLevel,
 *   attestationChallenge, softwareEnforced, teeEnforced }`
 * @throws Error with a sentence
 */
function androidKeyDescription(extnValue) {
  log.debug("Entering androidKeyDescription().");
  const read = berOf(extnValue);
  const items = read && read.valueBlock && Array.isArray(read.valueBlock.value)
    ? read.valueBlock.value : [];
  if (items.length < 8) {
    log.debug("Leaving androidKeyDescription(). Not a KeyDescription.");
    // error-code: none — a parse failure, refused by the caller
    throw new Error('the Android key attestation extension is not a ' +
                    'KeyDescription (it has ' + items.length + ' field(s), ' +
                    'not 8)');
  }
  const integer = function (one) {
    log.debug("Entering integer().");
    log.debug("Leaving integer().");
    return one && one.valueBlock && one.valueBlock.valueDec !== undefined
      ? Number(one.valueBlock.valueDec) : NaN;
  };
  const list = function (one) {
    log.debug("Entering list().");
    const out = { purpose: [], allApplications: false, origin: null };
    const fields = one && one.valueBlock && Array.isArray(one.valueBlock.value)
      ? one.valueBlock.value : [];
    fields.forEach(function (field) {
      if (field.idBlock.tagClass !== 3) {
        return;
      }
      const inner = field.valueBlock && Array.isArray(field.valueBlock.value)
        ? field.valueBlock.value[0] : null;
      if (field.idBlock.tagNumber === 1 && inner &&
          Array.isArray(inner.valueBlock.value)) {
        out.purpose = inner.valueBlock.value.map(integer);
      } else if (field.idBlock.tagNumber === 600) {
        out.allApplications = true;
      } else if (field.idBlock.tagNumber === 702) {
        out.origin = integer(inner);
      }
    });
    log.debug("Leaving list().");
    return out;
  };
  if (!(items[4] instanceof asn1js.OctetString)) {
    log.debug("Leaving androidKeyDescription(). No challenge.");
    // error-code: none — a parse failure, refused by the caller
    throw new Error('the KeyDescription\'s attestationChallenge is not an ' +
                    'OCTET STRING');
  }
  const out = {
    attestationVersion: integer(items[0]),
    attestationSecurityLevel: integer(items[1]),
    attestationChallenge: Buffer.from(items[4].valueBlock.valueHexView),
    softwareEnforced: list(items[6]),
    teeEnforced: list(items[7])
  };
  log.debug("Leaving androidKeyDescription(). version " +
            out.attestationVersion);
  return out;
}

// ----- A certificate request's attestation (#164 phase 2, 2026-09-26) ------
//
// draft-ietf-lamps-csr-attestation (revision 29, September 2026) section
// 4.3: a PKCS#10 request carries at most ONE attribute of type
// id-aa-attestation (1.2.840.113549.1.9.16.2.59) holding exactly one
//
//   AttestationBundle ::= SEQUENCE {
//     attestations SEQUENCE SIZE (1..MAX) OF AttestationStatement,
//     certs SEQUENCE SIZE (1..MAX) OF LimitedCertChoices OPTIONAL }
//   AttestationStatement ::= SEQUENCE { type OBJECT IDENTIFIER, stmt ANY }
//
// and LimitedCertChoices is a Certificate or an `other [3]`. (Figure 2 of
// revision 29 ends `certs ... OPTIONAL,` with a trailing comma, which is not
// valid ASN.1; the structure is read as written above.) An
// AttestationStatement is exactly TWO elements: revision 20's
// EvidenceStatement carried a third, `hint IA5String OPTIONAL`, and revision
// 29 has none, so a three-element statement is refused rather than read.
//
// RE-CHECKED ON 2026-10-06 (#257), AND NO CURRENT DOCUMENT DEFINES THE TPM
// STATEMENT. Revision 29 defines no statement format (section 4.2) and
// leaves the OID and syntax to "specification authors who define an
// attestation-statement format". Revision 21 removed appendix A.2, the TPM
// 2.0 example, and revisions 22 to 29 carry no TPM text; the working group's
// sample-data repository (lamps-wg/csr-attestation-examples) holds only a
// README, and no TCG profile of the statement was found (the TCG's OID
// registry was not reachable to check). So the TPM 2.0 statement verified is
// the TCG's `tcg-attest-tpm-certify` (2.23.133.20.1) in the one syntax ever
// published, revision 20's appendix A.2.3:
//
//   Tcg-csr-tpm-certify ::= SEQUENCE {
//     tpmSAttest OCTET STRING, signature OCTET STRING,
//     tpmTPublic OCTET STRING OPTIONAL }
//
// rcbj's rule is that a disagreement between a specification and itself is
// FLAGGED, not resolved silently, and revision 20 disagrees with itself (the
// list is on #257 too):
//
//   1. A.2.2 writes `tcg-kp-AIKCertificate ::= { id-tcg 8 3 }` where the
//      module defines only `tcg`; the value read is 2.23.133.8.3, the TCG EK
//      Credential Profile's (`device_attestation.ts`'s OID_TCG_AIK).
//   2. A.1's statement set names the type `Tcg-attest-tpm-certify`; A.2.3
//      defines `Tcg-csr-tpm-certify`. Only the OID is on the wire.
//   3. Section 5 says the A.2 example carries the hint
//      "tpmverifier.example.com"; A.2.3 has no hint, and revision 29's
//      AttestationStatement has no hint field. Revision 29 is followed.
//   4. A.2.5.5 says TPM2_Certify yields "TPM2B_ATTEST" and TPM2_ReadPublic
//      "TPM2B_PUBLIC" (both SIZED), while A.2.3's fields are named for
//      TPMS_ATTEST and TPMT_PUBLIC (both bare). BOTH spellings are read
//      (`tpm2bContents()`), and the reading is unambiguous: a TPMS_ATTEST
//      begins with TPM_GENERATED_VALUE (0xff544347), whose first two octets
//      are no plausible size, and a TPMT_PUBLIC with its type, which equals
//      its own length minus two only for a 3- or 37-octet structure no key
//      has.
//   5. A.2.5.5 lists TPM2_Certify's inputs as the key and the AK and OMITS
//      qualifyingData — the input that becomes extraData, and the only place
//      a freshness nonce can be.
//   6. Revision 29 section 4.3 says an attestation-format specification
//      "should mandate the precise mechanism for nonce selection", and none
//      exists for this one. This service's rule, which
//      draft-ietf-lamps-attestation-freshness section 8 ("MUST use the
//      received nonce") implies: extraData IS the nonce's octets, with no
//      transformation (`common/cert_enrollment.ts`, #257).
//   7. The trailing comma in revision 29's Figure 2, above.
//
// These answer the structures; `common/device_attestation.ts` verifies them.
/** The id-aa-attestation attribute's OID. */
const ID_AA_ATTESTATION = '1.2.840.113549.1.9.16.2.59';
/** The tcg-attest-tpm-certify statement type's OID. */
const TCG_ATTEST_TPM_CERTIFY = '2.23.133.20.1';

// An AttestationBundle's DER as `{ attestations: [{ type, stmt }], certs:
// [der], otherCerts }` — `stmt` the DER of the statement's value, `certs`
// the X.509 certificates, `otherCerts` how many `other` formats were carried
// (none is read). Throws a sentence on anything else.
/**
 * Reads a certificate request's AttestationBundle.
 *
 * @param der - the attribute value's DER
 * @returns `{ attestations: [{ type, stmt }], certs, otherCerts }`
 * @throws Error with a sentence
 */
function csrAttestationBundle(der) {
  log.debug("Entering csrAttestationBundle().");
  const read = berOf(der);
  const items = read instanceof asn1js.Sequence ? read.valueBlock.value : null;
  if (!items || items.length < 1 || items.length > 2 ||
      !(items[0] instanceof asn1js.Sequence)) {
    log.debug("Leaving csrAttestationBundle(). Not a bundle.");
    // error-code: none — a parse failure, refused by the caller
    throw new Error('the id-aa-attestation value is not an AttestationBundle');
  }
  const attestations = items[0].valueBlock.value.map(function (one) {
    const pair = one instanceof asn1js.Sequence ? one.valueBlock.value : [];
    if (pair.length !== 2 ||
        !(pair[0] instanceof asn1js.ObjectIdentifier)) {
      // error-code: none — a parse failure, refused by the caller
      throw new Error('an AttestationStatement is not { type, stmt }');
    }
    return { type: pair[0].valueBlock.toString(),
             stmt: Buffer.from(pair[1].valueBeforeDecodeView) };
  });
  if (!attestations.length) {
    log.debug("Leaving csrAttestationBundle(). No statement.");
    // error-code: none — a parse failure, refused by the caller
    throw new Error('the AttestationBundle carries no attestation ' +
                    '(SIZE (1..MAX))');
  }
  const certs = [];
  let otherCerts = 0;
  if (items[1]) {
    if (!(items[1] instanceof asn1js.Sequence) ||
        !items[1].valueBlock.value.length) {
      log.debug("Leaving csrAttestationBundle(). Bad certs.");
      // error-code: none — a parse failure, refused by the caller
      throw new Error('the AttestationBundle\'s certs is not a non-empty ' +
                      'SEQUENCE');
    }
    items[1].valueBlock.value.forEach(function (one) {
      if (one instanceof asn1js.Sequence) {
        certs.push(Buffer.from(one.valueBeforeDecodeView));
      } else if (one.idBlock.tagClass === 3 && one.idBlock.tagNumber === 3) {
        otherCerts++;
      } else {
        // error-code: none — a parse failure, refused by the caller
        throw new Error('a certificate in the AttestationBundle is neither ' +
                        'a Certificate nor an other format (the draft ' +
                        'forbids the attribute-certificate choices)');
      }
    });
  }
  log.debug("Leaving csrAttestationBundle(). " + attestations.length +
            " statement(s), " + certs.length + " certificate(s).");
  return { attestations: attestations, certs: certs, otherCerts: otherCerts };
}

// A TPM2B's contents when `bytes` is exactly one TPM2B (a big-endian size
// then that many bytes), else `bytes` unchanged. Revision 20's appendix said
// the attester sends "TPM2B_ATTEST in binary format" and "TPM2B_PUBLIC"
// while the signature and the Name are over the contents, so both spellings
// are read, as WebAuthn's tpm format reads `sig` both ways (disagreement 4
// above).
/**
 * Returns a TPM2B's contents when the bytes are exactly one TPM2B, else the
 * bytes unchanged.
 *
 * @param bytes - the bytes
 * @returns the contents
 */
function tpm2bContents(bytes) {
  log.debug("Entering tpm2bContents().");
  const buf = Buffer.from(bytes || []);
  const sized = buf.length >= 2 && buf.readUInt16BE(0) === buf.length - 2;
  log.debug("Leaving tpm2bContents(). " + (sized ? 'Sized.' : 'Bare.'));
  return sized ? buf.subarray(2) : buf;
}

// Tcg-csr-tpm-certify's DER as `{ tpmSAttest, signature, tpmTPublic }`,
// each a Buffer (tpmTPublic null when absent), with TPM2B size prefixes
// taken off. Throws a sentence.
/**
 * Reads a Tcg-csr-tpm-certify statement, TPM2B size prefixes taken off.
 *
 * @param der - the statement's DER
 * @returns `{ tpmSAttest, signature, tpmTPublic }`
 * @throws Error with a sentence
 */
function tcgTpmCertifyStatement(der) {
  log.debug("Entering tcgTpmCertifyStatement().");
  const read = berOf(der);
  const items = read instanceof asn1js.Sequence ? read.valueBlock.value : [];
  const octets = items.filter(function (one) {
    return one instanceof asn1js.OctetString;
  });
  if (items.length < 2 || items.length > 3 || octets.length !== items.length) {
    log.debug("Leaving tcgTpmCertifyStatement(). Not the structure.");
    // error-code: none — a parse failure, refused by the caller
    throw new Error('the tcg-attest-tpm-certify statement is not SEQUENCE ' +
                    '{ tpmSAttest, signature, tpmTPublic OPTIONAL }');
  }
  const bytes = function (one) {
    log.debug("Entering bytes().");
    log.debug("Leaving bytes().");
    return Buffer.from(one.valueBlock.valueHexView);
  };
  log.debug("Leaving tcgTpmCertifyStatement().");
  return { tpmSAttest: tpm2bContents(bytes(items[0])),
           signature: bytes(items[1]),
           tpmTPublic: items[2] ? tpm2bContents(bytes(items[2])) : null };
}

// ===========================================================================
// SECTION 11 — SIGSTORE AND TUF: CANONICAL JSON, THRESHOLD SIGNATURES, THE
// REKOR SIGNED ENTRY TIMESTAMP AND DSSE (#170, 2026-09-23)
//
// What `spiffe/spiffe_sigstore.ts` and `spiffe/spiffe_sigstore_tuf.ts` need
// to believe a cosign signature and the sigstore trust root, as primitives:
//
//   * TWO CANONICAL JSON FORMS, and they are not the same thing. TUF
//     metadata is signed over securesystemslib's OLPC canonical form (sorted
//     keys, no whitespace, only `"` and `\` escaped, integers only); a Rekor
//     signed entry timestamp over RFC 8785 JCS (`jsoncanonicalizer` in
//     cosign). Written separately because a string with a control character
//     canonicalizes differently under the two, and a verifier that used the
//     wrong one would refuse good metadata or — worse — sign-check a
//     different byte string from the one that was signed.
//   * `verifyThresholdSignatures()`: TUF's rule — at least `threshold`
//     DISTINCT keyids of a role, each a key the role names, each signature
//     verifying over the canonical bytes. A keyid signing twice counts once.
//   * `verifyRekorSet()`: cosign's `VerifySET()` — the SET is an ECDSA
//     (ASN.1) signature over the JCS form of `{body, integratedTime,
//     logIndex, logID}`, by the log whose key's SHA-256 is `logID`.
//   * `dssePae()`: DSSE's pre-authentication encoding, which is what an
//     in-toto attestation's signature covers.
//   * `verifyWithPublicKey()`: one signature under a key held as an SPKI,
//     with the scheme cosign uses for the key's kind — ECDSA with SHA-256
//     (whatever the curve, as cosign's `LoadVerifier(pub, SHA256)`), RSA
//     PKCS#1 v1.5 with SHA-256, Ed25519, and the post-quantum families,
//     which cosign does not have and a key file here may hold.
// ===========================================================================

// securesystemslib's canonical JSON (OLPC): what a TUF signature covers.
// Throws on a value that has no canonical form (a non-integer number).
// A HOT PATH: it recurses once per value in a metadata document, so no
// Entering/Leaving pair — one would drown the log in thousands of lines per
// refresh.
/**
 * Serializes a value as securesystemslib's canonical JSON: what a TUF
 * signature covers.
 *
 * @param value - the value
 * @returns the canonical JSON
 * @throws Error for a value with no canonical form
 */
function olpcCanonicalJson(value) {
  if (value === null) {
    return 'null';
  }
  if (value === true || value === false) {
    return String(value);
  }
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      // error-code: none — a parse failure; the caller refuses the metadata
      throw new Error('canonical JSON has no floating-point numbers');
    }
    return String(value);
  }
  if (typeof value === 'string') {
    return '"' + value.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  }
  if (Array.isArray(value)) {
    return '[' + value.map(olpcCanonicalJson).join(',') + ']';
  }
  if (typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(function (key) {
      return olpcCanonicalJson(key) + ':' + olpcCanonicalJson(value[key]);
    }).join(',') + '}';
  }
  // error-code: none — a parse failure; the caller refuses the metadata
  throw new Error('canonical JSON cannot hold a ' + typeof value);
}

// RFC 8785 (JCS): ES6 serialization of strings and numbers, keys sorted by
// UTF-16 code units — which is JavaScript's own string comparison. A HOT
// PATH for the same reason as the function above: no Entering/Leaving pair
// in a function that recurses per value would drown the log.
/**
 * Serializes a value as RFC 8785 (JCS) canonical JSON.
 *
 * @param value - the value
 * @returns the canonical JSON
 */
function jcsCanonicalJson(value) {
  if (value === null || typeof value === 'boolean' ||
      typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      // error-code: none — a parse failure; the caller refuses the entry
      throw new Error('JCS has no representation for ' + value);
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(jcsCanonicalJson).join(',') + ']';
  }
  if (typeof value === 'object') {
    return '{' + Object.keys(value).sort().filter(function (key) {
      return value[key] !== undefined;
    }).map(function (key) {
      return JSON.stringify(key) + ':' + jcsCanonicalJson(value[key]);
    }).join(',') + '}';
  }
  // error-code: none — a parse failure; the caller refuses the entry
  throw new Error('JCS cannot hold a ' + typeof value);
}

// The DER SubjectPublicKeyInfo of a PEM `PUBLIC KEY` (or a bare base64
// body), or null. Read as bytes rather than through node, so a post-quantum
// key node cannot parse is still one.
/**
 * Returns the DER SubjectPublicKeyInfo of a PEM public key, read as bytes.
 *
 * @param pem - a `PUBLIC KEY` PEM, or a bare base64 body
 * @returns the DER, or null
 */
function spkiFromPublicKeyPem(pem) {
  log.debug("Entering spkiFromPublicKeyPem().");
  const text = String(pem || '');
  const match = /-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----/
    .exec(text);
  const body = (match ? match[1] : text).replace(/\s+/g, '');
  if (!body || /[^A-Za-z0-9+/=]/.test(body)) {
    log.debug("Leaving spkiFromPublicKeyPem(). Not a key.");
    return null;
  }
  const der = Buffer.from(body, 'base64');
  const described = publicKeyFromSpki(der);
  log.debug("Leaving spkiFromPublicKeyPem(). " + (described.kind || 'none'));
  return described.kind ? der : null;
}

// The PEM of a DER SubjectPublicKeyInfo, as cosign writes one
// (`cryptoutils.MarshalPublicKeyToPEM`).
/**
 * Returns the PEM of a DER SubjectPublicKeyInfo, as cosign writes one.
 *
 * @param spkiDer - the DER
 * @returns the PEM
 */
function publicKeyPemOfSpki(spkiDer) {
  log.debug("Entering publicKeyPemOfSpki().");
  const b64 = Buffer.from(spkiDer || []).toString('base64');
  log.debug("Leaving publicKeyPemOfSpki().");
  return '-----BEGIN PUBLIC KEY-----\n' +
         (b64.match(/.{1,64}/g) || []).join('\n') +
         '\n-----END PUBLIC KEY-----\n';
}

// ONE SIGNATURE UNDER A KEY HELD AS AN SPKI, with the scheme cosign uses for
// that kind of key (see the section head). `ecdsaEncoding` is 'der' (cosign,
// Rekor, TUF, CT) unless a caller says 'p1363'.
/**
 * Verifies one signature under a key held as an SPKI, with the scheme
 * cosign uses for that kind of key.
 *
 * @param spkiDer - the key's SPKI
 * @param data - the bytes signed
 * @param signature - the signature
 * @param ecdsaEncoding - `der` (the default) or `p1363`
 * @returns a promise of true or false
 */
async function verifyWithPublicKey(spkiDer, data, signature, ecdsaEncoding) {
  log.debug("Entering verifyWithPublicKey().");
  const described = publicKeyFromSpki(spkiDer);
  let scheme = null;
  if (described.kind === 'ec') {
    scheme = { family: 'ecdsa', hash: 'sha256',
               encoding: ecdsaEncoding || 'der' };
  } else if (described.kind === 'rsa') {
    scheme = { family: 'rsa-pkcs1', hash: 'sha256' };
  } else if (described.kind === 'ed25519' || described.kind === 'ed448') {
    scheme = { family: 'eddsa' };
  } else if (described.kind === 'pq') {
    scheme = { family: 'pq' };
  }
  if (!scheme) {
    log.debug("Leaving verifyWithPublicKey(). An unusable key.");
    return false;
  }
  const ok = await verifyRawSignature(scheme, described, data, signature);
  log.debug("Leaving verifyWithPublicKey(). " + ok);
  return ok;
}

// A TUF key (`{ keytype, scheme, keyval: { public } }`) as an SPKI, or null.
// ecdsa and rsa keys carry a PEM; an ed25519 key carries the 32 raw bytes as
// hex, which is wrapped in the fixed Ed25519 SPKI prefix (RFC 8410).
/**
 * Returns a TUF key as an SPKI.
 *
 * @param key - `{ keytype, scheme, keyval: { public } }`
 * @returns the DER, or null
 */
function tufKeySpki(key) {
  log.debug("Entering tufKeySpki().");
  const type = String((key && key.keytype) || '');
  const pub = String(((key && key.keyval) || {}).public || '');
  if (type === 'ed25519' && /^[0-9a-f]{64}$/i.test(pub)) {
    log.debug("Leaving tufKeySpki(). ed25519.");
    return Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'),
                          Buffer.from(pub, 'hex')]);
  }
  if (['ecdsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'rsa',
       'sigstore-oidc'].indexOf(type) >= 0 || /BEGIN PUBLIC KEY/.test(pub)) {
    log.debug("Leaving tufKeySpki(). PEM.");
    return spkiFromPublicKeyPem(pub);
  }
  log.debug("Leaving tufKeySpki(). Not a key this reads.");
  return null;
}

// TUF's threshold rule over one role (see the section head). `role` is
// `{ keyids, threshold }` and `keys` the root's key table. Resolves
// `{ ok, valid, threshold }`; `ok` only when at least `threshold` distinct
// keyids of the role verified.
/**
 * Applies TUF's threshold rule over one role's signatures.
 *
 * @param signed - the signed metadata
 * @param signatures - the signatures
 * @param keys - the root's key table
 * @param role - `{ keyids, threshold }`
 * @returns a promise of `{ ok, valid, threshold }`
 */
async function verifyThresholdSignatures(signed, signatures, keys, role) {
  log.debug("Entering verifyThresholdSignatures().");
  const threshold = Number((role && role.threshold) || 0);
  const allowed = ((role && role.keyids) || []).map(String);
  if (!Number.isInteger(threshold) || threshold < 1) {
    log.debug("Leaving verifyThresholdSignatures(). No threshold.");
    return { ok: false, valid: 0, threshold: threshold };
  }
  let bytes = null;
  try {
    bytes = Buffer.from(olpcCanonicalJson(signed), 'utf8');
  } catch (e) {
    log.debug("Caught in verifyThresholdSignatures(): " +
              ((e && e.message) || e));
    log.debug("Leaving verifyThresholdSignatures(). Not canonical.");
    return { ok: false, valid: 0, threshold: threshold };
  }
  const counted = {};
  const list = Array.isArray(signatures) ? signatures : [];
  for (let i = 0; i < list.length; i++) {
    const keyid = String((list[i] && list[i].keyid) || '');
    if (!keyid || counted[keyid] || allowed.indexOf(keyid) < 0) continue;
    const spki = tufKeySpki((keys || {})[keyid]);
    const sigHex = String((list[i] && list[i].sig) || '');
    if (!spki || !/^[0-9a-f]*$/i.test(sigHex) || !sigHex) continue;
    if (await verifyWithPublicKey(spki, bytes, Buffer.from(sigHex, 'hex'))) {
      counted[keyid] = true;
    }
  }
  const valid = Object.keys(counted).length;
  log.debug("Leaving verifyThresholdSignatures(). " + valid + " of " +
            threshold);
  return { ok: valid >= threshold, valid: valid, threshold: threshold };
}

// cosign's VerifySET(): `payload` is the bundle's `{ body, integratedTime,
// logIndex, logID }`, `set` the signed entry timestamp's bytes, `logs` the
// trusted Rekor logs `[{ logIdHex, spki }]`. Resolves '' when it verifies,
// otherwise why not.
/**
 * Verifies a Rekor signed entry timestamp: cosign's VerifySET().
 *
 * @param payload - `{ body, integratedTime, logIndex, logID }`
 * @param set - the signed entry timestamp's bytes
 * @param logs - the trusted Rekor logs `[{ logIdHex, spki }]`
 * @returns a promise of empty when it verifies, otherwise why not
 */
async function verifyRekorSet(payload, set, logs) {
  log.debug("Entering verifyRekorSet().");
  const p = payload || {};
  const logId = String(p.logID || '').toLowerCase();
  const trusted = (logs || []).filter(function (one) {
    return String(one.logIdHex || '').toLowerCase() === logId;
  })[0];
  if (!trusted) {
    log.debug("Leaving verifyRekorSet(). Unknown log.");
    return 'rekor log public key not found for payload (log ID ' + logId + ')';
  }
  let canonical = null;
  try {
    canonical = Buffer.from(jcsCanonicalJson({
      body: p.body, integratedTime: p.integratedTime,
      logIndex: p.logIndex, logID: p.logID }), 'utf8');
  } catch (e) {
    log.debug("Caught in verifyRekorSet(): " + ((e && e.message) || e));
    log.debug("Leaving verifyRekorSet(). Not canonical.");
    return 'the bundle payload cannot be canonicalized: ' +
           ((e && e.message) || e);
  }
  const ok = await verifyWithPublicKey(trusted.spki, canonical,
                                       Buffer.from(set || []));
  log.debug("Leaving verifyRekorSet(). " + ok);
  return ok ? '' : 'unable to verify SET';
}

// DSSE v1 pre-authentication encoding: "DSSEv1" SP LEN(type) SP type SP
// LEN(body) SP body, the lengths in ASCII decimal bytes.
/**
 * Returns the DSSE v1 pre-authentication encoding.
 *
 * @param payloadType - the payload type
 * @param payload - the payload
 * @returns the encoded bytes
 */
function dssePae(payloadType, payload) {
  log.debug("Entering dssePae().");
  const type = Buffer.from(String(payloadType || ''), 'utf8');
  const body = Buffer.from(payload || []);
  log.debug("Leaving dssePae().");
  return Buffer.concat([
    Buffer.from('DSSEv1 ' + type.length + ' ', 'utf8'), type,
    Buffer.from(' ' + body.length + ' ', 'utf8'), body]);
}

// Lower-case hex SHA-256 of bytes, and SHA-512 — the two hashes TUF target
// metadata and Rekor entries name. HOT PATHS: called per blob and per
// metadata file, one line each, so no Entering/Leaving pair — it would
// drown the log.
/**
 * Returns the lower-case hex SHA-256 of bytes.
 *
 * @param bytes - the bytes
 * @returns the digest
 */
function sha256Hex(bytes) {
  return nodeCrypto.createHash('sha256').update(Buffer.from(bytes || []))
    .digest('hex');
}

/**
 * Returns the lower-case hex SHA-512 of bytes.
 *
 * @param bytes - the bytes
 * @returns the digest
 */
function sha512Hex(bytes) {
  return nodeCrypto.createHash('sha512').update(Buffer.from(bytes || []))
    .digest('hex');
}

// ===========================================================================
// SECTION 12 — DKIM (RFC 6376, RFC 8463), FOR THE MAIL CHANNEL (#63).
//
// **WHY HERE AND NOT IN THE MAIL LIBRARY.** `common/mail.ts`'s SMTP transport
// is built on nodemailer, which has a DKIM signer of its own; it is not used,
// for the one-crypto-module rule this file's header argues — a second signer
// with its own key handling and its own canonicalization is exactly the
// drift that header records. So the MESSAGE is composed by the library, and
// its signature is made here.
//
// Both halves of the signature scheme are here, the canonicalization with the
// signing, for the same reason XML canonicalization sits with XML signing: a
// canonicalization that disagrees with the verifier's is a signature that
// fails with nothing to say why, and that is a property of the signature,
// not of the message.
//
// **relaxed/relaxed ONLY** (section 3.4.2 and 3.4.4). `simple` breaks on any
// relay that rewraps a header, and nothing here needs it.
//
// Two algorithms: `rsa-sha256` (section 3.3.1; RFC 8301 made it the only RSA
// one and set 1024 bits as the floor — this refuses less than 2048, the
// size RFC 8301 recommends) and `ed25519-sha256` (RFC 8463: PureEdDSA over the
// SHA-256 of the canonicalized header data, NOT over the data itself). DKIM
// has no post-quantum algorithm registered; when one is, it is a row below.
// ===========================================================================
/** The DKIM algorithms this service signs with. */
const DKIM_ALGORITHMS = ['rsa-sha256', 'ed25519-sha256'];

// The headers signed when present, in this order (section 5.4.1's list, less
// the ones this service never writes). `From` is REQUIRED (section 5.4) and
// the signature is refused without it.
const DKIM_SIGNED_HEADERS = ['from', 'reply-to', 'subject', 'date', 'to',
                             'cc', 'message-id', 'mime-version',
                             'content-type', 'content-transfer-encoding',
                             'in-reply-to', 'references'];

// Section 3.4.4: WSP runs to one SP, trailing WSP off every line, every
// trailing empty line off the body, and a non-empty body ends in CRLF. An
// empty body canonicalizes to the empty string.
/**
 * Canonicalizes a message body with DKIM's relaxed algorithm (RFC 6376
 * section 3.4.4).
 *
 * @param body - the body
 * @returns the canonical body; empty for an empty body
 */
function dkimRelaxedBody(body) {
  log.debug('Entering dkimRelaxedBody().');
  const text = Buffer.isBuffer(body) ? body.toString('binary')
                                     : String(body == null ? '' : body);
  const lines = text.replace(/\r?\n/g, '\r\n').split('\r\n').map(
    function (line) {
      return line.replace(/[ \t]+/g, ' ').replace(/ +$/, '');
    });
  while (lines.length && lines[lines.length - 1] === '') {
    lines.pop();
  }
  log.debug('Leaving dkimRelaxedBody().');
  return lines.length ? lines.join('\r\n') + '\r\n' : '';
}

// Section 3.4.2: the name lower-cased, the value unfolded, WSP runs to one
// SP, WSP off both ends of the value, no WSP around the colon.
/**
 * Canonicalizes one header field with DKIM's relaxed algorithm (RFC 6376
 * section 3.4.2).
 *
 * @param name - the field name
 * @param value - the field value
 * @returns the canonical `name:value`
 */
function dkimRelaxedHeader(name, value) {
  log.debug('Entering dkimRelaxedHeader().');
  const unfolded = String(value == null ? '' : value)
    .replace(/\r?\n(?=[ \t])/g, '')
    .replace(/[ \t]+/g, ' ')
    .trim();
  log.debug('Leaving dkimRelaxedHeader().');
  return String(name).trim().toLowerCase() + ':' + unfolded;
}

// Splits a raw RFC 5322 message into its header fields (name, raw value with
// folding kept) and its body. Exported for the tests' verifier.
function dkimSplitMessage(raw) {
  log.debug('Entering dkimSplitMessage().');
  const text = Buffer.isBuffer(raw) ? raw.toString('binary') : String(raw);
  const at = text.search(/\r?\n\r?\n/);
  const head = at < 0 ? text : text.slice(0, at);
  const body = at < 0 ? '' : text.slice(at).replace(/^\r?\n\r?\n/, '');
  const fields = [];
  head.split(/\r?\n(?![ \t])/).forEach(function (line) {
    const colon = line.indexOf(':');
    if (colon > 0) {
      fields.push({ name: line.slice(0, colon),
                    value: line.slice(colon + 1) });
    }
  });
  log.debug('Leaving dkimSplitMessage(). ' + fields.length + ' field(s).');
  return { fields: fields, body: body };
}

// ---------------------------------------------------------------------------
// THE SIGNATURE. `raw` is the whole message as it will be sent; what comes
// back is the complete `DKIM-Signature:` field (no trailing CRLF), for the
// caller to put in front of the message. Throws on a key or an option that
// cannot make a valid signature.
//
// Where a header occurs more than once, section 5.4.2 signs the LAST
// instance for each name listed once — and the list here names each once.
// ---------------------------------------------------------------------------
/**
 * Signs a message with DKIM (RFC 6376, RFC 8463).
 *
 * @param raw - the whole message as it will be sent
 * @param opts - `privateKeyPem`, `selector`, `domain`, `algorithm` and
 *   `timestamp`
 * @returns the complete `DKIM-Signature:` field, without a trailing CRLF
 * @throws Error on a key or an option that cannot make a valid signature
 */
function dkimSign(raw, opts) {
  log.debug('Entering dkimSign().');
  const o = opts || {};
  const algorithm = String(o.algorithm || 'rsa-sha256');
  if (DKIM_ALGORITHMS.indexOf(algorithm) < 0) {
    log.debug('Leaving dkimSign(). Unknown algorithm.');
    throw new Error('DKIM algorithm "' + algorithm + '" is not one of ' +
                    DKIM_ALGORITHMS.join(', '));
  }
  const domain = String(o.domain || '').trim().toLowerCase();
  const selector = String(o.selector || '').trim().toLowerCase();
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/
    .test(domain) ||
      !/^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/.test(selector)) {
    log.debug('Leaving dkimSign(). Bad domain or selector.');
    throw new Error('a DKIM signature needs a domain (d=) and a selector ' +
                    '(s=) that are DNS labels');
  }
  const key = nodeCrypto.createPrivateKey(o.privateKeyPem);
  const keyType = key.asymmetricKeyType;
  if (algorithm === 'rsa-sha256') {
    const bits = keyType === 'rsa' && key.asymmetricKeyDetails
      ? Number(key.asymmetricKeyDetails.modulusLength) : 0;
    if (keyType !== 'rsa' || bits < 2048) {
      log.debug('Leaving dkimSign(). Not an RSA key of 2048 bits or more.');
      throw new Error('rsa-sha256 needs an RSA key of at least 2048 bits ' +
                      '(RFC 8301); this key is ' + (keyType || 'unknown') +
                      (bits ? ', ' + bits + ' bits' : ''));
    }
  } else if (keyType !== 'ed25519') {
    log.debug('Leaving dkimSign(). Not an Ed25519 key.');
    throw new Error('ed25519-sha256 needs an Ed25519 key; this key is ' +
                    (keyType || 'unknown'));
  }
  const message = dkimSplitMessage(raw);
  const bodyHash = nodeCrypto.createHash('sha256')
    .update(dkimRelaxedBody(message.body), 'binary').digest('base64');
  const lastOf = {};
  message.fields.forEach(function (field) {
    lastOf[field.name.trim().toLowerCase()] = field;
  });
  if (!lastOf['from']) {
    log.debug('Leaving dkimSign(). No From.');
    throw new Error('a DKIM signature must cover From (RFC 6376 section ' +
                    '5.4), and the message has none');
  }
  const signed = DKIM_SIGNED_HEADERS.filter(function (name) {
    return !!lastOf[name];
  });
  const timestamp = Math.floor(Number(o.timestamp) ||
                               Date.now() / 1000);
  const tags = 'v=1; a=' + algorithm + '; c=relaxed/relaxed; d=' + domain +
    '; s=' + selector + '; t=' + timestamp + '; h=' + signed.join(':') +
    '; bh=' + bodyHash + '; b=';
  const data = signed.map(function (name) {
    return dkimRelaxedHeader(name, lastOf[name].value) + '\r\n';
  }).join('') + dkimRelaxedHeader('DKIM-Signature', tags);
  let signature;
  if (algorithm === 'rsa-sha256') {
    signature = nodeCrypto.sign('sha256', Buffer.from(data, 'binary'), key);
  } else {
    // RFC 8463 section 3: the SHA-256 of the data is what Ed25519 signs.
    const digest = nodeCrypto.createHash('sha256')
      .update(data, 'binary').digest();
    signature = nodeCrypto.sign(null, digest, key);
  }
  log.debug('Leaving dkimSign(). ' + algorithm + ', d=' + domain + ', s=' +
            selector + ', ' + signed.length + ' header(s).');
  return 'DKIM-Signature: ' + tags + signature.toString('base64');
}

// ---------------------------------------------------------------------------
// A VERIFIER, for this service's own tests and for the console's "is my DKIM
// key the one DNS publishes" check — never for a message somebody else sent,
// because this service receives no mail. `publicKeyPem` is the selector's key
// (the p= of its DNS record, as a PEM). Answers `{ ok, why }`.
// ---------------------------------------------------------------------------
/**
 * Verifies a DKIM signature on a message, for this service's own tests and
 * the console's key check; never for mail somebody else sent.
 *
 * @param raw - the whole signed message
 * @param publicKeyPem - the selector's public key
 * @returns `{ ok, why }`
 */
function dkimVerify(raw, publicKeyPem) {
  log.debug('Entering dkimVerify().');
  const message = dkimSplitMessage(raw);
  const field = message.fields.filter(function (one) {
    return one.name.trim().toLowerCase() === 'dkim-signature';
  })[0];
  if (!field) {
    log.debug('Leaving dkimVerify(). No signature.');
    return { ok: false, why: 'no DKIM-Signature field' };
  }
  const tags = {};
  field.value.replace(/\r?\n[ \t]/g, '').split(';').forEach(function (part) {
    const eq = part.indexOf('=');
    if (eq > 0) {
      tags[part.slice(0, eq).trim()] = part.slice(eq + 1).replace(/\s+/g, '');
    }
  });
  const bodyHash = nodeCrypto.createHash('sha256')
    .update(dkimRelaxedBody(message.body), 'binary').digest('base64');
  if (bodyHash !== tags.bh) {
    log.debug('Leaving dkimVerify(). Body hash differs.');
    return { ok: false, why: 'the body hash does not match bh=' };
  }
  const lastOf = {};
  message.fields.forEach(function (one) {
    lastOf[one.name.trim().toLowerCase()] = one;
  });
  const withoutB = field.value.replace(/(;\s*b=)[^;]*$/, '$1');
  const data = String(tags.h || '').split(':').map(function (name) {
    const one = lastOf[name.trim().toLowerCase()];
    return one ? dkimRelaxedHeader(name, one.value) + '\r\n' : '';
  }).join('') + dkimRelaxedHeader('DKIM-Signature', withoutB);
  const signature = Buffer.from(String(tags.b || ''), 'base64');
  let ok = false;
  try {
    const key = nodeCrypto.createPublicKey(publicKeyPem);
    ok = tags.a === 'ed25519-sha256'
      ? nodeCrypto.verify(null, nodeCrypto.createHash('sha256')
        .update(data, 'binary').digest(), key, signature)
      : nodeCrypto.verify('sha256', Buffer.from(data, 'binary'), key,
                          signature);
  } catch (e) {
    log.debug('Caught in dkimVerify(): ' + ((e && e.message) || e));
    ok = false;
  }
  log.debug('Leaving dkimVerify(). ' + ok);
  return { ok: ok, why: ok ? '' : 'the signature does not verify' };
}

// ===========================================================================
// SECTION 13 — RANDOM VALUES (#65, 2026-09-23).
//
// **THE GENERATOR IS NODE'S AND THIS SECTION ADDS NONE.** `crypto.randomBytes`,
// `randomInt`, `randomUUID` and `getRandomValues` are all OpenSSL's DRBG,
// seeded from the operating system on every platform node runs on (getrandom
// on Linux, BCryptGenRandom on Windows, the kernel source on macOS), and
// under OpenSSL's FIPS provider they become the FIPS DRBG with no change
// here. That is the "platform-independent secure random number generator" the
// ticket asked for, and it was already in use at almost every site.
//
// **THE COMMUNITY MODULES WERE REVIEWED AND NONE IS ADOPTED.** The good ones —
// nanoid's `customAlphabet`, crypto-random-string, otp-generator — end at
// exactly these calls and rejection-sample exactly as `randomString()` does;
// they would be a dependency on the path of every secret for ten lines, and
// both of the first two are ESM-only. Several popular ones are worse than
// nothing: randomstring falls back to `Math.random()` when its source throws,
// rand-token takes `x % chars.length`, random-js's default engine IS
// `Math.random()`. `randomString()` is nanoid's design, rejection sampling,
// and its test (a chi-square over many draws) is nanoid's test.
//
// **WHAT THE SECTION IS FOR is the three mistakes it makes impossible,** each
// of which this tree had on the day it was written:
//
//   1. **A MODULO OVER AN ALPHABET.** `ALPHABET[byte % ALPHABET.length]` is
//      biased whenever the length does not divide 256: GNAP's 31-character
//      user-code alphabet drew its first eight characters 9/256 of the time
//      and the rest 8/256 — a code a person types, which is the one kind of
//      value short enough for the bias to matter. SPIFFE's Azure challenge
//      nonce did the same over 62 characters (harmless at 190 bits, the same
//      bug). `randomString()` draws each index with `randomInt()`, which
//      rejection-samples inside node, so no alphabet size can reintroduce
//      it — `backup_codes.ts` argued this per module; it is now said once.
//   2. **A SECOND GENERATOR.** `forge.random` is a Fortuna DRBG in
//      JavaScript, seeded from node's but with its own state on the heap,
//      outside FIPS mode, and fifty times slower (about 91 µs for 32 bytes
//      against 1.7 µs). It drew the content key and IV of every encrypted
//      SAML assertion and the ID of every SAML and WS-Federation document —
//      and, until a second pass the same day, it went on drawing INSIDE
//      forge after those two call sites were gone: the blinding of every
//      RSA XML signature, the older key transports' OAEP seed and padding,
//      the SCEP key unwrap. `installForgeRandom()` below points forge's own
//      generator at node's, so no caller, vendored or not, can reach
//      Fortuna; the key transports and the unwrap moved to node's
//      `publicEncrypt()` / `privateDecrypt()` as well.
//   3. **A SHORT SECRET.** `randomToken()` refuses fewer than 128 bits, so a
//      bearer value cannot be made guessable by a length typed in a hurry.
//
// `tests/random_values.js` holds all three: the distribution, forge's
// generator answering with node's bytes, and a reading of the service's
// source that fails on `Math.random`, `forge.random`, forge's own RSA
// encrypt and decrypt, a second generator package, or a random byte taken
// modulo anything.
//
// No Entering/Leaving pair on the four below: they are called several times
// in a single request (every ID, every nonce, every code), and a pair per
// draw would drown the log — the hot-path exception of the root CLAUDE.md's
// style rules. `randomString()`'s refusal is the one exit worth a line.
// ===========================================================================

// The fewest bits `randomToken()` will make. NIST SP 800-63B-4 asks 64 of a
// look-up secret and RFC 6749 section 10.10 128 of a token an attacker could
// guess at; this section takes the larger for everything it makes.
/** The fewest bits `randomToken()` will make: 128. */
const RANDOM_TOKEN_MIN_BITS = 128;

// forge's `random` context, answering from node's generator in forge's
// binary-string shape (the header of this file, where it is called, and
// reason 2 above). `getBytes()` keeps its optional callback. It runs while
// this module is loading, BEFORE the logger below exists, so it has no
// Entering/Leaving pair — `common/config_file.js`'s situation — and it
// cannot fail: every member it sets is a plain function.
/**
 * Makes forge's `random` context answer from node's CSPRNG.
 *
 * Runs while this module loads, before the logger exists, and cannot fail.
 * @param forgeModule - the node-forge module
 */
function installForgeRandom(forgeModule) {
  const ctx = forgeModule.random;
  const draw = function (count) {
    return nodeCrypto.randomBytes(Number(count) || 0).toString('binary');
  };
  const generate = function (count, callback) {
    const bytes = draw(count);
    if (typeof callback === 'function') {
      process.nextTick(callback, null, bytes);
      return undefined;
    }
    return bytes;
  };
  ctx.generate = generate;
  ctx.getBytes = generate;
  ctx.getBytesSync = draw;
  // Seeding means nothing to node's DRBG; accepted and dropped rather than
  // left feeding a Fortuna pool nothing reads any more.
  ctx.collect = function () {
    return undefined;
  };
  ctx.collectInt = function () {
    return undefined;
  };
  ctx.createInstance = function () {
    return ctx;
  };
  ctx.drawsFromNode = true;
  return ctx;
}

// `n` bytes from node's CSPRNG. The one spelling, so the source test has one
// thing to allow.
/**
 * Returns `n` bytes from node's CSPRNG: the one spelling of it.
 *
 * @param n - how many bytes
 * @returns the bytes
 */
function randomBytes(n) {
  return nodeCrypto.randomBytes(n);
}

// An integer in [min, max), uniform — node's `randomInt`, rejection-sampled.
/**
 * Returns a uniform integer in [min, max), from node's `randomInt`.
 *
 * @param min - the lowest value, inclusive
 * @param max - the bound, exclusive
 * @returns the integer
 */
function randomInt(min, max) {
  return nodeCrypto.randomInt(min, max);
}

// A random v4 UUID (RFC 9562 section 5.4).
/**
 * Returns a random v4 UUID (RFC 9562 section 5.4).
 *
 * @returns the UUID
 */
function randomUuid() {
  return nodeCrypto.randomUUID();
}

// At least `bits` of randomness (rounded up to whole bytes), base64url.
/**
 * Returns at least `bits` of randomness, rounded up to whole bytes, as
 * base64url.
 *
 * @param bits - how many bits; 256 when omitted
 * @returns the token
 * @throws Error when fewer than `RANDOM_TOKEN_MIN_BITS` are asked for
 */
function randomToken(bits) {
  const want = bits === undefined ? 256 : Number(bits);
  if (!Number.isInteger(want) || want < RANDOM_TOKEN_MIN_BITS) {
    // error-code: none — a programming error; every caller passes a constant
    throw new Error('crypto: randomToken() makes at least ' +
                    RANDOM_TOKEN_MIN_BITS + ' bits, not ' + bits);
  }
  return nodeCrypto.randomBytes(Math.ceil(want / 8)).toString('base64url');
}

// `length` characters, each drawn UNIFORMLY from `alphabet` (reason 1 above).
// An alphabet with a repeated character is refused, because a repeat is a
// bias of its own that no sampling can undo — the character is simply twice
// as likely.
/**
 * Returns `length` characters, each drawn uniformly from `alphabet`.
 *
 * @param alphabet - the characters to draw from, each once
 * @param length - how many to draw
 * @returns the string
 * @throws Error for an alphabet of fewer than two distinct characters, a
 *   repeated character, or a length that is not a whole number
 */
function randomString(alphabet, length) {
  const chars = Array.from(String(alphabet || ''));
  const n = Number(length);
  if (chars.length < 2 || new Set(chars).size !== chars.length ||
      !Number.isInteger(n) || n < 0) {
    log.debug('Leaving randomString(). Refused: an alphabet of ' +
              chars.length + ', length ' + length + '.');
    // error-code: none — a programming error; every alphabet is a constant
    throw new Error('crypto: randomString() needs two or more distinct ' +
                    'characters and a whole length');
  }
  let out = '';
  for (let i = 0; i < n; i++) {
    out += chars[nodeCrypto.randomInt(0, chars.length)];
  }
  return out;
}

// ===========================================================================
// SECTION 14 — HTTP MESSAGE SIGNATURES (RFC 9421) AND CONTENT-DIGEST (RFC
// 9530) (#178, 2026-10-05).
//
// An HTTP signature is a signature over a string that neither party
// transmits. The signer builds it out of the message, the verifier builds it
// again out of the message it RECEIVED, and the two strings must agree byte
// for byte. Two callers use it:
//
//   * GNAP's `httpsig` key proof (RFC 9635 section 7.3.1), from
//     `gnap/gnap_proof.ts`. GNAP decides the tag, the required components
//     and the key.
//   * The FAPI 2.0 HTTP Signatures profile at this service's OAuth resource
//     servers (signed requests in, signed responses out), from
//     `oauth-oidc/http_signatures.ts`. That module decides the same things for
//     `fapi-2-request` and `fapi-2-response`.
//
// It was `gnap/gnap_httpsig.ts` until #178, when rcbj's rule moved it here.
// The rule, as he restated it on 2026-10-05, is: "All crypto operations
// across all protocols and use cases are to be centralized in a common
// module." The GNAP file signed, verified, MACed and hashed on node's
// OpenSSL in a directory of its own. This section is that code, unchanged in
// what it builds and refuses, with four differences:
//
//   1. `;req` (section 2.4) is IMPLEMENTED rather than refused, because a
//      FAPI response signature must cover the request's `@method`,
//      `@target-uri`, `content-digest` and, when the request was signed, its
//      `signature` and `signature-input`. A response message carries the
//      request it answers as `message.request`. `httpsigRequestTarget()`
//      below says what is still refused.
//   2. Every JWS algorithm this service speaks is admitted under section
//      3.3.7, read off `JWS_ALGS` rather than listed again. That includes
//      ES256K and the post-quantum and composite algorithms (ML-DSA, SLH-DSA,
//      ML-DSA + traditional), which are signed and verified by
//      `jwsSignatureOver()` and `jwsSignatureValid()`, the same functions that
//      do it for a JWS. Section 3.3.7's rule holds for all of them: the
//      signature base is the JWS Signing Input as-is, and the `alg` signature
//      parameter is never used with a JWS name.
//   3. A key may be a JWK as well as a KeyObject or bytes, so a caller holding
//      a client's registered JWKS does not convert keys itself. An RSA public
//      key goes through `rsaKeyProblem()` like every other RSA verification
//      here: the exponent, the ROCA fingerprint and the 2048-bit floor.
//   4. The error codes are STS-KEYS-0107 to 0154. STS-GNAP-0200 to 0246 are
//      retired, with the same meanings in the same order, because a code is
//      never renumbered or reused.
//
// The rest of the original header still applies, and is kept here:
//
// THE SIGNATURE BASE IS THE WHOLE GAME. Section 2 is a list of
// canonicalization rules, and each is implemented where it is stated and
// cited by number:
//
//   * a field value is STRIPPED, has obsolete line folding replaced by one
//     space, and repeated field lines are joined with exactly ", " (2.1);
//   * `@authority` and `@scheme` are LOWERCASED and the default port omitted
//     (2.2.3, 2.2.4), while `@method` is NOT, because the method is
//     case-sensitive (2.2.1);
//   * `@path` and `@query` are the RAW, still-percent-encoded text of the
//     target URI (2.2.6, 2.2.7), and an absent query is `?`, not the empty
//     string;
//   * `@query-param` is DECODED AND RE-ENCODED (2.2.8), so that `+` and `%20`
//     sign alike, and a parameter named twice is an ERROR rather than the
//     first one, since that ambiguity is exactly the one an attacker would
//     choose;
//   * `;sf` and `;key=` re-serialize through `common/structured_fields.ts`
//     (2.1.1, 2.1.2) and `;bs` wraps each field line as a Byte Sequence
//     (2.1.3);
//   * a component identifier may appear ONCE (2.5 step 2.1), and equality
//     ignores parameter ORDER while serialization preserves it (2).
//
// `@signature-params` is always the last line and is never in the covered
// list, because it is what makes a signature cover its own metadata (2.3).
//
// WHAT IS REFUSED RATHER THAN IMPLEMENTED: `;tr` (2.1.4, because the message
// model here has no trailer section); `@status` on a REQUEST (2.2.9); `;req`
// on a request, or on a response with no request given (2.4); and `;sf` or
// `;key=` on a field whose Structured Field type is not known (2.1.1; callers
// name further types with `options.fieldTypes`).
//
// REPRESENTATION CHOICES THAT DECIDE INTEROPERABILITY: ECDSA signatures are
// r||s at the curve's coordinate size and never DER (3.3.4). RSASSA-PSS uses
// a salt as long as the hash. An HMAC is compared in constant time. RSA keys
// under 2048 bits and HMAC secrets shorter than their hash are refused (RFC
// 7518 sections 3.3 and 3.2), so the HTTP names offer no downgrade the JWS
// names do not (section 7.3.6).
//
// THE REFUSAL SHAPE is `{ ok: false, errorCode, why }`, MARKED with the code,
// never a response. The client-facing error is the caller's to choose: the
// same failed signature is GNAP's `invalid_client` at a grant endpoint and a
// 401 at a FAPI resource server.
//
// It stays a LEAF: `./structured_fields` requires only `config` and
// `instance_slot`.
// ===========================================================================
const sf = require('./structured_fields');

// RFC 9530 section 7.2: only the two "Active" algorithms. The "Deprecated"
// ones MUST NOT be used where the digest is signed for authenticity (section
// 5), which is the only reason this service computes one. So they are
// unknown, and an unknown algorithm is ignored by the verifier, as section 2
// allows.
const DIGEST_ALGORITHMS = {
  'sha-256': 'sha256',
  'sha-512': 'sha512'
};

// The derived components of section 2.2 and whether each belongs to a request
// or a response message.
const DERIVED = {
  '@method': 'request',
  '@target-uri': 'request',
  '@authority': 'request',
  '@scheme': 'request',
  '@request-target': 'request',
  '@path': 'request',
  '@query': 'request',
  '@query-param': 'request',
  '@status': 'response'
};

// Fields whose Structured Field type is known, so that `;sf` and `;key=` can
// be honoured (RFC 9421 section 2.1.1). Each row cites the document defining
// the type.
const KNOWN_FIELD_TYPES = {
  'signature': 'dictionary',            // RFC 9421 section 4.2
  'signature-input': 'dictionary',      // RFC 9421 section 4.1
  'accept-signature': 'dictionary',     // RFC 9421 section 5.1
  'content-digest': 'dictionary',       // RFC 9530 section 2
  'repr-digest': 'dictionary',          // RFC 9530 section 3
  'want-content-digest': 'dictionary',  // RFC 9530 section 4
  'want-repr-digest': 'dictionary',     // RFC 9530 section 4
  'client-cert': 'item',                // RFC 9440 section 2.2
  'client-cert-chain': 'list',          // RFC 9440 section 2.3
  'priority': 'dictionary',             // RFC 9218 section 4
  'cache-status': 'list',               // RFC 9211 section 2
  'proxy-status': 'list'                // RFC 9209 section 2
};

// The six registered metadata parameters (section 6.3.2) have types, and a
// parameter of the wrong type is a signature a conforming verifier cannot
// read: `created="1618884473"` is a String and not a timestamp.
const PARAM_TYPES = {
  created: 'integer',
  expires: 'integer',
  nonce: 'string',
  alg: 'string',
  keyid: 'string',
  tag: 'string'
};

// The algorithms. Section 3.3's "HTTP Signature Algorithms" registry is listed
// here. The JWS names of section 3.3.7 are derived from JWS_ALGS just below,
// so an algorithm added to that table is an HTTP signature algorithm too,
// with no second list to forget.
const HTTP_SIGNATURE_ALGORITHMS = {
  'rsa-pss-sha512': { registry: 'http', kind: 'rsa-pss', hash: 'sha512',
                      saltLength: 64, spec: 'RFC 9421 section 3.3.1' },
  'rsa-v1_5-sha256': { registry: 'http', kind: 'rsa-v1_5', hash: 'sha256',
                       spec: 'RFC 9421 section 3.3.2' },
  'hmac-sha256': { registry: 'http', kind: 'hmac', hash: 'sha256',
                   minKeyBytes: 32, spec: 'RFC 9421 section 3.3.3' },
  'ecdsa-p256-sha256': { registry: 'http', kind: 'ecdsa', hash: 'sha256',
                         curve: 'prime256v1', coordinateBytes: 32,
                         spec: 'RFC 9421 section 3.3.4' },
  'ecdsa-p384-sha384': { registry: 'http', kind: 'ecdsa', hash: 'sha384',
                         curve: 'secp384r1', coordinateBytes: 48,
                         spec: 'RFC 9421 section 3.3.5' },
  'ed25519': { registry: 'http', kind: 'eddsa', curves: ['ed25519'],
               spec: 'RFC 9421 section 3.3.6' }
};

// Section 3.3.7: "JSON Web Signature (JWS) algorithms". One row per JWS_ALGS
// row, in the shape the checks below read. The post-quantum and composite
// rows are kind 'jws-pq', signed and verified by the JWS functions
// themselves.
Object.keys(JWS_ALGS).forEach(function (alg) {
  const spec = JWS_ALGS[alg];
  const cite = 'RFC 9421 section 3.3.7, ' + alg;
  let row;
  if (spec.family === 'hmac') {
    row = { kind: 'hmac', hash: spec.hash,
            minKeyBytes: nodeCrypto.createHash(spec.hash).digest().length };
  } else if (spec.family === 'rsa') {
    row = spec.padding !== undefined
      ? { kind: 'rsa-pss', hash: spec.hash, saltLength: spec.saltLength }
      : { kind: 'rsa-v1_5', hash: spec.hash };
  } else if (spec.family === 'ec') {
    row = { kind: 'ecdsa', hash: spec.hash, curve: spec.namedCurve,
            coordinateBytes: spec.sigBytes / 2 };
  } else if (spec.family === 'okp') {
    // RFC 8037 section 3.1: EdDSA names both curves.
    row = { kind: 'eddsa', curves: ['ed25519', 'ed448'] };
  } else {
    row = { kind: 'jws-pq' };
  }
  HTTP_SIGNATURE_ALGORITHMS[alg] = Object.assign(row,
    { registry: 'jws', jws: alg, spec: cite });
});

/** The Content-Digest algorithms this section computes and checks. */
const CONTENT_DIGEST_ALGORITHMS = Object.keys(DIGEST_ALGORITHMS);

// ---------------------------------------------------------------------------
// THE ONE PLACE A REFUSAL IS MADE. Logged at warn with the code at the front
// of the line — a failed proof is an operator's question before it is
// anything else — and marked, per the subsystem contract.
// ---------------------------------------------------------------------------
function httpsigRefuse(code, why) {
  log.debug("Entering httpsigRefuse().");
  const result = { ok: false, errorCode: code, why: why };
  log.warn(errorCodes.tag(code) + why);
  log.debug("Leaving httpsigRefuse().");
  return errorCodes.mark(result, code);
}

function httpsigIsRefusal(value) {
  log.debug("Entering httpsigIsRefusal().");
  log.debug("Leaving httpsigIsRefusal().");
  return !!value && value.ok === false;
}

function httpsigBodyBytes(body) {
  log.debug("Entering httpsigBodyBytes().");
  if (body === undefined || body === null) {
    log.debug("Leaving httpsigBodyBytes(). No content.");
    return Buffer.alloc(0);
  }
  if (Buffer.isBuffer(body)) {
    log.debug("Leaving httpsigBodyBytes(). Buffer.");
    return body;
  }
  if (body instanceof Uint8Array) {
    log.debug("Leaving httpsigBodyBytes(). Uint8Array.");
    return Buffer.from(body);
  }
  log.debug("Leaving httpsigBodyBytes(). String.");
  return Buffer.from(String(body), 'utf8');
}

// `algorithm` may be one name or an array of names, in which case every
// member is computed — section 2's second example, and what a client
// supporting a population of verifiers sends. It THROWS on an unknown name,
// carrying the code: an unsupported algorithm here is the caller's own
// configuration, not anything a client sent.
/**
 * Computes a Content-Digest field value for a body.
 *
 * @param body - the body's bytes
 * @param algorithm - one algorithm name, or an array of them, each computed
 * @returns the serialized Dictionary
 * @throws Error, carrying its code, for an unknown algorithm name
 */
function contentDigest(body, algorithm) {
  log.debug("Entering contentDigest().");
  const names = Array.isArray(algorithm) ? algorithm
                                         : [algorithm === undefined ?
                                            'sha-256' : algorithm];
  const bytes = httpsigBodyBytes(body);
  const dictionary = [];
  for (let k = 0; k < names.length; k++) {
    const hash = DIGEST_ALGORITHMS[names[k]];
    if (!hash) {
      const why = 'Content-Digest cannot be computed with "' +
                  String(names[k]) +
                  '": only sha-256 and sha-512, the two Active algorithms ' +
                  'of the RFC 9530 registry, are supported.';
      log.warn(errorCodes.tag('STS-KEYS-0107') + why);
      const err = /** @type {any} */ (new Error(why));
      err.errorCode = 'STS-KEYS-0107';
      errorCodes.mark(err, 'STS-KEYS-0107');
      log.debug("Leaving contentDigest(). Unsupported " +
                "algorithm.");
      throw err;
    }
    dictionary.push([names[k], {
      type: 'bytes',
      value: nodeCrypto.createHash(hash).update(bytes).digest(),
      params: []
    }]);
  }
  log.debug("Leaving contentDigest().");
  return sf.serializeDictionary(dictionary);
}

// Section 2 read with GNAP's requirement (RFC 9635 section 7.3.1: "The
// verifier MUST validate this field value"): EVERY member whose algorithm is
// accepted must match, and at least one must be present. "Any one matches"
// would let a client send a correct sha-256 beside a wrong sha-512 and have a
// verifier that prefers sha-512 accept a body the sha-512 does not describe.
/**
 * Verifies a Content-Digest field against a body: every member whose
 * algorithm is accepted must match, and at least one must be present.
 *
 * @param headerValue - the Content-Digest field value
 * @param body - the body's bytes
 * @param options - `accepted`, the algorithms accepted (sha-256 and
 *   sha-512 by default)
 * @returns `{ ok: true, algorithms }` naming those matched, or a refusal
 */
function verifyContentDigest(headerValue, body, options) {
  log.debug("Entering verifyContentDigest().");
  const accepted = (options && Array.isArray(options.accepted))
    ? options.accepted : ['sha-256', 'sha-512'];
  for (let k = 0; k < accepted.length; k++) {
    if (!DIGEST_ALGORITHMS[accepted[k]]) {
      log.debug("Leaving verifyContentDigest(). Unsupported " +
                "accepted algorithm.");
      return httpsigRefuse('STS-KEYS-0107',
                         'The verifier was configured to accept the ' +
                         'Content-Digest algorithm "' +
                         String(accepted[k]) + '", which is not supported; ' +
                         'only sha-256 and sha-512 are.');
    }
  }
  const text = Array.isArray(headerValue) ? headerValue.join(', ') :
               headerValue;
  if (typeof text !== 'string' || text.trim() === '') {
    log.debug("Leaving verifyContentDigest(). Absent.");
    return httpsigRefuse('STS-KEYS-0108',
                       'The message has no Content-Digest field to ' +
                       'validate against its content (RFC 9530 section 2).');
  }
  let dictionary;
  try {
    dictionary = sf.parseDictionary(text);
  } catch (e) {
    log.debug("Caught in verifyContentDigest(): " +
              ((e && e.message) || e));
    log.debug("Leaving verifyContentDigest(). Malformed.");
    return httpsigRefuse('STS-KEYS-0109',
                       'The Content-Digest field is not a Structured Field ' +
                       'Dictionary: ' + e.message);
  }
  const bytes = httpsigBodyBytes(body);
  const matched = [];
  for (let k = 0; k < dictionary.length; k++) {
    const name = dictionary[k][0];
    if (accepted.indexOf(name) < 0) {
      // Not accepted, or not an algorithm this module knows: ignored, as RFC
      // 9530 section 2 allows. It still had to PARSE — a malformed member
      // anywhere makes the whole field malformed (RFC 8941 section 4.2).
      continue;
    }
    const member = dictionary[k][1];
    if (!member || member.type !== 'bytes') {
      log.debug("Leaving verifyContentDigest(). Not a byte " +
                "sequence.");
      return httpsigRefuse('STS-KEYS-0110',
                         'The Content-Digest member "' + name + '" is a ' +
                         (member ? member.type : 'nothing') +
                         ', not the Byte Sequence RFC 9530 section 2 ' +
                         'requires.');
    }
    const expected = nodeCrypto.createHash(DIGEST_ALGORITHMS[name])
                               .update(bytes)
                               .digest();
    if (expected.length !== member.value.length ||
        !nodeCrypto.timingSafeEqual(expected, member.value)) {
      log.debug("Leaving verifyContentDigest(). Mismatch.");
      return httpsigRefuse('STS-KEYS-0111',
                         'The Content-Digest member "' + name +
                         '" does not match the content: the body was ' +
                         'changed, or the digest was computed over ' +
                         'something other than the bytes sent.');
    }
    matched.push(name);
  }
  if (matched.length === 0) {
    log.debug("Leaving verifyContentDigest(). No accepted " +
              "algorithm.");
    return httpsigRefuse('STS-KEYS-0112',
                       'The Content-Digest field carries no digest in an ' +
                       'accepted algorithm (' + accepted.join(', ') +
                       '); it carries ' +
                       (dictionary.length ?
                        dictionary.map((p) => { return p[0]; }).join(', ')
                                          : 'no members') + '.');
  }
  log.debug("Leaving verifyContentDigest(). " +
            matched.join(', '));
  return { ok: true, algorithms: matched };
}

// ===========================================================================
// COMPONENT IDENTIFIERS.
// ===========================================================================

// A JavaScript value handed in as a parameter, turned into a bare item. A
// value that is already a bare item is kept, so a caller that needs a Token
// rather than a String can say so.
function httpsigBareItem(value) {
  log.debug("Entering httpsigBareItem().");
  let bare = null;
  if (value && typeof value === 'object' && !Buffer.isBuffer(value) &&
      typeof value.type === 'string' && 'value' in value) {
    bare = { type: value.type, value: value.value };
  } else if (typeof value === 'boolean') {
    bare = { type: 'boolean', value: value };
  } else if (Buffer.isBuffer(value)) {
    bare = { type: 'bytes', value: value };
  } else if (typeof value === 'number') {
    bare = { type: Number.isInteger(value) ? 'integer' : 'decimal',
             value: value };
  } else if (typeof value === 'string') {
    bare = { type: 'string', value: value };
  }
  log.debug("Leaving httpsigBareItem(). " +
            (bare ? bare.type : 'not a bare item'));
  return bare;
}

// Parameters from either an ordered [[key, value]] array or a plain object
// (in its insertion order). Duplicate keys are last-wins in the first
// position, which is what a PARSER would have made of the same text (RFC 8941
// section 4.2.3.2) — so a signer cannot build an identifier no verifier could
// parse back to itself. THROWS on a value that is not a bare item; callers
// map it.
function httpsigParamsFrom(input) {
  log.debug("Entering httpsigParamsFrom().");
  if (input === undefined || input === null) {
    log.debug("Leaving httpsigParamsFrom(). None.");
    return [];
  }
  const pairs = Array.isArray(input) ? input :
                Object.keys(input).map((key) => {
    return [key, input[key]];
  });
  const out = [];
  pairs.forEach((pair) => {
    if (!Array.isArray(pair) || pair.length !== 2) {
      throw new Error('each parameter must be a [key, value] pair');
    }
    if (pair[1] === undefined) {
      // An object member present but undefined is how a caller writes "no
      // such parameter" ({ expires: undefined }); section 2.3 step 5 skips
      // parameters "not available or not used", so it is skipped too.
      return;
    }
    sf.serializeKey(pair[0]);
    const bare = httpsigBareItem(pair[1]);
    if (!bare) {
      throw new Error('the parameter "' + pair[0] + '" has a value that is ' +
                      'not a Structured Field bare item');
    }
    sf.serializeBareItem(bare);
    let at = -1;
    for (let k = 0; k < out.length; k++) {
      if (out[k][0] === pair[0]) {
        at = k;
      }
    }
    if (at >= 0) {
      out[at][1] = bare;
    } else {
      out.push([pair[0], bare]);
    }
  });
  log.debug("Leaving httpsigParamsFrom(). " + out.length +
            " parameter(s).");
  return out;
}

// A component identifier from any of the forms a caller may write:
//
//   '@method'                              a bare NAME, no parameters
//   '"@query-param";name="Pet"'            a serialized identifier (it begins
//                                          with a DQUOTE, which no name can)
//   { name: 'signature', params: { key: 'old' } }
//   { type: 'string', value: 'x', params: [[...]] }   a parsed sf-string item
//
// The NAME rule is section 2.1's: a field name is used LOWERCASED, and a name
// that is not is refused rather than lowercased, because silently lowercasing
// it would sign a component the signer did not name.
function httpsigComponentItem(component) {
  log.debug("Entering httpsigComponentItem().");
  let item;
  try {
    if (typeof component === 'string' && component[0] === '"') {
      item = sf.parseItem(component);
    } else if (typeof component === 'string') {
      item = { type: 'string', value: component, params: [] };
    } else if (component && typeof component === 'object' &&
               component.type === 'string') {
      item = { type: 'string', value: component.value,
               params: httpsigParamsFrom(component.params) };
    } else if (component && typeof component === 'object' &&
               typeof component.name === 'string') {
      item = { type: 'string', value: component.name,
               params: httpsigParamsFrom(component.params) };
    } else {
      throw new Error('it is not a name, a serialized identifier or a ' +
                      '{name, params} object');
    }
    if (item.type !== 'string') {
      throw new Error('a component name is an sf-string (RFC 9421 section ' +
                      '2.5), and this is a ' + item.type);
    }
    sf.serializeItem(item);
  } catch (e) {
    log.debug("Caught in httpsigComponentItem(): " +
              ((e && e.message) || e));
    log.debug("Leaving httpsigComponentItem(). Malformed.");
    return httpsigRefuse('STS-KEYS-0113',
                       'A covered component identifier is malformed: ' +
                       e.message + '.');
  }
  const name = item.value;
  const fieldName = /^[!#$%&'*+\-.^_`|~0-9a-z]+$/;
  if (!(name[0] === '@' && name.length > 1) && !fieldName.test(name)) {
    log.debug("Leaving httpsigComponentItem(). Bad name.");
    return httpsigRefuse('STS-KEYS-0113',
                       'The component name "' + name +
                       '" is neither a derived component name nor a ' +
                       'lowercased HTTP field name (RFC 9421 sections 2.1 ' +
                       'and 2.2).');
  }
  log.debug("Leaving httpsigComponentItem(). " + name);
  return { ok: true, item: item };
}

// Two identifiers are the same when the names are equal and the parameters
// are equal AS A SET — section 2: `"foo";bar;baz` and `"foo";baz;bar` "cannot
// be in the same message".
function httpsigIdentityOf(item) {
  log.debug("Entering httpsigIdentityOf().");
  const params = (item.params || []).map((pair) => {
    return sf.serializeParams([pair]);
  }).sort();
  log.debug("Leaving httpsigIdentityOf().");
  return JSON.stringify([item.value, params]);
}

// The header lines of a named field, as an array of strings, or null when the
// field is absent. A header value may be one combined string or an array of
// the separate field lines — the second form is needed only for `;bs`, which
// wraps each line on its own (section 2.1.3).
function httpsigFieldLines(message, name) {
  log.debug("Entering httpsigFieldLines(). " + name);
  const headers = message && message.headers;
  if (!headers || typeof headers !== 'object') {
    log.debug("Leaving httpsigFieldLines(). No headers.");
    return null;
  }
  let raw;
  const keys = Object.keys(headers);
  for (let k = 0; k < keys.length; k++) {
    if (keys[k].toLowerCase() === name) {
      raw = headers[keys[k]];
    }
  }
  if (raw === undefined || raw === null) {
    log.debug("Leaving httpsigFieldLines(). Absent.");
    return null;
  }
  const lines = (Array.isArray(raw) ? raw : [raw]).map(String);
  log.debug("Leaving httpsigFieldLines(). " + lines.length +
            " line(s).");
  return lines.length ? lines : null;
}

// Section 2.1 steps 2 and 3: strip the ends, and replace obsolete line
// folding (OWS CRLF RWS, RFC 9112 section 5.2) with a single space.
function httpsigNormalizeLine(line) {
  log.debug("Entering httpsigNormalizeLine().");
  log.debug("Leaving httpsigNormalizeLine().");
  return line.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '')
             .replace(/[ \t]*\r?\n[ \t]+/g, ' ');
}

// The parts of the target URI, read out of the RAW string, because section
// 2.2.6 and 2.2.7 want the path and query "before decoding any
// percent-encoded octets" and a WHATWG URL object re-encodes and resolves dot
// segments. The URL parser is used for what it is right about — that the
// string is absolute, and the host normalization of 2.2.3.
function httpsigTargetParts(message) {
  log.debug("Entering httpsigTargetParts().");
  const raw = message && message.targetUri;
  if (typeof raw !== 'string') {
    log.debug("Leaving httpsigTargetParts(). No target URI.");
    return null;
  }
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#.*)?$/.exec(raw);
  if (!m) {
    log.debug("Leaving httpsigTargetParts(). Not absolute.");
    return null;
  }
  let url;
  try {
    url = new URL(raw);
  } catch (e) {
    log.debug("Caught in httpsigTargetParts(): " +
              ((e && e.message) || e));
    // Not a URI the WHATWG parser accepts; the caller refuses with the code
    // for a missing target, which is what this is to a signature base.
    log.debug("Leaving httpsigTargetParts(). Unparseable: " + e.message);
    return null;
  }
  const scheme = m[1].toLowerCase();
  let authority = url.host.toLowerCase();
  // WHATWG omits the default port for http and https only; section 2.2.3 says
  // the default port of the SCHEME is omitted, and those are the two schemes
  // an HTTP request has.
  const hashAt = raw.indexOf('#');
  log.debug("Leaving httpsigTargetParts().");
  return {
    targetUri: hashAt >= 0 ? raw.slice(0, hashAt) : raw,
    scheme: scheme,
    authority: authority,
    path: m[3] === '' ? '/' : m[3],
    query: m[4] === undefined ? null : m[4]
  };
}

// ---------------------------------------------------------------------------
// `@query-param`, section 2.2.8: the WHATWG application/x-www-form-urlencoded
// PARSER (section 5.1 of the URL Standard), then the "percent-encode after
// encoding" step with the urlencoded percent-encode set and WITHOUT
// space-as-plus — which is why the RFC's example turns `with+plus+whitespace`
// into `with%20plus%20whitespace`. That set leaves exactly ASCII
// alphanumerics and `*-._` unencoded.
// ---------------------------------------------------------------------------
function httpsigPercentDecode(text) {
  log.debug("Entering httpsigPercentDecode().");
  const bytes = Buffer.from(text, 'utf8');
  const out = [];
  for (let k = 0; k < bytes.length; k++) {
    const b = bytes[k];
    if (b === 0x25 && k + 2 < bytes.length &&
        /^[0-9A-Fa-f]{2}$/.test(String.fromCharCode(bytes[k + 1],
                                                    bytes[k + 2]))) {
      out.push(parseInt(String.fromCharCode(bytes[k + 1], bytes[k + 2]), 16));
      k += 2;
    } else {
      out.push(b);
    }
  }
  log.debug("Leaving httpsigPercentDecode().");
  return Buffer.from(out).toString('utf8');
}

function httpsigUrlencode(text) {
  log.debug("Entering httpsigUrlencode().");
  const bytes = Buffer.from(text, 'utf8');
  let out = '';
  for (let k = 0; k < bytes.length; k++) {
    const c = String.fromCharCode(bytes[k]);
    if (/^[A-Za-z0-9*\-._]$/.test(c)) {
      out += c;
    } else {
      out += '%' + bytes[k].toString(16).toUpperCase().padStart(2, '0');
    }
  }
  log.debug("Leaving httpsigUrlencode().");
  return out;
}

function httpsigQueryParams(query) {
  log.debug("Entering httpsigQueryParams().");
  const out = [];
  (query || '').split('&').forEach((sequence) => {
    if (sequence === '') {
      return;
    }
    const eq = sequence.indexOf('=');
    const name = eq >= 0 ? sequence.slice(0, eq) : sequence;
    const value = eq >= 0 ? sequence.slice(eq + 1) : '';
    out.push([httpsigUrlencode(httpsigPercentDecode(name.replace(/\+/g,
                                    ' '))),
              httpsigUrlencode(httpsigPercentDecode(value.replace(/\+/g,
                                    ' ')))]);
  });
  log.debug("Leaving httpsigQueryParams(). " + out.length +
            " parameter(s).");
  return out;
}

// Which parameters a component may carry. A parameter outside this list is
// "not understood" (section 2.5 step 2.5, first bullet) and is an error.
function httpsigCheckParams(name, params, allowed) {
  log.debug("Entering httpsigCheckParams(). " + name);
  for (let k = 0; k < params.length; k++) {
    const key = params[k][0];
    const value = params[k][1];
    if (allowed.indexOf(key) < 0) {
      log.debug("Leaving httpsigCheckParams(). Not understood.");
      return httpsigRefuse('STS-KEYS-0114',
                         'The parameter "' + key +
                         '" is not understood on the component "' +
                         name + '" (RFC 9421 section 2.5 step 2.5).');
    }
    const isFlag = key === 'sf' || key === 'bs' || key === 'req' ||
                   key === 'tr';
    if (isFlag && !(value.type === 'boolean' && value.value === true)) {
      // A false flag would make `"x";sf=?0` a second identifier for the value
      // `"x"` already names — two identifiers, one value, and a signature
      // over one standing for the other.
      log.debug("Leaving httpsigCheckParams(). Flag not true.");
      return httpsigRefuse('STS-KEYS-0114',
                         'The parameter "' + key + '" on "' + name +
                         '" is a Boolean flag and is only meaningful as ' +
                         'true (RFC 9421 sections 2.1 and 6.5.2).');
    }
    if ((key === 'key' || key === 'name') && value.type !== 'string') {
      log.debug("Leaving httpsigCheckParams(). Not a string.");
      return httpsigRefuse('STS-KEYS-0114',
                         'The parameter "' + key + '" on "' + name +
                         '" must be a String, not a ' + value.type +
                         ' (RFC 9421 sections 2.1.2 and 2.2.8).');
    }
  }
  log.debug("Leaving httpsigCheckParams().");
  return null;
}

function httpsigDerivedValue(message, name, params) {
  log.debug("Entering httpsigDerivedValue(). " + name);
  if (!Object.prototype.hasOwnProperty.call(DERIVED, name)) {
    log.debug("Leaving httpsigDerivedValue(). Unknown.");
    return httpsigRefuse('STS-KEYS-0116',
                       'The derived component "' + name +
                       '" is not one this verifier understands (RFC 9421 ' +
                       'sections 2.2 and 2.5).');
  }
  const problem = httpsigCheckParams(name, params,
                                   name === '@query-param' ? ['name', 'req'] :
                                   ['req']);
  if (problem) {
    log.debug("Leaving httpsigDerivedValue(). Parameters.");
    return problem;
  }
  const isResponse = message && message.status !== undefined &&
                     message.status !== null;
  if ((DERIVED[name] === 'response') !== isResponse) {
    log.debug("Leaving httpsigDerivedValue(). Wrong message kind.");
    return httpsigRefuse('STS-KEYS-0117',
                       name === '@status'
                    ? '@status MUST NOT be used in a request message (RFC ' +
                       '9421 section 2.2.9).'
                    : 'The component "' + name + '" targets a request, and ' +
                       'this message is a response (RFC 9421 section 2.2).');
  }
  if (name === '@status') {
    const status = message.status;
    if (!Number.isInteger(status) || status < 100 || status > 999) {
      log.debug("Leaving httpsigDerivedValue(). Bad status.");
      return httpsigRefuse('STS-KEYS-0117',
                         'The response status "' + String(status) +
                         '" is not a three-digit integer (RFC 9421 section ' +
                         '2.2.9).');
    }
    log.debug("Leaving httpsigDerivedValue(). @status");
    return { ok: true, value: String(status) };
  }
  if (name === '@method') {
    if (typeof message.method !== 'string' || message.method === '') {
      log.debug("Leaving httpsigDerivedValue(). No method.");
      return httpsigRefuse('STS-KEYS-0118',
                         'The request has no method to derive @method from.');
    }
    log.debug("Leaving httpsigDerivedValue(). @method");
    return { ok: true, value: message.method };
  }
  const parts = httpsigTargetParts(message);
  if (!parts) {
    log.debug("Leaving httpsigDerivedValue(). No target.");
    return httpsigRefuse('STS-KEYS-0118',
                       'The request has no absolute target URI to derive ' +
                       name + ' from (RFC 9421 section 2.2.2); got ' +
                       JSON.stringify(message && message.targetUri) + '.');
  }
  let value;
  switch (name) {
    case '@target-uri':
      value = parts.targetUri;
      break;
    case '@authority':
      value = parts.authority;
      break;
    case '@scheme':
      value = parts.scheme;
      break;
    case '@request-target':
      value = typeof message.requestTarget === 'string'
        ? message.requestTarget
        : parts.path + (parts.query === null ? '' : '?' + parts.query);
      break;
    case '@path':
      value = parts.path;
      break;
    case '@query':
      value = '?' + (parts.query === null ? '' : parts.query);
      break;
    default: {
      const wanted = sf.paramValue(params, 'name');
      if (wanted === undefined) {
        log.debug("Leaving httpsigDerivedValue(). No name.");
        return httpsigRefuse('STS-KEYS-0119',
                           '@query-param requires a name parameter (RFC ' +
                           '9421 section 2.2.8).');
      }
      const matches = httpsigQueryParams(parts.query).filter((pair) => {
        return pair[0] === wanted;
      });
      if (matches.length === 0) {
        log.debug("Leaving httpsigDerivedValue(). Query parameter " +
                  "absent.");
        return httpsigRefuse('STS-KEYS-0119',
                           'The query parameter "' + wanted +
                           '" named as a covered component does not occur ' +
                           'in the target URI (RFC 9421 section 2.2.8).');
      }
      if (matches.length > 1) {
        log.debug("Leaving httpsigDerivedValue(). Query parameter " +
                  "repeated.");
        return httpsigRefuse('STS-KEYS-0120',
                           'The query parameter "' + wanted + '" occurs ' +
                           matches.length +
                           ' times; a parameter that occurs more than once ' +
                           'MUST NOT be covered by name (RFC 9421 section ' +
                           '2.2.8).');
      }
      value = matches[0][1];
    }
  }
  log.debug("Leaving httpsigDerivedValue(). " + name);
  return { ok: true, value: value };
}

function httpsigFieldValue(message, name, params, options) {
  log.debug("Entering httpsigFieldValue(). " + name);
  const problem = httpsigCheckParams(name, params, ['sf', 'key', 'bs', 'req',
                                   'tr']);
  if (problem) {
    log.debug("Leaving httpsigFieldValue(). Parameters.");
    return problem;
  }
  if (sf.param(params, 'tr') !== undefined) {
    log.debug("Leaving httpsigFieldValue(). Trailer.");
    return httpsigRefuse('STS-KEYS-0121',
                       'The component "' + name +
                       '";tr names a trailer field, and trailers are not ' +
                       'part of the message this verifier is given (RFC ' +
                       '9421 section 2.1.4).');
  }
  const bs = sf.param(params, 'bs') !== undefined;
  const key = sf.paramValue(params, 'key');
  const strict = sf.param(params, 'sf') !== undefined;
  if (bs && (strict || key !== undefined)) {
    log.debug("Leaving httpsigFieldValue(). Incompatible.");
    return httpsigRefuse('STS-KEYS-0122',
                       'The component "' + name + '" combines ;bs with ' +
                       (strict ? ';sf' : ';key') + ', which are mutually ' +
                       'incompatible (RFC 9421 sections 2.1 and 2.5 step ' +
                       '2.5).');
  }
  const lines = httpsigFieldLines(message, name);
  if (!lines) {
    log.debug("Leaving httpsigFieldValue(). Absent.");
    return httpsigRefuse('STS-KEYS-0123',
                       'The HTTP field "' + name +
                       '" is a covered component and is not present in the ' +
                       'message (RFC 9421 section 2.5).');
  }
  const normalized = lines.map((line) => httpsigNormalizeLine(line));
  if (bs) {
    log.debug("Leaving httpsigFieldValue(). bs.");
    return {
      ok: true,
      value: sf.serializeList(normalized.map((line) => {
        return { type: 'bytes', value: Buffer.from(line, 'latin1'),
                 params: [] };
      }))
    };
  }
  const combined = normalized.join(', ');
  if (!strict && key === undefined) {
    log.debug("Leaving httpsigFieldValue(). Plain.");
    return { ok: true, value: combined };
  }
  const types = Object.assign({}, KNOWN_FIELD_TYPES,
                              (options && options.fieldTypes) || {});
  const type = types[name];
  if (!type || (key !== undefined && type !== 'dictionary')) {
    log.debug("Leaving httpsigFieldValue(). Type unknown.");
    return httpsigRefuse('STS-KEYS-0124',
                       'The component "' + name + '" asks for ' +
                       (key !== undefined ? ';key' : ';sf') +
                       ', and "' + name + '" is ' +
                       (type ? 'a Structured Field ' + type +
                               ', not a Dictionary'
                             : 'not a Structured Field type this ' +
                               'verifier knows') +
                       ' (RFC 9421 sections 2.1.1 and 2.1.2).');
  }
  let value;
  try {
    if (key !== undefined) {
      const member = sf.member(sf.parseDictionary(combined), key);
      if (member === undefined) {
        log.debug("Leaving httpsigFieldValue(). Key absent.");
        return httpsigRefuse('STS-KEYS-0125',
                           'The Dictionary field "' + name +
                           '" has no member "' + key + '", which is a ' +
                           'covered component (RFC 9421 section 2.1.2).');
      }
      value = member.type === 'innerList' ? sf.serializeInnerList(member)
                                          : sf.serializeItem(member);
    } else if (type === 'dictionary') {
      value = sf.serializeDictionary(sf.parseDictionary(combined));
    } else if (type === 'list') {
      value = sf.serializeList(sf.parseList(combined));
    } else {
      value = sf.serializeItem(sf.parseItem(combined));
    }
  } catch (e) {
    log.debug("Caught in httpsigFieldValue(): " +
              ((e && e.message) || e));
    log.debug("Leaving httpsigFieldValue(). Malformed.");
    return httpsigRefuse('STS-KEYS-0126',
                       'The field "' + name +
                       '" does not parse as a Structured Field ' + type +
                       ': ' + e.message);
  }
  log.debug("Leaving httpsigFieldValue(). Strict.");
  return { ok: true, value: value };
}

// WHICH MESSAGE A COMPONENT IS READ FROM, AND WITH WHICH PARAMETERS. Without
// `;req` it is the message itself. With it, section 2.4 says the component
// "is to be derived from the request message" a response answers. Two cases
// are refused rather than guessed at:
//
//   * `;req` on a REQUEST. Section 2.4: a signature targeting a request
//     "MUST NOT" use it. Reading the request's own value would sign the same
//     component under two identifiers.
//   * `;req` on a response whose request the caller did not supply. Deriving
//     the value from the response instead would sign the wrong message's value,
//     and it would verify.
//
// `@status;req` falls to the derived-component check, because a request has
// no status (section 2.2.9).
function httpsigRequestTarget(message, name, params) {
  log.debug("Entering httpsigRequestTarget(). " + name);
  if (sf.param(params, 'req') === undefined) {
    log.debug("Leaving httpsigRequestTarget(). The message itself.");
    return { ok: true, message: message, params: params };
  }
  const isResponse = message && message.status !== undefined &&
                     message.status !== null;
  if (!isResponse) {
    log.debug("Leaving httpsigRequestTarget(). ;req on a request.");
    return httpsigRefuse('STS-KEYS-0115',
                         'The component "' + name + '";req names a value ' +
                         'from the request a RESPONSE answers, and this ' +
                         'message is a request; a signature targeting a ' +
                         'request MUST NOT use ;req (RFC 9421 section 2.4).');
  }
  const request = message.request;
  if (!request || typeof request !== 'object' ||
      (request.status !== undefined && request.status !== null)) {
    log.debug("Leaving httpsigRequestTarget(). No related request.");
    return httpsigRefuse('STS-KEYS-0154',
                         'The component "' + name + '";req names a value ' +
                         'from the request this response answers, and no ' +
                         'request message was given to read it from (RFC ' +
                         '9421 section 2.4).');
  }
  log.debug("Leaving httpsigRequestTarget(). The related request.");
  return { ok: true, message: request,
           params: params.filter((pair) => { return pair[0] !== 'req'; }) };
}

// A component's canonical value, or a refusal. `identifier` is the serialized
// component identifier the value is written after in a signature base.
/**
 * Returns a component's canonical value in a message, with its serialized
 * component identifier.
 *
 * @param message - the HTTP message
 * @param component - the component
 * @param options - per-call options, such as extra field types
 * @returns `{ ok: true, value, identifier }`, or a refusal
 */
function httpSignatureComponentValue(message, component, options) {
  log.debug("Entering httpSignatureComponentValue().");
  const normalized = httpsigComponentItem(component);
  if (httpsigIsRefusal(normalized)) {
    log.debug("Leaving httpSignatureComponentValue(). Identifier.");
    return normalized;
  }
  const item = normalized.item;
  const name = item.value;
  if (name === '@signature-params') {
    log.debug("Leaving httpSignatureComponentValue(). @signature-params.");
    return httpsigRefuse('STS-KEYS-0127',
                       '@signature-params MUST NOT be listed among the ' +
                       'covered components; it is always the last line of ' +
                       'the signature base (RFC 9421 section 2.3).');
  }
  // `;req` (section 2.4): the value comes from the REQUEST this response
  // answers, which the caller hands in as `message.request`. The identifier
  // keeps the flag, because it is part of what is signed. The value is derived
  // from the request with the flag taken off, so `"@method";req` reads the
  // request's @method exactly as `"@method"` would on the request itself.
  const req = httpsigRequestTarget(message, name, item.params);
  if (httpsigIsRefusal(req)) {
    log.debug("Leaving httpSignatureComponentValue(). ;req.");
    return req;
  }
  const result = name[0] === '@'
    ? httpsigDerivedValue(req.message, name, req.params)
    : httpsigFieldValue(req.message, name, req.params, options);
  if (httpsigIsRefusal(result)) {
    log.debug("Leaving httpSignatureComponentValue(). Refused.");
    return result;
  }
  // Section 2: a component value MUST NOT contain a newline; section 2.5 step
  // 4: the base is ASCII. Both are checked on the VALUE, so the refusal can
  // name the component that broke them.
  if (/[\r\n]/.test(result.value) || /[^\x20-\x7e\t]/.test(result.value)) {
    log.debug("Leaving httpSignatureComponentValue(). Not printable ASCII.");
    return httpsigRefuse('STS-KEYS-0128',
                       'The value of the component "' + name +
                       '" contains a newline or a character outside ASCII, ' +
                       'which a signature base may not (RFC 9421 sections ' +
                       '2 and 2.5 step 4); ;bs exists for such a field.');
  }
  log.debug("Leaving httpSignatureComponentValue().");
  return { ok: true, value: result.value, identifier: sf.serializeItem(item),
           item: item };
}

// ===========================================================================
// THE SIGNATURE BASE, SECTION 2.5, AND THE SIGNATURE PARAMETERS, SECTION 2.3.
// ===========================================================================

function httpsigCheckSignatureParams(params) {
  log.debug("Entering httpsigCheckSignatureParams().");
  for (let k = 0; k < params.length; k++) {
    const wanted = PARAM_TYPES[params[k][0]];
    if (wanted && params[k][1].type !== wanted) {
      log.debug("Leaving httpsigCheckSignatureParams(). Wrong type.");
      return httpsigRefuse('STS-KEYS-0129',
                         'The signature parameter "' + params[k][0] +
                         '" must be ' +
                         (wanted === 'integer' ? 'an Integer' : 'a String') +
                         ', not a ' +
                         params[k][1].type + ' (RFC 9421 section 2.3).');
    }
    if (wanted === 'integer' && params[k][1].value < 0) {
      log.debug("Leaving httpsigCheckSignatureParams(). Negative time.");
      return httpsigRefuse('STS-KEYS-0129',
                         'The signature parameter "' + params[k][0] +
                         '" is a negative UNIX timestamp (RFC 9421 section ' +
                         '2.3).');
    }
  }
  log.debug("Leaving httpsigCheckSignatureParams().");
  return null;
}

// `covered` is either an Inner List (whose own `params` are used when
// `signatureParams` is not given — which is what a PARSED Signature-Input
// member is) or an array of components in any form `componentItem()` reads.
// `signatureParams` is an ordered [[key, value]] array or a plain object.
/**
 * Builds the signature base (RFC 9421 section 2.5) over the covered
 * components.
 *
 * @param message - the HTTP message
 * @param covered - an Inner List, or an array of components
 * @param signatureParams - an ordered `[[key, value]]` array or a plain
 *   object; an Inner List's own `params` when absent
 * @param options - per-call options, such as extra field types
 * @returns `{ ok: true, base, signatureParams, components }`, or a refusal
 */
function httpSignatureBase(message, covered, signatureParams, options) {
  log.debug("Entering httpSignatureBase().");
  let components;
  let paramsInput = signatureParams;
  if (covered && covered.type === 'innerList' &&
      Array.isArray(covered.value)) {
    components = covered.value;
    if (paramsInput === undefined) {
      paramsInput = covered.params;
    }
  } else if (Array.isArray(covered)) {
    components = covered;
  } else {
    log.debug("Leaving httpSignatureBase(). No component list.");
    return httpsigRefuse('STS-KEYS-0113',
                       'The covered components must be an array or an ' +
                       'Inner List.');
  }
  let params;
  try {
    params = httpsigParamsFrom(paramsInput);
  } catch (e) {
    log.debug("Caught in httpSignatureBase(): " +
              ((e && e.message) || e));
    log.debug("Leaving httpSignatureBase(). Parameters.");
    return httpsigRefuse('STS-KEYS-0129',
                       'The signature parameters cannot be serialized: ' +
                       e.message + '.');
  }
  const paramProblem = httpsigCheckSignatureParams(params);
  if (paramProblem) {
    log.debug("Leaving httpSignatureBase(). Parameter types.");
    return paramProblem;
  }
  const items = [];
  const lines = [];
  const seen = {};
  for (let k = 0; k < components.length; k++) {
    const normalized = httpsigComponentItem(components[k]);
    if (httpsigIsRefusal(normalized)) {
      log.debug("Leaving httpSignatureBase(). Identifier.");
      return normalized;
    }
    const identity = httpsigIdentityOf(normalized.item);
    if (seen[identity]) {
      log.debug("Leaving httpSignatureBase(). Duplicate.");
      return httpsigRefuse('STS-KEYS-0130',
                         'The component ' +
                         sf.serializeItem(normalized.item) + ' is covered ' +
                         'more than once; each component identifier MUST ' +
                         'occur only once (RFC 9421 sections 2 and 2.5 ' +
                         'step 2.1).');
    }
    seen[identity] = true;
    const cv = httpSignatureComponentValue(message, normalized.item, options);
    if (httpsigIsRefusal(cv)) {
      log.debug("Leaving httpSignatureBase(). Component refused.");
      return cv;
    }
    items.push(normalized.item);
    lines.push(cv.identifier + ': ' + cv.value);
  }
  const serializedParams = sf.serializeInnerList(
      { type: 'innerList', value: items, params: params });
  lines.push('"@signature-params": ' + serializedParams);
  log.debug("Leaving httpSignatureBase(). " + items.length +
            " component(s).");
  return {
    ok: true,
    base: lines.join('\n'),
    signatureParams: serializedParams,
    components: items,
    params: params
  };
}

function httpsigAlgorithmNamed(name) {
  log.debug("Entering httpsigAlgorithmNamed().");
  log.debug("Leaving httpsigAlgorithmNamed().");
  return typeof name === 'string' &&
         Object.prototype.hasOwnProperty.call(HTTP_SIGNATURE_ALGORITHMS, name)
    ? HTTP_SIGNATURE_ALGORITHMS[name] : null;
}

// THE KEY A CALLER HANDED IN, IN THE FORM THE PRIMITIVE TAKES. A KeyObject
// or bytes pass through unchanged. A JWK is read here, so a caller holding a
// client's registered JWKS or a realm signer's JWK does not convert it: `oct`
// becomes the secret's bytes, `AKP` stays a JWK (or becomes its `priv` seed
// when signing) for `pq_jose`, and anything else becomes a KeyObject. A
// public JWK whose `use` or `key_ops` says it is not for verification is
// refused, as `verifyCompactJws()` refuses it (RFC 7517 sections 4.2 and
// 4.3). Throws on a JWK node cannot read; `httpsigCheckKey()` maps that.
function httpsigKeyOf(entry, key, purpose) {
  log.debug("Entering httpsigKeyOf(). " + purpose);
  const isJwk = key && typeof key === 'object' && !Buffer.isBuffer(key) &&
                !(key instanceof Uint8Array) &&
                !(key instanceof nodeCrypto.KeyObject) &&
                typeof key.kty === 'string';
  if (!isJwk) {
    log.debug("Leaving httpsigKeyOf(). Not a JWK.");
    return key;
  }
  if (purpose === 'verify') {
    const misuse = jwkUseProblem(key);
    if (misuse) {
      log.debug("Leaving httpsigKeyOf(). " + misuse);
      throw new Error('the JWK is ' + misuse);
    }
  }
  if (key.kty === 'oct') {
    log.debug("Leaving httpsigKeyOf(). A secret.");
    return Buffer.from(String(key.k || ''), 'base64url');
  }
  if (key.kty === 'AKP') {
    if (purpose === 'sign' && typeof key.priv !== 'string') {
      log.debug("Leaving httpsigKeyOf(). A public AKP key, to sign.");
      throw new Error('an AKP JWK with no "priv" member, which is a public ' +
                      'key and cannot sign');
    }
    log.debug("Leaving httpsigKeyOf(). An AKP key.");
    return purpose === 'sign' ? Buffer.from(key.priv, 'base64url') : key;
  }
  const made = purpose === 'sign'
    ? nodeCrypto.createPrivateKey({ key: key, format: 'jwk' })
    : nodeCrypto.createPublicKey({ key: key, format: 'jwk' });
  log.debug("Leaving httpsigKeyOf(). A " + made.asymmetricKeyType + " key.");
  return made;
}

// Is this key material appropriate for this algorithm (section 3.1 step 1,
// section 3.2 step 8)? A key of the wrong family is refused BEFORE node is
// asked, because node's answer to an Ed25519 key under an RSA algorithm is an
// exception whose text names neither. Returns null, or a refusal.
function httpsigCheckKey(name, entry, key, purpose) {
  log.debug("Entering httpsigCheckKey(). " + name + " " + purpose);
  if (entry.kind === 'jws-pq') {
    // `pq_jose` signs with the private seed or key as bytes, and verifies
    // with an AKP JWK or the public key's bytes. Its own checks (the seed's
    // length, the signature's) answer the rest.
    const bytes = Buffer.isBuffer(key) || key instanceof Uint8Array;
    const akp = !!key && typeof key === 'object' && key.kty === 'AKP' &&
                (key.alg === undefined || key.alg === name);
    if (purpose === 'sign' ? !bytes : !(bytes || akp)) {
      log.debug("Leaving httpsigCheckKey(). Not a post-quantum key.");
      return httpsigRefuse('STS-KEYS-0131',
                           name + ' needs ' + (purpose === 'sign'
                             ? 'its private key as bytes'
                             : 'an AKP JWK for ' + name + ' or the public ' +
                               'key as bytes') +
                           ', and the key given is not one (RFC 9964).');
    }
    log.debug("Leaving httpsigCheckKey(). Post-quantum.");
    return null;
  }
  if (entry.kind === 'hmac') {
    let length = -1;
    if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
      length = key.length;
    } else if (key instanceof nodeCrypto.KeyObject && key.type === 'secret') {
      length = key.symmetricKeySize;
    }
    if (length < 0) {
      log.debug("Leaving httpsigCheckKey(). Not a secret.");
      return httpsigRefuse('STS-KEYS-0131',
                           name + ' needs a shared secret (a Buffer), and ' +
                           'the key given is not one.');
    }
    if (length < entry.minKeyBytes) {
      log.debug("Leaving httpsigCheckKey(). Secret too short.");
      return httpsigRefuse('STS-KEYS-0131',
                           name + ' needs a secret of at least ' +
                           entry.minKeyBytes + ' octets, the size of its ' +
                           'hash; this one has ' + length + ' (RFC 7518 ' +
                           'section 3.2).');
    }
    log.debug("Leaving httpsigCheckKey(). Secret.");
    return null;
  }
  if (!(key instanceof nodeCrypto.KeyObject) || key.type === 'secret' ||
      (purpose === 'sign' && key.type !== 'private')) {
    log.debug("Leaving httpsigCheckKey(). Not an asymmetric key.");
    return httpsigRefuse('STS-KEYS-0131',
                         name + ' needs ' +
                         (purpose === 'sign' ? 'a private' : 'a public') +
                         ' asymmetric KeyObject, and the key given is not ' +
                         'one.');
  }
  const type = key.asymmetricKeyType;
  const details = key.asymmetricKeyDetails || {};
  let problem = null;
  if (entry.kind === 'rsa-v1_5' || entry.kind === 'rsa-pss') {
    if (type !== 'rsa' && !(type === 'rsa-pss' && entry.kind === 'rsa-pss')) {
      problem = 'is a ' + type + ' key, not an RSA key' +
                (type === 'rsa-pss' ? ' usable for PKCS#1 v1.5' : '');
    } else if (!(details.modulusLength >= 2048)) {
      problem = 'is an RSA key of ' + details.modulusLength +
                ' bits, under the 2048 RFC 7518 section 3.3 requires';
    } else if (type === 'rsa-pss' && details.hashAlgorithm &&
               details.hashAlgorithm !== entry.hash) {
      problem = 'is an RSASSA-PSS key restricted to ' + details.hashAlgorithm;
    } else if (purpose === 'verify') {
      // The checks every RSA verification here makes (#202): an exponent
      // or a modulus that makes a forgery.
      const weak = rsaKeyProblem(key, 2048);
      if (weak) {
        problem = 'is ' + weak;
      }
    }
  } else if (entry.kind === 'ecdsa') {
    if (type !== 'ec' || details.namedCurve !== entry.curve) {
      problem = 'is a ' + type +
                (details.namedCurve ? ' ' + details.namedCurve : '') +
                ' key, not an EC key on ' + entry.curve;
    }
  } else if (entry.kind === 'eddsa') {
    if (entry.curves.indexOf(type) < 0) {
      problem = 'is a ' + type + ' key, not ' + entry.curves.join(' or ');
    }
  }
  if (problem) {
    log.debug("Leaving httpsigCheckKey(). " + problem);
    return httpsigRefuse('STS-KEYS-0131',
                         'The key for ' + name + ' ' + problem + ' (' +
                         entry.spec + ').');
  }
  log.debug("Leaving httpsigCheckKey().");
  return null;
}

// HTTP_SIGN, section 3.3. Throws whatever the primitive throws; callers map
// it. A post-quantum or composite JWS algorithm is signed by
// `jwsSignatureOver()`, the function that signs it inside a JWS.
function httpsigRawSign(entry, key, data) {
  log.debug("Entering httpsigRawSign(). " + entry.kind);
  let out;
  switch (entry.kind) {
    case 'jws-pq':
      out = jwsSignatureOver(entry.jws, key, data);
      break;
    case 'hmac':
      out = nodeCrypto.createHmac(entry.hash, key).update(data).digest();
      break;
    case 'rsa-v1_5':
      out = nodeCrypto.sign(entry.hash, data, key);
      break;
    case 'rsa-pss':
      out = nodeCrypto.sign(entry.hash, data, {
        key: key, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: entry.saltLength
      });
      break;
    case 'ecdsa':
      out = nodeCrypto.sign(entry.hash, data,
                            { key: key, dsaEncoding: 'ieee-p1363' });
      break;
    default:
      out = nodeCrypto.sign(null, data, key);
  }
  log.debug("Leaving httpsigRawSign().");
  return out;
}

// HTTP_VERIFY, section 3.3. The HMAC comparison is constant-time, and a
// length difference is a plain false: `timingSafeEqual` throws on unequal
// lengths, and an exception there would be a different code path an
// attacker can time. A post-quantum or composite JWS algorithm is verified
// by `jwsSignatureValid()`.
function httpsigRawVerify(entry, key, data, signature) {
  log.debug("Entering httpsigRawVerify(). " + entry.kind);
  let ok;
  switch (entry.kind) {
    case 'jws-pq':
      ok = jwsSignatureValid(entry.jws, key, data, signature);
      break;
    case 'hmac': {
      const expected = nodeCrypto.createHmac(entry.hash, key)
                                 .update(data)
                                 .digest();
      ok = expected.length === signature.length &&
           nodeCrypto.timingSafeEqual(expected, signature);
      break;
    }
    case 'rsa-v1_5':
      ok = nodeCrypto.verify(entry.hash, data, key, signature);
      break;
    case 'rsa-pss':
      ok = nodeCrypto.verify(entry.hash, data, {
        key: key, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: entry.saltLength
      }, signature);
      break;
    case 'ecdsa':
      // r||s at the coordinate size and nothing else: a DER signature, or one
      // of the other curve's length, is not this algorithm's output (3.3.4).
      ok = signature.length === 2 * entry.coordinateBytes &&
           nodeCrypto.verify(entry.hash, data,
                             { key: key, dsaEncoding: 'ieee-p1363' },
                             signature);
      break;
    default:
      ok = nodeCrypto.verify(null, data, key, signature);
  }
  log.debug("Leaving httpsigRawVerify(). " + ok);
  return !!ok;
}

// ===========================================================================
// SIGNING, SECTION 3.1, AND PUTTING A SIGNATURE IN A MESSAGE, SECTION 4.
// ===========================================================================

// options: { label, components, params, key, algorithm, fieldTypes }
//
// `algorithm` may be an HTTP registry name or a JWS name; when it is absent
// the `alg` parameter names it. It is never INVENTED into the parameters:
// whether the signature carries `alg` is the signer's decision (GNAP forbids
// it), so the parameters are exactly what the caller passed, in the caller's
// order.
/**
 * Signs a message (section 3.1). The parameters are exactly what the caller
 * passed, in its order; `alg` is never added.
 *
 * @param message - the HTTP message
 * @param options - `{ label, components, params, key, algorithm, fieldTypes
 *   }`
 * @returns `{ ok: true, label, algorithm, signatureInput, ... }`, or a
 *   refusal
 */
function signHttpMessage(message, options) {
  log.debug("Entering signHttpMessage().");
  const opts = options || {};
  try {
    sf.serializeKey(opts.label);
  } catch (e) {
    log.debug("Caught in signHttpMessage(): " + ((e && e.message) || e));
    log.debug("Leaving signHttpMessage(). Label.");
    return httpsigRefuse('STS-KEYS-0132',
                       'The signature label ' + JSON.stringify(opts.label) +
                       ' is not a valid Dictionary key (RFC 9421 section ' +
                       '4.1): ' + e.message);
  }
  let params;
  try {
    params = httpsigParamsFrom(opts.params);
  } catch (e) {
    log.debug("Caught in signHttpMessage(): " + ((e && e.message) || e));
    log.debug("Leaving signHttpMessage(). Parameters.");
    return httpsigRefuse('STS-KEYS-0129',
                       'The signature parameters cannot be serialized: ' +
                       e.message + '.');
  }
  const algParam = sf.paramValue(params, 'alg');
  const name = opts.algorithm !== undefined ? opts.algorithm : algParam;
  if (name === undefined) {
    log.debug("Leaving signHttpMessage(). No algorithm.");
    return httpsigRefuse('STS-KEYS-0133',
                       'No signature algorithm was named, by the caller or ' +
                       'by an alg parameter (RFC 9421 section 3.1 step 1).');
  }
  const entry = httpsigAlgorithmNamed(name);
  if (!entry) {
    log.debug("Leaving signHttpMessage(). Unknown algorithm.");
    return httpsigRefuse('STS-KEYS-0134',
                       'The signature algorithm ' + JSON.stringify(name) +
                       ' is not supported; the supported ones are ' +
                       Object.keys(HTTP_SIGNATURE_ALGORITHMS).join(', ') + '.');
  }
  if (algParam !== undefined &&
      (entry.registry === 'jws' || algParam !== name)) {
    log.debug("Leaving signHttpMessage(). alg conflict.");
    return httpsigRefuse('STS-KEYS-0135',
                       entry.registry === 'jws'
                    ? 'The JWS algorithm ' + name + ' cannot be signalled ' +
                       'with the alg signature parameter (RFC 9421 section ' +
                       '3.3.7).'
                    : 'The alg parameter "' + algParam + '" names a ' +
                       'different algorithm from the one signing, ' +
                       name + ' (RFC 9421 section 3.2 step 6.5).');
  }
  let signingKey;
  try {
    signingKey = httpsigKeyOf(entry, opts.key, 'sign');
  } catch (e) {
    log.debug("Caught in signHttpMessage(): " + ((e && e.message) || e));
    log.debug("Leaving signHttpMessage(). The key cannot be read.");
    return httpsigRefuse('STS-KEYS-0131',
                         'The key for ' + name + ' cannot be read: ' +
                         e.message + '.');
  }
  const keyProblem = httpsigCheckKey(name, entry, signingKey, 'sign');
  if (keyProblem) {
    log.debug("Leaving signHttpMessage(). Key.");
    return keyProblem;
  }
  const built = httpSignatureBase(message, opts.components || [], params,
                                   opts);
  if (httpsigIsRefusal(built)) {
    log.debug("Leaving signHttpMessage(). Base.");
    return built;
  }
  let signatureBytes;
  try {
    signatureBytes = httpsigRawSign(entry, signingKey, Buffer.from(built.base,
                                  'ascii'));
  } catch (e) {
    log.debug("Caught in signHttpMessage(): " + ((e && e.message) || e));
    log.debug("Leaving signHttpMessage(). Primitive threw.");
    return httpsigRefuse('STS-KEYS-0136',
                       'Signing with ' + name +
                       ' failed inside the cryptographic library: ' +
                       e.message);
  }
  log.debug("Leaving signHttpMessage(). " + opts.label);
  return {
    ok: true,
    label: opts.label,
    algorithm: name,
    signatureInput: opts.label + '=' + built.signatureParams,
    signature: opts.label + '=' +
               sf.serializeItem({ type: 'bytes', value: signatureBytes,
                                  params: [] }),
    signatureParams: built.signatureParams,
    base: built.base,
    signatureBytes: signatureBytes
  };
}

function httpsigHeaderKeyFor(headers, name) {
  log.debug("Entering httpsigHeaderKeyFor().");
  const keys = Object.keys(headers);
  for (let k = 0; k < keys.length; k++) {
    if (keys[k].toLowerCase() === name) {
      log.debug("Leaving httpsigHeaderKeyFor().");
      return keys[k];
    }
  }
  log.debug("Leaving httpsigHeaderKeyFor().");
  return name;
}

// A NEW message with `result`'s two members appended to the message's
// Signature-Input and Signature fields — the shape of RFC 9635 section
// 7.3.1.1, where the key-rotation signature is added beside the old key's and
// covers it.
//
// It APPENDS TEXT rather than re-serializing what was there. A later
// signature may cover the whole `signature-input` field without `;key`, and
// that covers its bytes as sent; re-serializing the existing members would
// change those bytes under a signature that has already been made. The
// existing value is still PARSED first, because appending to a malformed
// field makes one nobody can read, and a label already present in either
// field is refused — section 4 says a label MUST be unique, and a second
// member under it would replace the first for every last-wins parser.
/**
 * Returns a new message with a signature's two members appended to its
 * Signature-Input and Signature fields, as text, so bytes already signed do
 * not change (RFC 9635 section 7.3.1.1). A label already present is refused.
 *
 * @param message - the HTTP message
 * @param result - what `sign()` returned
 * @returns `{ ok: true, message }`, or a refusal
 */
function appendHttpSignature(message, result) {
  log.debug("Entering appendHttpSignature().");
  if (!result || result.ok !== true ||
      typeof result.signatureInput !== 'string' ||
      typeof result.signature !== 'string') {
    log.debug("Leaving appendHttpSignature(). Not a signature.");
    return httpsigRefuse('STS-KEYS-0137',
                       'Only a successful sign() result can be appended to ' +
                       'a message.');
  }
  const headers = Object.assign({}, (message && message.headers) || {});
  const fields = [['signature-input', result.signatureInput],
                  ['signature', result.signature]];
  for (let k = 0; k < fields.length; k++) {
    const lines = httpsigFieldLines({ headers: headers }, fields[k][0]);
    if (!lines) {
      continue;
    }
    let dictionary;
    try {
      dictionary = sf.parseDictionary(lines.join(', '));
    } catch (e) {
      log.debug("Caught in appendHttpSignature(): " +
                ((e && e.message) || e));
      log.debug("Leaving appendHttpSignature(). Existing field " +
                "malformed.");
      return httpsigRefuse('STS-KEYS-0138',
                         'The message\'s existing ' + fields[k][0] +
                         ' field is not a Dictionary, so nothing can be ' +
                         'appended to it: ' + e.message);
    }
    if (sf.member(dictionary, result.label) !== undefined) {
      log.debug("Leaving appendHttpSignature(). Label taken.");
      return httpsigRefuse('STS-KEYS-0137',
                         'The label "' + result.label +
                         '" is already used in the message\'s ' +
                         fields[k][0] +
                         ' field; a signature label MUST be unique (RFC ' +
                         '9421 section 4).');
    }
  }
  fields.forEach((field) => {
    const headerKey = httpsigHeaderKeyFor(headers, field[0]);
    const existing = headers[headerKey];
    if (existing === undefined || existing === null) {
      headers[headerKey] = field[1];
    } else if (Array.isArray(existing)) {
      headers[headerKey] = existing.concat([field[1]]);
    } else {
      headers[headerKey] = String(existing) + ', ' + field[1];
    }
  });
  log.debug("Leaving appendHttpSignature(). " + result.label);
  return { ok: true,
           message: Object.assign({}, message, { headers: headers }) };
}

// ===========================================================================
// PARSING THE TWO FIELDS, SECTIONS 4.1, 4.2 AND 3.2 STEPS 1 TO 3.
// ===========================================================================

function httpsigParseField(message, name) {
  log.debug("Entering httpsigParseField(). " + name);
  const lines = httpsigFieldLines(message, name);
  if (!lines) {
    log.debug("Leaving httpsigParseField(). Absent.");
    return { ok: true, dictionary: [] };
  }
  const duplicates = [];
  let dictionary = [];
  try {
    // Line by line as well as combined: a label repeated on two field lines
    // is just as much a second signature under one name as one repeated
    // within a line (section 4.1: "unique across all field values").
    dictionary = sf.parseDictionary(lines.join(', '), {
      onDuplicate: (key) => {
        log.debug("Entering onDuplicate().");
        duplicates.push(key);
        log.debug("Leaving onDuplicate().");
      }
    });
  } catch (e) {
    log.debug("Caught in httpsigParseField(): " +
              ((e && e.message) || e));
    log.debug("Leaving httpsigParseField(). Malformed.");
    return httpsigRefuse('STS-KEYS-0138',
                       'The ' + name + ' field is not a Structured Field ' +
                       'Dictionary (RFC 9421 section 4): ' + e.message);
  }
  if (duplicates.length) {
    log.debug("Leaving httpsigParseField(). Duplicate label.");
    return httpsigRefuse('STS-KEYS-0139',
                       'The ' + name + ' field uses the label "' +
                       duplicates[0] + '" more than once; labels MUST be ' +
                       'unique across all field values (RFC 9421 sections ' +
                       '4.1 and 4.2).');
  }
  log.debug("Leaving httpsigParseField(). " +
            dictionary.length + " member(s).");
  return { ok: true, dictionary: dictionary };
}

function httpsigParamsObject(params) {
  log.debug("Entering httpsigParamsObject().");
  const out = {};
  (params || []).forEach((pair) => {
    out[pair[0]] = pair[1].value;
  });
  log.debug("Leaving httpsigParamsObject().");
  return out;
}

// Every signature the message carries, in Signature-Input order:
// { ok: true, signatures: [{ label, components, componentIds, params,
//   paramList, signature, serializedParams }] }, or a refusal.
/**
 * Parses every signature a message carries, in Signature-Input order.
 *
 * @param message - the HTTP message
 * @returns `{ ok: true, signatures }`, each with its label, components,
 *   parameters and signature, or a refusal
 */
function parseHttpSignatures(message) {
  log.debug("Entering parseHttpSignatures().");
  const inputs = httpsigParseField(message, 'signature-input');
  if (httpsigIsRefusal(inputs)) {
    log.debug("Leaving parseHttpSignatures(). Signature-Input.");
    return inputs;
  }
  const values = httpsigParseField(message, 'signature');
  if (httpsigIsRefusal(values)) {
    log.debug("Leaving parseHttpSignatures(). Signature.");
    return values;
  }
  if (inputs.dictionary.length === 0 && values.dictionary.length === 0) {
    log.debug("Leaving parseHttpSignatures(). None.");
    return httpsigRefuse('STS-KEYS-0140',
                       'The message carries no HTTP message signature: it ' +
                       'has no Signature-Input and no Signature field (RFC ' +
                       '9421 section 4).');
  }
  const labels = {};
  inputs.dictionary.forEach((pair) => { labels[pair[0]] = true; });
  values.dictionary.forEach((pair) => { labels[pair[0]] = true; });
  const out = [];
  const allLabels = Object.keys(labels);
  for (let k = 0; k < allLabels.length; k++) {
    const label = allLabels[k];
    const input = sf.member(inputs.dictionary, label);
    const value = sf.member(values.dictionary, label);
    if (input === undefined || value === undefined) {
      log.debug("Leaving parseHttpSignatures(). Label mismatch.");
      return httpsigRefuse('STS-KEYS-0141',
                         'The signature label "' + label +
                         '" is present in the ' +
                         (input === undefined ? 'Signature'
                                              : 'Signature-Input') +
                         ' field and not in the ' +
                         (input === undefined ? 'Signature-Input'
                                              : 'Signature') +
                         ' field; the presence of a label in one field but ' +
                         'not the other is an error (RFC 9421 section 4).');
    }
    const componentsAreStrings = input.type === 'innerList' &&
                                 input.value.every((item) => {
      return item.type === 'string';
    });
    if (!componentsAreStrings || value.type !== 'bytes') {
      log.debug("Leaving parseHttpSignatures(). Member types.");
      return httpsigRefuse('STS-KEYS-0142',
                         !componentsAreStrings
                      ? 'The Signature-Input member "' + label + '" is not ' +
                         'an Inner List of String component identifiers ' +
                         '(RFC 9421 section 4.1).'
                      : 'The Signature member "' + label +
                         '" is not a Byte Sequence (RFC 9421 section 4.2).');
    }
    out.push({
      label: label,
      components: input.value,
      componentIds: input.value.map((item) => {
        return sf.serializeItem(item);
      }),
      params: httpsigParamsObject(input.params),
      paramList: input.params,
      signature: value.value,
      serializedParams: sf.serializeInnerList(input)
    });
  }
  // Signature-Input order, which is the order a reader of the message sees.
  out.sort((a, b) => {
    return httpsigIndexOfLabel(inputs.dictionary, a.label) -
           httpsigIndexOfLabel(inputs.dictionary, b.label);
  });
  log.debug("Leaving parseHttpSignatures(). " + out.length +
            " signature(s).");
  return { ok: true, signatures: out };
}

function httpsigIndexOfLabel(dictionary, label) {
  log.debug("Entering httpsigIndexOfLabel().");
  for (let k = 0; k < dictionary.length; k++) {
    if (dictionary[k][0] === label) {
      log.debug("Leaving httpsigIndexOfLabel().");
      return k;
    }
  }
  log.debug("Leaving httpsigIndexOfLabel().");
  return -1;
}

// ===========================================================================
// VERIFYING, SECTION 3.2, WITH THE APPLICATION REQUIREMENTS OF 3.2.1.
// ===========================================================================

// options:
//   label             verify only this signature (it must be present)
//   keyFor(parsed)    -> { key, algorithm } | null; `parsed` is a
//                     parseSignatures() entry. REQUIRED: section 3.2 step 5
//                     says an unknown or untrusted key MUST fail.
//   now               seconds; defaults to the clock
//   maxAgeS           created must be within this many seconds of now
//   skewS             how far in the FUTURE created may be; defaults to
//   maxAgeS requireCreated    refuse a signature with no created (implied by
//   maxAgeS) requireComponents components that MUST be covered
//   requireTag        the tag parameter's required value
//   forbidAlgParam    refuse any signature carrying alg (RFC 9635 7.3.1)
//   allowedAlgorithms the algorithms policy allows (section 3.2 step 6.1)
//   require           'all' (default): every candidate must verify;
//                     'any': one verifying candidate is enough (RFC 9635
//                     section 7.3.1's "until it finds (at least) one")
//   fieldTypes        extra Structured Field types for ;sf and ;key
//
// Candidates are the labelled signature, else every signature with the
// required tag, else every signature. The default is 'all' because a verifier
// that quietly passed over a failing signature has made a policy decision its
// caller did not.
/**
 * Verifies a message's signatures (section 3.2) against the keys
 * `options.keyFor()` names; an unknown key fails.
 *
 * By default every candidate signature must verify.
 *
 * @param message - the HTTP message
 * @param options - `label`, `keyFor`, `now`, `maxAgeS`, `skewS`,
 *   `requireCreated`, `requireComponents`, `requireTag`, `forbidAlgParam`,
 *   `allowedAlgorithms`, `require` (`all` or `any`) and `fieldTypes`
 * @returns `{ ok: true, verified }`, or a refusal
 */
function verifyHttpMessage(message, options) {
  log.debug("Entering verifyHttpMessage().");
  const opts = options || {};
  const now = opts.now !== undefined ? opts.now
                                     : Math.floor(Date.now() / 1000);
  const parsed = parseHttpSignatures(message);
  if (httpsigIsRefusal(parsed)) {
    log.debug("Leaving verifyHttpMessage(). Parse.");
    return parsed;
  }
  let candidates = parsed.signatures;
  if (opts.label !== undefined) {
    candidates =
        candidates.filter((s) => { return s.label === opts.label; });
    if (candidates.length === 0) {
      log.debug("Leaving verifyHttpMessage(). Label absent.");
      return httpsigRefuse('STS-KEYS-0143',
                         'The message carries no signature labelled "' +
                         String(opts.label) +
                         '" (RFC 9421 section 3.2 step 1.1).');
    }
  } else if (opts.requireTag !== undefined) {
    candidates = candidates.filter((s) => {
      return s.params.tag === opts.requireTag;
    });
    if (candidates.length === 0) {
      log.debug("Leaving verifyHttpMessage(). No signature with the tag.");
      return httpsigRefuse('STS-KEYS-0144',
                         'No signature in the message carries tag="' +
                         String(opts.requireTag) +
                         '"; the tags present are ' + JSON.stringify(
                        parsed.signatures.map((s) => {
                      return s.params.tag === undefined ? null : s.params.tag;
                    })) + ' (RFC 9421 section 3.2.1).');
    }
  }
  const verified = [];
  let firstFailure = null;
  for (let k = 0; k < candidates.length; k++) {
    const result = httpsigVerifyOne(message, candidates[k], opts, now);
    if (result.ok) {
      verified.push(result);
    } else if (opts.require !== 'any') {
      log.debug("Leaving verifyHttpMessage(). " + candidates[k].label +
                " refused.");
      return result;
    } else if (!firstFailure) {
      firstFailure = result;
    }
  }
  if (verified.length === 0) {
    log.debug("Leaving verifyHttpMessage(). None verified.");
    return firstFailure;
  }
  log.debug("Leaving verifyHttpMessage(). " + verified.length +
            " verified.");
  return { ok: true, verified: verified };
}

function httpsigVerifyOne(message, parsed, opts, now) {
  log.debug("Entering httpsigVerifyOne(). " + parsed.label);
  const p = parsed.params;
  const paramProblem = httpsigCheckSignatureParams(parsed.paramList);
  if (paramProblem) {
    log.debug("Leaving httpsigVerifyOne(). Parameter types.");
    return paramProblem;
  }
  if (opts.requireTag !== undefined && p.tag !== opts.requireTag) {
    log.debug("Leaving httpsigVerifyOne(). Tag.");
    return httpsigRefuse('STS-KEYS-0144',
                       'The signature "' + parsed.label + '" carries ' +
                       (p.tag === undefined ? 'no tag' : 'tag="' + p.tag +
                        '"') +
                       ' and tag="' + opts.requireTag +
                       '" is required (RFC 9421 section 3.2.1).');
  }
  if (opts.forbidAlgParam && p.alg !== undefined) {
    log.debug("Leaving httpsigVerifyOne(). alg present.");
    return httpsigRefuse('STS-KEYS-0145',
                       'The signature "' + parsed.label +
                       '" carries the alg parameter, which this ' +
                       'application forbids (RFC 9635 section 7.3.1: "The ' +
                       'explicit alg signature parameter MUST NOT be ' +
                       'included").');
  }
  if ((opts.requireCreated ||
       opts.maxAgeS !== undefined) && p.created === undefined) {
    log.debug("Leaving httpsigVerifyOne(). No created.");
    return httpsigRefuse('STS-KEYS-0146',
                       'The signature "' + parsed.label +
                       '" has no created parameter, and its age must be ' +
                       'checked (RFC 9421 section 3.2.1).');
  }
  if (p.created !== undefined && opts.maxAgeS !== undefined) {
    const skew = opts.skewS !== undefined ? opts.skewS : opts.maxAgeS;
    if (now - p.created > opts.maxAgeS) {
      log.debug("Leaving httpsigVerifyOne(). Stale.");
      return httpsigRefuse('STS-KEYS-0147',
                         'The signature "' + parsed.label + '" was created ' +
                         (now - p.created) +
                         ' seconds ago, more than the ' + opts.maxAgeS +
                         ' allowed.');
    }
    if (p.created - now > skew) {
      log.debug("Leaving httpsigVerifyOne(). Future.");
      return httpsigRefuse('STS-KEYS-0148',
                         'The signature "' + parsed.label +
                         '" claims to be created ' + (p.created -
                     now) + ' seconds in the future, more than the ' + skew +
                         ' of clock skew allowed.');
    }
  }
  if (p.expires !== undefined && now >= p.expires) {
    log.debug("Leaving httpsigVerifyOne(). Expired.");
    return httpsigRefuse('STS-KEYS-0149',
                       'The signature "' + parsed.label + '" expired ' +
                       (now - p.expires) +
                       ' seconds ago (RFC 9421 section 2.3, expires).');
  }
  const required = opts.requireComponents || [];
  const covered = {};
  parsed.components.forEach((item) => {
    covered[httpsigIdentityOf(item)] = true;
  });
  for (let k = 0; k < required.length; k++) {
    const wanted = httpsigComponentItem(required[k]);
    if (httpsigIsRefusal(wanted)) {
      log.debug("Leaving httpsigVerifyOne(). Required component " +
                "malformed.");
      return wanted;
    }
    if (!covered[httpsigIdentityOf(wanted.item)]) {
      log.debug("Leaving httpsigVerifyOne(). Required component " +
                "missing.");
      return httpsigRefuse('STS-KEYS-0150',
                         'The signature "' + parsed.label +
                         '" does not cover the required component ' +
                         sf.serializeItem(wanted.item) + '; it covers (' +
                         parsed.componentIds.join(' ') +
                         ') (RFC 9421 section 3.2 step 4).');
    }
  }
  let keyed = null;
  try {
    keyed = typeof opts.keyFor === 'function' ? opts.keyFor(parsed) : null;
  } catch (e) {
    log.debug("Caught in httpsigVerifyOne(): " +
              ((e && e.message) || e));
    // A key lookup that throws is a key this verifier does not have; the
    // refusal below carries the reason rather than the process carrying the
    // exception.
    log.debug("keyFor() threw: " + e.message);
    keyed = null;
  }
  if (!keyed || keyed.key === undefined || keyed.key === null) {
    log.debug("Leaving httpsigVerifyOne(). No key.");
    return httpsigRefuse('STS-KEYS-0151',
                       'No verification key is known for the signature "' +
                       parsed.label + '"' +
                       (p.keyid !== undefined ? ' (keyid="' + p.keyid +
                        '")' : '') +
                       '; an unknown or untrusted key MUST fail (RFC 9421 ' +
                       'section 3.2 step 5).');
  }
  const fromKey = keyed.algorithm;
  const fromParam = p.alg;
  if (fromParam !== undefined) {
    const paramEntry = httpsigAlgorithmNamed(fromParam);
    if (!paramEntry || paramEntry.registry !== 'http') {
      log.debug("Leaving httpsigVerifyOne(). alg parameter unknown.");
      return httpsigRefuse('STS-KEYS-0134',
                         'The alg parameter "' + fromParam + '" is not an ' +
                         'algorithm in the HTTP Signature Algorithms ' +
                         'registry this verifier supports (RFC 9421 ' +
                         'sections 2.3 and 3.3.7).');
    }
    if (fromKey !== undefined && fromKey !== fromParam) {
      log.debug("Leaving httpsigVerifyOne(). alg conflict.");
      return httpsigRefuse('STS-KEYS-0135',
                         'The signature "' + parsed.label + '" says alg="' +
                         fromParam + '" and its key is for ' +
                         fromKey + '; when the algorithm is stated in more ' +
                         'than one place they MUST agree (RFC 9421 section ' +
                         '3.2 step 6.5).');
    }
  }
  const name = fromKey !== undefined ? fromKey : fromParam;
  if (name === undefined) {
    log.debug("Leaving httpsigVerifyOne(). No algorithm.");
    return httpsigRefuse('STS-KEYS-0133',
                       'No algorithm could be determined for the signature ' +
                       '"' + parsed.label +
                       '": the key names none and the signature carries no ' +
                       'alg parameter (RFC 9421 section 3.2 step 6).');
  }
  const entry = httpsigAlgorithmNamed(name);
  if (!entry) {
    log.debug("Leaving httpsigVerifyOne(). Unknown algorithm.");
    return httpsigRefuse('STS-KEYS-0134',
                       'The signature algorithm ' + JSON.stringify(name) +
                       ' is not supported.');
  }
  if (Array.isArray(opts.allowedAlgorithms) &&
      opts.allowedAlgorithms.indexOf(name) < 0) {
    log.debug("Leaving httpsigVerifyOne(). Not allowed.");
    return httpsigRefuse('STS-KEYS-0152',
                       'The algorithm ' + name +
                       ' is not one this verifier allows (' +
                       opts.allowedAlgorithms.join(', ') +
                       ') (RFC 9421 section 3.2 step 6.1).');
  }
  let verifyingKey;
  try {
    verifyingKey = httpsigKeyOf(entry, keyed.key, 'verify');
  } catch (e) {
    log.debug("Caught in httpsigVerifyOne(): " + ((e && e.message) || e));
    log.debug("Leaving httpsigVerifyOne(). The key cannot be read.");
    return httpsigRefuse('STS-KEYS-0131',
                         'The key for ' + name + ' cannot be read: ' +
                         e.message + '.');
  }
  const keyProblem = httpsigCheckKey(name, entry, verifyingKey, 'verify');
  if (keyProblem) {
    log.debug("Leaving httpsigVerifyOne(). Key.");
    return keyProblem;
  }
  const built = httpSignatureBase(message, parsed.components,
                                   parsed.paramList,
                                   opts);
  if (httpsigIsRefusal(built)) {
    log.debug("Leaving httpsigVerifyOne(). Base.");
    return built;
  }
  let good;
  try {
    good = httpsigRawVerify(entry, verifyingKey, Buffer.from(built.base, 'ascii'),
                          parsed.signature);
  } catch (e) {
    log.debug("Caught in httpsigVerifyOne(): " +
              ((e && e.message) || e));
    log.debug("Leaving httpsigVerifyOne(). Primitive threw.");
    return httpsigRefuse('STS-KEYS-0136',
                       'Verifying with ' + name + ' failed inside the ' +
                       'cryptographic library: ' + e.message);
  }
  if (!good) {
    log.debug("Leaving httpsigVerifyOne(). Bad signature.");
    return httpsigRefuse('STS-KEYS-0153',
                       'The signature "' + parsed.label +
                       '" does not verify with ' + name +
                       ' over the signature base rebuilt from the message: ' +
                       'the message was changed, or it was signed with a ' +
                       'different key (RFC 9421 section 3.2 step 8).');
  }
  log.debug("Leaving httpsigVerifyOne(). " + parsed.label +
            " verified.");
  return {
    ok: true,
    label: parsed.label,
    algorithm: name,
    keyid: p.keyid,
    components: parsed.componentIds,
    params: p,
    base: built.base
  };
}


// ===========================================================================
// SECTION 15 — DIGESTS, KEY DERIVATION AND KEY IMPORT, BY NAME (#178,
// 2026-10-05).
//
// rcbj's rule, restated on 2026-10-05: "All crypto operations across all
// protocols and use cases are to be centralized in a common module." It
// covers more than signatures. A digest, an HKDF, the import of a public key
// from a JWK and the export of one as SubjectPublicKeyInfo are cryptographic
// operations too, and a feature module that calls node's `crypto` for one of
// them is a second place that decides an algorithm. These are the small
// operations `gnap/` did on node directly until #178. #453 moves the rest of
// the service onto them, and onto the functions above.
//
// Each one names its algorithm from a closed list, so an unknown name is a
// thrown Error at the caller's own line rather than whatever node makes of it.
// ===========================================================================

// The digests a caller may ask for by name: SHA-2, SHA-3 and the two BLAKE2
// functions, by node's names. RFC 9635 section 4.2.3's interaction hash may
// name any of them through IANA's "Named Information Hash Algorithm"
// registry (`gnap/gnap_request.ts`'s HASH_METHODS). SHA-1 is not here:
// nothing new may choose it, and the callers that still meet it (a SPIRE
// fingerprint, a certificate thumbprint) have functions of their own that say
// why.
const DIGESTS = ['sha256', 'sha384', 'sha512', 'sha3-224', 'sha3-256',
                 'sha3-384', 'sha3-512', 'blake2s256', 'blake2b512'];
// HKDF (RFC 5869) is defined over an HMAC, so it takes the SHA-2 names only.
const HKDF_DIGESTS = ['sha256', 'sha384', 'sha512'];

// HOT PATH: a digest is computed per request in several places (a token's
// index, a GNAP key's identity), so no Entering/Leaving pair. It would drown
// the log.
/**
 * Returns the digest of a value under a named algorithm.
 *
 * @param algorithm - one of DIGESTS: SHA-2, SHA-3 or BLAKE2, by node's name
 * @param data - the bytes, or a string read as UTF-8
 * @param encoding - `hex`, `base64` or `base64url` for a string; a Buffer
 *   when absent
 * @returns {any} the digest: a string when an encoding is named, a Buffer
 *   when not
 * @throws Error for an algorithm outside the list
 */
function digest(algorithm, data, encoding) {
  if (DIGESTS.indexOf(algorithm) < 0) {
    // error-code: none — a programming error; every caller names a constant
    throw new Error('crypto: digest() computes ' + DIGESTS.join(', ') +
                    ', not "' + algorithm + '"');
  }
  const hash = nodeCrypto.createHash(algorithm)
    .update(typeof data === 'string' ? Buffer.from(data, 'utf8')
                                     : Buffer.from(data || []));
  return encoding ? hash.digest(encoding) : hash.digest();
}

// RFC 5869 HKDF in one call, for a caller deriving a purpose-bound key from a
// realm secret (GNAP's macaroon and biscuit root keys, `gnap_tokens.ts`). The
// extract and expand steps above are JWE's, kept apart because HPKE calls
// them separately.
/**
 * Derives key material with HKDF (RFC 5869).
 *
 * @param algorithm - `sha256`, `sha384` or `sha512`
 * @param ikm - the input keying material
 * @param salt - the salt; empty when absent
 * @param info - the context, bytes or a UTF-8 string
 * @param length - the octets wanted
 * @returns the output keying material
 * @throws Error for an algorithm outside the list
 */
function hkdf(algorithm, ikm, salt, info, length) {
  log.debug("Entering hkdf(). " + algorithm + " " + length);
  if (HKDF_DIGESTS.indexOf(algorithm) < 0) {
    log.debug("Leaving hkdf(). Unknown algorithm.");
    // error-code: none — a programming error; every caller names a constant
    throw new Error('crypto: hkdf() uses ' + HKDF_DIGESTS.join(', ') +
                    ', not "' + algorithm + '"');
  }
  const out = Buffer.from(nodeCrypto.hkdfSync(algorithm,
    Buffer.from(ikm || []), Buffer.from(salt || []),
    typeof info === 'string' ? Buffer.from(info, 'utf8')
                             : Buffer.from(info || []),
    length));
  log.debug("Leaving hkdf().");
  return out;
}

/**
 * Imports a public key from a JWK (RSA, EC or OKP).
 *
 * @param jwk - the JWK; private members are ignored
 * @returns the public KeyObject
 * @throws Error when node cannot read the JWK
 */
function publicKeyFromJwk(jwk) {
  log.debug("Entering publicKeyFromJwk(). " + (jwk && jwk.kty));
  const key = nodeCrypto.createPublicKey({ key: jwk, format: 'jwk' });
  log.debug("Leaving publicKeyFromJwk().");
  return key;
}

/**
 * Returns the public half of a private key (a KeyObject or a PEM), or the
 * public key itself.
 *
 * @param key - the key
 * @returns the public KeyObject
 */
function publicKeyOf(key) {
  log.debug("Entering publicKeyOf().");
  const out = key && key.type === 'public' ? key
                                           : nodeCrypto.createPublicKey(key);
  log.debug("Leaving publicKeyOf().");
  return out;
}

// The SubjectPublicKeyInfo of a key, for comparing two keys by value: the
// key a certificate holds against the key a JWK names (`gnap_proof.ts`).
/**
 * Returns a public key's SubjectPublicKeyInfo as DER.
 *
 * @param key - a public or private KeyObject, or a PEM
 * @returns the DER
 */
function spkiDerOf(key) {
  log.debug("Entering spkiDerOf().");
  const der = publicKeyOf(key).export({ type: 'spki', format: 'der' });
  log.debug("Leaving spkiDerOf().");
  return Buffer.from(der);
}

// ===========================================================================
// SECTION 17 — THE REST OF THE SERVICE'S OPERATIONS (#453, 2026-10-07).
//
// rcbj's rule of 2026-10-05 again: "All crypto operations across all
// protocols and use cases are to be centralized in a common module." Section
// 15 gave `gnap/` what it needed; #453 moved every other feature module off
// node's `crypto` — 130 files on the day — and these are the operations they
// still did directly: a certificate parsed, a private key imported, a key
// pair generated, an HMAC, a one-shot signature and its check, and the
// SHA-1 that a handful of specifications still name. `tests/
// crypto_centralised.js` fails on a `require('crypto')` anywhere else.
//
// Each takes its algorithm from a closed list, as section 15's do, so a
// feature module cannot choose one this file has not written down.
// ===========================================================================

// SHA-1 is in no list a caller may choose from (section 15's DIGESTS). Where
// a SPECIFICATION fixes it, the caller names which one, and the purpose is
// the argument for it. A new purpose is a new row here, and the row says
// which text requires it.
/** The purposes SHA-1 is computed for, each the text that fixes it. */
const SHA1_PURPOSES = Object.freeze({
  // SAML 2.0 Bindings 3.6.4 and SAML 1.1 Bindings 4.1.1.7: an artifact's
  // SourceID is the SHA-1 of the issuer's entity id (or its source URL).
  'saml-artifact-source-id': 'SAML 2.0 Bindings 3.6.4, SAML 1.1 4.1.1.7',
  // RFC 9562 section 5.5: a name-based UUID, version 5, is SHA-1.
  'uuid-v5': 'RFC 9562 section 5.5',
  // RFC 5280 section 4.2.1.2 method (1): a key identifier is the SHA-1 of
  // the subjectPublicKey BIT STRING.
  'key-identifier': 'RFC 5280 section 4.2.1.2',
  // RFC 6960 section 4.1.1: an OCSP CertID's issuerNameHash and
  // issuerKeyHash under the hash it names; SHA-1 is what every client sends.
  'ocsp-cert-id': 'RFC 6960 section 4.1.1',
  // A certificate's SHA-1 fingerprint, DRAWN for an operator comparing it
  // with what older tooling prints. Never compared by this service.
  'certificate-fingerprint': 'display only',
  // SPIRE's agent path for a node attestor, which hashes with SHA-1 so the
  // SPIFFE ID matches the one SPIRE itself mints for the same node.
  'spire-agent-path': 'SPIRE server node attestor agent paths'
});

// HOT PATH: a certificate fingerprint is drawn per row of a console list,
// so no Entering/Leaving pair. It would drown the log.
/**
 * Returns the SHA-1 of a value, for one of the purposes a specification
 * fixes it for.
 *
 * @param purpose - a key of SHA1_PURPOSES
 * @param data - the bytes, or a string read as UTF-8
 * @param encoding - `hex`, `base64` or `base64url`; a Buffer when absent
 * @returns {any} the digest
 * @throws Error for a purpose not in the list
 */
function sha1Digest(purpose, data, encoding) {
  if (!Object.prototype.hasOwnProperty.call(SHA1_PURPOSES, purpose)) {
    // error-code: none — a programming error; every caller names a constant
    throw new Error('crypto: sha1Digest() is for ' +
                    Object.keys(SHA1_PURPOSES).join(', ') +
                    ', not "' + purpose + '"');
  }
  const hash = nodeCrypto.createHash('sha1')
    .update(typeof data === 'string' ? Buffer.from(data, 'utf8')
                                     : Buffer.from(data || []));
  return encoding ? hash.digest(encoding) : hash.digest();
}

// An HMAC, by name, over the SHA-2 functions. (HOTP's HMAC-SHA-1 is
// `hotpCode()`'s, and RFC 4226 is its argument.)
const HMAC_DIGESTS = ['sha256', 'sha384', 'sha512'];

// HOT PATH: a CSRF token is MACed on every form drawn and posted, so no
// Entering/Leaving pair.
/**
 * Returns the HMAC of a value under a key.
 *
 * @param algorithm - `sha256`, `sha384` or `sha512`
 * @param key - the key: bytes, a string, or a secret KeyObject
 * @param data - the bytes, or a string read as UTF-8
 * @param encoding - `hex`, `base64` or `base64url`; a Buffer when absent
 * @returns {any} the MAC
 * @throws Error for an algorithm outside the list
 */
function hmac(algorithm, key, data, encoding) {
  if (HMAC_DIGESTS.indexOf(algorithm) < 0) {
    // error-code: none — a programming error; every caller names a constant
    throw new Error('crypto: hmac() uses ' + HMAC_DIGESTS.join(', ') +
                    ', not "' + algorithm + '"');
  }
  const mac = nodeCrypto.createHmac(algorithm, key)
    .update(typeof data === 'string' ? Buffer.from(data, 'utf8')
                                     : Buffer.from(data || []));
  return encoding ? mac.digest(encoding) : mac.digest();
}

// HOT PATH: a presented client certificate is parsed on every request over
// mutual TLS, and a console page parses one per row, so no Entering/Leaving
// pair. It throws exactly what node's constructor throws, because every
// caller already handles that.
/**
 * Parses a certificate.
 *
 * @param input - PEM text, DER bytes, or an already parsed certificate
 * @returns the X509Certificate
 * @throws Error when the input is not a certificate
 */
function parseCertificate(input) {
  if (input instanceof nodeCrypto.X509Certificate) {
    return input;
  }
  return new nodeCrypto.X509Certificate(input);
}

/**
 * Answers whether a value is a parsed certificate.
 *
 * @param value - anything
 * @returns true for an X509Certificate
 */
function isParsedCertificate(value) {
  return value instanceof nodeCrypto.X509Certificate;
}

/**
 * Imports a private key.
 *
 * @param input - anything node's `createPrivateKey()` takes: a PEM, a
 *   `{ key, format, type }` object, a private JWK as `{ key, format: 'jwk' }`,
 *   or a private KeyObject (returned as it is)
 * @returns the private KeyObject
 * @throws Error when the input is not a private key
 */
function privateKeyFrom(input) {
  log.debug("Entering privateKeyFrom().");
  const key = input && input.type === 'private' &&
              input instanceof nodeCrypto.KeyObject
    ? input
    : nodeCrypto.createPrivateKey(input);
  log.debug("Leaving privateKeyFrom().");
  return key;
}

/**
 * Answers whether a value is a key object (public, private or secret).
 *
 * @param value - anything
 * @returns true for a KeyObject
 */
function isKeyObject(value) {
  return value instanceof nodeCrypto.KeyObject;
}

// The kinds of key pair a caller may generate here. ML-DSA and ML-KEM are
// `pq_native.js`'s and `generateSigningJwkPair()`'s; DSA and plain DH are
// not on the list, and PKINIT's groups are section 16's.
const KEY_PAIR_TYPES = ['rsa', 'rsa-pss', 'ec', 'ed25519', 'ed448',
                        'x25519', 'x448'];

/**
 * Refuses a key pair type outside KEY_PAIR_TYPES.
 *
 * @param type - the type asked for
 * @throws Error for a type outside the list
 */
function checkKeyPairType(type) {
  if (KEY_PAIR_TYPES.indexOf(type) < 0) {
    // error-code: none — a programming error; every caller names a constant
    throw new Error('crypto: a key pair is one of ' +
                    KEY_PAIR_TYPES.join(', ') + ', not "' + type + '"');
  }
}

/**
 * Generates a key pair synchronously.
 *
 * @param type - one of KEY_PAIR_TYPES
 * @param options - node's options for that type (modulusLength,
 *   namedCurve, publicKeyEncoding, privateKeyEncoding, ...)
 * @returns {any} `{ publicKey, privateKey }`, KeyObjects or encoded as the
 *   options ask
 */
function generateKeyPairSync(type, options) {
  log.debug("Entering generateKeyPairSync(). " + type);
  checkKeyPairType(type);
  const pair = nodeCrypto.generateKeyPairSync(
    /** @type {any} */ (type), /** @type {any} */ (options || {}));
  log.debug("Leaving generateKeyPairSync().");
  return pair;
}

// libuv's thread pool rather than this thread: an RSA key of 3072 bits or
// more takes long enough to stall every request behind it.
/**
 * Generates a key pair on libuv's thread pool.
 *
 * @param type - one of KEY_PAIR_TYPES
 * @param options - as for `generateKeyPairSync()`
 * @returns {Promise<any>} a promise of `{ publicKey, privateKey }`
 */
function generateKeyPairAsync(type, options) {
  log.debug("Entering generateKeyPairAsync(). " + type);
  checkKeyPairType(type);
  log.debug("Leaving generateKeyPairAsync().");
  return new Promise(function (resolve, reject) {
    nodeCrypto.generateKeyPair(/** @type {any} */ (type),
      /** @type {any} */ (options || {}),
      function (err, publicKey, privateKey) {
        if (err) {
          log.debug("Caught in generateKeyPairAsync(): " +
                    ((err && err.message) || err));
          reject(err);
          return;
        }
        resolve({ publicKey: publicKey, privateKey: privateKey });
      });
  });
}

// The hashes a one-shot signature is made under (`null` for EdDSA and
// ML-DSA, whose algorithms fix their own), and the wider list one is
// CHECKED under: SHA-1 is verified where a peer's protocol still sends it
// (WebAuthn's RS1, a SCEP client's PKCS#7) and this service never signs
// with it.
const SIGN_HASHES = [null, 'sha256', 'sha384', 'sha512'];
const VERIFY_HASHES = [null, 'sha1', 'sha256', 'sha384', 'sha512'];

/**
 * Normalises and checks a one-shot signature's hash name.
 *
 * @param hash - the name, or null/undefined
 * @param allowed - the list it must be in
 * @returns the name, or null
 * @throws Error for a name outside the list
 */
function signatureHash(hash, allowed) {
  const name = hash === undefined || hash === null || hash === ''
    ? null
    : String(hash).toLowerCase().replace(/^sha-/, 'sha');
  if (allowed.indexOf(name) < 0) {
    // error-code: none — a programming error; every caller names a constant
    // or a hash it has already matched against a table of its own
    throw new Error('crypto: a signature hash is one of ' +
                    allowed.join(', ') + ', not "' + hash + '"');
  }
  return name;
}

// HOT PATH: signatures are made per token and per response, so no
// Entering/Leaving pair. It is node's `crypto.sign()` with the hash checked.
/**
 * Signs bytes with a private key (node's one-shot `sign()`).
 *
 * @param hash - `sha256`, `sha384`, `sha512`, or null for EdDSA and ML-DSA
 * @param data - the bytes
 * @param key - a private KeyObject, a PEM, or `{ key, dsaEncoding,
 *   padding, saltLength }`
 * @returns the signature
 * @throws Error for a hash outside the list, or what node throws
 */
function signBytes(hash, data, key) {
  return nodeCrypto.sign(signatureHash(hash, SIGN_HASHES),
    Buffer.from(data), key);
}

// HOT PATH, as signBytes(). It throws what node throws for an unusable key,
// which is what every caller was written against.
/**
 * Checks a signature over bytes (node's one-shot `verify()`).
 *
 * @param hash - as for signBytes(), and `sha1`
 * @param data - the bytes signed
 * @param key - a public KeyObject, a PEM, or `{ key, dsaEncoding,
 *   padding, saltLength }`
 * @param signature - the signature
 * @returns true when it verifies
 * @throws Error for a hash outside the list, or what node throws
 */
function signatureValid(hash, data, key, signature) {
  return nodeCrypto.verify(signatureHash(hash, VERIFY_HASHES),
    Buffer.from(data), key, Buffer.from(signature));
}

/**
 * Answers whether this build of node computes a named digest.
 *
 * @param name - node's name for it
 * @returns true when it does
 */
function digestSupported(name) {
  log.debug("Entering digestSupported(). " + name);
  const yes = nodeCrypto.getHashes().indexOf(String(name)) >= 0;
  log.debug("Leaving digestSupported().");
  return yes;
}

/** The OpenSSL option that refuses TLS renegotiation on a server socket. */
const TLS_NO_RENEGOTIATION = nodeCrypto.constants.SSL_OP_NO_RENEGOTIATION;

// ---------------------------------------------------------------------------
// #453 SWEEP GROUP REGIONS. Each group of the sweep added what it needed
// between its own two markers, so the groups merged without touching one
// another's lines.
// ---------------------------------------------------------------------------

// --- #453 group A (gnap token libraries): begin ---

// ===========================================================================
// GNAP'S THREE TOKEN LIBRARIES, HELD HERE AND NOWHERE ELSE (#453, rcbj's
// decision of 2026-10-05).
//
// The `macaroon`, `biscuit` and `zcap` GNAP token formats each sit on a
// library that does its format's cryptography: `macaroon` (the HMAC-SHA256
// caveat chain), `@biscuit-auth/biscuit-wasm` (Ed25519 block signatures,
// inside WebAssembly) and `jsonld-signatures` with the Digital Bazaar ZCAP
// and Ed25519 packages. Until #453 `gnap/token_*.ts` required them directly.
// Now THIS FILE is the only module that requires any of them, and what
// `gnap/` keeps is the format's grammar — the caveat grammar and the access
// model of a macaroon, the Datalog of a biscuit, the capability document of
// a zcap — handed in here as data or as a callback that builds data.
//
// **WHAT WRAPPING DOES NOT CHANGE: the macaroon and biscuit computations are
// still the libraries' own.** The macaroon library has no hook for supplying
// the HMAC, and the biscuit engine none for an external Ed25519 signer, so
// both still compute inside the library. What moved is where KEYS are
// handled (a root key is checked and a KeyObject turned into the library's
// key object here, so `gnap/` never holds the library's key types), where
// the algorithms and key sizes are decided (`MACAROON_MIN_ROOT_KEY_BYTES`,
// Ed25519 for a biscuit), and who may call the library at all. Reimplementing
// a format's cryptography here stays a later option (most worth it for the
// macaroon's small HMAC chain).
//
// **THE ZCAP COMPATIBILITY SUITE IS THE EXCEPTION, AND THE SIGNATURE IS
// MADE HERE.** `Ed25519Signature2020` takes a `signer` (`sign({ data })`)
// and a `verifier` (`verify({ data, signature })`) in place of a key pair —
// confirmed against the installed `@digitalbazaar/ed25519-signature-2020`
// 5.4.0, whose `sign()` calls `this.signer.sign({ data: verifyData })` and
// whose `verifySignature()` uses `this.verifier` when one is set. So the
// library only canonicalises (URDNA2015) and hashes, and the Ed25519
// signature over its bytes is `signRawSignature()` / `verifyRawSignature()`
// here: the private key never reaches the library. Ed25519 is
// deterministic, so a capability signed this way is BYTE-IDENTICAL to one
// the library signed with the key pair it used to be handed (probed on
// 2026-10-07: the same JSON, and the same answers for a good proof, an
// altered capability and a proof naming another key).
//
// The three JCS suites (`eddsa-jcs-2022` and the two post-quantum ones) were
// already made and checked by `oid4vc/vc_data_integrity.ts` through this
// file, wrapped by `gnap/token_zcap.ts` in a jsonld-signatures suite object.
// That stays: REUSING it is the alternative #453 asked to be checked, and it
// is the one that keeps those tokens byte-compatible, because it IS the
// implementation that made them. This file may not require it (a leaf), so
// `token_zcap.ts` builds that suite object and hands it in; jsonld-signatures
// hands a `-jcs-` proof to the suite untouched, so here it only runs the
// ZCAP purpose (chain, root, controller) around it.
//
// Every library is loaded LAZILY, once, by the first call that needs it —
// never when this file is required — so a process that never sees a GNAP
// token pays nothing. A failed load is forgotten so a later call may try
// again (a file briefly unreadable during a deploy should not disable a
// format for the life of the process).
// ===========================================================================

// ---------------------------------------------------------------------------
// MACAROONS (`macaroon` 3, libmacaroons v2).
// ---------------------------------------------------------------------------

/** The shortest macaroon root key accepted, in bytes. */
const MACAROON_MIN_ROOT_KEY_BYTES = 32;

/** @type {any} */
let macaroonLibrary = null;

// The npm `macaroon` package, required at the first use.
function macaroonLib() {
  log.debug("Entering macaroonLib().");
  if (!macaroonLibrary) {
    macaroonLibrary = require('macaroon');
  }
  log.debug("Leaving macaroonLib().");
  return macaroonLibrary;
}

/**
 * Answers whether a value is a usable macaroon root key: bytes, at least
 * `MACAROON_MIN_ROOT_KEY_BYTES` long.
 *
 * @param rootKey - the candidate
 * @returns true when it is usable
 */
function macaroonRootKeyUsable(rootKey) {
  log.debug("Entering macaroonRootKeyUsable().");
  const ok = rootKey instanceof Uint8Array &&
    rootKey.length >= MACAROON_MIN_ROOT_KEY_BYTES;
  log.debug("Leaving macaroonRootKeyUsable(). " + ok);
  return ok;
}

// A library macaroon as plain data — what the v2 serialiser in
// `gnap/token_macaroon.ts` reads — so the library's object never leaves
// this file. The getters already copy, so nothing here aliases its state.
function macaroonView(mac) {
  log.debug("Entering macaroonView().");
  const view = {
    location: mac.location,
    identifier: mac.identifier,
    caveats: mac.caveats,
    signature: mac.signature
  };
  log.debug("Leaving macaroonView().");
  return view;
}

/**
 * Mints a version 2 macaroon: an identifier and first-party caveats chained
 * under HMAC-SHA256 from a root key.
 *
 * @param rootKey - the root key, at least `MACAROON_MIN_ROOT_KEY_BYTES`
 * @param identifier - the macaroon's identifier
 * @param location - its location hint
 * @param caveats - the first-party caveats, in order
 * @returns `{ location, identifier, caveats, signature }`
 * @throws Error for an unusable root key, or what the library throws
 */
function macaroonMint(rootKey, identifier, location, caveats) {
  log.debug("Entering macaroonMint(). " + (caveats || []).length +
            " caveat(s).");
  if (!macaroonRootKeyUsable(rootKey)) {
    log.debug("Leaving macaroonMint(). Root key unusable.");
    // error-code: none — the caller checks macaroonRootKeyUsable() first
    // and refuses with its own code; this is the backstop
    throw new Error('a macaroon root key must be at least ' +
                    MACAROON_MIN_ROOT_KEY_BYTES + ' bytes');
  }
  const mac = macaroonLib().newMacaroon({
    identifier: identifier,
    location: location,
    rootKey: rootKey,
    version: 2
  });
  (caveats || []).forEach(function (c) {
    mac.addFirstPartyCaveat(c);
  });
  const view = macaroonView(mac);
  log.debug("Leaving macaroonMint().");
  return view;
}

/**
 * Reads a libmacaroons v2 binary macaroon WITHOUT verifying it.
 *
 * @param bytes - the serialised macaroon
 * @returns `{ location, identifier, caveats, signature }`
 * @throws Error when the bytes are not a v2 macaroon (the library's text)
 */
function macaroonImport(bytes) {
  log.debug("Entering macaroonImport().");
  const view = macaroonView(
      macaroonLib().importMacaroon(new Uint8Array(bytes)));
  log.debug("Leaving macaroonImport().");
  return view;
}

/**
 * Verifies a macaroon's HMAC chain under its root key. Every first-party
 * caveat is accepted while the chain is walked: what a caveat MEANS is the
 * caller's grammar, read once the chain is known to be good.
 *
 * @param bytes - the serialised macaroon
 * @param rootKey - the root key
 * @returns true when the chain verifies
 */
function macaroonVerify(bytes, rootKey) {
  log.debug("Entering macaroonVerify().");
  if (!macaroonRootKeyUsable(rootKey)) {
    log.debug("Leaving macaroonVerify(). Root key unusable.");
    return false;
  }
  try {
    macaroonLib().importMacaroon(new Uint8Array(bytes))
      .verify(rootKey, function () {
        return null;
      }, []);
  } catch (e) {
    log.debug("Caught in macaroonVerify(): " + ((e && e.message) || e));
    log.debug("Leaving macaroonVerify(). The chain does not verify.");
    return false;
  }
  log.debug("Leaving macaroonVerify(). Verified.");
  return true;
}

/**
 * Appends first-party caveats to a macaroon: the attenuation anybody holding
 * one can make, keyed by its current signature and needing no root key.
 *
 * @param bytes - the serialised macaroon
 * @param caveats - the caveats to append, in order
 * @returns `{ location, identifier, caveats, signature }` of the result
 * @throws Error when the bytes are not a v2 macaroon, or what the library
 *   throws
 */
function macaroonAttenuate(bytes, caveats) {
  log.debug("Entering macaroonAttenuate(). " + (caveats || []).length +
            " caveat(s).");
  const mac = macaroonLib().importMacaroon(new Uint8Array(bytes)).clone();
  (caveats || []).forEach(function (c) {
    mac.addFirstPartyCaveat(c);
  });
  const view = macaroonView(mac);
  log.debug("Leaving macaroonAttenuate().");
  return view;
}

// ---------------------------------------------------------------------------
// ZCAP-LD DELEGATIONS (`@digitalbazaar/zcap`, `jsonld-signatures`, and the
// Ed25519 2020 suite and key class). The ZCAP and Ed25519 packages are ES
// modules, loaded by dynamic import; `import()` stays a real dynamic import
// in this CommonJS file.
// ---------------------------------------------------------------------------

/** The compatibility proof suite, signed and verified here. */
const ZCAP_LEGACY_SUITE = 'Ed25519Signature2020';
const ZCAP_SUITE_CONTEXT_URL =
  'https://w3id.org/security/suites/ed25519-2020/v1';
const ZCAP_SECURITY_V2_URL = 'https://w3id.org/security/v2';

/** @type {Promise<any> | null} */
let zcapLoading = null;

// The libraries, once. A failure clears the promise so a later call may try
// again.
function zcapLibraries() {
  log.debug("Entering zcapLibraries().");
  if (!zcapLoading) {
    zcapLoading = Promise.all([
      import('@digitalbazaar/zcap'),
      import('@digitalbazaar/ed25519-signature-2020'),
      import('@digitalbazaar/ed25519-verification-key-2020')
    ]).then(function (/** @type {any[]} */ mods) {
      const security = require('@digitalbazaar/security-context');
      return {
        jsigs: require('jsonld-signatures'),
        zcap: mods[0],
        Ed25519Signature2020: mods[1].Ed25519Signature2020,
        suiteContext: mods[1].suiteContext,
        Ed25519VerificationKey2020: mods[2].Ed25519VerificationKey2020,
        securityContexts: security.contexts
      };
    }).catch(function (e) {
      log.debug("Caught in zcapLibraries(): " + ((e && e.message) || e));
      zcapLoading = null;
      throw e;
    });
  }
  log.debug("Leaving zcapLibraries().");
  return zcapLoading;
}

/**
 * Loads the ZCAP libraries, once, so a caller can refuse a load failure in
 * its own words before it does anything else.
 *
 * @returns a promise that rejects with the load's error
 */
async function zcapReady() {
  log.debug("Entering zcapReady().");
  await zcapLibraries();
  log.debug("Leaving zcapReady().");
}

// An Ed25519VerificationKey2020 for a public KeyObject — the library's key
// class, built from the key's JWK `x` and never leaving this file.
async function zcapPublicPair(lib, keyId, controller, publicKey) {
  log.debug("Entering zcapPublicPair().");
  const jwk = publicKey.export({ format: 'jwk' });
  const pair = await lib.Ed25519VerificationKey2020.fromJsonWebKey({
    id: keyId, controller: controller, type: 'JsonWebKey',
    publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }
  });
  log.debug("Leaving zcapPublicPair().");
  return pair;
}

/**
 * The Ed25519VerificationKey2020 verification method a compatibility-suite
 * controller document lists for a key.
 *
 * @param keyId - the method's id, `<controller>#<fragment>`
 * @param controller - the controller document's URL
 * @param publicKey - an Ed25519 public KeyObject
 * @returns the method, without a `@context`
 */
async function zcapVerificationMethod(keyId, controller, publicKey) {
  log.debug("Entering zcapVerificationMethod().");
  const lib = await zcapLibraries();
  const pair = await zcapPublicPair(lib, keyId, controller, publicKey);
  const method = pair.export({ publicKey: true, includeContext: false });
  log.debug("Leaving zcapVerificationMethod().");
  return method;
}

// THE SIGNER AND THE VERIFIER THE COMPATIBILITY SUITE IS HANDED (see the
// header): the library canonicalises, this file signs and checks.
function zcapEd25519Signer(keyId, privateKey) {
  log.debug("Entering zcapEd25519Signer().");
  log.debug("Leaving zcapEd25519Signer().");
  return {
    id: keyId,
    algorithm: 'Ed25519',
    sign: async function sign(/** @type {any} */ options) {
      log.debug("Entering sign().");
      const out = signRawSignature({ family: 'eddsa' }, privateKey,
                                   options.data);
      log.debug("Leaving sign().");
      return new Uint8Array(out);
    }
  };
}

function zcapEd25519Verifier(keyId, publicKey) {
  log.debug("Entering zcapEd25519Verifier().");
  log.debug("Leaving zcapEd25519Verifier().");
  return {
    id: keyId,
    algorithm: 'Ed25519',
    verify: async function verify(/** @type {any} */ options) {
      log.debug("Entering verify().");
      const ok = await verifyRawSignature({ family: 'eddsa' }, publicKey,
                                          options.data, options.signature);
      log.debug("Leaving verify(). " + ok);
      return ok;
    }
  };
}

// THE OFFLINE DOCUMENT LOADER. Nothing is fetched: it serves the ONE root
// capability `rootTarget` derives, the ZCAP context (the zcap package's own
// loader) and — for the compatibility suite only — that suite's context,
// security v2 (jsonld-signatures FRAMES a non-DID controller document with
// it), the controller document and the one verification method. Any other
// URL throws, so a proof naming another key or a chain to another root is a
// load failure and so a verification failure. A JCS suite needs none of the
// compatibility documents: its signature is not over JSON-LD and its
// controller document is handed to the purpose.
function zcapLoader(lib, rootController, rootTarget, legacy) {
  log.debug("Entering zcapLoader().");
  const root = lib.zcap.createRootCapability({
    controller: rootController, invocationTarget: rootTarget });
  function answer(documentUrl, document) {
    log.debug("Entering answer().");
    log.debug("Leaving answer().");
    return { contextUrl: null, documentUrl: documentUrl, document: document,
             tag: 'static' };
  }
  log.debug("Leaving zcapLoader().");
  return lib.zcap.extendDocumentLoader(async function offlineLoader(
      /** @type {string} */ documentUrl) {
    log.debug("Entering offlineLoader().");
    if (legacy) {
      if (documentUrl === ZCAP_SUITE_CONTEXT_URL) {
        log.debug("Leaving offlineLoader().");
        return answer(documentUrl,
                      lib.suiteContext.contexts.get(ZCAP_SUITE_CONTEXT_URL));
      }
      if (documentUrl === ZCAP_SECURITY_V2_URL) {
        log.debug("Leaving offlineLoader().");
        return answer(documentUrl,
                      lib.securityContexts.get(ZCAP_SECURITY_V2_URL));
      }
      if (documentUrl === legacy.controller) {
        log.debug("Leaving offlineLoader().");
        return answer(documentUrl, legacy.controllerDocument);
      }
      if (documentUrl === legacy.keyId) {
        log.debug("Leaving offlineLoader().");
        return answer(documentUrl,
                      legacy.pair.export({ publicKey: true,
                                           includeContext: true }));
      }
    }
    if (documentUrl === root.id) {
      log.debug("Leaving offlineLoader().");
      return answer(documentUrl, root);
    }
    log.debug("Leaving offlineLoader().");
    throw new Error('the offline ZCAP document loader serves no document ' +
                    'at ' + documentUrl);
  });
}

/**
 * Signs a capability as ONE ZCAP delegation from the root capability its
 * `invocationTarget` derives, which `controller` controls.
 *
 * `options`: `cryptosuite`; `controller` and `keyId`; and either, for
 * `Ed25519Signature2020`, `privateKey` (an Ed25519 KeyObject), `date` and
 * `controllerDocument` (served by the offline loader), or, for a JCS suite,
 * `suite` — the caller's jsonld-signatures suite object, which makes the
 * proof through `oid4vc/vc_data_integrity.ts`.
 *
 * @param capability - the unsigned capability
 * @param options - as above
 * @returns a promise of the signed capability
 * @throws Error (rejects) with the libraries' reason when they refuse
 */
async function zcapDelegate(capability, options) {
  const o = options || {};
  log.debug("Entering zcapDelegate(). " + o.cryptosuite);
  const lib = await zcapLibraries();
  let suite;
  let legacy = null;
  if (o.cryptosuite === ZCAP_LEGACY_SUITE) {
    legacy = {
      controller: o.controller, keyId: o.keyId,
      controllerDocument: o.controllerDocument,
      pair: await zcapPublicPair(lib, o.keyId, o.controller,
                                 nodeCrypto.createPublicKey(o.privateKey))
    };
    suite = new lib.Ed25519Signature2020({
      signer: zcapEd25519Signer(o.keyId, o.privateKey), date: o.date });
  } else {
    suite = o.suite;
  }
  const signed = await lib.jsigs.sign(capability, {
    suite: suite,
    purpose: new lib.zcap.CapabilityDelegation(
        { parentCapability: capability.parentCapability }),
    documentLoader: zcapLoader(lib, o.controller,
                               capability.invocationTarget, legacy)
  });
  log.debug("Leaving zcapDelegate().");
  return signed;
}

/**
 * Verifies a capability's delegation proof: one link from the root
 * capability `rootTarget` derives, controlled by `controller`.
 *
 * `options`: `cryptosuite`; `controller`, `keyId`, `controllerDocument`;
 * `rootTarget`, `expectedRootCapability`, `date`; and `publicKey` (an
 * Ed25519 KeyObject) for `Ed25519Signature2020`, or `suite` for a JCS suite.
 * The compatibility suite's controller document is LOADED (from the offline
 * loader); a JCS suite's is handed to the purpose.
 *
 * @param doc - the capability
 * @param options - as above
 * @returns a promise of jsonld-signatures' `{ verified, error }`; a throw
 *   is answered as `{ verified: false, error }`
 */
async function zcapVerifyDelegation(doc, options) {
  const o = options || {};
  log.debug("Entering zcapVerifyDelegation(). " + o.cryptosuite);
  let result;
  try {
    const lib = await zcapLibraries();
    let verifyOptions;
    if (o.cryptosuite === ZCAP_LEGACY_SUITE) {
      const legacy = {
        controller: o.controller, keyId: o.keyId,
        controllerDocument: o.controllerDocument,
        pair: await zcapPublicPair(lib, o.keyId, o.controller, o.publicKey)
      };
      verifyOptions = {
        suite: new lib.Ed25519Signature2020({
          verifier: zcapEd25519Verifier(o.keyId, o.publicKey) }),
        purpose: new lib.zcap.CapabilityDelegation({
          expectedRootCapability: o.expectedRootCapability,
          allowTargetAttenuation: true,
          date: o.date
        }),
        documentLoader: zcapLoader(lib, o.controller, o.rootTarget, legacy)
      };
    } else {
      verifyOptions = {
        suite: o.suite,
        purpose: new lib.zcap.CapabilityDelegation({
          expectedRootCapability: o.expectedRootCapability,
          allowTargetAttenuation: true,
          date: o.date,
          controller: o.controllerDocument
        }),
        documentLoader: zcapLoader(lib, o.controller, o.rootTarget, null)
      };
    }
    result = await lib.jsigs.verify(doc, verifyOptions);
  } catch (e) {
    log.debug("Caught in zcapVerifyDelegation(): " + ((e && e.message) || e));
    // jsigs reports through `result`; a throw is malformed input it could
    // not even start on, which is the same answer for the caller.
    result = { verified: false, error: e };
  }
  log.debug("Leaving zcapVerifyDelegation(). " +
            !!(result && result.verified));
  return result;
}

// ---------------------------------------------------------------------------
// BISCUITS (`@biscuit-auth/biscuit-wasm`, Biscuit v3).
//
// THE LOADER, AND WHY IT IS NOT `require()`. The package is built with
// wasm-pack's `bundler` target: its entry point is `import * as wasm from
// "./biscuit_bg.wasm"`, which only a bundler resolves, and its exports map
// has an `import` condition and nothing else, so `require()` and `import()`
// of the package both fail in node. `biscuitInstantiate()` does what a
// bundler would: compile `module/biscuit_bg.wasm`, build the import object
// by importing every module `WebAssembly.Module.imports()` names (relative
// to `module/`), instantiate, hand the instance to the glue with
// `__wbg_set_wasm()` and call `__wbindgen_start()`. The package directory is
// found by walking this file's own `module.paths`, as `require` would,
// because the exports map hides `package.json` from `require.resolve`; from
// `common/` that reaches the package root's `node_modules`.
//
// WHY THE WHOLE LOADER MOVED HERE rather than only the key handling: the
// handle the loader produces IS the library — the key classes, the token
// parser and the builders are all members of it — so a loader left in
// `gnap/` would be a second holder of the library and a second place keys
// could be turned into its key objects. What stays in `gnap/token_biscuit.ts`
// is everything that is not the library: the Datalog it writes and the
// queries it reads the model back with, handed in as source, parameters and
// rule text. The library's objects (tokens, authorizers, builders) are made,
// used and FREED here, inside one call each.
//
// `__wbindgen_start()` prints "biscuit-wasm loading" through `console.log`.
// It is synchronous, so `console.log` is replaced for exactly that call and
// put back in a `finally`; the line goes to the debug log instead of stdout.
//
// **Load the module once per process**: a second instance in the same
// process is not supported, which is one more reason there is one holder.
// ---------------------------------------------------------------------------

const BISCUIT_PACKAGE = '@biscuit-auth/biscuit-wasm';

// The run limits of the priming evaluation below — `gnap/token_biscuit.ts`'s
// LIMITS, the bound on every real evaluation, which it passes on each call.
// The prime's answer is discarded, so these only bound its cost.
const BISCUIT_PRIME_LIMITS = { max_facts: 10000, max_iterations: 100,
                               max_time_micro: 250000 };

/** @type {Promise<any> | null} */
let biscuitLoading = null;

// Where the package is installed, walking the directories `require` would.
function biscuitPackageDir() {
  log.debug("Entering biscuitPackageDir().");
  const fs = require('fs');
  const path = require('path');
  // `module` is typed as this file's exports by the checker; its `paths`
  // are node's, the node_modules directories `require` walks from here.
  const dirs = /** @type {any} */ (module).paths || [];
  for (let i = 0; i < dirs.length; i++) {
    const candidate = path.join(dirs[i], BISCUIT_PACKAGE);
    if (fs.existsSync(path.join(candidate, 'package.json'))) {
      log.debug("Leaving biscuitPackageDir().");
      return candidate;
    }
  }
  log.debug("Leaving biscuitPackageDir(). Not installed.");
  return null;
}

// THE FIRST RULE-APPLYING EVALUATION AFTER LOAD, ABSORBED HERE (#432,
// 2026-10-03). The library's first evaluation that applies a rule can be
// refused on its run limits whatever the budget; later ones measure
// correctly. So the load runs ONE throwaway evaluation that applies a rule,
// before any token is judged, and discards its answer. The limits are not
// raised: no budget changes the first answer, and every later evaluation is
// bounded as before, so the bound on a hostile block stands.
function biscuitPrime(bg) {
  log.debug("Entering biscuitPrime().");
  /** @type {any} */
  let authorizer = null;
  try {
    const builder = new bg.AuthorizerBuilder();
    builder.addCode('prime(1); primed($x) <- prime($x); allow if true;');
    authorizer = builder.buildUnauthenticated();
    authorizer.authorizeWithLimits(BISCUIT_PRIME_LIMITS);
    log.debug("Leaving biscuitPrime(). It did not time out this time.");
  } catch (e) {
    // Expected: the first evaluation may be refused (see above). Anything
    // else is logged and left — the evaluations that matter report their
    // own refusals.
    log.debug("Caught in biscuitPrime(): " + biscuitErrorText(e));
    log.debug("Leaving biscuitPrime(). Primed.");
  } finally {
    if (authorizer) {
      authorizer.free();
    }
  }
}

// The library's errors are plain objects; a string for the debug log.
function biscuitErrorText(e) {
  log.debug("Entering biscuitErrorText().");
  if (e instanceof Error) {
    log.debug("Leaving biscuitErrorText().");
    return e.message;
  }
  try {
    log.debug("Leaving biscuitErrorText().");
    return JSON.stringify(e);
  } catch (err) {
    log.debug("Caught in biscuitErrorText(): " +
              ((err && err.message) || err));
    log.debug("Leaving biscuitErrorText().");
    // A cyclic or exotic value: String() is the best available description.
    return String(e);
  }
}

async function biscuitInstantiate() {
  log.debug("Entering biscuitInstantiate().");
  const fs = require('fs');
  const path = require('path');
  const url = require('url');
  const dir = biscuitPackageDir();
  if (!dir) {
    log.debug("Leaving biscuitInstantiate(). Package not installed.");
    throw new Error(BISCUIT_PACKAGE + ' is not installed');
  }
  const moduleDir = path.join(dir, 'module');
  /** @type {any} */
  const wasmBytes = fs.readFileSync(path.join(moduleDir, 'biscuit_bg.wasm'));
  const compiled = await WebAssembly.compile(wasmBytes);
  /** @type {Record<string, any>} */
  const imports = {};
  const wanted = WebAssembly.Module.imports(compiled);
  for (let i = 0; i < wanted.length; i++) {
    const name = wanted[i].module;
    if (!imports[name]) {
      imports[name] = await import(url.pathToFileURL(
          path.join(moduleDir, name)).href);
    }
  }
  const bg = imports['./biscuit_bg.js'];
  if (!bg || typeof bg.__wbg_set_wasm !== 'function') {
    log.debug("Leaving biscuitInstantiate(). Glue module not found.");
    throw new Error('the biscuit glue module ./biscuit_bg.js was not ' +
                    'among the WASM imports');
  }
  const instance = await WebAssembly.instantiate(compiled, imports);
  /** @type {any} */
  const exported = instance.exports;
  bg.__wbg_set_wasm(exported);
  if (typeof exported.__wbindgen_start === 'function') {
    const original = console.log;
    console.log = function () {
      log.debug('biscuit-wasm: ' + Array.prototype.join.call(arguments, ' '));
    };
    try {
      exported.__wbindgen_start();
    } finally {
      console.log = original;
    }
  }
  biscuitPrime(bg);
  log.debug("Leaving biscuitInstantiate(). Loaded.");
  return bg;
}

// The one lazy load, shared by every call; a failure allows a new attempt.
function biscuitLibrary() {
  log.debug("Entering biscuitLibrary().");
  if (!biscuitLoading) {
    biscuitLoading = biscuitInstantiate().catch(function (e) {
      log.debug("Caught in biscuitLibrary(): " + ((e && e.message) || e));
      biscuitLoading = null;
      throw e;
    });
  }
  log.debug("Leaving biscuitLibrary().");
  return biscuitLoading;
}

/**
 * Loads the biscuit WebAssembly library, once, so a caller can refuse a
 * load failure in its own words before it does anything else.
 *
 * @returns a promise that rejects with the load's error
 */
async function biscuitReady() {
  log.debug("Entering biscuitReady().");
  await biscuitLibrary();
  log.debug("Leaving biscuitReady().");
}

// An Ed25519 KeyObject's raw `d` (private) or `x` (public), or null: the
// one key kind a biscuit root key is here.
function biscuitRawKey(keyObject, member) {
  log.debug("Entering biscuitRawKey().");
  if (!keyObject || typeof keyObject.export !== 'function' ||
      keyObject.asymmetricKeyType !== 'ed25519') {
    log.debug("Leaving biscuitRawKey().");
    return null;
  }
  const jwk = keyObject.export({ format: 'jwk' });
  log.debug("Leaving biscuitRawKey().");
  return jwk[member] ? Buffer.from(jwk[member], 'base64url') : null;
}

// The token, verified under the root public key; `{ ok:false, stage }` for
// a key that is not an Ed25519 public KeyObject ('key') or a token that does
// not parse or verify ('parse'). The caller frees `token`.
function biscuitParse(bg, value, publicKey) {
  log.debug("Entering biscuitParse().");
  const x = biscuitRawKey(publicKey, 'x');
  if (!x) {
    log.debug("Leaving biscuitParse(). Public key unusable.");
    return { ok: false, stage: 'key', error: null };
  }
  try {
    const root = bg.PublicKey.fromBytes(new Uint8Array(x),
                                        bg.SignatureAlgorithm.Ed25519);
    const token = bg.Biscuit.fromBase64(value, root);
    log.debug("Leaving biscuitParse(). Parsed.");
    return { ok: true, token: token };
  } catch (e) {
    log.debug("Caught in biscuitParse(): " + biscuitErrorText(e));
    log.debug("Leaving biscuitParse(). Refused.");
    return { ok: false, stage: 'parse', error: e };
  }
}

/**
 * Mints a biscuit whose authority block is the caller's Datalog, sealed
 * with an Ed25519 root key.
 *
 * `prepare()` builds the block (`{ source, params }`); it is called inside
 * the library step, so a throw from it is answered as the library's.
 *
 * @param privateKey - an Ed25519 private KeyObject
 * @param prepare - builds `{ source, params }`
 * @returns a promise of `{ ok: true, value, revocationIds }`, or
 *   `{ ok: false, stage, error }` — stage `key` (not an Ed25519 private
 *   KeyObject), `load` (the library could not be loaded) or `library`
 */
async function biscuitMint(privateKey, prepare) {
  log.debug("Entering biscuitMint().");
  const d = biscuitRawKey(privateKey, 'd');
  if (!d) {
    log.debug("Leaving biscuitMint(). Private key unusable.");
    return { ok: false, stage: 'key', error: null };
  }
  let bg;
  try {
    bg = await biscuitLibrary();
  } catch (e) {
    log.debug("Caught in biscuitMint(): " + ((e && e.message) || e));
    log.debug("Leaving biscuitMint(). Library unavailable.");
    return { ok: false, stage: 'load', error: e };
  }
  try {
    const root = bg.PrivateKey.fromBytes(new Uint8Array(d),
                                         bg.SignatureAlgorithm.Ed25519);
    const p = prepare();
    const builder = bg.Biscuit.builder();
    builder.addCodeWithParameters(p.source, p.params, {});
    const token = builder.build(root);
    const value = token.toBase64();
    // One revocation identifier per block, the authority block's first.
    const revocationIds = [].concat(token.getRevocationIdentifiers() || [])
      .map(function (/** @type {unknown} */ one) {
        return String(one);
      });
    token.free();
    log.debug("Leaving biscuitMint(). Minted.");
    return { ok: true, value: value, revocationIds: revocationIds };
  } catch (e) {
    log.debug("Caught in biscuitMint(): " + biscuitErrorText(e));
    log.debug("Leaving biscuitMint(). Library failure.");
    return { ok: false, stage: 'library', error: e };
  }
}

/**
 * Verifies a biscuit under its root public key and runs an authorizer over
 * it: the caller's Datalog facts and policies, then each query in order,
 * then the authorization itself, every evaluation bounded by `limits`.
 *
 * A query that throws stops the run (the queries after it and the
 * authorization are not run). The library's errors come back as they were
 * thrown, for the caller to read (`RunLimit`, `FailedLogic`).
 *
 * @param value - the token, URL-safe base64
 * @param publicKey - an Ed25519 public KeyObject
 * @param run - `{ authorizer, queries, limits }`: `authorizer()` builds
 *   `{ source, params }` (called inside the build step), `queries` the
 *   rule texts, `limits` the run limits
 * @returns a promise of `{ ok: false, stage, error }` — stage `key`,
 *   `load`, `parse` or `build` — or `{ ok: true, rows, queryError,
 *   authorizeError, blocks }`: `rows[i]` the terms of each fact query `i`
 *   produced; `authorizeError` undefined when authorization was not run,
 *   null when it passed
 */
async function biscuitAuthorize(value, publicKey, run) {
  log.debug("Entering biscuitAuthorize().");
  let bg;
  try {
    bg = await biscuitLibrary();
  } catch (e) {
    log.debug("Caught in biscuitAuthorize(): " + ((e && e.message) || e));
    log.debug("Leaving biscuitAuthorize(). Library unavailable.");
    return { ok: false, stage: 'load', error: e };
  }
  const parsed = biscuitParse(bg, value, publicKey);
  if (!parsed.ok) {
    log.debug("Leaving biscuitAuthorize(). " + parsed.stage);
    return parsed;
  }
  const token = parsed.token;
  /** @type {any} */
  let authorizer = null;
  try {
    try {
      const p = run.authorizer();
      const builder = new bg.AuthorizerBuilder();
      builder.addCodeWithParameters(p.source, p.params, {});
      authorizer = builder.buildAuthenticated(token);
    } catch (e) {
      log.debug("Caught in biscuitAuthorize(): " + biscuitErrorText(e));
      log.debug("Leaving biscuitAuthorize(). Authorizer not built.");
      return { ok: false, stage: 'build', error: e };
    }
    const rows = [];
    let queryError = null;
    const queries = run.queries || [];
    for (let i = 0; i < queries.length; i++) {
      try {
        rows.push(authorizer.queryWithLimits(bg.Rule.fromString(queries[i]),
                                             run.limits)
          .map(function (/** @type {any} */ f) {
            return f.terms();
          }));
      } catch (e) {
        log.debug("Caught in biscuitAuthorize(): " + biscuitErrorText(e));
        queryError = e;
        break;
      }
    }
    let authorizeError;
    if (!queryError) {
      try {
        authorizer.authorizeWithLimits(run.limits);
        authorizeError = null;
      } catch (e) {
        log.debug("Caught in biscuitAuthorize(): " + biscuitErrorText(e));
        authorizeError = e;
      }
    }
    const blocks = token.countBlocks();
    log.debug("Leaving biscuitAuthorize(). blocks=" + blocks);
    return { ok: true, rows: rows, queryError: queryError,
             authorizeError: authorizeError, blocks: blocks };
  } finally {
    if (authorizer) {
      authorizer.free();
    }
    token.free();
  }
}

/**
 * Appends a block to a biscuit — the attenuation a resource server makes
 * without the authorization server. The token is verified first: the
 * library will not open one it has not verified.
 *
 * `prepare()` is called once the token has parsed, and answers the block
 * (`{ source, params }`) or `{ refusal }`, which is passed back untouched.
 *
 * @param value - the token, URL-safe base64
 * @param publicKey - an Ed25519 public KeyObject
 * @param prepare - builds the block, or refuses
 * @returns a promise of `{ ok: true, value }`, or `{ ok: false, stage,
 *   error }` — stage `key`, `load`, `parse` or `library` — or
 *   `{ ok: false, stage: 'prepare', refusal }`
 */
async function biscuitAttenuate(value, publicKey, prepare) {
  log.debug("Entering biscuitAttenuate().");
  let bg;
  try {
    bg = await biscuitLibrary();
  } catch (e) {
    log.debug("Caught in biscuitAttenuate(): " + ((e && e.message) || e));
    log.debug("Leaving biscuitAttenuate(). Library unavailable.");
    return { ok: false, stage: 'load', error: e };
  }
  const parsed = biscuitParse(bg, value, publicKey);
  if (!parsed.ok) {
    log.debug("Leaving biscuitAttenuate(). " + parsed.stage);
    return parsed;
  }
  try {
    const block = prepare();
    if (block.refusal) {
      log.debug("Leaving biscuitAttenuate(). Refused by the caller.");
      return { ok: false, stage: 'prepare', refusal: block.refusal };
    }
    let out;
    try {
      const builder = bg.Biscuit.block_builder();
      builder.addCodeWithParameters(block.source, block.params, {});
      const next = parsed.token.appendBlock(builder);
      out = next.toBase64();
      next.free();
    } catch (e) {
      log.debug("Caught in biscuitAttenuate(): " + biscuitErrorText(e));
      log.debug("Leaving biscuitAttenuate(). Library refused.");
      return { ok: false, stage: 'library', error: e };
    }
    log.debug("Leaving biscuitAttenuate(). Appended.");
    return { ok: true, value: out };
  } finally {
    parsed.token.free();
  }
}

// --- #453 group A: end ---

// (separator between group regions)

// --- #453 group B (common, keys and certificates): begin ---

// --- #453 group B: end ---

// (separator between group regions)

// --- #453 group C (common, cluster, persistence, ldap, risk): begin ---

// --- #453 group C: end ---

// (separator between group regions)

// --- #453 group D (oauth-oidc, federation, saml, ssf, portal): begin ---

// --- #453 group D: end ---

// (separator between group regions)

// --- #453 group E (oid4vc, oidfed, authn, admin, pki): begin ---

// --- #453 group E: end ---

// (separator between group regions)

// --- #453 group F (spiffe, scep, est, acme, scim, kerberos, tls): begin ---

// --- #453 group F: end ---

// ===========================================================================
// SECTION 16 — PKINIT: CMS SIGNED DATA, DIFFIE-HELLMAN AND THE AS REPLY KEY
// (#179, 2026-10-05).
//
// RFC 4556 authenticates a Kerberos AS-REQ with a certificate: the client
// SIGNS an AuthPack in a CMS SignedData, the KDC verifies it, both sides run
// a Diffie-Hellman exchange, and the AS reply key is DERIVED from the agreed
// secret. Every one of those is a cryptographic operation, so every one of
// them is here, for rcbj's rule of 2026-10-05 ("all crypto operations across
// all protocols and use cases are to be centralized in a common module"):
// `kerberos/krb5_pkinit.ts` decides what to accept, and asks this section
// to read, verify, agree, derive and sign.
//
//   * CMS SignedData (RFC 5652), READ AND VERIFIED: the client's
//     signedAuthPack — one SignerInfo, the content-type and message-digest
//     signed attributes, a signature over the signed attributes AS THEY
//     ARRIVED (`scep/scep_cms.ts`'s fourth decision, for its reason). An
//     anonymous request (RFC 8062 section 4.1.1) carries a SignedData with
//     no SignerInfo and no certificate, which `pkinitReadSignedData()` reads
//     and the caller recognises.
//   * CMS SignedData, WRITTEN: the KDC's dhSignedData over a KDCDHKeyInfo,
//     signed with the realm's KDC key — RSA PKCS #1 v1.5 or ECDSA, SHA-256 —
//     with the certificate chain minus the Root (RFC 4556 section 3.2.3.1
//     item 6: "MUST NOT contain root CA certificates").
//   * THE DIGESTS ARE SHA-256, SHA-384 AND SHA-512. RFC 4556 predates
//     SHA-2's ubiquity and RFC 8636 section 4 is how a KDC says it refuses
//     the older ones: KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED with
//     TD-CMS-DIGEST-ALGORITHMS, the list from `PKINIT_CMS_DIGEST_OIDS`.
//     SHA-1 and MD5 are refused in both modes.
//   * MODP DIFFIE-HELLMAN over RFC 3526's groups 14 to 18, and RFC 5349's
//     ECDH over P-256, P-384 and P-521. GROUP 2 (1024 bits) IS REFUSED,
//     although RFC 4556 section 3.2.1 makes it a MUST: RFC 3766 puts it near
//     80 bits, and MIT's own client has refused it since 1.17 (its
//     `pkinit_dh_min_bits` defaults to 2048). The refusal is
//     KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED with TD-DH-PARAMETERS listing
//     what is taken, which is how a client learns to retry.
//   * NO RSA KEY TRANSPORT (RFC 4556 section 3.2.3.2), which #179 excludes:
//     the reply key encrypted to the client's RSA key has no forward secrecy,
//     and the Marvin attack is about exactly that decryption. A request
//     without a clientPublicValue is the caller's refusal,
//     KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED.
//   * THE REPLY KEY: RFC 4556 section 3.2.3.1's `octetstring2key()` (SHA-1
//     in counter mode), and RFC 8636 section 6's KDFs — SP 800-56A's one-step
//     KDF over SHA-1, SHA-256, SHA-384 or SHA-512 with an ASN.1 OtherInfo
//     that binds the AS-REQ and the PA-PK-AS-REP into the key. The OtherInfo
//     is a Kerberos structure and `kerberos/krb5_pkinit_codec.ts` encodes it;
//     what is here is the hashing. Both are held to RFC 8636 section 8's
//     vectors by `tests/kerberos_pkinit.js`.
//
// **POST-QUANTUM.** No post-quantum PKINIT is standardised. The two places
// one would go are named here so the next reader does not have to find them:
// the KEY AGREEMENT (`pkinitKeyAgreement()`) is the quantum-exposed part — a
// recorded exchange is broken by whoever can later solve the discrete log —
// and an ML-KEM encapsulation to a key in the clientPublicValue would replace
// it, with the reply key derived from the shared secret through the same RFC
// 8636 KDF; and the SIGNATURES (`pkinitVerifySignedData()`,
// `pkinitSignedData()`) would take ML-DSA through CMS (RFC 9882) where the
// table `PKINIT_CMS_SIGNATURES` lists the classical ones. Neither is offered
// until a client exists to send it.
//
// It stays a LEAF: node's `crypto` and `asn1js`, nothing of this service.
// ===========================================================================

// The OIDs PKINIT's CMS uses.
/** The object identifiers PKINIT's CMS and key agreement use. */
const PKINIT_OID = {
  signedData: '1.2.840.113549.1.7.2',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  authData: '1.3.6.1.5.2.3.1',
  dhKeyData: '1.3.6.1.5.2.3.2',
  dhPublicNumber: '1.2.840.10046.2.1',
  ecPublicKey: '1.2.840.10045.2.1'
};

// The digests a CMS signature here may be made over, by OID, in the order
// the KDC prefers them — the order TD-CMS-DIGEST-ALGORITHMS lists.
/**
 * The CMS digest algorithms PKINIT accepts, by OID, in preference order.
 */
const PKINIT_CMS_DIGEST_OIDS = {
  '2.16.840.1.101.3.4.2.1': { id: 'sha256', label: 'SHA-256' },
  '2.16.840.1.101.3.4.2.2': { id: 'sha384', label: 'SHA-384' },
  '2.16.840.1.101.3.4.2.3': { id: 'sha512', label: 'SHA-512' }
};
// The ones a client may send and is told no about, by name.
const PKINIT_REFUSED_DIGESTS = {
  '1.3.14.3.2.26': 'SHA-1',
  '1.2.840.113549.2.5': 'MD5'
};

// A SignerInfo's signatureAlgorithm: the key it needs and, where the OID
// names one, the digest it must agree with. `rsaEncryption` names none and
// takes the SignerInfo's digestAlgorithm, which is what OpenSSL — and so
// MIT's client — writes. RSASSA-PSS and EdDSA are not in PKINIT's use and
// are refused as unknown.
/**
 * The CMS signature algorithms PKINIT verifies, by OID, with the key type
 * each needs and the digest an OID names.
 */
const PKINIT_CMS_SIGNATURES = {
  '1.2.840.113549.1.1.1': { key: 'rsa', digest: null,
                            label: 'RSA PKCS #1 v1.5' },
  '1.2.840.113549.1.1.11': { key: 'rsa', digest: 'sha256',
                             label: 'sha256WithRSAEncryption' },
  '1.2.840.113549.1.1.12': { key: 'rsa', digest: 'sha384',
                             label: 'sha384WithRSAEncryption' },
  '1.2.840.113549.1.1.13': { key: 'rsa', digest: 'sha512',
                             label: 'sha512WithRSAEncryption' },
  '1.2.840.10045.4.3.2': { key: 'ec', digest: 'sha256',
                           label: 'ecdsa-with-SHA256' },
  '1.2.840.10045.4.3.3': { key: 'ec', digest: 'sha384',
                           label: 'ecdsa-with-SHA384' },
  '1.2.840.10045.4.3.4': { key: 'ec', digest: 'sha512',
                           label: 'ecdsa-with-SHA512' }
};

// The key-agreement groups, in the order the KDC prefers them — the order
// TD-DH-PARAMETERS lists. The curves first: P-256 is faster than any MODP
// group and stronger than group 14. `node` is node's name for each.
/**
 * The Diffie-Hellman groups PKINIT agrees over, in preference order:
 * RFC 5349's curves, then RFC 3526's MODP groups 14 to 18.
 */
const PKINIT_DH_GROUPS = [
  { id: 'P-256', kind: 'ec', oid: '1.2.840.10045.3.1.7', node: 'prime256v1',
    bits: 256, label: 'ECDH on P-256 (RFC 5349)' },
  { id: 'P-384', kind: 'ec', oid: '1.3.132.0.34', node: 'secp384r1',
    bits: 384, label: 'ECDH on P-384 (RFC 5349)' },
  { id: 'P-521', kind: 'ec', oid: '1.3.132.0.35', node: 'secp521r1',
    bits: 521, label: 'ECDH on P-521 (RFC 5349)' },
  { id: 'modp14', kind: 'modp', node: 'modp14', bits: 2048,
    label: 'RFC 3526 group 14 (2048-bit MODP)' },
  { id: 'modp15', kind: 'modp', node: 'modp15', bits: 3072,
    label: 'RFC 3526 group 15 (3072-bit MODP)' },
  { id: 'modp16', kind: 'modp', node: 'modp16', bits: 4096,
    label: 'RFC 3526 group 16 (4096-bit MODP)' },
  { id: 'modp17', kind: 'modp', node: 'modp17', bits: 6144,
    label: 'RFC 3526 group 17 (6144-bit MODP)' },
  { id: 'modp18', kind: 'modp', node: 'modp18', bits: 8192,
    label: 'RFC 3526 group 18 (8192-bit MODP)' }
];

// RFC 8636 section 6's KDFs, strongest first — the order the KDC picks from
// the client's unordered set.
/**
 * RFC 8636's key derivation functions, strongest first.
 */
const PKINIT_KDFS = [
  { oid: '1.3.6.1.5.2.3.6.3', hash: 'sha512',
    label: 'id-pkinit-kdf-ah-sha512' },
  { oid: '1.3.6.1.5.2.3.6.4', hash: 'sha384',
    label: 'id-pkinit-kdf-ah-sha384' },
  { oid: '1.3.6.1.5.2.3.6.2', hash: 'sha256',
    label: 'id-pkinit-kdf-ah-sha256' },
  { oid: '1.3.6.1.5.2.3.6.1', hash: 'sha1', label: 'id-pkinit-kdf-ah-sha1' }
];

// ---------------------------------------------------------------------------
// A HANDFUL OF DER WRITERS. The structures written here are small and fixed,
// and writing the bytes is plainer than building asn1js objects to write
// them: a definite-length TLV, an INTEGER from unsigned bytes, a SET OF
// sorted as DER requires.
// ---------------------------------------------------------------------------
function pkinitDerLength(n) {
  log.debug("Entering pkinitDerLength().");
  if (n < 0x80) {
    log.debug("Leaving pkinitDerLength().");
    return Buffer.from([n]);
  }
  const bytes = [];
  let rest = n;
  while (rest > 0) {
    bytes.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  }
  log.debug("Leaving pkinitDerLength().");
  return Buffer.from([0x80 | bytes.length].concat(bytes));
}

function pkinitTlv(tag, content) {
  log.debug("Entering pkinitTlv().");
  const body = Buffer.concat((Array.isArray(content) ? content : [content])
    .map(function (one) { return Buffer.from(one); }));
  log.debug("Leaving pkinitTlv().");
  return Buffer.concat([Buffer.from([tag]), pkinitDerLength(body.length),
                        body]);
}

function pkinitOidDer(dotted) {
  log.debug("Entering pkinitOidDer(). " + dotted);
  const arcs = String(dotted).split('.').map(function (one) {
    return BigInt(one);
  });
  const out = [];
  const writeArc = function (arc) {
    const septets = [Number(arc & 0x7fn)];
    let rest = arc >> 7n;
    while (rest > 0n) {
      septets.unshift(Number(rest & 0x7fn) | 0x80);
      rest >>= 7n;
    }
    out.push.apply(out, septets);
  };
  writeArc(arcs[0] * 40n + arcs[1]);
  arcs.slice(2).forEach(writeArc);
  log.debug("Leaving pkinitOidDer().");
  return pkinitTlv(0x06, Buffer.from(out));
}

// An unsigned big-endian value as a DER INTEGER: leading zeros dropped, one
// put back where the top bit would read as a sign.
function pkinitUnsignedIntegerDer(bytes) {
  log.debug("Entering pkinitUnsignedIntegerDer().");
  let value = Buffer.from(bytes || []);
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) {
    start++;
  }
  value = value.subarray(start);
  if (!value.length) {
    value = Buffer.from([0]);
  }
  if (value[0] & 0x80) {
    value = Buffer.concat([Buffer.from([0]), value]);
  }
  log.debug("Leaving pkinitUnsignedIntegerDer().");
  return pkinitTlv(0x02, value);
}

// DER's SET OF: the elements sorted by their encodings (X.690 11.6).
function pkinitSetOf(elements) {
  log.debug("Entering pkinitSetOf().");
  const sorted = elements.map(function (one) {
    return Buffer.from(one);
  }).sort(Buffer.compare);
  log.debug("Leaving pkinitSetOf().");
  return pkinitTlv(0x31, sorted);
}

// ---------------------------------------------------------------------------
// READING, WITH asn1js. One value and nothing after it, as `scep_cms.ts`
// reads: bytes nobody signed riding behind a signed structure are bytes two
// readers disagree about.
// ---------------------------------------------------------------------------
function pkinitReadOne(bytes, what) {
  log.debug("Entering pkinitReadOne(). " + what);
  const buf = Buffer.from(bytes || []);
  let parsed = null;
  try {
    parsed = buf.length ? asn1js.fromBER(new Uint8Array(buf).buffer) : null;
  } catch (e) {
    log.debug("Caught in pkinitReadOne(): " + ((e && e.message) || e));
    parsed = null;
  }
  if (!parsed || parsed.offset === -1 || parsed.offset !== buf.length ||
      parsed.result.error) {
    log.debug("Leaving pkinitReadOne(). Not one value.");
    // error-code: none — a reader; the caller refuses what does not decode
    throw new Error('pkinit: ' + what + ' is not one BER value');
  }
  log.debug("Leaving pkinitReadOne().");
  return parsed.result;
}

// HOT PATH helpers for the tree walk below: called per node of every
// SignedData, so no Entering/Leaving pair. It would drown the log.
function pkinitKids(node) {
  return node && node.valueBlock && Array.isArray(node.valueBlock.value)
    ? node.valueBlock.value : [];
}

// HOT PATH: per node of every SignedData, as pkinitKids() above.
function pkinitIs(node, tagClass, tagNumber) {
  return !!(node && node.idBlock && node.idBlock.tagClass === tagClass &&
            node.idBlock.tagNumber === tagNumber);
}

// HOT PATH: per node of every SignedData, as pkinitKids() above.
function pkinitRaw(node) {
  return Buffer.from(node.valueBeforeDecodeView);
}

// HOT PATH: per node of every SignedData, as pkinitKids() above.
function pkinitOidOf(node) {
  return pkinitIs(node, 1, 6) ? String(node.valueBlock.toString()) : '';
}

// The octets of an OCTET STRING, primitive or BER-constructed, or of an
// implicitly tagged one. HOT PATH: per node, as pkinitKids() above.
function pkinitOctets(node) {
  if (!node || !node.idBlock) {
    return null;
  }
  if (node.idBlock.isConstructed ||
      (node.valueBlock && node.valueBlock.isConstructed)) {
    const parts = [];
    const kids = pkinitKids(node);
    for (let i = 0; i < kids.length; i++) {
      const one = pkinitOctets(kids[i]);
      if (one === null) {
        return null;
      }
      parts.push(one);
    }
    return Buffer.concat(parts);
  }
  const view = node.valueBlock && node.valueBlock.valueHexView;
  return view ? Buffer.from(view) : null;
}

// A certificate's issuer Name and serialNumber, as their encodings, and its
// subjectKeyIdentifier when it has one: what a SignerIdentifier is matched
// against.
/**
 * Reads a certificate's issuer, serial number and subject key identifier as
 * their DER encodings, for matching a CMS SignerIdentifier.
 *
 * @param certDer - the certificate
 * @returns `{ issuer, serial, ski }`; `ski` is null when absent
 * @throws Error when it is not a certificate
 */
function pkinitCertificateIds(certDer) {
  log.debug("Entering pkinitCertificateIds().");
  const cert = pkinitReadOne(certDer, 'a certificate');
  const tbs = pkinitKids(cert)[0];
  const fields = pkinitKids(tbs);
  const i = pkinitIs(fields[0], 3, 0) ? 1 : 0;
  const serial = fields[i];
  const issuer = fields[i + 2];
  if (!pkinitIs(serial, 1, 2) || !pkinitIs(issuer, 1, 16)) {
    log.debug("Leaving pkinitCertificateIds(). Not a certificate.");
    // error-code: none — a reader; the caller refuses what does not decode
    throw new Error('pkinit: not an X.509 certificate');
  }
  let ski = null;
  const extensions = fields.filter(function (one) {
    return pkinitIs(one, 3, 3);
  })[0];
  pkinitKids(pkinitKids(extensions)[0]).forEach(function (ext) {
    const parts = pkinitKids(ext);
    if (pkinitOidOf(parts[0]) === '2.5.29.14') {
      const wrapped = pkinitOctets(parts[parts.length - 1]);
      try {
        ski = pkinitOctets(pkinitReadOne(wrapped, 'a subjectKeyIdentifier'));
      } catch (e) {
        log.debug("Caught in pkinitCertificateIds(): " +
                  ((e && e.message) || e));
        ski = null;
      }
    }
  });
  log.debug("Leaving pkinitCertificateIds().");
  return { issuer: pkinitRaw(issuer), serial: pkinitRaw(serial), ski: ski };
}

// ---------------------------------------------------------------------------
// READ A SignedData: `{ eContentType, eContent, certificates, signerInfos }`,
// each SignerInfo with its sid, digest, signature algorithm, the signed
// attributes as they arrived and the two this section checks. Throws when it
// is not one.
// ---------------------------------------------------------------------------
/**
 * Reads a CMS ContentInfo holding a SignedData: the encapsulated content,
 * the certificates and each SignerInfo with its signed attributes as they
 * arrived.
 *
 * @param contentInfoDer - the ContentInfo
 * @returns `{ eContentType, eContent, certificates, signerInfos }`
 * @throws Error when it is not a SignedData
 */
function pkinitReadSignedData(contentInfoDer) {
  log.debug("Entering pkinitReadSignedData().");
  const info = pkinitReadOne(contentInfoDer, 'the ContentInfo');
  const top = pkinitKids(info);
  if (!pkinitIs(info, 1, 16) ||
      pkinitOidOf(top[0]) !== PKINIT_OID.signedData ||
      !pkinitIs(top[1], 3, 0)) {
    log.debug("Leaving pkinitReadSignedData(). Not a SignedData.");
    // error-code: none — a reader; the caller refuses what does not decode
    throw new Error('pkinit: the ContentInfo does not hold a SignedData');
  }
  const signed = pkinitKids(pkinitKids(top[1])[0]);
  const encap = pkinitKids(signed[2]);
  const eContentType = pkinitOidOf(encap[0]);
  const eContent = encap[1] && pkinitIs(encap[1], 3, 0)
    ? pkinitOctets(pkinitKids(encap[1])[0]) : null;
  let at = 3;
  const certificates = [];
  if (signed[at] && pkinitIs(signed[at], 3, 0)) {
    pkinitKids(signed[at]).forEach(function (one) {
      if (pkinitIs(one, 1, 16)) {
        certificates.push(pkinitRaw(one));
      }
    });
    at++;
  }
  if (signed[at] && pkinitIs(signed[at], 3, 1)) {
    at++;
  }
  const signerSet = signed[at];
  if (!eContentType || !pkinitIs(signerSet, 1, 17) ||
      signed.length !== at + 1) {
    log.debug("Leaving pkinitReadSignedData(). Malformed.");
    // error-code: none — a reader; the caller refuses what does not decode
    throw new Error('pkinit: the SignedData is not well formed');
  }
  const signerInfos = pkinitKids(signerSet).map(function (si) {
    const f = pkinitKids(si);
    const sid = f[1];
    let k = 3;
    let signedAttrsRaw = null;
    const attrs = {};
    if (f[k] && pkinitIs(f[k], 3, 0)) {
      signedAttrsRaw = pkinitRaw(f[k]);
      pkinitKids(f[k]).forEach(function (attr) {
        const parts = pkinitKids(attr);
        const type = pkinitOidOf(parts[0]);
        const values = pkinitKids(parts[1]);
        if (values.length !== 1) {
          // error-code: none — a reader; the caller refuses what does not decode
          throw new Error('pkinit: a signed attribute has ' + values.length +
                          ' values');
        }
        if (type === PKINIT_OID.contentType) {
          attrs.contentType = pkinitOidOf(values[0]);
        } else if (type === PKINIT_OID.messageDigest) {
          attrs.messageDigest = pkinitOctets(values[0]);
        }
      });
      k++;
    }
    return {
      sid: pkinitIs(sid, 3, 0)
        ? { ski: pkinitOctets(sid) }
        : { issuer: pkinitRaw(pkinitKids(sid)[0]),
            serial: pkinitRaw(pkinitKids(sid)[1]) },
      digestAlg: pkinitOidOf(pkinitKids(f[2])[0]),
      signedAttrsRaw: signedAttrsRaw,
      contentTypeAttr: attrs.contentType || '',
      messageDigestAttr: attrs.messageDigest || null,
      signatureAlg: pkinitOidOf(pkinitKids(f[k])[0]),
      signature: pkinitOctets(f[k + 1])
    };
  });
  log.debug("Leaving pkinitReadSignedData(). " + certificates.length +
            " certificate(s), " + signerInfos.length + " signer(s).");
  return { eContentType: eContentType, eContent: eContent,
           certificates: certificates, signerInfos: signerInfos };
}

// Does a SignerIdentifier name this certificate?
/**
 * Says whether a SignerInfo's identifier names a certificate.
 *
 * @param sid - the `sid` of a `pkinitReadSignedData()` signer
 * @param certDer - the certificate
 * @returns true when it does
 */
function pkinitSignerIdentifies(sid, certDer) {
  log.debug("Entering pkinitSignerIdentifies().");
  let ids = null;
  try {
    ids = pkinitCertificateIds(certDer);
  } catch (e) {
    log.debug("Caught in pkinitSignerIdentifies(): " +
              ((e && e.message) || e));
    log.debug("Leaving pkinitSignerIdentifies(). Not a certificate.");
    return false;
  }
  const same = sid.ski
    ? !!ids.ski && ids.ski.equals(Buffer.from(sid.ski))
    : ids.issuer.equals(Buffer.from(sid.issuer)) &&
      ids.serial.equals(Buffer.from(sid.serial));
  log.debug("Leaving pkinitSignerIdentifies(). " + same);
  return same;
}

// ---------------------------------------------------------------------------
// VERIFY a SignedData's one signature with the signer's certificate.
// Answers `{ ok: true, digest }` or `{ ok: false, reason, why }`, the reason
// being which RFC 4556 error the caller sends: `digest`
// (KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED) or `signature`
// (KDC_ERR_INVALID_SIG).
// ---------------------------------------------------------------------------
/**
 * Verifies a SignedData's one signature with the signer's certificate: the
 * digest, the content-type and message-digest attributes and the signature
 * over the signed attributes as they arrived.
 *
 * @param signed - a `pkinitReadSignedData()` answer
 * @param certDer - the signer's certificate
 * @returns `{ ok: true, digest }`, or `{ ok: false, reason, why }` with a
 *   reason of `digest` or `signature`
 */
function pkinitVerifySignedData(signed, certDer) {
  log.debug("Entering pkinitVerifySignedData().");
  const signer = signed.signerInfos[0];
  if (signed.signerInfos.length !== 1) {
    log.debug("Leaving pkinitVerifySignedData(). Not one signer.");
    return { ok: false, reason: 'signature',
             why: 'the SignedData has ' + signed.signerInfos.length +
                  ' SignerInfos; RFC 4556 section 3.2.1 item 4 requires one' };
  }
  const digest = PKINIT_CMS_DIGEST_OIDS[signer.digestAlg];
  if (!digest) {
    log.debug("Leaving pkinitVerifySignedData(). Digest refused.");
    return { ok: false, reason: 'digest',
             why: 'the AuthPack is signed over ' +
                  (PKINIT_REFUSED_DIGESTS[signer.digestAlg] ||
                   'an unknown digest (' + signer.digestAlg + ')') +
                  '; this KDC accepts SHA-256, SHA-384 and SHA-512' };
  }
  let x509 = null;
  try {
    x509 = new nodeCrypto.X509Certificate(Buffer.from(certDer));
  } catch (e) {
    log.debug("Caught in pkinitVerifySignedData(): " + ((e && e.message) || e));
    x509 = null;
  }
  const keyType = x509 ? x509.publicKey.asymmetricKeyType : '';
  const sig = PKINIT_CMS_SIGNATURES[signer.signatureAlg];
  if (!x509 || !sig || sig.key !== keyType ||
      (sig.digest && sig.digest !== digest.id)) {
    log.debug("Leaving pkinitVerifySignedData(). Signature algorithm.");
    return { ok: false, reason: 'signature',
             why: 'the signature algorithm (' + signer.signatureAlg + ') is ' +
                  'not one this KDC verifies, or does not agree with the ' +
                  'digest or with the ' + (keyType || 'unreadable') +
                  ' key in the signer\'s certificate' };
  }
  if (!signer.signedAttrsRaw || signer.contentTypeAttr !==
      signed.eContentType) {
    log.debug("Leaving pkinitVerifySignedData(). content-type attribute.");
    // RFC 4556 section 3.2.1 item 2: "the signed attribute content-type MUST
    // be present in this SignedData instance".
    return { ok: false, reason: 'signature',
             why: 'the SignedData carries no content-type signed attribute ' +
                  'naming its content (' + signed.eContentType + ')' };
  }
  const computed = nodeCrypto.createHash(digest.id)
    .update(signed.eContent || Buffer.alloc(0)).digest();
  const claimed = signer.messageDigestAttr;
  if (!claimed || claimed.length !== computed.length ||
      !nodeCrypto.timingSafeEqual(claimed, computed)) {
    log.debug("Leaving pkinitVerifySignedData(). message-digest.");
    return { ok: false, reason: 'signature',
             why: 'the message-digest signed attribute is not the ' +
                  digest.label + ' of the AuthPack' };
  }
  const signedBytes = Buffer.from(signer.signedAttrsRaw);
  signedBytes[0] = 0x31;
  let verified = false;
  try {
    verified = nodeCrypto.verify(digest.id, signedBytes, x509.publicKey,
                                 signer.signature || Buffer.alloc(0));
  } catch (e) {
    log.debug("Caught in pkinitVerifySignedData(): " + ((e && e.message) || e));
    verified = false;
  }
  if (!verified) {
    log.debug("Leaving pkinitVerifySignedData(). Does not verify.");
    return { ok: false, reason: 'signature',
             why: 'the signature over the AuthPack does not verify with the ' +
                  'signer\'s certificate' };
  }
  log.debug("Leaving pkinitVerifySignedData(). " + digest.label + ", " +
            sig.label);
  return { ok: true, digest: digest.id };
}

// ---------------------------------------------------------------------------
// WRITE a SignedData: one signer, SHA-256, the content-type and
// message-digest signed attributes, the signer's certificate and the chain
// handed in (the caller leaves the Root out). RSA keys sign PKCS #1 v1.5 and
// say `rsaEncryption`, as OpenSSL writes it; EC keys sign ECDSA.
// ---------------------------------------------------------------------------
/**
 * Writes a CMS ContentInfo holding a SignedData over `content`, signed with
 * SHA-256 by an RSA or EC key, carrying the given certificates — or, with no
 * `privateKey`, RFC 8062's unsigned SignedData, with no signer and no
 * certificate.
 *
 * @param opts - `contentType` (an OID), `content` (bytes), `signerCertDer`,
 *   `chainDers` (more certificates, the Root left out) and `privateKey`
 * @returns the ContentInfo's DER
 * @throws Error for a key that is neither RSA nor EC
 */
function pkinitSignedData(opts) {
  log.debug("Entering pkinitSignedData(). " + opts.contentType);
  const content = Buffer.from(opts.content);
  const sha256 = pkinitTlv(0x30, [pkinitOidDer('2.16.840.1.101.3.4.2.1')]);
  if (!opts.privateKey) {
    // RFC 8062 section 4.1.1's anonymous AuthPack: "the signerInfos field of
    // the SignedData ... is empty, and the certificates field is absent".
    log.debug("Leaving pkinitSignedData(). Unsigned.");
    return pkinitTlv(0x30, [pkinitOidDer(PKINIT_OID.signedData),
      pkinitTlv(0xa0, [pkinitTlv(0x30, [
        pkinitUnsignedIntegerDer([3]),
        pkinitSetOf([sha256]),
        pkinitTlv(0x30, [pkinitOidDer(opts.contentType),
                         pkinitTlv(0xa0, [pkinitTlv(0x04, content)])]),
        pkinitTlv(0x31, [])])])]);
  }
  const key = nodeCrypto.createPrivateKey(opts.privateKey);
  const kind = key.asymmetricKeyType;
  if (kind !== 'rsa' && kind !== 'ec') {
    log.debug("Leaving pkinitSignedData(). Unsupported key.");
    // error-code: none — a programming error; the KDC key is RSA or EC
    throw new Error('pkinit: a KDC signs with RSA or EC, not ' + kind);
  }
  const signatureAlg = kind === 'rsa'
    ? pkinitTlv(0x30, [pkinitOidDer('1.2.840.113549.1.1.1'),
                       Buffer.from([0x05, 0x00])])
    : pkinitTlv(0x30, [pkinitOidDer('1.2.840.10045.4.3.2')]);
  const attrs = [
    pkinitTlv(0x30, [pkinitOidDer(PKINIT_OID.contentType),
                     pkinitSetOf([pkinitOidDer(opts.contentType)])]),
    pkinitTlv(0x30, [pkinitOidDer(PKINIT_OID.messageDigest),
                     pkinitSetOf([pkinitTlv(0x04,
                       nodeCrypto.createHash('sha256').update(content)
                         .digest())])])
  ];
  const signedAttrs = pkinitSetOf(attrs);
  const signature = nodeCrypto.sign('sha256', signedAttrs, key);
  const ids = pkinitCertificateIds(opts.signerCertDer);
  const signerInfo = pkinitTlv(0x30, [
    pkinitUnsignedIntegerDer([1]),
    pkinitTlv(0x30, [ids.issuer, ids.serial]),
    sha256,
    Buffer.concat([Buffer.from([0xa0]), signedAttrs.subarray(1)]),
    signatureAlg,
    pkinitTlv(0x04, signature)
  ]);
  const certificates = [opts.signerCertDer].concat(opts.chainDers || []);
  const signedData = pkinitTlv(0x30, [
    // Version 3: the content is not id-data (RFC 5652 section 5.1).
    pkinitUnsignedIntegerDer([3]),
    pkinitSetOf([sha256]),
    pkinitTlv(0x30, [pkinitOidDer(opts.contentType),
                     pkinitTlv(0xa0, [pkinitTlv(0x04, content)])]),
    pkinitTlv(0xa0, certificates.map(function (one) {
      return Buffer.from(one);
    })),
    pkinitSetOf([signerInfo])
  ]);
  log.debug("Leaving pkinitSignedData().");
  return pkinitTlv(0x30, [pkinitOidDer(PKINIT_OID.signedData),
                          pkinitTlv(0xa0, [signedData])]);
}

// ---------------------------------------------------------------------------
// THE KEY AGREEMENT. The client's SubjectPublicKeyInfo names the group and
// carries its public value; the KDC makes an ephemeral key in the same
// group, computes the shared secret and answers its own public value in the
// form KDCDHKeyInfo's BIT STRING carries (RFC 3279: a DER INTEGER for MODP,
// the uncompressed point for a curve). Answers `{ ok: true, group, secret,
// kdcPublicValue }` or `{ ok: false, reason: 'params' | 'value', why }`;
// `params` is KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED.
//
// **THE SHARED SECRET IS PADDED TO THE MODULUS** (RFC 4556 section 3.2.3.1:
// "padded with leading zeros such that the size of DHSharedSecret in octets
// is the same as that of the modulus"), which node does not promise. An ECDH
// secret is the x-coordinate at the field's size (RFC 5349 section 4), which
// node does.
//
// **THE CLIENT'S VALUE IS CHECKED** before it is used: 1 < y < p - 1 for a
// MODP group, whose primes are safe primes so that the range check is the
// small-subgroup check; a point on the curve for ECDH, which node refuses
// otherwise.
// ---------------------------------------------------------------------------
/**
 * Runs the KDC's half of a PKINIT Diffie-Hellman exchange against the
 * client's SubjectPublicKeyInfo: the group checked against
 * `PKINIT_DH_GROUPS`, the client's value checked, an ephemeral key made.
 *
 * @param clientSpkiDer - the AuthPack's clientPublicValue
 * @returns `{ ok: true, group, secret, kdcPublicValue }`, or `{ ok: false,
 *   reason, why }` with a reason of `params` or `value`
 */
function pkinitKeyAgreement(clientSpkiDer) {
  log.debug("Entering pkinitKeyAgreement().");
  let spki;
  try {
    spki = pkinitReadOne(clientSpkiDer, 'the clientPublicValue');
  } catch (e) {
    log.debug("Caught in pkinitKeyAgreement(): " + ((e && e.message) || e));
    log.debug("Leaving pkinitKeyAgreement(). Unreadable.");
    return { ok: false, reason: 'params',
             why: 'the clientPublicValue is not a SubjectPublicKeyInfo' };
  }
  const algorithm = pkinitKids(pkinitKids(spki)[0]);
  const bits = pkinitKids(spki)[1];
  const oid = pkinitOidOf(algorithm[0]);
  const publicBits = bits && pkinitIs(bits, 1, 3) && bits.valueBlock &&
                     bits.valueBlock.valueHexView
    ? Buffer.from(bits.valueBlock.valueHexView) : null;
  if (!publicBits) {
    log.debug("Leaving pkinitKeyAgreement(). No public value.");
    return { ok: false, reason: 'params',
             why: 'the clientPublicValue carries no public key' };
  }
  if (oid === PKINIT_OID.ecPublicKey) {
    const curveOid = pkinitOidOf(algorithm[1]);
    const group = PKINIT_DH_GROUPS.filter(function (one) {
      return one.kind === 'ec' && one.oid === curveOid;
    })[0];
    if (!group) {
      log.debug("Leaving pkinitKeyAgreement(). Curve refused.");
      return { ok: false, reason: 'params',
               why: 'ECDH on the curve ' + (curveOid || '(not named)') +
                    ' is not accepted; this KDC agrees on P-256, P-384 and ' +
                    'P-521' };
    }
    const ecdh = nodeCrypto.createECDH(group.node);
    ecdh.generateKeys();
    let secret;
    try {
      secret = ecdh.computeSecret(publicBits);
    } catch (e) {
      log.debug("Caught in pkinitKeyAgreement(): " + ((e && e.message) || e));
      log.debug("Leaving pkinitKeyAgreement(). Not a point on the curve.");
      return { ok: false, reason: 'value',
               why: 'the client\'s ECDH public value is not a point on ' +
                    group.id };
    }
    log.debug("Leaving pkinitKeyAgreement(). " + group.id);
    return { ok: true, group: group, secret: Buffer.from(secret),
             kdcPublicValue: Buffer.from(ecdh.getPublicKey(null,
                                                            'uncompressed')) };
  }
  if (oid !== PKINIT_OID.dhPublicNumber) {
    log.debug("Leaving pkinitKeyAgreement(). Not DH.");
    return { ok: false, reason: 'params',
             why: 'the clientPublicValue is a ' + (oid || 'unnamed') +
                  ' key, not Diffie-Hellman (dhpublicnumber) or ECDH ' +
                  '(id-ecPublicKey)' };
  }
  const domain = pkinitKids(algorithm[1]).map(function (one) {
    return pkinitIs(one, 1, 2) ? Buffer.from(one.valueBlock.valueHexView)
                               : null;
  });
  const stripped = function (buf) {
    log.debug("Entering stripped().");
    let i = 0;
    while (buf && i < buf.length - 1 && buf[i] === 0) {
      i++;
    }
    log.debug("Leaving stripped().");
    return buf ? buf.subarray(i) : Buffer.alloc(0);
  };
  const p = stripped(domain[0]);
  const g = stripped(domain[1]);
  const group = PKINIT_DH_GROUPS.filter(function (one) {
    if (one.kind !== 'modp') {
      return false;
    }
    const known = nodeCrypto.getDiffieHellman(one.node);
    return stripped(known.getPrime()).equals(p) &&
           stripped(known.getGenerator()).equals(g);
  })[0];
  if (!group) {
    log.debug("Leaving pkinitKeyAgreement(). Group refused.");
    return { ok: false, reason: 'params',
             why: 'the Diffie-Hellman group (' + (p.length * 8) + '-bit ' +
                  'modulus) is not one of RFC 3526\'s groups 14 to 18; ' +
                  'group 2 and any group of the client\'s own are refused' };
  }
  const dh = nodeCrypto.getDiffieHellman(group.node);
  const prime = BigInt('0x' + dh.getPrime().toString('hex'));
  let y;
  try {
    const intNode = pkinitReadOne(publicBits, 'the DH public value');
    y = pkinitIs(intNode, 1, 2)
      ? BigInt('0x' + (Buffer.from(intNode.valueBlock.valueHexView)
                         .toString('hex') || '0'))
      : -1n;
  } catch (e) {
    log.debug("Caught in pkinitKeyAgreement(): " + ((e && e.message) || e));
    y = -1n;
  }
  if (y <= 1n || y >= prime - 1n) {
    log.debug("Leaving pkinitKeyAgreement(). Value out of range.");
    return { ok: false, reason: 'value',
             why: 'the client\'s Diffie-Hellman public value is outside ' +
                  '1 < y < p - 1' };
  }
  dh.generateKeys();
  const modulusBytes = dh.getPrime().length;
  const yBytes = Buffer.from(y.toString(16).padStart(modulusBytes * 2, '0'),
                             'hex');
  const raw = Buffer.from(dh.computeSecret(yBytes));
  const secret = Buffer.concat([Buffer.alloc(Math.max(0,
                                  modulusBytes - raw.length)), raw]);
  log.debug("Leaving pkinitKeyAgreement(). " + group.id);
  return { ok: true, group: group, secret: secret,
           kdcPublicValue: pkinitUnsignedIntegerDer(dh.getPublicKey()) };
}

// The groups this KDC takes, as the AlgorithmIdentifiers TD-DH-PARAMETERS
// lists (RFC 4556 section 3.2.2; RFC 3279 section 2.3.3 for a MODP group,
// its DomainParameters p, g and q; RFC 5349 section 4 for a curve).
/**
 * Returns the AlgorithmIdentifiers of the groups this KDC agrees over, in
 * preference order, for TD-DH-PARAMETERS.
 *
 * @returns the DER of each
 */
function pkinitDhParameters() {
  log.debug("Entering pkinitDhParameters().");
  const out = PKINIT_DH_GROUPS.map(function (group) {
    if (group.kind === 'ec') {
      return pkinitTlv(0x30, [pkinitOidDer(PKINIT_OID.ecPublicKey),
                              pkinitOidDer(group.oid)]);
    }
    const dh = nodeCrypto.getDiffieHellman(group.node);
    const p = BigInt('0x' + dh.getPrime().toString('hex'));
    const q = (p - 1n) / 2n;
    return pkinitTlv(0x30, [pkinitOidDer(PKINIT_OID.dhPublicNumber),
      pkinitTlv(0x30, [pkinitUnsignedIntegerDer(dh.getPrime()),
                       pkinitUnsignedIntegerDer(dh.getGenerator()),
                       pkinitUnsignedIntegerDer(Buffer.from(
                         q.toString(16).padStart(dh.getPrime().length * 2,
                                                 '0'), 'hex'))])]);
  });
  log.debug("Leaving pkinitDhParameters().");
  return out;
}

// The digests this KDC accepts in a SignedData, as AlgorithmIdentifiers, for
// TD-CMS-DIGEST-ALGORITHMS (RFC 8636 section 4).
/**
 * Returns the AlgorithmIdentifiers of the CMS digests this KDC accepts, in
 * preference order, for TD-CMS-DIGEST-ALGORITHMS.
 *
 * @returns the DER of each
 */
function pkinitDigestAlgorithms() {
  log.debug("Entering pkinitDigestAlgorithms().");
  log.debug("Leaving pkinitDigestAlgorithms().");
  return Object.keys(PKINIT_CMS_DIGEST_OIDS).map(function (oid) {
    return pkinitTlv(0x30, [pkinitOidDer(oid)]);
  });
}

// RFC 4556 section 3.2.1 item 6: paChecksum is the SHA-1 of the
// KDC-REQ-BODY. SHA-1 because the RFC fixes it, and only as a binding of the
// request to the signed AuthPack: the reply key's binding to the exchange is
// RFC 8636's KDF, whose OtherInfo covers the whole AS-REQ.
/**
 * Computes RFC 4556's paChecksum, the SHA-1 of the KDC-REQ-BODY, and
 * compares it with the one a request carries in constant time.
 *
 * @param reqBodyBytes - the KDC-REQ-BODY as it arrived
 * @param claimed - the PKAuthenticator's paChecksum
 * @returns true when they agree
 */
function pkinitPaChecksumMatches(reqBodyBytes, claimed) {
  log.debug("Entering pkinitPaChecksumMatches().");
  const computed = nodeCrypto.createHash('sha1')
    .update(Buffer.from(reqBodyBytes || [])).digest();
  const given = Buffer.from(claimed || []);
  log.debug("Leaving pkinitPaChecksumMatches().");
  return given.length === computed.length &&
         nodeCrypto.timingSafeEqual(given, computed);
}

// The key-generation seed length of an AS reply key's enctype, which is its
// key length for every enctype this KDC uses: random-to-key is the identity
// for the AES enctypes (RFC 3962, RFC 8009) and for rc4-hmac (RFC 4757).
function pkinitSeedBytes(etype) {
  log.debug("Entering pkinitSeedBytes(). " + etype);
  const profile = KRB5_PRF_ETYPES[etype];
  if (!profile) {
    log.debug("Leaving pkinitSeedBytes(). Unknown enctype.");
    // error-code: none — the caller chose the enctype from this KDC's list
    throw new Error('pkinit: no reply key of enctype ' + etype +
                    ' is derived here');
  }
  log.debug("Leaving pkinitSeedBytes().");
  return profile.keyBytes;
}

/**
 * RFC 4556 section 3.2.3.1's `octetstring2key()`: the SHA-1 of a counter
 * octet and the input, in counter mode, truncated to the enctype's key
 * length, as the AS reply key.
 *
 * @param etype - the reply key's enctype
 * @param x - DHSharedSecret, with n_c and n_k when DH keys are reused
 * @returns `{ etype, key }`
 */
function pkinitOctetString2Key(etype, x) {
  log.debug("Entering pkinitOctetString2Key(). " + etype);
  const size = pkinitSeedBytes(etype);
  const parts = [];
  let have = 0;
  for (let counter = 0; have < size; counter++) {
    const block = nodeCrypto.createHash('sha1')
      .update(Buffer.from([counter & 0xff])).update(Buffer.from(x)).digest();
    parts.push(block);
    have += block.length;
  }
  log.debug("Leaving pkinitOctetString2Key().");
  return { etype: Number(etype),
           key: new Uint8Array(Buffer.concat(parts).subarray(0, size)) };
}

/**
 * RFC 8636 section 6's KDF: SP 800-56A's one-step KDF, H(counter || Z ||
 * OtherInfo) in counter mode, truncated to the enctype's key length, as the
 * AS reply key.
 *
 * @param kdfOid - one of `PKINIT_KDFS`
 * @param z - the Diffie-Hellman shared secret, padded to the modulus
 * @param otherInfo - the DER OtherInfo (`krb5_pkinit_codec.ts` builds it)
 * @param etype - the reply key's enctype
 * @returns `{ etype, key }`
 * @throws Error for a KDF not in the table
 */
function pkinitKdf(kdfOid, z, otherInfo, etype) {
  log.debug("Entering pkinitKdf(). " + kdfOid + " " + etype);
  const kdf = PKINIT_KDFS.filter(function (one) {
    return one.oid === String(kdfOid);
  })[0];
  if (!kdf) {
    log.debug("Leaving pkinitKdf(). Unknown KDF.");
    // error-code: none — the caller chose the KDF from `PKINIT_KDFS`
    throw new Error('pkinit: ' + kdfOid + ' is not a KDF of RFC 8636');
  }
  const size = pkinitSeedBytes(etype);
  const parts = [];
  let have = 0;
  for (let counter = 1; have < size; counter++) {
    const c = Buffer.alloc(4);
    c.writeUInt32BE(counter >>> 0, 0);
    const block = nodeCrypto.createHash(kdf.hash).update(c)
      .update(Buffer.from(z)).update(Buffer.from(otherInfo)).digest();
    parts.push(block);
    have += block.length;
  }
  log.debug("Leaving pkinitKdf(). " + kdf.label);
  return { etype: Number(etype),
           key: new Uint8Array(Buffer.concat(parts).subarray(0, size)) };
}

/**
 * The one place this service signs, verifies, encrypts and decrypts.
 *
 * XML Signature and Encryption, JWS and JWE, keys and certificates, password
 * hashing, the key-encryption key, raw signatures, TPM and attestation
 * structures, the Kerberos PRF, DKIM, random values, HTTP Message
 * Signatures with Content-Digest, and PKINIT's CMS, key agreement and reply
 * key. A leaf library that
 * may never require `helpers` back.
 * @namespace
 */
module.exports = {
  // --- section 17: the rest of the service's operations (#453) ---
  SHA1_PURPOSES: SHA1_PURPOSES,
  sha1Digest: sha1Digest,
  HMAC_DIGESTS: HMAC_DIGESTS,
  hmac: hmac,
  parseCertificate: parseCertificate,
  isParsedCertificate: isParsedCertificate,
  privateKeyFrom: privateKeyFrom,
  isKeyObject: isKeyObject,
  KEY_PAIR_TYPES: KEY_PAIR_TYPES,
  generateKeyPairSync: generateKeyPairSync,
  generateKeyPairAsync: generateKeyPairAsync,
  signBytes: signBytes,
  signatureValid: signatureValid,
  digestSupported: digestSupported,
  TLS_NO_RENEGOTIATION: TLS_NO_RENEGOTIATION,
  // --- #453 group A exports: begin ---
  // GNAP's three token libraries, held here and nowhere else (#453).
  MACAROON_MIN_ROOT_KEY_BYTES: MACAROON_MIN_ROOT_KEY_BYTES,
  macaroonRootKeyUsable: macaroonRootKeyUsable,
  macaroonMint: macaroonMint,
  macaroonImport: macaroonImport,
  macaroonVerify: macaroonVerify,
  macaroonAttenuate: macaroonAttenuate,
  ZCAP_LEGACY_SUITE: ZCAP_LEGACY_SUITE,
  zcapReady: zcapReady,
  zcapVerificationMethod: zcapVerificationMethod,
  zcapDelegate: zcapDelegate,
  zcapVerifyDelegation: zcapVerifyDelegation,
  biscuitReady: biscuitReady,
  biscuitMint: biscuitMint,
  biscuitAuthorize: biscuitAuthorize,
  biscuitAttenuate: biscuitAttenuate,
  // --- #453 group A exports: end ---
  //
  // --- #453 group B exports: begin ---
  // --- #453 group B exports: end ---
  //
  // --- #453 group C exports: begin ---
  // --- #453 group C exports: end ---
  //
  // --- #453 group D exports: begin ---
  // --- #453 group D exports: end ---
  //
  // --- #453 group E exports: begin ---
  // --- #453 group E exports: end ---
  //
  // --- #453 group F exports: begin ---
  // --- #453 group F exports: end ---
  //
  // --- section 16: PKINIT's CMS, key agreement and reply key (#179) ---
  PKINIT_OID: PKINIT_OID,
  PKINIT_CMS_DIGEST_OIDS: PKINIT_CMS_DIGEST_OIDS,
  PKINIT_CMS_SIGNATURES: PKINIT_CMS_SIGNATURES,
  PKINIT_DH_GROUPS: PKINIT_DH_GROUPS,
  PKINIT_KDFS: PKINIT_KDFS,
  pkinitCertificateIds: pkinitCertificateIds,
  pkinitReadSignedData: pkinitReadSignedData,
  pkinitSignerIdentifies: pkinitSignerIdentifies,
  pkinitVerifySignedData: pkinitVerifySignedData,
  pkinitSignedData: pkinitSignedData,
  pkinitKeyAgreement: pkinitKeyAgreement,
  pkinitDhParameters: pkinitDhParameters,
  pkinitDigestAlgorithms: pkinitDigestAlgorithms,
  pkinitPaChecksumMatches: pkinitPaChecksumMatches,
  pkinitOctetString2Key: pkinitOctetString2Key,
  pkinitKdf: pkinitKdf,
  // --- section 15: digests, key derivation and key import (#178) ---
  DIGESTS: DIGESTS,
  digest: digest,
  hkdf: hkdf,
  publicKeyFromJwk: publicKeyFromJwk,
  publicKeyOf: publicKeyOf,
  spkiDerOf: spkiDerOf,
  // --- section 14: HTTP Message Signatures and Content-Digest (#178) ---
  HTTP_SIGNATURE_ALGORITHMS: HTTP_SIGNATURE_ALGORITHMS,
  CONTENT_DIGEST_ALGORITHMS: CONTENT_DIGEST_ALGORITHMS,
  HTTP_SIGNATURE_FIELD_TYPES: KNOWN_FIELD_TYPES,
  contentDigest: contentDigest,
  verifyContentDigest: verifyContentDigest,
  httpSignatureComponentValue: httpSignatureComponentValue,
  httpSignatureBase: httpSignatureBase,
  signHttpMessage: signHttpMessage,
  appendHttpSignature: appendHttpSignature,
  parseHttpSignatures: parseHttpSignatures,
  verifyHttpMessage: verifyHttpMessage,
  // --- section 13: random values (#65) ---
  RANDOM_TOKEN_MIN_BITS: RANDOM_TOKEN_MIN_BITS,
  installForgeRandom: installForgeRandom,
  randomBytes: randomBytes,
  randomInt: randomInt,
  randomUuid: randomUuid,
  randomToken: randomToken,
  randomString: randomString,
  // --- section 12: DKIM (#63) ---
  DKIM_ALGORITHMS: DKIM_ALGORITHMS,
  dkimSign: dkimSign,
  dkimVerify: dkimVerify,
  dkimRelaxedBody: dkimRelaxedBody,
  dkimRelaxedHeader: dkimRelaxedHeader,
  sessionStateHash: sessionStateHash,
  userAgentFingerprint: userAgentFingerprint,
  credentialFingerprint: credentialFingerprint,
  truncatedSha256Hex: truncatedSha256Hex,
  pwnedPasswordDigest: pwnedPasswordDigest,
  certificateIdentifiers: certificateIdentifiers,
  // --- a credential several processes have to derive alike ---
  deriveSharedCredential: deriveSharedCredential,
  // --- XML digital signature ---
  PLACEMENT: PLACEMENT,
  signXml: signXml,
  verifyXmlSignature: verifyXmlSignature,
  signQueryString: signQueryString,
  verifyQueryString: verifyQueryString,
  idOf: idOf,
  // Section 1a: which XML signature algorithms are verified, the one
  // primitive, and the two questions a registration or a caller asks.
  xmlSignatureAlgorithms: xmlSignatureAlgorithms,
  xmlAlgorithmVerdict: xmlAlgorithmVerdict,
  xmlSignatureKeyProblem: xmlSignatureKeyProblem,
  xmlSignatureKeyTypeUsable: xmlSignatureKeyTypeUsable,
  verifyXmlSignatureValue: verifyXmlSignatureValue,
  sha1SignaturesAllowed: sha1Allowed,
  // --- XML encryption ---
  encryptElement: encryptElement,
  encryptAssertion: encryptAssertion,
  decryptElement: decryptElement,
  BLOCK_CIPHERS: BLOCK_CIPHERS,
  KEY_TRANSPORTS: KEY_TRANSPORTS,
  KEY_AGREEMENTS: KEY_AGREEMENTS,
  KEY_WRAPS: KEY_WRAPS,
  OAEP_DIGESTS: OAEP_DIGESTS,
  MGF1_URIS: MGF1_URIS,
  cipherByUri: cipherByUri,
  transportByUri: transportByUri,
  // --- JWS / JWT ---
  signJws: signJws,
  verifyJws: verifyJws,
  // The three that compute a post-quantum signature on libuv's thread pool
  // and resolve with exactly what their synchronous namesakes return. See
  // signJwsAsync() for which callers use them and why the others do not.
  signJwsAsync: signJwsAsync,
  verifyJwsAsync: verifyJwsAsync,
  verifyCompactJwsAsync: verifyCompactJwsAsync,
  tokenClockSkew: tokenClockSkew,
  // The one JWS algorithm table and the operations built on it (the JWE
  // exports follow from JWE_ALG down).
  b64u: b64u,
  JWS_ALGS: JWS_ALGS,
  JWS_SIGNING_ALGS: JWS_SIGNING_ALGS,
  idTokenHashFor: idTokenHashFor,
  idTokenHalfHash: idTokenHalfHash,
  JWS_ASYMMETRIC_ALGS: JWS_ASYMMETRIC_ALGS,
  jwsSpec: jwsSpec,
  protectedHeaderFor: protectedHeaderFor,
  verifyCompactJws: verifyCompactJws,
  // The byte-level halves of the JOSE doors (#202): what external test
  // vectors are held to. See each function's head.
  jwsSignatureValid: jwsSignatureValid,
  jwsSignatureOver: jwsSignatureOver,
  sealJweContent: sealJweContent,
  openJweContent: openJweContent,
  aesKeyWrap: aesKeyWrap,
  aesKeyUnwrap: aesKeyUnwrap,
  // The CipherValue opener decryptElement() uses, exported so Wycheproof
  // can hold its PADDING verdict to vectors — decryptElement() itself
  // answers every CBC failure identically, on purpose (STS-KEYS-0078).
  openXmlContent: openXmlContent,
  checkJwtClaims: checkJwtClaims,
  JWE_ALG: JWE_ALG,
  JWE_ALGS: JWE_ALGS,
  JWE_DECRYPT_ALGS: JWE_DECRYPT_ALGS,
  // The families, for a caller that holds ONE kind of key and has to say which
  // algorithms it will therefore accept. `client_auth.js` narrows to the
  // symmetric list for a client_secret_jwt client and to the asymmetric one
  // for private_key_jwt, which is the alg-confusion refusal one layer up.
  JWE_RSA_ALGS: JWE_RSA_ALGS,
  JWE_ECDH_ALGS: JWE_ECDH_ALGS,
  JWE_ASYMMETRIC_ALGS: JWE_ASYMMETRIC_ALGS,
  // EXPORTED FOR ONE CALLER AND IT IS A TEST, which is worth the line rather
  // than hiding: RFC 7517 Appendix C publishes a PBES2 vector — a password, a
  // salt, an iteration count and the sixteen bytes that come out — and there
  // is no other way to check the derivation against an EXTERNAL answer. A
  // round trip through this file's own wrap and unwrap agrees with itself
  // whatever the salt construction is, which is how a mutant that dropped the
  // algorithm name from the salt survived the first mutation round on
  // `tests/assertion_grant.js`. Dropping it makes one password produce the
  // same key for three different key sizes, and nothing about a round trip can
  // see that.
  pbes2Key: pbes2Key,
  JWE_SYMMETRIC_ALGS: JWE_SYMMETRIC_ALGS,
  JWE_ENCS: JWE_ENCS,
  encryptJweCompact: encryptJweCompact,
  decryptJweCompact: decryptJweCompact,
  // --- post-quantum and HPKE key establishment (section 4a, #82) ---
  // The families, each a list of `alg` values: ML-KEM (pqc-kem-05), HPKE
  // (both drafts), the Integrated subset (no `enc`), the post-quantum subset
  // (ML-KEM and HPKE-8 to 16) and the PQ/T hybrids.
  JWE_MLKEM_ALGS: JWE_MLKEM_ALGS,
  JWE_HPKE_ALGS: JWE_HPKE_ALGS,
  JWE_HPKE_INTEGRATED_ALGS: JWE_HPKE_INTEGRATED_ALGS,
  JWE_POST_QUANTUM_ALGS: JWE_POST_QUANTUM_ALGS,
  JWE_HYBRID_ALGS: JWE_HYBRID_ALGS,
  isIntegratedJweAlg: isIntegratedJweAlg,
  jweRecipientKeyFits: jweRecipientKeyFits,
  jweRecipientKeyNeed: jweRecipientKeyNeed,
  describeJweKemAlg: describeJweKemAlg,
  generateJweKemKeyPair: generateJweKemKeyPair,
  deriveJweKemKeyPair: deriveJweKemKeyPair,
  publicJweKemJwk: publicJweKemJwk,
  // EXPORTED FOR THE VECTORS: tests/jwe_pq_kem.js holds the KEMs, the key
  // schedule and the KMAC derivation to draft-ietf-hpke-pq-05's,
  // draft-irtf-cfrg-concrete-hybrid-kems's and jose-hpke-encrypt-22's
  // published answers, and a round trip through this file's own encrypt and
  // decrypt would agree with itself whatever the construction was.
  hpke: {
    KEMS: HPKE_KEMS,
    KDFS: HPKE_KDFS,
    AEADS: HPKE_AEADS,
    deriveKeyPair: hpkeDeriveKeyPair,
    generateKeyPair: hpkeGenerateKeyPair,
    encap: hpkeEncap,
    decap: hpkeDecap,
    setupSender: hpkeSetupSender,
    setupReceiver: hpkeSetupReceiver,
    hybridExpand: hybridExpand,
    hybridEncaps: hybridEncaps,
    hybridDecaps: hybridDecaps,
    mlkemCheckEncapsulationKey: mlkemCheckEncapsulationKey,
    // The encapsulation key of a seed (FIPS 203 KeyGen_internal), and the
    // X25519 / X448 exchange with RFC 7748's all-zero refusal — for
    // Wycheproof's ML-KEM keygen and XDH files.
    mlkemEncapsulationKeyOf: function (set, seed) {
      log.debug('Entering hpke.mlkemEncapsulationKeyOf().');
      log.debug('Leaving hpke.mlkemEncapsulationKeyOf().');
      return mlkemFromSeed(set, seed).ek;
    },
    montgomeryDh: montgomeryDh,
    // The suite AEADs, by id, for Wycheproof's ChaCha20-Poly1305 file.
    aeadSeal: function (aeadId, key, nonce, aad, pt) {
      log.debug('Entering hpke.aeadSeal().');
      log.debug('Leaving hpke.aeadSeal().');
      return hpkeAeadSeal(HPKE_AEADS[aeadId], key, nonce, aad, pt);
    },
    aeadOpen: function (aeadId, key, nonce, aad, ct) {
      log.debug('Entering hpke.aeadOpen().');
      log.debug('Leaving hpke.aeadOpen().');
      return hpkeAeadOpen(HPKE_AEADS[aeadId], key, nonce, aad, ct);
    },
    mlkemJoseKdf: mlkemJoseKdf,
    recipientStructure: joseHpkeRecipientStructure
  },
  // --- keys, certificates, thumbprints ---
  // Exported for a caller that mints a certificate through neither generator
  // below, so that the one reason a serial is random is written down once.
  certificateSerial: certificateSerial,
  selfSignedRsaCertificate: selfSignedRsaCertificate,
  selfSignedMlDsaCertificate: selfSignedMlDsaCertificate,
  mlDsaAvailable: mlDsaAvailable,
  ML_DSA_OIDS: ML_DSA_OIDS,
  stripPem: stripPem,
  canonicalJwk: canonicalJwk,
  jwkThumbprint: jwkThumbprint,
  JWK_THUMBPRINT_URI_PREFIX: JWK_THUMBPRINT_URI_PREFIX,
  jwkThumbprintUri: jwkThumbprintUri,
  SIGNING_JWK_PAIR_ALGS: SIGNING_JWK_PAIR_ALGS,
  generateSigningJwkPair: generateSigningJwkPair,
  certificateThumbprint: certificateThumbprint,
  certificateSpkiThumbprint: certificateSpkiThumbprint,
  publicKeySpkiThumbprint: publicKeySpkiThumbprint,
  constantTimeEquals: constantTimeEquals,
  // --- one-time passwords (RFC 4226 section 5.3) ---
  // The primitive only. The time step, the skew window, the replay guard and
  // base32 are `common/totp.ts`'s, for the reason written above hotpCode().
  HOTP_ALGS: HOTP_ALGS,
  hotpSpec: hotpSpec,
  hotpCode: hotpCode,
  hashSecret: hashSecret,
  // The cost a NEW hash is written under, for the console and the tests.
  scryptParameters: scryptParameters,
  hashSecretAsync: hashSecretAsync,
  // ENVELOPE ENCRYPTION AT REST (#391): data encryption keys wrapped under
  // the key-encryption key, and values sealed under the DEKs.
  encryptWithDek: encryptWithDek,
  decryptWithDek: decryptWithDek,
  dekIdOf: dekIdOf,
  generateDek: generateDek,
  generateDekId: generateDekId,
  wrapDek: wrapDek,
  unwrapDek: unwrapDek,
  deriveDek: deriveDek,
  kekAccounting: kekAccounting,
  KEK_PARAMETERS: KEK_PARAMETERS,
  isEncryptedWithKek: isEncryptedWithKek,
  // AES-256-SIV (#391), for the data keys of directory data and for
  // `tests/wycheproof.js`.
  aesSivEncrypt: aesSivEncrypt,
  aesSivDecrypt: aesSivDecrypt,
  aesCmac: aesCmac,
  dekAlgOf: dekAlgOf,
  kekBytes: kekBytes,
  verifySecret: verifySecret,
  verifySecretAsync: verifySecretAsync,
  isHashedSecret: isHashedSecret,
  // --- section 8: raw signatures and TPM 2.0 (#40) ---
  RAW_SIGNATURE_FAMILIES: RAW_SIGNATURE_FAMILIES,
  publicKeyFromSpki: publicKeyFromSpki,
  verifyRawSignature: verifyRawSignature,
  signRawSignature: signRawSignature,
  hmacSha256: hmacSha256,
  ephemeralKeyPair: ephemeralKeyPair,
  olpcCanonicalJson: olpcCanonicalJson,
  jcsCanonicalJson: jcsCanonicalJson,
  spkiFromPublicKeyPem: spkiFromPublicKeyPem,
  publicKeyPemOfSpki: publicKeyPemOfSpki,
  verifyWithPublicKey: verifyWithPublicKey,
  tufKeySpki: tufKeySpki,
  verifyThresholdSignatures: verifyThresholdSignatures,
  verifyRekorSet: verifyRekorSet,
  dssePae: dssePae,
  sha256Hex: sha256Hex,
  sha512Hex: sha512Hex,
  ecdsaIntegersToP1363: ecdsaIntegersToP1363,
  tpmKdfa: tpmKdfa,
  tpmMakeCredential: tpmMakeCredential,
  verifyPkcs7SignedData: verifyPkcs7SignedData,
  sha256OfFile: sha256OfFile,
  sha256Digester: sha256Digester,
  // --- section 9: the Kerberos PRF and KRB-FX-CF2 (#173) ---
  KRB5_PRF_ETYPES: KRB5_PRF_ETYPES,
  krb5Nfold: krb5Nfold,
  krb5Prf: krb5Prf,
  krb5PrfPlus: krb5PrfPlus,
  krbFxCf2: krbFxCf2,
  // --- section 10: WebAuthn's COSE signatures and attestation structures
  //     (#105) ---
  COSE_SIGNATURE_ALGS: COSE_SIGNATURE_ALGS,
  coseSignatureAlg: coseSignatureAlg,
  verifyCoseSignature: verifyCoseSignature,
  TPM_ALG: TPM_ALG,
  TPM_GENERATED_VALUE: TPM_GENERATED_VALUE,
  TPM_ST_ATTEST_CERTIFY: TPM_ST_ATTEST_CERTIFY,
  tpmHashName: tpmHashName,
  tpmParsePublic: tpmParsePublic,
  tpmParseAttest: tpmParseAttest,
  tpmParseSignature: tpmParseSignature,
  tpmName: tpmName,
  fidoAaguidExtension: fidoAaguidExtension,
  appleAttestationNonce: appleAttestationNonce,
  androidKeyDescription: androidKeyDescription,
  ID_AA_ATTESTATION: ID_AA_ATTESTATION,
  TCG_ATTEST_TPM_CERTIFY: TCG_ATTEST_TPM_CERTIFY,
  csrAttestationBundle: csrAttestationBundle,
  tpm2bContents: tpm2bContents,
  tcgTpmCertifyStatement: tcgTpmCertifyStatement,
  // --- the algorithm URIs, so that there is one spelling of each in the
  //     process. Taken from the vendored module rather than re-declared.
  /** The XML Signature namespace. */
  DS_NS: xmldsig.DS_NS,
  /** The XML Encryption namespace. */
  XENC_NS: xmldsig.XENC_NS,
  /** The XML Encryption 1.1 namespace. */
  XENC11_NS: xmldsig.XENC11_NS,
  /** The exclusive canonicalization algorithm URI. */
  C14N_EXCLUSIVE: xmldsig.C14N_EXCLUSIVE,
  /** The enveloped-signature transform URI. */
  TRANSFORM_ENVELOPED: xmldsig.TRANSFORM_ENVELOPED,
  /** The RSA-SHA256 signature method URI. */
  SIG_RSA_SHA256: xmldsig.SIG_ALG_RSA_SHA256,
  /** The SHA-256 digest method URI. */
  DIGEST_SHA256: xmldsig.XENC_NS + 'sha256',
  // The vendored engine itself, for the two pages that expose a general XML
  // signature tool and need its algorithm tables. Everything else here should
  // use the six functions above.
  xmldsig: xmldsig
};
