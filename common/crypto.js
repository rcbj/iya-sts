// @ts-check
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
const forge = require('node-forge');
// The DER writer for the post-quantum certificate below. node-forge cannot
// represent an ML-DSA key at all, so that one certificate is built by hand.
const asn1js = require('asn1js');
const jwt = require('jsonwebtoken');
const bunyan = require('bunyan');
const config = require('./config');
const pqJose = require('./pq_jose');

// ---------------------------------------------------------------------------
// REQUIRED FOR ITS EFFECT, and the effect is the point: loading the pool is
// what hands pq_jose.js the pool to use, so this line is why signJwsAsync()
// below computes in a child process rather than in this one. See the foot of
// common/worker_pool.js, which explains why the reference goes that way round
// and why a worker process is never armed by it.
//
// This module is where the line belongs because this module is what routes an
// `alg` to pq_jose.js in the first place — every path that can reach a
// post-quantum signature comes through here.
//
// **THE VALUE IS KEPT NOW, AND WAS DISCARDED UNTIL 2026-09-07.** The effect
// above is still the reason the line is here, but `hashSecretAsync()` below
// hands the pool a job DIRECTLY rather than through pq_jose.js — a scrypt
// derivation is not a JOSE operation and routing it through that module would
// have put a password in a file about post-quantum signing. Requiring it twice
// would be the same module object either way; naming it says that this file
// uses the pool as well as arming it.
// ---------------------------------------------------------------------------
const workerPool = require('./worker_pool');
const xmldom = require('@xmldom/xmldom');
// THE FAILURE CODES. A LEAF with no requires, so this file stays one (rule 3r).
// A verdict that refuses carries its code NON-ENUMERABLY — `errorCodes.mark()`
// puts it under a Symbol — so no member a caller compares or serialises moves;
// a caller that wants the condition's name reads it with `codeOf()`.
const errorCodes = require('./error_codes');

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
function signXml(xml, opts) {
  log.debug("Entering signXml().");
  const options = opts || {};
  const what = options.what || 'XML document';
  log.debug('Entering signXml(). what=' + what + ', placement=' +
            (options.placement || PLACEMENT.AFTER_ISSUER));
  if (!options.privateKeyPem) {
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

// Whether SHA-1 signatures are accepted. Read on every call: runtime.
function sha1Allowed() {
  log.debug("Entering sha1Allowed().");
  const on = config.value('saml.allowSha1Signatures') === true;
  log.debug("Leaving sha1Allowed(). " + on);
  return on;
}

// What a SignatureMethod and a set of DigestMethods amount to, before any
// cryptography: `{ problem, code, weak, sha1 }`. `problem` is '' when the
// algorithms are ones this file verifies and policy allows.
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
      'refused while saml.allowSha1Signatures is off';
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
function xmlSignatureKeyProblem(certificate) {
  log.debug("Entering xmlSignatureKeyProblem().");
  const found = verificationKeyFrom(certificate, null);
  if (found.problem) {
    log.debug("Leaving xmlSignatureKeyProblem(). Unreadable.");
    return found.problem;
  }
  const type = String(found.key.asymmetricKeyType || '');
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

// THE ONE PRIMITIVE: does `signature` verify over `octets` under
// `signatureMethod` with `key`? A key of the wrong type for the method is
// `false` — another registered certificate may be the right one — and never a
// throw. `pss` is pssParameters()'s answer for `rsa-pss`.
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
function signQueryString(queryString, privateKeyPem, sigAlg) {
  log.debug('Entering signQueryString().');
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
const BLOCK_CIPHERS = {
  'aes256-gcm': { uri: XENC11_NS + 'aes256-gcm', keyBytes: 32, mode: 'AES-GCM',
                  ivBytes: 12, tagBytes: 16 },
  'aes128-gcm': { uri: XENC11_NS + 'aes128-gcm', keyBytes: 16, mode: 'AES-GCM',
                  ivBytes: 12, tagBytes: 16 },
  'aes256-cbc': { uri: XENC_NS + 'aes256-cbc', keyBytes: 32, mode: 'AES-CBC',
                  ivBytes: 16, tagBytes: 0 },
  'aes128-cbc': { uri: XENC_NS + 'aes128-cbc', keyBytes: 16, mode: 'AES-CBC',
                  ivBytes: 16, tagBytes: 0 }
};

// The two key transports. `rsa-1_5` is RSAES-PKCS1-v1_5 and is offered because
// old service providers require it, not because it is safe.
const KEY_TRANSPORTS = {
  'rsa-oaep-mgf1p': { uri: XENC_NS + 'rsa-oaep-mgf1p', scheme: 'RSA-OAEP' },
  'rsa-1_5': { uri: XENC_NS + 'rsa-1_5', scheme: 'RSAES-PKCS1-V1_5' }
};

function cipherByUri(uri) {
  log.debug("Entering cipherByUri().");
  const name = Object.keys(BLOCK_CIPHERS).filter(function (key) {
    return BLOCK_CIPHERS[key].uri === uri;
  })[0];
  log.debug("Leaving cipherByUri().");
  return name ? Object.assign({ name: name }, BLOCK_CIPHERS[name]) : null;
}

function transportByUri(uri) {
  log.debug("Entering transportByUri().");
  const name = Object.keys(KEY_TRANSPORTS).filter(function (key) {
    return KEY_TRANSPORTS[key].uri === uri;
  })[0];
  log.debug("Leaving transportByUri().");
  return name ? Object.assign({ name: name }, KEY_TRANSPORTS[name]) : null;
}

// The forge options for a key transport. RSA-OAEP here is SHA-1/MGF1-SHA1,
// which is what `rsa-oaep-mgf1p` MEANS — the newer `rsa-oaep` URI carries its
// digest in a child element and is deliberately not offered, because a service
// provider that can do that can do GCM too and this list exists for the ones
// that cannot.
function transportOptions(transport) {
  log.debug("Entering transportOptions().");
  if (transport.scheme === 'RSA-OAEP') {
    log.debug("Leaving transportOptions().");
    return { md: forge.md.sha1.create(), mgf1: { md: forge.md.sha1.create() } };
  }
  log.debug("Leaving transportOptions().");
  return undefined;
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

function encryptElement(xml, certPem, opts) {
  log.debug("Entering encryptElement().");
  opts = opts || {};
  const wrapper = opts.wrapper || 'saml:EncryptedAssertion';
  const cipher = BLOCK_CIPHERS[opts.algorithm] || BLOCK_CIPHERS['aes256-gcm'];
  const transport = KEY_TRANSPORTS[opts.keyTransport] ||
                    KEY_TRANSPORTS['rsa-oaep-mgf1p'];
  artifact(opts, 'SAML 2.0 ' + wrapper, 'before encryption', xml);

  const cert = forge.pki.certificateFromPem(certPem);
  const key = forge.random.getBytesSync(cipher.keyBytes);
  const iv = forge.random.getBytesSync(cipher.ivBytes);
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
  const wrapped = cert.publicKey.encrypt(key, transport.scheme,
                                         transportOptions(transport));
  const certB64 = certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');

  const encrypted =
    '<' + wrapper + ' xmlns:saml="' + NS_SAML + '">' +
    '<xenc:EncryptedData xmlns:xenc="' + XENC_NS + '" Type="' + XENC_NS +
    'Element"><xenc:EncryptionMethod ' +
      'Algorithm="' + cipher.uri + '"/>' +
      '<ds:KeyInfo xmlns:ds="' + DS_NS + '">' +
        '<xenc:EncryptedKey>' +
          '<xenc:EncryptionMethod Algorithm="' + transport.uri + '">' +
            // The digest child belongs to OAEP and is meaningless under
            // RSA-1_5, so it is emitted only where it means something. A
            // service provider parsing strictly refuses the stray element.
            (transport.scheme === 'RSA-OAEP'
              ? '<ds:DigestMethod xmlns:ds="' + DS_NS + '" Algorithm="' +
                DS_NS + 'sha1"/>'
              : '') +
          '</xenc:EncryptionMethod>' +
          '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' + certB64 +
          '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' +
          '<xenc:CipherData><xenc:CipherValue>' + forge.util.encode64(wrapped) +
          '</xenc:CipherValue></xenc:CipherData>' +
        '</xenc:EncryptedKey>' +
      '</ds:KeyInfo>' +
      '<xenc:CipherData><xenc:CipherValue>' + forge.util.encode64(body) +
      '</xenc:CipherValue></xenc:CipherData>' +
    '</xenc:EncryptedData></' + wrapper + '>';

  artifact(opts, 'SAML 2.0 ' + wrapper,
           'after encryption (' + cipher.name + ', key wrapped with ' +
           transport.name + ')',
           encrypted);
  log.debug("Leaving encryptElement(). " + cipher.name + " / " +
            transport.name + ".");
  return encrypted;
}

// The original name, kept because WS-Trust calls it and its signature is part
// of that module's contract. It is now one line over encryptElement().
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

function decryptElement(xml, privateKeyPem, opts) {
  log.debug("Entering decryptElement().");
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
  const dataMethod = data.getElementsByTagNameNS('*', 'EncryptionMethod')[0];
  const cipher = cipherByUri(dataMethod ? dataMethod.getAttribute('Algorithm') :
                             '');
  if (!cipher) {
    log.debug("Leaving decryptElement(). Unknown block cipher.");
    return errorCodes.mark({ ok: false, why: 'the data is encrypted with ' +
             ((dataMethod && dataMethod.getAttribute('Algorithm')) || '(no ' +
                 'algorithm stated)') +
             ', and this service reads only ' +
             Object.keys(BLOCK_CIPHERS).join(', ') },
                           'STS-KEYS-0017');
  }
  const keyEl = data.getElementsByTagNameNS('*', 'EncryptedKey')[0];
  if (!keyEl) {
    // A <RetrievalMethod> pointing at an EncryptedKey elsewhere in the document
    // is legal and is not implemented: nothing this service issues produces
    // one, and saying so is more useful than a null dereference three lines
    // down.
    log.debug("Leaving decryptElement(). No EncryptedKey.");
    return errorCodes.mark({ ok: false, why: 'there is no ' +
             '<xenc:EncryptedKey> inside the KeyInfo. A key carried ' +
             'elsewhere and pointed at with <ds:RetrievalMethod> is legal ' +
             'and is not implemented here' }, 'STS-KEYS-0018');
  }
  const keyMethod = keyEl.getElementsByTagNameNS('*', 'EncryptionMethod')[0];
  const transport = transportByUri(keyMethod ?
                                   keyMethod.getAttribute('Algorithm') : '');
  if (!transport) {
    log.debug("Leaving decryptElement(). Unknown key transport.");
    return errorCodes.mark({ ok: false, why: 'the key is wrapped with ' +
             ((keyMethod && keyMethod.getAttribute('Algorithm')) || '(no ' +
                 'algorithm stated)') +
             ', and this service unwraps only ' +
             Object.keys(KEY_TRANSPORTS).join(', ') },
                           'STS-KEYS-0019');
  }
  // Two CipherValues: the wrapped key inside EncryptedKey, and the data. Read
  // the key's from the EncryptedKey subtree rather than from the document, or a
  // document whose EncryptedKey comes second yields the wrong one.
  const keyCipher = keyEl.getElementsByTagNameNS('*', 'CipherValue')[0];
  const dataCipherEls = data.getElementsByTagNameNS('*', 'CipherValue');
  let dataCipher = null;
  for (let n = 0; n < dataCipherEls.length; n++) {
    if (!keyEl.contains || !keyEl.contains(dataCipherEls[n])) {
      dataCipher = dataCipherEls[n];
    }
  }
  if (!keyCipher || !dataCipher) {
    log.debug("Leaving decryptElement(). A CipherValue is missing.");
    return errorCodes.mark({ ok: false, why: 'the element is missing one of ' +
             'its two <xenc:CipherValue>s — the wrapped key, or the ' +
             'data' }, 'STS-KEYS-0020');
  }

  try {
    const priv = forge.pki.privateKeyFromPem(privateKeyPem);
    const key = priv.decrypt(forge.util.decode64(
        (keyCipher.textContent || '').trim()),
                             transport.scheme, transportOptions(transport));
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
    const raw = forge.util.decode64((dataCipher.textContent || '').trim());
    const iv = raw.slice(0, cipher.ivBytes);
    const decipher = forge.cipher.createDecipher(cipher.mode, key);
    if (cipher.tagBytes) {
      const tag = raw.slice(raw.length - cipher.tagBytes);
      decipher.start({ iv: iv, tag: forge.util.createBuffer(tag),
                       tagLength: cipher.tagBytes * 8 });
      decipher.update(forge.util.createBuffer(
        raw.slice(cipher.ivBytes, raw.length - cipher.tagBytes)));
    } else {
      decipher.start({ iv: iv });
      decipher.update(forge.util.createBuffer(raw.slice(cipher.ivBytes)));
    }
    if (!decipher.finish()) {
      // For GCM this is the authentication tag failing, which means the
      // ciphertext was altered; for CBC it is the padding. They are different
      // facts and the message says which, because "decryption failed" sends
      // somebody looking at their key when the document was edited in transit.
      log.debug("Leaving decryptElement(). The cipher refused.");
      return errorCodes.mark({ ok: false, why: cipher.tagBytes
        ? 'the AES-GCM authentication tag did not verify, so the ciphertext ' +
          'was altered after it was encrypted'
        : 'the AES-CBC padding is not valid, so the key or the ciphertext is ' +
          'wrong' },
                             'STS-KEYS-0022');
    }
    const plain = forge.util.decodeUtf8(decipher.output.getBytes());
    // ---------------------------------------------------------------------
    // DOES IT PARSE? A cipher that finished is not a document that survived,
    // and the gap between those two is CBC's whole problem.
    //
    // AES-GCM is authenticated: an altered ciphertext fails the tag above and
    // never reaches here. AES-CBC IS NOT. Altering a byte of CBC ciphertext
    // corrupts one block, flips bits in the next, and quite often still leaves
    // valid PKCS#7 padding — so `finish()` returns true and hands back
    // plausible-looking rubbish. Measured, not assumed: flipping one character
    // of a CBC cipher value here returns the element TRUNCATED mid-tag, with no
    // error anywhere.
    //
    // So the plaintext is parsed before it is called a success. That is not
    // integrity — nothing can retrofit integrity onto unauthenticated CBC, and
    // this service offers CBC precisely because real service providers require
    // it — but it turns "here is your NameID" plus a crash two frames later
    // into one refusal that says what happened. A caller that wanted the bytes
    // whatever they are is not a caller this function has.
    if (!parsesAsFragment(plain)) {
      log.debug("Leaving decryptElement(). The plaintext is not XML.");
      return errorCodes.mark({ ok: false, why: 'the decryption produced ' +
               'something that is not well-formed ' +
               'XML' + (cipher.tagBytes ? '' : ', and ' + cipher.name + ' is ' +
               'UNAUTHENTICATED — an altered ciphertext can decrypt to ' +
               'rubbish with valid padding and no error, which is what a GCM ' +
               'algorithm would have caught') }, 'STS-KEYS-0023');
    }
    artifact(opts, 'SAML 2.0 encrypted element',
             'after decryption (' + cipher.name + ', key unwrapped with ' +
             transport.name + ')', plain);
    log.debug("Leaving decryptElement(). " + plain.length + " characters.");
    return { ok: true, xml: plain, algorithm: cipher.name,
             keyTransport: transport.name };
  } catch (e) {
    // forge throws on a key that will not unwrap at all, which is the RSA-OAEP
    // equivalent of the length check above. Swallowed into an answer for the
    // reason this whole function answers rather than throws.
    //
    // THE MESSAGE IS NOT ASSUMED TO BE ABOUT THE KEY, and that is a correction
    // rather than caution: this catch covers the decryption AND the parse, and
    // while it said "the wrapped key could not be unwrapped" unconditionally, a
    // NamespaceError from a perfectly good NameID was reported as a wrong
    // certificate — which sends somebody to re-fetch metadata over a bug in the
    // parser three lines away.
    const aboutTheKey = /oaep|padding|rsa|decrypt|key/i.test(e.message || '');
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
// AKP members and `THUMBPRINT_MEMBERS` carries them, 2026-09-13; DPoP still
// refuses these algorithms by name.)
pqJose.PQ_ALGS.forEach(function (alg) {
  JWS_ALGS[alg] = { family: 'pq', hash: null, kty: 'AKP', alg: alg,
                    ownSigner: true };
});

// Every signing algorithm, and the asymmetric ones — the split matters because
// several specifications say "an asymmetric algorithm, never a MAC and never
// none": DPoP proofs (RFC 9449 section 4.2), OID4VCI proofs of possession, and
// request objects are all in that class.
const JWS_SIGNING_ALGS = Object.keys(JWS_ALGS);
const JWS_ASYMMETRIC_ALGS = JWS_SIGNING_ALGS.filter(function (alg) {
  return JWS_ALGS[alg].family !== 'hmac';
});

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
    const pqSig = pqJose.sign(algorithm, key, Buffer.from(pqInput, 'ascii'));
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
    const signature = nodeCrypto.sign(spec.hash, Buffer.from(input, 'ascii'),
        nodeParamsFor(spec, key));
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
// Post-quantum signing is the one thing this service does that takes SECONDS —
// 14.6 and 15.4 of them were measured for a single SLH-DSA-SHAKE-128s token on
// 2026-08-29 — and node runs this service's six listener families on one
// thread, so for those seconds it answers nobody: not another HTTP caller, not
// the KDC on port 88. See common/worker.js.
//
// So the four call paths that can reach a post-quantum `alg` — the ID Token,
// the signed UserInfo response, a client assertion and an OID4VCI proof — call
// this instead, and it hands the computation to the pool. **EVERY OTHER
// ALGORITHM IS UNCHANGED AND IS NOT DEFERRED**: an RS256 signature is
// microseconds, so sending it to a child process would cost an IPC round trip
// to save nothing. Those resolve with the value signJws() computed, which is
// what lets a caller be written one way and not two.
//
// `opts.session` is passed through as the routing hint — see worker_pool.js.
// It is a preference and never a correctness requirement, so a caller with no
// session to name simply omits it.
// ---------------------------------------------------------------------------
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
    // never has to know which algorithms go to the pool.
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
  log.debug('Leaving signJwsAsync(). ' + algorithm + ', handed to the pool.');
  return pqJose.signAsync(algorithm, key, Buffer.from(input, 'ascii'),
                          { session: options.session })
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
// and 23.3 seconds on 2026-08-29 (see common/worker.js). So:
//
//   prepareVerification()  everything up to the check — and every refusal that
//                          is about the TOKEN rather than about the signature
//   verifyBytes()          the check itself, for everything but post-quantum
//   finishVerification()   the refusal for a signature that did not hold up,
//                          and the payload
//
// `verifyCompactJws()` below runs the three in a row exactly as it always did.
// `verifyCompactJwsAsync()` runs the same three with the post-quantum check
// handed to the pool. THE ORDER OF THE REFUSALS IS PART OF THE CONTRACT: a
// token whose `alg` is not in the caller's list is refused for that and never
// for its signature, whichever entry point was used.
// ---------------------------------------------------------------------------
function prepareVerification(token, key, options) {
  log.debug('Entering prepareVerification().');
  const parts = String(token || '').split('.');
  if (parts.length !== 3) {
    log.debug('Leaving prepareVerification(). Not three parts.');
    throw new Error('a compact JWS has three dot-separated parts; this has ' +
      parts.length + '.');
  }
  let header;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
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
    signature: Buffer.from(parts[2], 'base64url'),
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
    prepared.pub = (key && key.pub) ? Buffer.from(key.pub, 'base64url')
      : (typeof key === 'string' ? Buffer.from(key, 'base64url')
                                 : Buffer.from(key));
  }
  log.debug('Leaving prepareVerification(). alg=' + header.alg);
  return prepared;
}

// Everything but post-quantum, which is every algorithm whose check is
// microseconds and belongs in the process that is holding the request open.
function verifyBytes(prepared, key) {
  log.debug('Entering verifyBytes(). alg=' + prepared.header.alg);
  const spec = prepared.spec;
  const signingInput = prepared.signingInput;
  const signature = prepared.signature;
  if (spec.family === 'hmac') {
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

function verifyCompactJws(token, key, opts) {
  log.debug("Entering verifyCompactJws().");
  const options = opts || {};
  log.debug('Entering verifyCompactJws().');
  const prepared = prepareVerification(token, key, options);
  const ok = prepared.spec.family === 'pq'
    ? pqJose.verify(prepared.header.alg, prepared.pub, prepared.signingInput,
                    prepared.signature)
    : verifyBytes(prepared, key);
  const out = finishVerification(prepared, ok);
  log.debug('Leaving verifyCompactJws(). ' + prepared.header.alg +
            ' verified.');
  return out;
}

// The same verification with the post-quantum check handed to the pool. Every
// other algorithm resolves with what verifyCompactJws() computed, for the
// reason signJwsAsync() gives: an RS256 check is microseconds, and an IPC round
// trip to save that would be a cost with no saving.
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
  log.debug('Leaving verifyCompactJwsAsync(). Handed to the pool.');
  return pqJose.verifyAsync(prepared.header.alg, prepared.pub,
                            prepared.signingInput, prepared.signature,
                            { session: options.session })
    .then(function (ok) {
      return finishVerification(prepared, ok);
    });
}

// The claim checks `jsonwebtoken` performs, for the two algorithms it cannot
// verify. Written once, here, so that an EdDSA or ES256K token is held to
// exactly the same rules as an RS256 one — a token that skipped `exp` because
// of the curve it was signed on would be the worst kind of inconsistency.
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
    log.debug('Leaving verifyJwsAsync(). Handed to the pool.');
    return verifyCompactJwsAsync(token, key,
        { algorithms: allowed, session: options.session })
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
const JWE_RSA_ALGS = ['RSA-OAEP-256', 'RSA-OAEP'];
const JWE_ECDH_ALGS = ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW',
                       'ECDH-ES+A256KW'];
const JWE_AESKW_ALGS = ['A128KW', 'A192KW', 'A256KW'];
const JWE_AESGCMKW_ALGS = ['A128GCMKW', 'A192GCMKW', 'A256GCMKW'];
const JWE_PBES2_ALGS = ['PBES2-HS256+A128KW', 'PBES2-HS384+A192KW',
                        'PBES2-HS512+A256KW'];
const JWE_SYMMETRIC_ALGS = JWE_AESKW_ALGS.concat(JWE_AESGCMKW_ALGS,
                                                 JWE_PBES2_ALGS, ['dir']);
// The families that encrypt to a RECIPIENT'S PUBLIC KEY. Kept as a name of
// its own because it is what the three surfaces that encrypt OUTWARD may offer
// — a signed UserInfo response, an OID4VCI Credential Response, an encrypted
// assertion this service mints — and every one of them holds the recipient's
// JWKS and no shared secret. Advertising the symmetric families there would be
// a metadata member a client could register and this service would then try to
// satisfy by deriving a key from the JSON of a public key.
const JWE_ASYMMETRIC_ALGS = JWE_RSA_ALGS.concat(JWE_ECDH_ALGS);
const JWE_ALGS = JWE_ASYMMETRIC_ALGS.concat(JWE_SYMMETRIC_ALGS);
// **THE SAME LIST, AND THAT IS THE CHANGE.** It was `['RSA-OAEP-256']` on the
// argument that what arrives here is encrypted to the RSA key this service
// publishes — true of the one caller that existed then (OID4VCI's encrypted
// Credential Request) and false the moment a client could encrypt an assertion
// to a key of its own choosing. A caller now picks by what it HOLDS rather
// than by what this table permits, and `decryptJweCompact()` refuses by name
// when it was handed no key of the right kind.
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
  const decipher = nodeCrypto.createDecipheriv(spec.cipher, cek, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const out = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  log.debug('Leaving openContent(). GCM.');
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
function concatKdf(z, keyBytes, algId) {
  log.debug('Entering concatKdf(). algId=' + algId);
  const u32 = function (n) {
    log.debug("Entering u32().");
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n >>> 0);
    log.debug("Leaving u32().");
    return b;
  };
  const alg = Buffer.from(algId, 'utf8');
  const otherInfo = Buffer.concat([u32(alg.length), alg, u32(0), u32(0),
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

function aesKeyWrap(kek, plaintextKey) {
  log.debug('Entering aesKeyWrap().');
  const cipher = nodeCrypto.createCipheriv('id-aes' + (kek.length * 8) +
      '-wrap', kek, AES_KW_IV);
  const out = Buffer.concat([cipher.update(plaintextKey), cipher.final()]);
  log.debug('Leaving aesKeyWrap().');
  return out;
}

function aesKeyUnwrap(kek, wrapped) {
  log.debug('Entering aesKeyUnwrap().');
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

function wrapCek(alg, recipientJwk, cek, header) {
  log.debug('Entering wrapCek(). alg=' + alg);
  if (JWE_ALGS.indexOf(alg) === -1) {
    log.debug('Leaving wrapCek(). Unknown alg.');
    throw new Error('encryptJweCompact: unsupported alg "' + alg +
      '"; this service encrypts with ' + JWE_ALGS.join(', ') + '.');
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
    return { cek: concatKdf(z, cek.length, header.enc),
             encryptedKey: Buffer.alloc(0) };
  }
  const kek = concatKdf(z, ECDH_KW_BYTES[alg], alg);
  log.debug('Leaving wrapCek(). ' + alg + '.');
  return { cek: cek, encryptedKey: aesKeyWrap(kek, cek) };
}

function encryptJweCompact(plaintext, opts) {
  log.debug("Entering encryptJweCompact().");
  const options = opts || {};
  log.debug('Entering encryptJweCompact(). alg=' + (options.alg || JWE_ALG) +
            ', enc=' + options.enc);
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
  const wrapped = wrapCek(alg, keyMaterial, random, header);
  const headerB64 = b64u(Buffer.from(JSON.stringify(header), 'utf8'));

  const sealed = sealContent(spec, wrapped.cek, iv,
      Buffer.from(headerB64, 'ascii'), Buffer.from(plaintext, 'utf8'));

  const compact = [headerB64, b64u(wrapped.encryptedKey), b64u(iv),
                   b64u(sealed.ciphertext), b64u(sealed.tag)].join('.');
  log.debug('Leaving encryptJweCompact(). ' + compact.length + ' characters.');
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
      // A GCM decipher; the name is built, so the checker cannot see the mode.
      const decipher = /** @type {import('crypto').DecipherGCM} */ (
        nodeCrypto.createDecipheriv('aes-' + (kek.length * 8) + '-gcm', kek,
                                    Buffer.from(String(header.iv),
                                                'base64url')));
      decipher.setAuthTag(Buffer.from(String(header.tag), 'base64url'));
      const out = Buffer.concat([decipher.update(encryptedKey),
                                 decipher.final()]);
      log.debug('Leaving unwrapCek(). AES-GCM key wrap.');
      return out;
    }
    const out = aesKeyUnwrap(kek, encryptedKey);
    log.debug('Leaving unwrapCek(). AES key wrap.');
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
    const out = concatKdf(z, spec.cekBytes, header.enc);
    log.debug('Leaving unwrapCek(). ECDH-ES direct.');
    return out;
  }
  const kek = concatKdf(z, ECDH_KW_BYTES[alg], alg);
  const out = aesKeyUnwrap(kek, encryptedKey);
  log.debug('Leaving unwrapCek(). ' + alg + '.');
  return out;
}

// ---------------------------------------------------------------------------
// DECRYPT A COMPACT JWE. `opts`:
//
//   privateKey    a node KeyObject — RSA for the two RSA-OAEP algorithms, EC
//                 for the four ECDH-ES ones.
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
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
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

// ===========================================================================
// SECTION 5 — KEYS, CERTIFICATES, THUMBPRINTS
// ===========================================================================

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
               'repository pins 24.16.0 in its Dockerfile. Everything else ' +
               'here is unaffected: the POST-QUANTUM JOSE algorithms come ' +
               'from @noble/post-quantum and work on every runtime. It is ' +
               'the CERTIFICATE that needs OpenSSL.');
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
                    'which is node 24 — this repository pins 24.16.0. The ' +
                    'post-quantum JOSE algorithms are unaffected: they come ' +
                    'from @noble/post-quantum and need nothing of OpenSSL.');
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
const JWK_THUMBPRINT_URI_PREFIX =
  'urn:ietf:params:oauth:jwk-thumbprint:sha-256:';

function jwkThumbprintUri(jwk) {
  log.debug("Entering jwkThumbprintUri().");
  const uri = JWK_THUMBPRINT_URI_PREFIX + jwkThumbprint(jwk);
  log.debug("Leaving jwkThumbprintUri().");
  return uri;
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
// **A PER-RECORD SUBKEY, DERIVED WITH HKDF.** The KEK itself never encrypts
// anything: each record is encrypted under HKDF-SHA256(KEK, salt, info), where
// the salt is 16 random bytes stored with the record. Two reasons, and the
// second is the operational one: a single key encrypting many records under
// many IVs is one IV-reuse bug away from catastrophic in GCM, and a derived
// subkey per record means the same KEK can protect the whole store without any
// record's IV mattering to any other. The `info` string pins the PURPOSE, so a
// ciphertext from this store cannot be decrypted by a future caller deriving
// for something else.
//
// **THE STORED FORM IS SELF-DESCRIBING**, modelled on `hashSecret()` above and
// for the same reason: `$aesgcm$1$salt$iv$tag$ciphertext`, all base64. A
// version at the front so the scheme can change without a migration that has to
// guess what it is reading, and every parameter beside the data rather than in
// a constant somewhere that a later build might disagree about.
//
// **THE INFO STRING WAS `mock-sts key material v1` UNTIL 2026-09-12**, when
// the product name in every identifier this service stores and emits became
// `sts`. No migration was written, and that is a decision rather than an
// oversight: development data does not persist between runs, so nothing
// sealed under the old label ever has to be read back. **A PRODUCT deployment
// holding records sealed under the old label would need RE-KEYING** — the info
// is an HKDF input, so a record sealed under `mock-sts key material v1`
// derives a different subkey and cannot be opened under this one; `open()`
// would report it as undecryptable exactly as it reports a rotated KEK.
// ---------------------------------------------------------------------------

const KEK_INFO = 'sts key material v1';
const KEK_SALT_BYTES = 16;
const KEK_IV_BYTES = 12;      // NIST SP 800-38D's recommended GCM nonce length.
const KEK_KEY_BYTES = 32;     // AES-256.

// The KEK as bytes, however it arrived. A provider may hand back raw bytes, hex
// or base64 — a human pasting a secret into a vault writes text — so the shape
// is decided here, once, rather than by each of the five adapters.
//
// **A KEK SHORTER THAN 32 BYTES IS REFUSED RATHER THAN PADDED OR STRETCHED.**
// Stretching a short secret would let a four-character password protect every
// signing key this service holds while the log said AES-256, which is exactly
// the kind of comfortable lie this repository refuses everywhere else.
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
const KEK_PARAMETERS = {
  envelope: '$aesgcm$1$salt$iv$tag$ciphertext, each field base64',
  version: '1',
  cipher: 'aes-256-gcm',
  keyBits: KEK_KEY_BYTES * 8,
  ivBits: KEK_IV_BYTES * 8,
  tagBits: 128,
  kdf: 'HKDF-SHA256',
  kdfSaltBits: KEK_SALT_BYTES * 8,
  kdfInfo: KEK_INFO,
  perRecordSubkey: true
};

function encryptWithKek(kek, plaintext, label) {
  log.debug('Entering encryptWithKek().');
  const master = kekBytes(kek);
  const salt = nodeCrypto.randomBytes(KEK_SALT_BYTES);
  const subkey = nodeCrypto.hkdfSync('sha256', master, salt,
                                     Buffer.from(KEK_INFO, 'utf8'),
                                     KEK_KEY_BYTES);
  const iv = nodeCrypto.randomBytes(KEK_IV_BYTES);
  const cipher = nodeCrypto.createCipheriv('aes-256-gcm', Buffer.from(subkey),
                                           iv);
  const body = Buffer.concat([cipher.update(Buffer.from(String(plaintext),
                                                        'utf8')),
                              cipher.final()]);
  const tag = cipher.getAuthTag();
  const out = '$aesgcm$1$' + salt.toString('base64') + '$' +
              iv.toString('base64') + '$' + tag.toString('base64') + '$' +
              body.toString('base64');
  countKek(label, 'encryptions', Buffer.byteLength(String(plaintext), 'utf8'),
           body.length);
  log.debug('Leaving encryptWithKek(). ' + body.length + ' byte(s) of ' +
      'ciphertext.');
  return out;
}

function isEncryptedWithKek(stored) {
  log.debug("Entering isEncryptedWithKek().");
  log.debug("Leaving isEncryptedWithKek().");
  return /^\$aesgcm\$/.test(String(stored || ''));
}

function decryptWithKek(kek, stored, label) {
  log.debug('Entering decryptWithKek().');
  const parts = String(stored || '').split('$');
  // `$aesgcm$1$salt$iv$tag$body` splits to ['', 'aesgcm', '1', s, i, t, b].
  //
  // **THE TWO REFUSALS BELOW COUNT AS FAILURES AND THE ONE AT THE BOTTOM DOES
  // TOO, which is a deliberate flattening.** A caller cannot tell them apart
  // and neither should the figure: what a reader of that number wants to know
  // is *how often did this service fail to read something it had written*, and
  // splitting it into wrong-shape, wrong-version and wrong-key would be three
  // columns of which two are always zero.
  if (parts.length !== 7 || parts[1] !== 'aesgcm') {
    countKek(label, 'failures', 0, 0);
    throw new Error('this is not a record encrypted by this service');
  }
  if (parts[2] !== '1') {
    countKek(label, 'failures', 0, 0);
    throw new Error('the record names encryption version "' + parts[2] +
                    '", which this build does not know how to read');
  }
  const master = kekBytes(kek);
  const salt = Buffer.from(parts[3], 'base64');
  const iv = Buffer.from(parts[4], 'base64');
  const tag = Buffer.from(parts[5], 'base64');
  const body = Buffer.from(parts[6], 'base64');
  const subkey = nodeCrypto.hkdfSync('sha256', master, salt,
                                     Buffer.from(KEK_INFO, 'utf8'),
                                     KEK_KEY_BYTES);
  const decipher = nodeCrypto.createDecipheriv('aes-256-gcm',
                                               Buffer.from(subkey), iv);
  decipher.setAuthTag(tag);
  // THROWS ON A BAD TAG, and that is the whole point of GCM here: the caller
  // gets an error rather than the wrong key.
  // **THE `final()` IS WRAPPED SO THAT A BAD TAG IS COUNTED AND STILL
  // THROWS.** The throw is the whole point of GCM here and must not be
  // softened into a return: `keystore.js` turns it into a fatal at startup,
  // because a service that cannot read its own signing key must not come up
  // generating a new one and silently invalidating every token it ever issued.
  // Counting it costs nothing and is the figure an operator who has just
  // rotated a key-encryption key actually wants.
  let out = null;
  try {
    out = Buffer.concat([decipher.update(body), decipher.final()]);
  } catch (e) {
    countKek(label, 'failures', 0, 0);
    log.debug('Leaving decryptWithKek(). It would not open.');
    throw e;
  }
  countKek(label, 'decryptions', out.length, body.length);
  log.debug('Leaving decryptWithKek(). ' + out.length + ' byte(s).');
  return out.toString('utf8');
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
// client points at a post-quantum algorithm. See common/worker.js.
//
// The sync door is kept and is not deprecated: `workers.count = 0` is a
// supported configuration, the parent project loads this tree in process, and
// a caller that cannot be made asynchronous is better off blocking than
// wrong. Both doors produce the same stored form, because there is one
// definition of it.
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

// The one line that goes to a worker, and the only place either async door
// differs from its sync twin. `opts.session` is the pool's routing hint and
// may be omitted — see worker_pool.js; it is a preference and never a
// correctness requirement, because a worker remembers nothing.
function deriveAsync(plaintext, spec, opts) {
  log.debug('Entering deriveAsync(). N=' + spec.N);
  log.debug("Leaving deriveAsync().");
  return workerPool.run('scrypt.derive', {
    plaintext: String(plaintext == null ? '' : plaintext),
    salt: Buffer.from(spec.salt), keylen: spec.keylen,
    N: spec.N, r: spec.r, p: spec.p, maxmem: spec.maxmem
  }, opts).then(function (result) {
    log.debug('Leaving deriveAsync(). ' + result.derived.length + ' bytes.');
    return Buffer.from(result.derived);
  });
}

function hashSecretAsync(plaintext, opts) {
  log.debug('Entering hashSecretAsync().');
  const salt = nodeCrypto.randomBytes(SCRYPT_SALT_BYTES);
  // Read ONCE, here, and carried in the job — the worker holds no policy and
  // must be handed every parameter, and reading the setting again when the
  // answer comes back could encode different parameters from the ones the
  // derivation actually used.
  const cost = scryptParameters();
  const spec = { N: cost.N, r: cost.r, p: cost.p, salt: salt,
                 keylen: cost.keylen, maxmem: cost.maxmem };
  log.debug('Leaving hashSecretAsync(). Handed to the pool.');
  return deriveAsync(plaintext, spec, opts).then(function (derived) {
    return encodeStoredSecret(spec.N, spec.r, spec.p, salt, derived);
  }, function (e) {
    // THE POOL FAILED, SO IT IS COMPUTED HERE INSTEAD — see the block in
    // verifySecretAsync() below for why that is the right answer rather than
    // a fallback that hides something.
    log.warn(errorCodes.tag('STS-KEYS-0006') +
             'crypto: the worker pool could not derive a password hash and ' +
             'it is being computed in this process instead: ' + e.message);
    return hashSecret(plaintext);
  });
}

// Whether a stored value is one of ours. A directory this service did not seed
// may hold a `userPassword` in any of the forms RFC 4519 permits — including
// plaintext — and a verification that treated one of those as a scrypt string
// would refuse a correct password rather than saying it cannot read the value.
function isHashedSecret(stored) {
  log.debug("Entering isHashedSecret().");
  log.debug("Leaving isHashedSecret().");
  return /^\$scrypt\$/.test(String(stored || ''));
}

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
function verifySecretAsync(plaintext, stored, opts) {
  log.debug('Entering verifySecretAsync().');
  const spec = decodeStoredSecret(stored);
  if (!spec) {
    log.debug('Leaving verifySecretAsync(). Nothing readable is stored.');
    return Promise.resolve(false);
  }
  log.debug('Leaving verifySecretAsync(). Handed to the pool.');
  return deriveAsync(plaintext, spec, opts).then(function (derived) {
    return constantTimeEquals(derived, spec.expected);
  }, function (e) {
    // ---------------------------------------------------------------------
    // THE POOL FAILED, SO THE COMPARISON IS MADE HERE, and the alternative
    // that was written first is worth recording because it looked right.
    //
    // Answering `false` matches the sync twin's return shape — it answers
    // false for a stored value it cannot recompute — so it read as the
    // consistent choice. It is not: the sync twin has no worker to lose, so
    // `false` there always means "this password does not match this value",
    // while `false` here would ALSO mean "a child process died". That is a
    // person told their correct password is wrong, counted against the
    // sign-in rate limiter, on a service that is working.
    //
    // Computing it here is the answer the pool's own design already gives.
    // A worker holds no state, so a job it did not finish can simply be run
    // again — `workers.count = 0` runs every job in this process and is a
    // SUPPORTED configuration producing identical bytes, so this is that
    // configuration for one job. It blocks for 68ms, which is the cost of
    // being right.
    // ---------------------------------------------------------------------
    log.warn(errorCodes.tag('STS-KEYS-0006') +
             'crypto: the worker pool could not recompute a stored secret, ' +
             'so the comparison is being made in this process instead: ' +
             e.message);
    return verifySecret(plaintext, stored);
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
const RAW_SIGNATURE_FAMILIES = ['rsa-pkcs1', 'rsa-pss', 'ecdsa', 'eddsa',
                                'pq'];

// The curve sizes an ECDSA r||s signature is padded to.
const ECDSA_BYTES = { 'prime256v1': 32, 'secp384r1': 48, 'secp521r1': 66 };

// What a SubjectPublicKeyInfo holds, as a caller choosing a scheme needs to
// know it: `kind` is 'rsa', 'ec', 'ed25519', 'ed448' or 'pq', `key` the node
// KeyObject where node can read one, `curve` for EC, and `pqAlgorithm` (the
// vendored engine's name, 'ML-DSA-65') for a post-quantum key. `kind` is ''
// for anything else. Never throws.
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

// An ECDSA signature held as its two integers, big-endian and unpadded (Go's
// big.Int.Bytes(), an SSH mpint), as the r||s the primitive above takes.
// `curve` is node's name ('prime256v1'). null when either integer is longer
// than the curve allows.
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

// The SHA-256 of a file, streamed, lowercase hex — refusing one larger than
// `limit` bytes when `limit` is above 0 (SPIRE's `util.GetSHA256Digest()`,
// which the unix workload attestor hashes an executable with, #40). Rejects
// with a sentence.
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

module.exports = {
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
  cipherByUri: cipherByUri,
  transportByUri: transportByUri,
  // --- JWS / JWT ---
  signJws: signJws,
  verifyJws: verifyJws,
  // The three that hand a post-quantum computation to the worker pool and
  // resolve with exactly what their synchronous namesakes return. See
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
  JWS_ASYMMETRIC_ALGS: JWS_ASYMMETRIC_ALGS,
  jwsSpec: jwsSpec,
  protectedHeaderFor: protectedHeaderFor,
  verifyCompactJws: verifyCompactJws,
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
  certificateThumbprint: certificateThumbprint,
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
  encryptWithKek: encryptWithKek,
  decryptWithKek: decryptWithKek,
  kekAccounting: kekAccounting,
  KEK_PARAMETERS: KEK_PARAMETERS,
  isEncryptedWithKek: isEncryptedWithKek,
  kekBytes: kekBytes,
  verifySecret: verifySecret,
  verifySecretAsync: verifySecretAsync,
  isHashedSecret: isHashedSecret,
  // --- section 8: raw signatures and TPM 2.0 (#40) ---
  RAW_SIGNATURE_FAMILIES: RAW_SIGNATURE_FAMILIES,
  publicKeyFromSpki: publicKeyFromSpki,
  verifyRawSignature: verifyRawSignature,
  ecdsaIntegersToP1363: ecdsaIntegersToP1363,
  tpmKdfa: tpmKdfa,
  tpmMakeCredential: tpmMakeCredential,
  verifyPkcs7SignedData: verifyPkcs7SignedData,
  sha256OfFile: sha256OfFile,
  // --- the algorithm URIs, so that there is one spelling of each in the
  //     process. Taken from the vendored module rather than re-declared.
  DS_NS: xmldsig.DS_NS,
  XENC_NS: xmldsig.XENC_NS,
  XENC11_NS: xmldsig.XENC11_NS,
  C14N_EXCLUSIVE: xmldsig.C14N_EXCLUSIVE,
  TRANSFORM_ENVELOPED: xmldsig.TRANSFORM_ENVELOPED,
  SIG_RSA_SHA256: xmldsig.SIG_ALG_RSA_SHA256,
  DIGEST_SHA256: xmldsig.XENC_NS + 'sha256',
  // The vendored engine itself, for the two pages that expose a general XML
  // signature tool and need its algorithm tables. Everything else here should
  // use the six functions above.
  xmldsig: xmldsig
};
