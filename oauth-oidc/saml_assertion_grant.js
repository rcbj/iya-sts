'use strict';
//
// File: saml_assertion_grant.js
//
// ===========================================================================
// RFC 7522: A SAML 2.0 ASSERTION INSTEAD OF A CREDENTIAL.
//
// **THIS FILE IS `assertion_grant.js` FOR THE OTHER PROFILE OF RFC 7521, AND
// THE TWO ARE SEPARATE IMPLEMENTATIONS RATHER THAN ONE WITH A FORMAT FLAG.**
// That is the same decision `saml/CLAUDE.md` records about SAML 2.0 and SAML
// 1.1, made again for the same reason: the framework is shared and nothing
// else is. RFC 7523's assertion is a JWT — three base64url parts, a claim set,
// a JWS — and RFC 7522's is an XML document with an enveloped XML Signature, a
// `<Conditions>` element, a `<SubjectConfirmation>` and a `Recipient`
// attribute that has no JWT equivalent at all. There is no claim in RFC 7523
// that corresponds to `Recipient`, and no element in RFC 7522 that corresponds
// to `jti`; a shared implementation would be a `switch` in every check.
//
// What IS shared is the framework: `common/pki.js` issues the key pair, the
// replay rule is the same rule, the scope is narrowed the same way, and the
// issuer must be declared for the same reason. Those arguments are made in
// `assertion_grant.js` and are CITED here rather than repeated — with one
// exception, the registered-issuer refusal, which is repeated in full because
// it is the one thing here that refuses by default and a reader who arrives at
// this file first must not have to go and find it.
//
// ---------------------------------------------------------------------------
// TWO USES OF ONE FORMAT, AND THEY ARE NOT THE SAME FEATURE.
//
//   RFC 7522 section 2.1   AN AUTHORIZATION GRANT.
//                          `grant_type=…:saml2-bearer` + `assertion`. The
//                          assertion says WHO THE TOKEN IS FOR.
//
//   RFC 7522 section 2.2   CLIENT AUTHENTICATION.
//                          `client_assertion_type=…:saml2-bearer` +
//                          `client_assertion`. The assertion says WHO IS
//                          CALLING, and section 3 item 3B makes the `<Subject>`
//                          the `client_id`.
//
// Both are here, in ONE `verify()` with a `clientId` option, which is the
// opposite arrangement from RFC 7523's two files — and the reason is that the
// checks really are the same eleven checks. In RFC 7523 the two halves diverge
// at the KEY (a client secret may verify a client assertion, and nothing may
// verify a grant that way); in RFC 7522 there is no symmetric option at all,
// because XML Signature over a shared secret is not something any SAML
// implementation emits. So the only difference between the two sections here
// is what the Subject has to be, and that is one `if`.
//
// ---------------------------------------------------------------------------
// **THE KEY PAIRS ARE SEPARATE FROM RFC 7523's, PER APPLICATION, AND THAT IS
// THE DESIGN DECISION THIS FILE EXISTS TO ENFORCE.**
//
// An application may hold two key pairs issued by this realm's certificate
// authority: one for RFC 7523 (`oauthAssertion*`) and one for RFC 7522
// (`oauthSamlAssertion*`). They are two attribute sets that no code path
// crosses — this module NEVER reads `oauthAssertionCertificate` and
// `assertion_grant.js` never reads `oauthSamlAssertionCertificate` — so a key
// pair issued for one profile cannot sign for the other, and taking one off an
// application leaves the other working.
//
// **AND THAT IS WHY A BARE CERTIFICATE PATH IS NOT ENOUGH HERE, WHICH IS THE
// ONE PLACE THIS FILE IS STRICTER THAN `assertion_grant.js`.** Over there a
// signature may be verified with a key out of an `x5c` header once the chain
// has been shown to reach this realm's Root CA, and that is sound for a JWT:
// the chain is evidence this service issued the key. It would NOT be sound
// here, because it is evidence about the REALM and not about the application —
// so an application's RFC 7523 leaf, pasted into a SAML assertion's
// `<ds:KeyInfo>`, would chain perfectly and sign a SAML assertion. That is
// exactly the crossing the two attribute sets exist to prevent. So:
//
//   **a SAML assertion is verified ONLY against a certificate registered
//   against the asserting party under the RFC 7522 attributes.** A
//   `<ds:KeyInfo>` certificate is used to CHOOSE among those and never as a
//   key in its own right; one that matches none of them is refused by name.
//
// Nothing is lost by it. RFC 7523's chain path exists because a JWKS is the
// thing a client registers and a certificate is the awkward case; here the
// thing registered IS a certificate, so "present the certificate instead of
// registering it" saves nobody anything.
//
// ---------------------------------------------------------------------------
// EVERY ITEM OF RFC 7522 SECTION 3 IS IMPLEMENTED, and the list is here
// because "MAY" is where implementations quietly differ:
//
//   item 1   `<Issuer>`, compared by Simple String Comparison (RFC 3986
//            section 6.2.1) — which is what `===` on two strings is, and is
//            said out loud because SAML implementations are full of
//            case-folding and trailing-slash helpfulness that this one does
//            not do
//   item 2   `<Conditions><AudienceRestriction><Audience>` must name this
//            authorization server. REFUSED when it does not, and there is no
//            setting that turns that off
//   item 3   `<Subject>`; and for client authentication the `<NameID>` MUST be
//            the client_id
//   item 4   an expiry, from `<Conditions>` NotOnOrAfter or from a
//            `<SubjectConfirmationData>` NotOnOrAfter — EITHER satisfies it,
//            which is the item read literally
//   item 5   at least one bearer `<SubjectConfirmation>`; its `Recipient` is
//            checked against the token endpoint, its `NotOnOrAfter` is
//            required when it is the only expiry, and its `Address` is READ
//            AND REPORTED and never enforced (the item leaves it to the
//            server, and a mock refusing on a client's source address would be
//            refusing on a proxy's)
//   item 6   both NotOnOrAfter instants with the configured skew; a
//            `<SubjectConfirmation>` that has expired is DISCARDED and the
//            others still considered, which is the item's own distinction and
//            not a leniency; and the replay cache, on the assertion's `ID`
//   item 7   `<AuthnStatement>` — carried and REPORTED, never required. The
//            item is a SHOULD in both directions
//   item 8   `<AttributeStatement>` — every attribute is carried onto the
//            issued token, which is RFC 7523 claim 8's treatment of the same
//            thing
//   item 9   the signature. **REQUIRED, and it is the whole security of this
//            grant** — an unsigned assertion is refused by name
//   item 10  encrypted elements: a whole `<EncryptedAssertion>` is decrypted
//            with this realm's own key, and an `<EncryptedID>` in the Subject
//            is decrypted the same way
//   item 11  `<Conditions>` in full — NotBefore, and an unrecognised
//            `<Condition>` type, which SAML core section 2.5.1 makes Invalid
//            rather than ignorable
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3). It registers no route. It requires `helpers.js`,
// `config.js`, `applications.js`, `common/crypto.js` and `common/realms.js` —
// none of which requires it back — and it is required by `oauth2.js` (9) and
// by `client_auth.js`. **IT DOES NOT REQUIRE `assertion_grant.js` AND MUST
// NOT**: the two share a framework and no code, and a require between them
// would be the first step towards the format flag the header refuses.
// ===========================================================================

const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const realms = require('../common/realms');
const stsCrypto = require('../common/crypto');
const applications = require('../common/applications');
const config = require('../common/config');
const { log, STS } = require('../common/helpers');

// RFC 7522 section 2.1 and section 2.2. One value each, spelt once, because a
// caller that sends the wrong one is told which is expected rather than being
// told its assertion is invalid.
const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:saml2-bearer';
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:saml2-bearer';
// RFC 7521 section 4.2's error code, which is `invalid_grant` for section 2.1
// and `invalid_client` for section 2.2 — the same document refused for the
// same reason gets two codes depending on what it was being used AS. The
// mapping is `assertion_grant.js`'s note word for word, and it is true of both
// profiles because it is RFC 7521's rule rather than either profile's.
const GRANT_ERROR = 'invalid_grant';

// SAML 2.0 core, section 2.4.1.1. The one confirmation method this profile
// names (RFC 7522 section 3 item 5).
const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
// SAML core section 2.5.1. The condition types this service RECOGNISES —
// anything else makes the assertion Invalid rather than being ignored, which
// is item 11 and is the one check here that most implementations skip.
const KNOWN_CONDITIONS = ['AudienceRestriction', 'OneTimeUse', 'ProxyRestriction'];

// ---------------------------------------------------------------------------
// THE REPLAY CACHE. Per trust realm, like every other store here.
//
// **IT IS A THIRD CACHE, beside `client_auth.js`'s and
// `assertion_grant.js`'s**, and the argument for the second one is the
// argument for this one: a document used to authenticate a client and a
// document used to authorize an issuance are two different credentials. What
// is new here is that the identifier is an XML `ID` attribute rather than a
// `jti`, and the two namespaces have no reason to be disjoint — a SAML
// assertion whose ID happened to equal somebody's jti would otherwise spend
// it.
//
// BOTH SECTIONS SHARE THIS ONE, which is the opposite of the arrangement next
// door, and it is deliberate: the two RFC 7522 sections are verified by ONE
// function against ONE registered certificate set, so an assertion that would
// authenticate a client would also grant for it, and remembering it once is
// what stops the same document being spent twice under two parameter names.
// ---------------------------------------------------------------------------
const MAX_ASSERTIONS = 1000;
const seenAssertions = realms.map({ persist: 'saml_assertion_grant.seen' });

function forgetStaleAssertions() {
  log.debug('Entering forgetStaleAssertions().');
  const now = Date.now();
  seenAssertions.forEach(function (forgetAt, key) {
    if (forgetAt < now) {
      seenAssertions.delete(key);
    }
  });
  while (seenAssertions.size > MAX_ASSERTIONS) {
    const oldest = seenAssertions.keys().next();
    if (oldest.done) {
      break;
    }
    seenAssertions.delete(oldest.value);
  }
  log.debug('Leaving forgetStaleAssertions().');
}

function skewSeconds() {
  // THE SAME SETTING BOTH RFC 7523 SECTIONS USE, deliberately. It answers "how
  // far out may somebody else's clock be", and this service has no reason to
  // hold a different opinion about that because the document arrived as XML.
  return Number(config.value('oauth2.clientAssertionSkewS')) || 0;
}

function enabled() {
  return config.value('oauth2.saml2BearerGrant') !== false;
}

function requiresRegisteredIssuer() {
  return config.value('oauth2.saml2BearerRequireRegisteredIssuer') !== false;
}

function maxLifetimeSeconds() {
  const seconds = Number(config.value('oauth2.saml2BearerMaxLifetimeS'));
  return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) : 0;
}

// ---------------------------------------------------------------------------
// RFC 7522 SECTION 2.1: "The SAML Assertion XML data MUST be encoded using
// base64url ... and where the padding bits are set to zero."
//
// **BOTH ENCODINGS ARE ACCEPTED AND THE STANDARD ONE IS WARNED ABOUT**, which
// is this service's usual shape: the specification is quoted at the caller and
// the caller is not stopped. Several widely-deployed SAML stacks emit standard
// base64 here — the assertion is base64 everywhere else in SAML, so the
// profile's one deviation is easy to miss — and a mock that refused it would
// send a client author looking at their signature code.
//
// Node's base64url decoder accepts `+` and `/` silently, so the two cannot be
// told apart after the fact. They are told apart BEFORE: `-` or `_` says
// base64url, `+` or `/` says standard, and neither says it does not matter.
// ---------------------------------------------------------------------------
function decode(presented) {
  log.debug('Entering decode().');
  const text = String(presented || '').trim();
  if (!text) {
    log.debug('Leaving decode(). Nothing was presented.');
    return { ok: false, why: 'no assertion was presented.' };
  }
  let xml = '';
  try {
    xml = Buffer.from(text.replace(/\s+/g, ''), 'base64url').toString('utf8');
  } catch (e) {
    log.debug('Leaving decode(). It is not base64.');
    return { ok: false, why: 'the assertion is not base64url: ' + e.message };
  }
  if (/[+/]/.test(text) && !/[-_]/.test(text)) {
    log.warn('saml_assertion_grant: an assertion arrived in STANDARD base64. ' +
             'RFC 7522 section 2.1 asks for base64url (RFC 4648 section 5). ' +
             'It decoded, so it is accepted — but a stricter authorization ' +
             'server will refuse it.');
  }
  if (xml.indexOf('<') < 0) {
    // A caller that sent the raw XML unencoded is the commonest first mistake
    // with this grant, and "the assertion is not XML" would send them looking
    // at their document. This says which layer is wrong.
    log.debug('Leaving decode(). The base64 did not decode to XML.');
    return { ok: false, why: 'the `assertion` parameter decoded to something ' +
             'that is not XML. RFC 7522 section 2.1 says the SAML Assertion ' +
             'is carried base64url-encoded; XML sent as-is arrives here as ' +
             'nonsense because base64 will decode almost anything.' };
  }
  log.debug('Leaving decode(). ' + xml.length + ' characters of XML.');
  return { ok: true, xml: xml };
}

// The value of an attribute on an element, as a string, with no undefined.
function attr(el, name) {
  const value = el && el.getAttribute ? el.getAttribute(name) : '';
  return value === null || value === undefined ? '' : String(value);
}

function childrenByLocal(parent, local) {
  const out = [];
  if (!parent || !parent.childNodes) {
    return out;
  }
  for (let i = 0; i < parent.childNodes.length; i++) {
    const node = parent.childNodes[i];
    if (node.nodeType === 1 && node.localName === local) {
      out.push(node);
    }
  }
  return out;
}

function firstByLocal(parent, local) {
  return childrenByLocal(parent, local)[0] || null;
}

function textOf(el) {
  return el ? String(el.textContent || '').trim() : '';
}

// ---------------------------------------------------------------------------
// RFC 7522 SECTION 3 ITEM 10 — AN ENCRYPTED ASSERTION.
//
// The whole document may arrive as `<saml:EncryptedAssertion>`, which is the
// direct analogue of RFC 7523 claim 10's nested JWT and is decrypted with the
// same key: this REALM's own private key, the one it publishes a certificate
// for. There is no symmetric option, for the header's reason.
//
// **A DOCUMENT THAT IS ONLY ENCRYPTED IS STILL REFUSED**, and the refusal is
// item 9's: encryption says nothing about who wrote a document. The check is
// not here — it is where the signature is checked, on the assertion that comes
// OUT of this — which is the ordering that makes an encrypted unsigned
// assertion fail for the right reason.
// ---------------------------------------------------------------------------
function decryptIfNeeded(xml) {
  log.debug('Entering decryptIfNeeded().');
  let doc = null;
  try {
    doc = new DOMParser().parseFromString(String(xml), 'text/xml');
  } catch (e) {
    log.debug('Leaving decryptIfNeeded(). It did not parse.');
    return { ok: false, why: 'the assertion is not well-formed XML: ' + e.message };
  }
  const root = doc && doc.documentElement;
  if (!root) {
    log.debug('Leaving decryptIfNeeded(). No root element.');
    return { ok: false, why: 'the assertion decoded to XML with no root element.' };
  }
  if (root.localName !== 'EncryptedAssertion') {
    log.debug('Leaving decryptIfNeeded(). Not encrypted.');
    return { ok: true, xml: String(xml), encrypted: false };
  }
  const opened = stsCrypto.decryptElement(String(xml), STS.privateKeyPem);
  if (!opened.ok) {
    log.debug('Leaving decryptIfNeeded(). It would not decrypt.');
    return { ok: false, why: 'this assertion arrived as a ' +
             '<saml:EncryptedAssertion> (RFC 7522 section 3 item 10) and ' +
             'could not be decrypted: ' + opened.why + '. It must be ' +
             'encrypted to the certificate this authorization server ' +
             'publishes.' };
  }
  log.debug('Leaving decryptIfNeeded(). Decrypted ' + opened.algorithm + '.');
  return { ok: true, xml: opened.xml, encrypted: true,
           encryption: { algorithm: opened.algorithm,
                         keyTransport: opened.keyTransport } };
}

// ---------------------------------------------------------------------------
// EVERY FACT THE CHECKS BELOW NEED, READ ONCE.
//
// It reads and does not decide, which is the split `verify()` depends on: the
// order the checks run in is RFC 7522 section 3's and is stated there, and a
// reader who fell into a parser would lose it.
//
// **NOTHING READ HERE IS BELIEVED UNTIL THE SIGNATURE HAS VERIFIED.** The
// issuer is used before then, for one purpose only — finding candidate
// certificates — which is the same single exception `assertion_grant.js`
// makes and for the same reason.
// ---------------------------------------------------------------------------
function read(xml) {
  log.debug('Entering read().');
  let doc = null;
  try {
    doc = new DOMParser().parseFromString(String(xml), 'text/xml');
  } catch (e) {
    log.debug('Leaving read(). It did not parse.');
    return { ok: false, why: 'the assertion is not well-formed XML: ' + e.message };
  }
  const root = doc && doc.documentElement;
  if (!root || root.localName !== 'Assertion') {
    log.debug('Leaving read(). The root is not an Assertion.');
    return { ok: false, why: 'RFC 7522 section 2.1: the `assertion` parameter ' +
             'carries a single SAML 2.0 <Assertion>. This document\'s root ' +
             'element is <' + ((root && root.localName) || 'nothing') + '>' +
             (root && root.localName === 'Response'
               ? ' — a <Response> is the browser profile\'s envelope and this ' +
                 'profile takes the assertion out of it'
               : '') + '.' };
  }

  const subject = firstByLocal(root, 'Subject');
  const nameId = subject ? firstByLocal(subject, 'NameID') : null;
  const encryptedId = subject ? firstByLocal(subject, 'EncryptedID') : null;
  // RFC 7522 section 3 item 10 again, one element down. Decrypted here rather
  // than in decryptIfNeeded() because it is INSIDE the signed document: taking
  // it out before the signature is checked would be verifying a document this
  // service had edited.
  let nameIdValue = textOf(nameId);
  let nameIdFormat = attr(nameId, 'Format');
  let idWasEncrypted = false;
  if (!nameId && encryptedId) {
    const opened = stsCrypto.decryptElement(
      new XMLSerializer().serializeToString(encryptedId), STS.privateKeyPem);
    if (opened.ok) {
      const inner = new DOMParser().parseFromString(opened.xml, 'text/xml');
      const el = inner && inner.documentElement;
      nameIdValue = textOf(el);
      nameIdFormat = attr(el, 'Format');
      idWasEncrypted = true;
    } else {
      log.warn('saml_assertion_grant: an assertion carried an <EncryptedID> ' +
               'that would not decrypt (' + opened.why + '). The subject is ' +
               'read as absent, which is what the refusal below will say.');
    }
  }

  const confirmations = (subject ? childrenByLocal(subject, 'SubjectConfirmation') : [])
    .map(function (sc) {
      const data = firstByLocal(sc, 'SubjectConfirmationData');
      return {
        method: attr(sc, 'Method'),
        hasData: !!data,
        recipient: attr(data, 'Recipient'),
        notOnOrAfter: attr(data, 'NotOnOrAfter'),
        notBefore: attr(data, 'NotBefore'),
        inResponseTo: attr(data, 'InResponseTo'),
        address: attr(data, 'Address')
      };
    });

  const conditionsEl = firstByLocal(root, 'Conditions');
  const audiences = [];
  const unknownConditions = [];
  if (conditionsEl) {
    for (let i = 0; i < conditionsEl.childNodes.length; i++) {
      const node = conditionsEl.childNodes[i];
      if (node.nodeType !== 1) {
        continue;
      }
      if (node.localName === 'AudienceRestriction') {
        childrenByLocal(node, 'Audience').forEach(function (one) {
          const value = textOf(one);
          if (value) {
            audiences.push(value);
          }
        });
      } else if (KNOWN_CONDITIONS.indexOf(node.localName) < 0) {
        // SAML core section 2.5.1: a condition an implementation does not
        // understand makes the assertion Invalid. Recorded by NAME rather than
        // counted, because the refusal has to say which one.
        unknownConditions.push(node.localName === 'Condition'
          ? (attr(node, 'xsi:type') || attr(node, 'type') || 'Condition')
          : node.localName);
      }
    }
  }

  const attributes = {};
  childrenByLocal(root, 'AttributeStatement').forEach(function (statement) {
    childrenByLocal(statement, 'Attribute').forEach(function (one) {
      const name = attr(one, 'Name');
      if (!name) {
        return;
      }
      const values = childrenByLocal(one, 'AttributeValue').map(textOf);
      // ACCUMULATED rather than replaced. Two <Attribute> elements with one
      // Name is legal SAML and is how a multi-valued attribute is spelt by
      // about half the implementations that emit one; taking the last would
      // silently drop the rest.
      attributes[name] = (attributes[name] || []).concat(
        values.length ? values : ['']);
    });
  });

  const signature = firstByLocal(root, 'Signature');
  let keyInfoCertificate = '';
  if (signature) {
    const keyInfo = firstByLocal(signature, 'KeyInfo');
    const x509Data = keyInfo ? firstByLocal(keyInfo, 'X509Data') : null;
    const x509 = x509Data ? firstByLocal(x509Data, 'X509Certificate') : null;
    keyInfoCertificate = textOf(x509).replace(/\s+/g, '');
  }

  const out = {
    ok: true,
    // TRIMMED, AND THAT IS NOT TIDINESS. An `ID` is an xsd:ID, and XML
    // attribute-value normalisation strips leading and trailing whitespace
    // from a non-CDATA attribute — which this parser does not do, because it
    // has no schema to tell it the type. Untrimmed, an assertion carrying
    // `ID=" "` passed the "is there an ID" check below and every such
    // assertion in the realm then shared ONE replay key: the first is
    // remembered and every other one from that issuer is refused as a replay
    // of a document it has never seen. `tests/saml_assertion_grant.js` sends
    // exactly that, and found it.
    id: attr(root, 'ID').trim(),
    version: attr(root, 'Version'),
    issueInstant: attr(root, 'IssueInstant'),
    issuer: textOf(firstByLocal(root, 'Issuer')),
    hasSubject: !!subject,
    subject: nameIdValue,
    nameIdFormat: nameIdFormat,
    subjectWasEncrypted: idWasEncrypted,
    confirmations: confirmations,
    hasConditions: !!conditionsEl,
    notBefore: attr(conditionsEl, 'NotBefore'),
    notOnOrAfter: attr(conditionsEl, 'NotOnOrAfter'),
    audiences: audiences,
    unknownConditions: unknownConditions,
    attributes: attributes,
    authnStatements: childrenByLocal(root, 'AuthnStatement').length,
    signed: !!signature,
    keyInfoCertificate: keyInfoCertificate
  };
  log.debug('Leaving read(). issuer=' + out.issuer + ', id=' + out.id);
  return out;
}

// A base64 DER body as a PEM certificate. The `<ds:X509Certificate>` element
// and an `x5c` member carry exactly the same bytes in exactly the same
// encoding, which is why this looks like `assertion_grant.js`'s `pem()`.
function pemFrom(b64) {
  return '-----BEGIN CERTIFICATE-----\n' +
         String(b64).replace(/\s+/g, '').replace(/(.{64})/g, '$1\n')
           .replace(/\n$/, '') +
         '\n-----END CERTIFICATE-----\n';
}

function thumbprintOf(pem) {
  try {
    return stsCrypto.certificateThumbprint(pem, { format: 'base64url' });
  } catch (e) {
    // An unreadable certificate has no thumbprint and must not match one.
    // Swallowed rather than thrown because the caller is comparing a list and
    // one bad member is not a reason to refuse the others.
    log.debug('thumbprintOf(): a certificate could not be read: ' + e.message);
    return '';
  }
}

// ---------------------------------------------------------------------------
// WHICH CERTIFICATES MAY HAVE SIGNED AN ASSERTION FROM THIS PARTY.
//
// TWO ATTRIBUTES AND THEY ARE ORed, which is `keysForParty()`'s decision next
// door made again for this profile:
//
//   `oauthSamlAssertionSigningCertificate`  what the party REGISTERED, by
//                                           value. The analogue of `jwks`, and
//                                           what a party with a key of its own
//                                           uses.
//   `oauthSamlAssertionCertificate`         what THIS SERVICE ISSUED it for
//                                           RFC 7522, from its own certificate
//                                           authority.
//
// **NEITHER OF THEM IS `oauthAssertionJwks` OR `oauthAssertionCertificate`**,
// and that absence is the point of the file — see the header. It is also the
// reason this function exists at all rather than a shared one: a shared reader
// with a profile argument would be one edit away from reading both sets.
//
// An entry may hold SEVERAL registered certificates, newline-separated PEM
// blocks in one value, because a party rotating a certificate holds two for as
// long as assertions signed by the old one are still in flight.
// ---------------------------------------------------------------------------
function certificatesForParty(fields) {
  log.debug('Entering certificatesForParty().');
  const found = [];
  const problems = [];
  [['oauthSamlAssertionSigningCertificate', 'registered'],
   ['oauthSamlAssertionCertificate', 'issued']].forEach(function (pair) {
    const raw = fields ? fields[pair[0]] : '';
    const text = Array.isArray(raw) ? raw.join('\n') : String(raw || '');
    if (!text.trim()) {
      return;
    }
    const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    if (!blocks || !blocks.length) {
      problems.push(pair[0] + ': it holds no PEM certificate block');
      return;
    }
    blocks.forEach(function (pem) {
      const thumbprint = thumbprintOf(pem);
      if (!thumbprint) {
        problems.push(pair[0] + ': a certificate in it could not be read');
        return;
      }
      found.push({ pem: pem, source: pair[1], thumbprint: thumbprint });
    });
  });
  log.debug('Leaving certificatesForParty(). ' + found.length + ' certificate(s).');
  return { certificates: found, problems: problems };
}

// The application entry allowed to issue assertions under this `<Issuer>`.
// `oauthSamlAssertionIssuer` is the declaration; an application that declared
// none is found by its own identifier, for `issuerEntry()`'s reason next door —
// an assertion a client issues about itself names its own client_id, and
// asking an operator to write that down twice would be a configuration step
// with no decision in it.
function issuerEntry(iss) {
  log.debug('Entering issuerEntry(). iss=' + iss);
  // RFC 7522 section 3 item 1: Simple String Comparison, RFC 3986 section
  // 6.2.1. No case folding, no trailing-slash tolerance, no scheme
  // normalisation — which is what `===` is, and is said out loud because SAML
  // stacks are full of helpfulness this one deliberately does not have.
  const wanted = String(iss || '');
  if (!wanted) {
    log.debug('Leaving issuerEntry(). No issuer.');
    return null;
  }
  const all = applications.list();
  for (let i = 0; i < all.length; i++) {
    const fields = all[i].fields || {};
    const declared = fields.oauthSamlAssertionIssuer;
    const values = Array.isArray(declared) ? declared
      : (declared ? [String(declared)] : []);
    if (values.indexOf(wanted) >= 0) {
      log.debug('Leaving issuerEntry(). Declared by ' + all[i].identifier + '.');
      return { identifier: all[i].identifier, fields: fields, declared: true };
    }
  }
  const byClientId = applications.forClientId(wanted);
  if (byClientId) {
    log.debug('Leaving issuerEntry(). It is a client_id.');
    return { identifier: byClientId.identifier,
             fields: byClientId.fields || {}, declared: false };
  }
  const byIdentifier = applications.get(wanted);
  if (byIdentifier) {
    log.debug('Leaving issuerEntry(). It is an application identifier.');
    return { identifier: wanted, fields: byIdentifier.fields || {},
             declared: false };
  }
  log.debug('Leaving issuerEntry(). Nobody has declared it.');
  return null;
}

// xsd:dateTime to epoch milliseconds, or NaN. Written out rather than left to
// Date.parse alone so that "there was no attribute" and "the attribute was not
// a time" are different answers — a refusal naming a malformed NotOnOrAfter
// sends somebody to their template, and one naming a missing one sends them to
// the profile.
function instantOf(text) {
  if (!text) {
    return null;
  }
  const at = Date.parse(String(text));
  return isFinite(at) ? at : NaN;
}

function refuse(description) {
  return { ok: false, error: GRANT_ERROR, description: description };
}

// ---------------------------------------------------------------------------
// THE CHECKS, IN RFC 7522 SECTION 3's ORDER, WITH ONE THING FIRST.
//
// **THE SIGNATURE IS VERIFIED BEFORE ANY ELEMENT IS BELIEVED**, which is not
// the order section 3 lists them in and is the order they have to run in. That
// section's items are about `<Issuer>`, `<Subject>`, `<Conditions>` and
// `<SubjectConfirmation>`, and reading any of those out of an unverified
// document is reading what an attacker wrote. So the issuer is resolved from
// the unverified `<Issuer>` ONLY to find candidate certificates, nothing is
// decided on it, and every check below runs on a document a signature has
// already vouched for.
//
// `opts.clientId`, where it is set, puts this in RFC 7522 SECTION 2.2 —
// CLIENT AUTHENTICATION — which changes exactly two things: item 3B makes the
// Subject the client_id, and the certificates come from the caller (which
// already holds the client's entry) rather than from an issuer lookup.
// ---------------------------------------------------------------------------
async function verify(opts) {
  log.debug('Entering verify().');
  const options = opts || {};
  const audiences = (options.audiences || []).map(String);
  const asClient = !!options.clientId;

  if (!asClient && !enabled()) {
    log.debug('Leaving verify(). The grant is switched off.');
    return { ok: false, error: 'unsupported_grant_type',
             description: 'This authorization server does not perform the ' +
                          'SAML 2.0 bearer grant (RFC 7522 section 2.1). ' +
                          'oauth2.saml2BearerGrant is off.' };
  }

  const decoded = decode(options.assertion);
  if (!decoded.ok) {
    log.debug('Leaving verify(). It would not decode.');
    return { ok: false, error: asClient ? 'invalid_client' : 'invalid_request',
             description: 'grant_type="' + GRANT_TYPE + '" takes a base64url ' +
                          'SAML 2.0 Assertion (RFC 7522 section 2.1): ' +
                          decoded.why };
  }

  // --- RFC 7522 section 3 item 10: it may be encrypted ----------------------
  const opened = decryptIfNeeded(decoded.xml);
  if (!opened.ok) {
    log.debug('Leaving verify(). It would not decrypt.');
    return refuse(opened.why);
  }
  const xml = opened.xml;

  const parsed = read(xml);
  if (!parsed.ok) {
    log.debug('Leaving verify(). It would not parse.');
    return refuse(parsed.why);
  }
  if (parsed.version && parsed.version !== '2.0') {
    // SAML 1.1 assertions exist here — `saml/saml11.js` builds them — and this
    // profile is not about them. Named rather than left to fail somewhere in
    // the Conditions, because the two documents look alike enough that
    // somebody will send the wrong one.
    log.debug('Leaving verify(). Not a SAML 2.0 assertion.');
    return refuse('this assertion says Version="' + parsed.version + '". RFC ' +
                  '7522 is the SAML 2.0 profile of RFC 7521 and this ' +
                  'authorization server reads Version="2.0" here. A SAML 1.1 ' +
                  'assertion has no profile of RFC 7521 at all.');
  }

  // --- item 1: the issuer ---------------------------------------------------
  const iss = parsed.issuer;
  if (!iss) {
    log.debug('Leaving verify(). No issuer.');
    return refuse('RFC 7522 section 3 item 1: an assertion must carry an ' +
                  '<Issuer> naming the entity that issued it.');
  }

  // --- Which certificates could have signed it ------------------------------
  let party = null;
  let certificates = [];
  let problems = [];
  if (asClient) {
    // SECTION 2.2. The caller holds the client's entry and hands the two
    // attributes over, so there is no lookup to do: the client_id came from
    // the request and the certificates are that client's.
    const read2 = certificatesForParty({
      oauthSamlAssertionSigningCertificate: options.registeredCertificate || '',
      oauthSamlAssertionCertificate: options.issuedCertificate || ''
    });
    certificates = read2.certificates;
    problems = read2.problems;
  } else {
    party = issuerEntry(iss);
    if (party) {
      const read2 = certificatesForParty(party.fields);
      certificates = read2.certificates;
      problems = read2.problems;
    }
    if (!party && requiresRegisteredIssuer()) {
      // THE ONE REFUSAL THAT IS NOT ABOUT THE DOCUMENT, and it is written out
      // in full rather than citing `assertion_grant.js` — see the header. An
      // assertion IS the whole authorization here too.
      log.warn('saml_assertion_grant: a SAML 2.0 bearer grant was presented ' +
               'for Issuer="' + iss + '", which no application in this realm ' +
               'has declared. Refused.');
      log.debug('Leaving verify(). Nobody has declared that issuer.');
      return refuse('no application in this realm is registered to issue SAML ' +
                    '2.0 assertions as "' + iss + '". This grant cannot be ' +
                    'permissive: an assertion IS the whole authorization — ' +
                    'there is no browser, no password and no consent step in ' +
                    'it — so accepting one from anybody would mean anybody ' +
                    'who can reach this port getting an access token as ' +
                    'anybody. Declare the issuer on an application entry as ' +
                    '`oauthSamlAssertionIssuer`, and give it a certificate ' +
                    'on `oauthSamlAssertionSigningCertificate` or a key pair ' +
                    'issued for RFC 7522 from /admin/pki. ' +
                    '`oauth2.saml2BearerRequireRegisteredIssuer` turns this ' +
                    'refusal off, and reading what it says before doing so is ' +
                    'the point of it having a description.');
    }
  }
  if (!certificates.length) {
    log.debug('Leaving verify(). No certificate to try.');
    return refuse(problems.length
      ? problems.join('; ') + '.'
      : 'there is no certificate registered against "' +
        (asClient ? options.clientId : iss) + '" to verify this SAML ' +
        'assertion with. Put one on the application entry as ' +
        '`oauthSamlAssertionSigningCertificate`, or issue it an RFC 7522 ' +
        'signing key pair from /admin/pki. **The RFC 7523 key pair is not ' +
        'read here**: the two profiles hold separate key pairs on purpose, so ' +
        'an application with only a JWT one has nothing registered for this.');
  }

  // --- item 9: the signature ------------------------------------------------
  if (!parsed.signed) {
    log.debug('Leaving verify(). It is not signed.');
    return refuse('RFC 7522 section 3 item 9: the assertion MUST be digitally ' +
                  'signed or have a MAC applied by the issuer, and this one ' +
                  'carries no <ds:Signature> of its own. An unsigned ' +
                  'assertion is a request to issue a token for anybody who ' +
                  'asks.' +
                  (opened.encrypted
                    ? ' It WAS encrypted, and encryption does not stand in ' +
                      'for a signature: an encrypted document says nothing ' +
                      'about who wrote it.'
                    : ''));
  }
  // **A CERTIFICATE THAT ARRIVED WITH THE SIGNATURE IS NOT EVIDENCE**, and
  // here it is not even a fallback — see the header. It narrows the candidate
  // list and a value matching none of it is refused by name, because "the
  // signature did not verify" would send somebody to look at their signing
  // code when what is wrong is which key they registered.
  let narrowed = certificates;
  if (parsed.keyInfoCertificate) {
    const presented = thumbprintOf(pemFrom(parsed.keyInfoCertificate));
    narrowed = certificates.filter(function (one) {
      return one.thumbprint === presented;
    });
    if (!narrowed.length) {
      log.debug('Leaving verify(). The KeyInfo certificate is not registered.');
      return refuse('this assertion carries a certificate in its ' +
                    '<ds:KeyInfo> that is not registered against "' +
                    (asClient ? options.clientId : iss) + '" for RFC 7522. A ' +
                    'certificate that arrives WITH a signature proves nothing ' +
                    'on its own, and this profile does not accept one merely ' +
                    'because it chains to this realm\'s certificate authority ' +
                    '— that would let any key pair this realm ever issued, ' +
                    'the application\'s own RFC 7523 one included, sign a ' +
                    'SAML assertion. Register it on ' +
                    '`oauthSamlAssertionSigningCertificate`.');
    }
  }
  let verified = null;
  let usedCertificate = null;
  let lastWhy = '';
  for (let i = 0; i < narrowed.length && !verified; i++) {
    const result = stsCrypto.verifyXmlSignature(xml, {
      // NAMED, and it is the whole reason this service has a verifier of its
      // own — see `common/crypto.js`. An assertion that carried a second
      // signed element would otherwise be checked at whichever one came
      // first in document order.
      element: 'Assertion',
      certPem: narrowed[i].pem
    });
    if (result.ok) {
      verified = result;
      usedCertificate = narrowed[i];
    } else {
      lastWhy = result.why || 'it did not verify';
    }
  }
  if (!verified) {
    log.debug('Leaving verify(). The signature did not verify.');
    return refuse('the signature on this assertion did not verify against ' +
                  (narrowed.length === 1 ? 'the certificate' :
                   'any of the ' + narrowed.length + ' certificates') +
                  ' registered against "' + (asClient ? options.clientId : iss) +
                  '" for RFC 7522: ' + lastWhy + '.');
  }

  // === From here on the document has been vouched for. ======================

  // --- item 11 and item 6: the Conditions -----------------------------------
  if (parsed.unknownConditions.length) {
    return refuse('this assertion carries a <Condition> this authorization ' +
                  'server does not understand (' +
                  parsed.unknownConditions.join(', ') + '). SAML 2.0 core ' +
                  'section 2.5.1 makes an assertion Invalid when a condition ' +
                  'cannot be evaluated, and RFC 7522 section 3 item 11 says ' +
                  'the assertion must be valid in all other respects per that ' +
                  'specification — so it is refused rather than ignored.');
  }
  const now = Date.now();
  const skewMs = skewSeconds() * 1000;
  const notBefore = instantOf(parsed.notBefore);
  if (isNaN(notBefore)) {
    return refuse('this assertion\'s <Conditions> NotBefore is "' +
                  parsed.notBefore + '", which is not an xsd:dateTime.');
  }
  if (notBefore !== null && now + skewMs < notBefore) {
    return refuse('this assertion is not valid until ' +
                  new Date(notBefore).toISOString() + ' and it is now ' +
                  new Date(now).toISOString() + '. This authorization server ' +
                  'allows ' + skewSeconds() + ' seconds of clock difference ' +
                  '(oauth2.clientAssertionSkewS).');
  }
  const conditionsExpiry = instantOf(parsed.notOnOrAfter);
  if (isNaN(conditionsExpiry)) {
    return refuse('this assertion\'s <Conditions> NotOnOrAfter is "' +
                  parsed.notOnOrAfter + '", which is not an xsd:dateTime.');
  }
  if (conditionsExpiry !== null && now - skewMs >= conditionsExpiry) {
    return refuse('this assertion expired at ' +
                  new Date(conditionsExpiry).toISOString() +
                  ' (its <Conditions> NotOnOrAfter). RFC 7522 section 3 item ' +
                  '6: the authorization server MUST reject the entire ' +
                  'assertion once that instant has passed.');
  }

  // --- item 2: the audience -------------------------------------------------
  // **NO SETTING TURNS THIS OFF**, which is item 2 read literally: "The
  // authorization server MUST reject any Assertion that does not contain its
  // own identity as the intended audience." It is what stops an assertion
  // minted for one authorization server being replayed at another.
  if (!parsed.hasConditions || !parsed.audiences.length) {
    return refuse('RFC 7522 section 3 item 2: an assertion must carry a ' +
                  '<Conditions> with an <AudienceRestriction> naming this ' +
                  'authorization server. This one names ' +
                  (parsed.hasConditions ? 'no audience at all'
                                        : 'no <Conditions> at all') + '. ' +
                  'Acceptable values here are ' + audiences.join(' or ') + '.');
  }
  const matchedAudience = parsed.audiences.filter(function (one) {
    return audiences.indexOf(one) >= 0;
  })[0];
  if (!matchedAudience) {
    return refuse('RFC 7522 section 3 item 2: this assertion is addressed to ' +
                  parsed.audiences.join(', ') + ' and this authorization ' +
                  'server is ' + audiences.join(' or ') + '. The comparison ' +
                  'is Simple String Comparison (RFC 3986 section 6.2.1), so ' +
                  'a trailing slash or a different host spelling is a ' +
                  'different audience.');
  }

  // --- item 3: the subject --------------------------------------------------
  if (!parsed.hasSubject || !parsed.subject) {
    return refuse('RFC 7522 section 3 item 3: an assertion must contain a ' +
                  '<Subject> identifying the principal' +
                  (parsed.subjectWasEncrypted
                    ? '. Its <EncryptedID> would not decrypt with this ' +
                      'authorization server\'s key'
                    : parsed.hasSubject
                      ? '. This one has a <Subject> with no <NameID> in it'
                      : '') + '.');
  }
  if (asClient && parsed.subject !== String(options.clientId)) {
    return refuse('RFC 7522 section 3 item 3B: for client authentication the ' +
                  '<Subject> MUST be the client_id of the OAuth client. This ' +
                  'assertion names "' + parsed.subject + '" and the request ' +
                  'is for "' + options.clientId + '".');
  }

  // --- item 5 and item 6: the confirmations ---------------------------------
  // The bearer confirmations, then the ones that have not expired. They are
  // two steps because item 6 says an expired <SubjectConfirmation> is
  // DISCARDED — "the authorization server MUST reject the
  // <SubjectConfirmation> (but MAY still use the rest of the Assertion)" —
  // rather than making the assertion invalid, which is a distinction almost
  // every implementation collapses.
  const bearer = parsed.confirmations.filter(function (one) {
    return one.method === BEARER;
  });
  if (!bearer.length) {
    return refuse('RFC 7522 section 3 item 5: the <Subject> must contain at ' +
                  'least one <SubjectConfirmation> whose Method is "' +
                  BEARER + '". This assertion carries ' +
                  (parsed.confirmations.length
                    ? parsed.confirmations.map(function (one) {
                        return '"' + one.method + '"';
                      }).join(', ')
                    : 'none') + '.');
  }
  const live = [];
  const discarded = [];
  for (let i = 0; i < bearer.length; i++) {
    const one = bearer[i];
    const expiry = instantOf(one.notOnOrAfter);
    if (isNaN(expiry)) {
      return refuse('a <SubjectConfirmationData> NotOnOrAfter on this ' +
                    'assertion is "' + one.notOnOrAfter + '", which is not an ' +
                    'xsd:dateTime.');
    }
    if (expiry !== null && now - skewMs >= expiry) {
      discarded.push(one);
      continue;
    }
    // Item 5: "The <SubjectConfirmationData> element MUST have a Recipient
    // attribute with a value indicating the token endpoint URL ... The
    // authorization server MUST verify that the value of the Recipient
    // attribute matches the token endpoint URL." Only where there IS a
    // <SubjectConfirmationData>, which item 5 makes optional when the
    // <Conditions> carries a suitable NotOnOrAfter.
    if (one.hasData) {
      if (!one.recipient) {
        discarded.push(Object.assign({ why: 'no Recipient' }, one));
        continue;
      }
      if (audiences.indexOf(one.recipient) < 0) {
        discarded.push(Object.assign({ why: 'Recipient "' + one.recipient +
                                            '" is not this token endpoint' },
                                     one));
        continue;
      }
    }
    live.push(one);
  }
  if (!live.length) {
    return refuse('RFC 7522 section 3 items 5 and 6: this assertion carries ' +
                  bearer.length + ' bearer <SubjectConfirmation>(s) and none ' +
                  'of them can be used — ' +
                  discarded.map(function (one) {
                    return one.why || ('it expired at ' + one.notOnOrAfter);
                  }).join('; ') + '. A Recipient must be the token endpoint ' +
                  'this assertion was delivered to, which is ' +
                  audiences.join(' or ') + '.');
  }
  const used = live[0];
  // Item 5, last sentence: "The <SubjectConfirmationData> element MAY also
  // contain an Address attribute limiting the client address from which the
  // Assertion can be delivered. Verification of the Address is at the
  // discretion of the authorization server." REPORTED AND NOT ENFORCED, which
  // is this service's position on every optional constraint of this shape: a
  // mock refusing on a source address would be refusing on a proxy's, and
  // there is no configuration here that could tell the two apart.
  if (used.address) {
    log.warn('saml_assertion_grant: the assertion from "' + iss + '" carries ' +
             'a <SubjectConfirmationData> Address of "' + used.address + '". ' +
             'It is recorded and NOT enforced — RFC 7522 section 3 item 5 ' +
             'leaves that to the server, and the address this request arrived ' +
             'from is a proxy\'s as often as it is the client\'s.');
  }

  // --- item 4: there must be an expiry at all -------------------------------
  const confirmationExpiry = instantOf(used.notOnOrAfter);
  const expiresAt = conditionsExpiry !== null ? conditionsExpiry
                                              : confirmationExpiry;
  if (expiresAt === null) {
    return refuse('RFC 7522 section 3 item 4: an assertion must have an expiry ' +
                  'that limits the time window during which it can be used — ' +
                  'either a NotOnOrAfter on its <Conditions> or one on a ' +
                  '<SubjectConfirmationData>. This one has neither, which ' +
                  'makes it a credential anybody who captures it can use for ' +
                  'ever.');
  }

  // --- The ceiling on the lifetime ------------------------------------------
  // Item 6: "the authorization server may reject Assertions with a
  // NotOnOrAfter instant that is unreasonably far in the future", and leaves
  // "unreasonable" to it. Measured from the IssueInstant where there is one,
  // for the same reason the JWT profile measures from `iat`: a short life is
  // the whole difference between an assertion and a long-lived credential
  // somebody has to be able to revoke.
  const issued = instantOf(parsed.issueInstant);
  if (isNaN(issued)) {
    return refuse('this assertion\'s IssueInstant is "' + parsed.issueInstant +
                  '", which is not an xsd:dateTime.');
  }
  if (issued !== null && issued > now + skewMs) {
    return refuse('this assertion says it was issued at ' +
                  new Date(issued).toISOString() + ', which is in the future. ' +
                  'One of the two clocks involved is wrong, and this service ' +
                  'allows ' + skewSeconds() + ' seconds of difference ' +
                  '(oauth2.clientAssertionSkewS).');
  }
  const cap = maxLifetimeSeconds();
  if (cap && issued !== null && (expiresAt - issued) / 1000 > cap) {
    return refuse('this assertion is valid for ' +
                  Math.round((expiresAt - issued) / 1000) + ' seconds and ' +
                  'this authorization server accepts at most ' + cap +
                  ' (oauth2.saml2BearerMaxLifetimeS). RFC 7522 section 3 item ' +
                  '6 invites a server to refuse an assertion whose expiry is ' +
                  'unreasonably far in the future and leaves "unreasonable" ' +
                  'to it.');
  }

  // --- item 6: the replay ---------------------------------------------------
  if (!parsed.id) {
    return refuse('this assertion carries no ID attribute. SAML 2.0 core ' +
                  'section 2.3.3 makes it REQUIRED, and RFC 7522 section 3 ' +
                  'item 6 says a server may keep the set of used ID values to ' +
                  'refuse a replay — an assertion with no ID cannot be ' +
                  'remembered, so accepting one means accepting a bearer ' +
                  'credential this service has no way to spend.');
  }
  forgetStaleAssertions();
  const key = iss + ':' + parsed.id;
  if (seenAssertions.has(key)) {
    log.warn('saml_assertion_grant: "' + iss + '" replayed the assertion ID ' +
             parsed.id + '. A signed assertion is a credential until it ' +
             'expires, so a second use of one is refused.');
    log.debug('Leaving verify(). The ID was replayed.');
    return refuse('this assertion has been used already. Its ID is remembered ' +
                  'until it expires, because a signed assertion captured off ' +
                  'the wire is a credential until then. Mint a fresh one per ' +
                  'request.');
  }
  seenAssertions.set(key, expiresAt + skewMs);

  // --- RFC 7521 section 4.1: the requested scope ----------------------------
  // NARROWED AND NEVER WIDENED, which is the JWT profile's rule and is RFC
  // 7521's rather than either profile's. What carries it here is an
  // `<Attribute Name="scope">`, because SAML has no claim names — this
  // service's own reading, and the only one available: RFC 7522 says nothing
  // about how an assertion constrains a scope, and an AttributeStatement is
  // where a SAML assertion says everything else.
  const assertedScope = (parsed.attributes.scope || [])
    .join(' ').split(/\s+/).filter(Boolean);
  const requestedScope = String(options.scope || '').split(/\s+/).filter(Boolean);
  let scope = requestedScope;
  let scopeNarrowed = [];
  if (assertedScope.length) {
    if (!requestedScope.length) {
      scope = assertedScope;
    } else {
      scopeNarrowed = requestedScope.filter(function (one) {
        return assertedScope.indexOf(one) < 0;
      });
      scope = requestedScope.filter(function (one) {
        return assertedScope.indexOf(one) >= 0;
      });
      if (scopeNarrowed.length) {
        log.warn('saml_assertion_grant: "' + iss + '" presented an assertion ' +
                 'scoped "' + assertedScope.join(' ') + '" and the request ' +
                 'asked for "' + requestedScope.join(' ') + '". The values ' +
                 'the assertion does not carry were dropped: ' +
                 scopeNarrowed.join(' ') + '.');
      }
    }
  }

  log.info('saml_assertion_grant: an RFC 7522 section ' +
           (asClient ? '2.2' : '2.1') + ' assertion from "' + iss + '" for "' +
           parsed.subject + '" verified. ' + verified.signatureMethod +
           (opened.encrypted ? ', encrypted ' + opened.encryption.algorithm : '') +
           ', certificate from ' + usedCertificate.source +
           ', ID=' + parsed.id + '.');
  log.debug('Leaving verify(). Verified.');
  return {
    ok: true,
    issuer: iss,
    subject: parsed.subject,
    nameIdFormat: parsed.nameIdFormat,
    application: party ? party.identifier : (options.clientId || ''),
    declared: !!(party && party.declared),
    id: parsed.id,
    scope: scope,
    scopeNarrowed: scopeNarrowed,
    audience: parsed.audiences,
    matchedAudience: matchedAudience,
    recipient: used.recipient,
    address: used.address,
    // Item 7. Carried and reported, never required — the item is a SHOULD in
    // both directions, and which way it points says whether the issuer
    // authenticated the subject itself or is acting autonomously on their
    // behalf. A register that could not tell those apart would be saying the
    // person signed in somewhere when nobody knows that they did.
    authnStatements: parsed.authnStatements,
    directlyAuthenticated: parsed.authnStatements > 0,
    encrypted: !!opened.encrypted,
    encryption: opened.encryption || null,
    subjectWasEncrypted: parsed.subjectWasEncrypted,
    discardedConfirmations: discarded.length,
    signatureMethod: verified.signatureMethod || '',
    canonicalization: verified.canonicalization || '',
    certificateSource: usedCertificate.source,
    certificateThumbprint: usedCertificate.thumbprint,
    expiresAt: expiresAt,
    attributes: parsed.attributes
  };
}

// The attribute names this profile will not copy onto an issued token. Every
// one of them is either the assertion's own furniture or something the token
// endpoint decides for itself — and the list is SHORT where RFC 7523's is
// twelve, because a SAML assertion keeps its protocol furniture in ELEMENTS
// rather than in the attribute statement. `scope` is the only one that
// overlaps at all.
const PROTOCOL_ATTRIBUTES = ['scope'];

// ---------------------------------------------------------------------------
// RFC 7522 SECTION 3 ITEM 8 — the other statements, onto the token.
//
// A SAML attribute is a NAME AND A LIST, and a JWT claim is a name and a
// value, so the shape has to change on the way: a single value becomes a
// string and several stay a list. Collapsing a one-member list to its member
// is what every SAML-to-JWT bridge does and is what a relying party expects —
// `"department": ["engineering"]` in a token reads as a bug.
// ---------------------------------------------------------------------------
function extraClaimsFrom(attributes) {
  log.debug('Entering extraClaimsFrom().');
  const out = {};
  Object.keys(attributes || {}).forEach(function (name) {
    if (PROTOCOL_ATTRIBUTES.indexOf(name) >= 0) {
      return;
    }
    const values = attributes[name] || [];
    out[name] = values.length === 1 ? values[0] : values;
  });
  log.debug('Leaving extraClaimsFrom(). ' + Object.keys(out).length + ' claim(s).');
  return out;
}

module.exports = {
  GRANT_TYPE: GRANT_TYPE,
  ASSERTION_TYPE: ASSERTION_TYPE,
  PROTOCOL_ATTRIBUTES: PROTOCOL_ATTRIBUTES,
  BEARER: BEARER,
  enabled: enabled,
  requiresRegisteredIssuer: requiresRegisteredIssuer,
  maxLifetimeSeconds: maxLifetimeSeconds,
  decode: decode,
  read: read,
  certificatesForParty: certificatesForParty,
  verify: verify,
  extraClaimsFrom: extraClaimsFrom,
  // For the pages that report how many assertions are being remembered.
  assertionsRemembered: function () { return seenAssertions.size; }
};
