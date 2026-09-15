'use strict';
//
// File: person_assertions.js
//
// ===========================================================================
// RFC 7523 SECTION 2.1 WITH A PERSON AS THE ISSUER (2026-09-11).
//
// **A PERSON MAY HOLD A SIGNING KEY PAIR NOW, AND THIS IS THE REGISTER OF
// THEM.** `/admin/pki` issued one to an APPLICATION and to nothing else until
// today: a party this service trusts signs a document saying *this person is
// alice, issue a token for her*, and `oauth-oidc/assertion_grant.js` issues
// one. That is the delegated shape of the grant, where the issuer is a
// trusted third party and the `sub` is somebody else.
//
// RFC 7523 section 3 names no such requirement. Claim 1 says `iss` is "a
// unique identifier for the JWT issuer" and claim 2 says that in an
// authorization grant the `sub` "typically identifies an authorized accessor
// or resource owner" — so **a person signing an assertion about themselves is
// the profile read literally**, not an extension of it. It is the case a
// client author most often wants a server to exercise: a key the person holds,
// no browser, no password, and an access token at the end of it.
//
// ---------------------------------------------------------------------------
// THE ONE REFUSAL THIS MODULE EXISTS FOR: A PERSON MAY ONLY ASSERT ABOUT
// THEMSELVES.
//
// An APPLICATION that declares `oauthAssertionIssuer` is an operator saying
// *this party may speak about people*, which is the whole content of that
// declaration — so an application's assertion may carry any `sub` and does.
// A person's key pair is not that: it is a CREDENTIAL BELONGING TO ONE
// PERSON, issued so that they can present themselves, and reading it as an
// authority over other people would mean that anybody who is given a key on
// this page can obtain a token as anybody in the realm.
//
// So the rule is `iss` and `sub` must name the SAME person, and
// `assertion_grant.js` refuses anything else with a sentence that says this
// rather than reporting a lookup that failed. **An operator who wants a party
// that may speak about others has a way to say so and it is the one that
// already existed**: register an application and declare the issuer on it.
//
// ---------------------------------------------------------------------------
// THE ATTRIBUTES, AND WHY THEY SHARE NO NAME WITH THE APPLICATION'S.
//
// `oauthAssertion*` is an APPLICATION's RFC 7523 key pair and
// `oauthSamlAssertion*` is its RFC 7522 one; `applications.js` argues why
// those two share no name — no code path crosses them, so neither pair can
// sign for the other's profile. **This is that argument a third time**, for a
// third kind of holder: `stsAssertion*`, on the PERSON's entry, read by this
// module and by nothing else.
//
// The `sts` prefix is not decoration. It is what every attribute this service
// invented about a person already carries — `stsTotpCredential`,
// `stsBackupCodes`, `stsActivationToken` — and what tells them apart from the
// inetOrgPerson schema beside them, which is somebody else's and is listed in
// `common/inetorgperson.js`.
//
//   stsAssertionIssuer            the `iss` this person's assertions carry.
//                                 Multi-valued. Absent means their own
//                                 username, for the reason `issuerEntry()`
//                                 resolves an application by its client_id:
//                                 asking an operator to write a name down
//                                 twice is a configuration step with no
//                                 decision in it.
//   stsAssertionJwks              the public half, as a JWKS carrying the
//                                 certificate chain in `x5c`. This is what
//                                 verifies a signature.
//   stsAssertionCertificate       the leaf, PEM.
//   stsAssertionCertificateChain  the Issuing CA and the Intermediate, PEM.
//   stsAssertionKid               the `kid` inside the JWKS, so that a page
//                                 can show it without parsing JSON.
//   stsAssertionExpiresAt         the leaf's notAfter, as a GeneralizedTime.
//   stsAssertionPrivateKey        the private half. **SEALED** — see below.
//
// ---------------------------------------------------------------------------
// THE PRIVATE HALF IS SEALED, AND IT IS HANDED OVER ONCE.
//
// `applications.js` seals `oauthAssertionPrivateKey` under the key-encryption
// key wherever that key outlives the process (`keystore.persists()`, not
// `keystore.sealed()` — development's key is ephemeral and sealing a
// DIRECTORY attribute under it would leave the certificate readable after a
// restart and the private half permanent garbage). **The same mechanism and
// deliberately not a new one**, for a person: `keystore.seal()`,
// `keystore.open()`, and `isSealed()` is a prefix test on the envelope rather
// than a marker attribute nobody would keep in step.
//
// **AND THE ISSUE HANDS THE PEM BACK, WHICH THE APPLICATION'S DOES NOT.**
// That difference is the point rather than an inconsistency. An application's
// private key has a credentialed read door already — `applications.view()`
// opens it and `/admin/applications` and `GET /admin-api/applications` draw
// it — and a person's has none, because nothing in this service prints a
// person's entry through a module that would open it. The alternatives were a
// console page that renders somebody's private key on every visit, or a key
// this service holds and no human can ever obtain. So it is returned by the
// act that creates it, once, with the page saying so.
//
// ---------------------------------------------------------------------------
// TWO DOORS WRITE THROUGH THIS MODULE AND THEY ARE THE SAME ACT (2026-09-12).
//
// `/admin/pki` is an operator issuing to somebody, and `/portal/signing-key` is
// a person issuing to themselves. **Both call `pki.issueSigningKeyPair()` and
// then `write()` below**, so there is one answer to *what is on that entry
// after an issue* — a second implementation on either side would agree with
// this one until one of them grew an attribute.
//
// What differs is only what surrounds them: the portal's door is rate limited
// (an RSA key pair is CPU on the one thread this service answers everything
// on), it can be turned off with `pki.personSelfService` without touching a key
// anybody already holds, and it renders the private key rather than
// redirecting, for the reason that door's own header gives.
//
// **THE SELF-SERVICE DOOR IS ONLY ALLOWABLE BECAUSE OF THE REFUSAL ABOVE.** A
// button that minted a key able to assert about anybody would hand every person
// who can sign in a token as every other person; because the refusal lives in
// the GRANT rather than on either page, both doors get it and neither can
// forget it.
//
// ---------------------------------------------------------------------------
// THE DIRECTORY ARRIVES THROUGH `setDirectory()`, FILLED BY
// `ldap/ldap_server.js`, and this module holds no store of its own.
//
// Rule 3e's test answers yes both ways round, which is what a slot is for.
// This file is required by `oauth-oidc/assertion_grant.js`, which is required
// by `oauth2.js` at 9; a require from here to `ldap_server.js` (21) would
// register every `/ldap` route and the eight `/admin/ldap/*` console pages
// ahead of the authorization server (rule 1), and a require the other way
// would close a cycle through this module's own caller.
//
// It is a LIBRARY in rule 3's sense: it registers no route, and it requires
// `config.js`, `keystore.js` and `realms.js` — none of which requires it
// back.
// ===========================================================================

// The service's own logger, as every module here takes it.
const { log, subjectForName, nameForSubject } = require('./helpers');
const keystore = require('./keystore');
// A leaf. The refusal objects below carry `errorCode` for the caller that
// sends the response; it is never part of anything serialised.
const errorCodes = require('./error_codes');

// The declaration, and the six the issue writes. A LIST rather than six
// constants, because the console's *take the key pair off* control clears
// exactly this set and a seventh attribute added to the issue and not to the
// list would be one that survived being taken off.
const ISSUER_ATTRIBUTE = 'stsAssertionIssuer';

const KEY_ATTRIBUTES = ['stsAssertionJwks', 'stsAssertionCertificate',
                        'stsAssertionCertificateChain',
                        'stsAssertionPrivateKey', 'stsAssertionKid',
                        'stsAssertionExpiresAt', 'stsAssertionKeySource'];

// ===========================================================================
// AN RFC 7522 KEY PAIR TOO, SINCE 2026-09-13, AND IT IS A FOURTH SET.
//
// Until this date a person could hold an RFC 7523 key pair and not an RFC
// 7522 one, and `/admin/pki` refused the second by name — the SAML verifier
// read `oauthSamlAssertion*` off an application and nothing off a person, so a
// SAML key pair on a person's entry would have been one nothing could use.
// **The verifier reads a person's now** (`oauth-oidc/saml_assertion_grant.js`),
// under the same refusal the JWT profile makes: a person's assertion may name
// only themselves as its `<Subject>`.
//
// `stsSamlAssertion*` shares no name with `stsAssertion*`, for the reason the
// two application sets share none: no code path crosses them, so a person's
// JWT key pair cannot sign a SAML assertion and taking one off leaves the
// other working. There is no JWKS — what an XML Signature is checked against
// is a certificate, and what matches a presented `<ds:KeyInfo>` is its
// THUMBPRINT, which is the handle this set stores where the JWT set stores a
// `kid`.
//
// **AND BOTH SETS RECORD WHERE THE KEY PAIR CAME FROM** (`…KeySource`): issued
// here, or a certificate UPLOADED in its place — this realm's own, or an
// external authority's with its whole chain — in which case the person keeps
// the private key and the attribute that would hold it is empty. The words are
// `applications.KEY_SOURCES`, which this module does not require for
// `applications.js`'s own reason: it sits on the token endpoint's path, and a
// vocabulary of three words is not worth a module.
// ===========================================================================
const SAML_ISSUER_ATTRIBUTE = 'stsSamlAssertionIssuer';

const SAML_KEY_ATTRIBUTES = ['stsSamlAssertionCertificate',
                             'stsSamlAssertionCertificateChain',
                             'stsSamlAssertionPrivateKey',
                             'stsSamlAssertionThumbprint',
                             'stsSamlAssertionExpiresAt',
                             'stsSamlAssertionKeySource'];

// WHICH ATTRIBUTE HOLDS WHICH HALF, PER PROFILE — the shape
// `applications.KEY_PAIR_ATTRIBUTES` has, so a page drawing an application's
// key pairs and a person's reads one kind of table. `present` is the attribute
// whose presence means the profile holds a key pair at all.
const KEY_PAIR_ATTRIBUTES = {
  jwt: { issuer: ISSUER_ATTRIBUTE, certificate: 'stsAssertionCertificate',
         chain: 'stsAssertionCertificateChain',
         privateKey: 'stsAssertionPrivateKey', handle: 'stsAssertionKid',
         handleLabel: 'kid', jwks: 'stsAssertionJwks',
         expiresAt: 'stsAssertionExpiresAt', source: 'stsAssertionKeySource',
         present: 'stsAssertionJwks',
         attributes: KEY_ATTRIBUTES.slice() },
  saml: { issuer: SAML_ISSUER_ATTRIBUTE,
          certificate: 'stsSamlAssertionCertificate',
          chain: 'stsSamlAssertionCertificateChain',
          privateKey: 'stsSamlAssertionPrivateKey',
          handle: 'stsSamlAssertionThumbprint', handleLabel: 'thumbprint',
          jwks: '', expiresAt: 'stsSamlAssertionExpiresAt',
          source: 'stsSamlAssertionKeySource',
          present: 'stsSamlAssertionCertificate',
          attributes: SAML_KEY_ATTRIBUTES.slice() }
};

const PURPOSE_IDS = Object.keys(KEY_PAIR_ATTRIBUTES);

// Every attribute this module owns, which is what the directory has to hand
// back. A clear removes ONE PROFILE's slice of it — see `clear()`.
const ATTRIBUTES = [ISSUER_ATTRIBUTE].concat(KEY_ATTRIBUTES)
  .concat([SAML_ISSUER_ATTRIBUTE]).concat(SAML_KEY_ATTRIBUTES);

// The ones that are private key material. A list for `applications.js`'s
// reason: *is this attribute private key material* is a question somebody
// adding a name above has to answer, and a list is where they will look for
// it. The second arrived with the RFC 7522 set, which is that reason working.
const SEALED_ATTRIBUTES = ['stsAssertionPrivateKey',
                           'stsSamlAssertionPrivateKey'];

// An unknown profile id is `''`, and every caller turns that into a refusal
// rather than a default: quietly writing the other profile's key pair would
// put a key on the wrong attribute set with nothing saying so.
function purposeIdOf(purpose) {
  log.debug("Entering purposeIdOf().");
  const asked = String(purpose || '').trim() || 'jwt';
  log.debug("Leaving purposeIdOf().");
  return KEY_PAIR_ATTRIBUTES[asked] ? asked : '';
}

const SEAL_LABEL = 'person-private-key';

let directory = null;

// ---------------------------------------------------------------------------
// THE SLOT. Validated WHOLE, for `setLogoutReader()`'s reason: a filler that
// installed the read and not the write would leave this service able to verify
// an assertion from a person and unable to give anybody a key to sign one
// with, which reads on the page as a control that does nothing.
// ---------------------------------------------------------------------------
function setDirectory(hooks) {
  log.debug('Entering setDirectory().');
  const needed = ['read', 'write', 'persons'];
  const missing = needed.filter(function (name) {
    return !hooks || typeof hooks[name] !== 'function';
  });
  if (missing.length) {
    log.error(errorCodes.tag('STS-OAUTH-0084') +
              'person_assertions: setDirectory() was given something without ' +
              missing.join(', ') + ', so it was refused whole. Half of it ' +
              'would be a register that can verify an assertion and not ' +
              'issue a key to sign one with, or one that can issue a key and ' +
              'never find the person it belongs to.');
    log.debug('Leaving setDirectory(). Refused.');
    return false;
  }
  directory = hooks;
  log.debug('Leaving setDirectory(). A person may hold an assertion key pair.');
  return true;
}

// Is there a store at all? Read by `/admin/pki` and by the report, which say
// so rather than letting somebody press a button that quietly writes nothing.
function storable() {
  log.debug("Entering storable().");
  log.debug("Leaving storable().");
  return !!directory;
}

function isSealed(value) {
  log.debug("Entering isSealed().");
  log.debug("Leaving isSealed().");
  return String(value == null ? '' : value).indexOf('$aesgcm$') === 0;
}

// Seal on the way in, where this process holds a key-encryption key that will
// still be there after a restart. Returns null where sealing was REQUIRED and
// failed, which the caller turns into a refusal rather than a write: storing a
// private key in the clear in product mode would put a working signing
// credential in every directory dump, and doing it silently after being asked
// not to is worse than refusing.
function sealValue(name, value) {
  log.debug("Entering sealValue().");
  if (SEALED_ATTRIBUTES.indexOf(name) < 0 || !value) {
    log.debug("Leaving sealValue().");
    return String(value == null ? '' : value);
  }
  if (isSealed(value)) {
    log.debug("Leaving sealValue().");
    return String(value);
  }
  if (!keystore.persists()) {
    log.debug("Leaving sealValue().");
    return String(value);
  }
  const out = keystore.seal(String(value), SEAL_LABEL);
  if (!out) {
    log.debug("Leaving sealValue().");
    return null;
  }
  log.debug("Leaving sealValue().");
  return out;
}

// And open on the way out. A value that will NOT open is left as it is and
// reported, which is `openSealedFields()`'s rule word for word: rotating the
// key-encryption key produces one, the key pair is unusable either way, and a
// reader seeing `$aesgcm$…` where a PEM belongs plus a line in the log naming
// the person is a truer answer than an empty attribute — which would read as
// *no key pair was ever issued*.
function openValue(name, value, username) {
  log.debug("Entering openValue().");
  if (SEALED_ATTRIBUTES.indexOf(name) < 0 || !value || !isSealed(value)) {
    log.debug("Leaving openValue().");
    return String(value == null ? '' : value);
  }
  const opened = keystore.open(String(value), SEAL_LABEL);
  if (!opened) {
    log.warn(errorCodes.tag('STS-OAUTH-0088') +
             'person_assertions: the assertion private key on "' + username +
             '" is sealed and will not open under this process\'s ' +
             'key-encryption key — it was written under a different one. It ' +
             'is reported as it is stored rather than as absent, because ' +
             'absent would read as no key pair having been issued. Issue ' +
             'again on /admin/pki.');
    log.debug("Leaving openValue().");
    return String(value);
  }
  log.debug("Leaving openValue().");
  return opened;
}

function valuesOf(value) {
  log.debug("Entering valuesOf().");
  if (value === undefined || value === null || value === '') {
    log.debug("Leaving valuesOf().");
    return [];
  }
  log.debug("Leaving valuesOf().");
  return (Array.isArray(value) ? value : [value])
    .map(function (one) { return String(one); })
    .filter(Boolean);
}

// ---------------------------------------------------------------------------
// WHAT ONE PERSON HOLDS. `null` where there is no entry at all, which the
// callers keep apart from an entry holding nothing: the first is a name
// nobody in this realm has and the second is somebody who has not been issued
// a key pair.
// ---------------------------------------------------------------------------
function recordFor(username) {
  log.debug('Entering recordFor(). username=' + username);
  const name = String(username || '');
  if (!directory || !name) {
    log.debug('Leaving recordFor(). No directory or no name.');
    return null;
  }
  const raw = directory.read(name);
  if (!raw) {
    log.debug('Leaving recordFor(). Nobody by that name.');
    return null;
  }
  const out = { username: name,
                issuers: valuesOf(raw[ISSUER_ATTRIBUTE]),
                hasKeyPair: false,
                samlIssuers: valuesOf(raw[SAML_ISSUER_ATTRIBUTE]),
                hasSamlKeyPair: false };
  KEY_ATTRIBUTES.concat(SAML_KEY_ATTRIBUTES).forEach(function (attribute) {
    const first = valuesOf(raw[attribute])[0] || '';
    out[attribute] = openValue(attribute, first, name);
  });
  out.hasKeyPair = !!out.stsAssertionJwks;
  out.hasSamlKeyPair = !!out.stsSamlAssertionCertificate;
  // THE ISSUER A PERSON ASSERTS UNDER, defaulted to their own name. It is
  // `effectiveIssuers` rather than an overwrite of `issuers` so that a page
  // can tell a DECLARED value from the default — the same distinction
  // `issuerEntry()` carries as `declared`. One per profile, because the two
  // declarations are two attributes for `applications.js`'s reason: being
  // trusted to assert in one document format is not being trusted in the
  // other.
  out.effectiveIssuers = out.issuers.length ? out.issuers.slice() : [name];
  out.samlEffectiveIssuers = out.samlIssuers.length
    ? out.samlIssuers.slice() : [name];
  log.debug('Leaving recordFor(). ' +
            (out.hasKeyPair ? 'A JWT key pair. ' : 'No JWT key pair. ') +
            (out.hasSamlKeyPair ? 'A SAML key pair.' : 'No SAML key pair.'));
  return out;
}

// ---------------------------------------------------------------------------
// WHICH PERSON, IF ANY, ISSUES ASSERTIONS UNDER THIS `iss`.
//
// The DECLARED value wins and is searched first, because it is what somebody
// typed; a bare username is accepted after it for `issuerEntry()`'s reason,
// which is that an assertion a person makes about themselves names them and
// writing that down a second time is a configuration step with no decision in
// it.
//
// **A PERSON WITH NO KEY PAIR IS NOT AN ISSUER**, and that is deliberate
// rather than an optimisation: every person in this realm would otherwise be
// an issuer by the fallback above, so an assertion naming any of them would
// get past the registered-issuer refusal and be judged on its `x5c` alone.
// Holding a key pair is the thing an operator DID.
//
// **IT IS A SCAN, AND THE COST IS WRITTEN DOWN HERE RATHER THAN HIDDEN.** One
// read per person in the realm, on an assertion grant whose `iss` matched no
// application — so a realm carrying the bulk-load job's five thousand entries
// pays five thousand reads for such a request. Reading `iss` as a username
// FIRST would make the common case one read, and it was refused: a DECLARED
// value has to win over a bare name (that is what `issuerEntry()` does for an
// application, and what lets somebody assert under a URI), and a shortcut that
// answered before the declarations had been looked at would resolve one
// person's declared issuer to a different person who happens to be called
// that. An index keyed by declared issuer is the answer if this ever matters;
// it would be a second copy of what is on the entries, which is the thing this
// register deliberately does not keep.
//
// **`purpose` SAYS WHICH PROFILE IS ASKING** (2026-09-13), and it decides both
// halves of the question: which declaration is searched and which key pair
// makes somebody an issuer. A person holding only an RFC 7523 key pair is no
// RFC 7522 issuer, and the reverse — which is the crossing the two attribute
// sets exist to prevent, made once here instead of being hoped for. Absent
// means `jwt`, which is what every caller written before the SAML set sends.
// ---------------------------------------------------------------------------
function issuerFor(iss, purpose) {
  log.debug('Entering issuerFor(). iss=' + iss + ' purpose=' + purpose);
  const wanted = String(iss || '');
  const saml = purposeIdOf(purpose) === 'saml';
  if (!directory || !wanted || !purposeIdOf(purpose)) {
    log.debug('Leaving issuerFor(). No directory, issuer or profile.');
    return null;
  }
  const names = directory.persons() || [];
  let fallback = null;
  for (let i = 0; i < names.length; i++) {
    const record = recordFor(names[i]);
    if (!record || !(saml ? record.hasSamlKeyPair : record.hasKeyPair)) {
      continue;
    }
    const declared = saml ? record.samlIssuers : record.issuers;
    if (declared.indexOf(wanted) >= 0) {
      log.debug('Leaving issuerFor(). Declared by ' + record.username + '.');
      return { identifier: record.username, record: record, declared: true };
    }
    if (!fallback && !declared.length &&
        String(record.username) === wanted) {
      fallback = record;
    }
  }
  if (fallback) {
    log.debug('Leaving issuerFor(). It is a username.');
    return { identifier: fallback.username, record: fallback,
             declared: false };
  }
  log.debug('Leaving issuerFor(). Nobody here issues under that name.');
  return null;
}

// Does this `sub` name the person who signed? The comparison is on the
// username and on every issuer they declare, because an assertion whose `iss`
// and `sub` are both the declared issuer name is the same statement as one
// where both are the username — and refusing that would be refusing the
// natural spelling of *this is me*.
// `purpose` picks which declaration counts, for `issuerFor()`'s reason: an
// RFC 7522 `<Subject>` spelled as the person's declared SAML issuer is *this
// is me*, and the JWT declaration is a different name for a different
// profile. A record built by hand (a certificate naming somebody since
// deleted) carries only `effectiveIssuers`, so the SAML list falls back to it.
function subjectIsSelf(record, sub, purpose) {
  log.debug("Entering subjectIsSelf().");
  const wanted = String(sub || '');
  if (!record || !wanted) {
    log.debug("Leaving subjectIsSelf().");
    return false;
  }
  const names = purposeIdOf(purpose) === 'saml'
    ? (record.samlEffectiveIssuers || record.effectiveIssuers || [])
    : (record.effectiveIssuers || []);
  // THE PERSON'S OWN SUBJECT COUNTS AS THEM (2026-09-14). A `sub` is
  // `urn:uuid:<entryUUID>` now, which is exactly what a relying party holds and
  // what an assertion naming this person most naturally carries; refusing it
  // while accepting the bare username would make the stable identifier the one
  // spelling of yourself you may not use.
  // An alias of it too, which resolves to the same entry and so back to the
  // same subject (`ldap_server.js`'s `mergeCreateRace()`).
  const ownSubject = /^urn:uuid:/i.test(wanted)
    ? subjectForName(record.username) : '';
  const wantedSubject = ownSubject && wanted.toLowerCase() !==
    ownSubject.toLowerCase() ? subjectForName(nameForSubject(wanted)) : '';
  log.debug("Leaving subjectIsSelf().");
  return wanted === String(record.username) || names.indexOf(wanted) >= 0 ||
         (!!ownSubject && (ownSubject.toLowerCase() === wanted.toLowerCase() ||
                           wantedSubject === ownSubject));
}

// ---------------------------------------------------------------------------
// THE WRITE. Every value or none of them, and a failure says which one —
// `common/pki.js` hands a key pair over ONCE and keeps no copy, so a write
// that half-succeeded is a key pair that is gone with a certificate on the
// entry claiming otherwise.
//
// **`opts.purpose` PICKS THE SET** (2026-09-13), defaulting to `jwt` so the two
// callers written before the SAML set — `/admin/pki` and
// `/portal/signing-key` — write exactly what they wrote. A record from
// `pki.registerCertificate()` has an EMPTY private key, and writing it is what
// makes an upload a REPLACEMENT: an issued key pair's private half left beside
// somebody else's certificate would be a key for a certificate it does not
// match. The private key goes
// FIRST for the same reason: a write that fails after it leaves the old
// certificate with no key, which refuses rather than signs.
// ---------------------------------------------------------------------------
function write(username, record, opts) {
  log.debug('Entering write(). username=' + username);
  const name = String(username || '');
  const options = opts || {};
  const purpose = purposeIdOf(options.purpose);
  if (!directory) {
    log.debug('Leaving write(). No directory.');
    return { ok: false, errorCode: 'STS-OAUTH-0085',
             errors: ['This process has no directory, so there is nowhere to ' +
                      'put a person\'s assertion key pair. `ldap_server.js` ' +
                      'fills the slot at require time; a process without it ' +
                      'can verify nothing either.'] };
  }
  if (!purpose) {
    log.debug('Leaving write(). An unknown profile.');
    return { ok: false, errorCode: 'STS-PKI-0011',
             errors: ['"' + options.purpose + '" is not a profile a person ' +
                      'may hold a key pair for. There are ' +
                      PURPOSE_IDS.join(' and ') + '.'] };
  }
  const names = KEY_PAIR_ATTRIBUTES[purpose];
  const values = [
    [names.privateKey, record.privateKeyPem || ''],
    [names.certificate, record.certificatePem],
    [names.chain, (record.chainPem || []).join('')],
    [names.handle, purpose === 'saml' ? record.certificateThumbprint
                                      : record.kid],
    [names.expiresAt, generalizedTime(new Date(record.notAfter))],
    [names.source, record.source || 'issued']
  ];
  if (names.jwks) {
    values.splice(2, 0, [names.jwks, JSON.stringify(record.jwks)]);
  }
  if (options.issuer) {
    values.push([names.issuer, String(options.issuer)]);
  }
  const written = [];
  for (let i = 0; i < values.length; i++) {
    const attribute = values[i][0];
    const sealed = sealValue(attribute, values[i][1]);
    if (sealed === null) {
      log.error(errorCodes.tag('STS-OAUTH-0086') +
                'person_assertions: a signing key pair was issued to "' +
                name + '" and ' + attribute + ' could not be sealed. Nothing ' +
                'was written and the key pair is lost; issue again.');
      log.debug('Leaving write(). The seal failed.');
      return { ok: false, errorCode: 'STS-OAUTH-0086', written: written,
               errors: ['`' + attribute + '` could not be sealed under this ' +
                        'service\'s key-encryption key, so it was not ' +
                        'written. This service keeps no second copy of a ' +
                        'private key, so that key pair is gone. Fix the ' +
                        'key-encryption key — /admin/encryption says what is ' +
                        'wrong with it — and issue again.'] };
    }
    if (!directory.write(name, attribute, sealed)) {
      log.error(errorCodes.tag('STS-OAUTH-0087') +
                'person_assertions: a signing key pair was issued to "' +
                name + '" and ' + attribute + ' could not be written. The ' +
                'private key is not stored anywhere else and is now lost; ' +
                'issue again.');
      log.debug('Leaving write(). A write failed.');
      return { ok: false, errorCode: 'STS-OAUTH-0087', written: written,
               errors: ['`' + attribute + '` could not be written onto "' +
                        name + '". This service keeps no second copy of a ' +
                        'private key, so that key pair is gone. Issue ' +
                        'again.'] };
    }
    written.push(attribute);
  }
  log.info('person_assertions: "' + name + '" now holds an ' +
           (purpose === 'saml' ? 'RFC 7522' : 'RFC 7523') + ' signing ' +
           'key pair (' + (record.source || 'issued') + '), ' +
           names.handleLabel + '=' + values[3][1] + ', valid until ' +
           record.notAfter + '. It signs assertions ABOUT THAT PERSON and ' +
           'about nobody else.');
  log.debug('Leaving write(). ' + written.length + ' attribute(s).');
  return { ok: true, written: written, errors: [] };
}

// RFC 4517 GeneralizedTime, which is how every timestamp in this directory is
// spelled — the SAME three lines `pki_admin.js` writes out beside the
// application's expiry, and a fourth spelling of a timestamp on one entry
// would be worse than a fourth copy of this function. **Never with fractional
// seconds**: RFC 5280 section 4.1.2.5.2 forbids them and a reader that parses
// strictly refuses the whole value, which is the defect
// `tests/pki_anchor_drift.js` was written for.
function generalizedTime(when) {
  log.debug("Entering generalizedTime().");
  const d = when ? new Date(when) : new Date();
  const pad = function (n) {
    log.debug("Entering pad().");
    log.debug("Leaving pad().");
    return String(n).padStart(2, '0');
  };
  log.debug("Leaving generalizedTime().");
  return d.getUTCFullYear() + pad(d.getUTCMonth() + 1) + pad(d.getUTCDate()) +
         pad(d.getUTCHours()) + pad(d.getUTCMinutes()) +
         pad(d.getUTCSeconds()) + 'Z';
}

// Take the key pair off. ONE PERSON'S, and the declaration with it: unlike an
// application — which may hold a JWKS it registered itself beside the one this
// service issued — everything in this set was put there by the issue, so
// leaving the `iss` declaration behind would leave a person declared as an
// issuer with no key to issue with, which reads on the page as a key pair that
// would not clear.
//
// **ONE PROFILE AT A TIME** (2026-09-13). A person may hold both key pairs,
// and a control that took one off must leave the other working — the
// application arm's rule and for its reason. Absent means `jwt`, which is what
// `/portal/signing-key`'s Remove and `/admin/pki`'s person arm meant when they
// were written.
function clear(username, purpose) {
  log.debug('Entering clear(). username=' + username + ' purpose=' + purpose);
  const name = String(username || '');
  const id = purposeIdOf(purpose);
  if (!directory || !name || !id) {
    log.debug('Leaving clear(). No directory, name or profile.');
    return { ok: false, errorCode: 'STS-OAUTH-0089', removed: 0 };
  }
  const before = recordFor(name);
  if (!before) {
    log.debug('Leaving clear(). Nobody by that name.');
    return { ok: false, errorCode: 'STS-OAUTH-0090', removed: 0,
             unknown: true };
  }
  const names = KEY_PAIR_ATTRIBUTES[id];
  let removed = 0;
  [names.issuer].concat(names.attributes).forEach(function (attribute) {
    const held = attribute === names.issuer
      ? (id === 'saml' ? before.samlIssuers : before.issuers).length
      : !!before[attribute];
    if (!held) {
      return;
    }
    if (directory.write(name, attribute, '')) {
      removed += 1;
    }
  });
  log.debug('Leaving clear(). ' + removed + ' attribute(s).');
  return { ok: removed > 0, removed: removed };
}

// ---------------------------------------------------------------------------
// EVERYBODY IN THIS REALM WHO HOLDS ONE, for `/admin/pki` and for
// `GET /admin-api/pki`. **NO PRIVATE KEY IS IN THIS ANSWER.** It is the one
// report in this module that a page renders, and a page that drew a private
// key would be one that gives it away on every visit to everybody who can
// read the console.
// ---------------------------------------------------------------------------
function holders() {
  log.debug('Entering holders().');
  if (!directory) {
    log.debug('Leaving holders(). No directory.');
    return [];
  }
  const out = [];
  (directory.persons() || []).forEach(function (name) {
    const record = recordFor(name);
    if (!record || (!record.hasKeyPair && !record.issuers.length &&
                    !record.hasSamlKeyPair && !record.samlIssuers.length)) {
      return;
    }
    // THE JWT MEMBERS KEEP THEIR NAMES AND MEANINGS, and the SAML key pair is
    // a nested member beside them (2026-09-13): `/admin/pki` and the
    // certificate catalogue read the first set, and a row for somebody who
    // holds only a SAML key pair reads `hasKeyPair: false` there, which is
    // true of the profile those readers ask about.
    out.push({ username: record.username,
               hasKeyPair: record.hasKeyPair,
               declaredIssuers: record.issuers.slice(),
               issuers: record.effectiveIssuers.slice(),
               declared: record.issuers.length > 0,
               kid: record.stsAssertionKid,
               expiresAt: record.stsAssertionExpiresAt,
               source: record.stsAssertionKeySource ||
                       (record.hasKeyPair ? 'issued' : ''),
               certificatePem: record.stsAssertionCertificate,
               saml: { hasKeyPair: record.hasSamlKeyPair,
                       declaredIssuers: record.samlIssuers.slice(),
                       issuers: record.samlEffectiveIssuers.slice(),
                       declared: record.samlIssuers.length > 0,
                       thumbprint: record.stsSamlAssertionThumbprint,
                       expiresAt: record.stsSamlAssertionExpiresAt,
                       source: record.stsSamlAssertionKeySource ||
                               (record.hasSamlKeyPair ? 'issued' : ''),
                       certificatePem: record.stsSamlAssertionCertificate } });
  });
  log.debug('Leaving holders(). ' + out.length + ' person(s).');
  return out;
}

module.exports = {
  ISSUER_ATTRIBUTE: ISSUER_ATTRIBUTE,
  KEY_ATTRIBUTES: KEY_ATTRIBUTES,
  SAML_ISSUER_ATTRIBUTE: SAML_ISSUER_ATTRIBUTE,
  SAML_KEY_ATTRIBUTES: SAML_KEY_ATTRIBUTES,
  KEY_PAIR_ATTRIBUTES: KEY_PAIR_ATTRIBUTES,
  PURPOSE_IDS: PURPOSE_IDS,
  ATTRIBUTES: ATTRIBUTES,
  SEALED_ATTRIBUTES: SEALED_ATTRIBUTES,
  setDirectory: setDirectory,
  storable: storable,
  isSealed: isSealed,
  recordFor: recordFor,
  issuerFor: issuerFor,
  subjectIsSelf: subjectIsSelf,
  write: write,
  clear: clear,
  holders: holders,
  generalizedTime: generalizedTime
};
