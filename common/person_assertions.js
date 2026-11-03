// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
// `common/inetorgperson.ts`.
//
//   stsAssertionIssuer      the `iss` this person's assertions carry.
//                           Multi-valued. Absent means their own username, for
//                           the reason `issuerEntry()` resolves an application
//                           by its client_id: asking an operator to write a
//                           name down twice is a configuration step with no
//                           decision in it.
//   stsAssertionKeyPair     ONE VALUE PER KEY PAIR (#1290): a JSON record of
//                           the public half — the `kid`, the JWK carrying the
//                           certificate chain in `x5c`, the certificate and
//                           its chain, the serial and the authority that
//                           signed it, the label, where it came from, its
//                           validity, and its revocation when it was revoked
//                           here. This is what verifies a signature.
//   stsAssertionPrivateKey  ONE VALUE PER KEY PAIR THIS SERVICE GENERATED:
//                           `{ id, pem }` as JSON, the WHOLE VALUE **SEALED**
//                           — see below. An uploaded certificate has none.
//
// ---------------------------------------------------------------------------
// SEVERAL KEY PAIRS PER PROFILE, EACH REVOKED ON ITS OWN (#1290, rcbj,
// 2026-11-03).
//
// Until #1290 a person held ONE key pair per profile, in seven single-valued
// attributes (`stsAssertionJwks`, `…Certificate`, `…CertificateChain`,
// `…Kid`, `…ExpiresAt`, `…KeySource` and the private key), and Generate
// REPLACED it. `/portal/signing-key`'s third card, the TLS client
// certificate, held several from the day it was written; rcbj asked for the
// two signing-key cards to work the same way:
//
//   1. **GENERATE ADDS ONE**, optionally named after its use, and leaves the
//      ones already held working — a key on a laptop and a key in a CI job
//      are two keys, and rotating one must not break the other.
//   2. **A KEY PAIR IS REMOVED BY REVOKING IT**, row by row, with the TLS
//      card's two reasons (`REVOCATION_REASONS`): its certificate goes on the
//      issuing authority's CRL and its OCSP responder answers `revoked`, and
//      this service stops accepting what it signs. That REPLACES "take off",
//      which cleared the attributes and put nothing on any list — a
//      certificate this service had stopped believing that every other
//      relying party went on believing.
//   3. **A CAP PER PROFILE**, `pki.personSigningKeyMax` — the TLS card's
//      `pki.personTlsClientCertificateMax` again. It counts VALID key pairs
//      only, so revoking an old one makes room for a new one.
//
// **WHY THE RECORDS ARE ON THE ENTRY RATHER THAN IN THE CERTIFICATE REGISTER
// THE TLS CARD USES.** `tls_client_certificates.js` keeps a person's
// certificates in `pki.certify()`'s register by slot, and that was the
// design to mirror; it does not fit here for two reasons. A signing key is
// found by the VERIFIER — `assertion_grant.js` by `kid` in the person's JWKS,
// `saml_assertion_grant.js` by certificate thumbprint — off the entry the
// `iss` resolves to, and the register holds no JWK. And a person's key pair
// may be a certificate an EXTERNAL authority issued (`upload-certificate`),
// which no register of this service's authorities can hold. So the records
// stay where the single key pair was, one value each, and what is mirrored is
// the BEHAVIOUR: a list with a state per row (valid, expired, revoked,
// superseded), labels, the cap counting what still works, revocation through
// `pki_revocation.js` with the same two reasons, and expired records
// forgotten at the next issue (RFC 5280 section 3.3).
//
// **THE REVOCATION STATE IS READ FROM THE AUTHORITY, NOT ONLY FROM THE
// RECORD.** A key pair issued here records which authority signed it
// (`caId`), and its state is that authority's list — so a serial revoked on
// /admin/pki's revocation pane reads as revoked here too. A certificate an
// external authority issued has no list of ours to go on: revoking it here
// marks the record, the verifiers stop accepting it, and the reply says that
// its own authority's list is not this service's to write.
//
// **THE ISSUER DECLARATION GOES WITH THE LAST KEY.** Revoking leaves the
// other key pairs of the profile working and their declaration with them;
// revoking the last valid one clears the profile's declaration, for the
// reason "take off" cleared it: a person declared as an issuer with no key to
// issue with reads on the page as a key pair that would not go away.
//
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
// act that creates it, once, with the page saying so — and since #1290 it is
// dropped from the entry when its key pair is revoked, because a revoked
// key's private half is a liability with no use.
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
// `helpers.js`, `keystore.js`, `config.js` and `error_codes.js` — none of
// which requires it back — and `realms.js` and `pki_revocation.js` lazily.
// ===========================================================================

// The service's own logger, as every module here takes it.
const { log, subjectForName, nameForSubject } = require('./helpers');
const keystore = require('./keystore');
// The cap, `pki.personSigningKeyMax` (#1290). `config.js` is below
// `helpers.js` and requires nothing of this module.
const config = require('./config');
// A leaf. The refusal objects below carry `errorCode` for the caller that
// sends the response; it is never part of anything serialised.
const errorCodes = require('./error_codes');
// CAEP credential-change when this file changes a person's credential
// (#145), through `ssf/account_signals.ts` — required LAZILY, when an event
// is due. This file is loaded from `app.js`'s own chain, before the
// composition root defers instance building
// (`common/instance_slot.ts`), and requiring that module here at load time
// built its default instance too early for the root to install its own.
function accountSignals() {
  log.debug('Entering accountSignals().');
  log.debug('Leaving accountSignals().');
  return require('../ssf/account_signals');
}

// Revocation is `pki_revocation.js`'s, and the realm whose authorities it
// asks is the ambient one. Both LAZILY, for `tls_client_certificates.js`'s
// reason: `pki_revocation.js` requires `pki.js`, which requires modules this
// file's callers load, and this file is on `app.js`'s own chain.
function revocation() {
  log.debug('Entering revocation().');
  log.debug('Leaving revocation().');
  return require('./pki_revocation');
}

function currentRealm() {
  log.debug('Entering currentRealm().');
  log.debug('Leaving currentRealm().');
  return require('./realms').currentId();
}

/**
 * The attribute declaring the `iss` a person's RFC 7523 assertions are issued
 * under: `stsAssertionIssuer`.
 */
const ISSUER_ATTRIBUTE = 'stsAssertionIssuer';

/**
 * The two attributes holding a person's RFC 7523 key pairs, one value per key
 * pair: the public records, and the sealed private halves (#1290).
 */
const KEY_ATTRIBUTES = ['stsAssertionKeyPair', 'stsAssertionPrivateKey'];

// ===========================================================================
// AN RFC 7522 KEY PAIR TOO, SINCE 2026-09-13, AND IT IS A SECOND SET.
//
// Until that date a person could hold an RFC 7523 key pair and not an RFC
// 7522 one, and `/admin/pki` refused the second by name — the SAML verifier
// read `oauthSamlAssertion*` off an application and nothing off a person, so a
// SAML key pair on a person's entry would have been one nothing could use.
// **The verifier reads a person's now** (`oauth-oidc/saml_assertion_grant.js`),
// under the same refusal the JWT profile makes: a person's assertion may name
// only themselves as its `<Subject>`.
//
// `stsSamlAssertion*` shares no name with `stsAssertion*`, for the reason the
// two application sets share none: no code path crosses them, so a person's
// JWT key pair cannot sign a SAML assertion and revoking one leaves the other
// working. Its records carry no JWK — what an XML Signature is checked against
// is a certificate, and what matches a presented `<ds:KeyInfo>` is its
// THUMBPRINT, which is the handle this set's records go by where the JWT
// set's go by `kid`.
//
// **AND EVERY RECORD SAYS WHERE THE KEY PAIR CAME FROM** (`source`): issued
// here, or a certificate UPLOADED — this realm's own, or an external
// authority's with its whole chain — in which case the person keeps the
// private key and there is no private value for it. The words are
// `applications.KEY_SOURCES`, which this module does not require for
// `applications.js`'s own reason: it sits on the token endpoint's path, and a
// vocabulary of three words is not worth a module.
// ===========================================================================
/**
 * The attribute declaring the `<Issuer>` a person's RFC 7522 assertions are
 * issued under: `stsSamlAssertionIssuer`.
 */
const SAML_ISSUER_ATTRIBUTE = 'stsSamlAssertionIssuer';

/**
 * The two attributes holding a person's RFC 7522 key pairs, one value per key
 * pair: the public records, and the sealed private halves (#1290).
 */
const SAML_KEY_ATTRIBUTES = ['stsSamlAssertionKeyPair',
                             'stsSamlAssertionPrivateKey'];

// WHICH ATTRIBUTE HOLDS WHAT, PER PROFILE. `present` is the attribute whose
// presence means the profile holds a key pair at all (valid or not), which
// is what the directory is asked for its holders by; `handleLabel` is what
// the records go by.
/**
 * Which attribute holds what, per profile (`jwt` and `saml`): the issuer
 * declaration, the key pair records and the sealed private halves.
 */
const KEY_PAIR_ATTRIBUTES = {
  jwt: { issuer: ISSUER_ATTRIBUTE, keys: 'stsAssertionKeyPair',
         privateKey: 'stsAssertionPrivateKey', handleLabel: 'kid',
         present: 'stsAssertionKeyPair', rfc: 'RFC 7523',
         attributes: KEY_ATTRIBUTES.slice() },
  saml: { issuer: SAML_ISSUER_ATTRIBUTE, keys: 'stsSamlAssertionKeyPair',
          privateKey: 'stsSamlAssertionPrivateKey',
          handleLabel: 'thumbprint', present: 'stsSamlAssertionKeyPair',
          rfc: 'RFC 7522', attributes: SAML_KEY_ATTRIBUTES.slice() }
};

/**
 * The profiles a person may hold key pairs for: `jwt` and `saml`.
 */
const PURPOSE_IDS = Object.keys(KEY_PAIR_ATTRIBUTES);

// Every attribute this module owns, which is what the directory has to hand
// back.
/**
 * Every attribute this module owns, both profiles' declarations and key pairs.
 */
const ATTRIBUTES = [ISSUER_ATTRIBUTE].concat(KEY_ATTRIBUTES)
  .concat([SAML_ISSUER_ATTRIBUTE]).concat(SAML_KEY_ATTRIBUTES);

// The ones that are private key material. A list for `applications.js`'s
// reason: *is this attribute private key material* is a question somebody
// adding a name above has to answer, and a list is where they will look for
// it. Each VALUE is sealed whole, so `cell_rehome.ts` — which re-seals a
// value that begins `$aesgcm$` — moves it like any other sealed value.
/**
 * The attributes that hold private key material, each value sealed under the
 * key-encryption key where one persists.
 */
const SEALED_ATTRIBUTES = ['stsAssertionPrivateKey',
                           'stsSamlAssertionPrivateKey'];

/**
 * The two RFC 5280 reasons a holder may give when revoking their own key
 * pair: the TLS client certificate card's (#1290).
 */
const REVOCATION_REASONS = ['cessationOfOperation', 'keyCompromise'];

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
/**
 * Fills the directory slot this register reads and writes people through.
 *
 * Validated whole: hooks missing any of `read`, `write` and `persons` are
 * refused (STS-OAUTH-0084).
 *
 * @param hooks - `{ read, write, persons }`, and optionally `holdingAny`
 *   (#352), which `holders()` walks the directory through once. `write`
 *   takes an attribute name and a value, or an ARRAY of values (#1290)
 * @returns true when installed, false when refused
 */
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
/**
 * Tells whether there is a directory to store key pairs in.
 *
 * @returns true once the slot is filled
 */
function storable() {
  log.debug("Entering storable().");
  log.debug("Leaving storable().");
  return !!directory;
}

/**
 * Answers the most valid key pairs one person may hold for ONE profile:
 * `pki.personSigningKeyMax` (#1290).
 *
 * @returns the configured cap
 */
function maxPerPerson() {
  log.debug("Entering maxPerPerson().");
  log.debug("Leaving maxPerPerson().");
  return Number(config.value('pki.personSigningKeyMax'));
}

/**
 * Tells whether a stored value is sealed under the key-encryption key.
 *
 * @param value - the stored value
 * @returns true for a `$aesgcm$` value
 */
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
function sealValue(value) {
  log.debug("Entering sealValue().");
  if (!value || isSealed(value) || !keystore.persists()) {
    log.debug("Leaving sealValue().");
    return String(value == null ? '' : value);
  }
  // Under the CELL's key where there is one (#98): a person's key pair is
  // theirs and lives only in their home cell.
  const out = keystore.seal(String(value), SEAL_LABEL, 'cell');
  log.debug("Leaving sealValue().");
  return out || null;
}

// And open on the way out. A value that will NOT open is reported and treated
// as a private key that is HELD but unusable, which is `openSealedFields()`'s
// rule: rotating the key-encryption key produces one, and a line in the log
// naming the person is a truer answer than an absent key — which would read
// as *no key pair was ever issued here*.
function openValue(value, username) {
  log.debug("Entering openValue().");
  const text = String(value == null ? '' : value);
  if (!isSealed(text)) {
    log.debug("Leaving openValue().");
    return text;
  }
  const opened = keystore.open(text, SEAL_LABEL);
  if (!opened) {
    log.warn(errorCodes.tag('STS-OAUTH-0088') +
             'person_assertions: an assertion private key on "' + username +
             '" is sealed and will not open under this process\'s ' +
             'key-encryption key — it was written under a different one. ' +
             'It is counted as held and cannot be read; revoke that key ' +
             'pair and issue another.');
    log.debug("Leaving openValue().");
    return null;
  }
  log.debug("Leaving openValue().");
  return String(opened);
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

// One stored record, or null for a value that is not one. A value that will
// not parse is LOGGED and skipped rather than thrown: one damaged value must
// not take every other key pair of the person down with it.
function parseRecord(text, username) {
  log.debug("Entering parseRecord().");
  let out = null;
  try {
    out = JSON.parse(String(text));
  } catch (e) {
    log.warn('person_assertions: a key pair record on "' + username +
             '" is not JSON and is ignored: ' + ((e && e.message) || e));
    out = null;
  }
  log.debug("Leaving parseRecord().");
  return out && typeof out === 'object' && out.id ? out : null;
}

// The id a private value belongs to, without opening it where it is sealed:
// a sealed value is opened only when the private key itself is asked for.
// Null for a sealed value, which the caller resolves by opening it.
function privateIdOf(text) {
  log.debug("Entering privateIdOf().");
  if (isSealed(text)) {
    log.debug("Leaving privateIdOf(). Sealed.");
    return null;
  }
  const parsed = parseRecord(text, '');
  log.debug("Leaving privateIdOf().");
  return parsed ? String(parsed.id) : '';
}

// RFC 5280 serials compared in one spelling — `pki_revocation.js`'s rule,
// written out here because that module is required lazily and a comparison
// must not fail for want of it.
function normalSerial(text) {
  log.debug("Entering normalSerial().");
  const hex = String(text || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  log.debug("Leaving normalSerial().");
  return hex.replace(/^0+/, '') || '0';
}

// ---------------------------------------------------------------------------
// ONE KEY PAIR'S STATE, the TLS card's four words: `valid`, `expired`,
// `revoked`, or `superseded` (a revocation like any other, which a rebuilt
// branch writes, and reported as what it is). The issuing authority's list
// wins over the record, because it is what a relying party reads; the
// record's own mark is what an external authority's certificate has.
// ---------------------------------------------------------------------------
function stateOf(record, scope) {
  log.debug("Entering stateOf().");
  let listed = null;
  if (record.caId && record.serialHex) {
    try {
      listed = revocation().isRevoked(scope, record.caId, record.serialHex);
    } catch (e) {
      // No revocation register in this process (a test's stub directory, a
      // process with no authority). The record's own mark is all there is.
      log.debug("Caught in stateOf(): " + ((e && e.message) || e));
      listed = null;
    }
  }
  const revokedAt = listed ? listed.revokedAt
                           : (record.withdrawnAt || null);
  const reason = listed ? listed.reason : (record.withdrawnReason || null);
  const expired = !!record.notAfter &&
    new Date(record.notAfter).getTime() < Date.now();
  const state = revokedAt
    ? (reason === 'superseded' ? 'superseded' : 'revoked')
    : (expired ? 'expired' : 'valid');
  log.debug("Leaving stateOf(). " + state);
  return { state: state, revokedAt: revokedAt, reason: reason };
}

// ONE STORED RECORD'S STATE IN THE CURRENT REALM, for a reader that has the
// record in hand and not the entry — the reports source (#1290). Without it
// that reader could see only the record's own mark, and a key pair revoked
// on `/admin/pki`'s revocation pane, which writes the list and not the
// record, would go on counting as held.
/**
 * A stored key pair record's state, from the issuing authority's list in
 * the current realm and the record's own mark.
 *
 * @param record - one parsed `stsAssertionKeyPair` or
 *   `stsSamlAssertionKeyPair` value
 * @returns `{ state, revokedAt, reason }`; `state` is `valid`, `expired`,
 *   `revoked` or `superseded`
 */
function keyPairState(record) {
  log.debug("Entering keyPairState().");
  let scope = '';
  try {
    scope = currentRealm();
  } catch (e) {
    log.debug("Caught in keyPairState(): " + ((e && e.message) || e));
    scope = '';
  }
  const out = stateOf(record || {}, scope);
  log.debug("Leaving keyPairState(). " + out.state);
  return out;
}

// ---------------------------------------------------------------------------
// ONE PROFILE'S KEY PAIRS OUT OF THE ATTRIBUTES ALREADY READ, newest first,
// each with its state. **`openKeys` FALSE LEAVES THE PRIVATE KEYS OUT** — not
// opened and not copied sealed either — and it is what `holders()` and every
// page pass: a report of who holds which key pair is answered by public
// halves, and opening the private ones cost a `keystore.open()` per key per
// page view (#352). `privateKeyHeld` is answered either way, from the id a
// plain value carries and, for a sealed value, from the count of them.
// ---------------------------------------------------------------------------
function keysOf(name, raw, purpose, openKeys, scope) {
  log.debug('Entering keysOf(). purpose=' + purpose);
  const names = KEY_PAIR_ATTRIBUTES[purpose];
  const privates = valuesOf(raw[names.privateKey]);
  const opened = {};
  let sealedUnopened = 0;
  privates.forEach(function (text) {
    const id = privateIdOf(text);
    if (id) {
      opened[id] = openKeys ? (parseRecord(text, name) || {}).pem || '' : true;
      return;
    }
    if (!openKeys) {
      sealedUnopened += 1;
      return;
    }
    const plain = openValue(text, name);
    const parsed = plain ? parseRecord(plain, name) : null;
    if (parsed) {
      opened[String(parsed.id)] = String(parsed.pem || '');
    }
  });
  const rows = valuesOf(raw[names.keys]).map(function (text) {
    return parseRecord(text, name);
  }).filter(Boolean).map(function (record) {
    const state = stateOf(record, scope);
    const issued = String(record.source || 'issued') === 'issued';
    const row = Object.assign({}, record, {
      id: String(record.id),
      label: String(record.label || ''),
      source: String(record.source || 'issued'),
      chainPem: String(record.chainPem || ''),
      state: state.state,
      revokedAt: state.revokedAt,
      reason: state.reason,
      // A sealed value names no id until it is opened, so a page that did
      // not open them reads "held" for every issued key pair that is not
      // revoked while any sealed value is there — which is what the writer
      // keeps true: an issued key pair's private half is written with it and
      // dropped when it is revoked or forgotten.
      privateKeyHeld: Object.prototype.hasOwnProperty.call(opened,
                                                           String(record.id)) ||
                      (!openKeys && issued && sealedUnopened > 0 &&
                       (state.state === 'valid' || state.state === 'expired'))
    });
    if (openKeys) {
      row.privateKeyPem = typeof opened[row.id] === 'string'
        ? opened[row.id] : '';
    }
    return row;
  });
  rows.sort(function (a, b) {
    return String(b.createdAt || '').localeCompare(String(a.createdAt || ''));
  });
  log.debug('Leaving keysOf(). ' + rows.length + ' key pair(s).');
  return rows;
}

// ---------------------------------------------------------------------------
// WHAT ONE PERSON HOLDS. `null` where there is no entry at all, which the
// callers keep apart from an entry holding nothing: the first is a name
// nobody in this realm has and the second is somebody who has not been issued
// a key pair.
// ---------------------------------------------------------------------------
/**
 * Reads what one person holds: declared issuers and both profiles' key pairs,
 * each with its state, private keys opened.
 *
 * A sealed private key that will not open is logged (STS-OAUTH-0088) and its
 * key pair reported with no private key.
 *
 * @param username - the person's username
 * @returns the record — `keys.jwt` and `keys.saml` (newest first), `hasKeyPair`
 * and `hasSamlKeyPair` (a VALID one is held), `jwks` (the valid RFC 7523 keys)
 * and `samlCertificates` (the valid RFC 7522 certificates with their chains),
 * and the effective issuers (the username where none is declared); null where
 * there is no such entry
 */
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
  log.debug('Leaving recordFor().');
  return recordOf(name, raw, true);
}

// ---------------------------------------------------------------------------
// ONE PERSON'S RECORD OUT OF THE ATTRIBUTES ALREADY READ, which is
// `recordFor()`'s body since #352 (2026-09-29) so that `holders()` can build
// the same record out of a walk without a second read per person.
// ---------------------------------------------------------------------------
function recordOf(name, raw, openKeys) {
  log.debug('Entering recordOf(). username=' + name);
  let scope = '';
  try {
    scope = currentRealm();
  } catch (e) {
    log.debug("Caught in recordOf(): " + ((e && e.message) || e));
    scope = '';
  }
  const keys = { jwt: keysOf(name, raw, 'jwt', openKeys, scope),
                 saml: keysOf(name, raw, 'saml', openKeys, scope) };
  const valid = function (one) {
    return one.state === 'valid';
  };
  const out = { username: name,
                issuers: valuesOf(raw[ISSUER_ATTRIBUTE]),
                samlIssuers: valuesOf(raw[SAML_ISSUER_ATTRIBUTE]),
                keys: keys,
                hasKeyPair: keys.jwt.some(valid),
                hasSamlKeyPair: keys.saml.some(valid),
                // WHAT THE VERIFIERS READ, and only the VALID key pairs: a
                // revoked or expired one is not in it, so an assertion signed
                // with it finds no key by its `kid` or thumbprint and is
                // refused as one signed by nobody registered.
                jwks: { keys: keys.jwt.filter(valid).map(function (one) {
                  return one.jwk;
                }).filter(Boolean) },
                samlCertificates: keys.saml.filter(valid)
                  .map(function (one) {
                    return { pem: String(one.certificatePem || ''),
                             chain: String(one.chainPem || ''),
                             thumbprint: String(one.thumbprint || one.id) };
                  }) };
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
  log.debug('Leaving recordOf(). ' + keys.jwt.length + ' JWT and ' +
            keys.saml.length + ' SAML key pair(s).');
  return out;
}

// ---------------------------------------------------------------------------
// ONE PERSON'S KEY PAIRS FOR ONE PROFILE, as the TLS card's `listFor()` reads
// them: newest first, each with its state, NO private key. What
// `/portal/signing-key`, `/admin/users` and `/admin-api` draw.
// ---------------------------------------------------------------------------
/**
 * Lists one person's key pairs for one profile, each with its state: valid,
 * expired, revoked or superseded. No private key is in the answer.
 *
 * @param username - the person's username
 * @param purpose - `jwt` (the default) or `saml`
 * @returns one row per key pair, newest first; empty where there is no such
 *   person or profile
 */
function listFor(username, purpose) {
  log.debug('Entering listFor(). username=' + username);
  const id = purposeIdOf(purpose);
  const name = String(username || '');
  const raw = directory && name && id ? directory.read(name) : null;
  if (!raw) {
    log.debug('Leaving listFor(). Nothing to read.');
    return [];
  }
  let scope = '';
  try {
    scope = currentRealm();
  } catch (e) {
    log.debug("Caught in listFor(): " + ((e && e.message) || e));
    scope = '';
  }
  const rows = keysOf(name, raw, id, false, scope);
  log.debug('Leaving listFor(). ' + rows.length + ' key pair(s).');
  return rows;
}

/**
 * Lists one person's key pairs for one profile that are still valid: what the
 * cap counts.
 *
 * @param username - the person's username
 * @param purpose - `jwt` (the default) or `saml`
 * @returns the valid rows of `listFor()`
 */
function activeFor(username, purpose) {
  log.debug('Entering activeFor().');
  log.debug('Leaving activeFor().');
  return listFor(username, purpose).filter(function (one) {
    return one.state === 'valid';
  });
}

/**
 * Tells whether a person is at the cap for a profile: as many valid key pairs
 * as `pki.personSigningKeyMax`. Callers ask BEFORE generating a key pair, so
 * that one is not generated only to be refused by `write()`.
 *
 * @param username - the person's username
 * @param purpose - `jwt` (the default) or `saml`
 * @returns true at the cap
 */
function atCap(username, purpose) {
  log.debug('Entering atCap().');
  const held = activeFor(username, purpose).length;
  log.debug('Leaving atCap(). ' + held + ' valid.');
  return held >= maxPerPerson();
}

// A label is what a person calls the key pair — "CI job", "laptop" — and it
// lands on their own page and on /admin/users. The TLS card's rule for its
// device names, and for its reason: letters, digits, spaces and a little
// punctuation, so that nothing in it needs escaping to be read.
/**
 * Checks a key pair's label: at most 40 letters, digits, spaces, dots,
 * dashes, underscores and brackets.
 *
 * @param label - the label
 * @returns the sentence describing the problem, or an empty string
 */
function labelProblem(label) {
  log.debug("Entering labelProblem().");
  const text = String(label || '');
  log.debug("Leaving labelProblem().");
  return text.length <= 40 && /^[A-Za-z0-9 ._()-]*$/.test(text)
    ? ''
    : 'A name for the key pair is at most 40 letters, digits, spaces, ' +
      'dots, dashes, underscores and brackets.';
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
// **A PERSON WITH NO VALID KEY PAIR IS NOT AN ISSUER**, and that is deliberate
// rather than an optimisation: every person in this realm would otherwise be
// an issuer by the fallback above, so an assertion naming any of them would
// get past the registered-issuer refusal and be judged on its `x5c` alone.
// Holding a key pair is the thing an operator DID — and since #1290 a key
// pair that was revoked or has expired is not one held.
//
// **IT IS A SCAN OF THE KEY PAIRS' HOLDERS, AND THE COST IS WRITTEN DOWN HERE
// RATHER THAN HIDDEN.** One read per person holding the profile's records
// (since #616, which follows from the rule just above; it was one read per
// person in the realm, so a realm carrying the bulk-load job's five thousand
// entries paid five thousand reads for a grant whose `iss` matched no
// application). Reading `iss` as a username FIRST would make the common case
// one read, and it was refused: a DECLARED value has to win over a bare name
// (that is what `issuerEntry()` does for an application, and what lets
// somebody assert under a URI), and a shortcut that answered before the
// declarations had been looked at would resolve one person's declared issuer
// to a different person who happens to be called that. An index keyed by
// declared issuer is the answer if this ever matters; it would be a second
// copy of what is on the entries, which is the thing this register
// deliberately does not keep.
//
// **`purpose` SAYS WHICH PROFILE IS ASKING** (2026-09-13), and it decides both
// halves of the question: which declaration is searched and which key pairs
// make somebody an issuer. A person holding only RFC 7523 key pairs is no
// RFC 7522 issuer, and the reverse — which is the crossing the two attribute
// sets exist to prevent, made once here instead of being hoped for. Absent
// means `jwt`, which is what every caller written before the SAML set sends.
// ---------------------------------------------------------------------------
/**
 * Finds the person, if any, who issues assertions under an issuer name for a
 * profile.
 *
 * A declared issuer wins over a bare username, and a person with no valid key
 * pair for the profile is no issuer. One read per HOLDER of the profile's key
 * pairs (#616), not per person in the realm.
 *
 * @param iss - the assertion's issuer
 * @param purpose - `jwt` (the default) or `saml`
 * @returns `{ identifier, record, declared }`, or null
 */
function issuerFor(iss, purpose) {
  log.debug('Entering issuerFor(). iss=' + iss + ' purpose=' + purpose);
  const wanted = String(iss || '');
  const saml = purposeIdOf(purpose) === 'saml';
  if (!directory || !wanted || !purposeIdOf(purpose)) {
    log.debug('Leaving issuerFor(). No directory, issuer or profile.');
    return null;
  }
  // THE HOLDERS OF THE PROFILE'S KEY PAIRS, NOT EVERY PERSON (#616). A person
  // with no key pair for the profile is no issuer (below), so only they need
  // be read — and `holdingAny()` asks the directory for exactly them, in
  // `persons()`' order (in a windowed process the store's `attr_names`
  // holders, a page at a time). A directory without `holdingAny()` is walked
  // as before.
  const holderNames = typeof directory.holdingAny === 'function'
    ? (directory.holdingAny([KEY_PAIR_ATTRIBUTES[saml ? 'saml' : 'jwt']
      .present]) || []).map(function (one) {
      return String(one.username);
    })
    : null;
  const names = holderNames || directory.persons() || [];
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
/**
 * Tells whether an assertion's subject names the person who signed it: their
 * username, a declared issuer for the profile, or their own `urn:uuid:`
 * subject.
 *
 * @param record - the signer's record, from `recordFor()`
 * @param sub - the assertion's subject
 * @param purpose - `jwt` (the default) or `saml`
 * @returns true when the subject is the signer
 */
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
// WHICH AUTHORITY OF THIS REALM SIGNED A CERTIFICATE, by the id its
// revocation list is kept under — what a revocation has to name, because a
// serial is unique only within one issuer. An issued key pair says
// (`useCase`, `pki.issueSigningKeyPair()`); an uploaded certificate this
// realm's authority issued is found by asking each authority of the realm
// whether it issued that serial; an external authority's certificate is
// none of them, and answers ''.
// ---------------------------------------------------------------------------
function authorityOf(scope, record) {
  log.debug('Entering authorityOf().');
  const serial = String(record.serialHex || '');
  if (!serial) {
    log.debug('Leaving authorityOf(). No serial.');
    return '';
  }
  if (record.useCase) {
    log.debug('Leaving authorityOf(). Named by the issue.');
    return String(record.useCase);
  }
  if (String(record.source || '') === 'uploaded-external-ca') {
    log.debug('Leaving authorityOf(). An external authority.');
    return '';
  }
  let found = '';
  try {
    const rev = revocation();
    rev.authorities([scope]).some(function (one) {
      if (one.scope !== String(scope) || one.ca === 'root' ||
          one.ca === 'intermediate' || !rev.issuedHere(scope, one.ca, serial)) {
        return false;
      }
      found = String(one.ca);
      return true;
    });
  } catch (e) {
    // No authority in this process to ask: the certificate is held to its
    // record's own mark, which is what an external one is.
    log.debug('Caught in authorityOf(): ' + ((e && e.message) || e));
    found = '';
  }
  log.debug('Leaving authorityOf(). ' + (found || 'none of ours'));
  return found;
}

// ---------------------------------------------------------------------------
// THE WRITE. **IT ADDS ONE KEY PAIR** (#1290), where until then it replaced
// the one held. Every value or none of them, and a failure says which one —
// `common/pki.js` hands a key pair over ONCE and keeps no copy, so a write
// that half-succeeded is a key pair that is gone with a certificate on the
// entry claiming otherwise.
//
// **`opts.purpose` PICKS THE SET**, defaulting to `jwt`. A record from
// `pki.registerCertificate()` has an EMPTY private key: the person holds it,
// and no private value is written for that key pair. The private key goes
// FIRST, for the reason it always did: a write that fails after it leaves a
// private value with no record, which nothing reads, rather than a record
// whose key is lost.
//
// **THE CAP IS CHECKED HERE AS WELL AS AT THE DOORS.** The doors ask
// `atCap()` before generating a key pair, so that one is not generated only
// to be refused; this is the check that holds whatever door is added next.
// A record whose id is already held REPLACES that record — the same
// certificate uploaded twice is one key pair — and is not counted twice.
// Expired records are forgotten first (RFC 5280 section 3.3, and the TLS
// card's rule), so a person who replaces a key pair a year is not kept a
// record of every one; a REVOKED one that has not expired stays, because its
// record is what lets the page say it was revoked.
// ---------------------------------------------------------------------------
/**
 * Adds an issued or uploaded key pair to a person's entry, every value or a
 * failure naming which one.
 *
 * The private key is sealed and written first; a key pair that fails to seal
 * or write is lost, since this service keeps no copy. Refused at the cap
 * (`pki.personSigningKeyMax`, STS-PKI-0223) and for a label that is not a
 * short name (STS-PKI-0225). A CAEP credential-change event follows a
 * successful write.
 *
 * @param username - the person's username
 * @param record - the key pair from `pki.js`: private key, certificate, chain,
 * JWK, `kid`, thumbprint, serial, `notAfter`, `source`
 * @param opts - `purpose` (`jwt` by default), `issuer` to declare, `label`,
 * and `initiatingEntity` and `via` for the event
 * @returns `{ ok, written, key, errors }`, with `errorCode` on a refusal
 */
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
  const label = String(options.label || '').trim();
  const labelSaid = labelProblem(label);
  if (labelSaid) {
    log.debug('Leaving write(). Label refused.');
    return { ok: false, errorCode: 'STS-PKI-0225', errors: [labelSaid] };
  }
  const names = KEY_PAIR_ATTRIBUTES[purpose];
  const raw = directory.read(name);
  if (!raw) {
    log.debug('Leaving write(). Nobody by that name.');
    return { ok: false, errorCode: 'STS-OAUTH-0087', written: [],
             errors: ['There is nobody called "' + name + '" in this ' +
                      'realm, so the key pair could not be written. This ' +
                      'service keeps no second copy of a private key, so ' +
                      'that key pair is gone.'] };
  }
  let scope = '';
  try {
    scope = currentRealm();
  } catch (e) {
    log.debug("Caught in write(): " + ((e && e.message) || e));
    scope = '';
  }
  const id = String(purpose === 'saml' ? record.certificateThumbprint
                                       : record.kid);
  const nowMs = Date.now();
  const held = keysOf(name, raw, purpose, false, scope);
  // What stays: everything not expired, and not the record this one replaces.
  const kept = held.filter(function (one) {
    return one.id !== id && one.state !== 'expired';
  });
  const valid = kept.filter(function (one) {
    return one.state === 'valid';
  }).length;
  if (valid >= maxPerPerson()) {
    log.debug('Leaving write(). The cap is reached.');
    return { ok: false, errorCode: 'STS-PKI-0223', written: [],
             errors: ['"' + name + '" already holds ' + valid + ' ' +
                      names.rfc + ' signing key pair(s) that are still ' +
                      'valid, which is pki.personSigningKeyMax. Revoke one ' +
                      'that is no longer used and issue again.'] };
  }
  const keptIds = kept.map(function (one) {
    return one.id;
  });
  const source = String(record.source || 'issued');
  const stored = {
    id: id,
    label: label,
    kid: String(record.kid || ''),
    thumbprint: String(record.certificateThumbprint || ''),
    source: source,
    serialHex: String(record.serialHex || '').toLowerCase(),
    caId: authorityOf(scope, { serialHex: record.serialHex,
                               useCase: record.useCase, source: source }),
    subject: String(record.subject || ''),
    keyAlg: String(record.keyAlg || ''),
    jwsAlg: String(record.jwsAlg || ''),
    notBefore: String(record.notBefore || ''),
    notAfter: new Date(record.notAfter).toISOString(),
    expiresAt: generalizedTime(new Date(record.notAfter)),
    certificatePem: String(record.certificatePem || ''),
    chainPem: (Array.isArray(record.chainPem) ? record.chainPem
                                              : [record.chainPem || ''])
      .join(''),
    createdAt: new Date(nowMs).toISOString()
  };
  if (purpose === 'jwt') {
    stored.jwk = record.publicJwk ||
      ((record.jwks && record.jwks.keys) || [])[0] || null;
  }
  // THE PRIVATE HALVES THAT STAY: each value's id is read without opening a
  // sealed one where it can be, and a sealed one is opened only to learn
  // which key pair it belongs to. A private value whose key pair is not kept
  // is dropped with it.
  const privates = [];
  const unreadable = [];
  valuesOf(raw[names.privateKey]).forEach(function (text) {
    const plainId = privateIdOf(text);
    const ownId = plainId !== null ? plainId
      : (parseRecord(openValue(text, name) || '', name) || {}).id;
    if (ownId === undefined || ownId === null || ownId === '') {
      // A value that will not open stays: dropping it would be this write
      // destroying somebody's key material it could not read.
      unreadable.push(text);
      return;
    }
    if (keptIds.indexOf(String(ownId)) >= 0) {
      privates.push(text);
    }
  });
  const written = [];
  if (record.privateKeyPem) {
    const sealed = sealValue(JSON.stringify({ id: id,
                                              pem: record.privateKeyPem }));
    if (sealed === null) {
      log.error(errorCodes.tag('STS-OAUTH-0086') +
                'person_assertions: a signing key pair was issued to "' +
                name + '" and its private key could not be sealed. Nothing ' +
                'was written and the key pair is lost; issue again.');
      log.debug('Leaving write(). The seal failed.');
      return { ok: false, errorCode: 'STS-OAUTH-0086', written: written,
               errors: ['`' + names.privateKey + '` could not be sealed ' +
                        'under this service\'s key-encryption key, so it ' +
                        'was not written. This service keeps no second copy ' +
                        'of a private key, so that key pair is gone. Fix the ' +
                        'key-encryption key — /admin/encryption says what is ' +
                        'wrong with it — and issue again.'] };
    }
    privates.push(sealed);
  }
  const plan = [[names.privateKey, privates.concat(unreadable)],
                [names.keys, kept.map(function (one) {
                  return JSON.stringify(storedOf(one));
                }).concat([JSON.stringify(stored)])]];
  if (options.issuer) {
    const declared = valuesOf(raw[names.issuer]);
    if (declared.indexOf(String(options.issuer)) < 0) {
      plan.push([names.issuer, declared.concat([String(options.issuer)])]);
    }
  }
  for (let i = 0; i < plan.length; i++) {
    const attribute = plan[i][0];
    if (!directory.write(name, attribute, plan[i][1].length ? plan[i][1]
                                                            : '')) {
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
  log.info('person_assertions: "' + name + '" now holds another ' +
           names.rfc + ' signing key pair (' + source + '), ' +
           names.handleLabel + '=' + id + ', valid until ' +
           stored.notAfter + ' — ' + (valid + 1) + ' valid in all. It signs ' +
           'assertions ABOUT THAT PERSON and about nobody else.');
  // The certificate is what a receiver can name: its issuer and serial.
  accountSignals().certificateChanged({ username: name,
    pem: stored.certificatePem, changeType: 'create',
    friendlyName: label || (names.rfc + ' assertion signing key'),
    initiatingEntity: String(options.initiatingEntity || 'admin'),
    via: String(options.via || ''),
    reasonAdmin: 'A signing key pair for ' + (purpose === 'saml' ? 'SAML' :
                 'JWT') + ' assertions about ' + name + ' was issued.',
    reasonUser: 'A key that signs assertions about you was issued.' });
  log.debug('Leaving write(). ' + written.length + ' attribute(s).');
  return { ok: true, written: written, errors: [],
           key: Object.assign({}, stored, { state: 'valid',
                                            privateKeyHeld:
                                              !!record.privateKeyPem }) };
}

// A row back to what is stored: the state, the revocation the authority's
// list answered and the private-key flag are READ, never written — the list
// is the authority's, and a stored copy would be a second answer to it. What
// this module marked itself is `withdrawnAt` and `withdrawnReason`, which a
// row carries through untouched.
function storedOf(row) {
  log.debug("Entering storedOf().");
  const out = Object.assign({}, row);
  delete out.state;
  delete out.revokedAt;
  delete out.reason;
  delete out.privateKeyHeld;
  delete out.privateKeyPem;
  log.debug("Leaving storedOf().");
  return out;
}

// RFC 4517 GeneralizedTime, which is how every timestamp in this directory is
// spelled — the SAME three lines `pki_admin.js` writes out beside the
// application's expiry, and a fourth spelling of a timestamp on one entry
// would be worse than a fourth copy of this function. **Never with fractional
// seconds**: RFC 5280 section 4.1.2.5.2 forbids them and a reader that parses
// strictly refuses the whole value, which is the defect
// `tests/pki_anchor_drift.js` was written for.
/**
 * Spells a time as RFC 4517 GeneralizedTime, without fractional seconds.
 *
 * @param when - the time; now when absent
 * @returns the timestamp, such as `20260927120000Z`
 */
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

// ---------------------------------------------------------------------------
// REVOKE ONE KEY PAIR (#1290), which REPLACES "take off".
//
// **FOUND AMONG THIS PERSON'S OWN KEY PAIRS AND NOWHERE ELSE**, by its
// handle (`kid` or thumbprint) or by its certificate's serial — the TLS
// card's `revoke()` rule, for its reason: a handle belonging to somebody else
// matches nothing, so a door that takes one from a form body cannot be used
// to revoke another person's key pair.
//
// What it does, in order:
//
//   1. the certificate goes on its authority's revocation list
//      (`pki_revocation.revoke()`, idempotent — the earlier entry wins), so a
//      relying party that checks the CRL or asks the OCSP responder is told;
//      an external authority's certificate has no list here, and this step
//      is skipped and said;
//   2. the record is MARKED revoked with its reason, which is what an
//      external certificate's state is read from, and its private value is
//      dropped — a revoked key's private half is a liability with no use;
//   3. the verifiers stop accepting it: both read only VALID key pairs
//      (`recordOf()`), so an assertion signed with it finds no registered key;
//   4. where it was the profile's last valid key pair, the issuer
//      declaration goes with it (see the header);
//   5. CAEP credential-change `revoke`, and for `keyCompromise` a RISC
//      credential-compromise — the TLS card's events, for its reasons.
// ---------------------------------------------------------------------------
/**
 * Revokes one of a person's key pairs for one profile, found by handle or
 * serial among that person's key pairs only.
 *
 * Puts the certificate on its authority's CRL (an external authority's is
 * marked revoked here only), drops the private half, and clears the
 * profile's issuer declaration when no valid key pair is left. Raises CAEP
 * (and, for `keyCompromise`, RISC) events.
 *
 * @param username - the person's username
 * @param purpose - `jwt` (the default) or `saml`
 * @param handle - the key pair's `kid` or thumbprint, or its serial in hex
 * @param reasonId - one of `REVOCATION_REASONS`; `cessationOfOperation`
 *   otherwise
 * @param opts - `initiatingEntity` (`user` or `admin`) and `via`, for the
 *   events and the revocation entry's note
 * @returns `{ ok: true, key, reason, already, onList, why }`, or
 *   `{ ok: false, errorCode, errors }` when the person holds no such key pair
 */
function revoke(username, purpose, handle, reasonId, opts) {
  log.debug('Entering revoke(). username=' + username + ' purpose=' +
            purpose + ' handle=' + handle);
  const options = opts || {};
  const name = String(username || '');
  const id = purposeIdOf(purpose);
  const wanted = String(handle || '').trim();
  if (!directory) {
    log.debug('Leaving revoke(). No directory.');
    return { ok: false, errorCode: 'STS-OAUTH-0085',
             errors: ['This process has no directory, so nobody holds a key ' +
                      'pair to revoke.'] };
  }
  if (!id) {
    log.debug('Leaving revoke(). An unknown profile.');
    return { ok: false, errorCode: 'STS-PKI-0011',
             errors: ['"' + purpose + '" is not a profile a person may hold ' +
                      'a key pair for. There are ' + PURPOSE_IDS.join(' and ') +
                      '.'] };
  }
  const reason = REVOCATION_REASONS.indexOf(String(reasonId)) >= 0
    ? String(reasonId) : 'cessationOfOperation';
  const names = KEY_PAIR_ATTRIBUTES[id];
  const raw = name && wanted ? directory.read(name) : null;
  let scope = '';
  try {
    scope = currentRealm();
  } catch (e) {
    log.debug("Caught in revoke(): " + ((e && e.message) || e));
    scope = '';
  }
  const rows = raw ? keysOf(name, raw, id, false, scope) : [];
  const serial = /^[0-9A-Fa-f:]+$/.test(wanted) ? normalSerial(wanted) : '';
  const mine = rows.filter(function (one) {
    return one.id === wanted ||
           (!!serial && !!one.serialHex &&
            normalSerial(one.serialHex) === serial);
  })[0];
  if (!mine) {
    log.debug('Leaving revoke(). Not one of theirs.');
    return { ok: false, errorCode: 'STS-PKI-0224',
             errors: ['"' + name + '" holds no ' + names.rfc + ' signing key ' +
                      'pair with that ' + names.handleLabel + ' or serial ' +
                      'number.'] };
  }
  const initiating = String(options.initiatingEntity || 'admin');
  let onList = null;
  if (mine.caId && mine.serialHex) {
    onList = revocation().revoke(scope, mine.caId, {
      serialHex: mine.serialHex,
      reason: reason,
      subject: mine.subject,
      note: initiating === 'user'
        ? 'revoked by ' + name + ' on the user portal'
        : 'revoked for ' + name + ' by an administrator'
    });
    if (!onList.ok) {
      log.debug('Leaving revoke(). The authority refused.');
      return onList;
    }
  }
  const already = mine.state === 'revoked' || mine.state === 'superseded';
  // THE RECORD IS MARKED AND ITS PRIVATE HALF DROPPED. The mark is kept
  // whether or not the authority's list holds the serial (`withdrawnAt`), so
  // an external certificate's state survives, and a list entry that wins
  // over it reads the same either way.
  const revokedAt = (onList && onList.entry && onList.entry.revokedAt) ||
                    mine.revokedAt || new Date().toISOString();
  const kept = rows.map(function (one) {
    if (one.id !== mine.id) {
      return JSON.stringify(storedOf(one));
    }
    return JSON.stringify(storedOf(Object.assign({}, one, {
      withdrawnAt: revokedAt, withdrawnReason: mine.reason || reason })));
  });
  const privates = valuesOf(raw[names.privateKey]).filter(function (text) {
    const plainId = privateIdOf(text);
    const ownId = plainId !== null ? plainId
      : (parseRecord(openValue(text, name) || '', name) || {}).id;
    return String(ownId || '') !== mine.id;
  });
  directory.write(name, names.privateKey, privates.length ? privates : '');
  if (!directory.write(name, names.keys, kept)) {
    log.error(errorCodes.tag('STS-OAUTH-0087') +
              'person_assertions: the ' + names.rfc + ' key pair ' + mine.id +
              ' of "' + name + '" was revoked' +
              (onList ? ' on its authority\'s list' : '') + ' and its ' +
              'record could not be marked.');
  }
  // THE DECLARATION GOES WITH THE LAST VALID KEY PAIR, for the reason the
  // header gives.
  const left = rows.filter(function (one) {
    return one.id !== mine.id && one.state === 'valid';
  }).length;
  let undeclared = false;
  if (!left && valuesOf(raw[names.issuer]).length) {
    undeclared = directory.write(name, names.issuer, '');
  }
  log.info('person_assertions: the ' + names.rfc + ' key pair ' +
           names.handleLabel + '=' + mine.id + ' of "' + name + '" was ' +
           'REVOKED (' + reason + ')' +
           (onList ? ', on the "' + mine.caId + '" authority\'s list'
                   : ', on no list of this service — an external ' +
                     'authority issued it') +
           '. Assertions signed with it are refused from now on; ' + left +
           ' valid key pair(s) of the profile remain.');
  if (!already) {
    const friendly = mine.label || (names.rfc + ' assertion signing key');
    const signal = { username: name, initiatingEntity: initiating,
                     via: String(options.via || '') };
    accountSignals().certificateChanged(Object.assign({}, signal, {
      pem: mine.certificatePem, x509Serial: mine.serialHex,
      changeType: 'revoke', friendlyName: friendly,
      reasonAdmin: 'A ' + names.rfc + ' signing key pair of ' + name +
                   ' was revoked (' + reason + ').',
      reasonUser: initiating === 'user'
        ? 'You revoked a key that signs assertions about you.'
        : 'A key that signs assertions about you was revoked.' }));
    // "SOMEBODY ELSE MAY HAVE THE KEY" (#231): RISC 1.0 section 2.7's
    // `credential-compromise`, beside the CAEP revoke above.
    if (reason === 'keyCompromise') {
      accountSignals().credentialCompromised(Object.assign({}, signal, {
        credentialType: 'x509',
        reasonAdmin: 'A ' + names.rfc + ' signing key pair of ' + name +
                     ' (' + names.handleLabel + ' ' + mine.id + ') was ' +
                     'revoked because its key was compromised.',
        reasonUser: 'A key that signs assertions about you was revoked ' +
                    'because somebody else may have it.' }));
    }
  }
  log.debug('Leaving revoke(). Revoked.');
  return { ok: true, already: already, reason: reason,
           onList: !!onList, undeclared: undeclared, remaining: left,
           key: Object.assign({}, mine, { state: 'revoked',
                                          revokedAt: revokedAt,
                                          reason: mine.reason || reason,
                                          privateKeyHeld: false }),
           why: (onList
             ? 'The certificate is on the "' + mine.caId + '" authority\'s ' +
               'CRL and its OCSP responder answers `revoked` for it'
             : 'An external authority issued that certificate, so it is on ' +
               'no list of this service\'s — revoking it at its own ' +
               'authority is that authority\'s act — and this service has ' +
               'marked it revoked') +
             '. Assertions signed with it are refused from now on.' };
}

// ---------------------------------------------------------------------------
// EVERYBODY IN THIS REALM WHO HOLDS ONE, for `/admin/pki` and for
// `GET /admin-api/pki`. **NO PRIVATE KEY IS IN THIS ANSWER.** It is the one
// report in this module that a page renders, and a page that drew a private
// key would be one that gives it away on every visit to everybody who can
// read the console.
//
// **PRESENCE, READ IN ONE WALK, WITH NOTHING UNSEALED (#352, 2026-09-29).**
// The directory's `holdingAny()`: the people holding any of the four
// attributes that make somebody a row here (either profile's key pairs or
// declared issuer), with their raw values, in the one walk the directory
// makes anyway — and the record built from those values with `openKeys`
// false, so no private key is opened or even copied. A directory that offers
// no `holdingAny()` — an older filler, or a test's stub — is walked the old
// way, still without an unseal.
// ---------------------------------------------------------------------------
/**
 * Lists everybody in the realm who holds a key pair or declares an issuer, for
 * `/admin/pki` and the management API. No private key is in the answer, and
 * none is opened to build it.
 *
 * @returns one row per person: `jwt` and `saml`, each with `keys` (every key
 * pair with its state, newest first), `hasKeyPair` (a valid one is held),
 * the declared and effective issuers
 */
function holders() {
  log.debug('Entering holders().');
  if (!directory) {
    log.debug('Leaving holders(). No directory.');
    return [];
  }
  let found;
  if (typeof directory.holdingAny === 'function') {
    found = (directory.holdingAny([ISSUER_ATTRIBUTE,
      KEY_PAIR_ATTRIBUTES.jwt.present, SAML_ISSUER_ATTRIBUTE,
      KEY_PAIR_ATTRIBUTES.saml.present]) || []).map(function (one) {
      return recordOf(String(one.username), one.attributes || {}, false);
    });
  } else {
    found = (directory.persons() || []).map(function (name) {
      const raw = directory.read(String(name || ''));
      return raw ? recordOf(String(name), raw, false) : null;
    });
  }
  const out = [];
  found.forEach(function (record) {
    if (!record || (!record.keys.jwt.length && !record.issuers.length &&
                    !record.keys.saml.length && !record.samlIssuers.length)) {
      return;
    }
    const profile = function (keys, declared, effective, has) {
      return { hasKeyPair: has, keys: keys, declaredIssuers: declared.slice(),
               issuers: effective.slice(), declared: declared.length > 0 };
    };
    out.push({ username: record.username,
               jwt: profile(record.keys.jwt, record.issuers,
                            record.effectiveIssuers, record.hasKeyPair),
               saml: profile(record.keys.saml, record.samlIssuers,
                             record.samlEffectiveIssuers,
                             record.hasSamlKeyPair) });
  });
  log.debug('Leaving holders(). ' + out.length + ' person(s).');
  return out;
}

/**
 * The register of people who hold RFC 7523 and RFC 7522 signing key pairs,
 * which may assert about that person and about nobody else — several per
 * profile, each revoked on its own (#1290).
 *
 * Key pairs live on the person's directory entry, reached through a slot the
 * directory fills.
 *
 * @namespace
 */
module.exports = {
  ISSUER_ATTRIBUTE: ISSUER_ATTRIBUTE,
  KEY_ATTRIBUTES: KEY_ATTRIBUTES,
  SAML_ISSUER_ATTRIBUTE: SAML_ISSUER_ATTRIBUTE,
  SAML_KEY_ATTRIBUTES: SAML_KEY_ATTRIBUTES,
  KEY_PAIR_ATTRIBUTES: KEY_PAIR_ATTRIBUTES,
  PURPOSE_IDS: PURPOSE_IDS,
  ATTRIBUTES: ATTRIBUTES,
  SEALED_ATTRIBUTES: SEALED_ATTRIBUTES,
  REVOCATION_REASONS: REVOCATION_REASONS,
  setDirectory: setDirectory,
  storable: storable,
  maxPerPerson: maxPerPerson,
  isSealed: isSealed,
  recordFor: recordFor,
  listFor: listFor,
  activeFor: activeFor,
  atCap: atCap,
  labelProblem: labelProblem,
  issuerFor: issuerFor,
  subjectIsSelf: subjectIsSelf,
  write: write,
  revoke: revoke,
  keyPairState: keyPairState,
  holders: holders,
  generalizedTime: generalizedTime
};
