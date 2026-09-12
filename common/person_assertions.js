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
const { log } = require('./helpers');
const keystore = require('./keystore');

// The declaration, and the six the issue writes. A LIST rather than six
// constants, because the console's *take the key pair off* control clears
// exactly this set and a seventh attribute added to the issue and not to the
// list would be one that survived being taken off.
const ISSUER_ATTRIBUTE = 'stsAssertionIssuer';

const KEY_ATTRIBUTES = ['stsAssertionJwks', 'stsAssertionCertificate',
                        'stsAssertionCertificateChain',
                        'stsAssertionPrivateKey', 'stsAssertionKid',
                        'stsAssertionExpiresAt'];

// Every attribute this module owns, which is what the directory has to hand
// back and what a clear removes.
const ATTRIBUTES = [ISSUER_ATTRIBUTE].concat(KEY_ATTRIBUTES);

// The one that is private key material. A list for `applications.js`'s
// reason: *is this attribute private key material* is a question somebody
// adding a name above has to answer, and a list is where they will look for
// it.
const SEALED_ATTRIBUTES = ['stsAssertionPrivateKey'];

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
    log.error('person_assertions: setDirectory() was given something without ' +
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
  return !!directory;
}

function isSealed(value) {
  return String(value == null ? '' : value).indexOf('$aesgcm$') === 0;
}

// Seal on the way in, where this process holds a key-encryption key that will
// still be there after a restart. Returns null where sealing was REQUIRED and
// failed, which the caller turns into a refusal rather than a write: storing a
// private key in the clear in product mode would put a working signing
// credential in every directory dump, and doing it silently after being asked
// not to is worse than refusing.
function sealValue(name, value) {
  if (SEALED_ATTRIBUTES.indexOf(name) < 0 || !value) {
    return String(value == null ? '' : value);
  }
  if (isSealed(value)) {
    return String(value);
  }
  if (!keystore.persists()) {
    return String(value);
  }
  const out = keystore.seal(String(value), SEAL_LABEL);
  if (!out) {
    return null;
  }
  return out;
}

// And open on the way out. A value that will NOT open is left as it is and
// reported, which is `openSealedFields()`'s rule word for word: rotating the
// key-encryption key produces one, the key pair is unusable either way, and a
// reader seeing `$aesgcm$…` where a PEM belongs plus a line in the log naming
// the person is a truer answer than an empty attribute — which would read as
// *no key pair was ever issued*.
function openValue(name, value, username) {
  if (SEALED_ATTRIBUTES.indexOf(name) < 0 || !value || !isSealed(value)) {
    return String(value == null ? '' : value);
  }
  const opened = keystore.open(String(value), SEAL_LABEL);
  if (!opened) {
    log.warn('person_assertions: the assertion private key on "' + username +
             '" is sealed and will not open under this process\'s ' +
             'key-encryption key — it was written under a different one. It ' +
             'is reported as it is stored rather than as absent, because ' +
             'absent would read as no key pair having been issued. Issue ' +
             'again on /admin/pki.');
    return String(value);
  }
  return opened;
}

function valuesOf(value) {
  if (value === undefined || value === null || value === '') {
    return [];
  }
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
                hasKeyPair: false };
  KEY_ATTRIBUTES.forEach(function (attribute) {
    const first = valuesOf(raw[attribute])[0] || '';
    out[attribute] = openValue(attribute, first, name);
  });
  out.hasKeyPair = !!out.stsAssertionJwks;
  // THE ISSUER A PERSON ASSERTS UNDER, defaulted to their own name. It is
  // `effectiveIssuers` rather than an overwrite of `issuers` so that a page
  // can tell a DECLARED value from the default — the same distinction
  // `issuerEntry()` carries as `declared`.
  out.effectiveIssuers = out.issuers.length ? out.issuers.slice() : [name];
  log.debug('Leaving recordFor(). ' +
            (out.hasKeyPair ? 'A key pair.' : 'No key pair.'));
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
// ---------------------------------------------------------------------------
function issuerFor(iss) {
  log.debug('Entering issuerFor(). iss=' + iss);
  const wanted = String(iss || '');
  if (!directory || !wanted) {
    log.debug('Leaving issuerFor(). No directory or no issuer.');
    return null;
  }
  const names = directory.persons() || [];
  let fallback = null;
  for (let i = 0; i < names.length; i++) {
    const record = recordFor(names[i]);
    if (!record || !record.hasKeyPair) {
      continue;
    }
    if (record.issuers.indexOf(wanted) >= 0) {
      log.debug('Leaving issuerFor(). Declared by ' + record.username + '.');
      return { identifier: record.username, record: record, declared: true };
    }
    if (!fallback && !record.issuers.length &&
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
function subjectIsSelf(record, sub) {
  const wanted = String(sub || '');
  if (!record || !wanted) {
    return false;
  }
  return wanted === String(record.username) ||
         record.effectiveIssuers.indexOf(wanted) >= 0;
}

// ---------------------------------------------------------------------------
// THE WRITE. All seven values or none of them, and a failure says which one —
// `common/pki.js` hands a key pair over ONCE and keeps no copy, so a write
// that half-succeeded is a key pair that is gone with a certificate on the
// entry claiming otherwise.
// ---------------------------------------------------------------------------
function write(username, record, opts) {
  log.debug('Entering write(). username=' + username);
  const name = String(username || '');
  const options = opts || {};
  if (!directory) {
    log.debug('Leaving write(). No directory.');
    return { ok: false,
             errors: ['This process has no directory, so there is nowhere to ' +
                      'put a person\'s assertion key pair. `ldap_server.js` ' +
                      'fills the slot at require time; a process without it ' +
                      'can verify nothing either.'] };
  }
  const values = [
    ['stsAssertionJwks', JSON.stringify(record.jwks)],
    ['stsAssertionCertificate', record.certificatePem],
    ['stsAssertionCertificateChain', record.chainPem.join('')],
    ['stsAssertionPrivateKey', record.privateKeyPem],
    ['stsAssertionKid', record.kid],
    ['stsAssertionExpiresAt', generalizedTime(new Date(record.notAfter))]
  ];
  if (options.issuer) {
    values.push([ISSUER_ATTRIBUTE, String(options.issuer)]);
  }
  const written = [];
  for (let i = 0; i < values.length; i++) {
    const attribute = values[i][0];
    const sealed = sealValue(attribute, values[i][1]);
    if (sealed === null) {
      log.error('person_assertions: a signing key pair was issued to "' +
                name + '" and ' + attribute + ' could not be sealed. Nothing ' +
                'was written and the key pair is lost; issue again.');
      log.debug('Leaving write(). The seal failed.');
      return { ok: false, written: written,
               errors: ['`' + attribute + '` could not be sealed under this ' +
                        'service\'s key-encryption key, so it was not ' +
                        'written. This service keeps no second copy of a ' +
                        'private key, so that key pair is gone. Fix the ' +
                        'key-encryption key — /admin/encryption says what is ' +
                        'wrong with it — and issue again.'] };
    }
    if (!directory.write(name, attribute, sealed)) {
      log.error('person_assertions: a signing key pair was issued to "' +
                name + '" and ' + attribute + ' could not be written. The ' +
                'private key is not stored anywhere else and is now lost; ' +
                'issue again.');
      log.debug('Leaving write(). A write failed.');
      return { ok: false, written: written,
               errors: ['`' + attribute + '` could not be written onto "' +
                        name + '". This service keeps no second copy of a ' +
                        'private key, so that key pair is gone. Issue again.'] };
    }
    written.push(attribute);
  }
  log.info('person_assertions: "' + name + '" now holds an RFC 7523 signing ' +
           'key pair, kid=' + record.kid + ', valid until ' + record.notAfter +
           '. It signs assertions ABOUT THAT PERSON and about nobody else.');
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
  const d = when ? new Date(when) : new Date();
  const pad = function (n) { return String(n).padStart(2, '0'); };
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
function clear(username) {
  log.debug('Entering clear(). username=' + username);
  const name = String(username || '');
  if (!directory || !name) {
    log.debug('Leaving clear(). No directory or no name.');
    return { ok: false, removed: 0 };
  }
  const before = recordFor(name);
  if (!before) {
    log.debug('Leaving clear(). Nobody by that name.');
    return { ok: false, removed: 0, unknown: true };
  }
  let removed = 0;
  ATTRIBUTES.forEach(function (attribute) {
    const held = attribute === ISSUER_ATTRIBUTE
      ? before.issuers.length : !!before[attribute];
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
    if (!record || (!record.hasKeyPair && !record.issuers.length)) {
      return;
    }
    out.push({ username: record.username,
               hasKeyPair: record.hasKeyPair,
               declaredIssuers: record.issuers.slice(),
               issuers: record.effectiveIssuers.slice(),
               declared: record.issuers.length > 0,
               kid: record.stsAssertionKid,
               expiresAt: record.stsAssertionExpiresAt,
               certificatePem: record.stsAssertionCertificate });
  });
  log.debug('Leaving holders(). ' + out.length + ' person(s).');
  return out;
}

module.exports = {
  ISSUER_ATTRIBUTE: ISSUER_ATTRIBUTE,
  KEY_ATTRIBUTES: KEY_ATTRIBUTES,
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
