'use strict';
//
// File: rfc7523_person_issuer.js
//
// ===========================================================================
// A PERSON AS THE ISSUER OF AN RFC 7523 SECTION 2.1 ASSERTION, AND THE ONE
// RULE THAT COMES WITH IT.
//
// `tests/assertion_grant.js` beside this one covers the grant as a document —
// the eleven claims of section 3, the algorithms, the encryption, the replay
// cache — with an APPLICATION as the issuer, which is what that grant had
// until 2026-09-11. **This file is about the second kind of issuer**, and
// almost all of it is about one sentence: a person's signing key may sign an
// assertion about THAT PERSON and about nobody else.
//
// ---------------------------------------------------------------------------
// WHY THAT SENTENCE IS WORTH A TEST FILE.
//
// It is the whole security of the feature, and it is refused in a place a
// reader would not think to look at twice. An application declaring
// `oauthAssertionIssuer` is an operator saying *this party may speak about
// people*; a person holding a key pair has said nothing of the kind. If the
// rule lapses, every person who was ever issued a key on `/admin/pki` can
// obtain an access token as anybody in the realm — and nothing about the
// service looks wrong: the signature verifies, the issuer is registered, the
// claims are well formed, the token comes back.
//
// **AND THERE ARE TWO WAYS IN, WHICH IS THE HALF THAT WOULD BE MISSED.** A key
// found on the person's entry, and a CERTIFICATE presented in the assertion's
// own `x5c` header that this service can see it issued. The second does not go
// through the registry at all — that is the point of it — so a check written
// only against the registry would leave the hole open and pass. Section D is
// that case, and it is asserted with the entry CLEARED so that the registry
// cannot be what refuses it.
//
// ---------------------------------------------------------------------------
// **THE FILE NAME IS AN ORDERING CONSTRAINT AND THIS IS THE RECORD OF IT.**
//
// It would be `person_assertions.js`, after the module it is about. It is not,
// because every file in `tests/` runs in ONE process and they are run in name
// order — and this one has to ISSUE, which needs a certificate authority.
//
// **THE ROOT BECAME SERVICE-WIDE ON 2026-09-11**, so only the FIRST thing to
// build one chooses its subject: `tests/pki.js` builds with
// `organisation: 'Acme'` and asserts that the Root carries it, which is true
// exactly while nothing has built a Root before it. Named `person_*` this file
// would sort ahead of `pki.js`, build the Root with the default organisation,
// and that assertion would fail — reporting a defect in `common/pki.js` that
// is really a defect in the name of this file.
//
// So it sorts AFTER `pki_hierarchy.js`, which is the file that builds the whole
// tree, and `pki.hasChain()` below means it uses what is there rather than
// replacing it. Run alone it builds its own and passes; that is the case the
// guard is for.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS `tests/CLAUDE.md`'s FIRST QUESTION.
//
// Two of these claims cannot be reached over HTTP at all. **The sealing** is a
// property of what is on the entry rather than of any reply — the write door
// seals and the read door opens, so every request in the service sees a PEM
// whichever mode it is in. And **a certificate issued to a person who has
// since been deleted** is a state no sequence of endpoint calls can produce
// while still holding the private key that goes with it.
//
// The over-HTTP half is section 13 of `tests/vendored/sts_jwt_bearer_grant.js`,
// which issues through `/admin-api/pki`, signs with an implementation of its
// own and drives `/oauth2/token`. The two are not substitutes: this one says
// the rule holds, that one says the doors are wired to it.
// ===========================================================================

const nodeCrypto = require('crypto');
const pki = require('../common/pki');
const personAssertions = require('../common/person_assertions');
const assertionGrant = require('../oauth-oidc/assertion_grant');
const applications = require('../common/applications');
// The directory, for the entries these people live in. Requiring it here is
// what fills `person_assertions.setDirectory()` — the whole feature is
// unreachable without it, and a test that quietly ran against an unfilled slot
// would report that nothing is an issuer, which is the passing answer for the
// wrong reason.
const ldap = require('../ldap/ldap_server');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'rfc7523_person_issuer',
  level: process.env.LOG_LEVEL || 'info' });

const AUD = ['https://localhost:8081/oauth2/token'];

function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString('base64url');
}

// THIS FILE'S OWN SIGNER, for `sts_dpop.js`'s reason read one layer down: if
// the document under test were built by the module that verifies it, a shared
// misunderstanding of RFC 7515 would make every assertion below pass and
// interoperate with nobody. Three lines, RSA and EC alike through node's own
// `sign()`.
function signJws(header, payload, privateKeyPem) {
  log.debug("Entering signJws().");
  const head = b64u(Buffer.from(JSON.stringify(header), 'utf8'));
  const body = b64u(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signing = head + '.' + body;
  const digest = { RS256: 'sha256', RS384: 'sha384', RS512: 'sha512',
                   ES256: 'sha256', ES384: 'sha384' }[header.alg];
  if (!digest) {
    throw new Error('this file signs RS* and ES*; asked for ' + header.alg);
  }
  const options = /^ES/.test(header.alg)
    ? { key: privateKeyPem, dsaEncoding: 'ieee-p1363' } : privateKeyPem;
  const sig = nodeCrypto.sign(digest, Buffer.from(signing, 'ascii'), options);
  log.debug("Leaving signJws().");
  return signing + '.' + b64u(sig);
}

function seconds() {
  log.debug("Entering seconds().");
  log.debug("Leaving seconds().");
  return Math.floor(Date.now() / 1000);
}

let counter = 0;
function claimsFor(iss, sub) {
  log.debug("Entering claimsFor().");
  counter += 1;
  log.debug("Leaving claimsFor().");
  return { iss: iss, sub: sub, aud: AUD[0], iat: seconds(),
           exp: seconds() + 120, jti: 'person-assertions-' + counter };
}

async function run(t) {
  log.debug("Entering run().");
  // -------------------------------------------------------------------------
  // A. THE REGISTER, AND WHAT AN ISSUE PUTS ON THE ENTRY.
  // -------------------------------------------------------------------------
  t.check(personAssertions.storable(),
          'A. the directory filled person_assertions.setDirectory(), so a ' +
          'person can hold a key pair at all — without this every assertion ' +
          'below is refused for want of an issuer and the file passes having ' +
          'proved nothing');

  // **USED AND NOT REBUILT, AND THE DIFFERENCE COST A SUITE ONCE.** Every file
  // in `tests/` runs in ONE process and this hierarchy is shared state, so a
  // `buildChain()` here would REPLACE what is there — the whole tree
  // `tests/pki_hierarchy.js` built before this file ran (name order; see the
  // header), which the files after this one issue from. `pki.start()` is what
  // that file calls and is the one door that builds the whole tree rather than
  // the legacy single chain; calling it only when there is nothing leaves an
  // existing tree untouched.
  // `tests/pki_anchor_drift.js` records the same mistake and restores at its
  // end; this file avoids making it.
  const built = pki.hasChain()
    ? { ok: true }
    : await pki.start({});
  t.check(built.ok, 'a certificate authority exists to issue from — ENSURED ' +
          'and not rebuilt, because every file here runs in one process and ' +
          'this hierarchy is shared with the files that run after it',
          (built.errors || []).join(' '));

  const ALICE = 'pa-alice';
  const BOB = 'pa-bob';
  ldap.createUser(ALICE, {});
  ldap.createUser(BOB, {});

  const issued = await pki.issueSigningKeyPair(undefined, {
    identifier: ALICE, purpose: 'jwt', subjectKind: 'person'
  });
  t.check(issued.ok, 'a signing key pair is issued to a PERSON',
          (issued.errors || []).join(' '));
  const record = issued.issued;

  t.equal(record.subjectUri, 'urn:sts:person:' + ALICE,
          'and the certificate says WHO it is for in a URI subjectAltName. ' +
          'This is the fact section D rests on: a certificate read out of ' +
          'context says whether it belongs to a person or an application, ' +
          'where "which attribute was it stored in" is an answer nobody ' +
          'holding a PEM file can get to');
  t.check(/^person-/.test(record.kid),
          'the kid says so too, which is the half an operator reads',
          record.kid);

  const appIssued = await pki.issueSigningKeyPair(undefined, {
    identifier: 'pa-app', purpose: 'jwt'
  });
  t.equal((appIssued.issued || {}).subjectUri, 'urn:sts:application:pa-app',
          'and an issue that names no subject kind is an APPLICATION\'s, ' +
          'byte-for-byte what this function produced before people could ' +
          'hold a key pair — a default that changed the shape of a ' +
          'certificate would make this function\'s output depend on when it ' +
          'was called');

  const written = personAssertions.write(ALICE, record, {});
  t.check(written.ok, 'the key pair is written onto the person\'s own entry',
          (written.errors || []).join(' '));
  t.equal(written.written.length, 7,
          'seven attributes — the private key, the certificate, the JWKS, ' +
          'the chain, the kid, the expiry and (since 2026-09-13) where the ' +
          'key pair came from. All or none: ' +
          'common/pki.js hands a key pair over once and keeps no copy, so a ' +
          'half-written entry is a key pair that is gone with a certificate ' +
          'claiming otherwise');

  const held = personAssertions.recordFor(ALICE);
  t.check(held && held.hasKeyPair, 'and it reads back');
  t.equal(JSON.stringify(held.effectiveIssuers), JSON.stringify([ALICE]),
          'with the person\'s own name as the issuer they assert under. ' +
          'Nothing was declared, and asking an operator to write a name down ' +
          'twice is a configuration step with no decision in it — which is ' +
          'the rule issuerEntry() already follows for an application\'s ' +
          'client_id');
  t.check(/BEGIN (RSA )?PRIVATE KEY/.test(held.stsAssertionPrivateKey),
          'the private half comes back through this module OPENED, whatever ' +
          'the store holds — the seal protects the store rather than the ' +
          'caller that owns the register');
  t.equal(personAssertions.SEALED_ATTRIBUTES.join(','),
          'stsAssertionPrivateKey,stsSamlAssertionPrivateKey',
          'and exactly one attribute PER PROFILE is private key material — ' +
          'the RFC 7522 set arrived on 2026-09-13 with its own. It is a ' +
          'LIST rather than an `if` because "is this attribute a private ' +
          'key" is a question somebody adding an attribute has to answer, ' +
          'and a list is where they will look');

  const drawn = personAssertions.holders().filter(function (one) {
    return one.username === ALICE;
  })[0];
  t.check(drawn && !('privateKeyPem' in drawn) &&
          JSON.stringify(drawn).indexOf('PRIVATE KEY') < 0,
          'NO PRIVATE KEY IS IN holders(), which is the report /admin/pki ' +
          'draws — a console page that printed a person\'s private key would ' +
          'hand it to everybody who can read the console, on every visit',
          JSON.stringify(drawn).slice(0, 120));

  // -------------------------------------------------------------------------
  // B. THE GRANT: A PERSON ASSERTING ABOUT THEMSELVES.
  // -------------------------------------------------------------------------
  const alg = record.jwsAlg;
  const sign = function (claims, header) {
    log.debug("Entering sign().");
    log.debug("Leaving sign().");
    return signJws(Object.assign({ alg: alg, typ: 'JWT', kid: record.kid },
                                 header || {}),
                   claims, record.privateKeyPem);
  };

  const self = await assertionGrant.verify({
    assertion: sign(claimsFor(ALICE, ALICE)), audiences: AUD });
  t.check(self.ok, 'B. a person\'s assertion about THEMSELVES is accepted — ' +
          'RFC 7523 section 3 read literally: claim 1 asks only that `iss` ' +
          'be a unique identifier for the issuer, and claim 2 says the `sub` ' +
          'of an authorization grant typically identifies a resource owner',
          self.description);
  t.equal(self.issuerKind, 'person',
          'and the result says which kind of party signed it, because ' +
          '/admin/delegation draws the intermediary of the act out of this ' +
          'and "one party vouched for another" is the opposite of what ' +
          'happened');
  t.equal(self.person, ALICE, 'naming them');
  t.equal(self.keySource, 'stsAssertionJwks',
          'verified against the key on their own entry and not against an ' +
          'application\'s — the two attribute sets share no name and no code ' +
          'path crosses them');
  t.equal(self.application, '',
          'and no application is reported, because none was involved. A ' +
          'person reported as an application would be the delegation ' +
          'register inventing a party');

  const other = await assertionGrant.verify({
    assertion: sign(claimsFor(ALICE, BOB)), audiences: AUD });
  t.check(!other.ok,
          '**AND AN ASSERTION FROM THAT PERSON ABOUT SOMEBODY ELSE IS ' +
          'REFUSED.** This is the whole feature: a key issued to one ' +
          'resource owner is that person\'s credential rather than ' +
          'permission to speak for the others, and without the refusal ' +
          'anybody handed a key on /admin/pki can get a token as anybody in ' +
          'the realm');
  t.equal(other.error, 'invalid_grant',
          'as invalid_grant, which is RFC 7523 section 3\'s own code for an ' +
          'assertion that will not do');
  t.check(/only be about themselves/.test(String(other.description)),
          'and the sentence says WHY rather than reporting a lookup that ' +
          'failed — the refusal names the difference between a person\'s key ' +
          'and an application\'s declaration, because the operator reading ' +
          'it has to know which one they wanted',
          String(other.description).slice(0, 120));

  // THE CONTROL FOR IT, and it is the assertion that stops the check above
  // being satisfied by a grant that is simply broken: the SAME claims, the
  // same key, an APPLICATION as the issuer, and the third party goes through.
  applications.createApplication({ identifier: 'pa-broker',
                                  protocols: ['oauth2'] });
  // `add` AND NOT `set`: that attribute holds a LIST, and `applications.js`
  // refuses a set on one — a set would replace the list with one value and
  // read afterwards as the others having been forgotten.
  applications.updateApplication('pa-broker', {
    attribute: 'oauthAssertionIssuer', mode: 'add',
    value: 'https://broker.example.test/pa' });
  const brokerIssued = await pki.issueSigningKeyPair(undefined, {
    identifier: 'pa-broker', purpose: 'jwt' });
  applications.updateApplication('pa-broker', {
    attribute: 'oauthAssertionJwks', mode: 'set',
    value: JSON.stringify(brokerIssued.issued.jwks) });
  const byBroker = await assertionGrant.verify({
    assertion: signJws({ alg: brokerIssued.issued.jwsAlg, typ: 'JWT',
                         kid: brokerIssued.issued.kid },
                       claimsFor('https://broker.example.test/pa', BOB),
                       brokerIssued.issued.privateKeyPem),
    audiences: AUD });
  t.check(byBroker.ok,
          'while an APPLICATION that an operator declared as an issuer may ' +
          'assert about a third party exactly as it always could — which is ' +
          'the control that keeps the refusal above from being satisfied by ' +
          'a grant that has simply stopped working',
          byBroker.description);
  t.equal(byBroker.issuerKind, 'application', 'and is reported as one');

  // -------------------------------------------------------------------------
  // C. A PERSON WITH NO KEY PAIR IS NOT AN ISSUER.
  // -------------------------------------------------------------------------
  const bobRecord = personAssertions.recordFor(BOB);
  t.check(bobRecord && !bobRecord.hasKeyPair,
          'C. somebody who was never issued one holds no key pair');
  t.check(!personAssertions.issuerFor(BOB),
          'and is NOT an issuer. Every person in the realm would otherwise ' +
          'be one by the username fallback, so an assertion naming any of ' +
          'them would get past the registered-issuer refusal and be judged ' +
          'on its x5c alone. Holding a key pair is the thing an operator DID');
  t.check(!personAssertions.issuerFor('pa-nobody-at-all'),
          'and a name nobody has is nobody');

  // -------------------------------------------------------------------------
  // D. THE OTHER WAY IN: A CERTIFICATE THIS SERVICE ISSUED, PRESENTED ALONE.
  //
  // Asserted with the entry CLEARED, so that the registry cannot be what
  // refuses it. What is left is the `x5c` path — the one that does not go
  // through the registry at all.
  // -------------------------------------------------------------------------
  const cleared = personAssertions.clear(ALICE);
  t.check(cleared.ok, 'D. the key pair is taken off the entry',
          cleared.removed);
  t.check(!personAssertions.issuerFor(ALICE),
          'so nobody issues under that name any more');

  const x5c = record.jwks.keys[0].x5c;
  const chainSelf = await assertionGrant.verify({
    assertion: sign(claimsFor(ALICE, ALICE), { x5c: x5c, kid: undefined }),
    audiences: AUD });
  t.check(chainSelf.ok,
          'a certificate this service ISSUED is still evidence in its own ' +
          'right, so the same person may present it instead of a registered ' +
          'JWKS — that is what makes holding a certificate authority worth ' +
          'anything', chainSelf.description);
  t.equal(chainSelf.keySource, 'x5c', 'on the chain and not on the registry');
  t.equal(chainSelf.issuerKind, 'person',
          'and the CERTIFICATE is what says they are a person, since there ' +
          'is nothing on the entry left to say it');

  const chainOther = await assertionGrant.verify({
    assertion: sign(claimsFor(ALICE, BOB), { x5c: x5c, kid: undefined }),
    audiences: AUD });
  t.check(!chainOther.ok,
          '**AND THE RULE HOLDS ON THE CERTIFICATE ALONE.** This is the hole ' +
          'the URI subjectAltName exists to close: before people could hold ' +
          'a key pair, "it chains here" and "it may assert about somebody" ' +
          'were one sentence, and a check written only against the registry ' +
          'would leave a person\'s leaf able to name anybody as `sub`',
          JSON.stringify(chainOther).slice(0, 120));
  t.check(/only be about themselves/.test(String(chainOther.description)),
          'refused with the same sentence, because it is the same rule');

  // AND WITH THE PERSON GONE FROM THE DIRECTORY ALTOGETHER, which is the state
  // no sequence of HTTP requests can produce while still holding the key.
  ldap.deleteUser ? ldap.deleteUser(ALICE) : null;
  const deletedRecord = personAssertions.recordFor(ALICE);
  const chainDeleted = await assertionGrant.verify({
    assertion: sign(claimsFor(ALICE, BOB), { x5c: x5c, kid: undefined }),
    audiences: AUD });
  t.check(!chainDeleted.ok,
          'and it holds when the person has been deleted from the directory ' +
          'too' + (deletedRecord ? ' (the entry is still there in this ' +
          'process, so this is the same assertion made twice rather than a ' +
          'weaker one)' : '') + '. A check that lapses when the lookup fails ' +
          'is a check that lapses exactly when somebody has tidied the entry ' +
          'away — so what this service issued the certificate TO is read off ' +
          'the certificate, which is a fact about the certificate',
          JSON.stringify(chainDeleted).slice(0, 120));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'rfc7523_person_issuer',
  describe: 'a person as the issuer of an RFC 7523 section 2.1 assertion, ' +
            'and the one rule that comes with it: their key may assert about ' +
            'them and about nobody else, on the entry and on the certificate',
  run: run
};
