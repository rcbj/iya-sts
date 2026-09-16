'use strict';
//
// File: saml_assertion_grant.js
//
// ===========================================================================
// RFC 7522: THE ELEVEN ITEMS AS A MATRIX, AND THE SEPARATION THE TWO PROFILES
// REST ON.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// The whole flow is asserted over HTTP by
// `tests/vendored/sts_saml2_bearer_grant.js` — a real assertion at a real
// token endpoint, the refusals included, the console and the API that issue
// the key pair. What is HERE is what that job cannot ask.
//
//   * **THE ELEVEN ITEMS OF SECTION 3, AS A LOOP.** Twenty-two ways of being
//     wrong is twenty-two token requests over HTTP; here it is a table, and
//     what is being checked is the MODULE's reading of the specification
//     rather than anything about a request. The two that matter most are the
//     ones a server is most likely to get wrong in the lenient direction — an
//     expired `<SubjectConfirmation>` DISCARDED rather than fatal (item 6's
//     own distinction), and an unrecognised `<Condition>` making the assertion
//     Invalid rather than being ignored (item 11, by way of SAML core section
//     2.5.1).
//
//   * **THE TWO ATTRIBUTE SETS ARE DISJOINT, WHICH IS A PROPERTY OF THE
//     MODULES AND NOT OF A REQUEST.** An application may hold an RFC 7523 key
//     pair and an RFC 7522 one, and the whole design rests on no verifier
//     reading the other's attributes. Over HTTP the observable is that one
//     particular assertion was refused, which is satisfied by a service that
//     refuses for some other reason; here it is a comparison of two lists of
//     names and a read of the module's source.
//
//   * **THE CERTIFICATE PATH IS NOT A KEY SOURCE HERE**, which is the one
//     place this profile is stricter than RFC 7523. The assertion is that a
//     certificate this realm's own CA issued — a real one, built in this
//     process — is REFUSED when it is not the registered one, and that is
//     three certificates and one hierarchy rather than a request.
//
// **NEITHER FILE IMPLIES THE OTHER**, which is `tests/assertion_grant.js`'s
// split with its own over-HTTP job, word for word: this one says the reading
// of the specification is right and that one says the doors are wired up.
//
// ---------------------------------------------------------------------------
// IT SIGNS WITH `tests/vendored/saml_xmldsig.js`, WHICH IS ACROSS THE TWO
// HALVES OF THIS DIRECTORY, AND THAT IS DELIBERATE.
//
// There is ONE independent XML Signature implementation in this repository's
// tests and both halves use it. A second copy would be a second place for
// exclusive canonicalization to be wrong — which is the single hardest thing
// in that file and the one thing a wrong copy would hide, because a test whose
// own signer is broken in the same way as its expectations passes.
//
// It was the first require from `tests/` into `tests/vendored/`, and the
// ones that followed it — this signer in other files, and the ACME, SCEP and
// GNAP clients — are there on the same argument and no other: what makes such
// a require worth it is that the file is a SECOND IMPLEMENTATION of something
// under test, which the shared helpers there are not.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: this
// file must not inherit a CONFIG_FILE from whatever launched the run.
delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const pki = require('../common/pki');
const grant = require('../oauth-oidc/saml_assertion_grant');
const assertionGrant = require('../oauth-oidc/assertion_grant');
const applications = require('../common/applications');
const signer = require('./vendored/saml_xmldsig.js');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'saml_assertion_grant',
  level: process.env.LOG_LEVEL || 'info' });

const AUD = 'https://sts.example.test/oauth2/token';
const ISS = 'https://issuer.example.test/saml';

async function run(t) {
  log.debug("Entering run().");
  // -------------------------------------------------------------------------
  t.log.info('=== the two parameter values, spelt once each ===');
  // Every one of these is a string a client puts on the wire, and a typo in
  // one of them is a feature nothing can reach. They are asserted against the
  // RFC's own text rather than against themselves.
  t.equal(grant.GRANT_TYPE, 'urn:ietf:params:oauth:grant-type:saml2-bearer',
          'RFC 7522 section 2.1\'s grant_type');
  t.equal(grant.ASSERTION_TYPE,
          'urn:ietf:params:oauth:client-assertion-type:saml2-bearer',
          'RFC 7522 section 2.2\'s client_assertion_type');
  t.equal(grant.BEARER, 'urn:oasis:names:tc:SAML:2.0:cm:bearer',
          'SAML 2.0 core section 2.4.1.1\'s bearer confirmation method, ' +
          'which is the one method section 3 item 5 names');
  t.check(grant.GRANT_TYPE !== assertionGrant.GRANT_TYPE,
          'and NEITHER is RFC 7523\'s — two profiles of one framework, and a ' +
          'service that answered one URN for both would be accepting a JWT ' +
          'where a SAML assertion was asked for');

  // -------------------------------------------------------------------------
  t.log.info('=== THE TWO ATTRIBUTE SETS SHARE NO NAME ===');
  // The design in one assertion. `common/applications.js` declares both sets
  // and the claim is that they are disjoint — which is what makes "an
  // application may hold both key pairs and neither can sign for the other"
  // true by construction rather than by everybody remembering.
  const names = ((applications.SCHEMA || {}).attributes || [])
    .map(function (one) { return one.name; });
  const jwtSet = names.filter(function (n) {
    return /^oauthAssertion/.test(n);
  });
  const samlSet = names.filter(function (n) {
    return /^oauthSamlAssertion/.test(n);
  });
  t.check(jwtSet.length >= 6,
          'RFC 7523\'s attribute set is declared in the registry',
          jwtSet.join(', '));
  t.check(samlSet.length >= 7,
          'and RFC 7522\'s is too, as a set of its own',
          samlSet.join(', '));
  t.check(jwtSet.every(function (n) { return samlSet.indexOf(n) < 0; }),
          'AND THEY SHARE NO NAME. This is the whole separation: no verifier ' +
          'can read the other profile\'s key material by accident, because ' +
          'there is no attribute both of them look at',
          jwtSet.filter(function (n) { return samlSet.indexOf(n) >= 0; })
            .join(', ') || 'no overlap');
  // Read out of the SOURCE, because the claim is about what the module can
  // reach rather than about what it happened to do on one document. A grep is
  // a blunt instrument and it is the right one here: the failure being guarded
  // against is somebody adding `|| fields.oauthAssertionCertificate` as a
  // fallback, which would be invisible to every behavioural assertion below.
  const samlSource = require('fs')
    .readFileSync(require('path').join(__dirname,
      '../oauth-oidc/saml_assertion_grant.js'), 'utf8');
  const jwtSource = require('fs')
    .readFileSync(require('path').join(__dirname,
      '../oauth-oidc/assertion_grant.js'), 'utf8');
  t.check(!/fields\s*\[?\s*['"]?oauthAssertion(Jwks|Certificate|PrivateKey|Kid)/
            .test(samlSource) &&
          samlSource.indexOf("'oauthAssertionJwks'") < 0,
          'the RFC 7522 module never names an `oauthAssertion*` key attribute');
  t.check(jwtSource.indexOf('oauthSamlAssertion') < 0,
          'and the RFC 7523 module never names an `oauthSamlAssertion*` one ' +
          '— the two halves of one claim, and the half that would be added ' +
          'by somebody making the profiles "work together"');
  t.check(samlSource.indexOf("require('./assertion_grant')") < 0,
          'and neither requires the other, which is what keeps the format ' +
          'flag from being one edit away');

  // -------------------------------------------------------------------------
  t.log.info('=== the assertion parameter is base64url, and both encodings ' +
             'arrive ===');
  const sample = signer.buildAssertion({ issuer: ISS, subject: 'alice',
                                         audience: AUD, recipient: AUD });
  const fromUrl = grant.decode(signer.b64u(sample.xml));
  t.check(fromUrl.ok && fromUrl.xml === sample.xml,
          'RFC 7522 section 2.1: base64url in, the same octets out');
  const fromStandard = grant.decode(signer.b64(sample.xml));
  t.check(fromStandard.ok && fromStandard.xml === sample.xml,
          'STANDARD base64 is accepted too and warned about — several ' +
          'widely-deployed stacks send it, because the assertion is base64 ' +
          'everywhere else in SAML, and a mock that refused would send a ' +
          'client author to look at their signature code');
  const raw = grant.decode(sample.xml);
  t.check(!raw.ok && /base64url/.test(raw.why),
          'RAW XML IS REFUSED WITH A MESSAGE ABOUT THE ENCODING rather than ' +
          'about the document — base64 will decode almost anything, so ' +
          '"this is not a valid assertion" would send somebody to the wrong ' +
          'layer',
          raw.why);
  t.check(!grant.decode('').ok, 'and nothing at all is refused');

  // -------------------------------------------------------------------------
  t.log.info('=== what read() takes out of a document, before anything is ' +
             'believed ===');
  const rich = signer.buildAssertion({
    issuer: ISS, subject: 'alice', audience: AUD, recipient: AUD,
    authnStatement: true,
    attributes: { department: 'engineering', groups: ['a', 'b'],
                  scope: 'openid email' }
  });
  const parsed = grant.read(rich.xml);
  t.check(parsed.ok, 'a well-formed assertion parses', parsed.why);
  t.equal(parsed.issuer, ISS, 'the <Issuer>');
  t.equal(parsed.subject, 'alice', 'the <NameID>');
  t.equal(parsed.audiences.length, 1, 'the <Audience>');
  t.equal(parsed.confirmations.length, 1, 'the <SubjectConfirmation>');
  t.equal(parsed.confirmations[0].recipient, AUD, 'and its Recipient');
  t.equal(parsed.authnStatements, 1,
          'the <AuthnStatement>, which item 7 makes a SHOULD in both ' +
          'directions and which this service reports rather than requires');
  t.equal((parsed.attributes.groups || []).length, 2,
          'A MULTI-VALUED ATTRIBUTE KEEPS BOTH VALUES. Two <AttributeValue> ' +
          'elements under one <Attribute> is how about half the ' +
          'implementations in the world spell a list, and taking the last ' +
          'would silently drop the rest');
  t.check(grant.read('<saml:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:' +
                     'assertion"></saml:Response>').why
            .indexOf('browser profile') > 0,
          'A <Response> IS REFUSED BY NAME. It is the browser profile\'s ' +
          'envelope and this profile takes the assertion out of it, which is ' +
          'the first mistake anybody with a working SAML deployment makes');
  t.check(!grant.read('<not-xml').ok,
          'and something that is not XML is refused');

  // -------------------------------------------------------------------------
  t.log.info('=== RFC 7522 section 3 item 8: what reaches an issued token ===');
  t.equal(grant.PROTOCOL_ATTRIBUTES.join(','), 'scope',
          'ONE name, where RFC 7523\'s list is twelve — and the difference ' +
          'is a fact about the two formats rather than an omission: a SAML ' +
          'assertion keeps its protocol furniture in ELEMENTS, so there is ' +
          'nothing in the AttributeStatement to strip but the one attribute ' +
          'this service reads as a constraint');
  const claims = grant.extraClaimsFrom({ department: ['engineering'],
                                         groups: ['a', 'b'],
                                         scope: ['openid'] });
  t.equal(claims.department, 'engineering',
          'A ONE-MEMBER LIST BECOMES A STRING. `"department": ' +
          '["engineering"]` in a token reads as a bug to every relying party ' +
          'that meets it');
  t.check(Array.isArray(claims.groups) && claims.groups.length === 2,
          'and a list of two stays a list');
  t.check(claims.scope === undefined,
          'and `scope` does not reach the token — it is the issuer saying ' +
          'what the grant is FOR, which this service acts on rather than ' +
          'copies');

  // -------------------------------------------------------------------------
  t.log.info('=== the certificate authority issues two key pairs, and they ' +
             'are two ===');
  const built = await pki.buildChain(undefined, { organisation: 'Test' });
  t.check(built.ok, 'a hierarchy for this realm',
          (built.errors || []).join(' '));
  t.check(pki.PURPOSE_IDS.indexOf('jwt') >= 0 &&
          pki.PURPOSE_IDS.indexOf('saml') >= 0,
          'the two assertion profiles are the two purposes a key pair may be ' +
          'issued for', pki.PURPOSE_IDS.join(', '));
  const samlPair = await pki.issueSigningKeyPair(undefined,
    { identifier: 'app-under-test', purpose: 'saml' });
  const jwtPair = await pki.issueSigningKeyPair(undefined,
    { identifier: 'app-under-test' });
  t.check(samlPair.ok && jwtPair.ok, 'both are issued to ONE application',
          (samlPair.errors || jwtPair.errors || []).join(' '));
  t.equal(jwtPair.issued.purpose, 'jwt',
          'and the default purpose is the JWT one — every caller written ' +
          'before purposes existed sends nothing, and a default that changed ' +
          'their certificate would make this function\'s output depend on ' +
          'when it was called');
  t.check(samlPair.issued.certificateThumbprint !==
          jwtPair.issued.certificateThumbprint,
          'THEY ARE DIFFERENT CERTIFICATES OVER DIFFERENT KEYS, which is the ' +
          'requirement in one line');
  t.check(String(new nodeCrypto.X509Certificate(samlPair.issued.certificatePem)
            .subjectAltName).indexOf(grant.GRANT_TYPE) >= 0,
          'the SAML leaf carries the RFC 7522 grant-type URI as a second URI ' +
          'subjectAltName, so a certificate read out of context says which ' +
          'profile it was issued for');
  t.check(String(new nodeCrypto.X509Certificate(jwtPair.issued.certificatePem)
            .subjectAltName).indexOf(grant.GRANT_TYPE) < 0,
          'and the JWT leaf does NOT — its certificate is byte-for-byte the ' +
          'shape it was before purposes existed');
  const badPurpose = await pki.issueSigningKeyPair(undefined,
    { identifier: 'app-under-test', purpose: 'pkcs7' });
  t.check(!badPurpose.ok,
          'a purpose this service does not have is REFUSED rather than ' +
          'defaulted — quietly handing back the other profile\'s certificate ' +
          'would put a key pair on the wrong attribute set with nothing ' +
          'saying so',
          (badPurpose.errors || []).join(' '));

  // -------------------------------------------------------------------------
  t.log.info('=== the round trip: this suite signs, this service verifies ===');
  const key = samlPair.issued.privateKeyPem;
  const cert = samlPair.issued.certificatePem;

  // The one function every case below goes through. `clientId` puts it in
  // section 2.2 and hands the certificate over directly, which is what
  // `client_auth.js` does — the checks are the same eleven either way, and
  // this avoids a directory entry per case.
  async function tryIt(build, signOpts, overrides) {
    log.debug("Entering tryIt().");
    const a = signer.buildAssertion(Object.assign(
      { issuer: ISS, subject: 'alice', audience: AUD, recipient: AUD },
      build || {}));
    const o = overrides || {};
    const xml = signer.sign(a, o.key || key,
                            o.cert === null ? '' : (o.cert || cert),
                            signOpts || {});
    log.debug("Leaving tryIt().");
    return grant.verify(Object.assign({
      assertion: signer.b64u(xml), clientId: 'alice',
      issuedCertificate: cert, audiences: [AUD]
    }, o.verify || {}));
  }

  const good = await tryIt({ attributes: { department: 'engineering' } });
  t.check(good.ok,
          'A SIGNATURE MADE BY THIS SUITE VERIFIES IN THIS SERVICE. Two ' +
          'implementations of exclusive canonicalization agreeing, which is ' +
          'the assertion every refusal below rests on — a broken signer ' +
          'would make all of them pass for the wrong reason',
          good.description);
  t.equal(good.certificateSource, 'issued',
          'and the certificate it verified against is the one this realm ' +
          'issued for RFC 7522');
  t.check(String(good.signatureMethod).indexOf('rsa-sha256') > 0,
          'signed RSA-SHA256', good.signatureMethod);

  // -------------------------------------------------------------------------
  t.log.info('=== SECTION 3, ITEM BY ITEM, AS A TABLE ===');
  // Each row is a document that breaks exactly one rule, and each `expect` is
  // a phrase the refusal must carry. The phrases are the RULE rather than the
  // wording, so a message somebody rewrites still passes and a CHECK somebody
  // removes does not.
  const cases = [
    ['item 1 — no <Issuer>', { issuer: '' }, null, null, 'item 1'],
    ['item 2 — an audience that is somebody else',
     { audience: 'https://elsewhere.example/token' }, null, null, 'item 2'],
    ['item 2 — no <Conditions> at all, so no audience',
     { omitConditions: true }, null, null, 'item 2'],
    ['item 3 — no <Subject>', { omitSubject: true }, null, null, 'item 3'],
    ['item 3 — a <Subject> with no <NameID>', { omitNameId: true }, null, null,
     'item 3'],
    ['item 3B — a Subject that is not the client', { subject: 'somebody-else' },
     null, null, 'item 3B'],
    ['item 4 — no expiry anywhere',
     { notOnOrAfter: null, confirmationNotOnOrAfter: null }, null, null,
     'item 4'],
    ['item 5 — no bearer confirmation',
     { method: 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key' }, null, null,
     'item 5'],
    ['item 5 — a Recipient that is another token endpoint',
     { recipient: 'https://elsewhere.example/token' }, null, null, 'items 5'],
    ['item 5 — a <SubjectConfirmationData> with no Recipient',
     { recipient: null }, null, null, 'items 5'],
    ['item 6 — the <Conditions> have expired',
     { notOnOrAfter: signer.iso(-600000) }, null, null, 'item 6'],
    ['item 6 — it is not valid yet',
     { notBefore: signer.iso(600000), notOnOrAfter: signer.iso(900000) },
     null, null, 'not valid until'],
    ['item 6 — the confirmation has expired and it is the only one',
     { notOnOrAfter: null, confirmationNotOnOrAfter: signer.iso(-600000) },
     null, null, 'items 5'],
    ['item 6 — an expiry unreasonably far in the future',
     { notOnOrAfter: signer.iso(4000 * 1000) }, null, null,
     'saml2BearerMaxLifetimeS'],
    ['item 9 — the digest does not match', {}, { breakDigest: true }, null,
     'did not verify'],
    ['item 9 — signed by a stranger', {}, null,
     { cert: null,
       key: nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
         .privateKey.export({ type: 'pkcs8', format: 'pem' }) },
     'did not verify'],
    ['item 11 — a <Condition> nothing understands',
     { unknownCondition: 'ProhibitedByLaw' }, null, null, '2.5.1'],
    ['not SAML 2.0 at all', { version: '1.1' }, null, null, 'Version'],
    ['no ID to remember it by', { id: ' ' }, null, null, 'ID']
  ];
  for (let i = 0; i < cases.length; i++) {
    const row = cases[i];
    const result = await tryIt(row[1], row[2], row[3]);
    t.check(!result.ok && String(result.description).indexOf(row[4]) >= 0,
            row[0] + ' is refused, and the refusal names the rule',
            result.ok ? 'IT WAS ACCEPTED' : result.description);
  }

  // -------------------------------------------------------------------------
  t.log.info('=== the two items whose LENIENT reading is the usual bug ===');
  // Item 4 says the expiry may be on EITHER element, and half the
  // implementations in the world require the Conditions one. Both shapes are
  // asserted, because "it was refused" is what a server that requires the
  // wrong one does for a conforming client.
  const confirmationOnly = await tryIt({ notOnOrAfter: null });
  t.check(confirmationOnly.ok,
          'item 4: an expiry on the <SubjectConfirmationData> ALONE is ' +
          'enough, which is the item read literally rather than as "the ' +
          'Conditions must have one"',
          confirmationOnly.description);
  const conditionsOnly = await tryIt({ omitConfirmationData: true });
  t.check(conditionsOnly.ok,
          'and an expiry on the <Conditions> alone is enough, with NO ' +
          '<SubjectConfirmationData> at all — which item 5 permits in ' +
          'exactly that case and which a server demanding a Recipient would ' +
          'refuse',
          conditionsOnly.description);

  // Item 6's own distinction, and the one most implementations collapse: an
  // expired <SubjectConfirmation> is DISCARDED — "the authorization server
  // MUST reject the <SubjectConfirmation> (but MAY still use the rest of the
  // Assertion)" — where an expired <Conditions> makes the whole assertion
  // invalid. It cannot be seen at all unless a document carries one of each.
  const mixedXml = (function () {
    const a = signer.buildAssertion({ issuer: ISS, subject: 'alice',
      audience: AUD, recipient: AUD,
      confirmationNotOnOrAfter: signer.iso(-600000) });
    // A SECOND bearer confirmation, live, spliced in beside the dead one —
    // which is what a real issuer emits when it has rotated a recipient.
    return { built: a };
  })();
  const withTwo = mixedXml.built;
  withTwo.xml = withTwo.xml.replace(
    '</saml:Subject>',
    '<saml:SubjectConfirmation Method="' + grant.BEARER + '">' +
    '<saml:SubjectConfirmationData NotOnOrAfter="' + signer.iso(120000) +
    '" Recipient="' + AUD + '"></saml:SubjectConfirmationData>' +
    '</saml:SubjectConfirmation></saml:Subject>');
  const mixed = await grant.verify({
    assertion: signer.b64u(signer.sign(withTwo, key, cert)),
    clientId: 'alice', issuedCertificate: cert, audiences: [AUD] });
  t.check(mixed.ok,
          'ITEM 6: AN EXPIRED <SubjectConfirmation> IS DISCARDED AND THE ' +
          'LIVE ONE BESIDE IT IS USED. The item says a server MUST reject ' +
          'the confirmation and MAY still use the rest of the assertion, ' +
          'which is a distinction nearly every implementation collapses into ' +
          'refusing the document',
          mixed.description);
  t.equal(mixed.discardedConfirmations, 1,
          'and it says how many it discarded, because silently ignoring one ' +
          'is how a document that should have been refused gets accepted');

  // -------------------------------------------------------------------------
  t.log.info('=== THE CROSSING: the RFC 7523 key pair may not sign this ===');
  const crossed = await tryIt({}, null,
    { key: jwtPair.issued.privateKeyPem, cert: jwtPair.issued.certificatePem });
  t.check(!crossed.ok,
          'AN ASSERTION SIGNED WITH THE SAME APPLICATION\'S RFC 7523 KEY ' +
          'PAIR IS REFUSED. This is the requirement the two attribute sets ' +
          'exist for, and the certificate involved is a real one this ' +
          'realm\'s own CA issued moments ago — so it is not being refused ' +
          'for failing to chain',
          crossed.ok ? 'IT WAS ACCEPTED' : crossed.description);
  t.check(String(crossed.description).indexOf('KeyInfo') > 0 &&
          String(crossed.description).indexOf('chains') > 0,
          'and the refusal says WHY a chain is not enough here, which is the ' +
          'one place this profile is stricter than RFC 7523: a chain proves ' +
          'the REALM issued a key and says nothing about which application ' +
          'holds it',
          crossed.description);

  // The same certificate, now registered. The ONLY difference between this
  // case and the one above is which attribute the certificate sits in — which
  // is what makes the refusal a rule rather than a service failing for some
  // other reason.
  const registered = await grant.verify({
    assertion: signer.b64u(signer.sign(
      signer.buildAssertion({ issuer: ISS, subject: 'alice', audience: AUD,
                              recipient: AUD }),
      jwtPair.issued.privateKeyPem, jwtPair.issued.certificatePem)),
    clientId: 'alice',
    registeredCertificate: jwtPair.issued.certificatePem,
    audiences: [AUD] });
  t.check(registered.ok,
          'AND THE SAME CERTIFICATE REGISTERED UNDER THE RFC 7522 ATTRIBUTE ' +
          'IS ACCEPTED — one attribute is the whole difference, which is ' +
          'what tells a working rule from a service refusing for another ' +
          'reason',
          registered.description);
  t.equal(registered.certificateSource, 'registered',
          'and it says which of the two attributes vouched for it');

  // -------------------------------------------------------------------------
  t.log.info('=== the replay, on the assertion ID ===');
  const fixed = { id: signer.id() };
  const first = await tryIt(fixed);
  t.check(first.ok, 'an assertion is spent once', first.description);
  const second = await tryIt(fixed);
  t.check(!second.ok && /used already/.test(second.description),
          'AND THE SAME ID A SECOND TIME IS REFUSED. Item 6 makes the replay ' +
          'cache a MAY and a signed assertion captured off the wire is a ' +
          'credential until it expires, so "may" is not the useful reading',
          second.description);
  t.check(grant.assertionsRemembered() > 0,
          'and the count of what is being remembered is reportable, which is ' +
          'what the console draws');

  // -------------------------------------------------------------------------
  t.log.info('=== the settings, and what each one does NOT do ===');
  t.check(grant.enabled(),
          'the grant is on by default — RFC 7522 is a profile a client ' +
          'author exercises, and the off switch is for testing what their ' +
          'code does against a server that does not offer it');
  t.check(grant.requiresRegisteredIssuer(),
          'AND THE ISSUER MUST BE DECLARED, which is on by default and is ' +
          'the third refusal in this service that is — an assertion IS the ' +
          'whole authorization, so accepting one from anybody would mean ' +
          'anybody who can reach this port getting a token as anybody');
  t.check(grant.maxLifetimeSeconds() > 0,
          'and a ceiling on the lifetime is set',
          String(grant.maxLifetimeSeconds()) + 's');

  // See tests/assertion_grant.js: the ambient realm is shared by every file in
  // this run, so what this section built has to go.
  pki.clearChain(undefined);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'saml_assertion_grant',
  describe: 'RFC 7522: the eleven items of section 3 as a table, an XML ' +
            'Signature made by this suite\'s own code and verified by this ' +
            'service, the two items whose lenient reading is the usual bug, ' +
            'and the assertion the whole design rests on — that the RFC 7523 ' +
            'key pair on the same application cannot sign a SAML assertion',
  run: run
};
