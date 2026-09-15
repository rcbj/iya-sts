'use strict';
//
// File: pki_revocation.js
//
// ===========================================================================
// CRLs AND OCSP: THE REGISTER, THE TWO DOCUMENTS, AND THE ROTATION THAT FILLS
// THEM (2026-09-11).
//
// **WHY THIS IS IN PROCESS RATHER THAN OVER HTTP**, which is
// `tests/CLAUDE.md`'s question and the one that decides where a test goes. Most
// of it could be driven over HTTP and one part could not, and the parts that
// could are here anyway because they are cheaper here and because the part that
// cannot is the half that matters:
//
//   * **A CRL AND AN OCSP RESPONSE ARE BINARY DOCUMENTS THIS SERVICE SIGNS**,
//     and what is worth asserting about them is their STRUCTURE — the version,
//     the cRLNumber, the AKI, the per-entry reason code, the responder's
//     issuer-name and issuer-key hashes. Over HTTP that is a fetch and then
//     the same parsing, with a container in between.
//   * **ROTATION IS THE THING THAT FILLS THESE LISTS**, and asserting it means
//     reissuing an Issuing CA and counting what landed on two different
//     authorities' lists. There is no HTTP call that does that and then lets
//     you look.
//   * **AND ONE ASSERTION HERE IS ABOUT A ROW IN A STORE**: that revoking at
//     the Root's authority does not DELETE the Root. That is section F, it is
//     a regression test, and section F's header says what it cost.
//
// The over-HTTP half — the four endpoints answering, the media types, the
// cache headers, the console pane's two controls — is
// `tests/vendored/sts_pki_revocation.js`, which is this repository's own and
// drives the container.
//
// **THE NEGATIVES ARE MOST OF THIS FILE AND THAT IS DELIBERATE**, for the
// reason `tests/sts_dpop.js` gives about an identity provider that hands a
// working client a signed assertion: a revocation subsystem that answers
// `good` for a good certificate looks finished and is worth nothing. What it
// has to get right is `revoked` for a revoked one, `unknown` for a serial it
// never issued, `unauthorized` for an authority that does not exist, a refusal
// to release anything but a hold, and a refusal to move a revocation date
// forward.
// ===========================================================================

// Deleted rather than set, for the reason `config_realm_layer.js` gives: this
// file must not inherit a CONFIG_FILE from whatever launched the run.
delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const nodeCrypto = require('crypto');

const pki = require('../common/pki');
const revocation = require('../common/pki_revocation');
const keystore = require('../common/keystore');
const helpers = require('../common/helpers');
const x509 = require('../common/vendored/x509');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'pki_revocation',
  level: process.env.LOG_LEVEL || 'info' });

// **THE DEFAULT REALM, AND THAT IS A FIXTURE DECISION RATHER THAN
// LAZINESS.** The obvious thing is to make a realm of this file's own — and
// `tests/pki_hierarchy.js` records what happens when you do: a realm id this
// process's realm REGISTRY has never heard of is not a realm, so
// `helpers.stsKeysFor.of('rev-a')` answers the DEFAULT realm's key set and
// that realm's Issuing CAs certify nothing. Every list here is then empty and
// every assertion about what an authority has signed passes vacuously or
// fails for the wrong reason.
//
// `pki.start()` certifies the DEFAULT realm's keys before it returns — every
// other realm's are certified lazily, when they are first used — so the
// default realm is the one that has leaves to revoke at the moment this file
// runs. The hierarchy is still built for both.
const REALM = '';
const UNCERTIFIED_REALM = 'rev-a';

// ---------------------------------------------------------------------------
// AN OCSP REQUEST IS BUILT BY OPENSSL AND NOT BY pkijs, AND THE REASON IS NOT
// PURITY.
//
// pkijs is what BUILDS the answer, so a request built with the same library is
// this implementation agreeing with itself — the same argument
// `tests/crypto_module.js` makes about xml-crypto being kept as a dependency
// nothing in the service requires. It is also, in practice, the only way that
// works: `OCSPRequest.toSchema(true)` returns pkijs's CACHED TBS bytes, so a
// serial set after `createForCertificate()` never reaches the wire and every
// probe silently asks about the issuer's own serial instead; and substituting
// an `asn1js.Integer` from a separately-required copy of that package throws
// `this.value[i].toBER is not a function` three frames inside the encoder,
// because it is a different class object. Both cost an afternoon once.
//
// **AND THE REQUEST HAS TO BE BUILT IN THIS PROCESS.** In development mode the
// hierarchy is regenerated on every start, so a request built by an earlier
// process names a CA that no longer exists and EVERY answer is `unknown` — a
// green-looking run asserting nothing, which is how this was first got wrong.
// ---------------------------------------------------------------------------
let openSslMissing = '';
let scratch = '';

function haveOpenSsl() {
  log.debug("Entering haveOpenSsl().");
  if (openSslMissing) {
    log.debug("Leaving haveOpenSsl().");
    return false;
  }
  try {
    execFileSync('openssl', ['version'], { stdio: 'pipe' });
    log.debug("Leaving haveOpenSsl().");
    return true;
  } catch (e) {
    openSslMissing = e.message;
    log.debug("Leaving haveOpenSsl().");
    return false;
  }
}

function ocspRequestFor(issuerPem, serialHex, withNonce) {
  log.debug("Entering ocspRequestFor().");
  const issuerFile = path.join(scratch, 'issuer.pem');
  const out = path.join(scratch, 'req.der');
  fs.writeFileSync(issuerFile, issuerPem);
  // The flag order is built in one place rather than spliced, because an
  // argument list assembled by unshifting and splicing produced
  // `openssl ocsp -no_nonce ocsp -issuer …` and OpenSSL answered
  // `Use -help for summary`, which names nothing.
  const args = ['ocsp'];
  if (!withNonce) {
    args.push('-no_nonce');
  }
  args.push('-issuer', issuerFile, '-serial', '0x' + serialHex, '-reqout', out);
  execFileSync('openssl', args, { stdio: 'pipe' });
  log.debug("Leaving ocspRequestFor().");
  return fs.readFileSync(out);
}

// The per-certificate answer out of `answerOcsp()`. The RESPONSE status and
// the CERTIFICATE status are different fields and conflating them is how a
// test comes to assert `successful` about a revoked certificate and call it a
// pass — `successful` means the responder answered, and it answers
// `successful` for `good`, `revoked` and `unknown` alike.
async function ask(scope, caId, issuerPem, serialHex, withNonce) {
  log.debug("Entering ask().");
  const answer = await revocation.answerOcsp(
    scope, caId, ocspRequestFor(issuerPem, serialHex, withNonce));
  log.debug("Leaving ask().");
  return {
    responseStatus: answer.status,
    certStatus: ((answer.answers || [])[0] || {}).status || '',
    reason: ((answer.answers || [])[0] || {}).reason || '',
    der: answer.der
  };
}

// ===========================================================================

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== A. the register, and what a revocation IS ===');

  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-rev-'));
  await keystore.start();
  const started = await pki.start({
    realmIds: ['', UNCERTIFIED_REALM],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    }
  });
  t.check(started.ok && started.built, 'the hierarchy is built',
          JSON.stringify(started.errors || []));

  // ONE AUTHORITY PER CA AND NOT ONE PER REALM. A CRL is signed by an issuer
  // and lists serials that issuer minted, so a list per realm would be a
  // document with no valid issuer — nothing could sign it. That is the single
  // most load-bearing shape decision here and it is asserted first.
  const authorities = revocation.authorities(pki.knownScopes());
  t.check(authorities.length >= 6,
          'there is one authority per CERTIFICATE AUTHORITY — the Root, ' +
          'every Intermediate and every Issuing CA — rather than one per ' +
          'realm',
          authorities.map(function (one) {
            return (one.scope || 'default') + '/' + one.ca;
          }).join(' '));
  t.check(authorities.some(function (one) { return one.ca === 'root'; }) &&
          authorities.some(function (one) {
            return one.ca === 'intermediate';
          }) &&
          authorities.some(function (one) { return one.ca === 'jose'; }),
          'and all three tiers are among them, because all three sign ' +
          'something and therefore all three can be asked about it');

  // **THE ROOT IS LISTED ONCE.** `knownScopes()` already carries the process
  // branch — it filters out the SERVICE scope and nothing else — so a caller
  // that concatenated `PROCESS_SCOPE` onto it listed every process authority
  // twice. The console did exactly that for an hour and drew two sets of
  // Revoke buttons that both worked.
  const roots =
      authorities.filter(function (one) { return one.ca === 'root'; });
  t.equal(roots.length, 1,
          'the Root appears ONCE however the scope list was assembled — it ' +
          'belongs to no scope, so a walk that treats it as one scope\'s ' +
          'produces a duplicate for every scope');

  t.equal(revocation.REASONS.length, 9,
          'nine reasons: RFC 5280 section 5.3.1 defines eleven, 7 is unused ' +
          'and has never meant anything, and removeFromCRL is a DELTA-CRL ' +
          'verb rather than a reason — this service publishes no delta CRLs, ' +
          'so offering it would be a control that could never be honoured');
  t.check(!revocation.REASONS.some(function (one) { return one.code === 7; }),
          'and 7 is specifically not in the list');
  t.check(revocation.reason('certificateHold').code === 6,
          'the reason table maps id to code, which is what goes on the wire');
  t.check(!revocation.reason('notAReason'),
          'and a reason nobody defined resolves to nothing rather than to a ' +
          'default — a revocation filed under an invented code is a ' +
          'revocation a validator cannot act on');

  t.log.info('=== B. revoking: the positives, then every refusal ===');

  const issued = revocation.issuedList(REALM, 'jose');
  t.check(issued.length >= 2,
          'the jose Issuing CA has signed this realm\'s signing keys, and ' +
          'the register can list them — which is what the console\'s pane ' +
          'offers a Revoke button against',
          issued.length + ' certificate(s)');

  // **EVERY COUNT BELOW IS A DELTA AND THE FIRST VERSION USED ABSOLUTES.** It
  // passed alone and failed in `npm test` with `expected 1, got 8`, because
  // the whole in-process suite runs in ONE process: `tests/pki.js` and
  // `tests/pki_hierarchy.js` rotate this realm's authorities before this file
  // is reached, and every rotation supersedes what it replaced. Seven entries
  // were already on the jose list and they were all correct.
  //
  // A realm of this file's own was the other candidate and it does not work
  // here: an id the realm registry has never heard of is not a realm, so its
  // Issuing CAs certify nothing and there is nothing to revoke. So the
  // fixture is the default realm and the assertions are about what THIS FILE
  // changed.
  const joseBase = revocation.listFor(REALM, 'jose').length;
  const fresh = issued.filter(function (one) {
    return !revocation.isRevoked(REALM, 'jose', one.serialHex);
  });
  t.check(fresh.length >= 3,
          'at least three of them are not already revoked, which is what ' +
          'the sections below need to work with',
          fresh.length + ' of ' + issued.length + ' unrevoked');
  const first = fresh[0].serialHex;
  const second = fresh[1].serialHex;

  const done = revocation.revoke(REALM, 'jose', {
    serialHex: first, reason: 'keyCompromise', note: 'a test'
  });
  t.check(done.ok && done.entry.reasonCode === 1,
          'a certificate can be revoked, and the entry carries the CODE as ' +
          'well as the name because the code is what a CRL and an OCSP ' +
          'answer actually carry',
          JSON.stringify(done.errors || done.entry));
  t.equal(revocation.listFor(REALM, 'jose').length, joseBase + 1,
          'and it is on the list — ONE more than was there, rather than one ' +
          'in total');
  t.check(!!revocation.isRevoked(REALM, 'jose', first),
          'and the register says so when asked by serial');

  // IDEMPOTENCE, AND THE DIRECTION IT RESOLVES IN. A second revocation of the
  // same serial must not move the date FORWARD: a validator is entitled to act
  // on the first moment it was told about, and moving the date would be this
  // service asserting the certificate was valid for longer than it had already
  // said. The EARLIER entry wins.
  const firstAt = done.entry.revokedAt;
  const again = revocation.revoke(REALM, 'jose', {
    serialHex: first, reason: 'superseded'
  });
  t.check(again.ok && again.already,
          'revoking the same serial twice SUCCEEDS and reports that it was ' +
          'already revoked — a refusal would make an operator think the ' +
          'certificate was not on the list');
  t.equal(again.entry.revokedAt, firstAt,
          'and the ORIGINAL moment stands: moving a revocation date forward ' +
          'would be this service saying a certificate was valid for longer ' +
          'than it had already told a validator');
  t.equal(again.entry.reason, 'keyCompromise',
          'and the original REASON stands too, so a second call cannot ' +
          'downgrade a keyCompromise to a superseded');
  t.equal(revocation.listFor(REALM, 'jose').length, joseBase + 1,
          'and it added no second entry');

  // The refusals.
  const noSuch = revocation.revoke(REALM, 'not-an-authority',
                                   { serialHex: first });
  t.check(!noSuch.ok && /revocation is made BY AN ISSUER/.test(
            (noSuch.errors || []).join(' ')),
          'revoking at an authority that does not exist is REFUSED, and the ' +
          'refusal says why a serial alone is not a question: a serial is ' +
          'unique only within one issuer',
          (noSuch.errors || []).join(' '));
  const noSerial = revocation.revoke(REALM, 'jose', { serialHex: '' });
  t.check(!noSerial.ok, 'a revocation with no serial is refused');
  const zero = revocation.revoke(REALM, 'jose', { serialHex: '0' });
  t.check(!zero.ok,
          'and so is serial zero, which is what an empty hex string parses ' +
          'to and is not a serial any certificate here carries');
  const badReason = revocation.revoke(REALM, 'jose', {
    serialHex: second, reason: 'becauseIFeltLikeIt'
  });
  t.check(!badReason.ok && /RFC 5280/.test((badReason.errors || []).join(' ')),
          'a reason RFC 5280 does not define is REFUSED rather than mapped ' +
          'to unspecified — a revocation filed under an invented code is one ' +
          'a validator cannot act on',
          (badReason.errors || []).join(' '));
  t.equal(revocation.listFor(REALM, 'jose').length, joseBase + 1,
          'and none of those four refusals put anything on the list, which ' +
          'is the property that matters more than the message');

  t.log.info('=== C. a hold is the ONLY reason that can be undone ===');

  const held = revocation.revoke(REALM, 'jose', {
    serialHex: second, reason: 'certificateHold'
  });
  t.check(held.ok, 'a certificate can be put on hold');
  const releasedPermanent = revocation.release(REALM, 'jose', first);
  t.check(!releasedPermanent.ok &&
          /PERMANENT/.test((releasedPermanent.errors || []).join(' ')),
          'releasing a keyCompromise is REFUSED, and the refusal carries the ' +
          'reason: a validator may cache a permanent revocation for as long ' +
          'as the CRL it read says it is fresh, so undoing one here would ' +
          'produce a certificate this service calls good and half the world ' +
          'still calls revoked',
          (releasedPermanent.errors || []).join(' '));
  t.check(!!revocation.isRevoked(REALM, 'jose', first),
          'and the keyCompromise is still on the list after the refusal');

  const releasedHold = revocation.release(REALM, 'jose', second);
  t.check(releasedHold.ok, 'releasing a certificateHold succeeds');
  t.check(!revocation.isRevoked(REALM, 'jose', second),
          'and that serial is off the list entirely rather than marked ' +
          'released — RFC 5280 has no "was revoked" state on a base CRL');
  const releaseTwice = revocation.release(REALM, 'jose', second);
  t.check(!releaseTwice.ok,
          'releasing something that is not on the list is refused rather ' +
          'than silently succeeding');

  t.log.info('=== D. the CRL is a real signed document ===');

  const made = await revocation.buildCrl(REALM, 'jose');
  t.check(made.ok, 'a CRL is built', (made.errors || []).join(' '));
  t.equal(made.count, revocation.listFor(REALM, 'jose').length,
          'carrying exactly what is on the list and nothing else — a CRL ' +
          'that reported a different number from the register would be the ' +
          'two disagreeing about the one thing they are both for');
  t.equal(made.count, joseBase + 1,
          'which after a revoke and a released hold is one more than this ' +
          'file found');
  t.check(Buffer.isBuffer(made.der) && made.der.length > 200,
          'as DER rather than as a description of one');

  // **THE CRL NUMBER MOVES WITH EVERY CHANGE (RFC 5280 section 5.2.3).** It is
  // what lets a client tell a newer list from an older one, so a number that
  // did not move would make a released hold invisible to anything that
  // compares.
  const numberBefore = made.crlNumber;
  revocation.revoke(REALM, 'jose', { serialHex: second, reason: 'superseded' });
  const after = await revocation.buildCrl(REALM, 'jose');
  t.check(after.crlNumber > numberBefore,
          'and the cRLNumber MOVES on every change — RFC 5280 section 5.2.3, ' +
          'which is how a client tells a newer list from an older one',
          numberBefore + ' -> ' + after.crlNumber);
  t.equal(after.count, joseBase + 2, 'with both new entries on it');

  if (haveOpenSsl()) {
    const crlFile = path.join(scratch, 'list.crl');
    const caFile = path.join(scratch, 'ca.pem');
    fs.writeFileSync(crlFile, after.der);
    fs.writeFileSync(caFile, pki.rawRowFor(REALM).issuing.jose.certificatePem);
    // AN INDEPENDENT READER. pkijs built this document, so parsing it with
    // pkijs would be this implementation agreeing with itself.
    const text = execFileSync('openssl',
      ['crl', '-inform', 'DER', '-in', crlFile, '-noout', '-text'],
      { encoding: 'utf8' });
    t.check(/Version 2/.test(text),
            'OpenSSL reads it as a v2 CRL — v1 has no extensions at all, so ' +
            'a v1 list could carry neither the cRLNumber nor a reason code',
            text.split('\n')[0]);
    t.check(/X509v3 CRL Number/.test(text), 'with a cRLNumber extension');
    t.check(/Authority Key Identifier/.test(text),
            'and an Authority Key Identifier, which is what lets a client ' +
            'pick the right issuer certificate out of a bundle');
    t.check(/Key Compromise/i.test(text),
            'and the per-entry reason code is on the entry rather than ' +
            'implied by the list',
            (text.match(/Reason Code[^\n]*\n[^\n]*/) || [''])[0]);
    // **`verify OK` GOES TO STDERR AND NOT TO STDOUT**, which is the one
    // thing to know about scripting this command: reading stdout alone gives
    // an empty string and the assertion fails against a signature that is
    // perfectly good.
    let verified = '';
    try {
      const proc = require('child_process').spawnSync('openssl',
        ['crl', '-inform', 'DER', '-in', crlFile, '-CAfile', caFile, '-noout'],
        { encoding: 'utf8' });
      verified = String(proc.stdout || '') + String(proc.stderr || '');
    } catch (e) {
      // Reported through the assertion below rather than thrown: a machine
      // without a usable openssl is a weaker run, not a failing one.
      verified = 'openssl could not be run: ' + e.message;
    }
    t.check(/verify OK/i.test(verified),
            'and OpenSSL VERIFIES the signature against the issuing CA — ' +
            'which is the whole claim: this is a document a client can act ' +
            'on rather than a list this service prints',
            verified.trim());
  } else {
    t.log.warn('openssl is not on this machine (' + openSslMissing + '), so ' +
               'the CRL structure and signature are asserted by pkijs alone. ' +
               'That is a WEAKER claim and is reported rather than skipped ' +
               'silently.');
  }

  t.log.info('=== E. the OCSP responder: good, revoked, unknown, and two ' +
             'refusals that are answers ===');

  if (!haveOpenSsl()) {
    t.log.warn('openssl is not on this machine, so the OCSP section cannot ' +
               'build a request from an independent implementation and is ' +
               'not run. It is the half of this file most worth having.');
  } else {
    const issuerPem = pki.rawRowFor(REALM).issuing.jose.certificatePem;
    const good = issued.filter(function (one) {
      return one.serialHex !== first && one.serialHex !== second;
    })[0];

    const isGood = await ask(REALM, 'jose', issuerPem, good.serialHex, false);
    t.equal(isGood.responseStatus, 'successful',
            'the responder answers a well-formed request');
    t.equal(isGood.certStatus, 'good',
            'and a certificate this authority issued and has not revoked is ' +
            'GOOD. **`successful` is the RESPONSE status and says nothing ' +
            'about the certificate** — it is the answer for good, revoked ' +
            'and unknown alike, which is how a test comes to assert nothing ' +
            'while looking green');

    const isRevoked = await ask(REALM, 'jose', issuerPem, first, false);
    t.equal(isRevoked.certStatus, 'revoked', 'a revoked one is REVOKED');
    t.equal(isRevoked.reason, 'keyCompromise',
            'and the responder carries the REASON as well as the fact, ' +
            'because RFC 6960 section 4.2.1 has a place for it and a client ' +
            'that treats keyCompromise differently from superseded needs it');

    const never = await ask(REALM, 'jose', issuerPem, 'deadbeefdeadbeef',
                            false);
    t.equal(never.certStatus, 'unknown',
            'a serial this authority never issued is UNKNOWN and not good — ' +
            'which is the answer that matters most: a responder that said ' +
            '`good` about anything it had not heard of would vouch for every ' +
            'forgery anybody cared to present');

    // **AND THE OTHER WAY OF NOT KNOWING, WHICH IS A DIFFERENT BRANCH AND A
    // DIFFERENT DANGER.** The probe above asks the right responder about a
    // serial it never issued. This one asks the `jose` responder about a
    // certificate the `xml` authority issued — a request whose CertID hashes
    // name ANOTHER ISSUER. A responder that answered `good` here would vouch
    // for every issuer in the world, and the certificate really does exist
    // and really is good — at its own responder.
    //
    // **THE ANSWER IS `unauthorized` SINCE 2026-09-13, AND IT WAS A SIGNED
    // `unknown`.** A signed answer about a certificate this authority did not
    // issue is one no client can verify — RFC 6960 section 2.2 wants the
    // issuing CA's key or a responder it delegated to — and section 2.3 and
    // RFC 5019 section 2.2.3 name the answer for a responder that is not
    // authoritative for the request: `unauthorized`, unsigned. OpenSSL
    // refused the old one with *missing ocspsigning usage*.
    //
    // It was added because a mutant survived: turning the first branch's
    // `unknown` into `good` broke nothing, since no test had ever sent a
    // request built from a foreign issuer.
    const xmlIssuerPem = pki.rawRowFor(REALM).issuing.xml.certificatePem;
    const xmlLeaf = revocation.issuedList(REALM, 'xml')[0];
    if (xmlLeaf) {
      const foreign = await revocation.answerOcsp(REALM, 'jose',
        ocspRequestFor(xmlIssuerPem, xmlLeaf.serialHex, false));
      t.equal(foreign.status, 'unauthorized',
              'a request naming ANOTHER AUTHORITY\'s certificate is refused ' +
              '`unauthorized` at this responder, even though that certificate ' +
              'exists and is perfectly good at its own — a responder that ' +
              'vouched for it would vouch for every issuer in the world, and ' +
              'a signed `unknown` is an answer no client could verify');
      t.check(!foreign.answers,
              'and it carries no per-certificate answer at all: ' +
              '`unauthorized` has no responseBytes (RFC 6960 section 4.2.1)',
              JSON.stringify(foreign.answers));
      const atItsOwn = await ask(REALM, 'xml', xmlIssuerPem,
                                 xmlLeaf.serialHex, false);
      t.equal(atItsOwn.certStatus, 'good',
              'and the SAME certificate is good at its own responder, which ' +
              'is what makes the answer above a statement about the ' +
              'responder rather than about the certificate');
    } else {
      t.log.warn('the xml Issuing CA has certified nothing in this realm, so ' +
                 'the foreign-issuer branch of the responder is not covered ' +
                 'by this run.');
    }

    const wrongAuthority = await revocation.answerOcsp(
      REALM, 'no-such-ca', ocspRequestFor(issuerPem, first, false));
    t.equal(wrongAuthority.status, 'unauthorized',
            'a request to a responder that does not exist is UNAUTHORIZED ' +
            'rather than unknown — there is no responder at that address at ' +
            'all, which is a different fact from a responder that has not ' +
            'heard of a certificate, and RFC 6960 has both words');

    const garbage = await revocation.answerOcsp(
      REALM, 'jose', Buffer.from('this is not DER at all', 'utf8'));
    t.equal(garbage.status, 'malformedRequest',
            'and bytes that are not an OCSP request at all are ' +
            'MALFORMEDREQUEST — a status INSIDE the protocol, so a client ' +
            'can report what happened rather than guessing from an HTTP code');
    t.check(Buffer.isBuffer(garbage.der) && garbage.der.length > 0,
            'and even that refusal is a real OCSP response with bytes in it, ' +
            'rather than an error page a revocation client cannot parse');

    // THE NONCE, RFC 6960 section 4.4.1. A responder that ignores it lets a
    // captured response be replayed at a client that asked for freshness.
    const nonced = await ask(REALM, 'jose', issuerPem, good.serialHex, true);
    t.equal(nonced.certStatus, 'good',
            'a request carrying a nonce is answered');
    const requestDer = ocspRequestFor(issuerPem, good.serialHex, true);
    const nonceMarker = Buffer.from('2b0601050507300102', 'hex');
    t.check(requestDer.indexOf(nonceMarker) >= 0,
            'the request really does carry the nonce extension ' +
            '(1.3.6.1.5.5.7.48.1.2) — asserting an echo without checking ' +
            'that there was something to echo is the shape of test that ' +
            'passes against a responder doing nothing');
    const echoed = await revocation.answerOcsp(REALM, 'jose', requestDer);
    t.check(echoed.der.indexOf(nonceMarker) >= 0,
            'and the ANSWER carries it back — section 4.4.1. Without the ' +
            'echo a captured response can be replayed at a client that ' +
            'asked for freshness, and the client cannot tell');
  }

  t.log.info('=== F. rotation fills these lists, and must not empty the ' +
             'store ===');

  // **THE REGRESSION IN THIS SECTION COST THE ROOT CA.**
  //
  // `pki.saveRow()` treated a row with no `tiers`, no `objects` and no
  // `intermediate` as EMPTY and removed it. Two kinds of row have arrived
  // since that test was written and neither has any of the three: the SERVICE
  // row, which holds the Root alone, and a row holding only revocation
  // entries. `revocation.revoke()` saves through that function — so revoking
  // anything at the Root's authority DELETED THE ROOT, and since a rotation
  // supersedes what it replaced at that authority, `buildChain()` on any realm
  // destroyed the Root in the same act.
  //
  // **NOTHING THREW AND THE BUILD REPORTED SUCCESS.** The failure appeared one
  // call later as `trustAnchorsFor()` returning an empty array. These two
  // assertions are the guard.
  const rootScope = pki.SERVICE_SCOPE;
  const rootBase = revocation.listFor(rootScope, 'root').length;
  const intermediates = revocation.issuedList(rootScope, 'root')
    .filter(function (one) {
      return !revocation.isRevoked(rootScope, 'root', one.serialHex);
    });
  t.check(intermediates.length >= 2,
          'the Root has signed the Intermediates, and the register lists ' +
          'them — an authority signs AUTHORITIES as well as leaves, and a ' +
          'responder that did not know it would answer `unknown` about a ' +
          'perfectly valid Issuing CA at its own parent');
  // **THE ORDER OF THESE THREE ACTS IS THE TEST AND MUTATION TESTING IS WHAT
  // DECIDED IT.** The first version revoked permanently and then asserted the
  // Root was still there, and a mutant that removed the `root` guard from
  // `saveRow()` SURVIVED it — because a permanent revocation leaves an entry
  // on the row, and a row with entries is not empty by any reading. The row
  // that is actually at risk is the one saved with NOTHING on it but the
  // Root, and the only way to reach it is to put the list back to empty. So:
  // hold, check, RELEASE, check again.
  const holdAtRoot = revocation.revoke(rootScope, 'root', {
    serialHex: intermediates[0].serialHex, reason: 'certificateHold'
  });
  t.check(holdAtRoot.ok, 'an Intermediate can be put on hold at the Root');
  t.check(pki.hasRoot(),
          'and the Root survives being written to — revoking at the Root ' +
          'saves the SERVICE row back, and that row holds a Root and, at ' +
          'this moment, one list entry');

  const lifted = revocation.release(rootScope, 'root',
                                    intermediates[0].serialHex);
  t.check(lifted.ok, 'the hold can be lifted');
  t.equal(revocation.listFor(rootScope, 'root').length, rootBase,
          'which puts the Root\'s own list back to where this file found ' +
          'it — and when this file runs first that is EMPTY, which is the ' +
          'case the assertion below needs');
  t.check(pki.hasRoot(),
          'AND THE ROOT SURVIVES **THAT**, which is the case the assertion ' +
          'above cannot reach. The service row now holds a Root and nothing ' +
          'else, and `saveRow()` used to treat a row with no tiers, no ' +
          'objects and no intermediate as empty and REMOVE it. Nothing ' +
          'threw; every chain in the process composed to nothing one call ' +
          'later');
  t.check(pki.trustAnchorsFor(REALM).length > 0 &&
          pki.trustAnchorsFor(UNCERTIFIED_REALM).length > 0,
          'and both branches still chain to it');

  const rootRevoke = revocation.revoke(rootScope, 'root', {
    serialHex: intermediates[0].serialHex, reason: 'superseded'
  });
  t.check(rootRevoke.ok,
          'and an Intermediate can then be revoked permanently, which is ' +
          'what a Root rotation does');
  t.check(pki.hasRoot() && pki.trustAnchorsFor(REALM).length > 0,
          'with the Root and every anchor still there afterwards');
  // **AND THEN THE ENTRY IS TAKEN BACK OFF, BY HAND, WHICH NOTHING IN THE
  // SERVICE CAN DO (2026-09-12).** The Intermediate revoked above is a LIVE
  // one — the default realm's, or the process branch's — and since
  // `common/revocation_status.js` consults the register for a presented
  // certificate, leaving it `superseded` refuses every x5c assertion and every
  // X509-SVID under it for the rest of this process. `run.js` runs every file
  // in one process, so that was `tests/rfc7523_person_issuer.js` failing on a
  // revocation this file made. A permanent revocation cannot be released
  // through the API, which is the point of it, so the row is restored the way
  // `tests/CLAUDE.md` asks for any process-wide state a test touched: put back
  // exactly what was there.
  (function restoreRootList() {
    log.debug("Entering restoreRootList().");
    const row = pki.rawRowFor(rootScope);
    if (row && row.revoked && Array.isArray(row.revoked.root)) {
      row.revoked = Object.assign({}, row.revoked, {
        root: row.revoked.root.filter(function (one) {
          return revocation.normalSerial(one.serialHex) !==
                 revocation.normalSerial(intermediates[0].serialHex);
        })
      });
      pki.saveRow(rootScope, row);
    }
    log.debug("Leaving restoreRootList().");
  })();
  t.check(!revocation.isRevoked(rootScope, 'root', intermediates[0].serialHex),
          'and the live Intermediate this section revoked is off the Root\'s ' +
          'list again, so no later file in this process inherits a revoked ' +
          'branch');

  const joseBefore = revocation.listFor(REALM, 'jose').length;
  const intermediateBefore = revocation.listFor(REALM, 'intermediate').length;
  const leaves = revocation.issuedList(REALM, 'jose').length;
  const reissued = await pki.reissueUseCase(REALM, 'jose');
  t.check(reissued.ok, 'an Issuing CA can be reissued',
          (reissued.errors || []).join(' '));
  t.check(revocation.listFor(REALM, 'jose').length > joseBefore,
          'and the leaves it had signed are on ITS OWN list, because it is ' +
          'the authority that issued them',
          joseBefore + ' -> ' + revocation.listFor(REALM, 'jose').length +
          ' (' + leaves + ' leaf/leaves existed)');
  t.equal(revocation.listFor(REALM, 'intermediate').length,
          intermediateBefore + 1,
          'and the REPLACED ISSUING CA is on the INTERMEDIATE\'s list, ' +
          'because that is the authority that issued IT. Putting it on its ' +
          'own list would be a certificate revoking itself, which no ' +
          'validator would ever look for');
  const superseded = revocation.listFor(REALM, 'intermediate')
    .filter(function (one) { return one.reason === 'superseded'; });
  t.check(superseded.length >= 1,
          'and rotation files it as `superseded` (code 4) rather than ' +
          'unspecified — section 5.3.1 says to OMIT the extension for ' +
          'unspecified, so the commonest entry on any of these lists would ' +
          'otherwise carry no reason at all');

  t.log.info('=== G. every certificate NAMES its own lists, over http and ' +
             'ldap ===');

  // The addresses are only worth having if they are INSIDE the certificates,
  // because that is the only way a client that was handed a leaf finds them.
  const points = revocation.distributionPoints(REALM, 'jose');
  t.check(/^http:/.test(points.http) && /^ldap:/.test(points.ldap) &&
          /^http:/.test(points.ocsp) && /^http:/.test(points.caIssuers),
          'an authority has a CRL over http and ldap, an OCSP responder and a ' +
          'caIssuers address, all plain http',
          JSON.stringify(points));
  t.check(points.ldaps === undefined,
          'and NO ldaps:// address — RFC 5280 section 8 says a CA SHOULD NOT ' +
          'write one into an extension, and this service did until 2026-09-13',
          JSON.stringify(points));
  t.check(/certificateRevocationList;binary/.test(points.ldap),
          'and the LDAP form carries the ATTRIBUTE DESCRIPTION (RFC 4523 ' +
          'section 4) rather than just a DN — without it a client fetches ' +
          'the entry and finds no list, because the transfer syntax is part ' +
          'of the request');

  const leaf = pki.certificatesFor(REALM, 'jose')[0];
  if (leaf && haveOpenSsl()) {
    const leafFile = path.join(scratch, 'leaf.pem');
    fs.writeFileSync(leafFile, leaf.certificatePem);
    const text = execFileSync('openssl',
      ['x509', '-in', leafFile, '-noout', '-text'], { encoding: 'utf8' });
    t.check(/X509v3 CRL Distribution Points/.test(text),
            'and a leaf this authority signed carries cRLDistributionPoints');
    t.check(/URI:http:/.test(text) && /URI:ldap:/.test(text) &&
            !/URI:ldaps:/.test(text) && !/URI:https:/.test(text),
            'naming http and ldap and neither https nor ldaps (RFC 5280 ' +
            'section 8)',
            (text.match(/URI:[^\s]*/g) || []).slice(0, 4).join(' '));
    t.check(/OCSP - URI:http/.test(text),
            'and an Authority Information Access naming its OCSP responder');
    t.check(/CA Issuers - URI:http/.test(text),
            'and a caIssuers address, so a client sent an incomplete chain ' +
            'can finish building one');
  }

  // AN APPLICATION'S OR A PERSON'S SIGNING KEY PAIR, which went through
  // `issueSigningKeyPair()` rather than `certify()` and named no list at all
  // until 2026-09-12 — the one certificate this hierarchy hands to something
  // that is not this service.
  const pointsFor = revocation.distributionPoints(REALM, 'assertions');
  for (const kind of [{ purpose: 'jwt' }, { purpose: 'saml' },
                      { purpose: 'jwt', subjectKind: 'person' }]) {
    const pair = await pki.issueSigningKeyPair(REALM, Object.assign({
      identifier: 'rev-pointers-' + (kind.subjectKind || 'app') + '-' +
                  kind.purpose
    }, kind));
    const label = (kind.subjectKind || 'application') + ' ' + kind.purpose;
    t.check(pair.ok, 'an ' + label + ' signing key pair is issued',
            (pair.errors || []).join(' '));
    if (!pair.ok) {
      continue;
    }
    const cert = new nodeCrypto.X509Certificate(pair.issued.certificatePem);
    const described = await x509.describeCertificate(
        pair.issued.certificatePem);
    const flat = JSON.stringify(described.extensions);
    t.check(described.extensions.some(function (one) {
              return one.oid === '2.5.29.31';
            }) && flat.indexOf(pointsFor.http) >= 0 &&
            flat.indexOf(pointsFor.ldap) >= 0,
            'and the ' + label + ' key pair carries cRLDistributionPoints ' +
            '(2.5.29.31) naming the ASSERTIONS Issuing CA\'s list over http ' +
            'and ldap — the authority that signed it, not the realm');
    t.check(described.extensions.some(function (one) {
              return one.oid === '1.3.6.1.5.5.7.1.1';
            }) && flat.indexOf(pointsFor.ocsp) >= 0 &&
            flat.indexOf(pointsFor.caIssuers) >= 0,
            'and an Authority Information Access (1.3.6.1.5.5.7.1.1) naming ' +
            'that CA\'s OCSP responder and caIssuers address');
    t.check(revocation.issuedHere(REALM, 'assertions', cert.serialNumber),
            'and the authority KNOWS it issued that serial, so the responder ' +
            'the certificate points at answers `good` rather than disowning ' +
            'it as `unknown` — a pointer to a responder with no record of ' +
            'the certificate is worse than no pointer');
  }
  t.check(pki.issuedKeyPairsFor(REALM, 'assertions').every(function (one) {
            return !Object.keys(one).some(function (key) {
              return /private|public|pem|jwk/i.test(key);
            });
          }),
          'and what is recorded about an issued key pair holds no key — ' +
          'serial, subject, expiry and who it was for, which is what a CRL ' +
          'entry and an OCSP answer are made of');

  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch (e) {
    // The scratch directory is in the OS temp space and is a few kilobytes of
    // DER. Failing to remove it must not fail a test run.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pki_revocation',
  describe: 'CRLs and OCSP: one authority per CA rather than one per realm, ' +
            'the nine reasons, revoking and its four refusals, the hold that ' +
            'is the only reason RFC 5280 lets you undo, a CRL OpenSSL reads ' +
            'and verifies, a responder that answers good/revoked/unknown and ' +
            'two refusals that are answers, the nonce echo, rotation filling ' +
            'the lists at the right authority, and the emptiness test that ' +
            'deleted the Root',
  run: run
};
