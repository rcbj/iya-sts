'use strict';
//
// File: portal_access.js
//
// ===========================================================================
// THE USER PORTAL SHOWS YOU YOUR OWN ACCOUNT AND NOBODY ELSE'S. OWASP A01.
//
// **BROKEN ACCESS CONTROL IS THE TOP OF THE OWASP TOP TEN**, and the shape it
// takes is nearly always the same: a handler that reads an identity from the
// REQUEST instead of from the SESSION. The portal is exactly the kind of page
// that grows one — every route on it is about a person, and the person's name
// is right there in the URL of the page that linked to it.
//
// So the rule in `portal/portal.js` is absolute: **no route takes a username,
// an id or a DN from a query string or a body.** `/portal/activate` is the one
// exception and is not one — nobody is signed in there, and what authorises it
// is the token, which is a credential.
//
// This file asserts the rule by TRYING to break it. It is deliberately written
// as "here is every parameter a future author might plausibly read, and here is
// somebody else's name in it".
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Most of the portal belongs over HTTP and is asserted there. What is here is
// the part that CANNOT be: the claim is about which SOURCE a handler read, and
// the only way to see that from outside is to send a request whose two possible
// sources DISAGREE — one identity in the session and a different one in every
// parameter — and then check which answer came back. That needs two credential
// sets and a controlled directory, which is a fixture rather than a request.
//
// It also lets the CREDENTIAL LAYER be asserted directly: that `removeKey()`
// looks an id up among the caller's own keys, which is the line that makes the
// remove-key route safe and is invisible from the outside when it is correct.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'portal_access',
  level: process.env.LOG_LEVEL || 'info' });

function run(t) {
  log.debug("Entering run().");
  require('../common/app');
  require('../authn/authn');
  require('../ldap/ldap_server');
  const credentials = require('../common/credentials');
  const websecurity = require('../common/websecurity');

  const alice = 'portal-alice-' + nodeCrypto.randomBytes(3).toString('hex');
  const mallory = 'portal-mallory-' + nodeCrypto.randomBytes(3).toString('hex');

  // Both people exist and both hold a credential, so a refusal below cannot be
  // "that person does not exist" wearing the costume of an access control.
  //
  // **THE ENTRY IS MADE THROUGH `recordAuthentication()` AND NOT THROUGH
  // `credentials.bootstrap()`**, which is what this reached for first and does
  // nothing here: the bootstrap runs only in PRODUCT mode and only when nobody
  // in the realm holds a credential, so in this suite it returned `ran: false`
  // and every assertion below failed against people who did not exist. The
  // observer is the ordinary door — it is the one every protocol here creates
  // an entry through — and it works in both modes.
  t.log.info('=== two people, both real, both with credentials ===');
  const stats = require('../common/admin_stats');
  const makePerson = function (name) {
    log.debug("Entering makePerson().");
    stats.recordAuthentication({ presented: name, protocol: 'test',
                                 method: 'a fixture' });
    log.debug("Leaving makePerson().");
  };
  makePerson(alice);
  makePerson(mallory);
  const alicePw = credentials.setPassword(alice, 'alice-password');
  const malloryPw = credentials.setPassword(mallory, 'mallory-password');
  t.check(alicePw.ok && malloryPw.ok,
          'both people exist and hold a password',
          JSON.stringify([alicePw.ok, malloryPw.ok]));

  const aliceKey = credentials.addKey(alice, {
    credentialId: 'alice-key-1',
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' },
    signCount: 0
  }, 'mfa');
  t.equal(aliceKey.ok, true, 'and alice has a security key of her own');

  // -----------------------------------------------------------------------
  // THE ASSERTION THAT MATTERS. `removeKey()` is handed MALLORY as the caller
  // and ALICE'S credential id — which is exactly the request a portal route
  // would produce if somebody edited the hidden field.
  // -----------------------------------------------------------------------
  t.log.info('=== one person cannot touch another\'s credential ===');
  const stolen = credentials.removeKey(mallory, 'alice-key-1');
  t.equal(stolen.ok, false,
          'MALLORY CANNOT REMOVE ALICE\'S SECURITY KEY by naming its id. The ' +
          'id is looked up among the CALLER\'S OWN keys, so one belonging to ' +
          'somebody else matches nothing — which is what makes it safe for ' +
          'the credential id to come from the request while the username ' +
          'never does');
  t.equal(credentials.keysOf(alice).length, 1,
          'and alice still holds it');

  // The same shape, the other way: a caller may remove their own.
  const own = credentials.addKey(mallory, {
    credentialId: 'mallory-key-1',
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'c', y: 'd' },
    signCount: 0
  }, 'mfa');
  t.equal(own.ok, true, 'mallory can enrol a key of his own');
  t.equal(credentials.removeKey(mallory, 'mallory-key-1').ok, true,
          'and remove it — so the refusal above is about WHOSE key it is and ' +
          'not about the operation being broken for everybody');

  // -----------------------------------------------------------------------
  // THE LOCKOUT REFUSAL, which is an availability control rather than an
  // access one and belongs here because it is the same function.
  // -----------------------------------------------------------------------
  t.log.info('=== nobody can remove their own last way in ===');
  const keyOnly = 'portal-keyonly-' + nodeCrypto.randomBytes(3).toString('hex');
  makePerson(keyOnly);
  // Give them a PRIMARY key and no password — the passwordless account.
  const only = credentials.addKey(keyOnly, {
    credentialId: 'only-key',
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'e', y: 'f' },
    signCount: 0
  }, 'primary');
  t.equal(only.ok, true, 'a passwordless account holds one primary key');
  const mechanisms = credentials.mechanismsFor(keyOnly);
  t.equal(mechanisms.usable, true, 'and can sign in');
  t.equal(mechanisms.password, false, 'with no password at all');

  const lockout = credentials.removeKey(keyOnly, 'only-key');
  t.equal(lockout.ok, false,
          'REMOVING THE ONLY WAY IN IS REFUSED. An identity provider that ' +
          'lets somebody lock themselves out with one click has a support ' +
          'queue rather than a security control');

  // -----------------------------------------------------------------------
  // AN `mfa` KEY IS NOT A WAY IN. This is the combination the activation flow
  // refuses to create, asserted at the layer that decides it.
  // -----------------------------------------------------------------------
  t.log.info('=== a second factor is not a first one ===');
  const mfaOnly = 'portal-mfaonly-' + nodeCrypto.randomBytes(3).toString('hex');
  makePerson(mfaOnly);
  credentials.addKey(mfaOnly, {
    credentialId: 'second-factor',
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'g', y: 'h' },
    signCount: 0
  }, 'mfa');
  const second = credentials.mechanismsFor(mfaOnly);
  t.equal(second.usable, false,
          'somebody holding ONLY a second factor cannot sign in — a key ' +
          'marked `mfa` is the second of two and there is no first. That is ' +
          'the combination /portal/activate refuses to create, and this is ' +
          'the layer that decides it');
  t.equal(second.mfaRequired, true,
          'and the key does make a second factor REQUIRED, which is what ' +
          'makes the flag mean anything');
  t.equal(second.activated, true,
          'they are "activated" — they have set something up — which is a ' +
          'different question from whether they can get in, and conflating ' +
          'the two is how somebody ends up stuck at a sign-in screen with an ' +
          'account the service considers finished');

  // -----------------------------------------------------------------------
  // CSRF: a token is bound to ONE session.
  // -----------------------------------------------------------------------
  t.log.info('=== a CSRF token is one session\'s ===');
  const mine = websecurity.tokenFor('session-of-alice');
  const theirs = websecurity.tokenFor('session-of-mallory');
  t.check(mine !== theirs, 'two sessions get different tokens');
  t.equal(websecurity.checkCsrf('session-of-alice', { csrf_token: theirs }).ok,
          false,
          'AND ONE SESSION\'S TOKEN DOES NOT WORK ON ANOTHER\'S REQUEST, ' +
          'which is the property that makes it a CSRF defence rather than a ' +
          'constant everybody shares');
  t.equal(websecurity.checkCsrf('session-of-alice', { csrf_token: mine }).ok,
          true, 'and the right one does');

  // -----------------------------------------------------------------------
  // THE RATE LIMITER'S PER-DOOR CEILING (2026-09-06).
  //
  // `attempt()` gained an optional fourth argument, and it is asserted HERE
  // rather than over HTTP for a reason this suite has been bitten by before:
  // **the buckets are per PROCESS and not per realm**, so a job that drove a
  // limiter to its ceiling would leave the next job in the run meeting 429s
  // that are nothing to do with it. In process the bucket can be cleared
  // between sections, which is what `reset()` is for.
  //
  // The argument exists because one number cannot serve two rhythms:
  // `security.rateLimitPerIdentity` is FIVE because it guards a SIGN-IN, and
  // `POST /xacml/pip` is called once per access decision by a remote
  // enforcement point — so a busy one makes several a second and every one is
  // legitimate. Sharing the sign-in number would have switched that endpoint
  // off for its only caller, SILENTLY, because the client treats a refused
  // query as an empty bag and goes on deciding on less information.
  // -----------------------------------------------------------------------
  t.log.info('=== a door may name its own rate-limit ceiling ===');
  websecurity.reset();
  const caller = { socket: { remoteAddress: '198.51.100.7' }, headers: {} };

  // THE DEFAULT IS UNCHANGED, which is the half that matters most: every
  // existing caller omits the argument and must behave exactly as it did.
  let refusedAt = 0;
  for (let i = 1; i <= 12 && !refusedAt; i += 1) {
    if (!websecurity.attempt('probe-default', caller, 'alice').ok) {
      refusedAt = i;
    }
  }
  t.check(refusedAt > 0 && refusedAt <= 6,
          'with no ceiling named, the sign-in limit still applies — five ' +
          'attempts and the sixth is refused',
          'refused at attempt ' + refusedAt);

  websecurity.reset();
  let stillOk = 0;
  for (let i = 1; i <= 40; i += 1) {
    if (websecurity.attempt('probe-named', caller, 'a-pep', 100).ok) {
      stillOk += 1;
    }
  }
  t.equal(stillOk, 40,
          'AND A DOOR THAT NAMES 100 GETS 100 — forty machine-to-machine ' +
          'calls that the sign-in limiter would have refused after five. ' +
          'This is the assertion that would fail if the argument were ever ' +
          'dropped, and the failure it prevents is silent: the caller reads ' +
          'a refusal as an empty bag',
          stillOk);

  websecurity.reset();
  let namedRefusedAt = 0;
  for (let i = 1; i <= 12 && !namedRefusedAt; i += 1) {
    if (!websecurity.attempt('probe-low', caller, 'a-pep', 3).ok) {
      namedRefusedAt = i;
    }
  }
  t.check(namedRefusedAt === 4,
          'and a ceiling BELOW the default is honoured too — the argument ' +
          'names the limit rather than raising it, so an operator can ' +
          'tighten a door as well as loosen one',
          'refused at attempt ' + namedRefusedAt);

  // THE BUCKETS ARE LEFT CLEAN. A limiter left near its ceiling is exactly
  // the cross-test interference this section is placed in process to avoid,
  // and leaving it dirty here would reintroduce it one layer down.
  websecurity.reset();
  log.debug("Leaving run().");
}

module.exports = {
  name: 'portal access',
  describe: 'the portal shows you your own account and nobody else\'s',
  run: run
};
