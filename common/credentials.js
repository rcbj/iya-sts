// @ts-check
'use strict';
//
// File: credentials.js
//
// ---------------------------------------------------------------------------
// THE ONE PLACE A PRESENTED PASSWORD IS VERIFIED (2026-09-06).
//
// Four doors took a password and none of them checked one until product mode:
// the sign-in screen (`authn.js`), an LDAP bind (`ldap_server.js`), a
// WS-Security UsernameToken (`wstrust.js`) and SCIM Basic (`scim_auth.js`).
// More have joined since — the OAuth password grant, EST Basic, the portal's
// password forms (see *A PASSWORD THAT MUST BE CHANGED* below for the list).
// They all ask here now, and that is the whole point — four verifications is
// four chances to write the comparison differently, and the one written with
// `===` is a timing oracle nobody notices because it looks like every other
// string compare in the file.
//
// ---------------------------------------------------------------------------
// PERMISSIVENESS IS AN IMPLEMENTATION HERE, NOT AN ABSENCE, AND THAT IS THE
// ARCHITECTURAL POINT OF THE FILE.
//
// Before this, development-mode behaviour was that no code ran. There was
// nothing to swap: to make the service verify a password you had to ADD a check
// at four call sites and remember all four. Now `verify()` is always called and
// always answers; what the mode changes is what it answers with. A policy point
// with a permissive implementation can be swapped, extended, logged and tested.
// An absence can only be found by reading everything.
//
// **A NEW DOOR THAT TAKES A CREDENTIAL CALLS THIS.** If it needs a decision
// this does not offer, the decision belongs here beside the others rather than
// at the call site — see common/mode.js, which this file is the credential half
// of.
//
// ---------------------------------------------------------------------------
// WHAT DEVELOPMENT MODE STILL REFUSES, which surprises people.
//
// It is not "everything passes". The reserved password `invalid` is refused in
// both modes, and it predates this file: `wstrust.js` and `scim_auth.js` both
// carry it, because a mock that cannot be made to say NO cannot be used to test
// what a client does when it is told no. That convention is honoured here so
// that it means the same thing at all four doors instead of two.
//
// ---------------------------------------------------------------------------
// THE DIRECTORY ARRIVES THROUGH `setDirectory()`, filled by
// `ldap/ldap_server.js` at require time, and it is an INVERTED HOOK for the
// reason every other one on this path is (rule 3e): this file is required by
// `authn.js` at 8 and the directory is at 21, so a require in the obvious
// direction would drag every `/ldap` route to the front of the router. It
// carries TWO functions and is validated whole — a filler that installed the
// read and not the write would leave a service that can verify a password and
// can never set one, which is a product-mode deployment nobody can get into.
//
// A LIBRARY (rule 3): it registers no route. It requires `config`, `crypto`,
// `mode` and the further leaves each argued beside its require below, none of
// which requires it back.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
const config = require('./config');
const crypto = require('./crypto');
const mode = require('./mode');
// The three the authenticator-app section below needs, and none of them can
// require this file back: `realms` holds the pending enrolment (per realm, like
// every other pending record here), `keystore` seals the shared secret where
// the key-encryption key outlives the process, and `totp` is the mechanism
// itself. `keystore` requires `config`, `crypto`, `mode`, `realms`, `secrets`
// and a few other leaves; `totp` requires `config`, `crypto`, `helpers`,
// `realms` and `error_codes`. So this file stays a LEAF of the same shape it
// was.
const realms = require('./realms');
const keystore = require('./keystore');
const totp = require('./totp');
// THE THIRD SECOND FACTOR (2026-09-10), and it is on this list for the same
// reason `totp` is: it owns what a recovery code IS and this file owns where
// the set lives. It requires `config`, `crypto`, `helpers` and `error_codes`
// and nothing else, so it cannot reach back here and this file stays the leaf
// it was.
const backupCodes = require('./backup_codes');
// THE PASSWORD POLICY (2026-09-12). What a password here must look like, which
// of a person's old ones it may not be, and how one is made up. A LEAF that
// requires `helpers`, `mode`, `error_codes` and an npm package, so it cannot
// reach back here;
// its directory arrives through a slot `ldap_server.js` fills, like this
// file's.
const passwordPolicy = require('./password_policy');
// THE SECURITY KEY'S POLICY, AND IT IS THE ONE REQUIRE IN THIS FILE THAT
// POINTS OUT OF `common/` (2026-09-10).
//
// It is a LIBRARY (rule 3): it registers no route, so requiring it moves
// nothing in the route order, and it requires only `config`, `helpers` and
// `authn/webauthn.js` (and `error_codes`) — none of which can reach back
// here — so it cannot join
// a cycle. What it carries is the answer to *may a key be enrolled in this
// role, and how many may one person hold*, which is a question about the
// MECHANISM and belongs beside the mechanism. The alternative was a second
// copy of `webauthn.*` in this file, and a second copy of a policy is a second
// answer: `/portal/keys` would have refused an eleventh key while
// `/admin-api` allowed it, or the other way round, with nothing failing.
const webauthnPolicy = require('../authn/webauthn_policy');
// THE VERIFIER, for the two-step key enrolment below. A LEAF on the same terms
// as the policy module beside it — it registers nothing and requires only npm
// packages, `common/crypto` and `common/helpers`, so it can neither move a
// route nor close a cycle. It is required HERE for the reason the RFC 6238
// pair is here: **a two-step enrolment is a credential-store question**, and
// this file is the credential store. It already verifies a password and a
// one-time code; verifying the registration ceremony that produces a key is
// the same act on the third mechanism.
const webauthnVerifier = require('../authn/webauthn');
// THE ERROR CODES (2026-09-12). A LEAF that requires nothing, so it cannot
// close a cycle from here — which is why it is this and not `audit.js`, which
// this file must not reach. Every refusal below RETURNS a verdict to a caller
// that sends the response (the sign-in screen, the portal, an LDAP bind, a
// SCIM Basic header, the console), so the code rides ON the verdict:
// `coded()` attaches it under the Symbol `errorCodes.mark()` uses, NON-
// ENUMERABLY, so `errorCodes.codeOf(verdict)` reads it and a verdict handed
// whole to `/admin-api` as JSON carries no trace of it.
const errorCodes = require('./error_codes');
// SEVERAL NODES AGAINST ONE STORE (2026-09-14, #46 section 2). Every
// single-use credential this file holds — a TOTP step, a recovery code, a
// WebAuthn signature counter and ceremony, an activation or reset link, the
// bootstrap password — was spent by reading the directory entry and writing it
// back, which on one node is atomic and across nodes is two nodes both
// accepting inside the change log's window. The claims module spends a value
// ONCE in the store; the counters module advances a value that may only go
// UP. Both are LIBRARIES that require `config`, `realms`, `error_codes` and
// the capability table and reach `persistence.js` lazily, so neither can close
// a cycle from here, and on a memory or ldif store each is this process's own
// map — exactly as atomic as the entry check it sits behind.
const claims = require('../cluster/cluster_claims');
const counters = require('../cluster/cluster_counters');
const capabilities = require('../cluster/cluster_capabilities');

function coded(code, verdict) {
  log.debug("Entering coded().");
  log.debug("Leaving coded().");
  return errorCodes.mark(verdict, code);
}

// The attribute. RFC 4519 section 2.41 — the standard name, so an entry this
// service writes is one an ordinary LDAP client recognises, and one written by
// an ordinary LDAP client is one this service can read.
const PASSWORD_ATTRIBUTE = 'userPassword';

// ---------------------------------------------------------------------------
// THE SECURITY KEY, ON THE PERSON'S OWN ENTRY (2026-09-06).
//
// **IT WAS AN IN-MEMORY MAP IN `authn.js` AND THAT WAS THE WRONG PLACE.**
// `webauthnCredentials` is a `realms.map()` keyed by username, which means a
// key somebody enrolled did not survive a restart, could not be provisioned,
// could not be seen on any page, and could not be persisted by product mode.
// For a PASSWORDLESS key that is the whole account: the credential is the only
// one there is, so losing it on a restart loses the account.
//
// So it lives beside `userPassword`, on the entry, in the same store — one
// object per person carrying everything about how they authenticate.
//
// ---------------------------------------------------------------------------
// **AND FOR FOUR DAYS NOTHING WROTE TO IT (2026-09-06 to 2026-09-10).**
//
// The paragraph above describes the design and the design was right. What was
// missing is that `addKey()` below — the ONLY writer — **had no caller
// anywhere in this service.** `authn.js` went on setting its own map, so:
//
//   * `keysOf()` answered `[]` for everybody, so `mechanismsFor()` reported
//     `mfaKeys: 0, primaryKeys: 0` for everybody, for ever;
//   * `mfaRequired` could never become true from a key, so one enrolled at the
//     sign-in screen was **never demanded again** — the next sign-in had the
//     checkbox unticked and a password alone was accepted;
//   * `GET /authn/webauthn`'s gate (*does this person hold an `mfa` key?*)
//     refused everybody;
//   * `/portal/keys` could list and remove keys that could not exist, and
//     `/portal/activate`'s *a security key instead of a password* spent the
//     activation link, said "your account is ready" and enrolled nothing.
//
// **THE WHOLE ROLE MODEL BELOW WAS THEREFORE UNREACHABLE**, which is worth
// saying at the top of the thing it describes: `ROLES`, the last-way-in
// refusal, the per-person cap and `webauthn.primaryAllowed` were all correct
// and all decided nothing, because the state they decide about could not be
// created. A store with no writer looks exactly like a store nobody uses.
//
// `authn/authn.js` writes here now — its own header carries the argument —
// and `tests/vendored/sts_webauthn_second_factor.js` drives a real ceremony
// and reads the key back out of `GET /admin-api/users`, which is the assertion
// that would have caught it.
//
// **THE VALUE IS JSON AND THE ATTRIBUTE IS MULTI-VALUED**, because a person may
// hold several keys (a laptop and a phone, which is the ordinary case and the
// reason WebAuthn has a credential id at all). Each carries its own ROLE.
//
// **THE PUBLIC KEY IS NOT A SECRET AND IS NOT HASHED**, which is the one place
// this file departs from what it does with a password. A WebAuthn public key is
// published by design — the whole point of the scheme is that the verifier
// holds something useless to an attacker — so hashing it would make it
// unusable for the only thing it is for. What must never be stored is a
// PASSWORD, and this is not one.
const WEBAUTHN_ATTRIBUTE = 'stsWebauthnCredential';

// WHAT A KEY IS FOR. Two roles and no third, because a key can do exactly two
// things here (this was written when a key was the only second factor; an
// authenticator app and recovery codes joined it on 2026-09-10, and neither
// has a role — see the TOTP section below):
//
//   'primary'  the key signs somebody in ON ITS OWN — passwordless. The
//              credential IS the account.
//   'mfa'      the key is a SECOND factor and a password is the first. A
//              person whose only key is `mfa` and who has no password cannot
//              sign in at all, which is why the setup flow refuses that
//              combination rather than letting somebody lock themselves out.
const ROLES = ['primary', 'mfa'];

// THE RESERVED REFUSAL, honoured in BOTH modes. See the header.
const RESERVED_REFUSAL = 'invalid';

let directory = null;

function setDirectory(hooks) {
  log.debug('Entering setDirectory().');
  // The two the verifier cannot work without. The security-key and activation
  // functions are checked WHERE THEY ARE USED rather than here, so an older
  // `ldap_server.js` that offers only the password pair still gives a working
  // password sign-in instead of refusing the whole slot — which is the
  // difference between a version skew and an outage.
  // `readTotp` and `writeTotp` are NOT on this list, for the reason the
  // comment above gives about the security-key functions: they are checked
  // where they are used, so an older `ldap_server.js` that knows nothing about
  // authenticator apps still gives a working password sign-in rather than
  // having the whole slot refused.
  const needed = ['readPassword', 'writePassword'];
  const missing = needed.filter(function (name) {
    return !hooks || typeof hooks[name] !== 'function';
  });
  if (missing.length) {
    log.error(errorCodes.tag('STS-AUTHN-0047') +
              'credentials: setDirectory() was given something without ' +
              missing.join(', ') + ', so it was refused whole. Half of it ' +
              'would be a service that can check a password and never set ' +
              'one — which in product mode is a deployment nobody can sign ' +
              'in to.');
    log.debug('Leaving setDirectory(). Refused.');
    return false;
  }
  directory = hooks;
  log.debug('Leaving setDirectory(). Credentials are backed by the directory.');
  return true;
}

// Is there a store at all? Read by the console and by the mode report, which
// say so rather than letting somebody switch to product mode and discover at
// the sign-in screen that nothing can be verified.
function storable() {
  log.debug("Entering storable().");
  log.debug("Leaving storable().");
  return !!directory;
}

// ---------------------------------------------------------------------------
// THE PASSWORD OBSERVER (2026-09-12): THE ONE MOMENT A PLAINTEXT PASSWORD IS
// IN HAND, OFFERED TO WHOEVER NEEDS TO DERIVE SOMETHING FROM IT.
//
// A product-mode KDC needs a person's Kerberos long-term keys, and those are
// derived from the PASSWORD — RFC 3961 string-to-key over the plaintext and a
// salt. What this file stores is a scrypt hash, and no key can be derived from
// a hash. So the keys have to be made at the two moments this file holds the
// plaintext: when `setPassword()` has written one, and when `verify()` or
// `verifyAsync()` has just confirmed one. Those are exactly the two places the
// observer is called, and nowhere else.
//
// **AN INVERTED HOOK, AND RULE 3e's TEST IS PASSED ON A LAYERING CLAUSE AS
// WELL AS THE USUAL TWO.** The filler is `kerberos/krb5_person_keys.js`.
// A require from here to it would be `common/` reaching into `kerberos/`, which
// `common/CLAUDE.md` names as the layering inversion this directory's entry
// test exists to prevent; it would also drag the principal database and the
// Kerberos codec into every process that verifies a password (the parent
// project's in-process jobs, `npm test`); and that module requires THIS file,
// so the require would close a cycle. Nothing here knows what Kerberos is.
//
// **ONE FUNCTION, AND IT MAY NOT KEEP THE PASSWORD.** It is handed the
// plaintext synchronously and must not retain it past the work it starts —
// which for Kerberos is one asynchronous derivation. The call is WRAPPED: an
// observer that throws is logged and the set or the verification it was
// observing answers exactly what it would have answered without it. A password
// change or a sign-in that failed because a key could not be derived is the
// one outcome this hook must never cause.
//
// It is called only with a password this file has VERIFIED or WRITTEN — never
// on a development-mode verification, which checked nothing, and never on a
// refusal.
// ---------------------------------------------------------------------------
let passwordObserver = null;

function setPasswordObserver(fn) {
  log.debug('Entering setPasswordObserver().');
  if (fn !== null && typeof fn !== 'function') {
    log.error(errorCodes.tag('STS-AUTHN-0047') +
              'credentials: setPasswordObserver() was given something that ' +
              'is not a function, so it was refused.');
    log.debug('Leaving setPasswordObserver(). Refused.');
    return false;
  }
  passwordObserver = fn;
  log.debug('Leaving setPasswordObserver(). ' +
            (fn ? 'Installed.' : 'Cleared.'));
  return true;
}

// A password WRITTEN BY A DOOR THAT DOES NOT GO THROUGH setPassword() — the
// LDAP add and modify handlers, which ask `preparePassword()` for the hash and
// commit it into an atomic working copy of their own. Without this, a password
// changed over the socket derived no Kerberos keys until the next verified
// sign-in, and the old keys were refused in between. Called by the handler
// AFTER it has committed, for setPassword()'s reason.
function passwordWritten(name, password) {
  log.debug("Entering passwordWritten().");
  notifyPassword(name, password, 'set');
  log.debug("Leaving passwordWritten().");
}

function notifyPassword(name, password, event) {
  log.debug("Entering notifyPassword().");
  if (!passwordObserver || !name || !password) {
    log.debug("Leaving notifyPassword().");
    return;
  }
  try {
    passwordObserver(name, String(password), { event: event });
  } catch (e) {
    // Swallowed with a reason: see the header. What is lost is whatever the
    // observer derives, and the log says so; the credential act it observed
    // has already happened and must answer as though nothing was watching.
    log.warn('credentials: the password observer threw while observing a ' +
             event + ' for ' + name + ', and the ' + event +
             ' is unaffected: ' +
             e.message);
  }
  log.debug("Leaving notifyPassword().");
}

// ---------------------------------------------------------------------------
// THE VERIFICATION. One answer, always with a REASON, because the caller is a
// sign-in screen that has to say something and "no" on its own sends people to
// debug the wrong half.
//
// The reason is for the LOG and for the console, and deliberately NOT for the
// response body at a protocol endpoint: telling a caller "that person exists
// but the password is wrong" is the account-enumeration answer, and every door
// here already answers with its own protocol's single failure.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// VERIFICATION IS TWO FUNCTIONS AND A DERIVATION BETWEEN THEM, and the split
// is what lets `verify()` and `verifyAsync()` be one policy with two doors.
//
// EVERYTHING that can be decided without computing scrypt is decided in
// `verifyPrepare()` — the reserved refusal, development mode, a missing name,
// a missing store, a store that threw, nobody by that name, a stored form this
// service did not write. Those are the overwhelming majority of refusals and
// none of them costs 68ms. What comes back is either a finished answer or the
// stored value to compare against, and the two doors differ only in which
// process runs the comparison.
//
// The alternative — an async door with its own copy of those seven refusals —
// is the shape this file exists to avoid: `verify()` is the one place a
// presented password is checked, and two copies of "when do we say no" would
// eventually say it in two different sets of circumstances.
// ---------------------------------------------------------------------------
function verifyPrepare(username, password, opts) {
  log.debug("Entering verifyPrepare().");
  const name = String(username == null ? '' : username).trim();
  log.debug('Entering verifyPrepare(). username=' + name);
  const via = (opts && opts.via) || 'unstated';

  // BOTH MODES. A mock that cannot be made to say no is not a test fixture.
  if (String(password) === RESERVED_REFUSAL) {
    log.debug('Leaving verifyPrepare(). The reserved refusal password was ' +
              'presented.');
    return { done: coded('STS-AUTHN-0048',
                         { ok: false, reason: 'reserved-refusal',
             detail: 'the password "' + RESERVED_REFUSAL + '" is reserved ' +
                     'and is refused in every mode, so that a client can be ' +
                     'tested against a refusal without anything being ' +
                     'configured' }) };
  }

  if (!mode.verifiesCredentials()) {
    log.debug('Leaving verifyPrepare(). Development mode: nothing is checked.');
    return { done: { ok: true, reason: 'development-mode',
             detail: 'development mode checks no password in any protocol; ' +
                     'what was proved is that somebody typed a name' } };
  }

  if (!name) {
    log.debug('Leaving verifyPrepare(). No username.');
    return { done: coded('STS-AUTHN-0049', { ok: false, reason: 'no-username',
             detail: 'no username was presented' }) };
  }
  if (!directory) {
    // FAIL CLOSED, and this is the one place in this file where that matters.
    // Product mode with no store is a misconfiguration, and the permissive
    // answer to a misconfigured gate is how a service ends up authenticating
    // everybody while reporting that it authenticates nobody.
    log.error(errorCodes.tag('STS-AUTHN-0050') +
              'credentials: product mode is in force and no credential store ' +
              'is installed, so every verification is REFUSED. ' +
              'ldap_server.js fills setDirectory() at require time; a ' +
              'process without it cannot verify anybody.');
    log.debug('Leaving verifyPrepare(). No store.');
    return { done: coded('STS-AUTHN-0050', { ok: false, reason: 'no-store',
             detail: 'product mode is in force and no credential store is ' +
                     'installed, so nothing can be verified' }) };
  }

  let stored = '';
  try {
    stored = directory.readPassword(name) || '';
  } catch (e) {
    // A store that threw. Refused rather than passed, for the reason above,
    // and logged because it is a fault rather than a wrong password.
    log.error(errorCodes.tag('STS-AUTHN-0051') +
              'credentials: reading the stored password for ' + name +
              ' threw and the verification is being REFUSED: ' + e.message);
    log.debug('Leaving verifyPrepare(). The store threw.');
    return { done: coded('STS-AUTHN-0051', { ok: false, reason: 'store-error',
             detail: 'the credential store could not be read' }) };
  }

  if (!stored) {
    log.debug('Leaving verifyPrepare(). Nobody by that name holds a password.');
    return { done: coded('STS-AUTHN-0052', { ok: false, reason: 'no-credential',
             detail: 'no ' + PASSWORD_ATTRIBUTE + ' is set for "' + name +
                     '". In product mode a person with no stored credential ' +
                     'cannot sign in — set one from /admin/users, ' +
                     'POST /admin-api/users/set-password, SCIM, or an LDAP ' +
                     'modify' }) };
  }

  if (!crypto.isHashedSecret(stored)) {
    // A value some other client wrote — RFC 4519 permits several forms and
    // plaintext is one of them. REFUSED rather than compared: comparing would
    // mean this service accepting a credential form it does not control, and
    // silently accepting a plaintext password is how a store ends up full of
    // them.
    log.warn('credentials: ' + name + ' holds a ' + PASSWORD_ATTRIBUTE +
             ' that this service did not write and cannot read. It is being ' +
             'REFUSED rather than compared as plaintext.');
    log.debug('Leaving verifyPrepare(). Unreadable stored form.');
    return { done: coded('STS-AUTHN-0053',
                         { ok: false, reason: 'unreadable-credential',
             detail: 'the stored ' + PASSWORD_ATTRIBUTE + ' is not in the ' +
                     'form this service writes, so it cannot be verified' }) };
  }

  log.debug('Leaving verifyPrepare(). A comparison is needed.');
  return { stored: stored, name: name, via: via };
}

// The answer, once the comparison has been made in whichever process made it.
function verifyFinish(ok, name, via) {
  log.debug('Entering verifyFinish(). ' +
            (ok ? 'It matches.' : 'It does not.'));
  if (!ok) {
    // At INFO rather than WARN: a wrong password is an ordinary event and a
    // log that treats it as a fault is a log nobody reads.
    log.info('credentials: ' + name + ' presented a password that does not ' +
             'match (via ' + via + ').');
  }
  log.debug('Leaving verifyFinish().');
  return ok
    ? { ok: true, reason: 'verified',
        detail: 'the presented password matched the stored ' +
                PASSWORD_ATTRIBUTE }
    : coded('STS-AUTHN-0054', { ok: false, reason: 'wrong-password',
        detail: 'the presented password does not match' });
}

// ---------------------------------------------------------------------------
// A PASSWORD THAT MUST BE CHANGED BEFORE IT IS USED (2026-09-13).
//
// `pwdReset: TRUE` on the person's entry — draft-behera-ldap-password-policy's
// name for exactly this — says the password in force was not chosen by the
// person, and the bootstrap administrator is created with it: in product mode
// its first password is the generated one printed in the log.
//
// **THE SIGN-IN SCREEN IS THE ONE DOOR THAT CAN ASK FOR A NEW ONE**, so it
// passes `allowPasswordReset: true`, checks `passwordResetRequired()` itself
// and draws the change step (`authn/authn.js`). Every other door that takes a
// password — an LDAP bind, the OAuth password grant, a WS-Trust
// UsernameToken, SCIM and EST Basic — has nowhere to put that question, so in
// product mode a VERIFIED password flagged this way is refused there, and the
// log says why. Otherwise the log's password would go on working at those
// doors forever without ever being changed.
//
// **DEVELOPMENT MODE CHECKS NO PASSWORD AT THOSE DOORS**, so there is nothing
// there to refuse; the sign-in screen still forces the change in both modes.
// ---------------------------------------------------------------------------
function passwordResetRequired(username) {
  log.debug('Entering passwordResetRequired().');
  const name = String(username == null ? '' : username).trim();
  if (!name || !directory || typeof directory.readPasswordReset !== 'function') {
    log.debug('Leaving passwordResetRequired(). Nothing to ask.');
    return false;
  }
  let flagged = false;
  try {
    flagged = !!directory.readPasswordReset(name);
  } catch (e) {
    log.debug('Caught in passwordResetRequired(): ' +
              ((e && e.message) || e));
    flagged = false;
  }
  log.debug('Leaving passwordResetRequired(). ' + flagged);
  return flagged;
}

function setPasswordResetRequired(username, required) {
  log.debug('Entering setPasswordResetRequired(). required=' + !!required);
  const name = String(username == null ? '' : username).trim();
  if (!name || !directory ||
      typeof directory.writePasswordReset !== 'function') {
    log.debug('Leaving setPasswordResetRequired(). No store.');
    return false;
  }
  let written = false;
  try {
    written = !!directory.writePasswordReset(name, !!required);
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0143') + 'credentials: pwdReset for ' +
              name + ' could not be written: ' + e.message);
    written = false;
  }
  log.debug('Leaving setPasswordResetRequired(). written=' + written);
  return written;
}

// The refusal a non-interactive door gets for a verified password that must be
// changed first. Null where the answer stands as it is.
function resetRefusal(answer, name, opts) {
  log.debug('Entering resetRefusal().');
  if (!answer || !answer.ok || answer.reason !== 'verified' ||
      (opts && opts.allowPasswordReset === true) ||
      !passwordResetRequired(name)) {
    log.debug('Leaving resetRefusal(). The answer stands.');
    return null;
  }
  log.info('credentials: ' + name + ' presented the right password, and it ' +
           'must be changed at the sign-in screen before it can be used ' +
           'here (via ' + ((opts && opts.via) || 'unstated') + ').');
  log.debug('Leaving resetRefusal(). Refused.');
  return coded('STS-AUTHN-0142', { ok: false,
    reason: 'password-reset-required',
    detail: 'the password is right and must be changed first: pwdReset is ' +
            'TRUE on this entry, so sign in at the sign-in screen, which ' +
            'asks for a new one' });
}

function verify(username, password, opts) {
  log.debug('Entering verify().');
  const ready = verifyPrepare(username, password, opts);
  if (ready.done) {
    log.debug('Leaving verify(). Decided without a derivation.');
    return ready.done;
  }
  const ok = crypto.verifySecret(password, ready.stored);
  const finished = verifyFinish(ok, ready.name, ready.via);
  const answer = resetRefusal(finished, ready.name, opts) || finished;
  if (answer.ok && answer.reason === 'verified') {
    // The plaintext was just CONFIRMED — see the password observer above.
    notifyPassword(ready.name, password, 'verified');
  }
  log.debug('Leaving verify().');
  return answer;
}

// ---------------------------------------------------------------------------
// THE SAME VERIFICATION WITHOUT HOLDING THE EVENT LOOP, and it is the door
// every protocol surface here should be reaching for.
//
// scrypt at N=2^15 measured 68ms, and this process runs six listener families
// on one thread — so a password check on the sign-in screen is 68ms in which
// the KDC does not answer, the LDAP socket does not answer and every other
// request waits. It is a smaller number than an SLH-DSA signature's 14.6
// seconds and it is paid FAR more often: once per authentication, in five
// protocols. See common/worker.js.
//
// `opts.session` is the pool's routing hint and is passed straight through.
// ---------------------------------------------------------------------------
function verifyAsync(username, password, opts) {
  log.debug('Entering verifyAsync().');
  const ready = verifyPrepare(username, password, opts);
  if (ready.done) {
    log.debug('Leaving verifyAsync(). Decided without a derivation.');
    return Promise.resolve(ready.done);
  }
  log.debug('Leaving verifyAsync(). Handed to the pool.');
  return crypto.verifySecretAsync(password, ready.stored, opts)
    .then(function (ok) {
      const finished = verifyFinish(ok, ready.name, ready.via);
      const answer = resetRefusal(finished, ready.name, opts) || finished;
      if (answer.ok && answer.reason === 'verified') {
        notifyPassword(ready.name, password, 'verified');
      }
      return answer;
    });
}

// ---------------------------------------------------------------------------
// MAKING ONE UP. The one place this service invents a password, which is the
// same rule the header above states about hashing one.
//
// **IT IS DRAWN AGAINST THE PASSWORD POLICY SINCE 2026-09-12**, by
// `common/password_policy.js` over the `generate-password` package. Until then
// it was 32 bytes of `randomBytes` as base64url — 43 characters of letters,
// digits, `-` and `_`, which is a perfectly strong password and one a profile
// requiring an uppercase letter refuses about one time in a few hundred and a
// profile requiring two symbols refuses often. A generator that sometimes makes
// up passwords its own service rejects is the one outcome worse than no
// generator, so it draws until the profile is satisfied and every draw is
// uniform over the passwords that satisfy it.
//
// Not derived from the username, not a word list: this is handed to somebody
// once and then pasted, and a generated credential guessable from anything on
// the screen it was shown on is worse than no generator at all.
//
// Its callers are the same act at different moments — `bootstrap()` below, a
// new user created from the console or `/admin-api` (where it is the DEFAULT
// credential since the same day), and an operator's Generate on somebody's
// row. All SHOW IT ONCE and never again, because what is stored is a scrypt
// hash: this service cannot produce the value a second time, only replace it.
// ---------------------------------------------------------------------------
function generatePassword(username) {
  log.debug("Entering generatePassword().");
  log.debug("Leaving generatePassword().");
  return passwordPolicy.generate(passwordPolicy.profileFor(username));
}

// ---------------------------------------------------------------------------
// THE PASSWORD POLICY (2026-09-12), AND WHERE IT IS ASKED.
//
// **THE RULES LIVE IN `common/password_policy.js`**: a profile under
// `ou=passwordPolicies` with a minimum length, a number of previous passwords
// that may not be reused, a symbol count, an uppercase letter and a digit.
// **THEY ARE ASKED HERE**, for the reason this file exists: `setPassword()` is
// the one door behind the console, `/admin-api`, the portal's password form and
// an activation link, and `preparePassword()` beside it is what the LDAP add
// and modify handlers use for a `userPassword` written over the socket — so
// five ways of setting a password meet one rule, and none of them is `>=` where
// the others are `>`.
//
// **IT REPLACED A LENGTH-ONLY RULE THAT WAS HOURS OLD**, read from
// `security.passwordMinLength`, whose comment quoted NIST SP 800-63B section
// 5.1.1.2 against composition rules. That reading of NIST is right and the
// composition rules here are a deployment's choice rather than this file's
// advice: every one of them can be turned off on /admin/policies.
//
// **ENFORCED ONLY WHERE A PASSWORD IS VERIFIED**, which is
// `mode.verifiesCredentials()`. Development checks no password at any door, so
// refusing one there would be a policy about a credential nothing reads — and
// it would break every fixture that sets `secret`. The HISTORY is recorded in
// both modes, because recording it costs nothing: the previous hash moves, and
// no new hash is computed.
// ---------------------------------------------------------------------------

// What is wrong with this password's SHAPE under the profile in force, as one
// sentence, or '' where nothing is — or where nothing is checked. The contract
// the length-only rule had, kept so that a caller written against it reads the
// same answer. It does not look at the history, which needs a person.
function passwordProblem(password, username) {
  log.debug("Entering passwordProblem().");
  if (!mode.verifiesCredentials()) {
    log.debug("Leaving passwordProblem().");
    return '';
  }
  const profile = passwordPolicy.profileFor(username);
  const problems = passwordPolicy.problemsWith(password, profile);
  if (!problems.length) {
    log.debug("Leaving passwordProblem().");
    return '';
  }
  log.debug("Leaving passwordProblem().");
  return 'That password does not meet this realm\'s password policy, which ' +
         'asks for ' + problems.join(', ') + '. The rules are on ' +
         '/admin/policies (profile "' + profile.name + '").';
}

// The rules as a person reads them, and whether they are being enforced — for
// the forms that ask somebody for a password, so a page says what it will
// refuse BEFORE it refuses it.
function passwordRules(username) {
  log.debug("Entering passwordRules().");
  const profile = passwordPolicy.profileFor(username);
  log.debug("Leaving passwordRules().");
  return { enforced: mode.verifiesCredentials(),
           profile: profile.name,
           rules: passwordPolicy.describe(profile) };
}

// Was this password one of the person's last N? Compared against the CURRENT
// value and the remembered ones, each through the constant-time scrypt
// comparison every other secret here goes through. A stored value that is not
// a scrypt hash — something an `ldapmodify` wrote before the socket learnt to
// hash one — is compared as the string it is, in constant time, because a
// person whose current password is stored in the clear is still reusing it.
function reusedPassword(password, current, historyHashes, depth) {
  log.debug("Entering reusedPassword().");
  const candidates = [current].concat(historyHashes.slice(0, depth))
    .filter(function (one) { return !!one; });
  for (let i = 0; i < candidates.length; i++) {
    const stored = String(candidates[i]);
    const same = stored.indexOf('$scrypt$') === 0
      ? crypto.verifySecret(password, stored)
      : crypto.constantTimeEquals(password, stored);
    if (same) {
      log.debug("Leaving reusedPassword().");
      return true;
    }
  }
  log.debug("Leaving reusedPassword().");
  return false;
}

// ---------------------------------------------------------------------------
// PREPARING ONE: everything setting a password decides, and nothing it writes.
//
// Answers `{ ok: true, hash, history }` — the scrypt hash to store and the
// WHOLE history to leave on the entry — or `{ ok: false, reason, errors }`.
// Split out of `setPassword()` for the LDAP handlers, which must apply a
// password change inside a modify that is atomic across several changes (RFC
// 4511 section 4.6) and so cannot have it written for them half way through;
// and so that the two doors cannot disagree about a single rule.
//
// `opts.current` and `opts.history` let a caller that already holds the entry
// supply both, which is what a modify in flight does. Otherwise they are read
// from the store. `opts.generated` says the password was made up by this
// service a moment ago, which skips the history comparison — twenty random
// characters are not a previous password, and the comparison is up to six
// scrypt derivations on the one thread every socket is answered from.
// ---------------------------------------------------------------------------
function preparePassword(username, password, opts) {
  log.debug("Entering preparePassword().");
  const options = opts || {};
  const name = String(username == null ? '' : username).trim();
  log.debug('Entering preparePassword(). username=' + name);
  if (!password) {
    log.debug('Leaving preparePassword(). No password.');
    return coded('STS-AUTHN-0055', { ok: false, errors: ['Give a password. ' +
                                 'To take one away, remove ' +
                                 'the ' + PASSWORD_ATTRIBUTE + ' attribute ' +
                                 'from the entry.'] });
  }
  const profile = passwordPolicy.profileFor(name);
  const enforced = mode.verifiesCredentials();
  if (enforced) {
    const problems = passwordPolicy.problemsWith(password, profile);
    if (problems.length) {
      const said = passwordProblem(password, name);
      log.info('credentials: a password for ' + name + ' was refused by the ' +
               'password policy: ' + problems.join('; ') + '.');
      log.debug('Leaving preparePassword(). It breaks the policy.');
      return coded('STS-AUTHN-0056', { ok: false, reason: 'password-policy',
                                       problems: problems, errors: [said] });
    }
  }
  const current = options.current !== undefined ? String(options.current || '')
    : (directory ? String(directory.readPassword(name) || '') : '');
  const storedHistory = (options.history !== undefined ? options.history
    : (directory && typeof directory.readPasswordHistory === 'function'
       ? directory.readPasswordHistory(name) : [])).map(String);
  const remembered = storedHistory
    .map(passwordPolicy.hashOfHistoryValue)
    .filter(function (one) { return !!one; });
  if (enforced && profile.history > 0 && !options.generated &&
      reusedPassword(password, current, remembered, profile.history)) {
    // ONE SENTENCE FOR ALL OF THEM, deliberately. Saying WHICH previous
    // password it matched — the current one, or the third back — tells
    // whoever is typing something about a password that is not the one on
    // the screen, and the person it would help already knows.
    log.info('credentials: a password for ' + name + ' was refused: it is ' +
             'the current password or one of the last ' + profile.history +
             ' before it.');
    log.debug('Leaving preparePassword(). Reused.');
    return coded('STS-AUTHN-0057', { ok: false, reason: 'password-history',
             errors: ['That password has been used for this account ' +
                      'recently. This realm\'s password policy refuses the ' +
                      'current password and ' +
                      'the ' + profile.history + ' before it ' +
                      '(profile "' + profile.name + '"). Choose one you have ' +
                      'not used here.'] });
  }
  // THE HISTORY TO LEAVE: the value being replaced goes on the front, the
  // oldest fall off the back. The CURRENT value is only remembered when it is a
  // hash — a clear value an older `ldapmodify` left behind is not written into
  // a second attribute where it would outlive the password it was.
  const next = [];
  if (current && current.indexOf('$scrypt$') === 0) {
    next.push(passwordPolicy.historyValue(current));
  }
  const history = next.concat(storedHistory).slice(0, profile.history);
  log.debug('Leaving preparePassword(). Prepared; ' + history.length +
            ' remembered.');
  return { ok: true, hash: crypto.hashSecret(password), history: history,
           profile: profile.name };
}

// ---------------------------------------------------------------------------
// SETTING ONE. Hashed HERE rather than by the caller, so that no call site ever
// holds the decision about how — which is the same rule that keeps `crypto.js`
// the one place this service signs.
//
// `opts.generated` is passed by a caller that made the password up with
// `generatePassword()`; see `preparePassword()` for what it skips.
// ---------------------------------------------------------------------------
function setPassword(username, password, opts) {
  log.debug("Entering setPassword().");
  const name = String(username == null ? '' : username).trim();
  log.debug('Entering setPassword(). username=' + name);
  if (!name) {
    log.debug('Leaving setPassword(). No username.');
    return coded('STS-AUTHN-0058', { ok: false, errors: ['Name the person ' +
        'whose password to set.'] });
  }
  if (!directory) {
    // Before the policy, not after it: a policy read with no directory answers
    // the built-in defaults, and a refusal naming a rule would send somebody to
    // fix a password that could not have been stored whatever it was.
    if (!password) {
      log.debug('Leaving setPassword(). No password.');
      return coded('STS-AUTHN-0055', { ok: false, errors: ['Give a password. ' +
                                   'To take one away, remove ' +
                                   'the ' + PASSWORD_ATTRIBUTE + ' attribute ' +
                                   'from the entry.'] });
    }
    log.debug('Leaving setPassword(). No store.');
    return coded('STS-AUTHN-0059', { ok: false, errors: ['No credential ' +
                                 'store is installed in this process, so a ' +
                                 'password cannot be set.'] });
  }
  const prepared = preparePassword(name, password, opts);
  if (!prepared.ok) {
    log.debug('Leaving setPassword(). Refused.');
    return prepared;
  }
  let written = false;
  try {
    written = directory.writePassword(name, prepared.hash,
                                      { history: prepared.history });
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0060') +
              'credentials: writing the password for ' + name + ' threw: ' +
              e.message);
    log.debug('Leaving setPassword(). The store threw.');
    return coded('STS-AUTHN-0060', { ok: false, errors: ['The credential ' +
        'store refused the write: ' +
                                 e.message] });
  }
  if (!written) {
    log.debug('Leaving setPassword(). Nobody by that name.');
    return coded('STS-AUTHN-0061', { ok: false, errors: ['There is nobody ' +
        'called "' + name + '" ' +
                                 'in this realm\'s directory. In product ' +
                                 'mode every referenced object must be ' +
                                 'created ahead of time.'] });
  }
  log.info('credentials: a password was set for ' + name + '. It is stored ' +
           'as a scrypt hash and CANNOT BE READ BACK — this service can ' +
           'never show it again, which is why the caller is given it once ' +
           'and only at the moment it is created.');
  // The plaintext was just WRITTEN — see the password observer above. After
  // the write and not before it, so an observer reading the stored hash back
  // reads the one this password produced.
  notifyPassword(name, password, 'set');
  log.debug('Leaving setPassword(). Written.');
  return { ok: true, username: name,
           message: 'The password for ' + name + ' is set. It is stored as a ' +
                    'hash and cannot be shown again.' };
}

// Is there an entry for them at all, credential or not? Asked only by the
// bootstrap, which has to tell "nobody has a password" from "nobody exists".
function hasEntry(username) {
  log.debug("Entering hasEntry().");
  if (!directory || typeof directory.readPassword !== 'function') {
    log.debug("Leaving hasEntry().");
    return false;
  }
  try {
    log.debug("Leaving hasEntry().");
    // `readPassword()` answers '' both for an absent entry and for one with no
    // credential, so it cannot distinguish them — which is right for a
    // verification and useless here. The store's own creator is idempotent
    // (`createUser()` refuses a name already present), so the bootstrap asks
    // for creation and lets that refusal be the answer rather than testing
    // first. This returns false so the attempt is always made.
    return false;
  } catch (e) {
    log.debug("Caught in hasEntry(): " + ((e && e.message) || e));
    log.debug("Leaving hasEntry().");
    return false;
  }
}

// Does this person hold a credential at all? What /admin/users draws beside
// them and what the mode report counts, so that switching to product mode is a
// decision somebody makes knowing how many people it locks out.
function hasPassword(username) {
  log.debug("Entering hasPassword().");
  if (!directory) {
    log.debug("Leaving hasPassword().");
    return false;
  }
  try {
    log.debug("Leaving hasPassword().");
    return !!directory.readPassword(String(username || '').trim());
  } catch (e) {
    // Reported as "no credential" rather than thrown: this is drawn in a table.
    log.debug('hasPassword(): the store threw: ' + e.message);
    log.debug("Leaving hasPassword().");
    return false;
  }
}

// ---------------------------------------------------------------------------
// THE BOOTSTRAP ACCOUNT (2026-09-06). How a fresh product-mode service is
// reachable at all.
//
// **PRODUCT MODE CLOSES EVERY DOOR AT ONCE**, and that is the point of it — but
// it means a service started in product mode against an empty directory has no
// way in: the console needs a credential, `/admin-api` is gated behind the same
// one, and nothing else can set a password. Without this, the only way to
// deploy would be to start in development, provision, and restart — which is a
// documented dance nobody would follow and a mode nobody would use.
//
// So on the FIRST product-mode start where nobody holds a credential, one
// account is given a generated password and it is logged ONCE. It is the
// pattern Keycloak, Grafana and Jenkins all use, for the same reason, and it
// has the same two properties: the secret is in the log (so the log is
// sensitive), and it appears exactly once (so it cannot be recovered later —
// only reset).
//
// **THREE THINGS MAKE IT SAFE ENOUGH TO DO.**
//
//   * IT ONLY RUNS WHEN NOBODY HAS A CREDENTIAL. An existing deployment, or one
//     restored from a persistence store, has accounts already and this does
//     nothing — so it cannot overwrite a password or resurrect a disabled
//     administrator.
//   * THE PASSWORD IS GENERATED — `generatePassword()`, drawn against the
//     password policy since 2026-09-12 (it was 32 bytes of `randomBytes` as
//     base64url before that). Not a fixed default and not derived from
//     anything: a well-known bootstrap password is the single most reliable
//     way into a product, and this service would ship one to every deployment
//     at once.
//   * IT IS ANNOUNCED LOUDLY AND SAYS TO CHANGE IT. A bootstrap credential that
//     is not obviously temporary becomes permanent.
//
// **IT DOES NOT RUN IN DEVELOPMENT MODE.** There is nothing to bootstrap: every
// password is accepted, so an account with a generated one would be an account
// with a password that changes nothing and a log line that alarms people.
function bootstrap(opts) {
  log.debug('Entering bootstrap().');
  const options = opts || {};
  const username = String(options.username || 'admin').trim();
  if (!mode.isProduct()) {
    log.debug('Leaving bootstrap(). Development mode needs no bootstrap.');
    return { ran: false, why: 'development mode accepts every password, so ' +
                              'there is nothing to bootstrap' };
  }
  if (!directory) {
    log.debug('Leaving bootstrap(). No store.');
    return { ran: false, why: 'no credential store is installed' };
  }
  // ANYBODY AT ALL. `anyCredential` is asked of the store rather than of this
  // one name, because the question is "can somebody get in" and not "does the
  // admin account exist" — a deployment whose administrator is called something
  // else must not have a second one created beside them.
  let anybody = false;
  try {
    anybody = typeof directory.anyCredential === 'function'
      ? !!directory.anyCredential() : !!directory.readPassword(username);
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0062') +
              'credentials: the store could not be asked whether anybody ' +
              'holds a credential, so no bootstrap was attempted: ' +
              e.message);
    log.debug('Leaving bootstrap(). The store threw.');
    return { ran: false, why: 'the credential store could not be read' };
  }
  if (anybody) {
    log.debug('Leaving bootstrap(). Somebody already holds a credential.');
    return { ran: false, why: 'somebody already holds a credential, so this ' +
                              'service is already reachable' };
  }
  // CREATE THE ACCOUNT IF IT IS NOT THERE. This is the one place anything is
  // created in product mode, and the exception is argued at the slot in
  // ldap_server.js: a fresh deployment has an empty directory, so requiring the
  // account to pre-exist would mean the bootstrap could never run in the
  // situation it exists for.
  if (!hasEntry(username) && typeof directory.createPerson === 'function') {
    try {
      directory.createPerson(username);
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0063') +
                'credentials: the bootstrap account "' + username + '" could ' +
                'not be created: ' + e.message);
    }
  }
  const password = generatePassword(username);
  const written = setPassword(username, password, { generated: true });
  if (!written.ok) {
    log.error(errorCodes.tag('STS-AUTHN-0064') +
              'credentials: PRODUCT MODE AND NOBODY CAN SIGN IN. A bootstrap ' +
              'account could not be created: ' +
              (written.errors || []).join(' ') + ' There is no way into this ' +
              'service until a credential is set — start in development ' +
              'mode, provision one, and restart.');
    log.debug('Leaving bootstrap(). The write failed.');
    return { ran: false, why: (written.errors || []).join(' ') };
  }
  log.warn('=======================================================\n' +
           'PRODUCT MODE BOOTSTRAP — THIS IS SHOWN ONCE AND NEVER AGAIN.\n' +
           '\n' +
           '  username: ' + username + '\n' +
           '  password: ' + password + '\n\nNobody in this realm\'s ' +
           'directory held a credential, so this one was generated so that ' +
           'the service is reachable. It is stored as a scrypt hash and ' +
           'CANNOT be recovered — only reset.\n\nCHANGE IT. Sign in at ' +
           '/admin, or POST ' +
           '/admin-api/users/set-password.\n=======================================================');
  log.debug('Leaving bootstrap(). An account was created.');
  return { ran: true, username: username };
}

// ---------------------------------------------------------------------------
// ONE BOOTSTRAP FOR THE CLUSTER (2026-09-14, #46 section 8).
//
// **N NODES COLD-STARTED AGAINST AN EMPTY STORE PRINTED N PASSWORDS.** Each
// restored the same empty directory, each asked "does anybody hold a
// credential", each got no, and each generated, logged and wrote its own. The
// entry is last writer wins, so exactly one of the N passwords in N logs
// worked and nothing said which. Worse, the account ITSELF was made N times:
// `seedBootstrapAdministrator()` creates the entry on every node, and a node
// whose create committed after another node's password write replaced the
// entry with one that has no password at all — N passwords and none working.
//
// **SO THE WHOLE STEP — SEED AND PASSWORD — IS ONE CLAIM PER REALM.** `work`
// is the caller's (`server.js` seeds the administrator and then calls
// `bootstrap()`; this file cannot require `admin_rbac.js`, which requires it),
// and it runs only on the node that wins the claim, after that node has caught
// up with the store — so a node whose claim was won because an earlier
// winner's claim EXPIRED still sees the credential that winner wrote and does
// nothing. The winner waits for its own writes to commit and then gives the
// claim back, so a node starting afterwards asks the question again against a
// directory that answers it.
//
// **WHAT A NODE THAT LOSES SEES**: one info line naming the node holding the
// claim and when it took it, and NO password — it seeds nothing and writes
// nothing, and the password is in the winner's log alone. If the winner died
// before it wrote, the claim expires (`BOOTSTRAP_CLAIM_TTL_MS`) and the next
// node to start runs the bootstrap; a service nobody can sign in to for that
// long is the price of never printing a password that does not work.
//
// **A STORE THAT CANNOT BE ASKED RUNS NOTHING** (`STS-AUTHN-0185`), for the
// same reason: a node that cannot prove it is the only one generating must not
// print a credential that another node may be overwriting. On memory or ldif
// the claim is this process's, always won, and this is exactly the old step.
// ---------------------------------------------------------------------------
const BOOTSTRAP_CLAIM_TTL_MS = 5 * 60 * 1000;

function bootstrapOnce(realmId, work) {
  log.debug("Entering bootstrapOnce(). realm=" + realmId);
  const persistence = sharedStore();
  log.debug("Leaving bootstrapOnce(). Claiming.");
  return claims.claim({ scope: 'ops.bootstrap', value: 'administrator',
                        ttlMs: BOOTSTRAP_CLAIM_TTL_MS,
                        realm: String(realmId || '') })
    .then(function (claimed) {
      if (!claimed.ok && claimed.reason === 'used') {
        const holder = claimed.existing || {};
        // `existing` is null when the holder gave the claim back between this
        // node's INSERT and its look at the row — it has already finished.
        log.info('credentials: another node (' + (holder.origin
                   ? holder.origin + ', since ' +
                     new Date(Number(holder.claimedAt)).toISOString()
                   : 'which has just finished') + ') holds the ' +
                 'product-mode bootstrap for the "' +
                 (realmId || 'default') + '" realm. ' +
                 'This node seeds nothing and generates no password; if one ' +
                 'is generated it is in THAT node\'s log.');
        return { ran: false, lost: true, holder: holder };
      }
      if (!claimed.ok) {
        log.error(errorCodes.tag('STS-AUTHN-0185') + 'credentials: the ' +
                  'bootstrap for the "' + (realmId || 'default') + '" realm ' +
                  'was NOT attempted: this node could not ask the store ' +
                  'whether another node is running it (' +
                  (claimed.why || claimed.reason) + '). Restart once the ' +
                  'store answers.');
        return { ran: false, why: 'the store could not be asked' };
      }
      return Promise.resolve().then(function () {
        return persistence.clusterStore() &&
          typeof persistence.syncNow === 'function'
          ? persistence.syncNow() : null;
      }).catch(function (e) {
        log.warn('credentials: catching up before the bootstrap failed (' +
                 ((e && e.message) || e) + '); it runs against what this ' +
                 'node restored.');
        return null;
      }).then(function () {
        return work();
      }).then(function (result) {
        // THE CLAIM IS GIVEN BACK ONLY ONCE THE WRITES HAVE COMMITTED, so the
        // next node to take it reads a directory that already holds them.
        return Promise.resolve().then(function () {
          return persistence.clusterStore()
            ? Promise.all([persistence.flush(), persistence.flushMinted()])
            : null;
        }).catch(function (e) {
          log.debug("Caught in bootstrapOnce(): " + ((e && e.message) || e));
          return null;
        }).then(function () {
          return claims.release(claimed.handle);
        }).then(function () {
          return result;
        });
      });
    });
}

// ---------------------------------------------------------------------------
// THE KEYS SOMEBODY HOLDS, AND WHAT THEY ARE FOR.
// ---------------------------------------------------------------------------
function keysOf(username) {
  log.debug('Entering keysOf(). username=' + username);
  if (!directory || typeof directory.readWebauthn !== 'function') {
    log.debug('Leaving keysOf(). No store.');
    return [];
  }
  let raw = [];
  try {
    raw = directory.readWebauthn(String(username || '').trim()) || [];
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0065') +
              'credentials: reading the security keys for ' + username +
              ' threw: ' + e.message);
    log.debug("Leaving keysOf().");
    return [];
  }
  const out = [];
  raw.forEach(function (value) {
    try {
      const parsed = JSON.parse(value);
      if (parsed && parsed.credentialId && parsed.publicKeyJwk) {
        out.push(parsed);
      }
    } catch (e) {
      // A value some other client wrote. Skipped with a warning rather than
      // throwing: one malformed key must not stop the others being usable.
      log.warn('credentials: a ' + WEBAUTHN_ATTRIBUTE + ' value on ' +
               username + ' is not JSON this service wrote and is being ' +
               'ignored: ' + e.message);
    }
  });
  log.debug('Leaving keysOf(). ' + out.length + ' key(s).');
  return out;
}

// Add one. The caller has already verified the registration ceremony — this
// records what it produced.
function addKey(username, credential, role) {
  log.debug("Entering addKey().");
  const name = String(username || '').trim();
  log.debug('Entering addKey(). username=' + name + ', role=' + role);
  if (!directory || typeof directory.writeWebauthn !== 'function') {
    log.debug("Leaving addKey().");
    return coded('STS-AUTHN-0059', { ok: false, errors: ['No credential ' +
                                 'store is installed, so a security key ' +
                                 'cannot be recorded.'] });
  }
  if (ROLES.indexOf(String(role)) < 0) {
    log.debug("Leaving addKey().");
    return coded('STS-AUTHN-0066', { ok: false, errors: ['A security key is ' +
                                 'either "primary" (it signs somebody in on ' +
                                 'its own) or "mfa" (it is a second factor ' +
                                 'beside a password). ' +
                                 '"' + role + '" is neither.'] });
  }
  // ---------------------------------------------------------------------
  // THE `webauthn.*` POLICY, CHECKED AT THE ONE PLACE A KEY IS WRITTEN
  // (2026-09-10).
  //
  // HERE AND NOT AT EACH DOOR, which is the same argument `setPassword()`
  // makes about hashing: there are several ways to enrol a key — the sign-in
  // screen's ceremony, the portal's setup form, the portal's key page and an
  // activation link — and a check at each is one more chance for one of them
  // to be added without it. This is the
  // only function that puts a key on an entry, so a policy enforced here is a
  // policy enforced everywhere.
  //
  // **IT REFUSES AN ENROLMENT AND NEVER AN AUTHENTICATION.** A key already on
  // the entry goes on working when the role that produced it is switched off,
  // for `webauthn.enabled`'s reason — an operator moving a knob must not lock
  // somebody out of their own account, which for a `primary` key would be the
  // whole account.
  const allowed = webauthnPolicy.roleAllowed(role);
  if (!allowed.ok) {
    log.info('credentials: a "' + role +
             '" security key was NOT enrolled for ' +
             name + '. ' + allowed.why);
    log.debug("Leaving addKey().");
    return coded(errorCodes.codeOf(allowed) || 'STS-AUTHN-0044',
                 { ok: false, errors: [allowed.why] });
  }
  // HOW MANY. Several keys is the ordinary case and the specification expects
  // it — an assertion NAMES the credential that produced it, so there is none
  // of the ambiguity two shared secrets would have. The cap is here so that an
  // enrolment loop cannot grow an unbounded attribute on a directory entry,
  // which is a page that stops rendering and a flush that gets slower rather
  // than anything security-shaped.
  const held = keysOf(name);
  // ONE ROW PER CREDENTIAL ID, WHICHEVER DOOR ASKS (2026-09-14). The two
  // ceremony doors checked `excludeCredentials` against the list as it was
  // when the ceremony BEGAN, so the same attestation posted twice — or a key
  // written by another request since — became a second row for one device.
  // Asked here, the one writer, against the entry as it is now;
  // `addKeyClaimed()` below closes the concurrent case between nodes.
  const wantedId = String((credential || {}).credentialId || '');
  if (wantedId && held.some(function (one) {
    return String(one.credentialId) === wantedId;
  })) {
    log.info('credentials: ' + name + ' presented an authenticator that is ' +
             'already enrolled. Refused as a duplicate.');
    log.debug("Leaving addKey(). Already enrolled.");
    return coded('STS-AUTHN-0095', { ok: false, reason: 'duplicate',
             errors: ['That authenticator is already enrolled. Use a ' +
                      'DIFFERENT one — a backup on the same device is lost ' +
                      'with the original.'] });
  }
  const cap = webauthnPolicy.settings().maxKeysPerPerson;
  if (held.length >= cap) {
    log.info('credentials: ' + name + ' already holds ' + held.length +
             ' security key(s) and webauthn.maxKeysPerPerson is ' + cap +
             ', so another was not enrolled.');
    log.debug("Leaving addKey().");
    return coded('STS-AUTHN-0067', { ok: false,
             errors: [name + ' already holds ' + held.length + ' security ' +
                      'key(s), which is the most this realm allows ' +
                      '(webauthn.maxKeysPerPerson). Remove one first.'] });
  }
  const record = {
    credentialId: String(credential.credentialId),
    publicKeyJwk: credential.publicKeyJwk,
    signCount: Number(credential.signCount || 0),
    role: String(role),
    enrolledAt: Date.now(),
    // A label so a person with three keys can tell them apart on the portal.
    // Theirs to set; this is only the default.
    label: String(credential.label || 'security key')
  };
  let written = false;
  try {
    written = directory.writeWebauthn(name, JSON.stringify(record));
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0068') +
              'credentials: writing a security key for ' + name + ' threw: ' +
              e.message);
    log.debug("Leaving addKey().");
    return coded('STS-AUTHN-0068', { ok: false, errors: ['The credential ' +
        'store refused the write: ' +
                                 e.message] });
  }
  if (!written) {
    log.debug("Leaving addKey().");
    return coded('STS-AUTHN-0061', { ok: false, errors: ['There is nobody ' +
        'called "' + name + '" ' +
                                 'in this realm\'s directory.'] });
  }
  log.info('credentials: a security key was enrolled for ' + name +
           ' as a ' + role + ' credential.');
  // ---------------------------------------------------------------------
  // THE RECOVERY CODES, AND **ONLY FOR AN `mfa` KEY** (2026-09-10).
  //
  // The other call site is `confirmTotpEnrolment()`, and the condition here
  // is the whole difference between them: a `primary` key is a way IN rather
  // than a second factor, and issuing recovery codes for one would hand
  // somebody a list of strings that no screen in this service ever asks for.
  // The recovery screen stands in for a SECOND factor; an account whose only
  // credential is a passwordless key has no second-factor step to stand in
  // for, and its lost-key story is an operator and an activation link.
  //
  // It cannot fail the enrolment — see the TOTP call site — and it does
  // nothing when a set already exists, so enrolling a fourth key leaves the
  // list issued with the first one working.
  // **NO SET IS ISSUED HERE ANY MORE (2026-09-11)**, and what replaces it is
  // an ADVICE flag rather than silence. The header on the recovery-codes
  // section carries the argument and what it costs; the short version is that
  // a set is hashed now, and a hash can only be made while the code is in the
  // clear — so issuing one here would store a credential the person never
  // saw. `recoveryAdvised` is what `/portal/mfa` draws its standing prompt
  // from.
  const advised = role === 'mfa' && backupCodes.offered() &&
                  !backupCodesOf(name);
  log.debug("Leaving addKey().");
  return { ok: true, username: name, role: role,
           credentialId: record.credentialId,
           recoveryAdvised: advised,
           recoveryNote: advised
             ? 'This key is a SECOND factor, and you hold no recovery codes. ' +
               'Generate a set from your account page before you need it — ' +
               'this service will not issue one for you, and a set is shown ' +
               'once.'
             : '' };
}

// ---------------------------------------------------------------------------
// AN ASSERTION, SPENT ACROSS THE CLUSTER (2026-09-14, #46 section 2).
//
// `noteKeyUsed()` below reads the entry's keys, sets one counter and writes
// the whole attribute back. On one node that is the replay defence WebAuthn
// asks for. Across nodes it was two defects:
//
//   * **THE COUNTER COULD GO BACKWARDS.** Node A accepts counter 11 and node B
//     counter 10 at the same moment; whichever write lands last is the entry,
//     so it can say 10 — and a CLONED authenticator presenting 11 is then
//     accepted everywhere, which is exactly the thing WebAuthn Level 3 section
//     6.1.1 has the counter for.
//   * **ONE ASSERTION SIGNED IN TWICE.** Two nodes both checking against 10
//     both accept the same 11.
//
// So an assertion that verified is SPENT here before the sign-in stands, in
// two steps and in this order:
//
//   1. **THE CHALLENGE IS CLAIMED.** A ceremony's challenge is single-use by
//      construction and this is the only defence at all for an authenticator
//      whose counter is always 0 — which is every synced passkey. Two posts of
//      one assertion to two nodes: one wins.
//   2. **THE COUNTER IS ADVANCED** through `cluster/cluster_counters.js`,
//      which refuses a value not above the highest ANY node has recorded for
//      that credential. A counter of 0 against a stored 0 is accepted (no
//      counter, section 6.1.1); 0 against a stored 7 is a counter that went
//      backwards and is refused.
//
// A refused counter GIVES THE CHALLENGE BACK, so the person can try again
// inside the same step rather than being sent to the start for somebody
// else's clone. The entry is still written through `noteKeyUsed()` afterwards,
// for the "last used" a page draws — the counter row, not the entry, is what
// the next assertion is decided by across nodes; the entry stays the first,
// free check `webauthn.js` makes.
// ---------------------------------------------------------------------------
const WEBAUTHN_CHALLENGE_SCOPE = 'authn.webauthn-challenge';
const WEBAUTHN_COUNTER_SCOPE = 'authn.webauthn-sign-count';
// ---------------------------------------------------------------------------
// A REGISTRATION CLAIMS ITS CREDENTIAL ID (2026-09-14, #46 follow-up).
//
// `addKey()` refuses a credential id already on the entry, and on several
// nodes "already on the entry" is a question with a window: the same
// attestation posted to two nodes at once passes both checks, both nodes write
// a row, and the directory merge — which merges the key attribute BY VALUE,
// and two rows for one key differ in `enrolledAt` — keeps both. So the id is
// claimed in the store before the write, and a second registration of it is
// refused (`STS-AUTHN-0193`; `STS-AUTHN-0194` when the store cannot be asked —
// fail closed, `cluster_claims.js`'s rule).
//
// **HELD FOR ITS LIFETIME ON SUCCESS, GIVEN BACK ON A REFUSED WRITE.** A
// credential id is minted by the authenticator per registration, so nothing
// legitimate registers the same one again: the only second registration of an
// id is a replay of one attestation, which the claim should refuse for as long
// as that attestation's challenge could still be answered — and after that the
// entry's own check above does. On memory or ldif the claim is this process's
// map, as atomic as the check it backs.
// ---------------------------------------------------------------------------
const WEBAUTHN_REGISTRATION_SCOPE = 'authn.webauthn-registration';
const WEBAUTHN_REGISTRATION_CLAIM_MS = 30 * 60 * 1000;

function addKeyClaimed(username, credential, role) {
  log.debug("Entering addKeyClaimed().");
  const credentialId = String((credential || {}).credentialId || '');
  if (!credentialId) {
    log.debug("Leaving addKeyClaimed(). No id to claim; addKey() decides.");
    return Promise.resolve(addKey(username, credential, role));
  }
  const name = String(username || '').trim();
  log.debug("Leaving addKeyClaimed(). Claiming the credential id.");
  return claims.claim({
    scope: WEBAUTHN_REGISTRATION_SCOPE, value: credentialId,
    ttlMs: WEBAUTHN_REGISTRATION_CLAIM_MS, realm: realms.currentId()
  }).then(function (claimed) {
    if (!claimed.ok && claimed.reason === 'used') {
      log.warn('credentials: a security key registration for ' + name +
               ' was REFUSED: its credential id is being registered, or ' +
               'was just registered, by another request or node.');
      return coded('STS-AUTHN-0193', { ok: false, reason: 'duplicate',
        errors: ['That authenticator has just been registered by another ' +
                 'request. It is enrolled once; look for it on your key ' +
                 'list.'] });
    }
    if (!claimed.ok) {
      log.error(errorCodes.tag('STS-AUTHN-0194') + 'credentials: whether ' +
                'the credential id of a security key for ' + name + ' is ' +
                'already registered elsewhere could not be asked (' +
                (claimed.why || claimed.reason) + '), so it was not ' +
                'enrolled.');
      return coded('STS-AUTHN-0194', { ok: false, reason: 'store',
        errors: ['The security key could not be registered just now. Try ' +
                 'again.'] });
    }
    const stored = addKey(username, credential, role);
    if (!stored.ok) {
      claims.release(claimed.handle);
    }
    return stored;
  });
}

function spendAssertion(spec) {
  log.debug("Entering spendAssertion().");
  const s = spec || {};
  const name = String(s.username || '').trim();
  const credentialId = String(s.credentialId || '');
  const realmId = realms.currentId();
  const signCount = Math.max(0, Math.floor(Number(s.signCount) || 0));
  if (!credentialId || !s.challenge) {
    log.debug("Leaving spendAssertion(). Nothing to spend.");
    return Promise.resolve(coded('STS-AUTHN-0182', { ok: false,
      reason: 'store', detail: 'The assertion names no credential or ' +
                               'challenge, so it cannot be spent.' }));
  }
  log.debug("Leaving spendAssertion(). Claiming the challenge.");
  return claims.claim({
    scope: WEBAUTHN_CHALLENGE_SCOPE, value: String(s.challenge),
    ttlMs: Math.max(60000, Number(s.ttlMs) || 0), realm: realmId
  }).then(function (claimed) {
    if (!claimed.ok) {
      if (claimed.reason === 'used') {
        log.warn('credentials: a security-key assertion for ' + name +
                 ' verified and was REFUSED: its challenge had already been ' +
                 'answered, by another node or a request racing this one.');
        return coded('STS-AUTHN-0181', { ok: false, reason: 'replay',
          detail: 'this sign-in step has already been answered' });
      }
      log.error(errorCodes.tag('STS-AUTHN-0182') + 'credentials: a ' +
                'security-key assertion for ' + name + ' could not be ' +
                'proved unspent (' + (claimed.why || claimed.reason) +
                '), so it was refused.');
      return coded('STS-AUTHN-0182', { ok: false, reason: 'store',
        detail: 'the assertion could not be checked just now' });
    }
    return counters.advance({
      scope: WEBAUTHN_COUNTER_SCOPE, key: credentialId, value: signCount,
      realm: realmId
    }).then(function (answer) {
      if (!answer.ok) {
        claims.release(claimed.handle);
        if (answer.reason === 'behind') {
          log.warn('credentials: a security-key assertion for ' + name +
                   ' presented signature counter ' + signCount + ' and the ' +
                   'highest any node has recorded for that key is ' +
                   answer.highest + '. It was REFUSED — a counter that does ' +
                   'not go up is a replay or a CLONED authenticator ' +
                   '(WebAuthn Level 3 section 6.1.1).');
          return coded('STS-AUTHN-0035', { ok: false, reason: 'counter',
            highest: answer.highest,
            detail: 'the signature counter did not increase (now ' +
                    signCount + ', highest seen ' + answer.highest +
                    ') — the key may have been cloned' });
        }
        log.error(errorCodes.tag('STS-AUTHN-0182') + 'credentials: the ' +
                  'signature counter for ' + name + ' could not be advanced ' +
                  '(' + (answer.why || answer.reason) + '), so the ' +
                  'assertion was refused.');
        return coded('STS-AUTHN-0182', { ok: false, reason: 'store',
          detail: 'the signature counter could not be checked just now' });
      }
      const recorded = noteKeyUsed(name, credentialId, signCount);
      return { ok: true, recorded: !!recorded, advanced: answer.advanced };
    });
  });
}

// Update the signature counter after a successful assertion. WebAuthn's replay
// defence: an authenticator's counter only ever goes up, so a counter that went
// backwards is a cloned key. `webauthn.js` performs the CHECK; this records the
// new value so the next assertion has something to check against.
function noteKeyUsed(username, credentialId, signCount) {
  log.debug('Entering noteKeyUsed().');
  if (!directory || typeof directory.replaceWebauthn !== 'function') {
    log.debug("Leaving noteKeyUsed().");
    return false;
  }
  const keys = keysOf(username);
  const found = keys.filter(function (one) {
    return one.credentialId === String(credentialId);
  })[0];
  if (!found) {
    log.debug("Leaving noteKeyUsed().");
    return false;
  }
  found.signCount = Number(signCount || 0);
  found.lastUsedAt = Date.now();
  try {
    log.debug("Leaving noteKeyUsed().");
    return directory.replaceWebauthn(String(username || '').trim(),
      keys.map(function (one) { return JSON.stringify(one); }));
  } catch (e) {
    // The assertion already succeeded; failing to record the counter must not
    // undo it. Logged, because a counter that stops advancing is a replay
    // defence that stops defending.
    log.error(errorCodes.tag('STS-AUTHN-0038') +
              'credentials: the signature counter for ' + username +
              ' could not be recorded: ' + e.message);
    log.debug("Leaving noteKeyUsed().");
    return false;
  }
}

function removeKey(username, credentialId) {
  log.debug('Entering removeKey().');
  if (!directory || typeof directory.replaceWebauthn !== 'function') {
    log.debug("Leaving removeKey().");
    return coded('STS-AUTHN-0059', { ok: false, errors: ['No credential ' +
        'store is installed.'] });
  }
  const name = String(username || '').trim();
  const keys = keysOf(name);
  const kept = keys.filter(function (one) {
    return one.credentialId !== String(credentialId);
  });
  if (kept.length === keys.length) {
    log.debug("Leaving removeKey().");
    return coded('STS-AUTHN-0069', { ok: false, errors: ['No security key of ' +
        'that id is enrolled for ' +
                                 name + '.'] });
  }
  // ---------------------------------------------------------------------
  // **REFUSE TO REMOVE THE LAST WAY IN — AND AN `mfa` KEY IS NOT ONE.**
  //
  // A person whose only credential is a PRIMARY key would be locked out by
  // their own click, and an identity provider that lets somebody do that has a
  // support queue rather than a security control. That much is unchanged.
  //
  // **THE ROLE OF THE KEY BEING REMOVED WAS NOT LOOKED AT, AND THAT WAS A REAL
  // REFUSAL IN THE ONE CASE THE BUTTON EXISTS FOR (2026-09-10).** The guard
  // asked only *will they have a way in afterwards*, which is the right
  // question — and then answered it about a key that was never a way in.
  // Removing a SECOND FACTOR cannot reduce the number of ways in, because it
  // was not one: `mechanismsFor().usable` counts a password and `primary` keys
  // and nothing else, which is the same table this function is reasoning
  // about. So somebody with an `mfa` key and no password — the ordinary state
  // in development mode, where no password is ever CHECKED and most people
  // therefore have none SET — could not have that key cleared, and the
  // refusal said *that is the only way they can sign in* about a credential
  // that could not sign them in at all.
  //
  // It surfaced through the door it costs most at: `POST
  // /admin-api/users/clear-key`, which `admin-ui/CLAUDE.md` calls the way back
  // for somebody who lost their key.
  // `tests/vendored/sts_webauthn_second_factor.js` found it in its first run,
  // in the section after the one that made keys reachable at all.
  //
  // **THE PERSON MAY STILL BE UNABLE TO SIGN IN AFTERWARDS**, and that is not
  // this function's to fix: an account holding only a second factor is one
  // nobody can sign in to before the removal and after it. `usable: false` is
  // what reports that, and an activation link is what ends it.
  // ---------------------------------------------------------------------
  const removed = keys.filter(function (one) {
    return one.credentialId === String(credentialId);
  })[0];
  const stillHasPrimary =
      kept.some(function (one) { return one.role === 'primary'; });
  if (removed && removed.role === 'primary' &&
      !hasPassword(name) && !stillHasPrimary) {
    log.debug("Leaving removeKey().");
    return coded('STS-AUTHN-0070',
                 { ok: false, errors: ['That is the only way ' + name + ' ' +
                                 'can sign in — there is no password and no ' +
                                 'other primary security key. Set a password ' +
                                 'first, or enrol another key.'] });
  }
  try {
    directory.replaceWebauthn(name, kept.map(function (one) {
      return JSON.stringify(one);
    }));
  } catch (e) {
    log.debug("Leaving removeKey().");
    return coded('STS-AUTHN-0068', { ok: false, errors: ['The credential ' +
        'store refused the write: ' +
                                 e.message] });
  }
  log.info('credentials: a security key was removed for ' + name + '.');
  log.debug("Leaving removeKey().");
  return { ok: true, remaining: kept.length };
}

// ===========================================================================
// THE AUTHENTICATOR APP (RFC 6238), ON THE SAME ENTRY AS EVERYTHING ELSE
// (2026-09-10).
//
// The second second factor. `common/totp.js` owns the arithmetic and the
// policy; this section owns WHERE THE SECRET LIVES and the two-step enrolment
// that gets it there, because those are credential-store questions and this
// file is the credential store.
//
// ---------------------------------------------------------------------------
// SINGLE-VALUED, WHERE THE SECURITY KEY IS MULTI-VALUED, AND THE REASON IS IN
// THE PROTOCOL RATHER THAN IN A POLICY.
//
// A WebAuthn assertion NAMES THE CREDENTIAL that produced it, so several keys
// are one lookup. A TOTP code is six digits and names nothing. Two secrets
// would mean trying both — which doubles what a guess can hit, makes RFC 6238
// section 5.2's "accept a code once" ambiguous about which counter was spent,
// and leaves a person who has lost one of two apps with no way to say which.
//
// So enrolling replaces, and every surface that draws the enrolment says so
// before it draws the QR code. Somebody who scans a second one and leaves the
// first app configured has an authenticator that silently stopped working.
//
// ---------------------------------------------------------------------------
// THE SECRET CANNOT BE HASHED, WHICH MAKES IT THE ONLY CREDENTIAL HERE THAT IS
// STORED IN A FORM THIS SERVICE CAN READ BACK.
//
// A password is verified by hashing what was presented and comparing — so
// `userPassword` holds scrypt output and a directory dump is no use to
// anybody. **Verifying a TOTP code means COMPUTING it**, so the shared secret
// has to be recoverable. That is not a weakness in RFC 6238; it is what
// "shared secret" means, and it is exactly why this mechanism is a SECOND
// factor here and can never be made a first one.
//
// It changes what a directory dump is worth, though, and
// `/admin/ldap/directory` prints every attribute of every entry by design. So:
//
//   * **IN PRODUCT MODE THE SECRET IS SEALED**, with `keystore.seal()` — the
//     same AES-256-GCM under the same operator-supplied key-encryption key
//     that protects the signing keys and every minted row. A dump then prints
//     ciphertext, and an operator holding Admin Read cannot walk away able to
//     generate somebody's codes.
//   * **IN DEVELOPMENT MODE IT IS STORED AS THE BASE32 IT WAS SHOWN AS**, and
//     that is deliberate rather than an omission. Development mode has an
//     EPHEMERAL key-encryption key where it has one at all — generated per run
//     and never written down — so sealing here would mean an authenticator
//     that stops working at the next restart, silently, which is precisely
//     the defect that moved the WebAuthn credentials out of an in-memory map
//     and onto the entry. `keystore.persists()` is therefore the test, and not
//     `keystore.sealed()`: the question is whether the KEY outlives the
//     process, not whether there is one.
//
// **A RECORD SAYS WHICH IT IS** (`sealed`), so a store carried from one mode to
// another is read correctly rather than being decoded as base32 and producing
// codes that are wrong. A sealed secret that will not open is reported as an
// unusable enrolment and never as a wrong code — see `totpOf()`.
//
// ---------------------------------------------------------------------------
// ENROLMENT IS TWO STEPS AND THE FIRST ONE WRITES NOTHING.
//
// `beginTotpEnrolment()` mints a secret and holds it in a PENDING record, not
// on the entry (a sealed persisted row since 2026-09-14 — see `pendingTotp`);
// `confirmTotpEnrolment()` takes a code, checks it against that secret, and
// only then writes the attribute. **An unconfirmed secret on somebody's entry
// would be a second factor they cannot produce** — a person who opens the
// page, never scans the code and comes back tomorrow would be locked out of
// their own account by a form they abandoned. The pending record expires
// (`totp.enrolmentTtlMinutes`) and is per realm, like every other pending
// record in this service.
// ===========================================================================

// RFC 4519 has no attribute for this and neither does any other schema worth
// borrowing, so it is `sts`-prefixed like the security key beside it. The value
// is one JSON object; `ldap/ldap_server.js` writes it single-valued.
const TOTP_ATTRIBUTE = 'stsTotpCredential';

// The secret that has been SHOWN and not yet proved. Per realm, for the reason
// every other pending record here is: a realm is a logical copy of this
// service, and an enrolment begun in one is not an enrolment in another.
//
// ~~IT CARRIES NO `persist:` NAME~~ — **REVERSED 2026-09-14 (#46), BECAUSE
// THE PREMISE WAS AFFINITY AND A CLUSTER HAS NONE.** Until that day the
// argument was that the row is an UNCONFIRMED SHARED SECRET for an enrolment
// that is usually abandoned, and that nothing lost by keeping it in one
// process's memory, because "the only surfaces that read it hold worker
// affinity". Across NODES behind a balancer they do not: `POST /portal/mfa`
// answered by node A redirects to `GET /portal/mfa`, the balancer hands that
// to node B, and B had no pending secret to draw — no QR code, no secret, no
// way to confirm. The suite's `cluster` mode measured it in five jobs
// (`sts_portal_totp`, `sts_portal_backup_codes`,
// `sts_portal_directory_attributes`, `sts_step_up`, and the security-key
// page's twin below in `sts_portal_backup_keys`). A person pressing *Set up*
// again does not converge either: every retry has the same odds of landing
// on the node that did not make it.
//
// **WHAT THE ORIGINAL WORRY WAS ABOUT IS STILL ANSWERED, BY THE ROW'S SEAL AND
// ITS LIFETIME RATHER THAN BY ITS ABSENCE.** A persisted row is written only
// where minted state is (`persistence_minted.js`'s `enabled()`: product mode,
// a dispatched container, a cluster node — never a single development
// process, never memory or ldif), every body is `keystore.seal()`ed under the
// key-encryption key before it reaches the table, and the row goes the moment
// the enrolment is confirmed, abandoned or found expired by any process's
// sweep (`sweepPendingTotp()`), each a journalled delete. Its value is never
// edited in place — `beginTotpEnrolment()` sets a whole new record — so it
// owes no `touch()`. And it carries no `tombstone`: it is keyed by a NAME,
// which a person legitimately writes again every time they start over.
const pendingTotp = realms.map({ persist: 'credentials.pendingTotp' });

function pendingKeyOf(username) {
  log.debug("Entering pendingKeyOf().");
  log.debug("Leaving pendingKeyOf().");
  return String(username || '').trim().toLowerCase();
}

function sweepPendingTotp() {
  log.debug("Entering sweepPendingTotp().");
  const now = Date.now();
  pendingTotp.forEach(function (value, key) {
    if (!value || Number(value.expires || 0) < now) {
      pendingTotp.delete(key);
    }
  });
  log.debug("Leaving sweepPendingTotp().");
}

// ---------------------------------------------------------------------------
// READ THE ENROLMENT. Null where there is none, and null WITH A LOG LINE where
// there is one this process cannot use — a secret sealed under a
// key-encryption key that has since been rotated, most likely.
//
// **AN UNREADABLE ENROLMENT IS NOT "NO ENROLMENT"**, and the difference
// reaches the sign-in screen: `mechanismsFor()` reports it separately so that
// somebody is told their authenticator cannot be checked rather than being
// signed in with one factor as though they had never enrolled one. That is the
// same distinction `keystore.open()`'s comment draws about a session row, with
// the opposite conclusion, because the consequences are opposite: dropping an
// unreadable SESSION costs somebody a sign-in, and dropping an unreadable
// SECOND FACTOR silently removes a security control.
// ---------------------------------------------------------------------------
function totpOf(username) {
  log.debug("Entering totpOf().");
  const name = String(username || '').trim();
  log.debug('Entering totpOf(). username=' + name);
  if (!directory || typeof directory.readTotp !== 'function') {
    log.debug('Leaving totpOf(). No store.');
    return null;
  }
  let raw = '';
  try {
    raw = directory.readTotp(name) || '';
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0071') +
              'credentials: reading the authenticator enrolment for ' + name +
              ' threw: ' + e.message);
    log.debug("Leaving totpOf().");
    return null;
  }
  if (!raw) {
    log.debug('Leaving totpOf(). None enrolled.');
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.warn('credentials: the ' + TOTP_ATTRIBUTE + ' value on ' + name +
             ' is not JSON this service wrote and is being reported as an ' +
             'unusable enrolment rather than ignored: ' + e.message);
    log.debug("Leaving totpOf().");
    return { unusable: true, why: 'the stored value is not readable' };
  }
  if (parsed && parsed.sealed) {
    const opened = keystore.open(parsed.secret, 'totp-secret');
    if (!opened) {
      log.warn('credentials: the authenticator secret for ' + name + ' is ' +
               'sealed and will not open under this process\'s ' +
               'key-encryption key. It is reported as UNUSABLE rather than ' +
               'as absent, because absent would sign them in with one ' +
               'factor.');
      log.debug("Leaving totpOf().");
      return { unusable: true,
               why: 'the stored secret is sealed under a different ' +
                    'key-encryption key' };
    }
    parsed.secret = opened;
  }
  log.debug('Leaving totpOf(). An authenticator is enrolled.');
  return parsed;
}

function hasTotp(username) {
  log.debug("Entering hasTotp().");
  const record = totpOf(username);
  log.debug("Leaving hasTotp().");
  return !!record;
}

// Write it, sealing where the key outlives the process. One place, so that the
// two callers — a confirmation and a counter advance — cannot disagree about
// what is on the entry.
function writeTotpRecord(username, record) {
  log.debug('Entering writeTotpRecord().');
  const name = String(username || '').trim();
  const out = Object.assign({}, record);
  // `keystore.persists()` and not `keystore.sealed()`. See the header: the
  // question is whether the KEY survives a restart, and in development it does
  // not even when there is one.
  if (keystore.persists()) {
    const sealedSecret = keystore.seal(out.secret, 'totp-secret');
    if (!sealedSecret) {
      log.error(errorCodes.tag('STS-AUTHN-0072') +
                'credentials: the authenticator secret for ' + name + ' ' +
                'could not be sealed, so it was NOT written. Storing it in ' +
                'the clear in product mode would put a working second factor ' +
                'in every directory dump.');
      log.debug("Leaving writeTotpRecord().");
      return coded('STS-AUTHN-0072', { ok: false, errors: ['The shared ' +
                                   'secret could not be encrypted, so it was ' +
                                   'not stored.'] });
    }
    out.secret = sealedSecret;
    out.sealed = true;
  } else {
    out.sealed = false;
  }
  let written = false;
  try {
    written = directory.writeTotp(name, JSON.stringify(out));
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0073') +
              'credentials: writing the authenticator enrolment for ' + name +
              ' threw: ' + e.message);
    log.debug("Leaving writeTotpRecord().");
    return coded('STS-AUTHN-0073', { ok: false, errors: ['The credential ' +
        'store refused the write: ' +
                                 e.message] });
  }
  if (!written) {
    log.debug("Leaving writeTotpRecord().");
    return coded('STS-AUTHN-0061', { ok: false, errors: ['There is nobody ' +
        'called "' + name + '" ' +
                                 'in this realm\'s directory.'] });
  }
  log.debug('Leaving writeTotpRecord(). Written.');
  return { ok: true };
}

// ---------------------------------------------------------------------------
// STEP ONE: MINT A SECRET AND SHOW IT. Nothing is written to the directory.
//
// **IT REFUSES FOR SOMEBODY WHO DOES NOT EXIST IN PRODUCT MODE**, which is
// requirement two applied where it belongs — the same refusal the WebAuthn
// enrolment makes, for the same reason: a credential enrolled for an unknown
// name would create that name, and creating objects because something
// referenced them is what product mode removes.
// ---------------------------------------------------------------------------
function beginTotpEnrolment(username, opts) {
  log.debug("Entering beginTotpEnrolment().");
  const name = String(username || '').trim();
  log.debug('Entering beginTotpEnrolment(). username=' + name);
  const options = opts || {};
  if (!directory || typeof directory.writeTotp !== 'function') {
    log.debug("Leaving beginTotpEnrolment().");
    return coded('STS-AUTHN-0059', { ok: false, errors: ['No credential ' +
                                 'store is installed, so an authenticator ' +
                                 'app cannot be enrolled.'] });
  }
  if (!totp.offered()) {
    log.debug("Leaving beginTotpEnrolment().");
    return coded('STS-AUTHN-0074', { ok: false, errors: ['Authenticator apps ' +
                                 'are turned off on this service ' +
                                 '(totp.enabled).'] });
  }
  if (!name) {
    log.debug("Leaving beginTotpEnrolment().");
    return coded('STS-AUTHN-0058', { ok: false, errors: ['There is no name ' +
                                 'to enrol an authenticator for.'] });
  }
  if (!mode.autoCreates() && !hasEntry(name)) {
    log.info('credentials: product mode, so an authenticator was NOT ' +
             'enrolled for "' + name + '" — there is no entry for them.');
    log.debug("Leaving beginTotpEnrolment().");
    return coded('STS-AUTHN-0024', { ok: false, errors: ['There is nobody ' +
        'called "' + name + '" ' +
                                 'in this realm\'s directory. In product ' +
                                 'mode every referenced object must exist ' +
                                 'first.'] });
  }
  const live = totp.settings();
  const secret = totp.generateSecret();
  sweepPendingTotp();
  pendingTotp.set(pendingKeyOf(name), {
    secret: secret,
    algorithm: live.algorithm,
    digits: live.digits,
    period: live.period,
    expires: Date.now() + live.enrolmentTtlMs
  });
  const issuer = totp.issuerFor(options.base);
  log.info('credentials: an authenticator enrolment was started for ' + name +
           '. Nothing is stored until a code confirms it.');
  log.debug('Leaving beginTotpEnrolment(). Secret minted and held.');
  return {
    ok: true, username: name, secret: secret, issuer: issuer,
    grouped: totp.grouped(secret),
    algorithm: live.algorithm, digits: live.digits, period: live.period,
    uri: totp.otpauthUri({ issuer: issuer, account: name, secret: secret,
                           algorithm: live.algorithm, digits: live.digits,
                           period: live.period }),
    expiresAt: Date.now() + live.enrolmentTtlMs
  };
}

// What is waiting, if anything. Read by the page that redraws the QR code
// after a wrong code was typed — regenerating the secret there would mean a
// person who mistypes once has to scan again.
function pendingTotpFor(username) {
  log.debug("Entering pendingTotpFor().");
  sweepPendingTotp();
  const held = pendingTotp.get(pendingKeyOf(username));
  log.debug("Leaving pendingTotpFor().");
  return held || null;
}

function abandonTotpEnrolment(username) {
  log.debug("Entering abandonTotpEnrolment().");
  pendingTotp.delete(pendingKeyOf(username));
  log.debug("Leaving abandonTotpEnrolment().");
}

// ---------------------------------------------------------------------------
// STEP TWO: A CODE PROVES THE APP HAS IT, AND ONLY THEN IS IT STORED.
//
// The counter that was accepted is stored with it, so that the very code used
// to confirm the enrolment cannot also be used to sign in — RFC 6238 section
// 5.2 applied from the first moment rather than from the second.
// ---------------------------------------------------------------------------
function confirmTotpEnrolment(username, code) {
  log.debug("Entering confirmTotpEnrolment().");
  const name = String(username || '').trim();
  log.debug('Entering confirmTotpEnrolment(). username=' + name);
  const held = pendingTotpFor(name);
  if (!held) {
    log.debug('Leaving confirmTotpEnrolment(). Nothing pending.');
    return coded('STS-AUTHN-0075', { ok: false, reason: 'expired',
             errors: ['That enrolment has expired. Start again and scan the ' +
                      'new code.'] });
  }
  const verdict = totp.verify(held, code);
  if (!verdict.ok) {
    log.info('credentials: an authenticator enrolment for ' + name +
             ' was not confirmed (' + verdict.reason + ').');
    log.debug('Leaving confirmTotpEnrolment(). The code did not verify.');
    return coded(errorCodes.codeOf(verdict) || 'STS-AUTHN-0105',
                 { ok: false, reason: verdict.reason,
                   errors: [verdict.detail] });
  }
  const written = writeTotpRecord(name, {
    secret: held.secret,
    algorithm: held.algorithm, digits: held.digits, period: held.period,
    enrolledAt: Date.now(),
    // SPENT ALREADY. The confirmation code is a code, and a code is accepted
    // once.
    lastCounter: verdict.counter,
    lastUsedAt: Date.now(),
    label: 'authenticator app'
  });
  if (!written.ok) {
    log.debug("Leaving confirmTotpEnrolment().");
    return written;
  }
  abandonTotpEnrolment(name);
  log.info('credentials: ' + name + ' enrolled an authenticator app as a ' +
           'second factor.');
  // ---------------------------------------------------------------------
  // THE RECOVERY CODES ARE NOT ISSUED HERE ANY MORE (2026-09-11), AND THAT IS
  // THE REVERSAL THE SECTION HEADER ARGUES.
  //
  // This was one of exactly two places a set was created, as a side effect of
  // an enrolment succeeding. It cannot be, now that a set is HASHED: the hash
  // has to be made while the code is in the clear, so an automatic issue would
  // write a credential at a moment nobody was looking at it — and the person
  // would hold ten strings they had never seen.
  //
  // **WHAT REPLACES IT IS AN ADVICE FLAG AND NOT SILENCE.** The old
  // arrangement protected a real population — the people who never think to
  // ask are the ones who need it — and dropping that protection outright would
  // be a worse service. `recoveryAdvised` is reported on this result and by
  // `mechanismsFor()`, and `/portal/mfa` draws a standing prompt from it.
  const advised = backupCodes.offered() && !backupCodesOf(name);
  log.debug('Leaving confirmTotpEnrolment(). Enrolled.');
  return { ok: true, username: name,
           recoveryAdvised: advised,
           recoveryNote: advised
             ? 'You now have a second factor and no recovery codes. Generate ' +
               'a set from your account page before you need it — this ' +
               'service will not issue one for you, and a set is shown once.'
             : '' };
}

// ---------------------------------------------------------------------------
// VERIFY A CODE AT A SIGN-IN, AND SPEND IT.
//
// **THE COUNTER IS ADVANCED HERE AND NOWHERE ELSE**, which is the same
// arrangement `noteKeyUsed()` has with the WebAuthn signature counter — one
// place records what was spent, so a second call site cannot forget to. A
// failure to record it is LOGGED and does not undo the sign-in, for
// `noteKeyUsed()`'s reason: the authentication has already succeeded, and the
// cost is that one code could be replayed within its window rather than that
// somebody is refused.
//
// **IT IS REAL IN BOTH MODES.** See `common/totp.js`'s header — this is the
// SPNEGO exception read a second time: when it was written, the only other
// place in this service where a credential presented by an end user was
// checked in development mode (recovery codes joined it the same day).
// ---------------------------------------------------------------------------
// PREPARE / FINISH, `backupPrepare()`'s shape: everything decided against the
// entry is decided in the first half, so the synchronous door and the
// asynchronous one below refuse in the same order and cannot drift apart.
function totpPrepare(name, code, options) {
  log.debug("Entering totpPrepare().");
  const record = totpOf(name);
  if (!record) {
    log.debug('Leaving totpPrepare(). Nothing enrolled.');
    return { done: coded('STS-AUTHN-0076', { ok: false, reason: 'none',
             detail: 'No authenticator app is enrolled for ' + name + '.' }) };
  }
  if (record.unusable) {
    log.error(errorCodes.tag('STS-AUTHN-0077') +
              'credentials: ' + name + ' holds an authenticator enrolment ' +
              'this process cannot read (' + record.why + '), so the second ' +
              'factor cannot be checked. They are refused rather than let ' +
              'through on one factor.');
    log.debug('Leaving totpPrepare(). The enrolment is unusable.');
    return { done: coded('STS-AUTHN-0077', { ok: false, reason: 'unusable',
             detail: 'Your authenticator enrolment cannot be read by this ' +
                     'service, so it cannot be checked. An administrator ' +
                     'has to clear it on your row under /admin/users and ' +
                     'you can enrol again.' }) };
  }
  const verdict = totp.verify(record, code, options);
  if (!verdict.ok) {
    log.info('credentials: a code for ' + name + ' was refused (' +
             verdict.reason + ').');
    log.debug('Leaving totpPrepare(). Refused.');
    return { done: coded(errorCodes.codeOf(verdict) || 'STS-AUTHN-0105',
                 { ok: false, reason: verdict.reason,
                   detail: verdict.detail }) };
  }
  log.debug("Leaving totpPrepare().");
  return { record: record, verdict: verdict };
}

function totpFinish(name, record, verdict) {
  log.debug("Entering totpFinish().");
  record.lastCounter = verdict.counter;
  record.lastUsedAt = Date.now();
  const written = writeTotpRecord(name, record);
  if (!written.ok) {
    // NOT a refusal. See the header: the code verified, and failing to write
    // the counter is a defect in the store rather than a fact about the person
    // standing at the screen.
    log.error(errorCodes.tag('STS-AUTHN-0078') +
              'credentials: the accepted step for ' + name + ' could not be ' +
              'recorded, so that code could be replayed inside its window: ' +
              (written.errors || []).join(' '));
  }
  log.debug('Leaving totpFinish(). Accepted at step ' + verdict.counter + '.');
  return { ok: true, counter: verdict.counter, drift: verdict.drift };
}

// THE SYNCHRONOUS DOOR, KEPT FOR ITS CALLERS AND NOT CLUSTER-SAFE. It spends
// the step on the entry only, which is the whole defence on one node and two
// nodes' worth of acceptance across two. The sign-in screen uses
// `verifyTotpAsync()` below; nothing in this service calls this one any more.
function verifyTotp(username, code, opts) {
  log.debug("Entering verifyTotp().");
  const name = String(username || '').trim();
  log.debug('Entering verifyTotp(). username=' + name);
  const ready = totpPrepare(name, code, opts || {});
  if (ready.done) {
    log.debug('Leaving verifyTotp(). Refused.');
    return ready.done;
  }
  log.debug("Leaving verifyTotp().");
  return totpFinish(name, ready.record, ready.verdict);
}

// ---------------------------------------------------------------------------
// THE STEP, SPENT ACROSS THE CLUSTER (2026-09-14, #46 section 2).
//
// **RFC 6238 SECTION 5.2 WAS HELD ONCE PER NODE.** `lastCounter` is on the
// entry, and two nodes reading "last step 41" at the same moment both accepted
// step 42 — a code shoulder-surfed off a screen and typed at a second node
// while its owner typed it at the first was two sign-ins. Worse, the entry is
// last writer wins, so a node that accepted 42 after another accepted 43 could
// write the counter BACKWARDS, and 43 would then verify again anywhere.
//
// **A COUNTER AND NOT A CLAIM**, unlike every other single-use value in this
// file. A claim on (person, step) stops the same step twice;
// `totp.verify()` refuses every step AT OR BELOW the last one, and that is the
// property worth keeping across nodes — so the step is advanced through
// `cluster/cluster_counters.js`, which refuses anything not above the highest
// step any node has accepted, in one statement. The entry's `lastCounter`
// stays the FIRST check (no round trip for the ordinary repeat) and is still
// written, so a page that draws "last used" is right.
//
// **THE KEY NAMES THE ENROLMENT, NOT ONLY THE PERSON**: `enrolledAt` is part
// of it. Somebody who removes their authenticator and enrols a new one inside
// the same thirty seconds has a new secret whose codes have nothing to do with
// the old one's steps, and refusing their confirmation-adjacent sign-in because
// the OLD enrolment spent that step would be a wrong answer for no defence.
//
// **A STORE THAT CANNOT BE ASKED REFUSES** (`STS-AUTHN-0182`): a code this
// service cannot prove unspent is not one it may accept. That is the opposite
// of a failed ENTRY write after acceptance, which `totpFinish()` still logs and
// lets stand — by then the step is spent in the counter, which is the defence.
// ---------------------------------------------------------------------------
const TOTP_STEP_SCOPE = 'authn.totp-step';

function verifyTotpAsync(username, code, opts) {
  log.debug("Entering verifyTotpAsync().");
  const name = String(username || '').trim();
  const realmId = realms.currentId();
  let ready;
  try {
    ready = totpPrepare(name, code, opts || {});
  } catch (e) {
    log.debug("Caught in verifyTotpAsync(): " + ((e && e.message) || e));
    log.debug("Leaving verifyTotpAsync(). It threw.");
    return Promise.reject(e);
  }
  if (ready.done) {
    log.debug('Leaving verifyTotpAsync(). Refused before the store.');
    return Promise.resolve(ready.done);
  }
  log.debug("Leaving verifyTotpAsync(). Advancing the step.");
  return counters.advance({
    scope: TOTP_STEP_SCOPE,
    key: name + '\n' + String(ready.record.enrolledAt || 0),
    value: ready.verdict.counter,
    realm: realmId
  }).then(function (answer) {
    if (answer.ok) {
      return totpFinish(name, ready.record, ready.verdict);
    }
    if (answer.reason === 'behind') {
      log.warn('credentials: a code for ' + name + ' verified at step ' +
               ready.verdict.counter + ' and was REFUSED: step ' +
               answer.highest + ' has already been accepted for this ' +
               'enrolment, by another node or a request racing this one.');
      return coded('STS-AUTHN-0106', { ok: false, reason: 'replay',
        counter: ready.verdict.counter,
        detail: 'That code has already been used. Wait for your ' +
                'authenticator to show the next one.' });
    }
    log.error(errorCodes.tag('STS-AUTHN-0182') +
              'credentials: a code for ' + name + ' verified and could not ' +
              'be proved unspent (' + (answer.why || answer.reason) + '), ' +
              'so it was refused.');
    return coded('STS-AUTHN-0182', { ok: false, reason: 'store',
      detail: 'That code could not be checked just now. Try the next one ' +
              'in a moment.' });
  });
}

// ---------------------------------------------------------------------------
// WHO HOLDS WHAT, ACROSS THE WHOLE REALM (2026-09-10).
//
// **THE ONE FUNCTION HERE THAT ANSWERS ABOUT SOMEBODY OTHER THAN A NAMED
// PERSON**, written for the roster on `/admin/users` — the operator's view —
// and for the
// management API resource beside it. Everything else in this file is asked
// about one name because every other caller has one.
//
// It is HERE and not in `admin-ui/admin.js` for the reason this file exists at
// all: *who holds a credential* is a credential-store question, and the console
// answering it by reading `stsTotpCredential` off entries itself would be a
// second implementation of what an enrolment IS — including the sealed/clear
// distinction, which the console has no business knowing about.
//
// **IT IS THE UNION OF TWO POPULATIONS AND NEITHER ALONE WOULD DO.** The
// directory's own people are the authoritative list; but a service whose
// directory hook is missing still has people it has SEEN, and — the case that
// forced this — somebody provisioned through SCIM who spent an activation link,
// enrolled an authenticator and has never signed in is in the directory and in
// no other register. The caller passes the names it knows and this adds the
// rest.
//
// **IT IS CAPPED**, for `/portal/applications`'s reason: this walks the realm
// and reads an attribute per person on the one thread that answers every socket
// this service holds, and a directory with fifty thousand entries in it is a
// state this repository's own bulk-load jobs create deliberately.
// ---------------------------------------------------------------------------
//
// **THE CAP IS `credentials.factorScanLimit` SINCE 2026-09-12** and this
// constant is its default. The reply has always carried `capped` and `limit`,
// so a page drawing it says when it stopped; what an operator with a larger
// directory could not do was move the number.
const FACTOR_SCAN_LIMIT = 5000;

function factorScanLimit() {
  log.debug("Entering factorScanLimit().");
  const n = Number(config.value('credentials.factorScanLimit'));
  log.debug("Leaving factorScanLimit().");
  return isFinite(n) && n > 0 ? Math.floor(n) : FACTOR_SCAN_LIMIT;
}

function secondFactorHolders(alsoKnown, opts) {
  log.debug('Entering secondFactorHolders().');
  const options = opts || {};
  const limit = Math.max(1, Number(options.limit || factorScanLimit()));
  const seen = new Map();
  const add = function (name, source) {
    log.debug("Entering add().");
    const value = String(name == null ? '' : name).trim();
    if (!value) {
      log.debug("Leaving add().");
      return;
    }
    const key = value.toLowerCase();
    if (!seen.has(key)) {
      seen.set(key, { username: value, inDirectory: false, known: false });
    }
    seen.get(key)[source] = true;
    log.debug("Leaving add().");
  };
  let scanned = 0;
  let capped = false;
  if (directory && typeof directory.persons === 'function') {
    let people = [];
    try {
      people = directory.persons() || [];
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0079') +
                'credentials: listing this realm\'s people threw: ' +
                e.message);
    }
    scanned = people.length;
    if (people.length > limit) {
      capped = true;
      people = people.slice(0, limit);
    }
    people.forEach(function (name) { add(name, 'inDirectory'); });
  }
  (alsoKnown || []).forEach(function (name) { add(name, 'known'); });

  const rows = [];
  seen.forEach(function (row) {
    const mechanisms = mechanismsFor(row.username);
    rows.push({
      username: row.username,
      inDirectory: row.inDirectory,
      known: row.known,
      password: mechanisms.password,
      primaryKeys: mechanisms.primaryKeys,
      mfaKeys: mechanisms.mfaKeys,
      totp: mechanisms.totp,
      totpUsable: mechanisms.totpUsable,
      totpDetail: mechanisms.totpDetail,
      // THE RECOVERY CODES AS A COUNT AND NEVER AS CODES. This roster is the
      // operator's view and is drawn on `/admin/users`, which must never show
      // a working second factor — `backupCodeStatus()` is what the whole row
      // is built from and it carries none.
      backupCodes: mechanisms.backupCodes,
      // Whether this person should be told to generate a set — the flag that
      // replaced the automatic issue on 2026-09-11, on the roster so that an
      // operator can see the population it is true of rather than one row at
      // a time.
      recoveryAdvised: mechanisms.recoveryAdvised,
      mfaRequired: mechanisms.mfaRequired,
      secondFactor: mechanisms.secondFactor,
      usable: mechanisms.usable
    });
  });
  rows.sort(function (a, b) {
    return a.username.toLowerCase() < b.username.toLowerCase() ? -1 : 1;
  });
  log.debug('Leaving secondFactorHolders(). ' + rows.length +
            ' person/people.');
  return { rows: rows, scanned: scanned, capped: capped, limit: limit,
           store: !!directory };
}

// ---------------------------------------------------------------------------
// REMOVE IT. **THIS ONE CANNOT LOCK ANYBODY OUT AND SO HAS NO REFUSAL**, which
// is the whole difference from `removeKey()`: a TOTP secret is never the only
// way in, because it can never be a primary credential. What removing it does
// is drop the account to one factor, which is a real change and is therefore
// audited by every caller.
//
// It is used by the person themselves on `/portal/mfa` and by an operator's
// Clear on their row under `/admin/users` — the second being what somebody who
// has lost their phone needs, since there is no other way back: the secret is
// on a device this service cannot reach.
// ---------------------------------------------------------------------------
function removeTotp(username) {
  log.debug("Entering removeTotp().");
  const name = String(username || '').trim();
  log.debug('Entering removeTotp(). username=' + name);
  if (!directory || typeof directory.writeTotp !== 'function') {
    log.debug("Leaving removeTotp().");
    return coded('STS-AUTHN-0059', { ok: false, errors: ['No credential ' +
        'store is installed.'] });
  }
  abandonTotpEnrolment(name);
  if (!totpOf(name)) {
    log.debug('Leaving removeTotp(). There was none.');
    return coded('STS-AUTHN-0076', { ok: false, errors: ['No authenticator ' +
        'app is enrolled for ' +
                                 name + '.'] });
  }
  try {
    directory.writeTotp(name, null);
  } catch (e) {
    log.debug("Leaving removeTotp().");
    return coded('STS-AUTHN-0073', { ok: false, errors: ['The credential ' +
        'store refused the write: ' +
                                 e.message] });
  }
  log.info('credentials: the authenticator enrolment for ' + name +
           ' was removed. That account is down to one factor.');
  log.debug('Leaving removeTotp(). Removed.');
  return { ok: true, username: name };
}

// ===========================================================================
// RECOVERY CODES, ON THE SAME ENTRY AS EVERYTHING ELSE (2026-09-10).
//
// The THIRD second factor. It was the one nobody had to choose — a set was
// issued automatically the first time a person came to hold either of the
// other two — until 2026-09-11, when that reversed (see below): a person now
// generates a set when they ask. `common/backup_codes.js` owns what a code
// IS — the alphabet, the length, the comparison; this section owns WHERE THE
// SET LIVES, WHEN IT IS ISSUED and what spending one does, because those are
// credential-store questions and this file is the credential store.
//
// ---------------------------------------------------------------------------
// IT IS ISSUED WHEN THE PERSON ASKS TO SEE ONE, IN TWO STEPS, AND NOTHING IS
// STORED UNTIL THEY SAY THEY HAVE KEPT IT (2026-09-11).
//
// **THIS SECTION SAID THE OPPOSITE FOR AS LONG AS IT EXISTED AND THE OLD
// ARGUMENT IS KEPT HERE BECAUSE IT IS STILL TRUE.** It read:
//
// > IT IS ISSUED BY AN ACT AND NOT BY A REQUEST, AND THAT IS THE WHOLE
// > FEATURE. `ensureBackupCodes()` is called from exactly two places — the end
// > of `confirmTotpEnrolment()`, and `addKey()` when the role is `mfa`. There
// > is no "generate my codes" door anywhere. THE DEFECT THAT ARRANGEMENT
// > CLOSES IS A CATEGORY OF ACCOUNT, NOT A BUG: making recovery a thing a
// > person has to remember to ask for produces exactly the population it
// > exists to protect, one person at a time — the ones who did not ask are
// > precisely the ones who will need it.
//
// **THAT COST IS REAL AND IT HAS BEEN PAID RATHER THAN ARGUED AWAY.** What
// replaces the automatic issue is not silence: enrolling a second factor now
// leaves `/portal/mfa` carrying a standing, unmissable prompt to generate a
// set, and `mechanismsFor()` reports `recoveryAdvised` so any surface can
// draw it. A nudge somebody can ignore is weaker than a set they were handed,
// and that is the trade this change makes deliberately.
//
// **WHY IT HAD TO CHANGE**: a set is HASHED now (below), and a hash can only
// be made from a code at the moment it exists in the clear. An automatic
// issue would have to hash and store a list at a moment nobody was looking at
// it — which is a credential the person never saw, and the one thing worse
// than a way back nobody asked for.
//
// ---------------------------------------------------------------------------
// TWO STEPS, AND THE FIRST WRITES NOTHING.
//
// `beginBackupCodes()` generates a set and puts it in a PENDING map; nothing
// reaches the directory. `confirmBackupCodes()` takes that pending set, hashes
// every code and writes the record. **This is `beginTotpEnrolment()` /
// `confirmTotpEnrolment()` beside it, shape for shape, and for its reason**: a
// set written before the person said they had kept it is a second factor they
// cannot produce — somebody who opens the page, sees ten strings and closes
// the tab would otherwise have replaced a working list with one they never
// read.
//
// So the honest states are three and the page draws all of them: no set, a set
// SHOWN AND NOT YET CONFIRMED (which is not a credential and works nowhere),
// and a set confirmed.
//
// **A PENDING SET EXPIRES**, on `backupCodes.pendingTtlS`, and expiring it
// changes nothing about a set already confirmed. A person who walked away
// mid-flow comes back to the set they had.
//
// **AND CONFIRMING REPLACES.** A second set confirmed over a first is the only
// way a person reaches one, so the page says — before it generates anything —
// that the list they are holding stops working. That is the sharp edge of this
// design and it is stated where the button is, not here.
//
// ---------------------------------------------------------------------------
// HASHED AND NOT ENCRYPTED, WHICH IS `userPassword`'s RULE AND THE OPPOSITE OF
// THE TOTP SECRET BESIDE IT.
//
// `common/crypto.js` states it: a secret this service VERIFIES is hashed, a
// secret it must PRESENT cannot be. A recovery code used to be both, because
// `/portal/mfa` let a person read their remaining codes back. **It does not
// any more** — the set is shown ONCE, at the moment it is generated — so the
// code is verify-only and the rule points the other way.
//
// `backupCodes.hash()` is `crypto.hashSecret()`, which is scrypt at N=2^15 and
// is the same function `userPassword` goes through (rule 3r: one place). The
// consequence that had to be designed around is the COST: one hash is 72ms on
// this machine and a WRONG code must be compared against every code in the
// set, which measured **906ms of blocked event loop** for a default set of
// ten. So `verifyBackupCodeAsync()` exists and the sign-in door uses it — the
// candidates go to the WORKER POOL, in parallel.
//
// **A SET WRITTEN BY AN OLDER BUILD STILL WORKS**, and that is not
// compatibility for its own sake: somebody is holding it on paper, and the one
// thing this mechanism may never do is stop working with nothing having said
// so. `backupCodes.isHash()` tells the two forms apart PER ENTRY, a legacy
// entry is compared as a string exactly as it was, and the record is reported
// as `legacy` so `/portal/mfa` can invite the person to generate a hashed set
// — an invitation rather than a migration, because migrating would mean
// writing hashes of codes at a moment nobody is looking, which is the thing
// the paragraph above refuses.
//
// **A SET THAT WILL NOT OPEN IS REPORTED AS UNUSABLE AND NEVER AS ABSENT**,
// for `totpOf()`'s reason. It matters less than it did — a hashed vault is not
// sealed, so there is nothing to fail to open — and it is kept for the legacy
// sealed sets, which are exactly the ones somebody is holding on paper.
//
// ---------------------------------------------------------------------------
// THE WHOLE SET IS ONE BLOB AND THE COUNTS ARE OUTSIDE IT.
//
// (It was SEALED until 2026-09-11 and its entries were codes; since then the
// entries are hashes and the blob is stored in the clear — see
// `writeBackupCodesRecord()`. The argument below for one blob and the counts
// beside it is unchanged.)
//
// `vault` is a JSON array of `{ code, usedAt }` — sealed as one string — and
// `total`, `remaining`, `generatedAt` and `lastUsedAt` sit beside it in the
// clear. Two reasons, and the second is the one that decided it:
//
//   * A per-code seal would be N ciphertexts whose LENGTHS are a list of the
//     code lengths, and whose count is the number of codes. Nothing secret,
//     but nothing gained either.
//   * **Every page that reports on this needs the counts and almost none of
//     them needs the codes.** `/admin/users` says "7 of 10 unused" for an
//     operator who must never be shown the codes themselves; the sign-in
//     screen decides whether to offer the *use a recovery code* link at all.
//     Making those readable without opening the vault means the console can
//     be honest about an account whose codes this process cannot decrypt.
//
// **THE VAULT IS AUTHORITATIVE AND THE COUNTS ARE A RENDERING OF IT**,
// rewritten from the array on every write. A reader that needs to be right
// about how many are left opens the vault; a reader that needs to draw a page
// reads the count.
// ===========================================================================

// Invented, like the three beside it — nothing in RFC 4519 or any other schema
// worth borrowing has an attribute for a recovery code, because the notion
// postdates every LDAP schema document by decades. Single-valued: the value is
// one JSON object and `ldap/ldap_server.js` assigns rather than appends, for
// `stsTotpCredential`'s reason — a second value would be a second set, and a
// code names neither.
const BACKUP_CODES_ATTRIBUTE = 'stsBackupCodes';

// ---------------------------------------------------------------------------
// READ THE SET. Null where there is none, and `{ unusable: true }` where there
// is one this process cannot open — see the header: absent would let a second
// set be issued over a list somebody is holding on paper.
// ---------------------------------------------------------------------------
function backupCodesOf(username) {
  log.debug("Entering backupCodesOf().");
  const name = String(username || '').trim();
  log.debug('Entering backupCodesOf(). username=' + name);
  if (!directory || typeof directory.readBackupCodes !== 'function') {
    log.debug('Leaving backupCodesOf(). No store.');
    return null;
  }
  let raw = '';
  try {
    raw = directory.readBackupCodes(name) || '';
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0080') +
              'credentials: reading the recovery codes for ' + name +
              ' threw: ' + e.message);
    log.debug('Leaving backupCodesOf(). It threw.');
    return null;
  }
  if (!raw) {
    log.debug('Leaving backupCodesOf(). None issued.');
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.warn('credentials: the ' + BACKUP_CODES_ATTRIBUTE + ' value on ' +
             name + ' is not JSON this service wrote and is being reported ' +
             'as an unusable set rather than ignored: ' + e.message);
    log.debug('Leaving backupCodesOf(). Not JSON.');
    return { unusable: true, why: 'the stored value is not readable' };
  }
  let vault = parsed.vault;
  if (parsed && parsed.sealed) {
    const opened = keystore.open(parsed.vault, 'recovery-codes');
    if (!opened) {
      log.warn('credentials: the recovery codes for ' + name + ' are sealed ' +
               'and will not open under this process\'s key-encryption key. ' +
               'They are reported as UNUSABLE rather than as absent, because ' +
               'absent would let a second set be issued over the one that ' +
               'person is holding.');
      log.debug('Leaving backupCodesOf(). Sealed under another key.');
      return { unusable: true, sealed: true,
               total: Number(parsed.total || 0),
               remaining: Number(parsed.remaining || 0),
               generatedAt: Number(parsed.generatedAt || 0),
               lastUsedAt: Number(parsed.lastUsedAt || 0),
               why: 'the stored set is sealed under a different ' +
                    'key-encryption key' };
    }
    vault = opened;
  }
  let codes;
  try {
    codes = JSON.parse(vault);
  } catch (e) {
    log.warn('credentials: the recovery code list for ' + name + ' opened ' +
             'and is not the array this service writes: ' + e.message);
    log.debug('Leaving backupCodesOf(). The vault is not an array.');
    return { unusable: true, why: 'the stored code list is not readable' };
  }
  if (!Array.isArray(codes)) {
    log.debug('Leaving backupCodesOf(). The vault is not an array.');
    return { unusable: true, why: 'the stored code list is not a list' };
  }
  // **NORMALISED TO ONE SHAPE HERE, WHICH IS WHY NOTHING ABOVE THIS LINE
  // BRANCHES ON THE VERSION.** A version 2 entry is `{ hash, usedAt }` and a
  // version 1 entry — written before 2026-09-11, and possibly printed and
  // filed by its owner — is `{ code, usedAt }`. Both become `{ hash, usedAt }`
  // with `hashed` saying which the stored value really is, so every reader
  // below gets one field and the ONE place that has to care is the comparison
  // in `verifyBackupCode()`.
  //
  // The legacy form is not rewritten. Migrating it would mean hashing the
  // codes — which this service can still read — and that is a set of hashes
  // made at a moment nobody was looking at the codes, which is the thing the
  // header refuses. The portal invites the person to generate a new set
  // instead.
  const normalised = codes.map(function (one) {
    const stored = one && one.hash !== undefined ? one.hash : (one || {}).code;
    return { hash: String(stored || ''),
             usedAt: Number((one || {}).usedAt || 0) };
  });
  const legacy = normalised.some(function (one) {
    return one.hash && !backupCodes.isHash(one.hash);
  });
  log.debug('Leaving backupCodesOf(). ' + normalised.length + ' code(s), ' +
            normalised.filter(function (one) { return !one.usedAt; }).length +
            ' unused, hashed=' + !legacy + '.');
  return {
    codes: normalised,
    hashed: !legacy,
    legacy: legacy,
    sealed: !!parsed.sealed,
    generatedAt: Number(parsed.generatedAt || 0),
    lastUsedAt: Number(parsed.lastUsedAt || 0)
  };
}

// ---------------------------------------------------------------------------
// WRITE THE SET, sealing where the key outlives the process. ONE place, so
// that an issue and a spend cannot disagree about what is on the entry — the
// same arrangement `writeTotpRecord()` has with its two callers.
//
// The counts are computed HERE from the array rather than taken from the
// caller, which is what makes the header's "the vault is authoritative and the
// counts are a rendering of it" true by construction rather than by everybody
// remembering.
// ---------------------------------------------------------------------------
function writeBackupCodesRecord(username, codes, meta) {
  log.debug('Entering writeBackupCodesRecord().');
  const name = String(username || '').trim();
  const info = meta || {};
  // **EVERY ENTRY IS A HASH AND THE CALLER HAS ALREADY MADE IT.** Hashing
  // here would put scrypt inside the one function every spend goes through,
  // so marking a code used would re-hash the nine beside it — 650ms to record
  // something the caller already knew. `confirmBackupCodes()` hashes once, at
  // the only moment the codes exist in the clear.
  //
  // `hash` is carried verbatim, including a LEGACY entry that is a code
  // rather than a hash: a spend rewrites the whole array, and re-writing a
  // legacy set as anything but itself would silently break the list its owner
  // is holding on paper.
  const list = (codes || []).map(function (one) {
    return { hash: String(one.hash || ''), usedAt: Number(one.usedAt || 0) };
  });
  const plain = JSON.stringify(list);
  const out = {
    version: 2,
    total: list.length,
    remaining: list.filter(function (one) { return !one.usedAt; }).length,
    generatedAt: Number(info.generatedAt || Date.now()),
    lastUsedAt: Number(info.lastUsedAt || 0),
    // **NOT SEALED, AND THAT IS THE POINT OF THE CHANGE RATHER THAN AN
    // OMISSION.** The vault used to be encrypted under the key-encryption key
    // so that `/portal/mfa` could show the codes back; it holds scrypt hashes
    // now, which are not secret — `userPassword` sits in the clear beside
    // them for exactly the same reason. It also removes the failure mode the
    // old code had to refuse on: a set that could not be sealed was not
    // written at all, and a set that would not OPEN was a live credential
    // nobody could check.
    sealed: false,
    hashed: true,
    vault: plain
  };
  let written = false;
  try {
    written = directory.writeBackupCodes(name, JSON.stringify(out));
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0081') +
              'credentials: writing the recovery codes for ' + name +
              ' threw: ' + e.message);
    log.debug('Leaving writeBackupCodesRecord(). It threw.');
    return coded('STS-AUTHN-0081', { ok: false, errors: ['The credential ' +
        'store refused the write: ' +
                                 e.message] });
  }
  if (!written) {
    log.debug('Leaving writeBackupCodesRecord(). No entry.');
    return coded('STS-AUTHN-0061', { ok: false, errors: ['There is nobody ' +
        'called "' + name + '" ' +
                                 'in this realm\'s directory.'] });
  }
  log.debug('Leaving writeBackupCodesRecord(). ' + out.remaining + ' of ' +
            out.total + ' unused, sealed=' + out.sealed + '.');
  return { ok: true, total: out.total, remaining: out.remaining };
}

// ===========================================================================
// GENERATING A SET: TWO STEPS, AND THE FIRST WRITES NOTHING (2026-09-11).
//
// This replaces `ensureBackupCodes()`, which issued a set as a SIDE EFFECT of
// enrolling a second factor and is gone. The header above carries the old
// argument and what dropping it costs; what follows is the shape that replaced
// it.
//
// **IT IS `beginTotpEnrolment()` / `confirmTotpEnrolment()` AGAIN.** That pair
// is two doors away in this same file and the reasoning is identical: an
// unconfirmed secret written to somebody's entry is a second factor they
// cannot produce. Here it is sharper still, because confirming REPLACES — so a
// set written before the person said they had kept it would replace a working
// list with one they never read.
// ===========================================================================

// THE PENDING SETS. `realms.map()` for the reason every store in this service
// is: a set begun in one realm must not be confirmable in another, and the
// partition is a property of the declaration rather than of anybody
// remembering. Keyed by a handle rather than by username, so that two tabs
// cannot confirm each other's set — the handle is what the form carries back.
//
// **PERSISTED SINCE 2026-09-14 (#46)**, for `pendingTotp`'s reason read one
// door along: the page that shows the set and the form that confirms it can be
// answered by two nodes, and a confirm that lands on the node which did not
// generate the set stores nothing. The codes are in the clear in the RECORD —
// they have to be, the page shows them — and sealed in the ROW, which is gone
// when the set is confirmed, discarded, replaced or swept.
const pendingBackupCodes = realms.map({
  persist: 'credentials.pendingBackupCodes' });

// A pending set is a live credential in this service's memory — and, where
// minted state is written down, in one sealed row. It expires for the same
// reason an authorization code does: the window in which it can be confirmed
// should be the window in which somebody is actually looking at the page.
function pendingTtlMs() {
  log.debug("Entering pendingTtlMs().");
  log.debug("Leaving pendingTtlMs().");
  return Math.max(60, Math.min(3600,
    Number(config.value('backupCodes.pendingTtlS') || 900))) * 1000;
}

function forgetExpiredPending() {
  log.debug("Entering forgetExpiredPending().");
  const now = Date.now();
  pendingBackupCodes.forEach(function (record, handle) {
    if (record.expires < now) {
      pendingBackupCodes.delete(handle);
    }
  });
  log.debug("Leaving forgetExpiredPending().");
}

// ---------------------------------------------------------------------------
// STEP ONE: generate a set, show it, store NOTHING.
//
// **IT ANSWERS THE CODES IN THE CLEAR AND THIS IS THE ONLY MOMENT THEY
// EXIST.** After `confirmBackupCodes()` has hashed them there is no function
// anywhere — on the portal, the console or `/admin-api` — that can produce
// them again, which is the whole consequence of hashing and is said on every
// surface that draws them.
//
// It never throws and it never touches an existing set: a person who begins
// this and walks away still holds whatever they held before.
// ---------------------------------------------------------------------------
function beginBackupCodes(username, opts) {
  log.debug("Entering beginBackupCodes().");
  const name = String(username || '').trim();
  log.debug('Entering beginBackupCodes(). username=' + name);
  const options = opts || {};
  if (!directory || typeof directory.writeBackupCodes !== 'function') {
    // NOT an error, and the same version-skew contract every function here
    // keeps: an older `ldap/ldap_server.js` leaves a service whose second
    // factors work exactly as they did.
    log.debug('Leaving beginBackupCodes(). No store for them.');
    return coded('STS-AUTHN-0059', { ok: false, reason: 'no-store',
             errors: ['This credential store does not hold recovery codes.'] });
  }
  if (!backupCodes.offered()) {
    log.debug('Leaving beginBackupCodes(). Turned off.');
    return coded('STS-AUTHN-0082', { ok: false, reason: 'disabled',
             errors: ['Recovery codes are turned off on this service ' +
                      '(backupCodes.enabled).'] });
  }
  if (!name) {
    log.debug('Leaving beginBackupCodes(). No name.');
    return coded('STS-AUTHN-0058', { ok: false, reason: 'name',
             errors: ['A set of recovery codes belongs to somebody.'] });
  }
  const live = backupCodes.settings();
  const minted = backupCodes.generate({ count: options.count || live.count,
                                        length: options.length ||
                                                live.length });
  if (!minted) {
    log.error(errorCodes.tag('STS-AUTHN-0083') +
              'credentials: no recovery codes could be generated for ' + name +
              '.');
    log.debug('Leaving beginBackupCodes(). Generation failed.');
    return coded('STS-AUTHN-0083', { ok: false, reason: 'generate',
             errors: ['A set of recovery codes could not be generated.'] });
  }
  forgetExpiredPending();
  // ONE PENDING SET PER PERSON. Beginning again replaces the previous pending
  // set rather than adding to it — otherwise a person who pressed the button
  // twice would be holding two lists and could confirm the one they were no
  // longer looking at.
  pendingBackupCodes.forEach(function (record, handle) {
    if (record.username === name) {
      pendingBackupCodes.delete(handle);
    }
  });
  // A handle and not the username: two tabs must not be able to confirm each
  // other's set, and the form carries this back. `require('crypto')` inline
  // (as `generatePassword()` above once did, before the password policy drew
  // its passwords) because the module name `crypto` is taken here by THIS
  // service's crypto module, and shadowing that at the top of the file to save
  // a require is how somebody later reaches for `crypto.hashSecret()` and gets
  // node's.
  const handle = require('crypto').randomBytes(24).toString('base64url');
  pendingBackupCodes.set(handle, {
    username: name,
    codes: minted,
    begunAt: Date.now(),
    expires: Date.now() + pendingTtlMs()
  });
  log.info('credentials: a set of ' + minted.length + ' recovery codes was ' +
           'generated for ' + name + ' and is being SHOWN. Nothing is stored ' +
           'until they confirm they have kept it.');
  log.debug('Leaving beginBackupCodes(). ' + minted.length + ' pending.');
  return { ok: true, handle: handle, codes: minted.slice(),
           total: minted.length,
           expiresAt: Date.now() + pendingTtlMs(),
           replacing: !!backupCodesOf(name) };
}

// What is pending for this person, for a page that has to redraw itself.
function pendingBackupCodesFor(username, handle) {
  log.debug("Entering pendingBackupCodesFor().");
  forgetExpiredPending();
  const record = pendingBackupCodes.get(String(handle || ''));
  if (!record || record.username !== String(username || '').trim()) {
    log.debug("Leaving pendingBackupCodesFor().");
    return null;
  }
  log.debug("Leaving pendingBackupCodesFor().");
  return record;
}

// ---------------------------------------------------------------------------
// STEP TWO: the person says they have kept it, and NOW it is hashed and
// stored.
//
// **THE HASHING IS HERE AND NOWHERE ELSE**, which is what keeps a spend cheap:
// `writeBackupCodesRecord()` carries hashes verbatim, so marking one code used
// does not re-hash the nine beside it.
//
// **IT IS THE ONLY WRITER THAT CREATES A SET**, and it REPLACES: a set
// confirmed over an existing one is how a person reaches a second list, and
// the page says so before it generates anything. That is the reversal of the
// old ONCE rule, and the old rule's reason — a printed list that stops working
// with nothing having said so — is answered by saying so, loudly, at the one
// moment somebody is choosing.
// ---------------------------------------------------------------------------
function confirmBackupCodes(username, handle) {
  log.debug("Entering confirmBackupCodes().");
  const name = String(username || '').trim();
  log.debug('Entering confirmBackupCodes(). username=' + name);
  const record = pendingBackupCodesFor(name, handle);
  if (!record) {
    // The two causes are not told apart on purpose: a handle that expired and
    // a handle that was never this person's are the same thing to do about —
    // generate again — and distinguishing them would let a caller learn that
    // a handle it guessed belonged to somebody.
    log.debug('Leaving confirmBackupCodes(). No pending set.');
    return coded('STS-AUTHN-0084', { ok: false, reason: 'pending',
             errors: ['There is no set of recovery codes waiting to be ' +
                      'confirmed, or it has expired. Nothing was stored, so ' +
                      'the set you were shown does not work — generate ' +
                      'another one.'] });
  }
  const hashed = record.codes.map(function (code) {
    return { hash: backupCodes.hash(code), usedAt: 0 };
  });
  const written = writeBackupCodesRecord(name, hashed,
    { generatedAt: record.begunAt, lastUsedAt: 0 });
  if (!written.ok) {
    // **THE PENDING SET IS KEPT ON A FAILED WRITE**, which is the opposite of
    // what a tidy implementation does and is the point: the person is looking
    // at the codes right now, so leaving the handle live means pressing the
    // button again is the whole recovery. Dropping it would send somebody
    // holding a freshly printed list back to the beginning.
    log.error(errorCodes.tag('STS-AUTHN-0085') +
              'credentials: the recovery codes for ' + name + ' could not be ' +
              'stored (' + (written.errors || []).join(' ') + '). The set is ' +
              'still pending, so confirming again will retry.');
    log.debug('Leaving confirmBackupCodes(). The write failed.');
    return coded('STS-AUTHN-0085',
                 { ok: false, reason: 'store', retryable: true,
             errors: written.errors });
  }
  pendingBackupCodes.delete(handle);
  log.info('credentials: ' + name + ' confirmed a set of ' + written.total +
           ' recovery codes. Only the hashes are stored — this service can ' +
           'never show them again.');
  log.debug('Leaving confirmBackupCodes(). Stored ' + written.total + '.');
  return { ok: true, total: written.total, remaining: written.remaining };
}

// Throw away a pending set without storing it. The Cancel beside the Confirm:
// a person who decides they are not ready should not leave a live list in this
// process's memory for the rest of the TTL.
function discardBackupCodes(username, handle) {
  log.debug("Entering discardBackupCodes().");
  const record = pendingBackupCodesFor(username, handle);
  if (!record) {
    log.debug("Leaving discardBackupCodes().");
    return { ok: true, discarded: false };
  }
  pendingBackupCodes.delete(handle);
  log.info('credentials: a pending set of recovery codes for ' +
           String(username) + ' was discarded without being stored.');
  log.debug("Leaving discardBackupCodes().");
  return { ok: true, discarded: true };
}


// ---------------------------------------------------------------------------
// WHAT A PERSON HOLDS, WITHOUT THE CODES. What every page that reports on this
// asks — the console's per-person row, the portal's status card, the sign-in
// screen deciding whether to offer the link at all.
//
// **THE CODES ARE NOT IN IT AND THAT IS THE POINT.** One function answers *how
// many are left* and a different one answers *what are they*, so a page that
// wanted the first cannot accidentally render the second. `/admin/users` calls
// this one and there is no call site anywhere in the console for the other.
// ---------------------------------------------------------------------------
function backupCodeStatus(username) {
  log.debug("Entering backupCodeStatus().");
  const name = String(username || '').trim();
  log.debug('Entering backupCodeStatus(). username=' + name);
  const held = backupCodesOf(name);
  if (!held) {
    log.debug('Leaving backupCodeStatus(). None issued.');
    return { present: false, usable: false, total: 0, remaining: 0,
             used: 0, generatedAt: 0, lastUsedAt: 0, sealed: false, why: '' };
  }
  if (held.unusable) {
    log.debug('Leaving backupCodeStatus(). Present and unreadable.');
    // The counts come off the record's CLEAR half, which is exactly what the
    // header says that half is for: a console can be honest about a set this
    // process cannot decrypt rather than reporting it as nothing.
    return { present: true, usable: false,
             total: Number(held.total || 0),
             remaining: Number(held.remaining || 0),
             used: Math.max(0,
                            Number(held.total || 0) -
                            Number(held.remaining || 0)),
             generatedAt: Number(held.generatedAt || 0),
             lastUsedAt: Number(held.lastUsedAt || 0),
             sealed: !!held.sealed, why: held.why || '' };
  }
  const remaining = held.codes.filter(function (one) { return !one.usedAt; });
  log.debug('Leaving backupCodeStatus(). ' + remaining.length + ' of ' +
            held.codes.length + ' unused, hashed=' + !!held.hashed + '.');
  return { present: true, usable: true,
           total: held.codes.length, remaining: remaining.length,
           used: held.codes.length - remaining.length,
           generatedAt: held.generatedAt, lastUsedAt: held.lastUsedAt,
           sealed: held.sealed,
           // **HOW THE SET IS STORED, REPORTED (2026-09-11).** A set written
           // before that date holds the CODES and still verifies; one written
           // since holds scrypt hashes. It is on the STATUS rather than
           // available only by opening the set, for the reason the counts are:
           // every page that reports on this needs to know, and none of them
           // should be reading the entries to find out.
           hashed: !!held.hashed,
           legacy: !!held.legacy,
           why: '' };
}

// ---------------------------------------------------------------------------
// SHOWING A SET BACK IS NOT POSSIBLE ANY MORE, AND THIS FUNCTION IS THE PLACE
// THAT SAYS SO (2026-09-11).
//
// It used to open the sealed vault and hand the codes to `/portal/mfa`, which
// was the whole reason a set was ENCRYPTED rather than hashed. A set is hashed
// now, so there is nothing to show: `$scrypt$32768$8$1$…` is not a recovery
// code and no function anywhere can turn it back into one.
//
// **IT IS KEPT AS A REFUSAL RATHER THAN DELETED**, which is the same call
// `credentials.js` makes about an endpoint an error message names: the portal,
// the console and `/admin-api` all had a door here, and a door that vanishes
// answers 404 while a door that refuses explains. It also means a caller left
// over from an older build gets a sentence rather than `is not a function`.
// ---------------------------------------------------------------------------
function revealBackupCodes(username) {
  log.debug("Entering revealBackupCodes().");
  const name = String(username || '').trim();
  log.debug('Entering revealBackupCodes(). username=' + name);
  const held = backupCodesOf(name);
  log.debug('Leaving revealBackupCodes(). Refused: they are hashed.');
  return coded('STS-AUTHN-0086', {
    ok: false,
    impossible: true,
    present: !!held,
    errors: ['Recovery codes cannot be shown again. Since 2026-09-11 this ' +
             'service stores only a HASH of each code — the same scrypt hash ' +
             'it stores for a password — so there is nothing here to show ' +
             'and no function anywhere that could produce one. A set is ' +
             'displayed once, at the moment it is generated, and generating ' +
             'a new set replaces the one you have.']
  });
}

// ---------------------------------------------------------------------------
// SPEND ONE. The verification half, and it is REAL IN BOTH MODES for the
// reason `verifyTotp()` is: there is nothing left of a single-use recovery
// credential once the comparison goes, and a client author would have no
// artifact to test against.
//
// **THE CODE IS MARKED SPENT BEFORE THE CALLER IS TOLD IT WORKED**, which is
// the opposite of `verifyTotp()`'s arrangement with its counter and is the one
// place these two mechanisms differ on purpose. A TOTP code that verifies and
// whose counter fails to write can at worst be replayed inside a ninety-second
// window. **A recovery code whose spend fails to write is a permanent
// credential** — it would go on working for ever, which is the single property
// a single-use credential may not have. So a failed write REFUSES the
// authentication, and the person is told to use a different code.
//
// **EVERY CODE IN THE SET IS COMPARED EVEN AFTER A MATCH**, for the reason
// `totp.verify()` walks its whole window: returning early makes the time taken
// depend on WHICH code matched, which is a better oracle than the string
// comparison this bothers to make constant-time.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// COMPARING A PRESENTED CODE AGAINST A STORED SET.
//
// **ONE ENTRY MAY BE A HASH AND ANOTHER MAY BE A CODE**, which is the whole
// reason this is a function rather than a loop written twice: a set stored by
// a build older than 2026-09-11 holds the codes themselves, somebody is
// holding it on paper, and refusing it would be this mechanism breaking in
// exactly the way it exists to prevent. `backupCodes.isHash()` decides PER
// ENTRY, so a set is never half-refused.
//
// **EVERY ENTRY IS COMPARED EVEN AFTER A MATCH**, which the synchronous door
// below already did and which is kept: stopping early would make the time this
// takes a function of WHERE in the list the code sits, and the set is stored
// in generation order.
// ---------------------------------------------------------------------------
function compareOne(presented, entry) {
  log.debug("Entering compareOne().");
  const stored = String((entry || {}).hash || '');
  if (!stored) {
    log.debug("Leaving compareOne().");
    return false;
  }
  log.debug("Leaving compareOne().");
  return backupCodes.isHash(stored)
    ? backupCodes.matchesHash(presented, stored)
    : backupCodes.matches(presented, stored);
}

function matchAgainstSet(presented, entries, hits) {
  log.debug("Entering matchAgainstSet().");
  let matchedIndex = -1;
  let spentIndex = -1;
  for (let i = 0; i < entries.length; i++) {
    const hit = hits ? hits[i] : compareOne(presented, entries[i]);
    if (hit) {
      if (entries[i].usedAt) {
        if (spentIndex < 0) {
          spentIndex = i;
        }
      } else if (matchedIndex < 0) {
        matchedIndex = i;
      }
    }
  }
  log.debug("Leaving matchAgainstSet().");
  return { matchedIndex: matchedIndex, spentIndex: spentIndex };
}

// **PREPARE / COMPARE / FINISH, WHICH IS THIS FILE'S OWN SHAPE.**
// `verify()` above is already split this way (`verifyPrepare()` /
// `verifyFinish()`) and the reason is stated there: everything decidable
// WITHOUT the expensive comparison is decided in the first half, so the
// synchronous and asynchronous doors refuse in the same ORDER and cannot come
// to disagree about when to say no. Here the expensive half is scrypt over up
// to ten codes, and every refusal below costs none of it.
function backupPrepare(name, presented) {
  log.debug("Entering backupPrepare().");
  const held = backupCodesOf(name);
  if (!held) {
    log.debug('backupPrepare(): none issued.');
    log.debug("Leaving backupPrepare().");
    return { done: coded('STS-AUTHN-0087', { ok: false, reason: 'none',
                     detail: 'No recovery codes have been issued for ' + name +
                             '.' }) };
  }
  if (held.unusable) {
    log.error(errorCodes.tag('STS-AUTHN-0089') +
              'credentials: ' + name + ' holds a set of recovery codes this ' +
              'process cannot read (' + held.why + '), so they cannot be ' +
              'checked. They are refused rather than let through.');
    log.debug("Leaving backupPrepare().");
    return { done: coded('STS-AUTHN-0089', { ok: false, reason: 'unusable',
                     detail: 'Your recovery codes cannot be read by this ' +
                             'service, so they cannot be checked. An ' +
                             'administrator has to clear them on your row ' +
                             'under /admin/users.' }) };
  }
  // THE SHAPE FIRST, and it matters far more than it did. A password typed
  // into this box used to cost ten constant-time string comparisons; it would
  // now cost ten scrypt hashes — most of a second of blocked event loop, or
  // ten worker jobs — for something that cannot possibly be a code.
  if (!backupCodes.wellFormed(presented)) {
    log.debug('backupPrepare(): not the shape of a code.');
    log.debug("Leaving backupPrepare().");
    return { done: coded('STS-AUTHN-0090', { ok: false, reason: 'shape',
                     detail: 'A recovery code is letters and digits only — ' +
                             'the ones this service printed for you, in ' +
                             'groups. Dashes and spaces are ignored.' }) };
  }
  log.debug("Leaving backupPrepare().");
  return { held: held };
}

function backupFinish(name, held, found, alsoSpent) {
  log.debug("Entering backupFinish().");
  // Codes ANOTHER node has spent that this entry still shows unused — see
  // `verifyBackupCodeAsync()`. Written as spent with this one, so a write-back
  // from here does not resurrect them.
  const others = alsoSpent || [];
  const matchedIndex = found.matchedIndex;
  const spentIndex = found.spentIndex;
  if (matchedIndex < 0 && spentIndex >= 0) {
    // NAMED rather than answered as "wrong". Somebody working down a printed
    // list and re-typing the one they crossed out has done nothing suspicious
    // and needs to be told to use the next one, not that their list is
    // broken — which is exactly the distinction `totp.verify()` draws about a
    // replayed step.
    log.info('credentials: a recovery code for ' + name + ' was refused as ' +
             'already spent.');
    log.debug("Leaving backupFinish().");
    return coded('STS-AUTHN-0091', { ok: false, reason: 'spent',
             detail: 'That recovery code has already been used. Each one ' +
                     'works once — use the next unused code on your list.' });
  }
  if (matchedIndex < 0) {
    log.info('credentials: a recovery code for ' + name + ' did not match.');
    log.debug("Leaving backupFinish().");
    return coded('STS-AUTHN-0092', { ok: false, reason: 'mismatch',
             detail: 'That is not one of your recovery codes.' });
  }
  // THE HASHES ARE CARRIED VERBATIM. A spend rewrites the array to mark one
  // entry used and must not re-hash anything: the codes are not here to hash,
  // and re-hashing what IS here would hash a hash.
  const list = held.codes.map(function (one, i) {
    const spentNow = i === matchedIndex ||
      (!one.usedAt && others.indexOf(i) >= 0);
    return { hash: one.hash,
             usedAt: spentNow ? Date.now() : Number(one.usedAt || 0) };
  });
  const written = writeBackupCodesRecord(name, list,
    { generatedAt: held.generatedAt, lastUsedAt: Date.now() });
  if (!written.ok) {
    // A REFUSAL, and see the header: this is the one place in this file where
    // a failed write undoes a successful verification. A single-use credential
    // that could not be marked spent is a permanent one.
    log.error(errorCodes.tag('STS-AUTHN-0093') +
              'credentials: a recovery code for ' + name + ' verified and ' +
              'could NOT be marked as spent (' +
              (written.errors || []).join(' ') + '), so it was REFUSED. A ' +
              'code that cannot be spent is a code that works for ever.');
    log.debug("Leaving backupFinish().");
    return coded('STS-AUTHN-0093', { ok: false, reason: 'store',
             detail: 'That code is right and this service could not record ' +
                     'that it has been used, so it was not accepted. Try ' +
                     'another one, and tell an administrator.' });
  }
  log.info('credentials: ' + name + ' signed in with a recovery code. ' +
           written.remaining + ' of ' + written.total + ' remain.');
  log.debug("Leaving backupFinish().");
  return { ok: true, remaining: written.remaining, total: written.total };
}

function verifyBackupCode(username, presented) {
  log.debug("Entering verifyBackupCode().");
  const name = String(username || '').trim();
  log.debug('Entering verifyBackupCode(). username=' + name);
  const ready = backupPrepare(name, presented);
  if (ready.done) {
    log.debug('Leaving verifyBackupCode(). Refused before comparing.');
    return ready.done;
  }
  const out = backupFinish(name, ready.held,
                           matchAgainstSet(presented, ready.held.codes));
  log.debug('Leaving verifyBackupCode(). ok=' + out.ok);
  return out;
}

// ---------------------------------------------------------------------------
// THE ASYNCHRONOUS DOOR, AND IT IS THE ONE THE SIGN-IN SCREEN USES.
//
// **BECAUSE A WRONG CODE COSTS TEN SCRYPT HASHES.** Measured on this machine:
// 72ms each, 906ms for a default set of ten — and node runs this service's six
// listener families on ONE THREAD, so that is not a slow request, it is a
// service that answers nobody for most of a second. `common/CLAUDE.md` has the
// whole argument beside the `scrypt.derive` job, which exists for exactly
// this.
//
// **THE CANDIDATES GO IN PARALLEL**, which the password door does not do and
// does not need to: it has one hash to check and this has ten. Five workers
// turn 906ms of blocked loop into about 150ms of wall time during which this
// service keeps answering.
//
// The synchronous door above is KEPT and is not deprecated: `workers.count = 0`
// is a supported configuration that computes the same jobs in this process,
// `npm test` drives the sync door, and a caller that cannot be made
// asynchronous is better off blocking than wrong.
// ---------------------------------------------------------------------------
function verifyBackupCodeAsync(username, presented) {
  log.debug("Entering verifyBackupCodeAsync().");
  const name = String(username || '').trim();
  log.debug('Entering verifyBackupCodeAsync(). username=' + name);
  let ready;
  try {
    ready = backupPrepare(name, presented);
  } catch (e) {
    log.debug("Leaving verifyBackupCodeAsync().");
    return Promise.reject(e);
  }
  if (ready.done) {
    log.debug('Leaving verifyBackupCodeAsync(). Refused before comparing.');
    return Promise.resolve(ready.done);
  }
  const entries = ready.held.codes;
  // The realm the code belongs to, captured before any await: the reconcile a
  // spend schedules runs on a timer, outside the request's ambient realm.
  const realm = realms.current();
  log.debug("Leaving verifyBackupCodeAsync().");
  return Promise.all(entries.map(function (entry) {
    const stored = String((entry || {}).hash || '');
    if (!stored) {
      return Promise.resolve(false);
    }
    // A LEGACY entry is a string comparison and costs nothing, so it is done
    // here rather than dispatched — sending a `constantTimeEquals` to a worker
    // would be an IPC round trip to save nothing, which is the same judgement
    // `crypto.js` makes about RS256.
    if (!backupCodes.isHash(stored)) {
      return Promise.resolve(backupCodes.matches(presented, stored));
    }
    return backupCodes.matchesHashAsync(presented, stored);
  })).then(function (hits) {
    const found = matchAgainstSet(presented, entries, hits);
    if (found.matchedIndex < 0) {
      const refused = backupFinish(name, ready.held, found);
      log.debug('Leaving verifyBackupCodeAsync(). ok=' + refused.ok);
      return refused;
    }
    return spendBackupCode(name, ready.held, found, realm);
  });
}

// ---------------------------------------------------------------------------
// A RECOVERY CODE, SPENT ACROSS THE CLUSTER (2026-09-14, #46 section 2).
//
// **TWO DEFECTS, AND THE SECOND IS THE ONE WORTH UNDERSTANDING.**
//
//   * A code worked once PER NODE: each node read "unused" off its own copy of
//     the entry and wrote "used" back, and inside the change log's window both
//     accepted. Fixed by CLAIMING the code before it is accepted — the claim is
//     keyed by the person and the code's stored hash, which is unique per code
//     (a salted scrypt) and never the code.
//   * **SPENDING TWO DIFFERENT CODES ON TWO NODES AT ONCE LEFT ONE UNSPENT.**
//     The set is ONE attribute holding the whole array, the entry is last
//     writer wins, and A's write says "code 0 used, code 1 unused" while B's
//     says the reverse. Whichever lands last RESURRECTS the other's code on
//     the entry. A claim alone does not fix that: the claim still refuses the
//     resurrected code, but only for its lifetime, and after that the entry
//     is the only record and the entry is wrong.
//
// **THE CLAIMS ARE THE TRUTH ABOUT WHICH CODES ARE SPENT, AND THE ENTRY IS
// MADE TO CONVERGE ON THEM.** Three places do it, and each closes a hole the
// others leave:
//
//   1. **AT THE SPEND**, every code the entry still shows unused is asked
//      about (`isClaimed`, up to nine reads in parallel) and any another node
//      has claimed is written as spent together with this one. That alone is
//      not enough — of two concurrent spends, the one that asked BEFORE the
//      other claimed can be the last writer (linearise the four operations and
//      at least one of the two sees the other, but it need not be the one
//      whose write lands last).
//   2. **A SPEND ON A SHARED STORE SCHEDULES A RECONCILE** a few seconds
//      later (`RECOVERY_RECONCILE_MS`), once the other node's write has had
//      time to arrive: it catches up with the store, re-reads the set, and
//      writes any claimed-but-unmarked code as spent. The last write to the
//      entry is always followed by its writer's reconcile, and a reconcile
//      writes a superset of every claim made before it — so whichever order
//      the commits land in, the entry ends with every spent code marked. It
//      writes nothing if the set was REPLACED meanwhile (`generatedAt`
//      differs): writing an old set back over a new one would be far worse
//      than the defect it repairs.
//   3. **A CODE REFUSED BY ITS CLAIM** — the entry said unused, a claim said
//      spent — repairs the entry on the spot (`STS-AUTHN-0091`), which covers
//      a node that died between its write and its reconcile.
//
// **WHAT IS LEFT, SAID PLAINLY**: a claim lives at most thirty days (the
// ceiling `cluster_claims.js` puts on every claim). A code resurrected on the
// entry by a node that wrote it and then died before its reconcile, which is
// never presented and whose set sees no other spend for thirty days, is usable
// once more after that. Every step above has to fail, in that order, for it.
//
// **A CODE THAT VERIFIED AND COULD NOT BE WRITTEN KEEPS ITS CLAIM.** The door
// refuses it (`STS-AUTHN-0093`, as before) and the claim makes sure it stays
// spent — a code somebody was told not to use must not quietly work on the
// next node.
//
// **THE SYNCHRONOUS DOOR DOES NONE OF THIS** and has no caller outside the
// tests; see `verifyTotp()` beside it for the same note.
// ---------------------------------------------------------------------------
const RECOVERY_SCOPE = 'authn.recovery-code';
const RECOVERY_CLAIM_TTL_MS = 30 * 24 * 60 * 60 * 1000;
// Longer than LISTEN/NOTIFY's delivery (under a second) and the replication
// poll's five-second backstop, so the other node's write has normally arrived;
// the reconcile catches up explicitly as well, so this bounds the wait rather
// than the correctness.
const RECOVERY_RECONCILE_MS = 8000;

function recoveryClaimOf(name, entry, realmId) {
  log.debug("Entering recoveryClaimOf().");
  log.debug("Leaving recoveryClaimOf().");
  return { scope: RECOVERY_SCOPE, value: name + '\n' + String(entry.hash),
           ttlMs: RECOVERY_CLAIM_TTL_MS, realm: realmId };
}

// The indexes of codes this entry shows unused and a claim says are spent.
function claimedButUnmarked(name, codes, realmId, except) {
  log.debug("Entering claimedButUnmarked().");
  log.debug("Leaving claimedButUnmarked().");
  return Promise.all(codes.map(function (one, i) {
    if (i === except || one.usedAt || !one.hash) {
      return Promise.resolve(false);
    }
    return claims.isClaimed(recoveryClaimOf(name, one, realmId))
      .catch(function (e) {
        // Not claimed as far as this spend can tell. The reconcile asks again,
        // and a code a claim still guards is refused when presented anyway.
        log.debug("Caught in claimedButUnmarked(): " +
                  ((e && e.message) || e));
        return false;
      });
  })).then(function (flags) {
    return flags.map(function (flag, i) {
      return flag ? i : -1;
    }).filter(function (i) { return i >= 0; });
  });
}

function sharedStore() {
  log.debug("Entering sharedStore().");
  // LAZY, for `cluster_claims.js`'s reason: this file is a leaf on the require
  // path and must not pull the store module ahead of #4a.
  const persistence = require('../persistence/persistence');
  log.debug("Leaving sharedStore().");
  return persistence;
}

// Step 2 of the header: converge the entry on the claims.
function reconcileBackupCodes(username, realm, generatedAt) {
  log.debug("Entering reconcileBackupCodes().");
  const name = String(username || '').trim();
  const persistence = sharedStore();
  log.debug("Leaving reconcileBackupCodes().");
  return Promise.resolve().then(function () {
    return typeof persistence.syncNow === 'function' &&
      persistence.clusterStore() ? persistence.syncNow() : null;
  }).catch(function (e) {
    log.debug("Caught in reconcileBackupCodes(): " + ((e && e.message) || e));
    return null;
  }).then(function () {
    return realms.run(realm, function () {
      const held = backupCodesOf(name);
      if (!held || held.unusable ||
          (generatedAt !== undefined &&
           Number(held.generatedAt) !== Number(generatedAt))) {
        return { repaired: 0 };
      }
      return claimedButUnmarked(name, held.codes, realm.id, -1)
        .then(function (indexes) {
          if (!indexes.length) {
            return { repaired: 0 };
          }
          const list = held.codes.map(function (one, i) {
            return { hash: one.hash,
                     usedAt: indexes.indexOf(i) >= 0 ? Date.now()
                       : Number(one.usedAt || 0) };
          });
          const written = writeBackupCodesRecord(name, list,
            { generatedAt: held.generatedAt, lastUsedAt: held.lastUsedAt });
          if (!written.ok) {
            log.error(errorCodes.tag('STS-AUTHN-0184') + 'credentials: ' +
                      indexes.length + ' recovery code(s) of ' + name +
                      ' spent on another node could not be written as ' +
                      'spent: ' + (written.errors || []).join(' ') + ' Their ' +
                      'claims still refuse them.');
            return { repaired: 0, failed: indexes.length };
          }
          log.info('credentials: ' + indexes.length + ' recovery code(s) of ' +
                   name + ' spent on another node were written as spent on ' +
                   'the entry.');
          return { repaired: indexes.length };
        });
    });
  });
}

function scheduleBackupReconcile(name, realm, generatedAt) {
  log.debug("Entering scheduleBackupReconcile().");
  if (!sharedStore().clusterStore()) {
    // One process: nothing else writes this entry, so there is nothing to
    // converge.
    log.debug("Leaving scheduleBackupReconcile(). No shared store.");
    return;
  }
  const timer = setTimeout(function () {
    reconcileBackupCodes(name, realm, generatedAt).catch(function (e) {
      log.error(errorCodes.tag('STS-AUTHN-0184') + 'credentials: reconciling ' +
                'the recovery codes of ' + name + ' threw: ' +
                ((e && e.message) || e));
    });
  }, RECOVERY_RECONCILE_MS);
  if (timer && typeof timer.unref === 'function') {
    timer.unref();
  }
  log.debug("Leaving scheduleBackupReconcile().");
}

function spendBackupCode(name, held, found, realm) {
  log.debug("Entering spendBackupCode().");
  const entry = held.codes[found.matchedIndex];
  log.debug("Leaving spendBackupCode(). Claiming.");
  return claims.claim(recoveryClaimOf(name, entry, realm.id))
    .then(function (claimed) {
      if (!claimed.ok && claimed.reason === 'used') {
        log.warn('credentials: a recovery code for ' + name + ' matched a ' +
                 'code this entry shows unused and was REFUSED: it has ' +
                 'already been spent, by another node or a request racing ' +
                 'this one. The entry is being corrected.');
        return reconcileBackupCodes(name, realm, held.generatedAt)
          .catch(function (e) {
            log.debug("Caught in spendBackupCode(): " +
                      ((e && e.message) || e));
            return null;
          }).then(function () {
            return coded('STS-AUTHN-0091', { ok: false, reason: 'spent',
              detail: 'That recovery code has already been used. Each one ' +
                      'works once — use the next unused code on your list.' });
          });
      }
      if (!claimed.ok) {
        log.error(errorCodes.tag('STS-AUTHN-0182') + 'credentials: a ' +
                  'recovery code for ' + name + ' matched and could not be ' +
                  'proved unspent (' + (claimed.why || claimed.reason) +
                  '), so it was refused.');
        return coded('STS-AUTHN-0182', { ok: false, reason: 'store',
          detail: 'That code could not be checked just now. Try again in a ' +
                  'moment.' });
      }
      return claimedButUnmarked(name, held.codes, realm.id, found.matchedIndex)
        .then(function (others) {
          const out = backupFinish(name, held, found, others);
          if (out.ok) {
            scheduleBackupReconcile(name, realm, held.generatedAt);
          }
          return out;
        });
    });
}

// ---------------------------------------------------------------------------
// CLEAR THE SET. An operator's act on that person's row under `/admin/users`.
// (This said it was the ONLY way to a second set, issued by the next second
// factor enrolled; since 2026-09-11 a person generates a new set themselves
// and nothing issues one automatically — the log line below still says the
// old thing.)
//
// **IT CANNOT LOCK ANYBODY OUT AND SO HAS NO REFUSAL**, which is
// `removeTotp()`'s position exactly: a recovery code is never a way in on its
// own, so clearing the set drops the account to whatever it already had. What
// it removes is the way BACK, which is a real change and is why every caller
// audits it.
// ---------------------------------------------------------------------------
function removeBackupCodes(username) {
  log.debug("Entering removeBackupCodes().");
  const name = String(username || '').trim();
  log.debug('Entering removeBackupCodes(). username=' + name);
  if (!directory || typeof directory.writeBackupCodes !== 'function') {
    log.debug('Leaving removeBackupCodes(). No store.');
    return coded('STS-AUTHN-0059', { ok: false, errors: ['No credential ' +
        'store is installed.'] });
  }
  if (!backupCodesOf(name)) {
    log.debug('Leaving removeBackupCodes(). There was none.');
    return coded('STS-AUTHN-0087', { ok: false, errors: ['No recovery codes ' +
        'have been issued for ' +
                                 name + '.'] });
  }
  try {
    directory.writeBackupCodes(name, null);
  } catch (e) {
    log.debug('Leaving removeBackupCodes(). The write threw.');
    return coded('STS-AUTHN-0081', { ok: false, errors: ['The credential ' +
        'store refused the write: ' +
                                 e.message] });
  }
  log.info('credentials: the recovery codes for ' + name + ' were cleared. ' +
           'The next second factor they enrol issues a new set.');
  log.debug('Leaving removeBackupCodes(). Cleared.');
  return { ok: true, username: name };
}

// ---------------------------------------------------------------------------
// HOW CAN THIS PERSON SIGN IN? The question the sign-in screen, the activation
// flow and the portal all ask, answered once.
//
// `usable` is the whole of it: a person with no password and no PRIMARY key
// cannot authenticate, however many `mfa` keys they hold. That combination is
// reachable — enrol a key as a second factor, then remove the password — and it
// is exactly the lockout `removeKey()` above refuses to create.
//
// **THERE ARE TWO SECOND FACTORS SINCE 2026-09-10 AND `usable` DID NOT
// CHANGE**, which is the property to check first if this is ever reworked: an
// authenticator app can never be a primary credential (see the TOTP section
// above), so it cannot make an unusable account usable and it cannot be the
// thing whose removal locks somebody out.
//
// **WHAT DID CHANGE IS `mfaRequired`**, which is now "does this person hold
// EITHER kind of second factor". The sign-in screen reads it, so enrolling an
// authenticator is what makes a password alone stop being enough — the whole
// meaning of *a user configured to use it*.
// ---------------------------------------------------------------------------
function mechanismsFor(username) {
  log.debug("Entering mechanismsFor().");
  const name = String(username || '').trim();
  const keys = keysOf(name);
  const password = hasPassword(name);
  const primaryKeys =
      keys.filter(function (one) { return one.role === 'primary'; });
  const mfaKeys = keys.filter(function (one) { return one.role === 'mfa'; });
  const authenticator = totpOf(name);
  // An enrolment this process cannot READ is not an enrolment it can ignore:
  // it still means this person configured two factors, and reporting it as
  // absent would sign them in with one. `verifyTotp()` refuses it by name.
  const totpEnrolled = !!authenticator;
  log.debug("Leaving mechanismsFor().");
  return {
    username: name,
    password: password,
    primaryKeys: primaryKeys.length,
    mfaKeys: mfaKeys.length,
    keys: keys,
    // The authenticator app, reported as three separate facts because they
    // lead to three different sentences on a page: enrolled, when, and whether
    // this process can actually check it.
    totp: totpEnrolled,
    totpUsable: totpEnrolled && !authenticator.unusable,
    totpDetail: totpEnrolled
      ? { enrolledAt: authenticator.enrolledAt || 0,
          lastUsedAt: authenticator.lastUsedAt || 0,
          algorithm: authenticator.algorithm || '',
          digits: authenticator.digits || 0,
          period: authenticator.period || 0,
          sealed: !!authenticator.sealed,
          unusable: !!authenticator.unusable,
          why: authenticator.why || '' }
      : null,
    // Can they get in at all? UNCHANGED, and see the header: a second factor
    // has never been a way in on its own and an authenticator app is not one
    // either.
    usable: password || primaryKeys.length > 0,
    // THE RECOVERY CODES (2026-09-10), reported as a STATUS OBJECT and never
    // as the codes themselves. `backupCodeStatus()` is what fills it and its
    // header argues the split: one function answers *how many are left* and a
    // different one answers *what are they*, so a page that wanted the first
    // cannot render the second by accident.
    //
    // **IT IS NOT PART OF `mfaRequired` AND MUST NEVER BECOME SO.** A
    // recovery code is what somebody falls back to when they cannot produce
    // the factor they are configured for; a person holding nothing but a set
    // of codes is not a person configured for two factors, and treating them
    // as one would ask for a second factor at a sign-in they have no way to
    // complete.
    //
    // **THE SET IS NO LONGER ISSUED BY AN ENROLMENT EITHER (2026-09-11).** It
    // is generated when the person asks to see one and stored — hashed — only
    // once they confirm they have kept it. `recoveryAdvised` below is what
    // replaced the automatic issue.
    backupCodes: backupCodeStatus(name),
    // Is a second factor required of them? A person holding an `mfa` key or an
    // enrolled authenticator is saying their password alone is not enough, so
    // the sign-in screen demands it as well — which is what makes the flag mean
    // anything. **The recovery codes are deliberately not on this line** — see
    // the field above.
    mfaRequired: mfaKeys.length > 0 || totpEnrolled,
    // WHICH ONE, since there are two and the screen has to ask for the right
    // thing. A person holding both is asked for the SECURITY KEY, because it is
    // the stronger of the two and the ceremony is the one that is bound to this
    // origin; the code is what they fall back to when they are at a machine
    // with no authenticator attached, and `authn.js` draws that link.
    secondFactor: mfaKeys.length > 0 ? 'webauthn' :
                  (totpEnrolled ? 'totp' : ''),
    // Has this person finished setting themselves up? What product mode asks
    // before it will let an activation link be spent, and what the sign-in
    // screen asks before it refuses somebody with nothing. **An authenticator
    // app is deliberately NOT enough to count as activated**, for `usable`'s
    // reason: an account whose only credential is a second factor is an account
    // nobody can sign in to.
    activated: password || keys.length > 0,
    // ---------------------------------------------------------------------
    // SHOULD THIS PERSON BE TOLD TO GENERATE A SET? (2026-09-11)
    //
    // **THIS IS WHAT REPLACED THE AUTOMATIC ISSUE, AND IT IS WEAKER ON
    // PURPOSE-IN-THE-KNOWLEDGE-THAT-IT-IS.** A set used to be created as a
    // side effect of enrolling a second factor, which protected exactly the
    // population that never thinks to ask. Hashing made that impossible — a
    // hash can only be made while the code is in the clear — so what is left
    // is to ASK, everywhere it is true, and to keep asking.
    //
    // It is true of somebody who HAS a second factor and holds no usable set.
    // Not of somebody with no second factor at all: recovery codes stand in
    // for a factor, so prompting a password-only account would be offering a
    // way back from a door they have not walked through.
    //
    // **A LEGACY SET COUNTS AS HAVING ONE.** It still works, its owner may be
    // holding it on paper, and telling them to replace it would be this
    // service inventing urgency about a credential that is fine.
    recoveryAdvised: backupCodes.offered() &&
                     (mfaKeys.length > 0 || totpEnrolled) &&
                     !backupCodesOf(name),
    // IS A SECOND FACTOR REQUIRED OF THEM (2026-09-13), whether or not they
    // hold one — by an administrator on their entry, or by the realm. It is
    // NOT `mfaRequired` above, which is what they HOLD: somebody required to
    // use a second factor who has none is exactly who the sign-in screen asks
    // to enrol one.
    mfaRequirement: mfaRequirementFor(name),
    // A password reset link outstanding, as an expiry and never as a token.
    passwordResetLink: passwordResetPending(name)
  };
}

// ===========================================================================
// ENROLLING A SECURITY KEY, IN TWO STEPS (2026-09-10).
//
// **THIS IS THE DOOR THAT DID NOT EXIST, AND ITS ABSENCE IS WHY NOBODY COULD
// HOLD A BACKUP KEY.** Until today the only WebAuthn enrolment in this service
// was the sign-in screen's checkbox, which is enrol-on-first-use and is
// deliberately reserved for people who hold NO second factor yet — because
// enrolment there for somebody who already holds one is the bypass
// `authn/CLAUDE.md` argues at length: register your own authenticator, be
// signed in claiming two factors, never meet the one the account is configured
// for.
//
// So there was exactly one key per person and no way to add another. A lost
// YubiKey meant an operator clearing the enrolment, which is a support queue —
// and the whole reason WebAuthn has a credential id, a multi-valued attribute
// here and a `maxKeysPerPerson` setting is that **several keys per person is
// the ordinary case**: one at the desk, one in a drawer.
//
// ---------------------------------------------------------------------------
// TWO STEPS, AND THE FIRST WRITES NOTHING — the shape the RFC 6238 pair above
// already has, for the same reason.
//
// `beginKeyEnrolment()` mints a CHALLENGE and holds it in a pending record
// (persisted since 2026-09-14 — see `pendingKeys`);
// `confirmKeyEnrolment()` takes what the browser produced, verifies it against
// that challenge, and only then writes the key. A challenge on somebody's
// entry would be nothing at all — it is the ceremony that produces the
// credential — so unlike the TOTP secret there is no half-state to be locked
// out by. What the two steps buy here is the CHALLENGE BINDING itself: a
// registration is only worth anything if the challenge it signed over is one
// this service minted, for this person, recently.
//
// ---------------------------------------------------------------------------
// `excludeCredentials` IS THE PART THAT MAKES A BACKUP KEY MEAN SOMETHING.
//
// WebAuthn's own mechanism for *do not enrol this authenticator twice*: the
// keys the person already holds go out with the options, and a conforming
// authenticator that recognises one of them REFUSES rather than creating a
// second credential. Without it the commonest mistake — pressing Add and
// touching the key already plugged in — produces a second credential on the
// same device, which is a backup that is lost with the original.
//
// **IT IS THE BROWSER THAT ENFORCES IT AND THIS SERVICE CHECKS ANYWAY.** The
// list is a request like every other ceremony option, so
// `confirmKeyEnrolment()` refuses a credential id already on the entry — one
// authenticator, one row, however the ceremony was driven.
//
// ---------------------------------------------------------------------------
// THE ROLE IS CHOSEN AT THE START AND CARRIED, never read back off the answer.
//
// Same rule the sign-in screen's ceremony follows: the POST at the other end
// is the browser's RESULT and nothing in it says what was asked for. A role
// taken from the returned body would be a caller deciding whether their own
// credential is a way IN or a second factor.
// ===========================================================================

// The attribute is the same one `addKey()` writes; this register holds only
// what has been ASKED FOR and not yet proved. Per realm, like every other
// pending record here, and ~~carrying no `persist:` name~~ — **PERSISTED SINCE
// 2026-09-14 (#46)**. The old reason was "replicated to every process for no
// reader"; behind a balancer the reader is the node the ceremony's next
// request lands on, which drew `/portal/keys` with no challenge
// (`sts_portal_backup_keys`) because another node minted it. A challenge is
// not a credential, so the row leaks nothing, and it is sealed anyway like
// every minted row.
const pendingKeys = realms.map({ persist: 'credentials.pendingKeys' });

// Long enough to find the key in a drawer, short enough that an abandoned
// ceremony is not sitting in memory. It rides the SAME setting the
// authenticator app's unconfirmed enrolment does, because they are the same
// question asked about two mechanisms and two settings would be two answers to
// it.
function keyEnrolmentTtlMs() {
  log.debug("Entering keyEnrolmentTtlMs().");
  log.debug("Leaving keyEnrolmentTtlMs().");
  return Math.max(1, Number(config.value('totp.enrolmentTtlMinutes') || 10)) *
         60 * 1000;
}

function sweepPendingKeys() {
  log.debug("Entering sweepPendingKeys().");
  const now = Date.now();
  pendingKeys.forEach(function (value, key) {
    if (!value || value.expires < now) {
      pendingKeys.delete(key);
    }
  });
  log.debug("Leaving sweepPendingKeys().");
}

// ---------------------------------------------------------------------------
// STEP ONE: MINT A CHALLENGE AND SAY WHAT THE CEREMONY WILL BE.
//
// It REFUSES here rather than at the end wherever it can — the mechanism being
// off, the role not allowed, the cap reached, the person not existing in
// product mode — because a person who has touched their key and then been told
// the realm does not allow it has spent a ceremony on a refusal that was
// knowable before it started. `addKey()` makes the same checks at the end and
// that is not duplication: this one is a COURTESY and that one is the
// enforcement, and the enforcement has to be at the write.
// ---------------------------------------------------------------------------
function beginKeyEnrolment(username, opts) {
  log.debug("Entering beginKeyEnrolment().");
  const name = String(username || '').trim();
  log.debug('Entering beginKeyEnrolment(). username=' + name);
  const options = opts || {};
  const role = String(options.role || 'mfa');
  if (ROLES.indexOf(role) < 0) {
    log.debug('Leaving beginKeyEnrolment(). Not a role.');
    return coded('STS-AUTHN-0066', { ok: false, errors: ['A security key is ' +
                                 'either "primary" or "mfa". ' +
                                 '"' + role + '" is neither.'] });
  }
  const allowed = webauthnPolicy.roleAllowed(role);
  if (!allowed.ok) {
    log.debug('Leaving beginKeyEnrolment(). The role is not allowed here.');
    return coded(errorCodes.codeOf(allowed) || 'STS-AUTHN-0044',
                 { ok: false, errors: [allowed.why] });
  }
  if (!directory || typeof directory.writeWebauthn !== 'function') {
    log.debug("Leaving beginKeyEnrolment().");
    return coded('STS-AUTHN-0059', { ok: false, errors: ['No credential ' +
                                 'store is installed, so a security key ' +
                                 'cannot be enrolled.'] });
  }
  // PRODUCT MODE REFUSES TO ENROL FOR SOMEBODY WHO DOES NOT EXIST, which is
  // `addKey()`'s own refusal made early — see the header.
  if (!mode.autoCreates() && !hasAnyEntry(name)) {
    log.debug("Leaving beginKeyEnrolment().");
    return coded('STS-AUTHN-0024', { ok: false, errors: ['This service is in ' +
                                 'product mode, where a security key can ' +
                                 'only be enrolled for somebody who already ' +
                                 'exists.'] });
  }
  const held = keysOf(name);
  const cap = webauthnPolicy.settings().maxKeysPerPerson;
  if (held.length >= cap) {
    log.debug("Leaving beginKeyEnrolment().");
    return coded('STS-AUTHN-0067', { ok: false,
             errors: ['You already hold ' + held.length + ' security key(s), ' +
                      'which is the most this service allows. Remove one ' +
                      'first.'] });
  }
  sweepPendingKeys();
  const record = {
    // `require('crypto')` inline, which is what `issueActivation()` below
    // also does: the module-level `crypto` here is this service's OWN
    // crypto module, and node's is wanted for nothing but random bytes.
    id: require('crypto').randomBytes(24).toString('base64url'),
    username: name,
    challenge: require('crypto').randomBytes(32).toString('base64url'),
    role: role,
    label: String(options.label || '').trim(),
    // EVERY key they hold and not only the ones of this role: the point is
    // *this authenticator is already registered here*, which is a fact about
    // the device rather than about what the credential is for.
    exclude: held.map(function (one) { return one.credentialId; }),
    expires: Date.now() + keyEnrolmentTtlMs()
  };
  pendingKeys.set(name.toLowerCase(), record);
  log.info('credentials: ' + name + ' started enrolling a "' + role +
           '" security key. ' + record.exclude.length +
           ' authenticator(s) already enrolled are excluded.');
  log.debug('Leaving beginKeyEnrolment(). Challenge minted and held.');
  return { ok: true, enrolmentId: record.id, challenge: record.challenge,
           role: role, exclude: record.exclude.slice(),
           expiresAt: new Date(record.expires).toISOString() };
}

// Is there an entry at all? `hasEntry()` above answers false always and says so
// — it is the bootstrap's, and `readPassword()` cannot tell an absent entry
// from one with no password. This asks the question the key store can answer:
// `readWebauthn()` returns an array for an entry and throws or answers nothing
// for a name that is not there.
function hasAnyEntry(username) {
  log.debug("Entering hasAnyEntry().");
  if (!directory || typeof directory.readWebauthn !== 'function') {
    log.debug("Leaving hasAnyEntry().");
    return false;
  }
  try {
    log.debug("Leaving hasAnyEntry().");
    return Array.isArray(directory.readWebauthn(String(username || '').trim()));
  } catch (e) {
    log.debug("Caught in hasAnyEntry(): " + ((e && e.message) || e));
    log.debug("Leaving hasAnyEntry().");
    // Not there, or the store refused. Either way this is not somebody a key
    // may be enrolled for in product mode.
    return false;
  }
}

function pendingKeyEnrolmentFor(username) {
  log.debug("Entering pendingKeyEnrolmentFor().");
  sweepPendingKeys();
  const held = pendingKeys.get(String(username || '').trim().toLowerCase());
  log.debug("Leaving pendingKeyEnrolmentFor().");
  return held || null;
}

function abandonKeyEnrolment(username) {
  log.debug("Entering abandonKeyEnrolment().");
  pendingKeys.delete(String(username || '').trim().toLowerCase());
  log.debug("Leaving abandonKeyEnrolment().");
}

// ---------------------------------------------------------------------------
// STEP TWO: VERIFY WHAT THE BROWSER PRODUCED, AND ONLY THEN WRITE IT.
//
// The caller passes the ORIGIN and the RP ID because only it knows what the
// browser was talking to — a realm's base URL carries a path and an origin
// never does, which is the mistake `authn/authn.js`'s `originOf()` exists to
// stop being made twice.
// ---------------------------------------------------------------------------
// **IT ANSWERS A PROMISE SINCE 2026-09-14**: the write claims the credential
// id across nodes first (`addKeyClaimed()`). Every refusal before the write is
// the same object it was, resolved.
function confirmKeyEnrolment(username, enrolmentId, credential, opts) {
  log.debug("Entering confirmKeyEnrolment().");
  log.debug("Leaving confirmKeyEnrolment().");
  return Promise.resolve().then(function () {
    return checkKeyEnrolment(username, enrolmentId, credential, opts);
  });
}

function checkKeyEnrolment(username, enrolmentId, credential, opts) {
  log.debug("Entering checkKeyEnrolment().");
  const name = String(username || '').trim();
  log.debug('Entering checkKeyEnrolment(). username=' + name);
  const options = opts || {};
  const held = pendingKeyEnrolmentFor(name);
  if (!held) {
    log.debug('Leaving checkKeyEnrolment(). Nothing pending.');
    return coded('STS-AUTHN-0075', { ok: false, reason: 'expired',
             errors: ['That enrolment has expired. Start again.'] });
  }
  // THE ID IS CHECKED, so that a ceremony begun in one tab cannot be finished
  // with the challenge of another. It is the same rule the sign-in screen's
  // `mfa_id` follows.
  if (String(enrolmentId || '') !== held.id) {
    log.debug('Leaving checkKeyEnrolment(). A different enrolment.');
    return coded('STS-AUTHN-0094', { ok: false, reason: 'mismatch',
             errors: ['That enrolment is not the one in progress. Start ' +
                      'again.'] });
  }
  if (!credential || !credential.response ||
      !credential.response.attestationObject) {
    // The browser reports one error for a declined prompt, a missing
    // authenticator and a timeout, so what arrives is given back as given
    // rather than guessed at.
    const said = credential && credential.error
      ? credential.error + ': ' + (credential.message || '')
      : 'the browser sent no credential';
    log.debug('Leaving checkKeyEnrolment(). No credential.');
    return coded('STS-AUTHN-0022',
                 { ok: false, reason: 'browser', errors: [said] });
  }

  let verdict;
  try {
    verdict = webauthnVerifier.verifyRegistration({
      attestationObject: credential.response.attestationObject,
      clientDataJSON: credential.response.clientDataJSON,
      expectedChallenge: held.challenge,
      expectedOrigin: String(options.origin || ''),
      expectedRpId: String(options.rpId || ''),
      requireUserVerification: webauthnPolicy.requireUserVerification()
    });
  } catch (e) {
    log.debug('Leaving checkKeyEnrolment(). Verification threw.');
    return coded('STS-AUTHN-0027', { ok: false, reason: 'invalid',
             errors: ['The registration could not be checked: ' + e.message] });
  }
  if (!verdict.ok) {
    log.info('credentials: a security key enrolment for ' + name +
             ' did not verify — ' + (verdict.failed || []).join('; '));
    log.debug('Leaving checkKeyEnrolment(). It did not verify.');
    return coded(webauthnPolicy.failureCodeFor(verdict),
                 { ok: false, reason: 'invalid',
             errors: ['The registration did not verify — ' +
                      (verdict.failed || []).join('; ') + '.'] });
  }

  // **THE EXCLUSION, CHECKED HERE AS WELL AS REQUESTED.** `excludeCredentials`
  // is a request to the browser like every other ceremony option; this is what
  // makes one authenticator one row whatever drove the ceremony. It is refused
  // as a DUPLICATE rather than written as a second key, because two rows for
  // one device is a backup that is lost with the original.
  if (held.exclude.indexOf(String(verdict.credentialId)) >= 0) {
    log.info('credentials: ' + name + ' presented an authenticator that is ' +
             'already enrolled. Refused as a duplicate.');
    log.debug('Leaving checkKeyEnrolment(). Already enrolled.');
    return coded('STS-AUTHN-0095', { ok: false, reason: 'duplicate',
             errors: ['That authenticator is already enrolled. Use a ' +
                      'DIFFERENT one — a backup on the same device is lost ' +
                      'with the original.'] });
  }

  // THROUGH THE CLAIM (2026-09-14), which is why this function answers a
  // promise now — see `addKeyClaimed()`.
  log.debug('Leaving checkKeyEnrolment(). Writing through the claim.');
  return addKeyClaimed(name, {
    credentialId: verdict.credentialId,
    publicKeyJwk: verdict.publicKeyJwk,
    signCount: verdict.signCount,
    label: held.label || undefined,
    attachment: credential.authenticatorAttachment || null,
    userVerified: !!(verdict.flags && verdict.flags.uv),
    aaguid: verdict.aaguid || null,
    algorithm: verdict.algorithm || null
  }, held.role).then(function (stored) {
    return keyEnrolmentWritten(name, held, stored);
  });
}

// The end of `confirmKeyEnrolment()`, once the claimed write has answered.
function keyEnrolmentWritten(name, held, stored) {
  log.debug("Entering keyEnrolmentWritten().");
  if (!stored.ok) {
    // NOT ABANDONED. The ceremony was good and the write was refused — the cap
    // reached in another tab, the role turned off while they were touching the
    // key — so the pending record stays and the page can say what happened
    // without making them start over for a reason that may have gone away.
    log.debug('Leaving keyEnrolmentWritten(). The store refused it.');
    return coded(errorCodes.codeOf(stored) || 'STS-AUTHN-0068',
                 { ok: false, reason: 'refused', errors: stored.errors });
  }
  abandonKeyEnrolment(name);
  log.info('credentials: ' + name + ' enrolled a "' + held.role +
           '" security key. They now hold ' + keysOf(name).length + '.');
  log.debug('Leaving keyEnrolmentWritten(). Enrolled.');
  return { ok: true, username: name, role: held.role,
           credentialId: stored.credentialId, held: keysOf(name).length };
}

// ---------------------------------------------------------------------------
// THE ACTIVATION LINK (2026-09-06). HOW SOMEBODY WHO WAS PROVISIONED COMES TO
// HOLD A CREDENTIAL.
//
// **IT IS IN THIS FILE BECAUSE IT IS A CREDENTIAL**, and the most dangerous one
// here. A user object arrives from the management API or from SCIM with no way
// to authenticate; something has to let the person set one up, and that
// something can complete an account setup ON ITS OWN. A leaked activation URL
// is an account takeover — no password needed, no second factor, nothing else
// to guess.
//
// So it is treated as the credential it is, and every one of these is load
// bearing:
//
//   * **32 BYTES OF `randomBytes`**, base64url. Not derived from the username,
//     not a counter, not a UUIDv1 — an activation token that can be guessed
//     from a name is a list of accounts anybody can take.
//   * **HASHED AT REST**, with the same scrypt `hashSecret()` a password uses.
//     A directory dump must not be a list of working account-takeover URLs, and
//     this directory has pages that print every attribute of every entry.
//   * **SINGLE USE.** Consumed the moment it succeeds, so a link in a browser
//     history or a proxy log is spent.
//   * **TIME LIMITED**, `security.activationTtlMinutes`, a day by default
//     because the link is delivered by hand here.
//   * **RATE LIMITED** at the door it is spent at — see `websecurity.js`. A
//     32-byte token is not guessable, but the endpoint that takes one must not
//     be the one place in this service that answers guesses at network speed.
//   * **SHOWN ONCE**, at the moment it is minted, exactly like the bootstrap
//     password and a client secret.
//
// **IT DOES NOT SIGN ANYBODY IN.** Spending a link lets somebody CREATE a
// credential and nothing else; when the setup finishes they are sent to the
// ordinary sign-in screen to use it. That is the difference between a setup
// link and a magic link, and it is deliberate: a link that both proved identity
// and granted a session would be a permanent bypass of every mechanism the
// person is in the middle of configuring.
// ---------------------------------------------------------------------------
function activationTtlMs() {
  log.debug("Entering activationTtlMs().");
  log.debug("Leaving activationTtlMs().");
  return Math.max(1,
                  Number(config.value('security.activationTtlMinutes') ||
                         1440)) *
         60 * 1000;
}

// Mint one for somebody. Returns the token IN THE CLEAR exactly once — the
// caller shows it and forgets it, because what is stored is a hash and this
// service can never produce it again.
function issueActivation(username) {
  log.debug("Entering issueActivation().");
  const name = String(username || '').trim();
  log.debug('Entering issueActivation(). username=' + name);
  if (!name) {
    log.debug("Leaving issueActivation().");
    return coded('STS-AUTHN-0058', { ok: false, errors: ['Name the person to ' +
        'issue a link for.'] });
  }
  if (!directory || typeof directory.writeActivation !== 'function') {
    log.debug("Leaving issueActivation().");
    return coded('STS-AUTHN-0059', { ok: false, errors: ['No credential ' +
                                 'store is installed, so an activation link ' +
                                 'cannot be issued.'] });
  }
  const token = require('crypto').randomBytes(32).toString('base64url');
  const expires = Date.now() + activationTtlMs();
  let written = false;
  try {
    written = directory.writeActivation(name, crypto.hashSecret(token),
                                        expires);
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0101') +
              'credentials: writing an activation token for ' + name +
              ' threw: ' + e.message);
    log.debug("Leaving issueActivation().");
    return coded('STS-AUTHN-0101', { ok: false, errors: ['The credential ' +
        'store refused the write: ' +
                                 e.message] });
  }
  if (!written) {
    log.debug("Leaving issueActivation().");
    return coded('STS-AUTHN-0061', { ok: false, errors: ['There is nobody ' +
        'called "' + name + '" ' +
                                 'in this realm\'s directory. A person is ' +
                                 'provisioned first — through /admin-api, ' +
                                 'SCIM or an LDAP add — and activated ' +
                                 'after.'] });
  }
  // **THE TOKEN IS NOT LOGGED.** Every other credential event in this file logs
  // that it happened; this one logs that it happened and nothing about what.
  log.info('credentials: an activation link was issued for ' + name +
           ', valid until ' + new Date(expires).toISOString() + '. It is ' +
           'shown to the caller ONCE and stored only as a hash — this ' +
           'service cannot produce it again, only replace it.');
  log.debug("Leaving issueActivation().");
  return { ok: true, username: name, token: token, expires: expires,
           expiresAt: new Date(expires).toISOString() };
}

// Is this token the one on that person's entry, and is it still alive?
//
// **IT DOES NOT SAY WHICH OF THE THREE WENT WRONG TO A CALLER.** Wrong token,
// expired token and no token at all are one answer at the door, because
// distinguishing them tells an attacker whether a username is worth grinding.
// The `reason` is for the LOG.
function checkActivation(username, token) {
  log.debug("Entering checkActivation().");
  const name = String(username || '').trim();
  log.debug('Entering checkActivation(). username=' + name);
  if (!name || !token) {
    log.debug("Leaving checkActivation().");
    return coded('STS-AUTHN-0096', { ok: false, reason: 'incomplete' });
  }
  if (!directory || typeof directory.readActivation !== 'function') {
    log.debug("Leaving checkActivation().");
    return coded('STS-AUTHN-0059', { ok: false, reason: 'no-store' });
  }
  let held = null;
  try {
    held = directory.readActivation(name);
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0097') +
              'credentials: reading the activation token for ' + name +
              ' threw: ' + e.message);
    log.debug("Leaving checkActivation().");
    return coded('STS-AUTHN-0097', { ok: false, reason: 'store-error' });
  }
  if (!held || !held.hash) {
    log.debug("Leaving checkActivation().");
    return coded('STS-AUTHN-0098', { ok: false, reason: 'none-issued' });
  }
  if (held.expires && held.expires <= Date.now()) {
    log.debug("Leaving checkActivation().");
    return coded('STS-AUTHN-0099',
                 { ok: false, reason: 'expired', expired: true });
  }
  if (!crypto.verifySecret(token, held.hash)) {
    log.debug("Leaving checkActivation().");
    return coded('STS-AUTHN-0100', { ok: false, reason: 'mismatch' });
  }
  log.debug("Leaving checkActivation().");
  return { ok: true, reason: 'valid', expires: held.expires };
}

// Spend it. Called when the setup FINISHES, not when the link is opened — a
// link consumed on opening would strand anybody whose browser prefetched it or
// who reloaded the page.
function consumeActivation(username) {
  log.debug('Entering consumeActivation(). username=' + username);
  if (!directory || typeof directory.writeActivation !== 'function') {
    log.debug("Leaving consumeActivation().");
    return false;
  }
  try {
    directory.writeActivation(String(username || '').trim(), '', 0);
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0102') +
              'credentials: the activation token for ' + username +
              ' could not be cleared: ' + e.message);
    log.debug("Leaving consumeActivation().");
    return false;
  }
  log.info('credentials: the activation link for ' + username + ' was spent ' +
           'and is now invalid.');
  log.debug("Leaving consumeActivation().");
  return true;
}

// ---------------------------------------------------------------------------
// A LINK, SPENT ACROSS THE CLUSTER (2026-09-14, #46 section 2).
//
// An activation link and a password reset link are each "check the hash on
// the entry, do the work, clear the hash". On one node nothing yields between
// the check and the clear that matters; across nodes the entry is last writer
// wins and arrives a moment later, so the same link POSTed to two nodes at
// once set TWO passwords — and a link that leaked (a proxy log, a shared
// screen) raced against its owner was an account takeover that the owner's
// own successful setup did nothing to stop.
//
// **THE LINK IS CLAIMED BEFORE THE WORK, AND THE CLAIM IS WHAT MAKES IT
// SINGLE USE ACROSS NODES.** The value is the person and the token itself
// (stored as a digest by `cluster_claims.js`, never the token), so a link an
// administrator REISSUES is a new claim and the old one's claim guards nothing
// that still verifies. Its lifetime is what remains of the link's own, so the
// claim outlives every moment the hash on the entry could still verify.
//
// **WHERE IT IS CLAIMED IS THE PORTAL'S DECISION, NOT THIS FILE'S**, because
// only the door knows which request FINISHES: `/portal/activate` can take two
// POSTs (a password, then an authenticator code) and spends the link on the
// second. The door claims before it sets anything, releases the claim on any
// answer that does not finish (`releaseLink()`), and keeps it on the one that
// does. `checkActivation()` / `checkPasswordReset()` stay the first, free
// check; this is what decides a race between two requests that both passed
// it.
//
// **SYNCHRONOUS CALLERS KEEP THE SYNCHRONOUS CHECK.** These two functions are
// asynchronous because a claim on postgres is a round trip, and the portal's
// handlers are already `async`; `consumeActivation()` and
// `consumePasswordReset()` are unchanged and still clear the entry, which is
// what every page and `/admin/users` reads.
// ---------------------------------------------------------------------------
function linkClaim(kind, username, token) {
  log.debug("Entering linkClaim(). kind=" + kind);
  const name = String(username || '').trim();
  let held = null;
  try {
    held = kind === 'activation'
      ? directory.readActivation(name) : directory.readPasswordResetLink(name);
  } catch (e) {
    log.debug("Caught in linkClaim(): " + ((e && e.message) || e));
    held = null;
  }
  const remaining = held && held.expires ? held.expires - Date.now() : 0;
  log.debug("Leaving linkClaim().");
  return claims.claim({
    scope: 'credentials.' + kind,
    value: name + '\n' + String(token || ''),
    // A minute past the link's own expiry, for the clock skew between nodes.
    ttlMs: Math.max(60 * 1000, remaining + 60 * 1000)
  }).then(function (claimed) {
    if (claimed.ok) {
      return { ok: true, handle: claimed.handle };
    }
    if (claimed.reason === 'used') {
      log.warn('credentials: a ' + kind + ' link for ' + name + ' was ' +
               'REFUSED: another request is spending it or has spent it, on ' +
               'this node or another.');
      return coded('STS-AUTHN-0183', { ok: false, reason: 'spent' });
    }
    log.error(errorCodes.tag('STS-AUTHN-0182') + 'credentials: a ' + kind +
              ' link for ' + name + ' could not be proved unspent (' +
              (claimed.why || claimed.reason) + '), so it was refused.');
    return coded('STS-AUTHN-0182', { ok: false, reason: 'store' });
  });
}

function spendActivation(username, token) {
  log.debug("Entering spendActivation().");
  if (!directory || typeof directory.readActivation !== 'function') {
    log.debug("Leaving spendActivation(). No store.");
    return Promise.resolve(coded('STS-AUTHN-0059',
                                 { ok: false, reason: 'no-store' }));
  }
  log.debug("Leaving spendActivation().");
  return linkClaim('activation', username, token);
}

function spendPasswordReset(username, token) {
  log.debug("Entering spendPasswordReset().");
  if (!directory || typeof directory.readPasswordResetLink !== 'function') {
    log.debug("Leaving spendPasswordReset(). No store.");
    return Promise.resolve(coded('STS-AUTHN-0059',
                                 { ok: false, reason: 'no-store' }));
  }
  log.debug("Leaving spendPasswordReset().");
  return linkClaim('password-reset', username, token);
}

// Gives a link's claim back: the request that claimed it did not finish.
function releaseLink(handle) {
  log.debug("Entering releaseLink().");
  log.debug("Leaving releaseLink().");
  return claims.release(handle);
}

// Is one outstanding? What /admin/users draws beside somebody who cannot yet
// sign in, so an operator can tell "never activated" from "link already sent".
function activationPending(username) {
  log.debug("Entering activationPending().");
  if (!directory || typeof directory.readActivation !== 'function') {
    log.debug("Leaving activationPending().");
    return null;
  }
  try {
    const held = directory.readActivation(String(username || '').trim());
    if (!held || !held.hash) {
      log.debug("Leaving activationPending().");
      return null;
    }
    log.debug("Leaving activationPending().");
    return { expires: held.expires,
             expired: !!(held.expires && held.expires <= Date.now()) };
  } catch (e) {
    log.debug("Caught in activationPending(): " + ((e && e.message) || e));
    log.debug("Leaving activationPending().");
    return null;
  }
}

// ===========================================================================
// WHAT AN ADMINISTRATOR DOES TO SOMEBODY'S CREDENTIALS FROM THEIR /admin/users
// PAGE (2026-09-13).
//
// Five acts, and each is here rather than in `admin-core/admin_actions.js`
// because each is a question about the STORE: what a reset link is, which keys
// count as a way in, what a second factor is. The action decides who asked and
// what is said about it (the audit row, the Shared Signals events); this file
// decides what happens to the entry.
//
//   * **`removePassword()`** takes the password off, for a reset link that
//     revokes the one the person had. The removed hash goes on the front of the
//     history, so the link cannot put the same password straight back in
//     product mode, where the history is enforced.
//   * **A PASSWORD RESET LINK** is the activation link's shape for a person who
//     already has an account: 32 random bytes, hashed at rest, single use,
//     `security.passwordResetTtlMinutes`, shown once. Its own attributes and
//     not the activation token's, so issuing one does not throw away an
//     activation somebody else is in the middle of.
//   * **`removePrimaryKeys()`** takes every PRIMARY security key off, and
//     refuses where that would leave no way in — `removeKey()`'s rule about
//     the last way in, applied to all of them at once.
//   * **`removeSecondFactors()`** takes every second factor off: the
//     authenticator app, every `mfa` key and the recovery codes. It cannot lock
//     anybody out, because none of those is a way in.
//   * **`mfaRequirementFor()`** is whether a second factor is REQUIRED of
//     somebody who may hold none: `stsMfaRequired` on their entry, or
//     `authn.mfaRequired` for the realm. `mfaRequired` beside it in
//     `mechanismsFor()` is still what they HOLD; the sign-in screen reads both.
// ===========================================================================
// Is there an entry for them? `hasEntry()` above deliberately always answers
// false for the bootstrap's reason, so these actions ask the directory's own
// `personExists()`; a store without it is treated as holding them, and the
// write that follows is what refuses.
function entryExists(name) {
  log.debug("Entering entryExists().");
  if (!directory || typeof directory.personExists !== 'function') {
    log.debug("Leaving entryExists(). Cannot ask; assumed.");
    return true;
  }
  let found = false;
  try {
    found = !!directory.personExists(name);
  } catch (e) {
    log.debug("Caught in entryExists(): " + ((e && e.message) || e));
    found = false;
  }
  log.debug("Leaving entryExists(). " + found);
  return found;
}

function passwordResetTtlMs() {
  log.debug("Entering passwordResetTtlMs().");
  log.debug("Leaving passwordResetTtlMs().");
  return Math.max(1,
                  Number(config.value('security.passwordResetTtlMinutes'))) *
         60 * 1000;
}

function removePassword(username) {
  log.debug("Entering removePassword().");
  const name = String(username || '').trim();
  if (!name || !directory || typeof directory.clearPassword !== 'function') {
    log.debug("Leaving removePassword(). No store.");
    return coded('STS-AUTHN-0059', { ok: false, errors: ['No credential ' +
                                 'store is installed, so a password cannot ' +
                                 'be removed.'] });
  }
  let current = '';
  let history = [];
  try {
    current = String(directory.readPassword(name) || '');
    history = (typeof directory.readPasswordHistory === 'function'
      ? directory.readPasswordHistory(name) : []).map(String);
  } catch (e) {
    log.debug("Caught in removePassword(): " + ((e && e.message) || e));
  }
  if (!current) {
    log.debug("Leaving removePassword(). There was none.");
    return { ok: true, username: name, removed: false };
  }
  const profile = passwordPolicy.profileFor(name);
  const next = current.indexOf('$scrypt$') === 0
    ? [passwordPolicy.historyValue(current)] : [];
  let written = false;
  try {
    written = directory.clearPassword(name, {
      history: next.concat(history).slice(0, profile.history) });
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0169') + 'credentials: removing the ' +
              'password of ' + name + ' threw: ' + e.message);
    written = false;
  }
  if (!written) {
    log.debug("Leaving removePassword(). Not written.");
    return coded('STS-AUTHN-0169', { ok: false, errors: ['The password of ' +
                                 name + ' could not be removed from their ' +
                                 'entry.'] });
  }
  log.info('credentials: the password of ' + name + ' was removed. Nothing ' +
           'verifies against their entry until a new one is set.');
  log.debug("Leaving removePassword(). Removed.");
  return { ok: true, username: name, removed: true };
}

// Mint a password reset link for somebody who is in the directory. The token
// comes back IN THE CLEAR exactly once; what is stored is its hash.
function issuePasswordReset(username) {
  log.debug("Entering issuePasswordReset().");
  const name = String(username || '').trim();
  if (!name) {
    log.debug("Leaving issuePasswordReset(). No name.");
    return coded('STS-AUTHN-0058', { ok: false, errors: ['Name the person to ' +
        'issue a password reset link for.'] });
  }
  if (!directory || typeof directory.writePasswordResetLink !== 'function') {
    log.debug("Leaving issuePasswordReset(). No store.");
    return coded('STS-AUTHN-0059', { ok: false, errors: ['No credential ' +
                                 'store is installed, so a password reset ' +
                                 'link cannot be issued.'] });
  }
  if (!entryExists(name)) {
    log.debug("Leaving issuePasswordReset(). Nobody by that name.");
    return coded('STS-AUTHN-0061', { ok: false, errors: ['There is nobody ' +
        'called "' + name + '" in this realm\'s directory.'] });
  }
  const token = require('crypto').randomBytes(32).toString('base64url');
  const expires = Date.now() + passwordResetTtlMs();
  let written = false;
  try {
    written = directory.writePasswordResetLink(name, crypto.hashSecret(token),
                                               expires);
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0164') + 'credentials: writing a ' +
              'password reset link for ' + name + ' threw: ' + e.message);
    written = false;
  }
  if (!written) {
    log.debug("Leaving issuePasswordReset(). Not written.");
    return coded('STS-AUTHN-0164', { ok: false, errors: ['The password reset ' +
        'link could not be written onto ' + name + '\'s entry.'] });
  }
  // **THE TOKEN IS NOT LOGGED**, for the activation link's reason.
  log.info('credentials: a password reset link was issued for ' + name +
           ', valid until ' + new Date(expires).toISOString() + '. It is ' +
           'shown ONCE and stored only as a hash.');
  log.debug("Leaving issuePasswordReset().");
  return { ok: true, username: name, token: token, expires: expires,
           expiresAt: new Date(expires).toISOString() };
}

// Is this token the one on that person's entry, and is it still alive? The
// REASON is for the log; a page answers every failure with one sentence, so
// nobody learns which usernames have a link outstanding.
function checkPasswordReset(username, token) {
  log.debug("Entering checkPasswordReset().");
  const name = String(username || '').trim();
  if (!name || !token) {
    log.debug("Leaving checkPasswordReset(). Incomplete.");
    return coded('STS-AUTHN-0168', { ok: false, reason: 'incomplete' });
  }
  if (!directory || typeof directory.readPasswordResetLink !== 'function') {
    log.debug("Leaving checkPasswordReset(). No store.");
    return coded('STS-AUTHN-0059', { ok: false, reason: 'no-store' });
  }
  let held = null;
  try {
    held = directory.readPasswordResetLink(name);
  } catch (e) {
    log.debug("Caught in checkPasswordReset(): " + ((e && e.message) || e));
    held = null;
  }
  if (!held || !held.hash) {
    log.debug("Leaving checkPasswordReset(). None issued.");
    return coded('STS-AUTHN-0165', { ok: false, reason: 'none-issued' });
  }
  if (!held.expires || held.expires <= Date.now()) {
    log.debug("Leaving checkPasswordReset(). Expired.");
    return coded('STS-AUTHN-0166', { ok: false, reason: 'expired' });
  }
  if (!crypto.verifySecret(String(token), held.hash)) {
    log.debug("Leaving checkPasswordReset(). Mismatch.");
    return coded('STS-AUTHN-0167', { ok: false, reason: 'mismatch' });
  }
  log.debug("Leaving checkPasswordReset(). Valid.");
  return { ok: true, reason: 'valid', expires: held.expires };
}

// Spend it — when the new password is STORED, not when the link is opened, for
// the activation link's reason: a link burned by a mail scanner or a prefetch
// would strand somebody whose password was removed when it was issued.
function consumePasswordReset(username) {
  log.debug("Entering consumePasswordReset().");
  if (!directory || typeof directory.writePasswordResetLink !== 'function') {
    log.debug("Leaving consumePasswordReset(). No store.");
    return false;
  }
  let cleared = false;
  try {
    cleared = !!directory.writePasswordResetLink(String(username || '').trim(),
                                                 '', 0);
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0164') + 'credentials: the password ' +
              'reset link for ' + username + ' could not be cleared: ' +
              e.message);
    cleared = false;
  }
  log.debug("Leaving consumePasswordReset(). " + cleared);
  return cleared;
}

function passwordResetPending(username) {
  log.debug("Entering passwordResetPending().");
  if (!directory || typeof directory.readPasswordResetLink !== 'function') {
    log.debug("Leaving passwordResetPending(). No store.");
    return null;
  }
  let held = null;
  try {
    held = directory.readPasswordResetLink(String(username || '').trim());
  } catch (e) {
    log.debug("Caught in passwordResetPending(): " + ((e && e.message) || e));
    held = null;
  }
  log.debug("Leaving passwordResetPending().");
  return held && held.hash
    ? { expires: held.expires, expired: !(held.expires > Date.now()) }
    : null;
}

// Is a second factor required of this person, and by whom? `byRealm` is the
// setting as the AMBIENT realm reads it, which is the realm the sign-in screen
// runs in.
function mfaRequirementFor(username) {
  log.debug("Entering mfaRequirementFor().");
  const name = String(username || '').trim();
  let byUser = false;
  if (name && directory && typeof directory.readMfaRequired === 'function') {
    try {
      byUser = !!directory.readMfaRequired(name);
    } catch (e) {
      log.debug("Caught in mfaRequirementFor(): " + ((e && e.message) || e));
      byUser = false;
    }
  }
  const byRealm = !!config.value('authn.mfaRequired');
  log.debug("Leaving mfaRequirementFor(). user=" + byUser + ", realm=" +
            byRealm);
  return { required: byUser || byRealm, byUser: byUser, byRealm: byRealm };
}

function setMfaRequired(username, required) {
  log.debug("Entering setMfaRequired(). required=" + !!required);
  const name = String(username || '').trim();
  if (!name || !directory || typeof directory.writeMfaRequired !== 'function') {
    log.debug("Leaving setMfaRequired(). No store.");
    return coded('STS-AUTHN-0059', { ok: false, errors: ['No credential ' +
                                 'store is installed.'] });
  }
  if (!entryExists(name)) {
    log.debug("Leaving setMfaRequired(). Nobody by that name.");
    return coded('STS-AUTHN-0061', { ok: false, errors: ['There is nobody ' +
        'called "' + name + '" in this realm\'s directory.'] });
  }
  let written = false;
  try {
    written = !!directory.writeMfaRequired(name, !!required);
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0170') + 'credentials: ' +
              'stsMfaRequired for ' + name + ' could not be written: ' +
              e.message);
    written = false;
  }
  if (!written) {
    log.debug("Leaving setMfaRequired(). Not written.");
    return coded('STS-AUTHN-0170', { ok: false, errors: ['The second-factor ' +
        'requirement could not be written onto ' + name + '\'s entry.'] });
  }
  log.info('credentials: a second factor is ' +
           (required ? 'now REQUIRED of ' : 'no longer required of ') + name +
           '.');
  log.debug("Leaving setMfaRequired(). Written.");
  return { ok: true, username: name, required: !!required };
}

// The keys that went, as a caller may describe them — never the public key.
function keySummary(one) {
  log.debug("Entering keySummary().");
  log.debug("Leaving keySummary().");
  return { credentialId: one.credentialId, role: one.role,
           label: one.label || '', enrolledAt: one.enrolledAt || 0 };
}

function removePrimaryKeys(username) {
  log.debug("Entering removePrimaryKeys().");
  const name = String(username || '').trim();
  if (!directory || typeof directory.replaceWebauthn !== 'function') {
    log.debug("Leaving removePrimaryKeys(). No store.");
    return coded('STS-AUTHN-0059', { ok: false, errors: ['No credential ' +
        'store is installed.'] });
  }
  const keys = keysOf(name);
  const primary = keys.filter(function (one) {
    return one.role === 'primary';
  });
  if (!primary.length) {
    log.debug("Leaving removePrimaryKeys(). None held.");
    return coded('STS-AUTHN-0160', { ok: false, errors: [name + ' holds no ' +
        'security key in the primary role, so there is no passwordless ' +
        'sign-in to disable.'] });
  }
  // THE LAST WAY IN, for every primary key at once. A person with no password
  // whose primary keys all go cannot sign in, and an operator must not do what
  // `removeKey()` refuses the owner.
  if (!hasPassword(name)) {
    log.debug("Leaving removePrimaryKeys(). They would have no way in.");
    return coded('STS-AUTHN-0161', { ok: false, errors: [name + ' has no ' +
        'password, so their primary security keys are the only way they can ' +
        'sign in. Reset their password (or issue a reset link) first, then ' +
        'disable the keys.'] });
  }
  try {
    directory.replaceWebauthn(name, keys.filter(function (one) {
      return one.role !== 'primary';
    }).map(function (one) {
      return JSON.stringify(one);
    }));
  } catch (e) {
    log.error(errorCodes.tag('STS-AUTHN-0163') + 'credentials: removing the ' +
              'primary security keys of ' + name + ' threw: ' + e.message);
    log.debug("Leaving removePrimaryKeys(). The store threw.");
    return coded('STS-AUTHN-0163', { ok: false, errors: ['The credential ' +
        'store refused the write: ' + e.message] });
  }
  log.info('credentials: ' + primary.length + ' primary security key(s) of ' +
           name + ' were removed; they sign in with their password now.');
  log.debug("Leaving removePrimaryKeys(). Removed " + primary.length + ".");
  return { ok: true, username: name, removed: primary.map(keySummary) };
}

function removeSecondFactors(username) {
  log.debug("Entering removeSecondFactors().");
  const name = String(username || '').trim();
  if (!directory || typeof directory.replaceWebauthn !== 'function') {
    log.debug("Leaving removeSecondFactors(). No store.");
    return coded('STS-AUTHN-0059', { ok: false, errors: ['No credential ' +
        'store is installed.'] });
  }
  const keys = keysOf(name);
  const mfa = keys.filter(function (one) {
    return one.role === 'mfa';
  });
  const hadTotp = !!totpOf(name);
  const hadCodes = !!backupCodesOf(name);
  if (!mfa.length && !hadTotp && !hadCodes) {
    log.debug("Leaving removeSecondFactors(). None held.");
    return coded('STS-AUTHN-0162', { ok: false, errors: [name + ' holds no ' +
        'second factor — no authenticator app, no security key in the mfa ' +
        'role and no recovery codes — so there is nothing to disable.'] });
  }
  const done = { totp: false, keys: [], backupCodes: false };
  try {
    if (mfa.length) {
      directory.replaceWebauthn(name, keys.filter(function (one) {
        return one.role !== 'mfa';
      }).map(function (one) {
        return JSON.stringify(one);
      }));
      done.keys = mfa.map(keySummary);
    }
    if (hadTotp) {
      directory.writeTotp(name, null);
      done.totp = true;
    }
    if (hadCodes) {
      directory.writeBackupCodes(name, null);
      done.backupCodes = true;
    }
  } catch (e) {
    // WHAT WENT BEFORE THE THROW IS GONE AND IS REPORTED AS GONE, so a caller
    // emitting an event about each removal says what really happened.
    log.error(errorCodes.tag('STS-AUTHN-0163') + 'credentials: removing the ' +
              'second factors of ' + name + ' threw part way: ' + e.message);
    log.debug("Leaving removeSecondFactors(). The store threw.");
    return coded('STS-AUTHN-0163', { ok: false, removed: done,
             errors: ['The credential store refused a write part way ' +
                      'through: ' + e.message +
                      '. What was removed before it is listed.'] });
  }
  abandonTotpEnrolment(name);
  log.info('credentials: every second factor of ' + name + ' was removed ' +
           '(authenticator app: ' + done.totp + ', mfa keys: ' +
           done.keys.length + ', recovery codes: ' + done.backupCodes + ').');
  log.debug("Leaving removeSecondFactors(). Removed.");
  return { ok: true, username: name, removed: done };
}

// DECLARED AT REQUIRE TIME, for `cluster/cluster.js`'s reason: active-active
// is held to the capability table before anything later in startup runs, so a
// capability is the CODE being present. Each is the whole of its row — every
// door that spends one of these values goes through a function above.
//   * `authn.second-factors-once`: `verifyTotpAsync()`, the async recovery
//     code door, `spendAssertion()`;
//   * `credentials.links-once`: `spendActivation()`, `spendPasswordReset()`;
//   * `ops.bootstrap-once`: `bootstrapOnce()`.
capabilities.provide('authn.second-factors-once');
capabilities.provide('credentials.links-once');
capabilities.provide('ops.bootstrap-once');

module.exports = {
  // --- the authenticator app (RFC 6238) ---
  TOTP_ATTRIBUTE: TOTP_ATTRIBUTE,
  totpOf: totpOf,
  // THE RECOVERY CODES (2026-09-10). `revealBackupCodes()` used to be the one
  // export here that handed back a live credential; since 2026-09-11 the set
  // is hashed and it only refuses — its own header says why it is kept.
  BACKUP_CODES_ATTRIBUTE: BACKUP_CODES_ATTRIBUTE,
  // THE TWO-STEP ISSUE (2026-09-11). `ensureBackupCodes()` is gone: it issued
  // a set as a side effect of enrolling a second factor, which cannot survive
  // hashing — a hash can only be made while the code is in the clear, and an
  // automatic issue would hash a list nobody was looking at.
  beginBackupCodes: beginBackupCodes,
  confirmBackupCodes: confirmBackupCodes,
  discardBackupCodes: discardBackupCodes,
  pendingBackupCodesFor: pendingBackupCodesFor,
  backupCodeStatus: backupCodeStatus,
  revealBackupCodes: revealBackupCodes,
  verifyBackupCode: verifyBackupCode,
  // The door the sign-in screen uses. See its header: a wrong code is ten
  // scrypt hashes, which is 906ms of blocked event loop on one thread.
  verifyBackupCodeAsync: verifyBackupCodeAsync,
  removeBackupCodes: removeBackupCodes,
  hasTotp: hasTotp,
  beginTotpEnrolment: beginTotpEnrolment,
  pendingTotpFor: pendingTotpFor,
  abandonTotpEnrolment: abandonTotpEnrolment,
  confirmTotpEnrolment: confirmTotpEnrolment,
  verifyTotp: verifyTotp,
  removeTotp: removeTotp,
  secondFactorHolders: secondFactorHolders,
  issueActivation: issueActivation,
  checkActivation: checkActivation,
  consumeActivation: consumeActivation,
  activationPending: activationPending,
  WEBAUTHN_ATTRIBUTE: WEBAUTHN_ATTRIBUTE,
  ROLES: ROLES,
  keysOf: keysOf,
  addKey: addKey,
  removeKey: removeKey,
  // THE TWO-STEP ENROLMENT (2026-09-10), which is what lets somebody hold a
  // BACKUP key. `/portal/keys` drives all four; the sign-in screen's
  // enrol-on-first-use path does not, because there the ceremony is part of a
  // sign-in and the pending record it binds to is `authn.js`'s.
  beginKeyEnrolment: beginKeyEnrolment,
  pendingKeyEnrolmentFor: pendingKeyEnrolmentFor,
  abandonKeyEnrolment: abandonKeyEnrolment,
  confirmKeyEnrolment: confirmKeyEnrolment,
  addKeyClaimed: addKeyClaimed,
  noteKeyUsed: noteKeyUsed,
  mechanismsFor: mechanismsFor,
  bootstrap: bootstrap,
  PASSWORD_ATTRIBUTE: PASSWORD_ATTRIBUTE,
  RESERVED_REFUSAL: RESERVED_REFUSAL,
  setDirectory: setDirectory,
  // The plaintext-password observer (2026-09-12) — see the block above it.
  setPasswordObserver: setPasswordObserver,
  storable: storable,
  verify: verify,
  verifyAsync: verifyAsync,
  // A PASSWORD THAT MUST BE CHANGED (2026-09-13) — see resetRefusal().
  passwordResetRequired: passwordResetRequired,
  setPasswordResetRequired: setPasswordResetRequired,
  setPassword: setPassword,
  generatePassword: generatePassword,
  // The password policy, for a door that wants to say so before it tries —
  // `passwordRules()` for a form to print, `passwordProblem()` for the shape of
  // one password, and `preparePassword()` for the LDAP handlers, which have to
  // apply a change inside an atomic modify rather than have it written for
  // them.
  passwordProblem: passwordProblem,
  passwordRules: passwordRules,
  preparePassword: preparePassword,
  passwordWritten: passwordWritten,
  hasPassword: hasPassword,
  // WHAT AN ADMINISTRATOR DOES FROM A PERSON'S /admin/users PAGE (2026-09-13)
  // — see the block above module.exports.
  removePassword: removePassword,
  issuePasswordReset: issuePasswordReset,
  checkPasswordReset: checkPasswordReset,
  consumePasswordReset: consumePasswordReset,
  passwordResetPending: passwordResetPending,
  mfaRequirementFor: mfaRequirementFor,
  setMfaRequired: setMfaRequired,
  removePrimaryKeys: removePrimaryKeys,
  removeSecondFactors: removeSecondFactors,
  // SEVERAL NODES AGAINST ONE STORE (2026-09-14, #46) — each is argued above
  // its definition.
  verifyTotpAsync: verifyTotpAsync,
  spendAssertion: spendAssertion,
  reconcileBackupCodes: reconcileBackupCodes,
  spendActivation: spendActivation,
  spendPasswordReset: spendPasswordReset,
  releaseLink: releaseLink,
  bootstrapOnce: bootstrapOnce
};
