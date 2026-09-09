'use strict';
//
// File: credentials.js
//
// ---------------------------------------------------------------------------
// THE ONE PLACE A PRESENTED PASSWORD IS VERIFIED (2026-09-06).
//
// Four doors take a password and none of them checked one until product mode:
// the sign-in screen (`authn.js`), an LDAP bind (`ldap_server.js`), a
// WS-Security UsernameToken (`wstrust.js`) and SCIM Basic (`scim_auth.js`).
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
// THE DIRECTORY ARRIVES THROUGH `setDirectory()`, filled by `ldap/ldap_server.js`
// at require time, and it is an INVERTED HOOK for the reason every other one on
// this path is (rule 3e): this file is required by `authn.js` at 8 and the
// directory is at 21, so a require in the obvious direction would drag every
// `/ldap` route to the front of the router. It carries TWO functions and is
// validated whole — a filler that installed the read and not the write would
// leave a service that can verify a password and can never set one, which is a
// product-mode deployment nobody can get into.
//
// A LIBRARY (rule 3): it registers no route. It requires `config`, `crypto` and
// `mode`, none of which requires it back.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
const config = require('./config');
const crypto = require('./crypto');
const mode = require('./mode');

// The attribute. RFC 4519 section 2.41 — the standard name, so an entry this
// service writes is one an ordinary LDAP client recognises, and one written by
// an ordinary LDAP client is one this service can read.
const PASSWORD_ATTRIBUTE = 'userPassword';

// ---------------------------------------------------------------------------
// THE SECURITY KEY, ON THE PERSON'S OWN ENTRY (2026-09-06).
//
// **IT WAS AN IN-MEMORY MAP IN `authn.js` AND THAT WAS THE WRONG PLACE.**
// `webauthnCredentials` is a `realms.map()` keyed by username, which means a key
// somebody enrolled did not survive a restart, could not be provisioned, could
// not be seen on any page, and could not be persisted by product mode. For a
// PASSWORDLESS key that is the whole account: the credential is the only one
// there is, so losing it on a restart loses the account.
//
// So it lives beside `userPassword`, on the entry, in the same store — one
// object per person carrying everything about how they authenticate.
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

// WHAT A KEY IS FOR. Two roles and no third, because this service has exactly
// one second factor:
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
  const needed = ['readPassword', 'writePassword'];
  const missing = needed.filter(function (name) {
    return !hooks || typeof hooks[name] !== 'function';
  });
  if (missing.length) {
    log.error('credentials: setDirectory() was given something without ' +
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
  return !!directory;
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
  const name = String(username == null ? '' : username).trim();
  log.debug('Entering verifyPrepare(). username=' + name);
  const via = (opts && opts.via) || 'unstated';

  // BOTH MODES. A mock that cannot be made to say no is not a test fixture.
  if (String(password) === RESERVED_REFUSAL) {
    log.debug('Leaving verifyPrepare(). The reserved refusal password was presented.');
    return { done: { ok: false, reason: 'reserved-refusal',
             detail: 'the password "' + RESERVED_REFUSAL + '" is reserved and ' +
                     'is refused in every mode, so that a client can be tested ' +
                     'against a refusal without anything being configured' } };
  }

  if (!mode.verifiesCredentials()) {
    log.debug('Leaving verifyPrepare(). Development mode: nothing is checked.');
    return { done: { ok: true, reason: 'development-mode',
             detail: 'development mode checks no password in any protocol; ' +
                     'what was proved is that somebody typed a name' } };
  }

  if (!name) {
    log.debug('Leaving verifyPrepare(). No username.');
    return { done: { ok: false, reason: 'no-username',
             detail: 'no username was presented' } };
  }
  if (!directory) {
    // FAIL CLOSED, and this is the one place in this file where that matters.
    // Product mode with no store is a misconfiguration, and the permissive
    // answer to a misconfigured gate is how a service ends up authenticating
    // everybody while reporting that it authenticates nobody.
    log.error('credentials: product mode is in force and no credential store ' +
              'is installed, so every verification is REFUSED. ldap_server.js ' +
              'fills setDirectory() at require time; a process without it ' +
              'cannot verify anybody.');
    log.debug('Leaving verifyPrepare(). No store.');
    return { done: { ok: false, reason: 'no-store',
             detail: 'product mode is in force and no credential store is ' +
                     'installed, so nothing can be verified' } };
  }

  let stored = '';
  try {
    stored = directory.readPassword(name) || '';
  } catch (e) {
    // A store that threw. Refused rather than passed, for the reason above,
    // and logged because it is a fault rather than a wrong password.
    log.error('credentials: reading the stored password for ' + name +
              ' threw and the verification is being REFUSED: ' + e.message);
    log.debug('Leaving verifyPrepare(). The store threw.');
    return { done: { ok: false, reason: 'store-error',
             detail: 'the credential store could not be read' } };
  }

  if (!stored) {
    log.debug('Leaving verifyPrepare(). Nobody by that name holds a password.');
    return { done: { ok: false, reason: 'no-credential',
             detail: 'no ' + PASSWORD_ATTRIBUTE + ' is set for "' + name +
                     '". In product mode a person with no stored credential ' +
                     'cannot sign in — set one from /admin/users, ' +
                     'POST /admin-api/users/set-password, SCIM, or an LDAP ' +
                     'modify' } };
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
    return { done: { ok: false, reason: 'unreadable-credential',
             detail: 'the stored ' + PASSWORD_ATTRIBUTE + ' is not in the ' +
                     'form this service writes, so it cannot be verified' } };
  }

  log.debug('Leaving verifyPrepare(). A comparison is needed.');
  return { stored: stored, name: name, via: via };
}

// The answer, once the comparison has been made in whichever process made it.
function verifyFinish(ok, name, via) {
  log.debug('Entering verifyFinish(). ' + (ok ? 'It matches.' : 'It does not.'));
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
    : { ok: false, reason: 'wrong-password',
        detail: 'the presented password does not match' };
}

function verify(username, password, opts) {
  log.debug('Entering verify().');
  const ready = verifyPrepare(username, password, opts);
  if (ready.done) {
    log.debug('Leaving verify(). Decided without a derivation.');
    return ready.done;
  }
  const ok = crypto.verifySecret(password, ready.stored);
  log.debug('Leaving verify().');
  return verifyFinish(ok, ready.name, ready.via);
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
      return verifyFinish(ok, ready.name, ready.via);
    });
}

// ---------------------------------------------------------------------------
// MAKING ONE UP. The one place this service invents a password, which is the
// same rule the header above states about hashing one.
//
// **32 BYTES OF `randomBytes`, base64url.** Not derived from the username, not
// a word list, and not shortened for typing: this is handed to somebody once
// and then pasted, and a generated credential that is guessable from anything
// on the screen it was shown on is worse than no generator at all.
//
// It has two callers and they are the same act at two moments —
// `bootstrap()` below, which gives a fresh product-mode service a way in, and
// the `generate` option on /admin/users/new, which gives a person one. Both
// SHOW IT ONCE and never again, because what is stored is a scrypt hash: this
// service cannot produce the value a second time, only replace it.
// ---------------------------------------------------------------------------
function generatePassword() {
  return require('crypto').randomBytes(32).toString('base64url');
}

// ---------------------------------------------------------------------------
// SETTING ONE. Hashed HERE rather than by the caller, so that no call site ever
// holds the decision about how — which is the same rule that keeps `crypto.js`
// the one place this service signs.
// ---------------------------------------------------------------------------
function setPassword(username, password) {
  const name = String(username == null ? '' : username).trim();
  log.debug('Entering setPassword(). username=' + name);
  if (!name) {
    log.debug('Leaving setPassword(). No username.');
    return { ok: false, errors: ['Name the person whose password to set.'] };
  }
  if (!password) {
    log.debug('Leaving setPassword(). No password.');
    return { ok: false, errors: ['Give a password. To take one away, remove ' +
                                 'the ' + PASSWORD_ATTRIBUTE + ' attribute ' +
                                 'from the entry.'] };
  }
  if (!directory) {
    log.debug('Leaving setPassword(). No store.');
    return { ok: false, errors: ['No credential store is installed in this ' +
                                 'process, so a password cannot be set.'] };
  }
  let written = false;
  try {
    written = directory.writePassword(name, crypto.hashSecret(password));
  } catch (e) {
    log.error('credentials: writing the password for ' + name + ' threw: ' +
              e.message);
    log.debug('Leaving setPassword(). The store threw.');
    return { ok: false, errors: ['The credential store refused the write: ' +
                                 e.message] };
  }
  if (!written) {
    log.debug('Leaving setPassword(). Nobody by that name.');
    return { ok: false, errors: ['There is nobody called "' + name + '" in ' +
                                 'this realm\'s directory. In product mode ' +
                                 'every referenced object must be created ' +
                                 'ahead of time.'] };
  }
  log.info('credentials: a password was set for ' + name + '. It is stored ' +
           'as a scrypt hash and CANNOT BE READ BACK — this service can never ' +
           'show it again, which is why the caller is given it once and only ' +
           'at the moment it is created.');
  log.debug('Leaving setPassword(). Written.');
  return { ok: true, username: name,
           message: 'The password for ' + name + ' is set. It is stored as a ' +
                    'hash and cannot be shown again.' };
}

// Is there an entry for them at all, credential or not? Asked only by the
// bootstrap, which has to tell "nobody has a password" from "nobody exists".
function hasEntry(username) {
  if (!directory || typeof directory.readPassword !== 'function') return false;
  try {
    // `readPassword()` answers '' both for an absent entry and for one with no
    // credential, so it cannot distinguish them — which is right for a
    // verification and useless here. The store's own creator is idempotent
    // (`createUser()` refuses a name already present), so the bootstrap asks
    // for creation and lets that refusal be the answer rather than testing
    // first. This returns false so the attempt is always made.
    return false;
  } catch (e) {
    return false;
  }
}

// Does this person hold a credential at all? What /admin/users draws beside
// them and what the mode report counts, so that switching to product mode is a
// decision somebody makes knowing how many people it locks out.
function hasPassword(username) {
  if (!directory) return false;
  try {
    return !!directory.readPassword(String(username || '').trim());
  } catch (e) {
    // Reported as "no credential" rather than thrown: this is drawn in a table.
    log.debug('hasPassword(): the store threw: ' + e.message);
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
//   * THE PASSWORD IS 32 BYTES OF `randomBytes`, base64url. Not a fixed default
//     and not derived from anything: a well-known bootstrap password is the
//     single most reliable way into a product, and this service would ship one
//     to every deployment at once.
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
    log.error('credentials: the store could not be asked whether anybody ' +
              'holds a credential, so no bootstrap was attempted: ' + e.message);
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
      log.error('credentials: the bootstrap account "' + username + '" could ' +
                'not be created: ' + e.message);
    }
  }
  const password = generatePassword();
  const written = setPassword(username, password);
  if (!written.ok) {
    log.error('credentials: PRODUCT MODE AND NOBODY CAN SIGN IN. A bootstrap ' +
              'account could not be created: ' +
              (written.errors || []).join(' ') + ' There is no way into this ' +
              'service until a credential is set — start in development mode, ' +
              'provision one, and restart.');
    log.debug('Leaving bootstrap(). The write failed.');
    return { ran: false, why: (written.errors || []).join(' ') };
  }
  log.warn('=======================================================\n' +
           'PRODUCT MODE BOOTSTRAP — THIS IS SHOWN ONCE AND NEVER AGAIN.\n' +
           '\n' +
           '  username: ' + username + '\n' +
           '  password: ' + password + '\n' +
           '\n' +
           'Nobody in this realm\'s directory held a credential, so this one ' +
           'was generated so that the service is reachable. It is stored as a ' +
           'scrypt hash and CANNOT be recovered — only reset.\n' +
           '\n' +
           'CHANGE IT. Sign in at /admin, or POST /admin-api/users/set-password.\n' +
           '=======================================================');
  log.debug('Leaving bootstrap(). An account was created.');
  return { ran: true, username: username };
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
    log.error('credentials: reading the security keys for ' + username +
              ' threw: ' + e.message);
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
  const name = String(username || '').trim();
  log.debug('Entering addKey(). username=' + name + ', role=' + role);
  if (!directory || typeof directory.writeWebauthn !== 'function') {
    return { ok: false, errors: ['No credential store is installed, so a ' +
                                 'security key cannot be recorded.'] };
  }
  if (ROLES.indexOf(String(role)) < 0) {
    return { ok: false, errors: ['A security key is either "primary" (it ' +
                                 'signs somebody in on its own) or "mfa" (it ' +
                                 'is a second factor beside a password). ' +
                                 '"' + role + '" is neither.'] };
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
    log.error('credentials: writing a security key for ' + name + ' threw: ' +
              e.message);
    return { ok: false, errors: ['The credential store refused the write: ' +
                                 e.message] };
  }
  if (!written) {
    return { ok: false, errors: ['There is nobody called "' + name + '" in ' +
                                 'this realm\'s directory.'] };
  }
  log.info('credentials: a security key was enrolled for ' + name +
           ' as a ' + role + ' credential.');
  return { ok: true, username: name, role: role,
           credentialId: record.credentialId };
}

// Update the signature counter after a successful assertion. WebAuthn's replay
// defence: an authenticator's counter only ever goes up, so a counter that went
// backwards is a cloned key. `webauthn.js` performs the CHECK; this records the
// new value so the next assertion has something to check against.
function noteKeyUsed(username, credentialId, signCount) {
  log.debug('Entering noteKeyUsed().');
  if (!directory || typeof directory.replaceWebauthn !== 'function') return false;
  const keys = keysOf(username);
  const found = keys.filter(function (one) {
    return one.credentialId === String(credentialId);
  })[0];
  if (!found) return false;
  found.signCount = Number(signCount || 0);
  found.lastUsedAt = Date.now();
  try {
    return directory.replaceWebauthn(String(username || '').trim(),
      keys.map(function (one) { return JSON.stringify(one); }));
  } catch (e) {
    // The assertion already succeeded; failing to record the counter must not
    // undo it. Logged, because a counter that stops advancing is a replay
    // defence that stops defending.
    log.error('credentials: the signature counter for ' + username +
              ' could not be recorded: ' + e.message);
    return false;
  }
}

function removeKey(username, credentialId) {
  log.debug('Entering removeKey().');
  if (!directory || typeof directory.replaceWebauthn !== 'function') {
    return { ok: false, errors: ['No credential store is installed.'] };
  }
  const name = String(username || '').trim();
  const keys = keysOf(name);
  const kept = keys.filter(function (one) {
    return one.credentialId !== String(credentialId);
  });
  if (kept.length === keys.length) {
    return { ok: false, errors: ['No security key of that id is enrolled for ' +
                                 name + '.'] };
  }
  // **REFUSE TO REMOVE THE LAST WAY IN.** A person whose only credential is
  // this key would be locked out by their own click, and an identity provider
  // that lets somebody do that has a support queue rather than a security
  // control.
  const stillHasPrimary = kept.some(function (one) { return one.role === 'primary'; });
  if (!hasPassword(name) && !stillHasPrimary) {
    return { ok: false, errors: ['That is the only way ' + name + ' can sign ' +
                                 'in — there is no password and no other ' +
                                 'primary security key. Set a password first, ' +
                                 'or enrol another key.'] };
  }
  try {
    directory.replaceWebauthn(name, kept.map(function (one) {
      return JSON.stringify(one);
    }));
  } catch (e) {
    return { ok: false, errors: ['The credential store refused the write: ' +
                                 e.message] };
  }
  log.info('credentials: a security key was removed for ' + name + '.');
  return { ok: true, remaining: kept.length };
}

// ---------------------------------------------------------------------------
// HOW CAN THIS PERSON SIGN IN? The question the sign-in screen, the activation
// flow and the portal all ask, answered once.
//
// `usable` is the whole of it: a person with no password and no PRIMARY key
// cannot authenticate, however many `mfa` keys they hold. That combination is
// reachable — enrol a key as a second factor, then remove the password — and it
// is exactly the lockout `removeKey()` above refuses to create.
// ---------------------------------------------------------------------------
function mechanismsFor(username) {
  const name = String(username || '').trim();
  const keys = keysOf(name);
  const password = hasPassword(name);
  const primaryKeys = keys.filter(function (one) { return one.role === 'primary'; });
  const mfaKeys = keys.filter(function (one) { return one.role === 'mfa'; });
  return {
    username: name,
    password: password,
    primaryKeys: primaryKeys.length,
    mfaKeys: mfaKeys.length,
    keys: keys,
    // Can they get in at all?
    usable: password || primaryKeys.length > 0,
    // Is a second factor required of them? A person holding an `mfa` key is
    // saying their password alone is not enough, so the sign-in screen demands
    // the key as well — which is what makes the flag mean anything.
    mfaRequired: mfaKeys.length > 0,
    // Has this person finished setting themselves up? What product mode asks
    // before it will let an activation link be spent, and what the sign-in
    // screen asks before it refuses somebody with nothing.
    activated: password || keys.length > 0
  };
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
  return Math.max(1, Number(config.value('security.activationTtlMinutes') || 1440)) *
         60 * 1000;
}

// Mint one for somebody. Returns the token IN THE CLEAR exactly once — the
// caller shows it and forgets it, because what is stored is a hash and this
// service can never produce it again.
function issueActivation(username) {
  const name = String(username || '').trim();
  log.debug('Entering issueActivation(). username=' + name);
  if (!name) {
    return { ok: false, errors: ['Name the person to issue a link for.'] };
  }
  if (!directory || typeof directory.writeActivation !== 'function') {
    return { ok: false, errors: ['No credential store is installed, so an ' +
                                 'activation link cannot be issued.'] };
  }
  const token = require('crypto').randomBytes(32).toString('base64url');
  const expires = Date.now() + activationTtlMs();
  let written = false;
  try {
    written = directory.writeActivation(name, crypto.hashSecret(token), expires);
  } catch (e) {
    log.error('credentials: writing an activation token for ' + name +
              ' threw: ' + e.message);
    return { ok: false, errors: ['The credential store refused the write: ' +
                                 e.message] };
  }
  if (!written) {
    return { ok: false, errors: ['There is nobody called "' + name + '" in ' +
                                 'this realm\'s directory. A person is ' +
                                 'provisioned first — through /admin-api, ' +
                                 'SCIM or an LDAP add — and activated after.'] };
  }
  // **THE TOKEN IS NOT LOGGED.** Every other credential event in this file logs
  // that it happened; this one logs that it happened and nothing about what.
  log.info('credentials: an activation link was issued for ' + name +
           ', valid until ' + new Date(expires).toISOString() + '. It is ' +
           'shown to the caller ONCE and stored only as a hash — this service ' +
           'cannot produce it again, only replace it.');
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
  const name = String(username || '').trim();
  log.debug('Entering checkActivation(). username=' + name);
  if (!name || !token) {
    return { ok: false, reason: 'incomplete' };
  }
  if (!directory || typeof directory.readActivation !== 'function') {
    return { ok: false, reason: 'no-store' };
  }
  let held = null;
  try {
    held = directory.readActivation(name);
  } catch (e) {
    log.error('credentials: reading the activation token for ' + name +
              ' threw: ' + e.message);
    return { ok: false, reason: 'store-error' };
  }
  if (!held || !held.hash) {
    return { ok: false, reason: 'none-issued' };
  }
  if (held.expires && held.expires <= Date.now()) {
    return { ok: false, reason: 'expired', expired: true };
  }
  if (!crypto.verifySecret(token, held.hash)) {
    return { ok: false, reason: 'mismatch' };
  }
  return { ok: true, reason: 'valid', expires: held.expires };
}

// Spend it. Called when the setup FINISHES, not when the link is opened — a
// link consumed on opening would strand anybody whose browser prefetched it or
// who reloaded the page.
function consumeActivation(username) {
  log.debug('Entering consumeActivation(). username=' + username);
  if (!directory || typeof directory.writeActivation !== 'function') return false;
  try {
    directory.writeActivation(String(username || '').trim(), '', 0);
  } catch (e) {
    log.error('credentials: the activation token for ' + username +
              ' could not be cleared: ' + e.message);
    return false;
  }
  log.info('credentials: the activation link for ' + username + ' was spent ' +
           'and is now invalid.');
  return true;
}

// Is one outstanding? What /admin/users draws beside somebody who cannot yet
// sign in, so an operator can tell "never activated" from "link already sent".
function activationPending(username) {
  if (!directory || typeof directory.readActivation !== 'function') return null;
  try {
    const held = directory.readActivation(String(username || '').trim());
    if (!held || !held.hash) return null;
    return { expires: held.expires,
             expired: !!(held.expires && held.expires <= Date.now()) };
  } catch (e) {
    return null;
  }
}

module.exports = {
  issueActivation: issueActivation,
  checkActivation: checkActivation,
  consumeActivation: consumeActivation,
  activationPending: activationPending,
  WEBAUTHN_ATTRIBUTE: WEBAUTHN_ATTRIBUTE,
  ROLES: ROLES,
  keysOf: keysOf,
  addKey: addKey,
  removeKey: removeKey,
  noteKeyUsed: noteKeyUsed,
  mechanismsFor: mechanismsFor,
  bootstrap: bootstrap,
  PASSWORD_ATTRIBUTE: PASSWORD_ATTRIBUTE,
  RESERVED_REFUSAL: RESERVED_REFUSAL,
  setDirectory: setDirectory,
  storable: storable,
  verify: verify,
  verifyAsync: verifyAsync,
  setPassword: setPassword,
  generatePassword: generatePassword,
  hasPassword: hasPassword
};
