// @ts-check
// ---------------------------------------------------------------------------
// ssf/account_signals.js — WHAT A CREDENTIAL CHANGE SAYS OVER SHARED SIGNALS,
// FOR THE DOORS THAT MAKE ONE (2026-09-13).
//
// The administrator's controls on a person's /admin/users page (and the same
// actions on /admin-api/users) reset passwords, issue reset links, and take
// security keys, authenticator apps and recovery codes off an entry; the user
// portal's /portal/reset-password sets the password a link was for. Each of
// those is a CAEP `credential-change`, and a password reset or a cleared set of
// recovery codes is also a RISC event. `ssf/ssf.js` is what turns them into
// Security Event Tokens — `emitCredentialChange()` and `emitRiscAccountAct()`.
//
// **THIS FILE EXISTS BECAUSE THOSE DOORS CANNOT REQUIRE `ssf/ssf.js`.** The
// console's actions are at 18 in the require order, the portal just after
// `authn` (8), and SSF at 23b: a require from either would register every
// `/ssf` route ahead of theirs (rule 1) and close a cycle through
// `admin-ui/admin.js`. So this is a LIBRARY that requires nothing but the
// logger, and it reads `ssf.js` out of `require.cache` at the moment an event
// is due — which, in a running service, is always after the whole stack has
// loaded. A process that never loaded SSF (an in-process test, the parent
// project's Kerberos jobs) gets a no-op, and is told so in the answer rather
// than by a thrown `Cannot find module`.
//
// **NOT A SLOT, AND RULE 3e'S TEST SAYS WHY.** A slot is the price of a require
// that would close a cycle or move a route; there is no require here at all,
// only a cache lookup, which is the arrangement
// `admin-core/protocol_endpoints.js` uses for route-registering modules it
// must never load.
//
// **NOTHING HERE WAITS AND NOTHING HERE THROWS.** Every function returns a
// promise that resolves, and callers do not await it: a receiver's endpoint
// being slow must not hold up a page, and a failure must not undo a credential
// change that has already been written.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');

function loadedSsf() {
  log.debug('Entering loadedSsf().');
  let id = '';
  try {
    id = require.resolve('./ssf');
  } catch (e) {
    log.debug('Caught in loadedSsf(): ' + ((e && e.message) || e));
    log.debug('Leaving loadedSsf(). Not resolvable.');
    return null;
  }
  const cached = require.cache[id];
  log.debug('Leaving loadedSsf(). ' + (cached ? 'Loaded.' : 'Not loaded.'));
  return cached && cached.exports ? cached.exports : null;
}

// Hand one call to ssf.js, swallowing everything, so a caller can fire and
// forget. `what` names the call for the log.
function deliver(what, name, notice) {
  log.debug('Entering deliver(). ' + what);
  const ssf = loadedSsf();
  if (!ssf || typeof ssf[name] !== 'function') {
    log.debug('Leaving deliver(). Shared Signals is not loaded in this ' +
              'process, so nothing is sent.');
    return Promise.resolve({ sent: 0, streams: 0, why: 'ssf not loaded' });
  }
  let answer;
  try {
    answer = Promise.resolve(ssf[name](notice));
  } catch (e) {
    log.warn('account signals: ' + what + ' threw and nothing was sent: ' +
             ((e && e.message) || e));
    log.debug('Leaving deliver(). Threw.');
    return Promise.resolve({ sent: 0, streams: 0, why: String(e.message) });
  }
  log.debug('Leaving deliver(). Handed over.');
  return answer.catch(function (e) {
    log.warn('account signals: ' + what + ' failed and nothing more is ' +
             'sent: ' + ((e && e.message) || e));
    return { sent: 0, streams: 0, why: String((e && e.message) || e) };
  });
}

// CAEP credential-change. `change` is `{ username, credentialType, changeType,
// friendlyName, initiatingEntity, reasonAdmin, reasonUser, via }`.
function credentialChanged(change) {
  log.debug('Entering credentialChanged().');
  log.debug('Leaving credentialChanged().');
  return deliver('a CAEP credential-change', 'emitCredentialChange',
                 change || {});
}

// RISC account-credential-change-required: a password was reset for somebody
// or a reset link issued, so what they held is no longer trusted.
function credentialChangeRequired(notice) {
  log.debug('Entering credentialChangeRequired().');
  log.debug('Leaving credentialChangeRequired().');
  return deliver('a RISC account-credential-change-required',
                 'emitRiscAccountAct',
                 Object.assign({}, notice || {},
                               { act: 'credentialChangeRequired' }));
}

// RISC recovery-information-changed: somebody's recovery codes were cleared.
function recoveryInformationChanged(notice) {
  log.debug('Entering recoveryInformationChanged().');
  log.debug('Leaving recoveryInformationChanged().');
  return deliver('a RISC recovery-information-changed', 'emitRiscAccountAct',
                 Object.assign({}, notice || {}, { act: 'recoveryChanged' }));
}

// A security key, in CAEP's credential-type vocabulary. The record keeps no
// authenticator attachment, so a key cannot be told apart as platform or
// roaming after the fact; `fido2-roaming` is the reading that is true of every
// security key this service's ceremony enrols by default, and the label goes
// out as `friendly_name` so a receiver can tell two keys apart.
const KEY_CREDENTIAL_TYPE = 'fido2-roaming';
// An authenticator app, in the same vocabulary: CAEP's `app`.
const TOTP_CREDENTIAL_TYPE = 'app';

module.exports = {
  credentialChanged: credentialChanged,
  credentialChangeRequired: credentialChangeRequired,
  recoveryInformationChanged: recoveryInformationChanged,
  KEY_CREDENTIAL_TYPE: KEY_CREDENTIAL_TYPE,
  TOTP_CREDENTIAL_TYPE: TOTP_CREDENTIAL_TYPE
};
