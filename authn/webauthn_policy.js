// File: webauthn_policy.js
//
// ---------------------------------------------------------------------------
// THE WEBAUTHN CEREMONY'S OPTIONS, AND WHAT THIS SERVICE WILL DO WITH A KEY
// (2026-09-10).
//
// **THIS IS RULE 3: A LIBRARY.** It registers no route, so its position in the
// require order is not a position. It requires `common/config`,
// `common/helpers` and `./webauthn` — the last of which requires npm leaves and
// `common/crypto` — so it cannot join a cycle and nothing that requires it
// moves a route.
//
// ---------------------------------------------------------------------------
// WHY IT IS NOT IN `authn/webauthn.js` NEXT DOOR, WHICH IS THE OBVIOUS PLACE.
//
// That file is deliberately loadable ON ITS OWN. The debugger's
// `tests/webauthn_cross_impl.js` copies it — one file, beside its own scripts —
// and runs it against the same real ceremonies its browser-side implementation
// verifies, because two independent readings of one specification that agree is
// a real result and one implementation agreeing with itself is none. Its own
// header says so, and its `require('../common/helpers')` is inside a try/catch
// for exactly that reason.
//
// A `require('../common/config')` in there would end that. Not loudly: the same
// try/catch would swallow it and the module would go on verifying, with a
// settings function that silently answered defaults in the one place a reader
// would trust it. So the settings live here and the verifier stays a verifier.
//
// ---------------------------------------------------------------------------
// WHY IT IS NOT IN `authn/authn.js`, WHICH IS THE OTHER OBVIOUS PLACE.
//
// `admin-ui/crypto_metadata.js` (20a) and `admin-ui/admin.js` (18) both need
// the report, and `authn/authn.js` is 8 — requiring it from either would be
// requiring a module that is already loaded, which is harmless, but it would
// also mean the console reaching into the sign-in service for a table of
// algorithms. The rule `/admin/crypto-metadata` is built on is that an
// algorithm table is read FROM THE MODULE THAT PERFORMS THE ALGORITHM; this
// module is the one that decides the ceremony's parameters, so it is the one
// that reports them.
//
// ---------------------------------------------------------------------------
// THREE KINDS OF SETTING AND THE DIFFERENCE MATTERS AT EVERY CALL SITE.
//
//   * **CEREMONY** — handed to the browser in the options and no more. This
//     service cannot make a browser honour any of them.
//   * **CTAP2** — also handed to the browser, and translated by it into what
//     it asks the authenticator for. Same standing: a request, not a check.
//   * **POLICY** — `enabled`, `primaryAllowed`, `mfaAllowed`,
//     `maxKeysPerPerson`. Not WebAuthn at all. These are enforced HERE, by the
//     callers below, and they are the only four in this file that refuse
//     anything.
//
// **ONE CEREMONY SETTING IS ALSO ENFORCED AND IT IS THE ONE THAT COULD BE.**
// `userVerification: 'required'` is sent to the browser AND checked against the
// UV flag in the authenticator data when the ceremony comes back, because that
// flag is IN the signed bytes — so it is a claim this service can verify rather
// than a preference it can only express. `attestation`, `residentKey` and
// `authenticatorAttachment` have no equivalent: nothing signed says what the
// browser was asked for, so a check would be a comparison against a value this
// service itself supplied.
// ---------------------------------------------------------------------------

'use strict';

const config = require('../common/config');
const { log } = require('../common/helpers');
const webauthn = require('./webauthn');
// The error codes. A LEAF that requires nothing, so it cannot close a cycle
// from here. A refusal this module RETURNS carries its code non-enumerably,
// under the Symbol `mark()` uses, so a caller's `errorCodes.codeOf()` reads it
// and nothing that serialises the answer can send it anywhere.
const errorCodes = require('../common/error_codes');

// JOSE spelling -> COSE identifier, INVERTED from the verifier's own table
// rather than written out. That table is what decides whether a signature can
// be checked at all, so deriving the offer from it is what stops this service
// asking a browser for an algorithm it would then refuse to verify — a
// credential that enrols perfectly and never works again.
const ALG_IDS = {};
Object.keys(webauthn.COSE_ALGS).forEach(function (id) {
  ALG_IDS[webauthn.COSE_ALGS[id]] = Number(id);
});

// The order the default is written in, used when a caller's list leaves nothing
// usable. It is ES256 then RS256 because those are the two every authenticator
// implements and the two `pubKeyCredParams` was hardcoded to before any of this
// was settable.
const FALLBACK_ALGS = ['ES256', 'RS256'];

// ---------------------------------------------------------------------------
// THE SETTINGS, READ IN ONE PLACE.
//
// Every one through `config.value()`, which answers out of the AMBIENT REALM —
// so one realm may demand user verification and require a resident key while
// another asks for neither, and neither had to be told about the other. That
// falls out of the realm design rather than being arranged here.
//
// Unlike `totp.settings()`, **NOTHING HERE IS COPIED ONTO A CREDENTIAL AND
// FROZEN**. A TOTP secret is verified with the digits and period the QR code
// told the app, so changing the setting must not invalidate an existing
// enrolment. A WebAuthn assertion carries its own algorithm in the credential's
// stored public key and its own RP ID hash in the signed bytes, so there is
// nothing for a later setting to contradict — every row below applies to the
// NEXT ceremony and to every existing key alike.
// ---------------------------------------------------------------------------
function settings() {
  log.debug('Entering webauthn_policy settings().');
  const attachment = String(config.value('webauthn.authenticatorAttachment') ||
                            'any');
  const out = {
    enabled: config.value('webauthn.enabled') !== false,
    rpName: String(config.value('webauthn.rpName') || 'Mock authorization ' +
                                                      'server'),
    rpId: String(config.value('webauthn.rpId') || '').trim(),
    algorithms: algorithmsOffered(),
    userVerification: oneOf(config.value('webauthn.userVerification'),
                            ['discouraged', 'preferred', 'required'],
                            'preferred'),
    attestation: oneOf(config.value('webauthn.attestation'),
                       ['none', 'indirect', 'direct', 'enterprise'], 'direct'),
    timeoutMs: clamp(config.value('webauthn.timeoutMs'), 10000, 600000, 60000),
    // `any` is carried as the empty string on the way out, because the options
    // dictionary's absent member and its "no preference" value are the same
    // thing to a browser and there is no third state to represent.
    authenticatorAttachment: oneOf(attachment,
                                   ['any', 'platform', 'cross-platform'],
                                   'any'),
    residentKey: oneOf(config.value('webauthn.residentKey'),
                       ['discouraged', 'preferred', 'required'], 'discouraged'),
    credProps: config.value('webauthn.credProps') !== false,
    primaryAllowed: config.value('webauthn.primaryAllowed') !== false,
    mfaAllowed: config.value('webauthn.mfaAllowed') !== false,
    maxKeysPerPerson: clamp(config.value('webauthn.maxKeysPerPerson'), 1, 50,
                            10)
  };
  log.debug('Leaving webauthn_policy settings(). uv=' + out.userVerification +
            ', ' + out.algorithms.length + ' algorithm(s).');
  return out;
}

function oneOf(value, allowed, dflt) {
  log.debug("Entering oneOf().");
  const wanted = String(value == null ? '' : value);
  log.debug("Leaving oneOf().");
  return allowed.indexOf(wanted) >= 0 ? wanted : dflt;
}

function clamp(value, low, high, dflt) {
  log.debug("Entering clamp().");
  const n = Number(value);
  if (!Number.isFinite(n)) {
    log.debug("Leaving clamp().");
    return dflt;
  }
  log.debug("Leaving clamp().");
  return Math.max(low, Math.min(high, n));
}

// The offered algorithms, as JOSE names, filtered against what the verifier can
// actually check. A name outside that table is DROPPED WITH A WARNING rather
// than passed through: `pubKeyCredParams` naming an algorithm this service
// cannot verify produces a credential that registers, is stored, and then fails
// every assertion it is ever used for — with the failure landing at sign-in
// rather than at enrolment, which is the worst possible place for it.
function algorithmsOffered() {
  log.debug('Entering algorithmsOffered().');
  const asked = config.value('webauthn.algorithms');
  const list = (Array.isArray(asked) ? asked : String(asked || '').split(','))
    .map(function (name) { return String(name || '').trim(); })
    .filter(Boolean);
  const kept = [];
  list.forEach(function (name) {
    if (ALG_IDS[name] === undefined) {
      log.warn('webauthn: "' + name + '" is not an algorithm this service ' +
               'can verify, so it is NOT being offered to browsers. The ones ' +
               'it knows ' +
               'are ' + Object.keys(ALG_IDS).join(', ') + '. Offering ' +
               'one it cannot check would enrol a credential that never ' +
               'works again.');
      return;
    }
    if (kept.indexOf(name) < 0) {
      kept.push(name);
    }
  });
  if (!kept.length) {
    // NOT an empty list. `pubKeyCredParams: []` is a registration the browser
    // refuses outright, with an error the ceremony reports as one of its
    // several indistinguishable failures — so a typo in one setting would look
    // like a broken authenticator. The default is the safe answer and the
    // warning is how somebody finds out.
    log.warn('webauthn: webauthn.algorithms named nothing this service can ' +
             'verify, so the ceremony is offering ' +
             FALLBACK_ALGS.join(' and ') +
             ' instead. An empty pubKeyCredParams is refused by the browser ' +
             'and would look like a hardware failure.');
    log.debug('Leaving algorithmsOffered(). Fell back.');
    return FALLBACK_ALGS.slice();
  }
  log.debug('Leaving algorithmsOffered(). ' + kept.length + ' offered.');
  return kept;
}

// The COSE identifiers for `pubKeyCredParams`, in the order the names were
// given. Separate from `algorithms` above because the page wants the names and
// the ceremony wants the numbers, and computing either from the other at two
// call sites is how the two come to disagree.
function algorithmIds() {
  log.debug("Entering algorithmIds().");
  log.debug("Leaving algorithmIds().");
  return algorithmsOffered().map(function (name) { return ALG_IDS[name]; });
}

// Is the mechanism offered at all? Read at every door rather than only on the
// page that draws the button, for the reason `authn.js` gives about
// `authn.unauthenticatedSessions` and `totp.js` repeats: a page is markup and
// an endpoint is a door, and a form posted by hand while the setting is off
// must not enrol anybody.
function offered() {
  log.debug("Entering offered().");
  log.debug("Leaving offered().");
  return settings().enabled;
}

// May a key be enrolled in this role? ONE function for both roles rather than
// two predicates, so that a caller cannot check the wrong one — `roleAllowed`
// takes the role it is about to write, which is the same string
// `credentials.addKey()` will be handed.
//
// **IT ANSWERS ABOUT ENROLMENT AND NEVER ABOUT AUTHENTICATION.** A key already
// enrolled in a role that has since been turned off goes on working, for
// `webauthn.enabled`'s reason: an account configured for two factors is still
// configured for two, and a setting that silently downgraded it would be a
// security control whose off switch does something other than what it says.
// Worse for `primary`, where the person's ONLY credential would be the one
// being switched off — an operator moving a knob must not be able to lock
// somebody out of their own account.
function roleAllowed(role) {
  log.debug('Entering roleAllowed(). role=' + role);
  const live = settings();
  if (!live.enabled) {
    log.debug('Leaving roleAllowed(). WebAuthn is not offered here.');
    return errorCodes.mark({ ok: false,
             why: 'Security keys are switched off in this realm ' +
                  '(webauthn.enabled). A key already enrolled goes on ' +
                  'working; no new one can be enrolled.' }, 'STS-AUTHN-0044');
  }
  if (String(role) === 'primary' && !live.primaryAllowed) {
    log.debug('Leaving roleAllowed(). Primary keys are not allowed here.');
    return errorCodes.mark({ ok: false,
             why: 'A security key cannot be the only credential on an ' +
                  'account in this realm (webauthn.primaryAllowed). Enrol it ' +
                  'as a second factor beside a password ' +
                  'instead.' }, 'STS-AUTHN-0045');
  }
  if (String(role) === 'mfa' && !live.mfaAllowed) {
    log.debug('Leaving roleAllowed(). Second-factor keys are not allowed ' +
              'here.');
    return errorCodes.mark({ ok: false,
             why: 'A security key cannot be a second factor in this realm ' +
                  '(webauthn.mfaAllowed). An authenticator app is the other ' +
                  'one, where totp.enabled is on.' }, 'STS-AUTHN-0046');
  }
  log.debug('Leaving roleAllowed(). Allowed.');
  return { ok: true };
}

// ---------------------------------------------------------------------------
// WHICH CHECK A CEREMONY FAILED, AS AN ERROR CODE (2026-09-12).
//
// `authn/webauthn.js` names every check it makes and reports the ones that
// failed, in order. It cannot carry a code itself: it is copied, one file, into
// the debugger's cross-implementation test, where `../common/error_codes` does
// not exist. So the mapping from its check NAMES to codes lives here, beside
// the verifier's other policy, and both ceremony doors — the sign-in screen and
// `credentials.confirmKeyEnrolment()` — ask it. The FIRST failed check decides,
// because the verifier lists them in the order a relying party makes them.
//
// A name this table does not know answers the generic code rather than
// nothing, so a check added to the verifier still reaches the log with a code
// — one that says the table is behind.
// ---------------------------------------------------------------------------
const FAILED_CHECK_CODES = {
  'clientData.type is webauthn.create': 'STS-AUTHN-0028',
  'clientData.type is webauthn.get': 'STS-AUTHN-0028',
  'challenge matches': 'STS-AUTHN-0029',
  'origin matches': 'STS-AUTHN-0030',
  'rpIdHash is SHA-256 of the RP ID': 'STS-AUTHN-0031',
  'user presence': 'STS-AUTHN-0032',
  'user verification': 'STS-AUTHN-0033',
  'attested credential data present': 'STS-AUTHN-0034',
  'signature counter advanced': 'STS-AUTHN-0035',
  'signature verifies': 'STS-AUTHN-0036'
};

function failureCodeFor(verdict) {
  log.debug("Entering failureCodeFor().");
  const failed = (verdict && Array.isArray(verdict.failed)) ? verdict.failed :
                  [];
  for (let i = 0; i < failed.length; i++) {
    if (FAILED_CHECK_CODES[failed[i]]) {
      log.debug("Leaving failureCodeFor().");
      return FAILED_CHECK_CODES[failed[i]];
    }
  }
  log.debug("Leaving failureCodeFor().");
  return 'STS-AUTHN-0037';
}

// ---------------------------------------------------------------------------
// THE OPTIONS, AS THE BROWSER RECEIVES THEM.
//
// Built here and handed to the page as ONE JSON object on a data attribute,
// rather than as eleven attributes the script picks apart. Two reasons, and the
// second is the load-bearing one:
//
//   * The script is a STATIC RESOURCE (`/authn/webauthn.js`), served under
//     `script-src 'self'` — see `app.js` and the six-scripted-pages rule. It
//     cannot be generated per request, so everything that varies has to travel
//     as data.
//   * **A DICTIONARY THE SERVER BUILT IS ONE PLACE TO GET IT WRONG.** Eleven
//     attributes read one at a time is eleven chances for the script to coerce
//     a value differently from the way this file meant it — `"false"` being
//     truthy is the classic — and none of them would fail loudly. What the
//     script does now is `JSON.parse` and pass it on.
//
// **NOTHING SECRET IS IN IT AND NOTHING IN IT IS TRUSTED ON THE WAY BACK.**
// The options are a REQUEST to the browser; every security property of the
// ceremony is checked against the pending step and the origin when the result
// arrives — see `verifyRegistration()` and `verifyAssertion()`. A person who
// edits this attribute in the developer tools changes what their own browser
// is asked for and nothing about what this service will accept.
// ---------------------------------------------------------------------------
function creationOptions(rpId) {
  log.debug('Entering creationOptions(). rpId=' + rpId);
  const live = settings();
  const out = {
    rp: { name: live.rpName, id: rpId },
    algorithms: algorithmIds(),
    attestation: live.attestation,
    timeout: live.timeoutMs,
    authenticatorSelection: {
      userVerification: live.userVerification,
      residentKey: live.residentKey,
      // WebAuthn Level 3 keeps `requireResidentKey` for Level 1 clients and
      // says it MUST be true exactly when `residentKey` is `required`. Sent
      // rather than omitted, because the browsers that still read it are the
      // ones that would otherwise ignore the modern member entirely.
      requireResidentKey: live.residentKey === 'required'
    },
    credProps: live.credProps
  };
  // ABSENT AND NOT `"any"`. The options dictionary has no value meaning "no
  // preference" — the member is simply not there — and sending the string
  // `"any"` is a validation error in the browser rather than a wide filter.
  if (live.authenticatorAttachment !== 'any') {
    out.authenticatorSelection.authenticatorAttachment =
        live.authenticatorAttachment;
  }
  log.debug('Leaving creationOptions(). attestation=' + out.attestation);
  return out;
}

function requestOptions(rpId) {
  log.debug('Entering requestOptions(). rpId=' + rpId);
  const live = settings();
  const out = {
    rpId: rpId,
    userVerification: live.userVerification,
    timeout: live.timeoutMs
  };
  log.debug('Leaving requestOptions(). uv=' + out.userVerification);
  return out;
}

// Does this ceremony have to have verified the PERSON? What `authn/webauthn.js`
// is handed as `requireUserVerification`, and the one ceremony setting that
// becomes a CHECK rather than a request — see the header.
function requireUserVerification() {
  log.debug("Entering requireUserVerification().");
  log.debug("Leaving requireUserVerification().");
  return settings().userVerification === 'required';
}

// ---------------------------------------------------------------------------
// WHAT `/admin/webauthn` AND `/admin/crypto-metadata` DRAW. Read from this
// module and from the verifier beside it rather than written down over there,
// which is that page's whole design: the algorithm table lives with the code
// that performs the algorithm, so the report cannot describe something this
// service does not do.
// ---------------------------------------------------------------------------
function report() {
  log.debug('Entering webauthn_policy report().');
  const live = settings();
  const out = {
    offered: live.enabled,
    rpName: live.rpName,
    rpId: live.rpId,
    rpIdSource: live.rpId ? 'configured' : 'the host this service was ' +
                                           'reached on',
    // EVERY algorithm the verifier knows, with the ones being offered marked —
    // rather than only the offered ones. A page that listed two rows could not
    // answer the question somebody comes to it with, which is *what else could
    // I ask for*.
    algorithms: Object.keys(webauthn.COSE_ALGS).map(function (id) {
      const name = webauthn.COSE_ALGS[id];
      return { name: name, coseAlg: Number(id),
               offered: live.algorithms.indexOf(name) >= 0 };
    }),
    curves: Object.keys(webauthn.COSE_CURVES).map(function (id) {
      return { name: webauthn.COSE_CURVES[id], coseCurve: Number(id) };
    }),
    userVerification: live.userVerification,
    userVerificationEnforced: live.userVerification === 'required',
    attestation: live.attestation,
    attestationVerified: false,
    attestationFormats: ['packed', 'none', 'fido-u2f'],
    timeoutMs: live.timeoutMs,
    authenticatorAttachment: live.authenticatorAttachment,
    residentKey: live.residentKey,
    credProps: live.credProps,
    primaryAllowed: live.primaryAllowed,
    mfaAllowed: live.mfaAllowed,
    maxKeysPerPerson: live.maxKeysPerPerson,
    signatureCounter: 'checked — an authenticator\'s counter only ever goes ' +
                      'up, so one that went backwards is a cloned key.',
    clientDataHash: 'SHA-256 over clientDataJSON, concatenated after ' +
                    'authenticatorData and signed by the authenticator.'
  };
  log.debug('Leaving webauthn_policy report(). ' + out.algorithms.length +
            ' algorithm(s) known.');
  return out;
}

module.exports = {
  settings,
  offered,
  roleAllowed,
  algorithmsOffered,
  algorithmIds,
  creationOptions,
  requestOptions,
  requireUserVerification,
  report,
  failureCodeFor,
  // The JOSE-name-to-COSE-identifier map, exported for the tests that assert
  // the offer cannot name something the verifier does not know. DATA, like the
  // two tables it is derived from.
  ALG_IDS
};
