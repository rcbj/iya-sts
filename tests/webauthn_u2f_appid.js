// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/webauthn_u2f_appid.js
//
// ===========================================================================
// LEGACY FIDO U2F CREDENTIALS: THE IMPORT, THE appid EXTENSION AND
// appidExclude (#1955 P7, rcbj's reversal of the issue's D5).
//
//   U1. THE SETTING: `webauthn.u2fAppIds` is empty by default; its write
//       rule refuses anything that is not an https AppID (STS-AUTHN-0566);
//       an AppID relates to an RP ID only on its host or a dot-suffix.
//   U2. THE IMPORT, OFF: with the setting empty nothing is importable
//       (STS-AUTHN-0561), and the act names nobody without `user`
//       (STS-ADMIN-0951).
//   U3. THE IMPORT, ON: a bad key handle (STS-AUTHN-0562), a public key
//       that is no P-256 point (STS-AUTHN-0563) and a counter out of range
//       (STS-AUTHN-0564) are refused; a good one becomes a key on the entry
//       marked with its AppID, its counter, ES256 and not discoverable, and
//       the same key handle again is a duplicate (STS-AUTHN-0095). The
//       console's act (`import-u2f-key`) does the same and audits it.
//   U4. THE EXTENSION IN THE OPTIONS: a request names the AppID only where
//       it is permitted at the RP ID; a registration asks `appidExclude`
//       only where an AppID is permitted; the runtime makes `extensions` of
//       both; none of it with the setting off.
//   U5. THE HASH RULE, BOTH WAYS: a U2F-style assertion over SHA-256 of the
//       AppID verifies for an imported key ONLY when the client says it
//       used the appid extension; without that it is held to the RP ID and
//       fails; and a key registered here is held to the RP ID even when the
//       client claims appid true.
//   U6. ONE BUILDER AND ONE SET OF EXPECTATIONS (`assertionOptions()`,
//       `assertionExpectations()`): a ceremony naming the U2F key asks
//       `appid` and `preferred` UV, one naming only a key registered here is
//       `requestOptions()` byte for byte (the portal's device link, whose
//       linkable keys are never roaming U2F keys); a passwordless use and an
//       AppID no longer permitted are refused (STS-AUTHN-0565).
//   U7. EACH SURFACE THAT ASSERTS A KEY, through those two: the sign-in
//       screen's passkey step (which every re-authentication, step-up,
//       consent, GNAP interaction and the portal reach), a passwordless step
//       (a registration with appidExclude instead), a post-login upgrade's
//       proof, and the console's upgrade proof.
//   U8. A RE-AUTHENTICATION END TO END: the console's upgrade proof
//       (`credentials.proveKeyUpgrade()`, the one verifier of both upgrade
//       proofs) by the imported key is refused without `appid: true` and
//       accepted with it.
//
// IN PROCESS, in a realm created and removed here.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const credentials = require('../common/credentials');
const ldap = require('../ldap/ldap_server');
const webauthnPolicy = require('../authn/webauthn_policy');
const webauthn = require('../authn/webauthn');
const WebWebAuthn = require('../common/web_webauthn');
const adminActions = require('../admin-core/admin_actions');

const log = require('bunyan').createLogger({ name: 'webauthn_u2f_appid',
  level: process.env.LOG_LEVEL || 'info' });

const RP_ID = 'localhost';
const APP_ID = 'https://localhost/u2f/app-id.json';
const ORIGIN = 'https://localhost:8081';

/**
 * A U2F key: a P-256 pair, a key handle, and its public key as the
 * uncompressed point a U2F relying party kept.
 *
 * @returns {object} the key
 */
function u2fKey() {
  log.debug('Entering u2fKey().');
  const pair = nodeCrypto.generateKeyPairSync('ec',
                                              { namedCurve: 'prime256v1' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const point = Buffer.concat([Buffer.from([0x04]),
                               Buffer.from(jwk.x, 'base64url'),
                               Buffer.from(jwk.y, 'base64url')]);
  log.debug('Leaving u2fKey().');
  return { pair: pair, jwk: jwk,
           handle: nodeCrypto.randomBytes(64).toString('base64url'),
           point: point.toString('base64url') };
}

/**
 * An assertion as a client running a U2F key through WebAuthn makes it:
 * the authenticator data over SHA-256 of `hashed` (the AppID, or the RP
 * ID), UP set, the counter, and an ES256 signature.
 *
 * @param {object} key - the key from `u2fKey()`
 * @param {string} hashed - what the rpIdHash is the SHA-256 of
 * @param {number} counter - the signature counter
 * @returns {object} the verifier's input, less its expectations
 */
function assertion(key, hashed, counter) {
  log.debug('Entering assertion().');
  const count = Buffer.alloc(4);
  count.writeUInt32BE(counter, 0);
  const authData = Buffer.concat([
    nodeCrypto.createHash('sha256').update(hashed, 'utf8').digest(),
    Buffer.from([0x01]), count]);
  const challenge = nodeCrypto.randomBytes(32).toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: 'webauthn.get', challenge: challenge, origin: ORIGIN }));
  const signature = nodeCrypto.sign('sha256', Buffer.concat([
    authData, nodeCrypto.createHash('sha256').update(clientDataJSON)
      .digest()]), key.pair.privateKey);
  log.debug('Leaving assertion().');
  return { authenticatorData: authData.toString('base64url'),
           clientDataJSON: clientDataJSON.toString('base64url'),
           signature: signature.toString('base64url'),
           expectedChallenge: challenge, expectedOrigin: ORIGIN,
           expectedRpId: RP_ID, requireUserVerification: false };
}

/**
 * U1: the setting, its rule and the RP ID relation.
 *
 * @param {object} t - the test context
 * @returns {void}
 */
function setting(t) {
  log.debug('Entering setting().');
  const rule = function (value) {
    log.debug('Entering setting() rule().');
    const out = webauthnPolicy.WebauthnPolicy.u2fAppIdWriteRule(
      'webauthn.u2fAppIds', value);
    log.debug('Leaving setting() rule().');
    return out ? out.code : '';
  };
  t.check(webauthnPolicy.legacyAppIds().length === 0 &&
          rule('http://u2f.example.com/app') === 'STS-AUTHN-0566' &&
          rule('https://u2f.example.com/app#frag') === 'STS-AUTHN-0566' &&
          rule('https://user:pw@u2f.example.com/') === 'STS-AUTHN-0566' &&
          rule('not a url') === 'STS-AUTHN-0566' &&
          rule(APP_ID + ',https://u2f.example.com/app') === '' &&
          rule('') === '',
          'U1. empty by default, and only https AppIDs may be listed ' +
          '(STS-AUTHN-0566)', String(webauthnPolicy.legacyAppIds()));
  t.check(webauthnPolicy.appIdRelatesTo('https://u2f.example.com/a',
                                        'example.com') &&
          webauthnPolicy.appIdRelatesTo('https://example.com/a',
                                        'sts.example.com') &&
          webauthnPolicy.appIdRelatesTo(APP_ID, RP_ID) &&
          !webauthnPolicy.appIdRelatesTo('https://example.org/a',
                                         'example.com') &&
          !webauthnPolicy.appIdRelatesTo('https://badexample.com/a',
                                         'example.com'),
          'U1b. an AppID relates to an RP ID on its host or a dot-suffix, ' +
          'never on a bare string suffix', '');
  log.debug('Leaving setting().');
}

/**
 * U2: the import while the setting is empty.
 *
 * @param {object} t - the test context
 * @param {string} name - the person
 * @param {object} key - a U2F key
 * @returns {void}
 */
function importOff(t, name, key) {
  log.debug('Entering importOff().');
  const off = credentials.importU2fKey(name, { keyHandle: key.handle,
    publicKey: key.point, appId: APP_ID, counter: 3 });
  const nobody = adminActions.usersAction({ action: 'import-u2f-key',
    keyHandle: key.handle, publicKey: key.point, appId: APP_ID },
                                          { via: 'api', actor: 'tester' });
  t.check(off.ok === false && errorCodes.codeOf(off) === 'STS-AUTHN-0561' &&
          nobody.ok === false &&
          errorCodes.codeOf(nobody) === 'STS-ADMIN-0951' &&
          credentials.keysOf(name).length === 0,
          'U2. with webauthn.u2fAppIds empty nothing is imported ' +
          '(STS-AUTHN-0561), and the act needs a person (STS-ADMIN-0951)',
          JSON.stringify([off.errors, nobody.errors]));
  log.debug('Leaving importOff().');
}

/**
 * U3: the import while the AppID is permitted.
 *
 * @param {object} t - the test context
 * @param {string} name - the person
 * @param {object} key - a U2F key
 * @returns {object} the stored key
 */
function importOn(t, name, key) {
  log.debug('Entering importOn().');
  const one = function (fields) {
    log.debug('Entering importOn() one().');
    log.debug('Leaving importOn() one().');
    return credentials.importU2fKey(name, Object.assign({
      keyHandle: key.handle, publicKey: key.point, appId: APP_ID,
      counter: 7 }, fields));
  };
  const badHandle = one({ keyHandle: 'not base64!' });
  const longHandle = one({ keyHandle: Buffer.alloc(256, 1)
    .toString('base64url') });
  const badKey = one({ publicKey: Buffer.alloc(65, 4).toString('base64url') });
  const shortKey = one({ publicKey: Buffer.alloc(33, 2)
    .toString('base64url') });
  const badCounter = one({ counter: '4294967296' });
  const otherAppId = one({ appId: 'https://elsewhere.example.com/app' });
  t.check(errorCodes.codeOf(badHandle) === 'STS-AUTHN-0562' &&
          errorCodes.codeOf(longHandle) === 'STS-AUTHN-0562' &&
          errorCodes.codeOf(badKey) === 'STS-AUTHN-0563' &&
          errorCodes.codeOf(shortKey) === 'STS-AUTHN-0563' &&
          errorCodes.codeOf(badCounter) === 'STS-AUTHN-0564' &&
          errorCodes.codeOf(otherAppId) === 'STS-AUTHN-0561',
          'U3. a bad key handle, a public key that is no P-256 point, a ' +
          'counter out of range and an AppID not listed are each refused',
          JSON.stringify([badHandle, longHandle, badKey, shortKey,
                          badCounter, otherAppId].map(errorCodes.codeOf)));
  const done = adminActions.usersAction({ action: 'import-u2f-key',
    user: name, keyHandle: key.handle, publicKey: key.point,
    appId: APP_ID, counter: '7', label: 'Old office key' },
                                         { via: 'api', actor: 'tester' });
  const again = one({});
  const stored = credentials.keysOf(name).filter(function (k) {
    return k.credentialId === key.handle;
  })[0] || {};
  t.check(done.ok === true && stored.appid === APP_ID &&
          credentials.appIdOf(stored) === APP_ID &&
          stored.signCount === 7 && stored.algorithm === 'ES256' &&
          stored.publicKeyJwk && stored.publicKeyJwk.x === key.jwk.x &&
          stored.publicKeyJwk.y === key.jwk.y &&
          stored.discoverable === false && stored.userVerified === false &&
          stored.label === 'Old office key' &&
          stored.importedBy && stored.importedBy.username === 'tester' &&
          again.ok === false && errorCodes.codeOf(again) === 'STS-AUTHN-0095',
          'U3b. the act imports the key, marked with its AppID and its ' +
          'counter, and the same key handle again is a duplicate',
          JSON.stringify([done, stored, again.errors]));
  log.debug('Leaving importOn().');
  return stored;
}

/**
 * U4: the extensions in the options.
 *
 * @param {object} t - the test context
 * @param {boolean} on - whether the AppID is permitted now
 * @returns {void}
 */
function extensionsIn(t, on) {
  log.debug('Entering extensionsIn().');
  const request = webauthnPolicy.requestOptions(RP_ID, APP_ID);
  const elsewhere = webauthnPolicy.requestOptions('example.org', APP_ID);
  const plain = webauthnPolicy.requestOptions(RP_ID);
  const create = webauthnPolicy.creationOptions(RP_ID, 'security-key');
  const createElsewhere = webauthnPolicy.creationOptions('example.org',
                                                         'security-key');
  if (!on) {
    t.check(request.appid === undefined && create.appidExclude === undefined &&
            WebWebAuthn.requestExtensions(request) === undefined,
            'U4. with the setting off, no request names an AppID and no ' +
            'registration asks appidExclude',
            JSON.stringify([request, create.appidExclude]));
    log.debug('Leaving extensionsIn(). Off.');
    return;
  }
  const reqExt = WebWebAuthn.requestExtensions(request);
  const createExt = WebWebAuthn.creationExtensions(create);
  t.check(request.appid === APP_ID && reqExt && reqExt.appid === APP_ID &&
          elsewhere.appid === undefined && plain.appid === undefined &&
          create.appidExclude === APP_ID &&
          createExt && createExt.appidExclude === APP_ID &&
          createElsewhere.appidExclude === undefined,
          'U4b. permitted at the RP ID, the request carries appid and a ' +
          'registration appidExclude, each made an extension; at an RP ID ' +
          'the AppID does not relate to, neither',
          JSON.stringify([request, reqExt, create.appidExclude, createExt]));
  log.debug('Leaving extensionsIn().');
}

/**
 * U5: the rpIdHash rule both ways.
 *
 * @param {object} t - the test context
 * @param {object} key - the U2F key
 * @param {object} stored - its stored record
 * @returns {void}
 */
function hashRule(t, key, stored) {
  log.debug('Entering hashRule().');
  const verify = function (hashed, extra) {
    log.debug('Entering hashRule() verify().');
    const input = Object.assign(assertion(key, hashed, 8),
      { publicKeyJwk: stored.publicKeyJwk, previousSignCount: 7 }, extra);
    log.debug('Leaving hashRule() verify().');
    return webauthn.verifyAssertion(input);
  };
  const used = verify(APP_ID, { expectedAppId: APP_ID, appidUsed: true });
  const notSaid = verify(APP_ID, { expectedAppId: APP_ID, appidUsed: false });
  const notImported = verify(APP_ID, { appidUsed: true });
  const rpHashed = verify(RP_ID, { appidUsed: true });
  t.check(used.ok === true && used.appIdHashed === true &&
          notSaid.ok === false &&
          notSaid.failed.indexOf('rpIdHash is SHA-256 of the RP ID') >= 0 &&
          webauthnPolicy.failureCodeFor(notSaid) === 'STS-AUTHN-0031' &&
          notImported.ok === false && notImported.appIdHashed === false &&
          rpHashed.ok === true && rpHashed.appIdHashed === false,
          'U5. the AppID\'s hash is accepted only for an imported key whose ' +
          'client returned appid true; otherwise the RP ID\'s is required',
          JSON.stringify([used.failed, notSaid.failed, notImported.failed,
                          rpHashed.failed]));
  log.debug('Leaving hashRule().');
}

/**
 * U6: the shared builder and expectations.
 *
 * @param {object} t - the test context
 * @param {object} stored - the imported key's row
 * @returns {void}
 */
function shared(t, stored) {
  log.debug('Entering shared().');
  const plainKey = { credentialId: 'registered-here', algorithm: 'ES256' };
  const withU2f = webauthnPolicy.assertionOptions(RP_ID, [plainKey, stored]);
  const plainOnly = webauthnPolicy.assertionOptions(RP_ID, [plainKey]);
  const passwordless = webauthnPolicy.assertionExpectations(stored, RP_ID,
    { clientExtensionResults: { appid: true } }, true);
  const elsewhere = webauthnPolicy.assertionExpectations(stored,
    'example.org', { clientExtensionResults: { appid: true } }, false);
  const second = webauthnPolicy.assertionExpectations(stored, RP_ID,
    { clientExtensionResults: { appid: true } }, false);
  const ordinary = webauthnPolicy.assertionExpectations(plainKey, RP_ID,
    { clientExtensionResults: { appid: true } }, false);
  t.check(withU2f.appid === APP_ID && withU2f.userVerification ===
            'preferred' &&
          JSON.stringify(plainOnly) ===
            JSON.stringify(webauthnPolicy.requestOptions(RP_ID)) &&
          passwordless.refusal &&
          errorCodes.codeOf(passwordless.refusal) === 'STS-AUTHN-0565' &&
          elsewhere.refusal &&
          errorCodes.codeOf(elsewhere.refusal) === 'STS-AUTHN-0565' &&
          !second.refusal && second.expectedAppId === APP_ID &&
          second.appidUsed === true &&
          second.requireUserVerification === false &&
          !ordinary.refusal && ordinary.expectedAppId === undefined &&
          ordinary.requireUserVerification ===
            webauthnPolicy.requireUserVerification(),
          'U6. one builder and one set of expectations: appid and ' +
          'preferred UV where a U2F key is named, requestOptions() ' +
          'otherwise; passwordless or unpermitted refused (STS-AUTHN-0565)',
          JSON.stringify([withU2f, passwordless.refusal, elsewhere.refusal,
                          second, ordinary]));
  log.debug('Leaving shared().');
}

/**
 * U7 and U8: each surface's options, and the upgrade proof end to end.
 *
 * @param {object} t - the test context
 * @param {string} name - the person
 * @param {object} key - the U2F key
 * @returns {Promise<void>} when checked
 */
async function surfaces(t, name, key) {
  log.debug('Entering surfaces().');
  const authnModule = require('../authn/authn');
  const surface = new authnModule.Authn(authnModule.Authn.defaultDeps());
  const base = 'https://localhost:8081';
  const step = surface.webauthnFacts(base, 'u2f-step', { username: name,
    passwordless: false, challenge: 'AAAA' });
  const alone = surface.webauthnFacts(base, 'u2f-alone', { username: name,
    passwordless: true, challenge: 'AAAA' });
  t.check(step.mode === 'get' && step.ceremony.options.appid === APP_ID &&
          step.ceremony.options.userVerification === 'preferred' &&
          step.ceremony.allow.indexOf(key.handle) >= 0 &&
          alone.mode === 'create' &&
          alone.ceremony.options.appidExclude === APP_ID &&
          alone.ceremony.exclude.indexOf(key.handle) >= 0,
          'U7. the sign-in step names the U2F key with appid; a ' +
          'passwordless step offers a registration with appidExclude ' +
          'instead', JSON.stringify([step.ceremony, alone.ceremony.options]));
  const ctx = { via: 'api', actor: 'tester', base: base };
  const begin = function () {
    log.debug('Entering surfaces() begin().');
    log.debug('Leaving surfaces() begin().');
    return adminActions.usersAction({ action: 'begin-passkey-upgrade',
      user: name, credentialId: key.handle }, ctx);
  };
  const first = await begin();
  const postLogin = surface.webauthnFacts(base, 'u2f-upgrade',
    { username: name, upgradeId: String(first.upgradeId || 'x'),
      upgradeKey: key.handle });
  t.check(first.ok === true && first.ceremony.options.appid === APP_ID &&
          first.ceremony.options.userVerification === 'preferred' &&
          postLogin.mode === 'get' &&
          postLogin.ceremony.options.appid === APP_ID,
          'U7b. the console\'s upgrade proof and a post-login upgrade\'s ' +
          'proof ask appid through the same builder',
          JSON.stringify([first.errors, first.ceremony,
                          postLogin.ceremony && postLogin.ceremony.options]));
  const prove = function (begun, results) {
    log.debug('Entering surfaces() prove().');
    const made = assertion(key, APP_ID, 7 + (++proofs));
    const posted = { id: key.handle, rawId: key.handle, type: 'public-key',
      clientExtensionResults: results,
      response: { authenticatorData: made.authenticatorData,
                  clientDataJSON: Buffer.from(JSON.stringify({
                    type: 'webauthn.get',
                    challenge: begun.ceremony.challenge, origin: ORIGIN }))
                    .toString('base64url'),
                  signature: '', userHandle: null } };
    const cdj = Buffer.from(posted.response.clientDataJSON, 'base64url');
    posted.response.signature = nodeCrypto.sign('sha256', Buffer.concat([
      Buffer.from(made.authenticatorData, 'base64url'),
      nodeCrypto.createHash('sha256').update(cdj).digest()]),
    key.pair.privateKey).toString('base64url');
    log.debug('Leaving surfaces() prove().');
    return credentials.proveKeyUpgrade(name, String(begun.upgradeId),
      posted, { origin: ORIGIN, rpId: RP_ID });
  };
  let proofs = 0;
  const refused = await prove(first, {});
  const again = await begin();
  const proven = await prove(again, { appid: true });
  t.check(refused.ok === false && again.ok === true && proven.ok === true,
          'U8. a re-authentication by the imported key (the upgrade proof): ' +
          'refused without appid true, accepted with it',
          JSON.stringify([refused.errors, again.errors, proven.errors]));
  log.debug('Leaving surfaces().');
}

module.exports = {
  name: 'webauthn U2F appid',
  describe: 'Legacy FIDO U2F credentials (#1955 P7): webauthn.u2fAppIds ' +
            'off by default, the import and its refusals, the appid and ' +
            'appidExclude extensions in the options, and the rpIdHash held ' +
            'to the AppID only when the client used the extension',
  run: async function (t) {
    log.debug('Entering run().');
    void ldap;
    const id = 'u2f-appid-' + nodeCrypto.randomBytes(3).toString('hex');
    const made = realms.create({ id: id, name: id,
                                 description: 'Created by ' + __filename });
    if (!made.ok) {
      t.bad('could not create the realm "' + id + '"',
            (made.errors || []).join(' '));
      log.debug('Leaving run(). No realm.');
      return;
    }
    try {
      await realms.run(made.realm, async function () {
        const name = 'u2f-' + nodeCrypto.randomBytes(3).toString('hex');
        ldap.createUser(name, { invent: false });
        const key = u2fKey();
        setting(t);
        importOff(t, name, key);
        extensionsIn(t, false);
        const set = config.setOverride('webauthn.u2fAppIds', APP_ID);
        t.check(set && set.ok !== false &&
                webauthnPolicy.legacyAppIds()[0] === APP_ID,
                'U3a. the AppID is permitted once listed', JSON.stringify(set));
        try {
          const stored = importOn(t, name, key);
          extensionsIn(t, true);
          hashRule(t, key, stored);
          shared(t, stored);
          await surfaces(t, name, key);
        } finally {
          config.clearOverride('webauthn.u2fAppIds');
        }
      });
    } finally {
      realms.remove(id);
    }
    log.debug('Leaving run().');
  }
};
