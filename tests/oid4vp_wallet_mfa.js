'use strict';

// ===========================================================================
// tests/oid4vp_wallet_mfa.js — A WALLET AS A FACTOR (#38's follow-ups), AND
// `appAuthnMechanism: wallet`.
//
// #38 withheld the wallet from any request that demanded two factors: a
// presentation proves possession of one key. It is a FIRST factor that a
// second can follow, a SECOND factor after a password, and — where the
// issuer verified a key attestation saying the key is guarded by the
// person's own authentication — two factors in one act. What this file
// holds:
//
//   1. a wallet sign-in on a request that demands two factors is asked for a
//      second: a password where the person holds nothing else, their
//      authenticator app where they hold one, and the session then says
//      amr ["pop","pwd"] / ["pop","otp"] and acr "mfa";
//   2. a PASSWORD sign-in that demands two offers the wallet as the second
//      factor, and a presentation of THAT person's credential finishes it —
//      amr ["pwd","pop"], acr "mfa" — while somebody else's is refused
//      (STS-VC-0084);
//   3. a single wallet sign-in with no demand claims ONE factor, and is not
//      asked for a second;
//   4. a KEY ATTESTATION the issuer verified raises what the sign-in claims:
//      `hwk` for key storage at ISO 18045 Moderate, and `acr "mfa"` — which
//      answers a demand for two factors on its own — when the user
//      authentication is attested too; an attestation nobody trusts is
//      refused at issuance, and `oid4vci.keyAttestationRequired` refuses a
//      proof without one;
//   5. `appAuthnMechanism: wallet` on an application entry sends its people
//      straight to the wallet door, and says so when the door is shut.
//
// In a CHILD PROCESS, for `admin_credential_controls.js`'s reason.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'oid4vp_wallet_mfa',
  level: process.env.LOG_LEVEL || 'info' });

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.WSI_ROOT;
  const OUT = process.env.WSI_OUT;
  const walletKit = require(ROOT + '/tests/wallet_kit');

  walletKit.boot().then(async function (w) {
    const note = w.note;
    const m = w.m;
    try {
      await sections(w, note, m);
    } catch (e) {
      note(false, 'the child ran to the end', e && (e.stack || e.message));
    }
    await w.finish(OUT);
    process.exit(0);
  }).catch(function (e) {
    require('fs').writeFileSync(OUT, JSON.stringify([
      { ok: false, what: 'the child booted', detail: e && e.stack }]));
    process.exit(0);
  });

  async function sections(w, note, m) {
    const nodeCrypto = require('crypto');
    const credentials = require(ROOT + '/common/credentials');
    const totp = require(ROOT + '/common/totp');
    const adminActions = require(ROOT + '/admin-core/admin_actions');
    await w.inRealm(function () {
      w.provision();
      m.ldap.createUser('mfa-alice', { invent: false });
      m.ldap.createUser('mfa-bob', { invent: false });
      m.ldap.createUser('mfa-carol', { invent: false });
      credentials.setPassword('mfa-alice', 'Correct-Horse-1', {});
    });
    const aud = await w.inRealm(function () {
      return m.config.value('oid4vp.clientId');
    });

    // Signs in with the wallet and answers the wait page.
    async function walletSignIn(username, holder, credential, opts) {
      const o = opts || {};
      const who = o.who || w.browser();
      const one = await w.start(who, w.pendingSignIn(
        { begin: o.begin || {} }), { mfa: o.mfa });
      if (one.started.status !== 303) {
        return { who: who, started: one.started };
      }
      const presentation = w.presentSdJwt(credential, holder,
                                          one.requestObject.nonce, aud);
      await w.respond(one, presentation, { format: 'dc+sd-jwt' });
      const page = await w.request('GET', one.waitPath, { browser: who });
      return { who: who, page: page, one: one,
               session: w.sessionOf(who) };
    }

    function endSession(session) {
      if (session) {
        return w.inRealm(function () {
          m.authn.endSessionById(session.id, 'the test, tidying up');
        });
      }
      return null;
    }

    // ==================================================================
    // 1. A SECOND FACTOR AFTER THE WALLET
    // ==================================================================
    const aliceKey = w.holderKey();
    const alice = await w.issue('mfa-alice', aliceKey);
    note(!!alice.credential, '0a. mfa-alice holds a credential',
         alice.error);
    const forced = await walletSignIn('mfa-alice', aliceKey, alice.credential,
                                      { begin: { forceMfa: true } });
    const stepId = /name="mfa_id" value="([^"]+)"/.exec(forced.page.text);
    note(forced.page.status === 200 &&
         /id="password-factor-submit"/.test(forced.page.text) && !!stepId &&
         !forced.session,
         '1a. a wallet sign-in on a request that demands two factors is ' +
         'asked for a second — her password, which everybody here has — and ' +
         'no session exists yet', forced.page.status);
    const finished = await w.request('POST', '/authn/password-factor', {
      browser: forced.who,
      form: { mfa_id: stepId[1], password: 'Correct-Horse-1' } });
    const twoFactors = w.sessionOf(forced.who);
    note(finished.status === 303 && twoFactors &&
         JSON.stringify(twoFactors.amr) === '["pop","pwd"]' &&
         twoFactors.acr === 'mfa' &&
         twoFactors.user.username === 'mfa-alice',
         '1b. and the password finishes it: amr ["pop","pwd"], acr "mfa" — ' +
         'which is what a request asking for two factors (acr_values=mfa, ' +
         'RFC 9470\'s step-up, WS-Federation\'s wauth) is answered with',
         finished.status + ' ' +
         (twoFactors ? JSON.stringify([twoFactors.amr, twoFactors.acr]) : ''));
    await endSession(twoFactors);

    // Somebody who holds an authenticator app is asked for THAT.
    const enrolled = await w.inRealm(function () {
      const begun = credentials.beginTotpEnrolment('mfa-bob',
                                                   { base: w.base });
      const done = credentials.confirmTotpEnrolment('mfa-bob',
        totp.codeAt(begun.secret, Date.now(), begun));
      return done.ok ? begun : null;
    });
    const bobKey = w.holderKey();
    const bob = await w.issue('mfa-bob', bobKey);
    const bobForced = await walletSignIn('mfa-bob', bobKey, bob.credential,
                                         { begin: { forceMfa: true } });
    const bobStep = /name="mfa_id" value="([^"]+)"/.exec(bobForced.page.text);
    note(!!enrolled && bobForced.page.status === 200 &&
         /id="totp-submit"/.test(bobForced.page.text) && !!bobStep,
         '1c. somebody who holds an authenticator app is asked for the code ' +
         'instead of a password', bobForced.page.status);
    // THE NEXT STEP'S CODE: the enrolment above spent this one (RFC 6238
    // section 5.2 — a code is used once), and `totp.window` accepts a step
    // either side.
    const code = await w.inRealm(function () {
      return totp.codeAt(enrolled.secret,
                         Date.now() + (enrolled.period || 30) * 1000,
                         enrolled);
    });
    const bobDone = await w.request('POST', '/authn/totp', {
      browser: bobForced.who, form: { mfa_id: bobStep[1], code: code } });
    const bobSession = w.sessionOf(bobForced.who);
    note(bobDone.status === 303 && bobSession &&
         JSON.stringify(bobSession.amr) === '["pop","otp"]' &&
         bobSession.acr === 'mfa',
         '1d. and the session says amr ["pop","otp"], acr "mfa" — the first ' +
         'factor is the WALLET, so nothing claims a password nobody typed',
         bobDone.status + ' ' +
         (bobSession ? JSON.stringify(bobSession.amr) : ''));
    await endSession(bobSession);

    // The realm-wide requirement reaches this door too.
    await w.inRealm(function () {
      m.config.setOverride('authn.mfaRequired', 'true');
    });
    const required = await walletSignIn('mfa-bob', bobKey, bob.credential);
    note(required.page.status === 200 &&
         /id="totp-submit"/.test(required.page.text) && !required.session,
         '1e. authn.mfaRequired asks for one after a wallet sign-in too, ' +
         'with no demand from the request at all', required.page.status);
    await w.inRealm(function () {
      m.config.clearOverride('authn.mfaRequired');
    });

    // ==================================================================
    // 2. THE WALLET AS THE SECOND FACTOR
    // ==================================================================
    const pwId = w.pendingSignIn({ begin: { forceMfa: true } });
    const pwWho = w.browser();
    const posted = await w.request('POST', '/authn/login', {
      browser: pwWho,
      form: { authn_id: pwId, username: 'mfa-alice',
              password: 'Correct-Horse-1', action: 'login' } });
    const link = /id="wallet-second-factor" href="([^"]+)"/.exec(posted.text);
    note(posted.status === 200 && !!link &&
         /mfa=/.test(w.unescapeHtml(link ? link[1] : '')),
         '2a. a password sign-in that demands two factors offers the wallet ' +
         'as the second, naming the step',
         posted.status + ' ' + (link ? w.unescapeHtml(link[1]) : ''));
    const mfaId = new URL(w.unescapeHtml(link[1]), 'http://x')
      .searchParams.get('mfa');
    const asSecond = await walletSignIn('mfa-alice', aliceKey,
                                        alice.credential,
                                        { who: pwWho, mfa: mfaId });
    const bothFactors = w.sessionOf(pwWho);
    note(asSecond.page.status === 303 && bothFactors &&
         JSON.stringify(bothFactors.amr) === '["pwd","pop"]' &&
         bothFactors.acr === 'mfa',
         '2b. and her wallet finishes it: amr ["pwd","pop"], acr "mfa"',
         asSecond.page.status + ' ' +
         (bothFactors ? JSON.stringify(bothFactors.amr) : ''));
    await endSession(bothFactors);

    // Somebody ELSE's credential at that step.
    const carolKey = w.holderKey();
    const carol = await w.issue('mfa-carol', carolKey);
    const otherId = w.pendingSignIn({ begin: { forceMfa: true } });
    const otherWho = w.browser();
    const otherPosted = await w.request('POST', '/authn/login', {
      browser: otherWho,
      form: { authn_id: otherId, username: 'mfa-alice',
              password: 'Correct-Horse-1', action: 'login' } });
    const otherLink = /id="wallet-second-factor" href="([^"]+)"/
      .exec(otherPosted.text);
    const otherStep = new URL(w.unescapeHtml(otherLink[1]), 'http://x')
      .searchParams.get('mfa');
    const wrongPerson = await walletSignIn('mfa-carol', carolKey,
                                           carol.credential,
                                           { who: otherWho, mfa: otherStep });
    note(wrongPerson.page.status === 403 &&
         wrongPerson.page.code === 'STS-VC-0084' && !w.sessionOf(otherWho),
         '2c. a credential issued to SOMEBODY ELSE cannot be the second ' +
         'factor: two factors from two people are not two factors, ' +
         'STS-VC-0084',
         wrongPerson.page.status + ' ' + wrongPerson.page.code);

    // ==================================================================
    // 3. ONE FACTOR STAYS ONE FACTOR
    // ==================================================================
    const plain = await walletSignIn('mfa-alice', aliceKey, alice.credential);
    note(plain.page.status === 303 && plain.session &&
         JSON.stringify(plain.session.amr) === '["pop"]' &&
         plain.session.acr === '1',
         '3a. with no demand and no requirement a wallet sign-in claims ONE ' +
         'factor and is asked for nothing else',
         plain.page.status + ' ' +
         (plain.session ? JSON.stringify(plain.session.amr) : ''));
    await endSession(plain.session);

    // ==================================================================
    // 4. KEY ATTESTATIONS
    // ==================================================================
    const provider = await w.inRealm(function () {
      return m.stsCrypto.selfSignedRsaCertificate(
        { commonName: 'wallet provider' });
    });
    const providerKey = nodeCrypto.createPrivateKey(provider.privateKeyPem);
    function attestation(holder, levels, key) {
      return function (nonce) {
        const now = Math.floor(Date.now() / 1000);
        const claims = { iss: 'https://wallet.example', iat: now,
                         exp: now + 300, attested_keys: [holder.jwk],
                         nonce: nonce };
        if (levels.storage) {
          claims.key_storage = [levels.storage];
        }
        if (levels.user) {
          claims.user_authentication = [levels.user];
        }
        return m.stsCrypto.signJws(claims, key || providerKey, {
          algorithm: 'RS256',
          header: { alg: 'RS256', typ: 'key-attestation+jwt' } });
      };
    }
    await w.inRealm(function () {
      m.config.setOverride('oid4vci.keyAttestationTrustedCertificates',
                           provider.certPem);
    });
    const attestedKey = w.holderKey();
    const attested = await w.issue('mfa-carol', attestedKey,
      { attestation: attestation(attestedKey,
        { storage: 'iso_18045_moderate', user: 'iso_18045_moderate' }) });
    const attestedIn = await walletSignIn('mfa-carol', attestedKey,
                                          attested.credential);
    note(!!attested.credential && attestedIn.page.status === 303 &&
         attestedIn.session &&
         JSON.stringify(attestedIn.session.amr) === '["pop","hwk","mfa"]' &&
         attestedIn.session.acr === 'mfa',
         '4a. a key attestation the issuer verified — key storage AND user ' +
         'authentication at ISO 18045 Moderate — makes the sign-in claim ' +
         'amr ["pop","hwk","mfa"] and acr "mfa"',
         (attested.error || '') + ' ' + attestedIn.page.status + ' ' +
         (attestedIn.session ? JSON.stringify(attestedIn.session.amr) : ''));
    await endSession(attestedIn.session);
    const attestedForced = await walletSignIn('mfa-carol', attestedKey,
      attested.credential, { begin: { forceMfa: true } });
    note(attestedForced.page.status === 303 && attestedForced.session &&
         attestedForced.session.acr === 'mfa',
         '4b. and it answers a demand for two factors on its own — no ' +
         'second step is drawn', attestedForced.page.status);
    await endSession(attestedForced.session);

    const storageOnlyKey = w.holderKey();
    const storageOnly = await w.issue('mfa-carol', storageOnlyKey,
      { attestation: attestation(storageOnlyKey,
        { storage: 'iso_18045_moderate' }) });
    const storageIn = await walletSignIn('mfa-carol', storageOnlyKey,
                                         storageOnly.credential);
    note(storageIn.page.status === 303 && storageIn.session &&
         JSON.stringify(storageIn.session.amr) === '["pop","hwk"]' &&
         storageIn.session.acr === '1',
         '4c. key storage alone is hwk and ONE factor: nothing about the ' +
         'key says the person was there',
         storageIn.page.status + ' ' +
         (storageIn.session ? JSON.stringify(storageIn.session.amr) : ''));
    await endSession(storageIn.session);

    const untrusted = nodeCrypto.createPrivateKey(
      (await w.inRealm(function () {
        return m.stsCrypto.selfSignedRsaCertificate(
          { commonName: 'somebody else' });
      })).privateKeyPem);
    const untrustedKey = w.holderKey();
    const refused = await w.issue('mfa-carol', untrustedKey,
      { attestation: attestation(untrustedKey,
        { storage: 'iso_18045_high' }, untrusted) });
    note(!refused.credential && /invalid_proof/.test(refused.error || ''),
         '4d. an attestation no configured certificate verifies is refused ' +
         'at issuance, and the credential is not issued',
         (refused.error || '').slice(0, 160));

    await w.inRealm(function () {
      m.config.setOverride('oid4vci.keyAttestationRequired', 'true');
    });
    const bare = await w.issue('mfa-carol', w.holderKey());
    const metadata = await w.request('GET',
      '/.well-known/openid-credential-issuer');
    const advertised = metadata.json &&
      metadata.json.credential_configurations_supported.IdentityCredential
        .proof_types_supported;
    note(!bare.credential && /invalid_proof/.test(bare.error || '') &&
         advertised && advertised.jwt.key_attestations_required &&
         advertised.attestation,
         '4e. oid4vci.keyAttestationRequired refuses a proof without one, ' +
         'and the metadata says so (key_attestations_required), beside the ' +
         'attestation proof type',
         (bare.error || '').slice(0, 120) + ' ' +
         JSON.stringify(advertised || {}));
    const attestationOnlyKey = w.holderKey();
    const byAttestation = await w.issue('mfa-carol', attestationOnlyKey, {
      proofType: 'attestation',
      attestation: attestation(attestationOnlyKey,
        { storage: 'iso_18045_high', user: 'iso_18045_high' }) });
    const attestationOnlyIn = byAttestation.credential
      ? await walletSignIn('mfa-carol', attestationOnlyKey,
                           byAttestation.credential) : null;
    note(!!byAttestation.credential && attestationOnlyIn &&
         attestationOnlyIn.page.status === 303 &&
         attestationOnlyIn.session.acr === 'mfa',
         '4f. the attestation PROOF TYPE (Appendix F.3) issues a credential ' +
         'for the attested key, and it signs in with what the attestation ' +
         'claims', (byAttestation.error || '') + ' ' +
         (attestationOnlyIn ? attestationOnlyIn.page.status : ''));
    await endSession(attestationOnlyIn && attestationOnlyIn.session);
    await w.inRealm(function () {
      m.config.clearOverride('oid4vci.keyAttestationRequired');
      m.config.clearOverride('oid4vci.keyAttestationTrustedCertificates');
    });

    // ==================================================================
    // 5. appAuthnMechanism: wallet
    // ==================================================================
    const set = await w.inRealm(function () {
      return adminActions.applicationsAction({
        action: 'set', application: 'wsi-wallet',
        attribute: 'appAuthnMechanism', value: 'wallet' }, [], {});
    });
    const where = await w.inRealm(function () {
      return m.authn.beginAuthentication({ returnTo: '/wsi/after',
        protocol: 'wsi-probe', application: 'wsi-wallet' });
    });
    note(set.ok && /^\/authn\/wallet\?authn=/.test(where),
         '5a. appAuthnMechanism: wallet — set through the function the ' +
         'console and /admin-api both go through — sends that ' +
         'application\'s people straight to the wallet door',
         JSON.stringify(set.errors || set.message || '') + ' ' + where);
    await w.inRealm(function () {
      m.config.setOverride('oid4vp.signIn', 'false');
    });
    const shut = await w.inRealm(function () {
      return m.authn.beginAuthentication({ returnTo: '/wsi/after',
        protocol: 'wsi-probe', application: 'wsi-wallet' });
    });
    const screen = await w.request('GET', shut);
    note(/^\/authn\/login\?authn=/.test(shut) &&
         /oid4vp\.signIn is off/.test(screen.text),
         '5b. and with oid4vp.signIn off it falls back to the screen and ' +
         'says why, rather than sending somebody to a door that is shut',
         shut + ' ' + screen.status);
    await w.inRealm(function () {
      m.config.clearOverride('oid4vp.signIn');
      adminActions.applicationsAction({ action: 'set',
        application: 'wsi-wallet', attribute: 'appAuthnMechanism',
        value: '' }, [], {});
    });
  }
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'oid4vp-wallet-mfa');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oid4vp wallet as a factor',
  describe: 'a wallet as a first factor a second follows, as the second ' +
            'factor after a password, and as two where a verified key ' +
            'attestation says so; and appAuthnMechanism: wallet',
  run: run
};
