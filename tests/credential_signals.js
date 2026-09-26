'use strict';
//
// File: credential_signals.js
//
// ===========================================================================
// WHAT A DETECTED COMPROMISE AND EVERY PERSON CREDENTIAL NOW SAY (#231, #236,
// #237; 2026-09-26), in process, where what the doors hand Shared Signals
// can be read back without a stream.
//
// `ssf/ssf.ts`'s two emitters are replaced on its loaded exports by a
// recorder — `ssf/account_signals.ts` finds that module in `require.cache`
// at the moment an event is due, so every door's call arrives here exactly
// as it would reach the real transmitter, with its `risc.autoEmitTypes` and
// stream filtering still to come. What this holds:
//
//   A. #236, THE SIX CREDENTIALS WITH NO REGISTERED TYPE: the emailed factor
//      (opt-in create, code to link update, an administrator's clear
//      delete), a SIOP self-issued subject (create by the person, delete by
//      an administrator), an ACME EAB key and a SCEP challenge password
//      (create / delete, the challenge as `password` with a friendly name),
//      a HOBA key (create, then update for the same kid) — each with its
//      URN credential type.
//   B. #231, THE DETECTORS: the emailed factor turned off at its failure
//      limit (delete by `system`, and RISC credential-compromise with the
//      email URN and the person not mailed twice); a security key's
//      counter going backwards in `spendAssertion()` (RISC
//      credential-compromise `fido2-roaming`, and the person's risk standing
//      HIGH as `authenticator-compromised`); `clonedKeyVerdict()` true only
//      when the counter is the one failed check; a TLS client certificate
//      and an enrolled one revoked for keyCompromise (RISC
//      credential-compromise `x509`), and not for another reason.
//   C. #231 ITEM 5: a replayed one-time code is recorded under its own door,
//      scored as `totp-replay` at the next assessment, and NOT counted as a
//      refused password; no SET is sent for it.
//   D. #237, THE LDAP SOCKET: a credential attribute is refused on an add
//      and a modify in development too (STS-LDAP-0111, unwillingToPerform),
//      the prefixes included; `userPassword` deleted sends password/revoke;
//      a pre-hashed value kept in development sends update; `pwdReset` set
//      sends RISC account-credential-change-required once.
//   E. #237: the CIBA user code as `pin` — create, update, delete, and
//      nothing for clearing none; a bootstrap administrator's password as
//      create by `system`.
//   F. #231 ITEM 1, IN PRODUCT MODE AND OVER HTTP: a password found in a
//      (stubbed) breach at the sign-in screen sends RISC credential-compromise
//      (`password`) and account-credential-change-required, once, and the
//      change step is drawn.
//
// Two children, because each loads the whole stack and one of them is in
// product mode. `tests/vendored/sts_credential_signals.js` holds the parts
// that can be driven over the wire against a real stream.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'credential_signals',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// THE CHILD. Serialised with toString() and run with `node -e`, so it is
// self-contained; `CS_MODE` says which half it is.
// ---------------------------------------------------------------------------
/* eslint-disable no-undef */
function childMain() {
  const ROOT = process.env.CS_ROOT;
  const OUT = process.env.CS_OUT;
  const MODE = process.env.CS_MODE;
  const fs = require('fs');
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const sleep = function (ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const helpers = require(ROOT + '/common/helpers');
    const credentials = require(ROOT + '/common/credentials');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const ssf = require(ROOT + '/ssf/ssf');

    // THE RECORDER, on the loaded exports `account_signals.ts` reads.
    const sent = [];
    ssf.emitCredentialChange = function (n) {
      sent.push({ kind: 'caep', n: n || {} });
      return Promise.resolve({ sent: 1, streams: 1 });
    };
    ssf.emitRiscAccountAct = function (n) {
      sent.push({ kind: 'risc', n: n || {} });
      return Promise.resolve({ sent: 1, streams: 1 });
    };
    const since = function () {
      return sent.length;
    };
    const caepAfter = function (mark, who) {
      return sent.slice(mark).filter(function (one) {
        return one.kind === 'caep' && one.n.username === who;
      }).map(function (one) {
        return one.n;
      });
    };
    const riscAfter = function (mark, who, act) {
      return sent.slice(mark).filter(function (one) {
        return one.kind === 'risc' && one.n.username === who &&
               (!act || one.n.act === act);
      }).map(function (one) {
        return one.n;
      });
    };
    const brief = function (list) {
      return JSON.stringify(list.map(function (n) {
        return { t: n.credentialType, c: n.changeType,
                 i: n.initiatingEntity, f: n.friendlyName, act: n.act,
                 v: n.values };
      }));
    };

    if (MODE === 'development') {
      await realms.run(realms.DEFAULT_REALM, async function () {
        const keystore = require(ROOT + '/common/keystore');
        const pki = require(ROOT + '/common/pki');
        await keystore.start();
        await pki.start({ realmIds: [''],
          keySetFor: function (id) {
            return helpers.stsKeysFor.of(id);
          },
          keySetHeldFor: function () {
            return false;
          } });
        await pki.ensureScope(realms.currentId());
        const mail = require(ROOT + '/common/mail');
        const mailFactor = require(ROOT + '/common/mail_factor');
        const authnPolicy = require(ROOT + '/common/authn_policy');
        const siop = require(ROOT + '/oid4vc/siop');
        const core = require(ROOT + '/common/cert_enrollment');
        const scimAuth = require(ROOT + '/scim/scim_auth');
        const ciba = require(ROOT + '/oauth-oidc/ciba');
        const totp = require(ROOT + '/common/totp');
        const riskStore = require(ROOT + '/risk/risk_store');
        const riskFailures = require(ROOT + '/risk/risk_failures');
        const riskEngine = require(ROOT + '/risk/risk_engine');
        const tlsClient = require(ROOT + '/common/tls_client_certificates');
        const keyMaterial = require(ROOT + '/common/vendored/key_material');
        const x509 = require(ROOT + '/common/vendored/x509');
        const errorCodes = require(ROOT + '/common/error_codes');
        const audit = require(ROOT + '/common/audit');

        const person = function (name) {
          ldap.createUser(name, { invent: false });
          credentials.setPassword(name, 'Credential-Signals-1!');
        };

        // ================================================================
        // A. #236
        // ================================================================
        // A1. The emailed factor.
        person('cs-amy');
        mail.directory().writeAddress('cs-amy', 'amy@cs.example', 'admin');
        const opened = authnPolicy.save('default', Object.assign({},
          authnPolicy.DEFAULTS, { emailCodeSecondFactor: true,
            emailLinkSecondFactor: true, emailFailureLimit: 5 }));
        note(opened.ok, 'A1. the policy accepts both emailed kinds as a ' +
             'second factor', JSON.stringify(opened.errors));
        const EMAIL = 'urn:iya:sts:credential-type:email-otp';
        let mark = since();
        const optedIn = mailFactor.optIn('cs-amy', 'code', 'cs-amy', 'test');
        let got = caepAfter(mark, 'cs-amy');
        note(optedIn.ok && got.length === 1 &&
             got[0].credentialType === EMAIL &&
             got[0].changeType === 'create' &&
             got[0].initiatingEntity === 'user',
             'A1a. opting in to the emailed code is credential-change ' +
             EMAIL + ' create, by the person', brief(got));
        mark = since();
        mailFactor.optIn('cs-amy', 'link', 'cs-amy', 'test');
        got = caepAfter(mark, 'cs-amy');
        note(got.length === 1 && got[0].changeType === 'update',
             'A1b. moving from a code to a link is an update', brief(got));
        mark = since();
        mailFactor.optIn('cs-amy', 'link', 'cs-amy', 'test');
        note(caepAfter(mark, 'cs-amy').length === 0,
             'A1c. opting in to what is already held sends nothing');
        mark = since();
        mailFactor.clear('cs-amy', 'an-admin', 'console');
        got = caepAfter(mark, 'cs-amy');
        note(got.length === 1 && got[0].changeType === 'delete' &&
             got[0].initiatingEntity === 'admin',
             'A1d. an administrator\'s clear is a delete, by admin',
             brief(got));

        // A2. A SIOP self-issued subject.
        person('cs-sam');
        const pair = nodeCrypto.generateKeyPairSync('ec',
                                                    { namedCurve: 'P-256' });
        const jwk = pair.publicKey.export({ format: 'jwk' });
        const subject = JSON.stringify({ kty: jwk.kty, crv: jwk.crv,
                                         x: jwk.x, y: jwk.y });
        const SELF = 'urn:iya:sts:credential-type:self-issued-key';
        mark = since();
        const enrolled = siop.enrol('cs-sam', subject, 'phone',
                                    'self (SIOPv2)');
        got = caepAfter(mark, 'cs-sam');
        note(enrolled.ok && got.length === 1 &&
             got[0].credentialType === SELF &&
             got[0].changeType === 'create' &&
             got[0].initiatingEntity === 'user' &&
             got[0].friendlyName === 'phone',
             'A2a. enrolling a self-issued subject is ' + SELF + ' create, ' +
             'by the person, its label as friendly_name', brief(got));
        mark = since();
        const removed = siop.remove('cs-sam', subject, 'an-admin');
        got = caepAfter(mark, 'cs-sam');
        note(removed.ok && got.length === 1 &&
             got[0].changeType === 'delete' &&
             got[0].initiatingEntity === 'admin',
             'A2b. an administrator removing it is a delete, by admin',
             brief(got));

        // A3. ACME EAB and a SCEP challenge.
        person('cs-eve');
        const target = { kind: 'person', id: 'cs-eve' };
        const EAB = 'urn:iya:sts:credential-type:acme-eab-key';
        mark = since();
        const eab = core.createEab({ target: target, createdBy: 'cs-eve' });
        got = caepAfter(mark, 'cs-eve');
        note(eab.ok && got.length === 1 && got[0].credentialType === EAB &&
             got[0].changeType === 'create' &&
             got[0].initiatingEntity === 'user',
             'A3a. an EAB key made by the person is ' + EAB + ' create',
             brief(got));
        mark = since();
        core.deleteEab(eab.kid, 'an-admin');
        got = caepAfter(mark, 'cs-eve');
        note(got.length === 1 && got[0].changeType === 'delete' &&
             got[0].initiatingEntity === 'admin',
             'A3b. and deleting it by an administrator is a delete',
             brief(got));
        mark = since();
        const challenge = core.createScepChallenge({ target: target,
                                                     createdBy: 'an-admin' });
        got = caepAfter(mark, 'cs-eve');
        note(challenge.ok && got.length === 1 &&
             got[0].credentialType === 'password' &&
             /^SCEP challenge password /.test(String(got[0].friendlyName)) &&
             got[0].changeType === 'create' &&
             got[0].initiatingEntity === 'admin',
             'A3c. a SCEP challenge is the registered `password`, create, ' +
             'with a friendly_name saying which password', brief(got));
        mark = since();
        core.deleteScepChallenge(challenge.id, 'cs-eve');
        got = caepAfter(mark, 'cs-eve');
        note(got.length === 1 && got[0].changeType === 'delete' &&
             got[0].initiatingEntity === 'user',
             'A3d. and deleting it is a delete', brief(got));

        // A4. A HOBA key.
        person('cs-hob');
        const hobaPem = nodeCrypto.generateKeyPairSync('rsa',
          { modulusLength: 2048 }).publicKey.export({ type: 'spki',
                                                      format: 'pem' });
        const register = function () {
          return scimAuth.registerHobaKey({
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ pub: hobaPem, username: 'cs-hob',
                                        kid: 'cs-hob-kid' }).toString(),
            method: 'POST' });
        };
        const HOBA = 'urn:iya:sts:credential-type:hoba-key';
        mark = since();
        const reg1 = register();
        const reg2 = register();
        got = caepAfter(mark, 'cs-hob');
        note(reg1.status === 201 && reg2.status === 201 &&
             got.length === 2 && got[0].credentialType === HOBA &&
             got[0].changeType === 'create' &&
             got[1].changeType === 'update',
             'A4. a HOBA key is ' + HOBA + ' create, and the same kid ' +
             'registered again an update', brief(got));

        // ================================================================
        // B. #231, THE DETECTORS
        // ================================================================
        // B1. The emailed factor's failure limit.
        mailFactor.optIn('cs-amy', 'code', 'cs-amy', 'test');
        const compromiseMails = function () {
          return mail.list({ username: 'cs-amy' }).filter(function (row) {
            return /compromis/i.test(String(row.subject || '') + ' ' +
                                     String(row.template || ''));
          }).length;
        };
        const mailedBefore = compromiseMails();
        mark = since();
        let limit = null;
        for (let i = 0; i < 5; i += 1) {
          limit = mailFactor.noteFailure('cs-amy');
        }
        got = caepAfter(mark, 'cs-amy');
        const compromised = riscAfter(mark, 'cs-amy', 'credentialCompromise');
        await sleep(50);
        const mailedNow = compromiseMails() - mailedBefore;
        note(limit && limit.cleared && got.length === 1 &&
             got[0].changeType === 'delete' &&
             got[0].initiatingEntity === 'system',
             'B1a. the failure limit turning the factor off is a delete, by ' +
             'system', brief(got));
        note(compromised.length === 1 &&
             compromised[0].values.credential_type === EMAIL &&
             compromised[0].mailed === true,
             'B1b. and RISC credential-compromise with ' + EMAIL + ', the ' +
             'generic mail notice suppressed', brief(compromised));
        note(mailedNow === 1,
             'B1c. the person is mailed about it once, not twice',
             String(mailedNow));

        // B2. A cloned key, by the store's counter.
        person('cs-kay');
        const cred = 'cs-kay-cred-' + nodeCrypto.randomBytes(4)
          .toString('hex');
        const spend = function (count, challengeValue) {
          return credentials.spendAssertion({ username: 'cs-kay',
            credentialId: cred, signCount: count, challenge: challengeValue,
            ttlMs: 60000 });
        };
        const first = await spend(7, 'cs-c1-' + Date.now());
        mark = since();
        const backwards = await spend(3, 'cs-c2-' + Date.now());
        const cloned = riscAfter(mark, 'cs-kay', 'credentialCompromise');
        note(first.ok && !backwards.ok && backwards.reason === 'counter' &&
             errorCodes.codeOf(backwards) === 'STS-AUTHN-0035' &&
             cloned.length === 1 &&
             cloned[0].values.credential_type === 'fido2-roaming' &&
             cloned[0].initiatingEntity === 'system',
             'B2a. a counter that went backwards is refused STS-AUTHN-0035 ' +
             'and sends RISC credential-compromise fido2-roaming',
             brief(cloned));
        let standing = null;
        for (let i = 0; i < 40 && !standing; i += 1) {
          await sleep(25);
          standing = riskEngine.standingOf(realms.currentId(), 'cs-kay');
        }
        note(standing && standing.level === 'HIGH' &&
             (standing.signals || []).indexOf('authenticator-compromised') >=
               0,
             'B2b. and the person\'s risk standing is HIGH, ' +
             'authenticator-compromised', JSON.stringify(standing));
        const V = credentials.Credentials.clonedKeyVerdict;
        note(V({ ok: false, failed: ['signature counter advanced'] }) &&
             !V({ ok: false, failed: ['signature counter advanced',
                                      'signature verifies'] }) &&
             !V({ ok: false, failed: ['challenge matches'] }) &&
             !V({ ok: true, failed: [] }) && !V(null),
             'B2c. clonedKeyVerdict() is true only when the counter is the ' +
             'one failed check');

        // B3. keyCompromise at two of the three leaf revoke doors (the
        // third, /admin/pki, is over the wire).
        person('cs-tls');
        const made = await tlsClient.issue(undefined, { username: 'cs-tls',
          label: 'laptop', keyAlg: 'ec-p256' });
        const made2 = await tlsClient.issue(undefined, { username: 'cs-tls',
          label: 'phone', keyAlg: 'ec-p256' });
        mark = since();
        tlsClient.revoke(undefined, 'cs-tls', made2.issued.serialHex,
                         'cessationOfOperation');
        note(made2.ok && riscAfter(mark, 'cs-tls').length === 0,
             'B3a. a TLS client certificate revoked for cessation sends no ' +
             'RISC event');
        mark = since();
        tlsClient.revoke(undefined, 'cs-tls', made.issued.serialHex,
                         'keyCompromise');
        got = riscAfter(mark, 'cs-tls', 'credentialCompromise');
        note(made.ok && got.length === 1 &&
             got[0].values.credential_type === 'x509' &&
             caepAfter(mark, 'cs-tls').some(function (n) {
               return n.credentialType === 'x509' && n.changeType === 'revoke';
             }),
             'B3b. revoked for keyCompromise it sends RISC ' +
             'credential-compromise x509 beside the CAEP revoke',
             brief(got));
        person('cs-enr');
        const enrPair = await keyMaterial.generateKeyPair('ec-p256');
        const csr = await x509.certificationRequest({
          subject: 'CN=cs-enr', publicKeyPem: enrPair.publicPem,
          privateKeyPem: enrPair.privatePem, subjectAltName: [] });
        const enrolledCert = await core.issue({
          family: 'acme', profile: 'tls-client',
          principal: { kind: 'person', id: 'cs-enr', admin: false,
                       hasEntry: true, via: 'test' },
          target: { kind: 'person', id: 'cs-enr' },
          publicKeyPem: enrPair.publicPem, csrDer: Buffer.from(csr.der),
          requested: {}, via: 'test' });
        mark = since();
        const revokedEnrolled = enrolledCert.ok
          ? await core.revokeEnrolled(enrolledCert.record.serialHex,
                                      'keyCompromise', 'cs-enr')
          : null;
        got = riscAfter(mark, 'cs-enr', 'credentialCompromise');
        note(revokedEnrolled && revokedEnrolled.ok && got.length === 1 &&
             got[0].values.credential_type === 'x509' &&
             got[0].initiatingEntity === 'user',
             'B3c. an enrolled certificate revoked for keyCompromise by its ' +
             'holder sends RISC credential-compromise x509',
             JSON.stringify(enrolledCert.errors || '') + ' ' + brief(got));

        // ================================================================
        // C. #231 ITEM 5: a replayed one-time code
        // ================================================================
        person('cs-otp');
        const begun = credentials.beginTotpEnrolment('cs-otp',
          { base: 'https://localhost' });
        credentials.confirmTotpEnrolment('cs-otp',
          totp.codeAt(begun.secret, Date.now(), begun));
        const code = totp.codeAt(begun.secret, Date.now() + 30000, begun);
        mark = since();
        const once = await credentials.verifyTotpAsync('cs-otp', code);
        const twice = await credentials.verifyTotpAsync('cs-otp', code);
        await sleep(100);
        const sub = helpers.subjectForName('cs-otp');
        const rows = await riskStore.listFailures(realms.currentId(),
          { since: 0, subject: sub, door: riskFailures.TOTP_REPLAY_DOOR,
            limit: 10 }, false);
        const passwords = await riskStore.listFailures(realms.currentId(),
          { since: 0, subject: sub,
            excludeDoor: riskFailures.TOTP_REPLAY_DOOR, limit: 10 }, false);
        note(once.ok && !twice.ok && twice.reason === 'replay' &&
             rows.total === 1 && rows.rows[0].errorCode === 'STS-AUTHN-0106' &&
             passwords.total === 0 && sent.length === mark,
             'C1. the replay is refused, recorded under "' +
             riskFailures.TOTP_REPLAY_DOOR + '", not counted as a refused ' +
             'password, and no SET is sent',
             JSON.stringify({ rows: rows.total, pw: passwords.total,
                              sent: sent.length - mark }));
        const assessed = await riskEngine.assess({ realm: realms.currentId(),
          subject: sub, username: 'cs-otp', door: 'the test',
          sessionId: 'cs-otp-session', clientId: '',
          context: { address: '198.51.100.23' },
          userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ' +
                     '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36' });
        const ids = ((assessed && assessed.signals) || []).map(function (s) {
          return s.signal;
        });
        note(ids.indexOf('totp-replay') >= 0 &&
             ids.indexOf('account-failures') < 0,
             'C2. the next assessment carries totp-replay (×' +
             riskEngine.SIGNALS['totp-replay'].factor + ') and not ' +
             'account-failures', JSON.stringify(ids));

        // ================================================================
        // D. #237, THE LDAP SOCKET
        // ================================================================
        person('cs-ldap');
        const dn = ldap.objectFor('cs-ldap').entry.dn;
        const modify = function (operation, type, values) {
          return Promise.resolve(ldap.performOperation('modify', {
            dn: dn, boundDn: 'uid=someone,' + dn.split(',').slice(1).join(','),
            channel: 'ldaps',
            changes: [{ operation: operation,
                        modification: { type: type, values: values } }] }));
        };
        const refusedWrites = [];
        for (const type of ['stsTotpCredential', 'stsWebauthnCredential',
                            'stsAppPassword', 'stsBackupCodes',
                            'hobaPublicKey', 'stsAssertionJwks',
                            'stsSamlAssertionCertificate',
                            'stsSelfIssuedSubject', 'stsCibaUserCode',
                            'stsKrb5Keys']) {
          const answer = await modify('replace', type, ['x']);
          refusedWrites.push({ type: type, ok: answer.ok,
                               name: answer.errorName });
        }
        const audited = audit.list().filter(function (row) {
          return row.errorCode === 'STS-LDAP-0111';
        });
        note(refusedWrites.every(function (one) {
          return one.ok === false && one.name === 'UnwillingToPerformError';
        }) && audited.length >= refusedWrites.length,
             'D1. a modify of every credential attribute is refused ' +
             'unwillingToPerform, recorded STS-LDAP-0111, in development ' +
             'mode too', JSON.stringify(refusedWrites));
        const added = await Promise.resolve(ldap.performOperation('add', {
          dn: 'uid=cs-ldap-new,' + dn.split(',').slice(1).join(','),
          boundDn: '', channel: 'ldaps',
          attributes: [{ type: 'objectClass', values: ['inetOrgPerson'] },
                       { type: 'uid', values: ['cs-ldap-new'] },
                       { type: 'cn', values: ['x'] },
                       { type: 'sn', values: ['x'] },
                       { type: 'stsWebauthnCredential', values: ['{}'] }] }));
        note(!added.ok && added.errorName === 'UnwillingToPerformError' &&
             !(ldap.objectFor('cs-ldap-new') || {}).entry,
             'D2. an add carrying one is refused and adds nothing',
             JSON.stringify(added));
        mark = since();
        const hashed = await modify('replace', 'userPassword',
                                    ['$scrypt$made-up-by-the-test']);
        got = caepAfter(mark, 'cs-ldap');
        note(hashed.ok && got.length === 1 &&
             got[0].credentialType === 'password' &&
             got[0].changeType === 'update',
             'D3. a pre-hashed userPassword kept in development is ' +
             'credential-change password update', brief(got));
        mark = since();
        const gone = await modify('delete', 'userPassword', []);
        got = caepAfter(mark, 'cs-ldap');
        note(gone.ok && got.length === 1 &&
             got[0].credentialType === 'password' &&
             got[0].changeType === 'revoke',
             'D4. deleting userPassword is credential-change password revoke',
             brief(got));
        mark = since();
        const reset1 = await modify('replace', 'pwdReset', ['TRUE']);
        const reset2 = await modify('replace', 'pwdReset', ['TRUE']);
        got = riscAfter(mark, 'cs-ldap', 'credentialChangeRequired');
        note(reset1.ok && reset2.ok && got.length === 1,
             'D5. pwdReset set over LDAP sends RISC ' +
             'account-credential-change-required, once', brief(got));

        // ================================================================
        // E. #237: the CIBA user code, and a bootstrap password
        // ================================================================
        person('cs-pin');
        mark = since();
        const cleared0 = ciba.setUserCode('cs-pin', '');
        const set1 = ciba.setUserCode('cs-pin', 'blue-horse-7');
        const set2 = ciba.setUserCode('cs-pin', 'red-horse-8');
        const cleared = ciba.setUserCode('cs-pin', '');
        got = caepAfter(mark, 'cs-pin');
        note(cleared0.ok && set1.ok && set2.ok && cleared.ok &&
             got.map(function (n) {
               return n.credentialType + ':' + n.changeType;
             }).join(',') === 'pin:create,pin:update,pin:delete',
             'E1. the CIBA user code is pin create, update and delete, and ' +
             'clearing none sends nothing', brief(got));
        mark = since();
        credentials.noteBootstrapPassword('cs-pin', 'in the test');
        got = caepAfter(mark, 'cs-pin');
        note(got.length === 1 && got[0].changeType === 'create' &&
             got[0].initiatingEntity === 'system',
             'E2. a bootstrap password is credential-change password ' +
             'create, by system', brief(got));
      });
    } else {
      // ==================================================================
      // F. PRODUCT MODE: a breached password at the sign-in screen
      // ==================================================================
      const applications = require(ROOT + '/common/applications');
      const stsCrypto = require(ROOT + '/common/crypto');
      const fedHttp = require(ROOT + '/federation/federation_http');
      const breached = require(ROOT + '/common/breached_passwords');
      const server = http.createServer(app);
      await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
      const port = server.address().port;
      const request = function (method, urlPath, form, jar) {
        return new Promise(function (resolve) {
          const body = form ? new URLSearchParams(form).toString() : '';
          const headers = { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; ' +
            'Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' +
            'Chrome/140.0.0.0 Safari/537.36' };
          if (jar && jar.cookie) {
            headers.cookie = jar.cookie;
          }
          if (method !== 'GET') {
            headers['content-type'] = 'application/x-www-form-urlencoded';
            headers['content-length'] = Buffer.byteLength(body);
          }
          const req = http.request({ host: '127.0.0.1', port: port,
            path: urlPath, method: method, headers: headers }, function (res) {
            let text = '';
            if (jar) {
              (res.headers['set-cookie'] || []).forEach(function (line) {
                jar.cookie = [jar.cookie, line.split(';')[0]].filter(Boolean)
                  .join('; ');
              });
            }
            res.on('data', function (c) { text += c; });
            res.on('end', function () {
              resolve({ status: res.statusCode, headers: res.headers,
                        text: text });
            });
          });
          req.end(body);
        });
      };
      await realms.run(realms.DEFAULT_REALM, async function () {
        config.setOverride('oauth2.consentRequired', false);
        config.setOverride('security.rateLimitPerIdentity', '200');
        config.setOverride('security.rateLimitPerAddress', '1000');
        const BREACHED = 'Breached-At-Sign-In-Passw0rd!-5';
        ldap.createUser('cs-brie', { invent: false });
        const setFirst = credentials.setPassword('cs-brie', BREACHED);
        applications.createApplication({ identifier: 'cs-client',
          protocols: ['oauth2'],
          fields: { oauthClientId: 'cs-client',
                    oauthClientSecret: 'cs-client-secret-0123456789abcdef',
                    oauthRedirectUri: ['https://rp.cs.example/cb'],
                    oauthGrantType: ['authorization_code'],
                    oauthAllowedScope: ['openid'],
                    oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
        const bad = stsCrypto.pwnedPasswordDigest(BREACHED);
        fedHttp.fetchPublished = function (url) {
          const lines = ['0000000000000000000000000000000000A:3'];
          if (String(url).slice(-5) === bad.slice(0, 5)) {
            lines.push(bad.slice(5) + ':42');
          }
          return Promise.resolve({ ok: true, status: 200,
                                   body: Buffer.from(lines.join('\r\n')) });
        };
        breached.forget();
        config.setOverride('risk.breachCheck', 'on');
        const signIn = async function () {
          const jar = {};
          const verifier = nodeCrypto.randomBytes(32).toString('base64url');
          const first = await request('GET', '/oauth2/authorize?' +
            new URLSearchParams({ client_id: 'cs-client',
              response_type: 'code', redirect_uri: 'https://rp.cs.example/cb',
              scope: 'openid', state: 's', nonce: 'n',
              code_challenge: nodeCrypto.createHash('sha256')
                .update(verifier).digest('base64url'),
              code_challenge_method: 'S256' }).toString(), null, jar);
          const location = String(first.headers.location || '');
          const authnId = (location.match(/[?&]authn=([^&]+)/) || [])[1] ||
            '';
          const posted = await request('POST', '/authn/login',
            { authn_id: decodeURIComponent(authnId), username: 'cs-brie',
              password: BREACHED, action: 'login' }, jar);
          return { authnId: authnId, first: first, posted: posted };
        };
        let mark = since();
        const one = await signIn();
        await sleep(50);
        const compromised = riscAfter(mark, 'cs-brie', 'credentialCompromise');
        const required = riscAfter(mark, 'cs-brie',
                                   'credentialChangeRequired');
        note(setFirst.ok && one.authnId && one.posted.status === 200 &&
             credentials.passwordResetRequired('cs-brie'),
             'F1. the sign-in with a breached password is held at the ' +
             'change step', setFirst.ok + ' ' + one.first.status + ' ' +
             one.posted.status + ' ' + one.posted.text.slice(0, 200));
        note(compromised.length === 1 &&
             compromised[0].values.credential_type === 'password' &&
             compromised[0].initiatingEntity === 'system' &&
             required.length === 1,
             'F2. and it sends RISC credential-compromise (password) and ' +
             'account-credential-change-required',
             brief(compromised.concat(required)));
        mark = since();
        await signIn();
        await sleep(50);
        note(riscAfter(mark, 'cs-brie').length === 0,
             'F3. signing in again before changing it sends nothing more',
             brief(riscAfter(mark, 'cs-brie')));
      });
      server.close();
    }
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}
/* eslint-enable no-undef */

function inAChild(t, mode) {
  log.debug("Entering inAChild(). " + mode);
  const out = path.join(os.tmpdir(), 'credential-signals-' + process.pid +
                        '-' + mode + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  if (mode === 'product') {
    clean.STS_MODE = 'product';
  }
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', CS_ROOT: ROOT,
                                  CS_OUT: out, CS_MODE: mode }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the ' + mode + ' child reported ' +
                                        'its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1500))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, '[' + mode + '] ' + one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t, 'development');
  inAChild(t, 'product');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'credential_signals',
  describe: 'CAEP credential-change for the six credentials with no ' +
            'registered type (#236), RISC credential-compromise from every ' +
            'detector and the totp-replay risk signal (#231), and the LDAP ' +
            'socket, CIBA and bootstrap credential changes (#237)',
  run: run
};
