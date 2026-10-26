// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/passkey_dual_lane.js
//
// ===========================================================================
// A CLASSICAL PASSKEY AND A POST-QUANTUM ONE, SIDE BY SIDE (#643).
//
// `webauthn.pqcAlongsideClassical` (per realm, off by default) gives each
// passkey a LANE: the classical lane under the person's user handle with the
// configured algorithms less ML-DSA, the post-quantum lane under a second
// handle (`stsWebauthnPqcUserHandle`) with ML-DSA only, each excluding only
// its own keys. Asserted with REAL ceremonies from a software authenticator
// that signs ES256 and ML-DSA (`webauthn_attestation_kit.js`'s keys), in a
// CHILD PROCESS serving the stack on a loopback port
// (`passkey_discoverable.js`'s harness):
//
//   1. OFF: `lanes()` is classical alone; the registration options, with no
//      lane and in the classical lane, are the configured list ML-DSA first,
//      byte for byte; a post-quantum enrolment is refused (STS-AUTHN-0351);
//      the portal offers no choice and a classical row records no lane.
//   2. The switch on beside `webauthn.pqcOnly` is refused at the write,
//      either way round (STS-AUTHN-0353).
//   3. ON: a different `user.id` per lane, algorithm lists that do not
//      overlap, the post-quantum lane named `<username>+ml-dsa` /
//      `<display> (ML-DSA)` at creation, and per-lane exclude lists.
//   4. One person enrols an ES256 key in the classical lane and an
//      ML-DSA-65 key in the post-quantum lane; both rows exist with their
//      lanes and handles, the entry holds both handles, and the classical
//      lane's exclude list names the classical key only.
//   5. A credential in the wrong lane is refused as an algorithm that was
//      not offered (STS-AUTHN-0228), either way round.
//   6. Either handle names the same person (`userHandleHolder()`), and a
//      usernameless sign-in with each key signs that person in, the
//      session row recording the key's lane.
//   7. The post-quantum key returning the CLASSICAL handle is refused at
//      section 7.2 step 6 (STS-AUTHN-0303).
//   8. A typed `+ml-dsa`, `+ml-dsa-65` or `+pqc` name is refused at the
//      screen (STS-AUTHN-0354), and no such name holds alice's keys.
//   9. A key from before the lanes (no lane on its row) counts as
//      classical, and one from before #474 too.
//  10. The Signal API's data: one entry per lane, each with its own handle,
//      name and credential ids — the post-quantum one `<username>+ml-dsa-65`
//      after one ML-DSA-65 key, `<username>+ml-dsa` with two algorithms —
//      and the page draws `#wa-signal` and `#wa-signal-pqc`.
//  11. `webauthn.maxKeysPerPerson` counts both lanes.
//  12. The switch turned off: a post-quantum enrolment is refused, and the
//      post-quantum key still signs in.
//  13. A classical passkey proves possession before an ML-DSA registration:
//      alongside keeps both keys, a refusal leaves the classical one, and
//      with the lanes off the ML-DSA key replaces it.
//  14. An administrator's enrolment (#964), with the lanes on: a
//      self-enrolment begun first is still pending afterwards; the new
//      key's row and the answer both carry `lane` and `enrolledBy`; the
//      person's own confirmKeyEnrolment still drops that pending record.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'passkey_dual_lane',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in the child. Stringified, so it may use nothing from this file's
// scope, and — code in a `node -e` child — is exempt from the Entering/Leaving
// rule (root CLAUDE.md, *Code style*).
function childMain() {
  const ROOT = process.env.PKL_ROOT;
  const OUT = process.env.PKL_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const kit = require(ROOT + '/tests/webauthn_attestation_kit');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };

  function browser(port) {
    const jar = {};
    const go = function (method, urlPath) {
      return new Promise(function (resolve) {
        const headers = {};
        if (Object.keys(jar).length) {
          headers.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        const req = http.request({ host: '127.0.0.1', port: port,
                                   path: String(urlPath).replace(
                                     /^https?:\/\/[^/]+/, ''),
                                   method: method, headers: headers },
                                 function (res) {
          let text = '';
          (res.headers['set-cookie'] || []).forEach(function (line) {
            const pair = line.split(';')[0];
            const eq = pair.indexOf('=');
            jar[pair.slice(0, eq)] = pair.slice(eq + 1);
          });
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text });
          });
        });
        req.end();
      });
    };
    return { go: go, jar: jar };
  }

  // A SOFTWARE AUTHENTICATOR OVER THE KIT'S KEYS: ES256 (-7) or ML-DSA
  // (-48, -49, -50). It holds the user handle it was created under and hands
  // it back on every assertion, as a discoverable credential does.
  const sha256 = function (buf) {
    return nodeCrypto.createHash('sha256').update(buf).digest();
  };
  const makeAuthenticator = async function (alg, rpId, origin) {
    const cred = await kit.credential(alg);
    let signCount = 0;
    let userHandle = '';
    const clientData = function (type, challenge) {
      return Buffer.from(JSON.stringify({ type: type, challenge: challenge,
                                          origin: origin,
                                          crossOrigin: false }), 'utf8');
    };
    const id = cred.id.toString('base64url');
    return {
      credentialId: id,
      register: function (challenge, handle) {
        userHandle = handle;
        const count = Buffer.alloc(4);
        const idLen = Buffer.alloc(2);
        idLen.writeUInt16BE(cred.id.length, 0);
        // UP, UV and AT.
        const data = Buffer.concat([sha256(Buffer.from(rpId, 'utf8')),
          Buffer.from([0x45]), count, Buffer.alloc(16), idLen, cred.id,
          kit.cbor(cred.cose)]);
        const attestationObject = kit.cbor(new Map([['fmt', 'none'],
          ['attStmt', new Map()], ['authData', data]]));
        return { id: id, rawId: id, type: 'public-key',
                 authenticatorAttachment: 'platform',
                 clientExtensionResults: { credProps: { rk: true } },
                 response: {
                   attestationObject: attestationObject.toString('base64url'),
                   clientDataJSON: clientData('webauthn.create', challenge)
                     .toString('base64url') } };
      },
      assert: function (challenge, opts) {
        const o = opts || {};
        signCount += 1;
        const count = Buffer.alloc(4);
        count.writeUInt32BE(signCount, 0);
        // UP and UV.
        const data = Buffer.concat([sha256(Buffer.from(rpId, 'utf8')),
                                    Buffer.from([0x05]), count]);
        const cdj = clientData('webauthn.get', challenge);
        const signature = cred.sign(Buffer.concat([data, sha256(cdj)]));
        const handle = o.handle === undefined ? userHandle : o.handle;
        return { id: id, rawId: id, type: 'public-key',
                 response: {
                   authenticatorData: data.toString('base64url'),
                   clientDataJSON: cdj.toString('base64url'),
                   signature: Buffer.from(signature).toString('base64url'),
                   userHandle: handle || null } };
      }
    };
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const passkeyPolicy = require(ROOT + '/common/passkey_policy');
    const applications = require(ROOT + '/common/applications');
    const credentials = require(ROOT + '/common/credentials');
    const webauthnPolicy = require(ROOT + '/authn/webauthn_policy');
    const errorCodes = require(ROOT + '/common/error_codes');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const audit = require(ROOT + '/common/audit');
    const accountKeys = require(ROOT + '/portal/account_keys');
    const keysPages = require(ROOT + '/portal/web_keys');
    const authnScreen = require(ROOT + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const ORIGIN = 'http://127.0.0.1:' + port;
    const RPID = '127.0.0.1';
    const REDIRECT = 'https://rp.pkl.example/cb';
    const PASSWORD = 'correct-horse-battery-staple-pkl-7!';
    const ON = 'webauthn.pqcAlongsideClassical';
    // The default `webauthn.algorithms`, as COSE identifiers: what a realm
    // that never turned the switch on has always been sent (the snapshot).
    const CONFIGURED = [-48, -49, -50, -9, -7, -19, -8, -51, -35, -52, -36,
                        -53, -47, -37, -38, -39, -257, -258, -259];
    config.setOverride('oauth2.consentRequired', false);
    passkeyPolicy.save('default', Object.assign({}, passkeyPolicy.DEFAULTS,
                                                { allowUsernameless: true }));

    applications.createApplication({ identifier: 'pkl-public',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'pkl-public', oauthClientSecret: '',
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'none',
                oauthGrantType: ['authorization_code'] } });
    ['pkl-alice', 'pkl-bob', 'pkl-legacy', 'pkl-upgrade', 'pkl-failure'].forEach(function (name) {
      ldap.createUser(name, { invent: false });
      credentials.setPassword(name, PASSWORD);
    });

    const codeRecorded = function (code) {
      return audit.list().some(function (row) {
        return row.errorCode === code;
      });
    };
    const screenFor = async function () {
      const b = browser(port);
      const verifier = nodeCrypto.randomBytes(32).toString('base64url');
      const start = await b.go('GET', '/oauth2/authorize?' +
        new URLSearchParams({ client_id: 'pkl-public', response_type: 'code',
          redirect_uri: REDIRECT, scope: 'openid', state: 's',
          nonce: 'n-' + nodeCrypto.randomBytes(8).toString('hex'),
          code_challenge: nodeCrypto.createHash('sha256').update(verifier)
            .digest('base64url'),
          code_challenge_method: 'S256' }).toString());
      const opened = await authnScreen.open({ port: port, jar: b.jar,
        at: String(start.headers.location || '') });
      return { b: b, opened: opened, view: opened.view || {} };
    };
    const usernameless = async function (credentialOf) {
      const s = await screenFor();
      const armed = await authnScreen.passkeyOptions({ port: port,
        jar: s.b.jar, opened: s.opened });
      return authnScreen.act({ port: port, jar: s.b.jar, opened: s.opened,
        path: '/authn-api/pending/' + encodeURIComponent(s.opened.id) +
              '/passkey',
        body: { credential: JSON.stringify(credentialOf(armed.challenge)) }
      });
    };
    const signedIn = function (posted) {
      return posted.status === 302 || posted.status === 303;
    };
    const refusedAct = function (posted) {
      return posted.apiStatus === 400 && posted.next === 'refused';
    };
    // The session.start row of a person's newest session: the one whose
    // session this function has not answered before (the audit list's own
    // order is not what the assertion is about).
    const seenSessions = {};
    const lastStart = function (name) {
      const fresh = audit.list().filter(function (row) {
        return row.action === 'session.start' && row.actor === name &&
               !seenSessions[(row.detail || {}).sessionId];
      });
      fresh.forEach(function (row) {
        seenSessions[(row.detail || {}).sessionId] = true;
      });
      return fresh.length === 1 ? fresh[0] : null;
    };
    // An enrolment, begun and answered: `make(begun)` is the credential.
    const enrol = async function (name, opts, make) {
      const begun = credentials.beginKeyEnrolment(name, opts);
      if (!begun.ok) {
        return { begun: begun, done: begun };
      }
      const done = await credentials.confirmKeyEnrolment(name,
        begun.enrolmentId, make(begun), { origin: ORIGIN, rpId: RPID });
      if (!done.ok) {
        credentials.abandonKeyEnrolment(name);
      }
      return { begun: begun, done: done };
    };
    const ids = function (opts) {
      return JSON.stringify((opts || {}).algorithms || []);
    };
    const view = function (name) {
      const keys = new accountKeys.AccountKeys(
        accountKeys.AccountKeys.defaultDeps());
      return keys.view({ username: name, session: { user: { name: name } } },
                       ORIGIN);
    };

    // 1. OFF.
    const plain = webauthnPolicy.creationOptions(RPID, 'passkey');
    const classicalOff = webauthnPolicy.creationOptions(RPID, 'passkey',
                                                        'classical');
    note(JSON.stringify(webauthnPolicy.lanes()) === '["classical"]' &&
         ids(plain) === JSON.stringify(CONFIGURED) &&
         JSON.stringify(classicalOff) === JSON.stringify(plain),
         '1a. off: one lane, and the options — with no lane or in the ' +
         'classical lane — are the configured list, ML-DSA first, byte for ' +
         'byte', JSON.stringify(plain));
    const pqcOff = credentials.beginKeyEnrolment('pkl-bob',
      { role: 'primary', kind: 'passkey', lane: 'pqc' });
    note(!pqcOff.ok && errorCodes.codeOf(pqcOff) === 'STS-AUTHN-0351',
         '1b. off: a post-quantum enrolment is refused (STS-AUTHN-0351)',
         JSON.stringify(pqcOff));
    const bobOff = await makeAuthenticator(-7, RPID, ORIGIN);
    const bobEnrolled = await enrol('pkl-bob',
      { role: 'primary', kind: 'passkey' }, function (b) {
        return bobOff.register(b.challenge, b.userHandle);
      });
    const bobRow = credentials.keysOf('pkl-bob')[0] || {};
    note(bobEnrolled.done.ok && !('lane' in bobRow) &&
         credentials.keyLane(bobRow) === 'classical' &&
         JSON.stringify(view('pkl-bob').enrol.lanes) === '["classical"]',
         '1c. off: a classical row records no lane — as every row before ' +
         'the lanes — and the portal offers no choice',
         JSON.stringify(bobEnrolled.done) + ' ' + JSON.stringify(bobRow)
           .slice(0, 200));

    // 2. Beside pqcOnly, refused at the write either way round.
    config.setOverride('webauthn.pqcOnly', true);
    const refusedOn = config.checkOverrideCode(ON, 'true');
    config.clearOverride('webauthn.pqcOnly');
    config.setOverride(ON, true);
    const refusedOnly = config.checkOverrideCode('webauthn.pqcOnly', 'true');
    const fineOff = config.checkOverrideCode('webauthn.pqcOnly', 'false');
    note(refusedOn === 'STS-AUTHN-0353' && refusedOnly === 'STS-AUTHN-0353' &&
         fineOff === '',
         '2. the switch beside webauthn.pqcOnly is refused at the write, ' +
         'either way round (STS-AUTHN-0353)',
         [refusedOn, refusedOnly, fineOff].join(' '));

    // 3. ON.
    const classicalOn = webauthnPolicy.creationOptions(RPID, 'passkey',
                                                       'classical');
    const pqcOn = webauthnPolicy.creationOptions(RPID, 'passkey', 'pqc');
    const overlap = classicalOn.algorithms.filter(function (a) {
      return pqcOn.algorithms.indexOf(a) >= 0;
    });
    note(JSON.stringify(webauthnPolicy.lanes()) === '["classical","pqc"]' &&
         ids(pqcOn) === '[-48,-49,-50]' &&
         ids(classicalOn) === JSON.stringify(CONFIGURED.slice(3)) &&
         overlap.length === 0,
         '3a. on: two lanes, ML-DSA alone in the post-quantum one and the ' +
         'rest in the classical one, with no algorithm in both',
         ids(classicalOn) + ' / ' + ids(pqcOn));
    const aliceClassical = await makeAuthenticator(-7, RPID, ORIGIN);
    const alicePqc = await makeAuthenticator(-49, RPID, ORIGIN);
    const c1 = await enrol('pkl-alice', { role: 'primary', kind: 'passkey',
                                          lane: 'classical' },
      function (b) {
        return aliceClassical.register(b.challenge, b.userHandle);
      });
    const pqcBegun = credentials.beginKeyEnrolment('pkl-alice',
      { role: 'primary', kind: 'passkey', lane: 'pqc' });
    const pending = view('pkl-alice').enrol.pending || {};
    note(pqcBegun.ok && pqcBegun.lane === 'pqc' &&
         credentials.isUserHandle(pqcBegun.userHandle) &&
         pqcBegun.userHandle !== c1.begun.userHandle &&
         pqcBegun.exclude.length === 0 &&
         pending.user === 'pkl-alice+ml-dsa' &&
         pending.display === 'pkl-alice (ML-DSA)' &&
         ids(pending.options) === '[-48,-49,-50]',
         '3b. the post-quantum lane has its own handle, excludes none of the ' +
         'classical keys, and is named pkl-alice+ml-dsa / "pkl-alice ' +
         '(ML-DSA)" at creation', JSON.stringify(pending).slice(0, 300));

    // 4. Both lanes, one person.
    const p1 = await credentials.confirmKeyEnrolment('pkl-alice',
      pqcBegun.enrolmentId,
      alicePqc.register(pqcBegun.challenge, pqcBegun.userHandle),
      { origin: ORIGIN, rpId: RPID });
    const rows = credentials.keysOf('pkl-alice');
    const rowOf = function (id) {
      return rows.filter(function (one) {
        return one.credentialId === id;
      })[0] || {};
    };
    const cRow = rowOf(aliceClassical.credentialId);
    const pRow = rowOf(alicePqc.credentialId);
    note(c1.done.ok && p1.ok && rows.length === 2 &&
         credentials.keyLane(cRow) === 'classical' && pRow.lane === 'pqc' &&
         cRow.userHandle === credentials.userHandleOf('pkl-alice') &&
         pRow.userHandle === credentials.userHandleOf('pkl-alice',
                                                      { lane: 'pqc' }) &&
         cRow.userHandle !== pRow.userHandle &&
         credentials.keyAlgorithm(pRow).name === 'ML-DSA-65' &&
         credentials.keyAlgorithm(pRow).lane === 'pqc',
         '4a. an ES256 key in the classical lane and an ML-DSA-65 key in ' +
         'the post-quantum lane: both rows, each with its lane and its own ' +
         'handle, which the entry holds', JSON.stringify([c1.done, p1]));
    const again = credentials.beginKeyEnrolment('pkl-alice',
      { role: 'primary', kind: 'passkey', lane: 'classical' });
    note(again.ok &&
         JSON.stringify(again.exclude) ===
           JSON.stringify([aliceClassical.credentialId]),
         '4b. the classical lane excludes the classical key only',
         JSON.stringify(again.exclude));
    credentials.abandonKeyEnrolment('pkl-alice');

    // 5. The wrong lane.
    const wrongPqc = await makeAuthenticator(-48, RPID, ORIGIN);
    const w1 = await enrol('pkl-alice', { role: 'primary', kind: 'passkey',
                                          lane: 'classical' },
      function (b) {
        return wrongPqc.register(b.challenge, b.userHandle);
      });
    const wrongClassical = await makeAuthenticator(-7, RPID, ORIGIN);
    const w2 = await enrol('pkl-alice', { role: 'primary', kind: 'passkey',
                                          lane: 'pqc' },
      function (b) {
        return wrongClassical.register(b.challenge, b.userHandle);
      });
    note(!w1.done.ok && errorCodes.codeOf(w1.done) === 'STS-AUTHN-0228' &&
         !w2.done.ok && errorCodes.codeOf(w2.done) === 'STS-AUTHN-0228' &&
         credentials.keysOf('pkl-alice').length === 2,
         '5. an ML-DSA key answering the classical lane, and an ES256 key ' +
         'the post-quantum one, are refused as algorithms not offered ' +
         '(STS-AUTHN-0228)', JSON.stringify([w1.done, w2.done]));

    // 6. Either handle, one person.
    const holderC = credentials.userHandleHolder(cRow.userHandle) || {};
    const holderP = credentials.userHandleHolder(pRow.userHandle) || {};
    note(holderC.username === 'pkl-alice' && holderC.lane === 'classical' &&
         holderP.username === 'pkl-alice' && holderP.lane === 'pqc' &&
         credentials.ownerOfUserHandle(pRow.userHandle) === 'pkl-alice',
         '6a. either handle names the same person, and its lane',
         JSON.stringify([holderC, holderP]));
    lastStart('pkl-alice');
    let posted = await usernameless(function (challenge) {
      return aliceClassical.assert(challenge);
    });
    const startC = lastStart('pkl-alice');
    note(signedIn(posted) && startC &&
         startC.detail.credentialLane === 'classical' &&
         /^ES256 /.test(String(startC.detail.credentialAlgorithm)),
         '6b. a usernameless sign-in with the classical key signs her in, ' +
         'the session row recording ES256 and the classical lane',
         posted.status + ' ' + JSON.stringify(startC && startC.detail));
    posted = await usernameless(function (challenge) {
      return alicePqc.assert(challenge);
    });
    const startP = lastStart('pkl-alice');
    note(signedIn(posted) && startP &&
         startP.detail.credentialLane === 'pqc' &&
         /^ML-DSA-65 /.test(String(startP.detail.credentialAlgorithm)),
         '6c. and with the post-quantum key, under the other handle, the ' +
         'same person, the row recording ML-DSA-65 and the pqc lane',
         posted.status + ' ' + JSON.stringify(startP && startP.detail) +
         ' ' + posted.text.slice(0, 200));

    // 7. The post-quantum key under the classical handle.
    posted = await usernameless(function (challenge) {
      return alicePqc.assert(challenge, { handle: cRow.userHandle });
    });
    note(refusedAct(posted) && codeRecorded('STS-AUTHN-0303'),
         '7. the post-quantum key returning the classical handle is ' +
         'refused at section 7.2 step 6 (STS-AUTHN-0303)',
         posted.apiStatus + ' ' + posted.text.slice(0, 200));

    // 8. A lane's name is not a sign-in name.
    const typedNames = ['pkl-alice+ml-dsa', 'pkl-alice+ML-DSA-65',
                        'pkl-alice+pqc'];
    const typedAnswers = [];
    for (const name of typedNames) {
      const s = await screenFor();
      typedAnswers.push(await authnScreen.submit({ port: port, jar: s.b.jar,
        opened: s.opened, fields: { action: 'login', username: name,
                                    password: PASSWORD } }));
    }
    note(typedAnswers.every(refusedAct) && codeRecorded('STS-AUTHN-0354') &&
         typedNames.every(function (name) {
           return credentials.keysOf(name).length === 0;
         }),
         '8. a typed +ml-dsa, +ml-dsa-65 or +pqc name is refused at the ' +
         'screen (STS-AUTHN-0354), and holds none of alice\'s keys',
         typedAnswers.map(function (a) {
           return a.apiStatus + ' ' + a.next;
         }).join(', '));

    // 9. Keys from before the lanes are classical.
    const legacy = await makeAuthenticator(-7, RPID, ORIGIN);
    credentials.addKey('pkl-legacy', { credentialId: legacy.credentialId,
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' } },
      'primary');
    const legacyRow = credentials.keysOf('pkl-legacy')[0] || {};
    const legacyClassical = credentials.beginKeyEnrolment('pkl-legacy',
      { role: 'primary', lane: 'classical' });
    credentials.abandonKeyEnrolment('pkl-legacy');
    const legacyPqc = credentials.beginKeyEnrolment('pkl-legacy',
      { role: 'primary', lane: 'pqc' });
    credentials.abandonKeyEnrolment('pkl-legacy');
    note(!('lane' in legacyRow) && !legacyRow.userHandle &&
         credentials.keyLane(legacyRow) === 'classical' &&
         legacyClassical.exclude.indexOf(legacy.credentialId) >= 0 &&
         legacyPqc.exclude.indexOf(legacy.credentialId) < 0 &&
         credentials.keyLane(bobRow) === 'classical',
         '9. a key with no lane on its row — from before #474 here — is ' +
         'classical: the classical lane excludes it and the post-quantum ' +
         'lane does not', JSON.stringify([legacyClassical.exclude,
                                          legacyPqc.exclude]));

    // 10. The Signal API, one entry per lane.
    let signals = view('pkl-alice').signals || [];
    const sigOf = function (lane) {
      return signals.filter(function (one) {
        return one.lane === lane;
      })[0] || {};
    };
    note(signals.length === 2 &&
         sigOf('classical').userId === cRow.userHandle &&
         sigOf('pqc').userId === pRow.userHandle &&
         JSON.stringify(sigOf('classical').accepted) ===
           JSON.stringify([aliceClassical.credentialId]) &&
         JSON.stringify(sigOf('pqc').accepted) ===
           JSON.stringify([alicePqc.credentialId]) &&
         sigOf('classical').name === 'pkl-alice' &&
         sigOf('pqc').name === 'pkl-alice+ml-dsa-65' &&
         sigOf('pqc').display === 'pkl-alice (ML-DSA-65)',
         '10a. one signal per lane, each with its own handle and ids; the ' +
         'post-quantum one named for its one algorithm, pkl-alice+ml-dsa-65',
         JSON.stringify(signals));
    const block = keysPages.signalBlock(signals);
    note(/id="wa-signal" /.test(block) && /id="wa-signal-pqc" /.test(block) &&
         block.indexOf(pRow.userHandle) > block.indexOf('wa-signal-pqc'),
         '10b. the page draws #wa-signal and #wa-signal-pqc, each carrying ' +
         'its own lane', block.slice(0, 300));
    note((view('pkl-bob').signals || []).length === 1,
         '10c. a person holding no post-quantum handle is signalled one ' +
         'lane only');
    const alicePqc44 = await makeAuthenticator(-48, RPID, ORIGIN);
    const p2 = await enrol('pkl-alice', { role: 'primary', kind: 'passkey',
                                          lane: 'pqc' },
      function (b) {
        return alicePqc44.register(b.challenge, b.userHandle);
      });
    signals = view('pkl-alice').signals || [];
    note(p2.done.ok && sigOf('pqc').name === 'pkl-alice+ml-dsa' &&
         sigOf('pqc').display === 'pkl-alice (ML-DSA)' &&
         sigOf('pqc').accepted.length === 2 &&
         p2.begun.exclude.indexOf(alicePqc.credentialId) >= 0,
         '10d. with ML-DSA-65 and ML-DSA-44 keys the post-quantum signal is ' +
         'the generic pkl-alice+ml-dsa, and the lane excluded its own key',
         JSON.stringify(sigOf('pqc')));

    // 11. The cap counts both lanes.
    config.setOverride('webauthn.maxKeysPerPerson', 3);
    const capped = credentials.beginKeyEnrolment('pkl-alice',
      { role: 'primary', lane: 'classical' });
    config.clearOverride('webauthn.maxKeysPerPerson');
    note(!capped.ok && errorCodes.codeOf(capped) === 'STS-AUTHN-0067',
         '11. webauthn.maxKeysPerPerson counts both lanes: one classical ' +
         'and two post-quantum keys are three', JSON.stringify(capped));

    // 12. Off again.
    config.clearOverride(ON);
    const offAgain = credentials.beginKeyEnrolment('pkl-alice',
      { role: 'primary', lane: 'pqc' });
    posted = await usernameless(function (challenge) {
      return alicePqc.assert(challenge);
    });
    note(!offAgain.ok && errorCodes.codeOf(offAgain) === 'STS-AUTHN-0351' &&
         signedIn(posted),
         '12. switched off, a post-quantum enrolment is refused ' +
         '(STS-AUTHN-0351) and the post-quantum key still signs in',
         JSON.stringify(offAgain) + ' ' + posted.status);
    // 13. A classical passkey proves possession before an ML-DSA
    // registration. Both the alongside lane and in-place replacement work;
    // a failed registration leaves the original classical key unchanged.
    config.setOverride(ON, true);
    const upOld = await makeAuthenticator(-7, RPID, ORIGIN);
    const upSeed = await enrol('pkl-upgrade',
      { role: 'primary', kind: 'passkey', lane: 'classical' },
      function (b) { return upOld.register(b.challenge, b.userHandle); });
    const beginUpgrade = credentials.beginKeyUpgrade('pkl-upgrade',
      upOld.credentialId);
    const proveUpgrade = await credentials.proveKeyUpgrade('pkl-upgrade',
      beginUpgrade.upgradeId, upOld.assert(beginUpgrade.challenge),
      { origin: ORIGIN, rpId: RPID });
    const proofView = view('pkl-upgrade').upgrade || {};
    const proofHtml = keysPages.upgradeBlock(proofView,
      { html: function (key) { return '[' + key + ']'; } });
    const upNew = await makeAuthenticator(-49, RPID, ORIGIN);
    const sideDone = await credentials.confirmKeyUpgrade('pkl-upgrade',
      beginUpgrade.upgradeId,
      upNew.register(proveUpgrade.challenge, proveUpgrade.userHandle),
      { origin: ORIGIN, rpId: RPID });
    const sideRows = credentials.keysOf('pkl-upgrade');
    const oldSide = sideRows.filter(function (one) {
      return one.credentialId === upOld.credentialId;
    })[0] || {};
    const newSide = sideRows.filter(function (one) {
      return one.credentialId === upNew.credentialId;
    })[0] || {};
    const sideHistory = credentials.keyUpgradeHistory(newSide) || {};
    const upgradeOps = new accountKeys.AccountKeys(
      accountKeys.AccountKeys.defaultDeps()).accountOperations({
        BASE: '/account-api', PORTAL: '/portal' });
    note(upSeed.done.ok && beginUpgrade.ok && proveUpgrade.ok &&
         proofView.pending && proofView.pending.phase === 'registration' &&
         proofView.pending.options.algorithms.join(',') === '-48,-49,-50' &&
         proofHtml.indexOf('data-mode="create"') >= 0 &&
         upgradeOps.some(function (op) {
           return op.operationId === 'upgradeKey' &&
                  op.path === '/account-api/keys/upgrade';
         }) &&
         sideDone.ok && sideDone.mode === 'alongside' &&
         sideRows.length === 2 && oldSide.upgradedTo === upNew.credentialId &&
         sideHistory.previousAlgorithm === 'ES256' &&
         sideHistory.mode === 'alongside',
         '13a. the portal exposes an ML-DSA-only upgrade after proof, and ' +
         'the alongside write records both keys and upgrade history',
         JSON.stringify([beginUpgrade, proveUpgrade, sideDone, sideHistory]));
    const failOld = await makeAuthenticator(-7, RPID, ORIGIN);
    const failSeed = await enrol('pkl-failure',
      { role: 'primary', kind: 'passkey', lane: 'classical' },
      function (b) { return failOld.register(b.challenge, b.userHandle); });
    const failBegin = credentials.beginKeyUpgrade('pkl-failure',
      failOld.credentialId);
    const failProof = await credentials.proveKeyUpgrade('pkl-failure',
      failBegin.upgradeId, failOld.assert(failBegin.challenge),
      { origin: ORIGIN, rpId: RPID });
    const failDone = await credentials.confirmKeyUpgrade('pkl-failure',
      failBegin.upgradeId, { error: 'NotAllowedError' },
      { origin: ORIGIN, rpId: RPID });
    const failRows = credentials.keysOf('pkl-failure');
    note(failSeed.done.ok && failProof.ok && !failDone.ok &&
         failRows.length === 1 &&
         failRows[0].credentialId === failOld.credentialId &&
         !credentials.keyUpgradeHistory(failRows[0]),
         '13b. a refused ML-DSA registration keeps the classical passkey',
         JSON.stringify([failDone, failRows]));

    // 14. AN ADMINISTRATOR'S ENROLMENT DOES NOT RUN THE PERSON'S EPILOGUE
    // (#964). The two doors share verifyKeyRegistration; `written` is the
    // door's finish. Self-enrolment drops pendingKeys. An administrator's
    // must not — that record is the person's own ceremony — and must
    // answer lane and enrolledBy. The credential is the kit's `none`
    // attestation, the same bytes section 4 registers with, so
    // verification is not stubbed.
    const adminPolicy = passkeyPolicy.save('default',
      Object.assign({}, passkeyPolicy.DEFAULTS, {
        allowUsernameless: true, adminEnrolment: 'on' }));
    const kept = 'pkl-kept';
    ldap.createUser(kept, { invent: false });
    credentials.setPassword(kept, PASSWORD);
    const selfBegun = credentials.beginKeyEnrolment(kept, {
      role: 'mfa', kind: 'passkey', lane: 'pqc' });
    const admin = { username: 'pkl-operator',
                    sub: 'urn:uuid:pkl-operator' };
    const adminBegun = credentials.beginAdminKeyEnrolment(kept, admin, {
      role: 'mfa', kind: 'passkey', lane: 'pqc' });
    const adminAuth = await makeAuthenticator(-49, RPID, ORIGIN);
    const adminDone = adminBegun.ok
      ? await credentials.confirmAdminKeyEnrolment(kept, admin,
          adminBegun.enrolmentId,
          adminAuth.register(adminBegun.challenge,
                             adminBegun.userHandle),
          { origin: ORIGIN, rpId: RPID })
      : adminBegun;
    const still = credentials.pendingKeyEnrolmentFor(kept);
    const adminRow = credentials.keysOf(kept).filter(function (one) {
      return one.credentialId === adminAuth.credentialId;
    })[0] || {};
    const by = adminRow.enrolledBy || {};
    const answered = (adminDone && adminDone.enrolledBy) || {};
    note(adminPolicy.ok !== false && selfBegun.ok && adminBegun.ok &&
         adminDone.ok === true && !!still &&
         still.id === selfBegun.enrolmentId &&
         adminRow.lane === 'pqc' && by.username === admin.username &&
         by.sub === admin.sub && by.at > 0 &&
         adminDone.lane === 'pqc' &&
         answered.username === admin.username &&
         answered.sub === admin.sub && answered.at > 0,
         '14a. an administrator\'s enrolment keeps a pending ' +
         'self-enrolment, and the key and the answer carry lane and ' +
         'enrolledBy',
         JSON.stringify({ policy: adminPolicy.ok, self: selfBegun.ok,
           begun: adminBegun.ok, done: adminDone,
           pending: still && still.id,
           row: { lane: adminRow.lane, enrolledBy: adminRow.enrolledBy } }));
    const ownAuth = await makeAuthenticator(-49, RPID, ORIGIN);
    const ownDone = selfBegun.ok
      ? await credentials.confirmKeyEnrolment(kept, selfBegun.enrolmentId,
          ownAuth.register(selfBegun.challenge, selfBegun.userHandle),
          { origin: ORIGIN, rpId: RPID })
      : selfBegun;
    note(ownDone.ok === true &&
         credentials.pendingKeyEnrolmentFor(kept) === null,
         '14b. the person\'s own confirmKeyEnrolment still drops its ' +
         'pending record', JSON.stringify(ownDone));
    // Optional rows left out of a save are kept (#907), so `off` is said.
    passkeyPolicy.save('default', Object.assign({}, passkeyPolicy.DEFAULTS,
      { allowUsernameless: true, adminEnrolment: 'off' }));
    config.clearOverride(ON);
    const replaceOld = credentials.keysOf('pkl-bob')[0] || {};
    const replaceBegin = credentials.beginKeyUpgrade('pkl-bob',
      replaceOld.credentialId);
    const replaceProof = await credentials.proveKeyUpgrade('pkl-bob',
      replaceBegin.upgradeId, bobOff.assert(replaceBegin.challenge),
      { origin: ORIGIN, rpId: RPID });
    const replaceNew = await makeAuthenticator(-49, RPID, ORIGIN);
    const replaceDone = await credentials.confirmKeyUpgrade('pkl-bob',
      replaceBegin.upgradeId,
      replaceNew.register(replaceProof.challenge, replaceProof.userHandle),
      { origin: ORIGIN, rpId: RPID });
    const replaceRows = credentials.keysOf('pkl-bob');
    // #643 stores the classical lane by leaving `lane` off the row.
    // `keyLane()` is what reads that as classical. #939's replace write
    // puts the ML-DSA key in that lane; it does not add a second row.
    note(replaceBegin.ok && replaceProof.ok && replaceDone.ok &&
         replaceDone.mode === 'replace' &&
         replaceDone.lane === 'classical' &&
         replaceRows.length === 1 &&
         replaceRows[0].credentialId === replaceNew.credentialId &&
         credentials.keyLane(replaceRows[0]) === 'classical' &&
         replaceRows[0].lane !== 'pqc' &&
         (credentials.keyUpgradeHistory(replaceRows[0]) || {})
           .previousAlgorithm === 'ES256',
         '13c. when the lanes are not alongside, the ML-DSA key replaces ' +
         'the proved classical key in the classical lane',
         JSON.stringify([replaceDone, replaceRows,
           credentials.keyLane(replaceRows[0])]));
    server.close();
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'sts-pkl-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { PKL_OUT: out, PKL_ROOT: ROOT,
    STS_HTTPS: 'false' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      cwd: ROOT, env: env, encoding: 'utf8', timeout: 180000,
      maxBuffer: 256 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'passkey_dual_lane',
  describe: 'a classical and a post-quantum passkey side by side for one ' +
            'person, each lane with its own handle, algorithms and exclude ' +
            'list, behind webauthn.pqcAlongsideClassical (#643)',
  run: run
};
