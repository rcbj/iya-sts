// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/passkey_post_quantum_required.js
//
// ===========================================================================
// A POST-QUANTUM PASSKEY REQUIRED (#718).
//
// The passkey policy's `postQuantumRequired` (`off`, `sign-in`,
// `registration-and-sign-in`), decided by the issuance policy on the key's
// ALGORITHM. Asserted with REAL ceremonies from a software authenticator
// that signs ES256 and ML-DSA (`webauthn_attestation_kit.js`'s keys), in a
// CHILD PROCESS serving the stack on a loopback port
// (`passkey_dual_lane.js`'s harness):
//
//   1. THE SAVE: requiring it while the realm offers no ML-DSA is refused
//      (STS-AUTHN-0357); `webauthn.pqcOnly` or the post-quantum lane makes
//      it offered.
//   2. A NAMED PROFILE SELECTED BY APPLICATION refuses a classical passkey
//      for that application only: a usernameless sign-in to it is refused
//      after the ceremony (STS-AUTHN-0356, a `session.refuse` row), and the
//      same key signs in to another application.
//   3. An ML-DSA key enrolled with #643's switch off — its row records no
//      lane — signs in under the requirement: the algorithm decides.
//   4. THE FILTERED allowCredentials: the passkey step names only the
//      person's post-quantum keys, and the ML-DSA one signs in.
//   5. BOTH ROLES: a person holding only classical keys is told before the
//      ceremony, at the passwordless step (primary) and at the step after a
//      password (second factor), with the refusal recorded; an assertion
//      sent anyway is refused at the session's start.
//   6. THE SIGNAL: one CAEP credential-change per key and reason, however
//      many times the key is refused, and the mark on its row.
//   7. THE WARNINGS: `/portal/keys` and the console mark the classical key
//      and not the post-quantum one.
//   8. `registration-and-sign-in`: enrolment offers only ML-DSA; an ES256
//      enrolment is refused; `addKey()`, the one writer, refuses a classical
//      key (STS-AUTHN-0355, reason `post-quantum`) and takes an ML-DSA one;
//      with both lanes on, only the post-quantum lane is offered and a
//      classical choice becomes it.
//   9. The device link refuses a classical key while it is required.
//  10. `off` again: the classical key signs in.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'passkey_post_quantum_required',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in the child. Stringified, so it may use nothing from this file's
// scope, and — code in a `node -e` child — is exempt from the Entering/Leaving
// rule (root CLAUDE.md, *Code style*).
function childMain() {
  const ROOT = process.env.PQR_ROOT;
  const OUT = process.env.PQR_OUT;
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
  // (-48, -49, -50), `passkey_dual_lane.js`'s. It holds the user handle it
  // was created under and hands it back on every assertion.
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
      assert: function (challenge) {
        signCount += 1;
        const count = Buffer.alloc(4);
        count.writeUInt32BE(signCount, 0);
        // UP and UV.
        const data = Buffer.concat([sha256(Buffer.from(rpId, 'utf8')),
                                    Buffer.from([0x05]), count]);
        const cdj = clientData('webauthn.get', challenge);
        const signature = cred.sign(Buffer.concat([data, sha256(cdj)]));
        return { id: id, rawId: id, type: 'public-key',
                 response: {
                   authenticatorData: data.toString('base64url'),
                   clientDataJSON: cdj.toString('base64url'),
                   signature: Buffer.from(signature).toString('base64url'),
                   userHandle: userHandle || null } };
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
    const adminViews = require(ROOT + '/admin-core/admin_views');
    const deviceEnrolment = require(ROOT + '/common/device_enrolment');
    const authnScreen = require(ROOT + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const ORIGIN = 'http://127.0.0.1:' + port;
    const RPID = '127.0.0.1';
    const REDIRECT = 'https://rp.pqr.example/cb';
    const PASSWORD = 'correct-horse-battery-staple-pqr-7!';
    const STRICT = 'pqr-strict';
    const LOOSE = 'pqr-loose';
    config.setOverride('oauth2.consentRequired', false);

    // EVERY CAEP credential-change this child sends, counted: the facade is
    // the object `authn.ts` holds as its dependency (#530's arrangement).
    const accountSignals = require(ROOT + '/ssf/account_signals');
    const changes = [];
    const realChanged = accountSignals.credentialChanged;
    accountSignals.credentialChanged = function (said) {
      changes.push(said);
      return realChanged.apply(this, arguments);
    };

    [STRICT, LOOSE].forEach(function (client) {
      applications.createApplication({ identifier: client,
        protocols: ['oauth2'],
        fields: { oauthClientId: client, oauthClientSecret: '',
                  oauthRedirectUri: [REDIRECT],
                  oauthTokenEndpointAuthMethod: 'none',
                  oauthGrantType: ['authorization_code'] } });
    });
    ['pqr-alice', 'pqr-bob', 'pqr-carol', 'pqr-dave', 'pqr-erin']
      .forEach(function (name) {
        ldap.createUser(name, { invent: false });
        credentials.setPassword(name, PASSWORD);
      });

    const withDefaults = function (fields) {
      return Object.assign({}, passkeyPolicy.DEFAULTS,
                           { allowUsernameless: true }, fields || {});
    };
    const refusals = function (name, code) {
      return audit.list().filter(function (row) {
        return row.action === 'session.refuse' && row.errorCode === code &&
               String(row.actor) === name;
      }).length;
    };
    const screenFor = async function (client) {
      const b = browser(port);
      const verifier = nodeCrypto.randomBytes(32).toString('base64url');
      const start = await b.go('GET', '/oauth2/authorize?' +
        new URLSearchParams({ client_id: client, response_type: 'code',
          redirect_uri: REDIRECT, scope: 'openid', state: 's',
          nonce: 'n-' + nodeCrypto.randomBytes(8).toString('hex'),
          code_challenge: nodeCrypto.createHash('sha256').update(verifier)
            .digest('base64url'),
          code_challenge_method: 'S256' }).toString());
      const opened = await authnScreen.open({ port: port, jar: b.jar,
        at: String(start.headers.location || '') });
      return { b: b, opened: opened, view: opened.view || {} };
    };
    const usernameless = async function (client, key) {
      const s = await screenFor(client);
      const armed = await authnScreen.passkeyOptions({ port: port,
        jar: s.b.jar, opened: s.opened });
      return authnScreen.act({ port: port, jar: s.b.jar, opened: s.opened,
        path: '/authn-api/pending/' + encodeURIComponent(s.opened.id) +
              '/passkey',
        body: { credential: JSON.stringify(key.assert(armed.challenge)) }
      });
    };
    // The screen's first step for a typed name: passwordless, or after a
    // password; the passkey step's page it names.
    const firstStep = async function (client, name, passwordless) {
      const s = await screenFor(client);
      const step = await authnScreen.follow({ port: port, jar: s.b.jar,
        opened: s.opened, fields: { action: 'login', username: name,
          password: passwordless ? '' : PASSWORD,
          webauthn_only: passwordless ? '1' : '' } });
      return { s: s, step: step };
    };
    const signedIn = function (posted) {
      return posted.status === 302 || posted.status === 303;
    };
    const refusedAct = function (posted) {
      return posted.apiStatus === 400 && posted.next === 'refused';
    };
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
    const rowOf = function (name, id) {
      return credentials.keysOf(name).filter(function (one) {
        return one.credentialId === id;
      })[0] || {};
    };

    // 1. The save.
    config.setOverride('webauthn.algorithms', 'ES256,RS256');
    const noPq = passkeyPolicy.save('default',
                                    withDefaults({ postQuantumRequired:
                                                     'sign-in' }));
    const offStill = passkeyPolicy.save('default', withDefaults());
    config.setOverride('webauthn.pqcOnly', true);
    const withOnly = passkeyPolicy.save('default',
      withDefaults({ postQuantumRequired: 'registration-and-sign-in' }));
    config.clearOverride('webauthn.pqcOnly');
    config.setOverride('webauthn.pqcAlongsideClassical', true);
    const withLane = passkeyPolicy.save('default',
                                        withDefaults({ postQuantumRequired:
                                                         'sign-in' }));
    config.clearOverride('webauthn.pqcAlongsideClassical');
    config.clearOverride('webauthn.algorithms');
    passkeyPolicy.save('default', withDefaults());
    note(!noPq.ok && errorCodes.codeOf(noPq) === 'STS-AUTHN-0357' &&
         /offers no ML-DSA/.test((noPq.errors || []).join(' ')) &&
         offStill.ok && withOnly.ok && withLane.ok,
         '1. requiring a post-quantum passkey where the realm offers no ' +
         'ML-DSA is refused at the save (STS-AUTHN-0357); off is not, and ' +
         'webauthn.pqcOnly or the post-quantum lane offers it',
         JSON.stringify([noPq, offStill.ok, withOnly.ok, withLane.ok])
           .slice(0, 600));

    // The keys, enrolled while nothing is required (the switch off: one
    // lane, ML-DSA offered first).
    const aliceKey = await makeAuthenticator(-7, RPID, ORIGIN);
    const aliceMfa = await makeAuthenticator(-7, RPID, ORIGIN);
    const bobKey = await makeAuthenticator(-49, RPID, ORIGIN);
    const carolClassical = await makeAuthenticator(-7, RPID, ORIGIN);
    const carolPq = await makeAuthenticator(-48, RPID, ORIGIN);
    const daveKey = await makeAuthenticator(-7, RPID, ORIGIN);
    const enrolled = [];
    enrolled.push(await enrol('pqr-alice', { role: 'primary' }, function (b) {
      return aliceKey.register(b.challenge, b.userHandle);
    }));
    enrolled.push(await enrol('pqr-alice', { role: 'mfa' }, function (b) {
      return aliceMfa.register(b.challenge, b.userHandle);
    }));
    enrolled.push(await enrol('pqr-bob', { role: 'primary' }, function (b) {
      return bobKey.register(b.challenge, b.userHandle);
    }));
    enrolled.push(await enrol('pqr-carol', { role: 'primary' }, function (b) {
      return carolClassical.register(b.challenge, b.userHandle);
    }));
    enrolled.push(await enrol('pqr-carol', { role: 'primary' }, function (b) {
      return carolPq.register(b.challenge, b.userHandle);
    }));
    enrolled.push(await enrol('pqr-dave', { role: 'primary' }, function (b) {
      return daveKey.register(b.challenge, b.userHandle);
    }));
    const bobRow = rowOf('pqr-bob', bobKey.credentialId);
    note(enrolled.every(function (one) { return one.done.ok; }) &&
         !('lane' in bobRow) && bobRow.algorithm === 'ML-DSA-65',
         '(the keys: ES256 for alice, both roles, and dave; ML-DSA-65 for ' +
         'bob, whose row records no lane; ES256 and ML-DSA-44 for carol)',
         JSON.stringify(enrolled.map(function (one) {
           return one.done.ok || one.done.errors;
         })) + ' ' + JSON.stringify(bobRow).slice(0, 200));

    // 2. A named profile selected by application.
    const named = passkeyPolicy.save('pq-strict', Object.assign(
      withDefaults({ postQuantumRequired: 'sign-in' }),
      { selectApplications: STRICT, precedence: 10 }));
    note(named.ok, '(a named profile requiring a post-quantum passkey at ' +
         'sign-in, selected by ' + STRICT + ')',
         JSON.stringify(named.errors || []));
    const before = refusals('pqr-alice', 'STS-AUTHN-0356');
    let posted = await usernameless(STRICT, aliceKey);
    note(refusedAct(posted) &&
         /requires a post-quantum passkey/.test(posted.text) &&
         refusals('pqr-alice', 'STS-AUTHN-0356') === before + 1,
         '2a. a usernameless sign-in to the application the profile ' +
         'selects, with an ES256 passkey, is refused after the ceremony ' +
         '(STS-AUTHN-0356, a session.refuse row) and says why',
         posted.apiStatus + ' ' + posted.text.slice(0, 300));
    posted = await usernameless(LOOSE, aliceKey);
    note(signedIn(posted),
         '2b. the same key signs in to an application the profile does not ' +
         'select', posted.status + ' ' + posted.text.slice(0, 200));

    // 3. The algorithm decides: bob's ML-DSA key has no lane.
    posted = await usernameless(STRICT, bobKey);
    note(signedIn(posted),
         '3. an ML-DSA-65 key whose row records no lane signs in to the ' +
         'strict application', posted.status + ' ' + posted.text.slice(0,
                                                                      200));

    // 4. The filtered allowCredentials.
    let f = await firstStep(STRICT, 'pqr-carol', true);
    let done = await authnScreen.passkeyStep({ port: port, jar: f.s.b.jar,
                                               opened: f.step },
      function (c) {
        return carolPq.assert(c.challenge);
      });
    const allowStrict = ((done.armed.json || {}).allow || []);
    note(JSON.stringify(allowStrict) ===
           JSON.stringify([carolPq.credentialId]) &&
         done.answer.next === 'redirect',
         '4a. the passkey step names only carol\'s post-quantum key in ' +
         'allowCredentials, and it signs her in',
         JSON.stringify(allowStrict) + ' ' + done.answer.next);
    f = await firstStep(LOOSE, 'pqr-carol', true);
    done = await authnScreen.passkeyStep({ port: port, jar: f.s.b.jar,
                                           opened: f.step },
      function (c) {
        return carolClassical.assert(c.challenge);
      });
    const allowLoose = ((done.armed.json || {}).allow || []).slice().sort();
    note(allowLoose.length === 2 && done.answer.next === 'redirect',
         '4b. where nothing is required both keys are named, and the ' +
         'classical one signs her in', JSON.stringify(allowLoose) + ' ' +
         done.answer.next);

    // 5. Both roles, told before the ceremony.
    const daveBefore = refusals('pqr-dave', 'STS-AUTHN-0356');
    f = await firstStep(STRICT, 'pqr-dave', true);
    const daveView = (f.step.view || {}).webauthn || {};
    done = await authnScreen.passkeyStep({ port: port, jar: f.s.b.jar,
                                           opened: f.step },
      function (c) {
        return daveKey.assert(c.challenge);
      });
    note(daveView.mode === 'get' &&
         /requires a post-quantum passkey/.test(String(daveView.problem)) &&
         refusedAct(done.armed) &&
         /requires a post-quantum passkey/.test(done.armed.text) &&
         refusals('pqr-dave', 'STS-AUTHN-0356') === daveBefore + 1,
         '5a. PRIMARY: a person holding only a classical passkey is told on ' +
         'the passwordless step\'s page and the ceremony is refused before ' +
         'it is armed (STS-AUTHN-0356, recorded) — and offered no ' +
         'enrolment instead', JSON.stringify(daveView).slice(0, 200) + ' ' +
         done.armed.apiStatus + ' ' + done.armed.text.slice(0, 200));
    const aliceBefore = refusals('pqr-alice', 'STS-AUTHN-0356');
    f = await firstStep(STRICT, 'pqr-alice', false);
    const aliceView = (f.step.view || {}).webauthn || {};
    done = await authnScreen.passkeyStep({ port: port, jar: f.s.b.jar,
                                           opened: f.step },
      function (c) {
        return aliceMfa.assert(c.challenge);
      });
    note(f.step.page === 'webauthn' &&
         /requires a post-quantum passkey/.test(String(aliceView.problem)) &&
         refusedAct(done.armed) &&
         refusals('pqr-alice', 'STS-AUTHN-0356') === aliceBefore + 1,
         '5b. SECOND FACTOR: the step after a password is held to it too, ' +
         'told and refused before the ceremony',
         f.step.page + ' ' + JSON.stringify(aliceView).slice(0, 200) + ' ' +
         done.armed.apiStatus);
    // An assertion sent anyway, against the step's own challenge.
    const anyway = await authnScreen.stepAct({ port: port, jar: f.s.b.jar,
      opened: f.step, op: 'webauthn',
      body: { credential: JSON.stringify(
        aliceMfa.assert(String(aliceView.challenge || ''))) } });
    note(anyway.next !== 'redirect' &&
         refusals('pqr-alice', 'STS-AUTHN-0356') === aliceBefore + 2,
         '5c. and a second-factor assertion sent anyway is refused at the ' +
         'session\'s start (STS-AUTHN-0356, a session.refuse row)',
         anyway.apiStatus + ' ' + anyway.next + ' ' +
         anyway.text.slice(0, 200));

    // 6. The signal, once per key and reason.
    const signalsFor = function (name) {
      return changes.filter(function (one) {
        return one.username === name &&
               /passkey policy/.test(String(one.reasonAdmin || ''));
      }).length;
    };
    const aliceSignals = signalsFor('pqr-alice');
    posted = await usernameless(STRICT, aliceKey);
    const aliceRow = rowOf('pqr-alice', aliceKey.credentialId);
    note(refusedAct(posted) && aliceSignals === 2 &&
         signalsFor('pqr-alice') === 2 &&
         ((aliceRow.policyRefused || {})['post-quantum'] || {}).code ===
           'STS-AUTHN-0356' &&
         changes.filter(function (one) {
           return one.username === 'pqr-alice';
         }).every(function (one) {
           return one.initiatingEntity === 'policy' &&
                  one.changeType === 'update';
         }),
         '6. one CAEP credential-change by policy per key — alice\'s primary ' +
         'and second-factor keys, two — however often each is refused, and ' +
         'the mark on the row', aliceSignals + ' ' +
         signalsFor('pqr-alice') + ' ' +
         JSON.stringify(aliceRow.policyRefused || null));

    // 7. The warnings, under a default profile requiring it.
    const saved = passkeyPolicy.save('default',
                                     withDefaults({ postQuantumRequired:
                                                      'sign-in' }));
    const view = function (name) {
      const keys = new accountKeys.AccountKeys(
        accountKeys.AccountKeys.defaultDeps());
      return passkeyPolicy.withSelection(name, '', function () {
        return keys.view({ username: name,
                           session: { user: { name: name } } }, ORIGIN);
      });
    };
    const carolKeys = (view('pqr-carol').keys || []);
    const flagOf = function (rows, id) {
      return (rows.filter(function (one) {
        return one.credentialId === id;
      })[0] || {}).postQuantumRefused;
    };
    const drawn = carolKeys.map(function (one) {
      // A translator that names its keys, so the drawn sentence is the
      // catalog's key.
      return keysPages.passkeyRow(one, {
        html: function (key) {
          return '[' + key + ']';
        },
        text: function (key) {
          return key;
        } });
    }).join('');
    const console = adminViews.mfaJson('pqr-carol');
    const consoleOf = function (id) {
      return ((console.keys || []).filter(function (one) {
        return one.credentialId === id;
      })[0] || {}).postQuantumRefused;
    };
    note(saved.ok && flagOf(carolKeys, carolClassical.credentialId) === true &&
         flagOf(carolKeys, carolPq.credentialId) === false &&
         drawn.split('id="passkey-post-quantum-refused"').length === 2 &&
         drawn.indexOf('[portal.keys.postQuantumRefused]') >= 0 &&
         /requires a post-quantum passkey/.test(
           String(consoleOf(carolClassical.credentialId))) &&
         consoleOf(carolPq.credentialId) === '',
         '7. /portal/keys marks carol\'s classical key and not her ' +
         'post-quantum one, and the console carries the refusal beside the ' +
         'classical key only', JSON.stringify(carolKeys.map(function (one) {
           return [one.credentialId.slice(0, 8), one.postQuantumRefused];
         })) + ' ' + drawn.length);

    // 8. registration-and-sign-in.
    passkeyPolicy.save('default', withDefaults({
      postQuantumRequired: 'registration-and-sign-in' }));
    const offered = webauthnPolicy.creationOptions(RPID, 'passkey');
    const erinClassical = await makeAuthenticator(-7, RPID, ORIGIN);
    const classicalTry = await enrol('pqr-erin', { role: 'primary' },
      function (b) {
        return erinClassical.register(b.challenge, b.userHandle);
      });
    const written = credentials.addKey('pqr-erin', {
      credentialId: erinClassical.credentialId,
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' },
      algorithm: 'ES256', coseAlg: -7 }, 'primary');
    const erinPq = await makeAuthenticator(-50, RPID, ORIGIN);
    const pqTry = await enrol('pqr-erin', { role: 'primary' }, function (b) {
      return erinPq.register(b.challenge, b.userHandle);
    });
    note(JSON.stringify(offered.algorithms) === '[-48,-49,-50]' &&
         !classicalTry.done.ok &&
         !written.ok && written.reason === 'post-quantum' &&
         errorCodes.codeOf(written) === 'STS-AUTHN-0355' &&
         pqTry.done.ok &&
         rowOf('pqr-erin', erinPq.credentialId).algorithm === 'ML-DSA-87' &&
         !rowOf('pqr-erin', erinClassical.credentialId).credentialId,
         '8a. registration-and-sign-in: enrolment offers only ML-DSA, an ' +
         'ES256 enrolment is refused, addKey() refuses a classical key ' +
         '(STS-AUTHN-0355, reason post-quantum) and an ML-DSA-87 key is ' +
         'written', JSON.stringify([offered.algorithms, classicalTry.done,
                                    written, pqTry.done.ok]).slice(0, 600));
    config.setOverride('webauthn.pqcAlongsideClassical', true);
    const lanes = webauthnPolicy.lanes();
    const begunClassical = credentials.beginKeyEnrolment('pqr-erin',
      { role: 'primary', lane: 'classical' });
    credentials.abandonKeyEnrolment('pqr-erin');
    config.clearOverride('webauthn.pqcAlongsideClassical');
    note(JSON.stringify(lanes) === '["pqc"]' && begunClassical.ok &&
         begunClassical.lane === 'pqc' &&
         begunClassical.userHandle ===
           credentials.userHandleOf('pqr-erin', { lane: 'pqc' }),
         '8b. with both lanes on, only the post-quantum lane is offered, and ' +
         'a classical choice becomes it, under its own handle',
         JSON.stringify(lanes) + ' ' + JSON.stringify(begunClassical)
           .slice(0, 300));

    // 9. The device link.
    passkeyPolicy.save('default', withDefaults({ postQuantumRequired:
                                                   'sign-in' }));
    const linked = deviceEnrolment.beginLink({ username: 'pqr-dave',
      sessionId: 'pqr-session', credentialId: daveKey.credentialId,
      deviceId: 'pqr-device' });
    note(!linked.ok && errorCodes.codeOf(linked) === 'STS-AUTHN-0356',
         '9. the device link refuses a classical key while a post-quantum ' +
         'one is required (STS-AUTHN-0356)', JSON.stringify(linked));

    // 10. Off again.
    passkeyPolicy.reset('pq-strict');
    passkeyPolicy.save('default', withDefaults());
    posted = await usernameless(STRICT, daveKey);
    note(signedIn(posted),
         '10. off again: the classical key signs in to the strict ' +
         'application', posted.status + ' ' + posted.text.slice(0, 200));
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
  const out = path.join(os.tmpdir(), 'sts-pqr-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { PQR_OUT: out, PQR_ROOT: ROOT,
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
  name: 'passkey_post_quantum_required',
  describe: 'a post-quantum passkey required by the passkey policy (#718): ' +
            'the algorithm as the fact, both roles, the filtered ' +
            'allowCredentials, the save refused where no ML-DSA is offered, ' +
            'the warnings and the signal',
  run: run
};
